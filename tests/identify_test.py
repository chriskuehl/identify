# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import io
import os
import stat

import pytest

from identify import identify


def test_all_tags_includes_basic_ones():
    assert 'file' in identify.ALL_TAGS
    assert 'directory' in identify.ALL_TAGS


def test_tags_from_path_does_not_exist(tmpdir):
    x = tmpdir.join('foo')
    with pytest.raises(ValueError):
        identify.tags_from_path(x.strpath)


def test_tags_from_path_directory(tmpdir):
    x = tmpdir.join('foo')
    x.mkdir()
    assert identify.tags_from_path(x.strpath) == {'directory'}


def test_tags_from_path_symlink(tmpdir):
    x = tmpdir.join('foo')
    x.mksymlinkto(tmpdir.join('lol').ensure())
    assert identify.tags_from_path(x.strpath) == {'symlink'}


def test_tags_from_path_broken_symlink(tmpdir):
    x = tmpdir.join('foo')
    x.mksymlinkto(tmpdir.join('lol'))
    assert identify.tags_from_path(x.strpath) == {'symlink'}


def test_tags_from_path_simple_file(tmpdir):
    x = tmpdir.join('test.py').ensure()
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'python',
    }


def test_tags_from_path_file_with_shebang_non_executable(tmpdir):
    x = tmpdir.join('test')
    x.write_text('#!/usr/bin/env python\nimport sys\n', encoding='UTF-8')
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'python',
    }


def test_tags_from_path_file_with_shebang_non_executable_sls_py(tmpdir):
    x = tmpdir.join('test.sls')
    x.write_text('#! py\nimport sys\n', encoding='UTF-8')
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'python', 'salt',
    }


def test_tags_from_path_file_with_shebang_non_executable_sls_pydsl(tmpdir):
    x = tmpdir.join('test.sls')
    x.write_text('#! pydsl\nimport sys\n', encoding='UTF-8')
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'python', 'salt', 'pydsl',
    }


def test_tags_from_path_file_with_shebang_non_executable_sls_pyobjects(tmpdir):
    x = tmpdir.join('test.sls')
    x.write_text('#! pyobjects\nimport sys\n', encoding='UTF-8')
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'python', 'salt', 'pyobjects',
    }


def test_tags_from_path_file_with_shebang_non_executable_sls_yaml(tmpdir):
    x = tmpdir.join('test.sls')
    x.write_text('foo:\n  - bar\n', encoding='UTF-8')
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'salt',
    }


def test_tags_from_path_file_with_shebang_executable(tmpdir):
    x = tmpdir.join('test')
    x.write_text('#!/usr/bin/env python\nimport sys\n', encoding='UTF-8')
    make_executable(x.strpath)
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'executable', 'python',
    }


def test_tags_from_path_binary(tmpdir):
    x = tmpdir.join('test')
    x.write(b'\x7f\x45\x4c\x46\x02\x01\x01')
    make_executable(x.strpath)
    assert identify.tags_from_path(x.strpath) == {
        'file', 'binary', 'executable',
    }


@pytest.mark.parametrize(
    ('filename', 'expected'),
    (
        ('test.py', {'text', 'python'}),
        ('test.mk', {'text', 'makefile'}),
        ('Makefile', {'text', 'makefile'}),
        ('Dockerfile', {'text', 'dockerfile'}),
        ('Dockerfile.xenial', {'text', 'dockerfile'}),
        ('xenial.Dockerfile', {'text', 'dockerfile'}),
        ('mod/test.py', {'text', 'python'}),
        ('mod/Dockerfile', {'text', 'dockerfile'}),

        # case of extension should be ignored
        ('f.JPG', {'binary', 'image', 'jpeg'}),
        # but case of name checks should still be honored
        ('dockerfile.py', {'text', 'python'}),

        # full filename tests should take precedence over extension tests
        ('test.cfg', {'text'}),
        ('setup.cfg', {'text', 'ini'}),

        # Filename matches should still include extensions if applicable
        ('README.md', {'text', 'markdown', 'plain-text'}),

        ('test.weird-unrecognized-extension', set()),
        ('test', set()),
        ('', set()),
    ),
)
def test_tags_from_filename(filename, expected):
    assert identify.tags_from_filename(filename) == expected


@pytest.mark.parametrize(
    ('interpreter', 'expected'),
    (
        ('py', {'python'}),
        ('pydsl', {'python', 'pydsl'}),
        ('pyobjects', {'python', 'pyobjects'}),
        ('python', {'python'}),
        ('python3', {'python3', 'python'}),
        ('python3.5.2', {'python3', 'python'}),
        ('/usr/bin/python3.5.2', {'python3', 'python'}),
        ('/usr/bin/herpderpderpderpderp', set()),
        ('something-random', set()),
        ('', set()),
    ),
)
def test_tags_from_interpreter(interpreter, expected):
    assert identify.tags_from_interpreter(interpreter) == expected


@pytest.mark.parametrize(
    ('data', 'expected'),
    (
        (b'hello world', True),
        (b'', True),
        ('éóñəå  ⊂(◉‿◉)つ(ノ≥∇≤)ノ'.encode('utf8'), True),
        (r'¯\_(ツ)_/¯'.encode('utf8'), True),
        ('♪┏(・o･)┛♪┗ ( ･o･) ┓♪┏ ( ) ┛♪┗ (･o･ ) ┓♪┏(･o･)┛♪'.encode('utf8'), True),
        ('éóñå'.encode('latin1'), True),

        (b'hello world\x00', False),
        (b'\x7f\x45\x4c\x46\x02\x01\x01', False),  # first few bytes of /bin/bash
        (b'\x43\x92\xd9\x0f\xaf\x32\x2c', False),  # some /dev/urandom output
    ),
)
def test_is_text(data, expected):
    assert identify.is_text(io.BytesIO(data)) is expected


def test_file_is_text_simple(tmpdir):
    x = tmpdir.join('f')
    x.write_text('hello there\n', encoding='UTF-8')
    assert identify.file_is_text(x.strpath) is True


def test_file_is_text_does_not_exist(tmpdir):
    x = tmpdir.join('f')
    with pytest.raises(ValueError):
        identify.file_is_text(x.strpath)


@pytest.mark.parametrize(
    ('s', 'expected'),
    (
        (b'', ()),
        (b'#!/usr/bin/python', ('/usr/bin/python',)),
        (b'#!/usr/bin/env python', ('python',)),
        (b'#! /usr/bin/python', ('/usr/bin/python',)),
        (b'#!/usr/bin/foo  python', ('/usr/bin/foo', 'python')),
        # despite this being invalid, setuptools will write shebangs like this
        (b'#!"/path/with spaces/x" y', ('/path/with spaces/x', 'y')),
        # this is apparently completely ok to embed quotes
        (b"#!/path'with/quotes    y", ("/path'with/quotes", 'y')),
        # Don't regress on leading/trailing ws
        (b"#! /path'with/quotes y ", ("/path'with/quotes", 'y')),
        (b'\xf9\x93\x01\x42\xcd', ()),
        (b'#!\xf9\x93\x01\x42\xcd', ()),
        (b'#!\x00\x00\x00\x00', ()),
    ),
)
def test_parse_shebang(s, expected):
    assert identify.parse_shebang(io.BytesIO(s)) == expected


def test_parse_shebang_from_file_does_not_exist():
    with pytest.raises(ValueError):
        identify.parse_shebang_from_file('herp derp derp')


def test_parse_shebang_from_file_nonexecutable(tmpdir):
    x = tmpdir.join('f')
    x.write_text('#!/usr/bin/env python', encoding='UTF-8')
    assert identify.parse_shebang_from_file(x.strpath) == ('python',)


def test_parse_shebang_from_file_simple(tmpdir):
    x = tmpdir.join('f')
    x.write_text('#!/usr/bin/env python', encoding='UTF-8')
    make_executable(x.strpath)
    assert identify.parse_shebang_from_file(x.strpath) == ('python',)


def make_executable(filename):
    original_mode = os.stat(filename).st_mode
    os.chmod(
        filename,
        original_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
    )
