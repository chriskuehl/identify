import builtins
import errno
import io
import os
import socket
import stat
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

from identify import identify


def test_all_tags_includes_basic_ones():
    assert 'file' in identify.ALL_TAGS
    assert 'directory' in identify.ALL_TAGS
    assert 'executable' in identify.ALL_TAGS
    assert 'text' in identify.ALL_TAGS
    assert 'socket' in identify.ALL_TAGS


@pytest.mark.parametrize(
    'tag_group',
    (
        identify.TYPE_TAGS,
        identify.MODE_TAGS,
        identify.ENCODING_TAGS,
    ),
)
def test_all_tags_contains_all_groups(tag_group):
    assert tag_group < identify.ALL_TAGS


def test_all_tags_contains_each_type():
    assert 'xml' in identify.ALL_TAGS  # extension
    assert 'plist' in identify.ALL_TAGS  # extension, needs binary check
    assert 'dockerfile' in identify.ALL_TAGS  # by file convention
    assert 'python3' in identify.ALL_TAGS  # by shebang


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


def test_tags_from_path_socket():
    tmproot = '/tmp'  # short path avoids `OSError: AF_UNIX path too long`
    with TemporaryDirectory(dir=tmproot) as tmpdir:
        socket_path = os.path.join(tmpdir, 'socket')
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(socket_path)
            tags = identify.tags_from_path(socket_path)

    assert tags == {'socket'}


def test_tags_from_path_broken_symlink(tmpdir):
    x = tmpdir.join('foo')
    x.mksymlinkto(tmpdir.join('lol'))
    assert identify.tags_from_path(x.strpath) == {'symlink'}


def test_tags_from_path_simple_file(tmpdir):
    x = tmpdir.join('test.py').ensure()
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable', 'python',
    }


def test_tags_from_path_file_with_incomplete_shebang(tmpdir):
    x = tmpdir.join('test')
    x.write_text('#!   \n', encoding='UTF-8')
    make_executable(x.strpath)
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'executable',
    }


def test_tags_from_path_file_with_shebang_non_executable(tmpdir):
    x = tmpdir.join('test')
    x.write_text('#!/usr/bin/env python\nimport sys\n', encoding='UTF-8')
    assert identify.tags_from_path(x.strpath) == {
        'file', 'text', 'non-executable',
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


def test_tags_from_path_plist_binary(tmpdir):
    x = tmpdir.join('t.plist')
    x.write_binary(
        b'bplist00\xd1\x01\x02_\x10\x0fLast Login NameWDefault\x08\x0b\x1d\x00'
        b'\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%',
    )
    assert identify.tags_from_path(x.strpath) == {
        'file', 'plist', 'binary', 'non-executable',
    }


def test_tags_from_path_plist_text(tmpdir):
    x = tmpdir.join('t.plist')
    x.write(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'  # noqa: E501
        '<plist version="1.0">\n'
        '<dict>\n'
        '\t<key>Last Login Name</key>\n'
        '\t<string>Default</string>\n'
        '</dict>\n'
        '</plist>\n',
    )
    assert identify.tags_from_path(x.strpath) == {
        'file', 'plist', 'text', 'non-executable',
    }


@pytest.mark.parametrize(
    ('interpreter', 'expected'),
    (
        ('dson', {'salt', 'file', 'non-executable', 'text'}),
        ('genshi', {'salt', 'file', 'non-executable', 'text'}),
        ('gpg', {'salt', 'file', 'non-executable', 'text', 'gnupg'}),
        ('jinja', {'salt', 'file', 'non-executable', 'text', 'jinja'}),
        ('jinja|py', {'salt', 'file', 'non-executable', 'text', 'jinja'}),
        ('jinja|yaml', {'salt', 'file', 'non-executable', 'text', 'jinja'}),
        (
            'jinja|yaml|gpg', {
                'salt', 'file', 'non-executable', 'text', 'jinja',
            },
        ),
        ('py', {'salt', 'file', 'non-executable', 'text', 'python'}),
        ('pydsl', {'salt', 'file', 'non-executable', 'text', 'python'}),
        ('pyobjects', {'salt', 'file', 'non-executable', 'text', 'python'}),
        ('wempy', {'salt', 'file', 'non-executable', 'text'}),
        ('yaml', {'salt', 'file', 'non-executable', 'text', 'yaml'}),
        ('yamlex', {'salt', 'file', 'non-executable', 'text'}),
        ('yaml|gpg', {'salt', 'file', 'non-executable', 'text', 'yaml'}),
    ),
)
@pytest.mark.parametrize(
    ('interpreter_prefix',),
    (
        ('#!',),
        ('#! ',),
    ),
)
def test_tags_from_path_with_interpreter_check(
    tmpdir,
    interpreter_prefix,
    interpreter,
    expected,
):
    x = tmpdir.join('test.sls')
    x.write(interpreter_prefix + interpreter)
    assert identify.tags_from_path(x.strpath) == expected


@pytest.mark.parametrize(
    ('filename', 'expected'),
    (
        ('test.py', {'text', 'python'}),
        ('test.mk', {'text', 'makefile'}),
        ('Makefile', {'text', 'makefile'}),
        ('Dockerfile', {'text', 'dockerfile'}),
        ('Dockerfile.xenial', {'text', 'dockerfile'}),
        ('xenial.Dockerfile', {'text', 'dockerfile'}),
        ('Pipfile', {'text', 'toml'}),
        ('Pipfile.lock', {'text', 'json'}),
        ('mod/test.py', {'text', 'python'}),
        ('mod/Dockerfile', {'text', 'dockerfile'}),
        ('Gemfile', {'text', 'ruby'}),
        ('Gemfile.lock', {'text'}),

        # does not set binary / text
        ('f.plist', {'plist'}),

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
        ('éóñəå  ⊂(◉‿◉)つ(ノ≥∇≤)ノ'.encode(), True),
        (r'¯\_(ツ)_/¯'.encode(), True),
        ('♪┏(・o･)┛♪┗ ( ･o･) ┓♪┏ ( ) ┛♪┗ (･o･ ) ┓♪'.encode(), True),
        ('éóñå'.encode('latin1'), True),

        (b'hello world\x00', False),
        # first few bytes of /bin/bash
        (b'\x7f\x45\x4c\x46\x02\x01\x01', False),
        # some /dev/urandom output
        (b'\x43\x92\xd9\x0f\xaf\x32\x2c', False),
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
        # Test nix-shell specialites with shebang on second line
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#! nix-shell -i bash -p python',
            ('bash',),
        ),
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#! nix-shell -i python -p coreutils',
            ('python',),
        ),
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#! nix-shell -p coreutils -i python',
            ('python',),
        ),
        # multi-line and no whitespace variation
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#! nix-shell -p coreutils\n'
            b'#! nix-shell -i python',
            ('python',),
        ),
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#!nix-shell -p coreutils\n'
            b'#!nix-shell -i python',
            ('python',),
        ),
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#!\xf9\x93\x01\x42\xcd',
            ('nix-shell',),
        ),
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#!\x00\x00\x00\x00',
            ('nix-shell',),
        ),
        # non-proper nix-shell
        (b'#! /usr/bin/nix-shell', ('/usr/bin/nix-shell',)),
        (b'#! /usr/bin/env nix-shell', ('nix-shell',)),
        (
            b'#! /usr/bin/env nix-shell non-portable-argument',
            ('nix-shell', 'non-portable-argument'),
        ),
        (
            b'#! /usr/bin/env nix-shell\n'
            b'#! nix-shell -i',
            ('nix-shell',),   # guard against index error
        ),
        # interpret quotes correctly
        (
            b'#!/usr/bin/env nix-shell\n'
            b'#!nix-shell --argstr x "a -i python3 p"\n'
            b'#!nix-shell -p hello\n'
            b'#!nix-shell -i bash\n'
            b'#!nix-shell --argstr y "b -i runhaskell q"',
            ('bash',),
        ),
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
    assert identify.parse_shebang_from_file(x.strpath) == ()


def test_parse_shebang_from_file_simple(tmpdir):
    x = tmpdir.join('f')
    x.write_text('#!/usr/bin/env python', encoding='UTF-8')
    make_executable(x.strpath)
    assert identify.parse_shebang_from_file(x.strpath) == ('python',)


def test_parse_shebang_open_raises_einval(tmpdir):
    x = tmpdir.join('f')
    x.write('#!/usr/bin/env not-expected\n')
    make_executable(x)
    error = OSError(errno.EINVAL, f'Invalid argument {x}')
    with mock.patch.object(builtins, 'open', side_effect=error):
        assert identify.parse_shebang_from_file(x.strpath) == ()


def make_executable(filename):
    original_mode = os.stat(filename).st_mode
    os.chmod(
        filename,
        original_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
    )


def test_license_identification():
    assert identify.license_id('LICENSE') == 'MIT'


def test_license_exact_identification(tmpdir):
    wtfpl = '''\
DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
'''
    f = tmpdir.join('LICENSE')
    f.write(wtfpl)
    assert identify.license_id(f.strpath) == 'WTFPL'


def test_license_not_identified():
    assert identify.license_id(os.devnull) is None
