#
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''pytest configuration'''


import json
import os
import re
import shutil
import subprocess
import sys
import types
import xml.etree.ElementTree as ET
from collections import Counter
from contextlib import contextmanager

import pytest


def pytest_addoption(parser):
    parser.addoption('--disable-capture', action='store_true',
        help='Disable capture tests'
    )
    parser.addoption('--disable-gui', action='store_true',
        help='Disable GUI tests'
    )
    parser.addoption('--build-type', default='RelWithDebInfo',
        help='CMake build type for multi-config generators.'
    )
    parser.addoption('--program-path',
        help='Path to Wireshark executables.'
    )
    parser.addoption('--skip-missing-programs',
        help='Skip tests that lack programs from this list instead of failing'
             ' them. Use "all" to ignore all missing programs.'
    )
    parser.addoption('--enable-stratoshark', action='store_true',
        help='Enable Stratoshark and related tests'
    )
    parser.addoption('--enable-release', action='store_true',
        help='Enable release tests'
    )
    parser.addoption('--changed-since', metavar='REF',
        help='Skip the coverage classes of suite_dissection.py that the files'
             ' changed since REF cannot affect (see test/dissection_select.py)'
    )
    parser.addoption('--changed-since-sample', metavar='N', type=int, default=25,
        help='With --changed-since, the number of other coverage classes to run'
             ' when files outside the dissectors that tshark uses changed'
             ' (default %(default)s)'
    )


def _dissection_skip(config):
    '''Coverage classes to skip with --changed-since, computed once.'''
    if not hasattr(config, '_dissection_skip'):
        ref = config.getoption('--changed-since')
        if ref:
            import dissection_select
            config._dissection_skip = dissection_select.select(
                ref, config.getoption('--changed-since-sample'))
        else:
            config._dissection_skip = (set(), None)
    return config._dissection_skip


def pytest_report_header(config):
    return _dissection_skip(config)[1]


def pytest_collection_modifyitems(config, items):
    skip = _dissection_skip(config)[0]
    if not skip:
        return
    keep, drop = [], []
    for item in items:
        if item.cls is not None and item.cls.__name__ in skip and \
                os.path.basename(str(item.fspath)) == 'suite_dissection.py':
            drop.append(item)
        else:
            keep.append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep

@pytest.fixture(scope='session')
def capture_interface(request, cmd_dumpcap):
    '''
    Name of capture interface. Tests will be skipped if dumpcap is not
    available or no Loopback interface is available.
    '''
    disabled = request.config.getoption('--disable-capture', default=False)
    if disabled:
        pytest.skip('Capture tests are disabled via --disable-capture')
    proc = subprocess.Popen((cmd_dumpcap, '-D'), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    outs, errs = proc.communicate()
    if proc.returncode != 0:
        print('"dumpcap -D" exited with %d. stderr:\n%s' %
              (proc.returncode, errs))
        pytest.skip('Test requires capture privileges and an interface.')
    # Matches: "lo (Loopback)" (Linux), "lo0 (Loopback)" (macOS) or
    # "\Device\NPF_{...} (Npcap Loopback Adapter)" (Windows)
    print('"dumpcap -D" output:\n%s' % (outs,))
    m = re.search(r'^(\d+)\. .*\(.*Loopback.*\)', outs, re.MULTILINE|re.IGNORECASE)
    if not m:
        pytest.skip('Test requires a capture interface.')
    iface = m.group(1)
    # Interface found, check for capture privileges (needed for Linux).
    try:
        subprocess.check_output((cmd_dumpcap, '-L', '-i', iface),
                                stderr=subprocess.STDOUT,
                                universal_newlines=True)
        return iface
    except subprocess.CalledProcessError as e:
        print('"dumpcap -L -i %s" exited with %d. Output:\n%s' % (iface,
                                                                  e.returncode,
                                                                  e.output))
        pytest.skip('Test requires capture privileges.')


@pytest.fixture(scope='session')
def program_path(request):
    '''
    Path to the Wireshark binaries as set by the --program-path option, the
    WS_BIN_PATH environment variable or (curdir)/run.
    '''
    curdir_run = os.path.join(os.curdir, 'run')
    if sys.platform == 'win32':
        build_type = request.config.getoption('--build-type')
        curdir_run_config = os.path.join(curdir_run, build_type)
        if os.path.exists(curdir_run_config):
            curdir_run = curdir_run_config
    paths = (
        request.config.getoption('--program-path', default=None),
        os.environ.get('WS_BIN_PATH'),
        curdir_run,
    )
    for path in paths:
        if type(path) is str and os.path.isdir(path):
            return path
    raise AssertionError('Missing directory with Wireshark binaries')


@pytest.fixture(scope='session')
def program(program_path, request):
    skip_if_missing = request.config.getoption('--skip-missing-programs',
                                               default='')
    skip_if_missing = skip_if_missing.split(',') if skip_if_missing else []
    dotexe = ''
    if sys.platform.startswith('win32'):
        dotexe = '.exe'

    def resolver(name, stratoshark_program=False):
        stratoshark_enabled = request.config.getoption('--enable-stratoshark', default=False)
        if stratoshark_program and not stratoshark_enabled:
            pytest.skip(f'{name} has not been enabled via --enable-stratoshark')
        path = os.path.abspath(os.path.join(program_path, name + dotexe))
        if not os.access(path, os.X_OK):
            if skip_if_missing == ['all'] or os.path.basename(name) in skip_if_missing:
                pytest.skip('Program %s is not available' % (os.path.basename(name),))
            raise AssertionError('Program %s is not available' % (name,))
        return path
    return resolver


@pytest.fixture(scope='session')
def cmd_capinfos(program):
    return program('capinfos')


@pytest.fixture(scope='session')
def cmd_dftest(program):
    return program('dftest')


@pytest.fixture(scope='session')
def cmd_dumpcap(program):
    return program('dumpcap')


@pytest.fixture(scope='session')
def cmd_mergecap(program):
    return program('mergecap')


@pytest.fixture(scope='session')
def cmd_rawshark(program):
    return program('rawshark')


@pytest.fixture(scope='session')
def cmd_tshark(program):
    return program('tshark')


@pytest.fixture(scope='session')
def cmd_text2pcap(program):
    return program('text2pcap')


@pytest.fixture(scope='session')
def cmd_editcap(program):
    return program('editcap')


@pytest.fixture(scope='session')
def cmd_wireshark(program):
    return program('wireshark')


@pytest.fixture(scope='session')
def wireshark_command(cmd_wireshark):
    # Windows can always display the GUI and macOS can if we're in a login session.
    # On Linux, headless mode is used, see QT_QPA_PLATFORM in the 'test_env' fixture.
    if sys.platform == 'darwin' and 'SECURITYSESSIONID' not in os.environ:
        pytest.skip('Wireshark GUI tests require loginwindow session')
    if sys.platform not in ('win32', 'darwin', 'linux'):
        if 'DISPLAY' not in os.environ:
            pytest.skip('Wireshark GUI tests require DISPLAY')
    return (cmd_wireshark, '-ogui.update.enabled:FALSE')

@pytest.fixture(scope='session')
def cmd_strato(program):
    return program('strato', stratoshark_program=True)


@pytest.fixture(scope='session')
def cmd_extcap(program, request):
    def extcap_name(name, stratoshark_extcap=False):
        if stratoshark_extcap:
            stratoshark_enabled = request.config.getoption('--enable-stratoshark', default=False)
            if not stratoshark_enabled:
                pytest.skip(f'{name} has not been enabled via --enable-stratoshark')
            if sys.platform == 'darwin':
                return program(os.path.join('Stratoshark.app/Contents/MacOS/extcap', name))
            else:
                return program(os.path.join('extcap/stratoshark', name))
        else:
            if sys.platform == 'darwin':
                return program(os.path.join('Wireshark.app/Contents/MacOS/extcap', name))
            else:
                return program(os.path.join('extcap/wireshark', name))
    return extcap_name


@pytest.fixture(scope='session')
def features(cmd_tshark, make_env):
    '''Returns an object describing available features in tshark.'''
    try:
        tshark_v = subprocess.check_output(
            (cmd_tshark, '--log-fatal', 'warning', '--version'),
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=make_env()
        )
        tshark_v = re.sub(r'\s+', ' ', tshark_v)
    except subprocess.CalledProcessError as ex:
        print('Failed to detect tshark features: %s' % (ex,))
        tshark_v = ''
    gcry_m = re.search(r'\+Gcrypt +([0-9]+)\.([0-9]+)', tshark_v)
    gcry_ver = (int(gcry_m.group(1)),int(gcry_m.group(2)))
    tshark_v_parts = re.split(r'(?:Compile-|Run)time info:', tshark_v)
    try:
        tshark_runtime = tshark_v_parts[2]
    except IndexError:
        print(f'Failed to detect tshark runtime features: {tshark_v_parts}', file=sys.stderr)
        tshark_runtime = ''
    zstd_versions = [tuple(map(int, version)) for version in
                     re.findall(r'\+Zstandard (\d+)\.(\d+)\.(\d+)', tshark_v)]
    lua_versions = [tuple(map(int, version)) for version in
                    re.findall(r'\+Lua (\d+)\.(\d+)\.(\d+)', tshark_v)]
    return types.SimpleNamespace(
        have_x64='Compiler info: 64-bit' in tshark_v,
        have_lua='+Lua' in tshark_v,
        have_lua_unicode='(UfW patched)' in tshark_v,
        # wslua uses generational garbage collection with Lua 5.4.5 and later
        have_lua_gc_generational=bool(lua_versions) and min(lua_versions) >= (5, 4, 5),
        have_nghttp2='+nghttp2' in tshark_v,
        have_nghttp3='+nghttp3' in tshark_v,
        have_kerberos='+Kerberos' in tshark_v,
        have_gcrypt_1_10=gcry_m and gcry_ver >= (1, 10),
        have_gnutls='+GnuTLS' in tshark_v,
        have_pkcs11='PKCS#11' in tshark_v,
        have_brotli='+brotli' in tshark_v,
        have_zstd='+Zstandard' in tshark_v,
        have_zstd_fast=bool(zstd_versions) and min(zstd_versions) >= (1, 4, 0),
        have_plugins='Plugins: supported' in tshark_v,
        have_libsmi='+libsmi' in tshark_v,
        have_pcap='libpcap' in tshark_runtime,
    )


@pytest.fixture(scope='session')
def dirs():
    '''Returns fixed directories containing test input.'''
    this_dir = os.path.dirname(__file__)
    return types.SimpleNamespace(
        baseline_dir=os.path.join(this_dir, 'baseline'),
        capture_dir=os.path.join(this_dir, 'captures'),
        config_dir=os.path.join(this_dir, 'config'),
        key_dir=os.path.join(this_dir, 'keys'),
        lua_dir=os.path.join(this_dir, 'lua'),
        protobuf_lang_files_dir=os.path.join(this_dir, 'protobuf_lang_files'),
        tools_dir=os.path.join(this_dir, '..', 'tools'),
        dfilter_dir=os.path.join(this_dir, 'suite_dfilter'),
    )


@pytest.fixture(scope='session')
def capture_file(dirs):
    '''Returns the path to a capture file.'''
    def resolver(filename):
        return os.path.join(dirs.capture_dir, filename)
    return resolver

@pytest.fixture
def result_file(tmp_path):
    '''Returns the path to a temporary file.'''
    def result_file_real(filename):
        return str(tmp_path / filename)
    return result_file_real

@pytest.fixture
def home_path(tmp_path):
    '''Per-test home directory.'''
    return str(tmp_path / 'test-home')

@pytest.fixture
def conf_path(home_path):
    '''Path to the Wireshark configuration directory.'''
    if sys.platform.startswith('win32'):
        conf_path = os.path.join(home_path, 'Wireshark')
    else:
        conf_path = os.path.join(home_path, '.config', 'wireshark')
    os.makedirs(conf_path)
    return conf_path


@pytest.fixture(scope='session')
def make_env():
    """A factory for a modified environment to ensure reproducible tests."""
    def make_env_real(home=None):
        env = os.environ.copy()
        env['TZ'] = 'UTC'
        env['WIRESHARK_ABORT_ON_DISSECTOR_BUG'] = '1'
        home_env = 'APPDATA' if sys.platform.startswith('win32') else 'HOME'
        if home:
            env[home_env] = home
        else:
            # This directory is supposed not to be written and is used by
            # "readonly" tests that do not read any other preferences.
            env[home_env] = "/wireshark-tests-unused"
        # XDG_CONFIG_HOME takes precedence over HOME, which we don't want.
        try:
            del env['XDG_CONFIG_HOME']
        except KeyError:
            pass
        return env
    return make_env_real


@pytest.fixture
def base_env(home_path, make_env, request):
    """A modified environment to ensure reproducible tests. Tests can modify
    this environment as they see fit."""
    env = make_env(home=home_path)

    return env


@pytest.fixture
def test_env(base_env, conf_path, request, dirs):
    '''A process environment with a populated configuration directory.'''
    # Populate our UAT files
    uat_files = [
        '80211_keys',
        'dtlsdecrypttablefile',
        'esp_sa',
        'ssl_keys',
        'c1222_decryption_table',
        'ikev1_decryption_table',
        'ikev2_decryption_table',
    ]
    # uat.c replaces backslashes...
    key_dir_path = os.path.join(dirs.key_dir, '').replace('\\', '\\x5c')
    for uat in uat_files:
        template_file = os.path.join(dirs.config_dir, uat + '.tmpl')
        out_file = os.path.join(conf_path, uat)
        with open(template_file, 'r') as f:
            template_contents = f.read()
        cf_contents = template_contents.replace('TEST_KEYS_DIR', key_dir_path)
        with open(out_file, 'w') as f:
            f.write(cf_contents)

    env = base_env
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'
    env['WIRESHARK_QUIT_AFTER_CAPTURE'] = '1'

    # Allow GUI tests to be run without opening windows nor requiring a Xserver.
    # Set envvar QT_DEBUG_BACKINGSTORE=1 to save the window contents to a file
    # in the current directory, output0000.png, output0001.png, etc. Note that
    # this will overwrite existing files.
    if sys.platform == 'linux':
        # This option was verified working on Arch Linux with Qt 5.12.0-2 and
        # Ubuntu 16.04 with libqt5gui5 5.5.1+dfsg-16ubuntu7.5. On macOS and
        # Windows it unfortunately crashes (Qt 5.12.0).
        env['QT_QPA_PLATFORM'] = 'minimal'

    return env


@pytest.fixture
def test_env_80211_user_tk(base_env, conf_path, request, dirs):
    '''A process environment with a populated configuration directory.'''
    # Populate our UAT files
    uat_files = [
        '80211_keys',
    ]
    # uat.c replaces backslashes...
    key_dir_path = os.path.join(dirs.key_dir, '').replace('\\', '\\x5c')
    for uat in uat_files:
        template_file = os.path.join(dirs.config_dir, uat + '.user_tk_tmpl')
        out_file = os.path.join(conf_path, uat)
        with open(template_file, 'r') as f:
            template_contents = f.read()
        cf_contents = template_contents.replace('TEST_KEYS_DIR', key_dir_path)
        with open(out_file, 'w') as f:
            f.write(cf_contents)

    env = base_env
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'
    env['WIRESHARK_QUIT_AFTER_CAPTURE'] = '1'

    # Allow GUI tests to be run without opening windows nor requiring a Xserver.
    # Set envvar QT_DEBUG_BACKINGSTORE=1 to save the window contents to a file
    # in the current directory, output0000.png, output0001.png, etc. Note that
    # this will overwrite existing files.
    if sys.platform == 'linux':
        # This option was verified working on Arch Linux with Qt 5.12.0-2 and
        # Ubuntu 16.04 with libqt5gui5 5.5.1+dfsg-16ubuntu7.5. On macOS and
        # Windows it unfortunately crashes (Qt 5.12.0).
        env['QT_QPA_PLATFORM'] = 'minimal'

    return env

@pytest.fixture
def dfilter_env(base_env, conf_path, request, dirs):
    '''A process environment with a populated configuration directory.'''
    src_macro_path = os.path.join(dirs.dfilter_dir, 'test_dmacros')
    dst_macro_path = os.path.join(conf_path, 'dmacros')
    shutil.copy(src_macro_path, dst_macro_path)

    env = base_env
    return env

@pytest.fixture
def unicode_env(home_path, make_env):
    '''A Wireshark configuration directory with Unicode in its path.'''
    #home_env = 'APPDATA' if sys.platform.startswith('win32') else 'HOME'
    uni_home = os.path.join(home_path, 'unicode-Ф-€-中-testcases')
    env = make_env(home=uni_home)
    if sys.platform == 'win32':
        pluginsdir = os.path.join(uni_home, 'Wireshark', 'plugins')
    else:
        pluginsdir = os.path.join(uni_home, '.local/lib/wireshark/plugins')
    os.makedirs(pluginsdir)
    return types.SimpleNamespace(
        path=lambda *args: os.path.join(uni_home, *args),
        env=env,
        pluginsdir=pluginsdir
    )


@pytest.fixture(scope='session')
def make_screenshot():
    '''Creates a screenshot and save it to a file. Intended for CI purposes.'''
    def make_screenshot_real(filename):
        try:
            if sys.platform == 'darwin':
                subprocess.check_call(['screencapture', filename])
            else:
                print("Creating a screenshot on this platform is not supported")
                return
            size = os.path.getsize(filename)
            print("Created screenshot %s (%d bytes)" % (filename, size))
        except (subprocess.CalledProcessError, OSError) as e:
            print("Failed to take screenshot:", e)
    return make_screenshot_real


@pytest.fixture
def make_screenshot_on_error(request, make_screenshot, result_file):
    '''Writes a screenshot when a process times out.'''
    @contextmanager
    def make_screenshot_on_error_real():
        try:
            yield
        except subprocess.TimeoutExpired:
            filename = result_file('screenshot.png')
            make_screenshot(filename)
            raise
    return make_screenshot_on_error_real


@pytest.fixture
def tshark_fields(cmd_tshark, capture_file, test_env):
    '''Runs `tshark -r <capture> [-2] [-Y <filter>] -Tfields -e <field>...`
    over a capture in test/captures/ and returns its raw stdout.

    This is the standard dissector-test invocation, so it lives here rather
    than being reimplemented per suite.  Pass two_pass=True for generated
    fields that only resolve on the second dissection pass (e.g. a link to a
    later frame), separator to override the default tab field separator,
    prefs for preference overrides and args for any other options.
    '''
    def run(filename, dfilter=None, fields=('frame.number',), two_pass=False,
            separator=None, prefs=None, args=()):
        cmd = [cmd_tshark, '-r', capture_file(filename), *args]
        for pref, value in (prefs or {}).items():
            cmd += ['-o', f'{pref}:{value}']
        if two_pass:
            cmd.append('-2')
        if dfilter is not None:
            cmd += ['-Y', dfilter]
        cmd.append('-Tfields')
        if separator is not None:
            cmd += ['-E', f'separator={separator}']
        for field in fields:
            cmd += ['-e', field]
        return subprocess.check_output(cmd, encoding='utf-8', env=test_env)
    return run


@pytest.fixture
def assert_frame_matches(tshark_fields):
    '''Asserts that a display filter expression matches exactly the given
    frame of a capture.'''
    def check(filename, frame, expr):
        stdout = tshark_fields(filename, f'frame.number == {frame} && {expr}')
        assert stdout.strip() == str(frame), \
            f'Frame {frame}: filter did not match: {expr}'
    return check


@pytest.fixture
def assert_frames_match(tshark_fields):
    '''Asserts several (frame, expr) cases in a *single* tshark invocation.

    Spawning tshark is the dominant cost of a dissector suite (process startup
    plus dissector registration per call), so per-frame loops that each spawn
    tshark are collapsed here: the cases are OR'd into one display filter and
    the matching frame set is checked in one shot.

    A frame is reported only if its expr is true, so a missing frame in the
    output means that case failed; the exprs of cases that name the same
    frame must all be true.  Pass two_pass=True when any expr uses a
    field that needs the second dissection pass.
    '''
    def check(filename, cases, two_pass=False):
        exprs = {}
        for f, e in cases:
            exprs.setdefault(f, []).append(f'({e})')
        terms = [f'(frame.number == {f} && {" && ".join(es)})' for f, es in exprs.items()]
        stdout = tshark_fields(filename, ' || '.join(terms), two_pass=two_pass)
        got = sorted(int(x) for x in stdout.split())
        expected = sorted(exprs)
        assert got == expected, \
            f'matched frames {got}, expected {expected}; cases={cases}'
    return check


class Pdml:
    '''One capture's PDML, keyed by frame number. See dissect_pdml.

    Every lookup takes either a frame number or an element already found
    (a packet, or a subtree such as one list entry), so nested structures
    can be searched the same way as whole frames.

    With `registered` (field names, as `tshark -G fields` lists them), a
    name that is neither registered nor in this PDML raises KeyError, so a
    misspelled name cannot read as an absent field.
    '''

    def __init__(self, text, registered=None):
        self.root = ET.fromstring(text)
        self.packets = {
            int(p.find(".//field[@name='frame.number']").get('show')): p
            for p in self.root.iter('packet')}
        # The shared registry is referenced, not copied: it is large and
        # every cached Pdml has one.
        self.registered = registered
        self.names = {f.get('name') for f in self.root.iter('field')}

    def __getitem__(self, frame):
        return self.packets[frame]

    def _node(self, where):
        return self.packets[where] if isinstance(where, int) else where

    def _check(self, name):
        if (self.registered is not None and name not in self.registered
                and name not in self.names):
            raise KeyError(f'{name!r} is not a registered field')

    def fields(self, where, name):
        '''Every <field> named `name`, in tree order.'''
        self._check(name)
        return self._node(where).findall(f".//field[@name='{name}']")

    def field(self, where, name):
        '''The attributes of the first `name` field, or None.'''
        self._check(name)
        found = self._node(where).find(f".//field[@name='{name}']")
        return None if found is None else found.attrib

    def shows(self, where, name):
        return [f.get('show') for f in self.fields(where, name)]

    def values(self, where, name):
        '''Integer values; a Boolean's True/False reads as 1/0.'''
        return [int(s == 'True') if s in ('True', 'False') else int(s, 0)
                for s in self.shows(where, name)]

    def shownames(self, where, name):
        return [f.get('showname') for f in self.fields(where, name)]

    def label(self, where, name):
        '''The first `name` field's showname, after its "Name: " prefix.'''
        return self.field(where, name)['showname'].split(': ', 1)[1]

    def sizes(self, where, name):
        return [int(f.get('size')) for f in self.fields(where, name)]

    def extents(self, where, name):
        '''(pos, size) of every `name` field.'''
        return [(int(f.get('pos')), int(f.get('size'))) for f in self.fields(where, name)]

    def experts(self, where):
        return self.shows(where, '_ws.expert.message')

    def frames_with(self, name):
        # Checked even when there are no packets to look in.
        self._check(name)
        return sorted(n for n in self.packets if self.fields(n, name))


@pytest.fixture(scope='session')
def dissect_pdml(cmd_tshark, capture_file, make_env, tmp_path_factory, field_registry):
    '''Returns a Pdml for `tshark -r <capture> [-o ...] [-2] [-Y ...] -Tpdml`.

    Spawning tshark is the dominant cost of a dissector suite, so each
    (capture, prefs, two_pass) is dissected once per session and every test
    that asserts on it reads the cached tree.  The whole capture is dissected,
    as a -Y run would, so per-frame state is the same as in tshark_fields.
    '''
    env = make_env(home=str(tmp_path_factory.mktemp('dissect-pdml-home')))
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'
    cache = {}

    def run(filename, prefs=None, two_pass=False, dfilter=None):
        key = (filename, tuple(sorted((prefs or {}).items())), two_pass, dfilter)
        if key not in cache:
            cmd = [cmd_tshark, '-r', capture_file(filename)]
            for pref, value in (prefs or {}).items():
                cmd += ['-o', f'{pref}:{value}']
            if two_pass:
                cmd.append('-2')
            if dfilter is not None:
                cmd += ['-Y', dfilter]
            cmd.append('-Tpdml')
            cache[key] = Pdml(subprocess.check_output(cmd, encoding='utf-8', env=env),
                              field_registry.keys())
        return cache[key]
    return run


@pytest.fixture(scope='session')
def fields_table(dissect_pdml, field_registry, cmd_tshark, capture_file, make_env,
                 tmp_path_factory):
    '''Returns {frame: {field: value}} from `tshark -Tfields`.

    Values are exactly what tshark_fields prints (repeated occurrences joined
    with ','; '' when absent).  The first request on a (capture, prefs,
    two_pass) runs -Tfields once for every field in its cached dissect_pdml
    tree plus the Info and Protocol columns, so later requests on the capture
    are lookups; fields outside that set take a run of their own.
    '''
    env = make_env(home=str(tmp_path_factory.mktemp('fields-table-home')))
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'
    cache = {}

    def tfields(filename, fields, prefs, two_pass):
        head = [cmd_tshark, '-r', capture_file(filename)]
        for pref, value in (prefs or {}).items():
            head += ['-o', f'{pref}:{value}']
        if two_pass:
            head.append('-2')
        # tshark prints a field given twice only once, so frame.number is not in fields.
        head += ['-Tfields', '-e', 'frame.number']
        # A capture with many distinct fields would overrun Windows' 32767-character
        # command line, so the fields go in several runs whose rows are merged.
        chunks, chunk = [], []
        size = sum(len(a) + 1 for a in head)
        for field in fields:
            if chunk and size + len(field) + 4 > 30000:
                chunks.append(chunk)
                chunk, size = [], sum(len(a) + 1 for a in head)
            chunk.append(field)
            size += len(field) + 4
        chunks.append(chunk)
        table = {}
        for chunk in chunks:
            cmd = head + [a for field in chunk for a in ('-e', field)]
            # Not splitlines(): string fields may hold \x1c-\x1e, which it splits on.
            for line in subprocess.check_output(cmd, encoding='utf-8', env=env).split('\n')[:-1]:
                number, *values = line.split('\t')
                table.setdefault(int(number), {'frame.number': number}).update(zip(chunk, values))
        return table

    def lookup(key, fields):
        filename, prefs, two_pass = key
        if key not in cache:
            pdml = dissect_pdml(filename, dict(prefs), two_pass)
            names = {f.get('name') for f in pdml.root.iter('field')} & field_registry.keys()
            names = sorted(names - {'frame.number'} | {'_ws.col.info', '_ws.col.protocol'})
            cache[key] = tfields(filename, names, dict(prefs), two_pass)
        table = cache[key]
        missing = tuple(dict.fromkeys(
            f for f in fields if f not in next(iter(table.values()), {})))
        if missing:
            for number, row in tfields(filename, missing, dict(prefs), two_pass).items():
                table[number].update(row)
        return table

    def run(filename, fields, prefs=None, two_pass=False):
        fields = tuple(fields)
        table = lookup((filename, tuple(sorted((prefs or {}).items())), two_pass), fields)
        return {number: {f: row[f] for f in fields} for number, row in table.items()}
    return run


@pytest.fixture(scope='session')
def expert_tap_counts(cmd_tshark, capture_file, make_env, tmp_path_factory):
    '''Returns {summary: count} from `tshark -q -z expert`, which builds no tree.

    Compare it with the _ws.expert.message values of a tree dissection to
    check that a dissector reports the same experts with and without a tree.
    Rows are sliced by the tap's fixed format, printf("%12d %10s %18s  %s"),
    because protocol names may contain spaces.
    '''
    env = make_env(home=str(tmp_path_factory.mktemp('expert-tap-home')))
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'

    def run(filename, span=None):
        tap = 'expert'
        if span:
            tap += f',frame.number >= {span[0]} && frame.number <= {span[1]}'
        stdout = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(filename), '-q', '-z', tap],
            encoding='utf-8', env=env)
        counts = Counter()
        for line in stdout.splitlines():
            frequency = line[:12].strip()
            if (len(line) > 44 and frequency.isascii() and frequency.isdigit()
                    and line[12] == line[23] == ' ' and line[42:44] == '  '):
                counts[line[44:].rstrip()] += int(frequency)
        return counts
    return run


@pytest.fixture(scope='session')
def field_registry(cmd_tshark, make_env, tmp_path_factory):
    '''{abbrev: row} of `tshark -G fields` field rows, split on tabs.'''
    env = make_env(home=str(tmp_path_factory.mktemp('field-registry-home')))
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'
    output = subprocess.check_output([cmd_tshark, '-G', 'fields'], encoding='utf-8', env=env)
    return {row[2]: row for row in (line.split('\t') for line in output.splitlines())
            if len(row) >= 7 and row[0] == 'F'}


@pytest.fixture(scope='session')
def range_strings(cmd_tshark, make_env, tmp_path_factory):
    '''{abbrev: [(low, high, label)]} of `tshark -G values` range rows.'''
    env = make_env(home=str(tmp_path_factory.mktemp('range-strings-home')))
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'
    output = subprocess.check_output([cmd_tshark, '-G', 'values'], encoding='utf-8', env=env)
    ranges = {}
    for row in (line.split('\t') for line in output.splitlines()):
        if row[0] == 'R':
            ranges.setdefault(row[1], []).append((int(row[2], 0), int(row[3], 0), row[4]))
    return ranges


@pytest.fixture(scope='class', autouse=True)
def section_span(request):
    '''Sets SPAN, a section's first and last frame, on a class that names its SECTION.

    The class's capture is its CAPTURE or FILE, and SECTION is the pcapng
    section number (frame.section_number) its builder wrote.
    '''
    cls = request.cls
    if cls is None or not hasattr(cls, 'SECTION'):
        return
    capture = getattr(cls, 'CAPTURE', None) or cls.FILE
    rows = request.getfixturevalue('fields_table')(capture, ('frame.section_number',))
    frames = [n for n, row in rows.items() if row['frame.section_number'] == str(cls.SECTION)]
    assert frames, (capture, cls.SECTION)
    cls.SPAN = (frames[0], frames[-1])


@pytest.fixture(scope='session')
def sharkd_revisits(program, capture_file, make_env, tmp_path_factory):
    '''Loads a capture in sharkd, then re-dissects each frame of `order` in turn.

    This is what selecting frames in the GUI does after the first pass.
    Returns each frame's tree as a list of tuples of the node `keys`, in tree
    order, and checks that no tree has a dissector bug or malformed item.
    '''
    env = make_env(home=str(tmp_path_factory.mktemp('sharkd-home')))
    env['WIRESHARK_RUN_FROM_BUILD_DIRECTORY'] = '1'

    def run(capture, order, keys=('fn', 'l')):
        reqs = [{'jsonrpc': '2.0', 'id': 1, 'method': 'load',
                 'params': {'file': capture_file(capture)}}]
        reqs += [{'jsonrpc': '2.0', 'id': i, 'method': 'frame',
                  'params': {'frame': f, 'proto': True}}
                 for i, f in enumerate(order, 2)]
        proc = subprocess.run((program('sharkd'), '-'),
                              input=''.join(json.dumps(r) + '\n' for r in reqs),
                              capture_output=True, encoding='utf-8', env=env, check=True)
        resp = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        assert resp[0]['result']['status'] == 'OK'
        assert [r['id'] for r in resp] == list(range(1, len(order) + 2))
        trees = []
        for r in resp[1:]:
            names, items, pending = [], [], list(r['result']['tree'])
            while pending:
                node = pending.pop(0)
                names.append(node.get('fn', ''))
                items.append(tuple(node.get(k, '') for k in keys))
                pending[0:0] = node.get('n', [])
            assert not any(n == '_ws.dissector_bug' or n.startswith('_ws.malformed')
                           for n in names), items
            trees.append(items)
        return trees
    return run


#: Fields that legitimately differ between tshark's first and second pass.
PASS_DEPENDENT_FIELDS = frozenset({
    # Links to a later frame, which only a second pass has seen.
    'mctp.reassembled.in', 'mctpc.response_in', 'nvme-mi.response_in', 'nvme.cqe_pkt',
    'nvme.fabrics.cqe_pkt', 'nvme.data.tr0', 'nvme.data_req',
    'tcg-storage.response_in',
    # TCP conversation analysis, completed at the end of the stream.
    'tcp.completeness', 'tcp.completeness.data', 'tcp.completeness.str',
    'tcp.stream.client.contiguity_count', 'tcp.stream.server.contiguity_count',
    # An NVMe/TCP connection's queue is decided while its first command is
    # dissected, so only a revisit shows it on that command.
    'nvme-tcp.cmd.qid',
})


@pytest.fixture(scope='session')
def assert_pass_parity(dissect_pdml, fields_table):
    '''Asserts that a capture dissects the same on tshark's first pass and on
    a second pass (-2): every field's value, label, extent and visibility,
    except for PASS_DEPENDENT_FIELDS and any `allowed` extras, and the
    Protocol and Info columns (which PDML does not carry).

    The GUI re-dissects a frame whenever it is selected, so state that a
    dissector keeps across frames has to produce the same tree on every
    visit.
    '''
    def check(filename, allowed=()):
        skip = PASS_DEPENDENT_FIELDS | set(allowed)

        def items(pdml, frame):
            return [(f.get('name'), f.get('showname'), f.get('show'), f.get('value'),
                     f.get('size'), f.get('pos'), f.get('hide'))
                    for f in pdml[frame].iter('field') if f.get('name') not in skip]
        one, two = dissect_pdml(filename), dissect_pdml(filename, two_pass=True)
        assert sorted(one.packets) == sorted(two.packets)
        bad = [frame for frame in one.packets if items(one, frame) != items(two, frame)]
        assert not bad, f'{filename}: frames {bad} differ between passes'
        columns = ('_ws.col.protocol', '_ws.col.info')
        one, two = fields_table(filename, columns), fields_table(filename, columns, two_pass=True)
        bad = [frame for frame in one if one[frame] != two[frame]]
        assert not bad, f'{filename}: frames {bad} have different columns between passes'
    return check
