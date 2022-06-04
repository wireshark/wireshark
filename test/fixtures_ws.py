#
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Fixtures that are specific to Wireshark.'''

from contextlib import contextmanager
import os
import re
import subprocess
import sys
import tempfile
import types

import fixtures
import subprocesstest


@fixtures.fixture(scope='session')
def capture_interface(request, cmd_dumpcap):
    '''
    Name of capture interface. Tests will be skipped if dumpcap is not
    available or no Loopback interface is available.
    '''
    disabled = request.config.getoption('--disable-capture', default=False)
    if disabled:
        fixtures.skip('Capture tests are disabled via --disable-capture')
    proc = subprocess.Popen((cmd_dumpcap, '-D'), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    outs, errs = proc.communicate()
    if proc.returncode != 0:
        print('"dumpcap -D" exited with %d. stderr:\n%s' %
              (proc.returncode, errs))
        fixtures.skip('Test requires capture privileges and an interface.')
    # Matches: "lo (Loopback)" (Linux), "lo0 (Loopback)" (macOS) or
    # "\Device\NPF_{...} (Npcap Loopback Adapter)" (Windows)
    print('"dumpcap -D" output:\n%s' % (outs,))
    m = re.search(r'^(\d+)\. .*\(.*Loopback.*\)', outs, re.MULTILINE)
    if not m:
        fixtures.skip('Test requires a capture interface.')
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
        fixtures.skip('Test requires capture privileges.')


@fixtures.fixture(scope='session')
def program_path(request):
    '''
    Path to the Wireshark binaries as set by the --program-path option, the
    WS_BIN_PATH environment variable or (curdir)/run.
    '''
    curdir_run = os.path.join(os.curdir, 'run')
    if sys.platform == 'win32':
        curdir_run_config = os.path.join(curdir_run, 'RelWithDebInfo')
        if os.path.exists(curdir_run_config):
            curdir_run = curdir_run_config
    paths = (
        request.config.getoption('--program-path', default=None),
        os.environ.get('WS_BIN_PATH'),
        curdir_run,
    )
    for path in paths:
        if type(path) == str and os.path.isdir(path):
            return path
    raise AssertionError('Missing directory with Wireshark binaries')


@fixtures.fixture(scope='session')
def program(program_path, request):
    skip_if_missing = request.config.getoption('--skip-missing-programs',
                                               default='')
    skip_if_missing = skip_if_missing.split(',') if skip_if_missing else []
    dotexe = ''
    if sys.platform.startswith('win32'):
        dotexe = '.exe'

    def resolver(name):
        path = os.path.abspath(os.path.join(program_path, name + dotexe))
        if not os.access(path, os.X_OK):
            if skip_if_missing == ['all'] or name in skip_if_missing:
                fixtures.skip('Program %s is not available' % (name,))
            raise AssertionError('Program %s is not available' % (name,))
        return path
    return resolver


@fixtures.fixture(scope='session')
def cmd_capinfos(program):
    return program('capinfos')


@fixtures.fixture(scope='session')
def cmd_dumpcap(program):
    return program('dumpcap')


@fixtures.fixture(scope='session')
def cmd_mergecap(program):
    return program('mergecap')


@fixtures.fixture(scope='session')
def cmd_rawshark(program):
    return program('rawshark')


@fixtures.fixture(scope='session')
def cmd_tshark(program):
    return program('tshark')


@fixtures.fixture(scope='session')
def cmd_text2pcap(program):
    return program('text2pcap')


@fixtures.fixture(scope='session')
def cmd_editcap(program):
    return program('editcap')


@fixtures.fixture(scope='session')
def cmd_wireshark(program):
    return program('wireshark')


@fixtures.fixture(scope='session')
def wireshark_command(cmd_wireshark):
    # Windows can always display the GUI and macOS can if we're in a login session.
    # On Linux, headless mode is used, see QT_QPA_PLATFORM in the 'test_env' fixture.
    if sys.platform == 'darwin' and 'SECURITYSESSIONID' not in os.environ:
        fixtures.skip('Wireshark GUI tests require loginwindow session')
    if sys.platform not in ('win32', 'darwin', 'linux'):
        if 'DISPLAY' not in os.environ:
            fixtures.skip('Wireshark GUI tests require DISPLAY')
    return (cmd_wireshark, '-ogui.update.enabled:FALSE')


@fixtures.fixture(scope='session')
def cmd_extcap(program):
    def extcap_name(name):
        if sys.platform == 'darwin':
            return program(os.path.join('Wireshark.app/Contents/MacOS/extcap', name))
        else:
            return program(os.path.join('extcap', name))
    return extcap_name


@fixtures.fixture(scope='session')
def features(cmd_tshark, make_env):
    '''Returns an object describing available features in tshark.'''
    try:
        tshark_v = subprocess.check_output(
            (cmd_tshark, '--version'),
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=make_env()
        )
        tshark_v = re.sub(r'\s+', ' ', tshark_v)
    except subprocess.CalledProcessError as ex:
        print('Failed to detect tshark features: %s' % (ex,))
        tshark_v = ''
    gcry_m = re.search(r'with +Gcrypt +([0-9]+)\.([0-9]+)', tshark_v)
    gcry_ver = (int(gcry_m.group(1)),int(gcry_m.group(2)))
    return types.SimpleNamespace(
        have_x64='Compiled (64-bit)' in tshark_v,
        have_lua='with Lua' in tshark_v,
        have_nghttp2='with nghttp2' in tshark_v,
        have_kerberos='with Kerberos' in tshark_v,
        have_gnutls='with GnuTLS' in tshark_v,
        have_pkcs11='and PKCS #11 support' in tshark_v,
        have_brotli='with brotli' in tshark_v,
        have_plugins='binary plugins supported' in tshark_v,
    )


@fixtures.fixture(scope='session')
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
    )


@fixtures.fixture(scope='session')
def capture_file(dirs):
    '''Returns the path to a capture file.'''
    def resolver(filename):
        return os.path.join(dirs.capture_dir, filename)
    return resolver


@fixtures.fixture
def home_path():
    '''Per-test home directory, removed when finished.'''
    with tempfile.TemporaryDirectory(prefix='wireshark-tests-home-') as dirname:
        yield dirname


@fixtures.fixture
def conf_path(home_path):
    '''Path to the Wireshark configuration directory.'''
    if sys.platform.startswith('win32'):
        conf_path = os.path.join(home_path, 'Wireshark')
    else:
        conf_path = os.path.join(home_path, '.config', 'wireshark')
    os.makedirs(conf_path)
    return conf_path


@fixtures.fixture(scope='session')
def make_env():
    """A factory for a modified environment to ensure reproducible tests."""
    def make_env_real(home=None):
        env = os.environ.copy()
        env['TZ'] = 'UTC'
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


@fixtures.fixture
def base_env(home_path, make_env, request):
    """A modified environment to ensure reproducible tests. Tests can modify
    this environment as they see fit."""
    env = make_env(home=home_path)

    # Remove this if test instances no longer inherit from SubprocessTestCase?
    if isinstance(request.instance, subprocesstest.SubprocessTestCase):
        # Inject the test environment as default if it was not overridden.
        request.instance.injected_test_env = env
    return env


@fixtures.fixture
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

    # Remove this if test instances no longer inherit from SubprocessTestCase?
    if isinstance(request.instance, subprocesstest.SubprocessTestCase):
        # Inject the test environment as default if it was not overridden.
        request.instance.injected_test_env = env
    return env


@fixtures.fixture
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

    # Remove this if test instances no longer inherit from SubprocessTestCase?
    if isinstance(request.instance, subprocesstest.SubprocessTestCase):
        # Inject the test environment as default if it was not overridden.
        request.instance.injected_test_env = env
    return env

@fixtures.fixture
def unicode_env(home_path, make_env):
    '''A Wireshark configuration directory with Unicode in its path.'''
    home_env = 'APPDATA' if sys.platform.startswith('win32') else 'HOME'
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


@fixtures.fixture(scope='session')
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


@fixtures.fixture
def make_screenshot_on_error(request, make_screenshot):
    '''Writes a screenshot when a process times out.'''
    @contextmanager
    def make_screenshot_on_error_real():
        try:
            yield
        except subprocess.TimeoutExpired:
            filename = request.instance.filename_from_id('screenshot.png')
            make_screenshot(filename)
            raise
    return make_screenshot_on_error_real
