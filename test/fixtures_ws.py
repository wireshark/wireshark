#
# -*- coding: utf-8 -*-
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Fixtures that are specific to Wireshark.'''

import logging
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
    available or if the capture interface is unknown.
    '''
    iface = request.config.getoption('--capture-interface', default=None)
    disabled = request.config.getoption('--disable-capture', default=False)
    if disabled:
        fixtures.skip('Capture tests are disabled via --disable-capture')
    if iface:
        # If a non-empty interface is given, assume capturing is possible.
        return iface
    else:
        if sys.platform == 'win32':
            patterns = '.*(Ethernet|Network Connection|VMware|Intel)'
        else:
            patterns = None
        if patterns:
            try:
                output = subprocess.check_output((cmd_dumpcap, '-D'),
                                                 stderr=subprocess.DEVNULL,
                                                 universal_newlines=True)
                m = re.search(r'^(\d+)\. %s' % patterns, output, re.MULTILINE)
                if m:
                    return m.group(1)
            except subprocess.CalledProcessError:
                pass
    fixtures.skip('Test requires capture privileges and an interface.')


@fixtures.fixture(scope='session')
def program_path(request):
    '''
    Path to the Wireshark binaries as set by the --program-path option, the
    WS_BIN_PATH environment variable or (curdir)/run.
    '''
    paths = (
        request.config.getoption('--program-path', default=None),
        os.environ.get('WS_BIN_PATH'),
        os.path.join(os.curdir, 'run'),
    )
    for path in paths:
        if type(path) == str and os.path.isdir(path):
            return path
    raise AssertionError('Missing directory with Wireshark binaries')


@fixtures.fixture(scope='session')
def program(program_path):
    def resolver(name):
        dotexe = ''
        if sys.platform.startswith('win32'):
            dotexe = '.exe'
        path = os.path.normpath(os.path.join(program_path, name + dotexe))
        if not os.access(path, os.X_OK):
            fixtures.skip('Program %s is not available' % (name,))
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
    if sys.platform not in ('win32', 'darwin'):
        # TODO check DISPLAY for X11 on Linux or BSD?
        fixtures.skip('Wireshark GUI tests requires DISPLAY')
    return (cmd_wireshark, '-ogui.update.enabled:FALSE')


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
        logging.warning('Failed to detect tshark features: %s', ex)
        tshark_v = ''
    gcry_m = re.search(r'with +Gcrypt +([0-9]+\.[0-9]+)', tshark_v)
    return types.SimpleNamespace(
        have_lua='with Lua' in tshark_v,
        have_nghttp2='with nghttp2' in tshark_v,
        have_kerberos='with MIT Kerberos' in tshark_v or 'with Heimdal Kerberos' in tshark_v,
        have_libgcrypt16=gcry_m and float(gcry_m.group(1)) >= 1.6,
        have_libgcrypt17=gcry_m and float(gcry_m.group(1)) >= 1.7,
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

    # Remove this if test instances no longer inherit from SubprocessTestCase?
    if isinstance(request.instance, subprocesstest.SubprocessTestCase):
        # Inject the test environment as default if it was not overridden.
        request.instance.injected_test_env = env
    return env
