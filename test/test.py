#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Main test script'''

# To do:
# - Avoid printing Python tracebacks when we assert? It looks like we'd need
#   to override unittest.TextTestResult.addFailure().
# - Switch to Python 3 only? [Windows, Linux, macOS] x [Python 2, Python 3]
#   is painful.
# - Remove BIN_PATH/hosts via config.tearDownHostFiles + case_name_resolution.tearDownClass?


import argparse
import config
import os.path
import sys
import unittest

def find_test_ids(suite, all_ids):
    if hasattr(suite, '__iter__'):
        for s in suite:
            find_test_ids(s, all_ids)
    else:
        all_ids.append(suite.id())

def dump_failed_output(suite):
    if hasattr(suite, '__iter__'):
        for s in suite:
            dump_failures = getattr(s, 'dump_failures', None)
            if dump_failures:
                dump_failures()
            else:
                dump_failed_output(s)

def main():
    parser = argparse.ArgumentParser(description='Wireshark unit tests')
    cap_group = parser.add_mutually_exclusive_group()
    cap_group.add_argument('-e', '--enable-capture', action='store_true', help='Enable capture tests')
    cap_group.add_argument('-E', '--disable-capture', action='store_true', help='Disable capture tests')
    cap_group.add_argument('-i', '--capture-interface', nargs=1, default=None, help='Capture interface index or name')
    parser.add_argument('-p', '--program-path', nargs=1, default=os.path.curdir, help='Path to Wireshark executables.')
    list_group = parser.add_mutually_exclusive_group()
    list_group.add_argument('-l', '--list', action='store_true', help='List tests. One of "all" or a full or partial test name.')
    list_group.add_argument('--list-suites', action='store_true', help='List all suites.')
    list_group.add_argument('--list-groups', action='store_true', help='List all suites and groups.')
    list_group.add_argument('--list-cases', action='store_true', help='List all suites, groups, and cases.')
    parser.add_argument('-v', '--verbose', action='store_const', const=2, default=1, help='Verbose tests.')
    parser.add_argument('tests_to_run', nargs='*', metavar='test', default=['all'], help='Tests to run. One of "all" or a full or partial test name. Default is "all".')
    args = parser.parse_args()

    if args.enable_capture:
        config.setCanCapture(True)
    elif args.disable_capture:
        config.setCanCapture(False)

    if args.capture_interface:
        config.setCaptureInterface(args.capture_interface[0])

    all_tests = unittest.defaultTestLoader.discover(os.path.dirname(__file__), pattern='suite_*')

    all_ids = []
    find_test_ids(all_tests, all_ids)

    run_ids = []
    for tid in all_ids:
        for ttr in args.tests_to_run:
            ttrl = ttr.lower()
            if ttrl == 'all':
                run_ids = all_ids
                break
            if ttrl in tid.lower():
                run_ids.append(tid)

    if not run_ids:
        print('No tests found. You asked for:\n  ' + '\n  '.join(args.tests_to_run))
        parser.print_usage()
        sys.exit(1)

    if args.list:
        print('\n'.join(run_ids))
        sys.exit(0)

    all_suites = set()
    for aid in all_ids:
        aparts = aid.split('.')
        all_suites |= {aparts[0]}
    config.all_suites = list(all_suites)
    config.all_suites.sort()

    all_groups = set()
    for aid in all_ids:
        aparts = aid.split('.')
        if aparts[1].startswith('group_'):
            all_groups |= {'.'.join(aparts[:2])}
        else:
            all_groups |= {aparts[0]}
    config.all_groups = list(all_groups)
    config.all_groups.sort()

    if args.list_suites:
        print('\n'.join(config.all_suites))
        sys.exit(0)

    if args.list_groups:
        print('\n'.join(config.all_groups))
        sys.exit(0)

    if args.list_cases:
        cases = set()
        for rid in run_ids:
            rparts = rid.split('.')
            cases |= {'.'.join(rparts[:2])}
        print('\n'.join(list(cases)))
        sys.exit(0)

    program_path = args.program_path[0]
    if not config.setProgramPath(program_path):
        print('One or more required executables not found at {}\n'.format(program_path))
        parser.print_usage()
        sys.exit(1)

    #
    if sys.stdout.encoding != 'UTF-8':
        import codecs
        import locale
        sys.stderr.write('Warning: Output encoding is {0} and not UTF-8.\n'.format(sys.stdout.encoding))
        if sys.version_info[0] >= 3:
            sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout.buffer, 'backslashreplace')
            sys.stderr = codecs.getwriter(locale.getpreferredencoding())(sys.stderr.buffer, 'backslashreplace')
        else:
            sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout, 'backslashreplace')
            sys.stderr = codecs.getwriter(locale.getpreferredencoding())(sys.stderr, 'backslashreplace')

    run_suite = unittest.defaultTestLoader.loadTestsFromNames(run_ids)
    runner = unittest.TextTestRunner(verbosity=args.verbose)
    test_result = runner.run(run_suite)

    dump_failed_output(run_suite)

    if test_result.errors:
        sys.exit(2)

    if test_result.failures:
        sys.exit(1)

if __name__ == '__main__':
    main()
