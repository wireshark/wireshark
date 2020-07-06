#!/usr/bin/env python3
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


import argparse
import codecs
import os.path
import sys
import unittest
import fixtures
# Required to make fixtures available to tests!
import fixtures_ws

_all_test_groups = None

@fixtures.fixture(scope='session')
def all_test_groups():
    return _all_test_groups

def find_test_ids(suite, all_ids):
    if hasattr(suite, '__iter__'):
        for s in suite:
            find_test_ids(s, all_ids)
    else:
        all_ids.append(suite.id())

def main():
    if sys.version_info[0] < 3:
        print("Unit tests require Python 3")
        sys.exit(2)

    parser = argparse.ArgumentParser(description='Wireshark unit tests')
    cap_group = parser.add_mutually_exclusive_group()
    cap_group.add_argument('-E', '--disable-capture', action='store_true', help='Disable capture tests')
    release_group = parser.add_mutually_exclusive_group()
    release_group.add_argument('--enable-release', action='store_true', help='Enable release tests')
    parser.add_argument('-p', '--program-path', default=os.path.curdir, help='Path to Wireshark executables.')
    parser.add_argument('--skip-missing-programs',
        help='Skip tests that lack programs from this list instead of failing'
             ' them. Use "all" to ignore all missing programs.')
    list_group = parser.add_mutually_exclusive_group()
    list_group.add_argument('-l', '--list', action='store_true', help='List tests. One of "all" or a full or partial test name.')
    list_group.add_argument('--list-suites', action='store_true', help='List all suites.')
    list_group.add_argument('--list-groups', action='store_true', help='List all suites and groups.')
    list_group.add_argument('--list-cases', action='store_true', help='List all suites, groups, and cases.')
    parser.add_argument('-v', '--verbose', action='store_const', const=2, default=1, help='Verbose tests.')
    parser.add_argument('tests_to_run', nargs='*', metavar='test', default=['all'], help='Tests to run. One of "all" or a full or partial test name. Default is "all".')
    args = parser.parse_args()

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
    all_suites = sorted(all_suites)

    all_groups = set()
    for aid in all_ids:
        aparts = aid.split('.')
        if aparts[1].startswith('group_'):
            all_groups |= {'.'.join(aparts[:2])}
        else:
            all_groups |= {aparts[0]}
    all_groups = sorted(all_groups)
    global _all_test_groups
    _all_test_groups = all_groups

    if args.list_suites:
        print('\n'.join(all_suites))
        sys.exit(0)

    if args.list_groups:
        print('\n'.join(all_groups))
        sys.exit(0)

    if args.list_cases:
        cases = set()
        for rid in run_ids:
            rparts = rid.split('.')
            cases |= {'.'.join(rparts[:2])}
        print('\n'.join(list(cases)))
        sys.exit(0)

    if codecs.lookup(sys.stdout.encoding).name != 'utf-8':
        import locale
        sys.stderr.write('Warning: Output encoding is {0} and not utf-8.\n'.format(sys.stdout.encoding))
        sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout.buffer, 'backslashreplace')
        sys.stderr = codecs.getwriter(locale.getpreferredencoding())(sys.stderr.buffer, 'backslashreplace')

    run_suite = unittest.defaultTestLoader.loadTestsFromNames(run_ids)
    runner = unittest.TextTestRunner(verbosity=args.verbose)
    # for unittest compatibility (not needed with pytest)
    fixtures_ws.fixtures.create_session(args)
    try:
        test_result = runner.run(run_suite)
    finally:
        # for unittest compatibility (not needed with pytest)
        fixtures_ws.fixtures.destroy_session()

    if test_result.errors:
        sys.exit(2)

    if test_result.failures:
        sys.exit(1)

if __name__ == '__main__':
    main()
