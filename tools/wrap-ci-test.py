#!/usr/bin/env python3

#
# Add arbritrary commands to a GitLab CI compatible (JUnit) test report
# SPDX-License-Identifier: MIT
#
# Usage:
#   wrap-ci-test --file foo.xml --suite "Suite" --case "Name" --command "command"
#   wrap-ci-test --file foo.xml --suite "Suite" --case "Name" command [args] ...

# This script runs a command and adds it to a JUnit report which can then
# be used as a GitLab CI test report:
#
#   https://docs.gitlab.com/ee/ci/testing/unit_test_reports.html
#
# Commands can be specified with the "--command" flag, which will run
# in a subshell, or as a list of extra arguments, which will be run
# directly.
#
# Command output will be "teed". Scrubbed versions will be added to the
# report and unmodified versions will be printed to stdout and stderr.
#
# If the command exit code is nonzero it will be added to the report
# as a failure.
#
# The wrapper will return the command exit code.

# JUnit report information can be found at
# https://github.com/testmoapp/junitxml
# https://www.ibm.com/docs/en/developer-for-zos/14.2?topic=formats-junit-xml-format


import argparse
import html
import time
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(usage='\n  %(prog)s [options] --command "command"\n  %(prog)s [options] command ...')
    parser.add_argument('--file', required=True, type=pathlib.Path, help='The JUnit-compatible XML file')
    parser.add_argument('--suite', required=True, help='The testsuite_el name')
    parser.add_argument('--case', required=True, help='The testcase name')
    parser.add_argument('--command', help='The command to run if no extra arguments are provided')

    args, command_list = parser.parse_known_args()

    if (args.command and len(command_list) > 0) or (args.command is None and len(command_list) == 0):
        sys.stderr.write('Error: The command must be provided via the --command flag or extra arguments.\n')
        sys.exit(1)

    try:
        tree = ET.parse(args.file)
        testsuites_el = tree.getroot()
    except FileNotFoundError:
        testsuites_el = ET.Element('testsuites')
        tree = ET.ElementTree(testsuites_el)
    except ET.ParseError:
        sys.stderr.write(f'Error: {args.file} is invalid.\n')
        sys.exit(1)

    suites_time = float(testsuites_el.get('time', 0.0))
    suites_tests = int(testsuites_el.get('tests', 0)) + 1
    suites_failures = int(testsuites_el.get('failures', 0))

    testsuite_el = testsuites_el.find(f'./testsuite[@name="{args.suite}"]')
    if testsuite_el is None:
        testsuite_el = ET.Element('testsuite', attrib={'name': args.suite})
        testsuites_el.append(testsuite_el)

    suite_time = float(testsuite_el.get('time', 0.0))
    suite_tests = int(testsuite_el.get('tests', 0)) + 1
    suite_failures = int(testsuite_el.get('failures', 0))

    testcase_el = ET.Element('testcase', attrib={'name': args.case})
    testsuite_el.append(testcase_el)

    if args.command:
        proc_args = args.command
        in_shell = True
    else:
        proc_args = command_list
        in_shell = False

    start_time = time.perf_counter()
    proc = subprocess.run(proc_args, shell=in_shell, encoding='UTF-8', errors='replace', capture_output=True)
    case_time = time.perf_counter() - start_time

    testcase_el.set('time', f'{case_time}')
    testsuite_el.set('time', f'{suite_time + case_time}')
    testsuites_el.set('time', f'{suites_time + case_time}')

    # XXX Try to interleave them?
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)

    # Remove ANSI control sequences and escape other invalid characters
    # https://stackoverflow.com/a/14693789/82195
    ansi_seq_re = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    scrubbed_stdout = html.escape(ansi_seq_re.sub('', proc.stdout), quote=False)
    scrubbed_stderr = html.escape(ansi_seq_re.sub('', proc.stderr), quote=False)

    if proc.returncode != 0:
        failure_el = ET.Element('failure')
        failure_el.text = f'{scrubbed_stdout}{scrubbed_stderr}'
        testcase_el.append(failure_el)
        testsuite_el.set('failures', f'{suite_failures + 1}')
        testsuites_el.set('failures', f'{suites_failures + 1}')
    else:
        system_out_el = ET.Element('system-out')
        system_out_el.text = f'{scrubbed_stdout}'
        testcase_el.append(system_out_el)
        system_err_el = ET.Element('system-err')
        system_err_el.text = f'{scrubbed_stderr}'
        testcase_el.append(system_err_el)

    testsuite_el.set('tests', f'{suite_tests}')
    testsuites_el.set('tests', f'{suites_tests}')

    tree.write(args.file, encoding='UTF-8', xml_declaration=True)

    return proc.returncode

if __name__ == '__main__':
    sys.exit(main())
