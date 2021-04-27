#
# Externally configured Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''
External tests

This module reads one or more test case configuration files specified using `add_external_configs()`.
It creates a test case for each file and one or more tests as specfied.

Configuration files are JSON-formatted and must have the following structure:

    {
    "case_name": "happy_shark",
    "tests": [
    {
        "test_name": "dns",
        "tshark_args": [ "-r", "${case_dir}/tests/dns-1/dns.pcapng",
            "-Y", "dns", "-T", "fields", "-e", "dns.qry.name"
            ],
        "requirements": [
            [ "count", "in.m.yahoo.com", 1 ],
            [ "grep", "in.m.yahoo.com" ],
            [ "!grep", "in.m.notyahoo.com" ],
            [ "in", "in.m.yahoo.com", 0 ],
            [ "!in", "in.m.notyahoo.com", 0 ]
        ]
    }
    ]
    }

`${case_dir}` will be replaced by the path to the configuration file.

"requirements" is a list of search or count requirements.

Search requirements can have one of the following formats:

  Requirement                           Python test API equivalent
  [ "count", "<pattern>", <count> ]     assertEqual(countOutput('<pattern'), <count>)
  [ "grep", "<pattern>" ]               assertTrue(grepOutput('<pattern>'))
  [ "!grep", "<pattern>" ]              assertFalse(grepOutput('<pattern>'))
  [ "in", "<pattern>", <line> ]         assertIn('<pattern>', lines[<line>])
  [ "!in", "<pattern>", <line> ]        assertNotIn('<pattern>', lines[<line>])
'''

# To do:
# - Add JSON matching so that we can migrate group_asterisk to happy_shark.

import fixtures
import json
import os.path
import subprocesstest
import unittest
import traceback
import sys

external_configs = []
debug = True


def add_external_configs(configs):
    if configs:
        external_configs.extend(configs)


def make_tshark_test(tshark_args, requirements):
    '''TShark test function generator'''
    def tshark_test(self, cmd_tshark, features):

        proc = self.assertRun((cmd_tshark, *tshark_args))

        for requirement in requirements:
            negated = False
            try:
                if requirement[0].startswith('!'):
                    negated = True
            except IndexError:
                self.fail('Test type missing.')

            try:
                pattern = requirement[1]
            except IndexError:
                self.fail('Search pattern missing.')

            if requirement[0] == 'count':
                try:
                    required_count = requirement[2]
                except IndexError:
                    self.fail('"count" requires a count argument.')
                self.assertEqual(self.countOutput(pattern), required_count)
            elif requirement[0].endswith('grep'):
                if negated:
                    self.assertFalse(self.grepOutput(pattern))
                else:
                    self.assertTrue(self.grepOutput(pattern))
            elif requirement[0].endswith('in'):
                try:
                    stdout_line = proc.stdout_str.splitlines()[requirement[2]]
                except IndexError:
                    self.fail('"in" requires a line number (starting from zero).')
                if negated:
                    self.assertNotIn(pattern, stdout_line)
                else:
                    self.assertIn(pattern, stdout_line)
            else:
                self.fail('Unrecognized operation "{}"'.format(requirement[0]))

    return tshark_test


def load_tests(loader, standard_tests, pattern):
    '''Create our cases and suites. Run by unittest.defaultTestLoader.discover'''
    for config_file in external_configs:
        try:
            with open(config_file, 'r') as cf:
                config_str = cf.read()
                config_str = config_str.replace('${case_dir}', os.path.dirname(config_file))
                config = json.loads(config_str)
        except Error as e:
            print('Error reading {}: {}'.format(config_file, e))
            continue

        try:
            case_name = 'case_{}'.format(config['case_name'])
        except KeyError:
            print('Error reading {}: case_name not present'.format(config_file))
            continue

        case_tests = dict()
        try:
            # Create 'test_...' functions to match our configuration.
            test_num = 1
            for test_attrs in config['tests']:
                try:
                    test_name = 'test_{}'.format(test_attrs['test_name'])
                except KeyError:
                    print('{}: No test name for test {} '.format(config_file, test_num))
                    continue

                try:
                    requirements = test_attrs['requirements']
                    if not isinstance(requirements, list):
                        raise TypeError
                except:
                    print('{}: Missing or malformed requirements for test {} '.format(config_file, test_num))
                    continue

                tshark_test = make_tshark_test(test_attrs['tshark_args'], requirements)
                setattr(tshark_test, '__name__', test_name)
                case_tests[test_name] = tshark_test
                test_num += 1
            # Create a SubprocessTestCase name 'case_...' and add our 'test_...' functions.
            case_class = type(case_name, (subprocesstest.SubprocessTestCase,), case_tests)
            # Apply @fixtures.mark_usefixtures('test_env') and @fixtures.uses_fixtures
            case_class = fixtures.mark_usefixtures('test_env')(case_class)
            case_class = fixtures.uses_fixtures(case_class)
            globals()[case_name] = case_class
            # Hand our generated class over to unittest.defaultTestLoader.
            return loader.loadTestsFromTestCase(case_class)
        except KeyError:
            print('{}: Missing or malformed tests'.format(config_file))
        except:
            if debug:
                print(traceback.format_exc())
            raise
    return unittest.TestSuite()
