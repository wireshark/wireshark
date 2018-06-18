#
# -*- coding: utf-8 -*-
# Wireshark tests
# By
# Gerald Combs <gerald@wireshark.org>
# Gilbert Ramirez <gram [AT] alumni.rice.edu>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''EPAN unit tests'''

import config
import difflib
import os.path
import pprint
import re
import subprocesstest
import unittest

class case_unittests(subprocesstest.SubprocessTestCase):
    def test_unit_exntest(self):
        '''exntest'''
        self.assertRun(os.path.join(config.program_path, 'exntest'))

    def test_unit_oids_test(self):
        '''oids_test'''
        self.assertRun(os.path.join(config.program_path, 'oids_test'))

    def test_unit_reassemble_test(self):
        '''reassemble_test'''
        self.assertRun(os.path.join(config.program_path, 'reassemble_test'))

    def test_unit_tvbtest(self):
        '''tvbtest'''
        self.assertRun(os.path.join(config.program_path, 'tvbtest'))

    def test_unit_wmem_test(self):
        '''wmem_test'''
        self.assertRun((os.path.join(config.program_path, 'wmem_test'),
            '--verbose'
        ))

    def test_unit_wmem_test(self):
        '''wmem_test'''
        self.assertRun((os.path.join(config.program_path, 'wmem_test'),
            '--verbose'
        ))

    def test_unit_fieldcount(self):
        '''fieldcount'''
        self.assertRun((config.cmd_tshark, '-G', 'fieldcount'))

    def test_unit_ctest_coverage(self):
        '''Make sure CTest runs all of our tests.'''
        with open(os.path.join(config.this_dir, '..', 'CMakeLists.txt')) as cml_fd:
            group_re = re.compile('set *\( *_test_group_list')
            in_list = False
            cml_groups = []
            for cml_line in cml_fd:
                if group_re.search(cml_line):
                    in_list = True
                    continue
                if in_list:
                    if ')' in cml_line:
                        break
                    cml_groups.append(cml_line.strip())
        cml_groups.sort()
        if not config.all_groups == cml_groups:
            diff = '\n'.join(list(difflib.unified_diff(config.all_groups, cml_groups, 'all test groups', 'CMakeLists.txt test groups')))
            self.fail("CMakeLists.txt doesn't test all available groups:\n" + diff)


class Proto:
    """Data for a protocol."""
    def __init__(self, line):
        data = line.split("\t")
        assert len(data) == 3, "expected 3 columns in %s" % data
        assert data[0] == "P"
        self.name = data[1]
        self.abbrev = data[2]

class Field:
    """Data for a field."""
    def __init__(self, line):
        data = line.split("\t")
        assert len(data) == 8, "expected 8 columns in %s" % data
        assert data[0] == "F"
        self.name = data[1]
        self.abbrev = data[2]
        self.ftype = data[3]
        self.parent = data[4]
        self.base = data[5]
        self.bitmask = int(data[6],0)
        self.blurb = data[7]

class case_unit_ftsanity(subprocesstest.SubprocessTestCase):
    def test_unit_ftsanity(self):
        """Looks for problems in field type definitions."""
        tshark_proc = self.assertRun((config.cmd_tshark, "-G", "fields"))

        lines = tshark_proc.stdout_str.splitlines()
        # XXX We don't currently check protos.
        protos = [Proto(x) for x in lines if x[0] == "P"]
        fields = [Field(x) for x in lines if x[0] == "F"]

        err_list = []
        for field in fields:
            if field.bitmask != 0:
                if field.ftype.find("FT_UINT") != 0 and \
                        field.ftype.find("FT_INT") != 0 and \
                        field.ftype != "FT_BOOLEAN" and \
                        field.ftype != "FT_CHAR":
                    err_list.append("%s has a bitmask 0x%x but is type %s" % \
                            (field.abbrev, field.bitmask, field.ftype))

        self.assertEqual(len(err_list), 0, 'Found field type errors: \n' + '\n'.join(err_list))
