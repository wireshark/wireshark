#
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

import difflib
import os.path
import re
import subprocesstest
import fixtures


@fixtures.uses_fixtures
class case_unittests(subprocesstest.SubprocessTestCase):
    def test_unit_exntest(self, program, base_env):
        '''exntest'''
        self.assertRun(program('exntest'), env=base_env)

    def test_unit_oids_test(self, program, base_env):
        '''oids_test'''
        self.assertRun(program('oids_test'), env=base_env)

    def test_unit_reassemble_test(self, program, base_env):
        '''reassemble_test'''
        self.assertRun(program('reassemble_test'), env=base_env)

    def test_unit_tvbtest(self, program, base_env):
        '''tvbtest'''
        self.assertRun(program('tvbtest'), env=base_env)

    def test_unit_wmem_test(self, program, base_env):
        '''wmem_test'''
        self.assertRun((program('wmem_test'),
            '--verbose'
        ), env=base_env)

    def test_unit_wscbor_test(self, program, base_env):
        '''wscbor_test'''
        self.assertRun(program('wscbor_test'), env=base_env)

    def test_unit_epan(self, program, base_env):
        '''epan unit tests'''
        self.assertRun((program('test_epan'),
            '--verbose'
        ), env=base_env)

    def test_unit_wsutil(self, program, base_env):
        '''wsutil unit tests'''
        self.assertRun((program('test_wsutil'),
            '--verbose'
        ), env=base_env)

    def test_unit_fieldcount(self, cmd_tshark, test_env):
        '''fieldcount'''
        self.assertRun((cmd_tshark, '-G', 'fieldcount'), env=test_env)

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


@fixtures.uses_fixtures
class case_unit_ftsanity(subprocesstest.SubprocessTestCase):
    def test_unit_ftsanity(self, cmd_tshark, base_env):
        """Looks for problems in field type definitions."""
        tshark_proc = self.assertRun((cmd_tshark, "-G", "fields"), env=base_env)

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
