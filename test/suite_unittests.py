#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''EPAN unit tests'''

import config
import os.path
import subprocesstest
import sys
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

    def test_unit_ftsanity(self):
        '''ftsanity.py'''
        fts_cmd = [
            os.path.join(config.tools_dir, 'ftsanity.py'),
            config.cmd_tshark
        ]
        if sys.executable:
            fts_cmd.insert(0, sys.executable)
        self.assertRun(fts_cmd)

    def test_unit_fieldcount(self):
        '''fieldcount'''
        self.assertRun((config.cmd_tshark, '-G', 'fieldcount'))
