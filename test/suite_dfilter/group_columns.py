# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *

class TestDfilterColumns:
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "_ws.col.info"
        checkDFilterCount(dfilter, 1)

    def test_exists_2(self, checkDFilterFail):
        # Column not in the default configuration
        dfilter = "_ws.col.expert"
        error = f'"{dfilter}" is not a valid protocol or protocol field'
        checkDFilterFail(dfilter, error)

    def test_exists_3(self, checkDFilterFail):
        # Column not registered as field (it behaves unusally if filtered)
        dfilter = "_ws.col.delta_time_dis"
        error = f'"{dfilter}" is not a valid protocol or protocol field'
        checkDFilterFail(dfilter, error)

    def test_func_1(self, checkDFilterCount):
        dfilter = "len(_ws.col.protocol) == 4"
        checkDFilterCount(dfilter, 1)

    def test_matches_1(self, checkDFilterSucceed):
        dfilter = '_ws.col.info matches "^HEAD"'
        checkDFilterSucceed(dfilter)

    def test_equal_1(self, checkDFilterCount):
        dfilter = '_ws.col.protocol == "HTTP"'
        checkDFilterCount(dfilter, 1)

    def test_equal_2(self, checkDFilterCount):
        dfilter = '_ws.col.def_dst == "207.46.134.94"'
        checkDFilterCount(dfilter, 1)

    def test_not_equal_1(self, checkDFilterCount):
        dfilter = '_ws.col.def_src != "10.0.0.5"'
        checkDFilterCount(dfilter, 0)

    def test_read_filter(self, checkDFilterCountReadFilter):
        dfilter = '_ws.col.protocol == "HTTP"'
        checkDFilterCountReadFilter(dfilter, 1)

 #   def test_add_column(self, checkDFilterCount):
        # Add column to configuration
 #       dfilter = '_ws.col.expert == "Chat"'
 #       checkDFilterCount(dfilter, 1, 'gui.column.format:"Expert","%a"')
