#!/bin/bash
#
# Run the epan unit tests
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

unittests_step_test() {
	$DUT $ARGS > testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi
	test_step_ok
}

TOOL_SEARCH_PATHS="
	$WS_BIN_PATH
	$WS_BIN_PATH/epan
	$SOURCE_DIR/epan
	$WS_BIN_PATH/epan/wmem
	$SOURCE_DIR/epan/wmem
	$WS_BIN_PATH/tools
	$SOURCE_DIR/tools
"

check_dut() {
	TEST_EXE=""
	# WS_BIN_PATH must be checked first, otherwise
	# we'll find a non-functional program in epan or epan/wmem.
	for TEST_PATH in $TOOL_SEARCH_PATHS ; do
		if [ -x "$TEST_PATH/$1" ]; then
			TEST_EXE=$TEST_PATH/$1
			break
		fi
	done

	if [ -n "$TEST_EXE" ]; then
		if [[ "$WS_SYSTEM" == "Windows" && "$TEST_EXE" == *.py ]] ; then
			SCRIPT_PATH=$( cygpath -w "$TEST_EXE" )
			TSHARK_PATH=$( cygpath -w "$TSHARK" )
			DUT="python $SCRIPT_PATH"
		else
			TSHARK_PATH="$TSHARK"
			DUT=$TEST_EXE
		fi
	else
		test_step_failed "$1 not found. Have you built test-programs?"
		return 1
	fi
}

unittests_step_exntest() {
	check_dut exntest || return
	ARGS=
	unittests_step_test
}

unittests_step_oids_test() {
	check_dut oids_test || return
	ARGS=
	unittests_step_test
}

unittests_step_reassemble_test() {
	check_dut reassemble_test || return
	ARGS=
	unittests_step_test
}

unittests_step_tvbtest() {
	check_dut tvbtest || return
	ARGS=
	unittests_step_test
}

unittests_step_wmem_test() {
	check_dut wmem_test || return
	ARGS=--verbose
	unittests_step_test
}

unittests_step_ftsanity() {
	check_dut ftsanity.py || return
	ARGS=$TSHARK_PATH
	unittests_step_test
}

unittests_step_fieldcount() {
	check_dut tshark || return
	ARGS="-G fieldcount"
	unittests_step_test
}

unittests_cleanup_step() {
	rm -f ./testout.txt
}

unittests_suite() {
	test_step_set_pre unittests_cleanup_step
	test_step_set_post unittests_cleanup_step
	test_step_add "exntest" unittests_step_exntest
	test_step_add "oids_test" unittests_step_oids_test
	test_step_add "reassemble_test" unittests_step_reassemble_test
	test_step_add "tvbtest" unittests_step_tvbtest
	test_step_add "wmem_test" unittests_step_wmem_test
	test_step_add "ftsanity.py" unittests_step_ftsanity
	test_step_add "field count" unittests_step_fieldcount
}
#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# sh-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
