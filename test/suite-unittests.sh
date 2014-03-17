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

if [ "$WS_SYSTEM" == "Windows" ] ; then
	MAKE="nmake -f Makefile.nmake"
else
	MAKE=make
fi

unittests_step_test() {
	( cd `dirname $DUT` && $MAKE `basename $DUT` ) >testout.txt 2>&1
	if [ $? -ne 0 ]; then
		echo
		cat ./testout.txt
		test_step_failed "make $DUT failed"
		return
	fi

	# if we're on windows, we have to copy the test exe to the wireshark-gtk2
	# dir before we can use them.
	# {Note that 'INSTALL_DIR' must be a Windows Pathname)
	if [ "$WS_SYSTEM" == "Windows" ] ; then
		(cd `dirname $DUT` && $MAKE `basename $DUT`_install INSTALL_DIR='wireshark-gtk2\') > testout.txt 2>&1
		if [ $? -ne 0 ]; then
			echo
			cat ./testout.txt
			test_step_failed "install $DUT failed"
			return
		fi
		DUT=$SOURCE_DIR/wireshark-gtk2/`basename $DUT`
	fi

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


unittests_step_exntest() {
	DUT=$SOURCE_DIR/epan/exntest
	ARGS=
	unittests_step_test
}

unittests_step_oids_test() {
	DUT=$SOURCE_DIR/epan/oids_test
	ARGS=
	unittests_step_test
}

unittests_step_reassemble_test() {
	DUT=$SOURCE_DIR/epan/reassemble_test
	ARGS=
	unittests_step_test
}

unittests_step_tvbtest() {
	DUT=$SOURCE_DIR/epan/tvbtest
	ARGS=
	unittests_step_test
}

unittests_step_wmem_test() {
	DUT=$SOURCE_DIR/epan/wmem/wmem_test
	ARGS=--verbose
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
}
#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
