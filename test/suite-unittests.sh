#!/bin/bash
#
# Run the epan unit tests
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
		DUT=../wireshark-gtk2/`basename $DUT`
	fi

	$DUT > testout.txt 2>&1
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
	DUT=../epan/exntest
	unittests_step_test
}

unittests_step_reassemble_test() {
	DUT=../epan/reassemble_test
	unittests_step_test
}

unittests_step_tvbtest() {
	DUT=../epan/tvbtest
	unittests_step_test
}

unittests_cleanup_step() {
	rm -f ./testout.txt
}

unittests_suite() {
	test_step_set_pre unittests_cleanup_step
	test_step_set_post unittests_cleanup_step
	test_step_add "exntest" unittests_step_exntest
	test_step_add "reassemble_test" unittests_step_reassemble_test
	test_step_add "tvbtest" unittests_step_tvbtest
}
