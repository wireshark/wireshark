#!/bin/bash
#
# Test the command line options of the Wireshark tools
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2005 Ulf Lamping
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

# common exit status values
EXIT_OK=0
EXIT_COMMAND_LINE=1
EXIT_ERROR=2

# generic: check against a specific exit status with a single char option
# $1 command: tshark or dumpcap
# $2 option: a
# $3 expected exit status: 0
test_single_char_options()
{
	#echo "command: "$1" opt1: "$2" opt2: "$3" opt3: "$4" opt4: "$5" opt5: "$6
	$1 -$2  > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $3 ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
	rm ./testout.txt
}

# dumpcap

# Only with remote capture: A:ru
# Only with WinPcap: m:
# Only with WinPcap or 1.0.0-or-later libpcap: B:
# Only with 1.0.0-or-later libpcap: I
# Only with libpcap/WinPcap with bpf_image(): d

# check exit status of all invalid single char dumpcap options (must be 1)
clopts_suite_dumpcap_invalid_chars() {
	for index in C E F G H J K N O Q R T U V W X Y e j l o x z
	do
	  test_step_add "Invalid dumpcap parameter -$index, exit status must be $EXIT_COMMAND_LINE" "test_single_char_options $DUMPCAP $index $EXIT_COMMAND_LINE"
	done
}

# check exit status of all valid single char dumpcap options being (must be 0)
# tests only those options that cause dumpcap to do something other than
# capture
clopts_suite_dumpcap_valid_chars() {
	for index in h v
	do
	  test_step_add "Valid dumpcap parameter -$index, exit status must be $EXIT_OK" "test_single_char_options $DUMPCAP $index $EXIT_OK"
	done
}

# special case: interface-specific opts should work under Windows and fail as
# a regular user on other systems.
clopts_suite_dumpcap_interface_chars() {
	for index in D L
	do
          if [ "$SKIP_CAPTURE" -eq 0 ] ; then
	    test_step_add "Valid dumpcap parameter -$index, exit status must be $EXIT_OK" "test_single_char_options $DUMPCAP $index $EXIT_OK"
          else
	    test_step_add "Invalid permissions for dumpcap parameter -$index, exit status must be $EXIT_ERROR" "test_single_char_options $DUMPCAP $index $EXIT_ERROR"
          fi
        done
}

# check exit status and grep output string of an invalid capture filter
clopts_step_dumpcap_invalid_capfilter() {
        if [ "$WS_SYSTEM" != "Windows" ] ; then
                test_step_skipped
                return
        fi

	$DUMPCAP -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'Invalid capture filter "jkghg" for interface' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_output_print ./testout.txt
			test_step_ok
		else
			test_step_output_print ./testout.txt
			test_step_failed "Error message wasn't what we expected"
		fi
	fi
}

# check exit status and grep output string of an invalid interface
clopts_step_dumpcap_invalid_interfaces() {
	$DUMPCAP -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'The capture session could not be initiated' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_output_print ./testout.txt
			test_step_ok
		else
			test_step_output_print ./testout.txt
			test_step_failed "Error message wasn't what we expected"
		fi
	fi
}

# check exit status and grep output string of an invalid interface index
# (valid interface indexes start with 1)
clopts_step_dumpcap_invalid_interfaces_index() {
	$DUMPCAP -i 0 -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'There is no interface with that adapter index' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_ok
		else
			test_step_output_print ./testout.txt
			test_step_failed "Error message wasn't what we expected"
		fi
	fi
}

# TShark

# check exit status when reading an existing file
clopts_step_existing_file() {
	$TSHARK -r "${CAPTURE_DIR}dhcp.pcap" > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
	rm ./testout.txt
}


# check exit status when reading a non-existing file
clopts_step_nonexisting_file() {
	$TSHARK -r ThisFileDontExist.pcap  > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_ERROR ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
	rm  ./testout.txt
}


# check exit status of all invalid single char TShark options (must be 1)
clopts_suite_tshark_invalid_chars() {
	for index in A B C E F H J K M N O Q R T U W X Y Z a b c d e f i j k m o r s t u w y z
	do
	  test_step_add "Invalid TShark parameter -$index, exit status must be $EXIT_COMMAND_LINE" "test_single_char_options $TSHARK $index $EXIT_COMMAND_LINE"
	done
}


# check exit status of all valid single char TShark options being (must be 0)
clopts_suite_tshark_valid_chars() {
	for index in G h v
	do
	  test_step_add "Valid TShark parameter -$index, exit status must be $EXIT_OK" "test_single_char_options $TSHARK $index $EXIT_OK"
	done
}

# special case: interface-specific opts should work under Windows and fail as
# a regular user on other systems.
clopts_suite_tshark_interface_chars() {
	for index in D L
	do
          if [ "$SKIP_CAPTURE" -eq 0 ] ; then
	    test_step_add "Valid TShark parameter -$index, exit status must be $EXIT_OK" "test_single_char_options $TSHARK $index $EXIT_OK"
          else
	    test_step_add "Invalid permissions for TShark parameter -$index, exit status must be $EXIT_ERROR" "test_single_char_options $TSHARK $index $EXIT_ERROR"
          fi
        done
}

# S V l n p q x

# check exit status and grep output string of an invalid capture filter
clopts_step_tshark_invalid_capfilter() {
        if [ "$WS_SYSTEM" != "Windows" ] ; then
                test_step_skipped
                return
        fi

	$TSHARK -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'Invalid capture filter "jkghg" for interface' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_output_print ./testout.txt
			test_step_ok
		else
			test_step_output_print ./testout.txt
			test_step_failed "Error message wasn't what we expected"
		fi
	fi
}

# check exit status and grep output string of an invalid interface
clopts_step_tshark_invalid_interfaces() {
	$TSHARK -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'The capture session could not be initiated' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_output_print ./testout.txt
			test_step_ok
		else
			test_step_output_print ./testout.txt
			test_step_failed "Error message wasn't what we expected"
		fi
	fi
}

# check exit status and grep output string of an invalid interface index
# (valid interface indexes start with 1)
clopts_step_tshark_invalid_interfaces_index() {
	$TSHARK -i 0 -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'There is no interface with that adapter index' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_ok
		else
			test_step_output_print ./testout.txt
			test_step_failed "Error message wasn't what we expected"
		fi
	fi
}

# check exit status and grep output string of an invalid capture filter
# XXX - how to efficiently test the *invalid* flags?
clopts_step_valid_name_resolving() {
        if [ "$WS_SYSTEM" != "Windows" ] ; then
                test_step_skipped
                return
        fi

	$TSHARK -N mntC -a duration:1 > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
}

# check exit status of some basic functions
clopts_suite_basic() {
	test_step_add "Exit status for existing file: \"""${CAPTURE_DIR}dhcp.pcap""\" must be 0" clopts_step_existing_file
	test_step_add "Exit status for none existing files must be 2" clopts_step_nonexisting_file
}

clopts_suite_dumpcap_capture_options() {
	test_step_add  "Invalid dumpcap capture filter -f" clopts_step_dumpcap_invalid_capfilter
	test_step_add  "Invalid dumpcap capture interface -i" clopts_step_dumpcap_invalid_interfaces
	test_step_add  "Invalid dumpcap capture interface index 0" clopts_step_dumpcap_invalid_interfaces_index
}

clopts_suite_tshark_capture_options() {
	test_step_add  "Invalid TShark capture filter -f" clopts_step_tshark_invalid_capfilter
	test_step_add  "Invalid TShark capture interface -i" clopts_step_tshark_invalid_interfaces
	test_step_add  "Invalid TShark capture interface index 0" clopts_step_tshark_invalid_interfaces_index
}

clopts_post_step() {
	rm -f ./testout.txt ./testout2.txt
}

clopt_suite() {
	test_step_set_post clopts_post_step
	test_suite_add "Basic tests" clopts_suite_basic
	test_suite_add "Invalid dumpcap single char options" clopts_suite_dumpcap_invalid_chars
	test_suite_add "Valid dumpcap single char options" clopts_suite_dumpcap_valid_chars
	test_suite_add "Interface-specific dumpcap single char options" clopts_suite_dumpcap_interface_chars
	test_suite_add "Capture filter/interface options tests" clopts_suite_dumpcap_capture_options
	test_suite_add "Invalid TShark single char options" clopts_suite_tshark_invalid_chars
	test_suite_add "Valid TShark single char options" clopts_suite_tshark_valid_chars
	test_suite_add "Interface-specific TShark single char options" clopts_suite_tshark_interface_chars
	test_suite_add "Capture filter/interface options tests" clopts_suite_tshark_capture_options
	test_step_add  "Valid name resolution options -N (1s)" clopts_step_valid_name_resolving
	#test_remark_add "Undocumented command line option: G"
	#test_remark_add "Options currently unchecked: S, V, l, n, p, q and x"
}

## Emacs
## Local Variables:
## tab-width: 8
## indent-tabs-mode: t
## sh-basic-offset: 8
## End:
