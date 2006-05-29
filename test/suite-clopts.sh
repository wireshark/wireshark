#!/bin/bash
#
# Test the command line options of the Ethereal tools
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# 
 
# common exit status values
EXIT_OK=0
EXIT_COMMAND_LINE=1
EXIT_ERROR=2


# generic: check against a specific exit status with a single char option
# $1 command: tethereal
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


# check exit status when reading an existing file
clopts_step_existing_file() {
	$TETHEREAL -r $CAPFILE > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
	rm ./testout.txt
}


# check exit status when reading a none existing file
clopts_step_nonexisting_file() {
	$TETHEREAL -r ThisFileDontExist.pcap  > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_ERROR ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
	rm  ./testout.txt
}


# check exit status of all single char option being invalid
clopts_suite_tethereal_invalid_chars() {
	for index in A B C E F H I J K M N O P Q R T U W X Y Z a b c d e f g i j k m o r s t u w y z
	do
	  test_step_add "Invalid Tethereal parameter -$index, exit status must be $EXIT_COMMAND_LINE" "test_single_char_options $TETHEREAL $index $EXIT_COMMAND_LINE"
	done
}


# check exit status of all single char option being valid
clopts_suite_valid_chars() {
	for index in D G L h v
	do
	  test_step_add "Valid Tethereal parameter -$index, exit status must be $EXIT_OK" "test_single_char_options $TETHEREAL $index $EXIT_OK"
	done
}


# S V l n p q x

# check exit status and grep output string of an invalid capture filter
clopts_step_invalid_capfilter() {
	$TETHEREAL -f 'jkghg' -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'Invalid capture filter: "jkghg"' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_ok
		else
			cat ./testout.txt
			test_step_failed "Infos"
		fi
	fi
}

# check exit status and grep output string of an invalid interface
clopts_step_invalid_interface() {
	$TETHEREAL -i invalid_interface -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'The capture session could not be initiated!' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_ok
		else
			cat ./testout.txt
			test_step_failed "Infos"
		fi
	fi
}

# check exit status and grep output string of an invalid interface index
# (valid interface indexes start with 1)
clopts_step_invalid_interface_index() {
	$TETHEREAL -i 0 -w './testout.pcap' > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_COMMAND_LINE ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		grep -i 'there is no interface with that adapter index' ./testout.txt > /dev/null
		if [ $? -eq 0 ]; then
			test_step_ok
		else
			cat ./testout.txt
			test_step_failed "Infos"
		fi
	fi
}

# check exit status and grep output string of an invalid capture filter
# XXX - how to efficiently test the *invalid* flags?
clopts_step_valid_name_resolving() {
	$TETHEREAL -N mntC -a duration:1 > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
	else
		test_step_ok
	fi
}

# check exit status of some basic functions
clopts_suite_basic() {
	test_step_add "Exit status for existing file: \""$CAPFILE"\" must be 0" clopts_step_existing_file
	test_step_add "Exit status for none existing files must be 2" clopts_step_nonexisting_file
}


clopts_post_step() {
	rm -f ./testout.txt
}

clopt_suite() {
	test_step_set_post clopts_post_step
	test_suite_add "Basic tests" clopts_suite_basic
	test_suite_add "Invalid Tethereal single char options" clopts_suite_tethereal_invalid_chars
	test_suite_add "Valid Tethereal single char options" clopts_suite_valid_chars
	test_step_add  "Invalid capture filter -f" clopts_step_invalid_capfilter
	test_step_add  "Invalid capture interface -i" clopts_step_invalid_interface
	test_step_add  "Invalid capture interface index 0" clopts_step_invalid_interface_index
	test_step_add  "Valid name resolution options -N (1s)" clopts_step_valid_name_resolving
	#test_remark_add "Undocumented command line option: G"
	#test_remark_add "Options currently unchecked: S, V, l, n, p, q and x"
}

