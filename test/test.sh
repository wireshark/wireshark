#!/bin/bash
#
# Test various command line testable aspects of the Ethereal tools
#
# $Id$
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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

# an existing capture file
CAPFILE=./dhcp.pcap


source test-backend.sh

source config.sh
source suite-clopts.sh
source suite-io.sh
source suite-capture.sh


#check prerequisites
test_step_prerequisites() {

	NOTFOUND=0
	for i in "$ETHEREAL" "$TETHEREAL" "$CAPINFOS" "$DUMPCAP" ; do
		if [ ! -x $i ]; then
			echo "Couldn't find $i"
			NOTFOUND=1
		fi
	done 
	if [ $NOTFOUND -eq 1 ]; then
		test_step_failed "Tool not found"
		exit 1
	else
		test_step_ok
	fi
}


prerequisites_suite() {
	test_step_add "Prerequisites settings" test_step_prerequisites
}

test_suite() {
	test_suite_add "Prerequisites" prerequisites_suite
	test_suite_add "Command line options" clopt_suite
	test_suite_add "File I/O" io_suite
	test_suite_add "Capture" capture_suite
}


#test_set_output OFF # doesn't work
#test_set_output DOTTED
test_set_output VERBOSE


#test_suite_run "Tethereal command line options" clopt_suite
#test_suite_run "Tethereal capture" capture_suite


# all
#test_suite_run "All" test_suite
#test_suite_show "All" test_suite

MENU_LEVEL=0

menu_title[0]="All"
menu_function[0]=test_suite

echo "----------------------------------------------------------------------"

for ((a=0; a <= 100000000000 ; a++)) 
do
	TEST_STEPS[0]=0			# number of steps of a specific nesting level
	
	#echo $current_title $current_function
	test_suite_show "${menu_title[MENU_LEVEL]}" "${menu_function[MENU_LEVEL]}"
	echo "1-$TEST_STEPS  : Select item"
	echo "Enter: Test All"
	if [[ ! $MENU_LEVEL -eq 0 ]]; then
		echo "U    : Up"
	fi
	echo "Q    : Quit"
	echo ""
	read -n1 key
	newl=$'\x0d'
	echo "$newl----------------------------------------------------------------------"

	TEST_STEPS[0]=0			# number of steps of a specific nesting level

	#echo $key
	case "$key" in
		"Q" | "q")
		exit 0
	;;
		"T" | "t" | "")
LIMIT=1
for ((a=1; a <= LIMIT ; a++))  # Double parentheses, and "LIMIT" with no "$".
do
		test_suite_run "${menu_title[MENU_LEVEL]}" "${menu_function[MENU_LEVEL]}"
done
		echo "----------------------------------------------------------------------"
	;;
		"U" | "u")
		if [[ ! $MENU_LEVEL -eq 0 ]]; then
			let "MENU_LEVEL -= 1"
			#echo "----------------------------------------------------------------------"
		fi
	;;
		"1")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[1]}
		menu_function[MENU_LEVEL]=${test_function[1]}
	;;
		"2")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[2]}
		menu_function[MENU_LEVEL]=${test_function[2]}
	;;
		"3")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[3]}
		menu_function[MENU_LEVEL]=${test_function[3]}
	;;
		"4")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[4]}
		menu_function[MENU_LEVEL]=${test_function[4]}
	;;
		"5")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[5]}
		menu_function[MENU_LEVEL]=${test_function[5]}
	;;
		"6")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[6]}
		menu_function[MENU_LEVEL]=${test_function[6]}
	;;
		"7")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[7]}
		menu_function[MENU_LEVEL]=${test_function[7]}
	;;
		"8")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[8]}
		menu_function[MENU_LEVEL]=${test_function[8]}
	;;
		"9")
		let "MENU_LEVEL += 1"
		menu_title[MENU_LEVEL]=${test_title[9]}
		menu_function[MENU_LEVEL]=${test_function[9]}
	;;

	esac
done