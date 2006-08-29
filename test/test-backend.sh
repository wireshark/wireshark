#!/bin/bash
#
# Test backend
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


# References:
# http://www.gnu.org/software/bash/manual/bashref.html "Bash Reference Manual"
# http://www.tldp.org/LDP/abs/html/ "Advanced Bash-Scripting Guide"
# http://www.tldp.org/LDP/abs/html/colorizing.html "Colorizing" Scripts"
# http://www.junit.org/junit/javadoc/3.8.1/index.htm "JUnit javadoc"

# check undefined variables
# http://www.tldp.org/LDP/abs/html/options.html
# bash -u test.sh


# coloring the output
color_reset="tput sgr0"
color_green='\E[32;40m'
color_red='\E[31;40m'
color_blue='\E[36;40m'

# runtime flags
TEST_RUN="OFF"
TEST_OUTPUT="VERBOSE"	# "OFF", "DOTTED", "VERBOSE"

# runtime vars
TEST_NESTING_LEVEL=0	# nesting level of current test
TEST_STEPS[0]=0			# number of steps of a specific nesting level

# output counters
TEST_OK=0				# global count of succeeded steps
TEST_FAILED=0			# global count of failed steps

TEST_STEP_PRE_CB=
TEST_STEP_POST_CB=

# level number of this test item (suite or step)
test_level() {
	LIMIT_LEVEL=100
	
	for ((a=0; a <= LIMIT_LEVEL ; a++)) 
	do
		if [ ! $a -eq 0 ]; then
			echo -n "."
		fi
		echo -n "${TEST_STEPS[a]}"
		if [ $a -eq $TEST_NESTING_LEVEL ]; then
			#echo "end"
			return
		fi
	done                           
}

# set output format
# $1 - "OUT", "DOTTED", "VERBOSE"
test_set_output() {
	TEST_OUTPUT=$1
}

# run a test suite
# $1 name
# $2 command
test_suite_run() {
	# header
	echo -n -e $color_blue
	echo ""
	echo "### $1 ###"
	$color_reset

	TEST_RUN="ON"

	# run the actual test suite
	$2
	
	# results
	if [ $TEST_RUN = "ON" ]; then
		echo ""
		if [ $TEST_FAILED -eq 0 ]; then
			echo -n -e $color_green
		else
			echo -n -e $color_red
		fi
		echo "### Test suite results ###"
		echo -n -e $color_green
		echo "Ok    : $TEST_OK"
		echo -n -e $color_red
		echo "Failed: $TEST_FAILED"
		$color_reset
	fi

	# exit status
	#if [ $TEST_FAILED -eq 0 ]; then
	#	exit 0
	#else
	#	exit 1
	#fi

	TEST_RUN="OFF"
}


# show a test suite
# $1 name
# $2 command
test_suite_show() {

	# header
	echo -n -e $color_blue
	echo ""
	echo "### Test suite: $1 ###"
	echo ""
	echo "Subitems:"
	echo "---------"
	$color_reset

	# show this test suite subitems
	$2
	
	echo ""
}


# add a test suite
# $1 name
# $2 function
test_suite_add() {
	# increase step counter of this nesting level
	let "TEST_STEPS[$TEST_NESTING_LEVEL] += 1"
	
	if [ $TEST_RUN = "ON" ]; then
		echo ""
	fi
	
	# title output if we'll list the subitems 
	if [[ $TEST_RUN = "ON" ]]; then
		echo -n -e $color_blue
		test_level
		echo "  Suite: $1"
		$color_reset
	fi

	if [[ $TEST_NESTING_LEVEL -eq 0 ]]; then
		pos=${TEST_STEPS[$TEST_NESTING_LEVEL]}
		#echo "pos " $pos
		test_title[$pos]=$1
		test_function[$pos]=$2
		#echo ${test_title[1]}

	fi

	# reset test step counter back to zero
	TEST_STEP=0
	
	# call the suites function
	let "TEST_NESTING_LEVEL += 1"
	TEST_STEPS[$TEST_NESTING_LEVEL]=0
	$2
	let "TEST_NESTING_LEVEL -= 1"

	# title output (with subitem counter) if we don't listed the subitems
	if [[ ! $TEST_RUN = "ON" && $TEST_NESTING_LEVEL -eq 0 ]]; then
		echo -n -e $color_blue
		test_level
		echo "  Suite: $1 (${TEST_STEPS[TEST_NESTING_LEVEL+1]} subitems)"
		$color_reset
	fi	

}


# add a test step
# $1 name
# $2 function
test_step_add() {

	let "TEST_STEPS[$TEST_NESTING_LEVEL] += 1"

	if [[ ($TEST_RUN = "ON" && $TEST_OUTPUT = "DOTTED") && $TEST_NESTING_LEVEL -eq 0 ]]; then
		echo ""
	fi
	
	if [[ ( $TEST_RUN = "ON" && $TEST_OUTPUT = "VERBOSE" ) || $TEST_NESTING_LEVEL -eq 0 ]]; then
		echo -n -e $color_blue
		test_level
		echo -n " Step:" $1
		$color_reset
	fi

	if [ $TEST_RUN = "ON" ]; then		
		# preprecessing step
		$TEST_STEP_PRE_CB
		#echo "command: "$2" opt1: "$3" opt2: "$4" opt3: "$5" opt4: "$6" opt5: "$7
		TEST_STEP_NAME=$1
		# actually run the command to test now
		$2 
		#"$3" "$4" "$5" "$6" "$7"
		# post precessing step
		$TEST_STEP_POST_CB
	else
		if [[ $TEST_NESTING_LEVEL -eq 0 ]]; then
			echo ""
		fi
	fi
}


# set the preprocessing function
# $1 remark
test_step_set_pre() {
	TEST_STEP_PRE_CB=$1
}

# set the post processing function
# $1 remark
test_step_set_post() {
	TEST_STEP_POST_CB=$1
}

# add a test remark
# $1 remark
test_remark_add() {

	# test is running or toplevel item? -> show remark
	if [[ $TEST_RUN = "ON" || $TEST_NESTING_LEVEL -eq 0 ]]; then
		# test is running and output is dotted -> newline first
		if [[ $TEST_RUN = "ON" && $TEST_OUTPUT = "DOTTED" ]]; then
			echo ""
		fi
		
		# remark
		echo -n -e $color_blue
		echo "  Remark: $1"
		$color_reset
	fi
}


# the test step succeeded
test_step_ok() {
	# count appearance
	let "TEST_OK += 1"
	
	# output in green
	echo -n -e $color_green
	
	if [ $TEST_OUTPUT = "VERBOSE" ]; then
		echo " Ok"
	else
		echo -n .
	fi
	
	$color_reset
}

# the test step failed
# $1 output text
test_step_failed() {
	let "TEST_FAILED += 1"
	
	# output in red
	echo -n -e "$color_red"
	
	echo ""
	echo "\"$TEST_STEP_NAME\" Failed!"
	echo $1
	
	$color_reset
	
	exit 1
	
	# XXX - add a mechanism to optionally stop here
}

