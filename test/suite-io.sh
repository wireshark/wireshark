#!/bin/bash
#
# Test the file I/O of the Wireshark tools
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


# input of file
io_step_input_file() {
	$DUT -r dhcp.pcap -w ./testout.pcap > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		# part of the Prerequisite checks
		# probably wrong interface, output the possible interfaces
		$TSHARK -D
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi
	
	# ok, we got a capture file, does it contain exactly 10 packets?
	$CAPINFOS ./testout.pcap > ./testout.txt
	grep -i 'Number of packets: 4' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		# part of the Prerequisite checks
		# probably wrong interface, output the possible interfaces
		$TSHARK -D
		test_step_failed "No or not enough traffic captured. Probably the wrong interface: $TRAFFIC_CAPTURE_IFACE!"
	fi
}

# piping input file to stdout using "-w -" 
io_step_output_piping() {
	$DUT -r dhcp.pcap -w - > ./testout.pcap 2>./testout.txt
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		$TSHARK -D
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi
	
	# ok, we got a capture file, does it contain exactly 10 packets?
	$CAPINFOS ./testout.pcap > ./testout2.txt 2>&1
	grep -i 'Number of packets: 4' ./testout2.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		cat ./testout2.txt
		$TSHARK -D
		test_step_failed "No or not enough traffic captured. Probably the wrong interface: $TRAFFIC_CAPTURE_IFACE!"
	fi
}

# piping input file to stdout using "-w -" 
io_step_input_piping() {
	cat -B dhcp.pcap | $DUT -r - -w ./testout.pcap 2>./testout.txt
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		$TSHARK -D
		echo
		cat ./testout.txt
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi
	
	# ok, we got a capture file, does it contain exactly 10 packets?
	$CAPINFOS ./testout.pcap > ./testout2.txt 2>&1
	grep -i 'Number of packets: 4' ./testout2.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		cat ./testout2.txt
		$TSHARK -D
		test_step_failed "No or not enough traffic captured. Probably the wrong interface: $TRAFFIC_CAPTURE_IFACE!"
	fi
}

ethereal_io_suite() {
	# Q: quit after cap, k: start capture immediately
	DUT="$ETHEREAL"
	test_step_add "Input file" io_step_input_file
}

tshark_io_suite() {
	DUT=$TSHARK
	test_step_add "Input file" io_step_input_file
	test_step_add "Output piping" io_step_output_piping
	#test_step_add "Piping" io_step_input_piping
}

dumpcap_io_suite() {
	#DUT="$DUMPCAP -Q"
	DUT=$DUMPCAP
	
	test_step_add "Input file" io_step_input_file
}

io_cleanup_step() {
	rm -f ./testout.txt
	rm -f ./testout2.txt
	rm -f ./testout.pcap
	rm -f ./testout2.pcap
}

io_suite() {
	test_step_set_pre io_cleanup_step
	test_step_set_post io_cleanup_step
	test_suite_add "TShark file I/O" tshark_io_suite
	#test_suite_add "Ethereal file I/O" ethereal_io_suite
	#test_suite_add "Dumpcap file I/O" dumpcap_io_suite
}
