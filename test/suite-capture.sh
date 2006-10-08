#!/bin/bash
#
# Test the capture engine of the Wireshark tools
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


# capture exactly 10 packets
capture_step_10packets() {
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC -w ./testout.pcap -c 10  -a duration:$TRAFFIC_CAPTURE_DURATION > ./testout.txt 2>&1
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
	grep -i 'Number of packets: 10' ./testout.txt > /dev/null
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

# capture exactly 10 packets using "-w -" (piping to stdout)
capture_step_10packets_stdout() {
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC -c 10 -a duration:$TRAFFIC_CAPTURE_DURATION -w - > ./testout.pcap 2>./testout.txt
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
	grep -i 'Number of packets: 10' ./testout2.txt > /dev/null
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

# capture exactly 2 times 10 packets (multiple files)
capture_step_2multi_10packets() {
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC -w ./testout.pcap -c 10  -a duration:$TRAFFIC_CAPTURE_DURATION > ./testout.txt 2>&1
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
	grep -i 'Number of packets: 10' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		test_step_failed "Probably the wrong interface (no traffic captured)!"
	fi
}

# capture with a very unlikely read filter, packets must be zero afterwards
capture_step_read_filter() {
	# valid, but very unlikely filter
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC -w ./testout.pcap -a duration:$TRAFFIC_CAPTURE_DURATION -R 'dcerpc.cn_call_id==123456' -c 10 > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi

	# ok, we got a capture file, does it contain exactly 0 packets?
	$CAPINFOS ./testout.pcap > ./testout.txt
	grep -i 'Number of packets: 0' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		test_step_failed "Capture file should contain zero packets!"
	fi
}


# capture with a snapshot length
capture_step_snapshot() {
	# capture with a snapshot length of 68 bytes for $TRAFFIC_CAPTURE_DURATION seconds
	# this should result in no packets
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC -w ./testout.pcap -s 68 -a duration:$TRAFFIC_CAPTURE_DURATION > ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi

	# use tshark to filter out all packets, which are larger than 68 bytes
	$TSHARK -r ./testout.pcap -w ./testout2.pcap -R 'frame.cap_len>68' > ./testout.txt 2>&1

	# ok, we got a capture file, does it contain exactly 0 packets?
	$CAPINFOS ./testout2.pcap > ./testout.txt
	grep -i 'Number of packets: 0' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		test_step_failed "Capture file should contain zero packets!"
		return
	fi
}

wireshark_capture_suite() {
	# Q: quit after cap, k: start capture immediately
	DUT="$WIRESHARK -Q -k"
	test_step_add "Capture 10 packets" capture_step_10packets
	# piping to stdout doesn't work with Wireshark and capturing!
	#test_step_add "Capture 10 packets using stdout: -w -" capture_step_10packets_stdout
	# read filter doesn't work with Wireshark and capturing!
	#test_step_add "Capture read filter (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_read_filter
	test_step_add "Capture snapshot length 68 bytes (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_snapshot
}

tshark_capture_suite() {
	DUT=$TSHARK
	test_step_add "Capture 10 packets" capture_step_10packets
	test_step_add "Capture 10 packets using stdout: -w -" capture_step_10packets_stdout
	test_step_add "Capture read filter (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_read_filter
	test_step_add "Capture snapshot length 68 bytes (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_snapshot
}

dumpcap_capture_suite() {
	#DUT="$DUMPCAP -Q"
	DUT=$DUMPCAP
	test_step_add "Capture 10 packets" capture_step_10packets
	test_step_add "Capture 10 packets using stdout: -w -" capture_step_10packets_stdout
	# read (display) filters intentionally doesn't work with dumpcap!
	#test_step_add "Capture read filter (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_read_filter
	test_step_add "Capture snapshot length 68 bytes (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_snapshot
}

capture_cleanup_step() {
	rm -f ./testout.txt
	rm -f ./testout2.txt
	rm -f ./testout.pcap
	rm -f ./testout2.pcap
}

capture_suite() {
	test_step_set_pre capture_cleanup_step
	test_step_set_post capture_cleanup_step
	test_remark_add "Capture - need some traffic on interface: \"$TRAFFIC_CAPTURE_IFACE\""
	test_suite_add "TShark capture" tshark_capture_suite
	test_suite_add "Wireshark capture" wireshark_capture_suite
	test_suite_add "Dumpcap capture" dumpcap_capture_suite
}
