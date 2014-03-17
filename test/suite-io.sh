#!/bin/bash
#
# Test the file I/O of the Wireshark tools
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

IO_RAWSHARK_DHCP_PCAP_BASELINE="$TESTS_DIR/baseline/io-rawshark-dhcp-pcap.txt"
IO_RAWSHARK_DHCP_PCAP_TESTOUT=./io-rawshark-dhcp-pcap-testout.txt

# input of file
io_step_input_file() {
	$DUT -r "${CAPTURE_DIR}dhcp.pcap" -w ./testout.pcap > ./testout.txt 2>&1
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
	grep -Ei 'Number of packets:[[:blank:]]+4' ./testout.txt > /dev/null
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
	$DUT -r "${CAPTURE_DIR}dhcp.pcap" -w - > ./testout.pcap 2>./testout.txt
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
	grep -Ei 'Number of packets:[[:blank:]]+4' ./testout2.txt > /dev/null
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
	cat -B "${CAPTURE_DIR}dhcp.pcap" | $DUT -r - -w ./testout.pcap 2>./testout.txt
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
	grep -Ei 'Number of packets:[[:blank:]]+4' ./testout2.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		cat ./testout2.txt
		$TSHARK -D
		test_step_failed "No or not enough traffic captsured. Probably the wrong interface: $TRAFFIC_CAPTURE_IFACE!"
	fi
}

# Read a pcap from stdin
io_step_rawshark_pcap_stdin() {
	if [ $ENDIANNESS != "little" ] ; then
		test_step_skipped
		return
	fi
	tail -c +25 "${CAPTURE_DIR}dhcp.pcap" | $RAWSHARK -dencap:1 -R "udp.port==68" -nr - > $IO_RAWSHARK_DHCP_PCAP_TESTOUT 2> /dev/null
	diff -u --strip-trailing-cr $IO_RAWSHARK_DHCP_PCAP_BASELINE $IO_RAWSHARK_DHCP_PCAP_TESTOUT > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of rawshark read pcap via stdin differs from baseline"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}


wireshark_io_suite() {
	# Q: quit after cap, k: start capture immediately
	DUT="$WIRESHARK"
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

rawshark_io_suite() {
	test_step_add "Rawshark pcap stdin" io_step_rawshark_pcap_stdin
}

io_cleanup_step() {
	rm -f ./testout.txt
	rm -f ./testout2.txt
	rm -f ./testout.pcap
	rm -f ./testout2.pcap
	rm -f $IO_RAWSHARK_DHCP_PCAP_TESTOUT
}

io_suite() {
	test_step_set_pre io_cleanup_step
	test_step_set_post io_cleanup_step
	test_suite_add "TShark file I/O" tshark_io_suite
	#test_suite_add "Wireshark file I/O" wireshark_io_suite
	#test_suite_add "Dumpcap file I/O" dumpcap_io_suite
	test_suite_add "Rawshark file I/O" rawshark_io_suite
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
