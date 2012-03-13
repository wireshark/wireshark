#!/bin/bash
#
# Test file format conversions of the Wireshark tools
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

TS_ARGS="-Tfields -e frame.number -e frame.time_epoch -e frame.time_delta"

FF_BASELINE=./ff-ts-usec-pcap-direct.txt
DIFF_OUT=./diff-output.txt

# Microsecond pcap / stdin
ff_step_usec_pcap_stdin() {
	$TSHARK $TS_ARGS -i - < dhcp.pcap > ./ff-ts-usec-pcap-stdin.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-usec-pcap-stdin.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs microsecond pcap via stdin differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

# Nanosecond pcap / stdin
ff_step_nsec_pcap_stdin() {
	$TSHARK $TS_ARGS -i - < dhcp-nanosecond.pcap > ./ff-ts-nsec-pcap-stdin.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-nsec-pcap-stdin.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs nanosecond pcap via stdin differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

# Nanosecond pcap / direct
ff_step_nsec_pcap_direct() {
	$TSHARK $TS_ARGS -r dhcp-nanosecond.pcap > ./ff-ts-nsec-pcap-direct.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-nsec-pcap-direct.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs nanosecond pcap direct read differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

# Microsecond pcap-ng / stdin
ff_step_usec_pcapng_stdin() {
	$TSHARK $TS_ARGS -i - < dhcp.pcapng > ./ff-ts-usec-pcapng-stdin.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-usec-pcapng-stdin.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs microsecond pcap-ng via stdin differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

# Microsecond pcap-ng / direct
ff_step_usec_pcapng_direct() {
	$TSHARK $TS_ARGS -r dhcp.pcapng > ./ff-ts-usec-pcapng-direct.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-usec-pcapng-direct.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs microsecond pcap-ng direct read differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

# Nanosecond pcap-ng / stdin
ff_step_nsec_pcapng_stdin() {
	$TSHARK $TS_ARGS -i - < dhcp-nanosecond.pcapng > ./ff-ts-nsec-pcapng-stdin.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-nsec-pcapng-stdin.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs nanosecond pcap-ng via stdin differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

# Nanosecond pcap-ng / direct
ff_step_nsec_pcapng_direct() {
	$TSHARK $TS_ARGS -r dhcp-nanosecond.pcapng > ./ff-ts-nsec-pcapng-direct.txt 2> /dev/null
	diff -u $FF_BASELINE ./ff-ts-nsec-pcapng-direct.txt > $DIFF_OUT 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Output of microsecond pcap direct read vs nanosecond pcap-ng direct read differ"
		cat $DIFF_OUT
		return
	fi
	test_step_ok
}

tshark_ff_suite() {
	# Microsecond pcap direct read is used as the baseline.
	test_step_add "Microsecond pcap via stdin" ff_step_usec_pcap_stdin
	test_step_add "Nanosecond pcap via stdin" ff_step_nsec_pcap_stdin
	test_step_add "Nanosecond pcap direct read" ff_step_nsec_pcap_direct
#	test_step_add "Microsecond pcap-ng via stdin" ff_step_usec_pcapng_stdin
	test_step_add "Microsecond pcap-ng direct read" ff_step_usec_pcapng_direct
#	test_step_add "Nanosecond pcap-ng via stdin" ff_step_nsec_pcapng_stdin
	test_step_add "Nanosecond pcap-ng direct read" ff_step_nsec_pcapng_direct
}

ff_cleanup_step() {
	rm -f ./ff-ts-*.txt
	rm -f $DIFF_OUT
}

ff_prep_step() {
	ff_cleanup_step
	$TSHARK $TS_ARGS -r dhcp.pcap > $FF_BASELINE 2> /dev/null
}

fileformats_suite() {
	test_step_set_pre ff_prep_step
	test_step_set_post ff_cleanup_step
	test_suite_add "TShark file format conversion" tshark_ff_suite
	#test_suite_add "Wireshark file format" wireshark_ff_suite
	#test_suite_add "Editcap file format" editcap_ff_suite
}
