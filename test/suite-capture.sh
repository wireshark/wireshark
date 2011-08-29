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
# along with this program; if not, writeto the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#


# common exit status values
EXIT_OK=0
EXIT_COMMAND_LINE=1
EXIT_ERROR=2

capture_test_output_print() {
	wait
	for f in "$@"; do
		if [[ -f "$f" ]]; then
		printf " --> $f\n"
		cat "$f"
                printf "\n"
		fi
	done
}

traffic_gen_ping() {
	# Generate some traffic for quiet networks.
	# This will have to be adjusted for non-Windows systems.

	# the following will run in the background and return immediately
	{
	date
	for (( x=28; x<=58; x++ )) # in effect: number the packets
	do
		# How does ping _not_ have a standard set of arguments?
		case $WS_SYSTEM in
			Windows)
				ping -n 1 -l $x www.wireshark.org	;;
			SunOS)
				/usr/sbin/ping www.wireshark.org $x 1		;;
			*) # *BSD, Linux
				ping -c 1 -s $x www.wireshark.org	;;
		esac
		sleep 1
	done
	date
	} > ./testout_ping.txt 2>&1 &
}

ping_cleanup() {
	wait
	rm -f ./testout_ping.txt
}

# capture exactly 10 packets
capture_step_10packets() {
	if [ $SKIP_CAPTURE -ne 0 ] ; then
		test_step_skipped
		return
	fi

	traffic_gen_ping

	date > ./testout.txt
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC \
		-w ./testout.pcap \
		-c 10  \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		-f icmp \
		>> ./testout.txt 2>&1
	RETURNVALUE=$?
	date >> ./testout.txt
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		capture_test_output_print ./testout.txt
		# part of the Prerequisite checks
		# wrong interface ? output the possible interfaces
		$TSHARK -D
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		capture_test_output_print ./testout.txt
		test_step_failed "No output file!"
		return
	fi

	# ok, we got a capture file, does it contain exactly 10 packets?
	$CAPINFOS ./testout.pcap > ./testout2.txt
	grep -Ei 'Number of packets:[[:blank:]]+10' ./testout2.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
                $TSHARK -ta -r ./testout.pcap >> ./testout2.txt
		capture_test_output_print ./testout_ping.txt ./testout.txt ./testout2.txt
		# part of the Prerequisite checks
		# probably wrong interface, output the possible interfaces
		$TSHARK -D
		test_step_failed "No or not enough traffic captured. Probably the wrong interface: $TRAFFIC_CAPTURE_IFACE!"
	fi
}

# capture exactly 10 packets using "-w -" (piping to stdout)
capture_step_10packets_stdout() {
        if [ $SKIP_CAPTURE -ne 0 ] ; then
                test_step_skipped
                return
        fi

	traffic_gen_ping

	date > ./testout.txt
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC \
		-c 10 \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		-w - \
		-f icmp \
		> ./testout.pcap 2>>./testout.txt
	RETURNVALUE=$?
	date >> ./testout.txt
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		capture_test_output_print ./testout.txt
		$TSHARK -D
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
	grep -Ei 'Number of packets:[[:blank:]]+10' ./testout2.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		capture_test_output_print ./testout.txt ./testout2.txt
		$TSHARK -D
		test_step_failed "No or not enough traffic captured. Probably the wrong interface: $TRAFFIC_CAPTURE_IFACE!"
	fi
}

# capture packets via a fifo
capture_step_fifo() {
	mkfifo 'fifo'
	(cat $CAPFILE; sleep 1; tail -c +25 $CAPFILE) > fifo &
	$DUT -i fifo $TRAFFIC_CAPTURE_PROMISC \
		-w ./testout.pcap \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		> ./testout.txt 2>&1
	RETURNVALUE=$?
	rm 'fifo'
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		capture_test_output_print ./testout.txt
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi

	# ok, we got a capture file, does it contain exactly 8 packets?
	$CAPINFOS ./testout.pcap > ./testout.txt
	grep -Ei 'Number of packets:[[:blank:]]+8' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		capture_test_output_print ./testout.txt
		test_step_failed "No or not enough traffic captured."
	fi
}

# capture packets via a fifo
capture_step_stdin() {
	(cat $CAPFILE; sleep 1; tail -c +25 $CAPFILE) | \
	$DUT -i - $TRAFFIC_CAPTURE_PROMISC \
		-w ./testout.pcap \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		> ./testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		capture_test_output_print ./testout.txt ./dumpcap_debug_log.tmp
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi

	# ok, we got a capture file, does it contain exactly 8 packets?
	$CAPINFOS ./testout.pcap > ./testout.txt
	grep -Ei 'Number of packets:[[:blank:]]+8' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		capture_test_output_print ./testout.txt
		test_step_failed "No or not enough traffic captured."
	fi
}

# capture exactly 2 times 10 packets (multiple files)
capture_step_2multi_10packets() {
        if [ $SKIP_CAPTURE -ne 0 ] ; then
                test_step_skipped
                return
        fi

	traffic_gen_ping

	date > ./testout.txt
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC \
		-w ./testout.pcap \
		-c 10 \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		-f icmp \
		>> ./testout.txt 2>&1

	RETURNVALUE=$?
	date >> ./testout.txt
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		capture_test_output_print ./testout.txt
		# part of the Prerequisite checks
		# probably wrong interface, output the possible interfaces
		$TSHARK -D
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi

	# we should have an output file now
	if [ ! -f "./testout.pcap" ]; then
		test_step_failed "No output file!"
		return
	fi

	# ok, we got a capture file, does it contain exactly 10 packets?
	$CAPINFOS ./testout.pcap > ./testout.txt
	grep -Ei 'Number of packets:[[:blank:]]+10' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		capture_test_output_print ./testout.txt
		test_step_failed "Probably the wrong interface (no traffic captured)!"
	fi
}

# capture with a very unlikely read filter, packets must be zero afterwards
capture_step_read_filter() {
        if [ $SKIP_CAPTURE -ne 0 ] ; then
                test_step_skipped
                return
        fi

	traffic_gen_ping

	# valid, but very unlikely filter
	date > ./testout.txt
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC \
		-w ./testout.pcap \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		-R 'dcerpc.cn_call_id==123456' \
		-c 10 \
		-f icmp \
		>> ./testout.txt 2>&1
	RETURNVALUE=$?
	date >> ./testout.txt
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		capture_test_output_print ./testout.txt
		# part of the Prerequisite checks
		# wrong interface ? output the possible interfaces
		$TSHARK -D
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
	grep -Ei 'Number of packets:[[:blank:]]+0' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		capture_test_output_print ./testout.txt
		test_step_failed "Capture file should contain zero packets!"
	fi
}


# capture with a snapshot length
capture_step_snapshot() {
        if [ $SKIP_CAPTURE -ne 0 ] ; then
                test_step_skipped
                return
        fi

	traffic_gen_ping

	# capture with a snapshot length of 68 bytes for $TRAFFIC_CAPTURE_DURATION seconds
	# this should result in no packets greater than 68 bytes
	date > ./testout.txt
	$DUT -i $TRAFFIC_CAPTURE_IFACE $TRAFFIC_CAPTURE_PROMISC \
		-w ./testout.pcap \
		-s 68 \
		-a duration:$TRAFFIC_CAPTURE_DURATION \
		-f icmp \
		>> ./testout.txt 2>&1
	RETURNVALUE=$?
	date >> ./testout.txt
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		capture_test_output_print ./testout.txt
		# part of the Prerequisite checks
		# wrong interface ? output the possible interfaces
		$TSHARK -D
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
	if [ $? -ne 0 ]; then
		echo
		capture_test_output_print ./testout.txt
		test_step_failed "Problem running TShark!"
		return
	fi

	# ok, we got a capture file, does it contain exactly 0 packets?
	$CAPINFOS ./testout2.pcap > ./testout.txt
	grep -Ei 'Number of packets:[[:blank:]]+0' ./testout.txt > /dev/null
	if [ $? -eq 0 ]; then
		test_step_ok
	else
		echo
		capture_test_output_print ./testout.txt
		test_step_failed "Capture file should contain zero packets!"
		return
	fi
}

wireshark_capture_suite() {
	# k: start capture immediately
	# WIRESHARK_QUIT_AFTER_CAPTURE needs to be set.
	DUT="$WIRESHARK -k"
	test_step_add "Capture 10 packets" capture_step_10packets
	# piping to stdout doesn't work with Wireshark and capturing!
	#test_step_add "Capture 10 packets using stdout: -w -" capture_step_10packets_stdout
	if [ $TEST_FIFO ]; then
		test_step_add "Capture via fifo" capture_step_fifo
	fi
	test_step_add "Capture via stdin" capture_step_stdin
	# read filter doesn't work with Wireshark and capturing!
	#test_step_add "Capture read filter (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_read_filter
	test_step_add "Capture snapshot length 68 bytes (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_snapshot
}

tshark_capture_suite() {
	DUT=$TSHARK
	test_step_add "Capture 10 packets" capture_step_10packets
	test_step_add "Capture 10 packets using stdout: -w -" capture_step_10packets_stdout
	if [ $TEST_FIFO ]; then
		test_step_add "Capture via fifo" capture_step_fifo
	fi
	test_step_add "Capture via stdin" capture_step_stdin
	# tshark now using dumpcap for capturing, read filters won't work by definition
	#test_step_add "Capture read filter (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_read_filter
	test_step_add "Capture snapshot length 68 bytes (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_snapshot
}

dumpcap_capture_suite() {
	#DUT="$DUMPCAP -Q"
	DUT=$DUMPCAP
	test_step_add "Capture 10 packets" capture_step_10packets
	test_step_add "Capture 10 packets using stdout: -w -" capture_step_10packets_stdout
	if [ $TEST_FIFO ]; then
		test_step_add "Capture via fifo" capture_step_fifo
	fi
	test_step_add "Capture via stdin" capture_step_stdin
	# read (display) filters intentionally doesn't work with dumpcap!
	#test_step_add "Capture read filter (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_read_filter
	test_step_add "Capture snapshot length 68 bytes (${TRAFFIC_CAPTURE_DURATION}s)" capture_step_snapshot
}

capture_cleanup_step() {
	ping_cleanup
	rm -f ./testout.txt
	rm -f ./testout2.txt
	rm -f ./testout.pcap
	rm -f ./testout2.pcap
}

capture_suite() {
	test_step_set_pre capture_cleanup_step
	test_step_set_post capture_cleanup_step
	test_remark_add "Capture - need some traffic on interface: \"$TRAFFIC_CAPTURE_IFACE\""
	test_suite_add "Dumpcap capture" dumpcap_capture_suite
	test_suite_add "TShark capture" tshark_capture_suite
	test_suite_add "Wireshark capture" wireshark_capture_suite
}
