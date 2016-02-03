#!/bin/bash
#
# Run the mergecap unit tests
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# common checking code:
# arg 1 = return value from mergecap command
# arg 2 = file type string
# arg 3 = file encap
# arg 4 = number of IDBs generated
# arg 5 = number of file packets merged
# arg 6 = number of some IDB packets merged
mergecap_common_check() {
	if [ ! $1 -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "exit status of mergecap: $1"
		return
	fi

	grep -q "merging complete" testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		test_step_failed "mergecap didn't complete"
	fi

	$CAPINFOS -tEIc ./testout.pcap > capinfo_testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		cat ./capinfo_testout.txt
		test_step_failed "exit status of capinfos: $RETURNVALUE"
		return
	fi

	grep -Eiq "File type:[[:blank:]]+$2" capinfo_testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		cat ./capinfo_testout.txt
		test_step_failed "mergecap output format was not '$2'"
	fi

	grep -Eiq "File encapsulation:[[:blank:]]+$3" capinfo_testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		cat ./capinfo_testout.txt
		test_step_failed "mergecap output encap type was not '$3'"
	fi

	grep -Eiq "Number of interfaces in file:[[:blank:]]+$4" capinfo_testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		cat ./capinfo_testout.txt
		test_step_failed "mergecap output did not generate only $4 IDB"
	fi

	# this checks the file's number of packets
	grep -Eiq "Number of packets:[[:blank:]]+$5" capinfo_testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		cat ./capinfo_testout.txt
		test_step_failed "mergecap output did not generate $5 packets for file"
	fi

	# this checks the IDB number of packets
	grep -Eiq "Number of packets =[[:blank:]]+$6" capinfo_testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		cat ./capinfo_testout.txt
		test_step_failed "mergecap output did not generate $6 packets in IDB"
	fi
}



# this is a common one for legacy PCAP output
# for this, arg1=returnvalue, arg2=#of file and IDB packets
mergecap_common_pcap_pkt() {
	mergecap_common_check "$1" 'Wireshark/tcpdump/... - pcap' "Ethernet" "1" "$2" "$2"
}

# this is a common one for PCAPNG output
# for this, arg1=returnvalue, arg2=encap type, arg3=#of IDBs, arg4=# of file pkts, arg5=# of IDB pkts
mergecap_common_pcapng_pkt() {
	mergecap_common_check "$1" 'Wireshark/... - pcapng' "$2" "$3" "$4" "$5"
}



mergecap_step_basic_1_pcap_pcap_test() {
	$MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcap_pkt $RETURNVALUE 4
	test_step_ok
}

mergecap_step_basic_2_pcap_pcap_test() {
	$MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcap_pkt $RETURNVALUE 8
	test_step_ok
}

mergecap_step_basic_3_empty_pcap_pcap_test() {
	$MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}empty.pcap" "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}empty.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcap_pkt $RETURNVALUE 4
	test_step_ok
}

mergecap_step_basic_2_nano_pcap_pcap_test() {
	$MERGECAP -vF pcap -w testout.pcap "${CAPTURE_DIR}dhcp-nanosecond.pcap" "${CAPTURE_DIR}rsasnakeoil2.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcap_pkt $RETURNVALUE 62
	test_step_ok
}

mergecap_step_basic_1_pcap_pcapng_test() {
	$MERGECAP -v -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Ethernet" 1 4 4
	test_step_ok
}

mergecap_step_basic_2_pcap_pcapng_test() {
	$MERGECAP -v -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Ethernet" 1 8 8
	test_step_ok
}

mergecap_step_basic_2_pcap_none_pcapng_test() {
	$MERGECAP -vI 'none' -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Ethernet" 2 8 4
	test_step_ok
}

mergecap_step_basic_2_pcap_all_pcapng_test() {
	$MERGECAP -vI 'all' -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Ethernet" 1 8 8
	test_step_ok
}

mergecap_step_basic_2_pcap_any_pcapng_test() {
	$MERGECAP -vI 'any' -w testout.pcap "${CAPTURE_DIR}dhcp.pcap" "${CAPTURE_DIR}dhcp.pcap" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Ethernet" 1 8 8
	test_step_ok
}

mergecap_step_basic_1_pcapng_pcapng_test() {
	$MERGECAP -v -w testout.pcap "${CAPTURE_DIR}dhcp.pcapng" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Ethernet" 1 4 4
	test_step_ok
}

mergecap_step_1_pcapng_many_pcapng_test() {
	$MERGECAP -v -w testout.pcap "${CAPTURE_DIR}many_interfaces.pcapng.1" > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Per packet" 11 64 62
	test_step_ok
}

mergecap_step_3_pcapng_pcapng_test() {
	$MERGECAP -v -w testout.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Per packet" 11 88 86
	test_step_ok
}

mergecap_step_3_pcapng_none_pcapng_test() {
	$MERGECAP -vI 'none' -w testout.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
	RETURNVALUE=$?
	mergecap_common_pcapng_pkt $RETURNVALUE "Per packet" 33 88 62
	test_step_ok
}

mergecap_step_3_pcapng_all_pcapng_test() {
	# build a pcapng of all the interfaces repeated by using mode 'none'
	$MERGECAP -vI 'none' -w testin.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
	# the above generated 33 IDBs, 88 total pkts, 62 in first IDB

	# and use that generated pcap for our test
	$MERGECAP -vI 'all' -w testout.pcap ./testin.pcap ./testin.pcap ./testin.pcap > testout.txt 2>&1
	RETURNVALUE=$?
	# check for 33 IDBs, 88*3=264 total pkts, 62*3=186 in first IDB
	mergecap_common_pcapng_pkt $RETURNVALUE "Per packet" 33 264 186
	test_step_ok
}

mergecap_step_3_pcapng_any_pcapng_test() {
	# build a pcapng of all the interfaces repeated by using mode 'none'
	$MERGECAP -vI 'none' -w testin.pcap "${CAPTURE_DIR}"many_interfaces.pcapng* > testout.txt 2>&1
	# the above generated 33 IDBs, 88 total pkts, 62 in first IDB

	# and use that generated pcap for our test
	$MERGECAP -vI 'any' -w testout.pcap ./testin.pcap ./testin.pcap ./testin.pcap > testout.txt 2>&1
	RETURNVALUE=$?
	# check for 11 IDBs, 88*3=264 total pkts, 86*3=258 in first IDB
	mergecap_common_pcapng_pkt $RETURNVALUE "Per packet" 11 264 258
	test_step_ok
}


mergecap_cleanup_step() {
	rm -f ./testout.txt
	rm -f ./capinfo_testout.txt
	rm -f ./testout.pcap
	rm -f ./testin.pcap
}

mergecap_suite() {
	test_step_set_pre mergecap_cleanup_step
	test_step_set_post mergecap_cleanup_step
	test_step_add "1 pcap in ----> pcap out" mergecap_step_basic_1_pcap_pcap_test
	test_step_add "2 pcaps in ---> pcap out" mergecap_step_basic_2_pcap_pcap_test
	test_step_add "3 pcaps in ---> pcap out; two are empty" mergecap_step_basic_3_empty_pcap_pcap_test
	test_step_add "2 pcaps in ---> pcap out; one is nanosecond pcap" mergecap_step_basic_2_nano_pcap_pcap_test

	test_step_add "1 pcap in ----> pcapng out" mergecap_step_basic_1_pcap_pcapng_test
	test_step_add "2 pcaps in ---> pcapng out" mergecap_step_basic_2_pcap_pcapng_test
	test_step_add "2 pcaps in ---> pcapng out; merge mode none" mergecap_step_basic_2_pcap_none_pcapng_test
	test_step_add "2 pcaps in ---> pcapng out; merge mode all" mergecap_step_basic_2_pcap_all_pcapng_test
	test_step_add "2 pcaps in ---> pcapng out; merge mode any" mergecap_step_basic_2_pcap_any_pcapng_test

	test_step_add "1 pcapng in --> pcapng out" mergecap_step_basic_1_pcapng_pcapng_test
	test_step_add "1 pcapng in --> pcapng out; many interfaces" mergecap_step_1_pcapng_many_pcapng_test
	test_step_add "3 pcapngs in -> pcapng out; wildcarded" mergecap_step_3_pcapng_pcapng_test
	test_step_add "3 pcapngs in -> pcapng out; merge mode none" mergecap_step_3_pcapng_none_pcapng_test
	test_step_add "3 pcapngs in -> pcapng out; merge mode all" mergecap_step_3_pcapng_all_pcapng_test
	test_step_add "3 pcapngs in -> pcapng out; merge mode any" mergecap_step_3_pcapng_any_pcapng_test
}

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# sh-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
