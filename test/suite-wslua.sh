#!/bin/bash
#
# Run the epan unit tests
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

wslua_step_dir_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/dir.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_dissector_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# First run tshark with the dissector script.
	$TSHARK -r $CAPTURE_DIR/dns_port.pcap -V -X lua_script:$TESTS_DIR/lua/dissector.lua > testin.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testin.txt
		test_step_failed "exit status of $DUT: $RETURNVALUE"
		return
	fi

	# then run tshark again with the verification script. (it internally reads in testin.txt)
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/verify_dissector.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		echo
		cat ./testin.txt
		cat ./testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_field_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap -X lua_script:$TESTS_DIR/lua/field.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_file_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# First run tshark with the pcap_file_reader script.
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap -X lua_script:$TESTS_DIR/lua/pcap_file.lua > testin.txt 2>&1
	$TSHARK -r $CAPTURE_DIR/wpa-Induction.pcap.gz -X lua_script:$TESTS_DIR/lua/pcap_file.lua >> testin.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testin.txt
		test_step_failed "subtest-1 exit status of $DUT: $RETURNVALUE"
		return
	fi

	# then run tshark again without the script
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap > testout.txt 2>&1
	$TSHARK -r $CAPTURE_DIR/wpa-Induction.pcap.gz >> testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "subtest-2 exit status of $DUT: $RETURNVALUE"
		return
	fi

	# now compare the two files - they should be identical
	if diff -q ./testin.txt ./testout.txt; then
		rm ./testin.txt
	else
		echo
		cat ./testin.txt
		cat ./testout.txt
		test_step_failed "subtest-3 reading the pcap file with Lua did not match internal"
		return
	fi

	# Now generate a new capture file using the Lua writer.
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap -X lua_script:$TESTS_DIR/lua/pcap_file.lua -w testin.txt -F lua_pcap2 > testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "subtest-4 exit status of $DUT: $RETURNVALUE"
		return
	fi

	# now compare the two files - they should be identical
	if diff -q $CAPTURE_DIR/dhcp.pcap ./testin.txt; then
		rm ./testin.txt
	else
		echo
		cat ./testout.txt
		test_step_failed "subtest-5 creating a new pcap file using Lua did not match dhcp.cap"
		return
	fi

	# Now read an acme sipmsg.log using the acme Lua reader, writing it out as pcapng.
	$TSHARK -r $CAPTURE_DIR/sipmsg.log -X lua_script:$TESTS_DIR/lua/acme_file.lua -w testin.txt -F pcapng > testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "subtest-6 exit status of $DUT: $RETURNVALUE"
		return
	fi

	# testin.txt is now a pcapng, read it out using -V verbose into testout.txt
	$TSHARK -r ./testin.txt -V > testout.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "subtest-7 exit status of $DUT: $RETURNVALUE"
		return
	fi

	# now readout sip.pcapng into testin.txt using -V verbose
	$TSHARK -r $CAPTURE_DIR/sip.pcapng -V > testin.txt 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		echo
		cat ./testin.txt
		test_step_failed "subtest-8 exit status of $DUT: $RETURNVALUE"
		return
	fi

	# now compare testin and testout - they should be identical
	if diff -q ./testout.txt ./testin.txt; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		diff ./testout.txt ./testin.txt
		test_step_failed "subtest-9 writing the acme sipmsg.log out as pcapng did not match sip.pcapng"
	fi
}

wslua_step_listener_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap -X lua_script:$TESTS_DIR/lua/listener.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_nstime_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap -X lua_script:$TESTS_DIR/lua/nstime.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_pinfo_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/dhcp.pcap -X lua_script:$TESTS_DIR/lua/nstime.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}


wslua_step_proto_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# First run tshark with the proto script.
	$TSHARK -r $CAPTURE_DIR/dns_port.pcap -V -X lua_script:$TESTS_DIR/lua/proto.lua > testin.txt 2>&1
	grep -q "All tests passed!" testin.txt
	if [ $? -ne 0 ]; then
		cat ./testin.txt
		test_step_failed "didn't find pass marker"
	fi

	# then run tshark again with the verification script. (it internally reads in testin.txt)
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/verify_dissector.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		echo
		cat ./testin.txt
		cat ./testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_int64_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/int64.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		echo
		cat ./testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_args_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/script_args.lua -X lua_script1:1 > testout.txt 2>&1
	grep -q "All tests passed!" testout.txt
	if [ $? -ne 0 ]; then
		cat testout.txt
		test_step_failed "lua_args_test test 1 failed"
	fi
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/script_args.lua -X lua_script1:3 -X lua_script1:foo -X lua_script1:bar > testout.txt 2>&1
	grep -q "All tests passed!" testout.txt
	if [ $? -ne 0 ]; then
		cat testout.txt
		test_step_failed "lua_args_test test 2 failed"
	fi
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/script_args.lua -X lua_script:$TESTS_DIR/lua/script_args.lua -X lua_script1:3 -X lua_script2:1 -X lua_script1:foo -X lua_script1:bar > testout.txt 2>&1
	grep -q "All tests passed!" testout.txt
	if [ $? -ne 0 ]; then
		cat testout.txt
		test_step_failed "lua_args_test test 3 failed"
	fi
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/script_args.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		cat testout.txt
		test_step_failed "lua_args_test negative test 4 failed"
	fi
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/script_args.lua -X lua_script1:3 > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		cat testout.txt
		test_step_failed "lua_args_test negative test 5 failed"
	fi
	test_step_ok
}

wslua_step_globals_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/verify_globals.lua -X lua_script1:$TESTS_DIR/lua/ -X lua_script1:$TESTS_DIR/lua/globals_1.8.txt > testout.txt 2>&1
	grep -q "All tests passed!" testout.txt
	if [ $? -ne 0 ]; then
		cat testout.txt
		test_step_failed "lua_globals_test test 1 failed"
	fi
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/verify_globals.lua -X lua_script1:$TESTS_DIR/lua/ -X lua_script1:$TESTS_DIR/lua/globals_1.10.txt > testout.txt 2>&1
	grep -q "All tests passed!" testout.txt
	if [ $? -ne 0 ]; then
		cat testout.txt
		test_step_failed "lua_globals_test test 2 failed"
	fi
	test_step_ok
}

wslua_step_gregex_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/gregex.lua -X lua_script1:-d$TESTS_DIR/lua/ -X lua_script1:glib -X lua_script1:-V > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_struct_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	$TSHARK -r $CAPTURE_DIR/empty.pcap -X lua_script:$TESTS_DIR/lua/struct.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_step_tvb_test() {
	if [ $HAVE_LUA -ne 0 ]; then
		test_step_skipped
		return
	fi

	# Tshark catches lua script failures, so we have to parse the output.
	# perform this twice: once with a tree, once without
	$TSHARK -r $CAPTURE_DIR/dns_port.pcap -X lua_script:$TESTS_DIR/lua/tvb.lua -V > testout.txt 2>&1
	grep -q "All tests passed!" testout.txt
	if [ $? -ne 0 ]; then
		cat testout.txt
		test_step_failed "lua_args_test test 1 failed"
	fi

	$TSHARK -r $CAPTURE_DIR/dns_port.pcap -X lua_script:$TESTS_DIR/lua/tvb.lua > testout.txt 2>&1
	if grep -q "All tests passed!" testout.txt; then
		test_step_ok
	else
		cat testout.txt
		test_step_failed "didn't find pass marker"
	fi
}

wslua_cleanup_step() {
	rm -f ./testout.txt
	rm -f ./testin.txt
}

wslua_suite() {
	test_step_set_pre wslua_cleanup_step
	test_step_set_post wslua_cleanup_step
	test_step_add "wslua dir" wslua_step_dir_test
	test_step_add "wslua dissector" wslua_step_dissector_test
	test_step_add "wslua field/fieldinfo" wslua_step_field_test
	test_step_add "wslua file" wslua_step_file_test
	test_step_add "wslua globals" wslua_step_globals_test
	test_step_add "wslua gregex" wslua_step_gregex_test
	test_step_add "wslua int64" wslua_step_int64_test
	test_step_add "wslua listener" wslua_step_listener_test
	test_step_add "wslua nstime" wslua_step_nstime_test
	test_step_add "wslua pinfo" wslua_step_pinfo_test
	test_step_add "wslua proto/protofield" wslua_step_proto_test
	test_step_add "wslua script arguments" wslua_step_args_test
	test_step_add "wslua struct" wslua_step_struct_test
	test_step_add "wslua tvb" wslua_step_tvb_test
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
