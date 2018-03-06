#!/bin/bash
#
# Test suite for various ad-hoc dissection tests
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

dissection_http2_data_reassembly_test() {
	if [ $HAVE_NGHTTP2 -ne 0 ]; then
		test_step_skipped
		return
	fi

	local filename="${CAPTURE_DIR}/http2-data-reassembly.pcap"
	local keys="${TESTS_DIR}/keys/http2-data-reassembly.keys"

	# Check for a reassembled PNG image.
	$TSHARK -o ssl.keylog_file:$keys -d 'tcp.port==8443,ssl' \
		-Y 'http2.data.data matches "PNG" && http2.data.data matches "END"' \
		-r $filename |grep -q DATA

	if [ $? -ne 0 ]; then
		test_step_failed "could not find DATA frame with reassembled PNG content"
	else
		test_step_ok
	fi
	return
}

dissection_suite() {
	test_step_add "testing http2 data reassembly" dissection_http2_data_reassembly_test
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
