#!/bin/bash
#
# Test decryption capabilities of the Wireshark tools
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

# To do:
#   IEEE 802.15.4
#   IPsec / ESP
#   ISAKMP / IKEv2
#   PKCS#12
#   SNMP
#   DCERPC NETLOGON
#   Kerberos
#   KINK
#   LDAP
#   NTLMSSP
#   SPNEGO

# common exit status values
EXIT_OK=0
EXIT_COMMAND_LINE=1
EXIT_ERROR=2

UAT_FILES="
	80211_keys
	dtlsdecrypttablefile
	ssl_keys
	c1222_decryption_table
	ikev1_decryption_table
"

TEST_KEYS_DIR="$TESTS_DIR/keys/"
if [ "$WS_SYSTEM" == "Windows" ] ; then
	TEST_KEYS_DIR="`cygpath -w $TEST_KEYS_DIR`"
fi

#TS_ARGS="-Tfields -e frame.number -e frame.time_epoch -e frame.time_delta"
TS_DC_ARGS=""

DIFF_OUT=./diff-output.txt

# WPA PSK
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=wpa-Induction.pcap
decryption_step_80211_wpa_psk() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-Tfields -e http.request.uri \
		-r "$CAPTURE_DIR/wpa-Induction.pcap.gz" \
		-Y http \
		| grep favicon.ico > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt IEEE 802.11 WPA PSK"
		return
	fi
	test_step_ok
}

# WPA EAP (EAPOL Rekey)
# Included in git sources test/captures/wpa-eap-tls.pcap.gz
decryption_step_80211_wpa_eap() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-r "$CAPTURE_DIR/wpa-eap-tls.pcap.gz" \
		-Y "wlan.analysis.tk==7d9987daf5876249b6c773bf454a0da7" \
		 | grep "Group Message" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt IEEE 802.11 WPA EAP"
		return
	fi
	test_step_ok
}

# DTLS
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil.tgz
decryption_step_dtls() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e data.data \
		-r "$CAPTURE_DIR/snakeoil-dtls.pcap" -Y data \
		| grep "69:74:20:77:6f:72:6b:20:21:0a" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt DTLS"
		return
	fi
	test_step_ok
}

# SSL, using the server's private key
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil2_070531.tgz
decryption_step_ssl() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-r "$CAPTURE_DIR/rsasnakeoil2.pcap" -Y http \
		| grep favicon.ico > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the server's private key"
		return
	fi
	test_step_ok
}

# SSL, using the server's private key with password
decryption_step_ssl_with_password() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-r "$CAPTURE_DIR/dmgr.pcapng" -Y http \
		| grep unsecureLogon.jsp > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the server's private key with password"
		return
	fi
	test_step_ok
}

# SSL, using the master secret
decryption_step_ssl_master_secret() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-o "ssl.keylog_file: $TEST_KEYS_DIR/dhe1_keylog.dat" \
		-o "ssl.desegment_ssl_application_data: FALSE" \
		-o "http.ssl.port: 443" \
		-r "$CAPTURE_DIR/dhe1.pcapng.gz" -Y http \
		| grep test > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the master secret"
		return
	fi
	test_step_ok
}

# ZigBee
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7022
decryption_step_zigbee() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-r "$CAPTURE_DIR/sample_control4_2012-03-24.pcap" \
		-Tfields -e data.data \
		-Y zbee_aps \
		| grep "30:67:63:63:38:65:20:63:34:2e:64:6d:2e:74:76:20" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt ZigBee"
		return
	fi
	test_step_ok
}

# ANSI C12.22
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9196
decryption_step_c1222() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "c1222.decrypt: TRUE" \
		-o "c1222.baseoid:2.16.124.113620.1.22.0" \
		-r "$CAPTURE_DIR/c1222_std_example8.pcap" \
		-Tfields -e c1222.data \
		| grep "00:10:4d:41:4e:55:46:41:43:54:55:52:45:52:20:53:4e:20:92" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt C12.22 $RETURNVALUE"
		return
	fi
	test_step_ok
}

# DVB-CI
# simplified version of the sample capture in
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6700
decryption_step_dvb_ci() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		 -o "dvb-ci.sek: 00000000000000000000000000000000" \
		 -o "dvb-ci.siv: 00000000000000000000000000000000" \
		-Tfields -e dvb-ci.cc.sac.padding \
		-r "$CAPTURE_DIR/dvb-ci_UV1_0000.pcap" \
		| grep "80:00:00:00:00:00:00:00:00:00:00:00" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt DVB_CI"
		return
	fi
	test_step_ok
}

# IKEv1 (ISAKMP) with certificates
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7951
decryption_step_ikev1_certs() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e x509sat.printableString \
		-r "$CAPTURE_DIR/ikev1-certs.pcap" \
		| grep "OpenSwan" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt IKEv1"
		return
	fi
	test_step_ok
}

# HTTP2 (HPACK)
decryption_step_http2() {
		env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
				-Tfields -e http2.header.value \
				-d tcp.port==3000,http2 \
				-r "$CAPTURE_DIR/packet-h2-14_headers.pcapng" \
		> ./testout.txt
		grep "nghttp2" ./testout.txt > /dev/null 2>&1
		RETURNVALUE=$?
		if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
			-V \
			-d tcp.port==3000,http2 \
			-r "$CAPTURE_DIR/packet-h2-14_headers.pcapng" \
			> ./testout2.txt
		echo
		echo "Test output:"
		cat ./testout.txt
		echo "Verbose output:"
		cat ./testout2.txt
				test_step_failed "Failed to decode HTTP2 HPACK"
				return
		fi
		test_step_ok
}


tshark_decryption_suite() {
	test_step_add "IEEE 802.11 WPA PSK Decryption" decryption_step_80211_wpa_psk
	test_step_add "IEEE 802.11 WPA EAP Decryption" decryption_step_80211_wpa_eap
	test_step_add "DTLS Decryption" decryption_step_dtls
	test_step_add "SSL Decryption (private key)" decryption_step_ssl
	test_step_add "SSL Decryption (private key with password)" decryption_step_ssl_with_password
	test_step_add "SSL Decryption (master secret)" decryption_step_ssl_master_secret
	test_step_add "ZigBee Decryption" decryption_step_zigbee
	test_step_add "ANSI C12.22 Decryption" decryption_step_c1222
	test_step_add "DVB-CI Decryption" decryption_step_dvb_ci
	test_step_add "IKEv1 Decryption (certificates)" decryption_step_ikev1_certs
	test_step_add "HTTP2 (HPACK)" decryption_step_http2
}

decryption_cleanup_step() {
	rm -rf "$TEST_HOME"
}

decryption_prep_step() {
	decryption_cleanup_step

	TS_DC_ENV="${HOME_ENV}=${HOME_PATH}"

	for UAT in $UAT_FILES ; do
		sed -e "s|TEST_KEYS_DIR|${TEST_KEYS_DIR//\\/\\\\x5c}|" \
			< "$TESTS_DIR/config/$UAT.tmpl" \
			> "$CONF_PATH/$UAT"
	done
}

decryption_suite() {
	test_step_set_pre decryption_prep_step
	test_step_set_post decryption_cleanup_step
	test_suite_add "TShark decryption" tshark_decryption_suite
}

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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

