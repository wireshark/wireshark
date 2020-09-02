#
# -*- coding: utf-8 -*-
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Decryption tests'''

import os.path
import shutil
import subprocess
import subprocesstest
import sys
import sysconfig
import types
import unittest
import fixtures


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_80211(subprocesstest.SubprocessTestCase):
    def test_80211_wpa_psk(self, cmd_tshark, capture_file):
        '''IEEE 802.11 WPA PSK'''
        # https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=wpa-Induction.pcap
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-Tfields',
                '-e', 'http.request.uri',
                '-r', capture_file('wpa-Induction.pcap.gz'),
                '-Y', 'http',
            ))
        self.assertTrue(self.grepOutput('favicon.ico'))

    def test_80211_wpa_eap(self, cmd_tshark, capture_file):
        '''IEEE 802.11 WPA EAP (EAPOL Rekey)'''
        # Included in git sources test/captures/wpa-eap-tls.pcap.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-eap-tls.pcap.gz'),
                '-Y', 'wlan.analysis.tk==7d9987daf5876249b6c773bf454a0da7',
                ))
        self.assertTrue(self.grepOutput('Group Message'))

    def test_80211_wpa_eapol_incomplete_rekeys(self, cmd_tshark, capture_file):
        '''WPA decode with message1+2 only and secure bit set on message 2'''
        # Included in git sources test/captures/wpa-test-decode.pcap.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-test-decode.pcap.gz'),
                '-Y', 'icmp.resp_to == 4263',
                ))
        self.assertTrue(self.grepOutput('Echo'))

    def test_80211_wpa_psk_mfp(self, cmd_tshark, capture_file):
        '''WPA decode management frames with MFP enabled (802.11w)'''
        # Included in git sources test/captures/wpa-test-decode-mgmt.pcap.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-test-decode-mgmt.pcap.gz'),
                '-Y', 'wlan.fixed.reason_code == 2 || wlan.fixed.category_code == 3',
                ))
        self.assertEqual(self.countOutput('802.11.*SN=.*FN=.*Flags='), 3)

    def test_80211_wpa2_psk_mfp(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode WPA2 PSK with MFP enabled (802.11w)'''
        # Included in git sources test/captures/wpa2-psk-mfp.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-psk-mfp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e30e8c019bea43ea5262b10853b818d || wlan.analysis.gtk == 70cdbf2e5bc0ca22e53930818a5d80e4',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5'))   # Verifies GTK is correct
        self.assertTrue(self.grepOutput('DHCP Request'))          # Verifies TK is correct
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK is correct

    def test_80211_wpa_tdls(self, cmd_tshark, capture_file, features):
        '''WPA decode traffic in a TDLS (Tunneled Direct-Link Setup) session (802.11z)'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        # Included in git sources test/captures/wpa-test-decode-tdls.pcap.gz
        self.assertRun((cmd_tshark,
                #'-ouat:80211_keys:"wpa-pwd","12345678"',
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-test-decode-tdls.pcap.gz'),
                '-Y', 'icmp',
                ))
        self.assertEqual(self.countOutput('ICMP.*Echo .ping'), 2)

    def test_80211_wpa3_personal(self, cmd_tshark, capture_file):
        '''IEEE 802.11 decode WPA3 personal / SAE'''
        # Included in git sources test/captures/wpa3-sae.pcapng.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa3-sae.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 20a2e28f4329208044f4d7edca9e20a6 || wlan.analysis.gtk == 1fc82f8813160031d6bf87bca22b6354',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.18'))
        self.assertTrue(self.grepOutput('DHCP ACK'))

    def test_80211_owe(self, cmd_tshark, capture_file):
        '''IEEE 802.11 decode OWE'''
        # Included in git sources test/captures/owe.pcapng.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('owe.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 10f3deccc00d5c8f629fba7a0fff34aa || wlan.analysis.gtk == 016b04ae9e6050bcc1f940dda9ffff2b',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.2'))
        self.assertTrue(self.grepOutput('DHCP ACK'))

    def test_80211_wpa3_suite_b_192(self, cmd_tshark, capture_file):
        '''IEEE 802.11 decode WPA3 Suite B 192-bit'''
        # Included in git sources test/captures/wpa3-suiteb-192.pcapng.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa3-suiteb-192.pcapng.gz'),
                '-Tfields',
                '-e' 'wlan.rsn.ie.gtk.key',
                '-e' 'wlan.analysis.kck',
                '-e' 'wlan.analysis.kek',
                ))
        # Verify that correct PTKs (KCK, KEK) are derived and GTK correctly dissected
        self.assertEqual(self.countOutput('^29f92526ccda5a5dfa0ffa44c26f576ee2d45bae7c5f63369103b1edcab206ea\t' \
                                          'f49ac1a15121f1a597a60a469870450a588ef1f73a1017b1\t' \
                                          '0289b022b4f54262048d3493834ae591e811870c4520ee1395dd215a6092fbfb$'), 1)
        self.assertEqual(self.countOutput('^29f92526ccda5a5dfa0ffa44c26f576ee2d45bae7c5f63369103b1edcab206ea\t' \
                                          '1027c8d5b155ff574158bc50083e28f02e9636a2ac694901\t' \
                                          'd4814a364419fa881a8593083f51497fe9e30556a91cc5d0b11cd2b3226038e1$'), 1)
        self.assertEqual(self.countOutput('^29f92526ccda5a5dfa0ffa44c26f576ee2d45bae7c5f63369103b1edcab206ea\t' \
                                          '35db5e208c9caff2a4e00a54c5346085abaa6f422ef6df81\t' \
                                          'a14d0d683c01bc631bf142e82dc4995d87364eeacfab75d74cf470683bd10c51$'), 1)

    def test_80211_wpa1_gtk_rekey(self, cmd_tshark, capture_file):
        '''Decode WPA1 with multiple GTK rekeys'''
        # Included in git sources test/captures/wpa1-gtk-rekey.pcapng.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa1-gtk-rekey.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == "d0e57d224c1bb8806089d8c23154074c" || wlan.analysis.gtk == "6eaf63f4ad7997ced353723de3029f4d" || wlan.analysis.gtk == "fb42811bcb59b7845376246454fbdab7"',
                ))
        self.assertTrue(self.grepOutput('DHCP Discover'))
        self.assertEqual(self.countOutput('ICMP.*Echo .ping'), 8)

    def test_80211_wpa_extended_key_id_rekey(self, cmd_tshark, capture_file):
        '''WPA decode for Extended Key ID'''
        # Included in git sources test/captures/wpa_ptk_extended_key_id.pcap.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa_ptk_extended_key_id.pcap.gz'),
                '-Tfields',
                '-e' 'wlan.fc.type_subtype',
                '-e' 'wlan.ra',
                '-e' 'wlan.analysis.tk',
                '-e' 'wlan.analysis.gtk',
                '-e' 'wlan.rsn.ie.ptk.keyid',
                ))
        # Verify frames are decoded with the correct key
        self.assertEqual(self.countOutput('^32\t33:33:00:00:00:16\t\t234a9a6ddcca3cb728751cea49d01bb0\t$'), 5)
        self.assertEqual(self.countOutput('^32\t33:33:ff:00:00:00\t\t234a9a6ddcca3cb728751cea49d01bb0\t$'), 1)
        self.assertEqual(self.countOutput('^32\t33:33:ff:00:03:00\t\t234a9a6ddcca3cb728751cea49d01bb0\t$'), 1)
        self.assertEqual(self.countOutput('^32\tff:ff:ff:ff:ff:ff\t\t234a9a6ddcca3cb728751cea49d01bb0\t$'), 4)
        self.assertEqual(self.countOutput('^40\t02:00:00:00:03:00\t618b4d1829e2a496d7fd8c034a6d024d\t\t$'), 2)
        self.assertEqual(self.countOutput('^40\t02:00:00:00:00:00\t618b4d1829e2a496d7fd8c034a6d024d\t\t$'), 1)
        # Verify RSN PTK KeyID parsing
        self.assertEqual(self.countOutput('^40\t02:00:00:00:00:00\t\t\t1$'), 1)
        self.assertEqual(self.countOutput('^40\t02:00:00:00:00:00\tf31ecff5452f4c286cf66ef50d10dabe\t\t0$'), 1)
        self.assertEqual(self.countOutput('^40\t02:00:00:00:00:00\t28dd851decf3f1c2a35df8bcc22fa1d2\t\t1$'), 1)

    def test_80211_wpa_ccmp_256(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode CCMP-256'''
        # Included in git sources test/captures/wpa-ccmp-256.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-ccmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e6abbcf9dc0943936700b6825952218f58a47dfdf51dbb8ce9b02fd7d2d9e40 || wlan.analysis.gtk == 502085ca205e668f7e7c61cdf4f731336bb31e4f5b28ec91860174192e9b2190',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5')) # Verifies GTK is correct
        self.assertTrue(self.grepOutput('DHCP Request'))        # Verifies TK is correct
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK is correct

    def test_80211_wpa_gcmp(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode GCMP'''
        # Included in git sources test/captures/wpa-gcmp.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 755a9c1c9e605d5ff62849e4a17a935c || wlan.analysis.gtk == 7ff30f7a8dd67950eaaf2f20a869a62d',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5')) # Verifies GTK is correct
        self.assertTrue(self.grepOutput('DHCP Request'))        # Verifies TK is correct
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK is correct

    def test_80211_wpa_gcmp_256(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode GCMP-256'''
        # Included in git sources test/captures/wpa-gcmp-256.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == b3dc2ff2d88d0d34c1ddc421cea17f304af3c46acbbe7b6d808b6ebf1b98ec38 || wlan.analysis.gtk == a745ee2313f86515a155c4cb044bc148ae234b9c72707f772b69c2fede3e4016',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5')) # Verifies GTK is correct
        self.assertTrue(self.grepOutput('DHCP Request'))        # Verifies TK is correct
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK is correct

@fixtures.mark_usefixtures('test_env_80211_user_tk')
@fixtures.uses_fixtures
class case_decrypt_80211_user_tk(subprocesstest.SubprocessTestCase):
    def test_80211_user_tk_tkip(self, cmd_tshark, capture_file):
        '''IEEE 802.11 decode TKIP using user TK'''
        # Included in git sources test/captures/wpa1-gtk-rekey.pcapng.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa1-gtk-rekey.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == "d0e57d224c1bb8806089d8c23154074c" || wlan.analysis.gtk == "6eaf63f4ad7997ced353723de3029f4d" || wlan.analysis.gtk == "fb42811bcb59b7845376246454fbdab7"',
                ))
        self.assertTrue(self.grepOutput('DHCP Discover'))
        self.assertEqual(self.countOutput('ICMP.*Echo .ping'), 8)

    def test_80211_user_tk_ccmp(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode CCMP-128 using user TK'''
        # Included in git sources test/captures/wpa2-psk-mfp.pcapng.gz
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-psk-mfp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e30e8c019bea43ea5262b10853b818d || wlan.analysis.gtk == 70cdbf2e5bc0ca22e53930818a5d80e4',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5'))   # Verifies GTK decryption
        self.assertTrue(self.grepOutput('DHCP Request'))          # Verifies TK decryption
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK decryption

    def test_80211_user_tk_ccmp_256(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode CCMP-256 using user TK'''
        # Included in git sources test/captures/wpa-ccmp-256.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-ccmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e6abbcf9dc0943936700b6825952218f58a47dfdf51dbb8ce9b02fd7d2d9e40 || wlan.analysis.gtk == 502085ca205e668f7e7c61cdf4f731336bb31e4f5b28ec91860174192e9b2190',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5')) # Verifies GTK decryption
        self.assertTrue(self.grepOutput('DHCP Request'))        # Verifies TK decryption
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK decryption

    def test_80211_user_tk_gcmp(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode GCMP using user TK'''
        # Included in git sources test/captures/wpa-gcmp.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 755a9c1c9e605d5ff62849e4a17a935c || wlan.analysis.gtk == 7ff30f7a8dd67950eaaf2f20a869a62d',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5')) # Verifies GTK decryption
        self.assertTrue(self.grepOutput('DHCP Request'))        # Verifies TK decryption
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK decryption

    def test_80211_wpa_gcmp_256(self, cmd_tshark, capture_file, features):
        '''IEEE 802.11 decode GCMP-256 using user TK'''
        # Included in git sources test/captures/wpa-gcmp-256.pcapng.gz
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.assertRun((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == b3dc2ff2d88d0d34c1ddc421cea17f304af3c46acbbe7b6d808b6ebf1b98ec38 || wlan.analysis.gtk == a745ee2313f86515a155c4cb044bc148ae234b9c72707f772b69c2fede3e4016',
                ))
        self.assertTrue(self.grepOutput('Who has 192.168.5.5')) # Verifies GTK decryption
        self.assertTrue(self.grepOutput('DHCP Request'))        # Verifies TK decryption
        self.assertTrue(self.grepOutput(r'Echo \(ping\) request')) # Verifies TK decryption

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_dtls(subprocesstest.SubprocessTestCase):
    def test_dtls_rsa(self, cmd_tshark, capture_file, features):
        '''DTLS'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        # https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil.tgz
        self.assertRun((cmd_tshark,
                '-r', capture_file('snakeoil-dtls.pcap'),
                '-Tfields',
                '-e', 'data.data',
                '-Y', 'data',
            ))
        self.assertTrue(self.grepOutput('697420776f726b20210a'))

    def test_dtls_psk_aes128ccm8(self, cmd_tshark, capture_file):
        '''DTLS 1.2 with PSK, AES-128-CCM-8'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtls12-aes128ccm8.pcap'),
                '-o', 'dtls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-x'
            ))
        dt_count = self.countOutput('Decrypted DTLS')
        wfm_count = self.countOutput('Works for me!.')
        self.assertTrue(dt_count == 7 and wfm_count == 2)

    def test_dtls_dsb_aes128ccm8(self, cmd_tshark, capture_file):
        '''DTLS 1.2 with master secrets in a pcapng Decryption Secrets Block.'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('dtls12-aes128ccm8-dsb.pcapng'),
                '-x'
            ))
        dt_count = self.countOutput('Decrypted DTLS')
        wfm_count = self.countOutput('Works for me!.')
        self.assertTrue(dt_count == 7 and wfm_count == 2)

    def test_dtls_udt(self, cmd_tshark, dirs, capture_file, features):
        '''UDT over DTLS 1.2 with RSA key'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'udt-dtls.key')
        self.assertRun((cmd_tshark,
                '-r', capture_file('udt-dtls.pcapng.gz'),
                '-o', 'dtls.keys_list:0.0.0.0,0,data,{}'.format(key_file),
                '-Y', 'dtls && udt.type==ack',
            ))
        self.assertTrue(self.grepOutput('UDT'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_tls(subprocesstest.SubprocessTestCase):
    def test_tls_rsa(self, cmd_tshark, capture_file, features):
        '''TLS using the server's private RSA key.'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        # https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil2_070531.tgz
        self.assertRun((cmd_tshark,
                '-r', capture_file('rsasnakeoil2.pcap'),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ))
        self.assertTrue(self.grepOutput('favicon.ico'))

    def test_tls_rsa_pq(self, cmd_tshark, dirs, capture_file, features):
        '''TLS using the server's private key with p < q
        (test whether libgcrypt is correctly called)'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'rsa-p-lt-q.key')
        self.assertRun((cmd_tshark,
                '-r', capture_file('rsa-p-lt-q.pcap'),
                '-o', 'tls.keys_list:0.0.0.0,443,http,{}'.format(key_file),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ))
        self.assertTrue(self.grepOutput('/'))

    def test_tls_rsa_privkeys_uat(self, cmd_tshark, dirs, capture_file, features):
        '''Check TLS decryption works using the rsa_keys UAT.'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'rsa-p-lt-q.key')
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('rsa-p-lt-q.pcap'),
                '-o', 'uat:rsa_keys:"{}",""'.format(key_file.replace('\\', '\\x5c')),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ))
        self.assertIn('/', proc.stdout_str)

    def test_tls_rsa_with_password(self, cmd_tshark, capture_file, features):
        '''TLS using the server's private key with password'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        self.assertRun((cmd_tshark,
                '-r', capture_file('dmgr.pcapng'),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ))
        self.assertTrue(self.grepOutput('unsecureLogon.jsp'))

    def test_tls_master_secret(self, cmd_tshark, dirs, capture_file):
        '''TLS using the master secret and ssl.keylog_file preference aliasing'''
        key_file = os.path.join(dirs.key_dir, 'dhe1_keylog.dat')
        self.assertRun((cmd_tshark,
                '-r', capture_file('dhe1.pcapng.gz'),
                '-o', 'ssl.keylog_file: {}'.format(key_file),
                '-o', 'tls.desegment_ssl_application_data: FALSE',
                '-o', 'http.tls.port: 443',
                '-Tfields',
                '-e', 'http.request.method',
                '-e', 'http.request.uri',
                '-e', 'http.request.version',
                '-Y', 'http',
            ))
        self.assertTrue(self.grepOutput(r'GET\s+/test\s+HTTP/1.0'))

    def test_tls12_renegotiation(self, cmd_tshark, dirs, capture_file, features):
        '''TLS 1.2 with renegotiation'''
        if not features.have_gnutls:
            self.skipTest('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'rsasnakeoil2.key')
        # Test protocol alias while at it (ssl -> tls)
        self.assertRun((cmd_tshark,
                '-r', capture_file('tls-renegotiation.pcap'),
                '-o', 'tls.keys_list:0.0.0.0,4433,http,{}'.format(key_file),
                '-d', 'tcp.port==4433,ssl',
                '-Tfields',
                '-e', 'http.content_length',
                '-Y', 'http',
            ))
        count_0 = self.countOutput('^0$')
        count_2151 = self.countOutput('^2151$')
        self.assertTrue(count_0 == 1 and count_2151 == 1)

    def test_tls12_psk_aes128ccm(self, cmd_tshark, capture_file):
        '''TLS 1.2 with PSK, AES-128-CCM'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('tls12-aes128ccm.pcap'),
                '-o', 'tls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-q',
                '-z', 'follow,tls,ascii,0',
            ))
        self.assertTrue(self.grepOutput('http://www.gnu.org/software/gnutls'))

    def test_tls12_psk_aes256gcm(self, cmd_tshark, capture_file):
        '''TLS 1.2 with PSK, AES-256-GCM'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('tls12-aes256gcm.pcap'),
                '-o', 'tls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-q',
                '-z', 'follow,tls,ascii,0',
            ))
        self.assertTrue(self.grepOutput('http://www.gnu.org/software/gnutls'))

    def test_tls12_chacha20poly1305(self, cmd_tshark, dirs, features, capture_file):
        '''TLS 1.2 with ChaCha20-Poly1305'''
        if not features.have_libgcrypt17:
            self.skipTest('Requires GCrypt 1.7 or later.')
        key_file = os.path.join(dirs.key_dir, 'tls12-chacha20poly1305.keys')
        ciphers=[
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'DHE-RSA-CHACHA20-POLY1305',
            'RSA-PSK-CHACHA20-POLY1305',
            'DHE-PSK-CHACHA20-POLY1305',
            'ECDHE-PSK-CHACHA20-POLY1305',
            'PSK-CHACHA20-POLY1305',
        ]
        stream = 0
        for cipher in ciphers:
            self.assertRun((cmd_tshark,
                    '-r', capture_file('tls12-chacha20poly1305.pcap'),
                    '-o', 'tls.keylog_file: {}'.format(key_file),
                    '-q',
                    '-z', 'follow,tls,ascii,{}'.format(stream),
                ))
            stream += 1
            self.assertTrue(self.grepOutput('Cipher is {}'.format(cipher)))

    def test_tls13_chacha20poly1305(self, cmd_tshark, dirs, features, capture_file):
        '''TLS 1.3 with ChaCha20-Poly1305'''
        if not features.have_libgcrypt17:
            self.skipTest('Requires GCrypt 1.7 or later.')
        key_file = os.path.join(dirs.key_dir, 'tls13-20-chacha20poly1305.keys')
        self.assertRun((cmd_tshark,
                '-r', capture_file('tls13-20-chacha20poly1305.pcap'),
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-q',
                '-z', 'follow,tls,ascii,0',
            ))
        self.assertTrue(self.grepOutput('TLS13-CHACHA20-POLY1305-SHA256'))

    def test_tls13_rfc8446(self, cmd_tshark, dirs, features, capture_file):
        '''TLS 1.3 (normal session, then early data followed by normal data).'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        key_file = os.path.join(dirs.key_dir, 'tls13-rfc8446.keys')
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('tls13-rfc8446.pcap'),
                '-otls.keylog_file:{}'.format(key_file),
                '-Y', 'http',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'http.request.uri',
                '-e', 'http.file_data',
                '-E', 'separator=|',
            ))
        self.assertEqual([
            r'5|/first|',
            r'6||Request for /first, version TLSv1.3, Early data: no\n',
            r'8|/early|',
            r'10||Request for /early, version TLSv1.3, Early data: yes\n',
            r'12|/second|',
            r'13||Request for /second, version TLSv1.3, Early data: yes\n',
        ], proc.stdout_str.splitlines())

    def test_tls13_rfc8446_noearly(self, cmd_tshark, dirs, features, capture_file):
        '''TLS 1.3 (with undecryptable early data).'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        key_file = os.path.join(dirs.key_dir, 'tls13-rfc8446-noearly.keys')
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('tls13-rfc8446.pcap'),
                '-otls.keylog_file:{}'.format(key_file),
                '-Y', 'http',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'http.request.uri',
                '-e', 'http.file_data',
                '-E', 'separator=|',
            ))
        self.assertEqual([
            r'5|/first|',
            r'6||Request for /first, version TLSv1.3, Early data: no\n',
            r'10||Request for /early, version TLSv1.3, Early data: yes\n',
            r'12|/second|',
            r'13||Request for /second, version TLSv1.3, Early data: yes\n',
        ], proc.stdout_str.splitlines())

    def test_tls12_dsb(self, cmd_tshark, capture_file):
        '''TLS 1.2 with master secrets in pcapng Decryption Secrets Blocks.'''
        output = self.assertRun((cmd_tshark,
                '-r', capture_file('tls12-dsb.pcapng'),
                '-Tfields',
                '-e', 'http.host',
                '-e', 'http.response.code',
                '-Y', 'http',
            )).stdout_str.replace('\r\n', '\n')
        self.assertEqual('example.com\t\n\t200\nexample.net\t\n\t200\n', output)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_zigbee(subprocesstest.SubprocessTestCase):
    def test_zigbee(self, cmd_tshark, capture_file):
        '''ZigBee'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7022
        self.assertRun((cmd_tshark,
                '-r', capture_file('sample_control4_2012-03-24.pcap'),
                '-Tfields',
                '-e', 'data.data',
                '-Y', 'zbee_aps',
            ))
        self.assertTrue(self.grepOutput('3067636338652063342e646d2e747620'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_ansi_c1222(subprocesstest.SubprocessTestCase):
    def test_ansi_c1222(self, cmd_tshark, capture_file):
        '''ANSI C12.22'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9196
        self.assertRun((cmd_tshark,
                '-r', capture_file('c1222_std_example8.pcap'),
                '-o', 'c1222.decrypt: TRUE',
                '-o', 'c1222.baseoid: 2.16.124.113620.1.22.0',
                '-Tfields',
                '-e', 'c1222.data',
            ))
        self.assertTrue(self.grepOutput('00104d414e55464143545552455220534e2092'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_dvb_ci(subprocesstest.SubprocessTestCase):
    def test_dvb_ci(self, cmd_tshark, capture_file):
        '''DVB-CI'''
        # simplified version of the sample capture in
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6700
        self.assertRun((cmd_tshark,
                '-r', capture_file('dvb-ci_UV1_0000.pcap'),
                '-o', 'dvb-ci.sek: 00000000000000000000000000000000',
                '-o', 'dvb-ci.siv: 00000000000000000000000000000000',
                '-Tfields',
                '-e', 'dvb-ci.cc.sac.padding',
            ))
        self.assertTrue(self.grepOutput('800000000000000000000000'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_ipsec(subprocesstest.SubprocessTestCase):
    def test_ipsec_esp(self, cmd_tshark, capture_file):
        '''IPsec ESP'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12671
        self.assertRun((cmd_tshark,
                '-r', capture_file('esp-bug-12671.pcapng.gz'),
                '-o', 'esp.enable_encryption_decode: TRUE',
                '-Tfields',
                '-e', 'data.data',
            ))
        self.assertTrue(self.grepOutput('08090a0b0c0d0e0f1011121314151617'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_ike_isakmp(subprocesstest.SubprocessTestCase):
    def test_ikev1_certs(self, cmd_tshark, capture_file):
        '''IKEv1 (ISAKMP) with certificates'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7951
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev1-certs.pcap'),
                '-Tfields',
                '-e', 'x509sat.printableString',
            ))
        self.assertTrue(self.grepOutput('OpenSwan'))

    def test_ikev1_simultaneous(self, cmd_tshark, capture_file):
        '''IKEv1 (ISAKMP) simultaneous exchanges'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12610
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev1-bug-12610.pcapng.gz'),
                '-Tfields',
                '-e', 'isakmp.hash',
            ))
        self.assertTrue(self.grepOutput('b52521f774967402c9f6cee95fd17e5b'))

    def test_ikev1_unencrypted(self, cmd_tshark, capture_file):
        '''IKEv1 (ISAKMP) unencrypted phase 1'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12620
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev1-bug-12620.pcapng.gz'),
                '-Tfields',
                '-e', 'isakmp.hash',
            ))
        self.assertTrue(self.grepOutput('40043b640f4373250d5ac3a1fb63153c'))

    def test_ikev2_3des_sha160(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (3DES-CBC/SHA1_160)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-3des-sha1_160.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('02f7a0d5f1fdc8ea81039818c65bb9bd09af9b8917319b887ff9ba3046c344c7'))

    def test_ikev2_aes128_ccm12(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-128-CCM-12) - with CBC-MAC verification'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes128ccm12.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('c2104394299e1ffe7908ea720ad5d13717a0d454e4fa0a2128ea689411f479c4'))

    def test_ikev2_aes128_ccm12_2(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-128-CCM-12 using CTR mode, without checksum)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes128ccm12-2.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('aaa281c87b4a19046c57271d557488ca413b57228cb951f5fa9640992a0285b9'))

    def test_ikev2_aes192ctr_sha512(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-192-CTR/SHA2-512)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes192ctr.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('3ec23dcf9348485638407c754547aeb3085290082c49f583fdbae59263a20b4a'))

    def test_ikev2_aes256cbc_sha256(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-256-CBC/SHA2-256)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256cbc.pcapng'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('e1a8d550064201a7ec024a85758d0673c61c5c510ac13bcd225d6327f50da3d3'))

    def test_ikev2_aes256ccm16(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-256-CCM-16)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256ccm16.pcapng'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('fa2e74bdc01e30fb0b3ddc9723c9449095969da51f69e560209d2c2b7940210a'))

    def test_ikev2_aes256gcm16(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-256-GCM-16)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256gcm16.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('9ab71f14ab553cad873a1aa70b99df155dee77cdcf3694b3b7527acbb9712ded'))

    def test_ikev2_aes256gcm8(self, cmd_tshark, capture_file):
        '''IKEv2 decryption test (AES-256-GCM-8)'''
        self.assertRun((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256gcm8.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ))
        self.assertTrue(self.grepOutput('4a66d822d0afbc22ad9a92a2cf4287c920ad8ac3b069a4a7e75fe0a5d499f914'))


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_http2(subprocesstest.SubprocessTestCase):
    def test_http2(self, cmd_tshark, capture_file, features):
        '''HTTP2 (HPACK)'''
        if not features.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        self.assertRun((cmd_tshark,
                '-r', capture_file('packet-h2-14_headers.pcapng'),
                '-Tfields',
                '-e', 'http2.header.value',
                '-d', 'tcp.port==3000,http2',
            ))
        test_passed = self.grepOutput('nghttp2')
        if not test_passed:
            self.log_fd.write('\n\n-- Verbose output --\n\n')
            self.assertRun((cmd_tshark,
                    '-r', capture_file('packet-h2-14_headers.pcapng'),
                    '-V',
                    '-d', 'tcp.port==3000,http2',
                ))
        self.assertTrue(test_passed)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_kerberos(subprocesstest.SubprocessTestCase):
    def test_kerberos(self, cmd_tshark, dirs, features, capture_file):
        '''Kerberos'''
        # Files are from krb-816.zip on the SampleCaptures page.
        if not features.have_kerberos:
            self.skipTest('Requires kerberos.')
        keytab_file = os.path.join(dirs.key_dir, 'krb-816.keytab')
        self.assertRun((cmd_tshark,
                '-r', capture_file('krb-816.pcap.gz'),
                '-o', 'kerberos.decrypt: TRUE',
                '-o', 'kerberos.file: {}'.format(keytab_file),
                '-Tfields',
                '-e', 'kerberos.keyvalue',
            ))
        # keyvalue: ccda7d48219f73c3b28311c4ba7242b3
        self.assertTrue(self.grepOutput('ccda7d48219f73c3b28311c4ba7242b3'))


@fixtures.fixture(scope='session')
def run_wireguard_test(cmd_tshark, capture_file, features):
    if not features.have_libgcrypt18:
        fixtures.skip('Requires Gcrypt 1.8 or later')
    def runOne(self, args, keylog=None, pcap_file='wireguard-ping-tcp.pcap'):
        if keylog:
            keylog_file = self.filename_from_id('wireguard.keys')
            args += ['-owg.keylog_file:%s' % keylog_file]
            with open(keylog_file, 'w') as f:
                f.write("\n".join(keylog))
        proc = self.assertRun([cmd_tshark, '-r', capture_file(pcap_file)] + args)
        lines = proc.stdout_str.splitlines()
        return lines
    return runOne


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_wireguard(subprocesstest.SubprocessTestCase):
    # The "foo_alt" keys are similar as "foo" except that some bits are changed.
    # The crypto library should be able to handle this and internally the
    # dissector uses MSB to recognize whether a private key is set.
    key_Spriv_i = 'AKeZaHwBxjiKLFnkY2unvEdOTtg4AL+M9dQXfopFVFk='
    key_Spriv_i_alt = 'B6eZaHwBxjiKLFnkY2unvEdOTtg4AL+M9dQXfopFVJk='
    key_Spub_i = 'Igge9KzRytKNwrgkzDE/8hrLu6Ly0OqVdvOPWhA5KR4='
    key_Spriv_r = 'cFIxTUyBs1Qil414hBwEgvasEax8CKJ5IS5ZougplWs='
    key_Spub_r = 'YDCttCs9e1J52/g9vEnwJJa+2x6RqaayAYMpSVQfGEY='
    key_Epriv_i0 = 'sLGLJSOQfyz7JNJ5ZDzFf3Uz1rkiCMMjbWerNYcPFFU='
    key_Epriv_i0_alt = 't7GLJSOQfyz7JNJ5ZDzFf3Uz1rkiCMMjbWerNYcPFJU='
    key_Epriv_r0 = 'QC4/FZKhFf0b/eXEcCecmZNt6V6PXmRa4EWG1PIYTU4='
    key_Epriv_i1 = 'ULv83D+y3vA0t2mgmTmWz++lpVsrP7i4wNaUEK2oX0E='
    key_Epriv_r1 = 'sBv1dhsm63cbvWMv/XML+bvynBp9PTdY9Vvptu3HQlg='
    # Ephemeral keys and PSK for wireguard-psk.pcap
    key_Epriv_i2 = 'iCv2VTi/BC/q0egU931KXrrQ4TSwXaezMgrhh7uCbXs='
    key_Epriv_r2 = '8G1N3LnEqYC7+NW/b6mqceVUIGBMAZSm+IpwG1U0j0w='
    key_psk2 = '//////////////////////////////////////////8='
    key_Epriv_i3 = '+MHo9sfkjPsjCx7lbVhRLDvMxYvTirOQFDSdzAW6kUQ='
    key_Epriv_r3 = '0G6t5j1B/We65MXVEBIGuRGYadwB2ITdvJovtAuATmc='
    key_psk3 = 'iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg='
    # dummy key that should not work with anything.
    key_dummy = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx='

    def test_mac1_public(self, run_wireguard_test):
        """Check that MAC1 identification using public keys work."""
        lines = run_wireguard_test(self, [
            '-ouat:wg_keys:"Public","%s"' % self.key_Spub_i,
            '-ouat:wg_keys:"Public","%s"' % self.key_Spub_r,
            '-Y', 'wg.receiver_pubkey',
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.receiver_pubkey',
            '-e', 'wg.receiver_pubkey.known_privkey',
        ])
        self.assertEqual(4, len(lines))
        self.assertIn('1\t%s\t0' % self.key_Spub_r, lines)
        self.assertIn('2\t%s\t0' % self.key_Spub_i, lines)
        self.assertIn('13\t%s\t0' % self.key_Spub_r, lines)
        self.assertIn('14\t%s\t0' % self.key_Spub_i, lines)

    def test_mac1_private(self, run_wireguard_test):
        """Check that MAC1 identification using private keys work."""
        lines = run_wireguard_test(self, [
            '-ouat:wg_keys:"Private","%s"' % self.key_Spriv_i,
            '-ouat:wg_keys:"Private","%s"' % self.key_Spriv_r,
            '-Y', 'wg.receiver_pubkey',
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.receiver_pubkey',
            '-e', 'wg.receiver_pubkey.known_privkey',
        ])
        self.assertEqual(4, len(lines))
        self.assertIn('1\t%s\t1' % self.key_Spub_r, lines)
        self.assertIn('2\t%s\t1' % self.key_Spub_i, lines)
        self.assertIn('13\t%s\t1' % self.key_Spub_r, lines)
        self.assertIn('14\t%s\t1' % self.key_Spub_i, lines)

    def test_decrypt_initiation_sprivr(self, run_wireguard_test):
        """Check for partial decryption using Spriv_r."""
        lines = run_wireguard_test(self, [
            '-ouat:wg_keys:"Private","%s"' % self.key_Spriv_r,
            '-Y', 'wg.type==1',
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.static',
            '-e', 'wg.static.known_pubkey',
            '-e', 'wg.static.known_privkey',
            '-e', 'wg.timestamp.nanoseconds',
        ])
        # static pubkey is unknown because Spub_i is not added to wg_keys.
        self.assertIn('1\t%s\t0\t0\t%s' % (self.key_Spub_i, '356537872'), lines)
        self.assertIn('13\t%s\t0\t0\t%s' % (self.key_Spub_i, '490514356'), lines)

    def test_decrypt_initiation_ephemeral_only(self, run_wireguard_test):
        """Check for partial decryption using Epriv_i."""
        lines = run_wireguard_test(self, [
            '-ouat:wg_keys:"Public","%s"' % self.key_Spub_r,
            '-Y', 'wg.type==1',
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.ephemeral.known_privkey',
            '-e', 'wg.static',
            '-e', 'wg.timestamp.nanoseconds',
        ], keylog=[
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_i0,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_i1,
        ])
        # The current implementation tries to write as much decrypted data as
        # possible, even if the full handshake cannot be derived.
        self.assertIn('1\t1\t%s\t%s' % (self.key_Spub_i, ''), lines)
        self.assertIn('13\t1\t%s\t%s' % (self.key_Spub_i, ''), lines)

    def test_decrypt_full_initiator(self, run_wireguard_test):
        """
        Check for full handshake decryption using Spriv_r + Epriv_i.
        The public key Spub_r is provided via the key log as well.
        """
        lines = run_wireguard_test(self, [
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.ephemeral.known_privkey',
            '-e', 'wg.static',
            '-e', 'wg.timestamp.nanoseconds',
            '-e', 'wg.handshake_ok',
            '-e', 'icmp.type',
            '-e', 'tcp.dstport',
        ], keylog=[
            '  REMOTE_STATIC_PUBLIC_KEY = %s' % self.key_Spub_r,
            '  LOCAL_STATIC_PRIVATE_KEY = %s' % self.key_Spriv_i_alt,
            '  LOCAL_EPHEMERAL_PRIVATE_KEY = %s' % self.key_Epriv_i0_alt,
            '  LOCAL_EPHEMERAL_PRIVATE_KEY = %s' % self.key_Epriv_i1,
        ])
        self.assertIn('1\t1\t%s\t%s\t\t\t' % (self.key_Spub_i, '356537872'), lines)
        self.assertIn('2\t0\t\t\t1\t\t', lines)
        self.assertIn('3\t\t\t\t\t8\t', lines)
        self.assertIn('4\t\t\t\t\t0\t', lines)
        self.assertIn('13\t1\t%s\t%s\t\t\t' % (self.key_Spub_i, '490514356'), lines)
        self.assertIn('14\t0\t\t\t1\t\t', lines)
        self.assertIn('17\t\t\t\t\t\t443', lines)
        self.assertIn('18\t\t\t\t\t\t49472', lines)

    def test_decrypt_wg_full_initiator_dsb(self, run_wireguard_test):
        """
        Similar to test_decrypt_full_initiator, but using decryption keys
        embedded in the pcapng file. The embedded secrets do not contain leading
        spaces nor spaces around the '=' character.
        """
        lines = run_wireguard_test(self, [
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.ephemeral.known_privkey',
            '-e', 'wg.static',
            '-e', 'wg.timestamp.nanoseconds',
            '-e', 'wg.handshake_ok',
            '-e', 'icmp.type',
            '-e', 'tcp.dstport',
        ], pcap_file='wireguard-ping-tcp-dsb.pcapng')
        self.assertIn('1\t1\t%s\t%s\t\t\t' % (self.key_Spub_i, '356537872'), lines)
        self.assertIn('2\t0\t\t\t1\t\t', lines)
        self.assertIn('3\t\t\t\t\t8\t', lines)
        self.assertIn('4\t\t\t\t\t0\t', lines)
        self.assertIn('13\t1\t%s\t%s\t\t\t' % (self.key_Spub_i, '490514356'), lines)
        self.assertIn('14\t0\t\t\t1\t\t', lines)
        self.assertIn('17\t\t\t\t\t\t443', lines)
        self.assertIn('18\t\t\t\t\t\t49472', lines)

    def test_decrypt_full_responder(self, run_wireguard_test):
        """Check for full handshake decryption using responder secrets."""
        lines = run_wireguard_test(self, [
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.ephemeral.known_privkey',
            '-e', 'wg.static',
            '-e', 'wg.timestamp.nanoseconds',
            '-e', 'wg.handshake_ok',
            '-e', 'icmp.type',
            '-e', 'tcp.dstport',
        ], keylog=[
            'REMOTE_STATIC_PUBLIC_KEY=%s' % self.key_Spub_i,
            'LOCAL_STATIC_PRIVATE_KEY=%s' % self.key_Spriv_r,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_r0,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_r1,
        ])
        self.assertIn('1\t0\t%s\t%s\t\t\t' % (self.key_Spub_i, '356537872'), lines)
        self.assertIn('2\t1\t\t\t1\t\t', lines)
        self.assertIn('3\t\t\t\t\t8\t', lines)
        self.assertIn('4\t\t\t\t\t0\t', lines)
        self.assertIn('13\t0\t%s\t%s\t\t\t' % (self.key_Spub_i, '490514356'), lines)
        self.assertIn('14\t1\t\t\t1\t\t', lines)
        self.assertIn('17\t\t\t\t\t\t443', lines)
        self.assertIn('18\t\t\t\t\t\t49472', lines)

    def test_decrypt_psk_initiator(self, run_wireguard_test):
        """Check whether PSKs enable decryption for initiation keys."""
        lines = run_wireguard_test(self, [
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.handshake_ok',
        ], keylog=[
            'REMOTE_STATIC_PUBLIC_KEY = %s' % self.key_Spub_r,
            'LOCAL_STATIC_PRIVATE_KEY = %s' % self.key_Spriv_i,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_i2,
            'PRESHARED_KEY=%s' % self.key_psk2,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_r3,
            'PRESHARED_KEY=%s' % self.key_psk3,
        ], pcap_file='wireguard-psk.pcap')
        self.assertIn('2\t1', lines)
        self.assertIn('4\t1', lines)

    def test_decrypt_psk_responder(self, run_wireguard_test):
        """Check whether PSKs enable decryption for responder keys."""
        lines = run_wireguard_test(self, [
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.handshake_ok',
        ], keylog=[
            'REMOTE_STATIC_PUBLIC_KEY=%s' % self.key_Spub_i,
            'LOCAL_STATIC_PRIVATE_KEY=%s' % self.key_Spriv_r,
            # Epriv_r2 needs psk2. This tests handling of duplicate ephemeral
            # keys with multiple PSKs. It should not have adverse effects.
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_r2,
            'PRESHARED_KEY=%s' % self.key_dummy,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_r2,
            'PRESHARED_KEY=%s' % self.key_psk2,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_i3,
            'PRESHARED_KEY=%s' % self.key_psk3,
            # Epriv_i3 needs psk3, this tests that additional keys again have no
            # bad side-effects.
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_i3,
            'PRESHARED_KEY=%s' % self.key_dummy,
        ], pcap_file='wireguard-psk.pcap')
        self.assertIn('2\t1', lines)
        self.assertIn('4\t1', lines)

    def test_decrypt_psk_wrong_orderl(self, run_wireguard_test):
        """Check that the wrong order of lines indeed fail decryption."""
        lines = run_wireguard_test(self, [
            '-Tfields',
            '-e', 'frame.number',
            '-e', 'wg.handshake_ok',
        ], keylog=[
            'REMOTE_STATIC_PUBLIC_KEY=%s' % self.key_Spub_i,
            'LOCAL_STATIC_PRIVATE_KEY=%s' % self.key_Spriv_r,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_r2,
            'LOCAL_EPHEMERAL_PRIVATE_KEY=%s' % self.key_Epriv_i3,
            'PRESHARED_KEY=%s' % self.key_psk2, # note: swapped with previous line
            'PRESHARED_KEY=%s' % self.key_psk3,
        ], pcap_file='wireguard-psk.pcap')
        self.assertIn('2\t0', lines)
        self.assertIn('4\t0', lines)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_knxip(subprocesstest.SubprocessTestCase):
    # Capture files for these tests contain single telegrams.
    # For realistic (live captured) KNX/IP telegram sequences, see:
    # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14825

    def test_knxip_data_security_decryption_ok(self, cmd_tshark, capture_file):
        '''KNX/IP: Data Security decryption OK'''
        # capture_file('knxip_DataSec.pcap') contains KNX/IP ConfigReq DataSec PropExtValueWriteCon telegram
        self.assertRun((cmd_tshark,
                '-r', capture_file('knxip_DataSec.pcap'),
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ))
        self.assertTrue(self.grepOutput(' DataSec '))
        self.assertTrue(self.grepOutput(' PropExtValueWriteCon '))

    def test_knxip_data_security_decryption_fails(self, cmd_tshark, capture_file):
        '''KNX/IP: Data Security decryption fails'''
        # capture_file('knxip_DataSec.pcap') contains KNX/IP ConfigReq DataSec PropExtValueWriteCon telegram
        self.assertRun((cmd_tshark,
                '-r', capture_file('knxip_DataSec.pcap'),
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ))
        self.assertTrue(self.grepOutput(' DataSec '))
        self.assertFalse(self.grepOutput(' PropExtValueWriteCon '))

    def test_knxip_secure_wrapper_decryption_ok(self, cmd_tshark, capture_file):
        '''KNX/IP: SecureWrapper decryption OK'''
        # capture_file('knxip_SecureWrapper.pcap') contains KNX/IP SecureWrapper RoutingInd telegram
        self.assertRun((cmd_tshark,
                '-r', capture_file('knxip_SecureWrapper.pcap'),
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ))
        self.assertTrue(self.grepOutput(' SecureWrapper '))
        self.assertTrue(self.grepOutput(' RoutingInd '))

    def test_knxip_secure_wrapper_decryption_fails(self, cmd_tshark, capture_file):
        '''KNX/IP: SecureWrapper decryption fails'''
        # capture_file('knxip_SecureWrapper.pcap') contains KNX/IP SecureWrapper RoutingInd telegram
        self.assertRun((cmd_tshark,
                '-r', capture_file('knxip_SecureWrapper.pcap'),
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ))
        self.assertTrue(self.grepOutput(' SecureWrapper '))
        self.assertFalse(self.grepOutput(' RoutingInd '))

    def test_knxip_timer_notify_authentication_ok(self, cmd_tshark, capture_file):
        '''KNX/IP: TimerNotify authentication OK'''
        # capture_file('knxip_TimerNotify.pcap') contains KNX/IP TimerNotify telegram
        self.assertRun((cmd_tshark,
                '-r', capture_file('knxip_TimerNotify.pcap'),
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ))
        self.assertTrue(self.grepOutput(' TimerNotify '))
        self.assertTrue(self.grepOutput(' OK$'))

    def test_knxip_timer_notify_authentication_fails(self, cmd_tshark, capture_file):
        '''KNX/IP: TimerNotify authentication fails'''
        # capture_file('knxip_TimerNotify.pcap') contains KNX/IP TimerNotify telegram
        self.assertRun((cmd_tshark,
                '-r', capture_file('knxip_TimerNotify.pcap'),
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ))
        self.assertTrue(self.grepOutput(' TimerNotify '))
        self.assertFalse(self.grepOutput(' OK$'))

    def test_knxip_keyring_xml_import(self, cmd_tshark, dirs, capture_file):
        '''KNX/IP: keyring.xml import'''
        # key_file "keyring.xml" contains KNX decryption keys
        key_file = os.path.join(dirs.key_dir, 'knx_keyring.xml')
        # capture_file('empty.pcap') is empty
        # Write extracted key info to stdout
        self.assertRun((cmd_tshark,
                '-o', 'kip.key_file:' + key_file,
                '-o', 'kip.key_info_file:-',
                '-r', capture_file('empty.pcap'),
            ))
        self.assertTrue(self.grepOutput('^MCA 224[.]0[.]23[.]12 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$'))
        self.assertTrue(self.grepOutput('^GA 1/7/131 sender 1[.]1[.]1$'))
        self.assertTrue(self.grepOutput('^GA 1/7/131 sender 1[.]1[.]3$'))
        self.assertTrue(self.grepOutput('^GA 1/7/131 sender 1[.]1[.]4$'))
        self.assertTrue(self.grepOutput('^GA 1/7/132 sender 1[.]1[.]2$'))
        self.assertTrue(self.grepOutput('^GA 1/7/132 sender 1[.]1[.]4$'))
        self.assertTrue(self.grepOutput('^GA 6/7/191 sender 1[.]1[.]1$'))
        self.assertTrue(self.grepOutput('^GA 0/1/0 sender 1[.]1[.]1$'))
        self.assertTrue(self.grepOutput('^GA 0/1/0 sender 1[.]1[.]3$'))
        self.assertTrue(self.grepOutput('^GA 0/1/0 sender 1[.]1[.]4$'))
        self.assertTrue(self.grepOutput('^GA 0/1/0 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$'))
        self.assertTrue(self.grepOutput('^GA 1/7/131 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$'))
        self.assertTrue(self.grepOutput('^GA 1/7/132 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$'))
        self.assertTrue(self.grepOutput('^GA 6/7/191 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]1 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]1 SeqNr 45678$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]2 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]2 SeqNr 34567$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]3 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]3 SeqNr 23456$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]4 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$'))
        self.assertTrue(self.grepOutput('^IA 1[.]1[.]4 SeqNr 12345$'))
        self.assertTrue(self.grepOutput('^IA 2[.]1[.]0 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$'))
        self.assertTrue(self.grepOutput('^IA 2[.]1[.]0 SeqNr 1234$'))


@fixtures.fixture(scope='session')
def softhsm_paths(features):
    if sys.platform == 'win32':
        search_path = os.getenv('PATH') + r';C:\SoftHSM2\bin'
    else:
        search_path = None
    softhsm_tool = shutil.which('softhsm2-util', path=search_path)
    if not softhsm_tool:
        # Note: do not fallback to SoftHSMv1. While available on Ubuntu 14.04
        # (and 16.04), it is built with botan < 1.11.10 which causes a crash due
        # to a conflict with the GMP library that is also used by GnuTLS/nettle.
        # See https://github.com/randombit/botan/issues/1090
        fixtures.skip('SoftHSM is not found')
    # Find provider library path.
    bindir = os.path.dirname(softhsm_tool)
    libdir = os.path.join(os.path.dirname(bindir), 'lib')
    if sys.platform == 'win32':
        libdirs = [libdir, bindir]
        if features.have_x64:
            name = 'softhsm2-x64.dll'
        else:
            name = 'softhsm2.dll'
    else:
        # Debian/Ubuntu-specific paths
        madir = sysconfig.get_config_var('multiarchsubdir')
        libdir64_sub = os.path.join(libdir + '64', 'softhsm')
        libdir_sub = os.path.join(libdir, 'softhsm')
        libdirs = [os.path.join(libdir + madir, 'softhsm')] if madir else []
        libdirs += [libdir_sub, libdir64_sub]
        name = 'libsofthsm2.so'
    for libdir in libdirs:
        provider = os.path.join(libdir, name)
        if os.path.exists(provider):
            break
    else:
        # Even if p11-kit can automatically locate it, do not rely on it.
        fixtures.skip('SoftHSM provider library not detected')
    # Now check whether the import tool is usable. SoftHSM < 2.3.0 did not
    # set CKA_DECRYPT when using softhsm2-tool --import and therefore cannot be
    # used to import keys for decryption. Use GnuTLS p11tool as workaround.
    softhsm_version = subprocess.check_output([softhsm_tool, '--version'],
            universal_newlines=True).strip()
    use_p11tool = softhsm_version in ('2.0.0', '2.1.0', '2.2.0')
    if use_p11tool and not shutil.which('p11tool'):
        fixtures.skip('SoftHSM available, but GnuTLS p11tool is unavailable')
    return use_p11tool, softhsm_tool, provider


@fixtures.fixture
def softhsm(softhsm_paths, home_path, base_env):
    '''Creates a temporary SoftHSM token store (and set it in the environment),
    returns a function to populate that token store and the path to the PKCS #11
    provider library.'''
    use_p11tool, softhsm_tool, provider = softhsm_paths
    conf_path = os.path.join(home_path, 'softhsm-test.conf')
    db_path = os.path.join(home_path, 'softhsm-test-tokens')
    os.makedirs(db_path)
    with open(conf_path, 'w') as f:
        f.write('directories.tokendir = %s\n' % db_path)
        f.write('objectstore.backend = file\n')
        # Avoid syslog spam
        f.write('log.level = ERROR\n')
    base_env['SOFTHSM2_CONF'] = conf_path

    tool_env = base_env.copy()
    if sys.platform == 'win32':
        # Ensure that softhsm2-util can find the library.
        tool_env['PATH'] += ';%s' % os.path.dirname(provider)

    # Initialize tokens store.
    token_name = 'Wireshark-Test-Tokens'
    pin = 'Secret'
    subprocess.check_call([softhsm_tool, '--init-token', '--slot', '0',
        '--label', token_name, '--so-pin', 'Supersecret', '--pin', pin],
        env=tool_env)
    if use_p11tool:
        tool_env['GNUTLS_PIN'] = pin

    # Arbitrary IDs and labels.
    ids = iter(range(0xab12, 0xffff))
    def import_key(keyfile):
        '''Returns a PKCS #11 URI to identify the imported key.'''
        label = os.path.basename(keyfile)
        obj_id = '%x' % next(ids)
        if not use_p11tool:
            tool_args = [softhsm_tool, '--import', keyfile, '--label', label,
                    '--id', obj_id, '--pin', pin, '--token', token_name]
        else:
            # Fallback for SoftHSM < 2.3.0
            tool_args = ['p11tool', '--provider', provider, '--batch',
                    '--login', '--write', 'pkcs11:token=%s' % token_name,
                    '--load-privkey', keyfile, '--label', label, '--id', obj_id]
        subprocess.check_call(tool_args, env=tool_env)
        id_str = '%{}{}%{}{}'.format(*obj_id)
        return 'pkcs11:token=%s;id=%s;type=private' % (token_name, id_str)

    return types.SimpleNamespace(import_key=import_key, provider=provider, pin=pin)


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_pkcs11(subprocesstest.SubprocessTestCase):
    def test_tls_pkcs11(self, cmd_tshark, dirs, capture_file, features, softhsm):
        '''Check that a RSA key in a PKCS #11 token enables decryption.'''
        if not features.have_pkcs11:
            self.skipTest('Requires GnuTLS with PKCS #11 support.')
        key_file = os.path.join(dirs.key_dir, 'rsa-p-lt-q.p8')
        key_uri = softhsm.import_key(key_file)
        proc = self.assertRun((cmd_tshark,
                '-r', capture_file('rsa-p-lt-q.pcap'),
                '-o', 'uat:pkcs11_libs:"{}"'.format(softhsm.provider.replace('\\', '\\x5c')),
                '-o', 'uat:rsa_keys:"{}","{}"'.format(key_uri, softhsm.pin),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ))
        self.assertIn('/', proc.stdout_str)

@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_decrypt_smb2(subprocesstest.SubprocessTestCase):
    BAD_KEY = 'ffffffffffffffffffffffffffffffff'

    def check_bad_key(self, cmd_tshark, cap, disp_filter, sesid, seskey, s2ckey, c2skey):
        proc = self.assertRun((cmd_tshark,
                '-r', cap,
                '-o', 'uat:smb2_seskey_list:{},{},{},{}'.format(sesid, seskey, s2ckey, c2skey),
                '-Y', disp_filter,
        ))
        self.assertIn('Encrypted SMB', proc.stdout_str)

    #
    # SMB3.0 CCM bad keys tests
    #
    def test_smb300_bad_seskey(self, features, cmd_tshark, capture_file):
        '''Check that a bad session key doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', self.BAD_KEY, '""', '""')

    def test_smb300_bad_s2ckey(self, features, cmd_tshark, capture_file):
        '''Check that a bad s2c key doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', '""', self.BAD_KEY, '""')

    def test_smb300_bad_c2skey(self, features, cmd_tshark, capture_file):
        '''Check that a bad c2s key doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', '""', '""', self.BAD_KEY)

    def test_smb300_bad_deckey(self, features, cmd_tshark, capture_file):
        '''Check that bad decryption keys doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', '""', self.BAD_KEY, self.BAD_KEY)

    def test_smb300_bad_allkey(self, features, cmd_tshark, capture_file):
        '''Check that all bad keys doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', self.BAD_KEY, self.BAD_KEY, self.BAD_KEY)

    #
    # SMB3.1.1 CCM bad key tests
    #
    def test_smb311_bad_seskey(self, features, cmd_tshark, capture_file):
        '''Check that a bad session key doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', self.BAD_KEY, '""', '""')

    def test_smb311_bad_s2ckey(self, features, cmd_tshark, capture_file):
        '''Check that a bad s2c key doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', '""', self.BAD_KEY, '""')

    def test_smb311_bad_c2skey(self, features, cmd_tshark, capture_file):
        '''Check that a bad c2s key doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', '""', '""', self.BAD_KEY)

    def test_smb311_bad_deckey(self, features, cmd_tshark, capture_file):
        '''Check that bad decryption keys doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', '""', self.BAD_KEY, self.BAD_KEY)

    def test_smb311_bad_allkey(self, features, cmd_tshark, capture_file):
        '''Check that all bad keys doesn't crash'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', self.BAD_KEY, self.BAD_KEY, self.BAD_KEY)

    #
    # Decryption tests
    #

    def check_tree(self, cmd_tshark, cap, tree, sesid, seskey, s2ckey, c2skey):
        proc = self.assertRun((cmd_tshark,
                '-r', cap,
                '-o', 'uat:smb2_seskey_list:{},{},{},{}'.format(sesid, seskey, s2ckey, c2skey),
                '-Tfields',
                '-e', 'smb2.tree',
                '-Y', 'smb2.tree == "{}"'.format(tree.replace('\\', '\\\\')),
        ))
        self.assertEqual(tree, proc.stdout_str.strip())

    # SMB3.0 CCM
    def test_smb300_aes128ccm_seskey(self, features, cmd_tshark, capture_file):
        '''Check SMB 3.0 AES128CCM decryption with session key.'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_tree(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '1900009c003c0000',
                        '9a9ea16a0cdbeb6064772318073f172f', '""', '""')

    def test_smb300_aes128ccm_deckey(self, features, cmd_tshark, capture_file):
        '''Check SMB 3.0 AES128CCM decryption with decryption keys.'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_tree(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '1900009c003c0000',
                        '""', '8be6cc53d4beba29387e69aef035d497','bff985870e81784d533fdc09497b8eab')


    # SMB3.1.1 CCM
    def test_smb311_aes128ccm_seskey(self, features, cmd_tshark, capture_file):
        '''Check SMB 3.1.1 AES128CCM decryption with session key.'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_tree(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '2900009c003c0000',
                        'f1fa528d3cd182cca67bd4596dabd885', '""', '""')

    def test_smb311_aes128ccm_deckey(self, features, cmd_tshark, capture_file):
        '''Check SMB 3.1.1 AES128CCM decryption with decryption keys.'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_tree(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '2900009c003c0000',
                        '""', '763d5552dbc9650b700869467a5857e4', '35e69833c6578e438c8701cb40bf483e')

    # SMB3.1.1 GCM
    def test_smb311_aes128gcm_seskey(self, features, cmd_tshark, capture_file):
        '''Check SMB 3.1.1 AES128GCM decryption with session key.'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_tree(cmd_tshark, capture_file('smb311-aes-128-gcm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                        'e79161ded03bda1449b2c8e58f753953', '""', '""')

    def test_smb311_aes128gcm_deckey(self, features, cmd_tshark, capture_file):
        '''Check SMB 3.1.1 AES128GCM decryption with decryption keys.'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_tree(cmd_tshark, capture_file('smb311-aes-128-gcm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                        '""', 'b02f5de25e0562075c3dc329fa2aa396', '7201623a31754e6581864581209dd3d2')

    def check_partial(self, home_path, cmd_tshark, full_cap, pkt_skip, tree, sesid, s2ckey, c2skey):
        # generate a trace without NegProt and SessionSetup
        partial_cap = os.path.join(home_path, 'short.pcap')
        self.assertRun((cmd_tshark,
                        '-r', full_cap,
                        '-Y', 'frame.number >= %d'%pkt_skip,
                        '-w', partial_cap,
        ))
        self.check_tree(cmd_tshark, partial_cap, tree, sesid, '""', s2ckey, c2skey)

    def test_smb311_aes128gcm_partial(self, features, home_path, cmd_tshark, capture_file):
        '''Check SMB 3.1.1 AES128GCM decryption in capture missing session setup'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_partial(home_path, cmd_tshark,
                           capture_file('smb311-aes-128-gcm.pcap.gz'), 7,
                           r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                           'b02f5de25e0562075c3dc329fa2aa396', '7201623a31754e6581864581209dd3d2')

    def test_smb311_aes128gcm_partial_keyswap(self, features, home_path, cmd_tshark, capture_file):
        '''Check SMB 3.1.1 AES128GCM decryption in capture missing session setup with keys in wrong order'''
        if not features.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        self.check_partial(home_path, cmd_tshark,
                           capture_file('smb311-aes-128-gcm.pcap.gz'), 7,
                           r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                           '7201623a31754e6581864581209dd3d2', 'b02f5de25e0562075c3dc329fa2aa396')
