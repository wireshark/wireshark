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

import config
import os.path
import subprocesstest
import unittest

class case_decrypt_80211(subprocesstest.SubprocessTestCase):
    def test_80211_wpa_psk(self):
        '''IEEE 802.11 WPA PSK'''
        # https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=wpa-Induction.pcap
        capture_file = os.path.join(config.capture_dir, 'wpa-Induction.pcap.gz')
        self.runProcess((config.cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-Tfields',
                '-e', 'http.request.uri',
                '-r', capture_file,
                '-Y', 'http',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('favicon.ico'))

    def test_80211_wpa_eap(self):
        '''IEEE 802.11 WPA EAP (EAPOL Rekey)'''
        # Included in git sources test/captures/wpa-eap-tls.pcap.gz
        capture_file = os.path.join(config.capture_dir, 'wpa-eap-tls.pcap.gz')
        self.runProcess((config.cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file,
                '-Y', 'wlan.analysis.tk==7d9987daf5876249b6c773bf454a0da7',
                ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('Group Message'))

    def test_80211_wpa_eapol_incomplete_rekeys(self):
        '''WPA decode with message1+2 only and secure bit set on message 2'''
        # Included in git sources test/captures/wpa-test-decode.pcap.gz
        capture_file = os.path.join(config.capture_dir, 'wpa-test-decode.pcap.gz')
        self.runProcess((config.cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file,
                '-Y', 'icmp.resp_to == 4263',
                ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('Echo'))

    def test_80211_wpa_psk_mfp(self):
        '''WPA decode management frames with MFP enabled (802.11w)'''
        # Included in git sources test/captures/wpa-test-decode-mgmt.pcap.gz
        capture_file = os.path.join(config.capture_dir, 'wpa-test-decode-mgmt.pcap.gz')
        self.runProcess((config.cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file,
                '-Y', 'wlan.fixed.reason_code == 2 || wlan.fixed.category_code == 3',
                ),
            env=config.test_env)
        self.assertEqual(self.countOutput('802.11.*SN=.*FN=.*Flags='), 3)


    def test_80211_wpa_tdls(self):
        '''WPA decode traffic in a TDLS (Tunneled Direct-Link Setup) session (802.11z)'''
        if not config.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        # Included in git sources test/captures/wpa-test-decode-tdls.pcap.gz
        capture_file = os.path.join(config.capture_dir, 'wpa-test-decode-tdls.pcap.gz')
        self.runProcess((config.cmd_tshark,
                #'-ouat:80211_keys:"wpa-pwd","12345678"',
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file,
                '-Y', 'icmp',
                ),
            env=config.test_env)
        self.assertEqual(self.countOutput('ICMP.*Echo .ping'), 2)

class case_decrypt_dtls(subprocesstest.SubprocessTestCase):
    def test_dtls(self):
        '''DTLS'''
        # https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil.tgz
        capture_file = os.path.join(config.capture_dir, 'snakeoil-dtls.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'data.data',
                '-Y', 'data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('697420776f726b20210a'))

    def test_dtls_psk_aes128ccm8(self):
        '''DTLS 1.2 with PSK, AES-128-CCM-8'''
        capture_file = os.path.join(config.capture_dir, 'dtls12-aes128ccm8.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'dtls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-x'
            ),
            env=config.test_env)
        dt_count = self.countOutput('Decrypted DTLS')
        wfm_count = self.countOutput('Works for me!.')
        self.assertTrue(dt_count == 7 and wfm_count == 2)

    def test_dtls_udt(self):
        '''UDT over DTLS 1.2 with RSA key'''
        capture_file = os.path.join(config.capture_dir, 'udt-dtls.pcapng.gz')
        key_file = os.path.join(config.key_dir, 'udt-dtls.key')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'dtls.keys_list:0.0.0.0,0,data,{}'.format(key_file),
                '-Y', 'dtls && udt.type==ack',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('UDT'))

class case_decrypt_tls(subprocesstest.SubprocessTestCase):
    def test_tls(self):
        '''TLS using the server's private key'''
        # https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil2_070531.tgz
        capture_file = os.path.join(config.capture_dir, 'rsasnakeoil2.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('favicon.ico'))

    def test_tls_rsa_pq(self):
        '''TLS using the server's private key with p < q
        (test whether libgcrypt is correctly called)'''
        capture_file = os.path.join(config.capture_dir, 'rsa-p-lt-q.pcap')
        key_file = os.path.join(config.key_dir, 'rsa-p-lt-q.key')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'tls.keys_list:0.0.0.0,443,http,{}'.format(key_file),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('/'))

    def test_tls_with_password(self):
        '''TLS using the server's private key with password'''
        capture_file = os.path.join(config.capture_dir, 'dmgr.pcapng')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('unsecureLogon.jsp'))

    def test_tls_master_secret(self):
        '''TLS using the master secret and ssl.keylog_file preference aliasing'''
        capture_file = os.path.join(config.capture_dir, 'dhe1.pcapng.gz')
        key_file = os.path.join(config.key_dir, 'dhe1_keylog.dat')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'ssl.keylog_file: {}'.format(key_file),
                '-o', 'tls.desegment_ssl_application_data: FALSE',
                '-o', 'http.tls.port: 443',
                '-Tfields',
                '-e', 'http.request.method',
                '-e', 'http.request.uri',
                '-e', 'http.request.version',
                '-Y', 'http',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(r'GET\s+/test\s+HTTP/1.0'))

    def test_tls12_renegotiation(self):
        '''TLS 1.2 with renegotiation'''
        capture_file = os.path.join(config.capture_dir, 'tls-renegotiation.pcap')
        key_file = os.path.join(config.key_dir, 'rsasnakeoil2.key')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'tls.keys_list:0.0.0.0,4433,http,{}'.format(key_file),
                '-Tfields',
                '-e', 'http.content_length',
                '-Y', 'http',
            ),
            env=config.test_env)
        count_0 = self.countOutput('^0$')
        count_2151 = self.countOutput('^2151$')
        self.assertTrue(count_0 == 1 and count_2151 == 1)

    def test_tls12_psk_aes128ccm(self):
        '''TLS 1.2 with PSK, AES-128-CCM'''
        capture_file = os.path.join(config.capture_dir, 'tls12-aes128ccm.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'tls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-q',
                '-z', 'follow,tls,ascii,0',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('http://www.gnu.org/software/gnutls'))

    def test_tls12_psk_aes256gcm(self):
        '''TLS 1.2 with PSK, AES-256-GCM'''
        capture_file = os.path.join(config.capture_dir, 'tls12-aes256gcm.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'tls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-q',
                '-z', 'follow,tls,ascii,0',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('http://www.gnu.org/software/gnutls'))

    def test_tls12_chacha20poly1305(self):
        '''TLS 1.2 with ChaCha20-Poly1305'''
        if not config.have_libgcrypt17:
            self.skipTest('Requires GCrypt 1.7 or later.')
        capture_file = os.path.join(config.capture_dir, 'tls12-chacha20poly1305.pcap')
        key_file = os.path.join(config.key_dir, 'tls12-chacha20poly1305.keys')
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
            self.runProcess((config.cmd_tshark,
                    '-r', capture_file,
                    '-o', 'tls.keylog_file: {}'.format(key_file),
                    '-q',
                    '-z', 'follow,tls,ascii,{}'.format(stream),
                ),
                env=config.test_env)
            stream += 1
            self.assertTrue(self.grepOutput('Cipher is {}'.format(cipher)))

    def test_tls13_chacha20poly1305(self):
        '''TLS 1.3 with ChaCha20-Poly1305'''
        if not config.have_libgcrypt17:
            self.skipTest('Requires GCrypt 1.7 or later.')
        capture_file = os.path.join(config.capture_dir, 'tls13-20-chacha20poly1305.pcap')
        key_file = os.path.join(config.key_dir, 'tls13-20-chacha20poly1305.keys')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-q',
                '-z', 'follow,tls,ascii,0',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('TLS13-CHACHA20-POLY1305-SHA256'))

    def test_tls13_rfc8446(self):
        '''TLS 1.3 (normal session, then early data followed by normal data).'''
        if not config.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        capture_file = os.path.join(config.capture_dir, 'tls13-rfc8446.pcap')
        key_file = os.path.join(config.key_dir, 'tls13-rfc8446.keys')
        proc = self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-otls.keylog_file:{}'.format(key_file),
                '-Y', 'http',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'http.request.uri',
                '-e', 'http.file_data',
                '-E', 'separator=|',
            ),
            env=config.test_env)
        self.assertEqual([
            r'5|/first|',
            r'6||Request for /first, version TLSv1.3, Early data: no\n',
            r'8|/early|',
            r'10||Request for /early, version TLSv1.3, Early data: yes\n',
            r'12|/second|',
            r'13||Request for /second, version TLSv1.3, Early data: yes\n',
        ], proc.stdout_str.splitlines())

    def test_tls13_rfc8446_noearly(self):
        '''TLS 1.3 (with undecryptable early data).'''
        if not config.have_libgcrypt16:
            self.skipTest('Requires GCrypt 1.6 or later.')
        capture_file = os.path.join(config.capture_dir, 'tls13-rfc8446.pcap')
        key_file = os.path.join(config.key_dir, 'tls13-rfc8446-noearly.keys')
        proc = self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-otls.keylog_file:{}'.format(key_file),
                '-Y', 'http',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'http.request.uri',
                '-e', 'http.file_data',
                '-E', 'separator=|',
            ),
            env=config.test_env)
        self.assertEqual([
            r'5|/first|',
            r'6||Request for /first, version TLSv1.3, Early data: no\n',
            r'10||Request for /early, version TLSv1.3, Early data: yes\n',
            r'12|/second|',
            r'13||Request for /second, version TLSv1.3, Early data: yes\n',
        ], proc.stdout_str.splitlines())


class case_decrypt_zigbee(subprocesstest.SubprocessTestCase):
    def test_zigbee(self):
        '''ZigBee'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7022
        capture_file = os.path.join(config.capture_dir, 'sample_control4_2012-03-24.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'data.data',
                '-Y', 'zbee_aps',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('3067636338652063342e646d2e747620'))

class case_decrypt_ansi_c1222(subprocesstest.SubprocessTestCase):
    def test_ansi_c1222(self):
        '''ANSI C12.22'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9196
        capture_file = os.path.join(config.capture_dir, 'c1222_std_example8.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'c1222.decrypt: TRUE',
                '-o', 'c1222.baseoid: 2.16.124.113620.1.22.0',
                '-Tfields',
                '-e', 'c1222.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('00104d414e55464143545552455220534e2092'))

class case_decrypt_dvb_ci(subprocesstest.SubprocessTestCase):
    def test_dvb_ci(self):
        '''DVB-CI'''
        # simplified version of the sample capture in
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6700
        capture_file = os.path.join(config.capture_dir, 'dvb-ci_UV1_0000.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'dvb-ci.sek: 00000000000000000000000000000000',
                '-o', 'dvb-ci.siv: 00000000000000000000000000000000',
                '-Tfields',
                '-e', 'dvb-ci.cc.sac.padding',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('800000000000000000000000'))

class case_decrypt_ipsec(subprocesstest.SubprocessTestCase):
    def test_ipsec_esp(self):
        '''IPsec ESP'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12671
        capture_file = os.path.join(config.capture_dir, 'esp-bug-12671.pcapng.gz')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'esp.enable_encryption_decode: TRUE',
                '-Tfields',
                '-e', 'data.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('08090a0b0c0d0e0f1011121314151617'))

class case_decrypt_ike_isakmp(subprocesstest.SubprocessTestCase):
    def test_ikev1_certs(self):
        '''IKEv1 (ISAKMP) with certificates'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7951
        capture_file = os.path.join(config.capture_dir, 'ikev1-certs.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'x509sat.printableString',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('OpenSwan'))

    def test_ikev1_simultaneous(self):
        '''IKEv1 (ISAKMP) simultaneous exchanges'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12610
        capture_file = os.path.join(config.capture_dir, 'ikev1-bug-12610.pcapng.gz')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.hash',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('b52521f774967402c9f6cee95fd17e5b'))

    def test_ikev1_unencrypted(self):
        '''IKEv1 (ISAKMP) unencrypted phase 1'''
        # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12620
        capture_file = os.path.join(config.capture_dir, 'ikev1-bug-12620.pcapng.gz')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.hash',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('40043b640f4373250d5ac3a1fb63153c'))

    def test_ikev2_3des_sha160(self):
        '''IKEv2 decryption test (3DES-CBC/SHA1_160)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-3des-sha1_160.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('02f7a0d5f1fdc8ea81039818c65bb9bd09af9b8917319b887ff9ba3046c344c7'))

    def test_ikev2_aes128_ccm12(self):
        '''IKEv2 decryption test (AES-128-CCM-12) - with CBC-MAC verification'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes128ccm12.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('c2104394299e1ffe7908ea720ad5d13717a0d454e4fa0a2128ea689411f479c4'))

    def test_ikev2_aes128_ccm12_2(self):
        '''IKEv2 decryption test (AES-128-CCM-12 using CTR mode, without checksum)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes128ccm12-2.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('aaa281c87b4a19046c57271d557488ca413b57228cb951f5fa9640992a0285b9'))

    def test_ikev2_aes192ctr_sha512(self):
        '''IKEv2 decryption test (AES-192-CTR/SHA2-512)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes192ctr.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('3ec23dcf9348485638407c754547aeb3085290082c49f583fdbae59263a20b4a'))

    def test_ikev2_aes256cbc_sha256(self):
        '''IKEv2 decryption test (AES-256-CBC/SHA2-256)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes256cbc.pcapng')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('e1a8d550064201a7ec024a85758d0673c61c5c510ac13bcd225d6327f50da3d3'))

    def test_ikev2_aes256ccm16(self):
        '''IKEv2 decryption test (AES-256-CCM-16)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes256ccm16.pcapng')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('fa2e74bdc01e30fb0b3ddc9723c9449095969da51f69e560209d2c2b7940210a'))

    def test_ikev2_aes256gcm16(self):
        '''IKEv2 decryption test (AES-256-GCM-16)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes256gcm16.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('9ab71f14ab553cad873a1aa70b99df155dee77cdcf3694b3b7527acbb9712ded'))

    def test_ikev2_aes256gcm8(self):
        '''IKEv2 decryption test (AES-256-GCM-8)'''
        capture_file = os.path.join(config.capture_dir, 'ikev2-decrypt-aes256gcm8.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput('4a66d822d0afbc22ad9a92a2cf4287c920ad8ac3b069a4a7e75fe0a5d499f914'))

class case_decrypt_http2(subprocesstest.SubprocessTestCase):
    def test_http2(self):
        '''HTTP2 (HPACK)'''
        if not config.have_nghttp2:
            self.skipTest('Requires nghttp2.')
        capture_file = os.path.join(config.capture_dir, 'packet-h2-14_headers.pcapng')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-Tfields',
                '-e', 'http2.header.value',
                '-d', 'tcp.port==3000,http2',
            ),
            env=config.test_env)
        test_passed = self.grepOutput('nghttp2')
        if not test_passed:
            self.log_fd.write('\n\n-- Verbose output --\n\n')
            self.runProcess((config.cmd_tshark,
                    '-r', capture_file,
                    '-V',
                    '-d', 'tcp.port==3000,http2',
                ),
                env=config.test_env)
        self.assertTrue(test_passed)

class case_decrypt_kerberos(subprocesstest.SubprocessTestCase):
    def test_kerberos(self):
        '''Kerberos'''
        # Files are from krb-816.zip on the SampleCaptures page.
        if not config.have_kerberos:
            self.skipTest('Requires kerberos.')
        capture_file = os.path.join(config.capture_dir, 'krb-816.pcap.gz')
        keytab_file = os.path.join(config.key_dir, 'krb-816.keytab')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kerberos.decrypt: TRUE',
                '-o', 'kerberos.file: {}'.format(keytab_file),
                '-Tfields',
                '-e', 'kerberos.keyvalue',
            ),
            env=config.test_env)
        # keyvalue: ccda7d48219f73c3b28311c4ba7242b3
        self.assertTrue(self.grepOutput('ccda7d48219f73c3b28311c4ba7242b3'))

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

    def runOne(self, args, keylog=None, pcap_file='wireguard-ping-tcp.pcap'):
        if not config.have_libgcrypt17:
            self.skipTest('Requires Gcrypt 1.7 or later')
        capture_file = os.path.join(config.capture_dir, pcap_file)
        if keylog:
            keylog_file = self.filename_from_id('wireguard.keys')
            args += ['-owg.keylog_file:%s' % keylog_file]
            with open(keylog_file, 'w') as f:
                f.write("\n".join(keylog))
        proc = self.runProcess([config.cmd_tshark, '-r', capture_file] + args,
                               env=config.test_env)
        lines = proc.stdout_str.splitlines()
        return lines

    def test_mac1_public(self):
        """Check that MAC1 identification using public keys work."""
        lines = self.runOne([
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

    def test_mac1_private(self):
        """Check that MAC1 identification using private keys work."""
        lines = self.runOne([
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

    def test_decrypt_initiation_sprivr(self):
        """Check for partial decryption using Spriv_r."""
        lines = self.runOne([
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

    def test_decrypt_initiation_ephemeral_only(self):
        """Check for partial decryption using Epriv_i."""
        lines = self.runOne([
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

    def test_decrypt_full_initiator(self):
        """
        Check for full handshake decryption using Spriv_r + Epriv_i.
        The public key Spub_r is provided via the key log as well.
        """
        lines = self.runOne([
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

    def test_decrypt_full_responder(self):
        """Check for full handshake decryption using responder secrets."""
        lines = self.runOne([
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

    def test_decrypt_psk_initiator(self):
        """Check whether PSKs enable decryption for initiation keys."""
        lines = self.runOne([
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

    def test_decrypt_psk_responder(self):
        """Check whether PSKs enable decryption for responder keys."""
        lines = self.runOne([
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

    def test_decrypt_psk_wrong_orderl(self):
        """Check that the wrong order of lines indeed fail decryption."""
        lines = self.runOne([
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

class case_decrypt_knxip(subprocesstest.SubprocessTestCase):
    # Capture files for these tests contain single telegrams.
    # For realistic (live captured) KNX/IP telegram sequences, see:
    # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14825

    def test_knxip_data_security_decryption_ok(self):
        '''KNX/IP: Data Security decryption OK'''
        # capture_file contains KNX/IP ConfigReq DataSec PropExtValueWriteCon telegram
        capture_file = os.path.join(config.capture_dir, 'knxip_DataSec.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(' DataSec '))
        self.assertTrue(self.grepOutput(' PropExtValueWriteCon '))

    def test_knxip_data_security_decryption_fails(self):
        '''KNX/IP: Data Security decryption fails'''
        # capture_file contains KNX/IP ConfigReq DataSec PropExtValueWriteCon telegram
        capture_file = os.path.join(config.capture_dir, 'knxip_DataSec.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(' DataSec '))
        self.assertFalse(self.grepOutput(' PropExtValueWriteCon '))

    def test_knxip_secure_wrapper_decryption_ok(self):
        '''KNX/IP: SecureWrapper decryption OK'''
        # capture_file contains KNX/IP SecureWrapper RoutingInd telegram
        capture_file = os.path.join(config.capture_dir, 'knxip_SecureWrapper.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(' SecureWrapper '))
        self.assertTrue(self.grepOutput(' RoutingInd '))

    def test_knxip_secure_wrapper_decryption_fails(self):
        '''KNX/IP: SecureWrapper decryption fails'''
        # capture_file contains KNX/IP SecureWrapper RoutingInd telegram
        capture_file = os.path.join(config.capture_dir, 'knxip_SecureWrapper.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(' SecureWrapper '))
        self.assertFalse(self.grepOutput(' RoutingInd '))

    def test_knxip_timer_notify_authentication_ok(self):
        '''KNX/IP: TimerNotify authentication OK'''
        # capture_file contains KNX/IP TimerNotify telegram
        capture_file = os.path.join(config.capture_dir, 'knxip_TimerNotify.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(' TimerNotify '))
        self.assertTrue(self.grepOutput(' OK$'))

    def test_knxip_timer_notify_authentication_fails(self):
        '''KNX/IP: TimerNotify authentication fails'''
        # capture_file contains KNX/IP TimerNotify telegram
        capture_file = os.path.join(config.capture_dir, 'knxip_TimerNotify.pcap')
        self.runProcess((config.cmd_tshark,
                '-r', capture_file,
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ),
            env=config.test_env)
        self.assertTrue(self.grepOutput(' TimerNotify '))
        self.assertFalse(self.grepOutput(' OK$'))

    def test_knxip_keyring_xml_import(self):
        '''KNX/IP: keyring.xml import'''
        # key_file "keyring.xml" contains KNX decryption keys
        key_file = os.path.join(config.key_dir, 'knx_keyring.xml')
        # capture_file is empty
        capture_file = os.path.join(config.capture_dir, 'empty.pcap')
        # Write extracted key info to stdout
        self.runProcess((config.cmd_tshark,
                '-o', 'kip.key_file:' + key_file,
                '-o', 'kip.key_info_file:-',
                '-r', capture_file,
            ),
            env=config.test_env)
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
