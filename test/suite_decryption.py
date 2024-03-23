#
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
from subprocesstest import grep_output, count_output
import sys
import sysconfig
import types
import pytest
import binascii

class TestDecrypt80211:
    def test_80211_wep(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 WEP'''
        # Included in git sources test/captures/wep.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wep.pcapng.gz'),
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.1')
        assert grep_output(stdout, r'Echo \(ping\) request')

    def test_80211_wpa_psk(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 WPA PSK'''
        # https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/wpa-Induction.pcap
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-Tfields',
                '-e', 'http.request.uri',
                '-r', capture_file('wpa-Induction.pcap.gz'),
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'favicon.ico')

    def test_80211_wpa_eap(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 WPA EAP (EAPOL Rekey)'''
        # Included in git sources test/captures/wpa-eap-tls.pcap.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-eap-tls.pcap.gz'),
                '-Y', 'wlan.analysis.tk==7d9987daf5876249b6c773bf454a0da7',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Group Message')

    def test_80211_wpa_eapol_incomplete_rekeys(self, cmd_tshark, capture_file, test_env):
        '''WPA decode with message1+2 only and secure bit set on message 2'''
        # Included in git sources test/captures/wpa-test-decode.pcap.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-test-decode.pcap.gz'),
                '-Y', 'icmp.resp_to == 4263',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Echo')

    def test_80211_wpa_psk_mfp(self, cmd_tshark, capture_file, test_env):
        '''WPA decode management frames with MFP enabled (802.11w)'''
        # Included in git sources test/captures/wpa-test-decode-mgmt.pcap.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-test-decode-mgmt.pcap.gz'),
                '-Y', 'wlan.fixed.reason_code == 2 || wlan.fixed.category_code == 3',
                ), encoding='utf-8', env=test_env)
        assert count_output(stdout, '802.11.*SN=.*FN=.*Flags=') == 3

    def test_80211_wpa2_psk_mfp(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode WPA2 PSK with MFP enabled (802.11w)'''
        # Included in git sources test/captures/wpa2-psk-mfp.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-psk-mfp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e30e8c019bea43ea5262b10853b818d || wlan.analysis.gtk == 70cdbf2e5bc0ca22e53930818a5d80e4',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5')   # Verifies GTK is correct
        assert grep_output(stdout, 'DHCP Request')          # Verifies TK is correct
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK is correct

    def test_80211_wpa_tdls(self, cmd_tshark, capture_file, features, test_env):
        '''WPA decode traffic in a TDLS (Tunneled Direct-Link Setup) session (802.11z)'''
        # Included in git sources test/captures/wpa-test-decode-tdls.pcap.gz
        stdout = subprocess.check_output((cmd_tshark,
                #'-ouat:80211_keys:"wpa-pwd","12345678"',
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-test-decode-tdls.pcap.gz'),
                '-Y', 'icmp',
                ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'ICMP.*Echo .ping') == 2

    def test_80211_wpa3_personal(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 decode WPA3 personal / SAE'''
        # Included in git sources test/captures/wpa3-sae.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa3-sae.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 20a2e28f4329208044f4d7edca9e20a6 || wlan.analysis.gtk == 1fc82f8813160031d6bf87bca22b6354',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.18')
        assert grep_output(stdout, 'DHCP ACK')

    def test_80211_owe(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 decode OWE'''
        # Included in git sources test/captures/owe.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('owe.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 10f3deccc00d5c8f629fba7a0fff34aa || wlan.analysis.gtk == 016b04ae9e6050bcc1f940dda9ffff2b',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.2')
        assert grep_output(stdout, 'DHCP ACK')

    def test_80211_wpa3_suite_b_192(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 decode WPA3 Suite B 192-bit'''
        # Included in git sources test/captures/wpa3-suiteb-192.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa3-suiteb-192.pcapng.gz'),
                '-Tfields',
                '-e' 'wlan.rsn.ie.gtk_kde.gtk',
                '-e' 'wlan.analysis.kck',
                '-e' 'wlan.analysis.kek',
                ), encoding='utf-8', env=test_env)
        # Verify that correct PTKs (KCK, KEK) are derived and GTK correctly dissected
        assert count_output(stdout, '^29f92526ccda5a5dfa0ffa44c26f576ee2d45bae7c5f63369103b1edcab206ea\t' \
                                          'f49ac1a15121f1a597a60a469870450a588ef1f73a1017b1\t' \
                                          '0289b022b4f54262048d3493834ae591e811870c4520ee1395dd215a6092fbfb$') == 1
        assert count_output(stdout, '^29f92526ccda5a5dfa0ffa44c26f576ee2d45bae7c5f63369103b1edcab206ea\t' \
                                          '1027c8d5b155ff574158bc50083e28f02e9636a2ac694901\t' \
                                          'd4814a364419fa881a8593083f51497fe9e30556a91cc5d0b11cd2b3226038e1$') == 1
        assert count_output(stdout, '^29f92526ccda5a5dfa0ffa44c26f576ee2d45bae7c5f63369103b1edcab206ea\t' \
                                          '35db5e208c9caff2a4e00a54c5346085abaa6f422ef6df81\t' \
                                          'a14d0d683c01bc631bf142e82dc4995d87364eeacfab75d74cf470683bd10c51$') == 1

    def test_80211_wpa1_gtk_rekey(self, cmd_tshark, capture_file, test_env):
        '''Decode WPA1 with multiple GTK rekeys'''
        # Included in git sources test/captures/wpa1-gtk-rekey.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa1-gtk-rekey.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == "d0e57d224c1bb8806089d8c23154074c" || wlan.analysis.gtk == "6eaf63f4ad7997ced353723de3029f4d" || wlan.analysis.gtk == "fb42811bcb59b7845376246454fbdab7"',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'DHCP Discover')
        assert count_output(stdout, 'ICMP.*Echo .ping') == 8

    def test_80211_wpa_extended_key_id_rekey(self, cmd_tshark, capture_file, test_env):
        '''WPA decode for Extended Key ID'''
        # Included in git sources test/captures/wpa_ptk_extended_key_id.pcap.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa_ptk_extended_key_id.pcap.gz'),
                '-Tfields',
                '-e' 'wlan.fc.type_subtype',
                '-e' 'wlan.ra',
                '-e' 'wlan.analysis.tk',
                '-e' 'wlan.analysis.gtk',
                '-e' 'wlan.rsn.ie.ptk.keyid',
                ), encoding='utf-8', env=test_env)
        # Verify frames are decoded with the correct key
        assert count_output(stdout, '^0x0020\t33:33:00:00:00:16\t\t234a9a6ddcca3cb728751cea49d01bb0\t$') == 5
        assert count_output(stdout, '^0x0020\t33:33:ff:00:00:00\t\t234a9a6ddcca3cb728751cea49d01bb0\t$') == 1
        assert count_output(stdout, '^0x0020\t33:33:ff:00:03:00\t\t234a9a6ddcca3cb728751cea49d01bb0\t$') == 1
        assert count_output(stdout, '^0x0020\tff:ff:ff:ff:ff:ff\t\t234a9a6ddcca3cb728751cea49d01bb0\t$') == 4
        assert count_output(stdout, '^0x0028\t02:00:00:00:03:00\t618b4d1829e2a496d7fd8c034a6d024d\t\t$') == 2
        assert count_output(stdout, '^0x0028\t02:00:00:00:00:00\t618b4d1829e2a496d7fd8c034a6d024d\t\t$') == 1
        # Verify RSN PTK KeyID parsing
        assert count_output(stdout, '^0x0028\t02:00:00:00:00:00\t\t\t1$') == 1
        assert count_output(stdout, '^0x0028\t02:00:00:00:00:00\tf31ecff5452f4c286cf66ef50d10dabe\t\t0$') == 1
        assert count_output(stdout, '^0x0028\t02:00:00:00:00:00\t28dd851decf3f1c2a35df8bcc22fa1d2\t\t1$') == 1

    def test_80211_wpa_ccmp_256(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode CCMP-256'''
        # Included in git sources test/captures/wpa-ccmp-256.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-ccmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e6abbcf9dc0943936700b6825952218f58a47dfdf51dbb8ce9b02fd7d2d9e40 || wlan.analysis.gtk == 502085ca205e668f7e7c61cdf4f731336bb31e4f5b28ec91860174192e9b2190',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5') # Verifies GTK is correct
        assert grep_output(stdout, 'DHCP Request')        # Verifies TK is correct
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK is correct

    def test_80211_wpa_gcmp(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode GCMP'''
        # Included in git sources test/captures/wpa-gcmp.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 755a9c1c9e605d5ff62849e4a17a935c || wlan.analysis.gtk == 7ff30f7a8dd67950eaaf2f20a869a62d',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5') # Verifies GTK is correct
        assert grep_output(stdout, 'DHCP Request')        # Verifies TK is correct
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK is correct

    def test_80211_wpa_gcmp_256(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode GCMP-256'''
        # Included in git sources test/captures/wpa-gcmp-256.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == b3dc2ff2d88d0d34c1ddc421cea17f304af3c46acbbe7b6d808b6ebf1b98ec38 || wlan.analysis.gtk == a745ee2313f86515a155c4cb044bc148ae234b9c72707f772b69c2fede3e4016',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5') # Verifies GTK is correct
        assert grep_output(stdout, 'DHCP Request')        # Verifies TK is correct
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK is correct

    def test_80211_wpa2_ft_psk_no_roam(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 decode WPA2 FT PSK (without roam verification)'''
        # Included in git sources test/captures/wpa2-ft-psk.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-ft-psk.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == ba60c7be2944e18f31949508a53ee9d6 || wlan.analysis.gtk == 6eab6a5f8d880f81104ed65ab0c74449',
                ), encoding='utf-8', env=test_env)
        # Verifies that traffic from initial authentication can be decrypted (both TK and GTK)
        assert count_output(stdout, 'DHCP Discover') == 2
        assert count_output(stdout, 'DHCP Offer') == 1
        assert count_output(stdout, 'DHCP Request') == 2
        assert count_output(stdout, 'DHCP ACK') == 1
        assert count_output(stdout, 'ARP.*Who has') == 3
        assert count_output(stdout, 'ARP.*is at') == 1
        assert count_output(stdout, r'ICMP.*Echo \(ping\)') == 2

    def test_80211_wpa2_ft_psk_roam(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode WPA2 FT PSK'''
        # Included in git sources test/captures/wpa2-ft-psk.pcapng.gz

        # Verify TK and GTK for both initial authentication (AP1) and roam(AP2).
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-ft-psk.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == ba60c7be2944e18f31949508a53ee9d6 || wlan.analysis.gtk == 6eab6a5f8d880f81104ed65ab0c74449 || wlan.analysis.tk == a6a3304e5a8fabe0dc427cc41a707858 || wlan.analysis.gtk == a6cc605e10878f86b20a266c9b58d230',
                ), encoding='utf-8', env=test_env)
        assert count_output(stdout, 'DHCP Discover') == 2
        assert count_output(stdout, 'DHCP Offer') == 1
        assert count_output(stdout, 'DHCP Request') == 2
        assert count_output(stdout, 'DHCP ACK') == 1
        assert count_output(stdout, 'ARP.*Who has') == 5
        assert count_output(stdout, 'ARP.*is at') == 2
        assert count_output(stdout, r'ICMP.*Echo \(ping\)') == 4

    def test_80211_wpa2_ft_eap(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 decode WPA2 FT EAP'''
        # Included in git sources test/captures/wpa2-ft-eap.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-ft-eap.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 65471b64605bf2a04af296284cb4ae2a || wlan.analysis.gtk == 1783a5c28e046df6fb58cf4406c4b22c',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.1.1')    # Verifies GTK decryption
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK decryption

class TestDecrypt80211UserTk:
    def test_80211_user_tk_tkip(self, cmd_tshark, capture_file, test_env):
        '''IEEE 802.11 decode TKIP using user TK'''
        # Included in git sources test/captures/wpa1-gtk-rekey.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa1-gtk-rekey.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == "d0e57d224c1bb8806089d8c23154074c" || wlan.analysis.gtk == "6eaf63f4ad7997ced353723de3029f4d" || wlan.analysis.gtk == "fb42811bcb59b7845376246454fbdab7"',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'DHCP Discover')
        assert count_output(stdout, 'ICMP.*Echo .ping') == 8

    def test_80211_user_tk_ccmp(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode CCMP-128 using user TK'''
        # Included in git sources test/captures/wpa2-psk-mfp.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa2-psk-mfp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e30e8c019bea43ea5262b10853b818d || wlan.analysis.gtk == 70cdbf2e5bc0ca22e53930818a5d80e4',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5')   # Verifies GTK decryption
        assert grep_output(stdout, 'DHCP Request')          # Verifies TK decryption
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK decryption

    def test_80211_user_tk_ccmp_256(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode CCMP-256 using user TK'''
        # Included in git sources test/captures/wpa-ccmp-256.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-ccmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 4e6abbcf9dc0943936700b6825952218f58a47dfdf51dbb8ce9b02fd7d2d9e40 || wlan.analysis.gtk == 502085ca205e668f7e7c61cdf4f731336bb31e4f5b28ec91860174192e9b2190',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5') # Verifies GTK decryption
        assert grep_output(stdout, 'DHCP Request')        # Verifies TK decryption
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK decryption

    def test_80211_user_tk_gcmp(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode GCMP using user TK'''
        # Included in git sources test/captures/wpa-gcmp.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == 755a9c1c9e605d5ff62849e4a17a935c || wlan.analysis.gtk == 7ff30f7a8dd67950eaaf2f20a869a62d',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5') # Verifies GTK decryption
        assert grep_output(stdout, 'DHCP Request')        # Verifies TK decryption
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK decryption

    def test_80211_wpa_gcmp_256(self, cmd_tshark, capture_file, features, test_env):
        '''IEEE 802.11 decode GCMP-256 using user TK'''
        # Included in git sources test/captures/wpa-gcmp-256.pcapng.gz
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'wlan.enable_decryption: TRUE',
                '-r', capture_file('wpa-gcmp-256.pcapng.gz'),
                '-Y', 'wlan.analysis.tk == b3dc2ff2d88d0d34c1ddc421cea17f304af3c46acbbe7b6d808b6ebf1b98ec38 || wlan.analysis.gtk == a745ee2313f86515a155c4cb044bc148ae234b9c72707f772b69c2fede3e4016',
                ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'Who has 192.168.5.5') # Verifies GTK decryption
        assert grep_output(stdout, 'DHCP Request')        # Verifies TK decryption
        assert grep_output(stdout, r'Echo \(ping\) request') # Verifies TK decryption


class TestDecryptDTLS:
    def test_dtls_rsa(self, cmd_tshark, capture_file, features, test_env):
        '''DTLS'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        # https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/snakeoil.tgz
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('snakeoil-dtls.pcap'),
                '-Tfields',
                '-e', 'data.data',
                '-Y', 'data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '697420776f726b20210a')

    def test_dtls_psk_aes128ccm8(self, cmd_tshark, capture_file, test_env):
        '''DTLS 1.2 with PSK, AES-128-CCM-8'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtls12-aes128ccm8.pcap'),
                '-o', 'dtls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-x'
            ), encoding='utf-8', env=test_env)
        dt_count = count_output(stdout, 'Decrypted DTLS')
        wfm_count = count_output(stdout, 'Works for me!.')
        assert dt_count == 7 and wfm_count == 2

    def test_dtls_dsb_aes128ccm8(self, cmd_tshark, capture_file, test_env):
        '''DTLS 1.2 with master secrets in a pcapng Decryption Secrets Block.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dtls12-aes128ccm8-dsb.pcapng'),
                '-x'
            ), encoding='utf-8', env=test_env)
        dt_count = count_output(stdout, 'Decrypted DTLS')
        wfm_count = count_output(stdout, 'Works for me!.')
        assert dt_count == 7 and wfm_count == 2

    def test_dtls_udt(self, cmd_tshark, dirs, capture_file, features, test_env):
        '''UDT over DTLS 1.2 with RSA key'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'udt-dtls.key')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('udt-dtls.pcapng.gz'),
                '-o', 'dtls.keys_list:0.0.0.0,0,data,{}'.format(key_file),
                '-Y', 'dtls && udt.type==ack',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'UDT')


class TestDecryptTLS:
    def test_tls_rsa(self, cmd_tshark, capture_file, features, test_env):
        '''TLS using the server's private RSA key.'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        # https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/snakeoil2_070531.tgz
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rsasnakeoil2.pcap'),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'favicon.ico')

    def test_tls_rsa_pq(self, cmd_tshark, dirs, capture_file, features, test_env):
        '''TLS using the server's private key with p < q
        (test whether libgcrypt is correctly called)'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'rsa-p-lt-q.key')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rsa-p-lt-q.pcap'),
                '-o', 'tls.keys_list:0.0.0.0,443,http,{}'.format(key_file),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '/')

    def test_tls_rsa_privkeys_uat(self, cmd_tshark, dirs, capture_file, features, test_env):
        '''Check TLS decryption works using the rsa_keys UAT.'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'rsa-p-lt-q.key')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rsa-p-lt-q.pcap'),
                '-o', 'uat:rsa_keys:"{}",""'.format(key_file.replace('\\', '\\x5c')),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert '/' in stdout

    def test_tls_rsa_with_password(self, cmd_tshark, capture_file, features, test_env):
        '''TLS using the server's private key with password'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dmgr.pcapng'),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'unsecureLogon.jsp')

    def test_tls_master_secret(self, cmd_tshark, dirs, capture_file, test_env):
        '''TLS using the master secret and ssl.keylog_file preference aliasing'''
        key_file = os.path.join(dirs.key_dir, 'dhe1_keylog.dat')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dhe1.pcapng.gz'),
                '-o', 'ssl.keylog_file: {}'.format(key_file),
                '-o', 'tls.desegment_ssl_application_data: FALSE',
                '-o', 'http.tls.port: 443',
                '-Tfields',
                '-e', 'http.request.method',
                '-e', 'http.request.uri',
                '-e', 'http.request.version',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, r'GET\s+/test\s+HTTP/1.0')

    def test_tls12_renegotiation(self, cmd_tshark, dirs, capture_file, features, test_env):
        '''TLS 1.2 with renegotiation'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'rsasnakeoil2.key')
        # Test protocol alias while at it (ssl -> tls)
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls-renegotiation.pcap'),
                '-o', 'tls.keys_list:0.0.0.0,4433,http,{}'.format(key_file),
                '-d', 'tcp.port==4433,ssl',
                '-Tfields',
                '-e', 'http.content_length',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        count_0 = count_output(stdout, '^0$')
        count_2151 = count_output(stdout, '^2151$')
        assert count_0 == 1 and count_2151 == 1

    def test_tls12_psk_aes128ccm(self, cmd_tshark, capture_file, test_env):
        '''TLS 1.2 with PSK, AES-128-CCM'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls12-aes128ccm.pcap'),
                '-o', 'tls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-q',
                '-z', 'follow,tls,ascii,0',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'http://www.gnu.org/software/gnutls')

    def test_tls12_psk_aes256gcm(self, cmd_tshark, capture_file, test_env):
        '''TLS 1.2 with PSK, AES-256-GCM'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls12-aes256gcm.pcap'),
                '-o', 'tls.psk:ca19e028a8a372ad2d325f950fcaceed',
                '-q',
                '-z', 'follow,tls,ascii,0',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'http://www.gnu.org/software/gnutls')

    def test_tls12_chacha20poly1305(self, cmd_tshark, dirs, features, capture_file, test_env):
        '''TLS 1.2 with ChaCha20-Poly1305'''
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
            stdout = subprocess.check_output((cmd_tshark,
                    '-r', capture_file('tls12-chacha20poly1305.pcap'),
                    '-o', 'tls.keylog_file: {}'.format(key_file),
                    '-q',
                    '-z', 'follow,tls,ascii,{}'.format(stream),
                ), encoding='utf-8', env=test_env)
            stream += 1
            assert grep_output(stdout, 'Cipher is {}'.format(cipher))

    def test_tls13_chacha20poly1305(self, cmd_tshark, dirs, features, capture_file, test_env):
        '''TLS 1.3 with ChaCha20-Poly1305'''
        key_file = os.path.join(dirs.key_dir, 'tls13-20-chacha20poly1305.keys')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls13-20-chacha20poly1305.pcap'),
                '-o', 'tls.keylog_file: {}'.format(key_file),
                '-q',
                '-z', 'follow,tls,ascii,0',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'TLS13-CHACHA20-POLY1305-SHA256')

    def test_tls13_rfc8446(self, cmd_tshark, dirs, features, capture_file, test_env):
        '''TLS 1.3 (normal session, then early data followed by normal data).'''
        key_file = os.path.join(dirs.key_dir, 'tls13-rfc8446.keys')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls13-rfc8446.pcap'),
                '-otls.keylog_file:{}'.format(key_file),
                '-Y', 'http',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'http.request.uri',
                '-e', 'http.file_data',
                '-E', 'separator=|',
            ), encoding='utf-8', env=test_env)
        first_response = binascii.hexlify(b'Request for /first, version TLSv1.3, Early data: no\n').decode("ascii")
        early_response = binascii.hexlify(b'Request for /early, version TLSv1.3, Early data: yes\n').decode("ascii")
        second_response = binascii.hexlify(b'Request for /second, version TLSv1.3, Early data: yes\n').decode("ascii")
        # assert [
            # r'5|/first|',
            # fr'6||{first_response}',
            # r'8|/early|',
            # fr'10||{early_response}',
            # r'12|/second|',
            # fr'13||{second_response}',
        # ] == stdout.splitlines()

        assert [
            r'5|/first|',
            fr'6|/first|{first_response}',
            r'8|/early|',
            fr'10|/early|{early_response}',
            r'12|/second|',
            fr'13|/second|{second_response}',
        ] == stdout.splitlines()

    def test_tls13_rfc8446_noearly(self, cmd_tshark, dirs, features, capture_file, test_env):
        '''TLS 1.3 (with undecryptable early data).'''
        key_file = os.path.join(dirs.key_dir, 'tls13-rfc8446-noearly.keys')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls13-rfc8446.pcap'),
                '-otls.keylog_file:{}'.format(key_file),
                '-Y', 'http',
                '-Tfields',
                '-e', 'frame.number',
                '-e', 'http.request.uri',
                '-e', 'http.file_data',
                '-E', 'separator=|',
            ), encoding='utf-8', env=test_env)
        first_response = binascii.hexlify(b'Request for /first, version TLSv1.3, Early data: no\n').decode("ascii")
        early_response = binascii.hexlify(b'Request for /early, version TLSv1.3, Early data: yes\n').decode("ascii")
        second_response = binascii.hexlify(b'Request for /second, version TLSv1.3, Early data: yes\n').decode("ascii")
        # assert [
            # r'5|/first|',
            # fr'6||{first_response}',
            # fr'10||{early_response}',
            # r'12|/second|',
            # fr'13||{second_response}',
        # ] == stdout.splitlines()

        assert [
            r'5|/first|',
            fr'6|/first|{first_response}',
            fr'10||{early_response}',
            r'12|/second|',
            fr'13|/second|{second_response}',
        ] == stdout.splitlines()

    def test_tls12_dsb(self, cmd_tshark, capture_file, test_env):
        '''TLS 1.2 with master secrets in pcapng Decryption Secrets Blocks.'''
        output = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls12-dsb.pcapng'),
                '-Tfields',
                '-e', 'http.host',
                '-e', 'http.response.code',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert 'example.com\t\n\t200\nexample.net\t\n\t200\n' == output

    def test_tls_over_tls(self, cmd_tshark, dirs, capture_file, features, test_env):
        '''TLS using the server's private key with p < q
        (test whether libgcrypt is correctly called)'''
        if not features.have_gnutls:
            pytest.skip('Requires GnuTLS.')
        key_file = os.path.join(dirs.key_dir, 'tls-over-tls.key')
        output = subprocess.check_output((cmd_tshark,
                '-r', capture_file('tls-over-tls.pcapng.gz'),
                '-o', 'tls.keys_list:0.0.0.0,443,http,{}'.format(key_file),
                '-z', 'expert,tls.handshake.certificates',
                '-Tfields',
                '-e', 'tls.handshake.certificate_length',
                '-Y', 'tls.handshake.certificates',
            ), encoding='utf-8', env=test_env)
        assert '1152,1115,1352\n1152\n1412,1434,1382\n' == output


class TestDecryptZigbee:
    def test_zigbee(self, cmd_tshark, capture_file, test_env):
        '''ZigBee'''
        # https://gitlab.com/wireshark/wireshark/-/issues/7022
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('sample_control4_2012-03-24.pcap'),
                '-Tfields',
                '-e', 'data.data',
                '-Y', 'zbee_aps',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '3067636338652063342e646d2e747620')


class TestDecryptANSIC122:
    def test_ansi_c1222(self, cmd_tshark, capture_file, test_env):
        '''ANSI C12.22'''
        # https://gitlab.com/wireshark/wireshark/-/issues/9196
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('c1222_std_example8.pcap'),
                '-o', 'c1222.decrypt: TRUE',
                '-o', 'c1222.baseoid: 2.16.124.113620.1.22.0',
                '-Tfields',
                '-e', 'c1222.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '00104d414e55464143545552455220534e2092')


class TestDecryptDVBCI:
    def test_dvb_ci(self, cmd_tshark, capture_file, test_env):
        '''DVB-CI'''
        # simplified version of the sample capture in
        # https://gitlab.com/wireshark/wireshark/-/issues/6700
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('dvb-ci_UV1_0000.pcap'),
                '-o', 'dvb-ci.sek: 00000000000000000000000000000000',
                '-o', 'dvb-ci.siv: 00000000000000000000000000000000',
                '-Tfields',
                '-e', 'dvb-ci.cc.sac.padding',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '800000000000000000000000')


class TestDecryptIPsec:
    def test_ipsec_esp(self, cmd_tshark, capture_file, test_env):
        '''IPsec ESP'''
        # https://gitlab.com/wireshark/wireshark/-/issues/12671
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('esp-bug-12671.pcapng.gz'),
                '-o', 'esp.enable_encryption_decode: TRUE',
                '-Tfields',
                '-e', 'data.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '08090a0b0c0d0e0f1011121314151617')


class TestDecryptIkeIsakmp:
    def test_ikev1_certs(self, cmd_tshark, capture_file, test_env):
        '''IKEv1 (ISAKMP) with certificates'''
        # https://gitlab.com/wireshark/wireshark/-/issues/7951
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev1-certs.pcap'),
                '-Tfields',
                '-e', 'x509sat.printableString',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'OpenSwan')

    def test_ikev1_simultaneous(self, cmd_tshark, capture_file, test_env):
        '''IKEv1 (ISAKMP) simultaneous exchanges'''
        # https://gitlab.com/wireshark/wireshark/-/issues/12610
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev1-bug-12610.pcapng.gz'),
                '-Tfields',
                '-e', 'isakmp.hash',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'b52521f774967402c9f6cee95fd17e5b')

    def test_ikev1_unencrypted(self, cmd_tshark, capture_file, test_env):
        '''IKEv1 (ISAKMP) unencrypted phase 1'''
        # https://gitlab.com/wireshark/wireshark/-/issues/12620
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev1-bug-12620.pcapng.gz'),
                '-Tfields',
                '-e', 'isakmp.hash',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '40043b640f4373250d5ac3a1fb63153c')

    def test_ikev2_3des_sha160(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (3DES-CBC/SHA1_160)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-3des-sha1_160.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '02f7a0d5f1fdc8ea81039818c65bb9bd09af9b8917319b887ff9ba3046c344c7')

    def test_ikev2_aes128_ccm12(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-128-CCM-12) - with CBC-MAC verification'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes128ccm12.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'c2104394299e1ffe7908ea720ad5d13717a0d454e4fa0a2128ea689411f479c4')

    def test_ikev2_aes128_ccm12_2(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-128-CCM-12 using CTR mode, without checksum)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes128ccm12-2.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'aaa281c87b4a19046c57271d557488ca413b57228cb951f5fa9640992a0285b9')

    def test_ikev2_aes192ctr_sha512(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-192-CTR/SHA2-512)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes192ctr.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '3ec23dcf9348485638407c754547aeb3085290082c49f583fdbae59263a20b4a')

    def test_ikev2_aes256cbc_sha256(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-256-CBC/SHA2-256)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256cbc.pcapng'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'e1a8d550064201a7ec024a85758d0673c61c5c510ac13bcd225d6327f50da3d3')

    def test_ikev2_aes256ccm16(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-256-CCM-16)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256ccm16.pcapng'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'fa2e74bdc01e30fb0b3ddc9723c9449095969da51f69e560209d2c2b7940210a')

    def test_ikev2_aes256gcm16(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-256-GCM-16)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256gcm16.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '9ab71f14ab553cad873a1aa70b99df155dee77cdcf3694b3b7527acbb9712ded')

    def test_ikev2_aes256gcm8(self, cmd_tshark, capture_file, test_env):
        '''IKEv2 decryption test (AES-256-GCM-8)'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('ikev2-decrypt-aes256gcm8.pcap'),
                '-Tfields',
                '-e', 'isakmp.auth.data',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '4a66d822d0afbc22ad9a92a2cf4287c920ad8ac3b069a4a7e75fe0a5d499f914')


class TestDecryptHttp2:
    def test_http2(self, cmd_tshark, capture_file, features, test_env):
        '''HTTP2 (HPACK)'''
        if not features.have_nghttp2:
            pytest.skip('Requires nghttp2.')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('packet-h2-14_headers.pcapng'),
                '-Tfields',
                '-e', 'http2.header.value',
                '-d', 'tcp.port==3000,http2',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, 'nghttp2')


class TestDecryptKerberos:
    def test_kerberos(self, cmd_tshark, dirs, features, capture_file, test_env):
        '''Kerberos'''
        # Files are from krb-816.zip on the SampleCaptures page.
        if not features.have_kerberos:
            pytest.skip('Requires kerberos.')
        keytab_file = os.path.join(dirs.key_dir, 'krb-816.keytab')
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('krb-816.pcap.gz'),
                '-o', 'kerberos.decrypt: TRUE',
                '-o', 'kerberos.file: {}'.format(keytab_file),
                '-Tfields',
                '-e', 'kerberos.keyvalue',
            ), encoding='utf-8', env=test_env)
        # keyvalue: ccda7d48219f73c3b28311c4ba7242b3
        assert grep_output(stdout, 'ccda7d48219f73c3b28311c4ba7242b3')


@pytest.fixture
def run_wireguard_test(cmd_tshark, capture_file, result_file, features, test_env):
    def runOne(self, args, keylog=None, pcap_file='wireguard-ping-tcp.pcap'):
        if keylog:
            keylog_file = result_file('wireguard.keys')
            args += ['-owg.keylog_file:%s' % keylog_file]
            with open(keylog_file, 'w') as f:
                f.write("\n".join(keylog))
        stdout = subprocess.check_output([cmd_tshark, '-r', capture_file(pcap_file)] + args, encoding='utf-8', env=test_env)
        return stdout.splitlines()
    return runOne


class TestDecryptWireguard:
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
        assert len(lines) == 4
        assert '1\t%s\tFalse' % self.key_Spub_r in lines
        assert '2\t%s\tFalse' % self.key_Spub_i in lines
        assert '13\t%s\tFalse' % self.key_Spub_r in lines
        assert '14\t%s\tFalse' % self.key_Spub_i in lines

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
        assert len(lines) == 4
        assert '1\t%s\tTrue' % self.key_Spub_r in lines
        assert '2\t%s\tTrue' % self.key_Spub_i in lines
        assert '13\t%s\tTrue' % self.key_Spub_r in lines
        assert '14\t%s\tTrue' % self.key_Spub_i in lines

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
        assert '1\t%s\tFalse\tFalse\t%s' % (self.key_Spub_i, '356537872') in lines
        assert '13\t%s\tFalse\tFalse\t%s' % (self.key_Spub_i, '490514356') in lines

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
        assert '1\tTrue\t%s\t%s' % (self.key_Spub_i, '') in lines
        assert '13\tTrue\t%s\t%s' % (self.key_Spub_i, '') in lines

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
        assert '1\tTrue\t%s\t%s\t\t\t' % (self.key_Spub_i, '356537872') in lines
        assert '2\tFalse\t\t\tTrue\t\t' in lines
        assert '3\t\t\t\t\t8\t' in lines
        assert '4\t\t\t\t\t0\t' in lines
        assert '13\tTrue\t%s\t%s\t\t\t' % (self.key_Spub_i, '490514356') in lines
        assert '14\tFalse\t\t\tTrue\t\t' in lines
        assert '17\t\t\t\t\t\t443' in lines
        assert '18\t\t\t\t\t\t49472' in lines

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
        assert '1\tTrue\t%s\t%s\t\t\t' % (self.key_Spub_i, '356537872') in lines
        assert '2\tFalse\t\t\tTrue\t\t' in lines
        assert '3\t\t\t\t\t8\t' in lines
        assert '4\t\t\t\t\t0\t' in lines
        assert '13\tTrue\t%s\t%s\t\t\t' % (self.key_Spub_i, '490514356') in lines
        assert '14\tFalse\t\t\tTrue\t\t' in lines
        assert '17\t\t\t\t\t\t443' in lines
        assert '18\t\t\t\t\t\t49472' in lines

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
        assert '1\tFalse\t%s\t%s\t\t\t' % (self.key_Spub_i, '356537872') in lines
        assert '2\tTrue\t\t\tTrue\t\t' in lines
        assert '3\t\t\t\t\t8\t' in lines
        assert '4\t\t\t\t\t0\t' in lines
        assert '13\tFalse\t%s\t%s\t\t\t' % (self.key_Spub_i, '490514356') in lines
        assert '14\tTrue\t\t\tTrue\t\t' in lines
        assert '17\t\t\t\t\t\t443' in lines
        assert '18\t\t\t\t\t\t49472' in lines

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
        assert '2\tTrue' in lines
        assert '4\tTrue' in lines

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
        assert '2\tTrue' in lines
        assert '4\tTrue' in lines

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
        assert '2\tFalse' in lines
        assert '4\tFalse' in lines


class TestDecryptKnxip:
    # Capture files for these tests contain single telegrams.
    # For realistic (live captured) KNX/IP telegram sequences, see:
    # https://gitlab.com/wireshark/wireshark/-/issues/14825

    def test_knxip_data_security_decryption_ok(self, cmd_tshark, capture_file, test_env):
        '''KNX/IP: Data Security decryption OK'''
        # capture_file('knxip_DataSec.pcap') contains KNX/IP ConfigReq DataSec PropExtValueWriteCon telegram
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('knxip_DataSec.pcap'),
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, ' DataSec ')
        assert grep_output(stdout, ' PropExtValueWriteCon ')

    def test_knxip_data_security_decryption_fails(self, cmd_tshark, capture_file, test_env):
        '''KNX/IP: Data Security decryption fails'''
        # capture_file('knxip_DataSec.pcap') contains KNX/IP ConfigReq DataSec PropExtValueWriteCon telegram
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('knxip_DataSec.pcap'),
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, ' DataSec ')
        assert not grep_output(stdout, ' PropExtValueWriteCon ')

    def test_knxip_secure_wrapper_decryption_ok(self, cmd_tshark, capture_file, test_env):
        '''KNX/IP: SecureWrapper decryption OK'''
        # capture_file('knxip_SecureWrapper.pcap') contains KNX/IP SecureWrapper RoutingInd telegram
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('knxip_SecureWrapper.pcap'),
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, ' SecureWrapper ')
        assert grep_output(stdout, ' RoutingInd ')

    def test_knxip_secure_wrapper_decryption_fails(self, cmd_tshark, capture_file, test_env):
        '''KNX/IP: SecureWrapper decryption fails'''
        # capture_file('knxip_SecureWrapper.pcap') contains KNX/IP SecureWrapper RoutingInd telegram
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('knxip_SecureWrapper.pcap'),
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, ' SecureWrapper ')
        assert not grep_output(stdout, ' RoutingInd ')

    def test_knxip_timer_notify_authentication_ok(self, cmd_tshark, capture_file, test_env):
        '''KNX/IP: TimerNotify authentication OK'''
        # capture_file('knxip_TimerNotify.pcap') contains KNX/IP TimerNotify telegram
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('knxip_TimerNotify.pcap'),
                '-o', 'kip.key_1:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, ' TimerNotify ')
        assert grep_output(stdout, ' OK$')

    def test_knxip_timer_notify_authentication_fails(self, cmd_tshark, capture_file, test_env):
        '''KNX/IP: TimerNotify authentication fails'''
        # capture_file('knxip_TimerNotify.pcap') contains KNX/IP TimerNotify telegram
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('knxip_TimerNotify.pcap'),
                '-o', 'kip.key_1:""', # "" is really necessary, otherwise test fails
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, ' TimerNotify ')
        assert not grep_output(stdout, ' OK$')

    def test_knxip_keyring_xml_import(self, cmd_tshark, dirs, capture_file, test_env):
        '''KNX/IP: keyring.xml import'''
        # key_file "keyring.xml" contains KNX decryption keys
        key_file = os.path.join(dirs.key_dir, 'knx_keyring.xml')
        # capture_file('empty.pcap') is empty
        # Write extracted key info to stdout
        stdout = subprocess.check_output((cmd_tshark,
                '-o', 'kip.key_file:' + key_file,
                '-o', 'kip.key_info_file:-',
                '-r', capture_file('empty.pcap'),
            ), encoding='utf-8', env=test_env)
        assert grep_output(stdout, '^MCA 224[.]0[.]23[.]12 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$')
        assert grep_output(stdout, '^GA 1/7/131 sender 1[.]1[.]1$')
        assert grep_output(stdout, '^GA 1/7/131 sender 1[.]1[.]3$')
        assert grep_output(stdout, '^GA 1/7/131 sender 1[.]1[.]4$')
        assert grep_output(stdout, '^GA 1/7/132 sender 1[.]1[.]2$')
        assert grep_output(stdout, '^GA 1/7/132 sender 1[.]1[.]4$')
        assert grep_output(stdout, '^GA 6/7/191 sender 1[.]1[.]1$')
        assert grep_output(stdout, '^GA 0/1/0 sender 1[.]1[.]1$')
        assert grep_output(stdout, '^GA 0/1/0 sender 1[.]1[.]3$')
        assert grep_output(stdout, '^GA 0/1/0 sender 1[.]1[.]4$')
        assert grep_output(stdout, '^GA 0/1/0 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$')
        assert grep_output(stdout, '^GA 1/7/131 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$')
        assert grep_output(stdout, '^GA 1/7/132 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$')
        assert grep_output(stdout, '^GA 6/7/191 key A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF$')
        assert grep_output(stdout, '^IA 1[.]1[.]1 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$')
        assert grep_output(stdout, '^IA 1[.]1[.]1 SeqNr 45678$')
        assert grep_output(stdout, '^IA 1[.]1[.]2 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$')
        assert grep_output(stdout, '^IA 1[.]1[.]2 SeqNr 34567$')
        assert grep_output(stdout, '^IA 1[.]1[.]3 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$')
        assert grep_output(stdout, '^IA 1[.]1[.]3 SeqNr 23456$')
        assert grep_output(stdout, '^IA 1[.]1[.]4 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$')
        assert grep_output(stdout, '^IA 1[.]1[.]4 SeqNr 12345$')
        assert grep_output(stdout, '^IA 2[.]1[.]0 key B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF$')
        assert grep_output(stdout, '^IA 2[.]1[.]0 SeqNr 1234$')


@pytest.fixture(scope='session')
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
        pytest.skip('SoftHSM is not found')
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
        # Look in a variety of paths, Debian/Ubuntu, Fedora, RHEL/CentOS
        madir = sysconfig.get_config_var('multiarchsubdir')
        libdir_archs = (libdir, libdir + '64')
        libdir_subs = ('softhsm', 'pkcs11', '')
        libdirs = [os.path.join(libdir + madir, 'softhsm')] if madir else []
        libdirs += [os.path.join(arch, sub) for sub in libdir_subs for arch in libdir_archs]
        name = 'libsofthsm2.so'
    for libdir in libdirs:
        provider = os.path.join(libdir, name)
        if os.path.exists(provider):
            break
    else:
        # Even if p11-kit can automatically locate it, do not rely on it.
        pytest.skip('SoftHSM provider library not detected')
    # Now check whether the import tool is usable. SoftHSM < 2.3.0 did not
    # set CKA_DECRYPT when using softhsm2-tool --import and therefore cannot be
    # used to import keys for decryption. Use GnuTLS p11tool as workaround.
    softhsm_version = subprocess.check_output([softhsm_tool, '--version'],
            universal_newlines=True).strip()
    use_p11tool = softhsm_version in ('2.0.0', '2.1.0', '2.2.0')
    if use_p11tool and not shutil.which('p11tool'):
        pytest.skip('SoftHSM available, but GnuTLS p11tool is unavailable')
    return use_p11tool, softhsm_tool, provider


@pytest.fixture
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


class TestDecryptPkcs11:
    def test_tls_pkcs11(self, cmd_tshark, dirs, capture_file, features, softhsm, test_env):
        '''Check that a RSA key in a PKCS #11 token enables decryption.'''
        if not features.have_pkcs11:
            pytest.skip('Requires GnuTLS with PKCS #11 support.')
        key_file = os.path.join(dirs.key_dir, 'rsa-p-lt-q.p8')
        key_uri = softhsm.import_key(key_file)
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture_file('rsa-p-lt-q.pcap'),
                '-o', 'uat:pkcs11_libs:"{}"'.format(softhsm.provider.replace('\\', '\\x5c')),
                '-o', 'uat:rsa_keys:"{}","{}"'.format(key_uri, softhsm.pin),
                '-Tfields',
                '-e', 'http.request.uri',
                '-Y', 'http',
            ), encoding='utf-8', env=test_env)
        assert '/' in stdout

class TestDecryptSmb2:
    BAD_KEY = 'ffffffffffffffffffffffffffffffff'

    @staticmethod
    def check_bad_key(cmd_tshark, cap, disp_filter, sesid, seskey, s2ckey, c2skey, env=None):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', cap,
                '-o', 'uat:smb2_seskey_list:{},{},{},{}'.format(sesid, seskey, s2ckey, c2skey),
                '-Y', disp_filter,
        ), encoding='utf-8', env=env)
        assert 'Encrypted SMB' in stdout

    #
    # SMB3.0 CCM bad keys tests
    #
    def test_smb300_bad_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that a bad session key doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', self.BAD_KEY, '""', '""', env=test_env)

    def test_smb300_bad_s2ckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that a bad s2c key doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', '""', self.BAD_KEY, '""', env=test_env)

    def test_smb300_bad_c2skey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that a bad c2s key doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', '""', '""', self.BAD_KEY, env=test_env)

    def test_smb300_bad_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that bad decryption keys doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', '""', self.BAD_KEY, self.BAD_KEY, env=test_env)

    def test_smb300_bad_allkey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that all bad keys doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '1900009c003c0000', self.BAD_KEY, self.BAD_KEY, self.BAD_KEY, env=test_env)

    #
    # SMB3.1.1 CCM bad key tests
    #
    def test_smb311_bad_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that a bad session key doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', self.BAD_KEY, '""', '""', env=test_env)

    def test_smb311_bad_s2ckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that a bad s2c key doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', '""', self.BAD_KEY, '""', env=test_env)

    def test_smb311_bad_c2skey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that a bad c2s key doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', '""', '""', self.BAD_KEY, env=test_env)

    def test_smb311_bad_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that bad decryption keys doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', '""', self.BAD_KEY, self.BAD_KEY, env=test_env)

    def test_smb311_bad_allkey(self, features, cmd_tshark, capture_file, test_env):
        '''Check that all bad keys doesn't crash'''
        TestDecryptSmb2.check_bad_key(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                           'frame.number == 7', '2900009c003c0000', self.BAD_KEY, self.BAD_KEY, self.BAD_KEY, env=test_env)

    #
    # Decryption tests
    #

    def check_tree(cmd_tshark, cap, tree, sesid, seskey, s2ckey, c2skey, env=None):
        stdout = subprocess.check_output((cmd_tshark,
                '-r', cap,
                '-o', 'uat:smb2_seskey_list:{},{},{},{}'.format(sesid, seskey, s2ckey, c2skey),
                '-Tfields',
                '-e', 'smb2.tree',
                '-Y', 'smb2.tree == "{}"'.format(tree.replace('\\', '\\\\')),
        ), encoding='unicode_escape', env=env)
        # Remove the escapes (we only have one field so this causes no issue)
        assert tree == stdout.strip()

    # SMB3.0 CCM
    def test_smb300_aes128ccm_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.0 AES128CCM decryption with session key.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '1900009c003c0000',
                        '9a9ea16a0cdbeb6064772318073f172f', '""', '""', env=test_env)

    def test_smb300_aes128ccm_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.0 AES128CCM decryption with decryption keys.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb300-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '1900009c003c0000',
                        '""', '8be6cc53d4beba29387e69aef035d497','bff985870e81784d533fdc09497b8eab', env=test_env)


    # SMB3.1.1 AES-CCM-128
    def test_smb311_aes128ccm_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128CCM decryption with session key.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '2900009c003c0000',
                        'f1fa528d3cd182cca67bd4596dabd885', '""', '""', env=test_env)

    def test_smb311_aes128ccm_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128CCM decryption with decryption keys.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-128-ccm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '2900009c003c0000',
                        '""', '763d5552dbc9650b700869467a5857e4', '35e69833c6578e438c8701cb40bf483e', env=test_env)

    # SMB3.1.1 AES-GCM-128
    def test_smb311_aes128gcm_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128GCM decryption with session key.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-128-gcm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                        'e79161ded03bda1449b2c8e58f753953', '""', '""', env=test_env)

    def test_smb311_aes128gcm_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128GCM decryption with decryption keys.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-128-gcm.pcap.gz'),
                        r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                        '""', 'b02f5de25e0562075c3dc329fa2aa396', '7201623a31754e6581864581209dd3d2', env=test_env)

    # SMB3.1.1 AES-CCM-256
    def test_smb311_aes256ccm_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES256CCM decryption with session key.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-256-ccm.pcap.gz'),
                        r'\\172.31.9.163\IPC$', 'd6fdb96d00000000',
                        '6b559c2e60519e344581d086a6d3d050',
                        '""',
                        '""', env=test_env)

    def test_smb311_aes256ccm_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES256CCM decryption with decryption keys.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-256-ccm.pcap.gz'),
                        r'\\172.31.9.163\IPC$', 'd6fdb96d00000000',
                        '""',
                        '014fccd4a53554bf5b54b27a32512b35fca262b90e088a5efa7d6c952418578b',
                        '1d34170138a77dac4abbe0149253c8b977a71f399081cda6cbaf62359670c1c5', env=test_env)

    # SMB3.1.1 AES-GCM-256
    def test_smb311_aes256gcm_seskey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES256GCM decryption with session key.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-256-gcm.pcap.gz'),
                        r'\\172.31.9.163\IPC$', '56dc03ab00000000',
                        '6a5004adfbdef1abd5879800675324e5',
                        '""',
                        '""', env=test_env)

    def test_smb311_aes256gcm_deckey(self, features, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES256GCM decryption with decryption keys.'''
        TestDecryptSmb2.check_tree(cmd_tshark, capture_file('smb311-aes-256-gcm.pcap.gz'),
                        r'\\172.31.9.163\IPC$', '56dc03ab00000000',
                        '""',
                        '46b64f320a0f856b63b3a0dc2c058a67267830a8cbdd44a088fbf1d0308a981f',
                        '484c30bf3e17e322e0d217764d4584a325ec0495519c3f1547e0f996ab76c4c4', env=test_env)

    def check_partial(home_path, cmd_tshark, full_cap, pkt_skip, tree, sesid, s2ckey, c2skey, env=None):
        # generate a trace without NegProt and SessionSetup
        partial_cap = os.path.join(home_path, 'short.pcap')
        stdout = subprocess.check_output((cmd_tshark,
                        '-r', full_cap,
                        '-Y', 'frame.number >= %d'%pkt_skip,
                        '-w', partial_cap,
        ), encoding='utf-8', env=env)
        TestDecryptSmb2.check_tree(cmd_tshark, partial_cap, tree, sesid, '""', s2ckey, c2skey)

    def test_smb311_aes128gcm_partial(self, features, home_path, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128GCM decryption in capture missing session setup'''
        TestDecryptSmb2.check_partial(home_path, cmd_tshark,
                           capture_file('smb311-aes-128-gcm.pcap.gz'), 7,
                           r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                           'b02f5de25e0562075c3dc329fa2aa396', '7201623a31754e6581864581209dd3d2', env=test_env)

    def test_smb311_aes128gcm_partial_keyswap(self, features, home_path, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128GCM decryption in capture missing session setup with keys in wrong order'''
        TestDecryptSmb2.check_partial(home_path, cmd_tshark,
                           capture_file('smb311-aes-128-gcm.pcap.gz'), 7,
                           r'\\dfsroot1.foo.test\IPC$', '3900000000400000',
                           '7201623a31754e6581864581209dd3d2', 'b02f5de25e0562075c3dc329fa2aa396', env=test_env)

    def test_smb311_aes256gcm_partial(self, features, home_path, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES128GCM decryption in capture missing session setup'''
        TestDecryptSmb2.check_partial(home_path, cmd_tshark,
                           capture_file('smb311-aes-256-gcm.pcap.gz'), 7,
                           r'\\172.31.9.163\IPC$', '56dc03ab00000000',
                           '46b64f320a0f856b63b3a0dc2c058a67267830a8cbdd44a088fbf1d0308a981f',
                           '484c30bf3e17e322e0d217764d4584a325ec0495519c3f1547e0f996ab76c4c4', env=test_env)

    def test_smb311_aes256gcm_partial_keyswap(self, features, home_path, cmd_tshark, capture_file, test_env):
        '''Check SMB 3.1.1 AES256GCM decryption in capture missing session setup with keys in wrong order'''
        TestDecryptSmb2.check_partial(home_path, cmd_tshark,
                           capture_file('smb311-aes-256-gcm.pcap.gz'), 7,
                           r'\\172.31.9.163\IPC$', '56dc03ab00000000',
                           '484c30bf3e17e322e0d217764d4584a325ec0495519c3f1547e0f996ab76c4c4',
                           '46b64f320a0f856b63b3a0dc2c058a67267830a8cbdd44a088fbf1d0308a981f', env=test_env)
