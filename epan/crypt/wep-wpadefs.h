/*
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __WEP_WPADEFS_H__
#define __WEP_WPADEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

/** @file
 * WEP and WPA definitions
 *
 * Copied from airpcap.h.
 */

/**
 * Maximum number of encryption keys.  This determines the size of
 * structures in packet-ieee80211.c, as well as the number of keys
 * in the IEEE 802.11 preferences.
 */
#define MAX_ENCRYPTION_KEYS 64

/**
 * Maximum size of a WEP key, in bytes. This is the size of an entry in the
 * AirpcapWepKeysCollection structure.
 */
#define WEP_KEY_MAX_SIZE 32

/**
 * WEP_KEY_MAX_SIZE is in bytes, but each byte is represented as a
 * hexadecimal string.
 */
#define WEP_KEY_MAX_CHAR_SIZE (WEP_KEY_MAX_SIZE*2)

/**
 * WEP_KEY_MAX_SIZE is in bytes, this is in bits...
 */
#define WEP_KEY_MAX_BIT_SIZE (WEP_KEY_MAX_SIZE*8)

#define WEP_KEY_MIN_CHAR_SIZE 2
#define WEP_KEY_MIN_BIT_SIZE  8

/**
 * WPA key sizes.
 */
#define WPA_KEY_MAX_SIZE 63 /* 63 chars followed by a '\0' */

#define WPA_KEY_MAX_CHAR_SIZE (WPA_KEY_MAX_SIZE*1)
#define WPA_KEY_MAX_BIT_SIZE  (WPA_KEY_MAX_SIZE*8)
#define WPA_KEY_MIN_CHAR_SIZE 8
#define WPA_KEY_MIN_BIT_SIZE  (WPA_KEY_MIN_CHAR_SIZE*8)

/**
 * SSID sizes
 */
#define WPA_SSID_MAX_SIZE 32

#define WPA_SSID_MAX_CHAR_SIZE (WPA_SSID_MAX_SIZE*1)
#define WPA_SSID_MAX_BIT_SIZE  (WPA_SSID_MAX_SIZE*8)
#define WPA_SSID_MIN_CHAR_SIZE 0
#define WPA_SSID_MIN_BIT_SIZE  (WPA_SSID_MIN_CHAR_SIZE*8)

/**
 * Let the user enter a raw PSK along with a passphrase + SSID
 */
#define WPA_PSK_KEY_SIZE 32 /* Fixed size, 32 bytes (256bit) */
#define WPA_PSK_KEY_CHAR_SIZE (WPA_PSK_KEY_SIZE*2)
#define WPA_PSK_KEY_BIT_SIZE  (WPA_PSK_KEY_SIZE*8)

/**
 * Prefix definitions for preferences
 */
#define STRING_KEY_TYPE_WEP "wep"
#define STRING_KEY_TYPE_WPA_PWD "wpa-pwd"
#define STRING_KEY_TYPE_WPA_PSK "wpa-psk"

#ifdef __cplusplus
}
#endif

#endif /* __WEP_WPADEFS_H__  */
