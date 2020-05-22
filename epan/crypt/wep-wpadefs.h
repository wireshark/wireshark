/* wap-wpadefs.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
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
 * Prefix definitions for preferences
 */
#define STRING_KEY_TYPE_WEP "wep"
#define STRING_KEY_TYPE_WPA_PWD "wpa-pwd"
#define STRING_KEY_TYPE_WPA_PSK "wpa-psk"
#define STRING_KEY_TYPE_TK "tk"

#ifdef __cplusplus
}
#endif

#endif /* __WEP_WPADEFS_H__  */
