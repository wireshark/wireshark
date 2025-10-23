/** @file
 *
 * Definitions for routines for u-law, A-law and linear PCM conversions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __G711_H__
#define __G711_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Converts a 16-bit linear PCM value to 8-bit A-law encoded format.
 *
 * Encodes a signed 16-bit linear PCM value into an 8-bit A-law value,
 * commonly used in telephony systems to compress audio data.
 *
 * @param pcm_val The 16-bit linear PCM value to encode.
 * @return The corresponding 8-bit A-law encoded value.
 */
WS_DLL_PUBLIC unsigned char linear2alaw(int pcm_val);

/**
 * @brief Converts an 8-bit A-law encoded value to a 16-bit linear PCM value.
 *
 * Decodes an 8-bit A-law value back into a signed 16-bit linear PCM value.
 *
 * @param a_val The 8-bit A-law encoded value.
 * @return The corresponding 16-bit linear PCM value.
 */
WS_DLL_PUBLIC int alaw2linear(unsigned char a_val);

/**
 * @brief Converts a 16-bit linear PCM value to u-law encoded format.
 *
 * Encodes a signed 16-bit linear PCM value into an 8-bit u-law value,
 * used in North American and Japanese telephony systems for audio compression.
 *
 * @param pcm_val The 16-bit linear PCM value to encode.
 * @return The corresponding 8-bit u-law encoded value.
 */
WS_DLL_PUBLIC unsigned char linear2ulaw(int pcm_val);

/**
 * @brief Converts a u-law encoded value to a 16-bit linear PCM value.
 *
 * Decodes an 8-bit u-law value back into a signed 16-bit linear PCM value.
 *
 * @param u_val The 8-bit u-law encoded value.
 * @return The corresponding 16-bit linear PCM value.
 */
WS_DLL_PUBLIC int ulaw2linear(unsigned char u_val);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __G711_H__ */
