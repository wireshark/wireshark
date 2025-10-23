/** @file
 * Compute the Adler32 checksum (RFC 1950)
 * 2003 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ADLER32_H
#define ADLER32_H

#include <wireshark.h>

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Updates an existing Adler-32 checksum with new data.
 *
 * Computes the Adler-32 checksum of the given buffer and updates the provided
 * checksum value. This allows incremental checksum computation across multiple buffers.
 *
 * @param adler The current Adler-32 checksum value.
 * @param buf Pointer to the data buffer.
 * @param len Length of the buffer in bytes.
 * @return Updated Adler-32 checksum.
 */
WS_DLL_PUBLIC uint32_t update_adler32(uint32_t adler, const uint8_t *buf, size_t len);

/**
 * @brief Computes the Adler-32 checksum of a byte array.
 *
 * Calculates the Adler-32 checksum for the entire buffer in one pass.
 *
 * @param buf Pointer to the byte array.
 * @param len Length of the array in bytes.
 * @return Adler-32 checksum of the buffer.
 */
WS_DLL_PUBLIC uint32_t adler32_bytes(const uint8_t *buf, size_t len);

/**
 * @brief Computes the Adler-32 checksum of a C string.
 *
 * Calculates the Adler-32 checksum for a NUL-terminated string.
 *
 * @param buf Pointer to the input string.
 * @return Adler-32 checksum of the string.
 */
WS_DLL_PUBLIC uint32_t adler32_str(const char *buf);

#ifdef __cplusplus
}
#endif

#endif  /* ADLER32_H */

