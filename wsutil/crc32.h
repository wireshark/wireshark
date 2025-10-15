/** @file
 * Declaration of CRC-32 routine and table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC32_H__
#define __CRC32_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRC32_CCITT_SEED 0xFFFFFFFF
#define CRC32C_PRELOAD   0xffffffff
#define CRC32_MPEG2_SEED 0xFFFFFFFF

/*
 * Byte swap fix contributed by Dave Wysochanski <davidw@netapp.com>.
 */
#define CRC32C_SWAP(crc32c_value)				\
	(((crc32c_value & 0xff000000) >> 24)	|	\
	 ((crc32c_value & 0x00ff0000) >>  8)	|	\
	 ((crc32c_value & 0x0000ff00) <<  8)	|	\
	 ((crc32c_value & 0x000000ff) << 24))

/**
 * @brief Lookup a CRC-32/CCITT table value by position.
 *
 * Retrieves the precomputed CRC value from the `crc32_ccitt_table` at the specified
 * position. This table is typically used to accelerate CRC-32/CCITT calculations
 * by avoiding repeated polynomial division.
 *
 * @param pos  Index into the CRC-32/CCITT lookup table (0–255).
 * @return     CRC value corresponding to the given position.
 */
WS_DLL_PUBLIC uint32_t crc32_ccitt_table_lookup (unsigned char pos);

/** Lookup the crc value in the crc32c_table
 @param pos Position in the table. */
WS_DLL_PUBLIC uint32_t crc32c_table_lookup (unsigned char pos);

/**
 @brief Compute CRC32C checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param crc The preload value for the CRC32C computation.
 @return The CRC32C checksum. */
WS_DLL_PUBLIC uint32_t crc32c_calculate(const void *buf, int len, uint32_t crc);

/**
 @brief Compute CRC32C checksum of a buffer of data without swapping seed crc
 or completed checksum
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param crc The preload value for the CRC32C computation.
 @return The CRC32C checksum. */
WS_DLL_PUBLIC uint32_t crc32c_calculate_no_swap(const void *buf, int len, uint32_t crc);

/**
 @brief Compute CRC32 CCITT checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
WS_DLL_PUBLIC uint32_t crc32_ccitt(const uint8_t *buf, unsigned len);

/**
 @brief Compute CRC32 CCITT checksum of a buffer of data.
 *
 * If computing the checksum over multiple buffers and you want to feed the partial CRC32
 * back in, remember to take the 1's complement of the partial CRC32 first.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32_ccitt_seed(const uint8_t *buf, unsigned len, uint32_t seed);

/**
 @brief Compute MPEG-2 CRC32 checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 MPEG-2 checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32_mpeg2_seed(const uint8_t *buf, unsigned len, uint32_t seed);

/**
 * @brief Computes CRC32 checksum for the given data with the polynom 0x0AA725CF using
 *  precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC32 checksum for the buffer
 */
WS_DLL_PUBLIC uint32_t crc32_0x0AA725CF_seed(const uint8_t *buf, unsigned len, uint32_t seed);

/**
 * @brief Computes CRC32 checksum for the given data with the polynom 0x5D6DCB using
 *  precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC32 checksum for the buffer
 */
WS_DLL_PUBLIC uint32_t crc32_0x5D6DCB_seed(const uint8_t *buf, unsigned len, uint32_t seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc32.h */
