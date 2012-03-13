/* crc32.h
 * Declaration of CRC-32 routine and table
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __CRC32_H__
#define __CRC32_H__

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

/** Lookup the crc value in the crc32_ccitt_table
 @param pos Position in the table. */
extern guint32 crc32_ccitt_table_lookup (guchar pos);

/** Lookup the crc value in the crc32c_table
 @param pos Position in the table. */
extern guint32 crc32c_table_lookup (guchar pos);

/** Compute CRC32C checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param crc The preload value for the CRC32C computation.
 @return The CRC32C checksum. */
extern guint32 crc32c_calculate(const void *buf, int len, guint32 crc);

/** Compute CRC32C checksum of a buffer of data without swapping seed crc
 or completed checksum
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param crc The preload value for the CRC32C computation.
 @return The CRC32C checksum. */
extern guint32 crc32c_calculate_no_swap(const void *buf, int len, guint32 crc);

/** Compute CRC32 CCITT checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
extern guint32 crc32_ccitt(const guint8 *buf, guint len);

/** Compute CRC32 CCITT checksum of a buffer of data.  If computing the
 *  checksum over multiple buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
extern guint32 crc32_ccitt_seed(const guint8 *buf, guint len, guint32 seed);

/** Compute MPEG-2 CRC32 checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 MPEG-2 checksum (using the given seed). */
extern guint32 crc32_mpeg2_seed(const guint8 *buf, guint len, guint32 seed);

int AirPDcapWepDecrypt(
	const guchar *seed,
	const size_t seed_len,
	guchar *cypher_text,
	const size_t data_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc32.h */
