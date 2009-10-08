/* crc32.h
 * Declaration of CRC-32 routine and table
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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

#ifndef __CRC32_H_
#define __CRC32_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRC32C_PRELOAD 0xffffffff

/*
 * Byte swap fix contributed by Dave Wysochanski <davidw@netapp.com>.
 */
#define CRC32C_SWAP(crc32c_value)				\
	(((crc32c_value & 0xff000000) >> 24)	|	\
	 ((crc32c_value & 0x00ff0000) >>  8)	|	\
	 ((crc32c_value & 0x0000ff00) <<  8)	|	\
	 ((crc32c_value & 0x000000ff) << 24))

#define CRC32C(c,d) (c=(c>>8)^crc32c_table[(c^(d))&0xFF])

extern const guint32 crc32c_table[256];

/** Compute CRC32C checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param crc The preload value for the CRC32C computation.
 @return The CRC32C checksum. */
extern guint32 crc32c_calculate(const void *buf, int len, guint32 crc);

extern const guint32 crc32_ccitt_table[256];

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

/** Compute CRC32 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
extern guint32 crc32_ccitt_tvb(tvbuff_t *tvb, guint len);

/** Compute CRC32 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
extern guint32 crc32_ccitt_tvb_offset(tvbuff_t *tvb, guint offset, guint len);

/** Compute CRC32 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
extern guint32 crc32_ccitt_tvb_seed(tvbuff_t *tvb, guint len, guint32 seed);

/** Compute CRC32 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
extern guint32 crc32_ccitt_tvb_offset_seed(tvbuff_t *tvb, guint offset,
                                           guint len, guint32 seed);

/** Compute IEEE 802.x CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The IEEE 802.x CRC32 checksum. */
extern guint32 crc32_802_tvb(tvbuff_t *tvb, guint len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc32.h */
