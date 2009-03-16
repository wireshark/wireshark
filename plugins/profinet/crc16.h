/*
 *      crc16.h
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2. See the file COPYING for more details.
 */
 
/* This code is directly based on linux code lib/crc16.c / .h (GPL V2 ONLY!)
 * $Id$
 */


/**
 * crc16 - compute the CRC-16 for the data buffer
 * @crc:        previous CRC value
 * @buffer:     data pointer
 * @len:        number of bytes in the buffer
 *
 * Returns the updated CRC value.
 */
extern guint16 crc16(guint16 crc, guint8 const *buffer, size_t len);
