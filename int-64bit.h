/* int-64bit.h
 * Handling of 64-bit integers 
 *
 * $Id: int-64bit.h,v 1.3 2001/11/02 10:09:47 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _INT_64BIT_H_
#define _INT_64BIT_H_

/*
 * Routines to convert between 64-bit integers, represented as
 * arrays of 8 bytes in network byte order (bit-endian), and ASCII strings
 * giving integer values in decimal or hexadecimal.
 */

/*
 * Convert an unsigned 64-bit integer into a string, in decimal.
 */
extern char *u64toa(const unsigned char *u64ptr);

/*
 * Convert a signed 64-bit integer into a string, in decimal.
 */
extern char *i64toa(const unsigned char *i64ptr);

/*
 * Convert a string to an unsigned 64-bit integer.
 */
unsigned char *atou64(const char *u64str, unsigned char *u64int);

/*
 * Convert a string to a signed 64-bit integer.
 */
unsigned char *atoi64(const char *i64str, unsigned char *i64int);

/*
 * Convert an unsigned 64-bit integer to a string, in hex.
 */
char *u64toh(const unsigned char *u64ptr);

/*
 * Convert a hex string to an unsigned 64-bit integer.
 */
unsigned char *htou64(const char *u64str, unsigned char *u64int);

#endif

