/* int-64bit.h
 * Handling of 64-bit integers 
 *
 * $Id: int-64bit.h,v 1.2 2001/10/29 21:53:58 guy Exp $
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
char *u64toa(const unsigned char *u64ptr);
unsigned char *atou64(const char *u64str, unsigned char *u64int);
char *u64toh(const unsigned char *u64ptr);
unsigned char *htou64(const char *u64str, unsigned char *u64int);


#endif

