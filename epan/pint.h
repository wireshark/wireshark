/* pint.h
 * Definitions for extracting and translating integers safely and portably
 * via pointers.
 *
 * $Id: pint.h,v 1.3 2000/11/11 10:23:43 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PINT_H__
#define __PINT_H__

#include <glib.h>

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 *
 * If G_HAVE_GINT64 is defined, so we can use "gint64" and "guint64" to
 * refer to 64-bit integral quantities, we also provide pntohll and
 * phtolell, which extract 64-bit integral quantities.
 */

#define pntohs(p)   ((guint16)                       \
                     ((guint16)*((guint8 *)(p)+0)<<8|  \
                      (guint16)*((guint8 *)(p)+1)<<0))

#define pntoh24(p)  ((guint32)*((guint8 *)(p)+0)<<16|  \
                     (guint32)*((guint8 *)(p)+1)<<8|  \
                     (guint32)*((guint8 *)(p)+2)<<0)

#define pntohl(p)   ((guint32)*((guint8 *)(p)+0)<<24|  \
                     (guint32)*((guint8 *)(p)+1)<<16|  \
                     (guint32)*((guint8 *)(p)+2)<<8|   \
                     (guint32)*((guint8 *)(p)+3)<<0)

#ifdef G_HAVE_GINT64
#define pntohll(p)  ((guint64)*((guint8 *)(p)+0)<<56|  \
                     (guint64)*((guint8 *)(p)+1)<<48|  \
                     (guint64)*((guint8 *)(p)+2)<<40|  \
                     (guint64)*((guint8 *)(p)+3)<<32|  \
                     (guint64)*((guint8 *)(p)+4)<<24|  \
                     (guint64)*((guint8 *)(p)+5)<<16|  \
                     (guint64)*((guint8 *)(p)+6)<<8|   \
                     (guint64)*((guint8 *)(p)+7)<<0)
#endif

#define pletohs(p)  ((guint16)                       \
                     ((guint16)*((guint8 *)(p)+1)<<8|  \
                      (guint16)*((guint8 *)(p)+0)<<0))

#define pletoh24(p) ((guint32)*((guint8 *)(p)+2)<<16|  \
                     (guint32)*((guint8 *)(p)+1)<<8|  \
                     (guint32)*((guint8 *)(p)+0)<<0)

#define pletohl(p)  ((guint32)*((guint8 *)(p)+3)<<24|  \
                     (guint32)*((guint8 *)(p)+2)<<16|  \
                     (guint32)*((guint8 *)(p)+1)<<8|   \
                     (guint32)*((guint8 *)(p)+0)<<0)

#ifdef G_HAVE_GINT64
#define pletohll(p) ((guint64)*((guint8 *)(p)+7)<<56|  \
                     (guint64)*((guint8 *)(p)+6)<<48|  \
                     (guint64)*((guint8 *)(p)+5)<<40|  \
                     (guint64)*((guint8 *)(p)+4)<<32|  \
                     (guint64)*((guint8 *)(p)+3)<<24|  \
                     (guint64)*((guint8 *)(p)+2)<<16|  \
                     (guint64)*((guint8 *)(p)+1)<<8|   \
                     (guint64)*((guint8 *)(p)+0)<<0)
#endif

	
/* Macros to byte-swap 32-bit and 16-bit quantities. */
#define	BSWAP32(x) \
	((((x)&0xFF000000)>>24) | \
	 (((x)&0x00FF0000)>>8) | \
	 (((x)&0x0000FF00)<<8) | \
	 (((x)&0x000000FF)<<24))
#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))

/* Turn host-byte-order values into little-endian values. */
#ifdef WORDS_BIGENDIAN
#define htoles(s) ((guint16)                       \
                    ((guint16)((s) & 0x00FF)<<8|  \
                     (guint16)((s) & 0xFF00)>>8))

#define htolel(l) ((guint32)((l) & 0x000000FF)<<24|  \
                   (guint32)((l) & 0x0000FF00)<<8|  \
                   (guint32)((l) & 0x00FF0000)>>8|   \
                   (guint32)((l) & 0xFF000000)>>24)
#else
#define htoles(s)	(s)
#define htolel(l)	(l)
#endif

#endif /* PINT_H */
