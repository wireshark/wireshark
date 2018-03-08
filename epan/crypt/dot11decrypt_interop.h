/* dot11decrypt_interop.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef	_DOT11DECRYPT_INTEROP_H
#define	_DOT11DECRYPT_INTEROP_H

/**
 * Cast data types commonly used (e.g. UINT16) to their
 * GLib equivalents.
 */

#include <glib.h>
#include <string.h>

#ifndef	INT
typedef	gint	INT;
#endif

#ifndef	UINT
typedef	guint	UINT;
#endif

#ifndef	UINT8
typedef	guint8	UINT8;
#endif

#ifndef	UINT16
typedef	guint16	UINT16;
#endif

#ifndef	UINT32
typedef	guint32	UINT32;
#endif

#ifndef	UINT64
typedef	guint64	UINT64;
#endif

#ifndef	USHORT
typedef	gushort	USHORT;
#endif

#ifndef	ULONG
typedef	gulong	ULONG;
#endif

#ifndef	ULONGLONG
typedef	guint64	ULONGLONG;
#endif

#ifndef	CHAR
typedef	gchar	CHAR;
#endif

#ifndef	UCHAR
typedef guchar	UCHAR;
#endif

#endif /* _DOT11DECRYPT_INTEROP_H */
