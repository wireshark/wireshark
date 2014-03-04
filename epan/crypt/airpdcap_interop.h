/* airpdcap_interop.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_AIRPDCAP_INTEROP_H
#define	_AIRPDCAP_INTEROP_H

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

#ifdef _WIN32
#include <winsock2.h>  /* ntohs() */
#endif

#ifndef	ntohs
#undef     ntohs
#define	ntohs(value)	g_ntohs(value)
#endif

#endif /* _AIRPDCAP_INTEROP_H */
