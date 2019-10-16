/* pint.h
 * Definitions for extracting and translating integers safely and portably
 * via pointers.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PINT_H__
#define __PINT_H__

#include <glib.h>

/* Routines that take a possibly-unaligned pointer to a 16-bit, 24-bit,
 * 32-bit, 40-bit, ... 64-bit integral quantity, in a particular byte
 * order, and fetch the value and return it in host byte order.
 *
 * The pntohN() routines fetch big-endian values; the pletohN() routines
 * fetch little-endian values.
 */

static inline guint16 pntoh16(const void *p)
{
    return (guint16)*((const guint8 *)(p)+0)<<8|
           (guint16)*((const guint8 *)(p)+1)<<0;
}

static inline guint32 pntoh24(const void *p)
{
    return (guint32)*((const guint8 *)(p)+0)<<16|
           (guint32)*((const guint8 *)(p)+1)<<8|
           (guint32)*((const guint8 *)(p)+2)<<0;
}

static inline guint32 pntoh32(const void *p)
{
    return (guint32)*((const guint8 *)(p)+0)<<24|
           (guint32)*((const guint8 *)(p)+1)<<16|
           (guint32)*((const guint8 *)(p)+2)<<8|
           (guint32)*((const guint8 *)(p)+3)<<0;
}

static inline guint64 pntoh40(const void *p)
{
    return (guint64)*((const guint8 *)(p)+0)<<32|
           (guint64)*((const guint8 *)(p)+1)<<24|
           (guint64)*((const guint8 *)(p)+2)<<16|
           (guint64)*((const guint8 *)(p)+3)<<8|
           (guint64)*((const guint8 *)(p)+4)<<0;
}

static inline guint64 pntoh48(const void *p)
{
    return (guint64)*((const guint8 *)(p)+0)<<40|
           (guint64)*((const guint8 *)(p)+1)<<32|
           (guint64)*((const guint8 *)(p)+2)<<24|
           (guint64)*((const guint8 *)(p)+3)<<16|
           (guint64)*((const guint8 *)(p)+4)<<8|
           (guint64)*((const guint8 *)(p)+5)<<0;
}

static inline guint64 pntoh56(const void *p)
{
    return (guint64)*((const guint8 *)(p)+0)<<48|
           (guint64)*((const guint8 *)(p)+1)<<40|
           (guint64)*((const guint8 *)(p)+2)<<32|
           (guint64)*((const guint8 *)(p)+3)<<24|
           (guint64)*((const guint8 *)(p)+4)<<16|
           (guint64)*((const guint8 *)(p)+5)<<8|
           (guint64)*((const guint8 *)(p)+6)<<0;
}

static inline guint64 pntoh64(const void *p)
{
    return (guint64)*((const guint8 *)(p)+0)<<56|
           (guint64)*((const guint8 *)(p)+1)<<48|
           (guint64)*((const guint8 *)(p)+2)<<40|
           (guint64)*((const guint8 *)(p)+3)<<32|
           (guint64)*((const guint8 *)(p)+4)<<24|
           (guint64)*((const guint8 *)(p)+5)<<16|
           (guint64)*((const guint8 *)(p)+6)<<8|
           (guint64)*((const guint8 *)(p)+7)<<0;
}

static inline guint16 pletoh16(const void *p)
{
    return (guint16)*((const guint8 *)(p)+1)<<8|
           (guint16)*((const guint8 *)(p)+0)<<0;
}

static inline guint32 pletoh24(const void *p)
{
    return (guint32)*((const guint8 *)(p)+2)<<16|
           (guint32)*((const guint8 *)(p)+1)<<8|
           (guint32)*((const guint8 *)(p)+0)<<0;
}

static inline guint32 pletoh32(const void *p)
{
    return (guint32)*((const guint8 *)(p)+3)<<24|
           (guint32)*((const guint8 *)(p)+2)<<16|
           (guint32)*((const guint8 *)(p)+1)<<8|
           (guint32)*((const guint8 *)(p)+0)<<0;
}

static inline guint64 pletoh40(const void *p)
{
    return (guint64)*((const guint8 *)(p)+4)<<32|
           (guint64)*((const guint8 *)(p)+3)<<24|
           (guint64)*((const guint8 *)(p)+2)<<16|
           (guint64)*((const guint8 *)(p)+1)<<8|
           (guint64)*((const guint8 *)(p)+0)<<0;
}

static inline guint64 pletoh48(const void *p)
{
    return (guint64)*((const guint8 *)(p)+5)<<40|
           (guint64)*((const guint8 *)(p)+4)<<32|
           (guint64)*((const guint8 *)(p)+3)<<24|
           (guint64)*((const guint8 *)(p)+2)<<16|
           (guint64)*((const guint8 *)(p)+1)<<8|
           (guint64)*((const guint8 *)(p)+0)<<0;
}

static inline guint64 pletoh56(const void *p)
{
    return (guint64)*((const guint8 *)(p)+6)<<48|
           (guint64)*((const guint8 *)(p)+5)<<40|
           (guint64)*((const guint8 *)(p)+4)<<32|
           (guint64)*((const guint8 *)(p)+3)<<24|
           (guint64)*((const guint8 *)(p)+2)<<16|
           (guint64)*((const guint8 *)(p)+1)<<8|
           (guint64)*((const guint8 *)(p)+0)<<0;
}

static inline guint64 pletoh64(const void *p)
{
    return (guint64)*((const guint8 *)(p)+7)<<56|
           (guint64)*((const guint8 *)(p)+6)<<48|
           (guint64)*((const guint8 *)(p)+5)<<40|
           (guint64)*((const guint8 *)(p)+4)<<32|
           (guint64)*((const guint8 *)(p)+3)<<24|
           (guint64)*((const guint8 *)(p)+2)<<16|
           (guint64)*((const guint8 *)(p)+1)<<8|
           (guint64)*((const guint8 *)(p)+0)<<0;
}
/* Pointer routines to put items out in a particular byte order.
 * These will work regardless of the byte alignment of the pointer.
 */

static inline void phton16(guint8 *p, guint16 v)
{
    p[0] = (guint8)(v >> 8);
    p[1] = (guint8)(v >> 0);
}

static inline void phton32(guint8 *p, guint32 v)
{
    p[0] = (guint8)(v >> 24);
    p[1] = (guint8)(v >> 16);
    p[2] = (guint8)(v >> 8);
    p[3] = (guint8)(v >> 0);
}

static inline void phton64(guint8 *p, guint64 v) {
    p[0] = (guint8)(v >> 56);
    p[1] = (guint8)(v >> 48);
    p[2] = (guint8)(v >> 40);
    p[3] = (guint8)(v >> 32);
    p[4] = (guint8)(v >> 24);
    p[5] = (guint8)(v >> 16);
    p[6] = (guint8)(v >> 8);
    p[7] = (guint8)(v >> 0);
}

static inline void phtole32(guint8 *p, guint32 v) {
    p[0] = (guint8)(v >> 0);
    p[1] = (guint8)(v >> 8);
    p[2] = (guint8)(v >> 16);
    p[3] = (guint8)(v >> 24);
}

static inline void phtole64(guint8 *p, guint64 v) {
    p[0] = (guint8)(v >> 0);
    p[1] = (guint8)(v >> 8);
    p[2] = (guint8)(v >> 16);
    p[3] = (guint8)(v >> 24);
    p[4] = (guint8)(v >> 32);
    p[5] = (guint8)(v >> 40);
    p[6] = (guint8)(v >> 48);
    p[7] = (guint8)(v >> 56);
}

/* Subtract two guint32s with respect to wraparound */
#define guint32_wraparound_diff(higher, lower) ((higher>lower)?(higher-lower):(higher+0xffffffff-lower+1))

#endif /* PINT_H */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
