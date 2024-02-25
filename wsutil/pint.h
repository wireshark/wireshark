/** @file
 *
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

#include <inttypes.h>

#include <glib.h>

/* Routines that take a possibly-unaligned pointer to a 16-bit, 24-bit,
 * 32-bit, 40-bit, ... 64-bit integral quantity, in a particular byte
 * order, and fetch the value and return it in host byte order.
 *
 * The pntohN() routines fetch big-endian values; the pletohN() routines
 * fetch little-endian values.
 */

/* On most architectures, accesses of 16, 32, and 64 bit quantities can be
 * heavily optimized. gcc and clang recognize portable versions below and,
 * at -Os and higher, optimize them appropriately (for gcc, that includes
 * for z/Architecture, PPC64, MIPS, etc.). Older versions don't do as good
 * of a job with 16 bit accesses, though.
 *
 * Unfortunately, MSVC and icc (both the "classic" version and the new
 * LLVM-based Intel C Compiler) do not, according to Matt Godbolt's Compiler
 * Explorer (https://godbolt.org) as of the end of 2022. They *do* recognize
 * and optimize a memcpy based approach (which avoids unaligned accesses on,
 * say, ARM32), though that requires byteswapping appropriately.
 */

#if (defined(_MSC_VER) && !defined(__clang__)) || defined(__INTEL_COMPILER) || defined(__INTEL_LLVM_COMPILER)
/* MSVC or Intel C Compiler (Classic or new LLVM version), but not
 * clang-cl on Windows.
 */
/* Unfortunately, C23 did not fully accept the N3022 Modern Bit Utilities
 * proposal, so a standard bytereverse function has been deferred for some
 * future version:
 * https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3048.htm
 * https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3022.htm
 *
 * So choose byteswap intrinsics we know we have.
 */
#if defined(_MSC_VER) && !defined(__INTEL_COMPILER) && !defined(__INTEL_LLVM_COMPILER) && !defined(__clang__)
/* Intel and clang-cl both define _MSC_VER when compiling on Windows for
 * greater compatibility (just as they define __GNUC__ on other platforms).
 * However, at least on some versions, while including the MSVC <stdlib.h>
 * provides access to the _byteswap_ intrinsics, they are not actually
 * optimized into a single x86 BSWAP function, unlike the gcc-style intrinsics
 * (which both support.) See: https://stackoverflow.com/q/72327906
 */
#include <stdlib.h> // For MSVC _byteswap intrinsics
#define pint_bswap16(x) _byteswap_ushort(x)
#define pint_bswap32(x) _byteswap_ulong(x)
/* Hopefully MSVC never decides that a long is 64 bit. */
#define pint_bswap64(x) _byteswap_uint64(x)
#elif defined(__INTEL_COMPILER)
/* The (deprecated) Intel C++ Compiler Classic has these byteswap intrinsics.
 * It also has the GCC-style intrinsics, though __builtin_bswap16 wasn't
 * added until some point after icc 13.0 but at least by 16.0, reflecting
 * that it wasn't added to gcc until 4.8.
 */
#define pint_bswap16(x) _bswap16(x)
#define pint_bswap32(x) _bswap32(x)
#define pint_bswap64(x) _bswap64(x)
#else
/* GCC-style _bswap intrinsics */
/* The new LLVM-based Intel C++ Compiler doesn't have the above intrinsics,
 * but it always has all the GCC intrinsics.
 */
/* __builtin_bswap32 and __builtin_bswap64 intrinsics have been supported
 * for a long time on gcc (4.1), and clang (pre 3.0), versions that predate
 * C11 and C+11 support, which we require, so we could assume we have them.
 *
 * __builtin_bswap16 was added a bit later, gcc 4.8, and clang 3.2. While
 * those versions or later are required for full C11 and C++11 support,
 * some earlier versions claim to support C11 and C++11 in ways that might
 * allow them to get past CMake. We don't use this codepath for those
 * compilers because they heavily optimize the portable versions, though.
 */
#define pint_bswap16(x) __builtin_bswap16(x)
#define pint_bswap32(x) __builtin_bswap32(x)
#define pint_bswap64(x) __builtin_bswap64(x)
#endif

static inline uint16_t pntoh16(const void *p)
{
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    ret = pint_bswap16(ret);
#endif
    return ret;
}

static inline uint32_t pntoh32(const void *p)
{
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    ret = pint_bswap32(ret);
#endif
    return ret;
}

static inline uint64_t pntoh64(const void *p)
{
    uint64_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    ret = pint_bswap64(ret);
#endif
    return ret;
}

static inline uint16_t pletoh16(const void *p)
{
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_BIG_ENDIAN
    ret = pint_bswap16(ret);
#endif
    return ret;
}

static inline uint32_t pletoh32(const void *p)
{
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_BIG_ENDIAN
    ret = pint_bswap32(ret);
#endif
    return ret;
}

static inline uint64_t pletoh64(const void *p)
{
    uint64_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_BIG_ENDIAN
    ret = pint_bswap64(ret);
#endif
    return ret;
}

static inline void phton16(uint8_t *p, uint16_t v)
{
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    v = pint_bswap16(v);
#endif
    memcpy(p, &v, sizeof(v));
}

static inline void phton32(uint8_t *p, uint32_t v)
{
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    v = pint_bswap32(v);
#endif
    memcpy(p, &v, sizeof(v));
}

static inline void phton64(uint8_t *p, uint64_t v) {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    v = pint_bswap64(v);
#endif
    memcpy(p, &v, sizeof(v));
}

static inline void phtole32(uint8_t *p, uint32_t v)
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
    v = pint_bswap32(v);
#endif
    memcpy(p, &v, sizeof(v));
}

static inline void phtole64(uint8_t *p, uint64_t v) {
#if G_BYTE_ORDER == G_BIG_ENDIAN
    v = pint_bswap64(v);
#endif
    memcpy(p, &v, sizeof(v));
}

#else
/* Portable functions */
static inline uint16_t pntoh16(const void *p)
{
    return (uint16_t)*((const uint8_t *)(p)+0)<<8|
           (uint16_t)*((const uint8_t *)(p)+1)<<0;
}

static inline uint32_t pntoh32(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+0)<<24|
           (uint32_t)*((const uint8_t *)(p)+1)<<16|
           (uint32_t)*((const uint8_t *)(p)+2)<<8|
           (uint32_t)*((const uint8_t *)(p)+3)<<0;
}

static inline uint64_t pntoh64(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<56|
           (uint64_t)*((const uint8_t *)(p)+1)<<48|
           (uint64_t)*((const uint8_t *)(p)+2)<<40|
           (uint64_t)*((const uint8_t *)(p)+3)<<32|
           (uint64_t)*((const uint8_t *)(p)+4)<<24|
           (uint64_t)*((const uint8_t *)(p)+5)<<16|
           (uint64_t)*((const uint8_t *)(p)+6)<<8|
           (uint64_t)*((const uint8_t *)(p)+7)<<0;
}

static inline uint16_t pletoh16(const void *p)
{
    return (uint16_t)*((const uint8_t *)(p)+1)<<8|
           (uint16_t)*((const uint8_t *)(p)+0)<<0;
}

static inline uint32_t pletoh32(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+3)<<24|
           (uint32_t)*((const uint8_t *)(p)+2)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+0)<<0;
}

static inline uint64_t pletoh64(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+7)<<56|
           (uint64_t)*((const uint8_t *)(p)+6)<<48|
           (uint64_t)*((const uint8_t *)(p)+5)<<40|
           (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
}

/* Pointer routines to put items out in a particular byte order.
 * These will work regardless of the byte alignment of the pointer.
 */

static inline void phton16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}

static inline void phton32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
}

static inline void phton64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v >> 0);
}

static inline void phtole32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void phtole64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}
#endif

static inline uint32_t pntoh24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+0)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+2)<<0;
}

static inline uint64_t pntoh40(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<32|
           (uint64_t)*((const uint8_t *)(p)+1)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+3)<<8|
           (uint64_t)*((const uint8_t *)(p)+4)<<0;
}

static inline uint64_t pntoh48(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<40|
           (uint64_t)*((const uint8_t *)(p)+1)<<32|
           (uint64_t)*((const uint8_t *)(p)+2)<<24|
           (uint64_t)*((const uint8_t *)(p)+3)<<16|
           (uint64_t)*((const uint8_t *)(p)+4)<<8|
           (uint64_t)*((const uint8_t *)(p)+5)<<0;
}

static inline uint64_t pntoh56(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<48|
           (uint64_t)*((const uint8_t *)(p)+1)<<40|
           (uint64_t)*((const uint8_t *)(p)+2)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+4)<<16|
           (uint64_t)*((const uint8_t *)(p)+5)<<8|
           (uint64_t)*((const uint8_t *)(p)+6)<<0;
}

static inline uint32_t pletoh24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+2)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+0)<<0;
}

static inline uint64_t pletoh40(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
}

static inline uint64_t pletoh48(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+5)<<40|
           (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
}

static inline uint64_t pletoh56(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+6)<<48|
           (uint64_t)*((const uint8_t *)(p)+5)<<40|
           (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
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
