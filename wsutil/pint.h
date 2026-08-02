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

#pragma once

#include <inttypes.h>

#include <glib.h>

/* Routines that:
 *
 *     take a possibly-unaligned pointer to a 16-bit, 24-bit, 32-bit,
 *     40-bit, ... 64-bit integral value, in a particular byte order,
 *     and fetch the value and return it in host byte order, as an
 *     unsigned quantity;
 *
 *     take a possibly-unaligned pointer to a space for a 16-bit, 24-bit,
 *     32-bit, 40-bit, ... 64-bit integral value, in a particular byte
 *     order, and an unsigned integral value of that width or larger, and
 *     store the value in that space.
 *
 * The pntohuN() routines fetch big-endian unsigned values; the pletohuN()
 * routines fetch little-endian unsigned values. The phtonuN() routines
 * store big-endian unsigned values; the phtoleN() routines store little-
 * endian unsigned values.
 */

/* On most architectures, accesses of 16-bit, 32-bit, and 64-bit quantities
 * can be heavily optimized.
 *
 * gcc and clang recognize idioms involving shifting and masking and, at
 * -Os and higher, optimize them appropriately to, for example, do
 * unaligned loads and stores, and use byte-swapping instructions if
 * the byte order isn't the host byte order, if the platform supports them)
 * Older versions don't do as good of a job with 16-bit accesses, though.
 *
 * Unfortunately, MSVC and icc (both the "classic" version and the new
 * LLVM-based Intel C Compiler) do not recognize and optimize those
 * idioms, according to Matt Godbolt's Compiler Explorer (https://godbolt.org)
 * as of the end of 2022. They *do* recognize and optimize a memcpy-based
 * approach (which avoids unaligned accesses on, say, ARM32), though that
 * requires byte-swapping appropriately.
 */
#if (defined(_MSC_VER) && !defined(__clang__)) || defined(__INTEL_COMPILER) || defined(__INTEL_LLVM_COMPILER)
  /* MSVC or Intel C Compiler (Classic or new LLVM version), but not
   * clang-cl on Windows.
   *
   * Unfortunately, C23 did not fully accept the N3022 Modern Bit Utilities
   * proposal, so a standard bytereverse function has been deferred for some
   * future version:
   * https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3048.htm
   * https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3022.htm
   *
   * So use byte-swap intrinsics
   */
  #define _USE_BSWAPS

  /* Choose the byte-swap intrinsics we know we have. */
  #if defined(_MSC_VER) && !defined(__INTEL_COMPILER) && !defined(__INTEL_LLVM_COMPILER) && !defined(__clang__)
    /* Intel and clang-cl both define _MSC_VER when compiling on Windows for
     * greater compatibility (just as they define __GNUC__ on other platforms).
     * However, at least on some versions, while including the MSVC <stdlib.h>
     * provides access to the _byteswap_ intrinsics, they are not actually
     * optimized into a single x86 BSWAP function, unlike the gcc-style
     * intrinsics (which both support).
     * See: https://stackoverflow.com/q/72327906
     */
    #include <stdlib.h> // For MSVC _byteswap intrinsics
    #define _pint_bswap16(x) _byteswap_ushort(x)
    #define _pint_bswap32(x) _byteswap_ulong(x)
    /* Hopefully MSVC never decides that a long is 64 bit. */
    #define _pint_bswap64(x) _byteswap_uint64(x)
  #elif defined(__INTEL_COMPILER)
    /* The (deprecated) Intel C++ Compiler Classic has these byteswap
     * intrinsics.
     *
     * It also has the GCC-style intrinsics, though __builtin_bswap16 wasn't
     * added until some point after icc 13.0 but at least by 16.0, reflecting
     * that it wasn't added to gcc until 4.8.
     */
    #define _pint_bswap16(x) _bswap16(x)
    #define _pint_bswap32(x) _bswap32(x)
    #define _pint_bswap64(x) _bswap64(x)
  #else
    /* GCC-style _bswap intrinsics.
     *
     * The new LLVM-based Intel C++ Compiler doesn't have the above intrinsics,
     * but it always has all the GCC intrinsics.
     *
     * __builtin_bswap32 and __builtin_bswap64 intrinsics have been supported
     * for a long time on gcc (4.1), and clang (pre 3.0), versions that predate
     * C11 and C+11 support, which we require, so we could assume we have them.
     *
     * __builtin_bswap16 was added a bit later, gcc 4.8, and clang 3.2. While
     * those versions or later are required for full C11 and C++11 support,
     * some earlier versions claim to support C11 and C++11 in ways that might
     * allow them to get past CMake. We don't use this codepath for those
     * compilers because they heavily optimize the portable versions, though.
     */
    #define _pint_bswap16(x) __builtin_bswap16(x)
    #define _pint_bswap32(x) __builtin_bswap32(x)
    #define _pint_bswap64(x) __builtin_bswap64(x)
  #endif

  /* Now define host-to-{big,little}-endian and {big,little}-endian-to-host
   * macros based on them and on the host byte order.
   */
  #if G_BYTE_ORDER == G_BIG_ENDIAN
    /* Big-to-host and host-to-big are no-ops.
     * Little-to-host and host-to-little are byte-swaps.
     */
    #define _pint_betoh16(x) (x)
    #define _pint_betoh32(x) (x)
    #define _pint_betoh64(x) (x)
    #define _pint_htobe16(x) (x)
    #define _pint_htobe32(x) (x)
    #define _pint_htobe64(x) (x)
    #define _pint_letoh16(x) _pint_bswap16(x)
    #define _pint_letoh32(x) _pint_bswap32(x)
    #define _pint_letoh64(x) _pint_bswap64(x)
    #define _pint_htole16(x) _pint_bswap16(x)
    #define _pint_htole32(x) _pint_bswap32(x)
    #define _pint_htole64(x) _pint_bswap64(x)
  #elif G_BYTE_ORDER == G_LITTLE_ENDIAN
    /* Little-to-host and host-to-little are no-ops.
     * Big-to-host and host-to-big are byte-swaps.
     */
    #define _pint_letoh16(x) (x)
    #define _pint_letoh32(x) (x)
    #define _pint_letoh64(x) (x)
    #define _pint_htole16(x) (x)
    #define _pint_htole32(x) (x)
    #define _pint_htole64(x) (x)
    #define _pint_betoh16(x) _pint_bswap16(x)
    #define _pint_betoh32(x) _pint_bswap32(x)
    #define _pint_betoh64(x) _pint_bswap64(x)
    #define _pint_htobe16(x) _pint_bswap16(x)
    #define _pint_htobe32(x) _pint_bswap32(x)
    #define _pint_htobe64(x) _pint_bswap64(x)
  #else
    #error "Sorry, we don't support byte orders other than big- and little-endian"
  #endif
#endif

/**
 * @brief Loads a 16-bit unsigned value from a 2-byte possibly-unaligned
 * area, in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 2 bytes of data in big-endian
 *          byte order.
 * @return The value converted to host byte order.
 */
static inline uint16_t pntohu16(const void *p)
{
#ifdef _USE_BSWAPS
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
    return _pint_betoh16(ret);
#else /* _USE_BSWAPS */
    return (uint16_t)*((const uint8_t *)(p)+0)<<8|
           (uint16_t)*((const uint8_t *)(p)+1)<<0;
#endif /* _USE_BSWAPS */
}

/**
 * @brief Loads a 32-bit unsigned value from a 4-byte possibly-unaligned
 * area, in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 4 bytes of data in big-endian
 *          byte order.
 * @return The value converted to host byte order.
 */
static inline uint32_t pntohu32(const void *p)
{
#ifdef _USE_BSWAPS
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
    return _pint_betoh32(ret);
#else /* _USE_BSWAPS */
    return (uint32_t)*((const uint8_t *)(p)+0)<<24|
           (uint32_t)*((const uint8_t *)(p)+1)<<16|
           (uint32_t)*((const uint8_t *)(p)+2)<<8|
           (uint32_t)*((const uint8_t *)(p)+3)<<0;
#endif /* _USE_BSWAPS */
}

/**
 * @brief Loads a 64-bit unsigned value from an 8-byte possibly-unaligned area,
 * in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 8 bytes of data in big-endian
 *          byte order.
 * @return The value converted to host byte order.
 */
static inline uint64_t pntohu64(const void *p)
{
#ifdef _USE_BSWAPS
    uint64_t ret;
    memcpy(&ret, p, sizeof(ret));
    return _pint_betoh64(ret);
#else /* _USE_BSWAPS */
    return (uint64_t)*((const uint8_t *)(p)+0)<<56|
           (uint64_t)*((const uint8_t *)(p)+1)<<48|
           (uint64_t)*((const uint8_t *)(p)+2)<<40|
           (uint64_t)*((const uint8_t *)(p)+3)<<32|
           (uint64_t)*((const uint8_t *)(p)+4)<<24|
           (uint64_t)*((const uint8_t *)(p)+5)<<16|
           (uint64_t)*((const uint8_t *)(p)+6)<<8|
           (uint64_t)*((const uint8_t *)(p)+7)<<0;
#endif /* _USE_BSWAPS */
}

/**
 * @brief Loads a 16-bit unsigned value from a 2-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 2 bytes of data in little-endian
 *          byte order.
 * @return The value converted to host byte order.
 */
static inline uint16_t pletohu16(const void *p)
{
#ifdef _USE_BSWAPS
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
    return _pint_letoh16(ret);
#else /* _USE_BSWAPS */
    return (uint16_t)*((const uint8_t *)(p)+1)<<8|
           (uint16_t)*((const uint8_t *)(p)+0)<<0;
#endif /* _USE_BSWAPS */
}

/**
 * @brief Loads a 32-bit unsigned value from a 4-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 4 bytes of data in little-endian
 *          byte order.
 * @return The value converted to host byte order.
 */
static inline uint32_t pletohu32(const void *p)
{
#ifdef _USE_BSWAPS
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
    return _pint_letoh32(ret);
#else /* _USE_BSWAPS */
    return (uint32_t)*((const uint8_t *)(p)+3)<<24|
           (uint32_t)*((const uint8_t *)(p)+2)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+0)<<0;
#endif /* _USE_BSWAPS */
}

/**
 * @brief Loads a 64-bit unsigned value from an 8-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 8 bytes of data in little-endian
 *          byte order.
 * @return The value converted to host byte order.
 */
static inline uint64_t pletohu64(const void *p)
{
#ifdef _USE_BSWAPS
    uint64_t ret;
    memcpy(&ret, p, sizeof(ret));
    return _pint_letoh64(ret);
#else /* _USE_BSWAPS */
    return (uint64_t)*((const uint8_t *)(p)+7)<<56|
           (uint64_t)*((const uint8_t *)(p)+6)<<48|
           (uint64_t)*((const uint8_t *)(p)+5)<<40|
           (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
#endif /* _USE_BSWAPS */
}

/**
 * @brief Stores a uint16_t into a 2-byte possibly-unaligned area, in
 * big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 2 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu16(uint8_t *p, uint16_t v)
{
#ifdef _USE_BSWAPS
    v = _pint_htobe16(v);
    memcpy(p, &v, sizeof(v));
#else /* _USE_BSWAPS */
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
#endif /* _USE_BSWAPS */
}

/**
 * @brief Stores a uint32_t into a 4-byte possibly-unaligned area, in
 * big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 4 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu32(uint8_t *p, uint32_t v)
{
#ifdef _USE_BSWAPS
    v = _pint_htobe32(v);
    memcpy(p, &v, sizeof(v));
#else /* _USE_BSWAPS */
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
#endif /* _USE_BSWAPS */
}

/**
 * @brief Stores a uint64_t into an 8-byte possibly-unaligned area, in
 * big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 8 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu64(uint8_t *p, uint64_t v)
{
#ifdef _USE_BSWAPS
    v = _pint_htobe64(v);
    memcpy(p, &v, sizeof(v));
#else /* _USE_BSWAPS */
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v >> 0);
#endif /* _USE_BSWAPS */
}

/**
 * @brief Stores a uint16_t into a 2-byte area possibly-unaligned, in
 * little-endian byte order.
 *
 * @param p Destination buffer; must have at least 2 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu16(uint8_t *p, uint16_t v)
{
#ifdef _USE_BSWAPS
    v = _pint_htole16(v);
    memcpy(p, &v, sizeof(v));
#else /* _USE_BSWAPS */
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
#endif /* _USE_BSWAPS */
}

/**
 * @brief Stores a uint32_t into a 4-byte possibly-unaligned area, in
 * little-endian byte order.
 *
 * @param p Destination buffer; must have at least 4 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu32(uint8_t *p, uint32_t v)
{
#ifdef _USE_BSWAPS
    v = _pint_htole32(v);
    memcpy(p, &v, sizeof(v));
#else /* _USE_BSWAPS */
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
#endif /* _USE_BSWAPS */
}

/**
 * @brief Stores a uint64_t into an 8-byte possibly-unaligned area, in
 * little-endian byte order.
 *
 * @param p Destination buffer; must have at least 8 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu64(uint8_t *p, uint64_t v)
{
#ifdef _USE_BSWAPS
    v = _pint_htole64(v);
    memcpy(p, &v, sizeof(v));
#else /* _USE_BSWAPS */
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
#endif /* _USE_BSWAPS */
}

/*
 * Single-byte versions, for completeness.
 */

/**
 * @brief Loads an 8-bit unsigned value from a 1-byte area, in big-endian
 * (network) byte order (not that it matters).
 *
 * @param p Source buffer, must have at least 1 byte of data.
 * @return The value converted to host byte order.
 */
static inline uint8_t pntohu8(const void *p)
{
    return *((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Loads an 8-bit unsigned value from a 1-byte area, in little-endian
 * byte order (not that it matters).
 *
 * @param p Source buffer, must have at least 1 byte of data.
 * @return The value converted to host byte order.
 */
static inline uint8_t pletohu8(const void *p)
{
    return *((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Stores a uint8_t into a 1-byte area, in big-endian (network) byte
 * order (not that it matters).
 *
 * @param p Destination buffer; must have at least 1 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu8(uint8_t *p, uint8_t v)
{
    p[0] = (uint8_t)((v) >> 0);
}

/**
 * @brief Stores a uint8_t into a 1-byte area, in little-endian byte
 * order (not that it matters).
 *
 * @param p Destination buffer; must have at least 1 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu8(uint8_t *p, uint8_t v)
{
    p[0] = (uint8_t)((v) >> 0);
}

/*
 * Non-power-of-2-sized versions.
 *
 * I don't know whether these are recognized idioms by the versions of GCC
 * and Clang that we support.
 *
 * We could implement them as fetching multiple values using the above and
 * combining them and storing multiple values after breaking them apart
 * and putting them in the right byte order using the above.
 */

/**
 * @brief Loads a 24-bit unsigned value from a 3-byte possibly-unaligned area,
 * in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 3 bytes of data in big-endian
 *          byte order.
 * @return The value converted to a host byte order uint32_t (zero-extended)
 */
static inline uint32_t pntohu24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+0)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+2)<<0;
}

/**
 * @brief Loads a 40-bit unsigned value from a 5-byte possibly-unaligned area,
 * in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 5 bytes of data in big-endian
 *          byte order.
 * @return The value converted to a host byte order uint64_t (zero-extended)
 */
static inline uint64_t pntohu40(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<32|
           (uint64_t)*((const uint8_t *)(p)+1)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+3)<<8|
           (uint64_t)*((const uint8_t *)(p)+4)<<0;
}

/**
 * @brief Loads a 48-bit unsigned value from a 6-byte possibly-unaligned area,
 * in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 6 bytes of data in big-endian
 *          byte order.
 * @return The value converted to a host byte order uint64_t (zero-extended)
 */
static inline uint64_t pntohu48(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<40|
           (uint64_t)*((const uint8_t *)(p)+1)<<32|
           (uint64_t)*((const uint8_t *)(p)+2)<<24|
           (uint64_t)*((const uint8_t *)(p)+3)<<16|
           (uint64_t)*((const uint8_t *)(p)+4)<<8|
           (uint64_t)*((const uint8_t *)(p)+5)<<0;
}

/**
 * @brief Loads a 56-bit unsigned value from a 7-byte possibly-unaligned area,
 * in big-endian (network) byte order.
 *
 * @param p Source buffer, must have at least 7 bytes of data in big-endian
 *          byte order.
 * @return The value converted to a host byte order uint64_t (zero-extended)
 */
static inline uint64_t pntohu56(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+0)<<48|
           (uint64_t)*((const uint8_t *)(p)+1)<<40|
           (uint64_t)*((const uint8_t *)(p)+2)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+4)<<16|
           (uint64_t)*((const uint8_t *)(p)+5)<<8|
           (uint64_t)*((const uint8_t *)(p)+6)<<0;
}

/**
 * @brief Loads a 24-bit unsigned value from a 3-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 3 bytes of data in little-endian
 *          byte order.
 * @return The value converted to a host byte order uint32_t (zero-extended)
 */
static inline uint32_t pletohu24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+2)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Loads a 40-bit unsigned value from a 4-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 5 bytes of data in little-endian
 *          byte order.
 * @return The value converted to a host byte order uint64_t (zero-extended)
 */
static inline uint64_t pletohu40(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Loads a 48-bit unsigned value from a 6-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 6 bytes of data in little-endian
 *          byte order.
 * @return The value converted to a host byte order uint64_t (zero-extended)
 */
static inline uint64_t pletohu48(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+5)<<40|
           (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Loads a 56-bit unsigned value from a 7-byte possibly-unaligned area,
 * in little-endian byte order.
 *
 * @param p Source buffer, must have at least 7 bytes of data in little-endian
 *          byte order.
 */
static inline uint64_t pletohu56(const void *p)
{
    return (uint64_t)*((const uint8_t *)(p)+6)<<48|
           (uint64_t)*((const uint8_t *)(p)+5)<<40|
           (uint64_t)*((const uint8_t *)(p)+4)<<32|
           (uint64_t)*((const uint8_t *)(p)+3)<<24|
           (uint64_t)*((const uint8_t *)(p)+2)<<16|
           (uint64_t)*((const uint8_t *)(p)+1)<<8|
           (uint64_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Stores a 24-bit unsigned value, in the lower bits of a uint32_t,
 * into a 3-byte possibly-unaligned area, in big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 3 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v) >> 16);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 0);
}

/**
 * @brief Stores a 40-bit unsigned value, in the lower bits of a uint64_t,
 * into a 5-byte possibly-unaligned area, in big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 5 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu40(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v) >> 32);
    p[1] = (uint8_t)((v) >> 24);
    p[2] = (uint8_t)((v) >> 16);
    p[3] = (uint8_t)((v) >> 8);
    p[4] = (uint8_t)((v) >> 0);
}

/**
 * @brief Stores a 48-bit unsigned value, in the lower bits of a uint64_t,
 * into a 6-byte possibly-unaligned area, in big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 6 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu48(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v) >> 40);
    p[1] = (uint8_t)((v) >> 32);
    p[2] = (uint8_t)((v) >> 24);
    p[3] = (uint8_t)((v) >> 16);
    p[4] = (uint8_t)((v) >> 8);
    p[5] = (uint8_t)((v) >> 0);
}

/**
 * @brief Stores a 56-bit unsigned value, in the lower bits of a uint64_t,
 * into a 7-byte possibly-unaligned area, in big-endian (network) byte order.
 *
 * @param p Destination buffer; must have at least 7 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtonu56(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v) >> 48);
    p[1] = (uint8_t)((v) >> 40);
    p[2] = (uint8_t)((v) >> 32);
    p[3] = (uint8_t)((v) >> 24);
    p[4] = (uint8_t)((v) >> 16);
    p[5] = (uint8_t)((v) >> 8);
    p[6] = (uint8_t)((v) >> 0);
}

/**
 * @brief Stores a 24-bit unsigned value, in the lower bits of a uint32_t,
 * into a 3-byte possibly-unaligned area, in little-endian byte order.
 *
 * @param p Destination buffer; must have at least 3 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v) >> 0);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 16);
}

/**
 * @brief Stores a 40-bit unsigned value, in the lower bits of a uint64_t,
 * into a 5-byte possibly-unaligned area, in little-endian byte order.
 *
 * @param p Destination buffer; must have at least 5 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu40(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v) >> 0);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 16);
    p[3] = (uint8_t)((v) >> 24);
    p[4] = (uint8_t)((v) >> 32);
}

/**
 * @brief Stores a 48-bit unsigned value, in the lower bits of a uint64_t,
 * into a 6-byte possibly-unaligned area, in little-endian byte order.
 *
 * @param p Destination buffer; must have at least 6 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu48(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v) >> 0);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 16);
    p[3] = (uint8_t)((v) >> 24);
    p[4] = (uint8_t)((v) >> 32);
    p[5] = (uint8_t)((v) >> 40);
}

/**
 * @brief Stores a 56-bit unsigned value, in the lower bits of a uint64_t,
 * into a 7-byte possibly-unaligned area, in little-endian byte order.
 *
 * @param p Destination buffer; must have at least 7 bytes available.
 * @param v Value, in host byte order, to write.
 */
static inline void phtoleu56(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v) >> 0);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 16);
    p[3] = (uint8_t)((v) >> 24);
    p[4] = (uint8_t)((v) >> 32);
    p[5] = (uint8_t)((v) >> 40);
    p[6] = (uint8_t)((v) >> 48);
}

/* Purge internal-to-this-header macros from the namespace */
#undef _USE_BSWAPS
#undef _pint_bswap16
#undef _pint_bswap32
#undef _pint_bswap64
#undef _pint_betoh16
#undef _pint_betoh32
#undef _pint_betoh64
#undef _pint_htobe16
#undef _pint_htobe32
#undef _pint_htobe64
#undef _pint_letoh16
#undef _pint_letoh32
#undef _pint_letoh64
#undef _pint_htole16
#undef _pint_htole32
#undef _pint_htole64

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
