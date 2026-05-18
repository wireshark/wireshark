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
 * The pntohuN() routines fetch big-endian unsigned values; the pletohuN()
  * routines fetch little-endian unsigned values.
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

/**
 * @brief Reads a big-endian (network-order) uint16_t from an unaligned pointer.
 * @param p Pointer to at least 2 bytes of data in network byte order.
 * @return The value converted to host byte order.
 */
static inline uint16_t pntohu16(const void *p)
{
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    ret = pint_bswap16(ret);
#endif
    return ret;
}

/**
 * @brief Reads a big-endian (network-order) uint32_t from an unaligned pointer.
 * @param p Pointer to at least 4 bytes of data in network byte order.
 * @return The value converted to host byte order.
 */
static inline uint32_t pntohu32(const void *p)
{
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    ret = pint_bswap32(ret);
#endif
    return ret;
}

/**
 * @brief Reads a big-endian (network-order) uint64_t from an unaligned pointer.
 * @param p Pointer to at least 8 bytes of data in network byte order.
 * @return The value converted to host byte order.
 */
static inline uint64_t pntohu64(const void *p)
{
    uint64_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    ret = pint_bswap64(ret);
#endif
    return ret;
}

/**
 * @brief Reads a little-endian uint16_t from an unaligned pointer.
 * @param p Pointer to at least 2 bytes of data in little-endian byte order.
 * @return The value converted to host byte order.
 */
static inline uint16_t pletohu16(const void *p)
{
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_BIG_ENDIAN
    ret = pint_bswap16(ret);
#endif
    return ret;
}

/**
 * @brief Reads a little-endian uint32_t from an unaligned pointer.
 * @param p Pointer to at least 4 bytes of data in little-endian byte order.
 * @return The value converted to host byte order.
 */
static inline uint32_t pletohu32(const void *p)
{
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_BIG_ENDIAN
    ret = pint_bswap32(ret);
#endif
    return ret;
}

/**
 * @brief Reads a little-endian uint64_t from an unaligned pointer.
 * @param p Pointer to at least 8 bytes of data in little-endian byte order.
 * @return The value converted to host byte order.
 */
static inline uint64_t pletohu64(const void *p)
{
    uint64_t ret;
    memcpy(&ret, p, sizeof(ret));
#if G_BYTE_ORDER == G_BIG_ENDIAN
    ret = pint_bswap64(ret);
#endif
    return ret;
}

/**
 * @brief Writes a uint16_t to an unaligned pointer in big-endian (network) byte order.
 * @param p Destination buffer; must have at least 2 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtonu16(uint8_t *p, uint16_t v)
{
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    v = pint_bswap16(v);
#endif
    memcpy(p, &v, sizeof(v));
}

/**
 * @brief Writes a uint32_t to an unaligned pointer in big-endian (network) byte order.
 * @param p Destination buffer; must have at least 4 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtonu32(uint8_t *p, uint32_t v)
{
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    v = pint_bswap32(v);
#endif
    memcpy(p, &v, sizeof(v));
}

/**
 * @brief Writes a uint64_t to an unaligned pointer in big-endian (network) byte order.
 * @param p Destination buffer; must have at least 8 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtonu64(uint8_t *p, uint64_t v)
{
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    v = pint_bswap64(v);
#endif
    memcpy(p, &v, sizeof(v));
}

/**
 * @brief Writes a uint16_t to an unaligned pointer in little-endian byte order.
 * @param p Destination buffer; must have at least 2 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtoleu16(uint8_t *p, uint32_t v)
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
    v = pint_bswap16(v);
#endif
    memcpy(p, &v, sizeof(v));
}

/**
 * @brief Writes a uint32_t to an unaligned pointer in little-endian byte order.
 * @param p Destination buffer; must have at least 4 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtoleu32(uint8_t *p, uint32_t v)
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
    v = pint_bswap32(v);
#endif
    memcpy(p, &v, sizeof(v));
}

/**
 * @brief Writes a uint64_t to an unaligned pointer in little-endian byte order.
 * @param p Destination buffer; must have at least 8 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtoleu64(uint8_t *p, uint64_t v)
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
    v = pint_bswap64(v);
#endif
    memcpy(p, &v, sizeof(v));
}

#else
/* Portable functions */

/**
 * @brief Convert a network byte order 16-bit unsigned integer to host byte order.
 *
 * @param p Pointer to the memory location containing the 16-bit unsigned integer in network byte order.
 * @return The converted 16-bit unsigned integer in host byte order.
 */
static inline uint16_t pntohu16(const void *p)
{
    return (uint16_t)*((const uint8_t *)(p)+0)<<8|
           (uint16_t)*((const uint8_t *)(p)+1)<<0;
}

/**
 * @brief Convert a network-order 32-bit unsigned integer to host order.
 *
 * @param p Pointer to the network-order 32-bit unsigned integer.
 * @return The host-order 32-bit unsigned integer.
 */
static inline uint32_t pntohu32(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+0)<<24|
           (uint32_t)*((const uint8_t *)(p)+1)<<16|
           (uint32_t)*((const uint8_t *)(p)+2)<<8|
           (uint32_t)*((const uint8_t *)(p)+3)<<0;
}

 /**
  * @brief Convert a network-order 64-bit unsigned integer to host order.
  *
  * @param p Pointer to the network-order 64-bit unsigned integer.
  * @return The host-order 64-bit unsigned integer.
  */

static inline uint64_t pntohu64(const void *p)
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

/**
 * @brief Convert a 16-bit big-endian value to a host-order unsigned integer.
 *
 * @param p Pointer to the memory location containing the big-endian 16-bit value.
 * @return uint16_t The converted host-order unsigned 16-bit integer.
 */
static inline uint16_t pletohu16(const void *p)
{
    return (uint16_t)*((const uint8_t *)(p)+1)<<8|
           (uint16_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Convert a 32-bit big-endian value to a host-order uint32_t.
 *
 * @param p Pointer to the 4-byte big-endian value.
 * @return The converted uint32_t value in host order.
 */
static inline uint32_t pletohu32(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+3)<<24|
           (uint32_t)*((const uint8_t *)(p)+2)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Convert a pointer to an unsigned 64-bit integer in little-endian format.
 *
 * @param p Pointer to the memory location containing the little-endian bytes.
 * @return The converted unsigned 64-bit integer.
 */
static inline uint64_t pletohu64(const void *p)
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

/**
 * @brief Writes a uint16_t to an unaligned pointer in big-endian (network) byte order.
 * @param p Destination buffer; must have at least 2 bytes available.
 * @param v Value in host byte order to write.
 */
static inline void phtonu16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}

/**
 * @brief Convert a 32-bit unsigned integer to network byte order and store it in a buffer.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The 32-bit unsigned integer value to convert.
 */
static inline void phtonu32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
}

/**
 * @brief Converts a 64-bit unsigned integer to network byte order and stores it in a buffer.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The 64-bit unsigned integer value to convert.
 */
static inline void phtonu64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v >> 0);
}

/**
 * @brief Convert a 16-bit unsigned integer from host byte order to little-endian and store it in memory.
 *
 * @param p Pointer to the memory location where the converted value will be stored.
 * @param v The 16-bit unsigned integer value to convert.
 */
static inline void phtoleu16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
}

/**
 * @brief Convert a 32-bit unsigned integer from host byte order to little-endian and store it in a buffer.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The 32-bit unsigned integer value to convert.
 */
static inline void phtoleu32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/**
 * @brief Converts a 64-bit unsigned integer from host byte order to little-endian byte order and stores it in a buffer.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The 64-bit unsigned integer value to convert.
 */
static inline void phtoleu64(uint8_t *p, uint64_t v) {
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

/*
 * Single-byte versions, for completeness.
*/

/**
 * @brief Convert a network byte order (big-endian) unsigned 8-bit integer to host byte order.
 *
 * @param p Pointer to the memory location containing the network byte order unsigned 8-bit integer.
 * @return uint8_t The host byte order unsigned 8-bit integer.
 */
static inline uint8_t pntohu8(const void *p)
{
    return *((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Convert a little-endian 8-bit value to a host byte order 8-bit value.
 *
 * @param p Pointer to the little-endian 8-bit value.
 * @return The host byte order 8-bit value.
 */
static inline uint8_t pletohu8(const void *p)
{
    return *((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Store an 8-bit unsigned integer in network byte order.
 *
 * @param p Pointer to the buffer where the value will be stored.
 * @param v The 8-bit unsigned integer value to store.
 */
static inline void phtonu8(uint8_t *p, uint8_t v)
{
    p[0] = (uint8_t)((v) >> 0);
}

/**
 * @brief Convert an unsigned 8-bit value from host byte order to little-endian format.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The unsigned 8-bit value to convert.
 */
static inline void phtoleu8(uint8_t *p, uint8_t v)
{
    p[0] = (uint8_t)((v) >> 0);
}

/**
 * @brief Convert a network-order 24-bit value to host order.
 *
 * This function takes a pointer to a buffer containing a 24-bit value in network
 * byte order and converts it to host byte order as a uint32_t.
 *
 * @param p Pointer to the buffer containing the 24-bit value.
 * @return The converted 24-bit value in host byte order.
 */
static inline uint32_t pntohu24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+0)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+2)<<0;
}

/**
 * @brief Convert a network-order 40-bit value to host order.
 *
 * This function takes a pointer to a buffer containing a 40-bit value in network
 * byte order and converts it to host byte order as a uint64_t.
 *
 * @param p Pointer to the buffer containing the 40-bit value.
 * @return The converted 40-bit value in host byte order.
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
 * @brief Convert a network-order 48-bit unsigned integer to host order.
 *
 * @param p Pointer to the memory location containing the 48-bit unsigned integer in network order.
 * @return The converted 48-bit unsigned integer in host order.
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
 * @brief Convert a network-order 56-bit value to host order.
 *
 * @param p Pointer to the 56-bit value in network order.
 * @return uint64_t The 56-bit value converted to host order.
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
 * @brief Convert a 24-bit big-endian value to an unsigned 32-bit integer.
 *
 * @param p Pointer to the memory location containing the 24-bit big-endian value.
 * @return uint32_t The converted 32-bit unsigned integer.
 */
static inline uint32_t pletohu24(const void *p)
{
    return (uint32_t)*((const uint8_t *)(p)+2)<<16|
           (uint32_t)*((const uint8_t *)(p)+1)<<8|
           (uint32_t)*((const uint8_t *)(p)+0)<<0;
}

/**
 * @brief Convert a 40-bit big-endian value to a 64-bit unsigned integer.
 *
 * @param p Pointer to the memory location containing the 40-bit big-endian value.
 * @return uint64_t The converted 64-bit unsigned integer.
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
 * @brief Convert a little-endian packed 48-bit integer to an unsigned 64-bit integer.
 *
 * @param p Pointer to the memory location containing the little-endian packed 48-bit integer.
 * @return uint64_t The converted unsigned 64-bit integer.
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
  * @brief Convert a 6-byte big-endian value to a 56-bit unsigned integer.
  *
  * @param p Pointer to the 6-byte big-endian value.
  * @return uint64_t The converted 56-bit unsigned integer.
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
  * @brief Convert a 32-bit unsigned integer to network byte order and store it in a buffer.
  *
  * @param p Pointer to the buffer where the converted value will be stored.
  * @param v The 32-bit unsigned integer value to convert.
  */

static inline void phtonu24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v) >> 16);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 0);
}

/**
 * @brief Converts a 40-bit unsigned integer to network byte order (big-endian) and stores it in a buffer.
 *
 * @param p Pointer to the buffer where the 40-bit value will be stored.
 * @param v The 40-bit unsigned integer value to convert.
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
 * @brief Converts a 48-bit unsigned integer to network byte order and stores it in a buffer.
 *
 * @param p Pointer to the buffer where the 48-bit value will be stored.
 * @param v The 48-bit unsigned integer value to convert.
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
  * @brief Convert a 64-bit unsigned integer to network byte order and store it in a buffer.
  *
  * @param p Pointer to the buffer where the result will be stored.
  * @param v The 64-bit unsigned integer value to convert.
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
 * @brief Convert a 24-bit unsigned integer from host byte order to little-endian format.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The 32-bit unsigned integer value to convert.
 */
static inline void phtoleu24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v) >> 0);
    p[1] = (uint8_t)((v) >> 8);
    p[2] = (uint8_t)((v) >> 16);
}

/**
 * @brief Convert a 64-bit unsigned integer to little-endian format and store it in a buffer.
 *
 * @param p Pointer to the buffer where the little-endian value will be stored.
 * @param v The 64-bit unsigned integer value to convert.
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
 * @brief Convert a 64-bit unsigned integer from host byte order to little-endian and store it in a buffer.
 *
 * @param p Pointer to the buffer where the converted value will be stored.
 * @param v The 64-bit unsigned integer value to convert.
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
 * @brief Convert a 64-bit unsigned integer from host byte order to little-endian byte order and store it in a buffer.
 *
 * @param p Pointer to the buffer where the converted bytes will be stored.
 * @param v The 64-bit unsigned integer value to convert.
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
