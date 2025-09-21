/*
 * endian.h
 *
 * This header defines the following endian macros as defined here:
 *
 *   http://austingroupbugs.net/view.php?id=162
 *
 *   BYTE_ORDER         this macro shall have a value equal to one
 *                      of the *_ENDIAN macros in this header.
 *   LITTLE_ENDIAN      if BYTE_ORDER == LITTLE_ENDIAN, the host
 *                      byte order is from least significant to
 *                      most significant.
 *   BIG_ENDIAN         if BYTE_ORDER == BIG_ENDIAN, the host byte
 *                      order is from most significant to least
 *                      significant.
 *
 * This header also defines several byte-swap interfaces, some that
 * map directly to the host byte swap intrinsics and some sensitive
 * to the host endian representation, performing a swap only if the
 * host representation differs from the chosen representation.
 *
 * Direct byte swapping interfaces:
 *
 *   u16 bswap16(u16 x); (* swap bytes 16-bit word *)
 *   u32 bswap32(u32 x); (* swap bytes 32-bit word *)
 *   u64 bswap64(u64 x); (* swap bytes 64-bit word *)
 *
 * Simplified host endian interfaces:
 *
 *   u16 be16(u16 x); (* big-endian representation 16-bit word *)
 *   u32 be32(u32 x); (* big-endian representation 32-bit word *)
 *   u64 be64(u64 x); (* big-endian representation 64-bit word *)
 *
 *   u16 le16(u16 x); (* little-endian representation 16-bit word *)
 *   u32 le32(u32 x); (* little-endian representation 32-bit word *)
 *   u64 le64(u64 x); (* little-endian representation 64-bit word *)
 *
 * BSD host endian interfaces:
 *
 *   u16 htobe16(u16 x) { return be16(x); }
 *   u16 htole16(u16 x) { return le16(x); }
 *   u16 be16toh(u16 x) { return be16(x); }
 *   u16 le16toh(u16 x) { return le16(x); }
 *
 *   u32 htobe32(u32 x) { return be32(x); }
 *   u32 htole32(u32 x) { return le32(x); }
 *   u32 be32toh(u32 x) { return be32(x); }
 *   u32 le32toh(u32 x) { return le32(x); }
 *
 *   u64 htobe64(u64 x) { return be64(x); }
 *   u64 htole64(u64 x) { return le64(x); }
 *   u64 be64toh(u64 x) { return be64(x); }
 *   u64 le64toh(u64 x) { return le64(x); }
 *
 * Copyright (c) 2016-2023 Michael Clark <michaeljclark@mac.com>
 *
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GCC/Clang */
#if defined(__GNUC__)
static inline u16 bswap16(u16 x) { return __builtin_bswap16(x); }
static inline u32 bswap32(u32 x) { return __builtin_bswap32(x); }
static inline u64 bswap64(u64 x) { return __builtin_bswap64(x); }
#define _BYTE_ORDER     __BYTE_ORDER__
#define _LITTLE_ENDIAN  __ORDER_LITTLE_ENDIAN__
#define _BIG_ENDIAN     __ORDER_BIG_ENDIAN__
#define __ENDIAN_DEFINED
#define __BSWAP_DEFINED
#endif /* __GNUC__ */

/* MSC/Windows */
#if defined(_WIN32) || defined(_MSC_VER)
/* assumes all Microsoft targets are little endian */
#include <stdlib.h>
static inline u16 bswap16(u16 x) { return _byteswap_ushort(x); }
static inline u32 bswap32(u32 x) { return _byteswap_ulong(x); }
static inline u64 bswap64(u64 x) { return _byteswap_uint64(x); }
#define _LITTLE_ENDIAN          1234
#define _BIG_ENDIAN             4321
#define _BYTE_ORDER             _LITTLE_ENDIAN
#define __ENDIAN_DEFINED
#define __BSWAP_DEFINED
#endif /* Windows */

/* OpenCL */
#if defined (__OPENCL_VERSION__)
#define _LITTLE_ENDIAN          1234
#define _BIG_ENDIAN             4321
#if defined (__ENDIAN_LITTLE__)
#define _BYTE_ORDER             _LITTLE_ENDIAN
#else
#define _BYTE_ORDER             _BIG_ENDIAN
#endif
#define bswap16(x)              as_ushort(as_uchar2(ushort(x)).s1s0)
#define bswap32(x)              as_uint(as_uchar4(uint(x)).s3s2s1s0)
#define bswap64(x)              as_ulong(as_uchar8(ulong(x)).s7s6s5s4s3s2s1s0)
#define __ENDIAN_DEFINED
#define __BSWAP_DEFINED
#endif

/* For everything else, use the compiler's predefined endian macros */
#if !defined (__ENDIAN_DEFINED) && defined (__BYTE_ORDER__) && \
    defined (__ORDER_LITTLE_ENDIAN__) && defined (__ORDER_BIG_ENDIAN__)
#define __ENDIAN_DEFINED
#define _BYTE_ORDER             __BYTE_ORDER__
#define _LITTLE_ENDIAN          __ORDER_LITTLE_ENDIAN__
#define _BIG_ENDIAN             __ORDER_BIG_ENDIAN__
#endif

/* No endian macros found */
#ifndef __ENDIAN_DEFINED
#error Could not determine CPU byte order
#endif

/* POSIX - http://austingroupbugs.net/view.php?id=162 */
#ifndef BYTE_ORDER
#define BYTE_ORDER              _BYTE_ORDER
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN           _LITTLE_ENDIAN
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN              _BIG_ENDIAN
#endif

/*
 * Natural to foreign endian helpers defined using bswap
 *
 * MSC can't lift byte swap expressions efficiently so we
 * define host integer swaps using explicit byte swapping.
 */

/* helps to have these function for symmetry */
static inline u8 le8(u8 x) { return x; }
static inline u8 be8(u8 x) { return x; }

#if defined(__BSWAP_DEFINED)
#if _BYTE_ORDER == _BIG_ENDIAN
static inline u16 be16(u16 x) { return x; }
static inline u32 be32(u32 x) { return x; }
static inline u64 be64(u64 x) { return x; }
static inline u16 le16(u16 x) { return bswap16(x); }
static inline u32 le32(u32 x) { return bswap32(x); }
static inline u64 le64(u64 x) { return bswap64(x); }
#endif
#if _BYTE_ORDER == _LITTLE_ENDIAN
static inline u16 be16(u16 x) { return bswap16(x); }
static inline u32 be32(u32 x) { return bswap32(x); }
static inline u64 be64(u64 x) { return bswap64(x); }
static inline u16 le16(u16 x) { return x; }
static inline u32 le32(u32 x) { return x; }
static inline u64 le64(u64 x) { return x; }
#endif

#else
#define __BSWAP_DEFINED

/*
 * Natural to foreign endian helpers using type punning
 *
 * Recent Clang and GCC lift these expressions to bswap
 * instructions. This makes baremetal code easier.
 */

static inline u16 be16(u16 x)
{
    union { u8 a[2]; u16 b; } y = {
        .a = { (u8)(x >> 8), (u8)(x) }
    };
    return y.b;
}

static inline u16 le16(u16 x)
{
    union { u8 a[2]; u16 b; } y = {
        .a = { (u8)(x), (u8)(x >> 8) }
    };
    return y.b;
}

static inline u32 be32(u32 x)
{
    union { u8 a[4]; u32 b; } y = {
        .a = { (u8)(x >> 24), (u8)(x >> 16),
               (u8)(x >> 8), (u8)(x) }
    };
    return y.b;
}

static inline u32 le32(u32 x)
{
    union { u8 a[4]; u32 b; } y = {
        .a = { (u8)(x), (u8)(x >> 8),
               (u8)(x >> 16), (u8)(x >> 24) }
    };
    return y.b;
}

static inline u64 be64(u64 x)
{
    union { u8 a[8]; u64 b; } y = {
        .a = { (u8)(x >> 56), (u8)(x >> 48),
               (u8)(x >> 40), (u8)(x >> 32),
               (u8)(x >> 24), (u8)(x >> 16),
               (u8)(x >> 8), (u8)(x) }
    };
    return y.b;
}

static inline u64 le64(u64 x)
{
    union { u8 a[8]; u64 b; } y = {
        .a = { (u8)(x), (u8)(x >> 8),
               (u8)(x >> 16), (u8)(x >> 24),
               (u8)(x >> 32), (u8)(x >> 40),
               (u8)(x >> 48), (u8)(x >> 56) }
    };
    return y.b;
}

/*
 * Define byte swaps using the natural endian helpers
 *
 * This method relies on the compiler lifting byte swaps.
 */
#if _BYTE_ORDER == _BIG_ENDIAN
u16 bswap16(u16 x) { return le16(x); }
u32 bswap32(u32 x) { return le32(x); }
u64 bswap64(u64 x) { return le64(x); }
#endif

#if _BYTE_ORDER == _LITTLE_ENDIAN
u16 bswap16(u16 x) { return be16(x); }
u32 bswap32(u32 x) { return be32(x); }
u64 bswap64(u64 x) { return be64(x); }
#endif
#endif

/*
 * BSD host integer interfaces
 */

#ifndef __HOSTSWAP_DEFINED
static inline u16 htobe16(u16 x) { return be16(x); }
static inline u16 htole16(u16 x) { return le16(x); }
static inline u16 be16toh(u16 x) { return be16(x); }
static inline u16 le16toh(u16 x) { return le16(x); }

static inline u32 htobe32(u32 x) { return be32(x); }
static inline u32 htole32(u32 x) { return le32(x); }
static inline u32 be32toh(u32 x) { return be32(x); }
static inline u32 le32toh(u32 x) { return le32(x); }

static inline u64 htobe64(u64 x) { return be64(x); }
static inline u64 htole64(u64 x) { return le64(x); }
static inline u64 be64toh(u64 x) { return be64(x); }
static inline u64 le64toh(u64 x) { return le64(x); }
#endif

#if __SIZE_WIDTH__ == 64
#define _htobel htobe64
#define _beltoh be64toh
#define _htolel htole64
#define _leltoh le64toh
#else
#define _htobel htobe32
#define _beltoh be32toh
#define _htolel htole32
#define _leltoh le32toh
#endif

#ifdef __cplusplus
}
#endif

#if __STDC_VERSION__ >= 201112L

#define htobe(X) _Generic((X),                \
                 short: htobe16,              \
                 unsigned short: htobe16,     \
                 int: htobe32,                \
                 unsigned int: htobe32,       \
                 long: _htobel,               \
                 unsigned long: _htobel,      \
                 long long: htobe64,          \
                 unsigned long long: htobe64  \
                 )(X)

#define betoh(X) _Generic((X),                \
                 short: be16toh,              \
                 unsigned short: be16toh,     \
                 int: be32toh,                \
                 unsigned int: be32toh,       \
                 long: _beltoh,               \
                 unsigned long: _beltoh,      \
                 long long: be64toh,          \
                 unsigned long long: be64toh  \
                 )(X)

#define htole(X) _Generic((X),                \
                 short: htole16,              \
                 unsigned short: htole16,     \
                 int: htole32,                \
                 unsigned int: htole32,       \
                 long: _htolel,               \
                 unsigned long: _htolel,      \
                 long long: htole64,          \
                 unsigned long long: htole64  \
                 )(X)

#define letoh(X) _Generic((X),                \
                 short: le16toh,              \
                 unsigned short: le16toh,     \
                 int: le32toh,                \
                 unsigned int: le32toh,       \
                 long: _leltoh,               \
                 unsigned long: _leltoh,      \
                 long long: le64toh,          \
                 unsigned long long: le64toh  \
                 )(X)

#elif defined (__cplusplus)

template <typename T> T htobe(T x);

template<> short htobe<short>(short x) { return htobe16(x); }
template<> unsigned short htobe<unsigned short>(unsigned short x) { return htobe16(x); }
template<> int htobe<int>(int x) { return htobe32(x); }
template<> unsigned int htobe<unsigned int>(unsigned int x) { return htobe32(x); }
template<> long htobe<long>(long x) { return _htobel(x); }
template<> unsigned long htobe<unsigned long>(unsigned long x) { return _htobel(x); }
template<> long long htobe<long long>(long long x) { return htobe64(x); }
template<> unsigned long long htobe<unsigned long long>(unsigned long long x) { return htobe64(x); }

template <typename T> T htole(T x);

template<> short htole<short>(short x) { return htole16(x); }
template<> unsigned short htole<unsigned short>(unsigned short x) { return htole16(x); }
template<> int htole<int>(int x) { return htole32(x); }
template<> unsigned int htole<unsigned int>(unsigned int x) { return htole32(x); }
template<> long htole<long>(long x) { return _htolel(x); }
template<> unsigned long htole<unsigned long>(unsigned long x) { return _htolel(x); }
template<> long long htole<long long>(long long x) { return htole64(x); }
template<> unsigned long long htole<unsigned long long>(unsigned long long x) { return htole64(x); }

template <typename T> T betoh(T x);

template<> short betoh<short>(short x) { return be16toh(x); }
template<> unsigned short betoh<unsigned short>(unsigned short x) { return be16toh(x); }
template<> int betoh<int>(int x) { return be32toh(x); }
template<> unsigned int betoh<unsigned int>(unsigned int x) { return be32toh(x); }
template<> long betoh<long>(long x) { return _beltoh(x); }
template<> unsigned long betoh<unsigned long>(unsigned long x) { return _beltoh(x); }
template<> long long betoh<long long>(long long x) { return be64toh(x); }
template<> unsigned long long betoh<unsigned long long>(unsigned long long x) { return be64toh(x); }

template <typename T> T letoh(T x);

template<> short letoh<short>(short x) { return le16toh(x); }
template<> unsigned short letoh<unsigned short>(unsigned short x) { return le16toh(x); }
template<> int letoh<int>(int x) { return le32toh(x); }
template<> unsigned int letoh<unsigned int>(unsigned int x) { return le32toh(x); }
template<> long letoh<long>(long x) { return _leltoh(x); }
template<> unsigned long letoh<unsigned long>(unsigned long x) { return _leltoh(x); }
template<> long long letoh<long long>(long long x) { return le64toh(x); }
template<> unsigned long long letoh<unsigned long long>(unsigned long long x) { return le64toh(x); }

#endif

#if defined (_MSC_VER)
#define bswap_ulong bswap32
#else
#define bswap_ulong bswap64
#endif
