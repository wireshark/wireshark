/*
 * bitmanip functions for C (generics) and C++ (template specializations)
 *
 * clz      -  count leading zero bits
 * ctz       - count trailing zero bits
 * popcnt    - bit population count
 * ispow2    - test if power of two
 * rupgtpow2 - round up to nearest power of two greater than
 * rupgepow2 - round up to nearest power of two greater than or equal to
 * rdnltpow2 - round down to nearest power of two less than
 * rdnlepow2 - round down to nearest power of two less than or equal to
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
#if defined (_MSC_VER)
#include <intrin.h>
#endif

#define _clz_defined 1
#define _ctz_defined 2
#define _popcnt_defined 4

#if defined (__GNUC__)
static inline uint clz_u32(uint val) { return val == 0 ? 32 : __builtin_clz(val); }
static inline uint clz_u64(ullong val) { return val == 0 ? 64 : __builtin_clzll(val); }
static inline uint ctz_u32(uint val) { return val == 0 ? 32 : __builtin_ctz(val); }
static inline uint ctz_u64(ullong val) { return val == 0 ? 64 : __builtin_ctzll(val); }
static inline uint popcnt_u32(uint val) { return __builtin_popcount(val); }
static inline uint popcnt_u64(ullong val) { return __builtin_popcountll(val); }
#define _bits_defined (_clz_defined | _ctz_defined | _popcnt_defined)
#elif defined (_MSC_VER) && defined (_M_X64)
static inline uint clz_u32(uint val) { return (int)_lzcnt_u32(val); }
static inline uint clz_u64(ullong val) { return (int)_lzcnt_u64(val); }
static inline uint ctz_u32(uint val) { return (int)_tzcnt_u32(val); }
static inline uint ctz_u64(ullong val) { return (int)_tzcnt_u64(val); }
static inline uint popcnt_u32(uint val) { return (int)__popcnt(val); }
static inline uint popcnt_u64(ullong val) { return (int)__popcnt64(val); }
#define _bits_defined (_clz_defined | _ctz_defined | _popcnt_defined)
#elif defined (_MSC_VER) && defined (_M_IX86)
static inline uint clz_u32(uint val) { uint long count; _BitScanReverse(&count, val); return val == 0 ? 32 : (count ^ 31); }
static inline uint clz_u64(ullong val) { uint long count; _BitScanReverse64(&count, val); return val == 0 ? 64 : (count ^ 63); }
static inline uint ctz_u32(uint val) { uint long count; _BitScanForward(&count, val); return val == 0 ? 32 : count; }
static inline uint ctz_u64(ullong val) { uint long count; _BitScanForward64(&count, val); return val == 0 ? 64 : count; }
#define _bits_defined (_clz_defined | _ctz_defined)
#else
#define _bits_defined 0
#endif

/*
 * algorithms from stanford bit twiddling hacks
 */

#if (_bits_defined & _popcnt_defined) != _popcnt_defined
static inline uint popcnt_u32(uint val)
{
    val = (val & 0x55555555) + ((val >> 1) & 0x55555555);
    val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
    val = (val & 0x0F0F0F0F) + ((val >> 4) & 0x0F0F0F0F);
    val = (val & 0x00FF00FF) + ((val >> 8) & 0x00FF00FF);
    val = (val & 0x0000FFFF) + ((val >>16) & 0x0000FFFF);
    return (uint)val;
}
static inline uint popcnt_u64(ullong val)
{
    val = (val & 0x5555555555555555ULL) + ((val >>  1) & 0x5555555555555555ULL);
    val = (val & 0x3333333333333333ULL) + ((val >>  2) & 0x3333333333333333ULL);
    val = (val & 0x0F0F0F0F0F0F0F0FULL) + ((val >>  4) & 0x0F0F0F0F0F0F0F0FULL);
    val = (val & 0x00FF00FF00FF00FFULL) + ((val >>  8) & 0x00FF00FF00FF00FFULL);
    val = (val & 0x0000FFFF0000FFFFULL) + ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (uint)((uint)(val) + (uint)(val >> 32));
}
#endif

#if (_bits_defined & _clz_defined) != _clz_defined
static inline uint clz_u32(uint x)
{
    x = x | (x >> 1);
    x = x | (x >> 2);
    x = x | (x >> 4);
    x = x | (x >> 8);
    x = x | (x >>16);
    return popcnt_u32(~x);
}

static inline uint clz_u64(ullong x)
{
    x = x | (x >> 1);
    x = x | (x >> 2);
    x = x | (x >> 4);
    x = x | (x >> 8);
    x = x | (x >>16);
    x = x | (x >>32);
    return popcnt_u64(~x);
}
#endif

#if (_bits_defined & _ctz_defined) != _ctz_defined
static inline uint ctz_u32(uint v)
{
    uint c = 32;
    v &= -(int)v;
    if (v) c--;
    if (v & 0x0000FFFF) c -= 16;
    if (v & 0x00FF00FF) c -= 8;
    if (v & 0x0F0F0F0F) c -= 4;
    if (v & 0x33333333) c -= 2;
    if (v & 0x55555555) c -= 1;
    return c;
}

static inline uint ctz_u64(ullong v)
{
    uint c = 64;
    v &= -(llong)v;
    if (v) c--;
    if (v & 0x00000000FFFFFFFFULL) c -= 32;
    if (v & 0x0000FFFF0000FFFFULL) c -= 16;
    if (v & 0x00FF00FF00FF00FFULL) c -= 8;
    if (v & 0x0F0F0F0F0F0F0F0FULL) c -= 4;
    if (v & 0x3333333333333333ULL) c -= 2;
    if (v & 0x5555555555555555ULL) c -= 1;
    return c;
}
#endif

static inline uint ispow2_u32(uint v) { return v && !(v & (v-1)); }
static inline uint ispow2_u64(ullong v) { return v && !(v & (v-1)); }

#if defined (_MSC_VER)
#define clz_ulong clz_u32
#define ctz_ulong ctz_u32
#define popcnt_ulong popcnt_u32
#define ispow2_ulong ispow2_u32
#else
#define clz_ulong clz_u64
#define ctz_ulong ctz_u64
#define popcnt_ulong popcnt_u64
#define ispow2_ulong ispow2_u64
#endif

/* C11 generics for clz, ctz, popcnt, ispow2, bswap */
#if __STDC_VERSION__ >= 201112L
#define clz(X) _Generic((X), uint: clz_u32, int: clz_u32, ulong: clz_ulong, long: clz_ulong, ullong: clz_u64, llong: clz_u64)(X)
#define ctz(X) _Generic((X), uint: ctz_u32, int: ctz_u32, ulong: ctz_ulong, long: ctz_ulong, ullong: ctz_u64, llong: ctz_u64)(X)
#define popcnt(X) _Generic((X), uint: popcnt_u32, int: popcnt_u32, ulong: popcnt_ulong, long: popcnt_ulong, ullong: popcnt_u64, llong: popcnt_u64)(X)
#define ispow2(X) _Generic((X), uint: ispow2_u32, int: ispow2_u32, ulong: ispow2_ulong, long: ispow2_ulong, ullong: ispow2_u64, llong: ispow2_u64)(X)
#define bswap(X) _Generic((X), ushort: bswap_u16, short: bswap_u16, uint: bswap_u32, int: bswap_u32, ulong: bswap_ulong, long: bswap_ulong, ullong: bswap_u64, llong: bswap_u64)(X)
#elif defined __cplusplus
/* C++ template specializations for clz, ctz, popcnt, ispow2, bswap */
template <typename T> uint clz(T v);
template <typename T> uint ctz(T v);
template <typename T> uint popcnt(T v);
template <typename T> uint ispow2(T v);
template <typename T> uint bswap(T v);
template <> short bswap<short>(short v) { return bswap_u16(v); }
template <> ushort bswap<ushort>(ushort v) { return bswap_u16(v); }
template <> uint clz<int>(int v) { return clz_u32(v); }
template <> uint ctz<int>(int v) { return ctz_u32(v); }
template <> uint popcnt<int>(int v) { return popcnt_u32(v); }
template <> uint ispow2<int>(int v) { return ispow2_u32(v); }
template <> int bswap<int>(int v) { return bswap_u32(v); }
template <> uint clz<uint>(uint v) { return clz_u32(v); }
template <> uint ctz<uint>(uint v) { return ctz_u32(v); }
template <> uint popcnt<uint>(uint v) { return popcnt_u32(v); }
template <> uint ispow2<uint>(uint v) { return ispow2_u32(v); }
template <> uint bswap<uint>(uint v) { return bswap_u32(v); }
template <> uint clz<llong>(llong v) { return clz_u64(v); }
template <> uint ctz<llong>(llong v) { return ctz_u64(v); }
template <> uint popcnt<llong>(llong v) { return popcnt_u64(v); }
template <> uint ispow2<llong>(llong v) { return ispow2_u64(v); }
template <> llong bswap<llong>(llong v) { return bswap_u64(v); }
template <> uint clz<ullong>(ullong v) { return clz_u64(v); }
template <> uint ctz<ullong>(ullong v) { return ctz_u64(v); }
template <> uint popcnt<ullong>(ullong v) { return popcnt_u64(v); }
template <> uint ispow2<ullong>(ullong v) { return ispow2_u64(v); }
template <> ullong bswap<ullong>(ullong v) { return bswap_u64(v); }
#endif

static inline uint rupgtpow2_u32(uint x) { return 1ull << (32 - clz(x-1)); }
static inline uint rupgepow2_u32(uint x) { return 1ull << (32 - clz(x)); }
static inline uint rdnlepow2_u32(uint x) { return 1ull << (31 - clz(x-1)); }
static inline uint rdnltpow2_u32(uint x) { return 1ull << (31 - clz(x)); }
static inline ullong rupgtpow2_u64(ullong x) { return 1ull << (64 - clz(x-1)); }
static inline ullong rupgepow2_u64(ullong x) { return 1ull << (64 - clz(x)); }
static inline ullong rdnlepow2_u64(ullong x) { return 1ull << (63 - clz(x-1)); }
static inline ullong rdnltpow2_u64(ullong x) { return 1ull << (63 - clz(x)); }

#if defined (_MSC_VER)
#define rupgtpow2_ulong rupgtpow2_u32
#define rupgepow2_ulong rupgepow2_u32
#define rdnlepow2_ulong rdnlepow2_u32
#define rdnltpow2_ulong rdnltpow2_u32
#else
#define rupgtpow2_ulong rupgtpow2_u64
#define rupgepow2_ulong rupgepow2_u64
#define rdnlepow2_ulong rdnlepow2_u64
#define rdnltpow2_ulong rdnltpow2_u64
#endif

/* C11 generics for roundpow2 */
#if __STDC_VERSION__ >= 201112L
#define rupgtpow2(X) _Generic((X), uint: rupgtpow2_u32, int: rupgtpow2_u32, ulong: rupgtpow2_ulong, long: rupgtpow2_ulong, ullong: rupgtpow2_u64, llong: rupgtpow2_u64)(X)
#define rupgepow2(X) _Generic((X), uint: rupgepow2_u32, int: rupgepow2_u32, ulong: rupgepow2_ulong, long: rupgepow2_ulong, ullong: rupgepow2_u64, llong: rupgepow2_u64)(X)
#define rdnlepow2(X) _Generic((X), uint: rdnlepow2_u32, int: rdnlepow2_u32, ulong: rdnlepow2_ulong, long: rdnlepow2_ulong, ullong: rdnlepow2_u64, llong: rdnlepow2_u64)(X)
#define rdnltpow2(X) _Generic((X), uint: rdnltpow2_u32, int: rdnltpow2_u32, ulong: rdnltpow2_ulong, long: rdnltpow2_ulong, ullong: rdnltpow2_u64, llong: rdnltpow2_u64)(X)
#elif defined __cplusplus
/* C++ template specializations for roundpow2 */
template <typename T> T rupgtpow2(T v);
template <typename T> T rupgepow2(T v);
template <typename T> T rdnlepow2(T v);
template <typename T> T rdnltpow2(T v);
template <> int rupgtpow2<int>(int v) { return rupgtpow2_u32(v); }
template <> int rupgepow2<int>(int v) { return rupgepow2_u32(v); }
template <> int rdnlepow2<int>(int v) { return rdnlepow2_u32(v); }
template <> int rdnltpow2<int>(int v) { return rdnltpow2_u32(v); }
template <> uint rupgtpow2<uint>(uint v) { return rupgtpow2_u32(v); }
template <> uint rupgepow2<uint>(uint v) { return rupgepow2_u32(v); }
template <> uint rdnlepow2<uint>(uint v) { return rdnlepow2_u32(v); }
template <> uint rdnltpow2<uint>(uint v) { return rdnltpow2_u32(v); }
template <> long rupgtpow2<long>(long v) { return rupgtpow2_u64(v); }
template <> long rupgepow2<long>(long v) { return rupgepow2_u64(v); }
template <> long rdnlepow2<long>(long v) { return rdnlepow2_u64(v); }
template <> long rdnltpow2<long>(long v) { return rdnltpow2_u64(v); }
template <> ulong rupgtpow2<ulong>(ulong v) { return rupgtpow2_u64(v); }
template <> ulong rupgepow2<ulong>(ulong v) { return rupgepow2_u64(v); }
template <> ulong rdnlepow2<ulong>(ulong v) { return rdnlepow2_u64(v); }
template <> ulong rdnltpow2<ulong>(ulong v) { return rdnltpow2_u64(v); }
template <> llong rupgtpow2<llong>(llong v) { return rupgtpow2_u64(v); }
template <> llong rupgepow2<llong>(llong v) { return rupgepow2_u64(v); }
template <> llong rdnlepow2<llong>(llong v) { return rdnlepow2_u64(v); }
template <> llong rdnltpow2<llong>(llong v) { return rdnltpow2_u64(v); }
template <> ullong rupgtpow2<ullong>(ullong v) { return rupgtpow2_u64(v); }
template <> ullong rupgepow2<ullong>(ullong v) { return rupgepow2_u64(v); }
template <> ullong rdnlepow2<ullong>(ullong v) { return rdnlepow2_u64(v); }
template <> ullong rdnltpow2<ullong>(ullong v) { return rdnltpow2_u64(v); }
#endif
