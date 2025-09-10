/*
 * 128-bit integer type with logic, shifts, arithmetic and bitmanip.
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

/* i128_t configuration */

#define I128_USE_BITS
#define I128_USE_TYPES
#define I128_USE_ENDIAN
#define I128_USE_INTRIN
#undef I128_USE_I128
#define I128_USE_INLINE
#undef I128_USE_LIBDIVIDE

#if defined I128_USE_LIBDIVIDE
#include "libdivide.h"
#endif

#if defined I128_USE_BITS
#include "bits.h"
#elif defined __GNUC__
#define clz(x) __extension__ ({ uint n = __builtin_clzll(x); n == 0 ? 64 : n; })
#define ctz(x) __extension__ ({ uint n = __builtin_ctzll(x); n == 0 ? 64 : n; })
#define popcnt(x) __builtin_popcount(x)
#define bswap64(x) __builtin_bswap64(x)
#elif defined _MSC_VER
#include <intrin.h>
#define clz(x) _lzcnt_u64(x)
#define ctz(x) _tzcnt_u64(x)
#define popcnt(x) __popcnt64(x)
#define bswap64(x) _byteswap_uint64(x)
#endif

#if defined I128_USE_TYPES
#include "types.h"
#else
typedef unsigned int uint;
typedef signed char i8;
typedef unsigned char u8;
typedef signed int i32;
typedef unsigned int u32;
typedef signed long long i64;
typedef unsigned long long u64;
#endif

#if defined I128_USE_ENDIAN
#include "endian.h"
#else
#define BYTE_ORDER    1234
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321
#endif

#if defined I128_USE_INLINE
#define _int_func_ static inline
#else
#define _int_func_
#endif

#if defined __GNUC__
#define i128_unused __attribute__ ((unused))
#else
#define i128_unused
#endif

/* i128_t structure */

typedef struct i128_t i128_t;
struct i128_t
{
    union {
        u64 n[2];
        u8 b[16];
#if defined(__SIZEOF_INT128__)
        __uint128_t m;
#endif
        struct {
#if BYTE_ORDER == LITTLE_ENDIAN
            u64 lo;
            i64 hi;
#endif
#if BYTE_ORDER == BIG_ENDIAN
            i64 hi;
            u64 lo;
#endif
        };
    };
};

/* i128_t interface */

_int_func_ i128_t i128_from_i64(i64 n);
_int_func_ i128_t i128_from_u64(u64 n);
_int_func_ i128_t i128_from_uv64(u64 *v);
_int_func_ i64 i64_from_i128(i128_t n);
_int_func_ u64 u64_from_i128(i128_t n);
_int_func_ u64* uv64_from_i128(i128_t *v);

_int_func_ i128_t i128_not(i128_t u);
_int_func_ i128_t i128_and(i128_t u, i128_t v);
_int_func_ i128_t i128_or(i128_t u, i128_t v);
_int_func_ i128_t i128_xor(i128_t u, i128_t v);
_int_func_ i128_t i128_sll(i128_t u, uint shamt);
_int_func_ i128_t i128_srl(i128_t u, uint shamt);
_int_func_ i128_t i128_sra(i128_t u, uint shamt);

_int_func_ i128_t i128_neg(i128_t u);
_int_func_ i128_t i128_add(i128_t u, i128_t v);
_int_func_ i128_t i128_sub(i128_t u, i128_t v);
_int_func_ i128_t i128_mul(i128_t u, i128_t v);
_int_func_ i128_t i128_mulu(i128_t u, i128_t v);

i128_t i128_div(i128_t u, i128_t v);
i128_t i128_divu(i128_t u, i128_t v);
i128_t i128_rem(i128_t u, i128_t v);
i128_t i128_remu(i128_t u, i128_t v);

static inline i128_t i128_divmod(i128_t u, i128_t v, i128_t *r);
static inline i128_t i128_divmodu(i128_t u, i128_t v, i128_t *r);

_int_func_ int i128_cmp_eq(i128_t u, i128_t v);
_int_func_ int i128_cmp_lt(i128_t u, i128_t v);
_int_func_ int i128_cmp_gt(i128_t u, i128_t v);
_int_func_ int i128_cmp_ltu(i128_t u, i128_t v);
_int_func_ int i128_cmp_gtu(i128_t u, i128_t v);
_int_func_ int i128_cmp_t(i128_t u, i128_t v);
_int_func_ int i128_cmp_tu(i128_t u, i128_t v);

_int_func_ uint i128_ctz(i128_t u);
_int_func_ uint i128_clz(i128_t u);
_int_func_ uint i128_popcnt(i128_t u);
_int_func_ i128_t i128_bswap(i128_t u);
_int_func_ i128_t i128_brev(i128_t u);

/* 64-bit 128-bit compiler intrinsics */

#if !(defined I128_USE_I128 && defined(__SIZEOF_INT128__))

/* 64-bit 128-bit compiler intrinsics forward decls */

static inline i128_t i128_umul_i64_i64(u64 x, u64 y);
static inline u64 i64_umulh_i64_i64(u64 x, u64 y);
static inline u64 i64_udiv_i128_i64(i128_t x, u64 y, u64 *r);
static inline u64 i64_udiv_i128_i128(i128_t u, i128_t v, i128_t *r);

/* i128_umul_i64_i64 */

#if defined I128_USE_INTRIN && defined(__SIZEOF_INT128__)
static inline i128_t i128_umul_i64_i64(u64 x, u64 y)
{
    i128_t r;
    r.m = (__uint128_t)x * (__uint128_t)y;
    return r;
}
#elif defined I128_USE_INTRIN && defined(_MSC_VER) && defined(_M_X64)
static inline i128_t i128_umul_i64_i64(u64 x, u64 y)
{
    i128_t r;
    u64 hi;
    _umul128(x, y, &hi);
    r.lo = x * y;
    r.hi = hi;
    return r;
}
#else
static inline i128_t i128_umul_i64_i64(u64 x, u64 y)
{
    const u64 mask = 0xffffffffll;
    u64 x0 =    x       & mask;
    u64 x1 =    x >> 32 & mask;
    u64 y0 =    y       & mask;
    u64 y1 =    y >> 32 & mask;
    u64 z0 =    x0 * y0;
    u64 z1 =    x1 * y0;
    u64 z2 =    x0 * y1;
    u64 z3 =    x1 * y1;
    u64 z4 =    z1 + (z0 >> 32);
    u64 c1 =    z2 + (z4 & mask);
    u64 hi =    z3 + (z4 >> 32) + (c1 >> 32);
    i128_t r;
    r.lo = x * y;
    r.hi = hi;
    return r;
}
#endif

/* i64_umulh_i64_i64 */

#if defined I128_USE_INTRIN && defined(__SIZEOF_INT128__)
static inline u64 i64_umulh_i64_i64(u64 x, u64 y)
{
    return (u64)(((__uint128_t)x * (__uint128_t)y) >> 64);
}
#elif defined I128_USE_INTRIN && defined(_MSC_VER) && defined(_M_X64)
static inline u64 i64_umulh_i64_i64(u64 x, u64 y)
{
    return __umulh(x, y);
}
#else
static inline u64 i64_umulh_i64_i64(u64 x, u64 y)
{
    const u64 mask = 0xffffffffll;
    u64 x0 =    x       & mask;
    u64 x1 =    x >> 32 & mask;
    u64 y0 =    y       & mask;
    u64 y1 =    y >> 32 & mask;
    u64 z0 =    x0 * y0;
    u64 z1 =    x1 * y0;
    u64 z2 =    x0 * y1;
    u64 z3 =    x1 * y1;
    u64 z4 =    z1 + (z0 >> 32);
    u64 c1 =    z2 + (z4 & mask);
    u64 hi =    z3 + (z4 >> 32) + (c1 >> 32);
    return hi;
}
#endif

/* i64_udiv_i128_i64 */

#if defined I128_USE_INTRIN && defined(_MSC_VER) && defined(_M_X64)
static inline u64 i64_udiv_i128_i64(i128_t x, u64 y, u64 *r)
{
    return _udiv128(x.hi, x.lo, y, r);
}
#elif defined I128_USE_INTRIN && defined(__GNUC__) && defined(__x86_64__)
static inline u64 i64_udiv_i128_i64(i128_t x, u64 y, u64 *r)
{
    u64 q;
    __asm__("divq %[v]" : "=a"(q), "=d"(*r) : [v] "r"(y), "a"(x.lo), "d"(x.hi));
    return q;
}
#else
static inline u64 i64_udiv_i128_i64(i128_t x, u64 y, u64 *r)
{
    // Computes a 128 / 64 -> 64 bit division, with a 64 bit remainder.
    // zlib License: based on https://github.com/ridiculousfish/libdivide

    const u64 b = ((u64)1 << 32);

    u32 q1, q0, den1, den0, num1, num0;
    u64 rem, qhat, rhat, c1, c2;
    int sh;

    // Check for overflow and divide by 0.
    if ((u64)x.hi >= y) {
        if (r != NULL) *r = ~0ull;
        return ~0ull;
    }

    // Determine the normalization factor.
    sh = clz(y);
    y <<= sh;
    x = i128_sll(x, sh);

    // Extract the low digits of the numerator and both digits of the denominator.
    num1 = (u32)(x.lo >> 32);
    num0 = (u32)(x.lo & 0xFFFFFFFFu);
    den1 = (u32)(y >> 32);
    den0 = (u32)(y & 0xFFFFFFFFu);

    // We wish to compute q1 = [n3 n2 n1] / [d1 d0].
    // Estimate q1 as [n3 n2] / [d1], and then correct it.
    // Note while qhat may be 2 digits, q1 is always 1 digit.
    qhat = (u64)x.hi / den1;
    rhat = (u64)x.hi % den1;
    c1 = qhat * den0;
    c2 = rhat * b + num1;
    if (c1 > c2) qhat -= (c1 - c2 > y) ? 2 : 1;
    q1 = (u32)qhat;

    // Compute the true (partial) remainder.
    rem = (u64)x.hi * b + num1 - q1 * y;

    // We wish to compute q0 = [rem1 rem0 n0] / [d1 d0].
    // Estimate q0 as [rem1 rem0] / [d1] and correct it.
    qhat = rem / den1;
    rhat = rem % den1;
    c1 = qhat * den0;
    c2 = rhat * b + num0;
    if (c1 > c2) qhat -= (c1 - c2 > y) ? 2 : 1;
    q0 = (u32)qhat;

    // Return remainder if requested.
    if (r != NULL) *r = (rem * b + num0 - q0 * y) >> sh;
    return ((u64)q1 << 32) | q0;
}
#endif

/* i64_udiv_i128_i128 */

static inline u64 i64_udiv_i128_i128(i128_t u, i128_t v, i128_t *r)
{
    // Computes a 128 / 128 -> 64 bit division, with a 128 bit remainder.
    // zlib License: based on https://github.com/ridiculousfish/libdivide

    // Here v >= 2**64
    // We know that v.hi != 0, so count leading zeros is OK
    // We have 0 <= n <= 63
    uint n = clz(v.hi);

    // Normalize the divisor so its MSB is 1
    i128_t v1t = i128_sll(v, n);
    u64 v1 = v1t.hi;  // i.e. v1 = v1t >> 64

    // To ensure no overflow
    i128_t u1 = i128_srl(u, 1);

    // Get quotient from divide unsigned insn.
    u64 ri;
    u64 q1 = i64_udiv_i128_i64(u1, v1, &ri);

    // Undo normalization and division of u by 2.
    i128_t q0 = i128_from_u64(q1);
    q0 = i128_sll(q0, n);
    q0 = i128_srl(q0, 63);

    // Make q0 correct or too small by 1
    // Equivalent to `if (q0 != 0) q0 = q0 - 1;`
    if (q0.hi != 0 || q0.lo != 0) {
        q0.hi -= (q0.lo == 0);  // borrow
        q0.lo -= 1;
    }

    // Now q0 is correct.
    // Compute q0 * v as q0v
    // = (q0.hi << 64 + q0.lo) * (v.hi << 64 + v.lo)
    // = (q0.hi * v.hi << 128) + (q0.hi * v.lo << 64) +
    //   (q0.lo * v.hi <<  64) + q0.lo * v.lo)
    // Each term is 128 bit
    // High half of full product (upper 128 bits!) are dropped
    i128_t q0v = i128_from_i64(0);
    q0v.hi = (u64)q0.hi * v.lo + q0.lo * (u64)v.hi + i64_umulh_i64_i64(q0.lo, v.lo);
    q0v.lo = q0.lo * v.lo;

    // Compute u - q0v as u_q0v
    // This is the remainder
    i128_t u_q0v = u;
    u_q0v.hi -= q0v.hi + (u.lo < q0v.lo);  // second term is borrow
    u_q0v.lo -= q0v.lo;

    // Check if u_q0v >= v
    // This checks if our remainder is larger than the divisor
    if (((u64)u_q0v.hi > (u64)v.hi) || (u_q0v.hi == v.hi && u_q0v.lo >= v.lo)) {
        // Increment q0
        q0.lo += 1;
        q0.hi += (q0.lo == 0);  // carry

        // Subtract v from remainder
        u_q0v.hi -= v.hi + (u_q0v.lo < v.lo);
        u_q0v.lo -= v.lo;
    }

    r->hi = u_q0v.hi;
    r->lo = u_q0v.lo;

    return q0.lo;
}
#endif

#if defined I128_USE_I128 && defined(__SIZEOF_INT128__)

/* __int128_t implementation */

_int_func_ i128_t i128_from_i64(i64 n)
{
    i128_t x;
    x.m = n;
    return x;
}

_int_func_ i128_t i128_from_u64(u64 n)
{
    i128_t x;
    x.m = n;
    return x;
}

_int_func_ i128_t i128_from_uv64(u64 *v)
{
    i128_t x;
#if BYTE_ORDER == LITTLE_ENDIAN
    x.m = (__uint128_t)v[0] | (__uint128_t)v[1] << 64;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    x.m = (__uint128_t)v[1] | (__uint128_t)v[0] << 64;
#endif
    return x;
}

_int_func_ i128_t i128_not(i128_t u)
{
    i128_t x;
    x.m = ~u.m;
    return x;
}

_int_func_ i128_t i128_and(i128_t u, i128_t v)
{
    i128_t x;
    x.m = u.m & v.m;
    return x;
}

_int_func_ i128_t i128_or(i128_t u, i128_t v)
{
    i128_t x;
    x.m = u.m | v.m;
    return x;
}

_int_func_ i128_t i128_xor(i128_t u, i128_t v)
{
    i128_t x;
    x.m = u.m ^ v.m;
    return x;
}

_int_func_ i128_t i128_sll(i128_t u, uint shamt)
{
    i128_t x;
    x.m = u.m << shamt;
    return x;
}

_int_func_ i128_t i128_srl(i128_t u, uint shamt)
{
    i128_t x;
    x.m = (__uint128_t)u.m >> shamt;
    return x;
}

_int_func_ i128_t i128_sra(i128_t u, uint shamt)
{
    i128_t x;
    x.m = (__int128_t)u.m >> shamt;
    return x;
}

_int_func_ i128_t i128_neg(i128_t u)
{
    i128_t x;
    x.m = -u.m;
    return x;
}

_int_func_ i128_t i128_add(i128_t u, i128_t v)
{
    i128_t x;
    x.m = u.m + v.m;
    return x;
}

_int_func_ i128_t i128_sub(i128_t u, i128_t v)
{
    i128_t x;
    x.m = u.m - v.m;
    return x;
}

_int_func_ i128_t i128_mul(i128_t u, i128_t v)
{
    i128_t x;
    u64 us, vs, rs;

    x = i128_mulu(u, v);
    us = u.hi & (1LL << 63);
    vs = v.hi & (1LL << 63);
    rs =  us ^ vs;
    x.hi = (x.hi & ((1ULL << 63) - 1)) | rs;

    return x;
}

_int_func_ i128_t i128_mulu(i128_t u, i128_t v)
{
    i128_t x;
    x.m = (__uint128_t)u.m * (__uint128_t)v.m;
    return x;
}

_int_func_ i128_t i128_divmodu(i128_t u, i128_t v, i128_t *r)
{
    i128_t q;
    q.m = (__uint128_t)u.m / (__uint128_t)v.m;
    r->m = (__uint128_t)u.m % (__uint128_t)v.m;
    return q;
}

_int_func_ int i128_cmp_eq(i128_t u, i128_t v)
{
    return u.m == v.m;
}

_int_func_ int i128_cmp_lt(i128_t u, i128_t v)
{
    return (__int128_t)u.m < (__int128_t)v.m;
}

_int_func_ int i128_cmp_gt(i128_t u, i128_t v)
{
    return (__int128_t)u.m > (__int128_t)v.m;
}

_int_func_ int i128_cmp_ltu(i128_t u, i128_t v)
{
    return (__uint128_t)u.m < (__uint128_t)v.m;
}

_int_func_ int i128_cmp_gtu(i128_t u, i128_t v)
{
    return (__uint128_t)u.m > (__uint128_t)v.m;
}

_int_func_ int i128_cmp_t(i128_t u, i128_t v)
{
    __int128_t x = u.m - v.m;
    return -(x < 0) + (x > 0);
}

_int_func_ int i128_cmp_tu(i128_t u, i128_t v)
{
    __uint128_t x = u.m - v.m;
    return -(x > u.m) + (x < u.m);
}

#else

/* i128_t 64-bit implementation */

_int_func_ i128_t i128_from_i64(i64 n)
{
    i128_t x;
    x.lo = n;
    x.hi = (n >> 63);
    return x;
}

_int_func_ i128_t i128_from_u64(u64 n)
{
    i128_t x;
    x.lo = n;
    x.hi = 0;
    return x;
}

_int_func_ i128_t i128_from_uv64(u64 *v)
{
    i128_t x;
#if BYTE_ORDER == LITTLE_ENDIAN
    x.lo = v[0];
    x.hi = v[1];
#endif
#if BYTE_ORDER == BIG_ENDIAN
    x.lo = v[1];
    x.hi = v[0];
#endif
    return x;
}

_int_func_ i128_t i128_not(i128_t u)
{
    i128_t x;
    x.lo = ~u.lo;
    x.hi = ~u.hi;
    return x;
}

_int_func_ i128_t i128_and(i128_t u, i128_t v)
{
    i128_t x;
    x.lo = u.lo & v.lo;
    x.hi = u.hi & v.hi;
    return x;
}

_int_func_ i128_t i128_or(i128_t u, i128_t v)
{
    i128_t x;
    x.lo = u.lo | v.lo;
    x.hi = u.hi | v.hi;
    return x;
}

_int_func_ i128_t i128_xor(i128_t u, i128_t v)
{
    i128_t x;
    x.lo = u.lo ^ v.lo;
    x.hi = u.hi ^ v.hi;
    return x;
}

_int_func_ i128_t i128_sll(i128_t u, uint shamt)
{
    i128_t x;
    if (shamt == 0) {
        x.lo = u.lo;
        x.hi = u.hi;
    } else if (shamt < 64) {
        x.lo = (u64)(u.lo << shamt);
        x.hi = (u64)(u.hi << shamt) | ((u64)u.lo >> (64-shamt));
    } else {
        shamt -= 64;
        x.lo = 0;
        x.hi = (u64)(u.lo << shamt);
    }
    return x;
}

_int_func_ i128_t i128_srl(i128_t u, uint shamt)
{
    i128_t x;
    if (shamt == 0) {
        x.lo = u.lo;
        x.hi = u.hi;
    } else if (shamt < 64) {
        x.lo = ((u64)u.lo >> shamt) | ((u64)u.hi << (64-shamt));;
        x.hi = ((u64)u.hi >> shamt);
    } else {
        shamt -= 64;
        x.lo = ((u64)u.hi >> shamt);
        x.hi = 0;
    }
    return x;
}

_int_func_ i128_t i128_sra(i128_t u, uint shamt)
{
    i128_t x;
    if (shamt == 0) {
        x.lo = u.lo;
        x.hi = u.hi;
    } else if (shamt < 64) {
        x.lo = ((u64)u.lo >> shamt) | ((u64)u.hi << (64-shamt));
        x.hi = ((i64)u.hi >> shamt);
    } else {
        shamt -= 64;
        x.lo = ((i64)u.hi >> shamt);
        x.hi = ((i64)u.hi >> 63);
    }
    return x;
}

_int_func_ i128_t i128_neg(i128_t u)
{
    i128_t x;
    x.lo = -(i64)u.lo;
    x.hi = -(i64)u.hi - !!x.lo;
    return x;
}

_int_func_ i128_t i128_add(i128_t u, i128_t v)
{
    i128_t x;
    x.lo = u.lo + v.lo;
    x.hi = u.hi + v.hi + (x.lo < u.lo);
    return x;
}

_int_func_ i128_t i128_sub(i128_t u, i128_t v)
{
    i128_t x;
    x.lo = u.lo - v.lo;
    x.hi = u.hi - v.hi - (x.lo > u.lo);
    return x;
}

_int_func_ i128_t i128_mul(i128_t u, i128_t v)
{
    i128_t x;
    u64 us, vs, rs;

    x = i128_mulu(u, v);
    us = u.hi & (1LL << 63);
    vs = v.hi & (1LL << 63);
    rs =  us ^ vs;
    x.hi = (x.hi & ((1ULL << 63) - 1)) | rs;

    return x;
}

_int_func_ i128_t i128_mulu(i128_t u, i128_t v)
{
    i128_t x;
    u64 x0 = u.lo;
    u64 x1 = u.hi;
    u64 y0 = v.lo;
    u64 y1 = v.hi;
    x = i128_umul_i64_i64(x0, y0);
    x.hi += x0 * y1 + x1 * y0;
    return x;
}

_int_func_ int i128_cmp_eq(i128_t u, i128_t v)
{
    return (u.hi == v.hi && u.lo == v.lo);
}

_int_func_ int i128_cmp_lt(i128_t u, i128_t v)
{
    return ((i64)u.hi < (i64)v.hi || (u.hi == v.hi && u.lo < v.lo));
}

_int_func_ int i128_cmp_gt(i128_t u, i128_t v)
{
    return ((i64)u.hi > (i64)v.hi || (u.hi == v.hi && u.lo > v.lo));
}

_int_func_ int i128_cmp_ltu(i128_t u, i128_t v)
{
    return ((u64)u.hi < (u64)v.hi || (u.hi == v.hi && u.lo < v.lo));
}

_int_func_ int i128_cmp_gtu(i128_t u, i128_t v)
{
    return ((u64)u.hi > (u64)v.hi || (u.hi == v.hi && u.lo > v.lo));
}

_int_func_ int i128_cmp_t(i128_t u, i128_t v)
{
    return ((i64)u.hi > (i64)v.hi || (u.hi == v.hi && u.lo > v.lo))
         - ((i64)u.hi < (i64)v.hi || (u.hi == v.hi && u.lo < v.lo));
}

_int_func_ int i128_cmp_tu(i128_t u, i128_t v)
{
    return ((u64)u.hi > (u64)v.hi || (u.hi == v.hi && u.lo > v.lo))
         - ((u64)u.hi < (u64)v.hi || (u.hi == v.hi && u.lo < v.lo));
}

#endif

/* 128-bit unsigned divmod using optimized intrinsics */

#if !(defined I128_USE_I128 && defined(__SIZEOF_INT128__))
static inline i128_t i128_divmodu(i128_t u, i128_t v, i128_t *r)
{
    i128_t q;

    if (v.hi == 0 && v.lo == 0) {
        q = i128_from_i64(-1);
        *r = u;
    }
    else if (u.hi == 0) {
        if (v.hi == 0) {
            q.hi = 0;
            q.lo = u.lo / v.lo;
            r->hi = 0;
            r->lo = u.lo % v.lo;
        } else {
            q = i128_from_u64(0);
            *r = u;
        }
    }
#if defined I128_USE_LIBDIVIDE
    else if (v.hi == 0) {
        i128_t q;
        r->hi = 0;
        if (u.hi < v.lo) {
            q.hi = 0;
            q.lo = libdivide_128_div_64_to_64(u.hi, u.lo, v.lo, (uint64_t *)&r->lo);
        } else {
            i128_t u2, u3;
            u2 = i128_from_u64(u.hi);
            q.hi = libdivide_128_div_64_to_64(u2.hi, u2.lo, v.lo, (uint64_t *)&u3.hi);
            u3.lo = u.lo;
            q.lo = libdivide_128_div_64_to_64(u3.hi, u3.lo, v.lo, (uint64_t *)&r->lo);
        }
        return q;
    }
    else {
        q.hi = 0;
        q.lo = libdivide_128_div_128_to_64(u.hi, u.lo, v.hi, v.lo,
            (uint64_t*)&r->hi, (uint64_t*)&r->lo);
    }
#else
    else if (v.hi == 0) {
        i128_t q;
        r->hi = 0;
        if ((u64)u.hi < v.lo) {
            q.hi = 0;
            q.lo = i64_udiv_i128_i64(u, v.lo, &r->lo);
        } else {
            i128_t u2, u3;
            u2 = i128_from_u64(u.hi);
            q.hi = i64_udiv_i128_i64(u2, v.lo, (u64*)&u3.hi);
            u3.lo = u.lo;
            q.lo = i64_udiv_i128_i64(u3, v.lo, &r->lo);
        }
        return q;
    }
    else {
        q.hi = 0;
        q.lo = i64_udiv_i128_i128(u, v, r);
    }
#endif

    return q;
}
#endif

/* 128-bit signed divmod layered on unsigned divmod */

static inline i128_t i128_divmod(i128_t u, i128_t v, i128_t *r)
{
    i128_t q, us, vs, rs;

    us = i128_sra(u, 127);
    vs = i128_sra(v, 127);
    rs =  i128_xor(us, vs);
    u = i128_sub(i128_xor(u, us), us);
    v = i128_sub(i128_xor(v, vs), vs);
    q = i128_sub(i128_xor(i128_divmodu(u, v, r), rs), rs);
    *r = i128_sub(i128_xor(*r, us), us);

    return q;
}

i128_t i128_div(i128_t u, i128_t v)
{
    i128_t q, r i128_unused;
    q = i128_divmod(u, v, &r);
    return q;
}

i128_t i128_divu(i128_t u, i128_t v)
{
    i128_t q, r i128_unused;
    q = i128_divmodu(u, v, &r);
    return q;
}

i128_t i128_rem(i128_t u, i128_t v)
{
    i128_t q i128_unused, r;
    q = i128_divmod(u, v, &r);
    return r;
}

i128_t i128_remu(i128_t u, i128_t v)
{
    i128_t q i128_unused, r;
    q = i128_divmodu(u, v, &r);
    return r;
}

/* 128-bit downcasts */

_int_func_ i64 i64_from_i128(i128_t n)
{
    return (i64)n.lo;
}

_int_func_ u64 u64_from_i128(i128_t n)
{
    return (u64)n.lo;
}

_int_func_ u64* uv64_from_i128(i128_t *v)
{
    return v->n;
}

/* 128-bit bitmanip */

_int_func_ uint i128_ctz(i128_t u)
{
    int n = ctz(u.lo);
    if (n == 64) n += ctz(u.hi);
    return n;
}

_int_func_ uint i128_clz(i128_t u)
{
    int n = clz(u.hi);
    if (n == 64) n += clz(u.lo);
    return n;
}

_int_func_ uint i128_popcnt(i128_t u)
{
    return popcnt(u.lo) + popcnt(u.hi);
}

_int_func_ i128_t i128_bswap(i128_t u)
{
    i128_t x;
    x.lo = bswap64(u.hi);
    x.hi = bswap64(u.lo);
    return x;
}

static inline u8 i8_brev(u8 u)
{
    // Reverse the bits in a byte with 4 operations (64-bit multiply, no division):
    // Source: Stanford Bit Twiddling Hacks
    // https://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith64Bits
    return (u8)(((u * 0x80200802ULL) & 0x0884422110ULL) * 0x0101010101ULL >> 32);
}

_int_func_ i128_t i128_brev(i128_t u)
{
    i128_t r = { 0 };
    for (unsigned i = 0; i < 16; i++) {
        r.b[i] = (u8)i8_brev(u.b[15-i]);
    }
    return r;
}
