/* curve25519.c
 * NaCl/Sodium-compatible API for Curve25519 cryptography.
 *
 * Copyright (c) 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "curve25519.h"
#include "ws_attributes.h"

#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
#define HAVE_X25519
#endif

#ifdef HAVE_X25519
static inline void
copy_and_reverse(unsigned char *dest, const unsigned char *src, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dest[n - 1 - i] = src[i];
    }
}

static int
x25519_mpi(unsigned char *q, const unsigned char *n, gcry_mpi_t mpi_p)
{
    unsigned char priv_be[32];
    unsigned char result_be[32];
    size_t result_len = 0;
    gcry_mpi_t mpi = NULL;
    gcry_ctx_t ctx = NULL;
    gcry_mpi_point_t P = NULL;
    gcry_mpi_point_t Q = NULL;
    int r = -1;

    /* Default to infinity (all zeroes). */
    memset(q, 0, 32);

    /* Keys are in little-endian, but gcry_mpi_scan expects big endian. Convert
     * keys and ensure that the result is a valid Curve25519 secret scalar. */
    copy_and_reverse(priv_be, n, 32);
    priv_be[0] &= 127;
    priv_be[0] |= 64;
    priv_be[31] &= 248;
    gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, priv_be, 32, NULL);

    if (gcry_mpi_ec_new(&ctx, NULL, "Curve25519")) {
        /* Should not happen, possibly out-of-memory. */
        goto leave;
    }

    /* Compute Q = nP */
    Q = gcry_mpi_point_new(0);
    P = gcry_mpi_point_set(NULL, mpi_p, NULL, GCRYMPI_CONST_ONE);
    gcry_mpi_ec_mul(Q, mpi, P, ctx);

    /* Note: mpi is reused to store the result. */
    if (gcry_mpi_ec_get_affine(mpi, NULL, Q, ctx)) {
        /* Infinity. */
        goto leave;
    }

    if (gcry_mpi_print(GCRYMPI_FMT_USG, result_be, 32, &result_len, mpi)) {
        /* Should not happen, possibly out-of-memory. */
        goto leave;
    }
    copy_and_reverse(q, result_be, result_len);
    r = 0;

leave:
    gcry_mpi_point_release(P);
    gcry_mpi_point_release(Q);
    gcry_ctx_release(ctx);
    gcry_mpi_release(mpi);
    /* XXX erase priv_be and result_be */
    return r;
}

int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    unsigned char p_be[32];
    gcry_mpi_t mpi_p = NULL;

    copy_and_reverse(p_be, p, 32);
    /* Clear unused bit. */
    p_be[0] &= 0x7f;
    gcry_mpi_scan(&mpi_p, GCRYMPI_FMT_USG, p_be, 32, NULL);
    int r = x25519_mpi(q, n, mpi_p);
    gcry_mpi_release(mpi_p);
    return r;
}

int
crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    gcry_mpi_t mpi_basepoint_x = gcry_mpi_set_ui(NULL, 9);
    int r = x25519_mpi(q, n, mpi_basepoint_x);
    gcry_mpi_release(mpi_basepoint_x);
    return r;
}
#else
int
crypto_scalarmult_curve25519(unsigned char *q _U_, const unsigned char *n _U_,
                             const unsigned char *p _U_)
{
    return -1;
}

int
crypto_scalarmult_curve25519_base(unsigned char *q _U_, const unsigned char *n _U_)
{
    return -1;
}
#endif /* HAVE_X25519 */
