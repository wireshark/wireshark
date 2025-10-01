/** @file
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

#ifndef __CURVE25519_H__
#define __CURVE25519_H__

#include <wireshark.h>

/**
 * @brief Perform scalar multiplication on Curve25519 to compute a shared secret.
 *
 * Computes the shared secret `Q = X25519(n, P)` using the Curve25519 elliptic curve.
 * Both inputs and the output are 32-byte values.
 *
 * This function adheres to the X25519 specification and ensures constant-time
 * execution for cryptographic safety. It returns 0 on success and -1 on failure,
 * such as when the input scalar is invalid or the computation fails internally.
 *
 * @param q  Output buffer for the computed shared secret (32 bytes).
 * @param n  Input scalar (secret key, 32 bytes).
 * @param p  Input point (public key, 32 bytes).
 * @return   0 on success, -1 on failure.
 */
WS_DLL_PUBLIC
int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                                 const unsigned char *p);

/**
 * @brief Compute the Curve25519 public key from a secret scalar.
 *
 * Calculates the public key `Q = X25519(n, base_point)` using the Curve25519
 * elliptic curve. This function multiplies the 32-byte secret scalar `n` by
 * the standard base point to produce the corresponding public key `q`.
 *
 * @param q  Output buffer for the public key (32 bytes).
 * @param n  Input secret scalar (private key, 32 bytes).
 * @return   0 on success, -1 on failure.
 */
WS_DLL_PUBLIC
int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);

#endif /* __CURVE25519_H__ */
