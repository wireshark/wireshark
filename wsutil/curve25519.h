/* curve25519.h
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

/*
 * Callers MUST check GCRYPT_VERSION_NUMBER >= 0x010700 before using this API.
 */

#ifndef __CURVE25519_H__
#define __CURVE25519_H__

#include "ws_symbol_export.h"
#include "wsgcrypt.h"

/*
 * Computes Q = X25519(n, P). In other words, given the secret key n, the public
 * key P, compute the shared secret Q. Each key is 32 bytes long.
 * Returns 0 on success or -1 on failure.
 */
WS_DLL_PUBLIC
int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                                 const unsigned char *p);

/*
 * Computes the Curve25519 32-byte public key Q from the 32-byte secret key n.
 * Returns 0 on success or -1 on failure.
 */
WS_DLL_PUBLIC
int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);

#endif /* __CURVE25519_H__ */
