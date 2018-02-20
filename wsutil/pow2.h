/* ws_pow2.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_POW2_H__
#define __WS_POW2_H__

/*
 * Macros to calculate pow2^M, for various power-of-2 values and positive
 * integer values of M.  That's (2^N)^M, i.e. 2^(N*M).
 *
 * The first argument is the type of the desired result; the second
 * argument is M.
 */
#define pow2(type, m)     (((type)1U) << (m))
#define pow4(type, m)     (((type)1U) << (2*(m)))
#define pow8(type, m)     (((type)1U) << (3*(m)))
#define pow16(type, m)    (((type)1U) << (4*(m)))
#define pow32(type, m)    (((type)1U) << (5*(m)))
#define pow64(type, m)    (((type)1U) << (6*(m)))
#define pow128(type, m)   (((type)1U) << (7*(m)))
#define pow256(type, m)   (((type)1U) << (8*(m)))

#endif /* __WS_POW2_H__ */
