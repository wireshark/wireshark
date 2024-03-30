/** @file
 *
 * Definitions for tap registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAPS_H__
#define __TAPS_H__

#include <glib.h>

#include <epan/tap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern tap_reg_t const tap_reg_listener[];

extern const unsigned long tap_reg_listener_count;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAPS_H__ */
