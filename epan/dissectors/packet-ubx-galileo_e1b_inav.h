/* packet-ubx-galileo_e1b_inav.h
 * u-blox UBX protocol dissection.
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2024 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_UBX_GALILEO_L1B_INAV_H
#define PACKET_UBX_H

#include <wsutil/pint.h>

extern const value_string DAY_NUMBER[];

extern void fmt_a0(char *label, int64_t c);
extern void fmt_a1(char *label, int32_t c);
extern void fmt_lat_correction(char *label, int32_t c);
extern void fmt_semi_circles_rate(char *label, int32_t c);

#endif
