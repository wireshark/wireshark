/* crc.h
 * header file of crc.c
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Mike Harvey <michael.harvey@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CRC_H
#define CRC_H

#include <glib.h>
#include <stdint.h>

/* use lookup tables to compute CRC values */
#ifdef STATIC_DATA
extern uint8_t crc8_table[];
extern uint32_t crc32_table[];
#else
void wimax_mac_gen_crc32_table(void);
void wimax_mac_gen_crc8_table(void);
#endif

uint32_t wimax_mac_calc_crc32(const uint8_t *data, unsigned data_len);
uint16_t wimax_mac_calc_crc16(const uint8_t *data, unsigned data_len);
uint8_t wimax_mac_calc_crc8(const uint8_t *data, unsigned data_len);

#endif /* CRC_H */
