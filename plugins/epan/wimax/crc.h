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

/**
 * @brief Generates a CRC32 lookup table.
 *
 * This function initializes the CRC32 lookup table using a little-endian (reflected) algorithm.
 */
void wimax_mac_gen_crc32_table(void);

/**
 * @brief Generates a CRC8 table for WiMAX MAC calculations.
 *
 * This function initializes a CRC8 lookup table used in WiMAX MAC layer for error detection.
 */
void wimax_mac_gen_crc8_table(void);
#endif

extern uint16_t crc16_table[];

/**
 * @brief Calculate the CRC32 checksum for a given data buffer.
 *
 * @param data Pointer to the data buffer.
 * @param data_len Length of the data buffer.
 * @return uint32_t The calculated CRC32 checksum.
 */
uint32_t wimax_mac_calc_crc32(const uint8_t *data, unsigned data_len);

/**
 * @brief Calculate the CRC-16 checksum for a given data buffer.
 *
 * This function computes the CRC-16 checksum using a lookup table and XOR operations.
 *
 * @param data Pointer to the input data buffer.
 * @param data_len Length of the data buffer.
 * @return The calculated CRC-16 value.
 */
uint16_t wimax_mac_calc_crc16(const uint8_t *data, unsigned data_len);

/**
 * @brief Calculate the CRC-8 value for a given data buffer.
 *
 * @param data Pointer to the input data buffer.
 * @param data_len Length of the input data buffer.
 * @return uint8_t The calculated CRC-8 value.
 */
uint8_t wimax_mac_calc_crc8(const uint8_t *data, unsigned data_len);

#endif /* CRC_H */
