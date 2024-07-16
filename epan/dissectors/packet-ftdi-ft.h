/* packet-ftdi-ft.h
 * FTDI FTxxxx USB converters dissector
 *
 * Copyright 2019 Tomasz Mon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_FTDI_FT_H__
#define __PACKET_FTDI_FT_H__

#include <glib.h>

typedef enum {
    FTDI_CHIP_UNKNOWN,
    FTDI_CHIP_FT8U232AM,
    FTDI_CHIP_FT232B,
    FTDI_CHIP_FT2232D,
    FTDI_CHIP_FT232R,
    FTDI_CHIP_FT2232H,
    FTDI_CHIP_FT4232H,
    FTDI_CHIP_FT232H,
    FTDI_CHIP_X_SERIES,
} FTDI_CHIP;

typedef enum {
    FTDI_INTERFACE_UNKNOWN,
    FTDI_INTERFACE_A,
    FTDI_INTERFACE_B,
    FTDI_INTERFACE_C,
    FTDI_INTERFACE_D,
} FTDI_INTERFACE;

typedef struct _ftdi_mpsse_info_t {
    uint32_t        bus_id;
    uint32_t        device_address;
    FTDI_CHIP       chip;
    FTDI_INTERFACE  iface;
    bool            mcu_mode;
} ftdi_mpsse_info_t;

#endif /* __PACKET_FTDI_FT_H__ */
