/* packet-i2c.h
 * Shared types for I2C dissectors
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_I2C_H__
#define __PACKET_I2C_H__

#include <epan/packet.h>

/*
 * Packet-scoped metadata for one I2C message.
 *
 * The source container owns the capture-specific details. The returned
 * metadata is packet-scoped and must not be retained after the current
 * packet's dissection.
 */
typedef struct {
    uint8_t bus;
} i2c_message_data;

const i2c_message_data *i2c_message_data_get(packet_info *pinfo);

#endif /* __PACKET_I2C_H__ */
