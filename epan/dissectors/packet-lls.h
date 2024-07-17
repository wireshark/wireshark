/* packet-lls.h
 * Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>

#ifndef __PACKET_LLS_H__
#define __PACKET_LLS_H__

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
} lls_slt_key_t;

typedef struct {
    uint8_t service_category;
    uint8_t sls_protocol;
    uint16_t service_id;
    int32_t major_channel_num;
    int32_t minor_channel_num;
} lls_slt_value_t;

/* SLT Table Routines */

void lls_extract_save_slt_table(packet_info *pinfo, dissector_handle_t xml_handle);
bool test_alc_over_slt(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data);
char *get_slt_channel_info(packet_info *pinfo);

#endif
