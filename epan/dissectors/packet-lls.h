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
    guint32 src_ip;
    guint32 dst_ip;
    guint16 dst_port;
} lls_slt_key_t;

typedef struct {
    guint8 service_category;
    guint8 sls_protocol;
    guint16 service_id;
    gint32 major_channel_num;
    gint32 minor_channel_num;
} lls_slt_value_t;

/* SLT Table Routines */

void lls_extract_save_slt_table(packet_info *pinfo, dissector_handle_t xml_handle);
gboolean test_alc_over_slt(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data);
gchar *get_slt_channel_info(packet_info *pinfo);

#endif
