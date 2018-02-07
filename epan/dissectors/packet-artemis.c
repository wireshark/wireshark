/* packet-artemis.c
 * Dissector of ActiveMQ Artemis Core Protocol, so far just the message headers
 * Implemented: 2017, Pavel Moravec, Red Hat <pmoravec@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Protocol information:
 * https://github.com/apache/activemq-artemis/blob/master/artemis-core-client/src/main/java/org/apache/activemq/artemis/core/protocol/core/impl/PacketImpl.java#L309-L326
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-tcp.h"
#include "stdio.h"

#define ARTEMIS_PORT 5445 /* Not IANA registered */

static int proto_artemis = -1;

/* handles */
static int hf_artemis_len = -1;
static int hf_artemis_type = -1;
static int hf_artemis_channel = -1;
static int hf_artemis_buffer = -1;

static gint ett_artemis = -1;

static expert_field ei_artemis_len_short = EI_INIT;


static dissector_handle_t artemis_tcp_handle = NULL;

void proto_register_artemis(void);
void proto_reg_handoff_artemis(void);
static int dissect_artemis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

static guint
get_artemis_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                         int offset, void *data _U_)
{
    /* The 4bytes length doesn't include the actual length byte, that's why the "+4" */
    return (guint) tvb_get_ntohl(tvb, offset) + 4;
}

static int
dissect_artemis_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    proto_item  *ti, *len_item;
    proto_tree  *artemis_tree;
    guint32     length;

    ti = proto_tree_add_item(tree, proto_artemis, tvb, 0, -1, ENC_NA);
    artemis_tree = proto_item_add_subtree(ti, ett_artemis);

    len_item = proto_tree_add_item_ret_uint(artemis_tree, hf_artemis_len, tvb, 0, 4, ENC_BIG_ENDIAN, &length);
    if (length < 9) {    /* 9 = 1(type) + channel(8), if length is smaller, we cant read even type+channel */
        expert_add_info(pinfo, len_item, &ei_artemis_len_short);
        return tvb_captured_length(tvb);
    }

    proto_tree_add_item(artemis_tree, hf_artemis_type, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(artemis_tree, hf_artemis_channel, tvb, 5, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(artemis_tree, hf_artemis_buffer,  tvb, 13, length-9, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_artemis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ARTEMIS");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* fixed_len = 4(len) + 1(type) + 8(channel) */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_artemis_message_len,
                         dissect_artemis_frame, data);

    return tvb_captured_length(tvb);
}

void
proto_register_artemis(void)
{
    static hf_register_info hf[] = {
        {&hf_artemis_len, {
            "Length", "artemis.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Length of the frame", HFILL}},
        {&hf_artemis_type, {
            "Type", "artemis.type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Type of the frame", HFILL}},
        {&hf_artemis_channel, {
            "Channel", "artemis.channel",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Channel ID of the frame", HFILL}},
        {&hf_artemis_buffer, {
            "Buffer", "artemis.buffer",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Binary buffer", HFILL}}
    };

    static gint *ett [] = {
         &ett_artemis
    };

    static ei_register_info ei[] = {
        { &ei_artemis_len_short, { "artemis.len_short", PI_PROTOCOL, PI_ERROR, "Frame length is too short", EXPFILL }}
    };

    expert_module_t* expert_artemis;

    proto_artemis = proto_register_protocol ( "Artemis Core Protocol", "Artemis", "artemis" );

    artemis_tcp_handle = register_dissector("artemis", dissect_artemis, proto_artemis);
    proto_register_field_array(proto_artemis, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_artemis = expert_register_protocol(proto_artemis);
    expert_register_field_array(expert_artemis, ei, array_length(ei));
}

void
proto_reg_handoff_artemis(void)
{
    static gboolean initialize = FALSE;

    if (!initialize) {
        /* Register TCP port for dissection */
        dissector_add_uint_with_preference("tcp.port", ARTEMIS_PORT, artemis_tcp_handle);
        initialize = TRUE;
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
