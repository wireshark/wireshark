/* packet-iperf.c
 * Routines for iPerf dissection
 * By Anish Bhatt <anish@gatech.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>

#define IPERF2_HDR_SIZE 24
#define IPERF2_UDP_HDR_SIZE 12

void proto_register_iperf2(void);
void proto_reg_handoff_iperf2(void);

static int proto_iperf2 = -1;

static int hf_iperf2_sequence = -1;
static int hf_iperf2_sec = -1;
static int hf_iperf2_usec = -1;
static int hf_iperf2_flags = -1;
static int hf_iperf2_num_threads = -1;
static int hf_iperf2_mport = -1;
static int hf_iperf2_bufferlen = -1;
static int hf_iperf2_mwinband = -1;
static int hf_iperf2_mamount = -1;

static gint ett_iperf2 = -1;
static gint ett_udphdr = -1;
static gint ett_client_hdr = -1;

static dissector_handle_t iperf2_handle_tcp = NULL;
static dissector_handle_t iperf2_handle_udp = NULL;


static int
dissect_iperf2(tvbuff_t *tvb, proto_tree *iperf2_tree, guint32 offset)
{
    proto_tree *client_tree;

    client_tree = proto_tree_add_subtree(iperf2_tree, tvb, offset, IPERF2_HDR_SIZE, ett_client_hdr, NULL, "iPerf2 Client Header");
    proto_tree_add_item(client_tree, hf_iperf2_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_num_threads, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_mport, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_bufferlen, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_mwinband, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(client_tree, hf_iperf2_mamount, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_iperf2_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    proto_item *ti;
    proto_tree *iperf2_tree;

    /*There is probably a better way to do this, for now ignore any TCP packet with payload
     > 24 bytes as only the first packet with a 24 byte payload has iperf headers. One way might
     be to check header flags, as there are only two possible values */
    if (tvb_reported_length(tvb) > IPERF2_HDR_SIZE)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iPerf2");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_iperf2, tvb, 0, IPERF2_HDR_SIZE, ENC_NA);
    iperf2_tree = proto_item_add_subtree(ti, ett_iperf2);

    return dissect_iperf2(tvb, iperf2_tree, 0);
}

static int
dissect_iperf2_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
    guint32 offset = 0;
    guint32 hdr_size = IPERF2_HDR_SIZE + IPERF2_UDP_HDR_SIZE;
    proto_item *ti;
    proto_tree *iperf2_tree, *udp_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iPerf2");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_iperf2, tvb, offset, hdr_size, ENC_NA);
    iperf2_tree = proto_item_add_subtree(ti, ett_iperf2);

    udp_tree = proto_tree_add_subtree(iperf2_tree, tvb, offset, IPERF2_UDP_HDR_SIZE, ett_udphdr, NULL, "iPerf2 UDP Header");

    proto_tree_add_item(udp_tree, hf_iperf2_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(udp_tree, hf_iperf2_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(udp_tree, hf_iperf2_usec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return dissect_iperf2(tvb, iperf2_tree, offset);
}

void
proto_register_iperf2(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_iperf2_sequence,
            { "iPerf2 sequence", "iperf2.udp.sequence", FT_INT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_sec,
            { "iPerf2 sec", "iperf2.udp.sec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_usec,
            { "iPerf2 usec", "iperf2.udp.usec", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_flags,
            { "Flags", "iperf2.client.flags", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_num_threads,
            { "Number of Threads", "iperf2.client.numthreads", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_mport,
            { "Server Port", "iperf2.client.port", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_bufferlen,
            { "Buffer Len", "iperf2.client.bufferlen", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_mwinband,
            { "Bandwidth", "iperf2.client.bandwidth", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_iperf2_mamount,
            { "Number of Bytes", "iperf2.client.num_bytes", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_iperf2,
        &ett_udphdr,
        &ett_client_hdr
    };

    /* Register the protocol name and description */
    proto_iperf2 = proto_register_protocol("iPerf2 Packet Data", "iPerf2", "iperf2");

    proto_register_field_array(proto_iperf2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    iperf2_handle_tcp = register_dissector("iperf2_tcp", dissect_iperf2_tcp, proto_iperf2);
    iperf2_handle_udp = register_dissector("iperf2_udp", dissect_iperf2_udp, proto_iperf2);
}

void
proto_reg_handoff_iperf2(void)
{
    dissector_add_for_decode_as_with_preference("tcp.port", iperf2_handle_tcp);
    dissector_add_for_decode_as_with_preference("udp.port", iperf2_handle_udp);
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
