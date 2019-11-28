/* packet-caneth.c
 * Routines for Controller Area Network over Ethernet dissection
 * Copyright 2018, Lazar Sumar <bugzilla@lazar.co.nz>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The CAN-ETH protocol is used for transmitting the Controller Area Network
 * (CAN) protocol over UDP.
 *
 * The protocol definition can be found at http://www.proconx.com/assets/files/products/caneth/canframe.pdf
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-socketcan.h>

#define CAN_FRAME_LEN   15

#define CAN_ID_OFFSET       0
#define CAN_DLC_OFFSET      4
#define CAN_DATA_OFFSET     5
#define CAN_EXT_FLAG_OFFSET 13
#define CAN_RTR_FLAG_OFFSET 14

static const gchar magic[] = "ISO11898";

void proto_reg_handoff_caneth(void);
void proto_register_caneth(void);

static int proto_caneth = -1;
static int hf_caneth_magic = -1;
static int hf_caneth_version = -1;
static int hf_caneth_frames = -1;
static int hf_caneth_options = -1;

static int hf_caneth_can_ident_ext = -1;
static int hf_caneth_can_ident_std = -1;
static int hf_caneth_can_extflag = -1;
static int hf_caneth_can_rtrflag = -1;
static int hf_caneth_can_len = -1;
static int hf_caneth_can_padding = -1;

#define CANETH_UDP_PORT 11898

static gint ett_caneth = -1;
static gint ett_caneth_frames = -1;
static gint ett_caneth_can = -1;

static int proto_can = -1;      // use CAN protocol for consistent filtering

static dissector_table_t can_subdissector_table;
/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define CANETH_MIN_LENGTH 10

static gboolean
test_caneth(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* Check that we have enough length for the Magic, Version, and Length */
    if (tvb_reported_length(tvb) < CANETH_MIN_LENGTH)
        return FALSE;
    /* Check that the magic id matches */
    if (tvb_strneql(tvb, offset, magic, 8) != 0)
        return FALSE;
    /* Check that the version is 1 as that is the only supported version */
    if (tvb_get_guint8(tvb, offset+8) != 1)
        return FALSE;
    /* Check that the version 1 limit of 16 can frames is respected */
    if (tvb_get_guint8(tvb, offset+9) > 16)
        return FALSE;
    return TRUE;
}

static guint
get_caneth_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint) tvb_get_ntohs(tvb, offset+3);
}

static int
dissect_caneth_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *can_tree;
    proto_item *ti;
    guint32     data_len;
    guint32     raw_can_id;
    gint8       ext_flag;
    gint8       rtr_flag;
    tvbuff_t*   next_tvb;
    struct can_info can_info;

    ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
    can_tree = proto_item_add_subtree(ti, ett_caneth_can);

    ext_flag = tvb_get_guint8(tvb, CAN_EXT_FLAG_OFFSET);
    rtr_flag = tvb_get_guint8(tvb, CAN_RTR_FLAG_OFFSET);
    proto_tree_add_item_ret_uint(can_tree, hf_caneth_can_ident_ext, tvb, CAN_ID_OFFSET, 4, ENC_LITTLE_ENDIAN, &raw_can_id);

    if (ext_flag)
    {
        can_info.id = raw_can_id & CAN_EFF_MASK;
    }
    else
    {
        can_info.id = raw_can_id & CAN_SFF_MASK;
    }

    can_info.id |= (ext_flag ? CAN_EFF_FLAG : 0) | (rtr_flag ? CAN_RTR_FLAG : 0);

    proto_tree_add_item_ret_uint(can_tree, hf_caneth_can_len, tvb, CAN_DLC_OFFSET, 1, ENC_NA, &data_len);
    proto_tree_add_item(can_tree, hf_caneth_can_extflag, tvb, CAN_EXT_FLAG_OFFSET, 1, ENC_NA);
    proto_tree_add_item(can_tree, hf_caneth_can_rtrflag, tvb, CAN_RTR_FLAG_OFFSET, 1, ENC_NA);

    next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, data_len);

    if (!dissector_try_payload_new(can_subdissector_table, next_tvb, pinfo, tree, TRUE, &can_info))
    {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    if (tvb_captured_length_remaining(tvb, CAN_DATA_OFFSET + data_len) > 0)
    {
        proto_tree_add_item(can_tree, hf_caneth_can_padding, tvb, CAN_DATA_OFFSET + data_len, -1, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_caneth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_tree *caneth_tree;
    proto_item *ti;
    guint32     frame_count, offset;
    tvbuff_t*   next_tvb;

    if (!test_caneth(pinfo, tvb, 0, data))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN-ETH");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_caneth, tvb, 0, -1, ENC_NA);
    caneth_tree = proto_item_add_subtree(ti, ett_caneth);

    proto_tree_add_item(caneth_tree, hf_caneth_magic, tvb, 0, 8, ENC_ASCII|ENC_NA);
    proto_tree_add_item(caneth_tree, hf_caneth_version, tvb, 8, 1, ENC_NA);
    proto_tree_add_item_ret_uint(caneth_tree, hf_caneth_frames, tvb, 9, 1, ENC_NA, &frame_count);

    for (offset = 10; frame_count-- > 0; offset += CAN_FRAME_LEN)
    {
        next_tvb = tvb_new_subset_length(tvb, offset, CAN_FRAME_LEN);
        dissect_caneth_can(next_tvb, pinfo, tree, data);
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0)
    {
        proto_tree_add_item(caneth_tree, hf_caneth_options, tvb, offset, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static gboolean
dissect_caneth_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return (udp_dissect_pdus(tvb, pinfo, tree, CANETH_MIN_LENGTH, test_caneth,
                     get_caneth_len, dissect_caneth, data) != 0);
}

void
proto_register_caneth(void)
{
    static hf_register_info hf[] = {
        {
            &hf_caneth_magic,
            {
                "Magic", "caneth.magic",
                FT_STRING, STR_ASCII,
                NULL, 0x0,
                "The magic identifier used to denote the start of a CAN-ETH packet", HFILL
            }
        },
        {
            &hf_caneth_version,
            {
                "Version", "caneth.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_caneth_frames,
            {
                "CAN Frames", "caneth.frames",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                "Number of enclosed CAN frames", HFILL
            }
        },
        {
            &hf_caneth_options,
            {
                "Options (Reserved)", "caneth.options",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                "Options field, reserved for future use, should be empty", HFILL
            }
        },
        {
            &hf_caneth_can_ident_ext,
            {
                "Identifier", "can.id",
                FT_UINT32, BASE_HEX,
                NULL, CAN_EFF_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_caneth_can_ident_std,
            {
                "Identifier", "can.id",
                FT_UINT32, BASE_HEX,
                NULL, CAN_SFF_MASK,
                NULL, HFILL
            }
        },
        {
            &hf_caneth_can_extflag,
            {
                "Extended Flag", "can.flags.xtd",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0,
                NULL, HFILL
            }
        },
        {
            &hf_caneth_can_rtrflag,
            {
                "Remote Transmission Request Flag", "can.flags.rtr",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0,
                NULL, HFILL
            }
        },
        {
            &hf_caneth_can_len,
            {
                "Frame-Length", "can.len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_caneth_can_padding,
            {
                "Padding", "caneth.can.padding",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        },
    };

    static gint *ett[] = {
        &ett_caneth,
        &ett_caneth_frames,
        &ett_caneth_can,
    };

    proto_caneth = proto_register_protocol("Controller Area Network over Ethernet", "CAN-ETH", "caneth");

    proto_register_field_array(proto_caneth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_caneth(void)
{
    dissector_handle_t caneth_handle = create_dissector_handle(dissect_caneth, proto_caneth);
    dissector_add_uint_with_preference("udp.port", CANETH_UDP_PORT, caneth_handle);

    heur_dissector_add("udp", dissect_caneth_heur_udp, "CAN-ETH over UDP", "caneth_udp", proto_caneth, HEURISTIC_ENABLE);

    can_subdissector_table = find_dissector_table("can.subdissector");
    proto_can = proto_get_id_by_filter_name("can");
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
