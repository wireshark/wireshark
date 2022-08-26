/* packet-iser.c
 * Routines for iSCSI RDMA Extensions dissection
 * Copyright 2014, Mellanox Technologies Ltd.
 * Code by Yan Burman.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>

#include "packet-infiniband.h"

#define ISER_WSV    0x08
#define ISER_RSV    0x04
#define ISER_REJ    0x01

#define ISER_ISCSI_CTRL    0x10
#define ISER_HELLO         0x20
#define ISER_HELLORPLY     0x30

#define ISER_OPCODE_MASK      0xf0
#define ISER_SPECIFIC_MASK    0x0f

#define ISER_HDR_SZ   (1 + 3 + 4 + 8 + 4 + 8)
#define ISCSI_HDR_SZ  48

#define ISER_ISCSI_HDR_SZ (ISER_HDR_SZ + ISCSI_HDR_SZ)

#define SID_ULP_MASK   0x00000000FF000000
#define SID_PROTO_MASK 0x0000000000FF0000
#define SID_PORT_MASK  0x000000000000FFFF

#define SID_ULP         0x01
#define SID_PROTO_TCP   0x06
#define TCP_PORT_ISER_RANGE    "3260"

#define SID_MASK (SID_ULP_MASK | SID_PROTO_MASK)
#define SID_ULP_TCP ((SID_ULP << 3 * 8) | (SID_PROTO_TCP << 2 * 8))

void proto_reg_handoff_iser(void);
void proto_register_iser(void);

static int proto_iser = -1;
static dissector_handle_t iscsi_handler;

static int proto_ib = -1;

/* iSER Header */
static int hf_iser_flags = -1;
static int hf_iser_opcode_f = -1;
static int hf_iser_RSV_f = -1;
static int hf_iser_WSV_f = -1;
static int hf_iser_REJ_f = -1;
static int hf_iser_write_stag = -1;
static int hf_iser_write_va = -1;
static int hf_iser_read_stag = -1;
static int hf_iser_read_va = -1;
static int hf_iser_ird = -1;
static int hf_iser_ord = -1;

/* Initialize the subtree pointers */
static gint ett_iser = -1;
static gint ett_iser_flags = -1;

/* global preferences */
static range_t *gPORT_RANGE;

static const value_string iser_flags_opcode[] = {
    { ISER_ISCSI_CTRL >> 4, "iSCSI Control-Type PDU"},
    { ISER_HELLO >> 4, "Hello Message"},
    { ISER_HELLORPLY >> 4, "HelloReply Message"},
    {0, NULL},
};

static int * const flags_fields[] = {
    &hf_iser_opcode_f,
    &hf_iser_WSV_f,
    &hf_iser_RSV_f,
    NULL
};
static int * const hello_flags_fields[] = {
    &hf_iser_opcode_f,
    NULL
};
static int * const hellorply_flags_fields[] = {
    &hf_iser_opcode_f,
    &hf_iser_REJ_f,
    NULL
};

static int dissect_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb;
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *iser_tree;
    guint offset = 0;
    guint8 flags, vers, opcode;

    if (tvb_reported_length(tvb) < ISER_ISCSI_HDR_SZ)
        return 0;

    flags = tvb_get_guint8(tvb, 0);
    opcode = flags & ISER_OPCODE_MASK;

    /* Check if the opcode is valid */
    switch (opcode) {
    case ISER_ISCSI_CTRL:
        switch (flags & ISER_SPECIFIC_MASK) {
        case 0:
        case ISER_WSV:
        case ISER_RSV:
        case ISER_RSV|ISER_WSV:
            break;

        default:
            return 0;
        }
        break;

    case ISER_HELLO:
    case ISER_HELLORPLY:
        vers = tvb_get_guint8(tvb, 1);
        if ((vers & 0xf) != 10)
            return 0;
        if (((vers >> 4) & 0x0f) != 10)
            return 0;
        break;

    default:
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iSER");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Set info only for hello, since for iscsi, the iscsi dissector will */
    switch (opcode) {
    case ISER_HELLO:
        col_set_str(pinfo->cinfo, COL_INFO, "iSER Hello");
        break;

    case ISER_HELLORPLY:
        col_set_str(pinfo->cinfo, COL_INFO, "iSER HelloRply");
        break;
    }

    if (tree) {
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_iser, tvb, 0, ISER_HDR_SZ, ENC_NA);

        iser_tree = proto_item_add_subtree(ti, ett_iser);

        switch (opcode) {
        case ISER_ISCSI_CTRL:
            proto_tree_add_bitmask(iser_tree, tvb, offset, hf_iser_flags,
                    ett_iser_flags, flags_fields, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(iser_tree, hf_iser_write_stag, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(iser_tree, hf_iser_write_va, tvb,
                    offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            proto_tree_add_item(iser_tree, hf_iser_read_stag, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(iser_tree, hf_iser_read_va, tvb,
                    offset, 8, ENC_BIG_ENDIAN);
            break;

        case ISER_HELLO:
            proto_tree_add_bitmask(iser_tree, tvb, offset, hf_iser_flags,
                    ett_iser_flags, hello_flags_fields, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(iser_tree, hf_iser_ird, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            break;

        case ISER_HELLORPLY:
            proto_tree_add_bitmask(iser_tree, tvb, offset, hf_iser_flags,
                    ett_iser_flags, hellorply_flags_fields, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(iser_tree, hf_iser_ord, tvb,
                    offset, 2, ENC_BIG_ENDIAN);
            break;
        }
    }

    if (opcode == ISER_ISCSI_CTRL) {
            next_tvb = tvb_new_subset_remaining(tvb, ISER_HDR_SZ);
            call_dissector(iscsi_handler, next_tvb, pinfo, tree);
    }

    return ISER_HDR_SZ;
}

static int
dissect_iser(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    conversation_t *conv;
    conversation_infiniband_data *convo_data = NULL;

    if (tvb_reported_length(tvb) < ISER_ISCSI_HDR_SZ)
        return FALSE;

    /* first try to find a conversation between the two current hosts. in most cases this
       will not work since we do not have the source QP. this WILL succeed when we're still
       in the process of CM negotiations */
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                             CONVERSATION_IBQP, pinfo->srcport, pinfo->destport, 0);

    if (!conv) {
        /* if not, try to find an established RC channel. recall Infiniband conversations are
           registered with one side of the channel. since the packet is only guaranteed to
           contain the qpn of the destination, we'll use this */
        conv = find_conversation(pinfo->num, &pinfo->dst, &pinfo->dst,
                                 CONVERSATION_IBQP, pinfo->destport, pinfo->destport, NO_ADDR_B|NO_PORT_B);

        if (!conv)
            return FALSE;   /* nothing to do with no conversation context */
    }

    convo_data = (conversation_infiniband_data *)conversation_get_proto_data(conv, proto_ib);

    if (!convo_data)
        return FALSE;

    if ((convo_data->service_id & SID_MASK) != SID_ULP_TCP)
        return FALSE;   /* the service id doesn't match that of TCP ULP - nothing for us to do here */

    if (!(value_is_in_range(gPORT_RANGE, (guint32)(convo_data->service_id & SID_PORT_MASK))))
        return FALSE;   /* the port doesn't match that of iSER - nothing for us to do here */

    dissect_packet(tvb, pinfo, tree, data);
    return TRUE;
}

void
proto_register_iser(void)
{
    module_t *iser_module;
    static hf_register_info hf[] = {
        { &hf_iser_flags,
            { "Flags", "iser.flags",
               FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_iser_opcode_f,
            { "Opcode", "iser.flags.opcode",
               FT_UINT8, BASE_HEX, VALS(iser_flags_opcode),
               ISER_OPCODE_MASK, NULL, HFILL}
        },
        { &hf_iser_RSV_f,
            { "RSV", "iser.flags.rsv",
               FT_BOOLEAN, 8, NULL, ISER_RSV, "Read STag Valid", HFILL}
        },
        { &hf_iser_WSV_f,
            { "WSV", "iser.flags.wsv",
               FT_BOOLEAN, 8, NULL, ISER_WSV, "Write STag Valid", HFILL}
        },
        { &hf_iser_REJ_f,
            { "REJ", "iser.flags.rej",
               FT_BOOLEAN, 8, NULL, ISER_REJ, "Target reject connection", HFILL}
        },
        { &hf_iser_write_stag,
            { "Write STag", "iser.write_stag",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_iser_write_va,
            { "Write Base Offset", "iser.write_base_offset",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_iser_read_stag,
            { "Read STag", "iser.read_stag",
               FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_iser_read_va,
            { "Read Base Offset", "iser.read_base_offset",
               FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_iser_ird,
            { "iSER-IRD", "iser.ird",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_iser_ord,
            { "iSER-ORD", "iser.ord",
               FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        }
    };

    static gint *ett[] = {
        &ett_iser,
        &ett_iser_flags
    };

    proto_iser = proto_register_protocol (
        "iSCSI Extensions for RDMA", /* name       */
        "iSER",      /* short name */
        "iser"       /* abbrev     */
        );

    proto_register_field_array(proto_iser, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    iser_module = prefs_register_protocol(proto_iser, proto_reg_handoff_iser);

    prefs_register_static_text_preference(iser_module, "use_decode_as",
        "Heuristic matching preferences removed.  Use Infiniband protocol preferences or Decode As.",
        "Simple heuristics can still be enable (may generate false positives) through Infiniband protocol preferences."
        "To force iSER dissection use Decode As");

    prefs_register_obsolete_preference(iser_module, "manual_en");

    prefs_register_obsolete_preference(iser_module, "addr_a");
    prefs_register_obsolete_preference(iser_module, "addr_a_type");
    prefs_register_obsolete_preference(iser_module, "addr_a_id");
    prefs_register_obsolete_preference(iser_module, "addr_a_qp");

    prefs_register_obsolete_preference(iser_module, "addr_b");
    prefs_register_obsolete_preference(iser_module, "addr_b_type");
    prefs_register_obsolete_preference(iser_module, "addr_b_id");
    prefs_register_obsolete_preference(iser_module, "addr_b_qp");

    range_convert_str(wmem_epan_scope(), &gPORT_RANGE, TCP_PORT_ISER_RANGE, MAX_TCP_PORT);
    prefs_register_range_preference(iser_module,
                                    "target_ports",
                                    "Target Ports Range",
                                    "Range of iSER target ports"
                                    "(default " TCP_PORT_ISER_RANGE ")",
                                    &gPORT_RANGE, MAX_TCP_PORT);
}

void
proto_reg_handoff_iser(void)
{
    heur_dissector_add("infiniband.payload", dissect_iser, "iSER Infiniband", "iser_infiniband", proto_iser, HEURISTIC_ENABLE);
    heur_dissector_add("infiniband.mad.cm.private", dissect_iser, "iSER in PrivateData of CM packets", "iser_ib_private", proto_iser, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("infiniband", create_dissector_handle( dissect_packet, proto_iser ) );

    iscsi_handler = find_dissector_add_dependency("iscsi", proto_iser);
    proto_ib = proto_get_id_by_filter_name( "infiniband" );
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
