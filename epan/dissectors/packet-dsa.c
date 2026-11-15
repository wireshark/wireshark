/* packet-dsa.c
 * Dissector for Marvell DSA- and EDSA-tagged Ethernet frames
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Dissects Ethernet frames with a Marvell (EtherType) Distributed
 * Switch Architecture tag. The switch chip uses it for bidirectionally
 * passing additional metadata.
 *
 * Frame layout:
 *   DSA:  | DA(6) | SA(6) | DSA tag(4) | EtherType/Length(2) | payload |
 *   EDSA: | DA(6) | SA(6) | prog. EtherType(2) | 0x0000(2) | DSA tag(4) | EtherType/Length(2) | payload |
 *
 * The first EtherType in the EDSA tag is not a constant but a
 * programmable value.
 *
 * The 4-byte DSA tag (big-endian bitfields):
 *   Byte 0: cmd[7:6] | tagged[5] | device[4:0]
 *   Byte 1: port[7:3] | cmd-specific[2:1] | cfi[0]
 *   Byte 2: pcp[7:5] | cmd-specific[4] | vid[11:8][3:0]
 *   Byte 3: vid[7:0]
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>
#include "packet-ieee8023.h"

void proto_register_dsa(void);
void proto_reg_handoff_dsa(void);

/* Protocols */
static int proto_dsa;
static int proto_edsa;

/* Subtrees */
static int ett_frame;
static int ett_tag_dsa;
static int ett_tag_edsa;

/* Header fields */
static int hf_dsa_da;
static int hf_dsa_sa;
static int hf_dsa_edsa_etype;
static int hf_dsa_edsa_reserved;
static int hf_dsa_type;
static int hf_dsa_len;
static int hf_dsa_cmd;
static int hf_dsa_tagged;
static int hf_dsa_device;
static int hf_dsa_port;
static int hf_dsa_trunk;
static int hf_dsa_rx_sniff;
static int hf_dsa_code;
static int hf_dsa_pcp;
static int hf_dsa_cfi;
static int hf_dsa_vid;
static int hf_dsa_ingress_vid;
static int hf_dsa_unused_byte1_bit1;
static int hf_dsa_unused_byte1_bits_21;
static int hf_dsa_unused_byte2_bit4;
static int hf_dsa_trailer;

/* Dissector handles */
static dissector_handle_t dsa_handle;
static dissector_handle_t edsa_handle;
static dissector_handle_t ethertype_handle;

/* Expert info */
static expert_module_t *expert_dsa;
static expert_field ei_dsa_too_short;
static expert_field ei_dsa_bad_reserved;
static expert_field ei_dsa_len;

/*
 * Geometry of the 4-byte DSA tag (big-endian; bit 7 is the MSB of each
 * byte). The masks name the bits as they sit within a byte.
 */
#define DSA_TAG_CMD_MASK  0xC0    /* byte 0, bits 7:6 (command)   */
#define DSA_TAG_CMD_POS   6       /* shift to isolate the command */
#define DSA_TAG_TAGGED    0x20    /* byte 0, bit 5 (tagged)       */
#define DSA_TAG_DEV_MASK  0x1F    /* byte 0, bits 4:0 (device)    */
#define DSA_TAG_PORT_MASK 0xF8    /* byte 1, bits 7:3 (port)      */
#define DSA_TAG_PORT_POS  3       /* shift to isolate the port    */
#define DSA_TAG_B1_BIT2   0x04    /* byte 1, bit 2                */
#define DSA_TAG_B1_BIT1   0x02    /* byte 1, bit 1                */
#define DSA_TAG_CFI       0x01    /* byte 1, bit 0 (CFI)          */
#define DSA_TAG_PCP_MASK  0xE0    /* byte 2, bits 7:5 (PCP)       */
#define DSA_TAG_B2_BIT4   0x10    /* byte 2, bit 4                */
#define DSA_TAG_VID_MASK  0x0FFF  /* byte 2, bits 3:0 + byte 3    */

/* DSA command values */
#define DSA_CMD_TO_CPU     0
#define DSA_CMD_FROM_CPU   1
#define DSA_CMD_TO_SNIFFER 2
#define DSA_CMD_FORWARD    3

static const value_string dsa_cmd_vals[] = {
    { DSA_CMD_TO_CPU, "TO_CPU" },
    { DSA_CMD_FROM_CPU, "FROM_CPU" },
    { DSA_CMD_TO_SNIFFER, "TO_SNIFFER" },
    { DSA_CMD_FORWARD, "FORWARD" },
    { 0, NULL }
};

/* DSA TO_CPU code values */
static const value_string dsa_code_vals[] = {
    { 0, "MGMT_TRAP" },
    { 1, "FRAME2REG" },
    { 2, "IGMP_MLD_TRAP" },
    { 3, "POLICY_TRAP" },
    { 4, "ARP_MIRROR" },
    { 5, "POLICY_MIRROR" },
    { 6, "RESERVED_6" },
    { 7, "RESERVED_7" },
    { 0, NULL }
};

/*
 * The TO_CPU code is 3 bits split across two bytes of the tag:
 *   code[2:1] = byte1 bits [2:1], code[0] = byte2 bit [4].
 * Crumb bit offsets are relative to the start of byte 1
 * (bit_offset = (tag_offset + 1) * 8), most significant crumb first.
 */
static const crumb_spec_t dsa_code_crumbs[] = {
    { 5, 2 },   /* byte1 bits [2:1] = code[2:1] */
    { 11, 1 },  /* byte2 bit [4]    = code[0]   */
    { 0, 0 }    /* sentinel */
};

/*
 * Dissect the 4-byte DSA tag at the given offset, in its own subtree
 * under the given tree. Returns the command value for info column use.
 */
static int
dissect_dsa_tag(proto_tree *parent_tree, tvbuff_t *tvb, unsigned tag_offset,
    uint32_t *port, bool *trunk)
{
    proto_tree *tag_tree;
    uint8_t byte0;
    uint8_t byte1;
    int cmd;
    bool tagged;

    if (tvb_reported_length_remaining(tvb, tag_offset) < 4) {
        return -1;
    }

    tag_tree = proto_tree_add_subtree(parent_tree, tvb, tag_offset, 4,
        ett_tag_dsa, NULL, "DSA tag");

    byte0 = tvb_get_uint8(tvb, tag_offset);

    cmd = (byte0 & DSA_TAG_CMD_MASK) >> DSA_TAG_CMD_POS;
    tagged = !!(byte0 & DSA_TAG_TAGGED);

    /* Byte 0: cmd[7:6] | tagged[5] | device[4:0] */
    proto_tree_add_item(tag_tree, hf_dsa_cmd, tvb, tag_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tag_tree, hf_dsa_tagged, tvb, tag_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tag_tree, hf_dsa_device, tvb, tag_offset, 1, ENC_BIG_ENDIAN);

    /* Byte 1: port[7:3] | (command-dependent bits [2:1]) | cfi[0] */
    byte1 = tvb_get_uint8(tvb, tag_offset + 1);
    *port = byte1 >> DSA_TAG_PORT_POS;
    proto_tree_add_item(tag_tree, hf_dsa_port, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);

    switch (cmd) {
    case DSA_CMD_TO_CPU: /* code[2:1] in byte1 bits [2:1], code[0] in byte2 bit [4] */
        proto_tree_add_split_bits_item_ret_val(tag_tree, hf_dsa_code, tvb,
            (tag_offset + 1) * 8, dsa_code_crumbs, NULL);
        break;
    case DSA_CMD_FROM_CPU: /* bits [2:1] both unused */
        proto_tree_add_item(tag_tree, hf_dsa_unused_byte1_bits_21, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);
        break;
    case DSA_CMD_TO_SNIFFER: /* bit2=rx_sniff (ingress), bit1=unused */
        proto_tree_add_item(tag_tree, hf_dsa_rx_sniff, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tag_tree, hf_dsa_unused_byte1_bit1, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);
        break;
    case DSA_CMD_FORWARD: /* bit2=trunk, bit1=unused */
        *trunk = !!(byte1 & DSA_TAG_B1_BIT2);
        proto_tree_add_item(tag_tree, hf_dsa_trunk, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tag_tree, hf_dsa_unused_byte1_bit1, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);
        break;
    default: /* unreachable: cmd is a 2-bit field, all values handled above */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    proto_tree_add_item(tag_tree, hf_dsa_cfi, tvb, tag_offset + 1, 1, ENC_BIG_ENDIAN);

    /* Byte 2: pcp[7:5] | (command-dependent bit4) | vid[11:8][3:0]
     * bit4 is code[0] only in TO_CPU (shown in the Code bitmap above);
     * unused in all other commands. */
    proto_tree_add_item(tag_tree, hf_dsa_pcp, tvb, tag_offset + 2, 1, ENC_BIG_ENDIAN);

    if (cmd != DSA_CMD_TO_CPU) {
        proto_tree_add_item(tag_tree, hf_dsa_unused_byte2_bit4, tvb, tag_offset + 2, 1, ENC_BIG_ENDIAN);
    }

    /* Bytes 2-3: VID (12 bits: byte2[3:0] + byte3[7:0]) */
    if (tagged) {
        proto_tree_add_item(tag_tree, hf_dsa_vid, tvb, tag_offset + 2, 2, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tag_tree, hf_dsa_ingress_vid, tvb, tag_offset + 2, 2, ENC_BIG_ENDIAN);
    }

    return cmd;
}

/*
 * Dissect the 8-byte EDSA tag at the given offset: a programmable
 * EtherType, a reserved field (which must be 0x0000), then the 4-byte
 * DSA tag. The EDSA tag gets its own subtree, with the DSA tag nested
 * inside it. Returns the command value for info column use, or -1 if
 * the tag is truncated.
 */
static int
dissect_edsa_tag(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb,
    unsigned tag_offset, uint32_t *port, bool *trunk)
{
    proto_tree *edsa_tree;

    /* The EtherType is programmable; show it as-is. */
    if (tvb_reported_length_remaining(tvb, tag_offset) < 2)
        return -1;

    edsa_tree = proto_tree_add_subtree(parent_tree, tvb, tag_offset, 8,
        ett_tag_edsa, NULL, "EDSA tag");

    proto_tree_add_item(edsa_tree, hf_dsa_edsa_etype, tvb, tag_offset, 2,
        ENC_BIG_ENDIAN);

    if (tvb_reported_length_remaining(tvb, tag_offset + 2) < 2)
        return -1;
    {
        uint16_t edsa_reserved = tvb_get_ntohs(tvb, tag_offset + 2);
        proto_item *res_ti = proto_tree_add_item(edsa_tree,
            hf_dsa_edsa_reserved, tvb, tag_offset + 2, 2, ENC_BIG_ENDIAN);
        if (edsa_reserved != 0) {
            expert_add_info_format(pinfo, res_ti, &ei_dsa_bad_reserved,
                "Non-zero EDSA reserved field 0x%04x", edsa_reserved);
        }
    }

    /* The 4-byte DSA tag the EDSA tag wraps */
    return dissect_dsa_tag(edsa_tree, tvb, tag_offset + 4, port, trunk);
}

/*
 * Common dissection of a DSA or EDSA frame.
 * The tvb starts at the beginning of the frame data (DA address).
 * The frame fields (addresses, type/length) are dissected directly; the
 * tag is delegated to dissect_dsa_tag() or dissect_edsa_tag(), each of
 * which nests its tag in its own subtree.
 */
static int
dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    bool is_edsa)
{
    proto_item       *ti;
    proto_tree       *frame_tree;
    unsigned          offset;
    uint16_t          etype;
    ethertype_data_t  ethertype_data;
    int               cmd;
    uint32_t          port = 0;
    bool              trunk = false;

    /* Full header length including the type/length field */
    const unsigned full_len = 12 + (is_edsa ? 4 : 0) + 4 + 2;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, is_edsa ? "EDSA" : "DSA");

    ti = proto_tree_add_item(tree, is_edsa ? proto_edsa : proto_dsa, tvb, 0,
        full_len, ENC_NA);
    frame_tree = proto_item_add_subtree(ti, ett_frame);

    if (tvb_reported_length(tvb) < full_len) {
        expert_add_info_format(pinfo, ti, &ei_dsa_too_short,
            "DSA frame too short: expected %u bytes, available %u bytes",
            full_len, tvb_reported_length(tvb));
    }

    offset = 0;

    /* DA and SA */
    if (tvb_reported_length_remaining(tvb, offset) < 12)
        goto out;
    proto_tree_add_item(frame_tree, hf_dsa_da, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(frame_tree, hf_dsa_sa, tvb, offset, 6, ENC_NA);
    offset += 6;

    /*
     * Dissect the 4-byte DSA tag, or the 8-byte EDSA tag, reporting the
     * port and the trunk bit, which the info column below is built from.
     */
    if (is_edsa) {
        cmd = dissect_edsa_tag(pinfo, frame_tree, tvb, offset, &port, &trunk);
        if (cmd < 0)
            goto out;
        offset += 8;
    } else {
        cmd = dissect_dsa_tag(frame_tree, tvb, offset, &port, &trunk);
        if (cmd < 0)
            goto out;
        offset += 4;
    }

    /* Info column */
    {
        const char *cmd_name = val_to_str_const(cmd, dsa_cmd_vals, "?");
        if (cmd == DSA_CMD_FORWARD && trunk)
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s, trunk %u", cmd_name, port);
        else
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s, port %u", cmd_name, port);
    }

    /*
     * The two bytes after the tag are the type/length field of the
     * encapsulated Ethernet frame, as in packet-eth.c:
     * a value <= the maximum 802.3 length (and non-zero) is a
     * length field (802.3/LLC framing, e.g. STP BPDUs); otherwise
     * it is an EtherType.
     */
    if (tvb_reported_length_remaining(tvb, offset) < 2)
        goto out;
    etype = tvb_get_ntohs(tvb, offset);
    if (etype <= IEEE_802_3_MAX_LEN && etype != ETHERTYPE_UNK) {
        bool is_802_2 = true;

        /*
         * If the first two bytes of the payload are 0xFFFF there
         * is no 802.2 (LLC) header; the payload is a "raw" 802.3
         * (IPX or CCSDS) payload.
         */
        if (tvb_reported_length_remaining(tvb, offset + 2) >= 2 &&
            tvb_get_ntohs(tvb, offset + 2) == 0xFFFF) {
            is_802_2 = false;
        }
        dissect_802_3(etype, is_802_2, tvb, offset + 2, pinfo,
            tree, frame_tree, hf_dsa_len, hf_dsa_trailer, &ei_dsa_len, 0);
        offset += 2;
    } else {
        proto_tree_add_item(frame_tree, hf_dsa_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        ethertype_data.etype = etype;
        ethertype_data.payload_offset = offset + 2;
        ethertype_data.fh_tree = frame_tree;
        ethertype_data.trailer_id = hf_dsa_trailer;
        ethertype_data.fcs_len = 0;
        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
        offset += 2;
    }

out:
    return tvb_captured_length(tvb);
}

static int
dissect_dsa_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    return dissect_frame(tvb, pinfo, tree, false);
}

static int
dissect_edsa_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    return dissect_frame(tvb, pinfo, tree, true);
}

void
proto_register_dsa(void)
{
    static hf_register_info hf[] = {
        { &hf_dsa_da,
            { "Destination", "dsa.da",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              "Destination address", HFILL }
        },
        { &hf_dsa_sa,
            { "Source", "dsa.sa",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              "Source address", HFILL }
        },
        { &hf_dsa_edsa_etype,
            { "DSA EtherType", "dsa.edsa.etype",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "EtherType marker preceding the DSA tag", HFILL }
        },
        { &hf_dsa_edsa_reserved,
            { "Reserved", "dsa.edsa.reserved",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "Reserved (should be 0x0000)", HFILL }
        },
        { &hf_dsa_type,
            { "Type", "dsa.type",
              FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
              "Encapsulated Ethernet protocol type", HFILL }
        },
        { &hf_dsa_len,
            { "Length", "dsa.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "802.3 length of the encapsulated frame payload", HFILL }
        },
        { &hf_dsa_cmd,
            { "Command", "dsa.cmd",
              FT_UINT8, BASE_DEC, VALS(dsa_cmd_vals), DSA_TAG_CMD_MASK,
              "DSA command", HFILL }
        },
        { &hf_dsa_tagged,
            { "Tagged", "dsa.tagged",
              FT_BOOLEAN, 8, NULL, DSA_TAG_TAGGED,
              "VLAN tag present in DSA header", HFILL }
        },
        { &hf_dsa_device,
            { "Device", "dsa.device",
              FT_UINT8, BASE_DEC, NULL, DSA_TAG_DEV_MASK,
              "Switch device number", HFILL }
        },
        { &hf_dsa_port,
            { "Port", "dsa.port",
              FT_UINT8, BASE_DEC, NULL, DSA_TAG_PORT_MASK,
              "Switch port number", HFILL }
        },
        { &hf_dsa_trunk,
            { "Trunk", "dsa.trunk",
              FT_BOOLEAN, 8, NULL, DSA_TAG_B1_BIT2,
              "Trunk (LAG) membership (FORWARD command)", HFILL }
        },
        { &hf_dsa_rx_sniff,
            { "Rx Sniff", "dsa.rx_sniff",
              FT_BOOLEAN, 8, NULL, DSA_TAG_B1_BIT2,
              "Ingress sniff (TO_SNIFFER command)", HFILL }
        },
        { &hf_dsa_code,
            { "Code", "dsa.code",
              FT_UINT8, BASE_DEC, VALS(dsa_code_vals), 0x0,
              "TO_CPU code (byte1 bits [2:1] + byte2 bit [4])", HFILL }
        },
        { &hf_dsa_pcp,
            { "PCP", "dsa.pcp",
              FT_UINT8, BASE_DEC, NULL, DSA_TAG_PCP_MASK,
              "802.1Q Priority Code Point", HFILL }
        },
        { &hf_dsa_cfi,
            { "CFI", "dsa.cfi",
              FT_BOOLEAN, 8, NULL, DSA_TAG_CFI,
              "802.1Q Canonical Format Indicator", HFILL }
        },
        { &hf_dsa_vid,
            { "VID", "dsa.vid",
              FT_UINT16, BASE_DEC, NULL, DSA_TAG_VID_MASK,
              "802.1Q VLAN ID (byte2[3:0] + byte3)", HFILL }
        },
        { &hf_dsa_ingress_vid,
            { "Ingress VID", "dsa.ingress_vid",
              FT_UINT16, BASE_DEC, NULL, DSA_TAG_VID_MASK,
              "Ingress VLAN ID (0=standalone, 4095=bridged)", HFILL }
        },
        { &hf_dsa_unused_byte1_bit1,
            { "Unused", "dsa.unused_byte1_bit1",
              FT_UINT8, BASE_HEX, NULL, DSA_TAG_B1_BIT1,
              "byte1 bit 1 (FORWARD or TO_SNIFFER command)", HFILL }
        },
        { &hf_dsa_unused_byte1_bits_21,
            { "Unused", "dsa.unused_byte1_bits_21",
              FT_UINT8, BASE_HEX, NULL, DSA_TAG_B1_BIT2 | DSA_TAG_B1_BIT1,
              "byte1 bits 2:1 (FROM_CPU command)", HFILL }
        },
        { &hf_dsa_unused_byte2_bit4,
            { "Unused", "dsa.unused_byte2_bit4",
              FT_UINT8, BASE_HEX, NULL, DSA_TAG_B2_BIT4,
              "byte2 bit 4 (any command but TO_CPU)", HFILL }
        },
        { &hf_dsa_trailer,
            { "Trailer", "dsa.trailer",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_frame,
        &ett_tag_dsa,
        &ett_tag_edsa,
    };

    static ei_register_info ei[] = {
        { &ei_dsa_too_short,
            { "dsa.too_short", PI_MALFORMED, PI_WARN, "DSA frame too short", EXPFILL }
        },
        { &ei_dsa_bad_reserved,
            { "dsa.bad_reserved", PI_MALFORMED, PI_WARN, "Non-zero EDSA reserved field", EXPFILL }
        },
        { &ei_dsa_len,
            { "dsa.len.past_end", PI_MALFORMED, PI_ERROR,
              "Length field value goes past the end of the payload", EXPFILL }
        },
    };

    proto_dsa = proto_register_protocol(
        "Marvell DSA-tagged Ethernet", "DSA-tagged", "dsa");
    proto_edsa = proto_register_protocol(
        "Marvell EDSA-tagged Ethernet", "EDSA-tagged", "edsa");
    proto_register_field_array(proto_dsa, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dsa = expert_register_protocol(proto_dsa);
    expert_register_field_array(expert_dsa, ei, array_length(ei));
}

void
proto_reg_handoff_dsa(void)
{
    dsa_handle = create_dissector_handle(dissect_dsa_frame, proto_dsa);
    edsa_handle = create_dissector_handle(dissect_edsa_frame, proto_edsa);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_DSA, dsa_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_EDSA, edsa_handle);

    ethertype_handle = find_dissector_add_dependency("ethertype", proto_dsa);
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
 * :indentSize=4:tabSize=8:noTabs=false:
 */
