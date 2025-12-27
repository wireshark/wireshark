/* packet-lsdp.c
 * Dissector for Lenbrook Service Discovery Protocol
 *
 * Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>

#define LSDP_UDP_PORT     11430
#define LSDP_HEADER_LEN       6
#define LSDP_HEADER_VER       1
#define LSDP_MAGIC       "LSDP"

void proto_register_lsdp(void);
void proto_reg_handoff_lsdp(void);

static dissector_handle_t lsdp_handle;

static int proto_lsdp;

/* Header Fields */
static int hf_lsdp_header_length;
static int hf_lsdp_header_magic_word;
static int hf_lsdp_header_proto_version;

/* Common Message Fields */
static int hf_lsdp_msg_length;
static int hf_lsdp_msg_type;
static int hf_lsdp_node_id_length;
static int hf_lsdp_node_id_mac;
static int hf_lsdp_node_id;

/* Query Message */
static int hf_lsdp_query;
static int hf_lsdp_query_count;
static int hf_lsdp_query_class;

/* Announce Message */
static int hf_lsdp_announce;
static int hf_lsdp_announce_addr_length;
static int hf_lsdp_announce_addr_ipv4;
static int hf_lsdp_announce_addr_ipv6;
static int hf_lsdp_announce_count;

/* Announce Message Records */
static int hf_lsdp_announce_record;
static int hf_lsdp_announce_record_class;
static int hf_lsdp_announce_record_count;

/* Announce Message Record TXT-Records */
static int hf_lsdp_announce_record_txt;
static int hf_lsdp_announce_record_txt_key_length;
static int hf_lsdp_announce_record_txt_key;
static int hf_lsdp_announce_record_txt_value_length;
static int hf_lsdp_announce_record_txt_value;

/* Delete Message */
static int hf_lsdp_delete;
static int hf_lsdp_delete_count;
static int hf_lsdp_delete_class;

/* Trees */
static int ett_lsdp;
static int ett_lsdp_node_id;
static int ett_lsdp_msg;
static int ett_lsdp_msg_rec;
static int ett_lsdp_msg_rec_txt;

/* Expert fields */
static expert_field ei_lsdp_unknown_msg_type;
static expert_field ei_lsdp_invalid_addr_len;

#define CLASS_PLAYER         0x0001
#define CLASS_SERVER         0x0002
#define CLASS_PLAYER_MZ      0x0003
#define CLASS_SOVI_MFG       0x0004
#define CLASS_SOVI_KEYPAD    0x0005
#define CLASS_PLAYER_SLAVE   0x0006
#define CLASS_REMOTE_APP     0x0007
#define CLASS_HUB            0x0008
#define CLASS_ALL            0xFFFF

static const value_string lsdp_class_id_vals[] = {
    { CLASS_PLAYER,       "BluOS Player" },
    { CLASS_SERVER,       "BluOS Server" },
    { CLASS_PLAYER_MZ,    "BluOS Player (secondary in multi-zone)" },
    { CLASS_SOVI_MFG,     "sovi-mfg (used for manufacturing testing)" },
    { CLASS_SOVI_KEYPAD,  "sovi-keypad" },
    { CLASS_PLAYER_SLAVE, "BluOS Player (pair slave)" },
    { CLASS_REMOTE_APP,   "Remote Web App (AVR OSD Web Page)" },
    { CLASS_HUB,          "BluOS Hub" },
    { CLASS_ALL,          "All Classes (Query Message)" },
    { 0,                  NULL }
};

static const value_string lsdp_class_id_short_vals[] = {
    { CLASS_PLAYER,       "Player" },
    { CLASS_SERVER,       "Server" },
    { CLASS_PLAYER_MZ,    "Multizone Player" },
    { CLASS_SOVI_MFG,     "sovi-mfg" },
    { CLASS_SOVI_KEYPAD,  "sovi-keypad" },
    { CLASS_PLAYER_SLAVE, "Slave Player" },
    { CLASS_REMOTE_APP,   "Web App" },
    { CLASS_HUB,          "Hub" },
    { CLASS_ALL,          "All Classes" },
    { 0,                  NULL }
};

#define MSG_TYPE_ANNOUNCE    0x41   // Chr. 'A'
#define MSG_TYPE_DELETE      0x44   // Chr. 'D'
#define MSG_TYPE_QUERY_BCR   0x51   // Chr. 'Q'
#define MSG_TYPE_QUERY_UCR   0x52   // Chr. 'R'

static const value_string lsdp_msg_type_vals[] = {
    { MSG_TYPE_ANNOUNCE,  "Announce Message" },
    { MSG_TYPE_DELETE,    "Delete Message" },
    { MSG_TYPE_QUERY_BCR, "Query Message (for broadcast response)" },
    { MSG_TYPE_QUERY_UCR, "Query Message (for unicast response)" },
    { 0,                  NULL }
};

static int
dissect_lsdp_node_info(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint8_t node_id_len;
    int start_offset = offset;
    proto_item *pi_id;
    proto_tree *id_tree;

    node_id_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_lsdp_node_id_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*
        Normally, Node-ID is the MAC address of an interface, but COULD also be an arbitrary ID.
        Populate Node-ID field and also MAC if length is 6.
    */
    pi_id = proto_tree_add_item(tree, hf_lsdp_node_id, tvb, offset, node_id_len, ENC_NA);
    if(node_id_len == 6) {
        id_tree = proto_item_add_subtree(pi_id, ett_lsdp_node_id);
        proto_tree_add_item(id_tree, hf_lsdp_node_id_mac, tvb, offset, node_id_len, ENC_NA);
    }
    offset += node_id_len;

    return offset - start_offset;
}

static int
dissect_lsdp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint8_t msg_type, msg_len;
    uint32_t addr_len, count, txt_count, k_len, v_len, class;
    int offset_s1, offset_s2;
    proto_item *msg_item, *rec_item, *txt_item;
    proto_tree *msg_tree, *rec_tree, *txt_tree;
    const char *key, *val;

    msg_len = tvb_get_uint8(tvb, offset);
    msg_type = tvb_get_uint8(tvb, offset+1);

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(msg_type, lsdp_msg_type_vals, "Unknown Message Type"));

    switch (msg_type) {
        case MSG_TYPE_QUERY_BCR:
        case MSG_TYPE_QUERY_UCR:

            msg_item = proto_tree_add_item(tree, hf_lsdp_query, tvb, offset, msg_len, ENC_NA);
            msg_tree = proto_item_add_subtree(msg_item, ett_lsdp_msg);

            proto_tree_add_item(msg_tree, hf_lsdp_msg_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(msg_tree, hf_lsdp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item_ret_uint(msg_tree, hf_lsdp_query_count, tvb, offset, 1, ENC_BIG_ENDIAN, &count);
            offset += 1;

            for(uint32_t i=0; i < count; i++) {
                proto_tree_add_item_ret_uint(msg_tree, hf_lsdp_query_class, tvb, offset, 2, ENC_BIG_ENDIAN, &class);
                col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(class, lsdp_class_id_short_vals, "Unknown Class"));
                offset += 2;
            }

            break;

        case MSG_TYPE_ANNOUNCE:

            msg_item = proto_tree_add_item(tree, hf_lsdp_announce, tvb, offset, msg_len, ENC_NA);
            msg_tree = proto_item_add_subtree(msg_item, ett_lsdp_msg);

            proto_tree_add_item(msg_tree, hf_lsdp_msg_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(msg_tree, hf_lsdp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            offset += dissect_lsdp_node_info(tvb, msg_tree, offset);

            proto_tree_add_item_ret_uint(msg_tree, hf_lsdp_announce_addr_length, tvb, offset, 1, ENC_BIG_ENDIAN, &addr_len);
            offset += 1;

            if(addr_len == 4) {
                proto_tree_add_item(msg_tree, hf_lsdp_announce_addr_ipv4, tvb, offset, addr_len, ENC_BIG_ENDIAN);
            } else if (addr_len==16) {
                proto_tree_add_item(msg_tree, hf_lsdp_announce_addr_ipv6, tvb, offset, addr_len, ENC_NA);
            } else {
                expert_add_info(pinfo, msg_tree, &ei_lsdp_invalid_addr_len);
            }
            offset += addr_len;

            proto_tree_add_item_ret_uint(msg_tree, hf_lsdp_announce_count, tvb, offset, 1, ENC_BIG_ENDIAN, &count);
            proto_item_append_text(msg_item, " (%d Record%s)", count, plurality(count, "", "s"));
            offset += 1;

            /* Loop Announce Records */
            for(uint32_t i=0; i < count; i++) {

                offset_s1 = offset;

                rec_item = proto_tree_add_item(msg_tree, hf_lsdp_announce_record, tvb, offset, 0, ENC_NA);
                rec_tree = proto_item_add_subtree(rec_item, ett_lsdp_msg_rec);

                proto_tree_add_item_ret_uint(rec_tree, hf_lsdp_announce_record_class, tvb, offset, 2, ENC_BIG_ENDIAN, &class);
                offset += 2;

                col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(class, lsdp_class_id_short_vals, "Unknown Class"));

                proto_tree_add_item_ret_uint(rec_tree, hf_lsdp_announce_record_count, tvb, offset, 1, ENC_BIG_ENDIAN, &txt_count);
                proto_item_append_text(rec_item, " (%d TXT-Record%s)", txt_count, plurality(txt_count, "", "s"));
                offset += 1;

                /* Loop TXT records (key-value pairs) */
                for(uint32_t j=0; j < txt_count; j++) {

                    offset_s2 = offset;

                    txt_item = proto_tree_add_item(rec_tree, hf_lsdp_announce_record_txt, tvb, offset, 0, ENC_NA);
                    txt_tree = proto_item_add_subtree(txt_item, ett_lsdp_msg_rec_txt);

                    proto_tree_add_item_ret_uint(txt_tree, hf_lsdp_announce_record_txt_key_length, tvb, offset, 1, ENC_BIG_ENDIAN, &k_len);
                    offset += 1;

                    proto_tree_add_item_ret_string(txt_tree, hf_lsdp_announce_record_txt_key, tvb, offset, k_len, ENC_UTF_8, pinfo->pool, (const uint8_t**)&key);
                    offset += k_len;

                    proto_tree_add_item_ret_uint(txt_tree, hf_lsdp_announce_record_txt_value_length, tvb, offset, 1, ENC_BIG_ENDIAN, &v_len);
                    offset += 1;

                    proto_tree_add_item_ret_string(txt_tree, hf_lsdp_announce_record_txt_value, tvb, offset, v_len, ENC_UTF_8, pinfo->pool, (const uint8_t**)&val);
                    offset += v_len;

                    proto_item_append_text(txt_item, " (%s: %s)", key, val);
                    proto_item_set_len(txt_item, offset - offset_s2);

                    /* Keys of interest for info column */
                    if(
                        strcmp(key, "name") == 0 ||
                        strcmp(key, "model") == 0 ||
                        strcmp(key, "version") == 0
                    ) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " %s='%s'", key, val);
                    }
                }

                proto_item_set_len(rec_item, offset - offset_s1);
            }

            break;

        case MSG_TYPE_DELETE:

            msg_item = proto_tree_add_item(tree, hf_lsdp_delete, tvb, offset, msg_len, ENC_NA);
            msg_tree = proto_item_add_subtree(msg_item, ett_lsdp_msg);

            proto_tree_add_item(msg_tree, hf_lsdp_msg_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(msg_tree, hf_lsdp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            offset += dissect_lsdp_node_info(tvb, msg_tree, offset);

            proto_tree_add_item_ret_uint(msg_tree, hf_lsdp_delete_count, tvb, offset, 1, ENC_BIG_ENDIAN, &count);
            offset += 1;

            for(uint32_t i=0; i < count; i++) {
                proto_tree_add_item_ret_uint(msg_tree, hf_lsdp_delete_class, tvb, offset, 2, ENC_BIG_ENDIAN, &class);
                col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(class, lsdp_class_id_short_vals, "Unknown Class"));
                offset += 2;
            }

            break;

        default:
            expert_add_info(pinfo, tree, &ei_lsdp_unknown_msg_type);
            break;
    }

    return msg_len;
}

static int
dissect_lsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset;
    proto_item *ti;
    proto_tree *lsdp_tree;

    /* Basic tests for LSDP */
    if(
        tvb_reported_length(tvb) < LSDP_HEADER_LEN ||                   // Header must be available
        tvb_get_uint8(tvb, 0) != LSDP_HEADER_LEN ||                     // Header length must be fixed
        tvb_strneql(tvb, 1, LSDP_MAGIC, strlen(LSDP_MAGIC)) != 0 ||      // Magic Word must match
        tvb_get_uint8(tvb, 5) != LSDP_HEADER_VER                        // We only support version 1
    )
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LSDP");
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_lsdp, tvb, 0, -1, ENC_NA);
    lsdp_tree = proto_item_add_subtree(ti, ett_lsdp);

    offset = 0;

    proto_tree_add_item(lsdp_tree, hf_lsdp_header_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(lsdp_tree, hf_lsdp_header_magic_word, tvb, offset, 4, ENC_ASCII);
    offset += 4;

    proto_tree_add_item(lsdp_tree, hf_lsdp_header_proto_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* One packet can contain multiple messages */
    while((unsigned)offset < tvb_reported_length(tvb)) {

        /*
            Ensure there are enough bytes remaining for another message
            - at least 2 bytes (length, type) must be available
            - length must not be zero - ensure offset to advance
        */
        if(
            tvb_reported_length_remaining(tvb, offset) < 2 ||
            tvb_get_uint8(tvb, offset) == 0
        )
            break;

        offset += dissect_lsdp_message(tvb, pinfo, lsdp_tree, offset);

    }

    proto_item_set_len(ti, offset);
    return offset;
}

void
proto_register_lsdp(void)
{
    static hf_register_info hf[] = {
        { &hf_lsdp_header_length,
            { "Header Length", "lsdp.header.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_header_magic_word,
            { "Magic Word", "lsdp.header.magic_word",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_header_proto_version,
            { "Protocol Version", "lsdp.header.proto_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_msg_length,
            { "Message Length", "lsdp.msg.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_msg_type,
            { "Message Type", "lsdp.msg.type",
            FT_UINT8, BASE_HEX,
            VALS(lsdp_msg_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_node_id_length,
            { "Node ID Length", "lsdp.node_id.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_node_id_mac,
            { "Node ID (MAC)", "lsdp.node_id.mac",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_node_id,
            { "Node ID", "lsdp.node_id",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_query,
            { "Query Message", "lsdp.query",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_query_count,
            { "Count", "lsdp.query.count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_query_class,
            { "Class", "lsdp.query.class",
            FT_UINT16, BASE_HEX,
            VALS(lsdp_class_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce,
            { "Announce Message", "lsdp.announce",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_addr_length,
            { "Address Length", "lsdp.announce.addr.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_addr_ipv4,
            { "Address", "lsdp.announce.addr_ipv4",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_addr_ipv6,
            { "Address", "lsdp.announce.addr_ipv6",
            FT_IPv6, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_count,
            { "Count", "lsdp.announce.count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record,
            { "Announce Record", "lsdp.announce.record",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_class,
            { "Class", "lsdp.announce.record.class",
            FT_UINT16, BASE_HEX,
            VALS(lsdp_class_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_count,
            { "Count", "lsdp.announce.record.count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_txt,
            { "TXT-Record", "lsdp.announce.record.txt",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_txt_key_length,
            { "Key Length", "lsdp.announce.record.txt.key.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_txt_key,
            { "Key", "lsdp.announce.record.txt.key",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_txt_value_length,
            { "Value Length", "lsdp.announce.record.txt.val.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_announce_record_txt_value,
            { "Key", "lsdp.announce.record.txt.val",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_delete,
            { "Delete Message", "lsdp.delete",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_delete_count,
            { "Count", "lsdp.delete.count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_lsdp_delete_class,
            { "Class", "lsdp.delete.class",
            FT_UINT16, BASE_HEX,
            VALS(lsdp_class_id_vals), 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_lsdp_unknown_msg_type,
            { "lsdp.unknown_msg_type", PI_MALFORMED, PI_ERROR,
                "Message is of invalid type", EXPFILL }
        },
        { &ei_lsdp_invalid_addr_len,
            { "lsdp.invalid_addr_len", PI_MALFORMED, PI_ERROR,
                "Address has an invalid length", EXPFILL }
        }
    };

    static int *ett[] = {
        &ett_lsdp,
        &ett_lsdp_node_id,
        &ett_lsdp_msg,
        &ett_lsdp_msg_rec,
        &ett_lsdp_msg_rec_txt
    };

    expert_module_t* expert_lsdp;

    proto_lsdp = proto_register_protocol ("Lenbrook Service Discovery Protocol", "LSDP", "lsdp");

    proto_register_field_array(proto_lsdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_lsdp = expert_register_protocol(proto_lsdp);
    expert_register_field_array(expert_lsdp, ei, array_length(ei));

    lsdp_handle = register_dissector("lsdp", dissect_lsdp, proto_lsdp);
}

void
proto_reg_handoff_lsdp(void)
{
    dissector_add_uint("udp.port", LSDP_UDP_PORT, lsdp_handle);
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
