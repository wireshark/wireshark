/* packet-iso14443.c
 * Routines for ISO14443 dissection
 * Copyright 2015, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* ISO14443 is a set of standards describing the communication between a
 * card reader and a contactless smartcard.
 *
 * This dissector handles the initialization messages defined in
 * ISO14443-3 and the activation and protocol messages from ISO14443-4
 *
 * The standards are available as "final committee drafts" from
 * http://wg8.de/wg8n1496_17n3613_Ballot_FCD14443-3.pdf
 * http://wg8.de/wg8n1344_17n3269_Ballot_FCD14443-4.pdf
 *
 * The pcap input format for this dissector is documented at
 * http://www.kaiser.cx/pcap-iso14443.html.
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

/* event byte in the PCAP ISO14443 pseudo-header */
#define ISO14443_EVT_DATA_PICC_TO_PCD  0xFF
#define ISO14443_EVT_DATA_PCD_TO_PICC  0xFE
#define ISO14443_EVT_FIELD_OFF         0xFD
#define ISO14443_EVT_FIELD_ON          0xFC

static const value_string iso14443_event[] = {
    { ISO14443_EVT_DATA_PICC_TO_PCD, "Data transfer PICC -> PCD" },
    { ISO14443_EVT_DATA_PCD_TO_PICC, "Data transfer PCD -> PICC" },
    { ISO14443_EVT_FIELD_ON,         "Field on" },
    { ISO14443_EVT_FIELD_OFF,        "Field off" },
    { 0, NULL }
};

#define IS_DATA_TRANSFER(e) \
    ((e)==ISO14443_EVT_DATA_PICC_TO_PCD || (e)==ISO14443_EVT_DATA_PCD_TO_PICC)

typedef enum _iso14443_cmd_t {
    CMD_TYPE_WUPA,    /* REQA, WUPA or ATQA */
    CMD_TYPE_WUPB,    /* REQB, WUPB or ATQB */
    CMD_TYPE_HLTA,
    CMD_TYPE_UID,     /* anticollision or selection commands
                         and their answers */
    CMD_TYPE_ATS,     /* RATS or ATS */
    CMD_TYPE_ATTRIB,  /* Attrib or the answer to Attrib */
    CMD_TYPE_BLOCK,   /* I-, R- or S-blocks */
    CMD_TYPE_UNKNOWN
} iso14443_cmd_t;

static wmem_tree_t *transactions = NULL;

typedef struct _iso14443_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    iso14443_cmd_t cmd;
} iso14443_transaction_t;

static const value_string iso14443_short_frame[] = {
    { 0x26 , "REQA" },
    { 0x52 , "WUPA" },
    { 0, NULL }
};

const true_false_string tfs_wupb_reqb = { "WUPB", "REQB" };

void proto_register_iso14443(void);
void proto_reg_handoff_iso14443(void);

static int proto_iso14443 = -1;

static dissector_table_t iso14443_cmd_type_table;

static int ett_iso14443 = -1;
static int ett_iso14443_hdr = -1;

static int hf_iso14443_hdr_ver = -1;
static int hf_iso14443_event = -1;
static int hf_iso14443_len_field = -1;
static int hf_iso14443_resp_to = -1;
static int hf_iso14443_resp_in = -1;
static int hf_iso14443_short_frame = -1;
static int hf_iso14443_apf = -1;
static int hf_iso14443_afi = -1;
static int hf_iso14443_ext_atqb = -1;
/* if this is present but unset, we have a REQB */
static int hf_iso14443_wupb = -1;


static expert_field ei_iso14443_unknown_cmd = EI_INIT;

/* Proximity Integrated Circuit Card, i.e. the smartcard */
#define ADDR_PICC "PICC"
/* Proximity Coupling Device, i.e. the card reader */
#define ADDR_PCD  "PCD"


static int dissect_iso14443_cmd_type_wupa(
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    guint8 direction = GPOINTER_TO_UINT(data);

    if (direction == ISO14443_EVT_DATA_PCD_TO_PICC) {
        const gchar *sf_str;
        sf_str = try_val_to_str(
            tvb_get_guint8(tvb, 0), iso14443_short_frame);
        proto_tree_add_item(tree, hf_iso14443_short_frame,
                tvb, 0, 1, ENC_BIG_ENDIAN);
        if (sf_str)
            col_set_str(pinfo->cinfo, COL_INFO, sf_str);
    }
    else if (direction == ISO14443_EVT_DATA_PICC_TO_PCD) {
        col_set_str(pinfo->cinfo, COL_INFO, "ATQA");
    }

    return tvb_captured_length(tvb);
}


static int dissect_iso14443_cmd_type_wupb(
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    guint8 direction = GPOINTER_TO_UINT(data);
    gint offset = 0;

    if (direction == ISO14443_EVT_DATA_PCD_TO_PICC) {
        guint8 param;

        proto_tree_add_item(tree, hf_iso14443_apf,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_afi,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        param = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_iso14443_ext_atqb,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_iso14443_wupb,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        col_set_str(pinfo->cinfo, COL_INFO,
                (param & 0x08) ? tfs_wupb_reqb.true_string :
                tfs_wupb_reqb.false_string);
    }
    else if (direction == ISO14443_EVT_DATA_PICC_TO_PCD) {
        col_set_str(pinfo->cinfo, COL_INFO, "ATQB");
    }

    return tvb_captured_length(tvb);
}


static int
dissect_iso14443_cmd_type_hlta(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_INFO, "HLTA");

    return tvb_captured_length(tvb);
}


static int
dissect_iso14443_cmd_type_uid(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_INFO, "UID");

    return tvb_captured_length(tvb);
}


static int dissect_iso14443_cmd_type_ats(
        tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_,
        void *data)
{
    guint8 direction = GPOINTER_TO_UINT(data);

    if (direction == ISO14443_EVT_DATA_PCD_TO_PICC) {
        col_set_str(pinfo->cinfo, COL_INFO, "RATS");
    }
    else if (direction == ISO14443_EVT_DATA_PICC_TO_PCD) {
        col_set_str(pinfo->cinfo, COL_INFO, "ATS");
    }

    return tvb_captured_length(tvb);
}


static int dissect_iso14443_cmd_type_attrib(
        tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_,
        void *data)
{
    guint8 direction = GPOINTER_TO_UINT(data);

    if (direction == ISO14443_EVT_DATA_PCD_TO_PICC) {
        col_set_str(pinfo->cinfo, COL_INFO, "Attrib");
    }
    else if (direction == ISO14443_EVT_DATA_PICC_TO_PCD) {
        col_set_str(pinfo->cinfo, COL_INFO, "Response to Attrib");
    }

    return tvb_captured_length(tvb);
}


static int
dissect_iso14443_cmd_type_block(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_INFO, "Block");

    return tvb_captured_length(tvb);
}


static gint
iso14443_set_addrs(guint8 event, packet_info *pinfo)
{
    if (!IS_DATA_TRANSFER(event))
        return -1;

    if (event == ISO14443_EVT_DATA_PICC_TO_PCD) {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_PICC)+1 , ADDR_PICC);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_PCD)+1, ADDR_PCD);
    }
    else {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_PCD)+1, ADDR_PCD);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_PICC)+1 , ADDR_PICC);
    }

    return 1;
}


static inline gboolean
iso14443_block_pcb(guint8 byte)
{
    if ((byte & 0xE2) == 0x02) {
        /* I-block */
        return TRUE;
    }
    else if ((byte & 0xE6) == 0xA2) {
        /* R-block */
        return TRUE;
    }
    else if ((byte & 0xC7) == 0xC2) {
        /* S-block */
        return TRUE;
    }

    return FALSE;
}


static iso14443_transaction_t *iso14443_get_transaction(
        packet_info *pinfo, proto_tree *tree, guint8 direction)
{
    proto_item *it;
    iso14443_transaction_t *iso14443_trans = NULL;

    if (direction == ISO14443_EVT_DATA_PCD_TO_PICC) {
        if (PINFO_FD_VISITED(pinfo)) {
            iso14443_trans = (iso14443_transaction_t *)wmem_tree_lookup32(
                    transactions, PINFO_FD_NUM(pinfo));
            if (iso14443_trans && iso14443_trans->rqst_frame==PINFO_FD_NUM(pinfo) &&
                    iso14443_trans->resp_frame!=0) {
               it = proto_tree_add_uint(tree, hf_iso14443_resp_in,
                       NULL, 0, 0, iso14443_trans->resp_frame);
               PROTO_ITEM_SET_GENERATED(it);
            }
        }
        else {
            iso14443_trans = wmem_new(wmem_file_scope(), iso14443_transaction_t);
            iso14443_trans->rqst_frame = PINFO_FD_NUM(pinfo);
            iso14443_trans->resp_frame = 0;
            /* iso14443_trans->ctrl = ctrl; */
            wmem_tree_insert32(transactions,
                    iso14443_trans->rqst_frame, (void *)iso14443_trans);
        }
    }
    else if (direction == ISO14443_EVT_DATA_PICC_TO_PCD) {
        iso14443_trans = (iso14443_transaction_t *)wmem_tree_lookup32_le(
                transactions, PINFO_FD_NUM(pinfo));
        if (iso14443_trans && iso14443_trans->resp_frame==0) {
            /* there's a pending request, this packet is the response */
            iso14443_trans->resp_frame = PINFO_FD_NUM(pinfo);
        }

        if (iso14443_trans && iso14443_trans->resp_frame == PINFO_FD_NUM(pinfo)) {
            it = proto_tree_add_uint(tree, hf_iso14443_resp_to,
                    NULL, 0, 0, iso14443_trans->rqst_frame);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }

    return iso14443_trans;
}


static iso14443_cmd_t iso14443_get_cmd_type(
        tvbuff_t *tvb, guint8 direction, iso14443_transaction_t *trans)
{
    guint8 first_byte;

    first_byte = tvb_get_guint8(tvb, 0);

    if (direction == ISO14443_EVT_DATA_PCD_TO_PICC) {
        if (tvb_reported_length(tvb) == 1) {
            return CMD_TYPE_WUPA;
        }
        else if (first_byte == 0x05) {
            return CMD_TYPE_WUPB;
        }
        else if (first_byte == 0x50) {
            return CMD_TYPE_HLTA;
        }
        else if (first_byte == 0x1D) {
            return CMD_TYPE_ATTRIB;
        }
        else if (first_byte == 0xE0) {
            return CMD_TYPE_ATS;
        }
        else if ((first_byte & 0x90) == 0x90) {
            return CMD_TYPE_UID;
        }
        else if (iso14443_block_pcb(first_byte)) {
            return CMD_TYPE_BLOCK;
        }
    }
    else if (direction == ISO14443_EVT_DATA_PICC_TO_PCD) {
        if (trans->cmd != CMD_TYPE_UNKNOWN) {
            return trans->cmd;
        }
        else if (iso14443_block_pcb(first_byte)) {
            return CMD_TYPE_BLOCK;
        }

        /* we don't try to detect any response messages based on their
           length - depending on the log tool, two trailing CRC bytes
           may be added or not */
    }

    return CMD_TYPE_UNKNOWN;
}


static gint
dissect_iso14443_msg(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, guint8 direction)
{
    iso14443_transaction_t *iso14443_trans;
    iso14443_cmd_t cmd;
    gint ret;

    iso14443_trans = iso14443_get_transaction(pinfo, tree, direction);
    if (!iso14443_trans)
        return -1;

    cmd = iso14443_get_cmd_type(tvb, direction, iso14443_trans);
    if (cmd != CMD_TYPE_UNKNOWN)
        iso14443_trans->cmd = cmd;

    ret = dissector_try_uint_new(iso14443_cmd_type_table, cmd,
            tvb, pinfo, tree, FALSE, GUINT_TO_POINTER(direction));
    if (ret == 0) {
        proto_tree_add_expert(tree, pinfo, &ei_iso14443_unknown_cmd,
                tvb, 0, tvb_captured_length(tvb));
        ret = tvb_captured_length(tvb);
    }

    return ret;
}


static int dissect_iso14443(tvbuff_t *tvb,
        packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        packet_len;
    gint        offset = 0, offset_ver, offset_evt, offset_len_field;
    gint        ret;
    guint8      version, event;
    const gchar *event_str;
    guint16     len_field;
    proto_item *tree_ti;
    proto_tree *iso14443_tree, *hdr_tree;
    tvbuff_t    *payload_tvb;

    if (tvb_captured_length(tvb) < 4)
        return 0;

    offset_ver = offset;
    version = tvb_get_guint8(tvb, offset++);
    if (version != 0)
        return 0;

    offset_evt = offset;
    event = tvb_get_guint8(tvb, offset++);
    event_str = try_val_to_str(event, iso14443_event);
    if (!event_str)
        return 0;

    packet_len = tvb_reported_length(tvb);
    offset_len_field = offset;
    len_field = tvb_get_ntohs(tvb, offset);
    if (len_field != (packet_len-4))
        return 0;
    offset += 2;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO 14443");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_ti = proto_tree_add_protocol_format(tree, proto_iso14443,
            tvb, 0, tvb_reported_length(tvb), "ISO 14443");
    iso14443_tree = proto_item_add_subtree(tree_ti, ett_iso14443);

    hdr_tree = proto_tree_add_subtree(iso14443_tree,
            tvb, 0, offset, ett_iso14443_hdr, NULL, "Pseudo header");

    proto_tree_add_item(hdr_tree, hf_iso14443_hdr_ver,
            tvb, offset_ver, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_iso14443_event,
            tvb, offset_evt, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_iso14443_len_field,
            tvb, offset_len_field, 2, ENC_BIG_ENDIAN);

    if (IS_DATA_TRANSFER(event)) {
        iso14443_set_addrs(event, pinfo);

        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        ret = dissect_iso14443_msg(payload_tvb, pinfo, iso14443_tree, event);
        if (ret > 0)
            offset += ret;
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, event_str);
    }

    return offset;
}


void
proto_register_iso14443(void)
{
    static hf_register_info hf[] = {
        { &hf_iso14443_hdr_ver,
            { "Version", "iso14443.hdr_version",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_event,
            { "Event", "iso14443.event",
                FT_UINT8, BASE_HEX, VALS(iso14443_event), 0, NULL, HFILL }
        },
        { &hf_iso14443_len_field,
            { "Length field", "iso14443.length_field",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_resp_in,
            { "Response In", "iso14443.resp_in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_iso14443_resp_to,
            { "Response To", "iso14443.resp_to",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_iso14443_short_frame,
            { "Short frame", "iso14443.short_frame",
                FT_UINT8, BASE_HEX, VALS(iso14443_short_frame), 0, NULL, HFILL }
        },
        { &hf_iso14443_apf,
            { "Anticollision prefix", "iso14443.apf",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_afi,
            { "Application Family Identifier", "iso14443.afi",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_ext_atqb,
            { "Extended ATQB", "iso14443.ext_atqb", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL }
        },
        { &hf_iso14443_wupb,
            { "WUPB/REQB", "iso14443.wupb",
                FT_BOOLEAN, 8, TFS(&tfs_wupb_reqb), 0x08, NULL, HFILL }
        }
   };

    static gint *ett[] = {
        &ett_iso14443,
        &ett_iso14443_hdr
    };

    static ei_register_info ei[] = {
        { &ei_iso14443_unknown_cmd,
            { "iso14443.cmd.unknown", PI_PROTOCOL, PI_WARN,
                "Unknown ISO1443 command", EXPFILL }
        }
    };

    expert_module_t* expert_iso14443;

    proto_iso14443 = proto_register_protocol(
            "ISO/IEC 14443", "ISO 14443", "iso14443");
    proto_register_field_array(proto_iso14443, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_iso14443 = expert_register_protocol(proto_iso14443);
    expert_register_field_array(expert_iso14443, ei, array_length(ei));

    iso14443_cmd_type_table = register_dissector_table(
            "iso14443.cmd_type", "ISO14443 Command Type",
            FT_UINT8, BASE_DEC, DISSECTOR_TABLE_ALLOW_DUPLICATE);

    new_register_dissector("iso14443", dissect_iso14443, proto_iso14443);

    transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}


void
proto_reg_handoff_iso14443(void)
{
  dissector_handle_t cmd_type_handle;

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_wupa, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_WUPA, cmd_type_handle);

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_wupb, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_WUPB, cmd_type_handle);

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_hlta, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_HLTA, cmd_type_handle);

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_uid, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_UID, cmd_type_handle);

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_ats, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_ATS, cmd_type_handle);

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_attrib, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_ATTRIB, cmd_type_handle);

  cmd_type_handle = new_create_dissector_handle(
          dissect_iso14443_cmd_type_block, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_BLOCK, cmd_type_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
