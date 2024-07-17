/* packet-ms-nns.c
 * Routines for .NET NegotiateStream Protocol (MS-NNS) dissection
 * Copyright 2020, Uli Heilmeier <uh@heilmeier.eu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wieshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Basic dissector for .NET NegotiateStream Protocol based on protocol reference found at
 * https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NNS/%5bMS-NNS%5d.pdf
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/conversation.h>

/* Prototypes */
void proto_reg_handoff_nns(void);
void proto_register_nns(void);

static dissector_handle_t gssapi_handle;


#define MS_NNS_MESSAGE_HANDSHAKE_DONE      20
#define MS_NNS_MESSAGE_HANDSHAKE_ERROR     21
#define MS_NNS_MESSAGE_HANDSHAKE_PROGRESS  22

static const value_string nns_message_id_vals[] = {
    { MS_NNS_MESSAGE_HANDSHAKE_DONE, "Handshake Done" },
    { MS_NNS_MESSAGE_HANDSHAKE_ERROR, "Handshake Error" },
    { MS_NNS_MESSAGE_HANDSHAKE_PROGRESS, "Handshake In Progress" },
    { 0, NULL}
};

struct nns_session_state {
    uint32_t  handshake_done;
    bool      first_handshake_done;
};

static int proto_nns;
static int hf_nns_message_id;
static int hf_nns_major_version;
static int hf_nns_minor_version;
static int hf_nns_auth_payload_size;
static int hf_nns_auth_payload;
static int hf_nns_payload_size;
static int hf_nns_payload;

static int ett_nns;
static int ett_nns_payload;

#define MS_NNS_MIN_LENGTH 4

static int
dissect_nns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item      *ti, *pti;
    proto_tree      *nns_tree, *payload_tree;
    unsigned        offset = 0;
    uint32_t        message_id;
    uint32_t        payload_size;
    conversation_t  *conversation;
    tvbuff_t        *nt_tvb;
    int             remaining;
    struct nns_session_state *session_state;

    if (tvb_reported_length(tvb) < MS_NNS_MIN_LENGTH)
        return 0;

    conversation = find_or_create_conversation(pinfo);

    session_state = (struct nns_session_state *)conversation_get_proto_data(conversation, proto_nns);
    if (!session_state) {
        session_state = wmem_new0(wmem_file_scope(), struct nns_session_state);
        conversation_add_proto_data(conversation, proto_nns, session_state);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS-NNS");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_nns, tvb, 0, -1, ENC_NA);

    nns_tree = proto_item_add_subtree(ti, ett_nns);

    /* As it is unknown if there is a one-way Handshake Done or a two-way Handshake Done we check the first frame
     * after the first Handshake Done if it looks like a Handshake Done message (0x140100). */

    if ( session_state->handshake_done && session_state->handshake_done < pinfo->num &&
            !(session_state->first_handshake_done && tvb_get_ntoh24(tvb, offset) == 0x140100)) {
        proto_tree_add_item_ret_uint(nns_tree, hf_nns_payload_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &payload_size);
        offset += 4;
        col_append_str(pinfo->cinfo, COL_INFO, "Data");
        if ( payload_size > 0) {
            remaining = tvb_reported_length_remaining(tvb, offset);
            if ((uint32_t) remaining < payload_size) {
                pinfo->desegment_offset = offset - 4;
                pinfo->desegment_len = payload_size - remaining;
                return (offset - 4);
            }
            proto_tree_add_item(nns_tree, hf_nns_payload, tvb, offset, payload_size, ENC_NA);
            offset += payload_size;
            session_state->first_handshake_done = false;
        }
    }
    else {
        proto_tree_add_item_ret_uint(nns_tree, hf_nns_message_id, tvb, offset, 1, ENC_NA, &message_id);
        offset += 1;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", val_to_str_const(message_id, nns_message_id_vals, "Unknown Record"));
        proto_tree_add_item(nns_tree, hf_nns_major_version, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(nns_tree, hf_nns_minor_version, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item_ret_uint(nns_tree, hf_nns_auth_payload_size, tvb, offset, 2, ENC_BIG_ENDIAN, &payload_size);
        offset += 2;
        if ( payload_size > 0) {
            if ((uint32_t) tvb_reported_length_remaining(tvb, offset) < payload_size) {
                pinfo->desegment_offset = offset - 5;
                pinfo->desegment_len = payload_size;
                return (offset - 5);
            }
            pti = proto_tree_add_item(nns_tree, hf_nns_auth_payload, tvb, offset, payload_size, ENC_NA);
            if (message_id == MS_NNS_MESSAGE_HANDSHAKE_DONE || message_id == MS_NNS_MESSAGE_HANDSHAKE_PROGRESS) {
                nt_tvb = tvb_new_subset_length(tvb, offset, payload_size);
                payload_tree = proto_item_add_subtree(pti, ett_nns_payload);
                call_dissector(gssapi_handle, nt_tvb, pinfo, payload_tree);
            }
            offset += payload_size;
        }
        if ( message_id == MS_NNS_MESSAGE_HANDSHAKE_DONE) {
            session_state->handshake_done = pinfo->num;
            session_state->first_handshake_done = (session_state->first_handshake_done ? false : true);
        }
    }
    return offset;
}

void proto_register_nns(void)
{
    static hf_register_info hf[] = {
        { &hf_nns_message_id,
          { "MessageID", "ms-nns.message_id",
            FT_UINT8, BASE_DEC, VALS(nns_message_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nns_major_version,
          { "Major Version", "ms-nns.major_version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nns_minor_version,
          { "Minor Version", "ms-nns.minor_version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nns_auth_payload_size,
          { "Auth Payload Size", "ms-nns.auth_payload_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nns_auth_payload,
          { "Auth Payload", "ms-nns.known_encoding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nns_payload_size,
          { "Payload Size", "ms-nns.payload_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nns_payload,
          { "Payload", "ms-nns.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_nns,
        &ett_nns_payload
    };

    proto_nns = proto_register_protocol(".NET NegotiateStream Protocol", "MS-NNS", "ms-nns");
    proto_register_field_array(proto_nns, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("ms-nns", dissect_nns, proto_nns);
}

void proto_reg_handoff_nns(void)
{
    gssapi_handle = find_dissector("gssapi");
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
