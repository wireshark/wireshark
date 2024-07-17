/* packet-mc-nmf.c
 * Routines for .NET Message Framing Protocol (MC-NMF) dissection
 * Copyright 2017-2020, Uli Heilmeier <uh@heilmeier.eu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wieshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Basic dissector for .NET Message Framing Protocol based on protocol reference found at
 * https://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/[MC-NMF].pdf
 * https://msdn.microsoft.com/en-us/library/cc219293.aspx
 *
 * Things missing:
 *  - heuristic to detect .NET MFP
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

/* Prototypes */
void proto_reg_handoff_mc_nmf(void);
void proto_register_mc_nmf(void);

static dissector_handle_t ms_nns_handle;
static dissector_handle_t tls_handle;

static dissector_handle_t mc_nmf_handle;

/* Initialize the protocol and registered fields */

#define MC_NMF_REC_VERSION      0
#define MC_NMF_REC_MODE         1
#define MC_NMF_REC_VIA          2
#define MC_NMF_REC_KNOWN_ENC    3
#define MC_NMF_REC_EXT_ENC      4
#define MC_NMF_REC_UNSIZED_ENV  5
#define MC_NMF_REC_SIZED_ENV    6
#define MC_NMF_REC_END          7
#define MC_NMF_REC_FAULT        8
#define MC_NMF_REC_UPGRADE_REQ  9
#define MC_NMF_REC_UPGRADE_RSP  10
#define MC_NMF_REC_PREAMBLE_ACK 11
#define MC_NMF_REC_PREAMBLE_END 12

static const value_string mc_nmf_record_type_vals[] = {
    { MC_NMF_REC_VERSION, "Version Record" },
    { MC_NMF_REC_MODE, "Mode Record" },
    { MC_NMF_REC_VIA, "Via Record" },
    { MC_NMF_REC_KNOWN_ENC, "Known Encoding Record" },
    { MC_NMF_REC_EXT_ENC, "Extensible Encoding Record" },
    { MC_NMF_REC_UNSIZED_ENV, "Unsized Envelope Record" },
    { MC_NMF_REC_SIZED_ENV, "Sized Envelope Record" },
    { MC_NMF_REC_END, "End Record" },
    { MC_NMF_REC_FAULT, "Fault Record" },
    { MC_NMF_REC_UPGRADE_REQ, "Upgrade Request Record" },
    { MC_NMF_REC_UPGRADE_RSP, "Upgrade Response Record" },
    { MC_NMF_REC_PREAMBLE_ACK, "Preamble Ack Record" },
    { MC_NMF_REC_PREAMBLE_END, "Preamble End Record" },
    { 0, NULL}
};

static const value_string mc_nmf_mode_vals[] = {
    { 1, "Singleton-Unsized" },
    { 2, "Duplex" },
    { 3, "Simplex" },
    { 4, "Singleton-Sized" },
    { 0, NULL }
};

static const value_string mc_nmf_encoding_vals[] = {
    { 0, "UTF-8" },
    { 1, "UTF-16" },
    { 2, "Unicode little-endian" },
    { 3, "UTF-8" },
    { 4, "UTF-16" },
    { 5, "Unicode little-endian" },
    { 6, "MTOM" },
    { 7, "Binary" },
    { 8, "Binary with in-band dictionary" },
    { 0, NULL }
};

struct mc_nmf_session_state {
    bool      upgrade_req;
    bool      negotiate;
    bool      tls;
    uint32_t  upgrade_rsp;
};

static int proto_mc_nmf;
static int hf_mc_nmf_record_type;
static int hf_mc_nmf_major_version;
static int hf_mc_nmf_minor_version;
static int hf_mc_nmf_mode;
static int hf_mc_nmf_known_encoding;
static int hf_mc_nmf_via_length;
static int hf_mc_nmf_via;
static int hf_mc_nmf_encoding_length;
static int hf_mc_nmf_encoding_type;
static int hf_mc_nmf_fault_length;
static int hf_mc_nmf_fault;
static int hf_mc_nmf_upgrade_length;
static int hf_mc_nmf_upgrade;
static int hf_mc_nmf_chunk_length;
static int hf_mc_nmf_chunk;
static int hf_mc_nmf_terminator;
static int hf_mc_nmf_payload_length;
static int hf_mc_nmf_payload;
static int hf_mc_nmf_upgrade_proto_data;

static expert_field ei_mc_nmf_size_too_big;

// [MC-NMF] does not have a defined port https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/51b5eb53-f488-4b74-b21d-8a498f016b61
// but 9389 is ADWS port https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/cfff3d7f-e7cd-4529-86a0-4de89efe3855
// which relies on [MC-NMF], so by doing this, all ADWS traffic on port 9389 is properly dissected by default
#define MC_NMF_TCP_PORT 9389

/* Initialize the subtree pointers */
static int ett_mc_nmf;
static int ett_mc_nmf_rec;

#define MC_NMF_MIN_LENGTH 1

static bool get_size_length(tvbuff_t *tvb, int *offset, unsigned *len_length, packet_info *pinfo, uint32_t *out_size) {
    uint8_t   lbyte;
    uint64_t  size = 0;
    unsigned  shiftcount = 0;

    lbyte = tvb_get_uint8(tvb, *offset);
    *offset += 1;
    *len_length += 1;
    size = ( lbyte & 0x7F);
    while ( lbyte & 0x80 ) {
        lbyte = tvb_get_uint8(tvb, *offset);
        *offset += 1;
        /* Guard against the pathological case of a sequence of 0x80
         * bytes (which add nothing to size).
         */
        if (*len_length >= 5) {
            expert_add_info(pinfo, NULL, &ei_mc_nmf_size_too_big);
            return false;
        }
        shiftcount = 7 * *len_length;
        size = ((lbyte & UINT64_C(0x7F)) << shiftcount) | (size);
        *len_length += 1;
        /*
         * Check if size if is too big to prevent against overflow.
         * According to spec an implementation SHOULD support record sizes as
         * large as 0xffffffff octets (encoded size requires five octets).
         */
        if (size > 0xffffffff) {
            expert_add_info(pinfo, NULL, &ei_mc_nmf_size_too_big);
            return false;
        }
    }
    *out_size = (uint32_t)size;
    return true;
}

static int
dissect_mc_nmf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item     *ti, *rti, *dti;
    proto_tree     *mc_nmf_tree, *rec_tree, *data_tree;
    unsigned       offset = 0;
    uint32_t       record_type;
    uint8_t        *upgrade_protocol;
    unsigned       len_length;
    int32_t        size;
    uint8_t        search_terminator;
    conversation_t *conversation;
    tvbuff_t       *nt_tvb;
    struct mc_nmf_session_state *session_state;

    if (tvb_reported_length(tvb) < MC_NMF_MIN_LENGTH)
        return 0;

    conversation = find_or_create_conversation(pinfo);

    session_state = (struct mc_nmf_session_state *)conversation_get_proto_data(conversation, proto_mc_nmf);

    if (!session_state) {
        session_state = wmem_new0(wmem_file_scope(), struct mc_nmf_session_state);

        conversation_add_proto_data(conversation, proto_mc_nmf, session_state);
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MC-NMF");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_mc_nmf, tvb, 0, -1, ENC_NA);

    mc_nmf_tree = proto_item_add_subtree(ti, ett_mc_nmf);

    if ( session_state->upgrade_rsp && session_state->upgrade_rsp < pinfo->num && session_state->negotiate) {
        dti = proto_tree_add_item(mc_nmf_tree, hf_mc_nmf_upgrade_proto_data, tvb,
              offset, -1, ENC_NA);
        data_tree = proto_item_add_subtree(dti, ett_mc_nmf_rec);
        nt_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(ms_nns_handle, nt_tvb, pinfo, data_tree);
        return offset + tvb_reported_length(nt_tvb);
    }
    else if ( session_state->upgrade_rsp && session_state->upgrade_rsp < pinfo->num && session_state->tls) {
            dti = proto_tree_add_item(mc_nmf_tree, hf_mc_nmf_upgrade_proto_data, tvb,
                  offset, -1, ENC_NA);
            data_tree = proto_item_add_subtree(dti, ett_mc_nmf_rec);
            nt_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(tls_handle, nt_tvb, pinfo, data_tree);
            return offset + tvb_reported_length(nt_tvb);
    }

    while (tvb_reported_length(tvb) > offset)
    {
        rti = proto_tree_add_item_ret_uint(mc_nmf_tree, hf_mc_nmf_record_type, tvb,
                offset, 1, ENC_BIG_ENDIAN, &record_type);
        offset += 1;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s", val_to_str_const(record_type, mc_nmf_record_type_vals, "Unknown Record"));

        switch (record_type) {
            case MC_NMF_REC_VERSION:
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                proto_tree_add_item(rec_tree, hf_mc_nmf_major_version, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(rec_tree, hf_mc_nmf_minor_version, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case MC_NMF_REC_MODE:
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                proto_tree_add_item(rec_tree, hf_mc_nmf_mode, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case MC_NMF_REC_VIA:
                size = 0;
                len_length = 0;
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                if (!get_size_length(tvb, &offset, &len_length, pinfo, &size))
                    return tvb_reported_length(tvb);
                proto_tree_add_uint(rec_tree, hf_mc_nmf_via_length, tvb, offset - len_length, len_length, size);
                proto_tree_add_item(rec_tree, hf_mc_nmf_via, tvb, offset, size, ENC_UTF_8);
                offset += size;
                break;
            case MC_NMF_REC_KNOWN_ENC:
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                proto_tree_add_item(rec_tree, hf_mc_nmf_known_encoding, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case MC_NMF_REC_EXT_ENC:
                size = 0;
                len_length = 0;
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                if (!get_size_length(tvb, &offset, &len_length, pinfo, &size))
                    return tvb_reported_length(tvb);
                proto_tree_add_uint(rec_tree, hf_mc_nmf_encoding_length, tvb, offset - len_length, len_length, size);
                proto_tree_add_item(rec_tree, hf_mc_nmf_encoding_type, tvb, offset, size, ENC_UTF_8);
                offset += size;
                break;
            case MC_NMF_REC_UNSIZED_ENV:
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                do {
                    size = 0;
                    len_length = 0;
                    if (!get_size_length(tvb, &offset, &len_length, pinfo, &size))
                        return tvb_reported_length(tvb);
                    proto_tree_add_uint(rec_tree, hf_mc_nmf_chunk_length, tvb, offset - len_length, len_length, size);
                    proto_tree_add_item(rec_tree, hf_mc_nmf_chunk, tvb, offset, size, ENC_NA);
                    offset += size;
                    search_terminator = tvb_get_uint8(tvb, offset);
                } while ( search_terminator != 0x00 );
                proto_tree_add_item(rec_tree, hf_mc_nmf_terminator, tvb,
                            offset, 1, ENC_NA);
                offset += 1;
                break;
            case MC_NMF_REC_SIZED_ENV:
                size = 0;
                len_length = 0;
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                if (!get_size_length(tvb, &offset, &len_length, pinfo, &size))
                    return tvb_reported_length(tvb);
                proto_tree_add_uint(rec_tree, hf_mc_nmf_payload_length, tvb, offset - len_length, len_length, size);
                proto_tree_add_item(rec_tree, hf_mc_nmf_payload, tvb, offset, size, ENC_NA);
                offset += size;
                break;
            case MC_NMF_REC_FAULT:
                size = 0;
                len_length = 0;
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                if (!get_size_length(tvb, &offset, &len_length, pinfo, &size))
                    return tvb_reported_length(tvb);
                proto_tree_add_uint(rec_tree, hf_mc_nmf_fault_length, tvb, offset - len_length, len_length, size);
                proto_tree_add_item(rec_tree, hf_mc_nmf_fault, tvb, offset, size, ENC_UTF_8);
                offset += size;
                break;
            case MC_NMF_REC_UPGRADE_REQ:
                size = 0;
                len_length = 0;
                rec_tree = proto_item_add_subtree(rti, ett_mc_nmf_rec);
                if (!get_size_length(tvb, &offset, &len_length, pinfo, &size))
                    return tvb_reported_length(tvb);
                proto_tree_add_uint(rec_tree, hf_mc_nmf_upgrade_length, tvb, offset - len_length, len_length, size);
                proto_tree_add_item(rec_tree, hf_mc_nmf_upgrade, tvb, offset, size, ENC_UTF_8);
                upgrade_protocol = tvb_get_string_enc(pinfo->pool, tvb, offset, size, ENC_UTF_8|ENC_NA);
                offset += size;
                if (strcmp((char*)upgrade_protocol, "application/negotiate") == 0) {
                    session_state->negotiate = true;
                }
                else if (strcmp((char*)upgrade_protocol, "application/ssl-tls") == 0) {
                    session_state->tls = true;
                }
                session_state->upgrade_req = true;
                break;
            case MC_NMF_REC_UPGRADE_RSP:
                if ( session_state->upgrade_req == true) {
                    session_state->upgrade_rsp = pinfo->num;
                }
                break;
            case MC_NMF_REC_END:
            case MC_NMF_REC_PREAMBLE_ACK:
            case MC_NMF_REC_PREAMBLE_END:
                break;
        }
    }
    return offset;
}

void proto_register_mc_nmf(void)
{
    static hf_register_info hf[] = {
        { &hf_mc_nmf_record_type,
          { "RecordType", "mc-nmf.record_type",
            FT_UINT8, BASE_DEC, VALS(mc_nmf_record_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_major_version,
          { "Major Version", "mc-nmf.major_version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_minor_version,
          { "Minor Version", "mc-nmf.minor_version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_mode,
          { "Mode", "mc-nmf.mode",
            FT_UINT8, BASE_DEC, VALS(mc_nmf_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_known_encoding,
          { "Known Encoding", "mc-nmf.known_encoding",
            FT_UINT8, BASE_DEC, VALS(mc_nmf_encoding_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_via_length,
          { "Via Length", "mc-nmf.via_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_via,
          { "Via", "mc-nmf.via",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_encoding_length,
          { "Encoding Length", "mc-nmf.encoding_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_encoding_type,
          { "Encoding Type", "mc-nmf.encoding_type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME Content-Type", HFILL }
        },
        { &hf_mc_nmf_fault_length,
          { "Fault Length", "mc-nmf.fault_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_fault,
          { "Fault", "mc-nmf.fault",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_upgrade_length,
          { "Upgrade Protocol Length", "mc-nmf.upgrade_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_upgrade,
          { "Upgrade Protocol", "mc-nmf.upgrade",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_chunk_length,
          { "DataChunk Length", "mc-nmf.chunk_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_chunk,
          { "DataChunk", "mc-nmf.chunk",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_terminator,
          { "Terminator", "mc-nmf.terminator",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_payload_length,
          { "Size", "mc-nmf.payload_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_payload,
          { "Payload", "mc-nmf.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mc_nmf_upgrade_proto_data,
          { "Upgrade Protocol Data", "mc-nmf.upgrade_protocol_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_mc_nmf,
        &ett_mc_nmf_rec
    };

    static ei_register_info ei[] = {
        { &ei_mc_nmf_size_too_big, { "mc-nmf.size_too_big", PI_MALFORMED, PI_ERROR, "Size too big", EXPFILL }},
    };

    expert_module_t* expert_mc_nmf;

    proto_mc_nmf = proto_register_protocol(".NET Message Framing Protocol", "MC-NMF", "mc-nmf");

    proto_register_field_array(proto_mc_nmf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mc_nmf = expert_register_protocol(proto_mc_nmf);
    expert_register_field_array(expert_mc_nmf, ei, array_length(ei));

    mc_nmf_handle = register_dissector("mc-nmf", dissect_mc_nmf, proto_mc_nmf);
}

void proto_reg_handoff_mc_nmf(void)
{
    dissector_add_uint_with_preference("tcp.port", MC_NMF_TCP_PORT, mc_nmf_handle);
    ms_nns_handle = find_dissector_add_dependency("ms-nns", proto_mc_nmf);
    tls_handle = find_dissector("tls");
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
