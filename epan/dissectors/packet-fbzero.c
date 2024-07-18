/* packet-fbzero.c
 * Routines for Zero Protocol dissection
 * Copyright 2016-2017, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Zero Protocol coming from Facebook and used the same framing like QUIC
 * (tag-map value) but based on TCP
 *
 * See
 *
 *    https://engineering.fb.com/networking-traffic/building-zero-protocol-for-fast-secure-mobile-connections/
 *
 * for some (not much!) information on it.
 *
 * It was reverse engineered based off of QUIC dissector functionality
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>

void proto_register_fb_zero(void);
void proto_reg_handoff_fb_zero(void);

static int proto_fb_zero;

static dissector_handle_t fb_zero_handle;

static int hf_fb_zero_puflags;
static int hf_fb_zero_puflags_vrsn;
static int hf_fb_zero_puflags_unknown;
static int hf_fb_zero_version;
static int hf_fb_zero_length;
static int hf_fb_zero_tag;
static int hf_fb_zero_tags;
static int hf_fb_zero_tag_number;
static int hf_fb_zero_tag_value;
static int hf_fb_zero_tag_type;
static int hf_fb_zero_tag_offset_end;
static int hf_fb_zero_tag_length;
static int hf_fb_zero_tag_sni;
static int hf_fb_zero_tag_vers;
static int hf_fb_zero_tag_sno;
static int hf_fb_zero_tag_aead;
static int hf_fb_zero_tag_scid;
static int hf_fb_zero_tag_time;
static int hf_fb_zero_tag_alpn;
static int hf_fb_zero_tag_pubs;
static int hf_fb_zero_tag_kexs;
static int hf_fb_zero_tag_nonc;

static int hf_fb_zero_tag_unknown;

static int hf_fb_zero_padding;
static int hf_fb_zero_payload;
static int hf_fb_zero_unknown;

static int ett_fb_zero;
static int ett_fb_zero_puflags;
static int ett_fb_zero_prflags;
static int ett_fb_zero_ft;
static int ett_fb_zero_ftflags;
static int ett_fb_zero_tag_value;

static expert_field ei_fb_zero_tag_undecoded;
static expert_field ei_fb_zero_tag_offset_end_invalid;
static expert_field ei_fb_zero_length_invalid;

#define FBZERO_MIN_LENGTH 3

#define VERSION_QTV 0x515456

/**************************************************************************/
/*                      Public Flags                                      */
/**************************************************************************/
#define PUFLAGS_VRSN    0x01
#define PUFLAGS_UNKN    0xFE

/**************************************************************************/
/*                      Message tag                                       */
/**************************************************************************/

#define MTAG_CHLO 0x43484C4F
#define MTAG_SNOM 0x534E4F4D
#define MTAG_SHLO 0x53484C4F
#define MTAG_REJ  0x52454A00
#define MTAG_PRST 0x50525354

static const value_string message_tag_vals[] = {
    { MTAG_CHLO, "Client Hello" },
    { MTAG_SNOM, "Server NOM??" },
    { MTAG_SHLO, "Server Hello" },
    { MTAG_REJ, "Rejection" },
    { MTAG_PRST, "Public Reset" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Tag                                               */
/**************************************************************************/

#define TAG_SNI  0x534E4900
#define TAG_VERS 0x56455253
#define TAG_SNO  0x534E4F00
#define TAG_AEAD 0x41454144
#define TAG_SCID 0x53434944
#define TAG_TIME 0x54494d45
#define TAG_ALPN 0x414C504E
#define TAG_PUBS 0x50554253
#define TAG_KEXS 0x4B455853
#define TAG_NONC 0x4E4F4E43

static const value_string tag_vals[] = {
    { TAG_SNI, "Server Name Indication" },
    { TAG_VERS, "Version" },
    { TAG_SNO, "Server nonce" },
    { TAG_AEAD, "Authenticated encryption algorithms" },
    { TAG_SCID, "Server config ID" },
    { TAG_TIME, "Time" },
    { TAG_ALPN, "ALPN" },
    { TAG_PUBS, "Public value" },
    { TAG_KEXS, "Key exchange algorithms" },
    { TAG_NONC, "Client Nonce" },
    { 0, NULL }
};


/**************************************************************************/
/*                      AEAD Tag                                          */
/**************************************************************************/

#define AEAD_AESG  0x41455347
#define AEAD_S20P  0x53323050
#define AEAD_CC12  0x43433132

static const value_string tag_aead_vals[] = {
    { AEAD_AESG, "AES-GCM with a 12-byte tag and IV" },
    { AEAD_S20P, "Salsa20 with Poly1305" },
    { AEAD_CC12, "ChaCha12 with Poly1305" },
    { 0, NULL }
};

/**************************************************************************/
/*                      KEXS Tag                                          */
/**************************************************************************/

#define KEXS_C255  0x43323535
#define KEXS_P256  0x50323536

static const value_string tag_kexs_vals[] = {
    { KEXS_C255, "Curve25519" },
    { KEXS_P256, "P-256" },
    { 0, NULL }
};


static uint32_t
dissect_fb_zero_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fb_zero_tree, unsigned offset, uint32_t tag_number){
    uint32_t tag_offset_start = offset + tag_number*4*2;
    uint32_t tag_offset = 0, total_tag_len = 0;
    int32_t tag_len = 0;
    bool tag_offset_valid = true;

    while(tag_number){
        proto_tree *tag_tree;
        proto_item *ti_tag, *ti_type, *ti_offset_len, *ti_len;
        uint32_t offset_end, tag;
        const uint8_t* tag_str;

        /*
         * This item covers the tag type and end offset; the tag values
         * are in a separate region following all the type/end offset
         * pairs.
         */
        ti_tag = proto_tree_add_item(fb_zero_tree, hf_fb_zero_tags, tvb, offset, 4*2, ENC_NA);
        tag_tree = proto_item_add_subtree(ti_tag, ett_fb_zero_tag_value);
        ti_type = proto_tree_add_item_ret_string(tag_tree, hf_fb_zero_tag_type, tvb, offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
        tag = tvb_get_ntohl(tvb, offset);
        proto_item_append_text(ti_type, " (%s)", val_to_str_const(tag, tag_vals, "Unknown"));
        proto_item_append_text(ti_tag, ": %s (%s)", tag_str, val_to_str_const(tag, tag_vals, "Unknown"));
        offset += 4;

        ti_offset_len = proto_tree_add_item_ret_uint(tag_tree, hf_fb_zero_tag_offset_end, tvb, offset, 4, ENC_LITTLE_ENDIAN, &offset_end);
        if(offset_end < tag_offset){
            expert_add_info_format(pinfo, ti_offset_len, &ei_fb_zero_tag_offset_end_invalid,
                                   "Invalid tag end offset %u < %u",
                                   offset_end, tag_offset);
            /*
             * We can continue to show the tag type, end offset, and length,
             * but we can no longer show the values, or subsequent length
             * values, as the end offset in the tag value region is bogus.
             */
            tag_offset_valid = false;
        } else {
            tag_len = offset_end - tag_offset;
            if(!tvb_bytes_exist(tvb, tag_offset_start + tag_offset, tag_len)){
                expert_add_info_format(pinfo, ti_offset_len, &ei_fb_zero_tag_offset_end_invalid,
                                       "Invalid tag end offset %u past end of packet",
                                       offset_end);
                /*
                 * We can continue to show the tag type, end offset,
                 * and length, but we can no longer show the values,
                 * as the end offset in the tag value region is bogus.
                 *
                 * We don't just throw an exception here, because we
                 * want to show all the tag type and end offset values.
                 */
                tag_offset_valid = false;
            }
            total_tag_len += tag_len;
            ti_len = proto_tree_add_uint(tag_tree, hf_fb_zero_tag_length, tvb, offset, 4, tag_len);
            proto_item_append_text(ti_tag, " (l=%u)", tag_len);
            proto_item_set_generated(ti_len);
        }
        offset += 4;

        if(tag_offset_valid){
            proto_tree_add_item(tag_tree, hf_fb_zero_tag_value, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
        }

        switch(tag){
            case TAG_SNI:
                if(tag_offset_valid){
                    proto_tree_add_item_ret_string(tag_tree, hf_fb_zero_tag_sni, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                    proto_item_append_text(ti_tag, ": %s", tag_str);
                    tag_offset += tag_len;
                }
                break;
            case TAG_VERS:
                if(tag_offset_valid){
                    if(tag_len != 4){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be 4", tag_len);
                        tag_offset += tag_len;
                        break;
                    }
                    proto_tree_add_item_ret_string(tag_tree, hf_fb_zero_tag_vers, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                    proto_item_append_text(ti_tag, ": %s", tag_str);
                    tag_offset += 4;
                }
            break;
            case TAG_SNO:
                if(tag_offset_valid){
                    proto_tree_add_item(tag_tree, hf_fb_zero_tag_sno, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                    tag_offset += tag_len;
                }
            break;
            case TAG_AEAD:
                if(tag_offset_valid){
                    while(offset_end - tag_offset >= 4){
                        proto_tree *ti_aead;
                        ti_aead = proto_tree_add_item(tag_tree, hf_fb_zero_tag_aead, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII);
                        proto_item_append_text(ti_aead, " (%s)", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_aead_vals, "Unknown"));
                        proto_item_append_text(ti_tag, ", %s", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_aead_vals, "Unknown"));
                        tag_offset += 4;
                    }
                    if(offset_end - tag_offset > 0){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be a multiple of 4", tag_len);
                        tag_offset = offset_end;
                    }
                }
            break;
            case TAG_SCID:
                if(tag_offset_valid){
                    proto_tree_add_item(tag_tree, hf_fb_zero_tag_scid, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                    tag_offset += tag_len;
                }
            break;
            case TAG_TIME:
                if(tag_offset_valid){
                    if(tag_len != 4){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be 4", tag_len);
                        tag_offset += tag_len;
                        break;
                    }
                    proto_tree_add_item(tag_tree, hf_fb_zero_tag_time, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_tag, ": %u", tvb_get_letohl(tvb, tag_offset_start + tag_offset));
                    tag_offset += 4;
                }
            break;
            case TAG_ALPN:
                if(tag_offset_valid){
                    if(tag_len != 4){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be 4", tag_len);
                        tag_offset += tag_len;
                        break;
                    }
                    proto_tree_add_item_ret_string(tag_tree, hf_fb_zero_tag_alpn, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                    proto_item_append_text(ti_tag, ": %s", tag_str);
                    tag_offset += 4;
                }
            break;
            case TAG_PUBS:
                if(tag_offset_valid){
                    /*TODO FIX: 24 Length + Pubs key?.. ! */
                    if(tag_len < 2){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be >= 2", tag_len);
                        tag_offset += tag_len;
                        break;
                    }
                    proto_tree_add_item(tag_tree, hf_fb_zero_tag_pubs, tvb, tag_offset_start + tag_offset, 2, ENC_LITTLE_ENDIAN);
                    tag_offset += 2;
                    while(offset_end - tag_offset >= 3){
                        proto_tree_add_item(tag_tree, hf_fb_zero_tag_pubs, tvb, tag_offset_start + tag_offset, 3, ENC_LITTLE_ENDIAN);
                        tag_offset += 3;
                    }
                    if(offset_end - tag_offset > 0){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be a multiple of 3", tag_len);
                        tag_offset = offset_end;
                    }
                }
            break;
            case TAG_KEXS:
                if(tag_offset_valid){
                    while(offset_end - tag_offset >= 4){
                        proto_tree *ti_kexs;
                        ti_kexs = proto_tree_add_item(tag_tree, hf_fb_zero_tag_kexs, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII);
                        proto_item_append_text(ti_kexs, " (%s)", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_kexs_vals, "Unknown"));
                        proto_item_append_text(ti_tag, ", %s", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_kexs_vals, "Unknown"));
                        tag_offset += 4;
                    }
                    if(offset_end - tag_offset > 0){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be a multiple of 4", tag_len);
                        tag_offset = offset_end;
                    }
                }
            break;
            case TAG_NONC:
                if(tag_offset_valid){
                    /*TODO: Enhance display: 32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data. */
                    if(tag_len != 32){
                        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                                               "Invalid tag length: %u, should be 32", tag_len);
                        tag_offset += tag_len;
                        break;
                    }
                    proto_tree_add_item(tag_tree, hf_fb_zero_tag_nonc, tvb, tag_offset_start + tag_offset, 32, ENC_NA);
                    tag_offset += 32;
                }
            break;
            default:
                expert_add_info_format(pinfo, ti_tag, &ei_fb_zero_tag_undecoded,
                                 "Dissector for FB Zero Tag"
                                 " %s (%s) code not implemented, Contact"
                                 " Wireshark developers if you want this supported",
                                 tvb_get_string_enc(pinfo->pool, tvb, offset-8, 4, ENC_ASCII|ENC_NA), val_to_str_const(tag, tag_vals, "Unknown"));
                if(tag_offset_valid){
                    proto_tree_add_item(tag_tree, hf_fb_zero_tag_unknown, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                    tag_offset += tag_len;
                }
                break;
        }

        tag_number--;
    }

    /* XXX - can this still occur? */
    if (offset + total_tag_len <= offset) {
        expert_add_info_format(pinfo, fb_zero_tree, &ei_fb_zero_length_invalid,
                         "Invalid total tag length: %u", total_tag_len);
        return offset + tvb_reported_length_remaining(tvb, offset);
    }
    return offset + total_tag_len;

}


static int
dissect_fb_zero_unencrypt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fb_zero_tree, unsigned offset, uint8_t len_pkn _U_){

    while(tvb_reported_length_remaining(tvb, offset) > 0){
        proto_item *ti;
        uint32_t message_tag, tag_number, length;
        const uint8_t* message_tag_str;
        proto_tree_add_item(fb_zero_tree, hf_fb_zero_unknown, tvb, offset, 1, ENC_NA);
        offset += 1;

        /*
         * XXX: in theory, a tagged message could be split between
         * TCP segments - even the *header containing the length*
         * could be split - but, from the sequence described in the
         * Facebook blog post, that's probably unlikely in practice.
         */
        proto_tree_add_item_ret_uint(fb_zero_tree, hf_fb_zero_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
        offset += 4;

        message_tag = tvb_get_ntohl(tvb, offset);
        /* check if it is a known message_tag (CHLO, SNOM...) */
        if(try_val_to_str(message_tag, message_tag_vals)){
            ti = proto_tree_add_item_ret_string(fb_zero_tree, hf_fb_zero_tag, tvb, offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &message_tag_str);

            proto_item_append_text(ti, ", Type: %s (%s)", message_tag_str,
                                   val_to_str_const(message_tag, message_tag_vals, "Unknown Tag"));
            col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_tag, message_tag_vals, "Unknown"));
            offset += 4;

            proto_tree_add_item(fb_zero_tree, hf_fb_zero_tag_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            tag_number = tvb_get_letohs(tvb, offset);
            offset += 2;

            proto_tree_add_item(fb_zero_tree, hf_fb_zero_padding, tvb, offset, 2, ENC_NA);
            offset += 2;

            offset = dissect_fb_zero_tag(tvb, pinfo, fb_zero_tree, offset, tag_number);
        } else {
            proto_tree_add_item(fb_zero_tree, hf_fb_zero_unknown, tvb, offset, length, ENC_NA);
            offset += length;
        }
    }

    return offset;

}

static int
dissect_fb_zero_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *ti_puflags;
    proto_tree *fb_zero_tree, *puflags_tree;
    unsigned offset = 0;
    uint8_t puflags;
    uint32_t message_tag, version;

    if (tvb_captured_length(tvb) < FBZERO_MIN_LENGTH)
        return 0;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FB_ZERO");

    ti = proto_tree_add_item(tree, proto_fb_zero, tvb, 0, -1, ENC_NA);
    fb_zero_tree = proto_item_add_subtree(ti, ett_fb_zero);

    /* Public Flags */
    ti_puflags = proto_tree_add_item(fb_zero_tree, hf_fb_zero_puflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    puflags_tree = proto_item_add_subtree(ti_puflags, ett_fb_zero_puflags);
    proto_tree_add_item(puflags_tree, hf_fb_zero_puflags_vrsn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_fb_zero_puflags_unknown, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    puflags = tvb_get_uint8(tvb, offset);
    offset += 1;

    if(puflags & PUFLAGS_VRSN){
        version = tvb_get_ntoh24(tvb, offset);
        if(version == VERSION_QTV){
            proto_tree_add_item(fb_zero_tree, hf_fb_zero_version, tvb, offset, 3, ENC_ASCII);
            offset += 3;
        }
    }

    /* Unencrypt Message (Handshake or Connection Close...) */
    message_tag = tvb_get_ntohl(tvb, offset+5);
    if (message_tag == MTAG_CHLO || message_tag == MTAG_SNOM) {
        offset = dissect_fb_zero_unencrypt(tvb, pinfo, fb_zero_tree, offset, 1);

    }else {     /* Payload... (encrypted... TODO FIX !) */
        col_add_str(pinfo->cinfo, COL_INFO, "Payload (Encrypted)");
        proto_tree_add_item(fb_zero_tree, hf_fb_zero_payload, tvb, offset, -1, ENC_NA);
    }
    return offset;
}


static int
dissect_fb_zero(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
    return dissect_fb_zero_common(tvb, pinfo, tree, NULL);
}

static bool dissect_fb_zero_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation = NULL;
    int offset = 0;
    uint32_t version, length, message_tag;
    /* Verify packet size (Flag (1 byte) + Version (3bytes) + Flag (1 byte) + length (4 bytes) + Tag (4 bytes)) */
    if (tvb_captured_length(tvb) < 13)
    {
        return false;
    }

    /* Flag */
    offset += 1;

    /* Version */
    version = tvb_get_ntoh24(tvb, offset);
    offset += 3;

    /* Flag */
    offset += 1;

    /* length */
    length = tvb_get_letohl(tvb, offset);
    offset += 4;

    /* (message) tag */
    message_tag = tvb_get_ntohl(tvb, offset);

    if (version == VERSION_QTV && length <= tvb_reported_length(tvb) && (message_tag == MTAG_CHLO || message_tag == MTAG_SNOM)) {
        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, fb_zero_handle);
        dissect_fb_zero(tvb, pinfo, tree, data);
        return true;
    }

    return false;
}

void
proto_register_fb_zero(void)
{
    static hf_register_info hf[] = {
        { &hf_fb_zero_puflags,
            { "Public Flags", "fb_zero.puflags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet public flags", HFILL }
        },
        { &hf_fb_zero_puflags_vrsn,
            { "Version", "fb_zero.puflags.version",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_VRSN,
              "Signifies that this packet also contains the version of the FB Zero protocol", HFILL }
        },
        { &hf_fb_zero_puflags_unknown,
            { "Unknown", "fb_zero.puflags.unknown",
              FT_UINT8, BASE_HEX, NULL, PUFLAGS_UNKN,
              NULL, HFILL }
        },

        { &hf_fb_zero_version,
            { "Version", "fb_zero.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "32 bit opaque tag that represents the version of the ZB Zero (Always QTV)", HFILL }
        },
        { &hf_fb_zero_length,
            { "Length", "fb_zero.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag,
            { "Tag", "fb_zero.tag",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_number,
            { "Tag Number", "fb_zero.tag_number",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tags,
            { "Tag/value", "fb_zero.tags",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_type,
            { "Tag Type", "fb_zero.tag_type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_offset_end,
            { "Tag offset end", "fb_zero.tag_offset_end",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_length,
            { "Tag length", "fb_zero.tag_offset_length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_value,
            { "Tag/value", "fb_zero.tag_value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_sni,
            { "Server Name Indication", "fb_zero.tag.sni",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "The fully qualified DNS name of the server, canonicalised to lowercase with no trailing period", HFILL }
        },
        { &hf_fb_zero_tag_vers,
            { "Version", "fb_zero.tag.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Version of FB Zero supported", HFILL }
        },
        { &hf_fb_zero_tag_sno,
            { "Server nonce", "fb_zero.tag.sno",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_aead,
            { "Authenticated encryption algorithms", "fb_zero.tag.aead",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A list of tags, in preference order, specifying the AEAD primitives supported by the server", HFILL }
        },
        { &hf_fb_zero_tag_scid,
            { "Server Config ID", "fb_zero.tag.scid",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "An opaque, 16-byte identifier for this server config", HFILL }
        },
        { &hf_fb_zero_tag_time,
            { "Time", "fb_zero.tag.time",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_tag_alpn,
            { "ALPN", "fb_zero.tag.alpn",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Application-Layer Protocol Negotiation supported", HFILL }
        },
        { &hf_fb_zero_tag_pubs,
            { "Public value", "fb_zero.tag.pubs",
              FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
              "A list of public values, 24-bit, little-endian length prefixed", HFILL }
        },
        { &hf_fb_zero_tag_kexs,
            { "Key exchange algorithms", "fb_zero.tag.kexs",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A list of tags, in preference order, specifying the key exchange algorithms that the server supports", HFILL }
        },
        { &hf_fb_zero_tag_nonc,
            { "Client nonce", "fb_zero.tag.nonc",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data", HFILL }
        },
        { &hf_fb_zero_tag_unknown,
            { "Unknown tag", "fb_zero.tag.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_padding,
            { "Padding", "fb_zero.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_fb_zero_payload,
            { "Payload", "fb_zero.payload",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Fb Zero Payload..", HFILL }
        },
        { &hf_fb_zero_unknown,
            { "Unknown", "fb_zero.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Unknown Data", HFILL }
        },
    };


    static int *ett[] = {
        &ett_fb_zero,
        &ett_fb_zero_puflags,
        &ett_fb_zero_prflags,
        &ett_fb_zero_ft,
        &ett_fb_zero_ftflags,
        &ett_fb_zero_tag_value
    };

    static ei_register_info ei[] = {
        { &ei_fb_zero_tag_undecoded, { "fb_zero.tag.undecoded", PI_UNDECODED, PI_NOTE, "Dissector for FB Zero Tag code not implemented, Contact Wireshark developers if you want this supported", EXPFILL }},
        { &ei_fb_zero_tag_offset_end_invalid, { "fb_zero.offset_end.invalid", PI_PROTOCOL, PI_ERROR, "Invalid tag end offset", EXPFILL }},
        { &ei_fb_zero_length_invalid, { "fb_zero.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid length", EXPFILL }},
    };

    expert_module_t *expert_fb_zero;

    proto_fb_zero = proto_register_protocol("(Facebook) Zero Protocol", "FBZERO", "fb_zero");

    fb_zero_handle = register_dissector("fb_zero", dissect_fb_zero, proto_fb_zero);

    proto_register_field_array(proto_fb_zero, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_fb_zero = expert_register_protocol(proto_fb_zero);
    expert_register_field_array(expert_fb_zero, ei, array_length(ei));
}

void
proto_reg_handoff_fb_zero(void)
{

    heur_dissector_add("tcp", dissect_fb_zero_heur, "FBZero (QUIC) over TCP", "fb_zero", proto_fb_zero, HEURISTIC_ENABLE);

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
