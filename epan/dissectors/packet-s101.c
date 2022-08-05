/* packet-S101.c
 * Routines for S101 dissection
 * Copyright 2018, Gilles Dufour <dufour.gilles@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This Dissector will dissect S101 frames used by Lawo Ember Plus protocol.
 * https://github.com/Lawo/ember-plus/
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <wsutil/crc16.h>
#include <epan/expert.h>


#define S101_HEADER_DATA_LENGTH 9
#define S101_BOF 0xFE
#define S101_EOF 0xFF
#define S101_CE  0xFD
#define S101_XOR 0x20
#define S101_INV 0xF8
#define S101_SLOT 0x00
#define S101_MSG_EMBER 0x0E
#define S101_CMD_EMBER 0x00
#define S101_CMD_KEEPALIVE_REQ 0x01
#define S101_CMD_KEEPALIVE_RESP 0x02
#define S101_VERSION 0x01
#define FLAG_SINGLE_PACKET 0xC0
#define FLAG_FIRST_MULTI_PACKET 0x80
#define FLAG_LAST_MULTI_PACKET 0x40
#define FLAG_EMPTY_PACKET 0x20
#define FLAG_MULTI_PACKET 0x00
#define S101_DTD_GLOW 0x01
#define S101_DTD_VERSION_MAJOR 0x02
#define S101_DTD_VERSION_MINOR 0x1F
#define S101_VALID_CRC 0xF0B8
#define APP_BYTES_LEN 2

static int hf_S101_frame_format = -1;
static int hf_S101_length_size = -1;
static int hf_S101_message_length = -1;
static int hf_S101_slot = -1;
static int hf_S101_message_type = -1;
static int hf_S101_cmd_type = -1;
static int hf_S101_version = -1;
static int hf_S101_flags = -1;
static int hf_S101_dtd_type = -1;
static int hf_S101_app_bytes_len = -1;
static int hf_S101_dtd_minor_ver = -1;
static int hf_S101_dtd_major_ver = -1;
static int hf_S101_crc = -1;
static int hf_S101_crc_status = -1;
static int hf_S101_eof = -1;
static int hf_S101_error = -1;

static dissector_handle_t glow_handle = NULL;
static reassembly_table s101_data_reassembly_table;

typedef struct _s101_fragment_t {
    guint32 id;
    int offset;
} s101_fragment_t;

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_S101(void);
void proto_register_S101(void);
static tvbuff_t *decode_s101_escaped_buffer(tvbuff_t *tvb, packet_info *pinfo, int *offset, guint16 *crc);
static guint32 get_fragment_pdu_id(packet_info *pinfo);
static s101_fragment_t* new_fragment_info(packet_info *pinfo);
static void display_expert_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int len);

/* Initialize the protocol and registered fields */
static int proto_S101 = -1;

/* Real port preferences should generally default to 0 unless there is an
 * IANA-registered (or equivalent) port for your protocol. */
#define S101_TCP_PORT 9000 /* Not IANA-registered */

/* Initialize the subtree pointers */
static gint ett_S101 = -1;
static gint ett_decoding_error = -1;

#define S101_MIN_LENGTH 5

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static int hf_msg_reassembled_data = -1;


static expert_field ei_s101_failed_reassembly = EI_INIT;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items msg_frag_items = {
    /* Fragment subtrees */
    &ett_msg_fragment,
    &ett_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    &hf_msg_reassembled_data,
    /* Tag */
    "Message fragments"
};

/*
 Create a unique id to link fragments together.
 This is a 4 bytes value:
 | SRCPORT (16) | SRC_ADDRESS (16) |
 SRC_ADDRESS is last 2 bytes of the src address.
 */
static guint32 get_fragment_pdu_id(packet_info *pinfo) {
    guint32 id = pinfo->srcport << 16;
    const guint8 *data = (const guint8*)pinfo->src.data;
    if (pinfo->src.len >= 2) {
        id =  id + (((guint32)data[pinfo->src.len - 2]) << 8) + (guint32)data[pinfo->src.len - 1];
    }
    return id;
}

static wmem_map_t* s101_fragment_info_hash = NULL;

static s101_fragment_t* new_fragment_info(packet_info *pinfo) {
    s101_fragment_t* fi = wmem_new(wmem_file_scope(), s101_fragment_t);
    if (NULL == fi) { return fi; }
    fi->id = pinfo->num;
    fi->offset = 0;
    return fi;
}

/* Get 1 byte
 If byte escaped, get the unescaped value
 */
static guint8 get_byte(tvbuff_t *tvb, int *offset, guint16 *crc) {
    guint8 b = tvb_get_guint8(tvb, *offset);
    *crc = crc16_ccitt_seed(&b, 1, *crc) ^ 0xFFFF;
    *offset = *offset + 1;
    if (b == S101_CE) {
        b = tvb_get_guint8(tvb, *offset);
        *crc = crc16_ccitt_seed(&b, 1, *crc) ^ 0xFFFF;
        *offset = *offset + 1;
        return (b ^ S101_XOR);
    } else {
        return b;
    }
}


static const value_string frame_format_vs[] = {
    { S101_BOF , "Escaped Frame" },
    { S101_INV , "UnEscaped Frame"},
    { 0, NULL}
};

static const value_string message_type_vs[] = {
    { S101_MSG_EMBER , "Ember" },
    { 0, NULL}
};

static const value_string command_type_vs[] = {
    { S101_CMD_EMBER , "Ember Command" },
    { S101_CMD_KEEPALIVE_REQ , "Keepalive Request" },
    { S101_CMD_KEEPALIVE_RESP , "Keepalive Response" },
    { 0, NULL}
};

static const value_string flags_vs[] = {
    { FLAG_SINGLE_PACKET , "Single Packet" },
    { FLAG_EMPTY_PACKET , "Empty Packet" },
    { FLAG_MULTI_PACKET , "Multi Packet" },
    { FLAG_LAST_MULTI_PACKET , "Last Packet" },
    { FLAG_FIRST_MULTI_PACKET , "First Packet" },
    { 0, NULL}
};

static const value_string dtd_type_vs[] = {
    { S101_DTD_GLOW , "DTD Glow" },
    { 0, NULL}
};



static void
display_expert_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int len) {
    proto_item* pi;
    proto_tree *error_tree;

    error_tree = proto_tree_add_subtree(tree, tvb, offset, len,
                           ett_decoding_error, &pi, "S101 Error");

    pi = proto_tree_add_string_format_value(
            error_tree, hf_S101_error, tvb, offset, len, "s101_error",
            "reassembly error");

    expert_add_info(pinfo, pi, &ei_s101_failed_reassembly);
}

/*
  Check s101 packet header format.
 If not valid, return 0.
 If valid, extract all header parameters and return 1.
 If variant1, set msgLength to zero.  We will have to search the end of frame.
 If variant2, the msgLength contains the msgLength in bytes 0-6 and byte 7 is the number of bytes.
 */
static int
find_s101_packet_header(tvbuff_t *tvb, int* offset, guint8 *start, guint8 *slot, guint8 *message, guint8 *version, guint8 *dtd, guint8 *command,
                           guint8 *flags, guint8* app_bytes, guint64 *msgLength, guint16 *crc)
{
    guint8 app_bytes_len = 0;
    int i;

    *start = tvb_get_guint8(tvb, *offset); // no CRC and no escaping on first bytes.
    *offset = *offset + 1;
    if (*start == S101_INV) { // Variant 2 of header - unescaped data
        //Read the frame length
        app_bytes_len = tvb_get_guint8(tvb, *offset) & 0x7;
        *offset = *offset + 1;

        if (app_bytes_len > 1) {
            *msgLength = tvb_get_bits64 (tvb, *offset, app_bytes_len * 8, ENC_BIG_ENDIAN);
            *msgLength = *msgLength + (((guint64)app_bytes_len) << 56);
            *offset = app_bytes_len;
        }
    }
    else if (*start != S101_BOF) {
        // IF NOT Begining of Frame - variant 1 - escaped data
        return 0;
    }
    else {
        *msgLength = 0;
    }

    *slot = get_byte(tvb, offset, crc);
    *message = get_byte(tvb, offset, crc);
    *command = get_byte(tvb, offset, crc);
    *version = get_byte(tvb, offset, crc);

    if (*command == S101_CMD_EMBER) {
        *flags = get_byte(tvb, offset, crc);
        *dtd = get_byte(tvb, offset, crc);
        app_bytes_len = get_byte(tvb, offset, crc);
    }
    if ((S101_SLOT != *slot) ||
        (S101_MSG_EMBER != *message) || (*command > S101_CMD_KEEPALIVE_RESP) ||
        (S101_VERSION != *version ) ||
        ((*command == S101_CMD_EMBER) &&
         ((*flags & 0xF) || (S101_DTD_GLOW != *dtd) || (APP_BYTES_LEN != app_bytes_len)))) {
        return 0;
    }
    if (*command == S101_CMD_EMBER) {
        for(i = 0; i < APP_BYTES_LEN; i++) {
            app_bytes[i] = get_byte(tvb, offset, crc);
        }
    }
    return 1;
}

static tvbuff_t *
decode_s101_escaped_buffer(tvbuff_t *tvb, packet_info *pinfo, int *offset, guint16 *crc) {
    tvbuff_t *next_tvb;
    int len;
    int i;
    guchar *decoded_buffer;
    guint8 b;

    len = tvb_captured_length(tvb);
    if (len <= 0) {
        return tvb;
    }
    decoded_buffer = (guchar*)wmem_alloc(pinfo->pool, len);
    if (decoded_buffer == NULL) {
        return tvb;
    }

    for(i = 0; *offset < len; ) {
        b = tvb_get_guint8(tvb, *offset);
        *offset = *offset + 1;
        if (b == S101_CE) {
            // Escaped Byte
            b = tvb_get_guint8(tvb, *offset);
            *offset = *offset + 1;
            b = (b ^ S101_XOR);
            decoded_buffer[i++] = b;
        }
        else {
            decoded_buffer[i] = b;
            if (b == S101_EOF) { // End of Frame
                // let's remove the CRC and the EOF
                if (i > 2) {
                    i -= 2;
                }
                break;
            }
            i++;
        }
        *crc = crc16_ccitt_seed(&b, 1, *crc) ^ 0xFFFF;
    }

    next_tvb = tvb_new_child_real_data(tvb, decoded_buffer, i, i);
    add_new_data_source(pinfo, next_tvb, "Decoded Data");
    return next_tvb;
}



/* Code to actually dissect the packets */
static int
dissect_S101(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *S101_tree;
    tvbuff_t     *tvb_payload;
    /* Other misc. local variables. */
    int         offset = 0;
    int         parsedLen = 0;
    int         len    = 0;
    int         current_offset;
    int         datalen = 0;
    guint16 crc_data;
    guint64 msgLength = 0;
    guint16 crc;
    guint8 start, slot, message, version, dtd, command, flags = 0xFF, app_bytes[APP_BYTES_LEN];

    /* Check that the packet is long enough for it to belong to us. */
    len = tvb_reported_length(tvb);
    if (len < S101_MIN_LENGTH)
        return 0;

    current_offset = 0;
    do {
        offset = current_offset;
        crc = 0xFFFF;
        if (0 == find_s101_packet_header(tvb, &offset, &start, &slot, &message, &version, &dtd,  &command, &flags, &app_bytes[0], &msgLength, &crc)) {
            break;
        }
        if (0 == current_offset) {
            /* Set the Protocol column to the constant string of S101 */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "S101");
        }

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_S101, tvb, current_offset, -1, ENC_NA);

        S101_tree = proto_item_add_subtree(ti, ett_S101);
        proto_tree_add_item(S101_tree, hf_S101_frame_format, tvb, current_offset++, 1, ENC_BIG_ENDIAN);

        if (msgLength != 0) {
            // Variant 2, the header contains a frame length
            int lengthSize = (int)(msgLength >> 56) & 0xF;
            proto_tree_add_item(S101_tree, hf_S101_length_size, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(S101_tree, hf_S101_message_length, tvb, current_offset,lengthSize, ENC_NA);
            current_offset += lengthSize;
        }
        proto_tree_add_item(S101_tree, hf_S101_slot, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(S101_tree, hf_S101_message_type, tvb, current_offset++,1, ENC_BIG_ENDIAN);
        proto_tree_add_item(S101_tree, hf_S101_cmd_type, tvb,current_offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(S101_tree, hf_S101_version, tvb, current_offset++, 1, ENC_BIG_ENDIAN);

        if (command == S101_CMD_EMBER) {
            proto_tree_add_item(S101_tree, hf_S101_flags, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(S101_tree, hf_S101_dtd_type, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(S101_tree, hf_S101_app_bytes_len, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(S101_tree, hf_S101_dtd_minor_ver, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(S101_tree, hf_S101_dtd_major_ver, tvb, current_offset++, 1, ENC_BIG_ENDIAN);
        }

        if (msgLength == 0) {
            //Variant 1 - data is encoded with escaped bytes.
            tvb_payload = decode_s101_escaped_buffer(tvb, pinfo, &current_offset, &crc);
            datalen = tvb_captured_length(tvb_payload);
            crc_data = tvb_get_ntohs(tvb, current_offset - 3);
            proto_tree_add_checksum(S101_tree, tvb, current_offset - 3, hf_S101_crc, hf_S101_crc_status, NULL,
                                    pinfo, crc == S101_VALID_CRC ? crc_data : crc ^ crc_data, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
            proto_tree_add_item(S101_tree, hf_S101_eof, tvb, current_offset - 1, 1, ENC_BIG_ENDIAN);
        }
        else {
            //variant 2.  Packet size is provided and no encoding
            datalen = (int)(msgLength & 0x0FFFFFFF) - S101_HEADER_DATA_LENGTH;
            tvb_payload = tvb_new_subset_length(tvb, current_offset, datalen);
            current_offset += datalen;
        }

        proto_item_set_len(ti, current_offset - offset);

        if (command == S101_CMD_EMBER) {
            if (flags != FLAG_SINGLE_PACKET) {
                fragment_head *frag_msg = NULL;
                guint32 id = get_fragment_pdu_id(pinfo);
                s101_fragment_t* fi = (s101_fragment_t*)wmem_map_lookup(s101_fragment_info_hash, &id);
                pinfo->fragmented = TRUE;

                if (flags == FLAG_FIRST_MULTI_PACKET) {
                    if (NULL == fi) {
                        fi = new_fragment_info(pinfo);
                        wmem_map_insert(s101_fragment_info_hash, &id, fi);
                    }
                    else {
                        fi->id = pinfo->num;
                    }
                    fragment_add(&s101_data_reassembly_table, tvb_payload, 0,
                             pinfo, fi->id, NULL,
                             0, datalen,
                             TRUE);
                    fi->offset = datalen;
                }
                else if (flags == FLAG_LAST_MULTI_PACKET) {
                    if (NULL != fi) {
                        // last fragment
                        frag_msg = fragment_add(&s101_data_reassembly_table, tvb_payload, 0,
                                            pinfo, fi->id, NULL,
                                            fi->offset, datalen,
                                            FALSE);
                        tvb_payload = process_reassembled_data(tvb, offset, pinfo,
                                                           "Reassembled Message", frag_msg, &msg_frag_items,
                                                           NULL, S101_tree);
                    }
                    if (frag_msg) { /* Reassembled */
                        col_append_str(pinfo->cinfo, COL_INFO,
                               " (Message Reassembled)");
                    }
                    else {
                        display_expert_info(S101_tree, tvb, pinfo, offset, current_offset - offset);
                    }
                }
                else if (NULL == fi) {
                    display_expert_info(S101_tree, tvb, pinfo, offset, current_offset - offset);
                }
                else if (flags == FLAG_MULTI_PACKET) {
                    fragment_add(&s101_data_reassembly_table, tvb_payload, 0,
                             pinfo, fi->id, NULL,
                             fi->offset, datalen,
                             TRUE);
                    fi->offset += datalen;
                    col_append_fstr(pinfo->cinfo, COL_INFO,
                                " (Message fragment)");
                }
            }

            // Call ASN1 Glow dissector - see epan/dissectors/asn1/glow/ if packet is complete.
            if ((flags == FLAG_LAST_MULTI_PACKET) && (tvb_payload == NULL)) {
                proto_item* pi;
                proto_tree_add_subtree(S101_tree, tvb, offset, current_offset - offset,
                                ett_decoding_error, &pi, "S101 Error");
                expert_add_info(pinfo, pi, &ei_s101_failed_reassembly);
            }
            else if ((glow_handle != NULL) && ((flags == FLAG_LAST_MULTI_PACKET) || (flags == FLAG_SINGLE_PACKET))) {
                parsedLen = call_dissector_only(glow_handle, tvb_payload, pinfo, S101_tree, data);
                if (parsedLen <= 0) {
                    break;
                }
            }
        }
    }while(current_offset < len);
    return current_offset;
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_S101(void)
{
    expert_module_t* expert_s101;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_S101_frame_format,
            { "Frame Format", "s101.format",
               FT_UINT8, BASE_HEX, VALS(frame_format_vs), 0x0, NULL, HFILL }},

        { &hf_S101_length_size,
            { "Bytes for Length", "s101.lensize",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_message_length,
            { "Message Length", "s101.msglen",
              FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_slot,
            { "Slot", "s101.slot",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_message_type,
          { "Message Type", "s101.msgtype",
            FT_UINT8, BASE_HEX, VALS(message_type_vs), 0x0, NULL, HFILL }},

        { &hf_S101_cmd_type,
            { "Command Type", "s101.cmdtype",
              FT_UINT8, BASE_HEX, VALS(command_type_vs), 0x0, NULL, HFILL }},

        { &hf_S101_version,
            { "Version", "s101.version",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_flags,
            { "Flags", "s101.flags",
              FT_UINT8, BASE_HEX, VALS(flags_vs), 0x0, NULL, HFILL }},

        { &hf_S101_dtd_type,
            { "DTD Type", "s101.dtdtype",
              FT_UINT8, BASE_DEC, VALS(dtd_type_vs), 0x0, NULL, HFILL }},

        { &hf_S101_app_bytes_len,
            { "App Bytes Length", "s101.applen",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_dtd_minor_ver,
            { "App Minor Version", "s101.appminver",
               FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_dtd_major_ver,
            { "App Major Version", "s101.appmajver",
              FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_crc,
            { "CRC", "s101.crc",
              FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_crc_status,
          { "Checksum Status", "s101.crc.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL }},

        { &hf_S101_eof,
            { "End of Frane", "s101.eof",
              FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_S101_error, {
                "S101 Error", "s101.error", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL }},

        // fragments info
        {&hf_msg_fragments,
            { "Message fragments", "s101.msg.fragments",
              FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment,
            { "Message fragment", "s101.msg.fragment",
              FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment_overlap,
            { "Message fragment overlap", "s101.msg.fragment.overlap",
              FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "s101.msg.fragment.overlap.conflicts",
              FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment_multiple_tails,
            { "Message has multiple tail fragments", "s101.msg.fragment.multiple_tails",
              FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment_too_long_fragment,
            { "Message fragment too long", "s101.msg.fragment.too_long_fragment",
              FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment_error,
            { "Message defragmentation error", "s101.msg.fragment.error",
              FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_fragment_count,
            { "Message fragment count", "s101.msg.fragment.count",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_reassembled_in,
            { "Reassembled in", "s101.msg.reassembled.in",
              FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_reassembled_length,
            { "Reassembled length", "s101.msg.reassembled.length",
              FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},

        {&hf_msg_reassembled_data,
            { "Reassembled Data", "s101.msg.reassembled.data",
              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_S101,
        &ett_msg_fragment,
        &ett_msg_fragments,
        &ett_decoding_error
    };

    static ei_register_info ei[] = {
        { &ei_s101_failed_reassembly, { "s101.reassembly_error", PI_MALFORMED, PI_WARN, "Reassembly Error", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_S101 = proto_register_protocol("S101",
            "S101", "s101");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_S101, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&s101_data_reassembly_table,
                              &addresses_ports_reassembly_table_functions);

    s101_fragment_info_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                     g_direct_hash, g_direct_equal);

    /* S101_module = prefs_register_protocol(proto_S101, NULL); */

    expert_s101 = expert_register_protocol(proto_S101);
    expert_register_field_array(expert_s101, ei, array_length(ei));
}

void
proto_reg_handoff_S101(void)
{
    static dissector_handle_t S101_handle;

    S101_handle = create_dissector_handle(dissect_S101,
            proto_S101);

    glow_handle = find_dissector_add_dependency("glow", proto_S101);
    dissector_add_uint_with_preference("tcp.port", S101_TCP_PORT, S101_handle);
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
