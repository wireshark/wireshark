/* packet-ssyncp.c
 * Routines for dissecting mosh's State Synchronization Protocol
 * Copyright 2020 Google LLC
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * State Synchronization Protocol is the protocol used by mosh:
 * <https://mosh.org/mosh-paper-draft.pdf>
 *
 * The protocol name is abbreviated as SSyncP to avoid conflict with the
 * "Scripting Service Protocol".
 *
 * The protocol is based on UDP, with a plaintext header followed by an
 * encrypted payload. For now we just support decrypting a single connection at
 * a time, using the MOSH_KEY dumped from the environment variables
 * (`cat /proc/$pid/environ | tr '\0' '\n' | grep MOSH_KEY` on Linux).
 * Note that to display the embedded protobuf properly, you'll have to add
 * src/protobufs/ from mosh's source code to the ProtoBuf search path.
 * For now we stop decoding after reaching the first level of protobufs; in
 * them, a second layer of protobufs is sometimes embedded (e.g. for
 * transmitting screen contents and such). Implementing that is left as an
 * exercise for the reader.
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/report_message.h>
#include <wsutil/wsgcrypt.h>

void proto_reg_handoff_ssyncp(void);
void proto_register_ssyncp(void);

static int proto_ssyncp = -1;
static int hf_ssyncp_direction = -1;
static int hf_ssyncp_seq = -1;
static int hf_ssyncp_encrypted = -1;
static int hf_ssyncp_seq_delta = -1;
static int hf_ssyncp_timestamp = -1;
static int hf_ssyncp_timestamp_reply = -1;
static int hf_ssyncp_frag_seq = -1;
static int hf_ssyncp_frag_final = -1;
static int hf_ssyncp_frag_idx = -1;
static int hf_ssyncp_rtt_to_server = -1;
static int hf_ssyncp_rtt_to_client = -1;

/* Initialize the subtree pointers */
static gint ett_ssyncp = -1;
static gint ett_ssyncp_decrypted = -1;

static expert_field ei_ssyncp_fragmented = EI_INIT;
static expert_field ei_ssyncp_bad_key = EI_INIT;

static const char *pref_ssyncp_key;
static char ssyncp_raw_aes_key[16];
static gboolean have_ssyncp_key;

static dissector_handle_t dissector_protobuf;

typedef struct _ssyncp_conv_info_t {
    /* last sequence numbers per direction */
    guint64 last_seq[2];
    /* for each direction, have we seen any traffic yet? */
    gboolean seen_packet[2];

    guint16 clock_offset[2];
    gboolean clock_seen[2];
} ssyncp_conv_info_t;

typedef struct _ssyncp_packet_info_t {
    gboolean first_packet;
    gint64 seq_delta;
    gboolean have_rtt_estimate;
    gint16 rtt_estimate;
} ssyncp_packet_info_t;

#define SSYNCP_IV_PAD 4
#define SSYNCP_SEQ_LEN 8
#define SSYNCP_DATAGRAM_HEADER_LEN (SSYNCP_SEQ_LEN + 2 + 2) /* 64-bit IV and two 16-bit timestamps */
#define SSYNCP_TRANSPORT_HEADER_LEN (8 + 2)
#define SSYNCP_AUTHTAG_LEN 16 /* 128-bit auth tag */

/*
 * We only match on 60001, which mosh uses for its first connection.
 * If there are more connections in the range 60002-61000, the user will have to
 * mark those as ssyncp traffic manually - we'd have too many false positives
 * otherwise.
 */
#define SSYNCP_UDP_PORT 60001

static int
dissect_ssyncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Check that we have at least a datagram plus an OCB auth tag. */
    if (tvb_reported_length(tvb) < SSYNCP_DATAGRAM_HEADER_LEN + SSYNCP_TRANSPORT_HEADER_LEN + SSYNCP_AUTHTAG_LEN)
        return 0;

    guint64 direction_and_seq = tvb_get_guint64(tvb, 0, ENC_BIG_ENDIAN);
    guint direction = direction_and_seq >> 63;
    guint64 seq = direction_and_seq & ~(1ULL << 63);

    /* Heuristic: The 63-bit sequence number starts from zero and increments
     * from there. Even if you send 1000 packets per second over 10 years, you
     * won't reach 2^35. So check that the sequence number is not outrageously
     * high.
     */
    if (seq > (1ULL << 35))
        return 0;

    /* On the first pass, track the previous sequence numbers per direction,
     * compute deltas between sequence numbers, and save those deltas.
     * On subsequent passes, use the computed deltas.
     */
    ssyncp_packet_info_t *ssyncp_pinfo;
    ssyncp_conv_info_t *ssyncp_info = NULL;
    if (pinfo->fd->visited) {
        ssyncp_pinfo = (ssyncp_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ssyncp, 0);
    } else {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        ssyncp_info = (ssyncp_conv_info_t *)conversation_get_proto_data(conversation, proto_ssyncp);
        if (!ssyncp_info) {
            ssyncp_info = wmem_new(wmem_file_scope(), ssyncp_conv_info_t);
            conversation_add_proto_data(conversation, proto_ssyncp, ssyncp_info);
            ssyncp_info->seen_packet[0] = FALSE;
            ssyncp_info->seen_packet[1] = FALSE;
            ssyncp_info->clock_seen[0] = FALSE;
            ssyncp_info->clock_seen[1] = FALSE;
        }

        ssyncp_pinfo = wmem_new(wmem_file_scope(), ssyncp_packet_info_t);
        ssyncp_pinfo->first_packet = !ssyncp_info->seen_packet[direction];
        if (ssyncp_pinfo->first_packet) {
            ssyncp_info->seen_packet[direction] = TRUE;
        } else {
            ssyncp_pinfo->seq_delta = seq - ssyncp_info->last_seq[direction];
        }
        ssyncp_pinfo->have_rtt_estimate = FALSE;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ssyncp, 0, ssyncp_pinfo);

        ssyncp_info->last_seq[direction] = seq;
    }

    /*** COLUMN DATA ***/

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ssyncp");

    col_clear(pinfo->cinfo, COL_INFO);

    char *direction_str = direction ? "Server->Client" : "Client->Server";
    col_set_str(pinfo->cinfo, COL_INFO, direction_str);

    /*** PROTOCOL TREE ***/

    /* create display subtree for the protocol */
    proto_item *ti = proto_tree_add_item(tree, proto_ssyncp, tvb, 0, -1, ENC_NA);

    proto_tree *ssyncp_tree = proto_item_add_subtree(ti, ett_ssyncp);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    proto_tree_add_item(ssyncp_tree, hf_ssyncp_direction, tvb,
            0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssyncp_tree, hf_ssyncp_seq, tvb,
            0, 8, ENC_BIG_ENDIAN);
#ifdef GCRY_OCB_BLOCK_LEN
    proto_item *encrypted_item =
#endif
       proto_tree_add_item(ssyncp_tree, hf_ssyncp_encrypted,
            tvb, 8, -1, ENC_NA);

    if (!ssyncp_pinfo->first_packet) {
        proto_item *delta_item =
                proto_tree_add_int64(ssyncp_tree, hf_ssyncp_seq_delta, tvb, 0, 0,
                        ssyncp_pinfo->seq_delta);
        proto_item_set_generated(delta_item);
    }

    unsigned char *decrypted = NULL;
    guint decrypted_len = 0;

    /* avoid build failure on ancient libgcrypt without OCB support */
#ifdef GCRY_OCB_BLOCK_LEN
    if (have_ssyncp_key) {
        gcry_error_t gcry_err;

        /* try to decrypt the rest of the packet */
        gcry_cipher_hd_t gcry_hd;
        gcry_err = gcry_cipher_open(&gcry_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OCB, 0);
        if (gcry_err_code(gcry_err)) {
            /* this shouldn't happen (even if the packet is garbage) */
            report_failure("ssyncp: unable to initialize cipher???");
            return tvb_captured_length(tvb);
        }
        gcry_err = gcry_cipher_setkey(gcry_hd, ssyncp_raw_aes_key, sizeof(ssyncp_raw_aes_key));
        if (gcry_err_code(gcry_err)) {
            /* this shouldn't happen (even if the packet is garbage) */
            report_failure("ssyncp: unable to set key???");
            gcry_cipher_close(gcry_hd);
            return tvb_captured_length(tvb);
        }
        char nonce[SSYNCP_IV_PAD + SSYNCP_SEQ_LEN];
        memset(nonce, 0, SSYNCP_IV_PAD);
        tvb_memcpy(tvb, nonce + SSYNCP_IV_PAD, 0, SSYNCP_SEQ_LEN);
        gcry_err = gcry_cipher_setiv(gcry_hd, nonce, sizeof(nonce));
        if (gcry_err_code(gcry_err)) {
            /* this shouldn't happen (even if the packet is garbage) */
            report_failure("ssyncp: unable to set iv???");
            gcry_cipher_close(gcry_hd);
            return tvb_captured_length(tvb);
        }
        decrypted_len = tvb_captured_length(tvb) - SSYNCP_SEQ_LEN - SSYNCP_AUTHTAG_LEN;
        decrypted = (unsigned char *)tvb_memdup(pinfo->pool, tvb,
                    SSYNCP_SEQ_LEN, decrypted_len);
        gcry_cipher_final(gcry_hd);
        gcry_err = gcry_cipher_decrypt(gcry_hd, decrypted, decrypted_len, NULL, 0);
        if (gcry_err_code(gcry_err)) {
            /* this shouldn't happen (even if the packet is garbage) */
            report_failure("ssyncp: unable to decrypt???");
            gcry_cipher_close(gcry_hd);
            return tvb_captured_length(tvb);
        }
        gcry_err = gcry_cipher_checktag(gcry_hd,
            tvb_get_ptr(tvb, SSYNCP_SEQ_LEN+decrypted_len, SSYNCP_AUTHTAG_LEN),
            SSYNCP_AUTHTAG_LEN);
        if (gcry_err_code(gcry_err) && gcry_err_code(gcry_err) != GPG_ERR_CHECKSUM) {
            /* this shouldn't happen (even if the packet is garbage) */
            report_failure("ssyncp: unable to check auth tag???");
            gcry_cipher_close(gcry_hd);
            return tvb_captured_length(tvb);
        }
        if (gcry_err_code(gcry_err)) {
            /* if the tag is wrong, the key was wrong and the decrypted data is useless */
            decrypted = NULL;
            expert_add_info(pinfo, encrypted_item, &ei_ssyncp_bad_key);
        }
        gcry_cipher_close(gcry_hd);
    }
#endif

    if (decrypted) {
        tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, decrypted, decrypted_len, decrypted_len);
        add_new_data_source(pinfo, decrypted_tvb, "Decrypted data");

        if (!pinfo->fd->visited) {
            guint16 our_clock16 = ((guint64)pinfo->abs_ts.secs * 1000 + pinfo->abs_ts.nsecs / 1000000) & 0xffff;
            guint16 sender_ts = tvb_get_guint16(decrypted_tvb, 0, ENC_BIG_ENDIAN);
            guint16 reply_ts = tvb_get_guint16(decrypted_tvb, 2, ENC_BIG_ENDIAN);
            ssyncp_info->clock_offset[direction] = sender_ts - our_clock16;
            ssyncp_info->clock_seen[direction] = TRUE;
            if (reply_ts != 0xffff && ssyncp_info->clock_seen[1-direction]) {
                guint16 projected_send_time_our_clock = reply_ts - ssyncp_info->clock_offset[1-direction];
                ssyncp_pinfo->rtt_estimate = our_clock16 - projected_send_time_our_clock;
                ssyncp_pinfo->have_rtt_estimate = TRUE;
            }
        }

        proto_tree *dec_tree = proto_tree_add_subtree(ssyncp_tree, decrypted_tvb,
                0, -1, ett_ssyncp_decrypted, NULL, "Decrypted data");

        proto_tree_add_item(dec_tree, hf_ssyncp_timestamp, decrypted_tvb,
                0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(dec_tree, hf_ssyncp_timestamp_reply, decrypted_tvb,
                2, 2, ENC_BIG_ENDIAN);

        if (ssyncp_pinfo->have_rtt_estimate) {
            int rtt_id = direction ? hf_ssyncp_rtt_to_server : hf_ssyncp_rtt_to_client;
            proto_item *rtt_item = proto_tree_add_int(dec_tree, rtt_id, decrypted_tvb, 2, 2, ssyncp_pinfo->rtt_estimate);
            proto_item_set_generated(rtt_item);
        }

        proto_tree_add_item(dec_tree, hf_ssyncp_frag_seq, decrypted_tvb,
                4, 8, ENC_BIG_ENDIAN);
        proto_tree_add_item(dec_tree, hf_ssyncp_frag_final, decrypted_tvb,
                12, 2, ENC_BIG_ENDIAN);
        proto_item *frag_idx_item = proto_tree_add_item(dec_tree,
                hf_ssyncp_frag_idx, decrypted_tvb, 12, 2, ENC_BIG_ENDIAN);

        /* TODO actually handle fragmentation; for now just bail out on fragmentation */
        if (tvb_get_guint16(decrypted_tvb, 12, ENC_BIG_ENDIAN) != 0x8000) {
            expert_add_info(pinfo, frag_idx_item, &ei_ssyncp_fragmented);
            return tvb_captured_length(tvb);
        }

        tvbuff_t *inflated_tvb = tvb_child_uncompress(decrypted_tvb, decrypted_tvb, 14, decrypted_len - 14);
        if (inflated_tvb == NULL)
            return tvb_captured_length(tvb);
        add_new_data_source(pinfo, inflated_tvb, "Inflated data");

        if (dissector_protobuf) {
            call_dissector_with_data(dissector_protobuf, inflated_tvb, pinfo,
                    dec_tree, "message,TransportBuffers.Instruction");
        }
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_ssyncp(void)
{
    static const true_false_string direction_name = {
        "Server->Client",
        "Client->Server"
    };

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_ssyncp_direction,
          { "Direction", "ssyncp.direction",
            FT_BOOLEAN, 8, TFS(&direction_name), 0x80,
            "Direction of packet", HFILL }
        },
        { &hf_ssyncp_seq,
          { "Sequence number", "ssyncp.seq",
            FT_UINT64, BASE_HEX, NULL, 0x7fffffffffffffff,
            "Monotonically incrementing packet sequence number", HFILL }
        },
        { &hf_ssyncp_encrypted,
          { "Encrypted data", "ssyncp.enc_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Encrypted RTT estimation fields and Transport Layer payload, encrypted with AES-128-OCB",
            HFILL }
        },
        { &hf_ssyncp_seq_delta,
          { "Sequence number delta", "ssyncp.seq_delta",
            FT_INT64, BASE_DEC, NULL, 0,
            "Delta from last sequence number; 1 is normal, 0 is duplicated packet, <0 is reordering, >1 is reordering or packet loss", HFILL }
        },
        { &hf_ssyncp_timestamp,
          { "Truncated timestamp", "ssyncp.timestamp",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Low 16 bits of sender's time in milliseconds", HFILL }
        },
        { &hf_ssyncp_timestamp_reply,
          { "Last timestamp received", "ssyncp.timestamp_reply",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Low 16 bits of timestamp of last received packet plus time since it was received (for RTT estimation)", HFILL }
        },
        { &hf_ssyncp_frag_seq,
          { "Fragment ID", "ssyncp.frag_seq",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Transport-level sequence number, used for fragment reassembly", HFILL }
        },
        { &hf_ssyncp_frag_final,
          { "Final fragment", "ssyncp.frag_final",
            FT_BOOLEAN, 16, NULL, 0x8000,
            "Is this the last fragment?", HFILL }
        },
        { &hf_ssyncp_frag_idx,
          { "Fragment Index", "ssyncp.frag_idx",
            FT_UINT16, BASE_HEX, NULL, 0x7fff,
            "Index of this fragment in the list of fragments of the transport-level message", HFILL }
        },
        { &hf_ssyncp_rtt_to_server,
          { "RTT estimate to server (in ms)", "ssyncp.rtt_est_to_server",
            FT_INT16, BASE_DEC, NULL, 0,
            "Estimated round trip time from point of capture to server", HFILL }
        },
        { &hf_ssyncp_rtt_to_client,
          { "RTT estimate to client (in ms)", "ssyncp.rtt_est_to_client",
            FT_INT16, BASE_DEC, NULL, 0,
            "Estimated round trip time from point of capture to client", HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ssyncp,
        &ett_ssyncp_decrypted
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_ssyncp_fragmented,
          { "ssyncp.fragmented", PI_REASSEMBLE, PI_WARN,
            "SSYNCP-level fragmentation, dissector can't handle that", EXPFILL }
        },
        { &ei_ssyncp_bad_key,
          { "ssyncp.badkey", PI_DECRYPTION, PI_WARN,
            "Encrypted data could not be decrypted with the provided key", EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_ssyncp = proto_register_protocol("State Synchronization Protocol", "SSyncP", "ssyncp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_ssyncp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_ssyncp = expert_register_protocol(proto_ssyncp);
    expert_register_field_array(expert_ssyncp, ei, array_length(ei));

    module_t *ssyncp_module = prefs_register_protocol(proto_ssyncp, proto_reg_handoff_ssyncp);

    prefs_register_string_preference(ssyncp_module, "key",
        "ssyncp MOSH_KEY",
        "MOSH_KEY AES key (from mosh-{client,server} environment variable)",
        &pref_ssyncp_key);
}

void
proto_reg_handoff_ssyncp(void)
{
    static dissector_handle_t ssyncp_handle;
    static gboolean initialized = FALSE;

    if (!initialized) {
        ssyncp_handle = create_dissector_handle(dissect_ssyncp, proto_ssyncp);
        dissector_add_uint("udp.port", SSYNCP_UDP_PORT, ssyncp_handle);

        dissector_protobuf = find_dissector("protobuf");
        if (dissector_protobuf == NULL) {
            report_failure("unable to find protobuf dissector");
        }

        initialized = TRUE;
    }

    have_ssyncp_key = FALSE;
    if (strlen(pref_ssyncp_key) != 0) {
        if (strlen(pref_ssyncp_key) != 22) {
            report_failure("ssyncp: invalid key, must be 22 characters long");
            return;
        }
        char base64_key[25];
        memcpy(base64_key, pref_ssyncp_key, 22);
        memcpy(base64_key+22, "==\0", 3);
        gsize out_len;
        if (g_base64_decode_inplace(base64_key, &out_len) == NULL || out_len != sizeof(ssyncp_raw_aes_key)) {
            report_failure("ssyncp: invalid key, base64 decoding (with \"==\" appended) failed");
            return;
        }
        memcpy(ssyncp_raw_aes_key, base64_key, sizeof(ssyncp_raw_aes_key));
        have_ssyncp_key = TRUE;
    }
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
