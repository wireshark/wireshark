/* packet-ipfs.c
 * Routines for IPFS / libp2p dissection: multistream-select negotiation,
 * libp2p Noise record framing and IPFS HTTP RPC requests.
 *
 * No cryptographic decryption is implemented here. TLS/WebSocket processing
 * is performed by Wireshark before the ws heuristic is invoked.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-http.h>


/*
 * Bounded framing. All reads go through the tvb accessors and are limited
 * to the captured bytes, so a short buffer yields IPFS_MORE, never an
 * exception.
 */

typedef enum
{
    IPFS_MULTISTREAM,
    IPFS_NOISE
} ipfs_phase;

typedef enum
{
    IPFS_OK,
    IPFS_MORE,
    IPFS_BAD
} ipfs_result;

typedef struct
{
    unsigned header;
    uint32_t length;
} ipfs_frame;

#define IPFS_MAX_TOKEN 4096U

static ipfs_result
ipfs_parse_frame(
    tvbuff_t *tvb,
    unsigned offset,
    ipfs_phase phase,
    ipfs_frame *f)
{
    unsigned n = tvb_captured_length_remaining(tvb, offset);

    f->header = 0;
    f->length = 0;

    if (phase == IPFS_NOISE) {
        if (n < 2) {
            return IPFS_MORE;
        }

        f->header = 2;
        f->length = tvb_get_ntohs(tvb, offset);

        if (!f->length) {
            return IPFS_BAD;
        }
    } else {
        uint32_t length = 0;
        uint8_t b = 0;
        unsigned i;

        /* Unsigned varint, at most two bytes (IPFS_MAX_TOKEN < 2^14). */
        for (i = 0; i < 2; i++) {
            if (i >= n) {
                return IPFS_MORE;
            }

            b = tvb_get_uint8(tvb, offset + i);
            length |= (uint32_t)(b & 0x7f) << (7 * i);

            if (!(b & 0x80)) {
                break;
            }
        }

        /* i == 2: varint too long; i == 1 && !b: non-minimal encoding. */
        if (i == 2 ||
            !length ||
            length > IPFS_MAX_TOKEN ||
            (i && !(b & 0x7f))) {
            return IPFS_BAD;
        }

        f->header = i + 1;
        f->length = length;
    }

    if (n - f->header < f->length) {
        return IPFS_MORE;
    }

    if (phase == IPFS_MULTISTREAM) {
        unsigned s = offset + f->header;
        uint8_t c;

        if (tvb_get_uint8(tvb, s + f->length - 1) != '\n') {
            return IPFS_BAD;
        }

        for (uint32_t i = 0; i + 1 < f->length; i++) {
            c = tvb_get_uint8(tvb, s + i);

            if (c < 0x20 || c > 0x7e) {
                return IPFS_BAD;
            }
        }

        c = tvb_get_uint8(tvb, s);

        if (c != '/' &&
            !(f->length == 3 &&
                ((c == 'n' && tvb_get_uint8(tvb, s + 1) == 'a') ||
                    (c == 'l' && tvb_get_uint8(tvb, s + 1) == 's')))) {
            return IPFS_BAD;
        }
    }

    return IPFS_OK;
}


void proto_register_ipfs(void);
void proto_reg_handoff_ipfs(void);

static int proto_ipfs;

static int hf_transport;
static int hf_token;
static int hf_length;
static int hf_noise_length;
static int hf_noise_data;
static int hf_noise_confirmed;
static int hf_command;
static int hf_argument;
static int hf_query;
static int hf_uri;
static int hf_status;
static int hf_candidate;
static int hf_evidence;
static int hf_opaque;

static int ett_ipfs;

static expert_field ei_bad = EI_INIT;
static expert_field ei_partial = EI_INIT;
static expert_field ei_opaque = EI_INIT;

static dissector_handle_t ipfs_tcp_handle;
static dissector_handle_t ipfs_ws_handle;

static bool pref_candidates = false;

static unsigned pref_peer_port = 4001;
static unsigned pref_api_port = 5001;

static int http_uri_id = -1;
static int http_status_id = -1;
static int tcp_len_id = -1;

typedef struct
{
    address origin;
    uint32_t origin_port;
    uint32_t first_frame;
    bool offered[2];
    ipfs_phase phase;
} ipfs_conversation;

typedef struct
{
    bool offered[2];
    ipfs_phase phase;
} ipfs_snapshot;

static ipfs_conversation *
ipfs_get_conversation(packet_info *pinfo, bool create)
{
    conversation_t *conv;
    ipfs_conversation *s;

    conv = find_or_create_conversation(pinfo);
    s = (ipfs_conversation *)conversation_get_proto_data(conv, proto_ipfs);

    if (!s && create) {
        s = wmem_new0(wmem_file_scope(), ipfs_conversation);

        copy_address_wmem(wmem_file_scope(), &s->origin, &pinfo->src);

        s->origin_port = pinfo->srcport;
        s->first_frame = pinfo->num;

        conversation_add_proto_data(conv, proto_ipfs, s);
    }

    return s;
}

static bool
ipfs_is_hello(tvbuff_t *tvb)
{
    static const uint8_t hello[] = {
        19, '/', 'm', 'u', 'l', 't', 'i', 's', 't', 'r', 'e', 'a',
        'm', '/', '1', '.', '0', '.', '0', '\n'
    };

    return tvb_captured_length(tvb) >= sizeof(hello) &&
        tvb_memeql(tvb, 0, hello, sizeof(hello)) == 0;
}

static int
dissect_ipfs_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool tcp)
{
    ipfs_conversation *s;
    ipfs_snapshot *saved;
    ipfs_snapshot local;
    unsigned dir;
    unsigned offset;
    unsigned captured;
    uint32_t key;

    s = ipfs_get_conversation(pinfo, true);

    dir = (addresses_equal(&s->origin, &pinfo->src) &&
        s->origin_port == pinfo->srcport) ? 0 : 1;

    /*
     * A snapshot per protocol layer makes redissection independent of the
     * conversation's final state, including several WebSocket PDUs per frame.
     */
    key = 0x10000U + pinfo->curr_layer_num;

    saved = (ipfs_snapshot *)p_get_proto_data(
        wmem_file_scope(), pinfo, proto_ipfs, key);

    if (!saved) {
        saved = wmem_new(wmem_file_scope(), ipfs_snapshot);

        saved->phase = s->phase;
        saved->offered[0] = s->offered[0];
        saved->offered[1] = s->offered[1];

        p_add_proto_data(wmem_file_scope(), pinfo, proto_ipfs, key, saved);
    }

    local = *saved;

    offset = 0;
    captured = tvb_captured_length(tvb);

    while (offset < captured) {
        unsigned remain;
        unsigned size;
        ipfs_frame f;
        ipfs_result result;
        proto_item *ti;
        proto_tree *sub;

        remain = captured - offset;

        result = ipfs_parse_frame(tvb, offset, local.phase, &f);

        /*
         * With only one decrypted direction, the peer's selection echo can
         * be missing. Require an observed /noise token and a complete, short
         * Noise record before inferring the transition; expose that uncertainty.
         */
        if (result == IPFS_BAD &&
            local.phase == IPFS_MULTISTREAM &&
            local.offered[dir] &&
            tvb_get_uint8(tvb, offset) == 0) {
            ipfs_frame candidate;
            ipfs_result candidate_result;

            candidate_result = ipfs_parse_frame(
                tvb, offset, IPFS_NOISE, &candidate);

            if (candidate_result == IPFS_MORE &&
                (!candidate.header || candidate.length >= 16) &&
                tcp &&
                pinfo->can_desegment &&
                tvb_captured_length(tvb) == tvb_reported_length(tvb)) {
                pinfo->desegment_offset = offset;

                pinfo->desegment_len = candidate.header ?
                    candidate.header + candidate.length - remain :
                    DESEGMENT_ONE_MORE_SEGMENT;

                /*
                 * Do not promote the conversation until a full record arrives.
                 */
                break;
            }

            if (candidate_result == IPFS_OK && candidate.length >= 16) {
                local.phase = IPFS_NOISE;
                f = candidate;
                result = IPFS_OK;
            }
        }

        if (result == IPFS_MORE &&
            tcp &&
            pinfo->can_desegment &&
            tvb_captured_length(tvb) == tvb_reported_length(tvb)) {
            pinfo->desegment_offset = offset;

            pinfo->desegment_len = f.header ?
                f.header + f.length - remain :
                DESEGMENT_ONE_MORE_SEGMENT;

            break;
        }

        size = result == IPFS_OK ?
            f.header + f.length : remain;

        ti = proto_tree_add_item(
            tree, proto_ipfs, tvb, offset, size, ENC_NA);

        sub = proto_item_add_subtree(ti, ett_ipfs);

        proto_item_set_generated(
            proto_tree_add_string(
                sub, hf_transport, tvb, 0, 0, tcp ? "TCP" : "WebSocket"));

        proto_item_set_generated(
            proto_tree_add_string(
                sub,
                hf_evidence,
                tvb,
                0,
                0,
                "libp2p negotiation (not unique to IPFS)"));

        if (result != IPFS_OK) {
            proto_tree_add_item(sub, hf_opaque, tvb, offset, remain, ENC_NA);

            expert_add_info_format(
                pinfo,
                ti,
                result == IPFS_MORE ? &ei_partial : &ei_bad,
                "%s %s frame; payload left opaque",
                result == IPFS_MORE ? "Incomplete" : "Invalid or unsupported",
                local.phase == IPFS_NOISE ? "Noise" : "multistream");

            break;
        }

        if (local.phase == IPFS_MULTISTREAM) {
            const char *token;

            token = (const char *)tvb_get_string_enc(
                pinfo->pool,
                tvb,
                offset + f.header,
                f.length - 1,
                ENC_ASCII);

            proto_tree_add_uint(
                sub, hf_length, tvb, offset, f.header, f.length);

            proto_tree_add_string(
                sub, hf_token, tvb, offset + f.header, f.length, token);

            proto_item_append_text(ti, ": multistream %s", token);

            col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPFS/libp2p");

            col_append_sep_fstr(
                pinfo->cinfo, COL_INFO, " | ", "%s", token);

            if (strcmp(token, "/noise") == 0) {
                local.offered[dir] = true;
            } else if (strcmp(token, "na") == 0) {
                local.offered[1 - dir] = false;
            } else if (token[0] == '/' &&
                strcmp(token, "/multistream/1.0.0") != 0) {
                local.offered[dir] = false;
            }

            if (local.offered[0] && local.offered[1]) {
                local.phase = IPFS_NOISE;
            }
        } else {
            proto_item_set_generated(
                proto_tree_add_boolean(
                    sub,
                    hf_noise_confirmed,
                    tvb,
                    0,
                    0,
                    local.offered[0] && local.offered[1]));

            proto_tree_add_item(
                sub, hf_noise_length, tvb, offset, 2, ENC_BIG_ENDIAN);

            proto_tree_add_item(
                sub, hf_noise_data, tvb, offset + 2, f.length, ENC_NA);

            proto_item_append_text(
                ti, ": Noise record (%u bytes)", f.length);

            col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPFS/libp2p");

            col_append_sep_fstr(
                pinfo->cinfo,
                COL_INFO,
                " | ",
                "Noise record: %u bytes",
                f.length);
        }

        offset += size;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        s->phase = local.phase;
        s->offered[0] = local.offered[0];
        s->offered[1] = local.offered[1];
    }

    return captured;
}

static int
dissect_ipfs_tcp(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    return dissect_ipfs_stream(tvb, pinfo, tree, true);
}

static int
dissect_ipfs_ws(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    return dissect_ipfs_stream(tvb, pinfo, tree, false);
}

static bool
dissect_ipfs_heur_tcp(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    if (!ipfs_is_hello(tvb)) {
        return false;
    }

    conversation_set_dissector(
        find_or_create_conversation(pinfo), ipfs_tcp_handle);

    call_dissector(ipfs_tcp_handle, tvb, pinfo, tree);

    return true;
}

static bool
dissect_ipfs_heur_ws(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    ipfs_conversation *s;

    s = ipfs_get_conversation(pinfo, false);

    if (!ipfs_is_hello(tvb) && (!s || pinfo->num < s->first_frame)) {
        return false;
    }

    call_dissector(ipfs_ws_handle, tvb, pinfo, tree);

    return true;
}

/*
 * Query values are display strings. Keep %00 escaped to avoid silent
 * truncation.
 */
static char *
ipfs_decode_query(wmem_allocator_t *pool, const char *src, size_t n)
{
    char *out;
    size_t j;
    size_t i;

    out = (char *)wmem_alloc(pool, n + 1);
    j = 0;

    for (i = 0; i < n; i++) {
        if (src[i] == '%' &&
            i + 2 < n &&
            g_ascii_isxdigit(src[i + 1]) &&
            g_ascii_isxdigit(src[i + 2])) {
            int v;

            v = g_ascii_xdigit_value(src[i + 1]) * 16 +
                g_ascii_xdigit_value(src[i + 2]);

            if (v) {
                out[j++] = (char)v;
                i += 2;
                continue;
            }
        }

        out[j++] = src[i] == '+' ? ' ' : src[i];
    }

    out[j] = 0;

    return out;
}

typedef struct
{
    unsigned count;
    char **uris;
    uint32_t status;
    bool candidate;
} rpc_snapshot;

static int
dissect_ipfs_rpc_post(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    rpc_snapshot *rpc;

    rpc = (rpc_snapshot *)p_get_proto_data(
        wmem_file_scope(), pinfo, proto_ipfs, 0x20000U);

    if (!rpc && !PINFO_FD_VISITED(pinfo)) {
        GPtrArray *uris;
        unsigned count;
        bool candidate;

        uris = http_uri_id < 0 ?
            NULL : proto_get_finfo_ptr_array(tree, http_uri_id);

        count = 0;

        for (unsigned i = 0; uris && i < uris->len; i++) {
            field_info *fi;
            const char *uri;

            fi = (field_info *)g_ptr_array_index(uris, i);
            uri = fvalue_get_string(fi->value);

            if (uri && strncmp(uri, "/api/v0/", 8) == 0) {
                count++;
            }
        }

        candidate = false;

        if (!count &&
            pref_candidates &&
            pinfo->ptype == PT_TCP &&
            (pinfo->srcport == pref_peer_port ||
                pinfo->destport == pref_peer_port) &&
            !ipfs_get_conversation(pinfo, false)) {
            GPtrArray *lens;

            lens = tcp_len_id < 0 ?
                NULL : proto_get_finfo_ptr_array(tree, tcp_len_id);

            candidate = lens &&
                lens->len &&
                fvalue_get_uinteger(
                    ((field_info *)g_ptr_array_index(lens, 0))->value) > 0;
        }

        if (count || candidate) {
            unsigned at;
            GPtrArray *statuses;

            rpc = wmem_new0(wmem_file_scope(), rpc_snapshot);

            rpc->count = count;
            rpc->candidate = candidate;

            if (count) {
                rpc->uris = wmem_alloc_array(
                    wmem_file_scope(), char *, count);
            }

            at = 0;

            for (unsigned i = 0; uris && i < uris->len; i++) {
                field_info *fi;
                const char *uri;

                fi = (field_info *)g_ptr_array_index(uris, i);
                uri = fvalue_get_string(fi->value);

                if (uri && strncmp(uri, "/api/v0/", 8) == 0) {
                    rpc->uris[at++] = wmem_strdup(wmem_file_scope(), uri);
                }
            }

            statuses = http_status_id < 0 ?
                NULL : proto_get_finfo_ptr_array(tree, http_status_id);

            if (uris && uris->len == 1 &&
                statuses && statuses->len == 1) {
                field_info *status;

                status = (field_info *)g_ptr_array_index(statuses, 0);
                rpc->status = fvalue_get_uinteger(status->value);
            }

            p_add_proto_data(
                wmem_file_scope(), pinfo, proto_ipfs, 0x20000U, rpc);
        }
    }

    /*
     * Postdissectors run on every frame. Returning non-zero adds "ipfs"
     * to the frame's protocol layers, so only claim frames where we
     * actually found IPFS evidence.
     */
    if (!rpc) {
        return 0;
    }

    for (unsigned i = 0; i < rpc->count; i++) {
        const char *uri;
        const char *q;
        size_t command_len;
        proto_item *ti;
        proto_tree *sub;
        char *command;

        uri = rpc->uris[i];
        q = strchr(uri, '?');

        command_len = q ?
            (size_t)(q - uri - 8) : strlen(uri + 8);

        ti = proto_tree_add_item(tree, proto_ipfs, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(ti);

        sub = proto_item_add_subtree(ti, ett_ipfs);

        proto_tree_add_string(
            sub, hf_transport, tvb, 0, 0, "HTTP RPC");

        proto_tree_add_string(
            sub,
            hf_evidence,
            tvb,
            0,
            0,
            "IPFS-compatible /api/v0/ endpoint");

        proto_tree_add_string(sub, hf_uri, tvb, 0, 0, uri);

        command = wmem_strndup(pinfo->pool, uri + 8, command_len);

        proto_tree_add_string(sub, hf_command, tvb, 0, 0, command);

        proto_item_append_text(ti, ": HTTP API %s", command);

        if (q) {
            const char *p;

            proto_tree_add_string(sub, hf_query, tvb, 0, 0, q + 1);

            p = q + 1;

            while (*p) {
                const char *end;
                const char *eq;

                end = strchr(p, '&');

                if (!end) {
                    end = p + strlen(p);
                }

                eq = (const char *)memchr(p, '=', end - p);

                if (eq) {
                    char *name;

                    name = ipfs_decode_query(pinfo->pool, p, eq - p);

                    if (strcmp(name, "arg") == 0) {
                        proto_tree_add_string(
                            sub,
                            hf_argument,
                            tvb,
                            0,
                            0,
                            ipfs_decode_query(pinfo->pool, eq + 1, end - eq - 1));
                    }
                }

                p = *end ? end + 1 : end;
            }
        }

        if (rpc->status) {
            proto_tree_add_uint(
                sub, hf_status, tvb, 0, 0, rpc->status);
        }
    }

    if (rpc->candidate) {
        proto_item *ti;
        proto_tree *sub;

        ti = proto_tree_add_item(tree, proto_ipfs, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(ti);

        sub = proto_item_add_subtree(ti, ett_ipfs);

        proto_tree_add_boolean(
            sub, hf_candidate, tvb, 0, 0, true);

        proto_tree_add_string(
            sub,
            hf_evidence,
            tvb,
            0,
            0,
            "Port only; protocol and encryption unconfirmed");

        expert_add_info(pinfo, ti, &ei_opaque);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ipfs(void)
{
    static hf_register_info hf[] = {
        {
            &hf_transport,
            {
                "Transport",
                "ipfs.transport",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_evidence,
            {
                "Identification evidence",
                "ipfs.evidence",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_token,
            {
                "Protocol / control token",
                "ipfs.multistream.token",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_length,
            {
                "Token length (includes newline)",
                "ipfs.multistream.length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_noise_length,
            {
                "Noise record length",
                "ipfs.noise.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_noise_confirmed,
            {
                "Both Noise negotiation directions observed",
                "ipfs.noise.negotiation_complete",
                FT_BOOLEAN,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_noise_data,
            {
                "Noise handshake or encrypted payload",
                "ipfs.noise.payload",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_opaque,
            {
                "Undecoded bytes",
                "ipfs.opaque",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_uri,
            {
                "RPC URI",
                "ipfs.rpc.uri",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_command,
            {
                "RPC command",
                "ipfs.rpc.command",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_argument,
            {
                "RPC argument (URL decoded)",
                "ipfs.rpc.argument",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_query,
            {
                "RPC query (raw)",
                "ipfs.rpc.query",
                FT_STRING,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_status,
            {
                "HTTP response status",
                "ipfs.rpc.status",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0,
                NULL,
                HFILL
            }
        },
        {
            &hf_candidate,
            {
                "Unconfirmed peer-port traffic",
                "ipfs.candidate",
                FT_BOOLEAN,
                BASE_NONE,
                NULL,
                0,
                NULL,
                HFILL
            }
        }
    };

    static int *ett[] = {
        &ett_ipfs
    };

    static ei_register_info ei[] = {
        {
            &ei_bad,
            {
                "ipfs.invalid",
                PI_UNDECODED,
                PI_WARN,
                "Invalid or unsupported framing",
                EXPFILL
            }
        },
        {
            &ei_partial,
            {
                "ipfs.incomplete",
                PI_REASSEMBLE,
                PI_WARN,
                "Incomplete record; no cross-WebSocket-message reassembly",
                EXPFILL
            }
        },
        {
            &ei_opaque,
            {
                "ipfs.unconfirmed",
                PI_UNDECODED,
                PI_NOTE,
                "Peer port match only: protocol and encryption unconfirmed",
                EXPFILL
            }
        }
    };

    module_t *ipfs_prefs;

    proto_ipfs = proto_register_protocol(
        "IPFS / libp2p visible protocols", "IPFS", "ipfs");

    proto_register_field_array(proto_ipfs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(
        expert_register_protocol(proto_ipfs), ei, array_length(ei));

    ipfs_prefs = prefs_register_protocol(
        proto_ipfs, proto_reg_handoff_ipfs);

    prefs_register_bool_preference(
        ipfs_prefs,
        "show_candidates",
        "Show unconfirmed peer-port traffic",
        "Annotate TCP payloads matching peer_port. "
        "This does not prove IPFS or encryption.",
        &pref_candidates);

    prefs_register_uint_preference(
        ipfs_prefs,
        "peer_port",
        "Candidate TCP peer port",
        "Used only for optional candidate annotations",
        10,
        &pref_peer_port);

    prefs_register_uint_preference(
        ipfs_prefs,
        "api_port",
        "HTTP RPC TCP port",
        "Additional port handed to Wireshark HTTP; 0 disables",
        10,
        &pref_api_port);

    ipfs_tcp_handle = register_dissector(
        "ipfs_tcp", dissect_ipfs_tcp, proto_ipfs);

    ipfs_ws_handle = register_dissector(
        "ipfs_ws", dissect_ipfs_ws, proto_ipfs);
}

void
proto_reg_handoff_ipfs(void)
{
    static bool initialized = false;
    static unsigned registered_api = 0;

    if (!initialized) {
        dissector_handle_t post;
        GArray *wanted;

        heur_dissector_add(
            "tcp",
            dissect_ipfs_heur_tcp,
            "IPFS/libp2p multistream over TCP",
            "ipfs_tcp",
            proto_ipfs,
            HEURISTIC_DISABLE);

        heur_dissector_add(
            "ws",
            dissect_ipfs_heur_ws,
            "IPFS/libp2p over WebSocket",
            "ipfs_ws",
            proto_ipfs,
            HEURISTIC_DISABLE);

        dissector_add_for_decode_as("tcp.port", ipfs_tcp_handle);

        dissector_add_string("ws.protocol", "libp2p", ipfs_ws_handle);

        post = create_dissector_handle(dissect_ipfs_rpc_post, proto_ipfs);
        register_postdissector(post);

        http_uri_id = proto_registrar_get_id_byname("http.request.uri");
        http_status_id = proto_registrar_get_id_byname("http.response.code");
        tcp_len_id = proto_registrar_get_id_byname("tcp.len");

        wanted = g_array_new(false, false, sizeof(int));

        if (http_uri_id >= 0) {
            g_array_append_val(wanted, http_uri_id);
        }

        if (http_status_id >= 0) {
            g_array_append_val(wanted, http_status_id);
        }

        if (tcp_len_id >= 0) {
            g_array_append_val(wanted, tcp_len_id);
        }

        set_postdissector_wanted_hfids(post, wanted);

        initialized = true;
    }

    if (registered_api && registered_api != pref_api_port) {
        http_tcp_dissector_delete(registered_api);
    }

    if (pref_api_port &&
        pref_api_port <= 65535 &&
        registered_api != pref_api_port) {
        http_tcp_port_add(pref_api_port);
    }

    registered_api = pref_api_port;
}
