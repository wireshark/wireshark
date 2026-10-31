/* packet-moq-hang.c
 * Routines for Media over QUIC - Hang dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * hang is a conferencing protocol layered on moq-lite:
 * https://datatracker.ietf.org/doc/draft-lcurley-moq-hang/
 *
 * hang has no framing of its own beyond moq-lite. It defines what moq-lite
 * frame payloads contain, which depends on the track:
 *
 *  - catalog.json: one UTF-8 JSON document per group, describing the media
 *    and data tracks of the broadcast, including how each is framed.
 *  - catalog.json.z, timeline.z (draft 03): JSON compressed with one raw
 *    DEFLATE stream per group, sync flushed at each frame boundary.
 *  - media tracks: a container (legacy, cmaf or loc) selected per rendition
 *    by the catalog. Drafts 00 and 01 have no container field; every track
 *    uses what draft 02 calls the legacy container.
 *  - data tracks (draft 03): JSON or opaque binary frames.
 *
 * There is no version number on the wire, so the catalog layout is used to
 * tell the drafts apart:
 *
 *  - draft 00: "video" and "audio" are arrays of {track: {name}, config}.
 *  - draft 01: "video" and "audio" are objects with a "renditions" map.
 *  - draft 02: renditions may carry a "container".
 *  - draft 03: adds "text", "json", "binary", "clock" and "archive".
 *
 * All four layouts are accepted at once, so a capture of any draft decodes
 * without configuration. Track roles are learned from catalog updates on the
 * first pass and remembered with the frame number that introduced them, so
 * a rendition whose container changes mid capture is decoded consistently.
 *
 * Not dissected: the recording format (section 9), which is data at rest,
 * and the LOC property block, which is shown undecoded.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>
#include <wsutil/wsjson.h>

#include "packet-moq-lite.h"

void proto_register_moq_hang(void);
void proto_reg_handoff_moq_hang(void);

static int proto_moq_hang;

static int hf_hang_track_role;
static int hf_hang_catalog_layout;
static int hf_hang_catalog_frame;
static int hf_hang_media_type;
static int hf_hang_container;
static int hf_hang_codec;
static int hf_hang_format;
static int hf_hang_timestamp;
static int hf_hang_time;
static int hf_hang_marker;
static int hf_hang_payload;
static int hf_hang_text;
static int hf_hang_compressed_len;
static int hf_hang_decompressed_len;

static int ett_hang;
static int ett_hang_decompressed;

static expert_field ei_hang_no_catalog;
static expert_field ei_hang_bad_catalog;
static expert_field ei_hang_unknown_container;
static expert_field ei_hang_decompress_failed;
static expert_field ei_hang_malformed;
static expert_field ei_hang_undecoded;

static dissector_handle_t json_handle;
static dissector_handle_t xml_handle;
static dissector_handle_t opus_handle;
static dissector_handle_t mp4_handle;

/* Preferences */
static bool hang_decode_all_broadcasts;
static bool hang_assume_legacy = true;

/* Track names fixed by the specification. */
#define HANG_CATALOG_TRACK          "catalog.json"
#define HANG_CATALOG_Z_TRACK        "catalog.json.z"
#define HANG_TIMELINE_TRACK_DEFAULT "timeline.z"
#define HANG_BROADCAST_SUFFIX       ".hang"

/* Cap on the JSON tokens of a catalog; real catalogs are far smaller. */
#define HANG_MAX_JSON_TOKENS        4096

typedef enum {
    HANG_ROLE_UNKNOWN,
    HANG_ROLE_CATALOG,
    HANG_ROLE_CATALOG_Z,
    HANG_ROLE_TIMELINE,
    HANG_ROLE_MEDIA,
    HANG_ROLE_DATA_JSON,
    HANG_ROLE_DATA_BINARY,
} hang_role_t;

static const value_string hang_role_vals[] = {
    { HANG_ROLE_UNKNOWN,     "Unknown (not in any catalog seen)" },
    { HANG_ROLE_CATALOG,     "Catalog" },
    { HANG_ROLE_CATALOG_Z,   "Catalog (DEFLATE)" },
    { HANG_ROLE_TIMELINE,    "Timeline (DEFLATE)" },
    { HANG_ROLE_MEDIA,       "Media" },
    { HANG_ROLE_DATA_JSON,   "JSON data" },
    { HANG_ROLE_DATA_BINARY, "Binary data" },
    { 0, NULL }
};

typedef enum {
    HANG_MEDIA_NONE,
    HANG_MEDIA_VIDEO,
    HANG_MEDIA_AUDIO,
    HANG_MEDIA_TEXT,
} hang_media_t;

static const value_string hang_media_vals[] = {
    { HANG_MEDIA_NONE,  "None" },
    { HANG_MEDIA_VIDEO, "Video" },
    { HANG_MEDIA_AUDIO, "Audio" },
    { HANG_MEDIA_TEXT,  "Text" },
    { 0, NULL }
};

typedef enum {
    HANG_CONTAINER_LEGACY,
    HANG_CONTAINER_CMAF,
    HANG_CONTAINER_LOC,
    HANG_CONTAINER_UNKNOWN,
} hang_container_t;

static const value_string hang_container_vals[] = {
    { HANG_CONTAINER_LEGACY,  "legacy" },
    { HANG_CONTAINER_CMAF,    "cmaf" },
    { HANG_CONTAINER_LOC,     "loc" },
    { HANG_CONTAINER_UNKNOWN, "unknown" },
    { 0, NULL }
};

typedef enum {
    HANG_LAYOUT_UNKNOWN,
    HANG_LAYOUT_00,
    HANG_LAYOUT_01,
    HANG_LAYOUT_02,
    HANG_LAYOUT_03,
} hang_layout_t;

static const value_string hang_layout_vals[] = {
    { HANG_LAYOUT_UNKNOWN, "Unknown" },
    { HANG_LAYOUT_00,      "draft-00 (track arrays)" },
    { HANG_LAYOUT_01,      "draft-01 (renditions, no container)" },
    { HANG_LAYOUT_02,      "draft-02 (renditions with container)" },
    { HANG_LAYOUT_03,      "draft-03 (text, data tracks, clock, archive)" },
    { 0, NULL }
};

/* What a track carried, as of a catalog update. */
typedef struct _hang_track_def {
    uint32_t          frame_num;    /* Frame of the catalog update. */
    hang_role_t       role;
    hang_media_t      media;
    hang_container_t  container;
    hang_layout_t     layout;
    bool              compressed;   /* Data tracks: "compression": "deflate". */
    const char       *codec;        /* Media: WebCodecs codec string. */
    const char       *format;       /* Text: vtt, ttml, utf8, ... */
} hang_track_def_t;

/* Per broadcast state, shared by every connection in the capture. */
typedef struct _hang_broadcast {
    /* Track name -> wmem_list_t of hang_track_def_t, in frame order. */
    wmem_map_t *tracks;
} hang_broadcast_t;

/*
 * A DEFLATE compressed group. Frames are only decodable with the preceding
 * frames of the group as history, so their compressed bytes are kept and the
 * prefix up to the frame is inflated whenever the frame is dissected.
 */
typedef struct _hang_zframe {
    uint32_t comp_start;    /* Start of this frame in the group buffer. */
    uint32_t comp_end;      /* End of this frame in the group buffer. */
    uint32_t plain_start;   /* Start of this frame's output; set lazily. */
    bool     plain_known;
} hang_zframe_t;

typedef struct _hang_zgroup {
    wmem_array_t *comp;     /* Compressed bytes, with sync flush trailers. */
    wmem_map_t   *frames;   /* moq-lite frame offset -> hang_zframe_t */
} hang_zgroup_t;

/* Broadcast path -> hang_broadcast_t */
static wmem_map_t *hang_broadcasts;
/* moq-lite group key -> hang_zgroup_t */
static wmem_map_t *hang_zgroups;

static const uint8_t hang_sync_flush[] = { 0x00, 0x00, 0xff, 0xff };

static void
hang_init(void)
{
    hang_broadcasts = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
    hang_zgroups = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
}

static hang_broadcast_t *
hang_broadcast_lookup(const char *path, bool create)
{
    hang_broadcast_t *bc = (hang_broadcast_t *)wmem_map_lookup(hang_broadcasts, path);

    if (bc == NULL && create) {
        bc = wmem_new0(wmem_file_scope(), hang_broadcast_t);
        bc->tracks = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
        wmem_map_insert(hang_broadcasts, wmem_strdup(wmem_file_scope(), path), bc);
    }
    return bc;
}

static void
hang_track_def_add(hang_broadcast_t *bc, const char *name, const hang_track_def_t *def)
{
    wmem_list_t *history = (wmem_list_t *)wmem_map_lookup(bc->tracks, name);

    if (history == NULL) {
        history = wmem_list_new(wmem_file_scope());
        wmem_map_insert(bc->tracks, wmem_strdup(wmem_file_scope(), name), history);
    }
    hang_track_def_t *copy = wmem_new(wmem_file_scope(), hang_track_def_t);
    *copy = *def;
    wmem_list_append(history, copy);
}

/* The definition of a track in effect at a frame, or NULL. */
static const hang_track_def_t *
hang_track_def_lookup(const char *path, const char *name, uint32_t frame_num)
{
    hang_broadcast_t *bc = hang_broadcast_lookup(path, false);
    const hang_track_def_t *found = NULL;

    if (bc == NULL) {
        return NULL;
    }
    wmem_list_t *history = (wmem_list_t *)wmem_map_lookup(bc->tracks, name);
    if (history == NULL) {
        return NULL;
    }
    for (wmem_list_frame_t *f = wmem_list_head(history); f != NULL; f = wmem_list_frame_next(f)) {
        const hang_track_def_t *def = (const hang_track_def_t *)wmem_list_frame_data(f);
        if (def->frame_num > frame_num) {
            break;
        }
        found = def;
    }
    return found;
}

/* ------------------------------------------------------------------------- */
/* Catalog parsing                                                           */
/* ------------------------------------------------------------------------- */

static char *
hang_json_strdup(const char *buf, const jsmntok_t *tok)
{
    return wmem_strndup(wmem_file_scope(), buf + tok->start, (size_t)(tok->end - tok->start));
}

/* json_get_string() decodes in place, so work on a scratch copy of the value. */
static const char *
hang_json_get_string(char *buf, jsmntok_t *obj, const char *key)
{
    char *value = json_get_string(buf, obj, key);
    return value != NULL ? wmem_strdup(wmem_file_scope(), value) : NULL;
}

static hang_container_t
hang_parse_container(char *buf, jsmntok_t *rendition, bool *present)
{
    jsmntok_t *container = json_get_object(buf, rendition, "container");
    const char *kind;

    *present = container != NULL;
    if (container == NULL) {
        return HANG_CONTAINER_LEGACY;   /* Default, and drafts 00/01. */
    }
    kind = json_get_string(buf, container, "kind");
    if (kind == NULL) {
        return HANG_CONTAINER_LEGACY;
    }
    if (strcmp(kind, "legacy") == 0) {
        return HANG_CONTAINER_LEGACY;
    }
    if (strcmp(kind, "cmaf") == 0) {
        return HANG_CONTAINER_CMAF;
    }
    if (strcmp(kind, "loc") == 0) {
        return HANG_CONTAINER_LOC;
    }
    return HANG_CONTAINER_UNKNOWN;
}

/*
 * Iterate over the members of a JSON object: calls fn(key, value) for each.
 * jsmn stores the tree flattened, so json_get_next_object() is used to skip
 * over each value to reach the following key.
 */
typedef void (*hang_member_fn)(char *buf, jsmntok_t *key, jsmntok_t *value, void *ctx);

static void
hang_json_foreach(char *buf, jsmntok_t *obj, hang_member_fn fn, void *ctx)
{
    if (obj == NULL || obj->type != JSMN_OBJECT) {
        return;
    }
    jsmntok_t *key = obj + 1;
    for (int i = 0; i < obj->size; i++) {
        jsmntok_t *value = key + 1;
        fn(buf, key, value, ctx);
        key = json_get_next_object(value);
    }
}

typedef struct {
    hang_broadcast_t *bc;
    uint32_t          frame_num;
    hang_layout_t     layout;
    hang_media_t      media;
    hang_role_t       role;
    bool              container_seen;
} hang_catalog_ctx_t;

static void
hang_add_rendition(char *buf, jsmntok_t *key, jsmntok_t *value, void *data)
{
    hang_catalog_ctx_t *ctx = (hang_catalog_ctx_t *)data;
    hang_track_def_t def = { 0 };
    bool present;

    if (value->type != JSMN_OBJECT) {
        return;
    }
    char *name = hang_json_strdup(buf, key);

    def.frame_num = ctx->frame_num;
    def.role = ctx->role;
    def.media = ctx->media;
    def.layout = ctx->layout;

    if (ctx->role == HANG_ROLE_MEDIA) {
        def.container = hang_parse_container(buf, value, &present);
        ctx->container_seen |= present;
        def.codec = hang_json_get_string(buf, value, "codec");
        def.format = hang_json_get_string(buf, value, "format");
    } else {
        const char *mode = json_get_string(buf, value, "compression");
        def.compressed = mode != NULL && strcmp(mode, "deflate") == 0;
    }
    hang_track_def_add(ctx->bc, name, &def);
}

/* Draft 00: {"video": [{"track": {"name": ...}, "config": {...}}]} */
static void
hang_parse_track_array(char *buf, jsmntok_t *array, hang_catalog_ctx_t *ctx)
{
    int len = json_get_array_len(array);

    for (int i = 0; i < len; i++) {
        jsmntok_t *entry = json_get_array_index(array, i);
        jsmntok_t *track, *config;
        hang_track_def_t def = { 0 };

        if (entry == NULL || entry->type != JSMN_OBJECT) {
            continue;
        }
        track = json_get_object(buf, entry, "track");
        config = json_get_object(buf, entry, "config");
        if (track == NULL) {
            continue;
        }
        const char *name = hang_json_get_string(buf, track, "name");
        if (name == NULL) {
            continue;
        }
        def.frame_num = ctx->frame_num;
        def.role = HANG_ROLE_MEDIA;
        def.media = ctx->media;
        def.container = HANG_CONTAINER_LEGACY;
        def.layout = HANG_LAYOUT_00;
        if (config != NULL) {
            def.codec = hang_json_get_string(buf, config, "codec");
        }
        hang_track_def_add(ctx->bc, name, &def);
    }
}

static hang_layout_t
hang_parse_catalog(wmem_allocator_t *pool, const char *path, uint32_t frame_num,
                   const uint8_t *data, int len)
{
    hang_catalog_ctx_t ctx = { 0 };
    char *buf;
    jsmntok_t *tokens;
    int ntok;

    if (len <= 0 || !json_validate(data, (size_t)len)) {
        return HANG_LAYOUT_UNKNOWN;
    }
    buf = (char *)wmem_strndup(pool, (const char *)data, (size_t)len);
    ntok = json_parse(buf, NULL, 0);
    if (ntok <= 0 || ntok > HANG_MAX_JSON_TOKENS) {
        return HANG_LAYOUT_UNKNOWN;
    }
    tokens = wmem_alloc_array(pool, jsmntok_t, ntok);
    if (json_parse(buf, tokens, ntok) <= 0 || tokens[0].type != JSMN_OBJECT) {
        return HANG_LAYOUT_UNKNOWN;
    }

    ctx.bc = hang_broadcast_lookup(path, true);
    ctx.frame_num = frame_num;

    static const struct {
        const char  *key;
        hang_media_t media;
    } media_sections[] = {
        { "video", HANG_MEDIA_VIDEO },
        { "audio", HANG_MEDIA_AUDIO },
        { "text",  HANG_MEDIA_TEXT },
    };

    /* Decide the layout first, so every track learns the same one. */
    ctx.layout = HANG_LAYOUT_01;
    for (unsigned i = 0; i < array_length(media_sections); i++) {
        if (json_get_array(buf, tokens, media_sections[i].key) != NULL) {
            ctx.layout = HANG_LAYOUT_00;
        }
    }
    if (json_get_object(buf, tokens, "text") != NULL ||
        json_get_object(buf, tokens, "json") != NULL ||
        json_get_object(buf, tokens, "binary") != NULL ||
        json_get_object(buf, tokens, "clock") != NULL ||
        json_get_object(buf, tokens, "archive") != NULL) {
        ctx.layout = HANG_LAYOUT_03;
    }

    for (unsigned i = 0; i < array_length(media_sections); i++) {
        jsmntok_t *array = json_get_array(buf, tokens, media_sections[i].key);
        jsmntok_t *section = json_get_object(buf, tokens, media_sections[i].key);

        ctx.media = media_sections[i].media;
        ctx.role = HANG_ROLE_MEDIA;
        if (array != NULL) {
            hang_parse_track_array(buf, array, &ctx);
        } else if (section != NULL) {
            hang_json_foreach(buf, json_get_object(buf, section, "renditions"),
                              hang_add_rendition, &ctx);
        }
    }

    /* Draft 03 data tracks. */
    ctx.media = HANG_MEDIA_NONE;
    ctx.role = HANG_ROLE_DATA_JSON;
    jsmntok_t *section = json_get_object(buf, tokens, "json");
    if (section != NULL) {
        hang_json_foreach(buf, json_get_object(buf, section, "tracks"), hang_add_rendition, &ctx);
    }
    ctx.role = HANG_ROLE_DATA_BINARY;
    section = json_get_object(buf, tokens, "binary");
    if (section != NULL) {
        hang_json_foreach(buf, json_get_object(buf, section, "tracks"), hang_add_rendition, &ctx);
    }

    /* Draft 03 segment index; the name is advertised, not fixed. */
    jsmntok_t *archive = json_get_object(buf, tokens, "archive");
    if (archive != NULL) {
        const char *name = hang_json_get_string(buf, archive, "track");
        if (name != NULL) {
            hang_track_def_t def = { 0 };
            def.frame_num = frame_num;
            def.role = HANG_ROLE_TIMELINE;
            def.layout = HANG_LAYOUT_03;
            hang_track_def_add(ctx.bc, name, &def);
        }
    }

    if (ctx.layout == HANG_LAYOUT_01 && ctx.container_seen) {
        ctx.layout = HANG_LAYOUT_02;
    }
    return ctx.layout;
}

/* Remember the layout a catalog was parsed with, keyed by the catalog frame. */
static void
hang_note_catalog(packet_info *pinfo, const moql_payload_info_t *info, tvbuff_t *json_tvb,
                  proto_tree *tree)
{
    hang_layout_t layout;
    uint32_t key = (uint32_t)(info->frame_offset & 0xffffffff);
    void *stored = p_get_proto_data(wmem_file_scope(), pinfo, proto_moq_hang, key);

    if (stored == NULL && !PINFO_FD_VISITED(pinfo)) {
        int len = tvb_captured_length(json_tvb);
        layout = hang_parse_catalog(pinfo->pool, info->broadcast_path, pinfo->num,
                                    tvb_get_ptr(json_tvb, 0, len), len);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_moq_hang, key,
                         GUINT_TO_POINTER((unsigned)layout + 1));
    } else {
        layout = stored != NULL ? (hang_layout_t)(GPOINTER_TO_UINT(stored) - 1)
                                : HANG_LAYOUT_UNKNOWN;
    }

    proto_item *ti = proto_tree_add_uint(tree, hf_hang_catalog_layout, json_tvb, 0, 0, layout);
    proto_item_set_generated(ti);
    if (layout == HANG_LAYOUT_UNKNOWN) {
        expert_add_info(pinfo, ti, &ei_hang_bad_catalog);
    }
}

/* ------------------------------------------------------------------------- */
/* DEFLATE tracks                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Return the decompressed output of one frame of a DEFLATE compressed group,
 * or NULL. The group's first frame must have been captured.
 */
static tvbuff_t *
hang_inflate_frame(tvbuff_t *tvb, packet_info *pinfo, const moql_payload_info_t *info)
{
    int len = tvb_captured_length(tvb);
    hang_zgroup_t *grp = NULL;
    hang_zframe_t *zf;

    if (info->group_key == NULL) {
        /* A datagram is a whole group. */
        uint8_t *buf = (uint8_t *)wmem_alloc(pinfo->pool, (size_t)len + sizeof(hang_sync_flush));
        tvb_memcpy(tvb, buf, 0, len);
        memcpy(buf + len, hang_sync_flush, sizeof(hang_sync_flush));
        tvbuff_t *ctvb = tvb_new_child_real_data(tvb, buf, len + 4, len + 4);
        return tvb_child_uncompress_zlib(tvb, ctvb, 0, len + 4);
    }

    grp = (hang_zgroup_t *)wmem_map_lookup(hang_zgroups, info->group_key);
    if (grp == NULL) {
        if (!info->first_in_group || PINFO_FD_VISITED(pinfo)) {
            return NULL;
        }
        grp = wmem_new0(wmem_file_scope(), hang_zgroup_t);
        grp->comp = wmem_array_new(wmem_file_scope(), 1);
        grp->frames = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        wmem_map_insert(hang_zgroups, info->group_key, grp);
    }

    zf = (hang_zframe_t *)wmem_map_lookup(grp->frames, &info->frame_offset);
    if (zf == NULL) {
        if (PINFO_FD_VISITED(pinfo)) {
            return NULL;
        }
        uint32_t comp_start = wmem_array_get_count(grp->comp);
        /* The trailer is stripped on the wire, as in RFC 7692. */
        wmem_array_append(grp->comp, tvb_get_ptr(tvb, 0, len), len);
        if (len < 4 || tvb_memeql(tvb, len - 4, hang_sync_flush, 4) != 0) {
            wmem_array_append(grp->comp, hang_sync_flush, sizeof(hang_sync_flush));
        }
        uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
        *key = info->frame_offset;
        zf = wmem_new0(wmem_file_scope(), hang_zframe_t);
        zf->comp_start = comp_start;
        zf->comp_end = wmem_array_get_count(grp->comp);
        wmem_map_insert(grp->frames, key, zf);
    }

    /* Inflate the group up to and including this frame. */
    tvbuff_t *ctvb = tvb_new_child_real_data(tvb, (const uint8_t *)wmem_array_get_raw(grp->comp),
                                             zf->comp_end, zf->comp_end);
    tvbuff_t *ptvb = tvb_child_uncompress_zlib(tvb, ctvb, 0, zf->comp_end);
    if (ptvb == NULL) {
        return NULL;
    }
    int plain_len = tvb_captured_length(ptvb);

    if (!zf->plain_known) {
        /* The previous frame's output ends where this one starts. */
        uint32_t start = 0;
        if (zf->comp_start > 0) {
            /* Inflate the prefix without this frame to find the boundary. */
            tvbuff_t *prev = tvb_child_uncompress_zlib(tvb, ctvb, 0, zf->comp_start);
            if (prev == NULL) {
                return NULL;
            }
            start = tvb_captured_length(prev);
        }
        zf->plain_start = start;
        zf->plain_known = true;
    }
    if (zf->plain_start > (uint32_t)plain_len) {
        return NULL;
    }
    return tvb_new_subset_length(ptvb, zf->plain_start, plain_len - (int)zf->plain_start);
}

/* ------------------------------------------------------------------------- */
/* Media                                                                     */
/* ------------------------------------------------------------------------- */

static void
hang_dissect_codec_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           const hang_track_def_t *def)
{
    int len = tvb_reported_length(tvb);

    if (def != NULL && def->media == HANG_MEDIA_TEXT) {
        const char *format = def->format != NULL ? def->format : "utf8";
        if (strcmp(format, "ttml") == 0 && xml_handle != NULL) {
            call_dissector(xml_handle, tvb, pinfo, tree);
        } else {
            proto_tree_add_item(tree, hf_hang_text, tvb, 0, len, ENC_UTF_8);
        }
        return;
    }
    if (def != NULL && def->codec != NULL && strcmp(def->codec, "opus") == 0 &&
        opus_handle != NULL) {
        call_dissector(opus_handle, tvb, pinfo, tree);
        return;
    }
    proto_tree_add_item(tree, hf_hang_payload, tvb, 0, len, ENC_NA);
}

static void
hang_dissect_legacy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *hang_ti,
                    const hang_track_def_t *def)
{
    uint64_t ts;
    unsigned lenvar;
    proto_item *ti;

    ti = proto_tree_add_item_ret_varint(tree, hf_hang_timestamp, tvb, 0, -1, ENC_VARINT_QUIC,
                                        &ts, &lenvar);
    if (lenvar == 0) {
        expert_add_info(pinfo, ti, &ei_hang_malformed);
        return;
    }

    nstime_t t;
    t.secs = (time_t)(ts / 1000000);
    t.nsecs = (int)((ts % 1000000) * 1000);
    ti = proto_tree_add_time(tree, hf_hang_time, tvb, 0, lenvar, &t);
    proto_item_set_generated(ti);

    int remaining = tvb_reported_length_remaining(tvb, lenvar);
    if (remaining == 0) {
        /*
         * An empty codec payload is never media (draft 03). Its meaning depends
         * on the media type; a group of only this frame is a discontinuity.
         */
        const char *marker;
        if (def != NULL && def->media == HANG_MEDIA_AUDIO) {
            marker = "Audio endpoint: samples at or after this timestamp are trimmed";
        } else if (def != NULL && def->media == HANG_MEDIA_VIDEO) {
            marker = "Exclusive end of the previous frame, or a discontinuity marker";
        } else {
            marker = "Empty payload marker";
        }
        ti = proto_tree_add_string(tree, hf_hang_marker, tvb, 0, lenvar, marker);
        proto_item_set_generated(ti);
        proto_item_append_text(hang_ti, ", %" PRIu64 " us, marker", ts);
        col_append_str(pinfo->cinfo, COL_INFO, " [hang marker]");
        return;
    }

    proto_item_append_text(hang_ti, ", %" PRIu64 " us, %d byte%s", ts, remaining,
                           plurality(remaining, "", "s"));
    hang_dissect_codec_payload(tvb_new_subset_remaining(tvb, lenvar), pinfo, tree, def);
}

static void
hang_dissect_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *hang_ti,
                   const hang_track_def_t *def)
{
    hang_container_t container = def != NULL ? def->container : HANG_CONTAINER_LEGACY;

    if (def != NULL) {
        proto_item *ti = proto_tree_add_uint(tree, hf_hang_media_type, tvb, 0, 0, def->media);
        proto_item_set_generated(ti);
        if (def->codec != NULL) {
            ti = proto_tree_add_string(tree, hf_hang_codec, tvb, 0, 0, def->codec);
            proto_item_set_generated(ti);
        }
        if (def->format != NULL) {
            ti = proto_tree_add_string(tree, hf_hang_format, tvb, 0, 0, def->format);
            proto_item_set_generated(ti);
        }
    }
    proto_item *cti = proto_tree_add_uint(tree, hf_hang_container, tvb, 0, 0, container);
    proto_item_set_generated(cti);

    switch (container) {
    case HANG_CONTAINER_LEGACY:
        hang_dissect_legacy(tvb, pinfo, tree, hang_ti, def);
        break;
    case HANG_CONTAINER_CMAF:
        /* Each frame is a moof+mdat fragment; init is in the catalog. */
        if (mp4_handle != NULL && tvb_reported_length(tvb) > 0) {
            call_dissector(mp4_handle, tvb, pinfo, tree);
        } else {
            proto_tree_add_item(tree, hf_hang_payload, tvb, 0, -1, ENC_NA);
        }
        break;
    case HANG_CONTAINER_LOC:
        proto_tree_add_expert_format_remaining(tree, pinfo, &ei_hang_undecoded, tvb, 0,
                                     "LOC frame (property block and codec payload) not decoded");
        break;
    default:
        proto_tree_add_expert_remaining(tree, pinfo, &ei_hang_unknown_container, tvb, 0);
        break;
    }
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                               */
/* ------------------------------------------------------------------------- */

static bool
hang_path_is_hang(const char *path)
{
    size_t len = strlen(path), slen = strlen(HANG_BROADCAST_SUFFIX);

    /* Tolerate a trailing slash, which some relays keep on broadcast paths. */
    while (len > 0 && path[len - 1] == '/') {
        len--;
    }
    return len >= slen && strncmp(path + len - slen, HANG_BROADCAST_SUFFIX, slen) == 0;
}

static hang_role_t
hang_track_role(const moql_payload_info_t *info, packet_info *pinfo, const hang_track_def_t **def)
{
    *def = hang_track_def_lookup(info->broadcast_path, info->track_name, pinfo->num);
    if (*def != NULL) {
        return (*def)->role;
    }
    if (strcmp(info->track_name, HANG_CATALOG_TRACK) == 0) {
        return HANG_ROLE_CATALOG;
    }
    if (strcmp(info->track_name, HANG_CATALOG_Z_TRACK) == 0) {
        return HANG_ROLE_CATALOG_Z;
    }
    if (strcmp(info->track_name, HANG_TIMELINE_TRACK_DEFAULT) == 0) {
        return HANG_ROLE_TIMELINE;
    }
    return HANG_ROLE_UNKNOWN;
}

static bool
dissect_moq_hang_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    moql_payload_info_t *info = (moql_payload_info_t *)data;
    const hang_track_def_t *def;
    hang_role_t role;
    proto_item *ti, *rti;
    proto_tree *hang_tree;
    int len = tvb_reported_length(tvb);

    if (info == NULL || info->broadcast_path == NULL || info->track_name == NULL) {
        return false;
    }
    role = hang_track_role(info, pinfo, &def);

    /*
     * Claim the payload if the broadcast looks like hang: a .hang path, a
     * catalog track, or a catalog already seen for this broadcast.
     */
    if (role == HANG_ROLE_UNKNOWN && !hang_decode_all_broadcasts &&
        !hang_path_is_hang(info->broadcast_path) &&
        hang_broadcast_lookup(info->broadcast_path, false) == NULL) {
        return false;
    }
    if (role == HANG_ROLE_UNKNOWN && !hang_assume_legacy) {
        return false;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MoQ-Hang");

    ti = proto_tree_add_item(tree, proto_moq_hang, tvb, 0, -1, ENC_NA);
    hang_tree = proto_item_add_subtree(ti, ett_hang);
    proto_item_append_text(ti, ", %s", info->track_name);

    rti = proto_tree_add_uint(hang_tree, hf_hang_track_role, tvb, 0, 0, role);
    proto_item_set_generated(rti);
    if (def != NULL) {
        proto_item *fti = proto_tree_add_uint(hang_tree, hf_hang_catalog_frame, tvb, 0, 0,
                                              def->frame_num);
        proto_item_set_generated(fti);
    }

    switch (role) {
    case HANG_ROLE_CATALOG:
        col_append_str(pinfo->cinfo, COL_INFO, " [hang catalog]");
        hang_note_catalog(pinfo, info, tvb, hang_tree);
        if (json_handle != NULL && len > 0) {
            call_dissector(json_handle, tvb, pinfo, hang_tree);
        }
        break;

    case HANG_ROLE_CATALOG_Z:
    case HANG_ROLE_TIMELINE:
    case HANG_ROLE_DATA_JSON:
    case HANG_ROLE_DATA_BINARY: {
        bool compressed = role == HANG_ROLE_CATALOG_Z || role == HANG_ROLE_TIMELINE ||
                          (def != NULL && def->compressed);
        tvbuff_t *plain = tvb;

        if (compressed && len > 0) {
            proto_item *zti = proto_tree_add_uint(hang_tree, hf_hang_compressed_len, tvb, 0, len, len);
            proto_item_set_generated(zti);
            plain = hang_inflate_frame(tvb, pinfo, info);
            if (plain == NULL) {
                proto_tree_add_expert(hang_tree, pinfo, &ei_hang_decompress_failed, tvb, 0, len);
                break;
            }
            add_new_data_source(pinfo, plain, "Decompressed hang frame");
            zti = proto_tree_add_uint(hang_tree, hf_hang_decompressed_len, plain, 0, 0,
                                      tvb_captured_length(plain));
            proto_item_set_generated(zti);
        }

        if (role == HANG_ROLE_CATALOG_Z) {
            col_append_str(pinfo->cinfo, COL_INFO, " [hang catalog]");
            /* The plain catalog.json sibling carries the same document. */
            if (info->first_in_group) {
                hang_note_catalog(pinfo, info, plain, hang_tree);
            }
        } else if (role == HANG_ROLE_TIMELINE) {
            col_append_str(pinfo->cinfo, COL_INFO,
                           info->first_in_group ? " [hang timeline checkpoint]"
                                                : " [hang timeline op]");
        }
        if (role == HANG_ROLE_DATA_BINARY) {
            proto_tree_add_item(hang_tree, hf_hang_payload, plain, 0, -1, ENC_NA);
        } else if (json_handle != NULL && tvb_captured_length(plain) > 0) {
            call_dissector(json_handle, plain, pinfo, hang_tree);
        }
        break;
    }

    case HANG_ROLE_MEDIA:
        hang_dissect_media(tvb, pinfo, hang_tree, ti, def);
        break;

    case HANG_ROLE_UNKNOWN:
    default:
        expert_add_info(pinfo, rti, &ei_hang_no_catalog);
        hang_dissect_media(tvb, pinfo, hang_tree, ti, NULL);
        break;
    }

    return true;
}

void
proto_register_moq_hang(void)
{
    static hf_register_info hf[] = {
        { &hf_hang_track_role,
          { "Track Role", "moq_hang.track_role",
            FT_UINT32, BASE_DEC, VALS(hang_role_vals), 0x0,
            "What the track carries, according to the catalog", HFILL }
        },
        { &hf_hang_catalog_layout,
          { "Catalog Layout", "moq_hang.catalog_layout",
            FT_UINT32, BASE_DEC, VALS(hang_layout_vals), 0x0,
            "The hang draft whose catalog layout this document follows (inferred)", HFILL }
        },
        { &hf_hang_catalog_frame,
          { "Catalog Frame", "moq_hang.catalog_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame containing the catalog update describing this track", HFILL }
        },
        { &hf_hang_media_type,
          { "Media Type", "moq_hang.media_type",
            FT_UINT32, BASE_DEC, VALS(hang_media_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_hang_container,
          { "Container", "moq_hang.container",
            FT_UINT32, BASE_DEC, VALS(hang_container_vals), 0x0,
            "The framing of each media frame", HFILL }
        },
        { &hf_hang_codec,
          { "Codec", "moq_hang.codec",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "WebCodecs codec string from the catalog", HFILL }
        },
        { &hf_hang_format,
          { "Text Format", "moq_hang.format",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Cue serialization of a text track", HFILL }
        },
        { &hf_hang_timestamp,
          { "Timestamp", "moq_hang.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Presentation timestamp in microseconds (legacy container)", HFILL }
        },
        { &hf_hang_time,
          { "Time", "moq_hang.time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Presentation timestamp", HFILL }
        },
        { &hf_hang_marker,
          { "Marker", "moq_hang.marker",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Meaning of a frame with an empty codec payload", HFILL }
        },
        { &hf_hang_payload,
          { "Payload", "moq_hang.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Codec specific or application payload", HFILL }
        },
        { &hf_hang_text,
          { "Cue", "moq_hang.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Text track cue", HFILL }
        },
        { &hf_hang_compressed_len,
          { "Compressed Length", "moq_hang.compressed_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hang_decompressed_len,
          { "Decompressed Length", "moq_hang.decompressed_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_hang,
        &ett_hang_decompressed,
    };

    static ei_register_info ei[] = {
        { &ei_hang_no_catalog,
          { "moq_hang.no_catalog", PI_UNDECODED, PI_NOTE,
            "Track not described by any catalog seen so far; assuming the legacy container",
            EXPFILL }
        },
        { &ei_hang_bad_catalog,
          { "moq_hang.bad_catalog", PI_MALFORMED, PI_WARN,
            "Catalog is not a JSON object", EXPFILL }
        },
        { &ei_hang_unknown_container,
          { "moq_hang.unknown_container", PI_UNDECODED, PI_NOTE,
            "Unknown container kind; consumers ignore this rendition", EXPFILL }
        },
        { &ei_hang_decompress_failed,
          { "moq_hang.decompress_failed", PI_UNDECODED, PI_NOTE,
            "Cannot decompress: the group's earlier frames were not captured", EXPFILL }
        },
        { &ei_hang_malformed,
          { "moq_hang.malformed", PI_MALFORMED, PI_ERROR,
            "Malformed hang frame", EXPFILL }
        },
        { &ei_hang_undecoded,
          { "moq_hang.undecoded", PI_UNDECODED, PI_NOTE,
            "Not decoded", EXPFILL }
        },
    };

    module_t *module;
    expert_module_t *expert;

    proto_moq_hang = proto_register_protocol("Media over QUIC - Hang", "MoQ-Hang", "moq_hang");
    proto_register_field_array(proto_moq_hang, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert = expert_register_protocol(proto_moq_hang);
    expert_register_field_array(expert, ei, array_length(ei));

    module = prefs_register_protocol(proto_moq_hang, NULL);
    prefs_register_bool_preference(module, "decode_all_broadcasts",
                                   "Treat every moq-lite broadcast as hang",
                                   "Decode payloads as hang even when the broadcast path does "
                                   "not end in \".hang\" and no catalog has been seen for it",
                                   &hang_decode_all_broadcasts);
    prefs_register_bool_preference(module, "assume_legacy",
                                   "Decode tracks missing from the catalog as legacy",
                                   "When the capture starts after the catalog was sent, decode "
                                   "unknown tracks of a hang broadcast with the legacy container",
                                   &hang_assume_legacy);

    register_init_routine(hang_init);
}

void
proto_reg_handoff_moq_hang(void)
{
    heur_dissector_add("moql.payload", dissect_moq_hang_heur, "Hang over MoQ-Lite",
                       "moq_hang_moql", proto_moq_hang, HEURISTIC_ENABLE);

    json_handle = find_dissector_add_dependency("json", proto_moq_hang);
    xml_handle = find_dissector_add_dependency("xml", proto_moq_hang);
    opus_handle = find_dissector_add_dependency("opus", proto_moq_hang);
    mp4_handle = find_dissector_add_dependency("mp4", proto_moq_hang);
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
