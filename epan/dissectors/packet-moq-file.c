/* packet-moq-file.c
 * Dissector for MoQ Object File records produced by wiretap/moq.c.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <wsutil/wsjson.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

void proto_register_moq_file(void);

static int proto_moq_file;
static int hf_moq_metadata_length;
static int hf_moq_metadata;
static int hf_moq_track_namespace;
static int hf_moq_track_name;
static int hf_moq_object_id;
static int hf_moq_group_id;
static int hf_moq_subgroup_id;
static int hf_moq_forwarding_pref;
static int hf_moq_object_status;
static int hf_moq_publisher_priority;
static int hf_moq_receive_time;
static int hf_moq_data_file;
static int hf_moq_data_offset;
static int hf_moq_data_length;
static int hf_moq_object_data;
static gint ett_moq_file;
static gint ett_moq_metadata;

static bool
moq_add_int_field(proto_tree *tree, int hf, tvbuff_t *metadata_tvb,
                  char *json, jsmntok_t *object, const char *key)
{
    int64_t value;
    if (!json_get_int(json, object, key, &value)) return false;
    proto_tree_add_int64(tree, hf, metadata_tvb, 0,
                         tvb_captured_length(metadata_tvb), value);
    return true;
}

static bool
moq_add_string_field(proto_tree *tree, int hf, tvbuff_t *metadata_tvb,
                     char *json, jsmntok_t *object, const char *key)
{
    char *value = json_get_string(json, object, key);
    if (value == NULL) return false;
    proto_tree_add_string(tree, hf, metadata_tvb, 0,
                           tvb_captured_length(metadata_tvb), value);
    /* json_get_string() returns a pointer into json; do not free it. */
    return true;
}

static int
dissect_moq_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MoQ File");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *root_item = proto_tree_add_item(tree, proto_moq_file, tvb, 0, -1, ENC_NA);
    proto_tree *root_tree = proto_item_add_subtree(root_item, ett_moq_file);
    if (tvb_captured_length(tvb) < 4) {
        return tvb_captured_length(tvb);
    }

    uint32_t metadata_len = tvb_get_ntohl(tvb, 0);
    proto_tree_add_uint(root_tree, hf_moq_metadata_length, tvb, 0, 4, metadata_len);
    gint metadata_remaining = tvb_captured_length_remaining(tvb, 4);
    if (metadata_remaining < 0 || metadata_len > (uint32_t)metadata_remaining) {
        proto_item_set_len(root_item, 4);
        return tvb_captured_length(tvb);
    }

    tvbuff_t *metadata_tvb = tvb_new_subset_length(tvb, 4, metadata_len);
    char *json = (char *)tvb_get_string_enc(pinfo->pool, metadata_tvb, 0, metadata_len, ENC_UTF_8 | ENC_NA);
    int num_tokens = json_parse_len(json, metadata_len, NULL, 0);
    jsmntok_t *tokens = NULL;
    char *track_name = NULL;
    int64_t object_id = 0, group_id = 0, subgroup_id = 0;
    bool has_object_id = false, has_group_id = false, has_subgroup_id = false;
    proto_tree *meta_tree = proto_tree_add_subtree(root_tree, tvb, 4, metadata_len, ett_moq_metadata, NULL, "MoQ object metadata");
    proto_tree_add_string(meta_tree, hf_moq_metadata, tvb, 4, metadata_len, json);

    if (num_tokens > 0) {
        tokens = g_new0(jsmntok_t, num_tokens);
        if (json_parse_len(json, metadata_len, tokens, (unsigned int)num_tokens) > 0 && tokens[0].type == JSMN_OBJECT) {
            track_name = json_get_string(json, &tokens[0], "trackName");
            has_object_id = json_get_int(json, &tokens[0], "objectID", &object_id);
            has_group_id = json_get_int(json, &tokens[0], "groupID", &group_id);
            has_subgroup_id = json_get_int(json, &tokens[0], "subgroupID", &subgroup_id);
            if (!has_subgroup_id)
                has_subgroup_id = json_get_int(json, &tokens[0], "subGroup", &subgroup_id);
            moq_add_string_field(meta_tree, hf_moq_track_name, metadata_tvb, json, &tokens[0], "trackName");
            moq_add_string_field(meta_tree, hf_moq_forwarding_pref, metadata_tvb, json, &tokens[0], "forwardingPref");
            moq_add_string_field(meta_tree, hf_moq_data_file, metadata_tvb, json, &tokens[0], "dataFile");
            moq_add_int_field(meta_tree, hf_moq_object_id, metadata_tvb, json, &tokens[0], "objectID");
            moq_add_int_field(meta_tree, hf_moq_group_id, metadata_tvb, json, &tokens[0], "groupID");
            if (!moq_add_int_field(meta_tree, hf_moq_subgroup_id, metadata_tvb, json, &tokens[0], "subgroupID"))
                moq_add_int_field(meta_tree, hf_moq_subgroup_id, metadata_tvb, json, &tokens[0], "subGroup");
            moq_add_int_field(meta_tree, hf_moq_object_status, metadata_tvb, json, &tokens[0], "objectStatus");
            moq_add_int_field(meta_tree, hf_moq_publisher_priority, metadata_tvb, json, &tokens[0], "publisherPriority");
            moq_add_int_field(meta_tree, hf_moq_receive_time, metadata_tvb, json, &tokens[0], "receiveTime");
            moq_add_int_field(meta_tree, hf_moq_data_offset, metadata_tvb, json, &tokens[0], "dataOffset");
            moq_add_int_field(meta_tree, hf_moq_data_length, metadata_tvb, json, &tokens[0], "dataLength");
            jsmntok_t *ns = json_get_array(json, &tokens[0], "trackNamespace");
            if (ns == NULL) ns = json_get_array(json, &tokens[0], "namesSpace");
            if (ns != NULL) {
                /* json_get_*() NUL-terminate values in place, so json + ns->start
                 * is not terminated at the end of the array; copy the span. */
                proto_tree_add_string(meta_tree, hf_moq_track_namespace, tvb, 4, metadata_len,
                    wmem_strndup(pinfo->pool, json + ns->start, (size_t)(ns->end - ns->start)));
            }
        }
        g_free(tokens);
    }

    gint object_offset = 4 + (gint)metadata_len;
    gint object_length = tvb_captured_length_remaining(tvb, object_offset);
    if (object_length > 0) {
        proto_tree_add_item(root_tree, hf_moq_object_data, tvb, object_offset, object_length, ENC_NA);
        if (track_name != NULL && has_group_id && has_object_id && has_subgroup_id) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Track %s G=%" PRId64 " S=%" PRId64 " O=%" PRId64 ", %u bytes",
                track_name, group_id, subgroup_id, object_id, object_length);
        } else if (track_name != NULL && has_group_id && has_object_id) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                "Track %s G=%" PRId64 " O=%" PRId64 ", %u bytes",
                track_name, group_id, object_id, object_length);
        } else if (track_name != NULL && has_object_id) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Track %s O=%" PRId64 ", %u bytes",
                track_name, object_id, object_length);
        } else {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Object data: %u bytes", object_length);
        }
    }
    return tvb_captured_length(tvb);
}

void
proto_register_moq_file(void)
{
    static hf_register_info hf[] = {
        { &hf_moq_metadata_length, { "Metadata length", "moq_file.metadata_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_metadata, { "Metadata JSON", "moq_file.metadata", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_track_namespace, { "Track namespace (Base64URL JSON array)", "moq_file.track_namespace", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_track_name, { "Track name (Base64URL)", "moq_file.track_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_object_id, { "Object ID", "moq_file.object_id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_group_id, { "Group ID", "moq_file.group_id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_subgroup_id, { "Subgroup ID", "moq_file.subgroup_id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_forwarding_pref, { "Forwarding preference", "moq_file.forwarding_pref", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_object_status, { "Object status", "moq_file.object_status", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_publisher_priority, { "Publisher priority", "moq_file.publisher_priority", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_receive_time, { "Receive time (Unix milliseconds)", "moq_file.receive_time", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_data_file, { "Data file", "moq_file.data_file", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_data_offset, { "Data offset", "moq_file.data_offset", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_data_length, { "Data length", "moq_file.data_length", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_moq_object_data, { "MoQT object bytes (header and payload)", "moq_file.object_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };
    static gint *ett[] = { &ett_moq_file, &ett_moq_metadata };

    proto_moq_file = proto_register_protocol("MoQ Object File", "MoQ File", "moq_file");
    proto_register_field_array(proto_moq_file, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("moq_file", dissect_moq_file, proto_moq_file);
}
