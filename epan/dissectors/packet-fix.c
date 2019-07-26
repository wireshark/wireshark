/* packet-fix.c
 * Routines for Financial Information eXchange (FIX) Protocol dissection
 * Copyright 2000, PC Drew <drewpc@ibsncentral.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Documentation: http://www.fixprotocol.org/
 * Fields and messages from http://www.quickfixengine.org/ and http://sourceforge.net/projects/quickfix/files/ xml
 *
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <wsutil/strtoi.h>

#include "packet-tcp.h"
#include "packet-tls.h"

void proto_register_fix(void);
void proto_reg_handoff_fix(void);

typedef struct _fix_parameter {
    int field_len;
    int tag_len;
    int value_offset;
    int value_len;
    int ctrla_offset;
} fix_parameter;

/* Initialize the protocol and registered fields */
static int proto_fix = -1;

/* desegmentation of fix */
static gboolean fix_desegment = TRUE;

/* Initialize the subtree pointers */
static gint ett_fix = -1;
static gint ett_unknown = -1;
static gint ett_badfield = -1;
static gint ett_checksum = -1;

static expert_field ei_fix_checksum_bad = EI_INIT;
static expert_field ei_fix_missing_field = EI_INIT;
static expert_field ei_fix_tag_invalid = EI_INIT;
static expert_field ei_fix_field_invalid = EI_INIT;

static int hf_fix_data = -1; /* continuation data */
static int hf_fix_checksum_good = -1;
static int hf_fix_checksum_bad = -1;
static int hf_fix_field_value = -1;
static int hf_fix_field_tag = -1;

static dissector_handle_t fix_handle;

/* 8=FIX */
#define MARKER_TAG "8=FIX"
#define MARKER_LEN 5

static int fix_marker(tvbuff_t *tvb, int offset)
{
    return tvb_strneql(tvb, offset, MARKER_TAG, MARKER_LEN);
}

/*
 * Fields and messages generated from http://www.quickfixengine.org/ xml (slightly modified)
 */

#include "packet-fix.h"

static void dissect_fix_init(void) {
    /* TODO load xml def for private field */
    /* TODO check that fix_fields is really sorted */
}

static int
tag_search(int key)
{
    int lower = 0, upper = array_length(fix_fields) -1;
    while (lower <= upper) {
        int middle = (lower + upper) / 2;
        int res = fix_fields[middle].tag;
        if (res < key) {
            lower = middle + 1;
        } else if (res == key) {
            return middle;
        } else {
            upper = middle - 1;
        }
    }
    return -1;
}

/* Code to actually dissect the packets */
static int fix_next_header(tvbuff_t *tvb, int offset)
{
    /* try to resync to the next start */
    guint         min_len = tvb_captured_length_remaining(tvb, offset);
    const guint8 *data    = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, min_len, ENC_ASCII);
    const guint8 *start   = data;

    while ((start = strstr(start, "\0018"))) {
        min_len = (guint) (start +1 -data);
        /*  if remaining length < 6 return and let the next desegment round
            test for 8=FIX
        */
        if (tvb_reported_length_remaining(tvb, min_len + offset) < MARKER_LEN)
           break;
        if (!fix_marker(tvb, min_len +offset) )
            break;
        start++;
    }
    return min_len;
}

/* ----------------------------------------------
  Format: name=value\001
*/
static fix_parameter *fix_param(tvbuff_t *tvb, int offset)
{
    static fix_parameter ret;
    int                  equals;

    ret.ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ret.ctrla_offset == -1) {
        return NULL;
    }

    ret.field_len = ret.ctrla_offset - offset + 1;
    equals = tvb_find_guint8(tvb, offset, ret.field_len, '=');
    if (equals == -1) {
        return NULL;
    }

    ret.value_offset = equals + 1;
    ret.tag_len      = ret.value_offset - offset - 1;
    ret.value_len    = ret.ctrla_offset - ret.value_offset;
    return &ret;
}

/* ---------------------------------------------- */
static int fix_header_len(tvbuff_t *tvb, int offset)
{
    int            base_offset, ctrla_offset;
    gint32         value;
    int            size;
    fix_parameter *tag;

    base_offset = offset;

    /* get at least the fix version: 8=FIX.x.x */
    if (fix_marker(tvb, offset) != 0) {
        return fix_next_header(tvb, offset);
    }

    /* begin string */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        /* it should be there, (minimum size is big enough)
         * if not maybe it's not really
         * a FIX packet but it's too late to bail out.
        */
        return fix_next_header(tvb, offset +MARKER_LEN) +MARKER_LEN;
    }
    offset = ctrla_offset + 1;

    /* msg length */
    if (!(tag = fix_param(tvb, offset)) || tvb_strneql(tvb, offset, "9=", 2)) {
        /* not a tag or not the BodyLength tag, give up */
        return fix_next_header(tvb, offset);
    }

    if (!ws_strtoi32(tvb_get_string_enc(wmem_packet_scope(), tvb, tag->value_offset,
            tag->value_len, ENC_ASCII), NULL, &value))
        return fix_next_header(tvb, base_offset +MARKER_LEN)  +MARKER_LEN;
    /* Fix version, msg type, length and checksum aren't in body length.
     * If the packet is big enough find the checksum
    */
    size = value + tag->ctrla_offset - base_offset + 1;
    if (tvb_reported_length_remaining(tvb, base_offset) > size +4) {
        /* 10= should be there */
        offset = base_offset +size;
        if (tvb_strneql(tvb, offset, "10=", 3) != 0) {
            /* No? bogus packet, try to find the next header */
            return fix_next_header(tvb, base_offset +MARKER_LEN)  +MARKER_LEN;
        }
        ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
        if (ctrla_offset == -1) {
            /* assume checksum is 7 bytes 10=xxx\01 */
            return size+7;
        }
        return size +ctrla_offset -offset +1;
    }
    else {
    }
    /* assume checksum is 7 bytes 10=xxx\01 */
    return size +7;
}

/* ---------------------------------------------- */
static int
dissect_fix_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item    *ti;
    proto_tree    *fix_tree;
    int            pdu_len;
    int            offset = 0;
    int            field_offset, ctrla_offset;
    int            tag_value;
    char          *value;
    guint32        ivalue;
    gboolean       ivalue_valid;
    proto_item*    pi;
    fix_parameter *tag;
    const char *msg_type;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FIX");
    col_clear(pinfo->cinfo, COL_INFO);

    /* get at least the fix version: 8=FIX.x.x */
    if (fix_marker(tvb, 0) != 0) {
        /* not a fix packet start but it's a fix packet */
        col_set_str(pinfo->cinfo, COL_INFO, "[FIX continuation]");
        ti = proto_tree_add_item(tree, proto_fix, tvb, 0, -1, ENC_NA);
        fix_tree = proto_item_add_subtree(ti, ett_fix);
        proto_tree_add_item(fix_tree, hf_fix_data, tvb, 0, -1, ENC_NA);
        return tvb_captured_length(tvb);
    }

    pdu_len = tvb_reported_length(tvb);
    ti = proto_tree_add_item(tree, proto_fix, tvb, 0, -1, ENC_NA);
    fix_tree = proto_item_add_subtree(ti, ett_fix);

    /* begin string */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        expert_add_info_format(pinfo, ti, &ei_fix_missing_field, "Missing BeginString field");
        return tvb_captured_length(tvb);
    }
    offset = ctrla_offset + 1;

    /* msg length */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        expert_add_info_format(pinfo, ti, &ei_fix_missing_field, "Missing BodyLength field");
        return tvb_captured_length(tvb);
    }
    offset = ctrla_offset + 1;

    /* msg type */
    if (!(tag = fix_param(tvb, offset)) || tag->value_len < 1) {
        expert_add_info_format(pinfo, ti, &ei_fix_missing_field, "Missing MsgType field");
        return tvb_captured_length(tvb);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    field_offset = 0;

    while(field_offset < pdu_len && (tag = fix_param(tvb, field_offset)) ) {
        int i, found;

        if (tag->tag_len < 1) {
            field_offset = tag->ctrla_offset + 1;
            continue;
        }

        if (!ws_strtou32(tvb_get_string_enc(wmem_packet_scope(), tvb, field_offset, tag->tag_len, ENC_ASCII),
                NULL, &tag_value)) {
            proto_tree_add_expert(fix_tree, pinfo, &ei_fix_tag_invalid, tvb, field_offset, tag->tag_len);
            break;
        }
        if (tag->value_len < 1) {
            proto_tree *field_tree;
            /* XXX - put an error indication here.  It's too late
               to return FALSE; we've already started dissecting,
               and if a heuristic dissector starts dissecting
               (either updating the columns or creating a protocol
               tree) and then gives up, it leaves crud behind that
               messes up other dissectors that might process the
               packet. */
            field_tree = proto_tree_add_subtree_format(fix_tree, tvb, field_offset, tag->field_len, ett_badfield, NULL, "%i: <missing value>", tag_value);
            proto_tree_add_uint(field_tree, hf_fix_field_tag, tvb, field_offset, tag->tag_len, tag_value);
            field_offset =  tag->ctrla_offset + 1;
            continue;
        }

        /* fix_fields array is sorted by tag_value */
        found = 0;
        if ((i = tag_search(tag_value)) >= 0) {
            found = 1;
        }

        value = tvb_get_string_enc(wmem_packet_scope(), tvb, tag->value_offset, tag->value_len, ENC_ASCII);
        ivalue_valid = ws_strtoi32(value, NULL, &ivalue);
        if (found) {
            if (fix_fields[i].table) {
                if (tree) {
                    switch (fix_fields[i].type) {
                    case 1: /* strings */
                        proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value,
                            "%s (%s)", value, str_to_str(value, (const string_string *)fix_fields[i].table, "unknown %s"));
                        if (tag_value == 35) {
                            /* Make message type part of the Info column */
                            msg_type = str_to_str(value, messages_val, "FIX Message (%s)");
                            col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", msg_type);
                            col_set_fence(pinfo->cinfo, COL_INFO);
                        }
                        break;
                    case 2: /* char */
                        proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value,
                            "%s (%s)", value, val_to_str(*value, (const value_string *)fix_fields[i].table, "unknown %d"));
                        break;
                    default:
                        if (ivalue_valid)
                            proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value,
                                "%s (%s)", value, val_to_str(ivalue, (const value_string *)fix_fields[i].table, "unknown %d"));
                        else {
                            pi = proto_tree_add_string(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value);
                            expert_add_info_format(pinfo, pi, &ei_fix_field_invalid, "Invalid string %s for fix field %u", value, i);
                        }
                        break;
                    }
                }
            }
            else {
              proto_item *item;

              /* checksum */
              switch(tag_value) {
              case 10:
                {
                    proto_tree *checksum_tree;
                    guint8 sum = 0;
                    const guint8 *sum_data = tvb_get_ptr(tvb, 0, field_offset);
                    gboolean sum_ok;
                    int j;

                    for (j = 0; j < field_offset; j++, sum_data++) {
                         sum += *sum_data;
                    }
                    sum_ok = (ivalue == sum);
                    if (sum_ok) {
                        item = proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len,
                                value, "%s [correct]", value);
                    }
                    else {
                        item = proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len,
                                value, "%s [incorrect should be %d]", value, sum);
                    }
                    checksum_tree = proto_item_add_subtree(item, ett_checksum);
                    item = proto_tree_add_boolean(checksum_tree, hf_fix_checksum_good, tvb, field_offset, tag->field_len, sum_ok);
                    proto_item_set_generated(item);
                    item = proto_tree_add_boolean(checksum_tree, hf_fix_checksum_bad, tvb, field_offset, tag->field_len, !sum_ok);
                    proto_item_set_generated(item);
                    if (!sum_ok)
                        expert_add_info(pinfo, item, &ei_fix_checksum_bad);
                }
                break;
              default:
                proto_tree_add_string(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value);
                break;
              }
            }
        }
        else if (tree) {
          proto_tree *field_tree;

          /* XXX - it could be -1 if the tag isn't a number */
          field_tree = proto_tree_add_subtree_format(fix_tree, tvb, field_offset, tag->field_len, ett_unknown, NULL,
              "%i: %s", tag_value, value);
          proto_tree_add_uint(field_tree, hf_fix_field_tag, tvb, field_offset, tag->tag_len, tag_value);
          proto_tree_add_item(field_tree, hf_fix_field_value, tvb, tag->value_offset, tag->value_len, ENC_ASCII|ENC_NA);
        }

        field_offset =  tag->ctrla_offset + 1;
    }
    return tvb_captured_length(tvb);
}

static guint
get_fix_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int fix_len;

    fix_len = fix_header_len(tvb, offset);
    return fix_len;
}

/* ------------------------------------
   fixed-length part isn't really a constant but if we assume it's at least:
       8=FIX.x.y\01   10
       9=x\01          4
       35=x\01         5
       10=y\01         5
                      24
       it should catch all 9= size
*/

#define FIX_MIN_LEN 24

static int
dissect_fix_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, fix_desegment, FIX_MIN_LEN,
                     get_fix_pdu_len, dissect_fix_packet, data);

    return tvb_captured_length(tvb);
}

static int
dissect_fix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    return dissect_fix_pdus(tvb, pinfo, tree, data);
}

/* Code to actually dissect the packets */
static gboolean
dissect_fix_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conv;

    /* get at least the fix version: 8=FIX.x.x */
    if (fix_marker(tvb, 0) != 0) {
        /* not a fix packet */
        return FALSE;
    }

    conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, fix_handle);

    dissect_fix_pdus(tvb, pinfo, tree, data);
    return TRUE;
}

static gboolean
dissect_fix_heur_ssl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dissector_handle_t *app_handle = (dissector_handle_t *) data;
    /* get at least the fix version: 8=FIX.x.x */
    if (fix_marker(tvb, 0) != 0) {
        /* not a fix packet */
        return FALSE;
    }

    dissect_fix_pdus(tvb, pinfo, tree, data);
    *app_handle = fix_handle;
    return TRUE;
}

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fix(void)
{
    static hf_register_info hf[] = {
        { &hf_fix_data,
          { "Continuation Data", "fix.data", FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_fix_field_tag,
          { "Field Tag",         "fix.field.tag", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Field length.", HFILL }},

        { &hf_fix_field_value,
          { "Field Value",       "fix.field.value", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_fix_checksum_good,
          { "Good Checksum",       "fix.checksum_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

        { &hf_fix_checksum_bad,
          { "Bad Checksum",        "fix.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum doesn't match packet content; False: matches content or not checked", HFILL }},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fix,
        &ett_unknown,
        &ett_badfield,
        &ett_checksum,
    };

    static ei_register_info ei[] = {
        { &ei_fix_checksum_bad, { "fix.checksum_bad.expert", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_fix_missing_field, { "fix.missing_field", PI_MALFORMED, PI_ERROR, "Missing mandatory field", EXPFILL }},
        { &ei_fix_tag_invalid, { "fix.tag.invalid", PI_MALFORMED, PI_ERROR, "Invalid Tag", EXPFILL }},
        { &ei_fix_field_invalid, { "fix.invalid_integer_string", PI_MALFORMED, PI_ERROR, "Invalid integer string", EXPFILL }}
    };

    module_t *fix_module;
    expert_module_t* expert_fix;

    /* register re-init routine */
    register_init_routine(&dissect_fix_init);

    /* Register the protocol name and description */
    proto_fix = proto_register_protocol("Financial Information eXchange Protocol", "FIX", "fix");

    /* Allow dissector to find be found by name. */
    fix_handle = register_dissector("fix", dissect_fix, proto_fix);

    proto_register_field_array(proto_fix, hf, array_length(hf));
    proto_register_field_array(proto_fix, hf_FIX, array_length(hf_FIX));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fix = expert_register_protocol(proto_fix);
    expert_register_field_array(expert_fix, ei, array_length(ei));

    fix_module = prefs_register_protocol(proto_fix, NULL);
    prefs_register_bool_preference(fix_module, "desegment",
                                   "Reassemble FIX messages spanning multiple TCP segments",
                                   "Whether the FIX dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &fix_desegment);
}


void
proto_reg_handoff_fix(void)
{
    /* Let the tcp dissector know that we're interested in traffic      */
    heur_dissector_add("tcp", dissect_fix_heur, "FIX over TCP", "fix_tcp", proto_fix, HEURISTIC_ENABLE);
    heur_dissector_add("tls", dissect_fix_heur_ssl, "FIX over TLS", "fix_tls", proto_fix, HEURISTIC_ENABLE);
    dissector_add_uint_range_with_preference("tcp.port", "", fix_handle);
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
