/* packet-fix.c
 * Routines for Financial Information eXchange (FIX) Protocol dissection
 * Copyright 2000, PC Drew <drewpc@ibsncentral.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Documentation: http://www.fixprotocol.org/
 * Fields and messages from http://www.quickfixengine.org/ xml
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

#include "packet-tcp.h"

typedef struct _fix_field {
    int         tag;    /* FIX tag */
    int         hf_id;
    int         type;   /* */
    const void *table;
} fix_field;

typedef struct _fix_parameter {
    int field_len;
    int tag_len;
    int value_offset;
    int value_len;
    int ctrla_offset;
} fix_parameter;

/* Initialize the protocol and registered fields */
static int proto_fix = -1;
static dissector_handle_t fix_handle;

/* desegmentation of fix */
static gboolean fix_desegment = TRUE;

/* Initialize the subtree pointers */
static gint ett_fix = -1;
static gint ett_unknow = -1;
static gint ett_badfield = -1;
static gint ett_checksum = -1;

static int hf_fix_data = -1; /* continuation data */
static int hf_fix_checksum_good = -1;
static int hf_fix_checksum_bad = -1;
static int hf_fix_field_value = -1;
static int hf_fix_field_tag = -1;

static range_t *global_fix_tcp_range = NULL;
static range_t *fix_tcp_range = NULL;

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
    /* try to resynch to the next start */
    guint min_len = tvb_length_remaining(tvb, offset);
    const guint8 *data = tvb_get_ephemeral_string(tvb, offset, min_len);
    const guint8 *start = data;

    while ((start = strstr(start, "\0018"))) {
        min_len = (guint) (start +1 -data);
        /*  if remaining length < 6 return and let the next desegment round
            test for 8=FIX
        */
        if (tvb_length_remaining(tvb, min_len + offset) < MARKER_LEN)
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
    int equals;

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
    ret.tag_len = ret.value_offset - offset - 1;
    ret.value_len = ret.ctrla_offset - ret.value_offset;
    return &ret;
}

/* ---------------------------------------------- */
static int fix_header_len(tvbuff_t *tvb, int offset)
{
    int base_offset, ctrla_offset;
    char *value;
    int size;
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

    value = tvb_get_ephemeral_string(tvb, tag->value_offset, tag->value_len);
    /* Fix version, msg type, length and checksum aren't in body length.
     * If the packet is big enough find the checksum
    */
    size = atoi(value) +tag->ctrla_offset - base_offset +1;
    if (tvb_length_remaining(tvb, base_offset) > size +4) {
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
static void
dissect_fix_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *fix_tree;
    int pdu_len;
    int offset = 0;
    int field_offset, ctrla_offset;
    int tag_value;
    char *value;
    char *tag_str;
    fix_parameter *tag;
    int check_sum = 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FIX");
    col_clear(pinfo->cinfo, COL_INFO);

    /* get at least the fix version: 8=FIX.x.x */
    if (fix_marker(tvb, 0) != 0) {
        /* not a fix packet start but it's a fix packet */
        col_set_str(pinfo->cinfo, COL_INFO, "[FIX continuation]");
        ti = proto_tree_add_item(tree, proto_fix, tvb, 0, -1, FALSE);
        fix_tree = proto_item_add_subtree(ti, ett_fix);
        proto_tree_add_item(fix_tree, hf_fix_data, tvb, 0, -1, FALSE);
        return;
    }

    pdu_len = tvb_reported_length(tvb);
    ti = proto_tree_add_item(tree, proto_fix, tvb, 0, -1, FALSE);
    fix_tree = proto_item_add_subtree(ti, ett_fix);

    /* begin string */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        return;
    }
    offset = ctrla_offset + 1;

    /* msg length */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        return;
    }
    offset = ctrla_offset + 1;

    /* msg type */
    if (!(tag = fix_param(tvb, offset)) || tag->value_len < 1) {
        return;
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        const char *msg_type;

        value = tvb_get_ephemeral_string(tvb, tag->value_offset, tag->value_len);
        msg_type = str_to_str(value, messages_val, "FIX Message (%s)");
        col_add_str(pinfo->cinfo, COL_INFO, msg_type);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    field_offset = 0;

    while(field_offset < pdu_len && (tag = fix_param(tvb, field_offset)) ) {
        int i, found;

        if (tag->tag_len < 1) {
            field_offset =  tag->ctrla_offset + 1;
            continue;
        }

        tag_str = tvb_get_ephemeral_string(tvb, field_offset, tag->tag_len);
        tag_value = atoi(tag_str);
        if (tag->value_len < 1) {
            proto_tree *field_tree;
            /* XXX - put an error indication here.  It's too late
               to return FALSE; we've already started dissecting,
               and if a heuristic dissector starts dissecting
               (either updating the columns or creating a protocol
               tree) and then gives up, it leaves crud behind that
               messes up other dissectors that might process the
               packet. */
            ti = proto_tree_add_text(fix_tree, tvb, field_offset, tag->field_len, "%i: <missing value>", tag_value);
            field_tree = proto_item_add_subtree(ti, ett_badfield);
            proto_tree_add_uint(field_tree, hf_fix_field_tag, tvb, field_offset, tag->tag_len, tag_value);
            field_offset =  tag->ctrla_offset + 1;
            continue;
        }

        /* fix_fields array is sorted by tag_value */
        found = 0;
        if ((i = tag_search(tag_value)) >= 0) {
            found = 1;
        }

        value = tvb_get_ephemeral_string(tvb, tag->value_offset, tag->value_len);
        if (found) {
            if (fix_fields[i].table) {
                if (tree) {
                    switch (fix_fields[i].type) {
                    case 1: /* strings */
                        proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value,
                            "%s (%s)", value, str_to_str(value, fix_fields[i].table, "unknow %s"));
                        break;
                    case 2: /* char */
                        proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value,
                            "%s (%s)", value, val_to_str(*value, fix_fields[i].table, "unknow %d"));
                        break;
                    default:
                        proto_tree_add_string_format_value(fix_tree, fix_fields[i].hf_id, tvb, field_offset, tag->field_len, value,
                            "%s (%s)", value, val_to_str(atoi(value), fix_fields[i].table, "unknow %d"));
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
                    const guint8 *data = tvb_get_ptr(tvb, 0, field_offset);
                    gboolean sum_ok;
                    int j;

                    for (j = 0; j < field_offset; j++, data++) {
                         sum += *data;
                    }
                    check_sum = 1;
                    sum_ok = (atoi(value) == sum);
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
                    PROTO_ITEM_SET_GENERATED(item);
                    item = proto_tree_add_boolean(checksum_tree, hf_fix_checksum_bad, tvb, field_offset, tag->field_len, !sum_ok);
                    PROTO_ITEM_SET_GENERATED(item);
                    if (!sum_ok)
                        expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR, "Bad checksum");
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
          ti = proto_tree_add_text(fix_tree, tvb, field_offset, tag->field_len, "%i: %s", tag_value, value);
          field_tree = proto_item_add_subtree(ti, ett_unknow);
          proto_tree_add_uint(field_tree, hf_fix_field_tag, tvb, field_offset, tag->tag_len, tag_value);
          proto_tree_add_item(field_tree, hf_fix_field_value, tvb, tag->value_offset, tag->value_len, FALSE);
        }

        field_offset =  tag->ctrla_offset + 1;

        tag_str = NULL;
    }
    return;
}

static guint
get_fix_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
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

static void
dissect_fix_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, fix_desegment, FIX_MIN_LEN,
                     get_fix_pdu_len, dissect_fix_packet);

}

static void
dissect_fix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_fix_pdus(tvb, pinfo, tree);
}

/* Code to actually dissect the packets */
static gboolean
dissect_fix_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    conversation_t *conv;

    /* get at least the fix version: 8=FIX.x.x */
    if (fix_marker(tvb, 0) != 0) {
        /* not a fix packet */
        return FALSE;
    }

    conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, fix_handle);

    dissect_fix_pdus(tvb, pinfo, tree);
    return TRUE;
}

/* Register the protocol with Wireshark */
static void range_delete_fix_tcp_callback(guint32 port) {
    dissector_delete_uint("tcp.port", port, fix_handle);
}

static void range_add_fix_tcp_callback(guint32 port) {
    dissector_add_uint("tcp.port", port, fix_handle);
}

static void fix_prefs(void)
{
    range_foreach(fix_tcp_range, range_delete_fix_tcp_callback);
    g_free(fix_tcp_range);
    fix_tcp_range = range_copy(global_fix_tcp_range);
    range_foreach(fix_tcp_range, range_add_fix_tcp_callback);
}

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fix(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
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
        &ett_unknow,
        &ett_badfield,
        &ett_checksum,
    };

    module_t *fix_module;

    /* register re-init routine */
    register_init_routine(&dissect_fix_init);

    /* Register the protocol name and description */
    proto_fix = proto_register_protocol("Financial Information eXchange Protocol",
                                        "FIX", "fix");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fix, hf, array_length(hf));
    proto_register_field_array(proto_fix, hf_FIX, array_length(hf_FIX));
    proto_register_subtree_array(ett, array_length(ett));

    fix_module = prefs_register_protocol(proto_fix, fix_prefs);
    prefs_register_bool_preference(fix_module, "desegment",
                                   "Reassemble FIX messages spanning multiple TCP segments",
                                   "Whether the FIX dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &fix_desegment);

    prefs_register_range_preference(fix_module, "tcp.port", "TCP Ports", "TCP Ports range", &global_fix_tcp_range, 65535);

    fix_tcp_range = range_empty();
}


void
proto_reg_handoff_fix(void)
{
    /* Let the tcp dissector know that we're interested in traffic      */
    heur_dissector_add("tcp", dissect_fix_heur, proto_fix);
    /* Register a fix handle to "tcp.port" to be able to do 'decode-as' */
    fix_handle = create_dissector_handle(dissect_fix, proto_fix);
    dissector_add_handle("tcp.port", fix_handle);
}

