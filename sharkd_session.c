/* sharkd_session.c
 *
 * Copyright (C) 2016 Jakub Zawadzki
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wtap_opttypes.h"
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <wsutil/wsjson.h>
#include <wsutil/json_dumper.h>
#include <wsutil/ws_assert.h>

#include <file.h>
#include <epan/epan_dissect.h>
#include <epan/exceptions.h>
#include <epan/color_filters.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/uat-int.h>
#include <wiretap/wtap.h>

#include <epan/column.h>

#include <ui/ssl_key_export.h>

#include <ui/io_graph_item.h>
#include <epan/stats_tree_priv.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/sequence_analysis.h>
#include <epan/expert.h>
#include <epan/export_object.h>
#include <epan/follow.h>
#include <epan/rtd_table.h>
#include <epan/srt_table.h>

#include <epan/dissectors/packet-h225.h>
#include <epan/rtp_pt.h>
#include <ui/voip_calls.h>
#include <ui/rtp_stream.h>
#include <ui/tap-rtp-common.h>
#include <ui/tap-rtp-analysis.h>
#include <ui/version_info.h>
#include <epan/to_str.h>

#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-rtp.h>
#include <ui/rtp_media.h>
#ifdef HAVE_SPEEXDSP
# include <speex/speex_resampler.h>
#else
# include "speexdsp/speex_resampler.h"
#endif /* HAVE_SPEEXDSP */

#include <epan/maxmind_db.h>

#include <wsutil/pint.h>
#include <wsutil/strtoi.h>

#include "globals.h"

#include "sharkd.h"

struct sharkd_filter_item
{
    guint8 *filtered; /* can be NULL if all frames are matching for given filter. */
};

static GHashTable *filter_table = NULL;

static int mode;
static guint32 rpcid;

static json_dumper dumper = {0};


static const char *
json_find_attr(const char *buf, const jsmntok_t *tokens, int count, const char *attr)
{
    int i;

    for (i = 0; i < count; i += 2)
    {
        const char *tok_attr  = &buf[tokens[i + 0].start];
        const char *tok_value = &buf[tokens[i + 1].start];

        if (!strcmp(tok_attr, attr))
            return tok_value;
    }

    return NULL;
}

static void
json_print_base64(const guint8 *data, size_t len)
{
    json_dumper_begin_base64(&dumper);
    json_dumper_write_base64(&dumper, data, len);
    json_dumper_end_base64(&dumper);
}

static void G_GNUC_PRINTF(2, 3)
sharkd_json_value_anyf(const char *key, const char *format, ...)
{
    if (key)
        json_dumper_set_member_name(&dumper, key);

    if (format) {
        va_list ap;
        va_start(ap, format);
        json_dumper_value_va_list(&dumper, format, ap);
        va_end(ap);
    }
}

static void
sharkd_json_value_string(const char *key, const char *str)
{
    if (key)
        json_dumper_set_member_name(&dumper, key);
    if (str)
        json_dumper_value_string(&dumper, str);
}

static void
sharkd_json_value_base64(const char *key, const guint8 *data, size_t len)
{
    if (key)
        json_dumper_set_member_name(&dumper, key);
    json_print_base64(data, len);
}

static void G_GNUC_PRINTF(2, 3)
sharkd_json_value_stringf(const char *key, const char *format, ...)
{
    if (key)
        json_dumper_set_member_name(&dumper, key);

    if (format) {
        va_list ap;
        va_start(ap, format);
        char* sformat = ws_strdup_printf("\"%s\"", format);
        json_dumper_value_va_list(&dumper, sformat, ap);
        g_free(sformat);
        va_end(ap);
    }
}

static void
sharkd_json_array_open(const char *key)
{
    if (key)
        json_dumper_set_member_name(&dumper, key);
    json_dumper_begin_array(&dumper);
}

static void
sharkd_json_array_close(void)
{
    json_dumper_end_array(&dumper);
}

static void
sharkd_json_response_open(guint32 id)
{
    json_dumper_begin_object(&dumper);  // start the message
    sharkd_json_value_string("jsonrpc", "2.0");
    sharkd_json_value_anyf("id", "%d", id);
}

static void
sharkd_json_response_close(void)
{
    json_dumper_finish(&dumper);

    /*
     * We do an explicit fflush after every line, because
     * we want output to be written to the socket as soon
     * as the line is complete.
     *
     * The stream is fully-buffered by default, so it's
     * only flushed when the buffer fills or the FILE *
     * is closed.  On UN*X, we could set it to be line
     * buffered, but the MSVC standard I/O routines don't
     * support line buffering - they only support *byte*
     * buffering, doing a write for every byte written,
     * which is too inefficient, and full buffering,
     * which is what you get if you request line buffering.
     */
    fflush(stdout);
}

static void
sharkd_json_result_prologue(guint32 id)
{
    sharkd_json_response_open(id);
    sharkd_json_value_anyf("result", NULL);
    json_dumper_begin_object(&dumper);  // start the result object
}

static void
sharkd_json_result_epilogue(void)
{
    json_dumper_end_object(&dumper);  // end the result object
    json_dumper_end_object(&dumper);  // end the message
    sharkd_json_response_close();
}

static void
sharkd_json_result_array_prologue(guint32 id)
{
    sharkd_json_response_open(id);
    sharkd_json_array_open("result");   // start the result array
}

static void
sharkd_json_result_array_epilogue(void)
{
    sharkd_json_array_close();        // end of result array
    json_dumper_end_object(&dumper);  // end the message
    sharkd_json_response_close();
}

static void
sharkd_json_simple_ok(guint32 id)
{
    sharkd_json_result_prologue(id);
    sharkd_json_value_string("status", "OK");
    sharkd_json_result_epilogue();
}

static void
sharkd_json_warning(guint32 id, char *warning)
{
    sharkd_json_result_prologue(id);
    sharkd_json_value_string("status", "Warning");
    sharkd_json_value_string("warning", warning);
    sharkd_json_result_epilogue();
}

static void G_GNUC_PRINTF(4, 5)
sharkd_json_error(guint32 id, int code, char* data, char* format, ...)
{
    sharkd_json_response_open(id);
    sharkd_json_value_anyf("error", NULL);
    json_dumper_begin_object(&dumper);
    sharkd_json_value_anyf("code", "%d", code);

    if (format)
    {
        // format the text message
        va_list args;

        va_start(args, format);
        char *error_msg = ws_strdup_vprintf(format, args);
        va_end(args);

        sharkd_json_value_string("message", error_msg);

        g_free(error_msg);
    }

    json_dumper_end_object(&dumper);

    if (data)
        sharkd_json_value_string("data", data);

    json_dumper_end_object(&dumper);
    sharkd_json_response_close();
}

static gboolean
is_param_match(const char *param_in, const char *valid_param)
{
    char* ptr;

    if ((ptr = g_strrstr(valid_param, "*")))
    {
        size_t prefix_len = ptr - valid_param;
        return !strncmp(param_in, valid_param, prefix_len);
    }
    else
        return !strcmp(param_in, valid_param);
}

/*
 * json_prep does four things:
 *
 *   1. check the syntax of the root and parameter members
 *   2. tokenize the names and values by zero terminating them
 *   3. unescape the names and values
 *   4. extracts and saves the rpcid
 *      - we have to do it here as it's needed for the error messages
 *
 * The objective is to minimise the validation work in the functions
 * that process each called method.
 *
 * This gets a little messy as the JSON parser creates a flat list
 * of all members rather than create a tree.
 */
static gboolean
json_prep(char* buf, const jsmntok_t* tokens, int count)
{
    int i;
    char* method = NULL;
    char* attr_name = NULL;
    char* attr_value = NULL;

#define SHARKD_JSON_ANY      0
#define SHARKD_JSON_STRING   1
#define SHARKD_JSON_INTEGER  2
#define SHARKD_JSON_UINTEGER 3
#define SHARKD_JSON_FLOAT    4
#define SHARKD_JSON_OBJECT   5
#define SHARKD_JSON_ARRAY    6
#define SHARKD_JSON_BOOLEAN  7
#define SHARKD_ARRAY_END     99

    struct member_attribute {
        const char* parent_ctx;
        const char* name;
        int level;
        jsmntype_t type;
        int value_type;
        gboolean is_mandatory;
    };

#define MANDATORY TRUE
#define OPTIONAL FALSE

    /*
     * The member attribute structure is key to the syntax checking.  The
     * array contains all of the root level (1) member names, the data
     * types permissable for the value and a boolean that indicates whether
     * or not the member is mandatory.
     *
     * Once we get into the next layer (2) of the json tree, we need to check
     * params member names and data types dependent in the context of the method
     * (parent_ctx).
     */

    struct member_attribute name_array[] = {
        // Root members
        {NULL,         "jsonrpc",    1, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {NULL,         "userid",     1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {NULL,         "id",         1, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, MANDATORY},
        {NULL,         "method",     1, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {NULL,         "params",     1, JSMN_OBJECT,       SHARKD_JSON_OBJECT,   OPTIONAL},

        // Valid methods
        {"method",     "analyse",    1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "bye",        1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "check",      1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "complete",   1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "download",   1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "dumpconf",   1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "follow",     1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "frame",      1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "frames",     1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "info",       1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "intervals",  1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "iograph",    1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "load",       1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "setcomment", 1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "setconf",    1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "status",     1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"method",     "tap",        1, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},

        // Parameters and their method context
        {"check",      "field",      2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"check",      "filter",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"complete",   "field",      2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"complete",   "pref",       2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"download",   "token",      2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"dumpconf",   "pref",       2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"follow",     "follow",     2, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {"follow",     "filter",     2, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {"frame",      "frame",      2, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, MANDATORY},
        {"frame",      "proto",      2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frame",      "ref_frame",  2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frame",      "prev_frame", 2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frame",      "columns",    2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frame",      "color",      2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frame",      "bytes",      2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frame",      "hidden",     2, JSMN_PRIMITIVE,    SHARKD_JSON_BOOLEAN,  OPTIONAL},
        {"frames",     "column*",    2, JSMN_UNDEFINED,    SHARKD_JSON_ANY,      OPTIONAL},
        {"frames",     "filter",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"frames",     "skip",       2, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, OPTIONAL},
        {"frames",     "limit",      2, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, OPTIONAL},
        {"frames",     "refs",       2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"intervals",  "interval",   2, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, OPTIONAL},
        {"intervals",  "filter",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "interval",   2, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, OPTIONAL},
        {"iograph",    "filter",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph0",     2, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {"iograph",    "graph1",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph2",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph3",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph4",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph5",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph6",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph7",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph8",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "graph9",     2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter0",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter1",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter2",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter3",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter4",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter5",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter6",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter7",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter8",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"iograph",    "filter9",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"load",       "file",       2, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {"setcomment", "frame",      2, JSMN_PRIMITIVE,    SHARKD_JSON_UINTEGER, MANDATORY},
        {"setcomment", "comment",    2, JSMN_STRING,       SHARKD_JSON_STRING,   OPTIONAL},
        {"setconf",    "name",       2, JSMN_STRING,       SHARKD_JSON_STRING,   MANDATORY},
        {"setconf",    "value",      2, JSMN_UNDEFINED,    SHARKD_JSON_ANY,      MANDATORY},
        {"tap",        "tap0",       2, JSMN_STRING,       SHARKD_JSON_STRING, MANDATORY},
        {"tap",        "tap1",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap2",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap3",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap4",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap5",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap6",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap7",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap8",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap9",       2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap10",      2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap11",      2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap12",      2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap13",      2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap14",      2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},
        {"tap",        "tap15",      2, JSMN_STRING,       SHARKD_JSON_STRING, OPTIONAL},

        // End of the name_array
        {NULL,         NULL,         0, JSMN_STRING,       SHARKD_ARRAY_END,   OPTIONAL},
    };

    rpcid = 0;

    /* sanity check, and split strings */
    if (count < 1 || tokens[0].type != JSMN_OBJECT)
    {
        sharkd_json_error(
                rpcid, -32600, NULL,
                "The request must an object"
                );
        return FALSE;
    }

    /* don't need [0] token */
    tokens++;
    count--;

    if (count & 1)
    {
        sharkd_json_error(
                rpcid, -32600, NULL,
                "The request must contain name/value pairs"
                );
        return FALSE;
    }

    for (i = 0; i < count; i += 2)
    {
        if (tokens[i].type != JSMN_STRING)
        {
            sharkd_json_error(
                    rpcid, -32600, NULL,
                    "Member names must be a string - member %d is not string", (i / 2) + 1
                    );
            return FALSE;
        }

        buf[tokens[i + 0].end] = '\0';
        buf[tokens[i + 1].end] = '\0';

        attr_name = &buf[tokens[i + 0].start];
        attr_value = &buf[tokens[i + 1].start];

        // we must get the id as soon as possible so that it's available in all future error messages
        if (!strcmp(attr_name, "id"))
        {
            if (!ws_strtou32(attr_value, NULL, &rpcid))
            {
                sharkd_json_error(
                        rpcid, -32600, NULL,
                        "The id value must be a positive integer"
                        );
                return FALSE;
            }
        }

        if (!strcmp(attr_name, "jsonrpc"))
        {
            if (strcmp(&buf[tokens[i + 1].start], "2.0"))
            {
                sharkd_json_error(
                        rpcid, -32600, NULL,
                        "Only JSON %s is supported", "2.0"
                        );
                return FALSE;
            }
        }

        /* unescape only value, as keys are simple strings */
        if (tokens[i + 1].type == JSMN_STRING && !json_decode_string_inplace(attr_value))
        {
            sharkd_json_error(
                    rpcid, -32600, NULL,
                    "Cannot unescape the value string of member %d", (i / 2) + 1
                    );
            return FALSE;
        }

        /* Confirm that the member is valid */
        gboolean match = FALSE;

        // We need to check root members (level 1) and parameters (level 2), hence the for loop.

        for (int level = 1; level < 3; level++)
        {
            size_t j = 0;

            while (name_array[j].value_type != SHARKD_ARRAY_END)  // iterate through the array until we hit the end
            {
                if (is_param_match(attr_name, name_array[j].name) && name_array[j].level == level)
                {
                    // We need to be sure the match is in the correct context
                    // i.e. is this a match for a root member (level 1) or for a parameter (level 2).

                    if (level == 1)
                    {
                        // need to guard against a parameter name matching a method name
                        if (method)
                        {
                            if (name_array[j].parent_ctx)
                            {
                                j++;
                                continue;
                            }

                            if (!strcmp(method, &buf[tokens[i + 0].start]))
                            {
                                j++;
                                continue;
                            }
                        }

                        match = TRUE;
                    }
                    else if (method)
                    {
                        if (level == 2 && !strcmp(name_array[j].parent_ctx, method))
                            match = TRUE;
                        else
                        {
                            j++;
                            continue;
                        }
                    }
                    else
                    {
                        j++;
                        continue;
                    }

                    // The match looks good, let's now check the data types

                    if (tokens[i + 1].type != name_array[j].type && name_array[j].type != SHARKD_JSON_ANY)
                    {
                        sharkd_json_error(
                                rpcid, -32600, NULL,
                                "The data type for member %s is not a valid", attr_name
                                );
                        return FALSE;
                    }
                    else if (name_array[j].type == JSMN_PRIMITIVE && name_array[j].value_type == SHARKD_JSON_UINTEGER)
                    {
                        guint32 temp;
                        if (!ws_strtou32(attr_value, NULL, &temp) || temp <= 0)
                        {
                            sharkd_json_error(
                                    rpcid, -32600, NULL,
                                    "The value for %s must be a positive integer", name_array[j].name
                                    );
                            return FALSE;
                        }
                    }
                    else if (name_array[j].type == JSMN_PRIMITIVE && name_array[j].value_type == SHARKD_JSON_BOOLEAN)
                    {
                        if (strcmp(attr_value, "true") && strcmp(attr_value, "false"))
                        {
                            sharkd_json_error(
                                    rpcid, -32600, NULL,
                                    "The value for %s must be a boolean (true or false)", name_array[j].name
                                    );
                            return FALSE;
                        }

                    }
                    break; // looks like a valid match
                }
                j++;
            }

            if (!strcmp(attr_name, "method"))
            {
                int k = 0;  // name array index
                // check that the request method is good
                while (name_array[k].value_type != SHARKD_ARRAY_END)
                {
                    if (name_array[k].parent_ctx)
                    {
                        if (!strcmp(attr_value, name_array[k].name) && !strcmp(name_array[k].parent_ctx, "method"))
                            method = attr_value;  // the method is valid
                    }

                    k++;
                }

                if (!method)
                {
                    sharkd_json_error(
                            rpcid, -32601, NULL,
                            "The method %s is not supported", attr_value
                            );
                    return FALSE;
                }
            }
        }

        if (!match)
        {
            sharkd_json_error(
                    rpcid, -32600, NULL,
                    "%s is not a valid member name", attr_name
                    );
            return FALSE;
        }
    }

    /* check for mandatory members */
    size_t j = 0;

    while (name_array[j].value_type != SHARKD_ARRAY_END)
    {
        if (name_array[j].is_mandatory && name_array[j].level == 1)
        {
            if (!json_find_attr(buf, tokens, count, name_array[j].name))
            {
                sharkd_json_error(
                        rpcid, -32600, NULL,
                        "Mandatory member %s is missing", name_array[j].name
                        );
                return FALSE;
            }
        }
        j++;
    }

    // check that the current request contains the mandatory parameters
    j = 0;

    while (name_array[j].value_type != SHARKD_ARRAY_END)
    {
        if (name_array[j].is_mandatory && name_array[j].level == 2 && !strcmp(method, name_array[j].parent_ctx))
        {
            if (!json_find_attr(buf, tokens, count, name_array[j].name))
            {
                sharkd_json_error(
                        rpcid, -32600, NULL,
                        "Mandatory parameter %s is missing", name_array[j].name
                        );
                return FALSE;
            }
        }
        j++;
    }


    // check that the parameters for the current request are valid for the method and that the data type for the value is valid

    return TRUE;
}

static void
sharkd_session_filter_free(gpointer data)
{
    struct sharkd_filter_item *l = (struct sharkd_filter_item *) data;

    g_free(l->filtered);
    g_free(l);
}

static const struct sharkd_filter_item *
sharkd_session_filter_data(const char *filter)
{
    struct sharkd_filter_item *l;

    l = (struct sharkd_filter_item *) g_hash_table_lookup(filter_table, filter);
    if (!l)
    {
        guint8 *filtered = NULL;

        int ret = sharkd_filter(filter, &filtered);

        if (ret == -1)
            return NULL;

        l = g_new(struct sharkd_filter_item, 1);
        l->filtered = filtered;

        g_hash_table_insert(filter_table, g_strdup(filter), l);
    }

    return l;
}

static gboolean
sharkd_rtp_match_init(rtpstream_id_t *id, const char *init_str)
{
    gboolean ret = FALSE;
    char **arr;
    guint32 tmp_addr_src, tmp_addr_dst;
    address tmp_src_addr, tmp_dst_addr;

    memset(id, 0, sizeof(*id));

    arr = g_strsplit(init_str, "_", 7); /* pass larger value, so we'll catch incorrect input :) */
    if (g_strv_length(arr) != 5)
        goto fail;

    /* TODO, for now only IPv4 */
    if (!get_host_ipaddr(arr[0], &tmp_addr_src))
        goto fail;

    if (!ws_strtou16(arr[1], NULL, &id->src_port))
        goto fail;

    if (!get_host_ipaddr(arr[2], &tmp_addr_dst))
        goto fail;

    if (!ws_strtou16(arr[3], NULL, &id->dst_port))
        goto fail;

    if (!ws_hexstrtou32(arr[4], NULL, &id->ssrc))
        goto fail;

    set_address(&tmp_src_addr, AT_IPv4, 4, &tmp_addr_src);
    copy_address(&id->src_addr, &tmp_src_addr);
    set_address(&tmp_dst_addr, AT_IPv4, 4, &tmp_addr_dst);
    copy_address(&id->dst_addr, &tmp_dst_addr);

    ret = TRUE;

fail:
    g_strfreev(arr);
    return ret;
}

static gboolean
sharkd_session_process_info_nstat_cb(const void *key, void *value, void *userdata _U_)
{
    stat_tap_table_ui *stat_tap = (stat_tap_table_ui *) value;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("name", stat_tap->title);
    sharkd_json_value_stringf("tap", "nstat:%s", (const char *) key);
    json_dumper_end_object(&dumper);

    return FALSE;
}

static gboolean
sharkd_session_process_info_conv_cb(const void* key, void* value, void* userdata _U_)
{
    struct register_ct *table = (struct register_ct *) value;

    const char *label = (const char *) key;

    if (get_conversation_packet_func(table))
    {
        json_dumper_begin_object(&dumper);
        sharkd_json_value_stringf("name", "Conversation List/%s", label);
        sharkd_json_value_stringf("tap", "conv:%s", label);
        json_dumper_end_object(&dumper);
    }

    if (get_hostlist_packet_func(table))
    {
        json_dumper_begin_object(&dumper);
        sharkd_json_value_stringf("name", "Endpoint/%s", label);
        sharkd_json_value_stringf("tap", "endpt:%s", label);
        json_dumper_end_object(&dumper);
    }
    return FALSE;
}

static gboolean
sharkd_session_seq_analysis_cb(const void *key, void *value, void *userdata _U_)
{
    register_analysis_t *analysis = (register_analysis_t *) value;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("name", sequence_analysis_get_ui_name(analysis));
    sharkd_json_value_stringf("tap", "seqa:%s", (const char *) key);
    json_dumper_end_object(&dumper);

    return FALSE;
}

static gboolean
sharkd_export_object_visit_cb(const void *key _U_, void *value, void *user_data _U_)
{
    register_eo_t *eo = (register_eo_t *) value;

    const int proto_id = get_eo_proto_id(eo);
    const char *filter = proto_get_protocol_filter_name(proto_id);
    const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("name", "Export Object/%s", label);
    sharkd_json_value_stringf("tap", "eo:%s", filter);
    json_dumper_end_object(&dumper);

    return FALSE;
}

static gboolean
sharkd_srt_visit_cb(const void *key _U_, void *value, void *user_data _U_)
{
    register_srt_t *srt = (register_srt_t *) value;

    const int proto_id = get_srt_proto_id(srt);
    const char *filter = proto_get_protocol_filter_name(proto_id);
    const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("name", "Service Response Time/%s", label);
    sharkd_json_value_stringf("tap", "srt:%s", filter);
    json_dumper_end_object(&dumper);

    return FALSE;
}

static gboolean
sharkd_rtd_visit_cb(const void *key _U_, void *value, void *user_data _U_)
{
    register_rtd_t *rtd = (register_rtd_t *) value;

    const int proto_id = get_rtd_proto_id(rtd);
    const char *filter = proto_get_protocol_filter_name(proto_id);
    const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("name", "Response Time Delay/%s", label);
    sharkd_json_value_stringf("tap", "rtd:%s", filter);
    json_dumper_end_object(&dumper);

    return FALSE;
}

static gboolean
sharkd_follower_visit_cb(const void *key _U_, void *value, void *user_data _U_)
{
    register_follow_t *follower = (register_follow_t *) value;

    const int proto_id = get_follow_proto_id(follower);
    const char *label  = proto_get_protocol_short_name(find_protocol_by_id(proto_id));
    const char *filter = label; /* correct: get_follow_by_name() is registered by short name */

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("name", "Follow/%s", label);
    sharkd_json_value_stringf("tap", "follow:%s", filter);
    json_dumper_end_object(&dumper);

    return FALSE;
}

/**
 * sharkd_session_process_info()
 *
 * Process info request
 *
 * Output object with attributes:
 *   (m) version - version number
 *
 *   (m) columns - available column formats, array of object with attributes:
 *                  'name'   - column name
 *                  'format' - column format-name
 *
 *   (m) stats   - available statistics, array of object with attributes:
 *                  'name' - statistic name
 *                  'tap'  - sharkd tap-name for statistic
 *
 *   (m) convs   - available conversation list, array of object with attributes:
 *                  'name' - conversation name
 *                  'tap'  - sharkd tap-name for conversation
 *
 *   (m) eo      - available export object list, array of object with attributes:
 *                  'name' - export object name
 *                  'tap'  - sharkd tap-name for eo
 *
 *   (m) srt     - available service response time list, array of object with attributes:
 *                  'name' - service response time name
 *                  'tap'  - sharkd tap-name for srt
 *
 *   (m) rtd     - available response time delay list, array of object with attributes:
 *                  'name' - response time delay name
 *                  'tap'  - sharkd tap-name for rtd
 *
 *   (m) seqa    - available sequence analysis (flow) list, array of object with attributes:
 *                  'name' - sequence analysis name
 *                  'tap'  - sharkd tap-name
 *
 *   (m) taps    - available taps, array of object with attributes:
 *                  'name' - tap name
 *                  'tap'  - sharkd tap-name
 *
 *   (m) follow  - available followers, array of object with attributes:
 *                  'name' - tap name
 *                  'tap'  - sharkd tap-name
 *
 *   (m) ftypes  - conversation table for FT_ number to string, array of FT_xxx strings.
 *
 *   (m) nstat   - available table-based taps, array of object with attributes:
 *                  'name' - tap name
 *                  'tap'  - sharkd tap-name
 *
 */
static void
sharkd_session_process_info(void)
{
    int i;

    sharkd_json_result_prologue(rpcid);

    sharkd_json_array_open("columns");
    for (i = 0; i < NUM_COL_FMTS; i++)
    {
        const char *col_format = col_format_to_string(i);
        const char *col_descr  = col_format_desc(i);

        json_dumper_begin_object(&dumper);
        sharkd_json_value_string("name", col_descr);
        sharkd_json_value_string("format", col_format);
        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    sharkd_json_array_open("stats");
    {
        GList *cfg_list = stats_tree_get_cfg_list();
        GList *l;

        for (l = cfg_list; l; l = l->next)
        {
            stats_tree_cfg *cfg = (stats_tree_cfg *) l->data;

            json_dumper_begin_object(&dumper);
            sharkd_json_value_string("name", cfg->name);
            sharkd_json_value_stringf("tap", "stat:%s", cfg->abbr);
            json_dumper_end_object(&dumper);
        }

        g_list_free(cfg_list);
    }
    sharkd_json_array_close();

    sharkd_json_array_open("ftypes");
    for (i = 0; i < FT_NUM_TYPES; i++)
        sharkd_json_value_string(NULL, ftype_name((ftenum_t) i));
    sharkd_json_array_close();

    sharkd_json_value_string("version", get_ws_vcs_version_info_short());

    sharkd_json_array_open("nstat");
    i = 0;
    stat_tap_iterate_tables(sharkd_session_process_info_nstat_cb, &i);
    sharkd_json_array_close();

    sharkd_json_array_open("convs");
    i = 0;
    conversation_table_iterate_tables(sharkd_session_process_info_conv_cb, &i);
    sharkd_json_array_close();

    sharkd_json_array_open("seqa");
    i = 0;
    sequence_analysis_table_iterate_tables(sharkd_session_seq_analysis_cb, &i);
    sharkd_json_array_close();

    sharkd_json_array_open("taps");
    {
        json_dumper_begin_object(&dumper);
        sharkd_json_value_string("name", "RTP streams");
        sharkd_json_value_string("tap", "rtp-streams");
        json_dumper_end_object(&dumper);

        json_dumper_begin_object(&dumper);
        sharkd_json_value_string("name", "Expert Information");
        sharkd_json_value_string("tap", "expert");
        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    sharkd_json_array_open("eo");
    i = 0;
    eo_iterate_tables(sharkd_export_object_visit_cb, &i);
    sharkd_json_array_close();

    sharkd_json_array_open("srt");
    i = 0;
    srt_table_iterate_tables(sharkd_srt_visit_cb, &i);
    sharkd_json_array_close();

    sharkd_json_array_open("rtd");
    i = 0;
    rtd_table_iterate_tables(sharkd_rtd_visit_cb, &i);
    sharkd_json_array_close();

    sharkd_json_array_open("follow");
    i = 0;
    follow_iterate_followers(sharkd_follower_visit_cb, &i);
    sharkd_json_array_close();

    sharkd_json_result_epilogue();
}

/**
 * sharkd_session_process_load()
 *
 * Process load request
 *
 * Input:
 *   (m) file - file to be loaded
 *
 * Output object with attributes:
 *   (m) err - error code
 */
static void
sharkd_session_process_load(const char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_file = json_find_attr(buf, tokens, count, "file");
    int err = 0;

    if (!tok_file)
        return;

    fprintf(stderr, "load: filename=%s\n", tok_file);

    if (sharkd_cf_open(tok_file, WTAP_TYPE_AUTO, FALSE, &err) != CF_OK)
    {
        sharkd_json_error(
                rpcid, -2001, NULL,
                "Unable to open the file"
                );
        return;
    }

    TRY
    {
        err = sharkd_load_cap_file();
    }
    CATCH(OutOfMemoryError)
    {
        sharkd_json_error(
                rpcid, -32603, NULL,
                "Load failed, out of memory"
                );
        fprintf(stderr, "load: OutOfMemoryError\n");
        err = ENOMEM;
    }
    ENDTRY;

    if (err == 0)
        sharkd_json_simple_ok(rpcid);
}

/**
 * sharkd_session_process_status()
 *
 * Process status request
 *
 * Output object with attributes:
 *   (m) frames   - count of currently loaded frames
 *   (m) duration - time difference between time of first frame, and last loaded frame
 *   (o) filename - capture filename
 *   (o) filesize - capture filesize
 */
static void
sharkd_session_process_status(void)
{
    sharkd_json_result_prologue(rpcid);

    sharkd_json_value_anyf("frames", "%u", cfile.count);
    sharkd_json_value_anyf("duration", "%.9f", nstime_to_sec(&cfile.elapsed_time));

    if (cfile.filename)
    {
        char *name = g_path_get_basename(cfile.filename);

        sharkd_json_value_string("filename", name);
        g_free(name);
    }

    if (cfile.provider.wth)
    {
        gint64 file_size = wtap_file_size(cfile.provider.wth, NULL);

        if (file_size > 0)
            sharkd_json_value_anyf("filesize", "%" PRId64, file_size);
    }

    sharkd_json_result_epilogue();
}

struct sharkd_analyse_data
{
    GHashTable *protocols_set;
    nstime_t *first_time;
    nstime_t *last_time;
};

static void
sharkd_session_process_analyse_cb(epan_dissect_t *edt, proto_tree *tree _U_,
        struct epan_column_info *cinfo _U_, const GSList *data_src _U_, void *data)
{
    struct sharkd_analyse_data *analyser = (struct sharkd_analyse_data *) data;
    packet_info *pi = &edt->pi;
    frame_data *fdata = pi->fd;

    if (analyser->first_time == NULL || nstime_cmp(&fdata->abs_ts, analyser->first_time) < 0)
        analyser->first_time = &fdata->abs_ts;

    if (analyser->last_time == NULL || nstime_cmp(&fdata->abs_ts, analyser->last_time) > 0)
        analyser->last_time = &fdata->abs_ts;

    if (pi->layers)
    {
        wmem_list_frame_t *frame;

        for (frame = wmem_list_head(pi->layers); frame; frame = wmem_list_frame_next(frame))
        {
            int proto_id = GPOINTER_TO_UINT(wmem_list_frame_data(frame));

            if (!g_hash_table_lookup_extended(analyser->protocols_set, GUINT_TO_POINTER(proto_id), NULL, NULL))
            {
                g_hash_table_insert(analyser->protocols_set, GUINT_TO_POINTER(proto_id), GUINT_TO_POINTER(proto_id));
                sharkd_json_value_string(NULL, proto_get_protocol_filter_name(proto_id));
            }
        }
    }

}

/**
 * sharkd_session_process_status()
 *
 * Process analyse request
 *
 * Output object with attributes:
 *   (m) frames  - count of currently loaded frames
 *   (m) protocols - protocol list
 *   (m) first     - earliest frame time
 *   (m) last      - latest frame time
 */
static void
sharkd_session_process_analyse(void)
{
    struct sharkd_analyse_data analyser;
    wtap_rec rec; /* Record metadata */
    Buffer rec_buf;   /* Record data */

    analyser.first_time = NULL;
    analyser.last_time  = NULL;
    analyser.protocols_set = g_hash_table_new(NULL /* g_direct_hash() */, NULL /* g_direct_equal */);

    sharkd_json_result_prologue(rpcid);

    sharkd_json_value_anyf("frames", "%u", cfile.count);

    sharkd_json_array_open("protocols");

    wtap_rec_init(&rec);
    ws_buffer_init(&rec_buf, 1514);

    for (guint32 framenum = 1; framenum <= cfile.count; framenum++)
    {
        enum dissect_request_status status;
        int err;
        gchar *err_info;

        status = sharkd_dissect_request(framenum,
                (framenum != 1) ? 1 : 0, framenum - 1,
                &rec, &rec_buf, NULL, SHARKD_DISSECT_FLAG_NULL,
                &sharkd_session_process_analyse_cb, &analyser,
                &err, &err_info);
        switch (status) {

            case DISSECT_REQUEST_SUCCESS:
                break;

            case DISSECT_REQUEST_NO_SUCH_FRAME:
                /* XXX - report the error. */
                break;

            case DISSECT_REQUEST_READ_ERROR:
                /*
                 * Free up the error string.
                 * XXX - report the error.
                 */
                g_free(err_info);
                break;
        }
    }

    sharkd_json_array_close();

    if (analyser.first_time)
        sharkd_json_value_anyf("first", "%.9f", nstime_to_sec(analyser.first_time));

    if (analyser.last_time)
        sharkd_json_value_anyf("last", "%.9f", nstime_to_sec(analyser.last_time));

    sharkd_json_result_epilogue();

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&rec_buf);

    g_hash_table_destroy(analyser.protocols_set);
}

static column_info *
sharkd_session_create_columns(column_info *cinfo, const char *buf, const jsmntok_t *tokens, int count)
{
    const char *columns_custom[32];
    guint16 columns_fmt[32];
    gint16 columns_occur[32];

    int i, cols;

    for (i = 0; i < 32; i++)
    {
        const char *tok_column;
        char tok_column_name[64];
        char *custom_sepa;

        snprintf(tok_column_name, sizeof(tok_column_name), "column%d", i);
        tok_column = json_find_attr(buf, tokens, count, tok_column_name);
        if (tok_column == NULL)
            break;

        columns_custom[i] = NULL;
        columns_occur[i] = 0;

        if ((custom_sepa = strchr(tok_column, ':')))
        {
            *custom_sepa = '\0'; /* XXX, C abuse: discarding-const */

            columns_fmt[i] = COL_CUSTOM;
            columns_custom[i] = tok_column;

            if (!ws_strtoi16(custom_sepa + 1, NULL, &columns_occur[i]))
                return NULL;
        }
        else
        {
            if (!ws_strtou16(tok_column, NULL, &columns_fmt[i]))
                return NULL;

            if (columns_fmt[i] >= NUM_COL_FMTS)
                return NULL;

            /* if custom, that it shouldn't be just custom number -> error */
            if (columns_fmt[i] == COL_CUSTOM)
                return NULL;
        }
    }

    cols = i;

    col_setup(cinfo, cols);

    for (i = 0; i < cols; i++)
    {
        col_item_t *col_item = &cinfo->columns[i];

        col_item->col_fmt = columns_fmt[i];
        col_item->col_title = NULL; /* no need for title */

        if (col_item->col_fmt == COL_CUSTOM)
        {
            col_item->col_custom_fields = g_strdup(columns_custom[i]);
            col_item->col_custom_occurrence = columns_occur[i];
        }

        col_item->col_fence = 0;
    }

    col_finalize(cinfo);

    return cinfo;
}

static void
sharkd_session_process_frames_cb(epan_dissect_t *edt, proto_tree *tree _U_,
        struct epan_column_info *cinfo, const GSList *data_src _U_, void *data _U_)
{
    packet_info *pi = &edt->pi;
    frame_data *fdata = pi->fd;
    wtap_block_t pkt_block = NULL;
    char *comment;

    json_dumper_begin_object(&dumper);

    sharkd_json_array_open("c");
    for (int col = 0; col < cinfo->num_cols; ++col)
    {
        const col_item_t *col_item = &cinfo->columns[col];

        sharkd_json_value_string(NULL, col_item->col_data);
    }
    sharkd_json_array_close();

    sharkd_json_value_anyf("num", "%u", pi->num);

    /*
     * Get the block for this record, if it has one.
     */
    if (fdata->has_modified_block)
        pkt_block = sharkd_get_modified_block(fdata);
    else
        pkt_block = pi->rec->block;

    /*
     * Does this record have any comments?
     */
    if (pkt_block != NULL &&
            WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, 0, &comment))
        sharkd_json_value_anyf("ct", "true");

    if (fdata->ignored)
        sharkd_json_value_anyf("i", "true");

    if (fdata->marked)
        sharkd_json_value_anyf("m", "true");

    if (fdata->color_filter)
    {
        sharkd_json_value_stringf("bg", "%x", color_t_to_rgb(&fdata->color_filter->bg_color));
        sharkd_json_value_stringf("fg", "%x", color_t_to_rgb(&fdata->color_filter->fg_color));
    }

    json_dumper_end_object(&dumper);
}

/**
 * sharkd_session_process_frames()
 *
 * Process frames request
 *
 * Input:
 *   (o) column0...columnXX - requested columns either number in range [0..NUM_COL_FMTS), or custom (syntax <dfilter>:<occurence>).
 *                            If column0 is not specified default column set will be used.
 *   (o) filter - filter to be used
 *   (o) skip=N   - skip N frames
 *   (o) limit=N  - show only N frames
 *   (o) refs  - list (comma separated) with sorted time reference frame numbers.
 *
 * Output array of frames with attributes:
 *   (m) c   - array of column data
 *   (m) num - frame number
 *   (o) i   - if frame is ignored
 *   (o) m   - if frame is marked
 *   (o) ct  - if frame is commented
 *   (o) bg  - color filter - background color in hex
 *   (o) fg  - color filter - foreground color in hex
 */
static void
sharkd_session_process_frames(const char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_filter = json_find_attr(buf, tokens, count, "filter");
    const char *tok_column = json_find_attr(buf, tokens, count, "column0");
    const char *tok_skip   = json_find_attr(buf, tokens, count, "skip");
    const char *tok_limit  = json_find_attr(buf, tokens, count, "limit");
    const char *tok_refs   = json_find_attr(buf, tokens, count, "refs");

    const guint8 *filter_data = NULL;

    guint32 next_ref_frame = G_MAXUINT32;
    guint32 skip;
    guint32 limit;

    wtap_rec rec; /* Record metadata */
    Buffer rec_buf;   /* Record data */
    column_info *cinfo = &cfile.cinfo;
    column_info user_cinfo;

    if (tok_column)
    {
        memset(&user_cinfo, 0, sizeof(user_cinfo));
        cinfo = sharkd_session_create_columns(&user_cinfo, buf, tokens, count);
        if (!cinfo)
        {
            sharkd_json_error(
                    rpcid, -13001, NULL,
                    "Column definition invalid - note column 6 requires a custom definition"
                    );
            return;
        }
    }

    if (tok_filter)
    {
        const struct sharkd_filter_item *filter_item;

        filter_item = sharkd_session_filter_data(tok_filter);
        if (!filter_item)
        {
            sharkd_json_error(
                    rpcid, -13002, NULL,
                    "Filter expression invalid"
                    );
            return;
        }

        filter_data = filter_item->filtered;
    }

    skip = 0;
    if (tok_skip)
    {
        if (!ws_strtou32(tok_skip, NULL, &skip))
            return;
    }

    limit = 0;
    if (tok_limit)
    {
        if (!ws_strtou32(tok_limit, NULL, &limit))
            return;
    }

    if (tok_refs)
    {
        if (!ws_strtou32(tok_refs, &tok_refs, &next_ref_frame))
            return;
    }

    sharkd_json_result_array_prologue(rpcid);

    wtap_rec_init(&rec);
    ws_buffer_init(&rec_buf, 1514);

    for (guint32 framenum = 1; framenum <= cfile.count; framenum++)
    {
        frame_data *fdata;
        enum dissect_request_status status;
        int err;
        gchar *err_info;

        if (filter_data && !(filter_data[framenum / 8] & (1 << (framenum % 8))))
            continue;

        if (skip)
        {
            skip--;
            continue;
        }

        if (tok_refs)
        {
            if (framenum >= next_ref_frame)
            {
                if (*tok_refs != ',')
                    next_ref_frame = G_MAXUINT32;

                while (*tok_refs == ',' && framenum >= next_ref_frame)
                {
                    if (!ws_strtou32(tok_refs + 1, &tok_refs, &next_ref_frame))
                    {
                        fprintf(stderr, "sharkd_session_process_frames() wrong format for refs: %s\n", tok_refs);
                        break;
                    }
                }

                if (*tok_refs == '\0' && framenum >= next_ref_frame)
                {
                    next_ref_frame = G_MAXUINT32;
                }
            }
        }

        fdata = sharkd_get_frame(framenum);
        status = sharkd_dissect_request(framenum,
                (framenum != 1) ? 1 : 0, framenum - 1,
                &rec, &rec_buf, cinfo,
                (fdata->color_filter == NULL) ? SHARKD_DISSECT_FLAG_COLOR : SHARKD_DISSECT_FLAG_NULL,
                &sharkd_session_process_frames_cb, NULL,
                &err, &err_info);
        switch (status) {

            case DISSECT_REQUEST_SUCCESS:
                break;

            case DISSECT_REQUEST_NO_SUCH_FRAME:
                /* XXX - report the error. */
                break;

            case DISSECT_REQUEST_READ_ERROR:
                /*
                 * Free up the error string.
                 * XXX - report the error.
                 */
                g_free(err_info);
                break;
        }

        if (limit && --limit == 0)
            break;
    }
    sharkd_json_result_array_epilogue();

    if (cinfo != &cfile.cinfo)
        col_cleanup(cinfo);

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&rec_buf);
}

static void
sharkd_session_process_tap_stats_node_cb(const stat_node *n)
{
    stat_node *node;

    sharkd_json_array_open(NULL);
    for (node = n->children; node; node = node->next)
    {
        json_dumper_begin_object(&dumper);

        /* code based on stats_tree_get_values_from_node() */
        sharkd_json_value_string("name", node->name);
        sharkd_json_value_anyf("count", "%d", node->counter);
        if (node->counter && ((node->st_flags & ST_FLG_AVERAGE) || node->rng))
        {
            switch(node->datatype)
            {
                case STAT_DT_INT:
                    sharkd_json_value_anyf("avg", "%.2f", ((float)node->total.int_total) / node->counter);
                    sharkd_json_value_anyf("min", "%d", node->minvalue.int_min);
                    sharkd_json_value_anyf("max", "%d", node->maxvalue.int_max);
                    break;
                case STAT_DT_FLOAT:
                    sharkd_json_value_anyf("avg", "%.2f", node->total.float_total / node->counter);
                    sharkd_json_value_anyf("min", "%f", node->minvalue.float_min);
                    sharkd_json_value_anyf("max", "%f", node->maxvalue.float_max);
                    break;
            }
        }

        if (node->st->elapsed)
            sharkd_json_value_anyf("rate", "%.4f", ((float)node->counter) / node->st->elapsed);

        if (node->parent && node->parent->counter)
            sharkd_json_value_anyf("perc", "%.2f", (node->counter * 100.0) / node->parent->counter);
        else if (node->parent == &(node->st->root))
            sharkd_json_value_anyf("perc", "100");

        if (prefs.st_enable_burstinfo && node->max_burst)
        {
            if (prefs.st_burst_showcount)
                sharkd_json_value_anyf("burstcount", "%d", node->max_burst);
            else
                sharkd_json_value_anyf("burstrate", "%.4f", ((double)node->max_burst) / prefs.st_burst_windowlen);

            sharkd_json_value_anyf("bursttime", "%.3f", (node->burst_time / 1000.0));
        }

        if (node->children)
        {
            sharkd_json_value_anyf("sub", NULL);
            sharkd_session_process_tap_stats_node_cb(node);
        }
        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();
}

/**
 * sharkd_session_process_tap_stats_cb()
 *
 * Output stats tap:
 *
 *   (m) tap        - tap name
 *   (m) type:stats - tap output type
 *   (m) name       - stat name
 *   (m) stats      - array of object with attributes:
 *                  (m) name       - stat item name
 *                  (m) count      - stat item counter
 *                  (o) avg        - stat item averange value
 *                  (o) min        - stat item min value
 *                  (o) max        - stat item max value
 *                  (o) rate       - stat item rate value (ms)
 *                  (o) perc       - stat item percentage
 *                  (o) burstrate  - stat item burst rate
 *                  (o) burstcount - stat item burst count
 *                  (o) burstttme  - stat item burst start
 *                  (o) sub        - array of object with attributes like in stats node.
 */
static void
sharkd_session_process_tap_stats_cb(void *psp)
{
    stats_tree *st = (stats_tree *) psp;

    json_dumper_begin_object(&dumper);

    sharkd_json_value_stringf("tap", "stats:%s", st->cfg->abbr);
    sharkd_json_value_string("type", "stats");
    sharkd_json_value_string("name", st->cfg->name);

    sharkd_json_value_anyf("stats", NULL);
    sharkd_session_process_tap_stats_node_cb(&st->root);

    json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_stats_cb(void *psp)
{
    stats_tree *st = (stats_tree *) psp;

    stats_tree_free(st);
}

struct sharkd_expert_tap
{
    GSList *details;
    GStringChunk *text;
};

/**
 * sharkd_session_process_tap_expert_cb()
 *
 * Output expert tap:
 *
 *   (m) tap         - tap name
 *   (m) type:expert - tap output type
 *   (m) details     - array of object with attributes:
 *                  (m) f - frame number, which generated expert information
 *                  (o) s - severity
 *                  (o) g - group
 *                  (m) m - expert message
 *                  (o) p - protocol
 */
static void
sharkd_session_process_tap_expert_cb(void *tapdata)
{
    struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *) tapdata;
    GSList *list;

    json_dumper_begin_object(&dumper);

    sharkd_json_value_string("tap", "expert");
    sharkd_json_value_string("type", "expert");

    sharkd_json_array_open("details");
    for (list = etd->details; list; list = list->next)
    {
        expert_info_t *ei = (expert_info_t *) list->data;
        const char *tmp;

        json_dumper_begin_object(&dumper);

        sharkd_json_value_anyf("f", "%u", ei->packet_num);

        tmp = try_val_to_str(ei->severity, expert_severity_vals);
        if (tmp)
            sharkd_json_value_string("s", tmp);

        tmp = try_val_to_str(ei->group, expert_group_vals);
        if (tmp)
            sharkd_json_value_string("g", tmp);

        sharkd_json_value_string("m", ei->summary);

        if (ei->protocol)
            sharkd_json_value_string("p", ei->protocol);

        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

static tap_packet_status
sharkd_session_packet_tap_expert_cb(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer, tap_flags_t flags _U_)
{
    struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *) tapdata;
    const expert_info_t *ei       = (const expert_info_t *) pointer;
    expert_info_t *ei_copy;

    if (ei == NULL)
        return TAP_PACKET_DONT_REDRAW;

    ei_copy = g_new(expert_info_t, 1);
    /* Note: this is a shallow copy */
    *ei_copy = *ei;

    /* ei->protocol, ei->summary might be allocated in packet scope, make a copy. */
    ei_copy->protocol = g_string_chunk_insert_const(etd->text, ei_copy->protocol);
    ei_copy->summary  = g_string_chunk_insert_const(etd->text, ei_copy->summary);

    etd->details = g_slist_prepend(etd->details, ei_copy);

    return TAP_PACKET_REDRAW;
}

static void
sharkd_session_free_tap_expert_cb(void *tapdata)
{
    struct sharkd_expert_tap *etd = (struct sharkd_expert_tap *) tapdata;

    g_slist_free_full(etd->details, g_free);
    g_string_chunk_free(etd->text);
    g_free(etd);
}

/**
 * sharkd_session_process_tap_flow_cb()
 *
 * Output flow tap:
 *   (m) tap         - tap name
 *   (m) type:flow   - tap output type
 *   (m) nodes       - array of strings with node address
 *   (m) flows       - array of object with attributes:
 *                  (m) t  - frame time string
 *                  (m) n  - array of two numbers with source node index and destination node index
 *                  (m) pn - array of two numbers with source and destination port
 *                  (o) c  - comment
 */
static void
sharkd_session_process_tap_flow_cb(void *tapdata)
{
    seq_analysis_info_t *graph_analysis = (seq_analysis_info_t *) tapdata;
    GList *flow_list;
    guint i;

    sequence_analysis_get_nodes(graph_analysis);

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("tap", "seqa:%s", graph_analysis->name);
    sharkd_json_value_string("type", "flow");

    sharkd_json_array_open("nodes");
    for (i = 0; i < graph_analysis->num_nodes; i++)
    {
        char *addr_str;

        addr_str = address_to_display(NULL, &(graph_analysis->nodes[i]));
        sharkd_json_value_string(NULL, addr_str);
        wmem_free(NULL, addr_str);
    }
    sharkd_json_array_close();

    sharkd_json_array_open("flows");
    flow_list = g_queue_peek_nth_link(graph_analysis->items, 0);
    while (flow_list)
    {
        seq_analysis_item_t *sai = (seq_analysis_item_t *) flow_list->data;

        flow_list = g_list_next(flow_list);

        if (!sai->display)
            continue;

        json_dumper_begin_object(&dumper);

        sharkd_json_value_string("t", sai->time_str);
        sharkd_json_value_anyf("n", "[%u,%u]", sai->src_node, sai->dst_node);
        sharkd_json_value_anyf("pn", "[%u,%u]", sai->port_src, sai->port_dst);

        if (sai->comment)
            sharkd_json_value_string("c", sai->comment);

        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_flow_cb(void *tapdata)
{
    seq_analysis_info_t *graph_analysis = (seq_analysis_info_t *) tapdata;

    sequence_analysis_info_free(graph_analysis);
}

struct sharkd_conv_tap_data
{
    const char *type;
    conv_hash_t hash;
    gboolean resolve_name;
    gboolean resolve_port;
};

static gboolean
sharkd_session_geoip_addr(address *addr, const char *suffix)
{
    const mmdb_lookup_t *lookup = NULL;
    gboolean with_geoip = FALSE;
    char json_key[64];

    if (addr->type == AT_IPv4)
    {
        const ws_in4_addr *ip4 = (const ws_in4_addr *) addr->data;

        lookup = maxmind_db_lookup_ipv4(ip4);
    }
    else if (addr->type == AT_IPv6)
    {
        const ws_in6_addr *ip6 = (const ws_in6_addr *) addr->data;

        lookup = maxmind_db_lookup_ipv6(ip6);
    }

    if (!lookup || !lookup->found)
        return FALSE;

    if (lookup->country)
    {
        snprintf(json_key, sizeof(json_key), "geoip_country%s", suffix);
        sharkd_json_value_string(json_key, lookup->country);
        with_geoip = TRUE;
    }

    if (lookup->country_iso)
    {
        snprintf(json_key, sizeof(json_key), "geoip_country_iso%s", suffix);
        sharkd_json_value_string(json_key, lookup->country_iso);
        with_geoip = TRUE;
    }

    if (lookup->city)
    {
        snprintf(json_key, sizeof(json_key), "geoip_city%s", suffix);
        sharkd_json_value_string(json_key, lookup->city);
        with_geoip = TRUE;
    }

    if (lookup->as_org)
    {
        snprintf(json_key, sizeof(json_key), "geoip_as_org%s", suffix);
        sharkd_json_value_string(json_key, lookup->as_org);
        with_geoip = TRUE;
    }

    if (lookup->as_number > 0)
    {
        snprintf(json_key, sizeof(json_key), "geoip_as%s", suffix);
        sharkd_json_value_anyf(json_key, "%u", lookup->as_number);
        with_geoip = TRUE;
    }

    if (lookup->latitude >= -90.0 && lookup->latitude <= 90.0)
    {
        snprintf(json_key, sizeof(json_key), "geoip_lat%s", suffix);
        sharkd_json_value_anyf(json_key, "%f", lookup->latitude);
        with_geoip = TRUE;
    }

    if (lookup->longitude >= -180.0 && lookup->longitude <= 180.0)
    {
        snprintf(json_key, sizeof(json_key), "geoip_lon%s", suffix);
        sharkd_json_value_anyf(json_key, "%f", lookup->longitude);
        with_geoip = TRUE;
    }

    return with_geoip;
}

struct sharkd_analyse_rtp_items
{
    guint32 frame_num;
    guint32 sequence_num;

    double delta;
    double jitter;
    double skew;
    double bandwidth;
    gboolean marker;

    double arrive_offset;

    /* from tap_rtp_stat_t */
    guint32 flags;
    guint16 pt;
};

struct sharkd_analyse_rtp
{
    const char *tap_name;
    rtpstream_id_t id;

    GSList *packets;
    double start_time;
    tap_rtp_stat_t statinfo;
};

static void
sharkd_session_process_tap_rtp_free_cb(void *tapdata)
{
    struct sharkd_analyse_rtp *rtp_req = (struct sharkd_analyse_rtp *) tapdata;

    g_slist_free_full(rtp_req->packets, g_free);
    g_free(rtp_req);
}

static tap_packet_status
sharkd_session_packet_tap_rtp_analyse_cb(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *pointer, tap_flags_t flags _U_)
{
    struct sharkd_analyse_rtp *rtp_req = (struct sharkd_analyse_rtp *) tapdata;
    const struct _rtp_info *rtp_info = (const struct _rtp_info *) pointer;

    if (rtpstream_id_equal_pinfo_rtp_info(&rtp_req->id, pinfo, rtp_info))
    {
        tap_rtp_stat_t *statinfo = &(rtp_req->statinfo);
        struct sharkd_analyse_rtp_items *item;

        rtppacket_analyse(statinfo, pinfo, rtp_info);

        item = g_new(struct sharkd_analyse_rtp_items, 1);

        if (!rtp_req->packets)
            rtp_req->start_time = nstime_to_sec(&pinfo->abs_ts);

        item->frame_num    = pinfo->num;
        item->sequence_num = rtp_info->info_seq_num;
        item->delta        = (statinfo->flags & STAT_FLAG_FIRST) ? 0.0 : statinfo->delta;
        item->jitter       = (statinfo->flags & STAT_FLAG_FIRST) ? 0.0 : statinfo->jitter;
        item->skew         = (statinfo->flags & STAT_FLAG_FIRST) ? 0.0 : statinfo->skew;
        item->bandwidth    = statinfo->bandwidth;
        item->marker       = rtp_info->info_marker_set ? TRUE : FALSE;
        item->arrive_offset= nstime_to_sec(&pinfo->abs_ts) - rtp_req->start_time;

        item->flags = statinfo->flags;
        item->pt    = statinfo->pt;

        /* XXX, O(n) optimize */
        rtp_req->packets = g_slist_append(rtp_req->packets, item);
    }

    return TAP_PACKET_REDRAW;
}

/**
 * sharkd_session_process_tap_rtp_analyse_cb()
 *
 * Output rtp analyse tap:
 *   (m) tap   - tap name
 *   (m) type  - tap output type
 *   (m) ssrc         - RTP SSRC
 *   (m) max_delta    - Max delta (ms)
 *   (m) max_delta_nr - Max delta packet #
 *   (m) max_jitter   - Max jitter (ms)
 *   (m) mean_jitter  - Mean jitter (ms)
 *   (m) max_skew     - Max skew (ms)
 *   (m) total_nr     - Total number of RTP packets
 *   (m) seq_err      - Number of sequence errors
 *   (m) duration     - Duration (ms)
 *   (m) items      - array of object with attributes:
 *                  (m) f    - frame number
 *                  (m) o    - arrive offset
 *                  (m) sn   - sequence number
 *                  (m) d    - delta
 *                  (m) j    - jitter
 *                  (m) sk   - skew
 *                  (m) bw   - bandwidth
 *                  (o) s    - status string
 *                  (o) t    - status type
 *                  (o) mark - rtp mark
 */
static void
sharkd_session_process_tap_rtp_analyse_cb(void *tapdata)
{
    const int RTP_TYPE_CN       = 1;
    const int RTP_TYPE_ERROR    = 2;
    const int RTP_TYPE_WARN     = 3;
    const int RTP_TYPE_PT_EVENT = 4;

    const struct sharkd_analyse_rtp *rtp_req = (struct sharkd_analyse_rtp *) tapdata;
    const tap_rtp_stat_t *statinfo = &rtp_req->statinfo;

    GSList *l;

    json_dumper_begin_object(&dumper);

    sharkd_json_value_string("tap", rtp_req->tap_name);
    sharkd_json_value_string("type", "rtp-analyse");
    sharkd_json_value_anyf("ssrc", "%u", rtp_req->id.ssrc);

    sharkd_json_value_anyf("max_delta", "%f", statinfo->max_delta);
    sharkd_json_value_anyf("max_delta_nr", "%u", statinfo->max_nr);
    sharkd_json_value_anyf("max_jitter", "%f", statinfo->max_jitter);
    sharkd_json_value_anyf("mean_jitter", "%f", statinfo->mean_jitter);
    sharkd_json_value_anyf("max_skew", "%f", statinfo->max_skew);
    sharkd_json_value_anyf("total_nr", "%u", statinfo->total_nr);
    sharkd_json_value_anyf("seq_err", "%u", statinfo->sequence);
    sharkd_json_value_anyf("duration", "%f", statinfo->time - statinfo->start_time);

    sharkd_json_array_open("items");
    for (l = rtp_req->packets; l; l = l->next)
    {
        struct sharkd_analyse_rtp_items *item = (struct sharkd_analyse_rtp_items *) l->data;

        json_dumper_begin_object(&dumper);

        sharkd_json_value_anyf("f", "%u", item->frame_num);
        sharkd_json_value_anyf("o", "%.9f", item->arrive_offset);
        sharkd_json_value_anyf("sn", "%u", item->sequence_num);
        sharkd_json_value_anyf("d", "%.2f", item->delta);
        sharkd_json_value_anyf("j", "%.2f", item->jitter);
        sharkd_json_value_anyf("sk", "%.2f", item->skew);
        sharkd_json_value_anyf("bw", "%.2f", item->bandwidth);

        if (item->pt == PT_CN)
        {
            sharkd_json_value_string("s", "Comfort noise (PT=13, RFC 3389)");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_CN);
        }
        else if (item->pt == PT_CN_OLD)
        {
            sharkd_json_value_string("s", "Comfort noise (PT=19, reserved)");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_CN);
        }
        else if (item->flags & STAT_FLAG_WRONG_SEQ)
        {
            sharkd_json_value_string("s", "Wrong sequence number");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_ERROR);
        }
        else if (item->flags & STAT_FLAG_DUP_PKT)
        {
            sharkd_json_value_string("s", "Suspected duplicate (MAC address) only delta time calculated");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_WARN);
        }
        else if (item->flags & STAT_FLAG_REG_PT_CHANGE)
        {
            sharkd_json_value_stringf("s", "Payload changed to PT=%u%s",
                    item->pt,
                    (item->flags & STAT_FLAG_PT_T_EVENT) ? " telephone/event" : "");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_WARN);
        }
        else if (item->flags & STAT_FLAG_WRONG_TIMESTAMP)
        {
            sharkd_json_value_string("s", "Incorrect timestamp");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_WARN);
        }
        else if ((item->flags & STAT_FLAG_PT_CHANGE)
                &&  !(item->flags & STAT_FLAG_FIRST)
                &&  !(item->flags & STAT_FLAG_PT_CN)
                &&  (item->flags & STAT_FLAG_FOLLOW_PT_CN)
                &&  !(item->flags & STAT_FLAG_MARKER))
        {
            sharkd_json_value_string("s", "Marker missing?");
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_WARN);
        }
        else if (item->flags & STAT_FLAG_PT_T_EVENT)
        {
            sharkd_json_value_stringf("s", "PT=%u telephone/event", item->pt);
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_PT_EVENT);
        }
        else if (item->flags & STAT_FLAG_MARKER)
        {
            sharkd_json_value_anyf("t", "%d", RTP_TYPE_WARN);
        }

        if (item->marker)
            sharkd_json_value_anyf("mark", "1");

        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

/**
 * sharkd_session_process_tap_conv_cb()
 *
 * Output conv tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) proto      - protocol short name
 *   (o) filter     - filter string
 *   (o) geoip      - whether GeoIP information is available, boolean
 *
 *   (o) convs      - array of object with attributes:
 *                  (m) saddr - source address
 *                  (m) daddr - destination address
 *                  (o) sport - source port
 *                  (o) dport - destination port
 *                  (m) txf   - TX frame count
 *                  (m) txb   - TX bytes
 *                  (m) rxf   - RX frame count
 *                  (m) rxb   - RX bytes
 *                  (m) start - (relative) first packet time
 *                  (m) stop  - (relative) last packet time
 *                  (o) filter - conversation filter
 *
 *   (o) hosts      - array of object with attributes:
 *                  (m) host - host address
 *                  (o) port - host port
 *                  (m) txf  - TX frame count
 *                  (m) txb  - TX bytes
 *                  (m) rxf  - RX frame count
 *                  (m) rxb  - RX bytes
 */
static void
sharkd_session_process_tap_conv_cb(void *arg)
{
    conv_hash_t *hash = (conv_hash_t *) arg;
    const struct sharkd_conv_tap_data *iu = (struct sharkd_conv_tap_data *) hash->user_data;
    const char *proto;
    int proto_with_port;
    guint i;

    int with_geoip = 0;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("tap", iu->type);

    if (!strncmp(iu->type, "conv:", 5))
    {
        sharkd_json_value_string("type", "conv");
        sharkd_json_array_open("convs");
        proto = iu->type + 5;
    }
    else if (!strncmp(iu->type, "endpt:", 6))
    {
        sharkd_json_value_string("type", "host");
        sharkd_json_array_open("hosts");
        proto = iu->type + 6;
    }
    else
    {
        sharkd_json_value_string("type", "err");
        proto = "";
    }

    proto_with_port = (!strcmp(proto, "TCP") || !strcmp(proto, "UDP") || !strcmp(proto, "SCTP"));

    if (iu->hash.conv_array != NULL && !strncmp(iu->type, "conv:", 5))
    {
        for (i = 0; i < iu->hash.conv_array->len; i++)
        {
            conv_item_t *iui = &g_array_index(iu->hash.conv_array, conv_item_t, i);
            char *src_addr, *dst_addr;
            char *src_port, *dst_port;
            char *filter_str;

            json_dumper_begin_object(&dumper);

            sharkd_json_value_string("saddr", (src_addr = get_conversation_address(NULL, &iui->src_address, iu->resolve_name)));
            sharkd_json_value_string("daddr", (dst_addr = get_conversation_address(NULL, &iui->dst_address, iu->resolve_name)));

            if (proto_with_port)
            {
                sharkd_json_value_string("sport", (src_port = get_conversation_port(NULL, iui->src_port, iui->etype, iu->resolve_port)));
                sharkd_json_value_string("dport", (dst_port = get_conversation_port(NULL, iui->dst_port, iui->etype, iu->resolve_port)));

                wmem_free(NULL, src_port);
                wmem_free(NULL, dst_port);
            }

            sharkd_json_value_anyf("rxf", "%" PRIu64, iui->rx_frames);
            sharkd_json_value_anyf("rxb", "%" PRIu64, iui->rx_bytes);

            sharkd_json_value_anyf("txf", "%" PRIu64, iui->tx_frames);
            sharkd_json_value_anyf("txb", "%" PRIu64, iui->tx_bytes);

            sharkd_json_value_anyf("start", "%.9f", nstime_to_sec(&iui->start_time));
            sharkd_json_value_anyf("stop", "%.9f", nstime_to_sec(&iui->stop_time));

            filter_str = get_conversation_filter(iui, CONV_DIR_A_TO_FROM_B);
            if (filter_str)
            {
                sharkd_json_value_string("filter", filter_str);
                g_free(filter_str);
            }

            wmem_free(NULL, src_addr);
            wmem_free(NULL, dst_addr);

            if (sharkd_session_geoip_addr(&(iui->src_address), "1"))
                with_geoip = 1;
            if (sharkd_session_geoip_addr(&(iui->dst_address), "2"))
                with_geoip = 1;

            json_dumper_end_object(&dumper);
        }
    }
    else if (iu->hash.conv_array != NULL && !strncmp(iu->type, "endpt:", 6))
    {
        for (i = 0; i < iu->hash.conv_array->len; i++)
        {
            hostlist_talker_t *host = &g_array_index(iu->hash.conv_array, hostlist_talker_t, i);
            char *host_str, *port_str;
            char *filter_str;

            json_dumper_begin_object(&dumper);

            sharkd_json_value_string("host", (host_str = get_conversation_address(NULL, &host->myaddress, iu->resolve_name)));

            if (proto_with_port)
            {
                sharkd_json_value_string("port", (port_str = get_conversation_port(NULL, host->port, host->etype, iu->resolve_port)));

                wmem_free(NULL, port_str);
            }

            sharkd_json_value_anyf("rxf", "%" PRIu64, host->rx_frames);
            sharkd_json_value_anyf("rxb", "%" PRIu64, host->rx_bytes);

            sharkd_json_value_anyf("txf", "%" PRIu64, host->tx_frames);
            sharkd_json_value_anyf("txb", "%" PRIu64, host->tx_bytes);

            filter_str = get_hostlist_filter(host);
            if (filter_str)
            {
                sharkd_json_value_string("filter", filter_str);
                g_free(filter_str);
            }

            wmem_free(NULL, host_str);

            if (sharkd_session_geoip_addr(&(host->myaddress), ""))
                with_geoip = 1;
            json_dumper_end_object(&dumper);
        }
    }
    sharkd_json_array_close();

    sharkd_json_value_string("proto", proto);
    sharkd_json_value_anyf("geoip", with_geoip ? "true" : "false");

    json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_conv_cb(void *arg)
{
    conv_hash_t *hash = (conv_hash_t *) arg;
    struct sharkd_conv_tap_data *iu = (struct sharkd_conv_tap_data *) hash->user_data;

    if (!strncmp(iu->type, "conv:", 5))
    {
        reset_conversation_table_data(hash);
    }
    else if (!strncmp(iu->type, "endpt:", 6))
    {
        reset_hostlist_table_data(hash);
    }

    g_free(iu);
}

/**
 * sharkd_session_process_tap_nstat_cb()
 *
 * Output nstat tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) fields: array of objects with attributes:
 *                  (m) c - name
 *
 *   (m) tables: array of object with attributes:
 *                  (m) t - table title
 *                  (m) i - array of items
 */
static void
sharkd_session_process_tap_nstat_cb(void *arg)
{
    stat_data_t *stat_data = (stat_data_t *) arg;
    guint i, j, k;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("tap", "nstat:%s", stat_data->stat_tap_data->cli_string);
    sharkd_json_value_string("type", "nstat");

    sharkd_json_array_open("fields");
    for (i = 0; i < stat_data->stat_tap_data->nfields; i++)
    {
        stat_tap_table_item *field = &(stat_data->stat_tap_data->fields[i]);

        json_dumper_begin_object(&dumper);
        sharkd_json_value_string("c", field->column_name);
        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    sharkd_json_array_open("tables");
    for (i = 0; i < stat_data->stat_tap_data->tables->len; i++)
    {
        stat_tap_table *table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table *, i);

        json_dumper_begin_object(&dumper);

        sharkd_json_value_string("t", table->title);

        sharkd_json_array_open("i");
        for (j = 0; j < table->num_elements; j++)
        {
            stat_tap_table_item_type *field_data;

            field_data = stat_tap_get_field_data(table, j, 0);
            if (field_data == NULL || field_data->type == TABLE_ITEM_NONE) /* Nothing for us here */
                continue;

            sharkd_json_array_open(NULL);
            for (k = 0; k < table->num_fields; k++)
            {
                field_data = stat_tap_get_field_data(table, j, k);

                switch (field_data->type)
                {
                    case TABLE_ITEM_UINT:
                        sharkd_json_value_anyf(NULL, "%u", field_data->value.uint_value);
                        break;

                    case TABLE_ITEM_INT:
                        sharkd_json_value_anyf(NULL, "%d", field_data->value.int_value);
                        break;

                    case TABLE_ITEM_STRING:
                        sharkd_json_value_string(NULL, field_data->value.string_value);
                        break;

                    case TABLE_ITEM_FLOAT:
                        sharkd_json_value_anyf(NULL, "%f", field_data->value.float_value);
                        break;

                    case TABLE_ITEM_ENUM:
                        sharkd_json_value_anyf(NULL, "%d", field_data->value.enum_value);
                        break;

                    case TABLE_ITEM_NONE:
                        sharkd_json_value_anyf(NULL, "null");
                        break;
                }
            }

            sharkd_json_array_close();
        }
        sharkd_json_array_close();
        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_nstat_cb(void *arg)
{
    stat_data_t *stat_data = (stat_data_t *) arg;

    free_stat_tables(stat_data->stat_tap_data);
}

/**
 * sharkd_session_process_tap_rtd_cb()
 *
 * Output rtd tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) stats - statistics rows - array object with attributes:
 *                  (m) type - statistic name
 *                  (m) num - number of messages
 *                  (m) min - minimum SRT time
 *                  (m) max - maximum SRT time
 *                  (m) tot - total SRT time
 *                  (m) min_frame - minimal SRT
 *                  (m) max_frame - maximum SRT
 *                  (o) open_req - Open Requests
 *                  (o) disc_rsp - Discarded Responses
 *                  (o) req_dup  - Duplicated Requests
 *                  (o) rsp_dup  - Duplicated Responses
 *   (o) open_req   - Open Requests
 *   (o) disc_rsp   - Discarded Responses
 *   (o) req_dup    - Duplicated Requests
 *   (o) rsp_dup    - Duplicated Responses
 */
static void
sharkd_session_process_tap_rtd_cb(void *arg)
{
    rtd_data_t *rtd_data = (rtd_data_t *) arg;
    register_rtd_t *rtd  = (register_rtd_t *) rtd_data->user_data;

    guint i, j;

    const char *filter = proto_get_protocol_filter_name(get_rtd_proto_id(rtd));

    /* XXX, some dissectors are having single table and multiple timestats (mgcp, megaco),
     *      some multiple table and single timestat (radius, h225)
     *      and it seems that value_string is used one for timestamp-ID, other one for table-ID
     *      I wonder how it will gonna work with multiple timestats and multiple tables...
     * (for usage grep for: register_rtd_table)
     */
    const value_string *vs = get_rtd_value_string(rtd);

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("tap", "rtd:%s", filter);
    sharkd_json_value_string("type", "rtd");

    if (rtd_data->stat_table.num_rtds == 1)
    {
        const rtd_timestat *ms = &rtd_data->stat_table.time_stats[0];

        sharkd_json_value_anyf("open_req", "%u", ms->open_req_num);
        sharkd_json_value_anyf("disc_rsp", "%u", ms->disc_rsp_num);
        sharkd_json_value_anyf("req_dup", "%u", ms->req_dup_num);
        sharkd_json_value_anyf("rsp_dup", "%u", ms->rsp_dup_num);
    }

    sharkd_json_array_open("stats");
    for (i = 0; i < rtd_data->stat_table.num_rtds; i++)
    {
        const rtd_timestat *ms = &rtd_data->stat_table.time_stats[i];

        for (j = 0; j < ms->num_timestat; j++)
        {
            const char *type_str;

            if (ms->rtd[j].num == 0)
                continue;

            json_dumper_begin_object(&dumper);

            if (rtd_data->stat_table.num_rtds == 1)
                type_str = val_to_str_const(j, vs, "Other"); /* 1 table - description per row */
            else
                type_str = val_to_str_const(i, vs, "Other"); /* multiple table - description per table */
            sharkd_json_value_string("type", type_str);

            sharkd_json_value_anyf("num", "%u", ms->rtd[j].num);
            sharkd_json_value_anyf("min", "%.9f", nstime_to_sec(&(ms->rtd[j].min)));
            sharkd_json_value_anyf("max", "%.9f", nstime_to_sec(&(ms->rtd[j].max)));
            sharkd_json_value_anyf("tot", "%.9f", nstime_to_sec(&(ms->rtd[j].tot)));
            sharkd_json_value_anyf("min_frame", "%u", ms->rtd[j].min_num);
            sharkd_json_value_anyf("max_frame", "%u", ms->rtd[j].max_num);

            if (rtd_data->stat_table.num_rtds != 1)
            {
                /* like in tshark, display it on every row */
                sharkd_json_value_anyf("open_req", "%u", ms->open_req_num);
                sharkd_json_value_anyf("disc_rsp", "%u", ms->disc_rsp_num);
                sharkd_json_value_anyf("req_dup", "%u", ms->req_dup_num);
                sharkd_json_value_anyf("rsp_dup", "%u", ms->rsp_dup_num);
            }

            json_dumper_end_object(&dumper);
        }
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_rtd_cb(void *arg)
{
    rtd_data_t *rtd_data = (rtd_data_t *) arg;

    free_rtd_table(&rtd_data->stat_table);
    g_free(rtd_data);
}

/**
 * sharkd_session_process_tap_srt_cb()
 *
 * Output srt tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *
 *   (m) tables - array of object with attributes:
 *                  (m) n - table name
 *                  (m) f - table filter
 *                  (o) c - table column name
 *                  (m) r - table rows - array object with attributes:
 *                            (m) n   - row name
 *                            (m) idx - procedure index
 *                            (m) num - number of events
 *                            (m) min - minimum SRT time
 *                            (m) max - maximum SRT time
 *                            (m) tot - total SRT time
 */
static void
sharkd_session_process_tap_srt_cb(void *arg)
{
    srt_data_t *srt_data = (srt_data_t *) arg;
    register_srt_t *srt = (register_srt_t *) srt_data->user_data;

    const char *filter = proto_get_protocol_filter_name(get_srt_proto_id(srt));

    guint i;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("tap", "srt:%s", filter);
    sharkd_json_value_string("type", "srt");

    sharkd_json_array_open("tables");
    for (i = 0; i < srt_data->srt_array->len; i++)
    {
        /* SRT table */
        srt_stat_table *rst = g_array_index(srt_data->srt_array, srt_stat_table *, i);

        int j;

        json_dumper_begin_object(&dumper);

        if (rst->name)
            sharkd_json_value_string("n", rst->name);
        else if (rst->short_name)
            sharkd_json_value_string("n", rst->short_name);
        else
            sharkd_json_value_stringf("n", "table%u", i);

        if (rst->filter_string)
            sharkd_json_value_string("f", rst->filter_string);

        if (rst->proc_column_name)
            sharkd_json_value_string("c", rst->proc_column_name);

        sharkd_json_array_open("r");
        for (j = 0; j < rst->num_procs; j++)
        {
            /* SRT row */
            srt_procedure_t *proc = &rst->procedures[j];

            if (proc->stats.num == 0)
                continue;

            json_dumper_begin_object(&dumper);

            sharkd_json_value_string("n", proc->procedure);

            if (rst->filter_string)
                sharkd_json_value_anyf("idx", "%d", proc->proc_index);

            sharkd_json_value_anyf("num", "%u", proc->stats.num);

            sharkd_json_value_anyf("min", "%.9f", nstime_to_sec(&proc->stats.min));
            sharkd_json_value_anyf("max", "%.9f", nstime_to_sec(&proc->stats.max));
            sharkd_json_value_anyf("tot", "%.9f", nstime_to_sec(&proc->stats.tot));

            json_dumper_end_object(&dumper);
        }
        sharkd_json_array_close();

        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

static void
sharkd_session_free_tap_srt_cb(void *arg)
{
    srt_data_t *srt_data = (srt_data_t *) arg;
    register_srt_t *srt = (register_srt_t *) srt_data->user_data;

    free_srt_table(srt, srt_data->srt_array);
    g_array_free(srt_data->srt_array, TRUE);
    g_free(srt_data);
}

struct sharkd_export_object_list
{
    struct sharkd_export_object_list *next;

    char *type;
    const char *proto;
    GSList *entries;
};

static struct sharkd_export_object_list *sharkd_eo_list;

/**
 * sharkd_session_process_tap_eo_cb()
 *
 * Output eo tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) proto      - protocol short name
 *   (m) objects    - array of object with attributes:
 *                  (m) pkt - packet number
 *                  (o) hostname - hostname
 *                  (o) type - content type
 *                  (o) filename - filename
 *                  (m) len - object length
 */
static void
sharkd_session_process_tap_eo_cb(void *tapdata)
{
    export_object_list_t *tap_object = (export_object_list_t *) tapdata;
    struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list *) tap_object->gui_data;
    GSList *slist;
    int i = 0;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("tap", object_list->type);
    sharkd_json_value_string("type", "eo");

    sharkd_json_value_string("proto", object_list->proto);

    sharkd_json_array_open("objects");
    for (slist = object_list->entries; slist; slist = slist->next)
    {
        const export_object_entry_t *eo_entry = (export_object_entry_t *) slist->data;

        json_dumper_begin_object(&dumper);

        sharkd_json_value_anyf("pkt", "%u", eo_entry->pkt_num);

        if (eo_entry->hostname)
            sharkd_json_value_string("hostname", eo_entry->hostname);

        if (eo_entry->content_type)
            sharkd_json_value_string("type", eo_entry->content_type);

        if (eo_entry->filename)
            sharkd_json_value_string("filename", eo_entry->filename);

        sharkd_json_value_stringf("_download", "%s_%d", object_list->type, i);

        sharkd_json_value_anyf("len", "%zu", eo_entry->payload_len);

        json_dumper_end_object(&dumper);

        i++;
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

static void
sharkd_eo_object_list_add_entry(void *gui_data, export_object_entry_t *entry)
{
    struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list *) gui_data;

    object_list->entries = g_slist_append(object_list->entries, entry);
}

static export_object_entry_t *
sharkd_eo_object_list_get_entry(void *gui_data, int row)
{
    struct sharkd_export_object_list *object_list = (struct sharkd_export_object_list *) gui_data;

    return (export_object_entry_t *) g_slist_nth_data(object_list->entries, row);
}

/**
 * sharkd_session_process_tap_rtp_cb()
 *
 * Output RTP streams tap:
 *   (m) tap        - tap name
 *   (m) type       - tap output type
 *   (m) streams    - array of object with attributes:
 *                  (m) ssrc        - RTP synchronization source identifier
 *                  (m) payload     - stream payload
 *                  (m) saddr       - source address
 *                  (m) sport       - source port
 *                  (m) daddr       - destination address
 *                  (m) dport       - destination port
 *                  (m) pkts        - packets count
 *                  (m) max_delta   - max delta (ms)
 *                  (m) max_jitter  - max jitter (ms)
 *                  (m) mean_jitter - mean jitter (ms)
 *                  (m) expectednr  -
 *                  (m) totalnr     -
 *                  (m) problem     - if analyser found the problem
 *                  (m) ipver       - address IP version (4 or 6)
 */
static void
sharkd_session_process_tap_rtp_cb(void *arg)
{
    rtpstream_tapinfo_t *rtp_tapinfo = (rtpstream_tapinfo_t *) arg;

    GList *listx;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("tap", "rtp-streams");
    sharkd_json_value_string("type", "rtp-streams");

    sharkd_json_array_open("streams");
    for (listx = g_list_first(rtp_tapinfo->strinfo_list); listx; listx = listx->next)
    {
        rtpstream_info_t *streaminfo = (rtpstream_info_t *) listx->data;
        rtpstream_info_calc_t calc;

        rtpstream_info_calculate(streaminfo, &calc);

        json_dumper_begin_object(&dumper);

        sharkd_json_value_anyf("ssrc", "%u", calc.ssrc);
        sharkd_json_value_string("payload", calc.all_payload_type_names);

        sharkd_json_value_string("saddr", calc.src_addr_str);
        sharkd_json_value_anyf("sport", "%u", calc.src_port);
        sharkd_json_value_string("daddr", calc.dst_addr_str);
        sharkd_json_value_anyf("dport", "%u", calc.dst_port);

        sharkd_json_value_anyf("pkts", "%u", calc.packet_count);

        sharkd_json_value_anyf("max_delta", "%f",calc.max_delta);
        sharkd_json_value_anyf("max_jitter", "%f", calc.max_jitter);
        sharkd_json_value_anyf("mean_jitter", "%f", calc.mean_jitter);

        sharkd_json_value_anyf("expectednr", "%u", calc.packet_expected);
        sharkd_json_value_anyf("totalnr", "%u", calc.total_nr);

        sharkd_json_value_anyf("problem", calc.problem ? "true" : "false");

        /* for filter */
        sharkd_json_value_anyf("ipver", "%d", (streaminfo->id.src_addr.type == AT_IPv6) ? 6 : 4);

        rtpstream_info_calc_free(&calc);

        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();

    json_dumper_end_object(&dumper);
}

/**
 * sharkd_session_process_tap()
 *
 * Process tap request
 *
 * Input:
 *   (m) tap0         - First tap request
 *   (o) tap1...tap15 - Other tap requests
 *
 * Output object with attributes:
 *   (m) taps  - array of object with attributes:
 *                  (m) tap  - tap name
 *                  (m) type - tap output type
 *                  ...
 *                  for type:stats see sharkd_session_process_tap_stats_cb()
 *                  for type:nstat see sharkd_session_process_tap_nstat_cb()
 *                  for type:conv see sharkd_session_process_tap_conv_cb()
 *                  for type:host see sharkd_session_process_tap_conv_cb()
 *                  for type:rtp-streams see sharkd_session_process_tap_rtp_cb()
 *                  for type:rtp-analyse see sharkd_session_process_tap_rtp_analyse_cb()
 *                  for type:eo see sharkd_session_process_tap_eo_cb()
 *                  for type:expert see sharkd_session_process_tap_expert_cb()
 *                  for type:rtd see sharkd_session_process_tap_rtd_cb()
 *                  for type:srt see sharkd_session_process_tap_srt_cb()
 *                  for type:flow see sharkd_session_process_tap_flow_cb()
 *
 *   (m) err   - error code
 */
static void
sharkd_session_process_tap(char *buf, const jsmntok_t *tokens, int count)
{
    void *taps_data[16];
    GFreeFunc taps_free[16];
    int taps_count = 0;
    int i;

    rtpstream_tapinfo_t rtp_tapinfo =
    { NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, TAP_ANALYSE, NULL, NULL, NULL, FALSE, FALSE};

    for (i = 0; i < 16; i++)
    {
        char tapbuf[32];
        const char *tok_tap;

        void *tap_data = NULL;
        GFreeFunc tap_free = NULL;
        const char *tap_filter = "";
        GString *tap_error = NULL;

        snprintf(tapbuf, sizeof(tapbuf), "tap%d", i);
        tok_tap = json_find_attr(buf, tokens, count, tapbuf);
        if (!tok_tap)
            break;

        if (!strncmp(tok_tap, "stat:", 5))
        {
            stats_tree_cfg *cfg = stats_tree_get_cfg_by_abbr(tok_tap + 5);
            stats_tree *st;

            if (!cfg)
            {
                sharkd_json_error(
                        rpcid, -11001, NULL,
                        "sharkd_session_process_tap() stat %s not found", tok_tap + 5
                        );
                return;
            }

            st = stats_tree_new(cfg, NULL, tap_filter);

            tap_error = register_tap_listener(st->cfg->tapname, st, st->filter, st->cfg->flags, stats_tree_reset, stats_tree_packet, sharkd_session_process_tap_stats_cb, NULL);

            if (!tap_error && cfg->init)
                cfg->init(st);

            tap_data = st;
            tap_free = sharkd_session_free_tap_stats_cb;
        }
        else if (!strcmp(tok_tap, "expert"))
        {
            struct sharkd_expert_tap *expert_tap;

            expert_tap = g_new0(struct sharkd_expert_tap, 1);
            expert_tap->text = g_string_chunk_new(100);

            tap_error = register_tap_listener("expert", expert_tap, NULL, 0, NULL, sharkd_session_packet_tap_expert_cb, sharkd_session_process_tap_expert_cb, NULL);

            tap_data = expert_tap;
            tap_free = sharkd_session_free_tap_expert_cb;
        }
        else if (!strncmp(tok_tap, "seqa:", 5))
        {
            seq_analysis_info_t *graph_analysis;
            register_analysis_t *analysis;
            const char *tap_name;
            tap_packet_cb tap_func;
            guint tap_flags;

            analysis = sequence_analysis_find_by_name(tok_tap + 5);
            if (!analysis)
            {
                sharkd_json_error(
                        rpcid, -11002, NULL,
                        "sharkd_session_process_tap() seq analysis %s not found", tok_tap + 5
                        );
                return;
            }

            graph_analysis = sequence_analysis_info_new();
            graph_analysis->name = tok_tap + 5;
            /* TODO, make configurable */
            graph_analysis->any_addr = FALSE;

            tap_name  = sequence_analysis_get_tap_listener_name(analysis);
            tap_flags = sequence_analysis_get_tap_flags(analysis);
            tap_func  = sequence_analysis_get_packet_func(analysis);

            tap_error = register_tap_listener(tap_name, graph_analysis, NULL, tap_flags, NULL, tap_func, sharkd_session_process_tap_flow_cb, NULL);

            tap_data = graph_analysis;
            tap_free = sharkd_session_free_tap_flow_cb;
        }
        else if (!strncmp(tok_tap, "conv:", 5) || !strncmp(tok_tap, "endpt:", 6))
        {
            struct register_ct *ct = NULL;
            const char *ct_tapname;
            struct sharkd_conv_tap_data *ct_data;
            tap_packet_cb tap_func = NULL;

            if (!strncmp(tok_tap, "conv:", 5))
            {
                ct = get_conversation_by_proto_id(proto_get_id_by_short_name(tok_tap + 5));

                if (!ct || !(tap_func = get_conversation_packet_func(ct)))
                {
                    sharkd_json_error(
                            rpcid, -11003, NULL,
                            "sharkd_session_process_tap() conv %s not found", tok_tap + 5
                            );
                    return;
                }
            }
            else if (!strncmp(tok_tap, "endpt:", 6))
            {
                ct = get_conversation_by_proto_id(proto_get_id_by_short_name(tok_tap + 6));

                if (!ct || !(tap_func = get_hostlist_packet_func(ct)))
                {
                    sharkd_json_error(
                            rpcid, -11004, NULL,
                            "sharkd_session_process_tap() endpt %s not found", tok_tap + 6
                            );
                    return;
                }
            }
            else
            {
                sharkd_json_error(
                        rpcid, -11005, NULL,
                        "sharkd_session_process_tap() conv/endpt(?): %s not found", tok_tap
                        );
                return;
            }

            ct_tapname = proto_get_protocol_filter_name(get_conversation_proto_id(ct));

            ct_data = g_new0(struct sharkd_conv_tap_data, 1);
            ct_data->type = tok_tap;
            ct_data->hash.user_data = ct_data;

            /* XXX: make configurable */
            ct_data->resolve_name = TRUE;
            ct_data->resolve_port = TRUE;

            tap_error = register_tap_listener(ct_tapname, &ct_data->hash, tap_filter, 0, NULL, tap_func, sharkd_session_process_tap_conv_cb, NULL);

            tap_data = &ct_data->hash;
            tap_free = sharkd_session_free_tap_conv_cb;
        }
        else if (!strncmp(tok_tap, "nstat:", 6))
        {
            stat_tap_table_ui *stat_tap = stat_tap_by_name(tok_tap + 6);
            stat_data_t *stat_data;

            if (!stat_tap)
            {
                sharkd_json_error(
                        rpcid, -11006, NULL,
                        "sharkd_session_process_tap() nstat=%s not found", tok_tap + 6
                        );
                return;
            }

            stat_tap->stat_tap_init_cb(stat_tap);

            stat_data = g_new0(stat_data_t, 1);
            stat_data->stat_tap_data = stat_tap;
            stat_data->user_data = NULL;

            tap_error = register_tap_listener(stat_tap->tap_name, stat_data, tap_filter, 0, NULL, stat_tap->packet_func, sharkd_session_process_tap_nstat_cb, NULL);

            tap_data = stat_data;
            tap_free = sharkd_session_free_tap_nstat_cb;
        }
        else if (!strncmp(tok_tap, "rtd:", 4))
        {
            register_rtd_t *rtd = get_rtd_table_by_name(tok_tap + 4);
            rtd_data_t *rtd_data;
            char *err;

            if (!rtd)
            {
                sharkd_json_error(
                        rpcid, -11007, NULL,
                        "sharkd_session_process_tap() rtd=%s not found", tok_tap + 4
                        );
                return;
            }

            rtd_table_get_filter(rtd, "", &tap_filter, &err);
            if (err != NULL)
            {
                sharkd_json_error(
                        rpcid, -11008, NULL,
                        "sharkd_session_process_tap() rtd=%s err=%s", tok_tap + 4, err
                        );
                g_free(err);
                return;
            }

            rtd_data = g_new0(rtd_data_t, 1);
            rtd_data->user_data = rtd;
            rtd_table_dissector_init(rtd, &rtd_data->stat_table, NULL, NULL);

            tap_error = register_tap_listener(get_rtd_tap_listener_name(rtd), rtd_data, tap_filter, 0, NULL, get_rtd_packet_func(rtd), sharkd_session_process_tap_rtd_cb, NULL);

            tap_data = rtd_data;
            tap_free = sharkd_session_free_tap_rtd_cb;
        }
        else if (!strncmp(tok_tap, "srt:", 4))
        {
            register_srt_t *srt = get_srt_table_by_name(tok_tap + 4);
            srt_data_t *srt_data;
            char *err;

            if (!srt)
            {
                sharkd_json_error(
                        rpcid, -11009, NULL,
                        "sharkd_session_process_tap() srt=%s not found", tok_tap + 4
                        );
                return;
            }

            srt_table_get_filter(srt, "", &tap_filter, &err);
            if (err != NULL)
            {
                sharkd_json_error(
                        rpcid, -11010, NULL,
                        "sharkd_session_process_tap() srt=%s err=%s", tok_tap + 4, err
                        );
                g_free(err);
                return;
            }

            srt_data = g_new0(srt_data_t, 1);
            srt_data->srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table *));
            srt_data->user_data = srt;
            srt_table_dissector_init(srt, srt_data->srt_array);

            tap_error = register_tap_listener(get_srt_tap_listener_name(srt), srt_data, tap_filter, 0, NULL, get_srt_packet_func(srt), sharkd_session_process_tap_srt_cb, NULL);

            tap_data = srt_data;
            tap_free = sharkd_session_free_tap_srt_cb;
        }
        else if (!strncmp(tok_tap, "eo:", 3))
        {
            register_eo_t *eo = get_eo_by_name(tok_tap + 3);
            export_object_list_t *eo_object;
            struct sharkd_export_object_list *object_list;

            if (!eo)
            {
                sharkd_json_error(
                        rpcid, -11011, NULL,
                        "sharkd_session_process_tap() eo=%s not found", tok_tap + 3
                        );
                return;
            }

            for (object_list = sharkd_eo_list; object_list; object_list = object_list->next)
            {
                if (!strcmp(object_list->type, tok_tap))
                {
                    g_slist_free_full(object_list->entries, (GDestroyNotify) eo_free_entry);
                    object_list->entries = NULL;
                    break;
                }
            }

            if (!object_list)
            {
                object_list = g_new(struct sharkd_export_object_list, 1);
                object_list->type = g_strdup(tok_tap);
                object_list->proto = proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo)));
                object_list->entries = NULL;
                object_list->next = sharkd_eo_list;
                sharkd_eo_list = object_list;
            }

            eo_object  = g_new0(export_object_list_t, 1);
            eo_object->add_entry = sharkd_eo_object_list_add_entry;
            eo_object->get_entry = sharkd_eo_object_list_get_entry;
            eo_object->gui_data = (void *) object_list;

            tap_error = register_tap_listener(get_eo_tap_listener_name(eo), eo_object, NULL, 0, NULL, get_eo_packet_func(eo), sharkd_session_process_tap_eo_cb, NULL);

            tap_data = eo_object;
            tap_free = g_free; /* need to free only eo_object, object_list need to be kept for potential download */
        }
        else if (!strcmp(tok_tap, "rtp-streams"))
        {
            tap_error = register_tap_listener("rtp", &rtp_tapinfo, tap_filter, 0, rtpstream_reset_cb, rtpstream_packet_cb, sharkd_session_process_tap_rtp_cb, NULL);

            tap_data = &rtp_tapinfo;
            tap_free = rtpstream_reset_cb;
        }
        else if (!strncmp(tok_tap, "rtp-analyse:", 12))
        {
            struct sharkd_analyse_rtp *rtp_req;

            rtp_req = (struct sharkd_analyse_rtp *) g_malloc0(sizeof(*rtp_req));
            if (!sharkd_rtp_match_init(&rtp_req->id, tok_tap + 12))
            {
                rtpstream_id_free(&rtp_req->id);
                g_free(rtp_req);
                continue;
            }

            rtp_req->tap_name = tok_tap;
            rtp_req->statinfo.first_packet = TRUE;
            rtp_req->statinfo.reg_pt = PT_UNDEFINED;

            tap_error = register_tap_listener("rtp", rtp_req, tap_filter, 0, NULL, sharkd_session_packet_tap_rtp_analyse_cb, sharkd_session_process_tap_rtp_analyse_cb, NULL);

            tap_data = rtp_req;
            tap_free = sharkd_session_process_tap_rtp_free_cb;
        }
        else
        {
            sharkd_json_error(
                    rpcid, -11012, NULL,
                    "sharkd_session_process_tap() %s not recognized", tok_tap
                    );
            return;
        }

        if (tap_error)
        {
            sharkd_json_error(
                    rpcid, -11013, NULL,
                    "sharkd_session_process_tap() name=%s error=%s", tok_tap, tap_error->str
                    );
            g_string_free(tap_error, TRUE);
            if (tap_free)
                tap_free(tap_data);
            return;
        }

        taps_data[taps_count] = tap_data;
        taps_free[taps_count] = tap_free;
        taps_count++;
    }

    fprintf(stderr, "sharkd_session_process_tap() count=%d\n", taps_count);
    if (taps_count == 0)
    {
        sharkd_json_result_prologue(rpcid);
        sharkd_json_array_open("taps");
        sharkd_json_array_close();
        sharkd_json_result_epilogue();
        return;
    }

    sharkd_json_result_prologue(rpcid);
    sharkd_json_array_open("taps");
    sharkd_retap();
    sharkd_json_array_close();
    sharkd_json_result_epilogue();

    for (i = 0; i < taps_count; i++)
    {
        if (taps_data[i])
            remove_tap_listener(taps_data[i]);

        if (taps_free[i])
            taps_free[i](taps_data[i]);
    }
}

/**
 * sharkd_session_process_follow()
 *
 * Process follow request
 *
 * Input:
 *   (m) follow  - follow protocol request (e.g. HTTP)
 *   (m) filter  - filter request (e.g. tcp.stream == 1)
 *
 * Output object with attributes:
 *
 *   (m) err    - error code
 *   (m) shost  - server host
 *   (m) sport  - server port
 *   (m) sbytes - server send bytes count
 *   (m) chost  - client host
 *   (m) cport  - client port
 *   (m) cbytes - client send bytes count
 *   (o) payloads - array of object with attributes:
 *                  (o) s - set if server sent, else client
 *                  (m) n - packet number
 *                  (m) d - data base64 encoded
 */
static void
sharkd_session_process_follow(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_follow = json_find_attr(buf, tokens, count, "follow");
    const char *tok_filter = json_find_attr(buf, tokens, count, "filter");

    register_follow_t *follower;
    GString *tap_error;

    follow_info_t *follow_info;
    const char *host;
    char *port;

    follower = get_follow_by_name(tok_follow);
    if (!follower)
    {
        sharkd_json_error(
                rpcid, -12001, NULL,
                "sharkd_session_process_follow() follower=%s not found", tok_follow
                );
        return;
    }

    /* follow_reset_stream ? */
    follow_info = g_new0(follow_info_t, 1);
    /* gui_data, filter_out_filter not set, but not used by dissector */

    tap_error = register_tap_listener(get_follow_tap_string(follower), follow_info, tok_filter, 0, NULL, get_follow_tap_handler(follower), NULL, NULL);
    if (tap_error)
    {
        sharkd_json_error(
                rpcid, -12002, NULL,
                "sharkd_session_process_follow() name=%s error=%s", tok_follow, tap_error->str
                );
        g_string_free(tap_error, TRUE);
        g_free(follow_info);
        return;
    }

    sharkd_retap();

    sharkd_json_result_prologue(rpcid);

    /* Server information: hostname, port, bytes sent */
    host = address_to_name(&follow_info->server_ip);
    sharkd_json_value_string("shost", host);

    port = get_follow_port_to_display(follower)(NULL, follow_info->server_port);
    sharkd_json_value_string("sport", port);
    wmem_free(NULL, port);

    sharkd_json_value_anyf("sbytes", "%u", follow_info->bytes_written[0]);

    /* Client information: hostname, port, bytes sent */
    host = address_to_name(&follow_info->client_ip);
    sharkd_json_value_string("chost", host);

    port = get_follow_port_to_display(follower)(NULL, follow_info->client_port);
    sharkd_json_value_string("cport", port);
    wmem_free(NULL, port);

    sharkd_json_value_anyf("cbytes", "%u", follow_info->bytes_written[1]);

    if (follow_info->payload)
    {
        follow_record_t *follow_record;
        GList *cur;

        sharkd_json_array_open("payloads");
        for (cur = g_list_last(follow_info->payload); cur; cur = g_list_previous(cur))
        {
            follow_record = (follow_record_t *) cur->data;

            json_dumper_begin_object(&dumper);

            sharkd_json_value_anyf("n", "%u", follow_record->packet_num);
            sharkd_json_value_base64("d", follow_record->data->data, follow_record->data->len);

            if (follow_record->is_server)
                sharkd_json_value_anyf("s", "%d", 1);

            json_dumper_end_object(&dumper);
        }
        sharkd_json_array_close();
    }

    sharkd_json_result_epilogue();

    remove_tap_listener(follow_info);
    follow_info_free(follow_info);
}

static void
sharkd_session_process_frame_cb_tree(epan_dissect_t *edt, proto_tree *tree, tvbuff_t **tvbs, gboolean display_hidden)
{
    proto_node *node;

    sharkd_json_array_open(NULL);
    for (node = tree->first_child; node; node = node->next)
    {
        field_info *finfo = PNODE_FINFO(node);

        if (!finfo)
            continue;

        if (!display_hidden && FI_GET_FLAG(finfo, FI_HIDDEN))
            continue;

        json_dumper_begin_object(&dumper);

        if (!finfo->rep)
        {
            char label_str[ITEM_LABEL_LENGTH];

            label_str[0] = '\0';
            proto_item_fill_label(finfo, label_str);
            sharkd_json_value_string("l", label_str);
        }
        else
        {
            sharkd_json_value_string("l", finfo->rep->representation);
        }

        if (finfo->ds_tvb && tvbs && tvbs[0] != finfo->ds_tvb)
        {
            int idx;

            for (idx = 1; tvbs[idx]; idx++)
            {
                if (tvbs[idx] == finfo->ds_tvb)
                {
                    sharkd_json_value_anyf("ds", "%d", idx);
                    break;
                }
            }
        }

        if (finfo->start >= 0 && finfo->length > 0)
            sharkd_json_value_anyf("h", "[%d,%d]", finfo->start, finfo->length);

        if (finfo->appendix_start >= 0 && finfo->appendix_length > 0)
            sharkd_json_value_anyf("i", "[%d,%d]", finfo->appendix_start, finfo->appendix_length);


        if (finfo->hfinfo)
        {
            char *filter;

            if (finfo->hfinfo->type == FT_PROTOCOL)
            {
                sharkd_json_value_string("t", "proto");
            }
            else if (finfo->hfinfo->type == FT_FRAMENUM)
            {
                sharkd_json_value_string("t", "framenum");
                sharkd_json_value_anyf("fnum", "%u", finfo->value.value.uinteger);
            }
            else if (FI_GET_FLAG(finfo, FI_URL) && IS_FT_STRING(finfo->hfinfo->type))
            {
                char *url = fvalue_to_string_repr(NULL, &finfo->value, FTREPR_DISPLAY, finfo->hfinfo->display);

                sharkd_json_value_string("t", "url");
                sharkd_json_value_string("url", url);
                wmem_free(NULL, url);
            }

            filter = proto_construct_match_selected_string(finfo, edt);
            if (filter)
            {
                sharkd_json_value_string("f", filter);
                wmem_free(NULL, filter);
            }
        }

        if (FI_GET_FLAG(finfo, FI_GENERATED))
            sharkd_json_value_anyf("g", "true");

        if (FI_GET_FLAG(finfo, FI_HIDDEN))
            sharkd_json_value_anyf("v", "true");

        if (FI_GET_FLAG(finfo, PI_SEVERITY_MASK))
        {
            const char *severity = try_val_to_str(FI_GET_FLAG(finfo, PI_SEVERITY_MASK), expert_severity_vals);

            ws_assert(severity != NULL);

            sharkd_json_value_string("s", severity);
        }

        if (((proto_tree *) node)->first_child)
        {
            if (finfo->tree_type != -1)
                sharkd_json_value_anyf("e", "%d", finfo->tree_type);

            sharkd_json_value_anyf("n", NULL);
            sharkd_session_process_frame_cb_tree(edt, (proto_tree *) node, tvbs, display_hidden);
        }

        json_dumper_end_object(&dumper);
    }
    sharkd_json_array_close();
}

static gboolean
sharkd_follower_visit_layers_cb(const void *key _U_, void *value, void *user_data)
{
    register_follow_t *follower = (register_follow_t *) value;
    packet_info *pi = (packet_info *) user_data;

    const int proto_id = get_follow_proto_id(follower);

    guint32 ignore_stream;
    guint32 ignore_sub_stream;

    if (proto_is_frame_protocol(pi->layers, proto_get_protocol_filter_name(proto_id)))
    {
        const char *layer_proto = proto_get_protocol_short_name(find_protocol_by_id(proto_id));
        char *follow_filter;

        follow_filter = get_follow_conv_func(follower)(NULL, pi, &ignore_stream, &ignore_sub_stream);

        json_dumper_begin_array(&dumper);
        json_dumper_value_string(&dumper, layer_proto);
        json_dumper_value_string(&dumper, follow_filter);
        json_dumper_end_array(&dumper);

        g_free(follow_filter);
    }

    return FALSE;
}

struct sharkd_frame_request_data
{
    gboolean display_hidden;
};

static void
sharkd_session_process_frame_cb(epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data)
{
    packet_info *pi = &edt->pi;
    frame_data *fdata = pi->fd;
    wtap_block_t pkt_block = NULL;

    const struct sharkd_frame_request_data * const req_data = (const struct sharkd_frame_request_data * const) data;
    const gboolean display_hidden = (req_data) ? req_data->display_hidden : FALSE;

    sharkd_json_result_prologue(rpcid);

    if (fdata->has_modified_block)
        pkt_block = sharkd_get_modified_block(fdata);
    else
        pkt_block = pi->rec->block;

    if (pkt_block)
    {
        guint i;
        guint n;
        gchar *comment;

        n = wtap_block_count_option(pkt_block, OPT_COMMENT);

        sharkd_json_array_open("comment");
        for (i = 0; i < n; i++) {
            if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_nth_string_option_value(pkt_block, OPT_COMMENT, i, &comment)) {
                sharkd_json_value_string(NULL, comment);
            }
        }
        sharkd_json_array_close();
    }

    if (tree)
    {
        tvbuff_t **tvbs = NULL;

        /* arrayize data src, to speedup searching for ds_tvb index */
        if (data_src && data_src->next /* only needed if there are more than one data source */)
        {
            guint count = g_slist_length((GSList *) data_src);
            guint i;

            tvbs = (tvbuff_t **) g_malloc0((count + 1) * sizeof(*tvbs));

            for (i = 0; i < count; i++)
            {
                const struct data_source *src = (const struct data_source *) g_slist_nth_data((GSList *) data_src, i);

                tvbs[i] = get_data_source_tvb(src);
            }

            tvbs[count] = NULL;
        }

        sharkd_json_value_anyf("tree", NULL);
        sharkd_session_process_frame_cb_tree(edt, tree, tvbs, display_hidden);

        g_free(tvbs);
    }

    if (cinfo)
    {
        int col;

        sharkd_json_array_open("col");
        for (col = 0; col < cinfo->num_cols; ++col)
        {
            const col_item_t *col_item = &cinfo->columns[col];

            sharkd_json_value_string(NULL, col_item->col_data);
        }
        sharkd_json_array_close();
    }

    if (fdata->ignored)
        sharkd_json_value_anyf("i", "true");

    if (fdata->marked)
        sharkd_json_value_anyf("m", "true");

    if (fdata->color_filter)
    {
        sharkd_json_value_stringf("bg", "%x", color_t_to_rgb(&fdata->color_filter->bg_color));
        sharkd_json_value_stringf("fg", "%x", color_t_to_rgb(&fdata->color_filter->fg_color));
    }

    if (data_src)
    {
        struct data_source *src = (struct data_source *) data_src->data;
        gboolean ds_open = FALSE;

        tvbuff_t *tvb;
        guint length;

        tvb = get_data_source_tvb(src);
        length = tvb_captured_length(tvb);

        if (length != 0)
        {
            const guchar *cp = tvb_get_ptr(tvb, 0, length);

            /* XXX pi.fd->encoding */
            sharkd_json_value_base64("bytes", cp, length);
        }
        else
        {
            sharkd_json_value_base64("bytes", "", 0);
        }

        data_src = data_src->next;
        if (data_src)
        {
            sharkd_json_array_open("ds");
            ds_open = TRUE;
        }

        while (data_src)
        {
            src = (struct data_source *) data_src->data;

            json_dumper_begin_object(&dumper);

            {
                char *src_name = get_data_source_name(src);

                sharkd_json_value_string("name", src_name);
                wmem_free(NULL, src_name);
            }

            tvb = get_data_source_tvb(src);
            length = tvb_captured_length(tvb);

            if (length != 0)
            {
                const guchar *cp = tvb_get_ptr(tvb, 0, length);

                /* XXX pi.fd->encoding */
                sharkd_json_value_base64("bytes", cp, length);
            }
            else
            {
                sharkd_json_value_base64("bytes", "", 0);
            }

            json_dumper_end_object(&dumper);

            data_src = data_src->next;
        }

        /* close ds, only if was opened */
        if (ds_open)
            sharkd_json_array_close();
    }

    sharkd_json_array_open("fol");
    follow_iterate_followers(sharkd_follower_visit_layers_cb, pi);
    sharkd_json_array_close();

    sharkd_json_result_epilogue();
}

#define SHARKD_IOGRAPH_MAX_ITEMS 250000 /* 250k limit of items is taken from wireshark-qt, on x86_64 sizeof(io_graph_item_t) is 152, so single graph can take max 36 MB */

struct sharkd_iograph
{
    /* config */
    int hf_index;
    io_graph_item_unit_t calc_type;
    guint32 interval;

    /* result */
    int space_items;
    int num_items;
    io_graph_item_t *items;
    GString *error;
};

static tap_packet_status
sharkd_iograph_packet(void *g, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_)
{
    struct sharkd_iograph *graph = (struct sharkd_iograph *) g;
    int idx;
    gboolean update_succeeded;

    idx = get_io_graph_index(pinfo, graph->interval);
    if (idx < 0 || idx >= SHARKD_IOGRAPH_MAX_ITEMS)
        return TAP_PACKET_DONT_REDRAW;

    if (idx + 1 > graph->num_items)
    {
        if (idx + 1 > graph->space_items)
        {
            int new_size = idx + 1024;

            graph->items = (io_graph_item_t *) g_realloc(graph->items, sizeof(io_graph_item_t) * new_size);
            reset_io_graph_items(&graph->items[graph->space_items], new_size - graph->space_items);

            graph->space_items = new_size;
        }
        else if (graph->items == NULL)
        {
            graph->items = g_new(io_graph_item_t, graph->space_items);
            reset_io_graph_items(graph->items, graph->space_items);
        }

        graph->num_items = idx + 1;
    }

    update_succeeded = update_io_graph_item(graph->items, idx, pinfo, edt, graph->hf_index, graph->calc_type, graph->interval);
    /* XXX - TAP_PACKET_FAILED if the item couldn't be updated, with an error message? */
    return update_succeeded ? TAP_PACKET_REDRAW : TAP_PACKET_DONT_REDRAW;
}

/**
 * sharkd_session_process_iograph()
 *
 * Process iograph request
 *
 * Input:
 *   (o) interval - interval time in ms, if not specified: 1000ms
 *   (m) graph0             - First graph request
 *   (o) graph1...graph9    - Other graph requests
 *   (o) filter0            - First graph filter
 *   (o) filter1...filter9  - Other graph filters
 *
 * Graph requests can be one of: "packets", "bytes", "bits", "sum:<field>", "frames:<field>", "max:<field>", "min:<field>", "avg:<field>", "load:<field>",
 * if you use variant with <field>, you need to pass field name in filter request.
 *
 * Output object with attributes:
 *   (m) iograph - array of graph results with attributes:
 *                  errmsg - graph cannot be constructed
 *                  items  - graph values, zeros are skipped, if value is not a number it's next index encoded as hex string
 */
static void
sharkd_session_process_iograph(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_interval = json_find_attr(buf, tokens, count, "interval");
    struct sharkd_iograph graphs[10];
    gboolean is_any_ok = FALSE;
    int graph_count;

    guint32 interval_ms = 1000; /* default: one per second */
    int i;

    if (tok_interval)
        ws_strtou32(tok_interval, NULL, &interval_ms);

    for (i = graph_count = 0; i < (int) G_N_ELEMENTS(graphs); i++)
    {
        struct sharkd_iograph *graph = &graphs[graph_count];

        const char *tok_graph;
        const char *tok_filter;
        char tok_format_buf[32];
        const char *field_name;

        snprintf(tok_format_buf, sizeof(tok_format_buf), "graph%d", i);
        tok_graph = json_find_attr(buf, tokens, count, tok_format_buf);
        if (!tok_graph)
            break;

        snprintf(tok_format_buf, sizeof(tok_format_buf), "filter%d", i);
        tok_filter = json_find_attr(buf, tokens, count, tok_format_buf);

        if (!strcmp(tok_graph, "packets"))
            graph->calc_type = IOG_ITEM_UNIT_PACKETS;
        else if (!strcmp(tok_graph, "bytes"))
            graph->calc_type = IOG_ITEM_UNIT_BYTES;
        else if (!strcmp(tok_graph, "bits"))
            graph->calc_type = IOG_ITEM_UNIT_BITS;
        else if (g_str_has_prefix(tok_graph, "sum:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_SUM;
        else if (g_str_has_prefix(tok_graph, "frames:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_FRAMES;
        else if (g_str_has_prefix(tok_graph, "fields:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_FIELDS;
        else if (g_str_has_prefix(tok_graph, "max:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_MAX;
        else if (g_str_has_prefix(tok_graph, "min:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_MIN;
        else if (g_str_has_prefix(tok_graph, "avg:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_AVERAGE;
        else if (g_str_has_prefix(tok_graph, "load:"))
            graph->calc_type = IOG_ITEM_UNIT_CALC_LOAD;
        else
            break;

        field_name = strchr(tok_graph, ':');
        if (field_name)
            field_name = field_name + 1;

        graph->interval = interval_ms;

        graph->hf_index = -1;
        graph->error = check_field_unit(field_name, &graph->hf_index, graph->calc_type);

        graph->space_items = 0; /* TODO, can avoid realloc()s in sharkd_iograph_packet() by calculating: capture_time / interval */
        graph->num_items = 0;
        graph->items = NULL;

        if (!graph->error)
            graph->error = register_tap_listener("frame", graph, tok_filter, TL_REQUIRES_PROTO_TREE, NULL, sharkd_iograph_packet, NULL, NULL);

        graph_count++;

        if (graph->error)
        {
            sharkd_json_error(
                    rpcid, -6001, NULL,
                    "%s", graph->error->str
                    );
            g_string_free(graph->error, TRUE);
            return;
        }

        if (graph->error == NULL)
            is_any_ok = TRUE;
    }

    /* retap only if we have at least one ok */
    if (is_any_ok)
        sharkd_retap();

    sharkd_json_result_prologue(rpcid);

    sharkd_json_array_open("iograph");
    for (i = 0; i < graph_count; i++)
    {
        struct sharkd_iograph *graph = &graphs[i];

        json_dumper_begin_object(&dumper);

        if (graph->error)
        {
            fprintf(stderr, "SNAP 6002 - we should never get to here.\n");
            g_string_free(graph->error, TRUE);
            exit(-1);
        }
        else
        {
            int idx;
            int next_idx = 0;

            sharkd_json_array_open("items");
            for (idx = 0; idx < graph->num_items; idx++)
            {
                double val;

                val = get_io_graph_item(graph->items, graph->calc_type, idx, graph->hf_index, &cfile, graph->interval, graph->num_items);

                /* if it's zero, don't display */
                if (val == 0.0)
                    continue;

                /* cause zeros are not printed, need to output index */
                if (next_idx != idx)
                    sharkd_json_value_stringf(NULL, "%x", idx);

                sharkd_json_value_anyf(NULL, "%f", val);
                next_idx = idx + 1;
            }
            sharkd_json_array_close();
        }
        json_dumper_end_object(&dumper);

        remove_tap_listener(graph);
        g_free(graph->items);
    }
    sharkd_json_array_close();

    sharkd_json_result_epilogue();
}

/**
 * sharkd_session_process_intervals()
 *
 * Process intervals request - generate basic capture file statistics per requested interval.
 *
 * Input:
 *   (o) interval - interval time in ms, if not specified: 1000ms
 *   (o) filter   - filter for generating interval request
 *
 * Output object with attributes:
 *   (m) intervals - array of intervals, with indexes:
 *             [0] - index of interval,
 *             [1] - number of frames during interval,
 *             [2] - number of bytes during interval.
 *
 *   (m) last   - last interval number.
 *   (m) frames - total number of frames
 *   (m) bytes  - total number of bytes
 *
 * NOTE: If frames are not in order, there might be items with same interval index, or even negative one.
 */
static void
sharkd_session_process_intervals(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_interval = json_find_attr(buf, tokens, count, "interval");
    const char *tok_filter = json_find_attr(buf, tokens, count, "filter");

    const guint8 *filter_data = NULL;

    struct
    {
        unsigned int frames;
        guint64 bytes;
    } st, st_total;

    nstime_t *start_ts;

    guint32 interval_ms = 1000; /* default: one per second */

    gint64 idx;
    gint64 max_idx = 0;

    if (tok_interval)
        ws_strtou32(tok_interval, NULL, &interval_ms);  // already validated

    if (tok_filter)
    {
        const struct sharkd_filter_item *filter_item;

        filter_item = sharkd_session_filter_data(tok_filter);
        if (!filter_item)
        {
            sharkd_json_error(
                    rpcid, -7001, NULL,
                    "Invalid filter parameter: %s", tok_filter
                    );
            return;
        }
        filter_data = filter_item->filtered;
    }

    st_total.frames = 0;
    st_total.bytes  = 0;

    st.frames = 0;
    st.bytes  = 0;

    idx = 0;

    sharkd_json_result_prologue(rpcid);
    sharkd_json_array_open("intervals");

    start_ts = (cfile.count >= 1) ? &(sharkd_get_frame(1)->abs_ts) : NULL;

    for (guint32 framenum = 1; framenum <= cfile.count; framenum++)
    {
        frame_data *fdata;
        gint64 msec_rel;
        gint64 new_idx;

        if (filter_data && !(filter_data[framenum / 8] & (1 << (framenum % 8))))
            continue;

        fdata = sharkd_get_frame(framenum);

        msec_rel = (fdata->abs_ts.secs - start_ts->secs) * (gint64) 1000 + (fdata->abs_ts.nsecs - start_ts->nsecs) / 1000000;
        new_idx  = msec_rel / interval_ms;

        if (idx != new_idx)
        {
            if (st.frames != 0)
            {
                sharkd_json_value_anyf(NULL, "[%" PRId64 ",%u,%" PRIu64 "]", idx, st.frames, st.bytes);
            }

            idx = new_idx;
            if (idx > max_idx)
                max_idx = idx;

            st.frames = 0;
            st.bytes  = 0;
        }

        st.frames += 1;
        st.bytes  += fdata->pkt_len;

        st_total.frames += 1;
        st_total.bytes  += fdata->pkt_len;
    }

    if (st.frames != 0)
    {
        sharkd_json_value_anyf(NULL, "[%" PRId64 ",%u,%" PRIu64 "]", idx, st.frames, st.bytes);
    }
    sharkd_json_array_close();

    sharkd_json_value_anyf("last", "%" PRId64, max_idx);
    sharkd_json_value_anyf("frames", "%u", st_total.frames);
    sharkd_json_value_anyf("bytes", "%" PRIu64, st_total.bytes);

    sharkd_json_result_epilogue();
}

/**
 * sharkd_session_process_frame()
 *
 * Process frame request
 *
 * Input:
 *   (m) frame - requested frame number
 *   (o) ref_frame - time reference frame number
 *   (o) prev_frame - previously displayed frame number
 *   (o) proto - set if output frame tree
 *   (o) columns - set if output frame columns
 *   (o) color - set if output color-filter bg/fg
 *   (o) bytes - set if output frame bytes
 *   (o) hidden - set if output hidden tree fields
 *
 * Output object with attributes:
 *   (m) err   - 0 if succeed
 *   (o) tree  - array of frame nodes with attributes:
 *                  l - label
 *                  t: 'proto', 'framenum', 'url' - type of node
 *                  f - filter string
 *                  s - severity
 *                  e - subtree ett index
 *                  n - array of subtree nodes
 *                  h - two item array: (item start, item length)
 *                  i - two item array: (appendix start, appendix length)
 *                  p - [RESERVED] two item array: (protocol start, protocol length)
 *                  ds- data src index
 *                  url  - only for t:'url', url
 *                  fnum - only for t:'framenum', frame number
 *                  g - if field is generated by Wireshark
 *                  v - if field is hidden
 *
 *   (o) col   - array of column data
 *   (o) bytes - base64 of frame bytes
 *   (o) ds    - array of other data srcs
 *   (o) comment - frame comment
 *   (o) fol   - array of follow filters:
 *                  [0] - protocol
 *                  [1] - filter string
 *   (o) i   - if frame is ignored
 *   (o) m   - if frame is marked
 *   (o) bg  - color filter - background color in hex
 *   (o) fg  - color filter - foreground color in hex
 */
static void
sharkd_session_process_frame(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_frame = json_find_attr(buf, tokens, count, "frame");
    const char *tok_ref_frame = json_find_attr(buf, tokens, count, "ref_frame");
    const char *tok_prev_frame = json_find_attr(buf, tokens, count, "prev_frame");
    column_info *cinfo = NULL;

    guint32 framenum, ref_frame_num, prev_dis_num;
    guint32 dissect_flags = SHARKD_DISSECT_FLAG_NULL;
    struct sharkd_frame_request_data req_data;
    wtap_rec rec; /* Record metadata */
    Buffer rec_buf;   /* Record data */
    enum dissect_request_status status;
    int err;
    gchar *err_info;

    ws_strtou32(tok_frame, NULL, &framenum);  // we have already validated this

    ref_frame_num = (framenum != 1) ? 1 : 0;
    if (tok_ref_frame)
    {
        ws_strtou32(tok_ref_frame, NULL, &ref_frame_num);
        if (ref_frame_num > framenum)
        {
            sharkd_json_error(
                    rpcid, -8001, NULL,
                    "Invalid ref_frame - The ref_frame occurs after the frame specified"
                    );
            return;
        }
    }

    prev_dis_num = framenum - 1;
    if (tok_prev_frame)
    {
        ws_strtou32(tok_prev_frame, NULL, &prev_dis_num);
        if (prev_dis_num >= framenum)
        {
            sharkd_json_error(
                    rpcid, -8002, NULL,
                    "Invalid prev_frame - The prev_frame occurs on or after the frame specified"
                    );
            return;
        }
    }

    if (json_find_attr(buf, tokens, count, "proto") != NULL)
        dissect_flags |= SHARKD_DISSECT_FLAG_PROTO_TREE;
    if (json_find_attr(buf, tokens, count, "bytes") != NULL)
        dissect_flags |= SHARKD_DISSECT_FLAG_BYTES;
    if (json_find_attr(buf, tokens, count, "columns") != NULL) {
        dissect_flags |= SHARKD_DISSECT_FLAG_COLUMNS;
        cinfo = &cfile.cinfo;
    }
    if (json_find_attr(buf, tokens, count, "color") != NULL)
        dissect_flags |= SHARKD_DISSECT_FLAG_COLOR;

    req_data.display_hidden = (json_find_attr(buf, tokens, count, "v") != NULL);

    wtap_rec_init(&rec);
    ws_buffer_init(&rec_buf, 1514);

    status = sharkd_dissect_request(framenum, ref_frame_num, prev_dis_num,
            &rec, &rec_buf, cinfo, dissect_flags,
            &sharkd_session_process_frame_cb, &req_data, &err, &err_info);
    switch (status) {

        case DISSECT_REQUEST_SUCCESS:
            /* success */
            break;

        case DISSECT_REQUEST_NO_SUCH_FRAME:
            sharkd_json_error(
                    rpcid, -8003, NULL,
                    "Invalid frame - The frame number requested is out of range"
                    );
            break;

        case DISSECT_REQUEST_READ_ERROR:
            sharkd_json_error(
                    rpcid, -8003, NULL,
                    /* XXX - show the error details */
                    "Read error - The frame could not be read from the file"
                    );
            g_free(err_info);
            break;
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&rec_buf);
}

/**
 * sharkd_session_process_check()
 *
 * Process check request.
 *
 * Input:
 *   (o) filter - filter to be checked
 *   (o) field - field to be checked
 *
 * Output object with attributes:
 *   (m) err - always 0
 *   (o) filter - 'ok', 'warn' or error message
 *   (o) field - 'ok', or 'notfound'
 */
static int
sharkd_session_process_check(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_filter = json_find_attr(buf, tokens, count, "filter");
    const char *tok_field = json_find_attr(buf, tokens, count, "field");

    if (tok_filter != NULL)
    {
        char *err_msg = NULL;
        dfilter_t *dfp;

        if (dfilter_compile(tok_filter, &dfp, &err_msg))
        {
            if (dfp && dfilter_deprecated_tokens(dfp))
                sharkd_json_warning(rpcid, err_msg);
            else
                sharkd_json_simple_ok(rpcid);

            dfilter_free(dfp);
            g_free(err_msg);
            return 0;
        }
        else
        {
            sharkd_json_error(
                    rpcid, -5001, NULL,
                    "Filter invalid - %s", err_msg
                    );
            return -5001;
        }
    }

    if (tok_field != NULL)
    {
        header_field_info *hfi = proto_registrar_get_byname(tok_field);

        if (!hfi)
        {
            sharkd_json_error(
                    rpcid, -5002, NULL,
                    "Field %s not found", tok_field
                    );
            return -5002;
        }
        else
        {
            sharkd_json_simple_ok(rpcid);
            return 0;
        }
    }

    sharkd_json_simple_ok(rpcid);
    return 0;
}

struct sharkd_session_process_complete_pref_data
{
    const char *module;
    const char *pref;
};

static guint
sharkd_session_process_complete_pref_cb(module_t *module, gpointer d)
{
    struct sharkd_session_process_complete_pref_data *data = (struct sharkd_session_process_complete_pref_data *) d;

    if (strncmp(data->pref, module->name, strlen(data->pref)) != 0)
        return 0;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_string("f", module->name);
    sharkd_json_value_string("d", module->title);
    json_dumper_end_object(&dumper);

    return 0;
}

static guint
sharkd_session_process_complete_pref_option_cb(pref_t *pref, gpointer d)
{
    struct sharkd_session_process_complete_pref_data *data = (struct sharkd_session_process_complete_pref_data *) d;
    const char *pref_name = prefs_get_name(pref);
    const char *pref_title = prefs_get_title(pref);

    if (strncmp(data->pref, pref_name, strlen(data->pref)) != 0)
        return 0;

    json_dumper_begin_object(&dumper);
    sharkd_json_value_stringf("f", "%s.%s", data->module, pref_name);
    sharkd_json_value_string("d", pref_title);
    json_dumper_end_object(&dumper);

    return 0; /* continue */
}

/**
 * sharkd_session_process_complete()
 *
 * Process complete request
 *
 * Input:
 *   (o) field - field to be completed
 *   (o) pref  - preference to be completed
 *
 * Output object with attributes:
 *   (m) err - always 0
 *   (o) field - array of object with attributes:
 *                  (m) f - field text
 *                  (o) t - field type (FT_ number)
 *                  (o) n - field name
 *   (o) pref  - array of object with attributes:
 *                  (m) f - pref name
 *                  (o) d - pref description
 */
static int
sharkd_session_process_complete(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_field = json_find_attr(buf, tokens, count, "field");
    const char *tok_pref  = json_find_attr(buf, tokens, count, "pref");

    sharkd_json_result_prologue(rpcid);

    if (tok_field != NULL && tok_field[0])
    {
        const size_t filter_length = strlen(tok_field);
        const int filter_with_dot = !!strchr(tok_field, '.');

        void *proto_cookie;
        void *field_cookie;
        int proto_id;

        sharkd_json_array_open("field");

        for (proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie))
        {
            protocol_t *protocol = find_protocol_by_id(proto_id);
            const char *protocol_filter;
            const char *protocol_name;
            header_field_info *hfinfo;

            if (!proto_is_protocol_enabled(protocol))
                continue;

            protocol_name   = proto_get_protocol_long_name(protocol);
            protocol_filter = proto_get_protocol_filter_name(proto_id);

            if (strlen(protocol_filter) >= filter_length && !g_ascii_strncasecmp(tok_field, protocol_filter, filter_length))
            {
                json_dumper_begin_object(&dumper);
                {
                    sharkd_json_value_string("f", protocol_filter);
                    sharkd_json_value_anyf("t", "%d", FT_PROTOCOL);
                    sharkd_json_value_string("n", protocol_name);
                }
                json_dumper_end_object(&dumper);
            }

            if (!filter_with_dot)
                continue;

            for (hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie))
            {
                if (hfinfo->same_name_prev_id != -1) /* ignore duplicate names */
                    continue;

                if (strlen(hfinfo->abbrev) >= filter_length && !g_ascii_strncasecmp(tok_field, hfinfo->abbrev, filter_length))
                {
                    json_dumper_begin_object(&dumper);
                    {
                        sharkd_json_value_string("f", hfinfo->abbrev);

                        /* XXX, skip displaying name, if there are multiple (to not confuse user) */
                        if (hfinfo->same_name_next == NULL)
                        {
                            sharkd_json_value_anyf("t", "%d", hfinfo->type);
                            sharkd_json_value_string("n", hfinfo->name);
                        }
                    }
                    json_dumper_end_object(&dumper);
                }
            }
        }

        sharkd_json_array_close();
    }

    if (tok_pref != NULL && tok_pref[0])
    {
        struct sharkd_session_process_complete_pref_data data;
        char *dot_sepa;

        data.module = tok_pref;
        data.pref = tok_pref;

        sharkd_json_array_open("pref");
        if ((dot_sepa = strchr(tok_pref, '.')))
        {
            module_t *pref_mod;

            *dot_sepa = '\0'; /* XXX, C abuse: discarding-const */
            data.pref = dot_sepa + 1;

            pref_mod = prefs_find_module(data.module);
            if (pref_mod)
                prefs_pref_foreach(pref_mod, sharkd_session_process_complete_pref_option_cb, &data);

            *dot_sepa = '.';
        }
        else
        {
            prefs_modules_foreach(sharkd_session_process_complete_pref_cb, &data);
        }
        sharkd_json_array_close();
    }

    sharkd_json_result_epilogue();

    return 0;
}

/**
 * sharkd_session_process_setcomment()
 *
 * Process setcomment request
 *
 * Input:
 *   (m) frame - frame number
 *   (o) comment - user comment
 *
 * Output object with attributes:
 *   (m) err   - error code: 0 succeed
 *
 * Note:
 *   For now, adds comments, doesn't remove or replace them.
 */
static void
sharkd_session_process_setcomment(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_frame   = json_find_attr(buf, tokens, count, "frame");
    const char *tok_comment = json_find_attr(buf, tokens, count, "comment");

    guint32 framenum;
    frame_data *fdata;
    wtap_opttype_return_val ret;
    wtap_block_t pkt_block = NULL;

    if (!tok_frame || !ws_strtou32(tok_frame, NULL, &framenum) || framenum == 0)
    {
        sharkd_json_error(
                rpcid, -3001, NULL,
                "Frame number must be a positive integer"
                );
        return;
    }

    fdata = sharkd_get_frame(framenum);  // BUG HERE - If no file loaded you get a crash
    if (!fdata)
    {
        sharkd_json_error(
                rpcid, -3002, NULL,
                "Frame number is out of range"
                );
        return;
    }

    pkt_block = sharkd_get_packet_block(fdata);

    ret = wtap_block_add_string_option(pkt_block, OPT_COMMENT, tok_comment, strlen(tok_comment));

    if (ret != WTAP_OPTTYPE_SUCCESS)
    {
        sharkd_json_error(
                rpcid, -3003, NULL,
                "Unable to set the comment"
                );
    }
    else
    {
        sharkd_set_modified_block(fdata, pkt_block);
        sharkd_json_simple_ok(rpcid);
    }
}

/**
 * sharkd_session_process_setconf()
 *
 * Process setconf request
 *
 * Input:
 *   (m) name  - preference name
 *   (m) value - preference value
 *
 * Output object with attributes:
 *   (m) err   - error code: 0 succeed
 */
static void
sharkd_session_process_setconf(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_name = json_find_attr(buf, tokens, count, "name");
    const char *tok_value = json_find_attr(buf, tokens, count, "value");
    char pref[4096];
    char *errmsg = NULL;

    prefs_set_pref_e ret;

    if (!tok_name || tok_name[0] == '\0')
    {
        sharkd_json_error(
                rpcid, -4001, NULL,
                "Preference name missing"
                );
        return;
    }

    if (!tok_value)
    {
        sharkd_json_error(
                rpcid, -4002, NULL,
                "Preference value missing"
                );
        return;
    }

    snprintf(pref, sizeof(pref), "%s:%s", tok_name, tok_value);

    ret = prefs_set_pref(pref, &errmsg);

    switch (ret)
    {
        case PREFS_SET_OK:
            sharkd_json_simple_ok(rpcid);
            break;

        case PREFS_SET_OBSOLETE:
            sharkd_json_error(
                    rpcid, -4003, NULL,
                    "The preference specified is obsolete"
                    );
            break;

        case PREFS_SET_NO_SUCH_PREF:
            sharkd_json_error(
                    rpcid, -4004, NULL,
                    "No such preference exists"
                    );
            break;

        default:
            sharkd_json_error(
                    rpcid, -4005, NULL,
                    "Unable to set the preference"
                    );
    }

    g_free(errmsg);
}

struct sharkd_session_process_dumpconf_data
{
    module_t *module;
};

static guint
sharkd_session_process_dumpconf_cb(pref_t *pref, gpointer d)
{
    struct sharkd_session_process_dumpconf_data *data = (struct sharkd_session_process_dumpconf_data *) d;
    const char *pref_name = prefs_get_name(pref);

    char json_pref_key[512];

    snprintf(json_pref_key, sizeof(json_pref_key), "%s.%s", data->module->name, pref_name);
    json_dumper_set_member_name(&dumper, json_pref_key);
    json_dumper_begin_object(&dumper);

    switch (prefs_get_type(pref))
    {
        case PREF_UINT:
        case PREF_DECODE_AS_UINT:
            sharkd_json_value_anyf("u", "%u", prefs_get_uint_value_real(pref, pref_current));
            if (prefs_get_uint_base(pref) != 10)
                sharkd_json_value_anyf("ub", "%u", prefs_get_uint_base(pref));
            break;

        case PREF_BOOL:
            sharkd_json_value_anyf("b", prefs_get_bool_value(pref, pref_current) ? "1" : "0");
            break;

        case PREF_STRING:
        case PREF_SAVE_FILENAME:
        case PREF_OPEN_FILENAME:
        case PREF_DIRNAME:
        case PREF_PASSWORD:
            sharkd_json_value_string("s", prefs_get_string_value(pref, pref_current));
            break;

        case PREF_ENUM:
            {
                const enum_val_t *enums;

                sharkd_json_array_open("e");
                for (enums = prefs_get_enumvals(pref); enums->name; enums++)
                {
                    json_dumper_begin_object(&dumper);

                    sharkd_json_value_anyf("v", "%d", enums->value);

                    if (enums->value == prefs_get_enum_value(pref, pref_current))
                        sharkd_json_value_anyf("s", "1");

                    sharkd_json_value_string("d", enums->description);

                    json_dumper_end_object(&dumper);
                }
                sharkd_json_array_close();
                break;
            }

        case PREF_RANGE:
        case PREF_DECODE_AS_RANGE:
            {
                char *range_str = range_convert_range(NULL, prefs_get_range_value_real(pref, pref_current));
                sharkd_json_value_string("r", range_str);
                wmem_free(NULL, range_str);
                break;
            }

        case PREF_UAT:
            {
                uat_t *uat = prefs_get_uat_value(pref);
                guint idx;

                sharkd_json_array_open("t");
                for (idx = 0; idx < uat->raw_data->len; idx++)
                {
                    void *rec = UAT_INDEX_PTR(uat, idx);
                    guint colnum;

                    sharkd_json_array_open(NULL);
                    for (colnum = 0; colnum < uat->ncols; colnum++)
                    {
                        char *str = uat_fld_tostr(rec, &(uat->fields[colnum]));

                        sharkd_json_value_string(NULL, str);
                        g_free(str);
                    }

                    sharkd_json_array_close();
                }

                sharkd_json_array_close();
                break;
            }

        case PREF_COLOR:
        case PREF_CUSTOM:
        case PREF_STATIC_TEXT:
        case PREF_OBSOLETE:
            /* TODO */
            break;
    }

#if 0
    sharkd_json_value_string("t", prefs_get_title(pref));
#endif

    json_dumper_end_object(&dumper);

    return 0; /* continue */
}

static guint
sharkd_session_process_dumpconf_mod_cb(module_t *module, gpointer d)
{
    struct sharkd_session_process_dumpconf_data *data = (struct sharkd_session_process_dumpconf_data *) d;

    data->module = module;
    prefs_pref_foreach(module, sharkd_session_process_dumpconf_cb, data);

    return 0;
}

/**
 * sharkd_session_process_dumpconf()
 *
 * Process dumpconf request
 *
 * Input:
 *   (o) pref - module, or preference, NULL for all
 *
 * Output object with attributes:
 *   (o) prefs   - object with module preferences
 *                  (m) [KEY] - preference name
 *                  (o) u - preference value (for PREF_UINT, PREF_DECODE_AS_UINT)
 *                  (o) ub - preference value suggested base for display (for PREF_UINT, PREF_DECODE_AS_UINT) and if different than 10
 *                  (o) b - preference value (only for PREF_BOOL) (1 true, 0 false)
 *                  (o) s - preference value (for PREF_STRING, PREF_SAVE_FILENAME, PREF_OPEN_FILENAME, PREF_DIRNAME, PREF_PASSWORD)
 *                  (o) e - preference possible values (only for PREF_ENUM)
 *                  (o) r - preference value (for PREF_RANGE, PREF_DECODE_AS_RANGE)
 *                  (o) t - preference value (only for PREF_UAT)
 */
static void
sharkd_session_process_dumpconf(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_pref = json_find_attr(buf, tokens, count, "pref");
    module_t *pref_mod;
    char *dot_sepa;

    if (!tok_pref)
    {
        struct sharkd_session_process_dumpconf_data data;

        data.module = NULL;

        sharkd_json_result_prologue(rpcid);

        sharkd_json_value_anyf("prefs", NULL);
        json_dumper_begin_object(&dumper);
        prefs_modules_foreach(sharkd_session_process_dumpconf_mod_cb, &data);
        json_dumper_end_object(&dumper);

        sharkd_json_result_epilogue();
        return;
    }

    if ((dot_sepa = strchr(tok_pref, '.')))
    {
        pref_t *pref = NULL;

        *dot_sepa = '\0'; /* XXX, C abuse: discarding-const */
        pref_mod = prefs_find_module(tok_pref);
        if (pref_mod)
            pref = prefs_find_preference(pref_mod, dot_sepa + 1);
        *dot_sepa = '.';

        if (pref)
        {
            struct sharkd_session_process_dumpconf_data data;

            data.module = pref_mod;

            sharkd_json_result_prologue(rpcid);

            sharkd_json_value_anyf("prefs", NULL);
            json_dumper_begin_object(&dumper);
            sharkd_session_process_dumpconf_cb(pref, &data);
            json_dumper_end_object(&dumper);

            sharkd_json_result_epilogue();
            return;
        }
        else
        {
            sharkd_json_error(
                    rpcid, -9001, NULL,
                    "Invalid pref %s.", tok_pref
                    );
            return;
        }

    }

    pref_mod = prefs_find_module(tok_pref);
    if (pref_mod)
    {
        struct sharkd_session_process_dumpconf_data data;

        data.module = pref_mod;

        sharkd_json_result_prologue(rpcid);

        sharkd_json_value_anyf("prefs", NULL);
        json_dumper_begin_object(&dumper);
        prefs_pref_foreach(pref_mod, sharkd_session_process_dumpconf_cb, &data);
        json_dumper_end_object(&dumper);

        sharkd_json_result_epilogue();
    }
    else
    {
        sharkd_json_error(
                rpcid, -9002, NULL,
                "Invalid pref %s.", tok_pref
                );
    }
}

struct sharkd_download_rtp
{
    rtpstream_id_t id;
    GSList *packets;
    double start_time;
};

static void
sharkd_rtp_download_free_items(void *ptr)
{
    rtp_packet_t *rtp_packet = (rtp_packet_t *) ptr;

    g_free(rtp_packet->info);
    g_free(rtp_packet->payload_data);
    g_free(rtp_packet);
}

static void
sharkd_rtp_download_decode(struct sharkd_download_rtp *req)
{
    /* based on RtpAudioStream::decode() 6e29d874f8b5e6ebc59f661a0bb0dab8e56f122a */
    /* TODO, for now only without silence (timing_mode_ = Uninterrupted) */

    static const int sample_bytes_ = sizeof(SAMPLE) / sizeof(char);

    guint32 audio_out_rate_ = 0;
    struct _GHashTable *decoders_hash_ = rtp_decoder_hash_table_new();
    struct SpeexResamplerState_ *audio_resampler_ = NULL;

    gsize resample_buff_len = 0x1000;
    SAMPLE *resample_buff = (SAMPLE *) g_malloc(resample_buff_len);
    spx_uint32_t cur_in_rate = 0;
    char *write_buff = NULL;
    size_t write_bytes = 0;
    unsigned channels = 0;
    unsigned sample_rate = 0;

    GSList *l;

    for (l = req->packets; l; l = l->next)
    {
        rtp_packet_t *rtp_packet = (rtp_packet_t *) l->data;

        SAMPLE *decode_buff = NULL;
        size_t decoded_bytes;

        decoded_bytes = decode_rtp_packet(rtp_packet, &decode_buff, decoders_hash_, &channels, &sample_rate);
        if (decoded_bytes == 0 || sample_rate == 0)
        {
            /* We didn't decode anything. Clean up and prep for the next packet. */
            g_free(decode_buff);
            continue;
        }

        if (audio_out_rate_ == 0)
        {
            guint32 tmp32;
            guint16 tmp16;
            char wav_hdr[44];

            /* First non-zero wins */
            audio_out_rate_ = sample_rate;

            RTP_STREAM_DEBUG("Audio sample rate is %u", audio_out_rate_);

            /* write WAVE header */
            memset(&wav_hdr, 0, sizeof(wav_hdr));
            memcpy(&wav_hdr[0], "RIFF", 4);
            memcpy(&wav_hdr[4], "\xFF\xFF\xFF\xFF", 4); /* XXX, unknown */
            memcpy(&wav_hdr[8], "WAVE", 4);

            memcpy(&wav_hdr[12], "fmt ", 4);
            memcpy(&wav_hdr[16], "\x10\x00\x00\x00", 4); /* PCM */
            memcpy(&wav_hdr[20], "\x01\x00", 2);         /* PCM */
            /* # channels */
            tmp16 = channels;
            memcpy(&wav_hdr[22], &tmp16, 2);
            /* sample rate */
            tmp32 = sample_rate;
            memcpy(&wav_hdr[24], &tmp32, 4);
            /* byte rate */
            tmp32 = sample_rate * channels * sample_bytes_;
            memcpy(&wav_hdr[28], &tmp32, 4);
            /* block align */
            tmp16 = channels * sample_bytes_;
            memcpy(&wav_hdr[32], &tmp16, 2);
            /* bits per sample */
            tmp16 = 8 * sample_bytes_;
            memcpy(&wav_hdr[34], &tmp16, 2);

            memcpy(&wav_hdr[36], "data", 4);
            memcpy(&wav_hdr[40], "\xFF\xFF\xFF\xFF", 4); /* XXX, unknown */

            json_dumper_write_base64(&dumper, wav_hdr, sizeof(wav_hdr));
        }

        // Write samples to our file.
        write_buff = (char *) decode_buff;
        write_bytes = decoded_bytes;

        if (audio_out_rate_ != sample_rate)
        {
            spx_uint32_t in_len, out_len;

            /* Resample the audio to match our previous output rate. */
            if (!audio_resampler_)
            {
                audio_resampler_ = speex_resampler_init(1, sample_rate, audio_out_rate_, 10, NULL);
                speex_resampler_skip_zeros(audio_resampler_);
                RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, audio_out_rate_);
            }
            else
            {
                spx_uint32_t audio_out_rate;
                speex_resampler_get_rate(audio_resampler_, &cur_in_rate, &audio_out_rate);

                if (sample_rate != cur_in_rate)
                {
                    speex_resampler_set_rate(audio_resampler_, sample_rate, audio_out_rate);
                    RTP_STREAM_DEBUG("Changed input rate from %u to %u Hz. Out is %u.", cur_in_rate, sample_rate, audio_out_rate_);
                }
            }
            in_len = (spx_uint32_t)rtp_packet->info->info_payload_len;
            out_len = (audio_out_rate_ * (spx_uint32_t)rtp_packet->info->info_payload_len / sample_rate) + (audio_out_rate_ % sample_rate != 0);
            if (out_len * sample_bytes_ > resample_buff_len)
            {
                while ((out_len * sample_bytes_ > resample_buff_len))
                    resample_buff_len *= 2;
                resample_buff = (SAMPLE *) g_realloc(resample_buff, resample_buff_len);
            }

            speex_resampler_process_int(audio_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
            write_buff = (char *) resample_buff;
            write_bytes = out_len * sample_bytes_;
        }

        /* Write the decoded, possibly-resampled audio */
        json_dumper_write_base64(&dumper, write_buff, write_bytes);

        g_free(decode_buff);
    }

    g_free(resample_buff);
    g_hash_table_destroy(decoders_hash_);
}

static tap_packet_status
sharkd_session_packet_download_tap_rtp_cb(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    const struct _rtp_info *rtp_info = (const struct _rtp_info *) data;
    struct sharkd_download_rtp *req_rtp = (struct sharkd_download_rtp *) tapdata;

    /* do not consider RTP packets without a setup frame */
    if (rtp_info->info_setup_frame_num == 0)
        return TAP_PACKET_DONT_REDRAW;

    if (rtpstream_id_equal_pinfo_rtp_info(&req_rtp->id, pinfo, rtp_info))
    {
        rtp_packet_t *rtp_packet;

        rtp_packet = g_new0(rtp_packet_t, 1);
        rtp_packet->info = (struct _rtp_info *) g_memdup2(rtp_info, sizeof(struct _rtp_info));

        if (rtp_info->info_all_data_present && rtp_info->info_payload_len != 0)
            rtp_packet->payload_data = (guint8 *) g_memdup2(&(rtp_info->info_data[rtp_info->info_payload_offset]), rtp_info->info_payload_len);

        if (!req_rtp->packets)
            req_rtp->start_time = nstime_to_sec(&pinfo->abs_ts);

        rtp_packet->frame_num = pinfo->num;
        rtp_packet->arrive_offset = nstime_to_sec(&pinfo->abs_ts) - req_rtp->start_time;

        /* XXX, O(n) optimize */
        req_rtp->packets = g_slist_append(req_rtp->packets, rtp_packet);
    }

    return TAP_PACKET_DONT_REDRAW;
}

/**
 * sharkd_session_process_download()
 *
 * Process download request
 *
 * Input:
 *   (m) token  - token to download
 *
 * Output object with attributes:
 *   (o) file - suggested name of file
 *   (o) mime - suggested content type
 *   (o) data - payload base64 encoded
 */
static void
sharkd_session_process_download(char *buf, const jsmntok_t *tokens, int count)
{
    const char *tok_token      = json_find_attr(buf, tokens, count, "token");

    if (!tok_token)
        return;

    if (!strncmp(tok_token, "eo:", 3))
    {
        struct sharkd_export_object_list *object_list;
        const export_object_entry_t *eo_entry = NULL;

        for (object_list = sharkd_eo_list; object_list; object_list = object_list->next)
        {
            size_t eo_type_len = strlen(object_list->type);

            if (!strncmp(tok_token, object_list->type, eo_type_len) && tok_token[eo_type_len] == '_')
            {
                int row;

                if (sscanf(&tok_token[eo_type_len + 1], "%d", &row) != 1)
                    break;

                eo_entry = (export_object_entry_t *) g_slist_nth_data(object_list->entries, row);
                break;
            }
        }

        if (eo_entry)
        {
            const char *mime     = (eo_entry->content_type) ? eo_entry->content_type : "application/octet-stream";
            const char *filename = (eo_entry->filename) ? eo_entry->filename : tok_token;

            sharkd_json_result_prologue(rpcid);
            sharkd_json_value_string("file", filename);
            sharkd_json_value_string("mime", mime);
            sharkd_json_value_base64("data", eo_entry->payload_data, eo_entry->payload_len);
            sharkd_json_result_epilogue();
        }
        else
        {
            sharkd_json_result_prologue(rpcid);
            sharkd_json_result_epilogue();
        }
    }
    else if (!strcmp(tok_token, "ssl-secrets"))
    {
        gsize str_len;
        char *str = ssl_export_sessions(&str_len);

        if (str)
        {
            const char *mime     = "text/plain";
            const char *filename = "keylog.txt";

            sharkd_json_result_prologue(rpcid);
            sharkd_json_value_string("file", filename);
            sharkd_json_value_string("mime", mime);
            sharkd_json_value_base64("data", str, str_len);
            sharkd_json_result_epilogue();
        }
        g_free(str);
    }
    else if (!strncmp(tok_token, "rtp:", 4))
    {
        struct sharkd_download_rtp rtp_req;
        GString *tap_error;

        memset(&rtp_req, 0, sizeof(rtp_req));
        if (!sharkd_rtp_match_init(&rtp_req.id, tok_token + 4))
        {
            sharkd_json_error(
                    rpcid, -10001, NULL,
                    "sharkd_session_process_download() rtp tokenizing error %s", tok_token
                    );
            return;
        }

        tap_error = register_tap_listener("rtp", &rtp_req, NULL, 0, NULL, sharkd_session_packet_download_tap_rtp_cb, NULL, NULL);
        if (tap_error)
        {
            sharkd_json_error(
                    rpcid, -10002, NULL,
                    "sharkd_session_process_download() rtp error %s", tap_error->str
                    );
            g_string_free(tap_error, TRUE);
            return;
        }

        sharkd_retap();
        remove_tap_listener(&rtp_req);

        if (rtp_req.packets)
        {
            const char *mime     = "audio/x-wav";
            const char *filename = tok_token;

            sharkd_json_result_prologue(rpcid);
            sharkd_json_value_string("file", filename);
            sharkd_json_value_string("mime", mime);

            sharkd_json_value_anyf("data", NULL);
            json_dumper_begin_base64(&dumper);
            sharkd_rtp_download_decode(&rtp_req);
            json_dumper_end_base64(&dumper);

            sharkd_json_result_epilogue();

            g_slist_free_full(rtp_req.packets, sharkd_rtp_download_free_items);
        }
    }
}

static void
sharkd_session_process(char *buf, const jsmntok_t *tokens, int count)
{
    if (json_prep(buf, tokens, count))
    {
        /* don't need [0] token */
        tokens++;
        count--;

        const char* tok_method = json_find_attr(buf, tokens, count, "method");

        if (!tok_method) {
            sharkd_json_error(
                    rpcid, -32601, NULL,
                    "No method found");
            return;
        }
        if (!strcmp(tok_method, "load"))
            sharkd_session_process_load(buf, tokens, count);
        else if (!strcmp(tok_method, "status"))
            sharkd_session_process_status();
        else if (!strcmp(tok_method, "analyse"))
            sharkd_session_process_analyse();
        else if (!strcmp(tok_method, "info"))
            sharkd_session_process_info();
        else if (!strcmp(tok_method, "check"))
            sharkd_session_process_check(buf, tokens, count);
        else if (!strcmp(tok_method, "complete"))
            sharkd_session_process_complete(buf, tokens, count);
        else if (!strcmp(tok_method, "frames"))
            sharkd_session_process_frames(buf, tokens, count);
        else if (!strcmp(tok_method, "tap"))
            sharkd_session_process_tap(buf, tokens, count);
        else if (!strcmp(tok_method, "follow"))
            sharkd_session_process_follow(buf, tokens, count);
        else if (!strcmp(tok_method, "iograph"))
            sharkd_session_process_iograph(buf, tokens, count);
        else if (!strcmp(tok_method, "intervals"))
            sharkd_session_process_intervals(buf, tokens, count);
        else if (!strcmp(tok_method, "frame"))
            sharkd_session_process_frame(buf, tokens, count);
        else if (!strcmp(tok_method, "setcomment"))
            sharkd_session_process_setcomment(buf, tokens, count);
        else if (!strcmp(tok_method, "setconf"))
            sharkd_session_process_setconf(buf, tokens, count);
        else if (!strcmp(tok_method, "dumpconf"))
            sharkd_session_process_dumpconf(buf, tokens, count);
        else if (!strcmp(tok_method, "download"))
            sharkd_session_process_download(buf, tokens, count);
        else if (!strcmp(tok_method, "bye"))
        {
            sharkd_json_simple_ok(rpcid);
            exit(0);
        }
        else
        {
            sharkd_json_error(
                    rpcid, -32601, NULL,
                    "The method \"%s\" is unknown", tok_method
                    );
        }
    }
}

int
sharkd_session_main(int mode_setting)
{
    char buf[2 * 1024];
    jsmntok_t *tokens = NULL;
    int tokens_max = -1;

    mode = mode_setting;

    fprintf(stderr, "Hello in child.\n");

    dumper.output_file = stdout;

    filter_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, sharkd_session_filter_free);

#ifdef HAVE_MAXMINDDB
    /* mmdbresolve was stopped before fork(), force starting it */
    uat_get_table_by_name("MaxMind Database Paths")->post_update_cb();
#endif

    while (fgets(buf, sizeof(buf), stdin))
    {
        /* every command is line seperated JSON */
        int ret;

        ret = json_parse(buf, NULL, 0);
        if (ret <= 0)
        {
            sharkd_json_error(
                    rpcid, -32600, NULL,
                    "Invalid JSON(1)"
                    );
            continue;
        }

        /* fprintf(stderr, "JSON: %d tokens\n", ret); */
        ret += 1;

        if (tokens == NULL || tokens_max < ret)
        {
            tokens_max = ret;
            tokens = (jsmntok_t *) g_realloc(tokens, sizeof(jsmntok_t) * tokens_max);
        }

        memset(tokens, 0, ret * sizeof(jsmntok_t));

        ret = json_parse(buf, tokens, ret);
        if (ret <= 0)
        {
            sharkd_json_error(
                    rpcid, -32600, NULL,
                    "Invalid JSON(2)"
                    );
            continue;
        }

        host_name_lookup_process();

        sharkd_session_process(buf, tokens, ret);
    }

    g_hash_table_destroy(filter_table);
    g_free(tokens);

    return 0;
}
