/* print.c
 * Routines for printing packet analysis trees.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/packet-range.h>
#include <epan/prefs.h>
#include <epan/print.h>
#include <epan/charsets.h>
#include <wsutil/filesystem.h>
#include <ws_version_info.h>
#include <wsutil/utf8_entities.h>
#include <ftypes/ftypes-int.h>

#define PDML_VERSION "0"
#define PSML_VERSION "0"

typedef struct {
    int                  level;
    print_stream_t      *stream;
    gboolean             success;
    GSList              *src_list;
    print_dissections_e  print_dissections;
    gboolean             print_hex_for_data;
    packet_char_enc      encoding;
    GHashTable          *output_only_tables; /* output only these protocols */
} print_data;

typedef struct {
    int             level;
    FILE           *fh;
    GSList         *src_list;
    gchar         **filter;
} write_pdml_data;

typedef struct {
    int             level;
    FILE           *fh;
    GSList         *src_list;
    gchar         **filter;
    gboolean        print_hex;
} write_json_data;

typedef struct {
    output_fields_t *fields;
    epan_dissect_t  *edt;
} write_field_data_t;

struct _output_fields {
    gboolean      print_bom;
    gboolean      print_header;
    gchar         separator;
    gchar         occurrence;
    gchar         aggregator;
    GPtrArray    *fields;
    GHashTable   *field_indicies;
    GPtrArray   **field_values;
    gchar         quote;
    gboolean      includes_col_fields;
};

static gchar *get_field_hex_value(GSList *src_list, field_info *fi);
static void proto_tree_print_node(proto_node *node, gpointer data);
static void proto_tree_write_node_pdml(proto_node *node, gpointer data);
static void proto_tree_write_node_json(proto_node *node, gpointer data);
static void proto_tree_write_node_ek(proto_node *node, gpointer data);
static const guint8 *get_field_data(GSList *src_list, field_info *fi);
static void pdml_write_field_hex_value(write_pdml_data *pdata, field_info *fi);
static void json_write_field_hex_value(write_json_data *pdata, field_info *fi);
static gboolean print_hex_data_buffer(print_stream_t *stream, const guchar *cp,
                                      guint length, packet_char_enc encoding);
static void write_specified_fields(fields_format format,
                                   output_fields_t *fields,
                                   epan_dissect_t *edt, column_info *cinfo,
                                   FILE *fh);
static void print_escaped_xml(FILE *fh, const char *unescaped_string);
static void print_escaped_json(FILE *fh, const char *unescaped_string);
static void print_escaped_ek(FILE *fh, const char *unescaped_string);

static void print_pdml_geninfo(proto_tree *tree, FILE *fh);

static void proto_tree_get_node_field_values(proto_node *node, gpointer data);

static gboolean json_is_first;

/* Cache the protocols and field handles that the print functionality needs
   This helps break explicit dependency on the dissectors. */
static int proto_data = -1;
static int proto_frame = -1;
static int hf_frame_arrival_time = -1;
static int hf_frame_number = -1;
static int hf_frame_len = -1;
static int hf_frame_capture_len = -1;

void print_cache_field_handles(void)
{
    proto_data = proto_get_id_by_short_name("Data");
    proto_frame = proto_get_id_by_short_name("Frame");
    hf_frame_arrival_time = proto_registrar_get_id_byname("frame.time");
    hf_frame_number = proto_registrar_get_id_byname("frame.number");
    hf_frame_len = proto_registrar_get_id_byname("frame.len");
    hf_frame_capture_len = proto_registrar_get_id_byname("frame.cap_len");
}

gboolean
proto_tree_print(print_args_t *print_args, epan_dissect_t *edt,
                 GHashTable *output_only_tables, print_stream_t *stream)
{
    print_data data;

    /* Create the output */
    data.level              = 0;
    data.stream             = stream;
    data.success            = TRUE;
    data.src_list           = edt->pi.data_src;
    data.encoding           = (packet_char_enc)edt->pi.fd->flags.encoding;
    data.print_dissections  = print_args->print_dissections;
    /* If we're printing the entire packet in hex, don't
       print uninterpreted data fields in hex as well. */
    data.print_hex_for_data = !print_args->print_hex;
    data.output_only_tables = output_only_tables;

    proto_tree_children_foreach(edt->tree, proto_tree_print_node, &data);
    return data.success;
}

/* Print a tree's data, and any child nodes. */
static void
proto_tree_print_node(proto_node *node, gpointer data)
{
    field_info   *fi    = PNODE_FINFO(node);
    print_data   *pdata = (print_data*) data;
    const guint8 *pd;
    gchar         label_str[ITEM_LABEL_LENGTH];
    gchar        *label_ptr;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    /* Don't print invisible entries. */
    if (PROTO_ITEM_IS_HIDDEN(node) && (prefs.display_hidden_proto_items == FALSE))
        return;

    /* Give up if we've already gotten an error. */
    if (!pdata->success)
        return;

    /* was a free format label produced? */
    if (fi->rep) {
        label_ptr = fi->rep->representation;
    }
    else { /* no, make a generic label */
        label_ptr = label_str;
        proto_item_fill_label(fi, label_str);
    }

    if (PROTO_ITEM_IS_GENERATED(node))
        label_ptr = g_strconcat("[", label_ptr, "]", NULL);

    pdata->success = print_line(pdata->stream, pdata->level, label_ptr);

    if (PROTO_ITEM_IS_GENERATED(node))
        g_free(label_ptr);

    if (!pdata->success)
        return;

    /*
     * If -O is specified, only display the protocols which are in the
     * lookup table.  Only check on the first level: once we start printing
     * a tree, print the rest of the subtree.  Otherwise we won't print
     * subitems whose abbreviation doesn't match the protocol--for example
     * text items (whose abbreviation is simply "text").
     */
    if ((pdata->output_only_tables != NULL) && (pdata->level == 0)
        && (g_hash_table_lookup(pdata->output_only_tables, fi->hfinfo->abbrev) == NULL)) {
        return;
    }

    /* If it's uninterpreted data, dump it (unless our caller will
       be printing the entire packet in hex). */
    if ((fi->hfinfo->id == proto_data) && (pdata->print_hex_for_data)) {
        /*
         * Find the data for this field.
         */
        pd = get_field_data(pdata->src_list, fi);
        if (pd) {
            if (!print_line(pdata->stream, 0, "")) {
                pdata->success = FALSE;
                return;
            }
            if (!print_hex_data_buffer(pdata->stream, pd,
                                       fi->length, pdata->encoding)) {
                pdata->success = FALSE;
                return;
            }
        }
    }

    /* If we're printing all levels, or if this node is one with a
       subtree and its subtree is expanded, recurse into the subtree,
       if it exists. */
    g_assert((fi->tree_type >= -1) && (fi->tree_type < num_tree_types));
    if ((pdata->print_dissections == print_dissections_expanded) ||
        ((pdata->print_dissections == print_dissections_as_displayed) &&
         (fi->tree_type >= 0) && tree_expanded(fi->tree_type))) {
        if (node->first_child != NULL) {
            pdata->level++;
            proto_tree_children_foreach(node,
                                        proto_tree_print_node, pdata);
            pdata->level--;
            if (!pdata->success)
                return;
        }
    }
}

#define PDML2HTML_XSL "pdml2html.xsl"
void
write_pdml_preamble(FILE *fh, const gchar *filename)
{
    time_t t = time(NULL);
    struct tm * timeinfo;
    char *fmt_ts;
    const char *ts;

    /* Create the output */
    timeinfo = localtime(&t);
    if (timeinfo != NULL) {
        fmt_ts = asctime(timeinfo);
        fmt_ts[strlen(fmt_ts)-1] = 0; /* overwrite \n */
        ts = fmt_ts;
    } else
        ts = "Not representable";

    fputs("<?xml version=\"1.0\"?>\n", fh);
    fputs("<?xml-stylesheet type=\"text/xsl\" href=\"" PDML2HTML_XSL "\"?>\n", fh);
    fprintf(fh, "<!-- You can find " PDML2HTML_XSL " in %s or at https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=" PDML2HTML_XSL ". -->\n", get_datafile_dir());
    fputs("<pdml version=\"" PDML_VERSION "\" ", fh);
    fprintf(fh, "creator=\"%s/%s\" time=\"%s\" capture_file=\"%s\">\n", PACKAGE, VERSION, ts, filename ? filename : "");
}

void
write_json_preamble(FILE *fh)
{
    fputs("[\n", fh);
    json_is_first = TRUE;
}

/* Check if the str match the protocolfilter. json_filter is space
   delimited string and str need to exact-match to one of the value. */
static gboolean check_protocolfilter(gchar **protocolfilter, const char *str)
{
    gboolean res = FALSE;
    gchar **ptr;

    if (str == NULL || protocolfilter == NULL) {
        return FALSE;
    }

    for (ptr = protocolfilter; *ptr; ptr++) {
        if (strcmp(*ptr, str) == 0) {
            res = TRUE;
            break;
        }
    }

    return res;
}

void
write_pdml_proto_tree(output_fields_t* fields, gchar **protocolfilter, epan_dissect_t *edt, FILE *fh)
{
    write_pdml_data data;

    g_assert(edt);
    g_assert(fh);

    /* Create the output */
    fprintf(fh, "<packet>\n");

    /* Print a "geninfo" protocol as required by PDML */
    print_pdml_geninfo(edt->tree, fh);

    if (fields == NULL || fields->fields == NULL) {
        /* Write out all fields */
        data.level    = 0;
        data.fh       = fh;
        data.src_list = edt->pi.data_src;
        data.filter   = protocolfilter;

        proto_tree_children_foreach(edt->tree, proto_tree_write_node_pdml,
                                    &data);
    } else {
        /* Write out specified fields */
        write_specified_fields(FORMAT_XML, fields, edt, NULL, fh);
    }

    fprintf(fh, "</packet>\n\n");
}

void
write_json_proto_tree(output_fields_t* fields, print_args_t *print_args, gchar **protocolfilter, epan_dissect_t *edt, FILE *fh)
{
    write_json_data data;
    char ts[30];
    time_t t = time(NULL);
    struct tm * timeinfo;

    g_assert(edt);
    g_assert(fh);

    /* Create the output */
    timeinfo = localtime(&t);
    if (timeinfo != NULL)
        strftime(ts, sizeof ts, "%Y-%m-%d", timeinfo);
    else
        g_strlcpy(ts, "XXXX-XX-XX", sizeof ts); /* XXX - better way of saying "Not representable"? */

    if (!json_is_first)
        fputs("  ,\n", fh);
    else
        json_is_first = FALSE;

    fputs("  {\n", fh);
    fprintf(fh, "    \"_index\": \"packets-%s\",\n", ts);
    fputs("    \"_type\": \"pcap_file\",\n", fh);
    fputs("    \"_score\": null,\n", fh);
    fputs("    \"_source\": {\n", fh);
    fputs("      \"layers\": {\n", fh);

    if (fields == NULL || fields->fields == NULL) {
        /* Write out all fields */
        data.level    = 1;
        data.fh       = fh;
        data.src_list = edt->pi.data_src;
        data.filter   = protocolfilter;
        data.print_hex = print_args->print_hex;

        proto_tree_children_foreach(edt->tree, proto_tree_write_node_json,
                                    &data);
    } else {
        /* Write out specified fields */
        write_specified_fields(FORMAT_JSON, fields, edt, NULL, fh);
    }

    fputs("      }\n", fh);
    fputs("    }\n", fh);
    fputs("  }\n", fh);

}

void
write_ek_proto_tree(output_fields_t* fields, print_args_t *print_args, gchar **protocolfilter, epan_dissect_t *edt, FILE *fh)
{
    write_json_data data;
    char ts[30];
    time_t t = time(NULL);
    struct tm  *timeinfo;
    nstime_t   *timestamp;
    GPtrArray  *finfo_array;

    g_assert(edt);
    g_assert(fh);

    /* Create the output */
    timeinfo = localtime(&t);
    if (timeinfo != NULL)
        strftime(ts, sizeof ts, "%Y-%m-%d", timeinfo);
    else
        g_strlcpy(ts, "XXXX-XX-XX", sizeof ts); /* XXX - better way of saying "Not representable"? */

    /* Get frame protocol's finfo. */
    finfo_array = proto_find_finfo(edt->tree, proto_frame);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    /* frame.time --> geninfo.timestamp */
    finfo_array = proto_find_finfo(edt->tree, hf_frame_arrival_time);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    timestamp = (nstime_t *)fvalue_get(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    fprintf(fh, "{\"index\" : {\"_index\": \"packets-%s\", \"_type\": \"pcap_file\", \"_score\": null}}\n", ts);
    /* Timestamp added for time indexing in Elasticsearch */
    fprintf(fh, "{\"timestamp\" : \"%" G_GUINT64_FORMAT "%03d\", \"layers\" : {", (guint64)timestamp->secs, timestamp->nsecs/1000000);

    if (fields == NULL || fields->fields == NULL) {
        /* Write out all fields */
        data.level    = 0;
        data.fh       = fh;
        data.src_list = edt->pi.data_src;
        data.filter   = protocolfilter;
        data.print_hex = print_args->print_hex;

        proto_tree_children_foreach(edt->tree, proto_tree_write_node_ek,
                                    &data);
    } else {
        /* Write out specified fields */
        write_specified_fields(FORMAT_EK, fields, edt, NULL, fh);
    }

    fputs("}}\n", fh);
}

void
write_fields_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh)
{
    g_assert(edt);
    g_assert(fh);

    /* Create the output */
    write_specified_fields(FORMAT_CSV, fields, edt, cinfo, fh);
}

/* Write out a tree's data, and any child nodes, as PDML */
static void
proto_tree_write_node_pdml(proto_node *node, gpointer data)
{
    field_info      *fi    = PNODE_FINFO(node);
    write_pdml_data *pdata = (write_pdml_data*) data;
    const gchar     *label_ptr;
    gchar            label_str[ITEM_LABEL_LENGTH];
    char            *dfilter_string;
    int              i;
    gboolean         wrap_in_fake_protocol;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    /* Will wrap up top-level field items inside a fake protocol wrapper to
       preserve the PDML schema */
    wrap_in_fake_protocol =
        (((fi->hfinfo->type != FT_PROTOCOL) ||
          (fi->hfinfo->id == proto_data)) &&
         (pdata->level == 0));

    /* Indent to the correct level */
    for (i = -1; i < pdata->level; i++) {
        fputs("  ", pdata->fh);
    }

    if (wrap_in_fake_protocol) {
        /* Open fake protocol wrapper */
        fputs("<proto name=\"fake-field-wrapper\">\n", pdata->fh);

        /* Indent to increased level before writing out field */
        pdata->level++;
        for (i = -1; i < pdata->level; i++) {
            fputs("  ", pdata->fh);
        }
    }

    /* Text label. It's printed as a field with no name. */
    if (fi->hfinfo->id == hf_text_only) {
        /* Get the text */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        }
        else {
            label_ptr = "";
        }

        /* Show empty name since it is a required field */
        fputs("<field name=\"", pdata->fh);
        fputs("\" show=\"", pdata->fh);
        print_escaped_xml(pdata->fh, label_ptr);

        fprintf(pdata->fh, "\" size=\"%d", fi->length);
        if (node->parent && node->parent->finfo && (fi->start < node->parent->finfo->start)) {
            fprintf(pdata->fh, "\" pos=\"%d", node->parent->finfo->start + fi->start);
        } else {
            fprintf(pdata->fh, "\" pos=\"%d", fi->start);
        }

        if (fi->length > 0) {
            fputs("\" value=\"", pdata->fh);
            pdml_write_field_hex_value(pdata, fi);
        }

        if (node->first_child != NULL) {
            fputs("\">\n", pdata->fh);
        }
        else {
            fputs("\"/>\n", pdata->fh);
        }
    }

    /* Uninterpreted data, i.e., the "Data" protocol, is
     * printed as a field instead of a protocol. */
    else if (fi->hfinfo->id == proto_data) {
        /* Write out field with data */
        fputs("<field name=\"data\" value=\"", pdata->fh);
        pdml_write_field_hex_value(pdata, fi);
        fputs("\">\n", pdata->fh);
    }
    /* Normal protocols and fields */
    else {
        if ((fi->hfinfo->type == FT_PROTOCOL) && (fi->hfinfo->id != proto_expert)) {
            fputs("<proto name=\"", pdata->fh);
        }
        else {
            fputs("<field name=\"", pdata->fh);
        }
        print_escaped_xml(pdata->fh, fi->hfinfo->abbrev);

#if 0
        /* PDML spec, see:
         * http://www.nbee.org/doku.php?id=netpdl:pdml_specification
         *
         * the show fields contains things in 'human readable' format
         * showname: contains only the name of the field
         * show: contains only the data of the field
         * showdtl: contains additional details of the field data
         * showmap: contains mappings of the field data (e.g. the hostname to an IP address)
         *
         * XXX - the showname shouldn't contain the field data itself
         * (like it's contained in the fi->rep->representation).
         * Unfortunately, we don't have the field data representation for
         * all fields, so this isn't currently possible */
        fputs("\" showname=\"", pdata->fh);
        print_escaped_xml(pdata->fh, fi->hfinfo->name);
#endif

        if (fi->rep) {
            fputs("\" showname=\"", pdata->fh);
            print_escaped_xml(pdata->fh, fi->rep->representation);
        }
        else {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str);
            fputs("\" showname=\"", pdata->fh);
            print_escaped_xml(pdata->fh, label_ptr);
        }

        if (PROTO_ITEM_IS_HIDDEN(node) && (prefs.display_hidden_proto_items == FALSE))
            fprintf(pdata->fh, "\" hide=\"yes");

        fprintf(pdata->fh, "\" size=\"%d", fi->length);
        if (node->parent && node->parent->finfo && (fi->start < node->parent->finfo->start)) {
            fprintf(pdata->fh, "\" pos=\"%d", node->parent->finfo->start + fi->start);
        } else {
            fprintf(pdata->fh, "\" pos=\"%d", fi->start);
        }
/*      fprintf(pdata->fh, "\" id=\"%d", fi->hfinfo->id);*/

        /* show, value, and unmaskedvalue attributes */
        switch (fi->hfinfo->type)
        {
        case FT_PROTOCOL:
            break;
        case FT_NONE:
            fputs("\" show=\"\" value=\"",  pdata->fh);
            break;
        default:
            dfilter_string = fvalue_to_string_repr(NULL, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
            if (dfilter_string != NULL) {

                fputs("\" show=\"", pdata->fh);
                print_escaped_xml(pdata->fh, dfilter_string);
            }
            wmem_free(NULL, dfilter_string);

            /*
             * XXX - should we omit "value" for any fields?
             * What should we do for fields whose length is 0?
             * They might come from a pseudo-header or from
             * the capture header (e.g., time stamps), or
             * they might be generated fields.
             */
            if (fi->length > 0) {
                fputs("\" value=\"", pdata->fh);

                if (fi->hfinfo->bitmask!=0) {
                    switch (fi->value.ftype->ftype) {
                        case FT_INT8:
                        case FT_INT16:
                        case FT_INT24:
                        case FT_INT32:
                            fprintf(pdata->fh, "%X", (guint) fvalue_get_sinteger(&fi->value));
                            break;
                        case FT_UINT8:
                        case FT_UINT16:
                        case FT_UINT24:
                        case FT_UINT32:
                            fprintf(pdata->fh, "%X", fvalue_get_uinteger(&fi->value));
                            break;
                        case FT_INT40:
                        case FT_INT48:
                        case FT_INT56:
                        case FT_INT64:
                            fprintf(pdata->fh, "%" G_GINT64_MODIFIER "X", fvalue_get_sinteger64(&fi->value));
                            break;
                        case FT_UINT40:
                        case FT_UINT48:
                        case FT_UINT56:
                        case FT_UINT64:
                        case FT_BOOLEAN:
                            fprintf(pdata->fh, "%" G_GINT64_MODIFIER "X", fvalue_get_uinteger64(&fi->value));
                            break;
                        default:
                            g_assert_not_reached();
                    }
                    fputs("\" unmaskedvalue=\"", pdata->fh);
                    pdml_write_field_hex_value(pdata, fi);
                }
                else {
                    pdml_write_field_hex_value(pdata, fi);
                }
            }
        }

        if (node->first_child != NULL) {
            fputs("\">\n", pdata->fh);
        }
        else if (fi->hfinfo->id == proto_data) {
            fputs("\">\n", pdata->fh);
        }
        else {
            fputs("\"/>\n", pdata->fh);
        }
    }

    /* We print some levels for PDML. Recurse here. */
    if (node->first_child != NULL) {
        if (pdata->filter == NULL || check_protocolfilter(pdata->filter, fi->hfinfo->abbrev)) {
            pdata->level++;
            proto_tree_children_foreach(node,
                                        proto_tree_write_node_pdml, pdata);
            pdata->level--;
        } else {
            /* Indent to the correct level */
            for (i = -2; i < pdata->level; i++) {
                fputs("  ", pdata->fh);
            }
            /* print dummy field */
            fputs("<field name=\"filtered\" value=\"", pdata->fh);
            print_escaped_xml(pdata->fh, fi->hfinfo->abbrev);
            fputs("\" />\n", pdata->fh);
        }
    }

    /* Take back the extra level we added for fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        pdata->level--;
    }

    if (node->first_child != NULL) {
        /* Indent to correct level */
        for (i = -1; i < pdata->level; i++) {
            fputs("  ", pdata->fh);
        }
        /* Close off current element */
        /* Data and expert "protocols" use simple tags */
        if ((fi->hfinfo->id != proto_data) && (fi->hfinfo->id != proto_expert)) {
            if (fi->hfinfo->type == FT_PROTOCOL) {
                fputs("</proto>\n", pdata->fh);
            }
            else {
                fputs("</field>\n", pdata->fh);
            }
        } else {
            fputs("</field>\n", pdata->fh);
        }
    }

    /* Close off fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        fputs("</proto>\n", pdata->fh);
    }
}


/* Write out a tree's data, and any child nodes, as JSON */
static void
proto_tree_write_node_json(proto_node *node, gpointer data)
{
    field_info      *fi    = PNODE_FINFO(node);
    write_json_data *pdata = (write_json_data*) data;
    const gchar     *label_ptr;
    gchar            label_str[ITEM_LABEL_LENGTH];
    char            *dfilter_string;
    int              i;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    /* Indent to the correct level */
    for (i = -3; i < pdata->level; i++) {
        fputs("  ", pdata->fh);
    }

    /* Text label. It's printed as a field with no name. */
    if (fi->hfinfo->id == hf_text_only) {
        /* Get the text */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        }
        else {
            label_ptr = "";
        }

        /* Show empty name since it is a required field */
        fputs("\"", pdata->fh);
        print_escaped_json(pdata->fh, label_ptr);

        if (node->first_child != NULL) {
            fputs("\": {\n", pdata->fh);
        }
        else {
            if (node->next == NULL) {
              fputs("\": \"\"\n",  pdata->fh);
            } else {
              fputs("\": \"\",\n",  pdata->fh);
            }
        }
    }

    /* Normal protocols and fields */
    else {
        /*
         * Hex dump -x
         */
        if (pdata->print_hex && fi->length > 0) {
            fputs("\"", pdata->fh);
            print_escaped_json(pdata->fh, fi->hfinfo->abbrev);
            fputs("_raw", pdata->fh);
            fputs("\": \"", pdata->fh);

            if (fi->hfinfo->bitmask!=0) {
                switch (fi->value.ftype->ftype) {
                    case FT_INT8:
                    case FT_INT16:
                    case FT_INT24:
                    case FT_INT32:
                        fprintf(pdata->fh, "%X", (guint) fvalue_get_sinteger(&fi->value));
                        break;
                    case FT_UINT8:
                    case FT_UINT16:
                    case FT_UINT24:
                    case FT_UINT32:
                        fprintf(pdata->fh, "%X", fvalue_get_uinteger(&fi->value));
                        break;
                    case FT_INT40:
                    case FT_INT48:
                    case FT_INT56:
                    case FT_INT64:
                        fprintf(pdata->fh, "%" G_GINT64_MODIFIER "X", fvalue_get_sinteger64(&fi->value));
                        break;
                    case FT_UINT40:
                    case FT_UINT48:
                    case FT_UINT56:
                    case FT_UINT64:
                    case FT_BOOLEAN:
                        fprintf(pdata->fh, "%" G_GINT64_MODIFIER "X", fvalue_get_uinteger64(&fi->value));
                        break;
                    default:
                        g_assert_not_reached();
                }
                fputs("\",\n", pdata->fh);
            }
            else {
                json_write_field_hex_value(pdata, fi);
                fputs("\",\n", pdata->fh);
            }

            /* Indent to the correct level */
            for (i = -3; i < pdata->level; i++) {
                fputs("  ", pdata->fh);
            }
        }


        fputs("\"", pdata->fh);

        print_escaped_json(pdata->fh, fi->hfinfo->abbrev);

        /* show, value, and unmaskedvalue attributes */
        switch (fi->hfinfo->type)
        {
        case FT_PROTOCOL:
            if (node->first_child != NULL) {
                fputs("\": {\n", pdata->fh);
            } else {
                fputs("\": \"", pdata->fh);
                if (fi->rep) {
                    print_escaped_json(pdata->fh, fi->rep->representation);
                }
                else {
                    label_ptr = label_str;
                    proto_item_fill_label(fi, label_str);
                    print_escaped_json(pdata->fh, label_ptr);
                }
                if (node->next == NULL) {
                    fputs("\"\n",  pdata->fh);
                } else {
                    fputs("\",\n",  pdata->fh);
                }
            }
            break;
        case FT_NONE:
            if (node->first_child != NULL) {
                fputs("\": {\n", pdata->fh);
            } else {
                if (node->next == NULL) {
                  fputs("\": \"\"\n",  pdata->fh);
                } else {
                  fputs("\": \"\",\n",  pdata->fh);
                }
            }
            break;
        default:
            dfilter_string = fvalue_to_string_repr(NULL, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
            if (dfilter_string != NULL) {
                fputs("\": \"", pdata->fh);
                print_escaped_json(pdata->fh, dfilter_string);
                if (node->first_child != NULL) {
                    fputs("\",\n", pdata->fh);
                    /* Indent to the correct level */
                    for (i = -3; i < pdata->level; i++) {
                        fputs("  ", pdata->fh);
                    }
                    fputs("\"", pdata->fh);
                    print_escaped_json(pdata->fh, fi->hfinfo->abbrev);
                    fputs("_tree\": {\n", pdata->fh);
                }
            }
            wmem_free(NULL, dfilter_string);

            if (node->first_child == NULL) {
                if (node->next == NULL) {
                    fputs("\"\n", pdata->fh);
                } else {
                    fputs("\",\n", pdata->fh);
                }
            }
        }

    }

    /* We print some levels for JSON. Recurse here. */
    if (node->first_child != NULL) {
        if (pdata->filter == NULL || check_protocolfilter(pdata->filter, fi->hfinfo->abbrev)) {
            pdata->level++;
            proto_tree_children_foreach(node, proto_tree_write_node_json, pdata);
            pdata->level--;
        } else {
            /* Indent to the correct level */
            for (i = -4; i < pdata->level; i++) {
                fputs("  ", pdata->fh);
            }
            /* print dummy field */
            fputs("\"filtered\": \"", pdata->fh);
            print_escaped_json(pdata->fh, fi->hfinfo->abbrev);
            fputs("\"\n", pdata->fh);
        }
    }

    if (node->first_child != NULL) {
        /* Indent to correct level */
        for (i = -3; i < pdata->level; i++) {
            fputs("  ", pdata->fh);
        }
        /* Close off current element */
        if (node->next == NULL) {
            fputs("}\n", pdata->fh);
        } else {
            fputs("},\n", pdata->fh);
        }
    }
}

/* Write out a tree's data, and any child nodes, as JSON for EK */
static void
proto_tree_write_node_ek(proto_node *node, gpointer data)
{
    field_info      *fi    = PNODE_FINFO(node);
    field_info      *fi_parent    = PNODE_FINFO(node->parent);
    write_json_data *pdata = (write_json_data*) data;
    const gchar     *label_ptr;
    gchar            label_str[ITEM_LABEL_LENGTH];
    char            *dfilter_string;
    int              i;
    gchar           *abbrev_escaped = NULL;

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    /* Text label. It's printed as a field with no name. */
    if (fi->hfinfo->id == hf_text_only) {
        /* Get the text */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        }
        else {
            label_ptr = "";
        }

        /* Show empty name since it is a required field */
        fputs("\"", pdata->fh);
        if (fi_parent != NULL) {
            print_escaped_ek(pdata->fh, fi_parent->hfinfo->abbrev);
            fputs("_", pdata->fh);
        }
        print_escaped_ek(pdata->fh, fi->hfinfo->abbrev);

        if (node->first_child != NULL) {
            fputs("\": \"", pdata->fh);
            print_escaped_json(pdata->fh, label_ptr);
            fputs("\",", pdata->fh);

        }
        else {
            if (node->next == NULL) {
                fputs("\": \"",  pdata->fh);
                print_escaped_json(pdata->fh, label_ptr);
                fputs("\"", pdata->fh);
            } else {
                fputs("\": \"",  pdata->fh);
                print_escaped_json(pdata->fh, label_ptr);
                fputs("\",", pdata->fh);
            }
        }
    }

    /* Normal protocols and fields */
    else {
        /*
         * Hex dump -x
         */
        if (pdata->print_hex && fi->length > 0) {
            fputs("\"", pdata->fh);
            if (fi_parent != NULL) {
                print_escaped_ek(pdata->fh, fi_parent->hfinfo->abbrev);
                fputs("_", pdata->fh);
            }
            print_escaped_ek(pdata->fh, fi->hfinfo->abbrev);
            fputs("_raw", pdata->fh);
            fputs("\": \"", pdata->fh);

            if (fi->hfinfo->bitmask!=0) {
                switch (fi->value.ftype->ftype) {
                    case FT_INT8:
                    case FT_INT16:
                    case FT_INT24:
                    case FT_INT32:
                        fprintf(pdata->fh, "%X", (guint) fvalue_get_sinteger(&fi->value));
                        break;
                    case FT_UINT8:
                    case FT_UINT16:
                    case FT_UINT24:
                    case FT_UINT32:
                        fprintf(pdata->fh, "%X", fvalue_get_uinteger(&fi->value));
                        break;
                    case FT_INT40:
                    case FT_INT48:
                    case FT_INT56:
                    case FT_INT64:
                        fprintf(pdata->fh, "%" G_GINT64_MODIFIER "X", fvalue_get_sinteger64(&fi->value));
                        break;
                    case FT_UINT40:
                    case FT_UINT48:
                    case FT_UINT56:
                    case FT_UINT64:
                    case FT_BOOLEAN:
                        fprintf(pdata->fh, "%" G_GINT64_MODIFIER "X", fvalue_get_uinteger64(&fi->value));
                        break;
                    default:
                        g_assert_not_reached();
                }
                fputs("\",", pdata->fh);
            }
            else {
                json_write_field_hex_value(pdata, fi);
                fputs("\",", pdata->fh);
            }
        }



        fputs("\"", pdata->fh);

        if (fi_parent != NULL) {
            print_escaped_ek(pdata->fh, fi_parent->hfinfo->abbrev);
            fputs("_", pdata->fh);
        }
        print_escaped_ek(pdata->fh, fi->hfinfo->abbrev);

        /* show, value, and unmaskedvalue attributes */
        switch (fi->hfinfo->type)
        {
        case FT_PROTOCOL:
            if (node->first_child != NULL) {
                fputs("\": {", pdata->fh);
            } else {
                fputs("\": \"", pdata->fh);
                if (fi->rep) {
                    print_escaped_json(pdata->fh, fi->rep->representation);
                }
                else {
                    label_ptr = label_str;
                    proto_item_fill_label(fi, label_str);
                    print_escaped_json(pdata->fh, label_ptr);
                }
                if (node->next == NULL) {
                    fputs("\"",  pdata->fh);
                } else {
                    fputs("\",",  pdata->fh);
                }
            }
            break;
        case FT_NONE:
            if (node->first_child != NULL) {
                fputs("\": \"\",",  pdata->fh);
            } else {
                if (node->next == NULL) {
                    fputs("\": \"\"",  pdata->fh);
                } else {
                    fputs("\": \"\",",  pdata->fh);
                }
            }
            break;
        default:
            dfilter_string = fvalue_to_string_repr(NULL, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
            if (dfilter_string != NULL) {
                fputs("\": \"", pdata->fh);
                print_escaped_json(pdata->fh, dfilter_string);
            }
            wmem_free(NULL, dfilter_string);

            if (node->next == NULL && node->first_child == NULL) {
                fputs("\"", pdata->fh);
            } else {
                fputs("\",", pdata->fh);
            }
        }

    }

    /* We print some levels for JSON. Recurse here. */
    if (node->first_child != NULL) {

        if (pdata->filter != NULL) {

            /* to to thread the '.' and '_' equally. The '.' is replace by print_escaped_ek for '_' */
            if (fi->hfinfo->abbrev != NULL) {
                if (strlen(fi->hfinfo->abbrev) > 0) {
                    abbrev_escaped = g_strdup(fi->hfinfo->abbrev);

                    i = 0;
                    while(abbrev_escaped[i]!='\0') {
                        if(abbrev_escaped[i]=='.') {
                            abbrev_escaped[i]='_';
                        }
                        i++;
                    }
                }
            }

            if(check_protocolfilter(pdata->filter, fi->hfinfo->abbrev) || check_protocolfilter(pdata->filter, abbrev_escaped)) {
                pdata->level++;
                proto_tree_children_foreach(node, proto_tree_write_node_ek, pdata);
                pdata->level--;
            } else {
                /* print dummy field */
                fputs("\"filtered\": \"", pdata->fh);
                print_escaped_ek(pdata->fh, fi->hfinfo->abbrev);
                fputs("\"", pdata->fh);
            }

            /* release abbrev_escaped string */
            if (abbrev_escaped != NULL) {
                g_free(abbrev_escaped);
            }

        } else {
            pdata->level++;
            proto_tree_children_foreach(node,
                                        proto_tree_write_node_ek, pdata);
            pdata->level--;
        }
    }

    if (node->first_child != NULL) {
        if (fi->hfinfo->type == FT_PROTOCOL) {
            /* Close off current element */
            if (node->next == NULL) {
                fputs("}", pdata->fh);
            } else {
                fputs("},", pdata->fh);
            }
        } else {
            if (node->next != NULL) {
                fputs(",", pdata->fh);
            }
        }
    }
}

/* Print info for a 'geninfo' pseudo-protocol. This is required by
 * the PDML spec. The information is contained in Wireshark's 'frame' protocol,
 * but we produce a 'geninfo' protocol in the PDML to conform to spec.
 * The 'frame' protocol follows the 'geninfo' protocol in the PDML. */
static void
print_pdml_geninfo(proto_tree *tree, FILE *fh)
{
    guint32     num, len, caplen;
    nstime_t   *timestamp;
    GPtrArray  *finfo_array;
    field_info *frame_finfo;
    gchar      *tmp;

    /* Get frame protocol's finfo. */
    finfo_array = proto_find_finfo(tree, proto_frame);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    frame_finfo = (field_info *)finfo_array->pdata[0];
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.number --> geninfo.num */
    finfo_array = proto_find_finfo(tree, hf_frame_number);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    num = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.frame_len --> geninfo.len */
    finfo_array = proto_find_finfo(tree, hf_frame_len);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    len = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.cap_len --> geninfo.caplen */
    finfo_array = proto_find_finfo(tree, hf_frame_capture_len);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    caplen = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.time --> geninfo.timestamp */
    finfo_array = proto_find_finfo(tree, hf_frame_arrival_time);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    timestamp = (nstime_t *)fvalue_get(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* Print geninfo start */
    fprintf(fh,
            "  <proto name=\"geninfo\" pos=\"0\" showname=\"General information\" size=\"%d\">\n",
            frame_finfo->length);

    /* Print geninfo.num */
    fprintf(fh,
            "    <field name=\"num\" pos=\"0\" show=\"%u\" showname=\"Number\" value=\"%x\" size=\"%d\"/>\n",
            num, num, frame_finfo->length);

    /* Print geninfo.len */
    fprintf(fh,
            "    <field name=\"len\" pos=\"0\" show=\"%u\" showname=\"Frame Length\" value=\"%x\" size=\"%d\"/>\n",
            len, len, frame_finfo->length);

    /* Print geninfo.caplen */
    fprintf(fh,
            "    <field name=\"caplen\" pos=\"0\" show=\"%u\" showname=\"Captured Length\" value=\"%x\" size=\"%d\"/>\n",
            caplen, caplen, frame_finfo->length);

    tmp = abs_time_to_str(NULL, timestamp, ABSOLUTE_TIME_LOCAL, TRUE);

    /* Print geninfo.timestamp */
    fprintf(fh,
            "    <field name=\"timestamp\" pos=\"0\" show=\"%s\" showname=\"Captured Time\" value=\"%d.%09d\" size=\"%d\"/>\n",
            tmp, (int) timestamp->secs, timestamp->nsecs, frame_finfo->length);

    wmem_free(NULL, tmp);

    /* Print geninfo end */
    fprintf(fh,
            "  </proto>\n");
}

void
write_pdml_finale(FILE *fh)
{
    fputs("</pdml>\n", fh);
}

void
write_json_finale(FILE *fh)
{
    fputs("]\n", fh);
}

void
write_psml_preamble(column_info *cinfo, FILE *fh)
{
    gint i;

    fputs("<?xml version=\"1.0\"?>\n", fh);
    fputs("<psml version=\"" PSML_VERSION "\" ", fh);
    fprintf(fh, "creator=\"%s/%s\">\n", PACKAGE, VERSION);
    fprintf(fh, "<structure>\n");

    for (i = 0; i < cinfo->num_cols; i++) {
        fprintf(fh, "<section>");
        print_escaped_xml(fh, cinfo->columns[i].col_title);
        fprintf(fh, "</section>\n");
    }

    fprintf(fh, "</structure>\n\n");
}

void
write_psml_columns(epan_dissect_t *edt, FILE *fh)
{
    gint i;

    fprintf(fh, "<packet>\n");

    for (i = 0; i < edt->pi.cinfo->num_cols; i++) {
        fprintf(fh, "<section>");
        print_escaped_xml(fh, edt->pi.cinfo->columns[i].col_data);
        fprintf(fh, "</section>\n");
    }

    fprintf(fh, "</packet>\n\n");
}

void
write_psml_finale(FILE *fh)
{
    fputs("</psml>\n", fh);
}

static gchar *csv_massage_str(const gchar *source, const gchar *exceptions)
{
    gchar *csv_str;
    gchar *tmp_str;

    /* In general, our output for any field can contain Unicode characters,
       so g_strescape (which escapes any non-ASCII) is the wrong thing to do.
       Unfortunately glib doesn't appear to provide g_unicode_strescape()... */
    csv_str = g_strescape(source, exceptions);
    tmp_str = csv_str;
    /* Locate the UTF-8 right arrow character and replace it by an ASCII equivalent */
    while ( (tmp_str = strstr(tmp_str, UTF8_RIGHTWARDS_ARROW)) != NULL ) {
        tmp_str[0] = ' ';
        tmp_str[1] = '>';
        tmp_str[2] = ' ';
    }
    tmp_str = csv_str;
    while ( (tmp_str = strstr(tmp_str, "\\\"")) != NULL )
        *tmp_str = '\"';
    return csv_str;
}

static void csv_write_str(const char *str, char sep, FILE *fh)
{
    gchar *csv_str;

    /* Do not escape the UTF-8 right arrow character */
    csv_str = csv_massage_str(str, UTF8_RIGHTWARDS_ARROW);
    fprintf(fh, "\"%s\"%c", csv_str, sep);
    g_free(csv_str);
}

void
write_csv_column_titles(column_info *cinfo, FILE *fh)
{
    gint i;

    for (i = 0; i < cinfo->num_cols - 1; i++)
        csv_write_str(cinfo->columns[i].col_title, ',', fh);
    csv_write_str(cinfo->columns[i].col_title, '\n', fh);
}

void
write_csv_columns(epan_dissect_t *edt, FILE *fh)
{
    gint i;

    for (i = 0; i < edt->pi.cinfo->num_cols - 1; i++)
        csv_write_str(edt->pi.cinfo->columns[i].col_data, ',', fh);
    csv_write_str(edt->pi.cinfo->columns[i].col_data, '\n', fh);
}

void
write_carrays_hex_data(guint32 num, FILE *fh, epan_dissect_t *edt)
{
    guint32       i = 0, src_num = 0;
    GSList       *src_le;
    tvbuff_t     *tvb;
    char         *name;
    const guchar *cp;
    guint         length;
    char          ascii[9];
    struct data_source *src;

    for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
        memset(ascii, 0, sizeof(ascii));
        src = (struct data_source *)src_le->data;
        tvb = get_data_source_tvb(src);
        length = tvb_captured_length(tvb);
        if (length == 0)
            continue;

        cp = tvb_get_ptr(tvb, 0, length);

        name = get_data_source_name(src);
        if (name) {
            fprintf(fh, "/* %s */\n", name);
            wmem_free(NULL, name);
        }
        if (src_num) {
            fprintf(fh, "static const unsigned char pkt%u_%u[%u] = {\n",
                    num, src_num, length);
        } else {
            fprintf(fh, "static const unsigned char pkt%u[%u] = {\n",
                    num, length);
        }
        src_num++;

        for (i = 0; i < length; i++) {
            fprintf(fh, "0x%02x", *(cp + i));
            ascii[i % 8] = g_ascii_isprint(*(cp + i)) ? *(cp + i) : '.';

            if (i == (length - 1)) {
                guint rem;
                rem = length % 8;
                if (rem) {
                    guint j;
                    for ( j = 0; j < 8 - rem; j++ )
                        fprintf(fh, "      ");
                }
                fprintf(fh, "  /* %s */\n};\n\n", ascii);
                break;
            }

            if (!((i + 1) % 8)) {
                fprintf(fh, ", /* %s */\n", ascii);
                memset(ascii, 0, sizeof(ascii));
            }
            else {
                fprintf(fh, ", ");
            }
        }
    }
}

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
/* XXX: What am I missing ?
 *      Why bother searching for fi->ds_tvb for the matching tvb
 *       in the data_source list ?
 *      IOW: Why not just use fi->ds_tvb for the arg to tvb_get_ptr() ?
 */

static const guint8 *
get_field_data(GSList *src_list, field_info *fi)
{
    GSList   *src_le;
    tvbuff_t *src_tvb;
    gint      length, tvbuff_length;
    struct data_source *src;

    for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
        src = (struct data_source *)src_le->data;
        src_tvb = get_data_source_tvb(src);
        if (fi->ds_tvb == src_tvb) {
            /*
             * Found it.
             *
             * XXX - a field can have a length that runs past
             * the end of the tvbuff.  Ideally, that should
             * be fixed when adding an item to the protocol
             * tree, but checking the length when doing
             * that could be expensive.  Until we fix that,
             * we'll do the check here.
             */
            tvbuff_length = tvb_captured_length_remaining(src_tvb,
                                                 fi->start);
            if (tvbuff_length < 0) {
                return NULL;
            }
            length = fi->length;
            if (length > tvbuff_length)
                length = tvbuff_length;
            return tvb_get_ptr(src_tvb, fi->start, length);
        }
    }
    g_assert_not_reached();
    return NULL;  /* not found */
}

/* Print a string, escaping out certain characters that need to
 * escaped out for XML. */
static void
print_escaped_xml(FILE *fh, const char *unescaped_string)
{
    const char *p;
    char        temp_str[8];

    if (fh == NULL || unescaped_string == NULL) {
        return;
    }

    for (p = unescaped_string; *p != '\0'; p++) {
        switch (*p) {
        case '&':
            fputs("&amp;", fh);
            break;
        case '<':
            fputs("&lt;", fh);
            break;
        case '>':
            fputs("&gt;", fh);
            break;
        case '"':
            fputs("&quot;", fh);
            break;
        case '\'':
            fputs("&#x27;", fh);
            break;
        default:
            if (g_ascii_isprint(*p))
                fputc(*p, fh);
            else {
                g_snprintf(temp_str, sizeof(temp_str), "\\x%x", (guint8)*p);
                fputs(temp_str, fh);
            }
        }
    }
}

static void
print_escaped_bare(FILE *fh, const char *unescaped_string, gboolean change_dot)
{
    const char *p;
    char        temp_str[8];

    if (fh == NULL || unescaped_string == NULL) {
        return;
    }

    for (p = unescaped_string; *p != '\0'; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", fh);
            break;
        case '\\':
            fputs("\\\\", fh);
            break;
        case '/':
            fputs("\\/", fh);
            break;
        case '\b':
            fputs("\\b", fh);
            break;
        case '\f':
            fputs("\\f", fh);
            break;
        case '\n':
            fputs("\\n", fh);
            break;
        case '\r':
            fputs("\\r", fh);
            break;
        case '\t':
            fputs("\\t", fh);
            break;
        case '.':
            if (change_dot)
                fputs("_", fh);
            else
                fputs(".", fh);
            break;
        default:
            if (g_ascii_isprint(*p))
                fputc(*p, fh);
            else {
                g_snprintf(temp_str, sizeof(temp_str), "\\u00%02x", (guint8)*p);
                fputs(temp_str, fh);
            }
        }
    }
}

/* Print a string, escaping out certain characters that need to
 * escaped out for JSON. */
static void
print_escaped_json(FILE *fh, const char *unescaped_string)
{
    print_escaped_bare(fh, unescaped_string, FALSE);
}

/* Print a string, escaping out certain characters that need to
 * escaped out for Elasticsearch title. */
static void
print_escaped_ek(FILE *fh, const char *unescaped_string)
{
    print_escaped_bare(fh, unescaped_string, TRUE);
}

static void
pdml_write_field_hex_value(write_pdml_data *pdata, field_info *fi)
{
    int           i;
    const guint8 *pd;

    if (!fi->ds_tvb)
        return;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        fprintf(pdata->fh, "field length invalid!");
        return;
    }

    /* Find the data for this field. */
    pd = get_field_data(pdata->src_list, fi);

    if (pd) {
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            fprintf(pdata->fh, "%02x", pd[i]);
        }
    }
}

static void
json_write_field_hex_value(write_json_data *pdata, field_info *fi)
{
    int           i;
    const guint8 *pd;

    if (!fi->ds_tvb)
        return;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        fprintf(pdata->fh, "field length invalid!");
        return;
    }

    /* Find the data for this field. */
    pd = get_field_data(pdata->src_list, fi);

    if (pd) {
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            fprintf(pdata->fh, "%02x", pd[i]);
        }
    }
}

gboolean
print_hex_data(print_stream_t *stream, epan_dissect_t *edt)
{
    gboolean      multiple_sources;
    GSList       *src_le;
    tvbuff_t     *tvb;
    char         *line, *name;
    const guchar *cp;
    guint         length;
    struct data_source *src;

    /*
     * Set "multiple_sources" iff this frame has more than one
     * data source; if it does, we need to print the name of
     * the data source before printing the data from the
     * data source.
     */
    multiple_sources = (edt->pi.data_src->next != NULL);

    for (src_le = edt->pi.data_src; src_le != NULL;
         src_le = src_le->next) {
        src = (struct data_source *)src_le->data;
        tvb = get_data_source_tvb(src);
        if (multiple_sources) {
            name = get_data_source_name(src);
            line = g_strdup_printf("%s:", name);
            wmem_free(NULL, name);
            print_line(stream, 0, line);
            g_free(line);
        }
        length = tvb_captured_length(tvb);
        if (length == 0)
            return TRUE;
        cp = tvb_get_ptr(tvb, 0, length);
        if (!print_hex_data_buffer(stream, cp, length,
                                   (packet_char_enc)edt->pi.fd->flags.encoding))
            return FALSE;
    }
    return TRUE;
}

/*
 * This routine is based on a routine created by Dan Lasley
 * <DLASLEY@PROMUS.com>.
 *
 * It was modified for Wireshark by Gilbert Ramirez and others.
 */

#define MAX_OFFSET_LEN   8       /* max length of hex offset of bytes */
#define BYTES_PER_LINE  16      /* max byte values printed on a line */
#define HEX_DUMP_LEN    (BYTES_PER_LINE*3)
                                /* max number of characters hex dump takes -
                                   2 digits plus trailing blank */
#define DATA_DUMP_LEN   (HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
                                /* number of characters those bytes take;
                                   3 characters per byte of hex dump,
                                   2 blanks separating hex from ASCII,
                                   1 character per byte of ASCII dump */
#define MAX_LINE_LEN    (MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
                                /* number of characters per line;
                                   offset, 2 blanks separating offset
                                   from data dump, data dump */

static gboolean
print_hex_data_buffer(print_stream_t *stream, const guchar *cp,
                      guint length, packet_char_enc encoding)
{
    register unsigned int ad, i, j, k, l;
    guchar                c;
    gchar                 line[MAX_LINE_LEN + 1];
    unsigned int          use_digits;

    static gchar binhex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /*
     * How many of the leading digits of the offset will we supply?
     * We always supply at least 4 digits, but if the maximum offset
     * won't fit in 4 digits, we use as many digits as will be needed.
     */
    if (((length - 1) & 0xF0000000) != 0)
        use_digits = 8; /* need all 8 digits */
    else if (((length - 1) & 0x0F000000) != 0)
        use_digits = 7; /* need 7 digits */
    else if (((length - 1) & 0x00F00000) != 0)
        use_digits = 6; /* need 6 digits */
    else if (((length - 1) & 0x000F0000) != 0)
        use_digits = 5; /* need 5 digits */
    else
        use_digits = 4; /* we'll supply 4 digits */

    ad = 0;
    i = 0;
    j = 0;
    k = 0;
    while (i < length) {
        if ((i & 15) == 0) {
            /*
             * Start of a new line.
             */
            j = 0;
            l = use_digits;
            do {
                l--;
                c = (ad >> (l*4)) & 0xF;
                line[j++] = binhex[c];
            } while (l != 0);
            line[j++] = ' ';
            line[j++] = ' ';
            memset(line+j, ' ', DATA_DUMP_LEN);

            /*
             * Offset in line of ASCII dump.
             */
            k = j + HEX_DUMP_LEN + 2;
        }
        c = *cp++;
        line[j++] = binhex[c>>4];
        line[j++] = binhex[c&0xf];
        j++;
        if (encoding == PACKET_CHAR_ENC_CHAR_EBCDIC) {
            c = EBCDIC_to_ASCII1(c);
        }
        line[k++] = ((c >= ' ') && (c < 0x7f)) ? c : '.';
        i++;
        if (((i & 15) == 0) || (i == length)) {
            /*
             * We'll be starting a new line, or
             * we're finished printing this buffer;
             * dump out the line we've constructed,
             * and advance the offset.
             */
            line[k] = '\0';
            if (!print_line(stream, 0, line))
                return FALSE;
            ad += 16;
        }
    }
    return TRUE;
}

gsize output_fields_num_fields(output_fields_t* fields)
{
    g_assert(fields);

    if (NULL == fields->fields) {
        return 0;
    } else {
        return fields->fields->len;
    }
}

void output_fields_free(output_fields_t* fields)
{
    g_assert(fields);

    if (NULL != fields->fields) {
        gsize i;

        if (NULL != fields->field_indicies) {
            /* Keys are stored in fields->fields, values are
             * integers.
             */
            g_hash_table_destroy(fields->field_indicies);
        }

        if (NULL != fields->field_values) {
            g_free(fields->field_values);
        }

        for(i = 0; i < fields->fields->len; ++i) {
            gchar* field = (gchar *)g_ptr_array_index(fields->fields,i);
            g_free(field);
        }
        g_ptr_array_free(fields->fields, TRUE);
    }

    g_free(fields);
}

#define COLUMN_FIELD_FILTER  "_ws.col."

void output_fields_add(output_fields_t *fields, const gchar *field)
{
    gchar *field_copy;

    g_assert(fields);
    g_assert(field);


    if (NULL == fields->fields) {
        fields->fields = g_ptr_array_new();
    }

    field_copy = g_strdup(field);

    g_ptr_array_add(fields->fields, field_copy);

    /* See if we have a column as a field entry */
    if (!strncmp(field, COLUMN_FIELD_FILTER, strlen(COLUMN_FIELD_FILTER)))
        fields->includes_col_fields = TRUE;

}

static void
output_field_check(void *data, void *user_data)
{
    gchar *field = (gchar *)data;
    GSList **invalid_fields = (GSList **)user_data;

    if (!strncmp(field, COLUMN_FIELD_FILTER, strlen(COLUMN_FIELD_FILTER)))
        return;

    if (!proto_registrar_get_byname(field)) {
        *invalid_fields = g_slist_prepend(*invalid_fields, field);
    }

}

GSList *
output_fields_valid(output_fields_t *fields)
{
    GSList *invalid_fields = NULL;
    if (fields->fields == NULL) {
        return NULL;
    }

    g_ptr_array_foreach(fields->fields, output_field_check, &invalid_fields);

    return invalid_fields;
}

gboolean output_fields_set_option(output_fields_t *info, gchar *option)
{
    const gchar *option_name;
    const gchar *option_value;

    g_assert(info);
    g_assert(option);

    if ('\0' == *option) {
        return FALSE; /* this happens if we're called from tshark -E '' */
    }
    option_name = strtok(option, "=");
    if (!option_name) {
        return FALSE;
    }
    option_value = option + strlen(option_name) + 1;
    if (*option_value == '\0') {
        return FALSE;
    }

    if (0 == strcmp(option_name, "header")) {
        switch (*option_value) {
        case 'n':
            info->print_header = FALSE;
            break;
        case 'y':
            info->print_header = TRUE;
            break;
        default:
            return FALSE;
        }
        return TRUE;
    }
    else if (0 == strcmp(option_name, "separator")) {
        switch (*option_value) {
        case '/':
            switch (*++option_value) {
            case 't':
                info->separator = '\t';
                break;
            case 's':
                info->separator = ' ';
                break;
            default:
                info->separator = '\\';
            }
            break;
        default:
            info->separator = *option_value;
            break;
        }
        return TRUE;
    }
    else if (0 == strcmp(option_name, "occurrence")) {
        switch (*option_value) {
        case 'f':
        case 'l':
        case 'a':
            info->occurrence = *option_value;
            break;
        default:
            return FALSE;
        }
        return TRUE;
    }
    else if (0 == strcmp(option_name, "aggregator")) {
        switch (*option_value) {
        case '/':
            switch (*++option_value) {
            case 's':
                info->aggregator = ' ';
                break;
            default:
                info->aggregator = '\\';
            }
            break;
        default:
            info->aggregator = *option_value;
            break;
        }
        return TRUE;
    }
    else if (0 == strcmp(option_name, "quote")) {
        switch (*option_value) {
        case 'd':
            info->quote = '"';
            break;
        case 's':
            info->quote = '\'';
            break;
        case 'n':
            info->quote = '\0';
            break;
        default:
            info->quote = '\0';
            return FALSE;
        }
        return TRUE;
    }
    else if (0 == strcmp(option_name, "bom")) {
        switch (*option_value) {
        case 'n':
            info->print_bom = FALSE;
            break;
        case 'y':
            info->print_bom = TRUE;
            break;
        default:
            return FALSE;
        }
        return TRUE;
    }

    return FALSE;
}

void output_fields_list_options(FILE *fh)
{
    fprintf(fh, "TShark: The available options for field output \"E\" are:\n");
    fputs("bom=y|n    Prepend output with the UTF-8 BOM (def: N: no)\n", fh);
    fputs("header=y|n    Print field abbreviations as first line of output (def: N: no)\n", fh);
    fputs("separator=/t|/s|<character>   Set the separator to use;\n     \"/t\" = tab, \"/s\" = space (def: /t: tab)\n", fh);
    fputs("occurrence=f|l|a  Select the occurrence of a field to use;\n     \"f\" = first, \"l\" = last, \"a\" = all (def: a: all)\n", fh);
    fputs("aggregator=,|/s|<character>   Set the aggregator to use;\n     \",\" = comma, \"/s\" = space (def: ,: comma)\n", fh);
    fputs("quote=d|s|n   Print either d: double-quotes, s: single quotes or \n     n: no quotes around field values (def: n: none)\n", fh);
}

gboolean output_fields_has_cols(output_fields_t* fields)
{
    g_assert(fields);
    return fields->includes_col_fields;
}

void write_fields_preamble(output_fields_t* fields, FILE *fh)
{
    gsize i;

    g_assert(fields);
    g_assert(fh);
    g_assert(fields->fields);

    if (fields->print_bom) {
        fputs(UTF8_BOM, fh);
    }


    if (!fields->print_header) {
        return;
    }

    for(i = 0; i < fields->fields->len; ++i) {
        const gchar* field = (const gchar *)g_ptr_array_index(fields->fields,i);
        if (i != 0 ) {
            fputc(fields->separator, fh);
        }
        fputs(field, fh);
    }
    fputc('\n', fh);
}

static void format_field_values(output_fields_t* fields, gpointer field_index, const gchar* value)
{
    guint      indx;
    GPtrArray* fv_p;

    if (NULL == value)
        return;

    /* Unwrap change made to disambiguiate zero / null */
    indx = GPOINTER_TO_UINT(field_index) - 1;

    if (fields->field_values[indx] == NULL) {
        fields->field_values[indx] = g_ptr_array_new();
    }

    /* Essentially: fieldvalues[indx] is a 'GPtrArray *' with each array entry */
    /*  pointing to a string which is (part of) the final output string.       */

    fv_p = fields->field_values[indx];

    switch (fields->occurrence) {
    case 'f':
        /* print the value of only the first occurrence of the field */
        if (g_ptr_array_len(fv_p) != 0)
            return;
        break;
    case 'l':
        /* print the value of only the last occurrence of the field */
        g_ptr_array_set_size(fv_p, 0);
        break;
    case 'a':
        /* print the value of all accurrences of the field */
        /* If not the first, add the 'aggregator' */
        if (g_ptr_array_len(fv_p) > 0) {
            g_ptr_array_add(fv_p, (gpointer)g_strdup_printf("%c", fields->aggregator));
        }
        break;
    default:
        g_assert_not_reached();
        break;
    }

    g_ptr_array_add(fv_p, (gpointer)value);
}

static void proto_tree_get_node_field_values(proto_node *node, gpointer data)
{
    write_field_data_t *call_data;
    field_info *fi;
    gpointer    field_index;

    call_data = (write_field_data_t *)data;
    fi = PNODE_FINFO(node);

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    field_index = g_hash_table_lookup(call_data->fields->field_indicies, fi->hfinfo->abbrev);
    if (NULL != field_index) {
        format_field_values(call_data->fields, field_index,
                            get_node_field_value(fi, call_data->edt) /* g_ alloc'd string */
            );
    }

    /* Recurse here. */
    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, proto_tree_get_node_field_values,
                                    call_data);
    }
}

static void write_specified_fields(fields_format format, output_fields_t *fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh)
{
    gsize     i;
    gboolean first = TRUE;
    gint      col;
    gchar    *col_name;
    gpointer  field_index;

    write_field_data_t data;

    g_assert(fields);
    g_assert(fields->fields);
    g_assert(edt);
    g_assert(fh);

    data.fields = fields;
    data.edt = edt;

    if (NULL == fields->field_indicies) {
        /* Prepare a lookup table from string abbreviation for field to its index. */
        fields->field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

        i = 0;
        while (i < fields->fields->len) {
            gchar *field = (gchar *)g_ptr_array_index(fields->fields, i);
            /* Store field indicies +1 so that zero is not a valid value,
             * and can be distinguished from NULL as a pointer.
             */
            ++i;
            g_hash_table_insert(fields->field_indicies, field, GUINT_TO_POINTER(i));
        }
    }

    /* Array buffer to store values for this packet              */
    /*  Allocate an array for the 'GPtrarray *' the first time   */
    /*   ths function is invoked for a file;                     */
    /*  Any and all 'GPtrArray *' are freed (after use) each     */
    /*   time (each packet) this function is invoked for a flle. */
    /* XXX: ToDo: use packet-scope'd memory & (if/when implemented) wmem ptr_array */
    if (NULL == fields->field_values)
        fields->field_values = g_new0(GPtrArray*, fields->fields->len);  /* free'd in output_fields_free() */

    proto_tree_children_foreach(edt->tree, proto_tree_get_node_field_values,
                                &data);

    switch (format) {
    case FORMAT_CSV:
        if (fields->includes_col_fields) {
            for (col = 0; col < cinfo->num_cols; col++) {
                /* Prepend COLUMN_FIELD_FILTER as the field name */
                col_name = g_strdup_printf("%s%s", COLUMN_FIELD_FILTER, cinfo->columns[col].col_title);
                field_index = g_hash_table_lookup(fields->field_indicies, col_name);
                g_free(col_name);

                if (NULL != field_index) {
                    format_field_values(fields, field_index, g_strdup(cinfo->columns[col].col_data));
                }
            }
        }

        for(i = 0; i < fields->fields->len; ++i) {
            if (0 != i) {
                fputc(fields->separator, fh);
            }
            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                gchar * str;
                gsize j;
                fv_p = fields->field_values[i];
                if (fields->quote != '\0') {
                    fputc(fields->quote, fh);
                }

                /* Output the array of (partial) field values */
                for (j = 0; j < g_ptr_array_len(fv_p); j++ ) {
                    str = (gchar *)g_ptr_array_index(fv_p, j);
                    fputs(str, fh);
                    g_free(str);
                }
                if (fields->quote != '\0') {
                    fputc(fields->quote, fh);
                }
                g_ptr_array_free(fv_p, TRUE);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        break;
    case FORMAT_XML:
        for(i = 0; i < fields->fields->len; ++i) {
            gchar *field = (gchar *)g_ptr_array_index(fields->fields, i);

            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                gchar * str;
                gsize j;
                fv_p = fields->field_values[i];

                /* Output the array of (partial) field values */
                for (j = 0; j < (g_ptr_array_len(fv_p)); j+=2 ) {
                    str = (gchar *)g_ptr_array_index(fv_p, j);

                    fprintf(fh, "  <field name=\"%s\" value=", field);
                    fputs("\"", fh);
                    print_escaped_xml(fh, str);
                    fputs("\"/>\n", fh);
                    g_free(str);
                }
                g_ptr_array_free(fv_p, TRUE);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        break;
    case FORMAT_JSON:
        for(i = 0; i < fields->fields->len; ++i) {
            gchar *field = (gchar *)g_ptr_array_index(fields->fields, i);

            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                gchar * str;
                gsize j;
                fv_p = fields->field_values[i];

                /* Output the array of (partial) field values */
                for (j = 0; j < (g_ptr_array_len(fv_p)); j += 2) {
                    str = (gchar *)g_ptr_array_index(fv_p, j);

                    if (j == 0) {
                        if (!first) {
                            fputs(",\n", fh);
                        }
                        fprintf(fh, "        \"%s\": [", field);
                    }
                    fputs("\"", fh);
                    print_escaped_json(fh, str);
                    fputs("\"", fh);
                    g_free(str);

                    if (j + 2 < (g_ptr_array_len(fv_p))) {
                        fputs(",", fh);
                    }
                    else {
                        fputs("]", fh);

                        }
                    }

                first = FALSE;
                g_ptr_array_free(fv_p, TRUE);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        fputc('\n',fh);
        break;
    case FORMAT_EK:
        for(i = 0; i < fields->fields->len; ++i) {
            gchar *field = (gchar *)g_ptr_array_index(fields->fields, i);

            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                gchar * str;
                gsize j;
                fv_p = fields->field_values[i];

                /* Output the array of (partial) field values */
                for (j = 0; j < (g_ptr_array_len(fv_p)); j += 2) {
                    str = (gchar *)g_ptr_array_index(fv_p, j);

                    if (j == 0) {
                        if (!first) {
                            fputs(",", fh);
                        }
                        fputs("\"", fh);
                        print_escaped_ek(fh, field);
                        fputs("\": [", fh);
                    }
                    fputs("\"", fh);
                    print_escaped_json(fh, str);
                    fputs("\"", fh);
                    g_free(str);

                    if (j + 2 < (g_ptr_array_len(fv_p))) {
                        fputs(",", fh);
                    }
                    else {
                        fputs("]", fh);

                        }
                    }

                first = FALSE;
                g_ptr_array_free(fv_p, TRUE);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        break;

    default:
        fprintf(stderr, "Unknown fields format %d\n", format);
        g_assert_not_reached();
        break;
    }
}

void write_fields_finale(output_fields_t* fields _U_ , FILE *fh _U_)
{
    /* Nothing to do */
}

/* Returns an g_malloced string */
gchar* get_node_field_value(field_info* fi, epan_dissect_t* edt)
{
    if (fi->hfinfo->id == hf_text_only) {
        /* Text label.
         * Get the text */
        if (fi->rep) {
            return g_strdup(fi->rep->representation);
        }
        else {
            return get_field_hex_value(edt->pi.data_src, fi);
        }
    }
    else if (fi->hfinfo->id == proto_data) {
        /* Uninterpreted data, i.e., the "Data" protocol, is
         * printed as a field instead of a protocol. */
        return get_field_hex_value(edt->pi.data_src, fi);
    }
    else {
        /* Normal protocols and fields */
        gchar      *dfilter_string;

        switch (fi->hfinfo->type)
        {
        case FT_PROTOCOL:
            /* Print out the full details for the protocol. */
            if (fi->rep) {
                return g_strdup(fi->rep->representation);
            } else {
                /* Just print out the protocol abbreviation */
                return g_strdup(fi->hfinfo->abbrev);
            }
        case FT_NONE:
            /* Return "1" so that the presence of a field of type
             * FT_NONE can be checked when using -T fields */
            return g_strdup("1");
        default:
            dfilter_string = fvalue_to_string_repr(NULL, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
            if (dfilter_string != NULL) {
                gchar* ret = g_strdup(dfilter_string);
                wmem_free(NULL, dfilter_string);
                return ret;
            } else {
                return get_field_hex_value(edt->pi.data_src, fi);
            }
        }
    }
}

static gchar*
get_field_hex_value(GSList *src_list, field_info *fi)
{
    const guint8 *pd;

    if (!fi->ds_tvb)
        return NULL;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        return g_strdup("field length invalid!");
    }

    /* Find the data for this field. */
    pd = get_field_data(src_list, fi);

    if (pd) {
        int        i;
        gchar     *buffer;
        gchar     *p;
        int        len;
        const int  chars_per_byte = 2;

        len    = chars_per_byte * fi->length;
        buffer = (gchar *)g_malloc(sizeof(gchar)*(len + 1));
        buffer[len] = '\0'; /* Ensure NULL termination in bad cases */
        p = buffer;
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            g_snprintf(p, chars_per_byte+1, "%02x", pd[i]);
            p += chars_per_byte;
        }
        return buffer;
    } else {
        return NULL;
    }
}

output_fields_t* output_fields_new(void)
{
    output_fields_t* fields     = g_new(output_fields_t, 1);
    fields->print_bom           = FALSE;
    fields->print_header        = FALSE;
    fields->separator           = '\t';
    fields->occurrence          = 'a';
    fields->aggregator          = ',';
    fields->fields              = NULL; /*Do lazy initialisation */
    fields->field_indicies      = NULL;
    fields->field_values        = NULL;
    fields->quote               ='\0';
    fields->includes_col_fields = FALSE;
    return fields;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
