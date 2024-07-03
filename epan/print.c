/* print.c
 * Routines for printing packet analysis trees.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/column.h>
#include <epan/column-info.h>
#include <epan/color_filters.h>
#include <epan/dfilter/dfilter.h>
#include <epan/prefs.h>
#include <epan/print.h>
#include <epan/charsets.h>
#include <wsutil/array.h>
#include <wsutil/json_dumper.h>
#include <wsutil/filesystem.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/str_util.h>
#include <wsutil/ws_assert.h>
#include <ftypes/ftypes.h>

#define PDML_VERSION "0"
#define PSML_VERSION "0"

typedef struct {
    int                  level;
    print_stream_t      *stream;
    bool                 success;
    GSList              *src_list;
    print_dissections_e  print_dissections;
    bool                 print_hex_for_data;
    packet_char_enc      encoding;
    GHashTable          *output_only_tables; /* output only these protocols */
} print_data;

typedef struct {
    int             level;
    FILE           *fh;
    GSList         *src_list;
    wmem_map_t     *filter;
} write_pdml_data;

typedef struct {
    GSList         *src_list;
    wmem_map_t     *filter;
    bool            print_hex;
    bool            print_text;
    proto_node_children_grouper_func node_children_grouper;
    json_dumper    *dumper;
} write_json_data;

typedef struct {
    output_fields_t *fields;
    epan_dissect_t  *edt;
} write_field_data_t;

struct _output_fields {
    bool          print_bom;
    bool          print_header;
    char          separator;
    char          occurrence;
    char          aggregator;
    GPtrArray    *fields;
    GPtrArray    *field_dfilters;
    GHashTable   *field_indicies;
    GPtrArray   **field_values;
    wmem_map_t   *protocolfilter;
    char          quote;
    bool          escape;
    bool          includes_col_fields;
};

static char *get_field_hex_value(GSList *src_list, field_info *fi);
static void proto_tree_print_node(proto_node *node, void *data);
static void proto_tree_write_node_pdml(proto_node *node, void *data);
static void proto_tree_write_node_ek(proto_node *node, write_json_data *data);
static const uint8_t *get_field_data(GSList *src_list, field_info *fi);
static void pdml_write_field_hex_value(write_pdml_data *pdata, field_info *fi);
static void json_write_field_hex_value(write_json_data *pdata, field_info *fi);
static bool print_hex_data_buffer(print_stream_t *stream, const unsigned char *cp,
                                      unsigned length, packet_char_enc encoding,
                                      unsigned hexdump_options);
static void write_specified_fields(fields_format format,
                                   output_fields_t *fields,
                                   epan_dissect_t *edt, column_info *cinfo,
                                   FILE *fh,
                                   json_dumper *dumper);
static void print_escaped_xml(FILE *fh, const char *unescaped_string);
static void print_escaped_csv(FILE *fh, const char *unescaped_string, char delimiter, char quote_char, bool escape_wsp);

typedef void (*proto_node_value_writer)(proto_node *, write_json_data *);
static void write_json_index(json_dumper *dumper, epan_dissect_t *edt);
static void write_json_proto_node_list(GSList *proto_node_list_head, write_json_data *data);
static void write_json_proto_node(GSList *node_values_head,
                                  const char *suffix,
                                  proto_node_value_writer value_writer,
                                  write_json_data *data);
static void write_json_proto_node_value_list(GSList *node_values_head,
                                             proto_node_value_writer value_writer,
                                             write_json_data *data);
static void write_json_proto_node_filtered(proto_node *node, write_json_data *data);
static void write_json_proto_node_hex_dump(proto_node *node, write_json_data *data);
static void write_json_proto_node_dynamic(proto_node *node, write_json_data *data);
static void write_json_proto_node_children(proto_node *node, write_json_data *data);
static void write_json_proto_node_value(proto_node *node, write_json_data *data);
static void write_json_proto_node_no_value(proto_node *node, write_json_data *data);
static const char *proto_node_to_json_key(proto_node *node);

static void print_pdml_geninfo(epan_dissect_t *edt, FILE *fh);
static void write_ek_summary(column_info *cinfo, write_json_data *pdata);

static void proto_tree_get_node_field_values(proto_node *node, void *data);

/* Cache the protocols and field handles that the print functionality needs
   This helps break explicit dependency on the dissectors. */
static int proto_data;
static int proto_frame;

void print_cache_field_handles(void)
{
    proto_data = proto_get_id_by_short_name("Data");
    proto_frame = proto_get_id_by_short_name("Frame");
}

bool
proto_tree_print(print_dissections_e print_dissections, bool print_hex,
                 epan_dissect_t *edt, GHashTable *output_only_tables,
                 print_stream_t *stream)
{
    print_data data;

    /* Create the output */
    data.level              = 0;
    data.stream             = stream;
    data.success            = true;
    data.src_list           = edt->pi.data_src;
    data.encoding           = (packet_char_enc)edt->pi.fd->encoding;
    data.print_dissections  = print_dissections;
    /* If we're printing the entire packet in hex, don't
       print uninterpreted data fields in hex as well. */
    data.print_hex_for_data = !print_hex;
    data.output_only_tables = output_only_tables;

    proto_tree_children_foreach(edt->tree, proto_tree_print_node, &data);
    return data.success;
}

/* Print a tree's data, and any child nodes. */
static void
proto_tree_print_node(proto_node *node, void *data)
{
    field_info   *fi    = PNODE_FINFO(node);
    print_data   *pdata = (print_data*) data;
    const uint8_t *pd;
    char          label_str[ITEM_LABEL_LENGTH];
    char         *label_ptr;

    /* dissection with an invisible proto tree? */
    ws_assert(fi);

    /* Don't print invisible entries. */
    if (proto_item_is_hidden(node) && (prefs.display_hidden_proto_items == false))
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

    if (proto_item_is_generated(node))
        label_ptr = g_strconcat("[", label_ptr, "]", NULL);

    pdata->success = print_line(pdata->stream, pdata->level, label_ptr);

    if (proto_item_is_generated(node))
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
                pdata->success = false;
                return;
            }
            if (!print_hex_data_buffer(pdata->stream, pd,
                                       fi->length, pdata->encoding, HEXDUMP_ASCII_INCLUDE)) {
                pdata->success = false;
                return;
            }
        }
    }

    /* If we're printing all levels, or if this node is one with a
       subtree and its subtree is expanded, recurse into the subtree,
       if it exists. */
    ws_assert((fi->tree_type >= -1) && (fi->tree_type < num_tree_types));
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
#define PDML2HTML_URL "https://gitlab.com/wireshark/wireshark/-/tree/master/resources/share/doc/wireshark/"
void
write_pdml_preamble(FILE *fh, const char *filename)
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

    fprintf(fh, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    fprintf(fh, "<?xml-stylesheet type=\"text/xsl\" href=\"" PDML2HTML_XSL "\"?>\n");
    fprintf(fh, "<!-- You can find " PDML2HTML_XSL " in %s or at "PDML2HTML_URL PDML2HTML_XSL ". -->\n", get_doc_dir());
    fprintf(fh, "<pdml version=\"" PDML_VERSION "\" creator=\"%s/%s\" time=\"%s\" capture_file=\"", PACKAGE, VERSION, ts);
    if (filename) {
        /* \todo filename should be converted to UTF-8. */
        print_escaped_xml(fh, filename);
    }
    fprintf(fh, "\">\n");
}

/* Check if the str matches the protocolfilter.
 *
 * @param[in]  protocolfilter a map of field abbreviations that pass the filter
 * to the flags for that field, or NULL if no filter (so all fields pass)
 * @param[in]  str the field abbreviation to lookup in the map.
 * @param[out] flags if not NULL, gets set to the value in the map for
 * the given key if found (undefined if return is false.)
 * @return     true if the filter passes the string, false if the filter
 * filters out the string.
 */
static bool check_protocolfilter(wmem_map_t *protocolfilter, const char *str, pf_flags *flags)
{
    bool res = false;
    void *value;

    if (protocolfilter == NULL) {
        if (flags) {
            *flags = PF_NONE;
        }
        return true;
    }

    if (str == NULL) {
        return false;
    }

    res = wmem_map_lookup_extended(protocolfilter, str, NULL, &value);
    if (res && flags) {
        *flags = GPOINTER_TO_UINT(value);
    }
    return res;
}

void
write_pdml_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh, bool use_color)
{
    write_pdml_data data;
    const color_filter_t *cfp;

    ws_assert(edt);
    ws_assert(fh);

    cfp = edt->pi.fd->color_filter;

    /* Create the output */
    if (use_color && (cfp != NULL)) {
        fprintf(fh, "<packet foreground='#%06x' background='#%06x'>\n",
            color_t_to_rgb(&cfp->fg_color),
            color_t_to_rgb(&cfp->bg_color));
    } else {
        fprintf(fh, "<packet>\n");
    }

    /* Print a "geninfo" protocol as required by PDML */
    print_pdml_geninfo(edt, fh);

    if (fields == NULL || fields->fields == NULL) {
        /* Write out all fields */
        data.level    = 0;
        data.fh       = fh;
        data.src_list = edt->pi.data_src;
        data.filter   = fields ? fields->protocolfilter : NULL;

        proto_tree_children_foreach(edt->tree, proto_tree_write_node_pdml,
                                    &data);
    } else {
        /* Write out specified fields */
        write_specified_fields(FORMAT_XML, fields, edt, cinfo, fh, NULL);
    }

    fprintf(fh, "</packet>\n\n");
}

void
write_ek_proto_tree(output_fields_t* fields,
                    bool print_summary, bool print_hex,
                    epan_dissect_t *edt,
                    column_info *cinfo,
                    FILE *fh)
{
    ws_assert(edt);
    ws_assert(fh);

    write_json_data data;

    json_dumper dumper = {
        .output_file = fh,
        .flags = JSON_DUMPER_DOT_TO_UNDERSCORE
    };

    data.dumper = &dumper;

    json_dumper_begin_object(&dumper);
    json_dumper_set_member_name(&dumper, "index");
    json_dumper_begin_object(&dumper);
    write_json_index(&dumper, edt);
    json_dumper_set_member_name(&dumper, "_type");
    json_dumper_value_string(&dumper, "doc");
    json_dumper_end_object(&dumper);
    json_dumper_end_object(&dumper);
    json_dumper_finish(&dumper);
    json_dumper_begin_object(&dumper);

    /* Timestamp added for time indexing in Elasticsearch */
    json_dumper_set_member_name(&dumper, "timestamp");
    json_dumper_value_anyf(&dumper, "\"%" PRIu64 "%03d\"", (uint64_t)edt->pi.abs_ts.secs, edt->pi.abs_ts.nsecs/1000000);

    if (print_summary)
        write_ek_summary(edt->pi.cinfo, &data);

    if (edt->tree) {
        json_dumper_set_member_name(&dumper, "layers");
        json_dumper_begin_object(&dumper);

        if (fields == NULL || fields->fields == NULL) {
            /* Write out all fields */
            data.src_list = edt->pi.data_src;
            data.filter = fields ? fields->protocolfilter : NULL;
            data.print_hex = print_hex;
            proto_tree_write_node_ek(edt->tree, &data);
        } else {
            /* Write out specified fields */
            write_specified_fields(FORMAT_EK, fields, edt, cinfo, NULL, data.dumper);
        }

        json_dumper_end_object(&dumper);
    }
    json_dumper_end_object(&dumper);
    json_dumper_finish(&dumper);
}

void
write_fields_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh)
{
    ws_assert(edt);
    ws_assert(fh);

    /* Create the output */
    write_specified_fields(FORMAT_CSV, fields, edt, cinfo, fh, NULL);
}

/* Indent to the correct level */
static void print_indent(int level, FILE *fh)
{
    /* Use a buffer pre-filled with spaces */
#define MAX_INDENT 2048
    static char spaces[MAX_INDENT];
    static bool inited = false;
    if (!inited) {
        for (int n=0; n < MAX_INDENT; n++) {
            spaces[n] = ' ';
        }
        inited = true;
    }

    if (fh == NULL) {
        return;
    }

    /* Temp terminate at right length and write to fh. */
    spaces[MIN(level*2, MAX_INDENT-1)] ='\0';
    fputs(spaces, fh);
    spaces[MIN(level*2, MAX_INDENT-1)] =' ';
}

/* Write out a tree's data, and any child nodes, as PDML */
static void
proto_tree_write_node_pdml(proto_node *node, void *data)
{
    field_info      *fi    = PNODE_FINFO(node);
    write_pdml_data *pdata = (write_pdml_data*) data;
    const char      *label_ptr;
    char             label_str[ITEM_LABEL_LENGTH];
    char            *dfilter_string;
    bool             wrap_in_fake_protocol;

    /* dissection with an invisible proto tree? */
    ws_assert(fi);

    /* Will wrap up top-level field items inside a fake protocol wrapper to
       preserve the PDML schema */
    wrap_in_fake_protocol =
        (((fi->hfinfo->type != FT_PROTOCOL) ||
          (fi->hfinfo->id == proto_data)) &&
         (pdata->level == 0));

    print_indent(pdata->level + 1, pdata->fh);

    if (wrap_in_fake_protocol) {
        /* Open fake protocol wrapper */
        fputs("<proto name=\"fake-field-wrapper\">\n", pdata->fh);
        pdata->level++;

        print_indent(pdata->level + 1, pdata->fh);
    }

    /* Text label. It's printed as a field with no name. */
    if (fi->hfinfo->id == hf_text_only) {
        /* Get the text */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        } else {
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
        } else {
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
    } else {
        /* Normal protocols and fields */
        if ((fi->hfinfo->type == FT_PROTOCOL) && (fi->hfinfo->id != proto_expert)) {
            fputs("<proto name=\"", pdata->fh);
        } else {
            fputs("<field name=\"", pdata->fh);
        }
        print_escaped_xml(pdata->fh, fi->hfinfo->abbrev);

#if 0
        /* PDML spec, see:
         * https://wayback.archive.org/web/20150330045501/http://www.nbee.org/doku.php?id=netpdl:pdml_specification
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
        } else {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str);
            fputs("\" showname=\"", pdata->fh);
            print_escaped_xml(pdata->fh, label_ptr);
        }

        if (proto_item_is_hidden(node) && (prefs.display_hidden_proto_items == false))
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
            dfilter_string = fvalue_to_string_repr(NULL, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
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
                    switch (fvalue_type_ftenum(fi->value)) {
                        case FT_INT8:
                        case FT_INT16:
                        case FT_INT24:
                        case FT_INT32:
                            fprintf(pdata->fh, "%X", (unsigned) fvalue_get_sinteger(fi->value));
                            break;
                        case FT_CHAR:
                        case FT_UINT8:
                        case FT_UINT16:
                        case FT_UINT24:
                        case FT_UINT32:
                            fprintf(pdata->fh, "%X", fvalue_get_uinteger(fi->value));
                            break;
                        case FT_INT40:
                        case FT_INT48:
                        case FT_INT56:
                        case FT_INT64:
                            fprintf(pdata->fh, "%" PRIX64, fvalue_get_sinteger64(fi->value));
                            break;
                        case FT_UINT40:
                        case FT_UINT48:
                        case FT_UINT56:
                        case FT_UINT64:
                        case FT_BOOLEAN:
                            fprintf(pdata->fh, "%" PRIX64, fvalue_get_uinteger64(fi->value));
                            break;
                        default:
                            ws_assert_not_reached();
                    }
                    fputs("\" unmaskedvalue=\"", pdata->fh);
                    pdml_write_field_hex_value(pdata, fi);
                } else {
                    pdml_write_field_hex_value(pdata, fi);
                }
            }
        }

        if (node->first_child != NULL) {
            fputs("\">\n", pdata->fh);
        } else if (fi->hfinfo->id == proto_data) {
            fputs("\">\n", pdata->fh);
        } else {
            fputs("\"/>\n", pdata->fh);
        }
    }

    /* We print some levels for PDML. Recurse here. */
    if (node->first_child != NULL) {
        pf_flags filter_flags = PF_NONE;
        if (pdata->filter == NULL || check_protocolfilter(pdata->filter, fi->hfinfo->abbrev, &filter_flags)) {
            wmem_map_t *_filter = NULL;
            /* Remove protocol filter for children, if children should be included */
            if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                _filter = pdata->filter;
                pdata->filter = NULL;
            }

            pdata->level++;
            proto_tree_children_foreach(node,
                                        proto_tree_write_node_pdml, pdata);
            pdata->level--;

            /* Put protocol filter back */
            if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                pdata->filter = _filter;
            }
        } else {
            print_indent(pdata->level + 2, pdata->fh);

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
        print_indent(pdata->level + 1, pdata->fh);

        /* Close off current element */
        /* Data and expert "protocols" use simple tags */
        if ((fi->hfinfo->id != proto_data) && (fi->hfinfo->id != proto_expert)) {
            if (fi->hfinfo->type == FT_PROTOCOL) {
                fputs("</proto>\n", pdata->fh);
            } else {
                fputs("</field>\n", pdata->fh);
            }
        } else {
            fputs("</field>\n", pdata->fh);
        }
    }

    /* Close off fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        print_indent(pdata->level + 1, pdata->fh);
        fputs("</proto>\n", pdata->fh);
    }
}

json_dumper
write_json_preamble(FILE *fh)
{
    json_dumper dumper = {
        .output_file = fh,
        .flags = JSON_DUMPER_FLAGS_PRETTY_PRINT
    };
    json_dumper_begin_array(&dumper);
    return dumper;
}

void
write_json_finale(json_dumper *dumper)
{
    json_dumper_end_array(dumper);
    json_dumper_finish(dumper);
}

static void
write_json_index(json_dumper *dumper, epan_dissect_t *edt)
{
    char ts[30];
    struct tm * timeinfo;
    char* str;

    timeinfo = localtime(&edt->pi.abs_ts.secs);
    if (timeinfo != NULL) {
        strftime(ts, sizeof(ts), "%Y-%m-%d", timeinfo);
    } else {
        (void) g_strlcpy(ts, "XXXX-XX-XX", sizeof(ts)); /* XXX - better way of saying "Not representable"? */
    }
    json_dumper_set_member_name(dumper, "_index");
    str = ws_strdup_printf("packets-%s", ts);
    json_dumper_value_string(dumper, str);
    g_free(str);
}

void
write_json_proto_tree(output_fields_t* fields,
                      print_dissections_e print_dissections,
                      bool print_hex,
                      epan_dissect_t *edt, column_info *cinfo,
                      proto_node_children_grouper_func node_children_grouper,
                      json_dumper *dumper)
{
    write_json_data data;

    data.dumper = dumper;

    json_dumper_begin_object(dumper);
    write_json_index(dumper, edt);
    json_dumper_set_member_name(dumper, "_type");
    json_dumper_value_string(dumper, "doc");
    json_dumper_set_member_name(dumper, "_score");
    json_dumper_value_string(dumper, NULL);
    json_dumper_set_member_name(dumper, "_source");
    json_dumper_begin_object(dumper);
    json_dumper_set_member_name(dumper, "layers");

    if (fields == NULL || fields->fields == NULL) {
        /* Write out all fields */
        data.src_list = edt->pi.data_src;
        data.filter = fields ? fields->protocolfilter : NULL;
        data.print_hex = print_hex;
        data.print_text = true;
        if (print_dissections == print_dissections_none) {
            data.print_text = false;
        }
        data.node_children_grouper = node_children_grouper;

        write_json_proto_node_children(edt->tree, &data);
    } else {
        write_specified_fields(FORMAT_JSON, fields, edt, cinfo, NULL, dumper);
    }

    json_dumper_end_object(dumper);
    json_dumper_end_object(dumper);
}

/**
 * Returns a boolean telling us whether that node list contains any node which has children
 */
static bool
any_has_children(GSList *node_values_list)
{
    GSList *current_node = node_values_list;
    while (current_node != NULL) {
        proto_node *current_value = (proto_node *) current_node->data;
        if (current_value->first_child != NULL) {
            return true;
        }
        current_node = current_node->next;
    }
    return false;
}

/**
 * Write a json object containing a list of key:value pairs where each key:value pair corresponds to a different json
 * key and its associated nodes in the proto_tree.
 * @param proto_node_list_head A 2-dimensional list containing a list of values for each different node json key. The
 * elements themselves are a linked list of values associated with the same json key.
 * @param pdata json writing metadata
 */
static void
write_json_proto_node_list(GSList *proto_node_list_head, write_json_data *pdata)
{
    GSList *current_node = proto_node_list_head;

    json_dumper_begin_object(pdata->dumper);

    // Loop over each list of nodes (differentiated by json key) and write the associated json key:value pair in the
    // output.
    while (current_node != NULL) {
        // Get the list of values for the current json key.
        GSList *node_values_list = (GSList *) current_node->data;

        // Retrieve the json key from the first value.
        proto_node *first_value = (proto_node *) node_values_list->data;
        const char *json_key = proto_node_to_json_key(first_value);
        // Check if the current json key is filtered from the output with the "-j" cli option.
        pf_flags filter_flags = PF_NONE;
        bool is_filtered = pdata->filter != NULL && !check_protocolfilter(pdata->filter, json_key, &filter_flags);

        field_info *fi = first_value->finfo;
        char *value_string_repr = fvalue_to_string_repr(NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);
        bool has_children = any_has_children(node_values_list);

        // We assume all values of a json key have roughly the same layout. Thus we can use the first value to derive
        // attributes of all the values.
        bool has_value = value_string_repr != NULL;
        bool is_pseudo_text_field = fi->hfinfo->id == hf_text_only;

        wmem_free(NULL, value_string_repr); // fvalue_to_string_repr returns allocated buffer

        // "-x" command line option. A "_raw" suffix is added to the json key so the textual value can be printed
        // with the original json key. If both hex and text writing are enabled the raw information of fields whose
        // length is equal to 0 is not written to the output. If the field is a special text pseudo field no raw
        // information is written either.
        if (pdata->print_hex && (!pdata->print_text || fi->length > 0) && !is_pseudo_text_field) {
            write_json_proto_node(node_values_list, "_raw", write_json_proto_node_hex_dump, pdata);
        }

        if (pdata->print_text && has_value) {
            write_json_proto_node(node_values_list, "", write_json_proto_node_value, pdata);
        }

        if (has_children) {
            // If a node has both a value and a set of children we print the value and the children in separate
            // key:value pairs. These can't have the same key so whenever a value is already printed with the node
            // json key we print the children with the same key with a "_tree" suffix added.
            char *suffix = has_value ? "_tree": "";

            if (is_filtered) {
                write_json_proto_node(node_values_list, suffix, write_json_proto_node_filtered, pdata);
            } else {
                // Remove protocol filter for children, if children should be included. This functionality is enabled
                // with the "-J" command line option. We save the filter so it can be reenabled when we are done with
                // the current key:value pair.
                wmem_map_t *_filter = NULL;
                if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                    _filter = pdata->filter;
                    pdata->filter = NULL;
                }

                // has_children is true if any of the nodes have children. So we're not 100% sure whether this
                // particular node has children or not => use the 'dynamic' version of 'write_json_proto_node'
                write_json_proto_node(node_values_list, suffix, write_json_proto_node_dynamic, pdata);

                // Put protocol filter back
                if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                    pdata->filter = _filter;
                }
            }
        }

        if (!has_value && !has_children && (pdata->print_text || (pdata->print_hex && is_pseudo_text_field))) {
            write_json_proto_node(node_values_list, "", write_json_proto_node_no_value, pdata);
        }

        current_node = current_node->next;
    }
    json_dumper_end_object(pdata->dumper);
}

/**
 * Writes a single node as a key:value pair. The value_writer param can be used to specify how the node's value should
 * be written.
 * @param node_values_head Linked list containing all nodes associated with the same json key in this object.
 * @param suffix Suffix that should be added to the json key.
 * @param value_writer A function which writes the actual values of the node json key.
 * @param pdata json writing metadata
 */
static void
write_json_proto_node(GSList *node_values_head,
                      const char *suffix,
                      proto_node_value_writer value_writer,
                      write_json_data *pdata)
{
    // Retrieve json key from first value.
    proto_node *first_value = (proto_node *) node_values_head->data;
    const char *json_key = proto_node_to_json_key(first_value);
    char* json_key_suffix = ws_strdup_printf("%s%s", json_key, suffix);
    json_dumper_set_member_name(pdata->dumper, json_key_suffix);
    g_free(json_key_suffix);
    write_json_proto_node_value_list(node_values_head, value_writer, pdata);
}

/**
 * Writes a list of values of a single json key. If multiple values are passed they are wrapped in a json array.
 * @param node_values_head Linked list containing all values that should be written.
 * @param value_writer Function which writes the separate values.
 * @param pdata json writing metadata
 */
static void
write_json_proto_node_value_list(GSList *node_values_head, proto_node_value_writer value_writer, write_json_data *pdata)
{
    GSList *current_value = node_values_head;

    // Write directly if only a single value is passed. Wrap in json array otherwise.
    if (current_value->next == NULL) {
        value_writer((proto_node *) current_value->data, pdata);
    } else {
        json_dumper_begin_array(pdata->dumper);

        while (current_value != NULL) {
            value_writer((proto_node *) current_value->data, pdata);
            current_value = current_value->next;
        }
        json_dumper_end_array(pdata->dumper);
    }
}

/**
 * Writes the value for a node that's filtered from the output.
 */
static void
write_json_proto_node_filtered(proto_node *node, write_json_data *pdata)
{
    const char *json_key = proto_node_to_json_key(node);

    json_dumper_begin_object(pdata->dumper);
    json_dumper_set_member_name(pdata->dumper, "filtered");
    json_dumper_value_string(pdata->dumper, json_key);
    json_dumper_end_object(pdata->dumper);
}

/**
 * Writes the hex dump of a node. A json array is written containing the hex dump, position, length, bitmask and type of
 * the node.
 */
static void
write_json_proto_node_hex_dump(proto_node *node, write_json_data *pdata)
{
    field_info *fi = node->finfo;

    json_dumper_begin_array(pdata->dumper);

    if (fi->hfinfo->bitmask!=0) {
        switch (fvalue_type_ftenum(fi->value)) {
            case FT_INT8:
            case FT_INT16:
            case FT_INT24:
            case FT_INT32:
                json_dumper_value_anyf(pdata->dumper, "\"%X\"", (unsigned) fvalue_get_sinteger(fi->value));
                break;
            case FT_CHAR:
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
                json_dumper_value_anyf(pdata->dumper, "\"%X\"", fvalue_get_uinteger(fi->value));
                break;
            case FT_INT40:
            case FT_INT48:
            case FT_INT56:
            case FT_INT64:
                json_dumper_value_anyf(pdata->dumper, "\"%" PRIX64 "\"", fvalue_get_sinteger64(fi->value));
                break;
            case FT_UINT40:
            case FT_UINT48:
            case FT_UINT56:
            case FT_UINT64:
            case FT_BOOLEAN:
                json_dumper_value_anyf(pdata->dumper, "\"%" PRIX64 "\"", fvalue_get_uinteger64(fi->value));
                break;
            default:
                ws_assert_not_reached();
        }
    } else {
        json_write_field_hex_value(pdata, fi);
    }

    /* Dump raw hex-encoded dissected information including position, length, bitmask, type */
    json_dumper_value_anyf(pdata->dumper, "%" PRId32, fi->start);
    json_dumper_value_anyf(pdata->dumper, "%" PRId32, fi->length);
    json_dumper_value_anyf(pdata->dumper, "%" PRIu64, fi->hfinfo->bitmask);
    json_dumper_value_anyf(pdata->dumper, "%" PRId32, (int32_t)fvalue_type_ftenum(fi->value));

    json_dumper_end_array(pdata->dumper);
}

/**
 * Writes the value of a node, which may be a simple node with no value and no children,
 * or a node with children -- this will be determined dynamically
 */
static void
write_json_proto_node_dynamic(proto_node *node, write_json_data *data)
{
    if (node->first_child == NULL) {
        write_json_proto_node_no_value(node, data);
    } else {
        write_json_proto_node_children(node, data);
    }
}

/**
 * Writes the children of a node. Calls write_json_proto_node_list internally which recursively writes children of nodes
 * to the output.
 */
static void
write_json_proto_node_children(proto_node *node, write_json_data *data)
{
    GSList *grouped_children_list = data->node_children_grouper(node);
    write_json_proto_node_list(grouped_children_list, data);
    g_slist_free_full(grouped_children_list, (GDestroyNotify) g_slist_free);
}

/**
 * Writes the value of a node to the output.
 */
static void
write_json_proto_node_value(proto_node *node, write_json_data *pdata)
{
    field_info *fi = node->finfo;
    // Get the actual value of the node as a string.
    char *value_string_repr = fvalue_to_string_repr(NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);

    //TODO: Have FTREPR_JSON include quotes where appropriate and use json_dumper_value_anyf() here,
    // so we can output booleans and numbers and not only strings.
    json_dumper_value_string(pdata->dumper, value_string_repr);

    wmem_free(NULL, value_string_repr);
}

/**
 * Write the value for a node that has no value and no children. This is the empty string for all nodes except those of
 * type FT_PROTOCOL for which the full name is written instead.
 */
static void
write_json_proto_node_no_value(proto_node *node, write_json_data *pdata)
{
    field_info *fi = node->finfo;

    if (fi->hfinfo->type == FT_PROTOCOL) {
        if (fi->rep) {
            json_dumper_value_string(pdata->dumper, fi->rep->representation);
        } else {
            char label_str[ITEM_LABEL_LENGTH];
            proto_item_fill_label(fi, label_str);
            json_dumper_value_string(pdata->dumper, label_str);
        }
    } else {
        json_dumper_value_string(pdata->dumper, "");
    }
}

/**
 * Groups each child of the node separately.
 * @return Linked list where each element is another linked list containing a single node.
 */
GSList *
proto_node_group_children_by_unique(proto_node *node) {
    GSList *unique_nodes_list = NULL;
    proto_node *current_child = node->first_child;

    while (current_child != NULL) {
        GSList *unique_node = g_slist_prepend(NULL, current_child);
        unique_nodes_list = g_slist_prepend(unique_nodes_list, unique_node);
        current_child = current_child->next;
    }

    return g_slist_reverse(unique_nodes_list);
}

/**
 * Groups the children of a node by their json key. Children are put in the same group if they have the same json key.
 * @return Linked list where each element is another linked list of nodes associated with the same json key.
 */
GSList *
proto_node_group_children_by_json_key(proto_node *node)
{
    /**
     * For each different json key we store a linked list of values corresponding to that json key. These lists are kept
     * in both a linked list and a hashmap. The hashmap is used to quickly retrieve the values of a json key. The linked
     * list is used to preserve the ordering of keys as they are encountered which is not guaranteed when only using a
     * hashmap.
     */
    GSList *same_key_nodes_list = NULL;
    GHashTable *lookup_by_json_key = g_hash_table_new(g_str_hash, g_str_equal);
    proto_node *current_child = node->first_child;

    /**
     * For each child of the node get the key and get the list of values already associated with that key from the
     * hashmap. If no list exist yet for that key create a new one and add it to both the linked list and hashmap. If a
     * list already exists add the node to that list.
     */
    while (current_child != NULL) {
        char *json_key = (char *) proto_node_to_json_key(current_child);
        GSList *json_key_nodes = (GSList *) g_hash_table_lookup(lookup_by_json_key, json_key);

        if (json_key_nodes == NULL) {
            json_key_nodes = g_slist_append(json_key_nodes, current_child);
            // Prepending in single linked list is O(1), appending is O(n). Better to prepend here and reverse at the
            // end than potentially looping to the end of the linked list for each child.
            same_key_nodes_list = g_slist_prepend(same_key_nodes_list, json_key_nodes);
            g_hash_table_insert(lookup_by_json_key, json_key, json_key_nodes);
        } else {
            // Store and insert value again to circumvent unused_variable warning.
            // Append in this case since most value lists will only have a single value.
            json_key_nodes = g_slist_append(json_key_nodes, current_child);
            g_hash_table_insert(lookup_by_json_key, json_key, json_key_nodes);
        }

        current_child = current_child->next;
    }

    // Hash table is not needed anymore since the linked list with the correct ordering is returned.
    g_hash_table_destroy(lookup_by_json_key);

    return g_slist_reverse(same_key_nodes_list);
}

/**
 * Returns the json key of a node. Tries to use the node's abbreviated name.
 * If the abbreviated name is not available the representation is used instead.
 *
 * XXX: The representation can have spaces or differ depending on the content,
 * which makes it difficult to match text-only fields with a -j/-J filter in tshark.
 * (Issue #17125).
 */
static const char *
proto_node_to_json_key(proto_node *node)
{
    const char *json_key;
    // Check if node has abbreviated name.
    if (node->finfo->hfinfo->id != hf_text_only) {
        json_key = node->finfo->hfinfo->abbrev;
    } else if (node->finfo->rep != NULL) {
        json_key = node->finfo->rep->representation;
    } else {
        json_key = "";
    }

    return json_key;
}

static bool
ek_check_protocolfilter(wmem_map_t *protocolfilter, const char *str, pf_flags *filter_flags)
{
    char *str_escaped = NULL;
    bool check;
    int i;

    if (check_protocolfilter(protocolfilter, str, filter_flags))
        return true;

    /* to to thread the '.' and '_' equally. The '.' is replace by print_escaped_ek for '_' */
    if (str != NULL && strlen(str) > 0) {
        str_escaped = g_strdup(str);

        i = 0;
        while (str_escaped[i] != '\0') {
            if (str_escaped[i] == '.') {
                str_escaped[i] = '_';
            }
            i++;
        }
    }

    check = check_protocolfilter(protocolfilter, str_escaped, filter_flags);
    g_free(str_escaped);
    return check;
}

/**
 * Finds a node's descendants to be printed as EK/JSON attributes.
 */
static void
write_ek_summary(column_info *cinfo, write_json_data* pdata)
{
    int i;

    for (i = 0; i < cinfo->num_cols; i++) {
        if (!get_column_visible(i))
            continue;
        json_dumper_set_member_name(pdata->dumper, g_ascii_strdown(cinfo->columns[i].col_title, -1));
        json_dumper_value_string(pdata->dumper, get_column_text(cinfo, i));
    }
}

/* Write out a tree's data, and any child nodes, as JSON for EK */
static void
// NOLINTNEXTLINE(misc-no-recursion)
ek_fill_attr(proto_node *node, GHashTable *attr_table, write_json_data *pdata)
{
    field_info *fi         = NULL;
    GSList *attr_instances = NULL;

    proto_node *current_node = node->first_child;
    while (current_node != NULL) {
        fi        = PNODE_FINFO(current_node);

        /* dissection with an invisible proto tree? */
        ws_assert(fi);

        attr_instances = (GSList *) g_hash_table_lookup(attr_table, fi->hfinfo->abbrev);
        attr_instances = g_slist_append(attr_instances, current_node);
        // Update instance list for this attr in hash table
        g_hash_table_insert(attr_table, g_strdup(fi->hfinfo->abbrev), attr_instances);

        /* Field, recurse through children*/
        if (fi->hfinfo->type != FT_PROTOCOL && current_node->first_child != NULL) {
            if (pdata->filter != NULL) {
                pf_flags filter_flags = PF_NONE;
                if (ek_check_protocolfilter(pdata->filter, fi->hfinfo->abbrev, &filter_flags)) {
                    wmem_map_t *_filter = NULL;
                    /* Remove protocol filter for children, if children should be included */
                    if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                        _filter = pdata->filter;
                        pdata->filter = NULL;
                    }

                    // We recurse here, but we're limited by our tree depth checks in proto.c
                    ek_fill_attr(current_node, attr_table, pdata);

                    /* Put protocol filter back */
                    if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                        pdata->filter = _filter;
                    }
                } else {
                    // Don't traverse children if filtered out
                }
            } else {
                // We recurse here, but we're limited by our tree depth checks in proto.c
                ek_fill_attr(current_node, attr_table, pdata);
            }
        } else {
            // Will descend into object at another point
        }

        current_node = current_node->next;
    }
}

static void
ek_write_name(proto_node *pnode, char* suffix, write_json_data* pdata)
{
    field_info *fi = PNODE_FINFO(pnode);
    char       *str;

    if (fi->hfinfo->parent != -1) {
        header_field_info* parent = proto_registrar_get_nth(fi->hfinfo->parent);
        str = ws_strdup_printf("%s_%s%s", parent->abbrev, fi->hfinfo->abbrev, suffix ? suffix : "");
        json_dumper_set_member_name(pdata->dumper, str);
    } else {
        str = ws_strdup_printf("%s%s", fi->hfinfo->abbrev, suffix ? suffix : "");
        json_dumper_set_member_name(pdata->dumper, str);
    }
    g_free(str);
}

static void
ek_write_hex(field_info *fi, write_json_data *pdata)
{
    if (fi->hfinfo->bitmask != 0) {
        switch (fvalue_type_ftenum(fi->value)) {
            case FT_INT8:
            case FT_INT16:
            case FT_INT24:
            case FT_INT32:
                json_dumper_value_anyf(pdata->dumper, "\"%X\"", (unsigned) fvalue_get_sinteger(fi->value));
                break;
            case FT_CHAR:
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
                json_dumper_value_anyf(pdata->dumper, "\"%X\"", fvalue_get_uinteger(fi->value));
                break;
            case FT_INT40:
            case FT_INT48:
            case FT_INT56:
            case FT_INT64:
                json_dumper_value_anyf(pdata->dumper, "\"%" PRIX64 "\"", fvalue_get_sinteger64(fi->value));
                break;
            case FT_UINT40:
            case FT_UINT48:
            case FT_UINT56:
            case FT_UINT64:
            case FT_BOOLEAN:
                json_dumper_value_anyf(pdata->dumper, "\"%" PRIX64 "\"", fvalue_get_uinteger64(fi->value));
                break;
            default:
                ws_assert_not_reached();
        }
    } else {
        json_write_field_hex_value(pdata, fi);
    }
}

static void
ek_write_field_value(field_info *fi, write_json_data* pdata)
{
    char label_str[ITEM_LABEL_LENGTH];
    char *dfilter_string;
    char time_buf[NSTIME_ISO8601_BUFSIZE];
    size_t time_len;

    /* Text label */
    if (fi->hfinfo->id == hf_text_only && fi->rep) {
        json_dumper_value_string(pdata->dumper, fi->rep->representation);
    } else {
        /* show, value, and unmaskedvalue attributes */
        switch(fi->hfinfo->type) {
        case FT_PROTOCOL:
            if (fi->rep) {
                json_dumper_value_string(pdata->dumper, fi->rep->representation);
            }
            else {
                proto_item_fill_label(fi, label_str);
                json_dumper_value_string(pdata->dumper, label_str);
            }
            break;
        case FT_NONE:
            json_dumper_value_string(pdata->dumper, NULL);
            break;
        case FT_BOOLEAN:
            if (fvalue_get_uinteger64(fi->value))
                json_dumper_value_anyf(pdata->dumper, "true");
            else
                json_dumper_value_anyf(pdata->dumper, "false");
            break;
        case FT_ABSOLUTE_TIME:
            time_len = nstime_to_iso8601(time_buf, sizeof(time_buf), fvalue_get_time(fi->value));
            if (time_len != 0) {
                json_dumper_value_anyf(pdata->dumper, "\"%s\"", time_buf);
            } else {
                json_dumper_value_anyf(pdata->dumper, "\"Not representable\"");
            }
            break;
        default:
            dfilter_string = fvalue_to_string_repr(NULL, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
            if (dfilter_string != NULL) {
                json_dumper_value_string(pdata->dumper, dfilter_string);
            }
            wmem_free(NULL, dfilter_string);
            break;
        }
    }
}

static void
ek_write_attr_hex(GSList *attr_instances, write_json_data *pdata)
{
    GSList *current_node = attr_instances;
    proto_node *pnode    = (proto_node *) current_node->data;
    field_info *fi       = NULL;

    // Raw name
    ek_write_name(pnode, "_raw", pdata);

    if (g_slist_length(attr_instances) > 1) {
        json_dumper_begin_array(pdata->dumper);
    }

    // Raw value(s)
    while (current_node != NULL) {
        pnode = (proto_node *) current_node->data;
        fi    = PNODE_FINFO(pnode);

        ek_write_hex(fi, pdata);

        current_node = current_node->next;
    }

    if (g_slist_length(attr_instances) > 1) {
        json_dumper_end_array(pdata->dumper);
    }
}

static void
// NOLINTNEXTLINE(misc-no-recursion)
ek_write_attr(GSList *attr_instances, write_json_data *pdata)
{
    GSList *current_node  = attr_instances;
    proto_node *pnode     = (proto_node *) current_node->data;
    field_info *fi        = PNODE_FINFO(pnode);
    pf_flags filter_flags = PF_NONE;

    // Hex dump -x
    if (pdata->print_hex && fi && fi->length > 0 && fi->hfinfo->id != hf_text_only) {
        ek_write_attr_hex(attr_instances, pdata);
    }

    // Print attr name
    ek_write_name(pnode, NULL, pdata);

    if (g_slist_length(attr_instances) > 1) {
        json_dumper_begin_array(pdata->dumper);
    }

    while (current_node != NULL) {
        pnode = (proto_node *) current_node->data;
        fi    = PNODE_FINFO(pnode);

        /* Field */
        if (fi->hfinfo->type != FT_PROTOCOL) {
            if (pdata->filter != NULL
                && !ek_check_protocolfilter(pdata->filter, fi->hfinfo->abbrev, &filter_flags)) {

                /* print dummy field */
                json_dumper_begin_object(pdata->dumper);
                json_dumper_set_member_name(pdata->dumper, "filtered");
                json_dumper_value_string(pdata->dumper, fi->hfinfo->abbrev);
                json_dumper_end_object(pdata->dumper);
            } else {
                ek_write_field_value(fi, pdata);
            }
        } else {
            /* Object */
            json_dumper_begin_object(pdata->dumper);

            if (pdata->filter != NULL) {
                if (ek_check_protocolfilter(pdata->filter, fi->hfinfo->abbrev, &filter_flags)) {
                    wmem_map_t *_filter = NULL;
                    /* Remove protocol filter for children, if children should be included */
                    if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                        _filter = pdata->filter;
                        pdata->filter = NULL;
                    }

                    proto_tree_write_node_ek(pnode, pdata);

                    /* Put protocol filter back */
                    if ((filter_flags&PF_INCLUDE_CHILDREN) == PF_INCLUDE_CHILDREN) {
                        pdata->filter = _filter;
                    }
                } else {
                    /* print dummy field */
                    json_dumper_set_member_name(pdata->dumper, "filtered");
                    json_dumper_value_string(pdata->dumper, fi->hfinfo->abbrev);
                }
            } else {
                proto_tree_write_node_ek(pnode, pdata);
            }

            json_dumper_end_object(pdata->dumper);
        }

        current_node = current_node->next;
    }

    if (g_slist_length(attr_instances) > 1) {
        json_dumper_end_array(pdata->dumper);
    }
}

// NOLINTNEXTLINE(misc-no-recursion)
void process_ek_attrs(gpointer key _U_, gpointer value, gpointer pdata)
{
    GSList *attr_instances = (GSList *) value;
    ek_write_attr(attr_instances, pdata);
}

/* Write out a tree's data, and any child nodes, as JSON for EK */
static void
// NOLINTNEXTLINE(misc-no-recursion)
proto_tree_write_node_ek(proto_node *node, write_json_data *pdata)
{
    GHashTable *attr_table  = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    GHashTableIter iter;
    gpointer key, value;
    ek_fill_attr(node, attr_table, pdata);

    // Print attributes
    g_hash_table_iter_init(&iter, attr_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        process_ek_attrs(key, value, pdata);
        g_hash_table_iter_remove(&iter);
        /* We lookup a list in the table, append to it, and re-insert it; as
         * g_slist_append() can change the start pointer of the list we can't
         * just append to the list without replacing the old value. In turn,
         * that means we can't set the value_destroy_func when creating
         * the hash table, because on re-insertion that would destroy the
         * nodes of the old list, which are still being used by the new list.
         * So free it here.
         */
        g_slist_free((GSList*)value);
    }
    g_hash_table_destroy(attr_table);
}

/* Print info for a 'geninfo' pseudo-protocol. This is required by
 * the PDML spec. The information is contained in Wireshark's 'frame' protocol,
 * but we produce a 'geninfo' protocol in the PDML to conform to spec.
 * The 'frame' protocol follows the 'geninfo' protocol in the PDML. */
static void
print_pdml_geninfo(epan_dissect_t *edt, FILE *fh)
{
    uint32_t    num, len, caplen;
    GPtrArray  *finfo_array;
    field_info *frame_finfo;
    char       *tmp;

    /* Get frame protocol's finfo. */
    finfo_array = proto_find_first_finfo(edt->tree, proto_frame);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    frame_finfo = (field_info *)finfo_array->pdata[0];
    g_ptr_array_free(finfo_array, true);

    /* frame.number, packet_info.num */
    num = edt->pi.num;

    /* frame.frame_len, packet_info.frame_data->pkt_len */
    len = edt->pi.fd->pkt_len;

    /* frame.cap_len --> packet_info.frame_data->cap_len */
    caplen = edt->pi.fd->cap_len;

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

    tmp = abs_time_to_str(NULL, &edt->pi.abs_ts, ABSOLUTE_TIME_LOCAL, true);

    /* Print geninfo.timestamp */
    fprintf(fh,
            "    <field name=\"timestamp\" pos=\"0\" show=\"%s\" showname=\"Captured Time\" value=\"%d.%09d\" size=\"%d\"/>\n",
            tmp, (int)edt->pi.abs_ts.secs, edt->pi.abs_ts.nsecs, frame_finfo->length);

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
write_psml_preamble(column_info *cinfo, FILE *fh)
{
    int i;

    fprintf(fh, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    fprintf(fh, "<psml version=\"" PSML_VERSION "\" creator=\"%s/%s\">\n", PACKAGE, VERSION);
    fprintf(fh, "<structure>\n");

    for (i = 0; i < cinfo->num_cols; i++) {
        if (!get_column_visible(i))
            continue;
        fprintf(fh, "<section>");
        print_escaped_xml(fh, cinfo->columns[i].col_title);
        fprintf(fh, "</section>\n");
    }

    fprintf(fh, "</structure>\n\n");
}

void
write_psml_columns(epan_dissect_t *edt, FILE *fh, bool use_color)
{
    int i;
    const color_filter_t *cfp = edt->pi.fd->color_filter;

    if (use_color && (cfp != NULL)) {
        fprintf(fh, "<packet foreground='#%06x' background='#%06x'>\n",
            color_t_to_rgb(&cfp->fg_color),
            color_t_to_rgb(&cfp->bg_color));
    } else {
        fprintf(fh, "<packet>\n");
    }

    for (i = 0; i < edt->pi.cinfo->num_cols; i++) {
        if (!get_column_visible(i))
            continue;
        fprintf(fh, "<section>");
        print_escaped_xml(fh, get_column_text(edt->pi.cinfo, i));
        fprintf(fh, "</section>\n");
    }

    fprintf(fh, "</packet>\n\n");
}

void
write_psml_finale(FILE *fh)
{
    fputs("</psml>\n", fh);
}

static char *csv_massage_str(const char *source, const char *exceptions)
{
    char *csv_str;
    char *tmp_str;

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

static void csv_write_str(const char *str, char sep, FILE *fh, bool print_separator)
{
    char *csv_str;

    /* Do not escape the UTF-8 right arrow character */
    csv_str = csv_massage_str(str, UTF8_RIGHTWARDS_ARROW);
    if (print_separator) {
        fprintf(fh, "%c\"%s\"", sep, csv_str);
    } else {
        fprintf(fh, "\"%s\"", csv_str);
    }
    g_free(csv_str);
}

void
write_csv_column_titles(column_info *cinfo, FILE *fh)
{
    int i;
    bool print_separator = false;
    // Avoid printing separator for first column

    for (i = 0; i < cinfo->num_cols; i++) {
        if (!get_column_visible(i))
            continue;
        csv_write_str(cinfo->columns[i].col_title, ',', fh, print_separator);
        print_separator = true;
    }
    if (print_separator) { // Only add line break if anything was output
        fprintf(fh, "\n");
    }
}

void
write_csv_columns(epan_dissect_t *edt, FILE *fh)
{
    int i;
    bool print_separator = false;
    // Avoid printing separator for first column

    for (i = 0; i < edt->pi.cinfo->num_cols; i++) {
        if (!get_column_visible(i))
            continue;
        csv_write_str(get_column_text(edt->pi.cinfo, i), ',', fh, print_separator);
        print_separator = true;
    }
    if (print_separator) { // Only add line break if anything was output
        fprintf(fh, "\n");
    }
}

void
write_carrays_hex_data(uint32_t num, FILE *fh, epan_dissect_t *edt)
{
    uint32_t      i = 0, src_num = 0;
    GSList       *src_le;
    tvbuff_t     *tvb;
    char         *name;
    const unsigned char *cp;
    unsigned      length;
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
            fprintf(fh, "// %s\n", name);
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
                unsigned rem;
                rem = length % 8;
                if (rem) {
                    unsigned j;
                    for ( j = 0; j < 8 - rem; j++ )
                        fprintf(fh, "      ");
                }
                fprintf(fh, "  // |%s|\n};\n\n", ascii);
                break;
            }

            if (!((i + 1) % 8)) {
                fprintf(fh, ", // |%s|\n", ascii);
                memset(ascii, 0, sizeof(ascii));
            } else {
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

static const uint8_t *
get_field_data(GSList *src_list, field_info *fi)
{
    GSList   *src_le;
    tvbuff_t *src_tvb;
    int       length, tvbuff_length;
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
    return NULL;  /* not found */
}

/* Print a string, escaping out certain characters that need to
 * escaped out for XML. */
static void
print_escaped_xml(FILE *fh, const char *unescaped_string)
{
    const char *p;

#define ESCAPED_BUFFER_SIZE 256
#define ESCAPED_BUFFER_LIMIT (ESCAPED_BUFFER_SIZE - (int)sizeof("&quot;"))
    static char temp_buffer[ESCAPED_BUFFER_SIZE];
    int         offset = 0;

    if (fh == NULL || unescaped_string == NULL) {
        return;
    }

    /* XXX: Why not use xml_escape() from epan/strutil.h ? */
    for (p = unescaped_string; *p != '\0' && (offset <= ESCAPED_BUFFER_LIMIT); p++) {
        switch (*p) {
        case '&':
            (void) g_strlcpy(&temp_buffer[offset], "&amp;", ESCAPED_BUFFER_SIZE-offset);
            offset += 5;
            break;
        case '<':
            (void) g_strlcpy(&temp_buffer[offset], "&lt;", ESCAPED_BUFFER_SIZE-offset);
            offset += 4;
            break;
        case '>':
            (void) g_strlcpy(&temp_buffer[offset], "&gt;", ESCAPED_BUFFER_SIZE-offset);
            offset += 4;
            break;
        case '"':
            (void) g_strlcpy(&temp_buffer[offset], "&quot;", ESCAPED_BUFFER_SIZE-offset);
            offset += 6;
            break;
        case '\'':
            (void) g_strlcpy(&temp_buffer[offset], "&#x27;", ESCAPED_BUFFER_SIZE-offset);
            offset += 6;
            break;
        case '\t':
        case '\n':
        case '\r':
            temp_buffer[offset++] = *p;
            break;
        default:
            /* XML 1.0 doesn't allow ASCII control characters, except
             * for the three whitespace ones above (which do *not*
             * include '\v' and '\f', so not the same group as isspace),
             * even as character references.
             * There's no official way to escape them, so we'll do this. */
            if (g_ascii_iscntrl(*p)) {
                offset += snprintf(&temp_buffer[offset], ESCAPED_BUFFER_SIZE-offset, "\\x%x", (uint8_t)*p);
            } else {
                /* Just copy character */
                temp_buffer[offset++] = *p;
            }
        }
        if (offset > ESCAPED_BUFFER_LIMIT) {
            /* Getting close to end of buffer so flush to fh */
            temp_buffer[offset] = '\0';
            fputs(temp_buffer, fh);
            offset = 0;
        }
    }
    if (offset) {
        /* Flush any outstanding data */
        temp_buffer[offset] = '\0';
        fputs(temp_buffer, fh);
    }
}

static void
print_escaped_csv(FILE *fh, const char *unescaped_string, char delimiter, char quote_char, bool escape_wsp)
{
    if (fh == NULL || unescaped_string == NULL) {
        return;
    }

    /* XXX: What about the field aggregator? Should that be escaped?
     * Should there be an "escape all non-printable" option?
     * (Instead of or in addition to escape wsp?)
     * Should there be a "escape all non ASCII?" option, similar
     * to the Wireshark output?
     */
    char *escaped_string;
    if (quote_char == '\0') {
        /* Not quoting, so we must escape the delimiter */
        escaped_string = ws_escape_csv(NULL, unescaped_string, false, delimiter, false, escape_wsp);
    } else {
        escaped_string = ws_escape_csv(NULL, unescaped_string, true, quote_char, true, escape_wsp);
    }
    fputs(escaped_string, fh);
    wmem_free(NULL, escaped_string);
}

static void
pdml_write_field_hex_value(write_pdml_data *pdata, field_info *fi)
{
    int           i;
    const uint8_t *pd;

    if (!fi->ds_tvb)
        return;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        fprintf(pdata->fh, "field length invalid!");
        return;
    }

    /* Find the data for this field. */
    pd = get_field_data(pdata->src_list, fi);

    if (pd) {
        /* Used fixed buffer where can, otherwise temp malloc */
        static char str_static[513];
        char *str = str_static;
        char* str_heap = NULL;
        if (fi->length > 256) {
            str_heap = (char*)g_malloc(fi->length*2 + 1);  /* no need to zero */
            str = str_heap;
        }

        static const char hex[] = "0123456789abcdef";

        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            str[2*i] =   hex[pd[i] >> 4];
            str[2*i+1] = hex[pd[i] & 0xf];
        }
        str[2 * fi->length] = '\0';
        fputs(str, pdata->fh);
        g_free(str_heap);            /* harmless/fast if NULL */
    }
}

static void
json_write_field_hex_value(write_json_data *pdata, field_info *fi)
{
    const uint8_t *pd;

    if (!fi->ds_tvb)
        return;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        json_dumper_value_string(pdata->dumper, "field length invalid!");
        return;
    }

    /* Find the data for this field. */
    pd = get_field_data(pdata->src_list, fi);

    if (pd) {
        int i;
        char* str = (char*)g_malloc(fi->length*2 + 1);    /* no need to zero */
        static const char hex[] = "0123456789abcdef";
        /* Print a simple hex dump */
        for (i = 0; i < fi->length; i++) {
            uint8_t c = pd[i];
            str[2 * i] = hex[c >> 4];
            str[2 * i + 1] = hex[c & 0xf];
        }
        str[2 * fi->length] = '\0';
        json_dumper_value_string(pdata->dumper, str);
        g_free(str);
    } else {
        json_dumper_value_string(pdata->dumper, "");
    }
}

bool
print_hex_data(print_stream_t *stream, epan_dissect_t *edt, unsigned hexdump_options)
{
    bool          multiple_sources;
    GSList       *src_le;
    tvbuff_t     *tvb;
    char         *line, *name;
    const unsigned char *cp;
    unsigned      length;
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
        if (multiple_sources && (HEXDUMP_SOURCE_OPTION(hexdump_options) == HEXDUMP_SOURCE_MULTI)) {
            name = get_data_source_name(src);
            line = ws_strdup_printf("%s:", name);
            wmem_free(NULL, name);
            print_line(stream, 0, line);
            g_free(line);
        }
        length = tvb_captured_length(tvb);
        if (length == 0)
            return true;
        cp = tvb_get_ptr(tvb, 0, length);
        if (!print_hex_data_buffer(stream, cp, length,
                                   (packet_char_enc)edt->pi.fd->encoding,
                                   HEXDUMP_ASCII_OPTION(hexdump_options)))
            return false;
        if (HEXDUMP_SOURCE_OPTION(hexdump_options) == HEXDUMP_SOURCE_PRIMARY) {
            return true;
        }
    }
    return true;
}

static bool print_hex_data_line(void *stream, const char *line)
{
    return print_line(stream, 0, line);
}

static bool print_hex_data_buffer(print_stream_t *stream, const unsigned char *cp,
                                      unsigned length, packet_char_enc encoding,
                                      unsigned hexdump_options)
{
    return hex_dump_buffer(print_hex_data_line, stream, cp, length,
                        encoding == PACKET_CHAR_ENC_CHAR_EBCDIC ? HEXDUMP_ENC_EBCDIC : HEXDUMP_ENC_ASCII,
                        hexdump_options);
}

size_t output_fields_num_fields(output_fields_t* fields)
{
    ws_assert(fields);

    if (NULL == fields->fields) {
        return 0;
    } else {
        return fields->fields->len;
    }
}

void output_fields_free(output_fields_t* fields)
{
    ws_assert(fields);

    if (NULL != fields->fields) {
        size_t i;

        if (NULL != fields->field_indicies) {
            /* Keys are stored in fields->fields, values are
             * integers.
             */
            g_hash_table_destroy(fields->field_indicies);
        }

        if (NULL != fields->field_dfilters) {
            g_ptr_array_unref(fields->field_dfilters);
        }

        if (NULL != fields->field_values) {
            g_free(fields->field_values);
        }

        for (i = 0; i < fields->fields->len; ++i) {
            char* field = (char *)g_ptr_array_index(fields->fields,i);
            g_free(field);
        }
        g_ptr_array_free(fields->fields, true);
    }

    g_free(fields);
}

void output_fields_add(output_fields_t *fields, const char *field)
{
    char *field_copy;

    ws_assert(fields);
    ws_assert(field);


    if (NULL == fields->fields) {
        fields->fields = g_ptr_array_new();
    }

    field_copy = g_strdup(field);

    g_ptr_array_add(fields->fields, field_copy);

    /* See if we have a column as a field entry */
    if (!strncmp(field, COLUMN_FIELD_FILTER, strlen(COLUMN_FIELD_FILTER)))
        fields->includes_col_fields = true;

}

/*
 * Returns true if the field did not exist yet (or existed with the same
 * filter_flags value), false if the field was in the protocolfilter with
 * a different flag.
 */
bool
output_fields_add_protocolfilter(output_fields_t* fields, const char* field, pf_flags filter_flags)
{
    void* value;
    bool ret = true;
    if (!fields->protocolfilter) {
        fields->protocolfilter = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
    }
    if (wmem_map_lookup_extended(fields->protocolfilter, field, NULL, &value)) {
        if (GPOINTER_TO_UINT(value) != (unsigned)filter_flags) {
            ret = false;
        }
    }
    wmem_map_insert(fields->protocolfilter, field, GINT_TO_POINTER(filter_flags));

    /* See if we have a column as a field entry */
    if (!strncmp(field, COLUMN_FIELD_FILTER, strlen(COLUMN_FIELD_FILTER)))
        fields->includes_col_fields = true;

    return ret;
}

static void
output_field_check(void *data, void *user_data)
{
    char *field = (char *)data;
    GSList **invalid_fields = (GSList **)user_data;

    dfilter_t *dfilter;
    if (dfilter_compile(field, &dfilter, NULL)) {
        dfilter_free(dfilter);
    } else {
        *invalid_fields = g_slist_prepend(*invalid_fields, field);
    }

}

static void
output_field_check_protocolfilter(void* key, void* value _U_, void* user_data)
{
    output_field_check(key, user_data);
}

GSList *
output_fields_valid(output_fields_t *fields)
{
    GSList *invalid_fields = NULL;
    if (fields->fields != NULL) {
        g_ptr_array_foreach(fields->fields, output_field_check, &invalid_fields);
    }

    if (fields->protocolfilter != NULL) {
        wmem_map_foreach(fields->protocolfilter, output_field_check_protocolfilter, &invalid_fields);
    }

    return invalid_fields;
}

bool output_fields_set_option(output_fields_t *info, char *option)
{
    const char *option_name;
    const char *option_value;

    ws_assert(info);
    ws_assert(option);

    if ('\0' == *option) {
        return false; /* this happens if we're called from tshark -E '' */
    }
    option_name = strtok(option, "=");
    if (!option_name) {
        return false;
    }
    option_value = option + strlen(option_name) + 1;
    if (*option_value == '\0') {
        return false;
    }

    if (0 == strcmp(option_name, "header")) {
        switch (*option_value) {
        case 'n':
            info->print_header = false;
            break;
        case 'y':
            info->print_header = true;
            break;
        default:
            return false;
        }
        return true;
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
        return true;
    }
    else if (0 == strcmp(option_name, "occurrence")) {
        switch (*option_value) {
        case 'f':
        case 'l':
        case 'a':
            info->occurrence = *option_value;
            break;
        default:
            return false;
        }
        return true;
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
        return true;
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
            return false;
        }
        return true;
    }
    else if (0 == strcmp(option_name, "bom")) {
        switch (*option_value) {
        case 'n':
            info->print_bom = false;
            break;
        case 'y':
            info->print_bom = true;
            break;
        default:
            return false;
        }
        return true;
    }
    else if (0 == strcmp(option_name, "escape")) {
        switch (*option_value) {
        case 'n':
            info->escape = false;
            break;
        case 'y':
            info->escape = true;
            break;
        default:
            return false;
        }
        return true;
    }

    return false;
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

bool output_fields_has_cols(output_fields_t* fields)
{
    ws_assert(fields);
    return fields->includes_col_fields;
}

static void
output_field_prime_edt(void *data, void *user_data)
{
    char *field = (char *)data;
    epan_dissect_t *edt = (epan_dissect_t*)user_data;

    /* Find a hf. Note in tshark we already converted the protocol from
     * its alias, if any.
     */
    header_field_info *hfinfo = proto_registrar_get_byname(field);
    if (hfinfo) {
        /* Rewind to the first hf of that name. */
        while (hfinfo->same_name_prev_id != -1) {
            hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
        }

        /* Prime all hf's with that name. */
        while (hfinfo) {
            proto_tree_prime_with_hfid_print(edt->tree, hfinfo->id);
            hfinfo = hfinfo->same_name_next;
        }
    }
}

static void
output_field_dfilter_prime_edt(void *data, void *user_data)
{
    dfilter_t *dfilter = (dfilter_t *)data;
    epan_dissect_t *edt = (epan_dissect_t*)user_data;

    if (dfilter) {
        epan_dissect_prime_with_dfilter(edt, dfilter);
    }
}

static void
dfilter_free_cb(void *data)
{
    dfilter_t *dcode = (dfilter_t*)data;

    dfilter_free(dcode);
}

void output_fields_prime_edt(epan_dissect_t *edt, output_fields_t* fields)
{
    if (fields->fields != NULL) {
        g_ptr_array_foreach(fields->fields, output_field_prime_edt, edt);

        if (fields->field_dfilters == NULL) {
            fields->field_dfilters = g_ptr_array_new_full(fields->fields->len, dfilter_free_cb);

            for (size_t i = 0; i < fields->fields->len; ++i) {
                char *field = (char *)g_ptr_array_index(fields->fields, i);
                dfilter_t *dfilter = NULL;

                /* For now, we only compile a filter for complex expressions.
                 * If it's just a field name, use the previous method.
                 */
                if (!proto_registrar_get_byname(field)) {
                    dfilter_compile_full(field, &dfilter, NULL, DF_EXPAND_MACROS|DF_OPTIMIZE|DF_RETURN_VALUES, __func__);
                }
                g_ptr_array_add(fields->field_dfilters, dfilter);
            }
        }

        g_ptr_array_foreach(fields->field_dfilters, output_field_dfilter_prime_edt, edt);
    }
}

void write_fields_preamble(output_fields_t* fields, FILE *fh)
{
    size_t i;

    ws_assert(fields);
    ws_assert(fh);
    ws_assert(fields->fields);

    if (fields->print_bom) {
        fputs(UTF8_BOM, fh);
    }


    if (!fields->print_header) {
        return;
    }

    for(i = 0; i < fields->fields->len; ++i) {
        const char* field = (const char *)g_ptr_array_index(fields->fields,i);
        if (i != 0 ) {
            fputc(fields->separator, fh);
        }
        fputs(field, fh);
    }
    fputc('\n', fh);
}

static void format_field_values(output_fields_t* fields, void *field_index, char* value)
{
    unsigned   indx;
    GPtrArray* fv_p;

    if (NULL == value)
        return;

    /* Unwrap change made to disambiguate zero / null */
    indx = GPOINTER_TO_UINT(field_index) - 1;

    if (fields->field_values[indx] == NULL) {
        fields->field_values[indx] = g_ptr_array_new_with_free_func(g_free);
    }

    /* Essentially: fieldvalues[indx] is a 'GPtrArray *' with each array entry */
    /*  pointing to a string which is (part of) the final output string.       */

    fv_p = fields->field_values[indx];

    switch (fields->occurrence) {
    case 'f':
        /* print the value of only the first occurrence of the field */
        if (g_ptr_array_len(fv_p) != 0) {
            /*
             * This isn't the first occurrence, so the value won't be used;
             * free it.
             */
            g_free(value);
            return;
        }
        break;
    case 'l':
        /* print the value of only the last occurrence of the field */
        if (g_ptr_array_len(fv_p) != 0) {
            /*
             * This isn't the first occurrence, so there's already a
             * value in the array, which won't be used; remove the
             * first (only) element in the array (which will free it,
             * as we created the GPtrArray with a free func) -
             * this value will replace it.
             */
            g_ptr_array_set_size(fv_p, 0);
        }
        break;
    case 'a':
        /* print the value of all occurrences of the field */
        break;
    default:
        ws_assert_not_reached();
        break;
    }

    g_ptr_array_add(fv_p, (void *)value);
}

static void proto_tree_get_node_field_values(proto_node *node, void *data)
{
    write_field_data_t *call_data;
    field_info *fi;
    void *      field_index;

    call_data = (write_field_data_t *)data;
    fi = PNODE_FINFO(node);

    /* dissection with an invisible proto tree? */
    ws_assert(fi);

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

static void write_specified_fields(fields_format format, output_fields_t *fields, epan_dissect_t *edt, column_info *cinfo _U_, FILE *fh, json_dumper *dumper)
{
    size_t    i;

    write_field_data_t data;

    ws_assert(fields);
    ws_assert(fields->fields);
    ws_assert(edt);
    /* JSON formats must go through json_dumper */
    if (format == FORMAT_JSON || format == FORMAT_EK) {
        ws_assert(!fh && dumper);
    } else {
        ws_assert(fh && !dumper);
    }

    data.fields = fields;
    data.edt = edt;

    if (NULL == fields->field_indicies) {
        /* Prepare a lookup table from string abbreviation for field to its index. */
        fields->field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

        i = 0;
        while (i < fields->fields->len) {
            char *field = (char *)g_ptr_array_index(fields->fields, i);
            /* Store field indicies +1 so that zero is not a valid value,
             * and can be distinguished from NULL as a pointer.
             */
            ++i;
            if (proto_registrar_get_byname(field)) {
                g_hash_table_insert(fields->field_indicies, field, GUINT_TO_POINTER(i));
            }
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

    i = 0;
    while(i < fields->fields->len) {
        dfilter_t *dfilter = (dfilter_t *)g_ptr_array_index(fields->field_dfilters, i);

        /* Match how the field indices are treated. */
        ++i;

        if (dfilter != NULL) {
            GPtrArray *fvals = NULL;
            bool passed = dfilter_apply_full(dfilter, edt->tree, &fvals);
            char *str;
            if (fvals != NULL) {
                int len = g_ptr_array_len(fvals);
                for (int j = 0; j < len; ++j) {
                    str = fvalue_to_string_repr(NULL, fvals->pdata[j], FTREPR_DISPLAY, BASE_NONE);
                    format_field_values(fields, GUINT_TO_POINTER(i), str);
                }
                g_ptr_array_unref(fvals);
            } else if (passed) {
                /* XXX - Should this be "1" (and "0" for !passed) like with
                 * FT_NONE fields, or a check mark / nothing like the GUI ? */
                //str = g_strdup("1");
                str = g_strdup(UTF8_CHECK_MARK);
                format_field_values(fields, GUINT_TO_POINTER(i), str);
            }
        }
    }

    proto_tree_children_foreach(edt->tree, proto_tree_get_node_field_values,
                                &data);

    switch (format) {
    case FORMAT_CSV:
        for(i = 0; i < fields->fields->len; ++i) {
            if (0 != i) {
                fputc(fields->separator, fh);
            }
            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                size_t j;
                fv_p = fields->field_values[i];

                /* Output the array of (partial) field values */
                if (g_ptr_array_len(fv_p) != 0) {
                    wmem_strbuf_t *buf = wmem_strbuf_new(NULL, g_ptr_array_index(fv_p, 0));
                    for (j = 1; j < g_ptr_array_len(fv_p); j++ ) {
                        wmem_strbuf_append_c(buf, fields->aggregator);
                        wmem_strbuf_append(buf, (char *)g_ptr_array_index(fv_p, j));
                    }
                    print_escaped_csv(fh, wmem_strbuf_get_str(buf), fields->separator, fields->quote, fields->escape);
                    wmem_strbuf_destroy(buf);
                }
                g_ptr_array_free(fv_p, true);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        break;
    case FORMAT_XML:
        for(i = 0; i < fields->fields->len; ++i) {
            char *field = (char *)g_ptr_array_index(fields->fields, i);

            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                char * str;
                size_t j;
                fv_p = fields->field_values[i];

                /* Output the array of (partial) field values */
                for (j = 0; j < (g_ptr_array_len(fv_p)); j++ ) {
                    str = (char *)g_ptr_array_index(fv_p, j);

                    fprintf(fh, "  <field name=\"%s\" value=", field);
                    fputs("\"", fh);
                    print_escaped_xml(fh, str);
                    fputs("\"/>\n", fh);
                }
                g_ptr_array_free(fv_p, true);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        break;
    case FORMAT_JSON:
        json_dumper_begin_object(dumper);
        for(i = 0; i < fields->fields->len; ++i) {
            char *field = (char *)g_ptr_array_index(fields->fields, i);

            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                char * str;
                size_t j;
                fv_p = fields->field_values[i];

                json_dumper_set_member_name(dumper, field);
                json_dumper_begin_array(dumper);

                /* Output the array of (partial) field values */
                for (j = 0; j < (g_ptr_array_len(fv_p)); j++ ) {
                    str = (char *) g_ptr_array_index(fv_p, j);
                    json_dumper_value_string(dumper, str);
                }

                json_dumper_end_array(dumper);

                g_ptr_array_free(fv_p, true);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        json_dumper_end_object(dumper);
        break;
    case FORMAT_EK:
        for(i = 0; i < fields->fields->len; ++i) {
            char *field = (char *)g_ptr_array_index(fields->fields, i);

            if (NULL != fields->field_values[i]) {
                GPtrArray *fv_p;
                char * str;
                size_t j;
                fv_p = fields->field_values[i];

                json_dumper_set_member_name(dumper, field);
                json_dumper_begin_array(dumper);

                /* Output the array of (partial) field values */
                for (j = 0; j < (g_ptr_array_len(fv_p)); j++ ) {
                    str = (char *)g_ptr_array_index(fv_p, j);
                    json_dumper_value_string(dumper, str);
                }

                json_dumper_end_array(dumper);

                g_ptr_array_free(fv_p, true);  /* get ready for the next packet */
                fields->field_values[i] = NULL;
            }
        }
        break;

    default:
        fprintf(stderr, "Unknown fields format %d\n", format);
        ws_assert_not_reached();
        break;
    }
}

void write_fields_finale(output_fields_t* fields _U_ , FILE *fh _U_)
{
    /* Nothing to do */
}

/* Returns an g_malloced string */
char* get_node_field_value(field_info* fi, epan_dissect_t* edt)
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
        char       *dfilter_string;

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
        case FT_UINT_BYTES:
        case FT_BYTES:
            {
                char *ret;
                const uint8_t *bytes = fvalue_get_bytes_data(fi->value);
                if (bytes) {
                    dfilter_string = (char *)wmem_alloc(NULL, 3*fvalue_length2(fi->value));
                    switch (fi->hfinfo->display) {
                    case SEP_DOT:
                        ret = bytes_to_hexstr_punct(dfilter_string, bytes, fvalue_length2(fi->value), '.');
                        break;
                    case SEP_DASH:
                        ret = bytes_to_hexstr_punct(dfilter_string, bytes, fvalue_length2(fi->value), '-');
                        break;
                    case SEP_COLON:
                        ret = bytes_to_hexstr_punct(dfilter_string, bytes, fvalue_length2(fi->value), ':');
                        break;
                    case SEP_SPACE:
                        ret = bytes_to_hexstr_punct(dfilter_string, bytes, fvalue_length2(fi->value), ' ');
                        break;
                    case BASE_NONE:
                    default:
                        ret = bytes_to_hexstr(dfilter_string, bytes, fvalue_length2(fi->value));
                        break;
                    }
                    *ret = '\0';
                    ret = g_strdup(dfilter_string);
                    wmem_free(NULL, dfilter_string);
                } else {
                    if (fi->hfinfo->display & BASE_ALLOW_ZERO) {
                        ret = g_strdup("<none>");
                    } else {
                        ret = g_strdup("<MISSING>");
                    }
                }
                return ret;
            }
            break;
        default:
            dfilter_string = fvalue_to_string_repr(NULL, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
            if (dfilter_string != NULL) {
                char* ret = g_strdup(dfilter_string);
                wmem_free(NULL, dfilter_string);
                return ret;
            } else {
                return get_field_hex_value(edt->pi.data_src, fi);
            }
        }
    }
}

static char*
get_field_hex_value(GSList *src_list, field_info *fi)
{
    const uint8_t *pd;

    if (!fi->ds_tvb)
        return NULL;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        return g_strdup("field length invalid!");
    }

    /* Find the data for this field. */
    pd = get_field_data(src_list, fi);

    if (pd) {
        int        i;
        char      *buffer;
        char      *p;
        int        len;
        const int  chars_per_byte = 2;

        len    = chars_per_byte * fi->length;
        buffer = (char *)g_malloc(sizeof(char)*(len + 1));
        buffer[len] = '\0'; /* Ensure NULL termination in bad cases */
        p = buffer;
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            snprintf(p, chars_per_byte+1, "%02x", pd[i]);
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
    fields->print_bom           = false;
    fields->print_header        = false;
    fields->separator           = '\t';
    fields->occurrence          = 'a';
    fields->aggregator          = ',';
    fields->fields              = NULL; /*Do lazy initialisation */
    fields->field_dfilters      = NULL;
    fields->field_indicies      = NULL;
    fields->field_values        = NULL;
    fields->protocolfilter      = NULL;
    fields->quote               ='\0';
    fields->escape              = true;
    fields->includes_col_fields = false;
    return fields;
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
