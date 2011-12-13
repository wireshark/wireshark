/* print.c
 * Routines for printing packet analysis trees.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/tvbuff.h>
#include <epan/packet.h>
#include <epan/emem.h>

#include "packet-range.h"
#include "print.h"
#include "isprint.h"
#include "ps.h"
#include "version_info.h"
#include <wsutil/file_util.h>
#include <epan/charsets.h>
#include <epan/dissectors/packet-data.h>
#include <epan/dissectors/packet-frame.h>
#include <epan/filesystem.h>

#define PDML_VERSION "0"
#define PSML_VERSION "0"

typedef struct {
	int			level;
	print_stream_t		*stream;
	gboolean		success;
	GSList		 	*src_list;
	print_dissections_e	print_dissections;
	gboolean		print_hex_for_data;
	packet_char_enc		encoding;
	epan_dissect_t		*edt;
} print_data;

typedef struct {
	int			level;
	FILE			*fh;
	GSList		 	*src_list;
	epan_dissect_t		*edt;
} write_pdml_data;

typedef struct {
    output_fields_t* fields;
	epan_dissect_t		*edt;
} write_field_data_t;

struct _output_fields {
    gboolean print_header;
    gchar separator;
    gchar occurrence;
    gchar aggregator;
    GPtrArray* fields;
    GHashTable* field_indicies;
    emem_strbuf_t** field_values;
    gchar quote;
};

GHashTable *output_only_tables = NULL;

static gboolean write_headers = FALSE;

static const gchar* get_field_hex_value(GSList* src_list, field_info *fi);
static void proto_tree_print_node(proto_node *node, gpointer data);
static void proto_tree_write_node_pdml(proto_node *node, gpointer data);
static const guint8 *get_field_data(GSList *src_list, field_info *fi);
static void write_pdml_field_hex_value(write_pdml_data *pdata, field_info *fi);
static gboolean print_hex_data_buffer(print_stream_t *stream, const guchar *cp,
    guint length, packet_char_enc encoding);
static void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size);
static void print_escaped_xml(FILE *fh, const char *unescaped_string);

static void print_pdml_geninfo(proto_tree *tree, FILE *fh);

static void proto_tree_get_node_field_values(proto_node *node, gpointer data);

static FILE *
open_print_dest(int to_file, const char *dest)
{
	FILE	*fh;

	/* Open the file or command for output */
	if (to_file)
		fh = ws_fopen(dest, "w");
	else
		fh = popen(dest, "w");

	return fh;
}

static gboolean
close_print_dest(int to_file, FILE *fh)
{
	/* Close the file or command */
	if (to_file)
		return (fclose(fh) == 0);
	else
		return (pclose(fh) == 0);
}

#define MAX_PS_LINE_LENGTH 256

gboolean
proto_tree_print(print_args_t *print_args, epan_dissect_t *edt,
    print_stream_t *stream)
{
	print_data data;

	/* Create the output */
	data.level = 0;
	data.stream = stream;
	data.success = TRUE;
	data.src_list = edt->pi.data_src;
	data.encoding = edt->pi.fd->flags.encoding;
	data.print_dissections = print_args->print_dissections;
	/* If we're printing the entire packet in hex, don't
	   print uninterpreted data fields in hex as well. */
	data.print_hex_for_data = !print_args->print_hex;
	data.edt = edt;

	proto_tree_children_foreach(edt->tree, proto_tree_print_node, &data);
	return data.success;
}

#define MAX_INDENT	160

/* Print a tree's data, and any child nodes. */
static
void proto_tree_print_node(proto_node *node, gpointer data)
{
	field_info	*fi = PNODE_FINFO(node);
	print_data	*pdata = (print_data*) data;
	const guint8	*pd;
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;

	g_assert(fi && "dissection with an invisible proto tree?");

	/* Don't print invisible entries. */
	if (PROTO_ITEM_IS_HIDDEN(node))
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

	if (PROTO_ITEM_IS_GENERATED(node)) {
		label_ptr = g_strdup_printf("[%s]", label_ptr);
	}

	if (!print_line(pdata->stream, pdata->level, label_ptr)) {
		pdata->success = FALSE;
		return;
	}

	/*
	 * If -O is specified, only display the protocols which are in the
	 * lookup table.  Only check on the first level: once we start printing
	 * a tree, print the rest of the subtree.  Otherwise we won't print
	 * subitems whose abbreviation doesn't match the protocol--for example
	 * text items (whose abbreviation is simply "text").
	 */
	if (output_only_tables != NULL && pdata->level == 0
	 && g_hash_table_lookup(output_only_tables, fi->hfinfo->abbrev) == NULL) {
	  pdata->success = TRUE;
	  return;
	}

	if (PROTO_ITEM_IS_GENERATED(node)) {
		g_free(label_ptr);
	}

	/* If it's uninterpreted data, dump it (unless our caller will
	   be printing the entire packet in hex). */
	if (fi->hfinfo->id == proto_data && pdata->print_hex_for_data) {
		/*
		 * Find the data for this field.
		 */
		pd = get_field_data(pdata->src_list, fi);
		if (pd) {
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
	g_assert(fi->tree_type >= -1 && fi->tree_type < num_tree_types);
	if (pdata->print_dissections == print_dissections_expanded ||
	    (pdata->print_dissections == print_dissections_as_displayed &&
		fi->tree_type >= 0 && tree_is_expanded[fi->tree_type])) {
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
write_pdml_preamble(FILE *fh, const gchar* filename)
{
	time_t t=time(NULL);
	char *ts=asctime(localtime(&t));
	ts[strlen(ts)-1]=0; /* overwrite \n */

	fputs("<?xml version=\"1.0\"?>\n", fh);
	fputs("<?xml-stylesheet type=\"text/xsl\" href=\"" PDML2HTML_XSL "\"?>\n", fh);
	fprintf(fh, "<!-- You can find " PDML2HTML_XSL " in %s or at http://anonsvn.wireshark.org/trunk/wireshark/" PDML2HTML_XSL ". -->\n", get_datafile_dir());
	fputs("<pdml version=\"" PDML_VERSION "\" ", fh);
	fprintf(fh, "creator=\"%s/%s\" time=\"%s\" capture_file=\"%s\">\n", PACKAGE, VERSION, ts, filename ? filename : "");
}

void
proto_tree_write_pdml(epan_dissect_t *edt, FILE *fh)
{
	write_pdml_data data;

	/* Create the output */
	data.level = 0;
	data.fh = fh;
	data.src_list = edt->pi.data_src;
	data.edt = edt;

	fprintf(fh, "<packet>\n");

	/* Print a "geninfo" protocol as required by PDML */
	print_pdml_geninfo(edt->tree, fh);

	proto_tree_children_foreach(edt->tree, proto_tree_write_node_pdml,
	    &data);

	fprintf(fh, "</packet>\n\n");
}

/* Write out a tree's data, and any child nodes, as PDML */
static void
proto_tree_write_node_pdml(proto_node *node, gpointer data)
{
	field_info	*fi = PNODE_FINFO(node);
	write_pdml_data	*pdata = (write_pdml_data*) data;
	const gchar	*label_ptr;
	gchar		label_str[ITEM_LABEL_LENGTH];
	char		*dfilter_string;
	size_t		chop_len;
	int		i;
	gboolean wrap_in_fake_protocol;

	g_assert(fi && "dissection with an invisible proto tree?");

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

		fputs("\" value=\"", pdata->fh);
		write_pdml_field_hex_value(pdata, fi);

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
		write_pdml_field_hex_value(pdata, fi);
		fputs("\">\n", pdata->fh);
	}
	/* Normal protocols and fields */
	else {
		if (fi->hfinfo->type == FT_PROTOCOL) {
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

		if (PROTO_ITEM_IS_HIDDEN(node))
			fprintf(pdata->fh, "\" hide=\"yes");

		fprintf(pdata->fh, "\" size=\"%d", fi->length);
		if (node->parent && node->parent->finfo && (fi->start < node->parent->finfo->start)) {
			fprintf(pdata->fh, "\" pos=\"%d", node->parent->finfo->start + fi->start);
		} else {
			fprintf(pdata->fh, "\" pos=\"%d", fi->start);
		}
/*		fprintf(pdata->fh, "\" id=\"%d", fi->hfinfo->id);*/

		/* show, value, and unmaskedvalue attributes */
		switch (fi->hfinfo->type)
		{
		case FT_PROTOCOL:
			break;
		case FT_NONE:
			fputs("\" show=\"\" value=\"",  pdata->fh);
			break;
		default:
			/* XXX - this is a hack until we can just call
			 * fvalue_to_string_repr() for *all* FT_* types. */
			dfilter_string = proto_construct_match_selected_string(fi,
			    pdata->edt);
			if (dfilter_string != NULL) {
				chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */

				/* XXX - Remove double-quotes. Again, once we
				 * can call fvalue_to_string_repr(), we can
				 * ask it not to produce the version for
				 * display-filters, and thus, no
				 * double-quotes. */
				if (dfilter_string[strlen(dfilter_string)-1] == '"') {
					dfilter_string[strlen(dfilter_string)-1] = '\0';
					chop_len++;
				}

				fputs("\" show=\"", pdata->fh);
				print_escaped_xml(pdata->fh, &dfilter_string[chop_len]);
			}

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
					fprintf(pdata->fh, "%X", fvalue_get_uinteger(&fi->value));
					fputs("\" unmaskedvalue=\"", pdata->fh);
					write_pdml_field_hex_value(pdata, fi);
				}
				else {
					write_pdml_field_hex_value(pdata, fi);
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

	/* We always print all levels for PDML. Recurse here. */
	if (node->first_child != NULL) {
		pdata->level++;
		proto_tree_children_foreach(node,
				proto_tree_write_node_pdml, pdata);
		pdata->level--;
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
		if (fi->hfinfo->id != proto_data) {   /* Data protocol uses simple tags */
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

/* Print info for a 'geninfo' pseudo-protocol. This is required by
 * the PDML spec. The information is contained in Wireshark's 'frame' protocol,
 * but we produce a 'geninfo' protocol in the PDML to conform to spec.
 * The 'frame' protocol follows the 'geninfo' protocol in the PDML. */
static void
print_pdml_geninfo(proto_tree *tree, FILE *fh)
{
	guint32 num, len, caplen;
	nstime_t *timestamp;
	GPtrArray *finfo_array;
	field_info *frame_finfo;

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
"  <proto name=\"geninfo\" pos=\"0\" showname=\"General information\" size=\"%u\">\n",
		frame_finfo->length);

	/* Print geninfo.num */
	fprintf(fh,
"    <field name=\"num\" pos=\"0\" show=\"%u\" showname=\"Number\" value=\"%x\" size=\"%u\"/>\n",
		num, num, frame_finfo->length);

	/* Print geninfo.len */
	fprintf(fh,
"    <field name=\"len\" pos=\"0\" show=\"%u\" showname=\"Frame Length\" value=\"%x\" size=\"%u\"/>\n",
		len, len, frame_finfo->length);

	/* Print geninfo.caplen */
	fprintf(fh,
"    <field name=\"caplen\" pos=\"0\" show=\"%u\" showname=\"Captured Length\" value=\"%x\" size=\"%u\"/>\n",
		caplen, caplen, frame_finfo->length);

	/* Print geninfo.timestamp */
	fprintf(fh,
"    <field name=\"timestamp\" pos=\"0\" show=\"%s\" showname=\"Captured Time\" value=\"%d.%09d\" size=\"%u\"/>\n",
		abs_time_to_str(timestamp, ABSOLUTE_TIME_LOCAL, TRUE), (int) timestamp->secs, timestamp->nsecs, frame_finfo->length);

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
write_psml_preamble(FILE *fh)
{
	fputs("<?xml version=\"1.0\"?>\n", fh);
	fputs("<psml version=\"" PSML_VERSION "\" ", fh);
	fprintf(fh, "creator=\"%s/%s\">\n", PACKAGE, VERSION);
	write_headers = TRUE;
}

void
proto_tree_write_psml(epan_dissect_t *edt, FILE *fh)
{
	gint	i;

	/* if this is the first packet, we have to create the PSML structure output */
	if(write_headers) {
	    fprintf(fh, "<structure>\n");

	    for(i=0; i < edt->pi.cinfo->num_cols; i++) {
		fprintf(fh, "<section>");
		print_escaped_xml(fh, edt->pi.cinfo->col_title[i]);
		fprintf(fh, "</section>\n");
	    }

	    fprintf(fh, "</structure>\n\n");

	    write_headers = FALSE;
	}

	fprintf(fh, "<packet>\n");

	for(i=0; i < edt->pi.cinfo->num_cols; i++) {
	    fprintf(fh, "<section>");
	    print_escaped_xml(fh, edt->pi.cinfo->col_data[i]);
	    fprintf(fh, "</section>\n");
	}

	fprintf(fh, "</packet>\n\n");
}

void
write_psml_finale(FILE *fh)
{
	fputs("</psml>\n", fh);
}

void
write_csv_preamble(FILE *fh _U_)
{
	write_headers = TRUE;
}

static gchar *csv_massage_str(const gchar *source, const gchar *exceptions)
{
    gchar *csv_str;
    gchar *tmp_str;

    csv_str = g_strescape(source, exceptions);
    tmp_str = csv_str;
    while ( (tmp_str = strstr(tmp_str, "\\\"")) != NULL )
        *tmp_str = '\"';
    return csv_str;
}

static void csv_write_str(const char *str, char sep, FILE *fh)
{
    gchar *csv_str;

    csv_str = csv_massage_str(str, NULL);
    fprintf(fh, "\"%s\"%c", csv_str, sep);
    g_free(csv_str);
}

void
proto_tree_write_csv(epan_dissect_t *edt, FILE *fh)
{
    gint i;

    /* if this is the first packet, we have to write the CSV header */
    if(write_headers) {
        for(i=0; i < edt->pi.cinfo->num_cols - 1; i++)
            csv_write_str(edt->pi.cinfo->col_title[i], ',', fh);
        csv_write_str(edt->pi.cinfo->col_title[i], '\n', fh);
        write_headers = FALSE;
    }

    for(i=0; i < edt->pi.cinfo->num_cols - 1; i++)
        csv_write_str(edt->pi.cinfo->col_data[i], ',', fh);
    csv_write_str(edt->pi.cinfo->col_data[i], '\n', fh);
}

void
write_csv_finale(FILE *fh _U_)
{

}

void
write_carrays_preamble(FILE *fh _U_)
{

}

void
proto_tree_write_carrays(guint32 num, FILE *fh, epan_dissect_t *edt)
{
	guint32 i = 0, src_num = 0;
	GSList *src_le;
	data_source *src;
	tvbuff_t *tvb;
	const char *name;
	const guchar *cp;
	guint length;
	char ascii[9];

	for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
		memset(ascii, 0, sizeof(ascii));
		src = (data_source *)src_le->data;
		tvb = src->tvb;
		length = tvb_length(tvb);
		if (length == 0)
			continue;

		cp = tvb_get_ptr(tvb, 0, length);

		name = get_data_source_name(src);
		if (name)
			fprintf(fh, "/* %s */\n", name);
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
			ascii[i % 8] = isprint(*(cp + i)) ? *(cp + i) : '.';

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

void
write_carrays_finale(FILE *fh _U_)
{

}

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
static const guint8 *
get_field_data(GSList *src_list, field_info *fi)
{
	GSList *src_le;
	data_source *src;
	tvbuff_t *src_tvb;
	gint length, tvbuff_length;

	for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
		src = (data_source *)src_le->data;
		src_tvb = src->tvb;
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
			tvbuff_length = tvb_length_remaining(src_tvb,
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
	return NULL;	/* not found */
}

/* Print a string, escaping out certain characters that need to
 * escaped out for XML. */
static void
print_escaped_xml(FILE *fh, const char *unescaped_string)
{
	const char *p;
	char temp_str[8];

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
				fputs("&apos;", fh);
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
write_pdml_field_hex_value(write_pdml_data *pdata, field_info *fi)
{
	int i;
	const guint8 *pd;

	if (!fi->ds_tvb)
		return;

	if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
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
	gboolean multiple_sources;
	GSList *src_le;
	data_source *src;
	tvbuff_t *tvb;
	const char *name;
	char *line;
	const guchar *cp;
	guint length;

	/*
	 * Set "multiple_sources" iff this frame has more than one
	 * data source; if it does, we need to print the name of
	 * the data source before printing the data from the
	 * data source.
	 */
	multiple_sources = (edt->pi.data_src->next != NULL);

	for (src_le = edt->pi.data_src; src_le != NULL;
	    src_le = src_le->next) {
		src = (data_source *)src_le->data;
		tvb = src->tvb;
		if (multiple_sources) {
			name = get_data_source_name(src);
			print_line(stream, 0, "");
			line = g_strdup_printf("%s:", name);
			print_line(stream, 0, line);
			g_free(line);
		}
		length = tvb_length(tvb);
		if (length == 0)
		    return TRUE;
		cp = tvb_get_ptr(tvb, 0, length);
		if (!print_hex_data_buffer(stream, cp, length,
		    edt->pi.fd->flags.encoding))
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

#define MAX_OFFSET_LEN	8	/* max length of hex offset of bytes */
#define BYTES_PER_LINE	16	/* max byte values printed on a line */
#define HEX_DUMP_LEN	(BYTES_PER_LINE*3)
				/* max number of characters hex dump takes -
				   2 digits plus trailing blank */
#define DATA_DUMP_LEN	(HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
				/* number of characters those bytes take;
				   3 characters per byte of hex dump,
				   2 blanks separating hex from ASCII,
				   1 character per byte of ASCII dump */
#define MAX_LINE_LEN	(MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
				/* number of characters per line;
				   offset, 2 blanks separating offset
				   from data dump, data dump */

static gboolean
print_hex_data_buffer(print_stream_t *stream, const guchar *cp,
    guint length, packet_char_enc encoding)
{
	register unsigned int ad, i, j, k, l;
	guchar c;
	guchar line[MAX_LINE_LEN + 1];
	unsigned int use_digits;
	static guchar binhex[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	if (!print_line(stream, 0, ""))
		return FALSE;

	/*
	 * How many of the leading digits of the offset will we supply?
	 * We always supply at least 4 digits, but if the maximum offset
	 * won't fit in 4 digits, we use as many digits as will be needed.
	 */
	if (((length - 1) & 0xF0000000) != 0)
		use_digits = 8;	/* need all 8 digits */
	else if (((length - 1) & 0x0F000000) != 0)
		use_digits = 7;	/* need 7 digits */
	else if (((length - 1) & 0x00F00000) != 0)
		use_digits = 6;	/* need 6 digits */
	else if (((length - 1) & 0x000F0000) != 0)
		use_digits = 5;	/* need 5 digits */
	else
		use_digits = 4;	/* we'll supply 4 digits */

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
		line[k++] = c >= ' ' && c < 0x7f ? c : '.';
		i++;
		if ((i & 15) == 0 || i == length) {
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

static
void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size)
{
	int rd, wr;
	char c;

	if (in == NULL) {
		out[0] = '\0';
		return;
	}

	for (rd = 0, wr = 0 ; wr < outbuf_size; rd++, wr++ ) {
		c = in[rd];
		switch (c) {
			case '(':
			case ')':
			case '\\':
				out[wr] = '\\';
				out[++wr] = c;
				break;

			default:
				out[wr] = c;
				break;
		}

		if (c == 0) {
			break;
		}
	}
}

/* Some formats need stuff at the beginning of the output */
gboolean
print_preamble(print_stream_t *self, gchar *filename)
{
	return (self->ops->print_preamble)(self, filename);
}

gboolean
print_line(print_stream_t *self, int indent, const char *line)
{
	return (self->ops->print_line)(self, indent, line);
}

/* Insert bookmark */
gboolean
print_bookmark(print_stream_t *self, const gchar *name, const gchar *title)
{
	return (self->ops->print_bookmark)(self, name, title);
}

gboolean
new_page(print_stream_t *self)
{
	return (self->ops->new_page)(self);
}

/* Some formats need stuff at the end of the output */
gboolean
print_finale(print_stream_t *self)
{
	return (self->ops->print_finale)(self);
}

gboolean
destroy_print_stream(print_stream_t *self)
{
	return (self->ops->destroy)(self);
}

typedef struct {
	int to_file;
	FILE *fh;
} output_text;

static gboolean
print_preamble_text(print_stream_t *self _U_, gchar *filename _U_)
{
	/* do nothing */
	return TRUE;	/* always succeeds */
}

static gboolean
print_line_text(print_stream_t *self, int indent, const char *line)
{
	output_text *output = (output_text *)self->data;
	char space[MAX_INDENT+1];
	int i;
	int num_spaces;

	/* Prepare the tabs for printing, depending on tree level */
	num_spaces = indent * 4;
	if (num_spaces > MAX_INDENT) {
		num_spaces = MAX_INDENT;
	}
	for (i = 0; i < num_spaces; i++) {
		space[i] = ' ';
	}
	/* The string is NUL-terminated */
	space[num_spaces] = '\0';

	fputs(space, output->fh);
	fputs(line, output->fh);
	putc('\n', output->fh);
	return !ferror(output->fh);
}

static gboolean
print_bookmark_text(print_stream_t *self _U_, const gchar *name _U_,
    const gchar *title _U_)
{
	/* do nothing */
	return TRUE;
}

static gboolean
new_page_text(print_stream_t *self)
{
	output_text *output = (output_text *)self->data;

	fputs("\f", output->fh);
	return !ferror(output->fh);
}

static gboolean
print_finale_text(print_stream_t *self _U_)
{
	/* do nothing */
	return TRUE;	/* always succeeds */
}

static gboolean
destroy_text(print_stream_t *self)
{
	output_text *output = (output_text *)self->data;
	gboolean ret;

	ret = close_print_dest(output->to_file, output->fh);
	g_free(output);
	g_free(self);
	return ret;
}

static const print_stream_ops_t print_text_ops = {
	print_preamble_text,
	print_line_text,
	print_bookmark_text,
	new_page_text,
	print_finale_text,
	destroy_text
};

static print_stream_t *
print_stream_text_alloc(int to_file, FILE *fh)
{
	print_stream_t *stream;
	output_text *output;

	output = (output_text *)g_malloc(sizeof *output);
	output->to_file = to_file;
	output->fh = fh;
	stream = (print_stream_t *)g_malloc(sizeof (print_stream_t));
	stream->ops = &print_text_ops;
	stream->data = output;

	return stream;
}

print_stream_t *
print_stream_text_new(int to_file, const char *dest)
{
	FILE *fh;

	fh = open_print_dest(to_file, dest);
	if (fh == NULL)
		return NULL;

	return print_stream_text_alloc(to_file, fh);
}

print_stream_t *
print_stream_text_stdio_new(FILE *fh)
{
	return print_stream_text_alloc(TRUE, fh);
}

typedef struct {
	int to_file;
	FILE *fh;
} output_ps;

static gboolean
print_preamble_ps(print_stream_t *self, gchar *filename)
{
	output_ps *output = (output_ps *)self->data;
	unsigned char psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

	print_ps_preamble(output->fh);

	fputs("%% the page title\n", output->fh);
	ps_clean_string(psbuffer, filename, MAX_PS_LINE_LENGTH);
	fprintf(output->fh, "/ws_pagetitle (%s - Wireshark " VERSION "%s) def\n", psbuffer, wireshark_svnversion);
	fputs("\n", output->fh);
	return !ferror(output->fh);
}

static gboolean
print_line_ps(print_stream_t *self, int indent, const char *line)
{
	output_ps *output = (output_ps *)self->data;
	unsigned char psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

	ps_clean_string(psbuffer, line, MAX_PS_LINE_LENGTH);
	fprintf(output->fh, "%d (%s) putline\n", indent, psbuffer);
	return !ferror(output->fh);
}

static gboolean
print_bookmark_ps(print_stream_t *self, const gchar *name, const gchar *title)
{
	output_ps *output = (output_ps *)self->data;
	unsigned char psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

	/*
	 * See the Adobe "pdfmark reference":
	 *
	 *	http://partners.adobe.com/asn/acrobat/docs/pdfmark.pdf
	 *
	 * The pdfmark stuff tells code that turns PostScript into PDF
	 * things that it should do.
	 *
	 * The /OUT stuff creates a bookmark that goes to the
	 * destination with "name" as the name and "title" as the title.
	 *
	 * The "/DEST" creates the destination.
	 */
	ps_clean_string(psbuffer, title, MAX_PS_LINE_LENGTH);
	fprintf(output->fh, "[/Dest /%s /Title (%s)   /OUT pdfmark\n", name,
	    psbuffer);
	fputs("[/View [/XYZ -4 currentpoint matrix currentmatrix matrix defaultmatrix\n",
	    output->fh);
	fputs("matrix invertmatrix matrix concatmatrix transform exch pop 20 add null]\n",
	    output->fh);
	fprintf(output->fh, "/Dest /%s /DEST pdfmark\n", name);
	return !ferror(output->fh);
}

static gboolean
new_page_ps(print_stream_t *self)
{
	output_ps *output = (output_ps *)self->data;

	fputs("formfeed\n", output->fh);
	return !ferror(output->fh);
}

static gboolean
print_finale_ps(print_stream_t *self)
{
	output_ps *output = (output_ps *)self->data;

	print_ps_finale(output->fh);
	return !ferror(output->fh);
}

static gboolean
destroy_ps(print_stream_t *self)
{
	output_ps *output = (output_ps *)self->data;
	gboolean ret;

	ret = close_print_dest(output->to_file, output->fh);
	g_free(output);
	g_free(self);
	return ret;
}

static const print_stream_ops_t print_ps_ops = {
	print_preamble_ps,
	print_line_ps,
	print_bookmark_ps,
	new_page_ps,
	print_finale_ps,
	destroy_ps
};

static print_stream_t *
print_stream_ps_alloc(int to_file, FILE *fh)
{
	print_stream_t *stream;
	output_ps *output;

	output = (output_ps *)g_malloc(sizeof *output);
	output->to_file = to_file;
	output->fh = fh;
	stream = (print_stream_t *)g_malloc(sizeof (print_stream_t));
	stream->ops = &print_ps_ops;
	stream->data = output;

	return stream;
}

print_stream_t *
print_stream_ps_new(int to_file, const char *dest)
{
	FILE *fh;

	fh = open_print_dest(to_file, dest);
	if (fh == NULL)
		return NULL;

	return print_stream_ps_alloc(to_file, fh);
}

print_stream_t *
print_stream_ps_stdio_new(FILE *fh)
{
	return print_stream_ps_alloc(TRUE, fh);
}

output_fields_t* output_fields_new(void)
{
    output_fields_t* fields = g_new(output_fields_t, 1);
    fields->print_header = FALSE;
    fields->separator = '\t';
    fields->occurrence = 'a';
    fields->aggregator = ',';
    fields->fields = NULL; /*Do lazy initialisation */
    fields->field_indicies = NULL;
    fields->field_values = NULL;
    fields->quote='\0';
    return fields;
}

gsize output_fields_num_fields(output_fields_t* fields)
{
    g_assert(fields);

    if(NULL == fields->fields) {
        return 0;
    } else {
        return fields->fields->len;
    }
}

void output_fields_free(output_fields_t* fields)
{
    g_assert(fields);

    if(NULL != fields->field_indicies) {
        /* Keys are stored in fields->fields, values are
         * integers.
         */
        g_hash_table_destroy(fields->field_indicies);
    }
    if(NULL != fields->fields) {
        gsize i;
        for(i = 0; i < fields->fields->len; ++i) {
            gchar* field = (gchar *)g_ptr_array_index(fields->fields,i);
            g_free(field);
        }
        g_ptr_array_free(fields->fields, TRUE);
    }

    g_free(fields);
}

void output_fields_add(output_fields_t* fields, const gchar* field)
{
    gchar* field_copy;

    g_assert(fields);
    g_assert(field);


    if(NULL == fields->fields) {
        fields->fields = g_ptr_array_new();
    }

    field_copy = g_strdup(field);

    g_ptr_array_add(fields->fields, field_copy);
}

gboolean output_fields_set_option(output_fields_t* info, gchar* option)
{
    const gchar* option_name;
    const gchar* option_value;

    g_assert(info);
    g_assert(option);

    if('\0' == *option) {
        return FALSE; /* Is this guarded against by option parsing? */
    }
    option_name = strtok(option,"=");
    if (!option_name) {
        return FALSE;
    }
    option_value = option + strlen(option_name) + 1;
    if(0 == strcmp(option_name, "header")) {
        switch(NULL == option_value ? '\0' : *option_value) {
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

    if(0 == strcmp(option_name,"separator")) {
        switch(NULL == option_value ? '\0' : *option_value) {
        case '\0':
            return FALSE;
        case '/':
            switch(*++option_value) {
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

    if(0 == strcmp(option_name, "occurrence")) {
        switch(NULL == option_value ? '\0' : *option_value) {
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

    if(0 == strcmp(option_name,"aggregator")) {
        switch(NULL == option_value ? '\0' : *option_value) {
        case '\0':
            return FALSE;
        case '/':
            switch(*++option_value) {
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

    if(0 == strcmp(option_name, "quote")) {
        switch(NULL == option_value ? '\0' : *option_value) {
        default: /* Fall through */
        case '\0':
            info->quote='\0';
            return FALSE;
        case 'd':
            info->quote='"';
            break;
        case 's':
            info->quote='\'';
            break;
        case 'n':
            info->quote='\0';
            break;
        }
        return TRUE;
    }

    return FALSE;
}

void output_fields_list_options(FILE *fh)
{
    fprintf(fh, "TShark: The available options for field output \"E\" are:\n");
    fputs("header=y|n    Print field abbreviations as first line of output (def: N: no)\n", fh);
    fputs("separator=/t|/s|<character>   Set the separator to use;\n     \"/t\" = tab, \"/s\" = space (def: /t: tab)\n", fh);
    fputs("occurrence=f|l|a  Select the occurrence of a field to use;\n     \"f\" = first, \"l\" = last, \"a\" = all (def: a: all)\n", fh);
    fputs("aggregator=,|/s|<character>   Set the aggregator to use;\n     \",\" = comma, \"/s\" = space (def: ,: comma)\n", fh);
    fputs("quote=d|s|n   Print either d: double-quotes, s: single quotes or \n     n: no quotes around field values (def: n: none)\n", fh);
}


void write_fields_preamble(output_fields_t* fields, FILE *fh)
{
    gsize i;

    g_assert(fields);
    g_assert(fh);

    if(!fields->print_header) {
        return;
    }

    for(i = 0; i < fields->fields->len; ++i) {
        const gchar* field = (const gchar *)g_ptr_array_index(fields->fields,i);
        if(i != 0 ) {
            fputc(fields->separator, fh);
        }
    	fputs(field, fh);
    }
    fputc('\n', fh);
}

static void proto_tree_get_node_field_values(proto_node *node, gpointer data)
{
    write_field_data_t *call_data;
    field_info *fi;
    gpointer field_index;

    call_data = (write_field_data_t *)data;
    fi = PNODE_FINFO(node);

    g_assert(fi && "dissection with an invisible proto tree?");

    field_index = g_hash_table_lookup(call_data->fields->field_indicies, fi->hfinfo->abbrev);
    if(NULL != field_index) {
        const gchar* value;

        value = get_node_field_value(fi, call_data->edt); /* ep_alloced string */

        if(NULL != value && '\0' != *value) {
            guint actual_index;
            actual_index = GPOINTER_TO_UINT(field_index);
            /* Unwrap change made to disambiguiate zero / null */
            if ( call_data->fields->field_values[actual_index - 1] == NULL ) {
                call_data->fields->field_values[actual_index - 1] = ep_strbuf_new(value);
            } else if ( call_data->fields->occurrence == 'l' ) {
                /* print only the value of the last occurrence of the field */
                ep_strbuf_printf(call_data->fields->field_values[actual_index - 1],"%s",value);
            } else if ( call_data->fields->occurrence == 'a' ) {
                /* print the value of all accurrences of the field */
                ep_strbuf_append_printf(call_data->fields->field_values[actual_index - 1],
                    "%c%s",call_data->fields->aggregator,value);
            }
        }
    }

    /* Recurse here. */
    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, proto_tree_get_node_field_values,
                                    call_data);
    }
}

void proto_tree_write_fields(output_fields_t* fields, epan_dissect_t *edt, FILE *fh)
{
    gsize i;

    write_field_data_t data;

    g_assert(fields);
    g_assert(edt);
    g_assert(fh);

    data.fields = fields;
    data.edt = edt;

    if(NULL == fields->field_indicies) {
        /* Prepare a lookup table from string abbreviation for field to its index. */
        fields->field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

        i = 0;
        while( i < fields->fields->len) {
            gchar* field = (gchar *)g_ptr_array_index(fields->fields, i);
             /* Store field indicies +1 so that zero is not a valid value,
              * and can be distinguished from NULL as a pointer.
              */
            ++i;
            g_hash_table_insert(fields->field_indicies, field, GUINT_TO_POINTER(i));
        }
    }

    /* Buffer to store values for this packet */
    fields->field_values = ep_alloc_array0(emem_strbuf_t*, fields->fields->len);

    proto_tree_children_foreach(edt->tree, proto_tree_get_node_field_values,
                                &data);

    for(i = 0; i < fields->fields->len; ++i) {
        if(0 != i) {
            fputc(fields->separator, fh);
        }
        if(NULL != fields->field_values[i]) {
            if(fields->quote != '\0') {
                fputc(fields->quote, fh);
            }
            fputs(fields->field_values[i]->str, fh);
            if(fields->quote != '\0') {
                fputc(fields->quote, fh);
            }
        }
    }
}

void write_fields_finale(output_fields_t* fields _U_ , FILE *fh _U_)
{
    /* Nothing to do */
}

/* Returns an ep_alloced string or a static constant*/
const gchar* get_node_field_value(field_info* fi, epan_dissect_t* edt)
{
    if (fi->hfinfo->id == hf_text_only) {
        /* Text label.
         * Get the text */
        if (fi->rep) {
            return fi->rep->representation;
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
        size_t      chop_len;

        switch (fi->hfinfo->type)
        {
        case FT_PROTOCOL:
            /* Print out the full details for the protocol. */
            if (fi->rep) {
                return fi->rep->representation;
            } else {
                /* Just print out the protocol abbreviation */
                return fi->hfinfo->abbrev;;
            }
        case FT_NONE:
            /* Return "1" so that the presence of a field of type
             * FT_NONE can be checked when using -T fields */
            return "1";
        default:
            /* XXX - this is a hack until we can just call
             * fvalue_to_string_repr() for *all* FT_* types. */
            dfilter_string = proto_construct_match_selected_string(fi,
                edt);
            if (dfilter_string != NULL) {
                chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */

                /* XXX - Remove double-quotes. Again, once we
                 * can call fvalue_to_string_repr(), we can
                 * ask it not to produce the version for
                 * display-filters, and thus, no
                 * double-quotes. */
                if (dfilter_string[strlen(dfilter_string)-1] == '"') {
                    dfilter_string[strlen(dfilter_string)-1] = '\0';
                    chop_len++;
                }

                return &(dfilter_string[chop_len]);
            } else {
                return get_field_hex_value(edt->pi.data_src, fi);
            }
        }
    }
}

static const gchar*
get_field_hex_value(GSList* src_list, field_info *fi)
{
    const guint8 *pd;

    if (!fi->ds_tvb)
        return NULL;

    if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
        return "field length invalid!";
    }

    /* Find the data for this field. */
    pd = get_field_data(src_list, fi);

    if (pd) {
        int i;
        gchar* buffer;
        gchar* p;
        int len;
        const int chars_per_byte = 2;

        len = chars_per_byte * fi->length;
        buffer = ep_alloc_array(gchar, len + 1);
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
