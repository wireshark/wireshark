/* print.c
 * Routines for printing packet analysis trees.
 *
 * $Id: print.c,v 1.62 2003/12/03 09:28:19 guy Exp $
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/tvbuff.h>
#include <epan/packet.h>

#include "print.h"
#include "ps.h"
#include "util.h"
#include "packet-data.h"

static void proto_tree_print_node(GNode *node, gpointer data);
static void print_hex_data_buffer(FILE *fh, register const guchar *cp,
    register guint length, char_enc encoding, gint format);
static void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size);

typedef struct {
	int		level;
	FILE		*fh;
	GSList		*src_list;
	gboolean	print_all_levels;
	gboolean	print_hex_for_data;
	char_enc	encoding;
	gint		format;		/* text or PostScript */
} print_data;

FILE *open_print_dest(int to_file, const char *dest)
{
	FILE	*fh;

	/* Open the file or command for output */
	if (to_file)
		fh = fopen(dest, "w");
	else
		fh = popen(dest, "w");

	return fh;
}

void close_print_dest(int to_file, FILE *fh)
{
	/* Close the file or command */
	if (to_file)
		fclose(fh);
	else
		pclose(fh);
}

void proto_tree_print(print_args_t *print_args, epan_dissect_t *edt,
    FILE *fh)
{
	print_data data;

	/* Create the output */
	data.level = 0;
	data.fh = fh;
	data.src_list = edt->pi.data_src;
	data.encoding = edt->pi.fd->flags.encoding;
	data.print_all_levels = print_args->expand_all;
	data.print_hex_for_data = !print_args->print_hex;
	    /* If we're printing the entire packet in hex, don't
	       print uninterpreted data fields in hex as well. */
	data.format = print_args->format;

	g_node_children_foreach((GNode*) edt->tree, G_TRAVERSE_ALL,
		proto_tree_print_node, &data);
}

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it.
 */
static const guint8 *
get_field_data(GSList *src_list, field_info *fi)
{
	GSList *src_le;
	data_source *src;
	tvbuff_t *src_tvb;

	for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
		src = src_le->data;
		src_tvb = src->tvb;
		if (fi->ds_tvb == src_tvb) {
			/*
			 * Found it.
			 */
			return tvb_get_ptr(src_tvb, fi->start, fi->length);
		}
	}
	g_assert_not_reached();
	return NULL;	/* not found */
}

#define MAX_INDENT	160

#define MAX_PS_LINE_LENGTH 256

/* Print a tree's data, and any child nodes. */
static
void proto_tree_print_node(GNode *node, gpointer data)
{
	field_info	*fi = PITEM_FINFO(node);
	print_data	*pdata = (print_data*) data;
	const guint8	*pd;
	gchar		label_str[ITEM_LABEL_LENGTH];
	gchar		*label_ptr;

	/* Don't print invisible entries. */
	if (!fi->visible)
		return;

	/* was a free format label produced? */
	if (fi->rep) {
		label_ptr = fi->rep->representation;
	}
	else { /* no, make a generic label */
		label_ptr = label_str;
		proto_item_fill_label(fi, label_str);
	}

	print_line(pdata->fh, pdata->level, pdata->format, label_ptr);

	/* If it's uninterpreted data, dump it (unless our caller will
	   be printing the entire packet in hex). */
	if (fi->hfinfo->id == proto_data && pdata->print_hex_for_data) {
		/*
		 * Find the data for this field.
		 */
		pd = get_field_data(pdata->src_list, fi);
		print_hex_data_buffer(pdata->fh, pd, fi->length,
		    pdata->encoding, pdata->format);
	}

	/* If we're printing all levels, or if this node is one with a
	   subtree and its subtree is expanded, recurse into the subtree,
	   if it exists. */
	g_assert(fi->tree_type >= -1 && fi->tree_type < num_tree_types);
	if (pdata->print_all_levels ||
	    (fi->tree_type >= 0 && tree_is_expanded[fi->tree_type])) {
		if (g_node_n_children(node) > 0) {
			pdata->level++;
			g_node_children_foreach(node, G_TRAVERSE_ALL,
				proto_tree_print_node, pdata);
			pdata->level--;
		}
	}
}

void print_hex_data(FILE *fh, gint format, epan_dissect_t *edt)
{
	gboolean multiple_sources;
	GSList *src_le;
	data_source *src;
	tvbuff_t *tvb;
	char *name;
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
		src = src_le->data;
		tvb = src->tvb;
		if (multiple_sources) {
			name = src->name;
			print_line(fh, 0, format, "");
			line = g_malloc(strlen(name) + 2);	/* <name>:\0 */
			strcpy(line, name);
			strcat(line, ":");
			print_line(fh, 0, format, line);
			g_free(line);
		}
		length = tvb_length(tvb);
		cp = tvb_get_ptr(tvb, 0, length);
		print_hex_data_buffer(fh, cp, length,
		    edt->pi.fd->flags.encoding, format);
	}
}

/*
 * This routine is based on a routine created by Dan Lasley
 * <DLASLEY@PROMUS.com>.
 *
 * It was modified for Ethereal by Gilbert Ramirez and others.
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

static void
print_hex_data_buffer(FILE *fh, register const guchar *cp,
    register guint length, char_enc encoding, gint format)
{
	register unsigned int ad, i, j, k, l;
	guchar c;
	guchar line[MAX_LINE_LEN + 1];
	unsigned int use_digits;
	static guchar binhex[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	print_line(fh, 0, format, "");

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
			k = 0;
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
		if (encoding == CHAR_EBCDIC) {
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
			print_line(fh, 0, format, line);
			ad += 16;
		}
	}
}

static
void ps_clean_string(unsigned char *out, const unsigned char *in,
			int outbuf_size)
{
	int rd, wr;
	char c;

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

void print_preamble(FILE *fh, gint format)
{
	if (format == PR_FMT_PS)
		print_ps_preamble(fh);
}

void print_finale(FILE *fh, gint format)
{
	if (format == PR_FMT_PS)
		print_ps_finale(fh);
}

void print_line(FILE *fh, int indent, gint format, char *line)
{
	char		space[MAX_INDENT+1];
	int		i;
	int		num_spaces;
	char		psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

	if (format == PR_FMT_PS) {
		ps_clean_string(psbuffer, line, MAX_PS_LINE_LENGTH);
		fprintf(fh, "%d (%s) putline\n", indent, psbuffer);
	} else {
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

		fputs(space, fh);
		fputs(line, fh);
		putc('\n', fh);
	}
}
