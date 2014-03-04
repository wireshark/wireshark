/*
 * Copyright 2004-2013, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
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

#ifndef __SCTP_STAT_GTK_H__
#define __SCTP_STAT_GTK_H__

#include "ui/tap-sctp-analysis.h"

struct notes {
	GtkWidget   *checktype;
	GtkWidget   *checksum;
	GtkWidget   *bundling;
	GtkWidget   *padding;
	GtkWidget   *length;
	GtkWidget   *value;
	GtkWidget   *chunks_ep1;
	GtkWidget   *bytes_ep1;
	GtkWidget   *chunks_ep2;
	GtkWidget   *bytes_ep2;
	struct page *page2;
	struct page *page3;
};

struct page {
	GtkWidget *addr_frame;
	GtkWidget *scrolled_window;
	GtkWidget *clist;
	GtkWidget *port;
	GtkWidget *veritag;
	GtkWidget *max_in;
	GtkWidget *min_in;
	GtkWidget *max_out;
	GtkWidget *min_out;
};

struct sctp_analyse {
	sctp_assoc_info_t *assoc;
	GtkWidget*        window;
	struct notes      *analyse_nb;
	GList             *children;
	guint16           num_children;
};

typedef struct _sctp_graph_t {
	gboolean  needs_redraw;
	gfloat    x_interval;
	gfloat    y_interval;
	GtkWidget *window;
	GtkWidget *draw_area;
#if GTK_CHECK_VERSION(2,22,0)
	cairo_surface_t *surface;
#else
	GdkPixmap *pixmap;
#endif
	gint      surface_width;
	gint      surface_height;
	gint      graph_type;
	gdouble   x_old;
	gdouble   y_old;
	gdouble   x_new;
	gdouble   y_new;
	guint16   offset;
	guint16   length;
	gboolean  tmp;
	gboolean  rectangle;
	gboolean  rectangle_present;
	guint32   rect_x_min;
	guint32   rect_x_max;
	guint32   rect_y_min;
	guint32   rect_y_max;
	guint32   x1_tmp_sec;
	guint32   x2_tmp_sec;
	guint32   x1_tmp_usec;
	guint32   x2_tmp_usec;
	guint32   x1_akt_sec;
	guint32   x2_akt_sec;
	guint32   x1_akt_usec;
	guint32   x2_akt_usec;
	guint32   tmp_width;
	guint32   axis_width;
	guint32   y1_tmp;
	guint32   y2_tmp;
	guint32   tmp_min_tsn1;
	guint32   tmp_max_tsn1;
	guint32   tmp_min_tsn2;
	guint32   tmp_max_tsn2;
	guint32   min_x;
	guint32   max_x;
	guint32   min_y;
	guint32   max_y;
	gboolean  uoff;
} sctp_graph_t;

struct sctp_udata {
	sctp_assoc_info_t   *assoc;
	sctp_graph_t        *io;
	struct sctp_analyse *parent;
	guint16             dir;
};

void assoc_analyse(sctp_assoc_info_t* assoc);

void set_child(struct sctp_udata *child, struct sctp_analyse *parent);

void remove_child(struct sctp_udata *child, struct sctp_analyse *parent);

void decrease_analyse_childcount(void);

void increase_analyse_childcount(void);

void increase_childcount(struct sctp_analyse *parent);

void decrease_childcount(struct sctp_analyse *parent);

void set_analyse_child(struct sctp_analyse *child);

void remove_analyse_child(struct sctp_analyse *child);

void create_graph(guint16 dir, struct sctp_analyse* u_data);

void create_byte_graph(guint16 dir, struct sctp_analyse* u_data);

void sctp_error_dlg_show(sctp_assoc_info_t* assoc);

void sctp_stat_dlg_update(void);

void sctp_chunk_stat_dlg_update(struct sctp_udata* udata, unsigned int direction);

void sctp_chunk_dlg_show(struct sctp_analyse* userdata);

void sctp_chunk_stat_dlg_show(unsigned int direction, struct sctp_analyse* userdata);

GtkWidget *get_stat_dlg(void);

GtkWidget *get_chunk_stat_dlg(void);

void update_analyse_dlg(struct sctp_analyse* u_data);

void sctp_set_assoc_filter(void);

#endif
