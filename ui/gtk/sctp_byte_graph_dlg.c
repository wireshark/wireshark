/*
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

#include <gtk/gtk.h>

#include "epan/filesystem.h"
#include <epan/strutil.h>

#include "../globals.h"
#include "ui/ui_util.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/sctp_stat.h"

#include "ui/gtk/old-gtk-compat.h"

#define DEFAULT_PIXELS_PER_TICK 2
#define MAX_PIXELS_PER_TICK     4
#define AUTO_MAX_YSCALE         0
#define MAX_TICK_VALUES         5
#define DEFAULT_TICK_VALUE      3
#define MAX_YSCALE             22
#define MAX_COUNT_TYPES         3

#define COUNT_TYPE_FRAMES   0
#define COUNT_TYPE_BYTES    1
#define COUNT_TYPE_ADVANCED 2

#define LEFT_BORDER   80
#define RIGHT_BORDER  20
#define TOP_BORDER    20
#define BOTTOM_BORDER 50

#define SUB_32(a, b)	a-b

struct chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
};

struct data_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32  tsn;
	guint16 sid;
	guint16 ssn;
	guint32  ppi;
};

struct init_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32  initiate_tag;
	guint32  a_rwnd;
	guint16 mos;
	guint16 mis;
	guint32  initial_tsn;
};

struct sack_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32  cum_tsn_ack;
	guint32  a_rwnd;
	guint16 nr_of_gaps;
	guint16 nr_of_dups;
	guint8  *tsns;
};

struct gaps {
	guint16 start;
	guint16 end;
};

static gboolean label_set = FALSE;
static guint32 max_tsn=0, min_tsn=0;


static void sctp_graph_set_title(struct sctp_udata *u_data);
static void create_draw_area(GtkWidget *box, struct sctp_udata *u_data);
static GtkWidget *zoomout_bt;

static void draw_sack_graph(struct sctp_udata *u_data)
{
	GdkColor red_color = {0, 65535, 0, 0};
	GdkColor green_color = {0, 0, 65535, 0};
	gint diff;
	GPtrArray *array = NULL;
	guint32 i, size = 0, start=0, end;
	gboolean more = FALSE;
	gint width;
	cairo_t *cr;

	if (u_data->dir == 1)
	{
		array = u_data->assoc->sort_sack1;
		size=u_data->assoc->n_sack_chunks_ep1;
		if (u_data->io->tmp == FALSE)
		{
			min_tsn = 0;
			max_tsn = u_data->assoc->max_bytes1;
		}
		else
		{
			min_tsn = u_data->io->tmp_min_tsn1;
			max_tsn = u_data->io->tmp_max_tsn1;
		}
	}
	else if (u_data->dir == 2)
	{
		array = u_data->assoc->sort_sack2;
		size = u_data->assoc->n_sack_chunks_ep2;
		if (u_data->io->tmp == FALSE)
		{
			min_tsn = 0;
			max_tsn = u_data->assoc->max_bytes2;
		}
		else
		{
			min_tsn = u_data->io->tmp_min_tsn2;
			max_tsn = u_data->io->tmp_max_tsn2;
		}
	}

	width = u_data->io->max_x - u_data->io->min_x;

	for (i=0; i<size; i++)
	{
		if (u_data->io->uoff)
			diff = (gint)((struct tsn_sort*)(g_ptr_array_index(array,  i)))->secs - u_data->io->min_x;
		else
			diff = (gint)((struct tsn_sort*)(g_ptr_array_index(array,  i)))->secs * 1000000 + ((struct tsn_sort*)(g_ptr_array_index(array,  i)))->usecs - u_data->io->min_x;
		end = start + ((struct tsn_sort*)(g_ptr_array_index(array,  i)))->length;
		if (end>max_tsn)
		{
			end = max_tsn;
			more = TRUE;
		}

		if (start >= min_tsn && diff > 0 && diff <= width)
		{
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			gdk_cairo_set_source_color (cr, &red_color);
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,
				LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff+0.5,
				u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-((SUB_32(start,min_tsn))*u_data->io->y_interval)+0.5);
			cairo_line_to(cr,
				LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff+0.5,
				u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-((SUB_32(end,min_tsn))*u_data->io->y_interval)+0.5);
				cairo_stroke(cr);
				cairo_destroy(cr);			
			if (more == TRUE)
			{
#if GTK_CHECK_VERSION(2,22,0)
				cr = cairo_create (u_data->io->surface);
#else
				cr = gdk_cairo_create (u_data->io->pixmap);
#endif
				gdk_cairo_set_source_color (cr, &green_color);
				cairo_set_line_width (cr, 1.0);
				cairo_move_to(cr,
					LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff+0.5,
					u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-((SUB_32(end,min_tsn))*u_data->io->y_interval)+0.5);
				cairo_line_to(cr,
					LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff,
					u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-((SUB_32(end+10,min_tsn))*u_data->io->y_interval)+0.5);
				cairo_stroke(cr);
				cairo_destroy(cr);
				more = FALSE;
			}
		}

	}
}


static void draw_tsn_graph(struct sctp_udata *u_data)
{
GPtrArray *array = NULL;
guint32 i, size = 0, start, end;
gint diff, width;
cairo_t *cr;

	if (u_data->dir == 1)
	{
		array = u_data->assoc->sort_tsn1;
		size = u_data->assoc->n_data_chunks_ep1;
		if (u_data->io->tmp == FALSE)
		{
			min_tsn = 0;
			max_tsn = u_data->assoc->max_bytes1;
		}
		else
		{
			min_tsn = u_data->io->tmp_min_tsn1;
			max_tsn = u_data->io->tmp_max_tsn1;
		}
	}
	else if (u_data->dir == 2)
	{
		array = u_data->assoc->sort_tsn2;
		size  = u_data->assoc->n_data_chunks_ep2;
		if (u_data->io->tmp == FALSE)
		{
			min_tsn = 0;
			max_tsn = u_data->assoc->max_bytes2;
		}
		else
		{
			min_tsn = u_data->io->tmp_min_tsn2;
			max_tsn = u_data->io->tmp_max_tsn2;
		}
	}
	width = u_data->io->max_x - u_data->io->min_x;

	for (i=0; i<size; i++)
	{
		if (u_data->io->uoff)
			diff = (gint)((struct tsn_sort*)(g_ptr_array_index(array, i)))->secs -u_data->io->min_x;
		else
			diff = (gint)((struct tsn_sort*)(g_ptr_array_index(array, i)))->secs*1000000 + ((struct tsn_sort*)(g_ptr_array_index(array, i)))->usecs-u_data->io->min_x;
		start = ((struct tsn_sort*)(g_ptr_array_index(array, i)))->offset;
		end = start + ((struct tsn_sort*)(g_ptr_array_index(array, i)))->length;
		if (start >= min_tsn && diff > 0 && diff <= width){
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,
				(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff)+0.5,
				(u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-((SUB_32(start,min_tsn))*u_data->io->y_interval))+0.5);
			cairo_line_to(cr,
				(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff)+0.5,
				(u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-((SUB_32(end,min_tsn))*u_data->io->y_interval))+0.5);
			cairo_stroke(cr);
			cairo_destroy(cr);
		}
	}

}


static void sctp_graph_draw(struct sctp_udata *u_data)
{
	int length, lwidth;
	guint32 distance=5, i, e, sec, w, start, a, j, b;
	gint label_width, label_height;
	char label_string[15];
	gfloat dis;
	gboolean write_label = FALSE;
	PangoLayout  *layout;
	GtkAllocation widget_alloc;
	cairo_t *cr;

	if (u_data->io->x1_tmp_sec == 0 && u_data->io->x1_tmp_usec == 0)
		u_data->io->offset = 0;
	else
		u_data->io->offset = 5;

	if (u_data->io->x2_tmp_sec - u_data->io->x1_tmp_sec > 1500)
	{
		u_data->io->min_x=u_data->io->x1_tmp_sec;
		u_data->io->max_x=u_data->io->x2_tmp_sec;
		u_data->io->uoff = TRUE;
	}
	else
	{
		u_data->io->min_x=((guint32) (u_data->io->x1_tmp_sec*1000000.0))+u_data->io->x1_tmp_usec;
		u_data->io->max_x=((guint32) (u_data->io->x2_tmp_sec*1000000.0))+u_data->io->x2_tmp_usec;
		u_data->io->uoff = FALSE;
	}

	u_data->io->tmp_width = u_data->io->max_x - u_data->io->min_x;

	if (u_data->dir == 1)
	{
		if (u_data->io->tmp == FALSE)
		{
			if (u_data->assoc->sort_tsn1 != NULL)
				u_data->io->max_y = u_data->io->tmp_max_tsn1 - u_data->io->tmp_min_tsn1;
			else
				u_data->io->max_y = 0;
			u_data->io->min_y = 0;
		}
		else
		{
			u_data->io->max_y = u_data->io->tmp_max_tsn1;
			u_data->io->min_y = u_data->io->tmp_min_tsn1;
		}
	}
	else if (u_data->dir == 2)
	{
		if (u_data->io->tmp == FALSE)
		{
			if (u_data->assoc->tsn2 != NULL)
				u_data->io->max_y = u_data->io->tmp_max_tsn2 - u_data->io->tmp_min_tsn2;
			else
				u_data->io->max_y = 0;
			u_data->io->min_y = 0;
		}
		else
		{
			u_data->io->max_y = u_data->io->tmp_max_tsn2;
			u_data->io->min_y = u_data->io->tmp_min_tsn2;
		}
	}

#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (u_data->io->surface);
#else
	cr = gdk_cairo_create (u_data->io->pixmap);
#endif
	cairo_set_source_rgb (cr, 1, 1, 1);
	gtk_widget_get_allocation(u_data->io->draw_area, &widget_alloc);
	cairo_rectangle (cr,
		0,
		0,
		widget_alloc.width,
		widget_alloc.height);
	cairo_fill (cr);
	cairo_destroy (cr);

	/* x_axis */
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (u_data->io->surface);
#else
	cr = gdk_cairo_create (u_data->io->pixmap);
#endif
	cairo_set_line_width (cr, 1.0);
	cairo_move_to(cr, LEFT_BORDER+u_data->io->offset+0.5, u_data->io->surface_height - BOTTOM_BORDER+0.5);
	cairo_line_to(cr, u_data->io->surface_width - RIGHT_BORDER + u_data->io->offset+0.5, u_data->io->surface_height - BOTTOM_BORDER+0.5);

	cairo_move_to(cr, u_data->io->surface_width - RIGHT_BORDER + u_data->io->offset+0.5, u_data->io->surface_height - BOTTOM_BORDER+0.5);
	cairo_line_to(cr, u_data->io->surface_width - RIGHT_BORDER + u_data->io->offset - 5+0.5, u_data->io->surface_height - BOTTOM_BORDER - 5+0.5);

	cairo_move_to(cr, u_data->io->surface_width - RIGHT_BORDER + u_data->io->offset + 0.5, u_data->io->surface_height - BOTTOM_BORDER + 0.5);
	cairo_line_to(cr, u_data->io->surface_width - RIGHT_BORDER + u_data->io->offset - 5.5, u_data->io->surface_height - BOTTOM_BORDER + 5.5);
	cairo_stroke(cr);
	cairo_destroy(cr);
	
	u_data->io->axis_width = u_data->io->surface_width - LEFT_BORDER - RIGHT_BORDER - u_data->io->offset;

	if(u_data->io->tmp_width>0){
		u_data->io->x_interval = (float)((u_data->io->axis_width*1.0)/u_data->io->tmp_width); /*distance in pixels between 2 data points*/
	} else {
		u_data->io->x_interval = (float)(u_data->io->axis_width);
	}

	e=0;
	if (u_data->io->x_interval < 1)
	{
		dis = 1 / u_data->io->x_interval;
		while (dis >1)
		{
			dis /= 10;
			e++;
		}
		distance = 1;
			for (i=0; i<=e+1; i++)
			distance *= 10;
	}
	else
		distance = 5;

	g_snprintf(label_string, sizeof(label_string), "%d", 0);
	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
	layout = gtk_widget_create_pango_layout(u_data->io->draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);

	if (u_data->io->x1_tmp_usec == 0)
		sec = u_data->io->x1_tmp_sec;
	else
		sec = u_data->io->x1_tmp_sec+1;

	if (u_data->io->offset != 0)
	{
		g_snprintf(label_string, sizeof(label_string), "%u", u_data->io->x1_tmp_sec);
		memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
		pango_layout_set_text(layout, label_string, -1);
		pango_layout_get_pixel_size(layout, &lwidth, NULL);

#if GTK_CHECK_VERSION(2,22,0)
		cr = cairo_create (u_data->io->surface);
#else
		cr = gdk_cairo_create (u_data->io->pixmap);
#endif
		cairo_move_to (cr, LEFT_BORDER - 25, u_data->io->surface_height - BOTTOM_BORDER + 20);
		pango_cairo_show_layout (cr, layout);
		cairo_destroy (cr);
		cr = NULL;

	}
	w = (guint32)(500 / (guint32)(distance * u_data->io->x_interval));
	if (w == 0)
		w = 1;
	if (w == 4 || w==3 || w==2)
	{
		w = 5;
		a = distance / 10;
		b = (guint32)((u_data->io->min_x/100000))%10; /* start for labels*/
	}
	else
	{
		a = distance / 5;
		b = 0;
	}

	if (!u_data->io->uoff)
	{
		if (a>=1000000)
		{
			start=u_data->io->min_x/1000000*1000000;
			if (a==1000000)
				b = 0;
		}
		else
		{
			start=u_data->io->min_x/100000;
			if (start%2!=0)
				start--;
			start*=100000;
			b = (guint32)((start/100000))%10;
		}
	}
	else
	{
		start = u_data->io->min_x;
		if (start%2!=0)
			start--;
		b = 0;

	}

	for (i=start, j=b; i<=u_data->io->max_x; i+=a, j++)
	{
		if (!u_data->io->uoff)
		if (i >= u_data->io->min_x && i % 1000000 != 0)
		{
			length = 5;
			g_snprintf(label_string, sizeof(label_string), "%d", i%1000000);

			if (j % w == 0)
			{
				length = 10;

				memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
				pango_layout_set_text(layout, label_string, -1);
				pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
				cr = cairo_create (u_data->io->surface);
#else
				cr = gdk_cairo_create (u_data->io->pixmap);
#endif
				cairo_move_to (cr,
					LEFT_BORDER + u_data->io->offset + (i - u_data->io->min_x) * u_data->io->x_interval - lwidth / 2,
					u_data->io->surface_height - BOTTOM_BORDER + 10);
				pango_cairo_show_layout (cr, layout);
				cairo_destroy (cr);
				cr = NULL;
			}
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,
				LEFT_BORDER + u_data->io->offset + (i - u_data->io->min_x) * u_data->io->x_interval + 0.5,
				u_data->io->surface_height - BOTTOM_BORDER + 0.5);
			cairo_line_to(cr,
				LEFT_BORDER + u_data->io->offset + (i - u_data->io->min_x) * u_data->io->x_interval + 0.5,
				u_data->io->surface_height - BOTTOM_BORDER + length + 0.5);
			cairo_stroke(cr);
			cairo_destroy(cr);
		}

		if (!u_data->io->uoff)
		{
			if (i%1000000==0 && j%w==0)
			{
				sec=i/1000000;
				write_label = TRUE;
			}
		}
		else
		{
			if (j%w == 0)
			{
				sec = i;
				write_label = TRUE;
			}
		}
		if (write_label)
		{
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,
				LEFT_BORDER + u_data->io->offset + (i - u_data->io->min_x) * u_data->io->x_interval + 0.5,
				u_data->io->surface_height - BOTTOM_BORDER + 0.5);
			cairo_line_to(cr,
				LEFT_BORDER + u_data->io->offset + (i - u_data->io->min_x) * u_data->io->x_interval + 0.5,
				u_data->io->surface_height - BOTTOM_BORDER + 10 + 0.5);
			cairo_stroke(cr);
			cairo_destroy(cr);

			g_snprintf(label_string, sizeof(label_string), "%d", sec);
			memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_move_to (cr,
				(LEFT_BORDER + u_data->io->offset + (i - u_data->io->min_x) * u_data->io->x_interval-10),
				u_data->io->surface_height - BOTTOM_BORDER + 20);
			pango_cairo_show_layout (cr, layout);
			cairo_destroy (cr);
			cr = NULL;

			write_label = FALSE;
		}
	}

	g_strlcpy(label_string, "sec", sizeof(label_string));

	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (u_data->io->surface);
#else
	cr = gdk_cairo_create (u_data->io->pixmap);
#endif
	cairo_move_to (cr,
		u_data->io->surface_width - RIGHT_BORDER - 10,
		u_data->io->surface_height - BOTTOM_BORDER + 30);
	pango_cairo_show_layout (cr, layout);
	cairo_destroy (cr);
	cr = NULL;

	distance = 5;

	/* y-axis */
#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (u_data->io->surface);
#else
	cr = gdk_cairo_create (u_data->io->pixmap);
#endif
	cairo_set_line_width (cr, 1.0);
	cairo_move_to(cr, LEFT_BORDER + 0.5, TOP_BORDER - u_data->io->offset + 0.5);
	cairo_line_to(cr, LEFT_BORDER + 0.5, u_data->io->surface_height - BOTTOM_BORDER - u_data->io->offset + 0.5);

	cairo_move_to(cr, LEFT_BORDER + 0.5, TOP_BORDER - u_data->io->offset + 0.5);
	cairo_line_to(cr, LEFT_BORDER - 5 + 0.5, TOP_BORDER - u_data->io->offset + 5 + 0.5);

	cairo_move_to(cr, LEFT_BORDER + 0.5, TOP_BORDER - u_data->io->offset + 0.5);
	cairo_line_to(cr, LEFT_BORDER +5 + 0.5, TOP_BORDER - u_data->io->offset + 5 + 0.5);
	cairo_stroke(cr);
	cairo_destroy(cr);

	u_data->io->y_interval = (float)(((u_data->io->surface_height - TOP_BORDER - BOTTOM_BORDER) * 1.0)/(u_data->io->max_y - u_data->io->min_y));

	e = 0;
	if (u_data->io->y_interval < 1)
	{
		dis = 1 / u_data->io->y_interval;
		while (dis > 1)
		{
			dis /= 10;
			e++;
		}
		distance = 1;
		for (i=0; i<=e; i++)
			distance = distance * 10;
	}
	else if (u_data->io->y_interval<2)
		distance = 10;

	if (u_data->io->max_y > 0)
	{
		for (i=u_data->io->min_y/distance*distance; i<=u_data->io->max_y; i+=distance/5)
		{
			if (i >= u_data->io->min_y)
			{
				length = 5;
				g_snprintf(label_string, sizeof(label_string), "%d", i);

				if (i%distance == 0 || (distance <= 5 && u_data->io->y_interval > 10))
				{
					length = 10;

					memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
					pango_layout_set_text(layout, label_string, -1);
					pango_layout_get_pixel_size(layout, &lwidth, NULL);
#if GTK_CHECK_VERSION(2,22,0)
					cr = cairo_create (u_data->io->surface);
#else
					cr = gdk_cairo_create (u_data->io->pixmap);
#endif
					cairo_move_to (cr,
						LEFT_BORDER - length - lwidth - 5,
						u_data->io->surface_height - BOTTOM_BORDER - u_data->io->offset - (i - u_data->io->min_y) * u_data->io->y_interval - 3);
					pango_cairo_show_layout (cr, layout);
					cairo_destroy (cr);
					cr = NULL;
				}
#if GTK_CHECK_VERSION(2,22,0)
				cr = cairo_create (u_data->io->surface);
#else
				cr = gdk_cairo_create (u_data->io->pixmap);
#endif
				cairo_set_line_width (cr, 1.0);
				cairo_move_to(cr,
					LEFT_BORDER - length + 0.5,
					u_data->io->surface_height - BOTTOM_BORDER - u_data->io->offset - (i - u_data->io->min_y) * u_data->io->y_interval + 0.5);
				cairo_line_to(cr,
					LEFT_BORDER + 0.5,
					u_data->io->surface_height - BOTTOM_BORDER - u_data->io->offset - (i - u_data->io->min_y) * u_data->io->y_interval + 0.5);
				cairo_stroke(cr);
				cairo_destroy(cr);
			}
		}
	}
	else
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "No Data Chunks sent");

	g_object_unref(G_OBJECT(layout));
}


static void sctp_graph_redraw(struct sctp_udata *u_data)
{
	sctp_graph_t *ios;
	GtkAllocation widget_alloc;
	cairo_t *cr;

	u_data->io->needs_redraw = TRUE;

	sctp_graph_draw(u_data);
	switch (u_data->io->graph_type)
	{
		case 0:
			draw_sack_graph(u_data);
			draw_tsn_graph(u_data);
			break;
		case 1:
			draw_tsn_graph(u_data);
			break;
		case 2:
			draw_sack_graph(u_data);
			break;
	}

	ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");
	g_assert(ios != NULL);

	cr = gdk_cairo_create (gtk_widget_get_window(u_data->io->draw_area));

#if GTK_CHECK_VERSION(2,22,0)
	cairo_set_source_surface (cr, ios->surface, 0, 0);
#else
	gdk_cairo_set_source_pixmap (cr, ios->pixmap, 0, 0);
#endif
	gtk_widget_get_allocation(u_data->io->draw_area, &widget_alloc);
	cairo_rectangle (cr, 0, 0, widget_alloc.width, widget_alloc.height);
	cairo_fill (cr);

	cairo_destroy (cr);
}


static void on_sack_bt(GtkWidget *widget _U_, struct sctp_udata *u_data)
{
	u_data = (struct sctp_udata *) u_data;
	u_data->io->graph_type = 2;
	sctp_graph_redraw(u_data);
}

static void on_tsn_bt(GtkWidget *widget _U_, struct sctp_udata *u_data)
{
	u_data->io->graph_type = 1;
	sctp_graph_redraw(u_data);
}

static void on_both_bt(GtkWidget *widget _U_, struct sctp_udata *u_data)
{
	u_data->io->graph_type = 0;
	sctp_graph_redraw(u_data);
}

static void
sctp_graph_close_cb(GtkWidget* widget _U_, gpointer u_data)
{
	struct sctp_udata *udata;

	udata = (struct sctp_udata *)u_data;
	gtk_grab_remove(GTK_WIDGET(udata->io->window));
	gtk_widget_destroy(GTK_WIDGET(udata->io->window));
}



static gboolean
on_configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
	GtkAllocation widget_alloc;
	cairo_t *cr;

	g_assert(u_data->io != NULL);

#if GTK_CHECK_VERSION(2,22,0)
	if(u_data->io->surface){
		cairo_surface_destroy (u_data->io->surface);
		u_data->io->surface=NULL;
	}
	gtk_widget_get_allocation(widget, &widget_alloc);
	u_data->io->surface = gdk_window_create_similar_surface (gtk_widget_get_window(widget),
			CAIRO_CONTENT_COLOR,
			widget_alloc.width,
			widget_alloc.height);
#else
	if(u_data->io->pixmap){
		g_object_unref(u_data->io->pixmap);
		u_data->io->pixmap = NULL;
	}
	gtk_widget_get_allocation(widget, &widget_alloc);
	u_data->io->pixmap = gdk_pixmap_new(gtk_widget_get_window(widget),
	                                    widget_alloc.width,
	                                    widget_alloc.height,
	                                    -1);
#endif
	u_data->io->surface_width = widget_alloc.width;
	u_data->io->surface_height = widget_alloc.height;

#if GTK_CHECK_VERSION(2,22,0)
	cr = cairo_create (u_data->io->surface);
#else
	cr = gdk_cairo_create (u_data->io->pixmap);
#endif
	cairo_rectangle (cr, 0, 0, widget_alloc.width, widget_alloc.height);
	cairo_set_source_rgb (cr, 1, 1, 1);
	cairo_fill (cr);
	cairo_destroy (cr);

	sctp_graph_redraw(u_data);
	return TRUE;
}

#if GTK_CHECK_VERSION(3,0,0)
static gboolean
on_draw_area_draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
	sctp_graph_t *ios = user_data;
	GtkAllocation allocation;

	gtk_widget_get_allocation (widget, &allocation);
	cairo_set_source_surface (cr, ios->surface, 0, 0);
	cairo_rectangle (cr, 0, 0, allocation.width, allocation.width);
	cairo_fill (cr);

	return FALSE;
}
#else
static gboolean
on_expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer user_data)
{
	sctp_graph_t *ios = user_data;
	cairo_t *cr;

	g_assert(ios != NULL);

	cr = gdk_cairo_create (gtk_widget_get_window(widget));

#if GTK_CHECK_VERSION(2,22,0)
	cairo_set_source_surface (cr, ios->surface, 0, 0);
#else
	gdk_cairo_set_source_pixmap (cr, ios->pixmap, 0, 0);
#endif
	cairo_rectangle (cr, event->area.x, event->area.y, event->area.width, event->area.height);
	cairo_fill (cr);

	cairo_destroy (cr);

	return FALSE;
}
#endif

static void
on_zoomin_bt (GtkWidget *widget _U_, struct sctp_udata *u_data)
{
	sctp_min_max_t *tmp_minmax;

	if (u_data->io->rectangle==TRUE)
	{
		tmp_minmax = g_malloc(sizeof(sctp_min_max_t));

		u_data->io->tmp_min_tsn1=u_data->io->y1_tmp+u_data->io->min_y;
		u_data->io->tmp_max_tsn1=u_data->io->y2_tmp+1+u_data->io->min_y;

		u_data->io->tmp_min_tsn2=u_data->io->tmp_min_tsn1;
		u_data->io->tmp_max_tsn2=u_data->io->tmp_max_tsn1;
		tmp_minmax->tmp_min_secs=u_data->io->x1_tmp_sec;
		tmp_minmax->tmp_min_usecs=	u_data->io->x1_tmp_usec;
		tmp_minmax->tmp_max_secs=	u_data->io->x2_tmp_sec;
		tmp_minmax->tmp_max_usecs=	u_data->io->x2_tmp_usec;
		tmp_minmax->tmp_min_tsn1=u_data->io->tmp_min_tsn1;
		tmp_minmax->tmp_max_tsn1=u_data->io->tmp_max_tsn1;
		tmp_minmax->tmp_min_tsn2=u_data->io->tmp_min_tsn2;
		tmp_minmax->tmp_max_tsn2=u_data->io->tmp_max_tsn2;
		u_data->assoc->min_max = g_slist_prepend(u_data->assoc->min_max, tmp_minmax);
		u_data->io->length = g_slist_length(u_data->assoc->min_max);
		u_data->io->tmp=TRUE;
		u_data->io->rectangle=FALSE;
		gtk_widget_set_sensitive(zoomout_bt, TRUE);
		sctp_graph_redraw(u_data);
	}
	else
	{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Please draw a rectangle around the area you want to zoom in!");
	}
}

static void
zoomin_bt_fcn (struct sctp_udata *u_data)
{
	sctp_min_max_t *tmp_minmax;

	tmp_minmax = g_malloc(sizeof(sctp_min_max_t));

	u_data->io->tmp_min_tsn1=u_data->io->y1_tmp+u_data->io->min_y;
	u_data->io->tmp_max_tsn1=u_data->io->y2_tmp+1+u_data->io->min_y;

	u_data->io->tmp_min_tsn2=u_data->io->tmp_min_tsn1;
	u_data->io->tmp_max_tsn2=u_data->io->tmp_max_tsn1;
	tmp_minmax->tmp_min_secs=u_data->io->x1_tmp_sec;
	tmp_minmax->tmp_min_usecs=u_data->io->x1_tmp_usec;
	tmp_minmax->tmp_max_secs=u_data->io->x2_tmp_sec;
	tmp_minmax->tmp_max_usecs=u_data->io->x2_tmp_usec;
	tmp_minmax->tmp_min_tsn1=u_data->io->tmp_min_tsn1;
	tmp_minmax->tmp_max_tsn1=u_data->io->tmp_max_tsn1;
	tmp_minmax->tmp_min_tsn2=u_data->io->tmp_min_tsn2;
	tmp_minmax->tmp_max_tsn2=u_data->io->tmp_max_tsn2;
	u_data->assoc->min_max = g_slist_prepend(u_data->assoc->min_max, tmp_minmax);
	u_data->io->length = g_slist_length(u_data->assoc->min_max);
	u_data->io->tmp=TRUE;
	u_data->io->rectangle=FALSE;
	gtk_widget_set_sensitive(zoomout_bt, TRUE);
	sctp_graph_redraw(u_data);
}

static void
on_zoomout_bt (GtkWidget *widget _U_, struct sctp_udata *u_data)
{
	sctp_min_max_t *tmp_minmax, *mm;
	gint l;

	l = g_slist_length(u_data->assoc->min_max);

	if (u_data->assoc->min_max!=NULL)
	{
		mm=(sctp_min_max_t *)((u_data->assoc->min_max)->data);
		u_data->assoc->min_max=g_slist_remove(u_data->assoc->min_max, mm);
		g_free(mm);

		if (l>2)
		{
			tmp_minmax = (sctp_min_max_t *)u_data->assoc->min_max->data;
			u_data->io->x1_tmp_sec=tmp_minmax->tmp_min_secs;
			u_data->io->x1_tmp_usec=tmp_minmax->tmp_min_usecs;
			u_data->io->x2_tmp_sec=tmp_minmax->tmp_max_secs;
			u_data->io->x2_tmp_usec=tmp_minmax->tmp_max_usecs;
			u_data->io->tmp_min_tsn1=tmp_minmax->tmp_min_tsn1;
			u_data->io->tmp_max_tsn1=tmp_minmax->tmp_max_tsn1;
			u_data->io->tmp_min_tsn2=tmp_minmax->tmp_min_tsn2;
			u_data->io->tmp_max_tsn2=tmp_minmax->tmp_max_tsn2;
			u_data->io->tmp=TRUE;
		}
		else
		{
			u_data->io->x1_tmp_sec=u_data->assoc->min_secs;
			u_data->io->x1_tmp_usec=u_data->assoc->min_usecs;
			u_data->io->x2_tmp_sec=u_data->assoc->max_secs;
			u_data->io->x2_tmp_usec=u_data->assoc->max_usecs;
			u_data->io->tmp_min_tsn1=0;
			u_data->io->tmp_max_tsn1=u_data->assoc->max_bytes1;
			u_data->io->tmp_min_tsn2=0;
			u_data->io->tmp_max_tsn2=u_data->assoc->max_bytes2;
			u_data->io->tmp=FALSE;
		}
	}
	else
	{
		u_data->io->x1_tmp_sec=u_data->assoc->min_secs;
		u_data->io->x1_tmp_usec=u_data->assoc->min_usecs;
		u_data->io->x2_tmp_sec=u_data->assoc->max_secs;
		u_data->io->x2_tmp_usec=u_data->assoc->max_usecs;
		u_data->io->tmp_min_tsn1=0;
		u_data->io->tmp_max_tsn1=u_data->assoc->max_bytes1;
		u_data->io->tmp_min_tsn2=0;
		u_data->io->tmp_max_tsn2=u_data->assoc->max_bytes2;
		u_data->io->tmp=FALSE;
	}
	if (g_slist_length(u_data->assoc->min_max)==1)
		gtk_widget_set_sensitive(zoomout_bt, FALSE);
	sctp_graph_redraw(u_data);
}


static gboolean
on_button_press_event (GtkWidget *widget _U_, GdkEventButton *event, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
	sctp_graph_t *ios;
	cairo_t *cr;

	if (u_data->io->rectangle==TRUE)
	{
#if GTK_CHECK_VERSION(2,22,0)
		cr = cairo_create (u_data->io->surface);
#else
		cr = gdk_cairo_create (u_data->io->pixmap);
#endif
		cairo_rectangle (cr,
			floor(MIN(u_data->io->x_old,u_data->io->x_new)),
			floor(MIN(u_data->io->y_old,u_data->io->y_new)),
			abs((long)(u_data->io->x_new-u_data->io->x_old)),
			abs((long)(u_data->io->y_new-u_data->io->y_old)));
		cairo_set_source_rgb (cr, 1, 1, 1);
		cairo_stroke (cr);
		cairo_destroy (cr);


		ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");
		g_assert(ios != NULL);

		cr = gdk_cairo_create (gtk_widget_get_window(u_data->io->draw_area));

#if GTK_CHECK_VERSION(2,22,0)
		cairo_set_source_surface (cr, ios->surface, 0, 0);
#else
		gdk_cairo_set_source_pixmap (cr, ios->pixmap, 0, 0);
#endif
		cairo_rectangle (cr, 0, 0, abs((long)(u_data->io->x_new-u_data->io->x_old)), abs((long)(u_data->io->y_new-u_data->io->y_old)));
		cairo_fill (cr);

		cairo_destroy (cr);

		sctp_graph_redraw(u_data);
	}

	u_data->io->x_old=event->x;
	u_data->io->y_old=event->y;
	if (u_data->io->y_old>u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset)
		u_data->io->y_old=u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset;
	if (u_data->io->x_old<LEFT_BORDER+u_data->io->offset)
		u_data->io->x_old=LEFT_BORDER+u_data->io->offset;
	u_data->io->rectangle=FALSE;

	return TRUE;
}


static gboolean
on_button_release_event (GtkWidget *widget _U_, GdkEventButton *event, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
	sctp_graph_t *ios;
	guint32 helpx, helpy, x1_tmp, x2_tmp, y_value;
	gint label_width, label_height;
	gdouble x_value, position, tfirst;
	gint lwidth;
	char label_string[30];
	GList *tsnlist=NULL;
	tsn_t *tsn, *tmptsn;
	PangoLayout  *layout;
	GtkAllocation widget_alloc;
	cairo_t *cr;

	g_snprintf(label_string, 15, "%d", 0);
	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
	layout = gtk_widget_create_pango_layout(u_data->io->draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);

	if (event->y > u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset)
		event->y = u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset;
	if (event->x < LEFT_BORDER+u_data->io->offset)
		event->x = LEFT_BORDER+u_data->io->offset;

	if (abs((long)(event->x-u_data->io->x_old))>10 || abs((long)(event->y-u_data->io->y_old))>10)
	{
		u_data->io->rect_x_min = (guint32) floor(MIN(u_data->io->x_old,event->x));
		u_data->io->rect_x_max = (guint32) ceil(MAX(u_data->io->x_old,event->x));
		u_data->io->rect_y_min = (guint32) floor(MIN(u_data->io->y_old,event->y));
		u_data->io->rect_y_max = (guint32) ceil(MAX(u_data->io->y_old,event->y));

#if GTK_CHECK_VERSION(2,22,0)
		cr = cairo_create (u_data->io->surface);
#else
		cr = gdk_cairo_create (u_data->io->pixmap);
#endif
		cairo_rectangle (cr,
			u_data->io->rect_x_min+0.5,
			u_data->io->rect_y_min+0.5,
			u_data->io->rect_x_max - u_data->io->rect_x_min,
			u_data->io->rect_y_max - u_data->io->rect_y_min);
		cairo_set_line_width (cr, 1.0);
		cairo_stroke (cr);
		cairo_destroy (cr);

		ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");
		g_assert(ios != NULL);

		cr = gdk_cairo_create (gtk_widget_get_window(u_data->io->draw_area));

#if GTK_CHECK_VERSION(2,22,0)
		cairo_set_source_surface (cr, ios->surface, 0, 0);
#else
		gdk_cairo_set_source_pixmap (cr, ios->pixmap, 0, 0);
#endif
		gtk_widget_get_allocation(u_data->io->draw_area, &widget_alloc);
		cairo_rectangle (cr, 0, 0, widget_alloc.width, widget_alloc.height);
		cairo_fill (cr);

		cairo_destroy (cr);

		x1_tmp=(guint32) floor(u_data->io->min_x+((u_data->io->x_old-LEFT_BORDER-u_data->io->offset)*u_data->io->tmp_width/u_data->io->axis_width));
		x2_tmp=(guint32) floor(u_data->io->min_x+((event->x-LEFT_BORDER-u_data->io->offset)*u_data->io->tmp_width/u_data->io->axis_width));
		helpx=MIN(x1_tmp, x2_tmp);
		if (helpx==x2_tmp)
		{
			x2_tmp=x1_tmp;
			x1_tmp=helpx;
		}
		if (u_data->io->uoff)
		{
			if (x2_tmp - x1_tmp <= 1500)
				u_data->io->uoff = FALSE;
			u_data->io->x1_tmp_sec=(guint32)x1_tmp;
			u_data->io->x1_tmp_usec=0;
			u_data->io->x2_tmp_sec=(guint32)x2_tmp;
			u_data->io->x2_tmp_usec=0;
		}
		else
		{
			u_data->io->x1_tmp_sec=(guint32)x1_tmp/1000000;
			u_data->io->x1_tmp_usec=x1_tmp%1000000;
			u_data->io->x2_tmp_sec=(guint32)x2_tmp/1000000;
			u_data->io->x2_tmp_usec=x2_tmp%1000000;
		}
		u_data->io->x1_akt_sec = u_data->io->x1_tmp_sec;
		u_data->io->x1_akt_usec = u_data->io->x1_tmp_usec;
		u_data->io->x2_akt_sec = u_data->io->x2_tmp_sec;
		u_data->io->x2_akt_usec = u_data->io->x2_tmp_usec;

		u_data->io->y1_tmp=(guint32)((u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-u_data->io->y_old)/u_data->io->y_interval);
		u_data->io->y2_tmp=(guint32)((u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-event->y)/u_data->io->y_interval);
		helpy = MIN(u_data->io->y1_tmp, u_data->io->y2_tmp);
		u_data->io->y2_tmp = MAX(u_data->io->y1_tmp, u_data->io->y2_tmp);
		u_data->io->y1_tmp = helpy;
		u_data->io->x_new=event->x;
		u_data->io->y_new=event->y;
		u_data->io->rectangle=TRUE;
		u_data->io->rectangle_present=TRUE;
	}
		else
	{
		if (u_data->io->rectangle_present==TRUE)
		{
			u_data->io->rectangle_present=FALSE;
			if (event->x >= u_data->io->rect_x_min && event->x <= u_data->io->rect_x_max &&
			     event->y >= u_data->io->rect_y_min && event->y <= u_data->io->rect_y_max)
				zoomin_bt_fcn(u_data);
			else
			{
				u_data->io->x1_tmp_sec = u_data->io->x1_akt_sec;
				u_data->io->x1_tmp_usec = u_data->io->x1_akt_usec;
				u_data->io->x2_tmp_sec = u_data->io->x2_akt_sec;
				u_data->io->x2_tmp_usec = u_data->io->x2_akt_usec;
				sctp_graph_redraw(u_data);
			}
		}
		else if (label_set)
		{
			label_set = FALSE;
			sctp_graph_redraw(u_data);
		}
		else
		{
			x_value = ((event->x-LEFT_BORDER-u_data->io->offset) * ((u_data->io->x2_tmp_sec+u_data->io->x2_tmp_usec/1000000.0)-(u_data->io->x1_tmp_sec+u_data->io->x1_tmp_usec/1000000.0)) / (u_data->io->surface_width-LEFT_BORDER-RIGHT_BORDER-u_data->io->offset))+u_data->io->x1_tmp_sec+u_data->io->x1_tmp_usec/1000000.0;
			y_value = (guint32) floor((u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset-event->y) * (max_tsn - min_tsn) / (u_data->io->surface_height-BOTTOM_BORDER-u_data->io->offset)) + min_tsn;

			if (u_data->dir == 1)
				tsnlist = g_list_last(u_data->assoc->tsn1);
			else
				tsnlist = g_list_last(u_data->assoc->tsn2);

			tsn = (tsn_t*) (tsnlist->data);
			tmptsn =(tsn_t*)(tsnlist->data);
			tfirst = tsn->secs + tsn->usecs/1000000.0;

			while (tsnlist)
			{
				tsnlist = g_list_previous(tsnlist);
				tsn = (tsn_t*) (tsnlist->data);
				if (tsn->secs+tsn->usecs/1000000.0<x_value)
				{
					tfirst = tsn->secs+tsn->usecs/1000000.0;
					tmptsn =tsn;
				}
				else
				{
					if ((tfirst+tsn->secs+tsn->usecs/1000000.0)/2.0<x_value)
					{
						x_value = tsn->secs+tsn->usecs/1000000.0;
						tmptsn = tsn;
					}
					else
						x_value = tmptsn->secs+tmptsn->usecs/1000000.0;
					break;
				}
			}
			cf_goto_frame(&cfile, tmptsn->frame_number);
			g_snprintf(label_string, sizeof(label_string), "(%.6f, %u)", x_value, y_value);
			label_set = TRUE;

#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,
				(event->x-2)+0.5,
				(event->y)+0.5);
			cairo_line_to(cr,
				(event->x+2)+0.5,
				(event->y)+0.5);
			cairo_stroke(cr);
			cairo_destroy(cr);

#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,
				(event->x)+0.5,
				(event->y-2)+0.5);
			cairo_line_to(cr,
				(event->x)+0.5,
				(event->y+2)+0.5);
			cairo_stroke(cr);
			cairo_destroy(cr);
			if (event->x+150>=u_data->io->surface_width)
				position = event->x - 150;
			else
				position = event->x + 5;

			memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);

#if GTK_CHECK_VERSION(2,22,0)
			cr = cairo_create (u_data->io->surface);
#else
			cr = gdk_cairo_create (u_data->io->pixmap);
#endif
			cairo_move_to (cr,
				position,
				event->y-10);
			pango_cairo_show_layout (cr, layout);
			cairo_destroy (cr);
			cr = NULL;

			ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");
			g_assert(ios != NULL);

			cr = gdk_cairo_create (gtk_widget_get_window(u_data->io->draw_area));

#if GTK_CHECK_VERSION(2,22,0)
			cairo_set_source_surface (cr, ios->surface, 0, 0);
#else
			gdk_cairo_set_source_pixmap (cr, ios->pixmap, 0, 0);
#endif
			gtk_widget_get_allocation(u_data->io->draw_area, &widget_alloc);
			cairo_rectangle (cr, 0, 0, widget_alloc.width, widget_alloc.height);
			cairo_fill (cr);

			cairo_destroy (cr);

		}
	}
	g_object_unref(G_OBJECT(layout));
	return TRUE;
}

static void init_sctp_graph_window(struct sctp_udata *u_data)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *bt_close, *sack_bt, *tsn_bt, *both_bt, *zoomin_bt;

	/* create the main window */

	u_data->io->window = dlg_window_new("SCTP Graphics");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(u_data->io->window), TRUE);

	vbox=ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
	gtk_container_add(GTK_CONTAINER(u_data->io->window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(vbox, u_data);

	sctp_graph_set_title(u_data);

	hbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbox), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing(GTK_BOX (hbox), 0);
	gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	sack_bt = gtk_button_new_with_label ("Adv. Rec. Window");
	gtk_box_pack_start(GTK_BOX(hbox), sack_bt, FALSE, FALSE, 0);
	gtk_widget_show(sack_bt);

	g_signal_connect(sack_bt, "clicked", G_CALLBACK(on_sack_bt), u_data);

	tsn_bt = gtk_button_new_with_label ("Data bytes sent");
	gtk_box_pack_start(GTK_BOX(hbox), tsn_bt, FALSE, FALSE, 0);
	gtk_widget_show(tsn_bt);
	g_signal_connect(tsn_bt, "clicked", G_CALLBACK(on_tsn_bt), u_data);

	both_bt = gtk_button_new_with_label ("Show both");
	gtk_box_pack_start(GTK_BOX(hbox), both_bt, FALSE, FALSE, 0);
	gtk_widget_show(both_bt);
	g_signal_connect(both_bt, "clicked", G_CALLBACK(on_both_bt), u_data);

	zoomin_bt = gtk_button_new_with_label ("Zoom in");
	gtk_box_pack_start(GTK_BOX(hbox), zoomin_bt, FALSE, FALSE, 0);
	gtk_widget_show(zoomin_bt);
	g_signal_connect(zoomin_bt, "clicked", G_CALLBACK(on_zoomin_bt), u_data);
	gtk_widget_set_tooltip_text(zoomin_bt, "Zoom in the area you have selected");

	zoomout_bt = gtk_button_new_with_label ("Zoom out");
	gtk_box_pack_start(GTK_BOX(hbox), zoomout_bt, FALSE, FALSE, 0);
	gtk_widget_show(zoomout_bt);
	g_signal_connect(zoomout_bt, "clicked", G_CALLBACK(on_zoomout_bt), u_data);
	gtk_widget_set_tooltip_text(zoomout_bt, "Zoom out one step");
	gtk_widget_set_sensitive(zoomout_bt, FALSE);

	bt_close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_box_pack_start(GTK_BOX(hbox), bt_close, FALSE, FALSE, 0);
	gtk_widget_show(bt_close);
	g_signal_connect(bt_close, "clicked", G_CALLBACK(sctp_graph_close_cb), u_data);

	g_signal_connect(u_data->io->draw_area,"button_press_event",G_CALLBACK(on_button_press_event), u_data);
	g_signal_connect(u_data->io->draw_area,"button_release_event",G_CALLBACK(on_button_release_event), u_data);
	gtk_widget_set_events(u_data->io->draw_area, GDK_BUTTON_PRESS_MASK | GDK_BUTTON_RELEASE_MASK | GDK_EXPOSURE_MASK);
	/* dlg_set_cancel(u_data->io->window, bt_close); */

	gtk_widget_show(u_data->io->window);
}

static void sctp_graph_set_title(struct sctp_udata *u_data)
{
	char *display_name;
	char *title;

	if(!u_data->io->window)
	{
		return;
	}
	display_name = cf_get_display_name(&cfile);
	title = g_strdup_printf("SCTP Data and Adv.Rcv.Window over Time: %s Port1 %u Port2 %u Endpoint %u",
	                        display_name, u_data->parent->assoc->port1, u_data->parent->assoc->port2, u_data->dir);
	g_free(display_name);
	gtk_window_set_title(GTK_WINDOW(u_data->io->window), title);
	g_free(title);
}


static void
gtk_sctpgraph_init(struct sctp_udata *u_data)
{
	sctp_graph_t *io;
	sctp_min_max_t* tmp_minmax;

	io=g_malloc(sizeof(sctp_graph_t));
	io->needs_redraw=TRUE;
	io->x_interval=1000;
	io->window=NULL;
	io->draw_area=NULL;
#if GTK_CHECK_VERSION(2,22,0)
	io->surface=NULL;
#else
	io->pixmap=NULL;
#endif
	io->surface_width=800;
	io->surface_height=600;
	io->graph_type=0;
	u_data->io=io;


	u_data->io->x1_tmp_sec=u_data->assoc->min_secs;
	u_data->io->x1_tmp_usec=u_data->assoc->min_usecs;
	u_data->io->x2_tmp_sec=u_data->assoc->max_secs;
	u_data->io->x2_tmp_usec=u_data->assoc->max_usecs;
	u_data->io->tmp_min_tsn1=0;
	u_data->io->tmp_max_tsn1=u_data->assoc->max_bytes1;
	u_data->io->tmp_min_tsn2=0;
	u_data->io->tmp_max_tsn2=u_data->assoc->max_bytes2;
	u_data->io->tmp=FALSE;
	tmp_minmax = g_malloc(sizeof(sctp_min_max_t));
	tmp_minmax->tmp_min_secs = u_data->assoc->min_secs;
	tmp_minmax->tmp_min_usecs=u_data->assoc->min_usecs;
	tmp_minmax->tmp_max_secs=u_data->assoc->max_secs;
	tmp_minmax->tmp_max_usecs=u_data->assoc->max_usecs;
	tmp_minmax->tmp_min_tsn2=u_data->io->tmp_min_tsn2;
	tmp_minmax->tmp_min_tsn1=u_data->io->tmp_min_tsn1;
	tmp_minmax->tmp_max_tsn1=u_data->io->tmp_max_tsn1;
	tmp_minmax->tmp_max_tsn2=u_data->io->tmp_max_tsn2;
	u_data->assoc->min_max = g_slist_prepend(u_data->assoc->min_max, tmp_minmax);

	/* build the GUI */
	init_sctp_graph_window(u_data);
	sctp_graph_redraw(u_data);
}


static void
quit(GObject *object _U_, gpointer user_data)
{
	struct sctp_udata *u_data=user_data;

	decrease_childcount(u_data->parent);
	remove_child(u_data, u_data->parent);
	g_free(u_data->io);
	u_data->assoc->min_max = NULL;
	g_free(u_data);
}


static void create_draw_area(GtkWidget *box, struct sctp_udata *u_data)
{
	u_data->io->draw_area=gtk_drawing_area_new();
	g_object_set_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t", u_data->io);
	g_signal_connect(u_data->io->draw_area, "destroy", G_CALLBACK(quit), u_data);

	gtk_widget_set_size_request(u_data->io->draw_area, u_data->io->surface_width, u_data->io->surface_height);

	/* signals needed to handle backing pixmap */
#if GTK_CHECK_VERSION(3,0,0)
	g_signal_connect(u_data->io->draw_area, "draw", G_CALLBACK(on_draw_area_draw_event), u_data->io);
#else
	g_signal_connect(u_data->io->draw_area, "expose_event", G_CALLBACK(on_expose_event), u_data->io);
#endif
	g_signal_connect(u_data->io->draw_area, "configure_event", G_CALLBACK(on_configure_event), u_data);

	gtk_widget_show(u_data->io->draw_area);
	gtk_box_pack_start(GTK_BOX(box), u_data->io->draw_area, TRUE, TRUE, 0);
}

static void insertion(GPtrArray *array, guint32 N)
{
	guint32 i, j;
	guint32 v;
	struct tsn_sort *help=NULL;

	for (i=1; i<N; i++)
	{
		v = ((struct tsn_sort*)(g_ptr_array_index(array,i)))->tsnumber;
		j=i;
		while (j>=1 && ((struct tsn_sort*)(g_ptr_array_index(array, j-1)))->tsnumber > v)
		{
			help=g_ptr_array_index(array, j);
			g_ptr_array_index(array, j)=g_ptr_array_index(array, j-1);
			g_ptr_array_index(array, j-1)=help;
			j--;
		}
		((struct tsn_sort*)(g_ptr_array_index(array, j)))->tsnumber=v;
	}
}

static void set_arw_offsets(struct sctp_udata *u_data)
{
	GPtrArray *s_array=NULL, *t_array=NULL;
	guint32 i, j=0;

	if (u_data->dir==1 && u_data->assoc->n_sack_chunks_ep1>0)
	{
		s_array=u_data->assoc->sort_sack1;
		t_array=u_data->assoc->sort_tsn1;
		insertion(s_array,u_data->assoc->n_sack_chunks_ep1);

		for (i=0; i<u_data->assoc->n_sack_chunks_ep1; i++)
		{
			while (((struct tsn_sort*)(g_ptr_array_index(s_array, i)))->tsnumber > ((struct tsn_sort*)(g_ptr_array_index(t_array, j)))->tsnumber)
			{
				j++;
			}
			((struct tsn_sort*)(g_ptr_array_index(s_array,i)))->offset = ((struct tsn_sort*)(g_ptr_array_index(t_array, j)))->offset
			  + ((struct tsn_sort*)(g_ptr_array_index(t_array, j)))->length;
		}

		u_data->assoc->sort_sack1=s_array;
	}

	if (u_data->dir==2 && u_data->assoc->n_sack_chunks_ep2>0)
	{
		s_array=u_data->assoc->sort_sack2;
		t_array=u_data->assoc->sort_tsn2;
		insertion(s_array,u_data->assoc->n_sack_chunks_ep2);
		j=0;
		for (i=0; i<u_data->assoc->n_sack_chunks_ep2; i++)
		{
			while (((struct tsn_sort*)(g_ptr_array_index(s_array, i)))->tsnumber > ((struct tsn_sort*)(g_ptr_array_index(t_array,j)))->tsnumber)
			{
				j++;
			}
			((struct tsn_sort*)(g_ptr_array_index(s_array, i)))->offset = ((struct tsn_sort*)(g_ptr_array_index(t_array, j)))->offset
			 + ((struct tsn_sort*)(g_ptr_array_index(t_array, j)))->length;
		}
		u_data->assoc->sort_sack2=s_array;
	}
}

static void compute_offsets(struct sctp_udata *u_data)
{
	struct tsn_sort t_sort;
	GPtrArray *array=NULL;
	guint32 i;
	guint32 sum=0;
	guint32 tsntmp=0;

	if (u_data->dir==1 && u_data->assoc->n_array_tsn1>0)
	{
		array=u_data->assoc->sort_tsn1;
		insertion(array,u_data->assoc->n_array_tsn1);

		for (i=0; i<u_data->assoc->n_array_tsn1; i++)
		{
			((struct tsn_sort*)(g_ptr_array_index(array, i)))->offset=sum;
			t_sort.tsnumber=((struct tsn_sort*)(g_ptr_array_index(array, i)))->tsnumber;
			if (t_sort.tsnumber>tsntmp)
				sum+=((struct tsn_sort*)(g_ptr_array_index(array, i)))->length;
			tsntmp=t_sort.tsnumber;
		}
		u_data->assoc->max_bytes1= ((struct tsn_sort*)(g_ptr_array_index(array, i-1)))->offset + ((struct tsn_sort*)(g_ptr_array_index(array, i-1)))->length;
		u_data->assoc->sort_tsn1=array;
	}
	if (u_data->dir==2 && u_data->assoc->n_array_tsn2>0)
	{
		sum=0;
		array=u_data->assoc->sort_tsn2;
		insertion(array,u_data->assoc->n_array_tsn2);

		for (i=0; i<u_data->assoc->n_array_tsn2; i++)
		{
			((struct tsn_sort*)(g_ptr_array_index(array,i)))->offset=sum;
			t_sort.tsnumber=((struct tsn_sort*)(g_ptr_array_index(array, i)))->tsnumber;
			if (t_sort.tsnumber>tsntmp)
				sum+=((struct tsn_sort*)(g_ptr_array_index(array, i)))->length;
			tsntmp=t_sort.tsnumber;
		}

		u_data->assoc->max_bytes2= ((struct tsn_sort*)(g_ptr_array_index(array,  u_data->assoc->n_data_chunks_ep2-1)))->offset + ((struct tsn_sort*)(g_ptr_array_index(array,  u_data->assoc->n_data_chunks_ep2-1)))->length;
		u_data->assoc->sort_tsn2=array;
	}
}

void create_byte_graph(guint16 dir, struct sctp_analyse* userdata)
{
	struct sctp_udata *u_data;

	u_data=g_malloc(sizeof(struct sctp_udata));
	u_data->assoc=g_malloc(sizeof(sctp_assoc_info_t));
	u_data->assoc=userdata->assoc;
	u_data->io=NULL;
	u_data->dir = dir;
	u_data->parent = userdata;
	if ((u_data->dir==1 && (u_data->assoc->n_array_tsn1==0))|| (u_data->dir==2 && (u_data->assoc->n_array_tsn2==0)))
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "No Data Chunks sent");
	else
	{
		set_child(u_data, u_data->parent);
		increase_childcount(u_data->parent);
		compute_offsets(u_data);
		set_arw_offsets(u_data);
		gtk_sctpgraph_init(u_data);
	}

}

