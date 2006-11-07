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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif


#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "globals.h"
#include "epan/filesystem.h"
#include "../color.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "main.h"
#include "compat_macros.h"
#include "simple_dialog.h"
#include "sctp_stat.h"

#define DEFAULT_PIXELS_PER_TICK 2
#define MAX_PIXELS_PER_TICK 4
#define AUTO_MAX_YSCALE 0
#define MAX_TICK_VALUES 5
#define DEFAULT_TICK_VALUE 3
#define MAX_YSCALE 22
#define MAX_COUNT_TYPES 3

#define COUNT_TYPE_FRAMES   0
#define COUNT_TYPE_BYTES    1
#define COUNT_TYPE_ADVANCED 2

#define LEFT_BORDER 60
#define RIGHT_BORDER 10
#define TOP_BORDER 10
#define BOTTOM_BORDER 50

#define SUB_32(a, b)	a-b
#define POINT_SIZE	3

struct chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
};

struct data_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32 tsn;
	guint16 sid;
	guint16 ssn;
	guint32 ppi;
};

struct init_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32 initiate_tag;
	guint32 a_rwnd;
	guint16 mos;
	guint16 mis;
	guint32 initial_tsn;
};

struct sack_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32 cum_tsn_ack;
	guint32 a_rwnd;
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
	tsn_t	*sack;
	GList *list=NULL, *tlist;
	guint16 gap_start=0, gap_end=0, i, j, nr;
	guint8 type;
	guint32 tsnumber;
	gint xvalue, yvalue;
	GdkColor red_color = {0, 65535, 0, 0};
	GdkColor green_color = {0, 0, 65535, 0};
	GdkGC *red_gc, *green_gc;
	struct sack_chunk_header *sack_header;
	struct gaps *gap;
	guint32 max_num, diff;
#if GTK_MAJOR_VERSION < 2
	GdkColormap *colormap;
#endif

	red_gc = gdk_gc_new(u_data->io->draw_area->window);
#if GTK_MAJOR_VERSION < 2
		colormap = gtk_widget_get_colormap (u_data->io->draw_area);
		if (!gdk_color_alloc (colormap, &red_color))
		{
			g_warning ("Couldn't allocate color");
		}

		gdk_gc_set_foreground(red_gc, &red_color);
#else
		gdk_gc_set_rgb_fg_color(red_gc, &red_color);
#endif

	green_gc = gdk_gc_new(u_data->io->draw_area->window);
#if GTK_MAJOR_VERSION < 2
		colormap = gtk_widget_get_colormap (u_data->io->draw_area);
		if (!gdk_color_alloc (colormap, &green_color))
		{
			g_warning ("Couldn't allocate color");
		}

		gdk_gc_set_foreground(green_gc, &green_color);
#else
		gdk_gc_set_rgb_fg_color(green_gc, &green_color);
#endif

	if (u_data->dir==2)
	{

		list = g_list_last(u_data->assoc->sack2);
		if (u_data->io->tmp==FALSE)
		{
			min_tsn=u_data->assoc->min_tsn2;
			max_tsn=u_data->assoc->max_tsn2;
		}
		else
		{
			min_tsn=u_data->assoc->min_tsn2+u_data->io->tmp_min_tsn2;
			max_tsn=u_data->assoc->min_tsn2+u_data->io->tmp_max_tsn2;
		}
	}
	else if (u_data->dir==1)
	{
		list = g_list_last(u_data->assoc->sack1);
		if (u_data->io->tmp==FALSE)
		{
			min_tsn=u_data->assoc->min_tsn1;
			max_tsn=u_data->assoc->max_tsn1;
		}
		else
		{
			min_tsn=u_data->assoc->min_tsn1+u_data->io->tmp_min_tsn1;
			max_tsn=u_data->assoc->min_tsn1+u_data->io->tmp_max_tsn1;
		}
	}

	while (list)
	{
		sack = (tsn_t*) (list->data);
		tlist = g_list_first(sack->tsns);
		while (tlist)
		{
			type = ((struct chunk_header *)tlist->data)->type;

			if (type == SCTP_SACK_CHUNK_ID)
			{
				sack_header =(struct sack_chunk_header *)tlist->data;
				nr=ntohs(sack_header->nr_of_gaps);
				tsnumber = g_ntohl(sack_header->cum_tsn_ack);

				if (sack->secs>=u_data->io->x1_tmp_sec)
				{
					if (nr>0)
					{
						gap = (struct gaps *)(&(sack_header->tsns));
						for(i=0;i<nr; i++)
						{
							gap_start=ntohs(gap->start);
							gap_end = ntohs(gap->end);
							max_num=gap_end+tsnumber;
							for (j=gap_start; j<=gap_end; j++)
							{
								if (u_data->io->uoff)
									diff = sack->secs - u_data->io->min_x;
								else
									diff=sack->secs*1000000+sack->usecs-u_data->io->min_x;
								xvalue = (guint32)(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff);
								yvalue = (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-POINT_SIZE-u_data->io->offset-((SUB_32(j+tsnumber,min_tsn))*u_data->io->y_interval));
								if (xvalue >= LEFT_BORDER+u_data->io->offset &&
								    xvalue <= u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset &&
								    yvalue >= TOP_BORDER-u_data->io->offset &&
								    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
									gdk_draw_arc(u_data->io->pixmap,green_gc,TRUE,
								             	    xvalue,
								                    yvalue,
								             	    POINT_SIZE, POINT_SIZE,0, (64*360) );
							}
							if (i < nr-1)
								gap++;
						}
					}
					else
						max_num=tsnumber;
					if (tsnumber>=min_tsn)
					{
						if (u_data->io->uoff)
							diff = sack->secs - u_data->io->min_x;
						else
							diff=sack->secs*1000000+sack->usecs-u_data->io->min_x;
						xvalue = (guint32)(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff);
						yvalue = (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-POINT_SIZE -u_data->io->offset-((SUB_32(tsnumber,min_tsn))*u_data->io->y_interval));
						if (xvalue >= LEFT_BORDER+u_data->io->offset && 
						    xvalue <= u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset &&
						    yvalue >= TOP_BORDER-u_data->io->offset &&
						    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
							gdk_draw_arc(u_data->io->pixmap,red_gc,TRUE,
								     xvalue,
								     yvalue,
								     POINT_SIZE, POINT_SIZE,0, (64*360) );
					}
				}
			tlist = g_list_next(tlist);
			}
		}
		list = g_list_previous(list);
	}
#if GTK_MAJOR_VERSION >= 2
		g_object_unref(G_OBJECT(red_gc));
		g_object_unref(G_OBJECT(green_gc));
#endif
}


static void draw_tsn_graph(struct sctp_udata *u_data)
{
	tsn_t *tsn;
	GList *list=NULL, *tlist;
	guint8 type;
	guint32 tsnumber=0;
	guint32 min_secs=0, diff;
	gint xvalue, yvalue;

	if (u_data->dir==1)
	{
		list = g_list_last(u_data->assoc->tsn1);
		if (u_data->io->tmp==FALSE)
		{
			min_tsn=u_data->assoc->min_tsn1;
			max_tsn=u_data->assoc->max_tsn1;
		}
		else
		{
			min_tsn=u_data->assoc->min_tsn1+u_data->io->tmp_min_tsn1;
			max_tsn=u_data->assoc->min_tsn1+u_data->io->tmp_max_tsn1;
		}
	}
	else if (u_data->dir==2)
	{
		list = g_list_last(u_data->assoc->tsn2);
		if (u_data->io->tmp==FALSE)
		{
			min_tsn=u_data->assoc->min_tsn2;
			max_tsn=u_data->assoc->max_tsn2;
		}
		else
		{
			min_tsn=u_data->assoc->min_tsn2+u_data->io->tmp_min_tsn2;
			max_tsn=u_data->assoc->min_tsn2+u_data->io->tmp_max_tsn2;
		}
	}

	while (list)
	{
		tsn = (tsn_t*) (list->data);
		tlist = g_list_first(tsn->tsns);
		while (tlist)
		{
			type = ((struct chunk_header *)tlist->data)->type;
			if (type == SCTP_DATA_CHUNK_ID)
				tsnumber = g_ntohl(((struct data_chunk_header *)tlist->data)->tsn);
			if (tsnumber>=min_tsn && tsnumber<=max_tsn && tsn->secs>=min_secs)
			{
					if (u_data->io->uoff)
						diff = tsn->secs - u_data->io->min_x;
					else
						diff=tsn->secs*1000000+tsn->usecs-u_data->io->min_x;
					xvalue = (guint32)(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff);
					yvalue = (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-POINT_SIZE-u_data->io->offset-((SUB_32(tsnumber,min_tsn))*u_data->io->y_interval));
					if (xvalue >= LEFT_BORDER+u_data->io->offset && 
					    xvalue <= u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset &&
					    yvalue >= TOP_BORDER-u_data->io->offset &&
					    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
						gdk_draw_arc(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,TRUE,
							     xvalue,
							     yvalue,
							     POINT_SIZE, POINT_SIZE, 0, (64*360));
			}
			tlist = g_list_next(tlist);
		}
		list = g_list_previous(list);
	}
}


static void sctp_graph_draw(struct sctp_udata *u_data)
{
	int length, lwidth;
	guint32  distance=5, i, e, sec, w, start, a, b, j;
	gint label_width, label_height;
	char label_string[15];
	gfloat dis;
	gboolean write_label = FALSE;

#if GTK_MAJOR_VERSION < 2
	GdkFont *font;
#else
	PangoLayout  *layout;
#endif

	if (u_data->io->x1_tmp_sec==0 && u_data->io->x1_tmp_usec==0)
		u_data->io->offset=0;
	else
		u_data->io->offset=5;

	if (u_data->io->x2_tmp_sec - u_data->io->x1_tmp_sec > 1500)
	{
		u_data->io->min_x=u_data->io->x1_tmp_sec;
		u_data->io->max_x=u_data->io->x2_tmp_sec;
		u_data->io->uoff = TRUE;
	}
	else
	{
		u_data->io->min_x=u_data->io->x1_tmp_sec*1000000.0+u_data->io->x1_tmp_usec;
		u_data->io->max_x=u_data->io->x2_tmp_sec*1000000.0+u_data->io->x2_tmp_usec;		
		u_data->io->uoff = FALSE;
	}

	u_data->io->tmp_width=u_data->io->max_x-u_data->io->min_x;

	if (u_data->dir==1)
	{
		if (u_data->io->tmp==FALSE)
		{
			if (u_data->assoc->tsn1!=NULL || u_data->assoc->sack1!=NULL)
				u_data->io->max_y=u_data->io->tmp_max_tsn1 - u_data->io->tmp_min_tsn1;
			else
				u_data->io->max_y= 0;
			u_data->io->min_y = 0;
		}
		else
		{
			u_data->io->max_y = u_data->io->tmp_max_tsn1;
			u_data->io->min_y = u_data->io->tmp_min_tsn1;
		}
	}
	else if (u_data->dir==2)
	{
		if (u_data->io->tmp==FALSE)
		{
			if (u_data->assoc->tsn2!=NULL || u_data->assoc->sack2!=NULL)
					u_data->io->max_y=u_data->io->tmp_max_tsn2 -u_data->io->tmp_min_tsn2;
			else
				u_data->io->max_y= 0;
			u_data->io->min_y = 0;
		}
		else
		{
			u_data->io->max_y = u_data->io->tmp_max_tsn2;
			u_data->io->min_y = u_data->io->tmp_min_tsn2;
		}
	}

	gdk_draw_rectangle(u_data->io->pixmap,
	                   u_data->io->draw_area->style->white_gc,
	                   TRUE,
	                   0, 0,
	                   u_data->io->draw_area->allocation.width,
	                   u_data->io->draw_area->allocation.height);

	distance=5;
	/* x_axis */
	gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc, LEFT_BORDER+u_data->io->offset,u_data->io->pixmap_height-BOTTOM_BORDER,u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset, u_data->io->pixmap_height-BOTTOM_BORDER);
	gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset, u_data->io->pixmap_height-BOTTOM_BORDER, u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset-5, u_data->io->pixmap_height-BOTTOM_BORDER-5);
	gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset, u_data->io->pixmap_height-BOTTOM_BORDER, u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset-5, u_data->io->pixmap_height-BOTTOM_BORDER+5);
	u_data->io->axis_width=u_data->io->pixmap_width-LEFT_BORDER-RIGHT_BORDER-u_data->io->offset;

	/* try to avoid dividing by zero */
	if(u_data->io->tmp_width>0){
		u_data->io->x_interval = (float)((u_data->io->axis_width*1.0)/u_data->io->tmp_width); /*distance in pixels between 2 data points*/
	} else {
		u_data->io->x_interval = (float)(u_data->io->axis_width);
	}

	e=0; /*number of decimals of x_interval*/
	if (u_data->io->x_interval<1)
	{
		dis=1/u_data->io->x_interval;
		while (dis >1)
		{
			dis/=10;
			e++;
		}
		distance=1;
		for (i=0; i<=e+1; i++)
			distance*=10; /*distance per 100 pixels*/
	}
	else
		distance=5;

#if GTK_MAJOR_VERSION < 2
	font = u_data->io->draw_area->style->font;
#endif

#if GTK_MAJOR_VERSION < 2
	label_width=gdk_string_width(font, label_string);
	label_height=gdk_string_height(font, label_string);
#else
	g_snprintf(label_string, 15, "%d", 0);
	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
	layout = gtk_widget_create_pango_layout(u_data->io->draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);

#endif

	if (u_data->io->x1_tmp_usec==0)
		sec=u_data->io->x1_tmp_sec;
	else
		sec=u_data->io->x1_tmp_sec+1;


	if (u_data->io->offset!=0)
	{
		g_snprintf(label_string, 15, "%u", u_data->io->x1_tmp_sec);

#if GTK_MAJOR_VERSION < 2
		lwidth=gdk_string_width(font, label_string);
		gdk_draw_string(u_data->io->pixmap,font,u_data->io->draw_area->style->black_gc,
		                LEFT_BORDER-25,
		                u_data->io->pixmap_height-BOTTOM_BORDER+20,
		                label_string);
#else
		memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
		pango_layout_set_text(layout, label_string, -1);
		pango_layout_get_pixel_size(layout, &lwidth, NULL);

		gdk_draw_layout(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
		                LEFT_BORDER-25,
		                u_data->io->pixmap_height-BOTTOM_BORDER+20,
		                layout);
#endif
	}

	w=(guint32)(500/(guint32)(distance*u_data->io->x_interval)); /*there will be a label for every w_th tic*/

	if (w==0)
		w=1;
	
	if (w==4 || w==3 || w==2)
	{
		w=5;
		a=distance/10;  /*distance between two tics*/
		b = (guint32)((u_data->io->min_x/100000))%10; /* start for labels*/
	}
	else
	{
		a=distance/5;
		b=0;
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
		if (i>=u_data->io->min_x && i%1000000!=0)
		{
			length=5;
			g_snprintf(label_string, 15, "%d", i%1000000);
			if (j%w==0)
			{
				length=10;

				#if GTK_MAJOR_VERSION < 2
					lwidth=gdk_string_width(font, label_string);
					gdk_draw_string(u_data->io->pixmap,font,u_data->io->draw_area->style->black_gc,
						(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval-lwidth/2),
						u_data->io->pixmap_height-BOTTOM_BORDER+10,
						label_string);
				#else
					memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
					pango_layout_set_text(layout, label_string, -1);
					pango_layout_get_pixel_size(layout, &lwidth, NULL);
					gdk_draw_layout(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
						(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval-lwidth/2),
						u_data->io->pixmap_height-BOTTOM_BORDER+10,
						layout);
				#endif
			}
			gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
				(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval),
				u_data->io->pixmap_height-BOTTOM_BORDER,
				(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval),
				u_data->io->pixmap_height-BOTTOM_BORDER+length);
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
			gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
			(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval),
			u_data->io->pixmap_height-BOTTOM_BORDER,
			(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval),
			u_data->io->pixmap_height-BOTTOM_BORDER+10);

			g_snprintf(label_string, 15, "%d", sec);
			#if GTK_MAJOR_VERSION < 2
				lwidth=gdk_string_width(font, label_string);
				gdk_draw_string(u_data->io->pixmap,font,u_data->io->draw_area->style->black_gc,
					(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval-10),
					u_data->io->pixmap_height-BOTTOM_BORDER+20,
					label_string);
			#else
				memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
				pango_layout_set_text(layout, label_string, -1);
				pango_layout_get_pixel_size(layout, &lwidth, NULL);

				gdk_draw_layout(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
				(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval-10),
					u_data->io->pixmap_height-BOTTOM_BORDER+20,
					layout);
			#endif
			write_label = FALSE;
		}
		
	}

	strcpy(label_string, "sec");

#if GTK_MAJOR_VERSION < 2
	lwidth=gdk_string_width(font, label_string);
	gdk_draw_string(u_data->io->pixmap,
	                font,
	                u_data->io->draw_area->style->black_gc,
	                u_data->io->pixmap_width-RIGHT_BORDER-10,
	                u_data->io->pixmap_height-BOTTOM_BORDER+30,
	                label_string);
#else
	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &lwidth, NULL);
	gdk_draw_layout(u_data->io->pixmap,
	                u_data->io->draw_area->style->black_gc,
	                u_data->io->pixmap_width-RIGHT_BORDER-10,
	                u_data->io->pixmap_height-BOTTOM_BORDER+30,
	                layout);
#endif

	distance=5;

	/* y-axis */
	gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc, LEFT_BORDER,TOP_BORDER-u_data->io->offset,LEFT_BORDER,u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset);
	gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,LEFT_BORDER,TOP_BORDER-u_data->io->offset, LEFT_BORDER-5, TOP_BORDER-u_data->io->offset+5);
	gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,LEFT_BORDER,TOP_BORDER-u_data->io->offset, LEFT_BORDER+5, TOP_BORDER-u_data->io->offset+5);

	u_data->io->y_interval = (float)(((u_data->io->pixmap_height-TOP_BORDER-BOTTOM_BORDER)*1.0)/(u_data->io->max_y-u_data->io->min_y));

	e=0;
	if (u_data->io->y_interval<1)
	{
		dis=1/u_data->io->y_interval;
		while (dis >1)
		{
			dis/=10;
			e++;
		}
		distance=1;
		for (i=0; i<=e; i++)
			distance=distance*10;
	}
	else if (u_data->io->y_interval<2)
		distance = 10;

	if (u_data->io->max_y>0)
	{
		for (i=u_data->io->min_y/distance*distance; i<=u_data->io->max_y; i+=distance/5)
		{
			if (i>=u_data->io->min_y)
			{
				length=5;
				g_snprintf(label_string, 15, "%d", i);
				if (i%distance==0 || (distance<=5 && u_data->io->y_interval>10))
				{
					length=10;

#if GTK_MAJOR_VERSION < 2
						lwidth=gdk_string_width(font, label_string);
						gdk_draw_string(u_data->io->pixmap,font,u_data->io->draw_area->style->black_gc,
						                LEFT_BORDER-length-lwidth-5,
						                (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval-POINT_SIZE),
						                label_string);
#else
						memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
						pango_layout_set_text(layout, label_string, -1);
						pango_layout_get_pixel_size(layout, &lwidth, NULL);
						gdk_draw_layout(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
						                LEFT_BORDER-length-lwidth-5,
						                (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval-POINT_SIZE),
						                layout);
#endif
				}
				gdk_draw_line(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,LEFT_BORDER-length,
				              (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval),
				              LEFT_BORDER,
				              (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval));
			}
		}
	}
	else if ((u_data->dir==1 && u_data->assoc->n_array_tsn1==0) || (u_data->dir==2 && u_data->assoc->n_array_tsn2==0))
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "No Data Chunks sent");
}


static void sctp_graph_redraw(struct sctp_udata *u_data)
{
sctp_graph_t *ios;

	u_data->io->needs_redraw=TRUE;

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
	ios=(sctp_graph_t *)OBJECT_GET_DATA(u_data->io->draw_area, "sctp_graph_t");

	if(!ios){
		exit(10);
	}


	gdk_draw_pixmap(u_data->io->draw_area->window,
	                u_data->io->draw_area->style->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
	                ios->pixmap,
	                0,0,
	                0, 0,
	                u_data->io->draw_area->allocation.width,
	                u_data->io->draw_area->allocation.height);
}


static void on_sack_bt(GtkWidget *widget _U_, struct sctp_udata *u_data)
{

	u_data = (struct sctp_udata *) u_data;
	u_data->io->graph_type=2;
	sctp_graph_redraw(u_data);
}

static void on_tsn_bt(GtkWidget *widget _U_, struct sctp_udata *u_data)
{

	u_data->io->graph_type=1;
	sctp_graph_redraw(u_data);
}

static void on_both_bt(GtkWidget *widget _U_, struct sctp_udata *u_data)
{

	u_data->io->graph_type=0;
	sctp_graph_redraw(u_data);
}

static void
sctp_graph_close_cb(GtkWidget* widget _U_, gpointer u_data)
{
	struct sctp_udata *udata;
	int dir;

	udata = (struct sctp_udata *)u_data;
	dir=udata->dir-1;
	gtk_grab_remove(GTK_WIDGET(udata->io->window));
	gtk_widget_destroy(GTK_WIDGET(udata->io->window));

}

static gint
configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, struct sctp_udata *u_data)
{
	if(!u_data->io){
		exit(10);
	}

	if(u_data->io->pixmap){
		gdk_pixmap_unref(u_data->io->pixmap);
		u_data->io->pixmap=NULL;
	}

	u_data->io->pixmap=gdk_pixmap_new(widget->window,
			widget->allocation.width,
			widget->allocation.height,
			-1);
	u_data->io->pixmap_width=widget->allocation.width;
	u_data->io->pixmap_height=widget->allocation.height;

	gdk_draw_rectangle(u_data->io->pixmap,
			widget->style->white_gc,
			TRUE,
			0, 0,
			widget->allocation.width,
			widget->allocation.height);
	sctp_graph_redraw(u_data);
	return TRUE;
}

static gint
expose_event(GtkWidget *widget, GdkEventExpose *event)
{
	sctp_graph_t *ios;

	ios=(sctp_graph_t *)OBJECT_GET_DATA(widget, "sctp_graph_t");
	if(!ios){
		exit(10);
	}

	gdk_draw_pixmap(widget->window,
	                widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
	                ios->pixmap,
	                event->area.x, event->area.y,
	                event->area.x, event->area.y,
	                event->area.width, event->area.height);

	return FALSE;
}


static void
on_zoomin_bt (GtkWidget *widget _U_, struct sctp_udata *u_data)
{
	sctp_min_max_t *tmp_minmax;

	if (u_data->io->rectangle_present==TRUE)
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
		u_data->io->rectangle_present=FALSE;
		gtk_widget_set_sensitive(zoomout_bt, TRUE);
		sctp_graph_redraw(u_data);
	}
	else
	{
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Please draw a rectangle around the area you want to zoom in!");
	}
}

static void
zoomin_bt (struct sctp_udata *u_data)
{
	sctp_min_max_t *tmp_minmax;

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
	u_data->io->rectangle_present=FALSE;
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
			u_data->io->tmp_min_tsn1=u_data->assoc->min_tsn1;
			u_data->io->tmp_max_tsn1=u_data->assoc->max_tsn1;
			u_data->io->tmp_min_tsn2=u_data->assoc->min_tsn2;
			u_data->io->tmp_max_tsn2=u_data->assoc->max_tsn2;
			u_data->io->tmp=FALSE;
		}
	}
	else
	{
		u_data->io->x1_tmp_sec=u_data->assoc->min_secs;
		u_data->io->x1_tmp_usec=u_data->assoc->min_usecs;
		u_data->io->x2_tmp_sec=u_data->assoc->max_secs;
		u_data->io->x2_tmp_usec=u_data->assoc->max_usecs;
		u_data->io->tmp_min_tsn1=u_data->assoc->min_tsn1;
		u_data->io->tmp_max_tsn1=u_data->assoc->max_tsn1;
		u_data->io->tmp_min_tsn2=u_data->assoc->min_tsn2;
		u_data->io->tmp_max_tsn2=u_data->assoc->max_tsn2;
		u_data->io->tmp=FALSE;
	}
	if (g_slist_length(u_data->assoc->min_max)==1)
		gtk_widget_set_sensitive(zoomout_bt, FALSE);
	sctp_graph_redraw(u_data);
}

static gint
on_button_press (GtkWidget *widget _U_, GdkEventButton *event, struct sctp_udata *u_data)
{
	sctp_graph_t *ios;

	if (u_data->io->rectangle==TRUE)
	{
		gdk_draw_rectangle(u_data->io->pixmap,u_data->io->draw_area->style->white_gc,
		                   FALSE,
		                   (gint)floor(MIN(u_data->io->x_old,u_data->io->x_new)),
		                   (gint)floor(MIN(u_data->io->y_old,u_data->io->y_new)),
		                   (gint)floor(abs((long)(u_data->io->x_new-u_data->io->x_old))),
		                   (gint)floor(abs((long)(u_data->io->y_new-u_data->io->y_old))));
		ios=(sctp_graph_t *)OBJECT_GET_DATA(u_data->io->draw_area, "sctp_graph_t");

		if(!ios){
			exit(10);
		}

		gdk_draw_pixmap(u_data->io->draw_area->window,
		                u_data->io->draw_area->style->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
		                ios->pixmap,
		                0,0,
		                0, 0,
		                (gint)(abs((long)(u_data->io->x_new-u_data->io->x_old))),
		                (gint)(abs((long)(u_data->io->y_new-u_data->io->y_old))));
		sctp_graph_redraw(u_data);
	}
	u_data->io->x_old=event->x;
	u_data->io->y_old=event->y;
	if (u_data->io->y_old>u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-POINT_SIZE)
		u_data->io->y_old=u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-POINT_SIZE;
	if (u_data->io->x_old<LEFT_BORDER+u_data->io->offset)
		u_data->io->x_old=LEFT_BORDER+u_data->io->offset;
	u_data->io->rectangle=FALSE;

	return TRUE;
}


static gint
on_button_release (GtkWidget *widget _U_, GdkEventButton *event, struct sctp_udata *u_data)
{
	sctp_graph_t *ios;
	guint32 helpx, helpy, x1_tmp, x2_tmp,  y_value;
	gint label_width, label_height;
	gdouble x_value, position;
	gint lwidth;
	char label_string[30];
	GdkGC *text_color;
	#if GTK_MAJOR_VERSION < 2
		GdkFont *font;
#else
		PangoLayout  *layout;
#endif

#if GTK_MAJOR_VERSION < 2
		font = u_data->io->draw_area->style->font;
#endif

#if GTK_MAJOR_VERSION < 2
		label_width=gdk_string_width(font, label_string);
		label_height=gdk_string_height(font, label_string);
#else
		g_snprintf(label_string, 15, "%d", 0);
		memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
		layout = gtk_widget_create_pango_layout(u_data->io->draw_area, label_string);
		pango_layout_get_pixel_size(layout, &label_width, &label_height);

#endif

	if (event->y>u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
		event->y = u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset;
	if (event->x < LEFT_BORDER+u_data->io->offset)
		event->x = LEFT_BORDER+u_data->io->offset;
	if (abs((long)(event->x-u_data->io->x_old))>10 || abs((long)(event->y-u_data->io->y_old))>10)
	{
		u_data->io->rect_x_min = (gint)floor(MIN(u_data->io->x_old,event->x));
		u_data->io->rect_x_max = (gint)ceil(MAX(u_data->io->x_old,event->x));
		u_data->io->rect_y_min = (gint)floor(MIN(u_data->io->y_old,event->y));
		u_data->io->rect_y_max = (gint)ceil(MAX(u_data->io->y_old,event->y))+POINT_SIZE;
		gdk_draw_rectangle(u_data->io->pixmap,u_data->io->draw_area->style->black_gc,
		                   FALSE,
		                   u_data->io->rect_x_min, u_data->io->rect_y_min,
		                   u_data->io->rect_x_max - u_data->io->rect_x_min,
				   u_data->io->rect_y_max - u_data->io->rect_y_min);
		ios=(sctp_graph_t *)OBJECT_GET_DATA(u_data->io->draw_area, "sctp_graph_t");

		if(!ios){
			exit(10);
		}

		gdk_draw_pixmap(u_data->io->draw_area->window,
		                u_data->io->draw_area->style->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
		                ios->pixmap,
		                0, 0,
		                0, 0,
		                u_data->io->draw_area->allocation.width,
		                u_data->io->draw_area->allocation.height);

		x1_tmp=(unsigned int)floor(u_data->io->min_x+((u_data->io->x_old-LEFT_BORDER-u_data->io->offset)*u_data->io->tmp_width/u_data->io->axis_width));
		x2_tmp=(unsigned int)floor(u_data->io->min_x+((event->x-LEFT_BORDER-u_data->io->offset)*u_data->io->tmp_width/u_data->io->axis_width));
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

		u_data->io->y1_tmp=(guint32)((u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-u_data->io->y_old)/u_data->io->y_interval);
		u_data->io->y2_tmp=(guint32)((u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-event->y)/u_data->io->y_interval);
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
				zoomin_bt(u_data);
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
			x_value = ((event->x-LEFT_BORDER-u_data->io->offset) * ((u_data->io->x2_tmp_sec+u_data->io->x2_tmp_usec/1000000.0)-(u_data->io->x1_tmp_sec+u_data->io->x1_tmp_usec/1000000.0)) / (u_data->io->pixmap_width-LEFT_BORDER-u_data->io->offset))+u_data->io->x1_tmp_sec+u_data->io->x1_tmp_usec/1000000.0;
			y_value = floor((u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-event->y) * (max_tsn - min_tsn) / (u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)) + min_tsn;
			text_color = u_data->io->draw_area->style->black_gc;
			g_snprintf(label_string, 30, "(%.6lf, %u)", x_value, y_value);
			label_set = TRUE;

			gdk_draw_line(u_data->io->pixmap,text_color, event->x-2, event->y, event->x+2, event->y);
			gdk_draw_line(u_data->io->pixmap,text_color, event->x, event->y-2, event->x, event->y+2);
			if (event->x+150>=u_data->io->pixmap_width)
				position = event->x - 150;
			else
				position = event->x + 5;

#if GTK_MAJOR_VERSION < 2
			lwidth=gdk_string_width(font, label_string);
		                            gdk_draw_string(u_data->io->pixmap,font,text_color,
		                            position,
		                            event->y-10,
		                            label_string);
#else
			memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);

			gdk_draw_layout(u_data->io->pixmap,text_color,
							position,
							event->y-10,
							layout);
	#endif
			ios=(sctp_graph_t *)OBJECT_GET_DATA(u_data->io->draw_area, "sctp_graph_t");

			if(!ios){
				exit(10);
			}
			gdk_draw_pixmap(u_data->io->draw_area->window,
		                    u_data->io->draw_area->style->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
		                    ios->pixmap,
		                    0, 0,
		                    0, 0,
		                    u_data->io->draw_area->allocation.width,
		                    u_data->io->draw_area->allocation.height);
		}
	}
	return TRUE;
}


static void init_sctp_graph_window(struct sctp_udata *u_data)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *bt_close, *sack_bt, *tsn_bt, *both_bt, *zoomin_bt;
	GtkTooltips *tooltip_in, *tooltip_out;

	/* create the main window */

	u_data->io->window=gtk_window_new(GTK_WINDOW_TOPLEVEL);

	gtk_widget_set_name(u_data->io->window, "SCTP Graphics");

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(u_data->io->window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(vbox, u_data);

	sctp_graph_set_title(u_data);

	hbox = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbox), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing(GTK_BUTTON_BOX (hbox), 0);
	gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	sack_bt = gtk_button_new_with_label ("Show Sacks");
	gtk_box_pack_start(GTK_BOX(hbox), sack_bt, FALSE, FALSE, 0);
	gtk_widget_show(sack_bt);

	gtk_signal_connect(GTK_OBJECT(sack_bt), "clicked", (GtkSignalFunc)on_sack_bt, u_data);

	tsn_bt = gtk_button_new_with_label ("Show TSNs");
	gtk_box_pack_start(GTK_BOX(hbox), tsn_bt, FALSE, FALSE, 0);
	gtk_widget_show(tsn_bt);
	SIGNAL_CONNECT(tsn_bt, "clicked", on_tsn_bt, u_data);

	both_bt = gtk_button_new_with_label ("Show both");
	gtk_box_pack_start(GTK_BOX(hbox), both_bt, FALSE, FALSE, 0);
	gtk_widget_show(both_bt);
	SIGNAL_CONNECT(both_bt, "clicked", on_both_bt, u_data);

	zoomin_bt = gtk_button_new_with_label ("Zoom in");
	gtk_box_pack_start(GTK_BOX(hbox), zoomin_bt, FALSE, FALSE, 0);
	gtk_widget_show(zoomin_bt);
	SIGNAL_CONNECT(zoomin_bt, "clicked", on_zoomin_bt, u_data);
	tooltip_in = gtk_tooltips_new();
	gtk_tooltips_set_tip(tooltip_in, zoomin_bt, "Zoom in the area you have selected", NULL);

	zoomout_bt = gtk_button_new_with_label ("Zoom out");
	gtk_box_pack_start(GTK_BOX(hbox), zoomout_bt, FALSE, FALSE, 0);
	gtk_widget_show(zoomout_bt);
	SIGNAL_CONNECT(zoomout_bt, "clicked", on_zoomout_bt, u_data);
	tooltip_out = gtk_tooltips_new();
	gtk_tooltips_set_tip(tooltip_out, zoomout_bt, "Zoom out one step", NULL);
	gtk_widget_set_sensitive(zoomout_bt, FALSE);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_box_pack_start(GTK_BOX(hbox), bt_close, FALSE, FALSE, 0);
	gtk_widget_show(bt_close);
	SIGNAL_CONNECT(bt_close, "clicked", sctp_graph_close_cb, u_data);

	gtk_signal_connect(GTK_OBJECT(u_data->io->draw_area),"button_press_event",(GtkSignalFunc)on_button_press, u_data);
	gtk_signal_connect(GTK_OBJECT(u_data->io->draw_area),"button_release_event",(GtkSignalFunc)on_button_release, u_data);
	gtk_widget_set_events(u_data->io->draw_area, GDK_BUTTON_PRESS_MASK | GDK_BUTTON_RELEASE_MASK | GDK_EXPOSURE_MASK);

	gtk_widget_show(u_data->io->window);
}

static void sctp_graph_set_title(struct sctp_udata *u_data)
{
	char *title;

	if(!u_data->io->window)
	{
		return;
	}
	title = g_strdup_printf("SCTP TSNs and Sacks over Time: %s Port1 %u Port2 %u Endpoint %u",
	                        cf_get_display_name(&cfile), u_data->parent->assoc->port1, u_data->parent->assoc->port2, u_data->dir);
	gtk_window_set_title(GTK_WINDOW(u_data->io->window), title);
	g_free(title);
}

static void
gtk_sctpgraph_init(struct sctp_udata *u_data)
{
	sctp_graph_t *io;
	gint dir;
	sctp_min_max_t* tmp_minmax;

	io=g_malloc(sizeof(sctp_graph_t));
	io->needs_redraw=TRUE;
	io->x_interval=1000;
	io->window=NULL;
	io->draw_area=NULL;
	io->pixmap=NULL;
	io->pixmap_width=800;
	io->pixmap_height=600;
	io->graph_type=0;
	dir=u_data->dir-1;
	u_data->io=io;
	u_data->io->x1_tmp_sec=u_data->assoc->min_secs;
	u_data->io->x1_tmp_usec=u_data->assoc->min_usecs;
	u_data->io->x2_tmp_sec=u_data->assoc->max_secs;
	u_data->io->x2_tmp_usec=u_data->assoc->max_usecs;
	u_data->io->tmp_min_tsn1=u_data->assoc->min_tsn1;
	u_data->io->tmp_max_tsn1=u_data->assoc->max_tsn1;
	u_data->io->tmp_min_tsn2=u_data->assoc->min_tsn2;
	u_data->io->tmp_max_tsn2=u_data->assoc->max_tsn2;
	u_data->io->tmp=FALSE;

	tmp_minmax = g_malloc(sizeof(sctp_min_max_t));
	tmp_minmax->tmp_min_secs = u_data->assoc->min_secs;
	tmp_minmax->tmp_min_usecs=u_data->assoc->min_usecs;
	tmp_minmax->tmp_max_secs=u_data->assoc->max_secs;
	tmp_minmax->tmp_max_usecs=u_data->assoc->max_usecs;
	tmp_minmax->tmp_min_tsn2=u_data->assoc->min_tsn2;
	tmp_minmax->tmp_min_tsn1=u_data->assoc->min_tsn1;
	tmp_minmax->tmp_max_tsn1=u_data->assoc->max_tsn1;
	tmp_minmax->tmp_max_tsn2=u_data->assoc->max_tsn2;
	u_data->assoc->min_max = g_slist_prepend(u_data->assoc->min_max, tmp_minmax);

	/* build the GUI */
	init_sctp_graph_window(u_data);
	sctp_graph_redraw(u_data);

}


static gint
quit(GtkObject *object _U_, gpointer user_data)
{
	struct sctp_udata *u_data=(struct sctp_udata*)user_data;

	decrease_childcount(u_data->parent);
	remove_child(u_data, u_data->parent);

	g_free(u_data->io);

	u_data->assoc->min_max = NULL;
	g_free(u_data);
	return TRUE;
}


static void create_draw_area(GtkWidget *box, struct sctp_udata *u_data)
{

	u_data->io->draw_area=gtk_drawing_area_new();
	SIGNAL_CONNECT(u_data->io->draw_area, "destroy", quit, u_data);
	OBJECT_SET_DATA(u_data->io->draw_area, "sctp_graph_t", u_data->io);

	WIDGET_SET_SIZE(u_data->io->draw_area, u_data->io->pixmap_width, u_data->io->pixmap_height);

	/* signals needed to handle backing pixmap */
	SIGNAL_CONNECT(u_data->io->draw_area, "expose_event", expose_event, NULL);
	SIGNAL_CONNECT(u_data->io->draw_area, "configure_event", configure_event, u_data);

	gtk_widget_show(u_data->io->draw_area);
	gtk_box_pack_start(GTK_BOX(box), u_data->io->draw_area, TRUE, TRUE, 0);
}



void create_graph(guint16 dir, struct sctp_analyse* userdata)
{
	struct sctp_udata *u_data;

	u_data=g_malloc(sizeof(struct sctp_udata));
	u_data->assoc=g_malloc(sizeof(sctp_assoc_info_t));
	u_data->assoc=userdata->assoc;
	u_data->io=NULL;
	u_data->dir = dir;
	u_data->parent = userdata;
	if ((u_data->dir==1 && u_data->assoc->n_array_tsn1==0)|| (u_data->dir==2 && u_data->assoc->n_array_tsn2==0))
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "No Data Chunks sent");
	else
	{
		set_child(u_data, u_data->parent);
		increase_childcount(u_data->parent);
		gtk_sctpgraph_init(u_data);
	}
}
