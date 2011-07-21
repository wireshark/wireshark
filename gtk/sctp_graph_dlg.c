/*
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
 * Copyright 2009, Varun Notibala <nbvarun [AT] gmail.com>
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
#include <stdio.h>
#include <math.h>
#include <string.h>

#include <gtk/gtk.h>

#include "epan/filesystem.h"
#include <epan/strutil.h>

#include "../globals.h"
#include "../color.h"
#include "../ui_util.h"
#include "../simple_dialog.h"

#include "gtk/dlg_utils.h"
#include "gtk/main.h"
#include "gtk/sctp_stat.h"

#include "gtk/old-gtk-compat.h"

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

#define LEFT_BORDER 60
#define RIGHT_BORDER 10
#define TOP_BORDER 10
#define BOTTOM_BORDER 50

#define SUB_32(a, b)	((a)-(b))
#define POINT_SIZE	3

static GtkWidget * sack_bt;

/*
 * Global variables that help in redrawing graph
 * for SACK and NRSACK
 */
static guint8 gIsSackChunkPresent   = 0;
static guint8 gIsNRSackChunkPresent = 0;

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

struct gaps {
	guint16 start;
	guint16 end;
};

struct sack_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32 cum_tsn_ack;
	guint32 a_rwnd;
	guint16 nr_of_gaps;
	guint16 nr_of_dups;
	struct gaps gaps[1];
};

struct nr_sack_chunk_header {
	guint8  type;
	guint8  flags;
	guint16 length;
	guint32 cum_tsn_ack;
	guint32 a_rwnd;
	guint16 nr_of_gaps;
	guint16 nr_of_nr_gaps;
	guint16 nr_of_dups;
	guint16 reserved;
	struct gaps gaps[1];
};

static gboolean label_set = FALSE;
static guint32 max_tsn=0, min_tsn=0;
static void sctp_graph_set_title(struct sctp_udata *u_data);
static void create_draw_area(GtkWidget *box, struct sctp_udata *u_data);
static GtkWidget *zoomout_bt;
#if defined(_WIN32) && !defined(__MINGW32__)
static int rint (double );	/* compiler template for Windows */
#endif

static void
draw_sack_graph(struct sctp_udata *u_data)
{
	tsn_t	*sack;
	GList *list=NULL, *tlist;
	guint16 gap_start=0, gap_end=0, i, j, nr, dup_nr;
	guint8 type;
	guint32 tsnumber, dup;
	gint xvalue, yvalue;
	GdkColor red_color = {0, 65535, 0, 0};
	GdkColor green_color = {0, 0, 65535, 0};
	GdkColor cyan_color = {0, 0, 65535, 65535};
	GdkGC *red_gc, *green_gc, *cyan_gc;
	struct sack_chunk_header *sack_header;
	struct gaps *gap;
	guint32 /*max_num,*/ diff;
	guint32 *dup_list;

	red_gc = gdk_gc_new(gtk_widget_get_window(u_data->io->draw_area));
	gdk_gc_set_rgb_fg_color(red_gc, &red_color);

	green_gc = gdk_gc_new(gtk_widget_get_window(u_data->io->draw_area));
	gdk_gc_set_rgb_fg_color(green_gc, &green_color);

	cyan_gc = gdk_gc_new(gtk_widget_get_window(u_data->io->draw_area));
	gdk_gc_set_rgb_fg_color(cyan_gc, &cyan_color);

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
				gIsSackChunkPresent = 1;
				sack_header =(struct sack_chunk_header *)tlist->data;
				nr=g_ntohs(sack_header->nr_of_gaps);
				tsnumber = g_ntohl(sack_header->cum_tsn_ack);
				dup_nr=g_ntohs(sack_header->nr_of_dups);

				if (sack->secs>=u_data->io->x1_tmp_sec)
				{
					if (nr>0)
					{
						gap = &sack_header->gaps[0];
						for(i=0;i<nr; i++)
						{
							gap_start=g_ntohs(gap->start);
							gap_end = g_ntohs(gap->end);
							/* max_num=gap_end+tsnumber; */
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
								    yvalue >= TOP_BORDER-u_data->io->offset-POINT_SIZE &&
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
					/*
					else
						max_num=tsnumber;
					*/
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
						    yvalue >= TOP_BORDER-u_data->io->offset-POINT_SIZE &&
						    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
						    {
							gdk_draw_arc(u_data->io->pixmap,red_gc,TRUE,
								     xvalue,
								     yvalue,
								     POINT_SIZE, POINT_SIZE,0, (64*360) );
							}
					}
					if (dup_nr > 0)
					{
						dup_list = (guint32 *)(((char *)&sack_header->nr_of_dups)+sizeof(guint16)+(nr*sizeof(struct gaps)));
						for (i = 0; i < dup_nr; i++)
						{
							dup = g_ntohl(dup_list[i]);
							if (dup >= min_tsn)
							{
								if (u_data->io->uoff)
									diff = sack->secs - u_data->io->min_x;
								else
									diff=sack->secs*1000000+sack->usecs-u_data->io->min_x;
								xvalue = (guint32)(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff);
								yvalue = (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-POINT_SIZE -u_data->io->offset-((SUB_32(dup,min_tsn))*u_data->io->y_interval));
								if (xvalue >= LEFT_BORDER+u_data->io->offset &&
								    xvalue <= u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset &&
								    yvalue >= TOP_BORDER-u_data->io->offset-POINT_SIZE &&
								    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
									gdk_draw_arc(u_data->io->pixmap,cyan_gc,TRUE,
									             xvalue,
									             yvalue,
									             POINT_SIZE, POINT_SIZE,0, (64*360) );
							}
						}
					}
				}
			}
			tlist = g_list_next(tlist);
		}
		list = g_list_previous(list);
	}
	g_object_unref(G_OBJECT(red_gc));
	g_object_unref(G_OBJECT(green_gc));
}

/*
 * This function plots the NR_SACK gap ack and
 * nr gap acks.
 * Red dot - Cumulative TSN ack
 * Green dot - Gap ack
 * Blue circle - NR Gap ack
 */
static void
draw_nr_sack_graph(struct sctp_udata *u_data)
{
	tsn_t *sack;
	GList *list=NULL, *tlist;
	guint16 gap_start=0, gap_end=0, i, numberOf_gaps, numberOf_nr_gaps;
	guint8 type;
	guint32 tsnumber, j;
	gint xvalue, yvalue;
	GdkColor red_color = {0, 65535, 0, 0};
	GdkColor blue_color = {0, 0, 0, 65535};
	GdkColor green_color = {0, 0, 65535, 0};
	GdkGC *red_gc, *blue_gc, *green_gc;
	struct nr_sack_chunk_header *nr_sack_header;
	struct gaps *nr_gap;
	guint32 /*max_num,*/ diff;
	/* This holds the sum of gap acks and nr gap acks */
	guint16 total_gaps = 0;

	red_gc = gdk_gc_new(gtk_widget_get_window(u_data->io->draw_area));
	gdk_gc_set_rgb_fg_color(red_gc, &red_color);
	blue_gc = gdk_gc_new(gtk_widget_get_window(u_data->io->draw_area));
	gdk_gc_set_rgb_fg_color(blue_gc, &blue_color);
	green_gc = gdk_gc_new(gtk_widget_get_window(u_data->io->draw_area));
	gdk_gc_set_rgb_fg_color(green_gc, &green_color);


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
			/*
			 * The tlist->data is memcpy ied to the appropriate structure
			 * They entire raw tvb bytes are copied on to one of the *_chunk_header
			 * structures in sctp_stat.c
			 */
			if (type == SCTP_NR_SACK_CHUNK_ID)
			{
				gIsNRSackChunkPresent = 1;
				nr_sack_header =(struct nr_sack_chunk_header *)tlist->data;
				numberOf_nr_gaps=g_ntohs(nr_sack_header->nr_of_nr_gaps);
				numberOf_gaps=g_ntohs(nr_sack_header->nr_of_gaps);
				tsnumber = g_ntohl(nr_sack_header->cum_tsn_ack);
				total_gaps = numberOf_gaps + numberOf_nr_gaps;
				if (sack->secs>=u_data->io->x1_tmp_sec)
				{
					/* If the number of nr_gaps is greater than 0 */
					if ( total_gaps > 0 )
					{
						nr_gap = &nr_sack_header->gaps[0];
						for ( i=0; i < total_gaps; i++ )
						{
							gap_start=g_ntohs(nr_gap->start);
							gap_end = g_ntohs(nr_gap->end);
							/* max_num= gap_end + tsnumber; */
							for ( j = gap_start; j <= gap_end; j++)
							{
								if (u_data->io->uoff)
									diff = sack->secs - u_data->io->min_x;
								else
									diff=sack->secs*1000000+sack->usecs-u_data->io->min_x;
								xvalue = (guint32)(LEFT_BORDER+u_data->io->offset+u_data->io->x_interval*diff);
								yvalue = (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-POINT_SIZE-u_data->io->offset-((SUB_32(j+tsnumber,min_tsn))*u_data->io->y_interval));
								if (xvalue >= LEFT_BORDER+u_data->io->offset &&
								    xvalue <= u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset &&
								    yvalue >= TOP_BORDER-u_data->io->offset-POINT_SIZE &&
								    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
								{
									/* Check if this is an GAP ACK or NR GAP ACK */
									if ( i >= numberOf_gaps)
									{
										/* This is a nr gap ack */
										gdk_draw_arc(u_data->io->pixmap,blue_gc,FALSE,
										             xvalue,
										             yvalue,
										             POINT_SIZE , POINT_SIZE,0, (64*360) );

										/* All NR GAP Acks are also gap acks, so plot these as
										 * gap acks - green dot.
										 * These will be shown as points with a green dot - GAP ACK
										 * surrounded by a blue circle - NR GAP ack
										 */
										gdk_draw_arc(u_data->io->pixmap, green_gc, TRUE,
										             xvalue,
										             yvalue,
										             POINT_SIZE , POINT_SIZE,0, (64*360) );

									}
									else
									{
										/* This is just a gap ack */
										gdk_draw_arc(u_data->io->pixmap, green_gc, TRUE,
										             xvalue,
										             yvalue,
										             POINT_SIZE , POINT_SIZE,0, (64*360) );
									}
								}
							}
							if (i < total_gaps-1)
								nr_gap++;
						}
					}
					/*
					else
						max_num=tsnumber;
					*/
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
						    yvalue >= TOP_BORDER-u_data->io->offset-POINT_SIZE &&
						    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
							gdk_draw_arc(u_data->io->pixmap,red_gc,TRUE,
								     xvalue,
								     yvalue,
								     POINT_SIZE, POINT_SIZE,0, (64*360) );
					}
				}
			}
			tlist = g_list_next(tlist);
		}
		list = g_list_previous(list);
	}
	g_object_unref(G_OBJECT(red_gc));
	g_object_unref(G_OBJECT(blue_gc));
	g_object_unref(G_OBJECT(green_gc));
}

static void
draw_tsn_graph(struct sctp_udata *u_data)
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
					    yvalue >= TOP_BORDER-u_data->io->offset-POINT_SIZE &&
					    yvalue <= u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)
						gdk_draw_arc(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,TRUE,
							     xvalue,
							     yvalue,
							     POINT_SIZE, POINT_SIZE, 0, (64*360));
			}
			tlist = g_list_next(tlist);
		}
		list = g_list_previous(list);
	}
}


static void
sctp_graph_draw(struct sctp_udata *u_data)
{
	int length, lwidth;
	guint32  distance=5, i, e, sec, w, start, a, b, j;
	gint label_width, label_height;
	char label_string[15];
	gfloat dis;
	gboolean write_label = FALSE;
	PangoLayout  *layout;

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
		u_data->io->min_x=(guint32)(u_data->io->x1_tmp_sec*1000000.0+u_data->io->x1_tmp_usec);
		u_data->io->max_x=(guint32)(u_data->io->x2_tmp_sec*1000000.0+u_data->io->x2_tmp_usec);
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
	                   gtk_widget_get_style(u_data->io->draw_area)->white_gc,
	                   TRUE,
	                   0, 0,
	                   u_data->io->draw_area->allocation.width,
	                   u_data->io->draw_area->allocation.height);

	distance=5;
	/* x_axis */
	gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc, LEFT_BORDER+u_data->io->offset,u_data->io->pixmap_height-BOTTOM_BORDER,u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset, u_data->io->pixmap_height-BOTTOM_BORDER);
	gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset, u_data->io->pixmap_height-BOTTOM_BORDER, u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset-5, u_data->io->pixmap_height-BOTTOM_BORDER-5);
	gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset, u_data->io->pixmap_height-BOTTOM_BORDER, u_data->io->pixmap_width-RIGHT_BORDER+u_data->io->offset-5, u_data->io->pixmap_height-BOTTOM_BORDER+5);
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

	g_snprintf(label_string, sizeof(label_string), "%d", 0);
	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
	layout = gtk_widget_create_pango_layout(u_data->io->draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);

	if (u_data->io->x1_tmp_usec==0)
		sec=u_data->io->x1_tmp_sec;
	else
		sec=u_data->io->x1_tmp_sec+1;


	if (u_data->io->offset!=0)
	{
		g_snprintf(label_string, sizeof(label_string), "%u", u_data->io->x1_tmp_sec);

		memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
		pango_layout_set_text(layout, label_string, -1);
		pango_layout_get_pixel_size(layout, &lwidth, NULL);

		gdk_draw_layout(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
		                LEFT_BORDER-25,
		                u_data->io->pixmap_height-BOTTOM_BORDER+20,
		                layout);
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
			g_snprintf(label_string, sizeof(label_string), "%d", i%1000000);
			if (j%w==0)
			{
				length=10;
				memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
				pango_layout_set_text(layout, label_string, -1);
				pango_layout_get_pixel_size(layout, &lwidth, NULL);
				gdk_draw_layout(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
					(guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval-lwidth/2),
					u_data->io->pixmap_height-BOTTOM_BORDER+10,
					layout);
			}
			gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
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
			gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
			              (guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval),
			              u_data->io->pixmap_height-BOTTOM_BORDER,
			              (guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval),
			              u_data->io->pixmap_height-BOTTOM_BORDER+10);

			g_snprintf(label_string, sizeof(label_string), "%d", sec);
			memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);

			gdk_draw_layout(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
			                (guint32)(LEFT_BORDER+u_data->io->offset+(i-u_data->io->min_x)*u_data->io->x_interval-10),
			                u_data->io->pixmap_height-BOTTOM_BORDER+20,
			                layout);
			write_label = FALSE;
		}

	}

	g_strlcpy(label_string, "sec", sizeof(label_string));

	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
	pango_layout_set_text(layout, label_string, -1);
	pango_layout_get_pixel_size(layout, &lwidth, NULL);
	gdk_draw_layout(u_data->io->pixmap,
	                gtk_widget_get_style(u_data->io->draw_area)->black_gc,
	                u_data->io->pixmap_width-RIGHT_BORDER-10,
	                u_data->io->pixmap_height-BOTTOM_BORDER+30,
	                layout);

	distance=5;

	/* y-axis */
	gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc, LEFT_BORDER,TOP_BORDER-u_data->io->offset,LEFT_BORDER,u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset);
	gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,LEFT_BORDER,TOP_BORDER-u_data->io->offset, LEFT_BORDER-5, TOP_BORDER-u_data->io->offset+5);
	gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,LEFT_BORDER,TOP_BORDER-u_data->io->offset, LEFT_BORDER+5, TOP_BORDER-u_data->io->offset+5);

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
				g_snprintf(label_string, sizeof(label_string), "%d", i);
				if (i%distance==0 || (distance<=5 && u_data->io->y_interval>10))
				{
					length=10;

					memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), sizeof(label_string));
					pango_layout_set_text(layout, label_string, -1);
					pango_layout_get_pixel_size(layout, &lwidth, NULL);
					gdk_draw_layout(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
					                LEFT_BORDER-length-lwidth-5,
					                (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval-POINT_SIZE),
					                layout);
				}
				gdk_draw_line(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,LEFT_BORDER-length,
				              (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval),
				              LEFT_BORDER,
				              (guint32)(u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-(i-u_data->io->min_y)*u_data->io->y_interval));
			}
		}
	}
	else if ((u_data->dir==1 && u_data->assoc->n_array_tsn1==0) || (u_data->dir==2 && u_data->assoc->n_array_tsn2==0))
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "No Data Chunks sent");
}

/* This function is used to change the title
 * in the graph dialogue to NR_SACK or SACK based on the
 * association
 * If an association has both SAKC and NR_SACK PDU's
 * a warning is popped
 */
static void
updateLabels(void)
{
	if (gIsSackChunkPresent && gIsNRSackChunkPresent)
	{
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, "This data set contains both SACK and NR SACK PDUs.");
		gtk_button_set_label( (GtkButton*) sack_bt, "Show both Sack and NR Sack");
	}
	else if (gIsSackChunkPresent)
		gtk_button_set_label( (GtkButton*) sack_bt, "Show Only Sack");
	else
		/* gIsNRSackChunkPresent will be true here */
		gtk_button_set_label( (GtkButton*) sack_bt, "Show Only NR Sack");
}

static void
sctp_graph_redraw(struct sctp_udata *u_data)
{
sctp_graph_t *ios;

	u_data->io->needs_redraw=TRUE;

	sctp_graph_draw(u_data);
	switch (u_data->io->graph_type)
	{
		case 0:
			/* Show both TSN and SACK information
			 * Reset the global sack variable
			 * for sack and nr sack cases
			 */
			gIsSackChunkPresent = 0;
			gIsNRSackChunkPresent = 0;
			draw_sack_graph(u_data);
			draw_nr_sack_graph(u_data);
			draw_tsn_graph(u_data);
			break;
		case 1:
			/* Show only TSN */
			draw_tsn_graph(u_data);
			break;
		case 2:
			/* Show only SACK information
			 * Reset the global sack variable
			 * for sack and nr sack cases
			 */
			gIsSackChunkPresent = 0;
			gIsNRSackChunkPresent = 0;
			draw_sack_graph(u_data);
			draw_nr_sack_graph(u_data);
			break;
	}

	/* Updates the sack / nr sack buttons */
	updateLabels();

	ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");
	g_assert(ios != NULL);

	gdk_draw_pixmap(gtk_widget_get_window(u_data->io->draw_area),
#if GTK_CHECK_VERSION(2,18,0)
	                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[gtk_widget_get_state(u_data->io->draw_area)],
#else
	                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
#endif
	                ios->pixmap,
	                0,0,
	                0, 0,
	                u_data->io->draw_area->allocation.width,
	                u_data->io->draw_area->allocation.height);
}


static void
on_sack_bt(GtkWidget *widget _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;

	u_data->io->graph_type=2;
	sctp_graph_redraw(u_data);
}

static void
on_tsn_bt(GtkWidget *widget _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;

	u_data->io->graph_type=1;
	sctp_graph_redraw(u_data);
}

static void
on_both_bt(GtkWidget *widget _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;

	u_data->io->graph_type=0;
	sctp_graph_redraw(u_data);
}

static void
sctp_graph_close_cb(GtkWidget* widget _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;

	gtk_grab_remove(GTK_WIDGET(u_data->io->window));
	gtk_widget_destroy(GTK_WIDGET(u_data->io->window));

}

static gboolean
configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;

	g_assert(u_data->io != NULL);

	if(u_data->io->pixmap){
		g_object_unref(u_data->io->pixmap);
		u_data->io->pixmap=NULL;
	}

	u_data->io->pixmap=gdk_pixmap_new(gtk_widget_get_window(widget),
			widget->allocation.width,
			widget->allocation.height,
			-1);
	u_data->io->pixmap_width=widget->allocation.width;
	u_data->io->pixmap_height=widget->allocation.height;

	gdk_draw_rectangle(u_data->io->pixmap,
			gtk_widget_get_style(widget)->white_gc,
			TRUE,
			0, 0,
			widget->allocation.width,
			widget->allocation.height);
	sctp_graph_redraw(u_data);
	return TRUE;
}

static gboolean
expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer user_data _U_)
{
	sctp_graph_t *ios;

	ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(widget), "sctp_graph_t");
	g_assert(ios != NULL);

	gdk_draw_pixmap(gtk_widget_get_window(widget),
#if GTK_CHECK_VERSION(2,18,0)
	                gtk_widget_get_style(widget)->fg_gc[gtk_widget_get_state(widget)],
#else
	                gtk_widget_get_style(widget)->fg_gc[GTK_WIDGET_STATE(widget)],
#endif
	                ios->pixmap,
	                event->area.x, event->area.y,
	                event->area.x, event->area.y,
	                event->area.width, event->area.height);

	return FALSE;
}


static void
on_zoomin_bt (GtkWidget *widget _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
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
zoomin_bt_fcn (struct sctp_udata *u_data)
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
on_zoomout_bt (GtkWidget *widget _U_, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
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

static gboolean
on_button_press_event (GtkWidget *widget _U_, GdkEventButton *event, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
	sctp_graph_t *ios;

	if (u_data->io->rectangle==TRUE)
	{
		gdk_draw_rectangle(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->white_gc,
		                   FALSE,
		                   (gint)floor(MIN(u_data->io->x_old,u_data->io->x_new)),
		                   (gint)floor(MIN(u_data->io->y_old,u_data->io->y_new)),
		                   (gint)floor(abs((long)(u_data->io->x_new-u_data->io->x_old))),
		                   (gint)floor(abs((long)(u_data->io->y_new-u_data->io->y_old))));
		ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");

		g_assert(ios != NULL);

		gdk_draw_pixmap(gtk_widget_get_window(u_data->io->draw_area),
#if GTK_CHECK_VERSION(2,18,0)
		                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[gtk_widget_get_state(u_data->io->draw_area)],
#else
		                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
#endif
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


static gboolean
on_button_release_event (GtkWidget *widget _U_, GdkEventButton *event, gpointer user_data)
{
	struct sctp_udata *u_data = user_data;
	sctp_graph_t *ios;
	guint32 helpx, helpy, x1_tmp, x2_tmp,  y_value, t_size=0, s_size=0, i, y_tolerance;
	gint label_width, label_height;
	gdouble x_value, position, s_diff=0, t_diff=0, x_tolerance=0.0001;
	gint lwidth;
	char label_string[30];
	GdkGC *text_color;
	GPtrArray *tsnlist = NULL, *sacklist=NULL;
	struct tsn_sort *tsn, *sack=NULL;
	gboolean sack_found = FALSE;
	PangoLayout  *layout;

	g_snprintf(label_string, 15, "%d", 0);
	memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
	layout = gtk_widget_create_pango_layout(u_data->io->draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);

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
		gdk_draw_rectangle(u_data->io->pixmap,gtk_widget_get_style(u_data->io->draw_area)->black_gc,
		                   FALSE,
		                   u_data->io->rect_x_min, u_data->io->rect_y_min,
		                   u_data->io->rect_x_max - u_data->io->rect_x_min,
				   u_data->io->rect_y_max - u_data->io->rect_y_min);
		ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");

		g_assert(ios != NULL);

		gdk_draw_pixmap(gtk_widget_get_window(u_data->io->draw_area),
#if GTK_CHECK_VERSION(2,18,0)
		                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[gtk_widget_get_state(u_data->io->draw_area)],
#else
		                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
#endif
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
			x_value = ((event->x-LEFT_BORDER-u_data->io->offset) * ((u_data->io->x2_tmp_sec+u_data->io->x2_tmp_usec/1000000.0)-(u_data->io->x1_tmp_sec+u_data->io->x1_tmp_usec/1000000.0)) / (u_data->io->pixmap_width-LEFT_BORDER-RIGHT_BORDER-u_data->io->offset))+u_data->io->x1_tmp_sec+u_data->io->x1_tmp_usec/1000000.0;
			y_value = (gint)rint((u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset-event->y) * (max_tsn - min_tsn) / (u_data->io->pixmap_height-BOTTOM_BORDER-u_data->io->offset)) + min_tsn;
			text_color = gtk_widget_get_style(u_data->io->draw_area)->black_gc;

			if (u_data->dir == 1)
			{
				tsnlist = u_data->assoc->sort_tsn1;
				t_size = u_data->assoc->n_data_chunks_ep1;
				sacklist = u_data->assoc->sort_sack1;
				s_size = u_data->assoc->n_sack_chunks_ep1;
			}
			else
			{
				tsnlist = u_data->assoc->sort_tsn2;
				t_size = u_data->assoc->n_data_chunks_ep2;
				sacklist = u_data->assoc->sort_sack2;
				s_size = u_data->assoc->n_sack_chunks_ep2;
			}
			x_tolerance = (gdouble)((u_data->io->tmp_width / u_data->io->axis_width*1.0))*5/1000000.0;
			y_tolerance = (guint32)(((u_data->io->max_y - u_data->io->min_y) / (u_data->io->pixmap_height-TOP_BORDER-BOTTOM_BORDER-u_data->io->offset)) * 2.0);
			if (y_tolerance==0)
				y_tolerance = 2;
			else if (y_tolerance > 5)
				y_tolerance = 5;

			for (i=0; i<s_size; i++)
			{
				sack = (struct tsn_sort*)(g_ptr_array_index(sacklist, i));
				if ((guint32)abs(sack->tsnumber - y_value)<y_tolerance)
				{
					s_diff = fabs((sack->secs+sack->usecs/1000000.0)- x_value);
					if (s_diff < x_tolerance)
						sack_found = TRUE;
					break;
				}
			}

			for (i=0; i<t_size; i++)
			{
				tsn = (struct tsn_sort*)(g_ptr_array_index(tsnlist, i));
				if ((guint32)abs(tsn->tsnumber - y_value)<y_tolerance)
				{
					t_diff = fabs((tsn->secs+tsn->usecs/1000000.0)- x_value);
					if (sack_found && s_diff < t_diff)
					{
						cf_goto_frame(&cfile, sack->framenumber);
						x_value = sack->secs+sack->usecs/1000000.0;
						y_value = sack->tsnumber;
					}
					else if (t_diff < x_tolerance)
					{
						cf_goto_frame(&cfile, tsn->framenumber);
						x_value = tsn->secs+tsn->usecs/1000000.0;
						y_value = tsn->tsnumber;
					}
					break;
				}
			}

			g_snprintf(label_string, sizeof(label_string), "(%.6lf, %u)", x_value, y_value);

			label_set = TRUE;

			gdk_draw_line(u_data->io->pixmap,text_color, (gint)(event->x-2), (gint)(event->y), (gint)(event->x+2), (gint)(event->y));
			gdk_draw_line(u_data->io->pixmap,text_color, (gint)(event->x), (gint)(event->y-2), (gint)(event->x), (gint)(event->y+2));
			if (event->x+150>=u_data->io->pixmap_width)
				position = event->x - 150;
			else
				position = event->x + 5;


			memcpy(label_string,(gchar *)g_locale_to_utf8(label_string, -1 , NULL, NULL, NULL), 15);
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);

			gdk_draw_layout(u_data->io->pixmap,text_color,
			                (gint)position,
			                (gint)(event->y-10),
			                layout);

			ios=(sctp_graph_t *)g_object_get_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t");
			g_assert(ios != NULL);

			gdk_draw_pixmap(gtk_widget_get_window(u_data->io->draw_area),
#if GTK_CHECK_VERSION(2,18,0)
			                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[gtk_widget_get_state(u_data->io->draw_area)],
#else
			                gtk_widget_get_style(u_data->io->draw_area)->fg_gc[GTK_WIDGET_STATE(u_data->io->draw_area)],
#endif
			                ios->pixmap,
			                0, 0,
			                0, 0,
			                u_data->io->draw_area->allocation.width,
			                u_data->io->draw_area->allocation.height);
		}
	}
	return TRUE;
}


static void
init_sctp_graph_window(struct sctp_udata *u_data)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *bt_close, *tsn_bt, *both_bt, *zoomin_bt;

	/* create the main window */
	u_data->io->window= dlg_window_new("WSCTP Graphics");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(u_data->io->window), TRUE);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(u_data->io->window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(vbox, u_data);

	sctp_graph_set_title(u_data);

	hbox = gtk_hbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_button_box_set_layout(GTK_BUTTON_BOX (hbox), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing(GTK_BOX (hbox), 0);
	gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);
	sack_bt = gtk_button_new_with_label ("Show Only Sacks");
	gtk_box_pack_start(GTK_BOX(hbox), sack_bt, FALSE, FALSE, 0);
	gtk_widget_show(sack_bt);
	g_signal_connect(sack_bt, "clicked", G_CALLBACK(on_sack_bt), u_data);

	tsn_bt = gtk_button_new_with_label ("Show Only TSNs");
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

	gtk_widget_show(u_data->io->window);
}

static void
sctp_graph_set_title(struct sctp_udata *u_data)
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


static void
quit(GtkObject *object _U_, gpointer user_data)
{
	struct sctp_udata *u_data=user_data;

	decrease_childcount(u_data->parent);
	remove_child(u_data, u_data->parent);

	g_free(u_data->io);

	u_data->assoc->min_max = NULL;
	g_free(u_data);
}


static void
create_draw_area(GtkWidget *box, struct sctp_udata *u_data)
{

	u_data->io->draw_area=gtk_drawing_area_new();
	g_signal_connect(u_data->io->draw_area, "destroy", G_CALLBACK(quit), u_data);
	g_object_set_data(G_OBJECT(u_data->io->draw_area), "sctp_graph_t", u_data->io);

	gtk_widget_set_size_request(u_data->io->draw_area, u_data->io->pixmap_width, u_data->io->pixmap_height);

	/* signals needed to handle backing pixmap */
	g_signal_connect(u_data->io->draw_area, "expose_event", G_CALLBACK(expose_event), NULL);
	g_signal_connect(u_data->io->draw_area, "configure_event", G_CALLBACK(configure_event), u_data);

	gtk_widget_show(u_data->io->draw_area);
	gtk_box_pack_start(GTK_BOX(box), u_data->io->draw_area, TRUE, TRUE, 0);
}



void
create_graph(guint16 dir, struct sctp_analyse* userdata)
{
	struct sctp_udata *u_data;

	u_data=g_malloc(sizeof(struct sctp_udata));
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

#if defined(_WIN32) && !defined(__MINGW32__)
/* replacement of Unix rint() for Windows */
static int
rint (double x)
{
	char *buf;
	int i,dec,sig;

	buf = _fcvt(x, 0, &dec, &sig);
	i = atoi(buf);
	if(sig == 1) {
		i = i * -1;
	}
	return(i);
}
#endif
