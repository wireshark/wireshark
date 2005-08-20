/* io_stat.c
 * io_stat   2002 Ronnie Sahlberg
 *
 * $Id$
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <ctype.h>

#include <gtk/gtk.h>

#include <epan/epan_dissect.h>
#include <epan/packet_info.h>

#include "gtkglobals.h"
#include "gui_utils.h"
#include <epan/stat.h>
#include "stat_menu.h"
#include <epan/tap.h>
#include "../register.h"
#include "alert_box.h"
#include "simple_dialog.h"
#include "../globals.h"
#include "../color.h"
#include "compat_macros.h"
#include "dlg_utils.h"
#include "filter_dlg.h"
#include "help_dlg.h"

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

#define MAX_GRAPHS 5

#define MAX_YSCALE 22
#define AUTO_MAX_YSCALE 0
static guint32 yscale_max[MAX_YSCALE] = {AUTO_MAX_YSCALE, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000, 10000000, 20000000, 50000000};

#define MAX_PIXELS_PER_TICK 4
#define DEFAULT_PIXELS_PER_TICK 2
static guint32 pixels_per_tick[MAX_PIXELS_PER_TICK] = {1, 2, 5, 10};


#define DEFAULT_PLOT_STYLE	0
#define PLOT_STYLE_LINE		0
#define PLOT_STYLE_IMPULSE	1
#define PLOT_STYLE_FILLED_BAR	2
#define MAX_PLOT_STYLES		3
static const char *plot_style_name[MAX_PLOT_STYLES] = {
	"Line",
	"Impulse",
	"FBar",
};


#define COUNT_TYPE_FRAMES   0
#define COUNT_TYPE_BYTES    1
#define COUNT_TYPE_ADVANCED 2
#define MAX_COUNT_TYPES 3
static const char *count_type_names[MAX_COUNT_TYPES] = {"Packets/Tick", "Bytes/Tick", "Advanced..."};

/* unit is in ms */
#define MAX_TICK_VALUES 5
#define DEFAULT_TICK_VALUE 3
static const guint tick_interval_values[MAX_TICK_VALUES] = { 1, 10, 100, 1000, 10000 };

#define CALC_TYPE_SUM	0
#define CALC_TYPE_COUNT	1
#define CALC_TYPE_MAX	2
#define CALC_TYPE_MIN	3
#define CALC_TYPE_AVG	4
#define CALC_TYPE_LOAD	5
#define MAX_CALC_TYPES 6
static const char *calc_type_names[MAX_CALC_TYPES] = {"SUM(*)", "COUNT(*)", "MAX(*)", "MIN(*)", "AVG(*)", "LOAD(*)"};


typedef struct _io_stat_calc_type_t {
	struct _io_stat_graph_t *gio;
	int calc_type;
} io_stat_calc_type_t;

#define NUM_IO_ITEMS 100000
typedef struct _io_item_t {
	guint32 frames; /* always calculated, will hold number of frames*/
	guint32 bytes;  /* always calculated, will hold number of bytes*/
	gint32 int_max;
	gint32 int_min;
	gint32 int_tot;
	nstime_t time_max;
	nstime_t time_min;
	nstime_t time_tot;
} io_item_t;

typedef struct _io_stat_graph_t {
	struct _io_stat_t *io;
	io_item_t items[NUM_IO_ITEMS];
	int plot_style;
	gboolean display;
	GtkWidget *display_button;
	GtkWidget *filter_field;
	GtkWidget *advanced_buttons;
	int calc_type;
	io_stat_calc_type_t calc_types[MAX_CALC_TYPES];
	int hf_index;
	GtkWidget *calc_field;
	GdkColor color;
	GdkGC *gc;
	construct_args_t *args;
	GtkWidget *filter_bt;
} io_stat_graph_t;


typedef struct _io_stat_t {
	gboolean needs_redraw;
	gint32 interval;    /* measurement interval in ms */
	guint32 last_interval; 
	guint32 max_interval; /* XXX max_interval and num_items are redundant */
	guint32 num_items;

	struct _io_stat_graph_t graphs[MAX_GRAPHS];
	GtkWidget *window;
	GtkWidget *draw_area;
	GdkPixmap *pixmap;
	GtkAdjustment *scrollbar_adjustment;
	GtkWidget *scrollbar;
	int pixmap_width;
	int pixmap_height;
	int pixels_per_tick;
	int max_y_units;
	int count_type;
} io_stat_t;	

#if GTK_MAJOR_VERSION < 2
GtkRcStyle *rc_style;
GdkColormap *colormap;
#endif



static void init_io_stat_window(io_stat_t *io);

static void
io_stat_set_title(io_stat_t *io)
{
	char		*title;

	if(!io->window){
		return;
	}
	title = g_strdup_printf("Ethereal IO Graphs: %s", cf_get_display_name(&cfile));
	gtk_window_set_title(GTK_WINDOW(io->window), title);
	g_free(title);
}

static void
io_stat_reset(io_stat_t *io)
{
	int i, j;

	io->needs_redraw=TRUE;
	for(i=0;i<MAX_GRAPHS;i++){
		for(j=0;j<NUM_IO_ITEMS;j++){
			io_item_t *ioi;
			ioi=&io->graphs[i].items[j];

			ioi->frames=0;
			ioi->bytes=0;
			ioi->int_max=0;
			ioi->int_min=0;
			ioi->int_tot=0;
			ioi->time_max.secs=0;
			ioi->time_max.nsecs=0;
			ioi->time_min.secs=0;
			ioi->time_min.nsecs=0;
			ioi->time_tot.secs=0;
			ioi->time_tot.nsecs=0;
		}
	}
	io->last_interval=0xffffffff;
	io->max_interval=0;
	io->num_items=0;

	io_stat_set_title(io);
}

static void
gtk_iostat_reset(void *g)
{
	io_stat_graph_t *gio=g;

	io_stat_reset(gio->io);
}

static int
gtk_iostat_packet(void *g, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	io_stat_graph_t *git=g;
	io_item_t *it;
	nstime_t time_delta;
	int idx;

	/* we sometimes get called when git is disabled.
	   this is a bug since the tap listener should be removed first */
	if(!git->display){
		return 0;
	}

	git->io->needs_redraw=TRUE;

	/* 
	 * Find which interval this is supposed to to in and store the
	 * interval index as idx
	 */
	time_delta.secs=pinfo->fd->rel_secs;
	time_delta.nsecs=pinfo->fd->rel_usecs*1000;
	if(time_delta.nsecs<0){
		time_delta.secs--;
		time_delta.nsecs+=1000000000;
	}
	if(time_delta.secs<0){
		return FALSE;
	}
	idx=(time_delta.secs*1000+time_delta.nsecs/1000000)/git->io->interval;

	/* some sanity checks */
	if((idx<0)||(idx>=NUM_IO_ITEMS)){
		return FALSE;
	}

	/* update num_items */
	if((guint32)idx > git->io->num_items){
		git->io->num_items=idx;
		git->io->max_interval=idx*git->io->interval;
	}

	/*
	 * Find the appropriate io_item_t structure 
	 */
	it=&git->items[idx];


	/*
	 * For ADVANCED mode we need to keep track of some more stuff
	 * than just frame and byte counts
	 */
	if(git->io->count_type==COUNT_TYPE_ADVANCED){
		GPtrArray *gp;
		guint i;

		gp=proto_get_finfo_ptr_array(edt->tree, git->hf_index);
		if(!gp){
			return FALSE;
		}

		/* update the appropriate counters, make sure that if 
		 * frames==0 then this is the first seen value so
		 * set any min/max values accordingly 
		 */
		for(i=0;i<gp->len;i++){
			int new_int;
			nstime_t *new_time;

			switch(proto_registrar_get_ftype(git->hf_index)){
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				new_int=fvalue_get_integer(&((field_info *)gp->pdata[i])->value);

				if((new_int>it->int_max)||(it->frames==0)){
					it->int_max=new_int;
				}
				if((new_int<it->int_min)||(it->frames==0)){
					it->int_min=new_int;
				}
				it->int_tot+=new_int;
				break;
			case FT_RELATIVE_TIME:
				new_time=fvalue_get(&((field_info *)gp->pdata[0])->value);

				switch(git->calc_type){
#ifdef G_HAVE_UINT64
					guint64 t, pt; /* time in us */
#else
					guint32 t, pt;
#endif
					int i;
				case CALC_TYPE_LOAD:
					/* it is a LOAD calculation of a relative time field. 
					 * add the time this call spanned to each
					 * interval it spanned according to its contribution 
					 * to that interval.
					 */
					t=new_time->secs;
					t=t*1000000+new_time->nsecs/1000;
					i=idx;
					/* handle current interval */
					pt=pinfo->fd->rel_secs*1000000+pinfo->fd->rel_usecs;
					pt=pt%(git->io->interval*1000);
					if(pt>t){
						pt=t;
					}
					while(t){
						git->items[i].time_tot.nsecs+=pt*1000;
						if(git->items[i].time_tot.nsecs>1000000000){
							git->items[i].time_tot.secs++;
							git->items[i].time_tot.nsecs-=1000000000;
						}

						if(i==0){
							break;
						}
						i--;
						t-=pt;
						if(t > (guint32) (git->io->interval*1000)){
							pt=git->io->interval*1000;
						} else {
							pt=t;
						}
					}
					break;
				default:
					if( (new_time->secs>it->time_max.secs)
					||( (new_time->secs==it->time_max.secs)
					  &&(new_time->nsecs>it->time_max.nsecs))
					||(it->frames==0)){
						it->time_max.secs=new_time->secs;
						it->time_max.nsecs=new_time->nsecs;
					}
					if( (new_time->secs<it->time_min.secs)
					||( (new_time->secs==it->time_min.secs)
					  &&(new_time->nsecs<it->time_min.nsecs))
					||(it->frames==0)){
						it->time_min.secs=new_time->secs;
						it->time_min.nsecs=new_time->nsecs;
					}
					it->time_tot.secs+=new_time->secs;
					it->time_tot.nsecs+=new_time->nsecs;
					if(it->time_tot.nsecs>=1000000000){
						it->time_tot.nsecs-=1000000000;
						it->time_tot.secs++;
					}
				}

			}
		}
	}

	it->frames++;
	it->bytes+=pinfo->fd->pkt_len;
	
	return TRUE;
}


static guint32
get_it_value(io_stat_t *io, int graph_id, int idx)
{
	guint32 value=0;
	int adv_type;
	io_item_t *it;

	it=&io->graphs[graph_id].items[idx];

	switch(io->count_type){
	case COUNT_TYPE_FRAMES:
		return it->frames;
	case COUNT_TYPE_BYTES:
		return it->bytes;
	}


	adv_type=proto_registrar_get_ftype(io->graphs[graph_id].hf_index);
	switch(adv_type){
	case FT_NONE:
		switch(io->graphs[graph_id].calc_type){
		case CALC_TYPE_COUNT:
			value=it->frames;
			break;
		default:
			break;
		}
		break;
	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		switch(io->graphs[graph_id].calc_type){
		case CALC_TYPE_SUM:
			value=it->int_tot;
			break;
		case CALC_TYPE_COUNT:
			value=it->frames;
			break;
		case CALC_TYPE_MAX:
			value=it->int_max;
			break;
		case CALC_TYPE_MIN:
			value=it->int_min;
			break;
		case CALC_TYPE_AVG:
			if(it->frames){
				value=it->int_tot/it->frames;
			} else {
				value=0;
			}
			break;
		default:
			break;
		}
		break;
	case FT_RELATIVE_TIME:
		switch(io->graphs[graph_id].calc_type){
		case CALC_TYPE_COUNT:
			value=it->frames;
			break;
		case CALC_TYPE_MAX:
			value=it->time_max.secs*1000000+it->time_max.nsecs/1000;
			break;
		case CALC_TYPE_MIN:
			value=it->time_min.secs*1000000+it->time_min.nsecs/1000;
			break;
		case CALC_TYPE_SUM:
			value=it->time_tot.secs*1000000+it->time_tot.nsecs/1000;
			break;
		case CALC_TYPE_AVG:
			if(it->frames){
#ifdef G_HAVE_UINT64
				guint64 t; /* time in us */
#else
				guint32 t;
#endif
				t=it->time_tot.secs;
				t=t*1000000+it->time_tot.nsecs/1000;
				value=t/it->frames;
			} else {
				value=0;
			}
			break;
		case CALC_TYPE_LOAD:
			value=(it->time_tot.secs*1000000+it->time_tot.nsecs/1000)/io->interval;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return value;
}


static void
print_time_scale_string(char *buf, int buf_len, guint32 t)
{
	if(t>=10000000){
		g_snprintf(buf, buf_len, "%ds",t/1000000);
	} else if(t>=1000000){
		g_snprintf(buf, buf_len, "%d.%03ds",t/1000000,(t%1000000)/1000);
	} else if(t>=10000){
		g_snprintf(buf, buf_len, "%dms",t/1000);
	} else if(t>=1000){
		g_snprintf(buf, buf_len, "%d.%03dms",t/1000,t%1000);
	} else {
		g_snprintf(buf, buf_len, "%dus",t);
	}
}

static void
io_stat_draw(io_stat_t *io)
{
	int i;
	guint32 last_interval, first_interval, interval_delta, delta_multiplier;
	gint32 current_interval;
	guint32 left_x_border;
	guint32 right_x_border;
	guint32 top_y_border;
	guint32 bottom_y_border;
#if GTK_MAJOR_VERSION < 2
	GdkFont *font;
#else
        PangoLayout  *layout;
#endif
	guint32 label_width, label_height;
	guint32 draw_width, draw_height;
	char label_string[15];

	/* new variables */
	guint32 num_time_intervals;
	guint32 max_value;		/* max value of seen data */
	guint32 max_y;			/* max value of the Y scale */
	gboolean draw_y_as_time;

#if GTK_MAJOR_VERSION <2
	font = io->draw_area->style->font;
#endif

	if(!io->needs_redraw){
		return;
	}
	io->needs_redraw=FALSE;


	/* 
	 * Find the length of the intervals we have data for
	 * so we know how large arrays we need to malloc()
	 */
	num_time_intervals=io->num_items;
	/* if there isnt anything to do, just return */
	if(num_time_intervals==0){
		return;
	}
	num_time_intervals+=1;
	/* XXX move this check to _packet() */
	if(num_time_intervals>NUM_IO_ITEMS){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "IO-Stat error. There are too many entries, bailing out");
		return;
	}


	/* 
	 * find the max value so we can autoscale the y axis
	 */
	max_value=0;
	for(i=0;i<MAX_GRAPHS;i++){
		int idx;

		if(!io->graphs[i].display){
			continue;
		}
		for(idx=0;(guint32) (idx) < num_time_intervals;idx++){
			guint32 val;

			val=get_it_value(io, i, idx);

			/* keep track of the max value we have encountered */
			if(val>max_value){
				max_value=val;
			}
		}
	}



	/* 
	 * Clear out old plot
	 */
        gdk_draw_rectangle(io->pixmap,
                           io->draw_area->style->white_gc,
                           TRUE,
                           0, 0,
                           io->draw_area->allocation.width,
                           io->draw_area->allocation.height);


	/*
	 * Calculate the y scale we should use
	 */
	if(io->max_y_units==AUTO_MAX_YSCALE){
		max_y=yscale_max[MAX_YSCALE-1];
		for(i=MAX_YSCALE-1;i>0;i--){
			if(max_value<yscale_max[i]){
				max_y=yscale_max[i];
			}
		}
	} else {
		/* the user had specified an explicit y scale to use */
		max_y=io->max_y_units;
	}


	/*
	 * If we use ADVANCED and all the graphs are plotting
	 * either MIN/MAX/AVG of an FT_RELATIVE_TIME field
	 * then we will do some some special processing for the
	 * labels for the Y axis below:
	 *   we will append the time unit " s" " ms" or " us"
	 *   and we will present the unit in decimal
	 */
	draw_y_as_time=FALSE;
	if(io->count_type==COUNT_TYPE_ADVANCED){
		draw_y_as_time=TRUE;
		for(i=0;i<MAX_GRAPHS;i++){
			int adv_type;

			if(!io->graphs[i].display){
				continue;
			}
			adv_type=proto_registrar_get_ftype(io->graphs[i].hf_index);
			switch(adv_type){
			case FT_RELATIVE_TIME:
				switch(io->graphs[i].calc_type){
				case CALC_TYPE_SUM:
				case CALC_TYPE_MAX:
				case CALC_TYPE_MIN:
				case CALC_TYPE_AVG:
					break;
				default:
					draw_y_as_time=FALSE;
				}
				break;
			default:
				draw_y_as_time=FALSE;
			}
		}
	}



	/* 
	 * Calculate size of borders surrounding the plot 
	 * The border on the right side needs to be adjusted depending
	 * on the width of the text labels. For simplicity we assume that the
	 * top y scale label will be the widest one
	 */
	if(draw_y_as_time){
		print_time_scale_string(label_string, 15, max_y);
	} else {
		g_snprintf(label_string, 15, "%d", max_y);
	}
#if GTK_MAJOR_VERSION < 2
        label_width=gdk_string_width(font, label_string);
        label_height=gdk_string_height(font, label_string);
#else
        layout = gtk_widget_create_pango_layout(io->draw_area, label_string);
        pango_layout_get_pixel_size(layout, &label_width, &label_height);
#endif
	left_x_border=10;
	right_x_border=label_width+20;
	top_y_border=10;
	bottom_y_border=label_height+20;


	/*
	 * Calculate the size of the drawing area for the actual plot
	 */
	draw_width=io->pixmap_width-right_x_border-left_x_border;
	draw_height=io->pixmap_height-top_y_border-bottom_y_border;


	/* 
	 * Draw the y axis and labels
	 * (we always draw the y scale with 11 ticks along the axis)
	 */
	gdk_draw_line(io->pixmap, io->draw_area->style->black_gc,
		io->pixmap_width-right_x_border+1, 
		top_y_border,
		io->pixmap_width-right_x_border+1, 
		io->pixmap_height-bottom_y_border);
	for(i=0;i<=10;i++){
		int xwidth, lwidth;

		xwidth=5;
		if(!(i%5)){
			/* first, middle and last tick are slightly longer */
			xwidth=10;
		}
		/* draw the tick */
		gdk_draw_line(io->pixmap, io->draw_area->style->black_gc, 
			io->pixmap_width-right_x_border+1, 
			io->pixmap_height-bottom_y_border-draw_height*i/10, 
			io->pixmap_width-right_x_border+1+xwidth, 
			io->pixmap_height-bottom_y_border-draw_height*i/10);
		/* draw the labels */
		if(i==0){
			if(draw_y_as_time){
				print_time_scale_string(label_string, 15, (max_y*i/10));
			} else {
				g_snprintf(label_string, 15, "%d", max_y*i/10);
			}
#if GTK_MAJOR_VERSION < 2
	                lwidth=gdk_string_width(font, label_string);
	                gdk_draw_string(io->pixmap,
        	                        font,
	                                io->draw_area->style->black_gc,
	                                io->pixmap_width-right_x_border+15+label_width-lwidth,
        	                        io->pixmap_height-bottom_y_border-draw_height*i/10+label_height/2,
                	                label_string);
#else
	                pango_layout_set_text(layout, label_string, -1);
	                pango_layout_get_pixel_size(layout, &lwidth, NULL);
			gdk_draw_layout(io->pixmap,
                	                io->draw_area->style->black_gc,
                        	        io->pixmap_width-right_x_border+15+label_width-lwidth,
                                	io->pixmap_height-bottom_y_border-draw_height*i/10-label_height/2,
	                                layout);
#endif
		}
		if(i==5){
			if(draw_y_as_time){
				print_time_scale_string(label_string, 15, (max_y*i/10));
			} else {
				g_snprintf(label_string, 15, "%d", max_y*i/10);
			}
#if GTK_MAJOR_VERSION < 2
	                lwidth=gdk_string_width(font, label_string);
	                gdk_draw_string(io->pixmap,
        	                        font,
	                                io->draw_area->style->black_gc,
	                                io->pixmap_width-right_x_border+15+label_width-lwidth,
        	                        io->pixmap_height-bottom_y_border-draw_height*i/10+label_height/2,
                	                label_string);
#else
	                pango_layout_set_text(layout, label_string, -1);
	                pango_layout_get_pixel_size(layout, &lwidth, NULL);
			gdk_draw_layout(io->pixmap,
                	                io->draw_area->style->black_gc,
                        	        io->pixmap_width-right_x_border+15+label_width-lwidth,
                                	io->pixmap_height-bottom_y_border-draw_height*i/10-label_height/2,
	                                layout);
#endif
		}
		if(i==10){
			if(draw_y_as_time){
				print_time_scale_string(label_string, 15, (max_y*i/10));
			} else {
				g_snprintf(label_string, 15, "%d", max_y*i/10);
			}
#if GTK_MAJOR_VERSION < 2
	                lwidth=gdk_string_width(font, label_string);
	                gdk_draw_string(io->pixmap,
        	                        font,
	                                io->draw_area->style->black_gc,
	                                io->pixmap_width-right_x_border+15+label_width-lwidth,
        	                        io->pixmap_height-bottom_y_border-draw_height*i/10+label_height/2,
                	                label_string);
#else
	                pango_layout_set_text(layout, label_string, -1);
	                pango_layout_get_pixel_size(layout, &lwidth, NULL);
			gdk_draw_layout(io->pixmap,
                	                io->draw_area->style->black_gc,
                        	        io->pixmap_width-right_x_border+15+label_width-lwidth,
                                	io->pixmap_height-bottom_y_border-draw_height*i/10-label_height/2,
	                                layout);
#endif
		}
	}



	/* 
	 * if we have not specified the last_interval via the gui,
	 * then just pick the current end of the capture so that is scrolls
	 * nicely when doing live captures
	 */
	if(io->last_interval==0xffffffff){
		last_interval=io->max_interval;
	} else {
		last_interval=io->last_interval;
	}
	



/*XXX*/
	/* plot the x-scale */
	gdk_draw_line(io->pixmap, io->draw_area->style->black_gc, left_x_border, io->pixmap_height-bottom_y_border+1, io->pixmap_width-right_x_border+1, io->pixmap_height-bottom_y_border+1);

	if((last_interval/io->interval)>draw_width/io->pixels_per_tick+1){
		first_interval=(last_interval/io->interval)-draw_width/io->pixels_per_tick+1;
		first_interval*=io->interval;
	} else {
		first_interval=0;
	}

	interval_delta=1;
	delta_multiplier=5;
	while(interval_delta<((last_interval-first_interval)/10)){
		interval_delta*=delta_multiplier;
		if(delta_multiplier==5){
			delta_multiplier=2;
		} else {
			delta_multiplier=5;
		}
	}

	for(current_interval=last_interval;current_interval>(gint32)first_interval;current_interval=current_interval-io->interval){
		int x, xlen;

		/* if pixels_per_tick is <5, only draw every 10 ticks */
		if((io->pixels_per_tick<10) && (current_interval%(10*io->interval))){
			continue;
		}

		if(current_interval%interval_delta){
			xlen=5;
		} else {
			xlen=10;
		}

		x=draw_width+left_x_border-((last_interval-current_interval)/io->interval)*io->pixels_per_tick;
		gdk_draw_line(io->pixmap, io->draw_area->style->black_gc, 
			x-1-io->pixels_per_tick/2,
			io->pixmap_height-bottom_y_border+1, 
			x-1-io->pixels_per_tick/2,
			io->pixmap_height-bottom_y_border+xlen+1);

		if(xlen==10){
			int lwidth;
			if(io->interval>=1000){
				g_snprintf(label_string, 15, "%ds", current_interval/1000);
			} else if(io->interval>=100){
				g_snprintf(label_string, 15, "%d.%1ds", current_interval/1000,(current_interval/100)%10);
			} else if(io->interval>=10){
				g_snprintf(label_string, 15, "%d.%2ds", current_interval/1000,(current_interval/10)%100);
			} else {
				g_snprintf(label_string, 15, "%d.%3ds", current_interval/1000,current_interval%1000);
			}
#if GTK_MAJOR_VERSION < 2
                        lwidth=gdk_string_width(font, label_string);
                        gdk_draw_string(io->pixmap,
                                        font,
                                        io->draw_area->style->black_gc,
                                        x-1-io->pixels_per_tick/2-lwidth/2,
                                        io->pixmap_height-bottom_y_border+15+label_height,
                                        label_string);
#else
                        pango_layout_set_text(layout, label_string, -1);
                        pango_layout_get_pixel_size(layout, &lwidth, NULL);
                        gdk_draw_layout(io->pixmap,
                                        io->draw_area->style->black_gc,
                                        x-1-io->pixels_per_tick/2-lwidth/2,
                                        io->pixmap_height-bottom_y_border+15,
                                        layout);
#endif
		}

	}
#if GTK_MAJOR_VERSION >= 2
        g_object_unref(G_OBJECT(layout));
#endif



	/* 
	 * Loop over all graphs and draw them 
	 */
	for(i=MAX_GRAPHS-1;i>=0;i--){
		guint32 interval;
		guint32 x_pos, y_pos, prev_x_pos, prev_y_pos;

		if(!io->graphs[i].display){
			continue;
		}

		/* initialize prev x/y to the low left corner of the graph */
		prev_x_pos=draw_width-1-io->pixels_per_tick*((last_interval-first_interval)/io->interval+1)+left_x_border;
		prev_y_pos=draw_height-1+top_y_border;

		for(interval=first_interval+io->interval;interval<=last_interval;interval+=io->interval){
			guint32 val;

			x_pos=draw_width-1-io->pixels_per_tick*((last_interval-interval)/io->interval+1)+left_x_border;

			val=get_it_value(io, i, interval/io->interval);
			if(val>max_y){
				y_pos=0;
			} else {
				y_pos=draw_height-1-(val*draw_height)/max_y+top_y_border;
			}

			/* dont need to draw anything if the segment
			 * is entirely above the top of the graph 
			 */
			if( (prev_y_pos==0) && (y_pos==0) ){
				prev_y_pos=y_pos;
				prev_x_pos=x_pos;
				continue;
			}

			switch(io->graphs[i].plot_style){
			case PLOT_STYLE_LINE:
				gdk_draw_line(io->pixmap, io->graphs[i].gc, 
					prev_x_pos, prev_y_pos, 
					x_pos, y_pos);
				break;
			case PLOT_STYLE_IMPULSE:
				if(val){
					gdk_draw_line(io->pixmap, io->graphs[i].gc, 
						x_pos, draw_height-1+top_y_border,
						x_pos, y_pos);
				}
				break;
			case PLOT_STYLE_FILLED_BAR:
				if(val){
				        gdk_draw_rectangle(io->pixmap,
                        			io->graphs[i].gc, TRUE,
						x_pos-io->pixels_per_tick/2,
						draw_height-1-(val*draw_height)/max_y+top_y_border,
						io->pixels_per_tick,
						(val*draw_height)/max_y);
						
				}
				break;
			}

			prev_y_pos=y_pos;
			prev_x_pos=x_pos;
		}
	}



	gdk_draw_pixmap(io->draw_area->window,
			io->draw_area->style->fg_gc[GTK_WIDGET_STATE(io->draw_area)],
			io->pixmap,
			0, 0,
			0, 0,
			io->pixmap_width, io->pixmap_height);


	/* update the scrollbar */
	io->scrollbar_adjustment->upper=(gfloat) io->max_interval;
	io->scrollbar_adjustment->step_increment=(gfloat) ((last_interval-first_interval)/10);
	io->scrollbar_adjustment->page_increment=(gfloat) (last_interval-first_interval);
	if((last_interval-first_interval)*100 < io->max_interval){
		io->scrollbar_adjustment->page_size=(gfloat) (io->max_interval/100);
	} else {
		io->scrollbar_adjustment->page_size=(gfloat) (last_interval-first_interval);
	}
	io->scrollbar_adjustment->value=last_interval-io->scrollbar_adjustment->page_size;
	gtk_adjustment_changed(io->scrollbar_adjustment);
	gtk_adjustment_value_changed(io->scrollbar_adjustment);

}

static void
io_stat_redraw(io_stat_t *io)
{
	io->needs_redraw=TRUE;
	io_stat_draw(io);
}

static void
gtk_iostat_draw(void *g)
{
	io_stat_graph_t *git=g;

	io_stat_draw(git->io);
}


/* ok we get called with both the filter and the field. 
   make sure the field is part of the filter.
   (make sure and make sure  just append it)
   the field MUST be part of the filter or else we wont
   be able to pick up the field values after the edt tree has been
   pruned 
*/
static GString *
enable_graph(io_stat_graph_t *gio, const char *filter, const char *field)
{
	char real_filter[260];

	gio->display=TRUE;
	
	real_filter[0]=0;
	if(filter){
		/* skip all whitespaces */
		while(*filter){
			if(*filter==' '){
				filter++;
				continue;
			}
			if(*filter=='\t'){
				filter++;
				continue;
			}
			break;
		}
		if(*filter){
			strncpy(real_filter, filter, 255);
			real_filter[255]=0;
		}
	}
	if(field){
		/* skip all whitespaces */
		while(*field){
			if(*field==' '){
				field++;
				continue;
			}
			if(*field=='\t'){
				field++;
				continue;
			}
			break;
		}
		if(*field){
			if(real_filter[0]!=0){
				strcat(real_filter, " && ");
			}
			strncat(real_filter, field, 259-strlen(real_filter));
			real_filter[259]=0;
		}
	}
	return register_tap_listener("frame", gio, real_filter[0]?real_filter:NULL,
	    gtk_iostat_reset, gtk_iostat_packet, gtk_iostat_draw);
}

static void
disable_graph(io_stat_graph_t *gio)
{
	if (gio->display) {
		gio->display=FALSE;
		protect_thread_critical_region();
		remove_tap_listener(gio);
		unprotect_thread_critical_region();
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(gio->display_button),
		    FALSE);
	}
}

static void
gtk_iostat_init(const char *optarg _U_)
{
	io_stat_t *io;
	int i=0;
	static color_t col[MAX_GRAPHS] = {
		{0,	0x0000,	0x0000,	0x0000},
		{0,	0xffff,	0x0000,	0x0000},
		{0,	0x0000,	0xffff,	0x0000},
		{0,	0x0000,	0x0000,	0xffff},
		{0,	0xffff,	0x5000,	0xffff}
	};
	GString *error_string;

	io=g_malloc(sizeof(io_stat_t));
	io->needs_redraw=TRUE;
	io->interval=1000;
	io->window=NULL;
	io->draw_area=NULL;
	io->pixmap=NULL;
	io->scrollbar=NULL;
	io->scrollbar_adjustment=NULL;
	io->pixmap_width=500;
	io->pixmap_height=200;
	io->pixels_per_tick=pixels_per_tick[DEFAULT_PIXELS_PER_TICK];
	io->max_y_units=AUTO_MAX_YSCALE;
	io->count_type=0;
	io->last_interval=0xffffffff;
	io->max_interval=0;
	io->num_items=0;

	for(i=0;i<MAX_GRAPHS;i++){
		io->graphs[i].gc=NULL;
		io->graphs[i].color.pixel=col[i].pixel;
		io->graphs[i].color.red=col[i].red;
		io->graphs[i].color.green=col[i].green;
		io->graphs[i].color.blue=col[i].blue;
		io->graphs[i].display=0;
		io->graphs[i].display_button=NULL;
		io->graphs[i].filter_field=NULL;
		io->graphs[i].advanced_buttons=NULL;
		io->graphs[i].io=io;

		io->graphs[i].args=g_malloc(sizeof(construct_args_t));
		io->graphs[i].args->title = NULL;
		io->graphs[i].args->wants_apply_button=TRUE;
		io->graphs[i].args->activate_on_ok=TRUE;

		io->graphs[i].filter_bt=NULL;
	}
	io_stat_reset(io);

	error_string=enable_graph(&io->graphs[0], NULL, NULL);
	if(error_string){
		fprintf(stderr, "ethereal: Can't attach io_stat tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		io->graphs[0].display=0;
		io->graphs[0].display_button=NULL;
		io->graphs[0].filter_field=NULL;
		io->graphs[0].advanced_buttons=NULL;
		exit(10);
	}			
		
	/* build the GUI */
	init_io_stat_window(io);

	cf_retap_packets(&cfile);
	io_stat_redraw(io);
}

static gint
quit(GtkWidget *widget, GdkEventExpose *event _U_)
{
	int i;
	io_stat_t *io;

	io=(io_stat_t *)OBJECT_GET_DATA(widget, "io_stat_t");

	for(i=0;i<MAX_GRAPHS;i++){
		if(io->graphs[i].display){
			protect_thread_critical_region();
			remove_tap_listener(&io->graphs[i]);
			unprotect_thread_critical_region();

			g_free( (gpointer) (io->graphs[i].args->title) );
			io->graphs[i].args->title=NULL;

			g_free(io->graphs[i].args);
			io->graphs[i].args=NULL;
		}
	}
	g_free(io);

	return TRUE;
}

/* create a new backing pixmap of the appropriate size */
static gint
configure_event(GtkWidget *widget, GdkEventConfigure *event _U_)
{
	int i;
	io_stat_t *io;

	io=(io_stat_t *)OBJECT_GET_DATA(widget, "io_stat_t");
	if(!io){
		exit(10);
	}

	if(io->pixmap){
		gdk_pixmap_unref(io->pixmap);
		io->pixmap=NULL;
	}

	io->pixmap=gdk_pixmap_new(widget->window,
			widget->allocation.width,
			widget->allocation.height,
			-1);
	io->pixmap_width=widget->allocation.width;
	io->pixmap_height=widget->allocation.height;

	gdk_draw_rectangle(io->pixmap,
			widget->style->white_gc,
			TRUE,
			0, 0,
			widget->allocation.width,
			widget->allocation.height);

	/* set up the colors and the GC structs for this pixmap */
	for(i=0;i<MAX_GRAPHS;i++){
		io->graphs[i].gc=gdk_gc_new(io->pixmap);
#if GTK_MAJOR_VERSION < 2
		colormap = gtk_widget_get_colormap (widget);
		if (!gdk_color_alloc (colormap, &io->graphs[i].color)){
			g_warning ("Couldn't allocate color");
		}

		gdk_gc_set_foreground(io->graphs[i].gc, &io->graphs[i].color);
#else
		gdk_gc_set_rgb_fg_color(io->graphs[i].gc, &io->graphs[i].color);
#endif
		
	}

	io_stat_redraw(io);
	return TRUE;
}

static gint
scrollbar_changed(GtkWidget *widget _U_, gpointer data)
{
	io_stat_t *io=(io_stat_t *)data;
	guint32 mi;

	mi=(guint32) (io->scrollbar_adjustment->value+io->scrollbar_adjustment->page_size);
	if(io->last_interval==mi){
		return TRUE;
	}
	if( (io->last_interval==0xffffffff)
	&&  (mi==io->max_interval) ){
		return TRUE;
	}

	io->last_interval=(mi/io->interval)*io->interval;
	io_stat_redraw(io);

	return TRUE;
}

/* redraw the screen from the backing pixmap */
static gint
expose_event(GtkWidget *widget, GdkEventExpose *event)
{
	io_stat_t *io;

	io=(io_stat_t *)OBJECT_GET_DATA(widget, "io_stat_t");
	if(!io){
		exit(10);
	}


	gdk_draw_pixmap(widget->window,
			widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
			io->pixmap,
			event->area.x, event->area.y,
			event->area.x, event->area.y,
			event->area.width, event->area.height);

	return FALSE;
}


static void
create_draw_area(io_stat_t *io, GtkWidget *box)
{
	io->draw_area=gtk_drawing_area_new();
	SIGNAL_CONNECT(io->draw_area, "destroy", quit, io);
	OBJECT_SET_DATA(io->draw_area, "io_stat_t", io);

	WIDGET_SET_SIZE(io->draw_area, io->pixmap_width, io->pixmap_height);

	/* signals needed to handle backing pixmap */
	SIGNAL_CONNECT(io->draw_area, "expose_event", expose_event, NULL);
	SIGNAL_CONNECT(io->draw_area, "configure_event", configure_event, io);

	gtk_widget_show(io->draw_area);
	gtk_box_pack_start(GTK_BOX(box), io->draw_area, TRUE, TRUE, 0);

	/* create the associated scrollbar */
	io->scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
	io->scrollbar=gtk_hscrollbar_new(io->scrollbar_adjustment);
	gtk_widget_show(io->scrollbar);
	gtk_box_pack_start(GTK_BOX(box), io->scrollbar, FALSE, FALSE, 0);
	SIGNAL_CONNECT(io->scrollbar_adjustment, "value_changed", scrollbar_changed, io);
}


static void
tick_interval_select(GtkWidget *item, gpointer key)
{
	int val;
	io_stat_t *io;

	io=(io_stat_t *)key;
	val=(int)OBJECT_GET_DATA(item, "tick_interval");

	io->interval=val;
	cf_retap_packets(&cfile);
	io_stat_redraw(io);
}

static void
pixels_per_tick_select(GtkWidget *item, gpointer key)
{
	int val;
	io_stat_t *io;

	io=(io_stat_t *)key;
	val=(int)OBJECT_GET_DATA(item, "pixels_per_tick");
	io->pixels_per_tick=val;
	io_stat_redraw(io);
}

static void
plot_style_select(GtkWidget *item, gpointer key)
{
	int val;
	io_stat_graph_t *ppt;

	ppt=(io_stat_graph_t *)key;
	val=(int)OBJECT_GET_DATA(item, "plot_style");

	ppt->plot_style=val;

	io_stat_redraw(ppt->io);
}

static void 
create_pixels_per_tick_menu_items(io_stat_t *io, GtkWidget *menu)
{
	char str[5];
	GtkWidget *menu_item;
	int i;

	for(i=0;i<MAX_PIXELS_PER_TICK;i++){
		g_snprintf(str, 5, "%u", pixels_per_tick[i]);
		menu_item=gtk_menu_item_new_with_label(str);

		OBJECT_SET_DATA(menu_item, "pixels_per_tick",
                                GUINT_TO_POINTER(pixels_per_tick[i]));
		SIGNAL_CONNECT(menu_item, "activate", pixels_per_tick_select, io);
		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(menu), menu_item);
	}
	gtk_menu_set_active(GTK_MENU(menu), DEFAULT_PIXELS_PER_TICK);
	return;
}


static void
yscale_select(GtkWidget *item, gpointer key)
{
	int val;
	io_stat_t *io;

	io=(io_stat_t *)key;
	val=(int)OBJECT_GET_DATA(item, "yscale_max");

	io->max_y_units=val;
	io_stat_redraw(io);
}

static void 
create_tick_interval_menu_items(io_stat_t *io, GtkWidget *menu)
{
	char str[15];
	GtkWidget *menu_item;
	int i;

	for(i=0;i<MAX_TICK_VALUES;i++){
		if(tick_interval_values[i]>=1000){
			g_snprintf(str, 15, "%u sec", tick_interval_values[i]/1000);
		} else if(tick_interval_values[i]>=100){
			g_snprintf(str, 15, "0.%1u sec", (tick_interval_values[i]/100)%10);
		} else if(tick_interval_values[i]>=10){
			g_snprintf(str, 15, "0.%02u sec", (tick_interval_values[i]/10)%10);
		} else {
			g_snprintf(str, 15, "0.%03u sec", (tick_interval_values[i])%10);
		}

		menu_item=gtk_menu_item_new_with_label(str);
		OBJECT_SET_DATA(menu_item, "tick_interval",
                                GUINT_TO_POINTER(tick_interval_values[i]));
		SIGNAL_CONNECT(menu_item, "activate", tick_interval_select, (gpointer)io);
		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(menu), menu_item);
	}
	gtk_menu_set_active(GTK_MENU(menu), DEFAULT_TICK_VALUE);
	return;
}

static void 
create_yscale_max_menu_items(io_stat_t *io, GtkWidget *menu)
{
	char str[15];
	GtkWidget *menu_item;
	int i;

	for(i=0;i<MAX_YSCALE;i++){
		if(yscale_max[i]==AUTO_MAX_YSCALE){
			strcpy(str,"Auto");
		} else {
			g_snprintf(str, 15, "%u", yscale_max[i]);
		}
		menu_item=gtk_menu_item_new_with_label(str);
		OBJECT_SET_DATA(menu_item, "yscale_max",
		                GUINT_TO_POINTER(yscale_max[i]));
		SIGNAL_CONNECT(menu_item, "activate", yscale_select, io);
		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(menu), menu_item);
	}
	return;
}

static void
count_type_select(GtkWidget *item, gpointer key)
{
	int val;
	io_stat_t *io;

	io=(io_stat_t *)key;
	val=(int)OBJECT_GET_DATA(item, "count_type");

	io->count_type=val;

	if(io->count_type==COUNT_TYPE_ADVANCED){
		int i;
		for(i=0;i<MAX_GRAPHS;i++){
			disable_graph(&io->graphs[i]);
			gtk_widget_show(io->graphs[i].advanced_buttons);
/* redraw the entire window so the unhidden widgets show up, hopefully */
{GdkRectangle update_rect;
update_rect.x=0;
update_rect.y=0;
update_rect.width=io->window->allocation.width;
update_rect.height=io->window->allocation.height;
gtk_widget_draw(io->window, &update_rect);
}
		}
	} else {
		int i;
		for(i=0;i<MAX_GRAPHS;i++){
			gtk_widget_hide(io->graphs[i].advanced_buttons);
		}
	}

	io_stat_redraw(io);
}

static void 
create_frames_or_bytes_menu_items(io_stat_t *io, GtkWidget *menu)
{
	GtkWidget *menu_item;
	int i;

	for(i=0;i<MAX_COUNT_TYPES;i++){
		menu_item=gtk_menu_item_new_with_label(count_type_names[i]);
		OBJECT_SET_DATA(menu_item, "count_type", GINT_TO_POINTER(i));
		SIGNAL_CONNECT(menu_item, "activate", count_type_select, io);
		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(menu), menu_item);
	}
	return;
}

static void
create_ctrl_menu(io_stat_t *io, GtkWidget *box, const char *name, void (*func)(io_stat_t *io, GtkWidget *menu))
{
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *option_menu;
	GtkWidget *menu;

	hbox=gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	label=gtk_label_new(name);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	option_menu=gtk_option_menu_new();
	menu=gtk_menu_new();
	(*func)(io, menu);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);
	gtk_box_pack_end(GTK_BOX(hbox), option_menu, FALSE, FALSE, 0);
	gtk_widget_show(option_menu);
}

static void
create_ctrl_area(io_stat_t *io, GtkWidget *box)
{
    GtkWidget *frame_vbox;
    GtkWidget *frame;
	GtkWidget *vbox;

	frame_vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(box), frame_vbox);
	gtk_widget_show(frame_vbox);

    frame = gtk_frame_new("X Axis");
	gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
    gtk_container_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
	gtk_widget_show(vbox);

	create_ctrl_menu(io, vbox, "Tick interval:", create_tick_interval_menu_items);
	create_ctrl_menu(io, vbox, "Pixels per tick:", create_pixels_per_tick_menu_items);

    frame = gtk_frame_new("Y Axis");
	gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
    gtk_container_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
	gtk_widget_show(vbox);

    create_ctrl_menu(io, vbox, "Unit:", create_frames_or_bytes_menu_items);
	create_ctrl_menu(io, vbox, "Scale:", create_yscale_max_menu_items);

	return;
}


static gint
filter_callback(GtkWidget *widget _U_, io_stat_graph_t *gio)
{
	const char *filter;
	const char *field;
	header_field_info *hfi;
	dfilter_t *dfilter;

	field=gtk_entry_get_text(GTK_ENTRY(gio->calc_field));

	/* this graph is not active, just update display and redraw */
	if(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gio->display_button))){
		disable_graph(gio);
		io_stat_redraw(gio->io);
		return 0;
	}

	/* first check if the field string is valid */
	if(gio->io->count_type==COUNT_TYPE_ADVANCED){
		/* warn and bail out if there was no field specified */
		if(field==NULL || field[0]==0){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "You didn't specify a field name.");
			disable_graph(gio);
			io_stat_redraw(gio->io);
			return 0;
		}
		/* warn and bail out if the field could not be found */
		hfi=proto_registrar_get_byname(field);
		if(hfi==NULL){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "'%s' isn't a valid field name.", field);
			disable_graph(gio);
			io_stat_redraw(gio->io);
			return 0;
		}
		gio->hf_index=hfi->id;
		/* check that the type is compatible */
		switch(hfi->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			/* these values support all calculations except LOAD */
			switch(gio->calc_type){
			case CALC_TYPE_LOAD:
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "LOAD(*) is only supported for relative-time fields.");
				disable_graph(gio);
				io_stat_redraw(gio->io);
				return 0;
			}
			/* these types support all calculations */
			break;
		case FT_RELATIVE_TIME:
			/* this type only supports COUNT, MAX, MIN, AVG */
			switch(gio->calc_type){
			case CALC_TYPE_SUM:
			case CALC_TYPE_COUNT:
			case CALC_TYPE_MAX:
			case CALC_TYPE_MIN:
			case CALC_TYPE_AVG:
			case CALC_TYPE_LOAD:
				break;
			default:
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "%s is a relative-time field, so %s calculations are not supported on it.",
				    field,
				    calc_type_names[gio->calc_type]);
				disable_graph(gio);
				io_stat_redraw(gio->io);
				return 0;
			}
			break;
		case FT_UINT64:
		case FT_INT64:
			/*
			 * XXX - support this if gint64/guint64 are
			 * available?
			 */
			if(gio->calc_type!=CALC_TYPE_COUNT){
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "%s is a 64-bit integer, so %s calculations are not supported on it.",
				    field,
				    calc_type_names[gio->calc_type]);
				disable_graph(gio);
				io_stat_redraw(gio->io);
				return 0;
			}
			break;
		default:
			/*
			 * XXX - support all operations on floating-point
			 * numbers?
			 */
			if(gio->calc_type!=CALC_TYPE_COUNT){
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "%s doesn't have integral values, so %s calculations are not supported on it.",
				    field,
				    calc_type_names[gio->calc_type]);
				disable_graph(gio);
				io_stat_redraw(gio->io);
				return 0;
			}
			break;
		}
	}

	/* first check if the filter string is valid. */
	filter=gtk_entry_get_text(GTK_ENTRY(gio->filter_field));
	if(!dfilter_compile(filter, &dfilter)) {
		bad_dfilter_alert_box(filter);
		disable_graph(gio);
		io_stat_redraw(gio->io);
		return 0;
	}
	if (dfilter != NULL)
		dfilter_free(dfilter);

	/* ok, we have a valid filter and the graph is active.
	   first just try to delete any previous settings and then apply
	   the new ones.
	*/
	protect_thread_critical_region();
	remove_tap_listener(gio);
	unprotect_thread_critical_region();
	
	io_stat_reset(gio->io);
	enable_graph(gio, filter, field);
	cf_retap_packets(&cfile);
	io_stat_redraw(gio->io);

	return 0;
}


static void
calc_type_select(GtkWidget *item _U_, gpointer key)
{
	io_stat_calc_type_t *ct=(io_stat_calc_type_t *)key;

	ct->gio->calc_type=ct->calc_type;

	/* disable the graph */
	disable_graph(ct->gio);
	io_stat_redraw(ct->gio->io);
}


static void 
create_calc_types_menu_items(io_stat_graph_t *gio, GtkWidget *menu)
{
	GtkWidget *menu_item;
	int i;

	for(i=0;i<MAX_CALC_TYPES;i++){
		gio->calc_types[i].gio=gio;
		gio->calc_types[i].calc_type=i;
		menu_item=gtk_menu_item_new_with_label(calc_type_names[i]);
		SIGNAL_CONNECT(menu_item, "activate", calc_type_select, &gio->calc_types[i]);
		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(menu), menu_item);
	}
	return;
}


static void
create_advanced_menu(io_stat_graph_t *gio, GtkWidget *box, const char *name, void (*func)(io_stat_graph_t *io, GtkWidget *menu))
{
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *option_menu;
	GtkWidget *menu;

	hbox=gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	label=gtk_label_new(name);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	option_menu=gtk_option_menu_new();
	menu=gtk_menu_new();
	(*func)(gio, menu);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);
	gtk_box_pack_end(GTK_BOX(hbox), option_menu, FALSE, FALSE, 0);
	gtk_widget_show(option_menu);
}

static void
create_advanced_field(io_stat_graph_t *gio, GtkWidget *box)
{

	gio->calc_field=gtk_entry_new_with_max_length(50);
	gtk_box_pack_start(GTK_BOX(box), gio->calc_field, FALSE, FALSE, 0);
	gtk_widget_show(gio->calc_field);
	SIGNAL_CONNECT(gio->calc_field, "activate", filter_callback, gio);
}


static void
create_advanced_box(io_stat_graph_t *gio, GtkWidget *box)
{
	GtkWidget *hbox;

	hbox=gtk_hbox_new(FALSE, 0);
	gio->advanced_buttons=hbox;
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_hide(hbox);

	gio->calc_type=CALC_TYPE_SUM;
	create_advanced_menu(gio, hbox, "Calc:", create_calc_types_menu_items);
	create_advanced_field(gio, hbox);
}


static void
filter_button_clicked(GtkWidget *w, gpointer uio)
{
	io_stat_graph_t *gio=(io_stat_graph_t *)uio;

	display_filter_construct_cb(w, gio->args);
	return;
}

static void
create_filter_box(io_stat_graph_t *gio, GtkWidget *box, int num)
{
	GtkWidget *option_menu;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *hbox;
	GtkWidget *label;
        char str[256];
	int i;

	hbox=gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	g_snprintf(str, 256, "Graph %d", num);
    gio->display_button=gtk_toggle_button_new_with_label(str);
	gtk_box_pack_start(GTK_BOX(hbox), gio->display_button, FALSE, FALSE, 0);
	gtk_widget_show(gio->display_button);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(gio->display_button), gio->display);
	SIGNAL_CONNECT(gio->display_button, "toggled", filter_callback, gio);

	label=gtk_label_new("Color");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

#if GTK_MAJOR_VERSION < 2
    /* setting the color of the display button doesn't work */
	rc_style = gtk_rc_style_new ();
	rc_style->fg[GTK_STATE_NORMAL] = gio->color;
	rc_style->color_flags[GTK_STATE_NORMAL] |= GTK_RC_FG;
	rc_style->fg[GTK_STATE_ACTIVE] = gio->color;
	rc_style->color_flags[GTK_STATE_ACTIVE] |= GTK_RC_FG;
	rc_style->fg[GTK_STATE_PRELIGHT] = gio->color;
	rc_style->color_flags[GTK_STATE_PRELIGHT] |= GTK_RC_FG;
	rc_style->fg[GTK_STATE_SELECTED] = gio->color;
	rc_style->color_flags[GTK_STATE_SELECTED] |= GTK_RC_FG;
	rc_style->fg[GTK_STATE_INSENSITIVE] = gio->color;
	rc_style->color_flags[GTK_STATE_INSENSITIVE] |= GTK_RC_FG;
	gtk_widget_modify_style (label, rc_style);
	gtk_rc_style_unref (rc_style);
#else
	gtk_widget_modify_fg(label, GTK_STATE_NORMAL, &gio->color); 
	gtk_widget_modify_fg(label, GTK_STATE_ACTIVE, &gio->color); 
	gtk_widget_modify_fg(label, GTK_STATE_PRELIGHT, &gio->color); 
	gtk_widget_modify_fg(label, GTK_STATE_SELECTED, &gio->color); 
	gtk_widget_modify_fg(label, GTK_STATE_INSENSITIVE, &gio->color); 
#endif
/*	gtk_signal_connect(GTK_OBJECT(gio->display_button), "toggled", GTK_SIGNAL_FUNC(filter_callback), gio);*/


	/* filter prefs dialog */
	gio->filter_bt=BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_DISPLAY_FILTER_ENTRY);

	g_snprintf(str, 256, "Ethereal: Display Filter  IO-Stat (Filter:%d)", num);
	if(gio->args->title){
		g_free( (gpointer) (gio->args->title) );
	}
	gio->args->title=g_strdup(str);	

	SIGNAL_CONNECT(gio->filter_bt, "clicked", filter_button_clicked, gio);
	SIGNAL_CONNECT(gio->filter_bt, "destroy", filter_button_destroy_cb, NULL);

	gtk_box_pack_start(GTK_BOX(hbox), gio->filter_bt, FALSE, TRUE, 0);
	gtk_widget_show(gio->filter_bt);

	gio->filter_field=gtk_entry_new_with_max_length(256);

	/* filter prefs dialog */
	OBJECT_SET_DATA(gio->filter_bt, E_FILT_TE_PTR_KEY, gio->filter_field);
	/* filter prefs dialog */

	gtk_box_pack_start(GTK_BOX(hbox), gio->filter_field, FALSE, FALSE, 0);
	gtk_widget_show(gio->filter_field);
	SIGNAL_CONNECT(gio->filter_field, "activate", filter_callback, gio);
    SIGNAL_CONNECT(gio->filter_field, "changed", filter_te_syntax_check_cb, NULL);

	create_advanced_box(gio, hbox);


	/*
	 * create PlotStyle menu
	 */
	g_snprintf(str, 256, " Style:");
	label=gtk_label_new(str);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	option_menu=gtk_option_menu_new();
	menu=gtk_menu_new();
	for(i=0;i<MAX_PLOT_STYLES;i++){
		menu_item=gtk_menu_item_new_with_label(plot_style_name[i]);
		OBJECT_SET_DATA(menu_item, "plot_style", GINT_TO_POINTER(i));
		SIGNAL_CONNECT(menu_item, "activate", plot_style_select, &gio->io->graphs[num-1]);
		gtk_widget_show(menu_item);
		gtk_menu_append(GTK_MENU(menu), menu_item);
	}
	gtk_menu_set_active(GTK_MENU(menu), DEFAULT_PLOT_STYLE);

	gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);
	gtk_box_pack_end(GTK_BOX(hbox), option_menu, FALSE, FALSE, 0);
	gtk_widget_show(option_menu);


	return;
}

static void
create_filter_area(io_stat_t *io, GtkWidget *box)
{
	GtkWidget *frame;
	GtkWidget *vbox;
	int i;

    frame=gtk_frame_new("Graphs");
	gtk_container_add(GTK_CONTAINER(box), frame);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
    gtk_container_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(vbox);

	for(i=0;i<MAX_GRAPHS;i++){
		create_filter_box(&io->graphs[i], vbox, i+1);
	}

	return;
}


static void 
init_io_stat_window(io_stat_t *io)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *bbox;
    GtkWidget *close_bt, *help_bt;

	/* create the main window */
	io->window=window_new(GTK_WINDOW_TOPLEVEL, "I/O Graphs");

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(io->window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(io, vbox);

	hbox=gtk_hbox_new(FALSE, 3);
	gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
    gtk_container_border_width(GTK_CONTAINER(hbox), 3);
	gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	create_filter_area(io, hbox);
	create_ctrl_area(io, hbox);

	io_stat_set_title(io);

    if(topic_available(HELP_STATS_IO_GRAPH_DIALOG)) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    }
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(io->window, close_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_IO_GRAPH_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_IO_GRAPH_DIALOG);
    }

    SIGNAL_CONNECT(io->window, "delete_event", window_delete_event_cb, NULL);

    gtk_widget_show(io->window);
    window_present(io->window);
}


static void 
gtk_iostat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	gtk_iostat_init(NULL);
}




void
register_tap_listener_gtk_iostat(void)
{
	register_stat_cmd_arg("io,stat", gtk_iostat_init);

	register_stat_menu_item("_IO Graphs", REGISTER_STAT_GROUP_GENERIC,
        gtk_iostat_cb, NULL, NULL, NULL);
}
