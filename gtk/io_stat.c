/* io_stat.c
 * io_stat   2002 Ronnie Sahlberg
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#include <gtk/gtk.h>

#include <epan/epan_dissect.h>
#include <epan/packet_info.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/strutil.h>

#include "../stat_menu.h"
#include "../alert_box.h"
#include "../simple_dialog.h"
#include "../color.h"

#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/stock_icons.h"
#include "gtk/dlg_utils.h"
#include "gtk/filter_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/pixmap_save.h"
#include "gtk/main.h"
#include "gtk/filter_autocomplete.h"

#include "gtk/old-gtk-compat.h"

#define MAX_GRAPHS 5

#define MAX_YSCALE 28
#define LOGARITHMIC_YSCALE 0
#define AUTO_MAX_YSCALE 1
#define DEFAULT_YSCALE_INDEX 1
static guint32 yscale_max[MAX_YSCALE] = {LOGARITHMIC_YSCALE, AUTO_MAX_YSCALE, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000, 5000000, 10000000, 20000000, 50000000, 100000000, 200000000, 500000000, 1000000000, 2000000000};

#define MAX_PIXELS_PER_TICK 4
#define DEFAULT_PIXELS_PER_TICK_INDEX 2
static guint32 pixels_per_tick[MAX_PIXELS_PER_TICK] = {1, 2, 5, 10};


#define DEFAULT_PLOT_STYLE	0
#define PLOT_STYLE_LINE		0
#define PLOT_STYLE_IMPULSE	1
#define PLOT_STYLE_FILLED_BAR	2
#define PLOT_STYLE_DOT		3
#define MAX_PLOT_STYLES		4
static const char *plot_style_name[MAX_PLOT_STYLES] = {
	"Line",
	"Impulse",
	"FBar",
	"Dot",
};

#define DEFAULT_COUNT_TYPE  0
#define COUNT_TYPE_FRAMES   0
#define COUNT_TYPE_BYTES    1
#define COUNT_TYPE_BITS     2
#define COUNT_TYPE_ADVANCED 3
#define MAX_COUNT_TYPES     4
static const char *count_type_names[MAX_COUNT_TYPES] = {"Packets/Tick", "Bytes/Tick", "Bits/Tick", "Advanced..."};

/* unit is in ms */
#define MAX_TICK_VALUES 7
#define DEFAULT_TICK_VALUE_INDEX 3
static const guint tick_interval_values[MAX_TICK_VALUES] = { 1, 10, 100, 1000, 10000, 60000, 600000 };

#define CALC_TYPE_SUM	0
#define CALC_TYPE_COUNT	1
#define CALC_TYPE_MAX	2
#define CALC_TYPE_MIN	3
#define CALC_TYPE_AVG	4
#define CALC_TYPE_LOAD	5
#define MAX_CALC_TYPES  6
#define DEFAULT_CALC_TYPE 0
static const char *calc_type_names[MAX_CALC_TYPES] = {"SUM(*)", "COUNT(*)", "MAX(*)", "MIN(*)", "AVG(*)", "LOAD(*)"};


typedef struct _io_stat_calc_type_t {
	struct _io_stat_graph_t *gio;
	int calc_type;
} io_stat_calc_type_t;

#define NUM_IO_ITEMS 100000
typedef struct _io_item_t {
	guint32 frames; /* always calculated, will hold number of frames*/
	guint32 bytes;  /* always calculated, will hold number of bytes*/
	guint32 fields;
	gint32 int_max;
	gint32 int_min;
	gint32 int_tot;
	gfloat float_max;
	gfloat float_min;
	gfloat float_tot;
	gdouble double_max;
	gdouble double_min;
	gdouble double_tot;
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
	int hf_index;
	GtkWidget *calc_field;
	GdkColor color;
#if GTK_CHECK_VERSION(2,22,0)
#else
	GdkGC *gc;
#endif
	construct_args_t *args;
	GtkWidget *filter_bt;
} io_stat_graph_t;


typedef struct _io_stat_t {
	gboolean needs_redraw;
	gint32 interval;      /* measurement interval in ms */
	guint32 last_interval;
	guint32 max_interval; /* XXX max_interval and num_items are redundant */
	guint32 num_items;
	guint32 left_x_border;
	guint32 right_x_border;
	gboolean view_as_time;
	nstime_t start_time;

	struct _io_stat_graph_t graphs[MAX_GRAPHS];
	GtkWidget *window;
	GtkWidget *draw_area;
	GdkPixmap *pixmap;
	GtkAdjustment *scrollbar_adjustment;
	GtkWidget *scrollbar;
	guint first_frame_num[NUM_IO_ITEMS];
	guint last_frame_num;
	int pixmap_width;
	int pixmap_height;
	int pixels_per_tick;
	int max_y_units;
	int count_type;
} io_stat_t;


static void init_io_stat_window(io_stat_t *io);
static void filter_callback(GtkWidget *widget _U_, gpointer user_data);

static void
io_stat_set_title(io_stat_t *io)
{
	char		*title;

	if(!io->window){
		return;
	}
	title = g_strdup_printf("Wireshark IO Graphs: %s", cf_get_display_name(&cfile));
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
			ioi->fields=0;
			ioi->int_max=0;
			ioi->int_min=0;
			ioi->int_tot=0;
			ioi->float_max=0;
			ioi->float_min=0;
			ioi->float_tot=0;
			ioi->double_max=0;
			ioi->double_min=0;
			ioi->double_tot=0;
			nstime_set_zero(&ioi->time_max);
			nstime_set_zero(&ioi->time_min);
			nstime_set_zero(&ioi->time_tot);
		}
	}
	io->last_interval=0xffffffff;
	io->max_interval=0;
	io->num_items=0;
	io->start_time.secs=0;
	io->start_time.nsecs=0;
	for(j=0;j<NUM_IO_ITEMS;j++) {
		io->first_frame_num[j]=0;
	}
	io->last_frame_num=0;

	io_stat_set_title(io);
}

static void
tap_iostat_reset(void *g)
{
	io_stat_graph_t *gio=g;

	io_stat_reset(gio->io);
}

static gboolean
tap_iostat_packet(void *g, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	io_stat_graph_t *git=g;
	io_item_t *it;
	nstime_t time_delta;
	int idx;

	/* we sometimes get called when git is disabled.
	   this is a bug since the tap listener should be removed first */
	if(!git->display){
		return FALSE;
	}

	git->io->needs_redraw=TRUE;

	/*
	 * Find which interval this is supposed to go in and store the
	 * interval index as idx
	 */
	time_delta=pinfo->fd->rel_ts;
	if(time_delta.nsecs<0){
		time_delta.secs--;
		time_delta.nsecs+=1000000000;
	}
	if(time_delta.secs<0){
		return FALSE;
	}
	idx=(int) ((time_delta.secs*1000+time_delta.nsecs/1000000)/git->io->interval);

	/* some sanity checks */
	if((idx<0)||(idx>=NUM_IO_ITEMS)){
		git->io->num_items = NUM_IO_ITEMS-1;
		return FALSE;
	}

	/* update num_items */
	if((guint32)idx > git->io->num_items){
		git->io->num_items=idx;
		git->io->max_interval=(idx+1)*git->io->interval;
	}

	/* set start time */
	if(git->io->start_time.secs == 0 && git->io->start_time.nsecs == 0) {
		nstime_diff (&git->io->start_time, &pinfo->fd->abs_ts, &pinfo->fd->rel_ts);
	}

	/* set first and last frame num in current interval */
	if (git->io->first_frame_num[idx] == 0) {
		git->io->first_frame_num[idx]=pinfo->fd->num;
	}
	git->io->last_frame_num=pinfo->fd->num;

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
		 * fields==0 then this is the first seen value so
		 * set any min/max values accordingly
		 */
		for(i=0;i<gp->len;i++){
			int new_int;
			float new_float;
			double new_double;
			nstime_t *new_time;

			switch(proto_registrar_get_ftype(git->hf_index)){
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				new_int=fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);

				if((new_int>it->int_max)||(it->fields==0)){
					it->int_max=new_int;
				}
				if((new_int<it->int_min)||(it->fields==0)){
					it->int_min=new_int;
				}
				it->int_tot+=new_int;
				it->fields++;
				break;
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				new_int=fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
				if((new_int>it->int_max)||(it->fields==0)){
					it->int_max=new_int;
				}
				if((new_int<it->int_min)||(it->fields==0)){
					it->int_min=new_int;
				}
				it->int_tot+=new_int;
				it->fields++;
				break;
			case FT_FLOAT:
				new_float=(gfloat)fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
				if((new_float>it->float_max)||(it->fields==0)){
					it->float_max=new_float;
				}
				if((new_float<it->float_min)||(it->fields==0)){
					it->float_min=new_float;
				}
				it->float_tot+=new_float;
				it->fields++;
				break;
			case FT_DOUBLE:
				new_double=fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
				if((new_double>it->double_max)||(it->fields==0)){
					it->double_max=new_double;
				}
				if((new_double<it->double_min)||(it->fields==0)){
					it->double_min=new_double;
				}
				it->double_tot+=new_double;
				it->fields++;
				break;
			case FT_RELATIVE_TIME:
				new_time=fvalue_get(&((field_info *)gp->pdata[0])->value);

				switch(git->calc_type){
					guint64 t, pt; /* time in us */
					int j;
				case CALC_TYPE_LOAD:
					/* it is a LOAD calculation of a relative time field.
					 * add the time this call spanned to each
					 * interval it spanned according to its contribution
					 * to that interval.
					 */
					t=new_time->secs;
					t=t*1000000+new_time->nsecs/1000;
					j=idx;
					/* handle current interval */
					pt=pinfo->fd->rel_ts.secs*1000000+pinfo->fd->rel_ts.nsecs/1000;
					pt=pt%(git->io->interval*1000);
					if(pt>t){
						pt=t;
					}
					while(t){
						git->items[j].time_tot.nsecs+=(int) (pt*1000);
						if(git->items[j].time_tot.nsecs>1000000000){
							git->items[j].time_tot.secs++;
							git->items[j].time_tot.nsecs-=1000000000;
						}

						if(j==0){
							break;
						}
						j--;
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
					||(it->fields==0)){
						it->time_max=*new_time;
					}
					if( (new_time->secs<it->time_min.secs)
					||( (new_time->secs==it->time_min.secs)
					  &&(new_time->nsecs<it->time_min.nsecs))
					||(it->fields==0)){
						it->time_min=*new_time;
					}
					nstime_add(&it->time_tot, new_time);
					it->fields++;
				}
			}
		}
	}

	it->frames++;
	it->bytes+=pinfo->fd->pkt_len;

	return TRUE;
}

static guint
get_frame_num(io_stat_t *io, guint32 idx, gboolean first)
{
	guint i, frame_num=0;

	if (idx>io->num_items) {
		return 0;
	}

	if (first) {
		frame_num=io->first_frame_num[idx];
	}

	if (frame_num==0) {
		/*
		 * If first frame not found we select the last
		 * frame in the previous interval
		 *
		 * If selecting the last frame we select the frame
		 * before the first frame in the next interval
		 */
		for(i=idx+1;i<=io->num_items;i++) {
			frame_num=io->first_frame_num[i];
			if (frame_num != 0) {
				return frame_num-1;
			}
		}

		/*
		 * If not found we select the last frame
		 */
		frame_num=io->last_frame_num;
	}

	return frame_num;
}

static guint32
get_it_value(io_stat_t *io, int graph_id, int idx)
{
	double value=0;
	int adv_type;
	io_item_t *it;

	it=&io->graphs[graph_id].items[idx];

	switch(io->count_type){
	case COUNT_TYPE_FRAMES:
		return it->frames;
	case COUNT_TYPE_BYTES:
		return it->bytes;
	case COUNT_TYPE_BITS:
		return (it->bytes * 8);
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
			if(it->fields){
				value=it->int_tot/it->fields;
			} else {
				value=0;
			}
			break;
		default:
			break;
		}
		break;
	case FT_FLOAT:
		switch(io->graphs[graph_id].calc_type){
		case CALC_TYPE_SUM:
			value=it->float_tot;
			break;
		case CALC_TYPE_COUNT:
			value=it->frames;
			break;
		case CALC_TYPE_MAX:
			value=it->float_max;
			break;
		case CALC_TYPE_MIN:
			value=it->float_min;
			break;
		case CALC_TYPE_AVG:
			if(it->fields){
				value=it->float_tot/it->fields;
			} else {
				value=0;
			}
			break;
		default:
			break;
		}
		break;
	case FT_DOUBLE:
		switch(io->graphs[graph_id].calc_type){
		case CALC_TYPE_SUM:
			value=it->double_tot;
			break;
		case CALC_TYPE_COUNT:
			value=it->frames;
			break;
		case CALC_TYPE_MAX:
			value=it->double_max;
			break;
		case CALC_TYPE_MIN:
			value=it->double_min;
			break;
		case CALC_TYPE_AVG:
			if(it->fields){
				value=it->double_tot/it->fields;
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
			value=(guint32) (it->time_max.secs*1000000+it->time_max.nsecs/1000);
			break;
		case CALC_TYPE_MIN:
			value=(guint32) (it->time_min.secs*1000000+it->time_min.nsecs/1000);
			break;
		case CALC_TYPE_SUM:
			value=(guint32) (it->time_tot.secs*1000000+it->time_tot.nsecs/1000);
			break;
		case CALC_TYPE_AVG:
			if(it->fields){
				guint64 t; /* time in us */

				t=it->time_tot.secs;
				t=t*1000000+it->time_tot.nsecs/1000;
				value=(guint32) (t/it->fields);
			} else {
				value=0;
			}
			break;
		case CALC_TYPE_LOAD:
			value=(guint32) ((it->time_tot.secs*1000000+it->time_tot.nsecs/1000)/io->interval);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return (guint32)value; /* FIXME: loss of precision, visible on the graph for small values */
}

static void
print_time_scale_string(char *buf, int buf_len, guint32 t, guint32 t_max, gboolean log_flag)
{
	if(t_max>=10000000 || (log_flag && t_max>=1000000)){
		g_snprintf(buf, buf_len, "%ds",t/1000000);
	} else if(t_max>=1000000){
		g_snprintf(buf, buf_len, "%d.%1ds",t/1000000,(t%1000000)/100000);
	} else if(t_max>=10000 || (log_flag && t_max>=1000)){
		g_snprintf(buf, buf_len, "%dms",t/1000);
	} else if(t_max>=1000){
		g_snprintf(buf, buf_len, "%d.%1dms",t/1000,(t%1000)/100);
	} else {
		g_snprintf(buf, buf_len, "%dus",t);
	}
}

static void
print_interval_string(char *buf, int buf_len, guint32 interval, io_stat_t *io,
		      gboolean ext)
{
	if (io->view_as_time) {
		struct tm *tmp;
		time_t sec_val = interval/1000 + io->start_time.secs;
		gint32 nsec_val = interval%1000 + io->start_time.nsecs/1000000;

		if(nsec_val >= 1000) {
			sec_val++;
			nsec_val -= 1000;
		}
		tmp = localtime (&sec_val);
		if(io->interval>=1000){
			g_snprintf(buf, buf_len, "%02d:%02d:%02d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
		} else if(io->interval>=100){
			g_snprintf(buf, buf_len, "%02d:%02d:%02d.%1d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val/100);
		} else if(io->interval>=10){
			g_snprintf(buf, buf_len, "%02d:%02d:%02d.%02d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val/10);
		} else {
			g_snprintf(buf, buf_len, "%02d:%02d:%02d.%03d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val);
		}
	} else {
		if (!ext) {
			g_snprintf(buf, buf_len, "%d.%03d", interval/1000,interval%1000);
		} else if(io->interval>=60000){
			g_snprintf(buf, buf_len, "%dm", interval/60000);
		} else if(io->interval>=1000){
			g_snprintf(buf, buf_len, "%ds", interval/1000);
		} else if(io->interval>=100){
			g_snprintf(buf, buf_len, "%d.%1ds", interval/1000,(interval/100)%10);
		} else if(io->interval>=10){
			g_snprintf(buf, buf_len, "%d.%02ds", interval/1000,(interval/10)%100);
		} else {
			g_snprintf(buf, buf_len, "%d.%03ds", interval/1000,interval%1000);
		}
	}
}

static void
io_stat_draw(io_stat_t *io)
{
	int i, tics, ystart, ys;
	guint32 last_interval, first_interval, interval_delta;
	gint32 current_interval;
	guint32 top_y_border;
	guint32 bottom_y_border;
	PangoLayout  *layout;
	int label_width, label_height;
	guint32 draw_width, draw_height;
	char label_string[45];

	/* new variables */
	guint32 num_time_intervals;
	guint32 max_value;		/* max value of seen data */
	guint32 max_y;			/* max value of the Y scale */
	gboolean draw_y_as_time;
#if GTK_CHECK_VERSION(2,22,0)
	cairo_t *cr;
#endif
	if(!io->needs_redraw){
		return;
	}
	io->needs_redraw=FALSE;

	/*
	 * Find the length of the intervals we have data for
	 * so we know how large arrays we need to malloc()
	 */
	num_time_intervals=io->num_items+1;

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
#if GTK_CHECK_VERSION(2,22,0)
	cr = gdk_cairo_create (io->pixmap);
	cairo_set_source_rgb (cr, 1, 1, 1);
	cairo_rectangle (cr, 0, 0, io->draw_area->allocation.width,io->draw_area->allocation.height);
	/*gdk_cairo_set_source_color (cr, &widget->style->base[widget->state]);*/
	cairo_fill (cr);
	cairo_destroy (cr);
#else
	gdk_draw_rectangle(io->pixmap,
			   gtk_widget_get_style(io->draw_area)->white_gc,
			   TRUE,
			   0, 0,
			   io->draw_area->allocation.width,
			   io->draw_area->allocation.height);
#endif
	/*
	 * Calculate the y scale we should use
	 */
	if(io->max_y_units==AUTO_MAX_YSCALE){
		max_y=yscale_max[MAX_YSCALE-1];
		for(i=MAX_YSCALE-1;i>1;i--){
			if(max_value<yscale_max[i]){
				max_y=yscale_max[i];
			}
		}
	} else if(io->max_y_units==LOGARITHMIC_YSCALE){
		max_y=1000000000;
		for(i=1000000000;i>1;i/=10){
			if(max_value<(guint32)i){
				max_y=i;
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
		if(io->max_y_units==LOGARITHMIC_YSCALE){
			print_time_scale_string(label_string, 15, 100000, 100000, TRUE); /* 100 ms */
		} else {
			print_time_scale_string(label_string, 15, max_y, max_y, FALSE);
		}
	} else {
		g_snprintf(label_string, 15, "%d", max_y);
	}
	layout = gtk_widget_create_pango_layout(io->draw_area, label_string);
	pango_layout_get_pixel_size(layout, &label_width, &label_height);

	io->left_x_border=10;
	io->right_x_border=label_width+20;
	top_y_border=10;
	bottom_y_border=label_height+20;


	/*
	 * Calculate the size of the drawing area for the actual plot
	 */
	draw_width=io->pixmap_width-io->right_x_border-io->left_x_border;
	draw_height=io->pixmap_height-top_y_border-bottom_y_border;


	/*
	 * Add a warning if too many entries
	 */
	if (num_time_intervals == NUM_IO_ITEMS) {
		g_snprintf (label_string, 45, "Warning: Graph limited to %d entries", NUM_IO_ITEMS);
		pango_layout_set_text(layout, label_string, -1);

		gdk_draw_layout(io->pixmap,
				gtk_widget_get_style(io->draw_area)->black_gc, 5,
				io->pixmap_height-bottom_y_border-draw_height-label_height/2,
				layout);
	}

	/*
	 * Draw the y axis and labels
	 * (we always draw the y scale with 11 ticks along the axis)
	 */
#if GTK_CHECK_VERSION(2,22,0)
	cr = gdk_cairo_create (io->pixmap);
	/*cairo_set_source_rgb(cr, 0, 0, 0);*/
	cairo_set_line_width (cr, 1.0);
	/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
	cairo_move_to(cr, io->pixmap_width-io->right_x_border+1.5, top_y_border+0.5);
	cairo_line_to(cr, io->pixmap_width-io->right_x_border+1.5,io->pixmap_height-bottom_y_border+0.5);
	cairo_stroke(cr);
	cairo_destroy(cr);
#else
	gdk_draw_line(io->pixmap, gtk_widget_get_style(io->draw_area)->black_gc,
		io->pixmap_width-io->right_x_border+1,
		top_y_border,
		io->pixmap_width-io->right_x_border+1,
		io->pixmap_height-bottom_y_border);
#endif
	if(io->max_y_units==LOGARITHMIC_YSCALE){
		tics=(int)log10((double)max_y);
		ystart=draw_height/10;
		ys=-1;
	} else {
		tics=10;
		ystart=ys=0;
	}

	for(i=ys;i<=tics;i++){
		int xwidth, lwidth, ypos;

		xwidth=5;
		if(io->max_y_units==LOGARITHMIC_YSCALE){
			if(i==ys) {
				/* position for the 0 value */
				ypos=io->pixmap_height-bottom_y_border;
			} else if(i==tics) {
				/* position for the top value, do not draw logarithmic tics above graph */
				ypos=io->pixmap_height-bottom_y_border-draw_height;
			} else {
				int j;
				/* draw the logarithmic tics */
				for(j=2;j<10;j++) {
					ypos=(int)(io->pixmap_height-bottom_y_border-(draw_height-ystart)*(i+log10((double)j))/tics-ystart);
					/* draw the tick */
#if GTK_CHECK_VERSION(2,22,0)
					cr = gdk_cairo_create (io->pixmap);
					/*cairo_set_source_rgb(cr, 0, 0, 0);*/
					cairo_set_line_width (cr, 1.0);
					/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
					cairo_move_to(cr, io->pixmap_width-io->right_x_border+1.5, ypos+0.5);
					cairo_line_to(cr, io->pixmap_width-io->right_x_border+1.5+xwidth,ypos+0.5);
					cairo_stroke(cr);
					cairo_destroy(cr);
#else
					gdk_draw_line(io->pixmap, gtk_widget_get_style(io->draw_area)->black_gc,
						      io->pixmap_width-io->right_x_border+1, ypos,
						      io->pixmap_width-io->right_x_border+1+xwidth, ypos);
#endif
				}
				ypos=io->pixmap_height-bottom_y_border-(draw_height-ystart)*i/tics-ystart;
			}
			/* all "main" logarithmic lines are slightly longer */
			xwidth=10;
		} else {
			if(!(i%5)){
				/* first, middle and last tick are slightly longer */
				xwidth=10;
			}
			ypos=io->pixmap_height-bottom_y_border-draw_height*i/10;
		}
		/* draw the tick */
#if GTK_CHECK_VERSION(2,22,0)
		cr = gdk_cairo_create (io->pixmap);
		/*cairo_set_source_rgb(cr, 0, 0, 0);*/
		cairo_set_line_width (cr, 1.0);
		/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
		cairo_move_to(cr, io->pixmap_width-io->right_x_border+1.5, ypos+0.5);
		cairo_line_to(cr, io->pixmap_width-io->right_x_border+1.5+xwidth,ypos+0.5);
		cairo_stroke(cr);
		cairo_destroy(cr);
#else
		gdk_draw_line(io->pixmap, gtk_widget_get_style(io->draw_area)->black_gc,
			      io->pixmap_width-io->right_x_border+1, ypos,
			      io->pixmap_width-io->right_x_border+1+xwidth, ypos);
#endif
		/* draw the labels */
		if(xwidth==10) {
			guint32 value;
			if(io->max_y_units==LOGARITHMIC_YSCALE){
				value=(guint32)(max_y/pow(10,tics-i));
				if(draw_y_as_time){
					print_time_scale_string(label_string, 15, value, value, TRUE);
				} else {
					g_snprintf(label_string, 15, "%d", value);
				}
			} else {
				value=(max_y/10)*i;
				if(draw_y_as_time){
					print_time_scale_string(label_string, 15, value, max_y, FALSE);
				} else {
					g_snprintf(label_string, 15, "%d", value);
				}
			}

	        pango_layout_set_text(layout, label_string, -1);
	        pango_layout_get_pixel_size(layout, &lwidth, NULL);

			gdk_draw_layout(io->pixmap,
					gtk_widget_get_style(io->draw_area)->black_gc,
					io->pixmap_width-io->right_x_border+15+label_width-lwidth,
					ypos-label_height/2,
	                layout);
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
#if GTK_CHECK_VERSION(2,22,0)
		cr = gdk_cairo_create (io->pixmap);
		/*cairo_set_source_rgb(cr, 0, 0, 0);*/
		cairo_set_line_width (cr, 1.0);
		/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
		cairo_move_to(cr, io->left_x_border+0.5, io->pixmap_height-bottom_y_border+1.5);
		cairo_line_to(cr, io->pixmap_width-io->right_x_border+1.5,io->pixmap_height-bottom_y_border+1.5);
		cairo_stroke(cr);
		cairo_destroy(cr);
#else
	gdk_draw_line(io->pixmap, gtk_widget_get_style(io->draw_area)->black_gc, 
		io->left_x_border, 
		io->pixmap_height-bottom_y_border+1, 
		io->pixmap_width-io->right_x_border+1, 
		io->pixmap_height-bottom_y_border+1);

#endif
	if((last_interval/io->interval)>=draw_width/io->pixels_per_tick){
		first_interval=(last_interval/io->interval)-draw_width/io->pixels_per_tick+1;
		first_interval*=io->interval;
	} else {
		first_interval=0;
	}

	interval_delta=(100/io->pixels_per_tick)*io->interval;
	for(current_interval=last_interval;current_interval>=(gint32)first_interval;current_interval=current_interval-io->interval){
		int x, xlen;

		/* if pixels_per_tick is 1 or 2, only draw every 10 ticks */
		/* if pixels_per_tick is 5, only draw every 5 ticks */
		if(((io->pixels_per_tick<5) && (current_interval%(10*io->interval))) ||
		   ((io->pixels_per_tick==5) && (current_interval%(5*io->interval)))){
			continue;
		}

		if(!(current_interval%interval_delta)){
			xlen=10;
		} else if(!(current_interval%(interval_delta/2))){
			xlen=8;
		} else {
			xlen=5;
		}
		x=draw_width+io->left_x_border-((last_interval-current_interval)/io->interval)*io->pixels_per_tick;
#if GTK_CHECK_VERSION(2,22,0)
		cr = gdk_cairo_create (io->pixmap);
		/*cairo_set_source_rgb(cr, 0, 0, 0);*/
		cairo_set_line_width (cr, 1.0);
		/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
		cairo_move_to(cr, x-1-io->pixels_per_tick/2+0.5, io->pixmap_height-bottom_y_border+1.5);
		cairo_line_to(cr, x-1-io->pixels_per_tick/2+0.5, io->pixmap_height-bottom_y_border+xlen+1.5);
		cairo_stroke(cr);
		cairo_destroy(cr);
#else
		gdk_draw_line(io->pixmap, gtk_widget_get_style(io->draw_area)->black_gc,
			x-1-io->pixels_per_tick/2,
			io->pixmap_height-bottom_y_border+1,
			x-1-io->pixels_per_tick/2,
			io->pixmap_height-bottom_y_border+xlen+1);
#endif
		if(xlen==10){
			int lwidth, x_pos;
			print_interval_string (label_string, 15, current_interval, io, TRUE);
			pango_layout_set_text(layout, label_string, -1);
			pango_layout_get_pixel_size(layout, &lwidth, NULL);

			if ((x-1-io->pixels_per_tick/2-lwidth/2) < 5) {
				x_pos=5;
			} else if ((x-1-io->pixels_per_tick/2+lwidth/2) > (io->pixmap_width-5)) {
				x_pos=io->pixmap_width-lwidth-5;
			} else {
				x_pos=x-1-io->pixels_per_tick/2-lwidth/2;
			}

			gdk_draw_layout(io->pixmap,
					gtk_widget_get_style(io->draw_area)->black_gc,
					x_pos,
					io->pixmap_height-bottom_y_border+15,
					layout);
		}

	}
	g_object_unref(G_OBJECT(layout));


	/*
	 * Loop over all graphs and draw them
	 */
	for(i=MAX_GRAPHS-1;i>=0;i--){
		guint64 val;
		guint32 interval, x_pos, y_pos, prev_x_pos, prev_y_pos;

		if(!io->graphs[i].display){
			continue;
		}

		/* initialize prev x/y to the value of the first interval */
		prev_x_pos=draw_width-1-io->pixels_per_tick*((last_interval-first_interval)/io->interval)+io->left_x_border;
		val=get_it_value(io, i, first_interval/io->interval);
		if(val>max_y){
			prev_y_pos=0;
		} else if(io->max_y_units==LOGARITHMIC_YSCALE){
			if (val==0) {
				prev_y_pos=(guint32)(draw_height-1+top_y_border);
			} else {
				prev_y_pos=(guint32)((draw_height-ystart)-1-((log10((double)((gint64)val)))*(draw_height-ystart))/(log10((double)max_y))+top_y_border);
			}
		} else {
			prev_y_pos=(guint32)(draw_height-1-(val*draw_height)/max_y+top_y_border);
		}

		for(interval=first_interval;interval<last_interval;interval+=io->interval){
			x_pos=draw_width-1-io->pixels_per_tick*((last_interval-interval)/io->interval)+io->left_x_border;

			val=get_it_value(io, i, interval/io->interval);
			if(val>max_y){
				y_pos=0;
			} else if(io->max_y_units==LOGARITHMIC_YSCALE){
				if (val==0) {
					y_pos=(guint32)(draw_height-1+top_y_border);
				} else {
					y_pos=(guint32)((draw_height-ystart)-1-((log10((double)((gint64)val)))*(draw_height-ystart))/(log10((double)max_y))+top_y_border);
				}
			} else {
				y_pos=(guint32)(draw_height-1-(val*draw_height)/max_y+top_y_border);
			}

			switch(io->graphs[i].plot_style){
			case PLOT_STYLE_LINE:
				/* dont need to draw anything if the segment
				 * is entirely above the top of the graph
				 */
				if( (prev_y_pos!=0) || (y_pos!=0) ){
#if GTK_CHECK_VERSION(2,22,0)
					cr = gdk_cairo_create (io->pixmap);
					/*cairo_set_source_rgb(cr, 0, 0, 0);*/
					gdk_cairo_set_source_color (cr, &io->graphs[i].color);
					cairo_set_line_width (cr, 1.0);
					/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
					cairo_move_to(cr, prev_x_pos+0.5, prev_y_pos+0.5);
					cairo_line_to(cr, x_pos+0.5, y_pos+0.5);
					cairo_stroke(cr);
					cairo_destroy(cr);
#else
					gdk_draw_line(io->pixmap, io->graphs[i].gc,
						prev_x_pos, prev_y_pos,
						x_pos, y_pos);
#endif
				}
				break;
			case PLOT_STYLE_IMPULSE:
				if(val){
#if GTK_CHECK_VERSION(2,22,0)
					cr = gdk_cairo_create (io->pixmap);
					/*cairo_set_source_rgb(cr, 0, 0, 0);*/
					cairo_set_line_width (cr, 1.0);
					/*cairo_set_line_cap (cr, CAIRO_LINE_CAP_SQUARE);*/
					cairo_move_to(cr, x_pos+0.5, draw_height-1+top_y_border+0.5);
					cairo_line_to(cr, x_pos+0.5, y_pos+0.5);
					cairo_stroke(cr);
					cairo_destroy(cr);
#else
					gdk_draw_line(io->pixmap, io->graphs[i].gc,
						x_pos, draw_height-1+top_y_border,
						x_pos, y_pos);
#endif
				}
				break;
			case PLOT_STYLE_FILLED_BAR:
				if(val){
#if GTK_CHECK_VERSION(2,22,0)
						cr = gdk_cairo_create (io->pixmap);
						cairo_rectangle (cr, 
							x_pos-io->pixels_per_tick/2, 
							y_pos, 
							io->pixels_per_tick, 
							draw_height-1+top_y_border-y_pos);
						cairo_set_source_rgb (cr, 1, 1, 1);
						cairo_fill (cr);
						cairo_destroy (cr);
#else
				        gdk_draw_rectangle(io->pixmap,
						io->graphs[i].gc, TRUE,
						x_pos-io->pixels_per_tick/2,
						y_pos,
						io->pixels_per_tick,
						draw_height-1+top_y_border-y_pos);
#endif
				}
				break;
			case PLOT_STYLE_DOT:
				if(val){

#if GTK_CHECK_VERSION(2,22,0)
					cr = gdk_cairo_create (io->pixmap);
					cairo_rectangle (cr, 
						x_pos-io->pixels_per_tick/2, 
						y_pos-io->pixels_per_tick/2, 
						io->pixels_per_tick, 
						io->pixels_per_tick);
					cairo_set_source_rgb (cr, 1, 1, 1);
					cairo_fill (cr);
					cairo_destroy (cr);
#else
			        gdk_draw_rectangle(io->pixmap,
						io->graphs[i].gc, TRUE,
						x_pos-io->pixels_per_tick/2,
						y_pos-io->pixels_per_tick/2,
						io->pixels_per_tick,
						io->pixels_per_tick);
#endif
				}
				break;
			}

			prev_y_pos=y_pos;
			prev_x_pos=x_pos;
		}
	}


#if GTK_CHECK_VERSION(2,22,0)
#else
	gdk_draw_pixmap(gtk_widget_get_window(io->draw_area),
#if GTK_CHECK_VERSION(2,18,0)
			gtk_widget_get_style(io->draw_area)->fg_gc[gtk_widget_get_state(io->draw_area)],
#else
			gtk_widget_get_style(io->draw_area)->fg_gc[GTK_WIDGET_STATE(io->draw_area)],
#endif
			io->pixmap,
			0, 0,
			0, 0,
			io->pixmap_width, io->pixmap_height);
#endif

	/* update the scrollbar */
	if (io->max_interval == 0) {
		gtk_adjustment_set_upper(io->scrollbar_adjustment, (gfloat) io->interval);
		gtk_adjustment_set_step_increment(io->scrollbar_adjustment, (gfloat) (io->interval/10));
		gtk_adjustment_set_page_increment(io->scrollbar_adjustment, (gfloat) io->interval);
	} else {
		gtk_adjustment_set_upper(io->scrollbar_adjustment, (gfloat) io->max_interval);
		gtk_adjustment_set_step_increment(io->scrollbar_adjustment, (gfloat) ((last_interval-first_interval)/10));
		gtk_adjustment_set_page_increment(io->scrollbar_adjustment, (gfloat) (last_interval-first_interval));
	}
	gtk_adjustment_set_page_size(io->scrollbar_adjustment, gtk_adjustment_get_page_increment(io->scrollbar_adjustment));
	gtk_adjustment_set_value(io->scrollbar_adjustment, (gfloat)first_interval);
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
tap_iostat_draw(void *g)
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
	char real_filter[262];

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
			g_snprintf(real_filter, 257, "(%s)", filter);
			real_filter[257]=0;
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
				g_strlcat(real_filter, " && ", 262);
			}
			g_strlcat(real_filter, field, 262);
		}
	}
	return register_tap_listener("frame", gio, real_filter[0]?real_filter:NULL,
				     TL_REQUIRES_PROTO_TREE,
				     tap_iostat_reset, tap_iostat_packet, tap_iostat_draw);
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
iostat_init(const char *optarg _U_, void* userdata _U_)
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
	io->interval=tick_interval_values[DEFAULT_TICK_VALUE_INDEX];
	io->window=NULL;
	io->draw_area=NULL;
	io->pixmap=NULL;
	io->scrollbar=NULL;
	io->scrollbar_adjustment=NULL;
	io->pixmap_width=500;
	io->pixmap_height=200;
	io->pixels_per_tick=pixels_per_tick[DEFAULT_PIXELS_PER_TICK_INDEX];
	io->max_y_units=AUTO_MAX_YSCALE;
	io->count_type=0;
	io->last_interval=0xffffffff;
	io->max_interval=0;
	io->num_items=0;
	io->left_x_border=0;
	io->right_x_border=500;
	io->view_as_time=FALSE;
	io->start_time.secs=0;
	io->start_time.nsecs=0;

	for(i=0;i<MAX_GRAPHS;i++){
#if GTK_CHECK_VERSION(2,22,0)
#else
		io->graphs[i].gc=NULL;
#endif
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
		io->graphs[i].args->modal_and_transient=FALSE;

		io->graphs[i].filter_bt=NULL;
	}
	io_stat_reset(io);

	error_string=enable_graph(&io->graphs[0], NULL, NULL);
        g_assert((error_string == NULL) && "Can't attach io_stat tap !");
#if 0
	if(error_string){

		fprintf(stderr, "wireshark: Can't attach io_stat tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		io->graphs[0].display=0;
		io->graphs[0].display_button=NULL;
		io->graphs[0].filter_field=NULL;
		io->graphs[0].advanced_buttons=NULL;
		exit(10);
	}
#endif
	/* build the GUI */
	init_io_stat_window(io);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(io->window));
	io_stat_redraw(io);
}

static void
draw_area_destroy_cb(GtkWidget *widget _U_, gpointer user_data)
{
	io_stat_t *io = user_data;
	int i;

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

	return;
}

static gboolean
pixmap_clicked_event(GtkWidget *widget _U_, GdkEventButton *event, gpointer user_data)
{
	io_stat_t *io = user_data;
	guint32 draw_width, interval, last_interval;
	guint frame_num;

	draw_width=io->pixmap_width-io->right_x_border-io->left_x_border;

	if ((event->x <= (draw_width+io->left_x_border+1-(draw_width/io->pixels_per_tick)*io->pixels_per_tick)) ||
	    (event->x >= (draw_width+io->left_x_border-io->pixels_per_tick/2))) {
	      /* Outside draw area */
	      return FALSE;
	}

	if ((event->button==1 || event->button==3) && io->pixmap!=NULL) {
		/*
		 * Button 1 selects the first package in the interval.
		 * Button 3 selects the last package in the interval.
		 */
		if (io->last_interval==0xffffffff) {
			last_interval=io->max_interval;
		} else {
			last_interval=io->last_interval;
		}

		interval=(guint32)((last_interval/io->interval)-(draw_width+io->left_x_border-event->x-io->pixels_per_tick/2-1)/io->pixels_per_tick);
		frame_num=get_frame_num (io, interval, event->button==1?TRUE:FALSE);
		if (frame_num != 0) {
			cf_goto_frame(&cfile, frame_num);
		}
	}

	return TRUE;
}

/* create a new backing pixmap of the appropriate size */
static gboolean
draw_area_configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer user_data)
{
	io_stat_t *io = user_data;
	int i;
	GtkWidget *save_bt;
#if GTK_CHECK_VERSION(2,22,0)
	cairo_t *cr;
#endif

	if(io->pixmap){
		g_object_unref(io->pixmap);
		io->pixmap=NULL;
	}

	io->pixmap=gdk_pixmap_new(gtk_widget_get_window(widget),
			widget->allocation.width,
			widget->allocation.height,
			-1);
	io->pixmap_width=widget->allocation.width;
	io->pixmap_height=widget->allocation.height;

	save_bt = g_object_get_data(G_OBJECT(io->window), "save_bt");
	g_object_set_data(G_OBJECT(save_bt), "pixmap", io->pixmap);
	gtk_widget_set_sensitive(save_bt, TRUE);

#if GTK_CHECK_VERSION(2,22,0)
	cr = gdk_cairo_create (io->pixmap);
	cairo_rectangle (cr, 0, 0, widget->allocation.width, widget->allocation.height);
	cairo_set_source_rgb (cr, 1, 1, 1);
	cairo_fill (cr);
	cairo_destroy (cr);
#else
	gdk_draw_rectangle(io->pixmap,
			gtk_widget_get_style(widget)->white_gc,
			TRUE,
			0, 0,
			widget->allocation.width,
			widget->allocation.height);
#endif
	/* set up the colors and the GC structs for this pixmap */
	for(i=0;i<MAX_GRAPHS;i++){
#if GTK_CHECK_VERSION(2,22,0)
#else
		io->graphs[i].gc=gdk_gc_new(io->pixmap);
		gdk_gc_set_rgb_fg_color(io->graphs[i].gc, &io->graphs[i].color);
#endif
	}

	io_stat_redraw(io);
	return TRUE;
}

static void
scrollbar_changed(GtkWidget *widget _U_, gpointer user_data)
{
	io_stat_t *io = user_data;
	guint32 mi;

	mi=(guint32) (gtk_adjustment_get_value(io->scrollbar_adjustment) + gtk_adjustment_get_page_size(io->scrollbar_adjustment));
	if(io->last_interval==mi){
		return;
	}
	if( (io->last_interval==0xffffffff)
	&&  (mi==io->max_interval) ){
		return;
	}

	io->last_interval=(mi/io->interval)*io->interval;
	io_stat_redraw(io);

	return;
}

/* redraw the screen from the backing pixmap */
static gboolean
draw_area_expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer user_data)
{
	io_stat_t *io = user_data;

	gdk_draw_pixmap(gtk_widget_get_window(widget),
#if GTK_CHECK_VERSION(2,18,0)
			gtk_widget_get_style(widget)->fg_gc[gtk_widget_get_state(widget)],
#else
			gtk_widget_get_style(widget)->fg_gc[GTK_WIDGET_STATE(widget)],
#endif
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
	g_signal_connect(io->draw_area, "destroy", G_CALLBACK(draw_area_destroy_cb), io);

	gtk_widget_set_size_request(io->draw_area, io->pixmap_width, io->pixmap_height);

	/* signals needed to handle backing pixmap */
	g_signal_connect(io->draw_area, "expose-event", G_CALLBACK(draw_area_expose_event), io);
	g_signal_connect(io->draw_area, "configure-event", G_CALLBACK(draw_area_configure_event), io);
	gtk_widget_add_events (io->draw_area, GDK_BUTTON_PRESS_MASK);
	g_signal_connect(io->draw_area, "button-press-event", G_CALLBACK(pixmap_clicked_event), io);

	gtk_widget_show(io->draw_area);
	gtk_box_pack_start(GTK_BOX(box), io->draw_area, TRUE, TRUE, 0);

	/* create the associated scrollbar */
	io->scrollbar_adjustment=(GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
	io->scrollbar=gtk_hscrollbar_new(io->scrollbar_adjustment);
	gtk_widget_show(io->scrollbar);
	gtk_box_pack_start(GTK_BOX(box), io->scrollbar, FALSE, FALSE, 0);
	g_signal_connect(io->scrollbar_adjustment, "value-changed", G_CALLBACK(scrollbar_changed), io);
}

static void
tick_interval_select(GtkWidget *item, gpointer user_data)
{
	io_stat_t *io = user_data;
	int i;

	i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	io->interval=tick_interval_values[i];
	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(io->window));
	io_stat_redraw(io);
}

static void
pixels_per_tick_select(GtkWidget *item, gpointer user_data)
{
	io_stat_t *io = user_data;
	int i;

	i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));
	io->pixels_per_tick=pixels_per_tick[i];
	io_stat_redraw(io);
}

static void
plot_style_select(GtkWidget *item, gpointer user_data)
{
	io_stat_graph_t *ppt = user_data;
	int val;

	val=gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	ppt->plot_style=val;

	io_stat_redraw(ppt->io);
}

static GtkWidget *
create_pixels_per_tick_menu_items(io_stat_t *io)
{
	char str[5];
	GtkWidget *combo_box;
	int i;
	combo_box = gtk_combo_box_text_new ();

	for(i=0;i<MAX_PIXELS_PER_TICK;i++){
		g_snprintf(str, 5, "%u", pixels_per_tick[i]);
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_PIXELS_PER_TICK_INDEX);
	g_signal_connect(combo_box, "changed", G_CALLBACK(pixels_per_tick_select), io);

	return combo_box;
}

static void
yscale_select(GtkWidget *item, gpointer user_data)
{
	io_stat_t *io = user_data;
	int i;

	i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	io->max_y_units = yscale_max[i];
	io_stat_redraw(io);
}

static GtkWidget *
create_tick_interval_menu_items(io_stat_t *io)
{
	GtkWidget *combo_box;
	char str[15];
	int i;

	combo_box = gtk_combo_box_text_new ();

	for(i=0;i<MAX_TICK_VALUES;i++){
		if(tick_interval_values[i]>=60000){
			g_snprintf(str, sizeof(str), "%u min", tick_interval_values[i]/60000);
		} else if(tick_interval_values[i]>=1000){
			g_snprintf(str, sizeof(str), "%u sec", tick_interval_values[i]/1000);
		} else if(tick_interval_values[i]>=100){
			g_snprintf(str, sizeof(str), "0.%1u sec", (tick_interval_values[i]/100)%10);
		} else if(tick_interval_values[i]>=10){
			g_snprintf(str, sizeof(str), "0.%02u sec", (tick_interval_values[i]/10)%10);
		} else {
			g_snprintf(str, sizeof(str), "0.%03u sec", (tick_interval_values[i])%10);
		}
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_TICK_VALUE_INDEX);
	g_signal_connect(combo_box, "changed", G_CALLBACK(tick_interval_select), io);

	return combo_box;
}

static GtkWidget *
create_yscale_max_menu_items(io_stat_t *io)
{
	char str[15];
	GtkWidget *combo_box;
	int i;

	combo_box = gtk_combo_box_text_new ();
	for(i=0;i<MAX_YSCALE;i++){
		if(yscale_max[i]==LOGARITHMIC_YSCALE){
			g_strlcpy(str, "Logarithmic", 15);
		} else if(yscale_max[i]==AUTO_MAX_YSCALE){
			g_strlcpy(str, "Auto", 15);
		} else {
			g_snprintf(str, 15, "%u", yscale_max[i]);
		}
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_YSCALE_INDEX);
	g_signal_connect(combo_box, "changed", G_CALLBACK(yscale_select), io);
	return combo_box;
}

static void
count_type_select(GtkWidget *item, gpointer user_data)
{
	io_stat_t *io = user_data;
	static gboolean advanced_visible=FALSE;
	int i;

	io->count_type = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	if(io->count_type==COUNT_TYPE_ADVANCED){
		for(i=0;i<MAX_GRAPHS;i++){
			disable_graph(&io->graphs[i]);
			gtk_widget_show(io->graphs[i].advanced_buttons);
			/* redraw the entire window so the unhidden widgets show up, hopefully */
			gtk_widget_queue_draw_area(io->window,
						   0,
						   0,
						   io->window->allocation.width,
						   io->window->allocation.height);
		}
		advanced_visible=TRUE;
		io_stat_redraw(io);
	} else if (advanced_visible) {
		for(i=0;i<MAX_GRAPHS;i++){
			gtk_widget_hide(io->graphs[i].advanced_buttons);
			filter_callback(item, &io->graphs[i]);
		}
		advanced_visible=FALSE;
	} else {
		io_stat_redraw(io);
	}
}

static GtkWidget *
create_frames_or_bytes_menu_items(io_stat_t *io)
{
	GtkWidget *combo_box;
	int i;

	combo_box = gtk_combo_box_text_new ();

	for(i=0;i<MAX_COUNT_TYPES;i++){
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), count_type_names[i]);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_COUNT_TYPE);
	g_signal_connect(combo_box, "changed", G_CALLBACK(count_type_select), io);
	return combo_box;
}

static void
create_ctrl_menu(io_stat_t *io, GtkWidget *box, const char *name, GtkWidget * (*func)(io_stat_t *io))
{
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *combo_box;

	hbox=gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	label=gtk_label_new(name);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	combo_box = (*func)(io);
	gtk_box_pack_end(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
	gtk_widget_show(combo_box);
}

static void
view_as_time_toggle_dest(GtkWidget *widget _U_, gpointer user_data)
{
	io_stat_t *io = user_data;

	io->view_as_time = io->view_as_time ? FALSE : TRUE;

	io_stat_redraw(io);
}

static void
create_ctrl_area(io_stat_t *io, GtkWidget *box)
{
	GtkWidget *frame_vbox;
	GtkWidget *frame;
	GtkWidget *vbox;
	GtkWidget *view_cb;

	frame_vbox=gtk_vbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(box), frame_vbox, FALSE, FALSE, 0);
	gtk_widget_show(frame_vbox);

	frame = gtk_frame_new("X Axis");
	gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
	gtk_widget_show(vbox);

	create_ctrl_menu(io, vbox, "Tick interval:", create_tick_interval_menu_items);
	create_ctrl_menu(io, vbox, "Pixels per tick:", create_pixels_per_tick_menu_items);

	view_cb = gtk_check_button_new_with_mnemonic("_View as time of day");
	gtk_container_add(GTK_CONTAINER(vbox), view_cb);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(view_cb), io->view_as_time);
	g_signal_connect(view_cb, "toggled", G_CALLBACK(view_as_time_toggle_dest), io);
	gtk_widget_show(view_cb);

	frame = gtk_frame_new("Y Axis");
	gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_END);
	gtk_widget_show(vbox);

	create_ctrl_menu(io, vbox, "Unit:", create_frames_or_bytes_menu_items);
	create_ctrl_menu(io, vbox, "Scale:", create_yscale_max_menu_items);

	return;
}

static void
filter_callback(GtkWidget *widget _U_, gpointer user_data)
{
	io_stat_graph_t *gio = user_data;
	const char *filter;
	const char *field=NULL;
	header_field_info *hfi;
	dfilter_t *dfilter;

	/* this graph is not active, just update display and redraw */
	if(!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gio->display_button))){
		disable_graph(gio);
		io_stat_redraw(gio->io);
		return;
	}

	/* first check if the field string is valid */
	if(gio->io->count_type==COUNT_TYPE_ADVANCED){
		field=gtk_entry_get_text(GTK_ENTRY(gio->calc_field));

		/* warn and bail out if there was no field specified */
		if(field==NULL || field[0]==0){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "You didn't specify a field name.");
			disable_graph(gio);
			io_stat_redraw(gio->io);
			return;
		}
		/* warn and bail out if the field could not be found */
		hfi=proto_registrar_get_byname(field);
		if(hfi==NULL){
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "There is no field named '%s'.", field);
			disable_graph(gio);
			io_stat_redraw(gio->io);
			return;
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
		case FT_FLOAT:
		case FT_DOUBLE:
			/* these values support all calculations except LOAD */
			switch(gio->calc_type){
			case CALC_TYPE_LOAD:
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "LOAD(*) is only supported for relative-time fields.");
				disable_graph(gio);
				io_stat_redraw(gio->io);
				return;
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
				return;
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
				return;
			}
			break;
		default:
			if(gio->calc_type!=CALC_TYPE_COUNT){
				simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
				    "%s doesn't have integral or float values, so %s calculations are not supported on it.",
				    field,
				    calc_type_names[gio->calc_type]);
				disable_graph(gio);
				io_stat_redraw(gio->io);
				return;
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
		return;
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
	gdk_window_raise(gtk_widget_get_window(gio->io->window));
	io_stat_redraw(gio->io);

	return;
}

static void
calc_type_select(GtkWidget *item, gpointer user_data)
{
	io_stat_graph_t *gio = user_data;

	gio->calc_type=gtk_combo_box_get_active (GTK_COMBO_BOX(item));

	/* disable the graph */
	disable_graph(gio);
	io_stat_redraw(gio->io);
}

static GtkWidget *
create_calc_types_menu_items(io_stat_graph_t *gio)
{
	GtkWidget *combo_box;
	int i;

	combo_box = gtk_combo_box_text_new ();
	for(i=0;i<MAX_CALC_TYPES;i++){
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), calc_type_names[i]);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_CALC_TYPE);
	g_signal_connect(combo_box, "changed", G_CALLBACK(calc_type_select), gio);
	return combo_box;
}

static void
create_advanced_menu(io_stat_graph_t *gio, GtkWidget *box, const char *name,  GtkWidget *(*func)(io_stat_graph_t *io))
{
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *combo_box;

	hbox=gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	label=gtk_label_new(name);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	combo_box = (*func)(gio);
	gtk_box_pack_end(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
	gtk_widget_show(combo_box);
}

static void
create_advanced_field(io_stat_graph_t *gio, GtkWidget *box)
{

	gio->calc_field=gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(gio->calc_field),100);
	gtk_box_pack_start(GTK_BOX(box), gio->calc_field, TRUE, TRUE, 0);
	gtk_widget_show(gio->calc_field);
	g_signal_connect(gio->calc_field, "activate", G_CALLBACK(filter_callback), gio);
	g_object_set_data (G_OBJECT(gio->calc_field), E_FILT_FIELD_NAME_ONLY_KEY, "");
	g_signal_connect(gio->calc_field, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
	g_object_set_data(G_OBJECT(box), E_FILT_AUTOCOMP_PTR_KEY, NULL);
	g_signal_connect(gio->calc_field, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	g_signal_connect(gio->io->window, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
	colorize_filter_te_as_empty(gio->calc_field);
}

static void
create_advanced_box(io_stat_graph_t *gio, GtkWidget *box)
{
	GtkWidget *hbox;

	hbox=gtk_hbox_new(FALSE, 0);
	gio->advanced_buttons=hbox;
	gtk_container_add(GTK_CONTAINER(box), hbox);
	gtk_box_set_child_packing(GTK_BOX(box), hbox, TRUE, TRUE, 0, GTK_PACK_START);
	gtk_widget_hide(hbox);

	gio->calc_type=CALC_TYPE_SUM;
	create_advanced_menu(gio, hbox, "Calc:", create_calc_types_menu_items);
	create_advanced_field(gio, hbox);
}

static void
filter_button_clicked(GtkWidget *w, gpointer user_data)
{
	io_stat_graph_t *gio = user_data;

	display_filter_construct_cb(w, gio->args);
	return;
}

static void
create_filter_box(io_stat_graph_t *gio, GtkWidget *box, int num)
{
	GtkWidget *combo_box;
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
	g_signal_connect(gio->display_button, "toggled", G_CALLBACK(filter_callback), gio);

	label=gtk_label_new("Color");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	gtk_widget_modify_fg(label, GTK_STATE_NORMAL, &gio->color);
	gtk_widget_modify_fg(label, GTK_STATE_ACTIVE, &gio->color);
	gtk_widget_modify_fg(label, GTK_STATE_PRELIGHT, &gio->color);
	gtk_widget_modify_fg(label, GTK_STATE_SELECTED, &gio->color);
	gtk_widget_modify_fg(label, GTK_STATE_INSENSITIVE, &gio->color);
/*	g_signal_connect(gio->display_button, "toggled", G_CALLBACK(filter_callback), gio);*/


	/* filter prefs dialog */
	gio->filter_bt=gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);

	g_snprintf(str, 256, "Wireshark: Display Filter  IO-Stat (Filter:%d)", num);
	g_free( (gpointer) (gio->args->title) );
	gio->args->title=g_strdup(str);

	g_signal_connect(gio->filter_bt, "clicked", G_CALLBACK(filter_button_clicked), gio);
	g_signal_connect(gio->filter_bt, "destroy", G_CALLBACK(filter_button_destroy_cb), NULL);

	gtk_box_pack_start(GTK_BOX(hbox), gio->filter_bt, FALSE, TRUE, 0);
	gtk_widget_show(gio->filter_bt);

	gio->filter_field=gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(gio->filter_field),256);
	/* filter prefs dialog */
	g_object_set_data(G_OBJECT(gio->filter_bt), E_FILT_TE_PTR_KEY, gio->filter_field);
	/* filter prefs dialog */

	gtk_box_pack_start(GTK_BOX(hbox), gio->filter_field, TRUE, TRUE, 0);
	gtk_widget_show(gio->filter_field);
	g_signal_connect(gio->filter_field, "activate", G_CALLBACK(filter_callback), gio);
	g_signal_connect(gio->filter_field, "changed", G_CALLBACK(filter_te_syntax_check_cb), NULL);
	g_object_set_data(G_OBJECT(box), E_FILT_AUTOCOMP_PTR_KEY, NULL);
	g_signal_connect(gio->filter_field, "key-press-event", G_CALLBACK (filter_string_te_key_pressed_cb), NULL);
	g_signal_connect(gio->io->window, "key-press-event", G_CALLBACK (filter_parent_dlg_key_pressed_cb), NULL);
	colorize_filter_te_as_empty(gio->filter_field);

	create_advanced_box(gio, hbox);

	/*
	 * create PlotStyle menu
	 */
	g_snprintf(str, 256, " Style:");
	label=gtk_label_new(str);
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

	combo_box = gtk_combo_box_text_new ();
	for(i=0;i<MAX_PLOT_STYLES;i++){
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), plot_style_name[i]);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_PLOT_STYLE);
	g_signal_connect(combo_box, "changed", G_CALLBACK(plot_style_select), &gio->io->graphs[num-1]);

	gtk_box_pack_end(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
	gtk_widget_show(combo_box);

	return;
}

static void
create_filter_area(io_stat_t *io, GtkWidget *box)
{
	GtkWidget *frame;
	GtkWidget *vbox;
	int i;

	frame=gtk_frame_new("Graphs");
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 0);
	gtk_widget_show(frame);

	vbox=gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
	gtk_box_set_child_packing(GTK_BOX(box), vbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(vbox);

	for(i=0;i<MAX_GRAPHS;i++){
		create_filter_box(&io->graphs[i], vbox, i+1);
	}

	return;
}

static void
copy_as_csv_cb(GtkWindow *copy_bt _U_, gpointer user_data)
{
	guint32         i, interval, val;
	char            string[15];
	GtkClipboard    *cb;
	GString         *CSV_str=g_string_new("");
	io_stat_t       *io = user_data;

	g_string_append(CSV_str, "\"Interval start\"");
	for(i=0;i<MAX_GRAPHS;i++) {
		if (io->graphs[i].display) {
			g_string_append_printf(CSV_str, ",\"Graph %d\"", i+1);
		}
	}
	g_string_append(CSV_str,"\n");

	for(interval=0; interval<io->max_interval; interval+=io->interval) {
		print_interval_string (string, 15, interval, io, FALSE);
		g_string_append_printf(CSV_str, "\"%s\"", string);
		for(i=0;i<MAX_GRAPHS;i++) {
			if (io->graphs[i].display) {
				val=get_it_value(io, i, interval/io->interval);
				g_string_append_printf(CSV_str, ",\"%d\"", val);
			}
		}
		g_string_append(CSV_str,"\n");
	}

	/* Now that we have the CSV data, copy it into the default clipboard */
	cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);    /* Get the default clipboard */
	gtk_clipboard_set_text(cb, CSV_str->str, -1);       /* Copy the CSV data into the clipboard */
	g_string_free(CSV_str, TRUE);                       /* Free the memory */
}

static void
init_io_stat_window(io_stat_t *io)
{
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *bbox;
	GtkWidget *close_bt, *help_bt;
	GtkWidget *copy_bt;
	GtkWidget *save_bt;

	/* create the main window, transient_for top_level */
	io->window = dlg_window_new("I/O Graphs");
	gtk_window_set_destroy_with_parent (GTK_WINDOW(io->window), TRUE);

	vbox=gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(io->window), vbox);
	gtk_widget_show(vbox);

	create_draw_area(io, vbox);

	hbox=gtk_hbox_new(FALSE, 3);
	gtk_box_pack_end(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_box_set_child_packing(GTK_BOX(vbox), hbox, FALSE, FALSE, 0, GTK_PACK_START);
	gtk_widget_show(hbox);

	create_filter_area(io, hbox);
	create_ctrl_area(io, hbox);

	io_stat_set_title(io);

	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_SAVE,
				  GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(io->window, close_bt, window_cancel_button_cb);
	gtk_widget_set_tooltip_text(close_bt,  "Enter the hostname or host IP address to be used as a source for remote capture.");
	save_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_SAVE);
	gtk_widget_set_sensitive(save_bt, FALSE);
	gtk_widget_set_tooltip_text(save_bt, "Save the displayed graph to a file");
	g_signal_connect(save_bt, "clicked", G_CALLBACK(pixmap_save_cb), NULL);
	g_object_set_data(G_OBJECT(io->window), "save_bt", save_bt);

	copy_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
	gtk_widget_set_tooltip_text(copy_bt, "Copy values from selected graphs to the clipboard in CSV (Comma Separated Values) format");
	g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), io);

	help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_IO_GRAPH_DIALOG);
	gtk_widget_set_tooltip_text (help_bt, "Show topic specific help");
	g_signal_connect(io->window, "delete-event", G_CALLBACK(window_delete_event_cb), NULL);

	gtk_widget_show(io->window);
	window_present(io->window);
}

#ifdef MAIN_MENU_USE_UIMANAGER
void
gui_iostat_cb(GtkAction *action _U_, gpointer user_data _U_)
{
	iostat_init(NULL,NULL);
}
#else
static void
gui_iostat_cb(GtkWidget *w _U_, gpointer d _U_)
{
	iostat_init(NULL,NULL);
}
#endif

void
register_tap_listener_gtk_iostat(void)
{
	register_stat_cmd_arg("io,stat", iostat_init,NULL);

#ifdef MAIN_MENU_USE_UIMANAGER
#else
	register_stat_menu_item_stock("_IO Graphs",
				      REGISTER_STAT_GROUP_GENERIC, WIRESHARK_STOCK_GRAPHS,
				      gui_iostat_cb, NULL, NULL, NULL);
#endif
}
