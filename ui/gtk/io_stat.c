/* io_stat.c
 * io_stat   2002 Ronnie Sahlberg
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
#include <math.h>
#include <ctype.h>
#include <gtk/gtk.h>

#include <epan/epan_dissect.h>
#include <epan/packet_info.h>
#include <epan/stat_cmd_args.h>
#include <epan/tap.h>
#include <epan/strutil.h>

#include "../../stat_menu.h"
#include "ui/alert_box.h"
#include "ui/io_graph_item.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/filter_dlg.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/pixmap_save.h"
#include "ui/gtk/main.h"
#include "ui/gtk/filter_autocomplete.h"
#include "ui/main_statusbar.h"

#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/gui_utils.h"

void register_tap_listener_gtk_iostat(void);

#define MAX_GRAPHS           5

#define MAX_YSCALE          28
#define LOGARITHMIC_YSCALE   0
#define AUTO_MAX_YSCALE      1
#define DEFAULT_YSCALE_INDEX 1
static guint32 yscale_max[MAX_YSCALE] = {LOGARITHMIC_YSCALE, AUTO_MAX_YSCALE, 10, 20,
                                         50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000,
                                         50000, 100000, 200000, 500000, 1000000, 2000000,
                                         5000000, 10000000, 20000000, 50000000, 100000000,
                                         200000000, 500000000, 1000000000, 2000000000};

#define NO_FILTER_ORDER           0
#define MAX_MOVING_AVERAGE_ORDER 10
static guint32 moving_average_orders[MAX_MOVING_AVERAGE_ORDER] = {NO_FILTER_ORDER, 4, 8, 16,
                                                                  32, 64, 128, 256, 512, 1024};
#define NO_FILTER             0
#define MOVING_AVERAGE_FILTER 1
#define GRAPH_NOFILTER        0
#define GRAPH_FOLLOWFILTER    1

#define MAX_PIXELS_PER_TICK   4
#define DEFAULT_PIXELS_PER_TICK_INDEX 2
static guint32 pixels_per_tick[MAX_PIXELS_PER_TICK] = {1, 2, 5, 10};


#define DEFAULT_PLOT_STYLE    0
#define PLOT_STYLE_LINE       0
#define PLOT_STYLE_IMPULSE    1
#define PLOT_STYLE_FILLED_BAR 2
#define PLOT_STYLE_DOT        3
#define MAX_PLOT_STYLES       4
static const char *plot_style_name[MAX_PLOT_STYLES] = {
    "Line",
    "Impulse",
    "FBar",
    "Dot",
};

/*
 * XXX - "Count types" and "calc types" are combined in io_graph_item_unit_t
 * in io_graph_item_t. The Qt port treats these as a single Y Axis "value unit"
 * type. Should we do the same here?
 */
#define DEFAULT_COUNT_TYPE  0
#define COUNT_TYPE_FRAMES   0
#define COUNT_TYPE_BYTES    1
#define COUNT_TYPE_BITS     2
#define COUNT_TYPE_ADVANCED 3
#define MAX_COUNT_TYPES     4
static const char *count_type_names[MAX_COUNT_TYPES] = {
    "Packets/Tick",
    "Bytes/Tick",
    "Bits/Tick",
    "Advanced..."};

/* unit is in ms */
#define MAX_TICK_VALUES 7
#define DEFAULT_TICK_VALUE_INDEX 3
static const guint tick_interval_values[MAX_TICK_VALUES] = { 1, 10, 100, 1000, 10000, 60000, 600000 };

#define CALC_TYPE_SUM          0
#define CALC_TYPE_COUNT_FRAMES 1
#define CALC_TYPE_COUNT_FIELDS 2
#define CALC_TYPE_MAX          3
#define CALC_TYPE_MIN          4
#define CALC_TYPE_AVG          5
#define CALC_TYPE_LOAD         6
#define MAX_CALC_TYPES         7
#define DEFAULT_CALC_TYPE      0
static const char *calc_type_names[MAX_CALC_TYPES] = {
    "SUM(*)",
    "COUNT FRAMES(*)",
    "COUNT FIELDS(*)",
    "MAX(*)",
    "MIN(*)",
    "AVG(*)",
    "LOAD(*)"};

#define CALC_TYPE_TO_ITEM_UNIT(ct) ((io_graph_item_unit_t)(ct + IOG_ITEM_UNIT_CALC_SUM))

/* Unused? */
#if 0
typedef struct _io_stat_calc_type_t {
    struct _io_stat_graph_t *gio;
    int calc_type;
} io_stat_calc_type_t;
#endif

#define NUM_IO_ITEMS 100000
typedef struct _io_stat_graph_t {
    struct _io_stat_t *io;
    io_graph_item_t    items[NUM_IO_ITEMS];
    int                plot_style;
    gboolean           display;
    GtkWidget         *display_button;
    GtkWidget         *filter_field;
    GtkWidget         *advanced_buttons;
    int                calc_type;
    int                hf_index;
    GtkWidget         *calc_field;
    GdkColor           color;
    GdkRGBA            rgba_color;
    construct_args_t  *args;
    GtkWidget         *filter_bt;

    gboolean follow_smooth;
    GtkWidget *follow_smooth_toggle;
} io_stat_graph_t;


typedef struct _io_stat_t {
    gboolean       needs_redraw;
    guint32        interval;    /* measurement interval in ms */
    guint32        last_interval; /* the last *displayed* interval */
    guint32        max_interval; /* the maximum interval based on the capture duration */
    guint32        num_items;   /* total number of items in all intervals (zero relative) */
    guint32        left_x_border;
    guint32        right_x_border;
    gboolean       view_as_time;
    nstime_t       start_time;

    struct _io_stat_graph_t graphs[MAX_GRAPHS];
    GtkWidget     *window;
    GtkWidget     *draw_area;
#if GTK_CHECK_VERSION(2,22,0)
    cairo_surface_t *surface;
#else
    GdkPixmap       *pixmap;
#endif
    GtkAdjustment *scrollbar_adjustment;
    GtkWidget     *scrollbar;

    int            surface_width;
    int            surface_height;
    int            pixels_per_tick;
    int            max_y_units;
    int            count_type;

    guint32        filter_order;
    int            filter_type;
} io_stat_t;


static void init_io_stat_window(io_stat_t *io);
static void filter_callback(GtkWidget *widget _U_, gpointer user_data);

static void
io_stat_set_title(io_stat_t *io)
{
    if (!io->window) {
        return;
    }
    set_window_title(io->window, "Wireshark IO Graphs");
}

static void
io_stat_reset(io_stat_t *io)
{
    int i;

    io->needs_redraw = TRUE;
    for (i=0; i<MAX_GRAPHS; i++) {
        reset_io_graph_items((io_graph_item_t *)io->graphs[i].items, NUM_IO_ITEMS);
    }
    io->last_interval    = 0xffffffff;
    io->max_interval     = 0;
    io->num_items        = 0;
    io->start_time.secs  = 0;
    io->start_time.nsecs = 0;
    io_stat_set_title(io);
}

static void
tap_iostat_reset(void *g)
{
    io_stat_graph_t *gio = (io_stat_graph_t *)g;

    io_stat_reset(gio->io);
}

static gboolean
tap_iostat_packet(void *g, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
    io_stat_graph_t *graph = (io_stat_graph_t *)g;
    io_stat_t       *io;
    epan_dissect_t  *adv_edt = NULL;
    int              idx;

    /* we sometimes get called when the graph is disabled.
       this is a bug since the tap listener should be removed first */
    if (!graph->display) {
        return FALSE;
    }

    io = graph->io;  /* Point up to the parent io_stat_t struct */
    io->needs_redraw = TRUE;

    idx = get_io_graph_index(pinfo, io->interval);
    
    /* some sanity checks */
    if ((idx < 0) || (idx >= NUM_IO_ITEMS)) {
        io->num_items = NUM_IO_ITEMS-1;
        return FALSE;
    }

    /* update num_items */
    if ((guint32)idx > io->num_items) {
        io->num_items = (guint32) idx;
    }

    /* set start time */
    if ((io->start_time.secs == 0) && (io->start_time.nsecs == 0)) {
        nstime_delta(&io->start_time, &pinfo->fd->abs_ts, &pinfo->rel_ts);
    }

    /* For ADVANCED mode we need to keep track of some more stuff than just frame and byte counts */
    if (io->count_type == COUNT_TYPE_ADVANCED) {
        adv_edt = edt;
    }

    if (!update_io_graph_item((io_graph_item_t*) graph->items, idx, pinfo, adv_edt, graph->hf_index, CALC_TYPE_TO_ITEM_UNIT(graph->calc_type), io->interval)) {
        return FALSE;
    }

    return TRUE;
}

static guint64
get_it_value(io_stat_t *io, int graph, int idx)
{
    guint64    value = 0;          /* FIXME: loss of precision, visible on the graph for small values */
    int        adv_type;
    io_graph_item_t *it;
    guint32    interval;

    g_assert(graph < MAX_GRAPHS);
    g_assert(idx < NUM_IO_ITEMS);

    it = &io->graphs[graph].items[idx];

    switch (io->count_type) {
    case COUNT_TYPE_FRAMES:
        return it->frames;
    case COUNT_TYPE_BYTES:
        return it->bytes;
    case COUNT_TYPE_BITS:
        return (it->bytes * 8);
    case COUNT_TYPE_ADVANCED:
        switch (io->graphs[graph].calc_type) {
        case CALC_TYPE_COUNT_FRAMES:
            return it->frames;
        case CALC_TYPE_COUNT_FIELDS:
            return it->fields;
        default:
            /* If it's COUNT_TYPE_ADVANCED but not one of the
             * generic ones we'll get it when we switch on the
             * adv_type below. */
            break;
        }
        break;
    }

    adv_type = proto_registrar_get_ftype(io->graphs[graph].hf_index);
    switch (adv_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_UINT64:
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
    case FT_INT64:
        switch (io->graphs[graph].calc_type) {
        case CALC_TYPE_SUM:
            value = it->int_tot;
            break;
        case CALC_TYPE_MAX:
            value = it->int_max;
            break;
        case CALC_TYPE_MIN:
            value = it->int_min;
            break;
        case CALC_TYPE_AVG:
            if (it->fields) {
                value = it->int_tot/it->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;
    case FT_FLOAT:
        switch (io->graphs[graph].calc_type) {
        case CALC_TYPE_SUM:
            value = (guint64)it->float_tot;
            break;
        case CALC_TYPE_MAX:
            value = (guint64)it->float_max;
            break;
        case CALC_TYPE_MIN:
            value = (guint64)it->float_min;
            break;
        case CALC_TYPE_AVG:
            if (it->fields) {
                value = (guint64)it->float_tot/it->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;
    case FT_DOUBLE:
        switch (io->graphs[graph].calc_type) {
        case CALC_TYPE_SUM:
            value = (guint64)it->double_tot;
            break;
        case CALC_TYPE_MAX:
            value = (guint64)it->double_max;
            break;
        case CALC_TYPE_MIN:
            value = (guint64)it->double_min;
            break;
        case CALC_TYPE_AVG:
            if (it->fields) {
                value = (guint64)it->double_tot/it->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;
    case FT_RELATIVE_TIME:
        switch (io->graphs[graph].calc_type) {
        case CALC_TYPE_MAX:
            value = (guint64) (it->time_max.secs*1000000 + it->time_max.nsecs/1000);
            break;
        case CALC_TYPE_MIN:
            value = (guint64) (it->time_min.secs*1000000 + it->time_min.nsecs/1000);
            break;
        case CALC_TYPE_SUM:
            value = (guint64) (it->time_tot.secs*1000000 + it->time_tot.nsecs/1000);
            break;
        case CALC_TYPE_AVG:
            if (it->fields) {
                guint64 t; /* time in us */

                t = it->time_tot.secs;
                t = t*1000000+it->time_tot.nsecs/1000;
                value = (guint64) (t/it->fields);
            } else {
                value = 0;
            }
            break;
        case CALC_TYPE_LOAD:
            if (idx == (int)io->num_items) {
                interval = (guint32)((cfile.elapsed_time.secs*1000) +
                       ((cfile.elapsed_time.nsecs+500000)/1000000));
                interval -= (io->interval * idx);
            } else {
                interval = io->interval;
            }
            value = (guint64) ((it->time_tot.secs*1000000 + it->time_tot.nsecs/1000) / interval);
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
print_time_scale_string(char *buf, int buf_len, guint32 t, guint32 t_max, gboolean log_flag)
{
    if ((t_max >= 10000000) || (log_flag && (t_max >= 1000000))) {
        g_snprintf(buf, buf_len, "%ds", t/1000000);
    } else if (t_max >= 1000000) {
        g_snprintf(buf, buf_len, "%d.%1ds", t/1000000, (t%1000000)/100000);
    } else if ((t_max >= 10000) || (log_flag && (t_max >= 1000))) {
        g_snprintf(buf, buf_len, "%dms", t/1000);
    } else if (t_max >= 1000) {
        g_snprintf(buf, buf_len, "%d.%1dms", t/1000,(t%1000)/100);
    } else {
        g_snprintf(buf, buf_len, "%dus", t);
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

        if (nsec_val >= 1000) {
            sec_val++;
            nsec_val -= 1000;
        }
        tmp = localtime (&sec_val);
        if (io->interval >= 1000) {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
        } else if (io->interval >= 100) {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d.%1d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val/100);
        } else if (io->interval >= 10) {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d.%02d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val/10);
        } else {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d.%03d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val);
        }
    } else {
        if (!ext) {
            g_snprintf(buf, buf_len, "%d.%03d", interval/1000,interval%1000);
        } else if (io->interval >= 60000) {
            g_snprintf(buf, buf_len, "%dm", interval/60000);
        } else if (io->interval >= 1000) {
            g_snprintf(buf, buf_len, "%ds", interval/1000);
        } else if (io->interval >= 100) {
            g_snprintf(buf, buf_len, "%d.%1ds", interval/1000,(interval/100)%10);
        } else if (io->interval >= 10) {
            g_snprintf(buf, buf_len, "%d.%02ds", interval/1000,(interval/10)%100);
        } else {
            g_snprintf(buf, buf_len, "%d.%03ds", interval/1000,interval%1000);
        }
    }
}

static void
io_stat_draw(io_stat_t *io)
{
    int            i, tics, ystart, ys;
    guint32        last_interval, first_interval, interval_delta;
    gint32         current_interval;
    guint32        top_y_border;
    guint32        bottom_y_border;
    PangoLayout   *layout;
    int            label_width, label_height;
    guint32        draw_width, draw_height;
    char           label_string[45];
    GtkAllocation  widget_alloc;

    /* new variables */
    guint32        num_time_intervals; /* number of intervals relative to 1 */
    guint64        max_value;   /* max value of seen data */
    guint32        max_y;       /* max value of the Y scale */
    gboolean       draw_y_as_time;
    gboolean       draw_y_as_load;
    cairo_t       *cr;

    if (!io->needs_redraw) {
        return;
    }
    io->needs_redraw = FALSE;
    /*
    * Set max_interval to duration rounded to the nearest ms. Add the Tick Interval so the last
    * interval will be displayed. For example, if duration = 11.844 secs and 'Tick Interval' == 1,
    * max_interval = 12000; if 0.1, 11900; if 0.01, 11850; and if 0.001, 11845.
    */
    io->max_interval = (guint32)((cfile.elapsed_time.secs*1000) +
        ((cfile.elapsed_time.nsecs+500000)/1000000) +
        io->interval);
    io->max_interval = (io->max_interval / io->interval) * io->interval;
    if (io->max_interval >= NUM_IO_ITEMS * io->interval) {
        /* XXX: Truncate the graph if it covers too much real time, as
         * otherwise we crash later trying to make the graph too wide. There's
         * no good way of warning the user, since this gets recalculated a
         * lot and any dialogue we pop up would spawn 100+ times when scrolling.
         *
         * Should at least stop us from crashing in:
         * https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8583
         */
        io->max_interval = (NUM_IO_ITEMS - 1) * io->interval;
    }
    /*
    * Find the length of the intervals we have data for
    * so we know how large arrays we need to malloc()
    */
    num_time_intervals = io->num_items+1;

    /* XXX move this check to _packet() */
    if (num_time_intervals > NUM_IO_ITEMS) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "IO-Stat error. There are too many entries, bailing out");
        return;
    }

    /*
    * find the max value so we can autoscale the y axis
    */
    max_value = 0;
    for (i=0; i<MAX_GRAPHS; i++) {
        int idx;

        if (!io->graphs[i].display) {
            continue;
        }
        for (idx=0; (guint32)(idx) < num_time_intervals; idx++) {
            guint64 val;

            val = get_it_value(io, i, idx);

            /* keep track of the max value we have encountered */
            if (val>max_value) {
                max_value = val;
            }
        }
    }

    /*
    * Clear out old plot
    */
#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create (io->surface);
#else
    cr = gdk_cairo_create (io->pixmap);
#endif
    cairo_set_source_rgb (cr, 1, 1, 1);
    gtk_widget_get_allocation(io->draw_area, &widget_alloc);
    cairo_rectangle (cr, 0, 0, widget_alloc.width,widget_alloc.height);
    cairo_fill (cr);
    cairo_destroy (cr);
    /*
    * Calculate the y scale we should use
    */
    if (io->max_y_units == AUTO_MAX_YSCALE) {
        max_y = yscale_max[MAX_YSCALE-1];
        for (i=MAX_YSCALE-1; i>1; i--) {
            if (max_value < yscale_max[i]) {
                max_y = yscale_max[i];
            }
        }
    } else if (io->max_y_units == LOGARITHMIC_YSCALE) {
        max_y = 1000000000;
        for (i=1000000000; i>1; i/=10) {
            if (max_value<(guint32)i) {
                max_y = i;
            }
        }
    } else {
        /* the user had specified an explicit y scale to use */
        max_y = io->max_y_units;
    }

    /*
    * If we use ADVANCED and all the graphs are plotting
    * either MIN/MAX/AVG of an FT_RELATIVE_TIME field
    * then we will do some some special processing for the
    * labels for the Y axis below:
    *   we will append the time unit " s" " ms" or " us"
    *   and we will present the unit in decimal
    */
    draw_y_as_time = FALSE;
    draw_y_as_load = FALSE;
    if (io->count_type == COUNT_TYPE_ADVANCED) {
        draw_y_as_time = TRUE;
        for (i=0; i<MAX_GRAPHS; i++) {
            int adv_type;

            if (!io->graphs[i].display) {
                continue;
            }
            if (io->graphs[i].calc_type == CALC_TYPE_LOAD) {
                draw_y_as_load = TRUE;
            }

            adv_type = proto_registrar_get_ftype(io->graphs[i].hf_index);
            switch (adv_type) {
            case FT_RELATIVE_TIME:
                switch (io->graphs[i].calc_type) {
                case CALC_TYPE_SUM:
                case CALC_TYPE_MAX:
                case CALC_TYPE_MIN:
                case CALC_TYPE_AVG:
                    break;
                default:
                    draw_y_as_time = FALSE;
                }
                break;
            default:
                draw_y_as_time = FALSE;
            }
        }
    }

    /*
    * Calculate size of borders surrounding the plot
    * The border on the right side needs to be adjusted depending
    * on the width of the text labels. For simplicity we assume that the
    * top y scale label will be the widest one
    */
    if (draw_y_as_time) {
        if (io->max_y_units == LOGARITHMIC_YSCALE) {
            print_time_scale_string(label_string, sizeof(label_string), 100000, 100000, TRUE); /* 100 ms */
        } else {
            print_time_scale_string(label_string, sizeof(label_string), max_y, max_y, FALSE);
        }
    } else {
        g_snprintf(label_string, sizeof(label_string), "%d", max_y);
    }
    layout = gtk_widget_create_pango_layout(io->draw_area, label_string);
    pango_layout_get_pixel_size(layout, &label_width, &label_height);

    io->left_x_border = 10;
    io->right_x_border = label_width + 20;
    top_y_border = 10;
    bottom_y_border = label_height + 20;

    /*
    * Calculate the size of the drawing area for the actual plot
    */
    draw_width = io->surface_width-io->right_x_border - io->left_x_border;
    draw_height = io->surface_height-top_y_border - bottom_y_border;

    /*
    * Add a warning if too many entries
    */
    if (num_time_intervals >= NUM_IO_ITEMS-1) {
        g_snprintf (label_string, sizeof(label_string), "Warning: Graph limited to %d entries", NUM_IO_ITEMS);
        pango_layout_set_text(layout, label_string, -1);

#if GTK_CHECK_VERSION(2,22,0)
        cr = cairo_create (io->surface);
#else
        cr = gdk_cairo_create (io->pixmap);
#endif
        cairo_move_to (cr, 5, io->surface_height-bottom_y_border-draw_height-label_height/2);
        pango_cairo_show_layout (cr, layout);
        cairo_destroy (cr);
        cr = NULL;
    }

    /* Draw the y axis and labels
    * (we always draw the y scale with 11 ticks along the axis)
    */
#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create (io->surface);
#else
    cr = gdk_cairo_create (io->pixmap);
#endif
    cairo_set_line_width (cr, 1.0);
    cairo_move_to(cr, io->surface_width-io->right_x_border+1.5, top_y_border + 0.5);
    cairo_line_to(cr, io->surface_width-io->right_x_border+1.5, io->surface_height-bottom_y_border + 0.5);
    cairo_stroke(cr);
    if (io->max_y_units == LOGARITHMIC_YSCALE) {
        tics = (int)log10((double)max_y);
        ystart = draw_height/10;
        ys = -1;
    } else {
        tics = 10;
        ystart = ys = 0;
    }

    for (i=ys; i<=tics; i++) {
        int xwidth, lwidth, ypos;

        xwidth = 5;
        if (io->max_y_units == LOGARITHMIC_YSCALE) {
            if (i == ys) {
                /* position for the 0 value */
                ypos = io->surface_height-bottom_y_border;
            } else if (i == tics) {
                /* position for the top value, do not draw logarithmic tics above graph */
                ypos = io->surface_height-bottom_y_border-draw_height;
            } else {
                int j;
                /* draw the logarithmic tics */
                for (j=2; j<10; j++) {
                    ypos = (int)(io->surface_height
                                 - bottom_y_border
                                 - (draw_height - ystart) * (i + log10((double)j))/tics
                                 - ystart);
                    /* draw the tick */
                    cairo_move_to(cr, io->surface_width-io->right_x_border+1.5, ypos+0.5);
                    cairo_line_to(cr, io->surface_width-io->right_x_border+1.5+xwidth,ypos+0.5);
                    cairo_stroke(cr);
                }
                ypos = io->surface_height-bottom_y_border-(draw_height-ystart)*i/tics-ystart;
            }
            /* all "main" logarithmic lines are slightly longer */
            xwidth = 10;
        } else {
            if (!(i%5)) {
                /* first, middle and last tick are slightly longer */
                xwidth = 10;
            }
            ypos = io->surface_height-bottom_y_border-draw_height*i/10;
        }
        /* draw the tick */
        cairo_move_to(cr, io->surface_width-io->right_x_border+1.5, ypos+0.5);
        cairo_line_to(cr, io->surface_width-io->right_x_border+1.5+xwidth,ypos+0.5);
        cairo_stroke(cr);
        /* draw the labels */
        if (xwidth == 10) {
            guint32 value;
            if (io->max_y_units == LOGARITHMIC_YSCALE) {
                value = (guint32)(max_y / pow(10,tics-i));
                if (draw_y_as_time) {
                    print_time_scale_string(label_string, sizeof(label_string), value, value, TRUE);
                } else if (draw_y_as_load) {
                    g_snprintf(label_string, sizeof(label_string), "%d.%1d", value/1000, (value/100)%10);
                } else {
                    g_snprintf(label_string, sizeof(label_string), "%d", value);
                }
            } else {
                value = (max_y/10)*i;
                if (draw_y_as_time) {
                    print_time_scale_string(label_string, sizeof(label_string), value, max_y, FALSE);
                } else if (draw_y_as_load) {
                    g_snprintf(label_string, sizeof(label_string), "%d.%1d", value/1000, (value/100)%10);
                } else {
                    g_snprintf(label_string, sizeof(label_string), "%d", value);
                }
            }

            pango_layout_set_text(layout, label_string, -1);
            pango_layout_get_pixel_size(layout, &lwidth, NULL);

            cairo_move_to (cr, io->surface_width-io->right_x_border+15+label_width-lwidth, ypos-label_height/2);
            pango_cairo_show_layout (cr, layout);

        }
    }

    /* If we have not specified the last_interval via the GUI, just pick the current end of the
    *  capture so that it scrolls nicely when doing live captures.
    */
    if (io->last_interval == 0xffffffff) {
        last_interval = io->max_interval;
    } else {
        last_interval = io->last_interval;
    }

    /*XXX*/
    /* plot the x-scale */
    cairo_move_to(cr, io->left_x_border+0.5, io->surface_height-bottom_y_border+1.5);
    cairo_line_to(cr, io->surface_width-io->right_x_border+1.5,io->surface_height-bottom_y_border+1.5);
    cairo_stroke(cr);
    if ((last_interval/io->interval) >= draw_width/io->pixels_per_tick) {
        first_interval  = (last_interval/io->interval)-draw_width/io->pixels_per_tick+1;
        first_interval *= io->interval;
    } else {
        first_interval = 0;
    }

    interval_delta = (100/io->pixels_per_tick)*io->interval;
    for (current_interval = last_interval;
         current_interval >= (gint32)first_interval;
         current_interval = current_interval-io->interval) {
        int x, xlen;

        /* if pixels_per_tick is 1 or 2, only draw every 10 ticks */
        /* if pixels_per_tick is 5, only draw every 5 ticks */
        if (((io->pixels_per_tick < 5) && (current_interval % (10*io->interval))) ||
            ((io->pixels_per_tick == 5) && (current_interval % (5*io->interval)))) {
                continue;
        }

        if (!(current_interval%interval_delta)) {
            xlen = 10;
        } else if (!(current_interval%(interval_delta/2))) {
            xlen = 8;
        } else {
            xlen = 5;
        }
        x = draw_width+io->left_x_border-((last_interval-current_interval)/io->interval)*io->pixels_per_tick;
        cairo_move_to(cr, x-1-io->pixels_per_tick/2+0.5, io->surface_height-bottom_y_border+1.5);
        cairo_line_to(cr, x-1-io->pixels_per_tick/2+0.5, io->surface_height-bottom_y_border+xlen+1.5);
        cairo_stroke(cr);
        if (xlen == 10) {
            int lwidth, x_pos;
            print_interval_string (label_string, sizeof(label_string), current_interval, io, TRUE);
            pango_layout_set_text(layout, label_string, -1);
            pango_layout_get_pixel_size(layout, &lwidth, NULL);

            if ((x-1-io->pixels_per_tick/2-lwidth/2) < 5) {
                x_pos = 5;
            } else if ((x-1-io->pixels_per_tick/2+lwidth/2) > (io->surface_width-5)) {
                x_pos = io->surface_width-lwidth-5;
            } else {
                x_pos = x-1-io->pixels_per_tick/2-lwidth/2;
            }
            cairo_move_to (cr, x_pos, io->surface_height-bottom_y_border+15);
            pango_cairo_show_layout (cr, layout);
        }

    }
    cairo_destroy (cr);
    cr = NULL;
    g_object_unref(G_OBJECT(layout));

    /*
    * Loop over all graphs and draw them
    */
#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create (io->surface);
#else
    cr = gdk_cairo_create (io->pixmap);
#endif
    cairo_set_line_width (cr, 1.0);

    for (i=MAX_GRAPHS-1; i>=0; i--) {
        guint64 val;
        guint32 interval, x_pos, y_pos, prev_x_pos, prev_y_pos;
        /* Moving average variables */
        guint32 mavg_in_average_count = 0, mavg_left = 0, mavg_right = 0;
        guint64 mavg_cumulated = 0;
        guint64 mavg_to_remove = 0, mavg_to_add = 0;

        if (!io->graphs[i].display) {
            continue;
        }

        if ((io->graphs[i].follow_smooth == GRAPH_FOLLOWFILTER) &&
            (io->filter_type == MOVING_AVERAGE_FILTER)) {
            /* "Warm-up phase" - calculate average on some data not displayed;
            just to make sure average on leftmost and rightmost displayed
            values is as reliable as possible
            */
            guint64 warmup_interval;

            if (first_interval/io->interval > io->filter_order/2) {
                warmup_interval = first_interval/io->interval - io->filter_order/2;
                warmup_interval *= io->interval;
            } else {
                warmup_interval = 0;
            }
            mavg_to_remove = warmup_interval;
            for (; warmup_interval < first_interval; warmup_interval += io->interval) {
                mavg_cumulated += get_it_value(io, i, (int)warmup_interval/io->interval);
                mavg_in_average_count++;
                mavg_left++;
            }
            mavg_cumulated += get_it_value(io, i, (int)warmup_interval/io->interval);
            mavg_in_average_count++;
            for (warmup_interval += io->interval;
                ((warmup_interval < (first_interval + (io->filter_order/2) * (guint64)io->interval)) &&
                 (warmup_interval <= (io->num_items * (guint64)io->interval)));
                 warmup_interval += io->interval) {

                mavg_cumulated += get_it_value(io, i, (int)warmup_interval / io->interval);
                mavg_in_average_count++;
                mavg_right++;
            }
            mavg_to_add = warmup_interval;
        }

        /* initialize prev x/y to the value of the first interval */
        prev_x_pos = draw_width-1 -
            io->pixels_per_tick * ((last_interval - first_interval) / io->interval) +
            io->left_x_border;
        val = get_it_value(io, i, first_interval / io->interval);

        if ((io->graphs[i].follow_smooth == GRAPH_FOLLOWFILTER) &&
            (io->filter_type == MOVING_AVERAGE_FILTER) &&
            (mavg_in_average_count > 0)) {
                val = mavg_cumulated / mavg_in_average_count;
        }

        if (val>max_y) {
            prev_y_pos = 0;
        } else if (io->max_y_units == LOGARITHMIC_YSCALE) {
            if (val == 0) {
                prev_y_pos = (guint32)(draw_height - 1 + top_y_border);
            } else {
                prev_y_pos = (guint32) (
                    (draw_height - ystart)-1 -
                    ((log10((double)((gint64)val)) * (draw_height - ystart)) / log10((double)max_y)) +
                    top_y_border
                    );
            }
        } else {
            prev_y_pos = (guint32)(draw_height-1-(val*draw_height)/max_y+top_y_border);
        }

        for (interval = first_interval;
             interval < last_interval;
             interval += io->interval) {
                x_pos = draw_width-1-io->pixels_per_tick*((last_interval-interval)/io->interval)+io->left_x_border;

                val = get_it_value(io, i, interval/io->interval);
                /* Moving average calculation */
                if ((io->graphs[i].follow_smooth == GRAPH_FOLLOWFILTER) &&
                    (io->filter_type == MOVING_AVERAGE_FILTER)) {
                    if (interval != first_interval) {
                        mavg_left++;
                        if (mavg_left > io->filter_order/2) {
                            mavg_left--;
                            mavg_in_average_count--;
                            mavg_cumulated -= get_it_value(io, i, (int)mavg_to_remove/io->interval);
                            mavg_to_remove += io->interval;
                        }
                        if (mavg_to_add<=(guint64)io->num_items*io->interval) {
                            mavg_in_average_count++;
                            mavg_cumulated += get_it_value(io, i, (int)mavg_to_add/io->interval);
                            mavg_to_add += io->interval;
                        } else {
                            mavg_right--;
                        }
                    }
                    if (mavg_in_average_count > 0) {
                        val = mavg_cumulated / mavg_in_average_count;
                    }
                }

                if (val>max_y) {
                    y_pos = 0;
                } else if (io->max_y_units == LOGARITHMIC_YSCALE) {
                    if (val == 0) {
                        y_pos = (guint32)(draw_height-1+top_y_border);
                    } else {
                        y_pos = (guint32) (
                            (draw_height - ystart) - 1 -
                            (log10((double)(gint64)val) * (draw_height - ystart)) / log10((double)max_y) +
                            top_y_border
                            );
                    }
                } else {
                    y_pos = (guint32)(draw_height - 1 -
                        ((val * draw_height) / max_y) +
                        top_y_border);
                }

                switch (io->graphs[i].plot_style) {
                case PLOT_STYLE_LINE:
                    /* Dont draw anything if the segment entirely above the top of the graph
                    */
                    if ( (prev_y_pos != 0) || (y_pos != 0) ) {
                        cairo_move_to(cr, prev_x_pos+0.5, prev_y_pos+0.5);
                        cairo_line_to(cr, x_pos+0.5, y_pos+0.5);
                        gdk_cairo_set_source_rgba (cr, &io->graphs[i].rgba_color);
                        cairo_stroke(cr);
                    }
                    break;
                case PLOT_STYLE_IMPULSE:
                    if (val) {
                        cairo_move_to(cr, x_pos+0.5, draw_height-1+top_y_border+0.5);
                        cairo_line_to(cr, x_pos+0.5, y_pos+0.5);
                        gdk_cairo_set_source_rgba (cr, &io->graphs[i].rgba_color);
                        cairo_stroke(cr);
                    }
                    break;
                case PLOT_STYLE_FILLED_BAR:
                    if (val) {
                        cairo_rectangle (cr,
                            x_pos-(gdouble)io->pixels_per_tick/2+0.5,
                            y_pos+0.5,
                            io->pixels_per_tick,
                            draw_height-1+top_y_border-y_pos);
                        gdk_cairo_set_source_rgba (cr, &io->graphs[i].rgba_color);
                        cairo_fill (cr);
                    }
                    break;
                case PLOT_STYLE_DOT:
                    if (val) {
                        cairo_arc (cr,
                            x_pos+0.5,
                            y_pos+0.5,
                            (gdouble)io->pixels_per_tick/2,
                            0,
                            2 * G_PI);
                        gdk_cairo_set_source_rgba (cr, &io->graphs[i].rgba_color);
                        cairo_fill (cr);
                    }
                    break;
                }

                prev_y_pos = y_pos;
                prev_x_pos = x_pos;
        }
    }
    cairo_destroy (cr);

    cr = gdk_cairo_create (gtk_widget_get_window(io->draw_area));

#if GTK_CHECK_VERSION(2,22,0)
    cairo_set_source_surface (cr, io->surface, 0, 0);
#else
    gdk_cairo_set_source_pixmap (cr, io->pixmap, 0, 0);
#endif
    cairo_rectangle (cr, 0, 0, io->surface_width, io->surface_height);
    cairo_fill (cr);

    cairo_destroy (cr);

    /* update the scrollbar */
    if (io->max_interval == 0) {
        gtk_adjustment_set_upper(io->scrollbar_adjustment, (gdouble) io->interval);
        gtk_adjustment_set_step_increment(io->scrollbar_adjustment, (gdouble) (io->interval/10));
        gtk_adjustment_set_page_increment(io->scrollbar_adjustment, (gdouble) io->interval);
    } else {
        gtk_adjustment_set_upper(io->scrollbar_adjustment, (gdouble) io->max_interval);
        gtk_adjustment_set_step_increment(io->scrollbar_adjustment, (gdouble) ((last_interval-first_interval)/10));
        gtk_adjustment_set_page_increment(io->scrollbar_adjustment, (gdouble) (last_interval-first_interval));
    }
    gtk_adjustment_set_page_size(io->scrollbar_adjustment, gtk_adjustment_get_page_increment(io->scrollbar_adjustment));
    gtk_adjustment_set_value(io->scrollbar_adjustment, (gdouble)first_interval);
    gtk_adjustment_changed(io->scrollbar_adjustment);
    gtk_adjustment_value_changed(io->scrollbar_adjustment);

}

static void
io_stat_redraw(io_stat_t *io)
{
    io->needs_redraw = TRUE;
    io_stat_draw(io);
}

static void
tap_iostat_draw(void *g)
{
    io_stat_graph_t *git = (io_stat_graph_t *)g;

    io_stat_draw(git->io);
}

/* ok we get called with both the filter and the field.
   make sure the field is part of the filter.
   (make sure and just append it)
   the field MUST be part of the filter or else we won't
   be able to pick up the field values after the edt tree has been
   pruned
*/
static GString *
enable_graph(io_stat_graph_t *gio, const char *filter, const char *field)
{
    GString *real_filter = NULL;
    GString *err_msg;

    gio->display = TRUE;

    if (filter) {
        /* skip all whitespaces */
        while (*filter) {
            if (*filter == ' ') {
                filter++;
                continue;
            }
            if (*filter == '\t') {
                filter++;
                continue;
            }
            break;
        }
        if (*filter) {
            real_filter = g_string_new("");
            g_string_printf(real_filter, "(%s)", filter);
        }
    }
    if (field) {
        /* skip all whitespaces */
        while (*field) {
            if (*field == ' ') {
                field++;
                continue;
            }
            if (*field == '\t') {
                field++;
                continue;
            }
            break;
        }
        if (*field) {
            if (real_filter) {
                g_string_append_printf(real_filter, " && (%s)", field);
            } else {
                real_filter = g_string_new(field);
            }
        }
    }
    err_msg = register_tap_listener("frame", gio, real_filter ? real_filter->str : NULL,
        TL_REQUIRES_PROTO_TREE, tap_iostat_reset, tap_iostat_packet,
        tap_iostat_draw);
    if (real_filter)
        g_string_free(real_filter, TRUE);
    return err_msg;
}

static void
disable_graph(io_stat_graph_t *gio)
{
    if (gio->display) {
        gio->display = FALSE;
        remove_tap_listener(gio);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(gio->display_button),
            FALSE);
    }
}

static void
iostat_init(const char *opt_arg _U_, void* userdata _U_)
{
    io_stat_t *io;
    int i = 0;
    static GdkColor col[MAX_GRAPHS] = {
        {0, 0x0000, 0x0000, 0x0000}, /* Black */
        {0, 0xffff, 0x0000, 0x0000}, /* Red */
        {0, 0x0000, 0xffff, 0x0000}, /* Green */
        {0, 0x0000, 0x0000, 0xffff}, /* Blue */
        {0, 0xffff, 0x5000, 0xffff}  /* Light brilliant magenta */
    };

    static GdkRGBA rgba_col[MAX_GRAPHS] = {
        {0.0, 0.0,   0.0,   1.0}, /* Black */
        {1.0, 0.0,   0.1,   1.0}, /* Red */
        {0.0, 1.0,   0.0,   1.0}, /* Green */
        {0.0, 0.0,   1.0,   1.0}, /* Blue */
        {1.0, 0.314, 1.0,   1.0}  /* Light brilliant magenta */
    };

    GString *error_string;

    io = g_new(io_stat_t,1);
    io->needs_redraw         = TRUE;
    io->interval             = tick_interval_values[DEFAULT_TICK_VALUE_INDEX];
    io->window               = NULL;
    io->draw_area            = NULL;
#if GTK_CHECK_VERSION(2,22,0)
    io->surface              = NULL;
#else
    io->pixmap               = NULL;
#endif
    io->scrollbar            = NULL;
    io->scrollbar_adjustment = NULL;
    io->surface_width        = 500;
    io->surface_height       = 200;
    io->pixels_per_tick      = pixels_per_tick[DEFAULT_PIXELS_PER_TICK_INDEX];
    io->max_y_units          = AUTO_MAX_YSCALE;
    io->count_type           = 0;
    io->last_interval        = 0xffffffff;
    io->max_interval         = 0;
    io->num_items            = 0;
    io->left_x_border        = 0;
    io->right_x_border       = 500;
    io->view_as_time         = FALSE;
    io->start_time.secs      = 0;
    io->start_time.nsecs     = 0;

    for (i=0; i<MAX_GRAPHS; i++) {
        io->graphs[i].color.pixel               = col[i].pixel;
        io->graphs[i].color.red                 = col[i].red;
        io->graphs[i].color.green               = col[i].green;
        io->graphs[i].color.blue                = col[i].blue;
        io->graphs[i].rgba_color.red            = rgba_col[i].red;
        io->graphs[i].rgba_color.green          = rgba_col[i].green;
        io->graphs[i].rgba_color.blue           = rgba_col[i].blue;
        io->graphs[i].rgba_color.alpha          = rgba_col[i].alpha;
        io->graphs[i].display                   = 0;
        io->graphs[i].display_button            = NULL;
        io->graphs[i].filter_field              = NULL;
        io->graphs[i].advanced_buttons          = NULL;
        io->graphs[i].io                        = io;

        io->graphs[i].args                      = g_new(construct_args_t,1);
        io->graphs[i].args->title               = NULL;
        io->graphs[i].args->wants_apply_button  = TRUE;
        io->graphs[i].args->activate_on_ok      = TRUE;
        io->graphs[i].args->modal_and_transient = FALSE;

        io->graphs[i].filter_bt                 = NULL;

        io->graphs[i].follow_smooth = GRAPH_FOLLOWFILTER;
    }
    io_stat_reset(io);

    error_string = enable_graph(&io->graphs[0], NULL, NULL);
    /* Can't attach io_stat tap ! */
    g_assert(error_string == NULL);
#if 0
    if (error_string) {

        fprintf(stderr, "wireshark: Can't attach io_stat tap: %s\n",
            error_string->str);
        g_string_free(error_string, TRUE);
        io->graphs[0].display          = 0;
        io->graphs[0].display_button   = NULL;
        io->graphs[0].filter_field     = NULL;
        io->graphs[0].advanced_buttons = NULL;
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
    io_stat_t      *io           = (io_stat_t *)user_data;
    int             i;
    GtkWidget      *save_bt      = (GtkWidget *)g_object_get_data(G_OBJECT(io->window), "save_bt");
    surface_info_t *surface_info = (surface_info_t *)g_object_get_data(G_OBJECT(save_bt), "surface-info");

    g_free(surface_info);

    for (i=0; i<MAX_GRAPHS; i++) {
        if (io->graphs[i].display) {
            remove_tap_listener(&io->graphs[i]);

            g_free( (gpointer) (io->graphs[i].args->title) );
            io->graphs[i].args->title = NULL;

            g_free(io->graphs[i].args);
            io->graphs[i].args = NULL;
        }
    }
    g_free(io);

    return;
}

static gboolean
pixmap_clicked_event(GtkWidget *widget _U_, GdkEventButton *event, gpointer g)
{
    io_stat_t       *io        = (io_stat_t *)g;
    io_stat_graph_t *graph;
    io_graph_item_t *it;
    guint32          draw_width, interval, last_interval;
    guint32          frame_num = 0;
    int              i;
    gboolean         load      = FALSE, outstanding_call = FALSE;

    draw_width = io->surface_width - io->right_x_border - io->left_x_border;

    if ((event->x <= (draw_width + io->left_x_border + 1 - (draw_width/io->pixels_per_tick)*io->pixels_per_tick)) ||
        (event->x >= (draw_width + io->left_x_border - io->pixels_per_tick/2))) {
          /* Outside draw area */
          return FALSE;
    }

    /*
     * An interval in the IO Graph drawing area has been clicked. If left-clicked (button 1), the frame
     * with the first response in that interval or if left-clicked (button 3) the last is highlighted.
     */
#if GTK_CHECK_VERSION(2,22,0)
    if (((event->button == 1) || (event->button == 3)) && (io->surface != NULL))
#else
    if (((event->button == 1) || (event->button == 3)) && (io->pixmap != NULL))
#endif
    {
        if (io->last_interval == 0xffffffff)
            last_interval = io->max_interval;
        else
            last_interval = io->last_interval;

        /* Get the interval that was clicked */
        if ((last_interval / io->interval) <
                ((draw_width + io->left_x_border - event->x -
                  io->pixels_per_tick / 2 - 1) / io->pixels_per_tick)) {
            interval = 0;
        }
        else {
            interval = (guint32) (
                    (last_interval / io->interval) -
                    ((draw_width + io->left_x_border - event->x -
                      io->pixels_per_tick / 2 - 1) / io->pixels_per_tick));
        }

        /* Determine the lowest or highest frame number depending on whether button 1 or 3 was clicked,
         *  respectively, among the up to 5 currently displayed graphs. */
        for (i=0; i<MAX_GRAPHS; i++) {
            graph = &io->graphs[i];
            if (graph->display) {
                it = &graph->items[interval];
                if (event->button == 1) {
                    if ((frame_num == 0) || (it->first_frame_in_invl < frame_num))
                        frame_num = it->first_frame_in_invl;
                } else {
                    if (it->last_frame_in_invl > frame_num)
                        frame_num = it->last_frame_in_invl;
                }
                if (graph->calc_type == CALC_TYPE_LOAD) {
                    load = TRUE;
                    if (it->time_tot.secs + it->time_tot.nsecs > 0)
                        outstanding_call = TRUE;
                }
            }
        }

        /* XXX - If the frame numbers of *calls* can somehow be determined, the first call or
         * response, whichever is first, and the last call or response, whichever is last,
         * could be highlighted. */
        if ((frame_num == 0) && load && outstanding_call) {
            statusbar_push_temporary_msg(
                "There is no response but at least one call is outstanding in this interval.");
            return FALSE;
        }

        if (frame_num != 0)
            cf_goto_frame(&cfile, frame_num);
    }
    return TRUE;
}

/* create a new backing pixmap of the appropriate size */
static gboolean
draw_area_configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer user_data)
{
    io_stat_t      *io           = (io_stat_t *)user_data;
    GtkWidget      *save_bt;
    GtkAllocation   widget_alloc;
    cairo_t        *cr;
#if GTK_CHECK_VERSION(2,22,0)
    surface_info_t *surface_info = g_new(surface_info_t, 1);
#endif

#if GTK_CHECK_VERSION(2,22,0)
    if (io->surface) {
         cairo_surface_destroy (io->surface);
        io->surface = NULL;
    }
#else
    if (io->pixmap) {
        g_object_unref(io->pixmap);
        io->pixmap = NULL;
    }
#endif

    gtk_widget_get_allocation(widget, &widget_alloc);
#if GTK_CHECK_VERSION(2,22,0)
    io->surface = gdk_window_create_similar_surface (gtk_widget_get_window(widget),
            CAIRO_CONTENT_COLOR,
            widget_alloc.width,
            widget_alloc.height);

#else
    io->pixmap = gdk_pixmap_new(gtk_widget_get_window(widget),
            widget_alloc.width,
            widget_alloc.height,
            -1);
#endif
    io->surface_width = widget_alloc.width;
    io->surface_height = widget_alloc.height;

    save_bt = (GtkWidget *)g_object_get_data(G_OBJECT(io->window), "save_bt");
#if GTK_CHECK_VERSION(2,22,0)
    surface_info->surface = io->surface;
    surface_info->width = widget_alloc.width;
    surface_info->height = widget_alloc.height;
    g_object_set_data(G_OBJECT(save_bt), "surface-info", surface_info);
    gtk_widget_set_sensitive(save_bt, TRUE);

    cr = cairo_create (io->surface);
#else
    g_object_set_data(G_OBJECT(save_bt), "pixmap", io->pixmap);
    gtk_widget_set_sensitive(save_bt, TRUE);

    cr = gdk_cairo_create (io->pixmap);
#endif
    cairo_rectangle (cr, 0, 0, widget_alloc.width, widget_alloc.height);
    cairo_set_source_rgb (cr, 1, 1, 1);
    cairo_fill (cr);
    cairo_destroy (cr);

    io_stat_redraw(io);
    return TRUE;
}

static void
scrollbar_changed(GtkWidget *widget _U_, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;
    guint32    mi;

    mi = (guint32) (gtk_adjustment_get_value(io->scrollbar_adjustment)
                    + gtk_adjustment_get_page_size(io->scrollbar_adjustment));

    if (io->last_interval == mi) {
        return;
    }

    io->last_interval = (mi/io->interval) * io->interval;
    io_stat_redraw(io);
    return;
}
#if GTK_CHECK_VERSION(3,0,0)
static gboolean
draw_area_draw(GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
    io_stat_t     *io = (io_stat_t *)user_data;
    GtkAllocation  allocation;

    gtk_widget_get_allocation (widget, &allocation);
    cairo_set_source_surface (cr, io->surface, 0, 0);
    cairo_rectangle (cr, 0, 0, allocation.width, allocation.width);
    cairo_fill (cr);

    return FALSE;
}
#else
/* redraw the screen from the backing pixmap */
static gboolean
draw_area_expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;
    cairo_t   *cr = gdk_cairo_create (gtk_widget_get_window(widget));

#if GTK_CHECK_VERSION(2,22,0)
    cairo_set_source_surface (cr, io->surface, 0, 0);
#else
    gdk_cairo_set_source_pixmap (cr, io->pixmap, 0, 0);
#endif
    cairo_rectangle (cr, event->area.x, event->area.y, event->area.width, event->area.height);
    cairo_fill (cr);

    cairo_destroy (cr);

    return FALSE;
}
#endif
static void
create_draw_area(io_stat_t *io, GtkWidget *box)
{
    io->draw_area = gtk_drawing_area_new();
    g_signal_connect(io->draw_area, "destroy", G_CALLBACK(draw_area_destroy_cb), io);

    gtk_widget_set_size_request(io->draw_area, io->surface_width, io->surface_height);

    /* signals needed to handle backing pixmap */
#if GTK_CHECK_VERSION(3,0,0)
    g_signal_connect(io->draw_area, "draw", G_CALLBACK(draw_area_draw), io);
#else
    g_signal_connect(io->draw_area, "expose-event", G_CALLBACK(draw_area_expose_event), io);
#endif
    g_signal_connect(io->draw_area, "configure-event", G_CALLBACK(draw_area_configure_event), io);
    gtk_widget_add_events (io->draw_area, GDK_BUTTON_PRESS_MASK);
    g_signal_connect(io->draw_area, "button-press-event", G_CALLBACK(pixmap_clicked_event), io);

    gtk_widget_show(io->draw_area);
    gtk_box_pack_start(GTK_BOX(box), io->draw_area, TRUE, TRUE, 0);

    /* create the associated scrollbar */
    io->scrollbar_adjustment = (GtkAdjustment *)gtk_adjustment_new(0,0,0,0,0,0);
    io->scrollbar = gtk_scrollbar_new(GTK_ORIENTATION_HORIZONTAL, io->scrollbar_adjustment);
    gtk_widget_show(io->scrollbar);
    gtk_box_pack_start(GTK_BOX(box), io->scrollbar, FALSE, FALSE, 0);
    g_signal_connect(io->scrollbar_adjustment, "value-changed", G_CALLBACK(scrollbar_changed), io);
}

static void
tick_interval_select(GtkWidget *item, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;
    int i;

    i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

    io->interval = tick_interval_values[i];
    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(io->window));
    io_stat_redraw(io);
}

static void
pixels_per_tick_select(GtkWidget *item, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;
    int i;

    i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));
    io->pixels_per_tick = pixels_per_tick[i];
    io_stat_redraw(io);
}

static void
plot_style_select(GtkWidget *item, gpointer user_data)
{
    io_stat_graph_t *ppt = (io_stat_graph_t *)user_data;
    int val;

    val = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

    ppt->plot_style = val;

    io_stat_redraw(ppt->io);
}

static GtkWidget *
create_pixels_per_tick_menu_items(io_stat_t *io)
{
    char       str[5];
    GtkWidget *combo_box;
    int        i;

    combo_box = gtk_combo_box_text_new ();

    for (i=0; i<MAX_PIXELS_PER_TICK; i++) {
        g_snprintf(str, sizeof(str), "%u", pixels_per_tick[i]);
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_PIXELS_PER_TICK_INDEX);
    g_signal_connect(combo_box, "changed", G_CALLBACK(pixels_per_tick_select), io);

    return combo_box;
}

static void
yscale_select(GtkWidget *item, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;
    int        i;

    i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

    io->max_y_units = yscale_max[i];
    io_stat_redraw(io);
}

static void
filter_select(GtkWidget *item, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;
    int        i;

    i = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

    if (i == NO_FILTER_ORDER) {
        io->filter_type = NO_FILTER;
    } else {
        io->filter_type = MOVING_AVERAGE_FILTER;
        io->filter_order = moving_average_orders[i];
    }
    io_stat_redraw(io);
}

static GtkWidget *
create_tick_interval_menu_items(io_stat_t *io)
{
    GtkWidget *combo_box;
    char       str[15];
    int        i;

    combo_box = gtk_combo_box_text_new ();

    for (i=0; i<MAX_TICK_VALUES; i++) {
        if (tick_interval_values[i] >= 60000) {
            g_snprintf(str, sizeof(str), "%u min", tick_interval_values[i]/60000);
        } else if (tick_interval_values[i] >= 1000) {
            g_snprintf(str, sizeof(str), "%u sec", tick_interval_values[i]/1000);
        } else if (tick_interval_values[i] >= 100) {
            g_snprintf(str, sizeof(str), "0.%1u sec", (tick_interval_values[i]/100)%10);
        } else if (tick_interval_values[i] >= 10) {
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
    char       str[15];
    GtkWidget *combo_box;
    int        i;

    combo_box = gtk_combo_box_text_new ();
    for (i=0; i<MAX_YSCALE; i++) {
        if (yscale_max[i] == LOGARITHMIC_YSCALE) {
            g_strlcpy(str, "Logarithmic", sizeof(str));
        } else if (yscale_max[i] == AUTO_MAX_YSCALE) {
            g_strlcpy(str, "Auto", sizeof(str));
        } else {
            g_snprintf(str, sizeof(str), "%u", yscale_max[i]);
        }
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_YSCALE_INDEX);
    g_signal_connect(combo_box, "changed", G_CALLBACK(yscale_select), io);
    return combo_box;
}

static GtkWidget *
create_filter_menu_items(io_stat_t *io)
{
    char       str[15];
    GtkWidget *combo_box;
    int        i;

    combo_box = gtk_combo_box_text_new ();

    for (i=0; i<MAX_MOVING_AVERAGE_ORDER; i++) {
        if (i == NO_FILTER_ORDER) {
            g_strlcpy(str, "No filter", sizeof(str));
        } else {
            g_snprintf(str, sizeof(str), "M.avg %u", moving_average_orders[i]);
        }
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), str);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), 0);
    g_signal_connect(combo_box, "changed", G_CALLBACK(filter_select), io);
    return combo_box;
}

static void
count_type_select(GtkWidget *item, gpointer user_data)
{
    io_stat_t       *io = (io_stat_t *)user_data;
    int              i;
    GtkAllocation    widget_alloc;
    static gboolean  advanced_visible = FALSE;

    io->count_type = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

    if (io->count_type == COUNT_TYPE_ADVANCED) {
        for (i=0; i<MAX_GRAPHS; i++) {
            disable_graph(&io->graphs[i]);
            gtk_widget_show(io->graphs[i].advanced_buttons);
            /* redraw the entire window so the unhidden widgets show up, hopefully */
            gtk_widget_get_allocation(io->window, &widget_alloc);
            gtk_widget_queue_draw_area(io->window,
                           0,
                           0,
                           widget_alloc.width,
                           widget_alloc.height);
        }
        advanced_visible = TRUE;
        io_stat_redraw(io);
    } else if (advanced_visible) {
        for (i=0; i<MAX_GRAPHS; i++) {
            gtk_widget_hide(io->graphs[i].advanced_buttons);
            filter_callback(item, &io->graphs[i]);
        }
        advanced_visible = FALSE;
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

    for (i=0; i<MAX_COUNT_TYPES; i++) {
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

    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
    gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);
    gtk_widget_show(hbox);

    label = gtk_label_new(name);
    gtk_widget_show(label);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    combo_box = (*func)(io);
    gtk_box_pack_end(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
    gtk_widget_show(combo_box);
}

static void
view_as_time_toggle_dest(GtkWidget *widget _U_, gpointer user_data)
{
    io_stat_t *io = (io_stat_t *)user_data;

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

    frame_vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_box_pack_start(GTK_BOX(box), frame_vbox, FALSE, FALSE, 0);
    gtk_widget_show(frame_vbox);

    frame = gtk_frame_new("X Axis");
    gtk_container_add(GTK_CONTAINER(frame_vbox), frame);
    gtk_widget_show(frame);

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(frame), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
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

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(frame), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
    gtk_widget_show(vbox);

    create_ctrl_menu(io, vbox, "Unit:", create_frames_or_bytes_menu_items);
    create_ctrl_menu(io, vbox, "Scale:", create_yscale_max_menu_items);
    create_ctrl_menu(io, vbox, "Smooth:", create_filter_menu_items);

    return;
}

static void
filter_callback(GtkWidget *widget, gpointer user_data)
{
    io_stat_graph_t   *gio   = (io_stat_graph_t *)user_data;
    const char        *filter;
    dfilter_t         *dfilter;
    const char        *field_name = NULL;

    /* this graph is not active, just update display and redraw */
    if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gio->display_button))) {
        disable_graph(gio);
        io_stat_redraw(gio->io);
        return;
    }

    /* first check if the field string is valid */
    if (gio->io->count_type == COUNT_TYPE_ADVANCED) {
        GString *err_str;
        field_name = gtk_entry_get_text(GTK_ENTRY(gio->calc_field));

        err_str = check_field_unit(field_name, &gio->hf_index, CALC_TYPE_TO_ITEM_UNIT(gio->calc_type));

        if (err_str) {
            /* warn and bail out */
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str->str);
            g_string_free(err_str, TRUE);
            disable_graph(gio);
            io_stat_redraw(gio->io);
            return;
        }
    }


    /* first check if the filter string is valid. */
    filter = gtk_entry_get_text(GTK_ENTRY(gio->filter_field));
    if (!dfilter_compile(filter, &dfilter)) {
        bad_dfilter_alert_box(gtk_widget_get_toplevel(widget),
            filter);
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
    remove_tap_listener(gio);

    io_stat_reset(gio->io);
    enable_graph(gio, filter, field_name);
    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(gio->io->window));
    io_stat_redraw(gio->io);

    return;
}

static void
calc_type_select(GtkWidget *item, gpointer user_data)
{
    io_stat_graph_t *gio = (io_stat_graph_t *)user_data;

    gio->calc_type = gtk_combo_box_get_active (GTK_COMBO_BOX(item));

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
    for (i=0; i<MAX_CALC_TYPES; i++) {
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

    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
    gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);
    gtk_widget_show(hbox);

    label = gtk_label_new(name);
    gtk_widget_show(label);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    combo_box = (*func)(gio);
    gtk_box_pack_end(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
    gtk_widget_show(combo_box);
}

static void
create_advanced_field(io_stat_graph_t *gio, GtkWidget *box)
{
    gio->calc_field = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(box), gio->calc_field, TRUE, TRUE, 0);
    gtk_widget_show(gio->calc_field);
    g_signal_connect(gio->calc_field, "activate", G_CALLBACK(filter_callback), gio);
    g_object_set_data (G_OBJECT(gio->calc_field), E_FILT_FIELD_NAME_ONLY_KEY, (gpointer)"");
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

    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
    gio->advanced_buttons = hbox;
    gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 0);
    gtk_widget_hide(hbox);

    gio->calc_type = CALC_TYPE_SUM;
    create_advanced_menu(gio, hbox, "Calc:", create_calc_types_menu_items);
    create_advanced_field(gio, hbox);
}

static void
filter_button_clicked(GtkWidget *w, gpointer user_data)
{
    io_stat_graph_t *gio = (io_stat_graph_t *)user_data;

    display_filter_construct_cb(w, gio->args);
    return;
}

static void
smooth_filter_toggled(GtkWidget *w, gpointer user_data)
{
    io_stat_graph_t *gio = (io_stat_graph_t *)user_data;

    gio->follow_smooth =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
    io_stat_redraw(gio->io);
}

static void
create_filter_box(io_stat_graph_t *gio, GtkWidget *box, int num)
{
    GtkWidget *combo_box;
    GtkWidget *hbox;
    GtkWidget *label;
    GtkWidget *smooth;
    char str[256];
    int  i;

    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
    gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);
    gtk_widget_show(hbox);

    g_snprintf(str, sizeof(str), "Graph %d", num);
    gio->display_button = gtk_toggle_button_new_with_label(str);
    gtk_box_pack_start(GTK_BOX(hbox), gio->display_button, FALSE, FALSE, 0);
    gtk_widget_show(gio->display_button);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(gio->display_button), gio->display);
    g_signal_connect(gio->display_button, "toggled", G_CALLBACK(filter_callback), gio);

    label = gtk_label_new("Color");
    gtk_widget_show(label);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

#if GTK_CHECK_VERSION(3,0,0)
    gtk_widget_override_color(label, (GtkStateFlags)GTK_STATE_FLAG_NORMAL, &gio->rgba_color);
    /* XXX gtk_widget_override_color() takes flags not state */
    gtk_widget_override_color(label, (GtkStateFlags)GTK_STATE_ACTIVE, &gio->rgba_color);
    gtk_widget_override_color(label, (GtkStateFlags)GTK_STATE_PRELIGHT, &gio->rgba_color);
    gtk_widget_override_color(label, (GtkStateFlags)GTK_STATE_SELECTED, &gio->rgba_color);
    gtk_widget_override_color(label, (GtkStateFlags)GTK_STATE_INSENSITIVE, &gio->rgba_color);
#else
    gtk_widget_modify_fg(label, GTK_STATE_NORMAL, &gio->color);
    gtk_widget_modify_fg(label, GTK_STATE_ACTIVE, &gio->color);
    gtk_widget_modify_fg(label, GTK_STATE_PRELIGHT, &gio->color);
    gtk_widget_modify_fg(label, GTK_STATE_SELECTED, &gio->color);
    gtk_widget_modify_fg(label, GTK_STATE_INSENSITIVE, &gio->color);
#endif
/*  g_signal_connect(gio->display_button, "toggled", G_CALLBACK(filter_callback), gio);*/


    /* filter prefs dialog */
    gio->filter_bt = ws_gtk_button_new_from_stock(WIRESHARK_STOCK_DISPLAY_FILTER_ENTRY);

    g_snprintf(str, sizeof(str), "Wireshark: Display Filter  IO-Stat (Filter:%d)", num);
    g_free( (gpointer) (gio->args->title) );
    gio->args->title = g_strdup(str);

    g_signal_connect(gio->filter_bt, "clicked", G_CALLBACK(filter_button_clicked), gio);
    g_signal_connect(gio->filter_bt, "destroy", G_CALLBACK(filter_button_destroy_cb), NULL);

    gtk_box_pack_start(GTK_BOX(hbox), gio->filter_bt, FALSE, TRUE, 0);
    gtk_widget_show(gio->filter_bt);

    gio->filter_field = gtk_entry_new();
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
    g_snprintf(str, sizeof(str), " Style:");
    label = gtk_label_new(str);
    gtk_widget_show(label);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    combo_box = gtk_combo_box_text_new ();
    for (i=0; i<MAX_PLOT_STYLES; i++) {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo_box), plot_style_name[i]);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), DEFAULT_PLOT_STYLE);
    g_signal_connect(combo_box, "changed", G_CALLBACK(plot_style_select), &gio->io->graphs[num-1]);

    gtk_box_pack_start(GTK_BOX(hbox), combo_box, FALSE, FALSE, 0);
    gtk_widget_show(combo_box);

    /*
     * Create smooth followfilter option
     */
    smooth = gtk_check_button_new_with_mnemonic("Smooth");
    gtk_widget_set_tooltip_text(smooth,  "Only has effect if a smothing filter is set");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(smooth),
        gio->follow_smooth);
    g_signal_connect(smooth, "toggled", G_CALLBACK(smooth_filter_toggled),
        gio);
    gtk_widget_show(smooth);
    gtk_box_pack_end(GTK_BOX(hbox), smooth, FALSE, FALSE, 0);

    return;
}

static void
create_filter_area(io_stat_t *io, GtkWidget *box)
{
    GtkWidget *frame;
    GtkWidget *vbox;
    int i;

    frame = gtk_frame_new("Graphs");
    gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 0);
    gtk_widget_show(frame);

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
    gtk_container_add(GTK_CONTAINER(frame), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
    gtk_widget_show(vbox);

    for (i=0; i<MAX_GRAPHS; i++) {
        create_filter_box(&io->graphs[i], vbox, i+1);
    }

    return;
}

static void
copy_as_csv_cb(GtkWindow *copy_bt _U_, gpointer user_data)
{
    guint32     i, interval;
    guint64     val;
    char        string[15];
    GtkClipboard *cb;
    GString     *CSV_str = g_string_new("");
    io_stat_t   *io = (io_stat_t *)user_data;

    g_string_append(CSV_str, "\"Interval start\"");
    for (i=0; i<MAX_GRAPHS; i++) {
        if (io->graphs[i].display) {
            g_string_append_printf(CSV_str, ",\"Graph %d\"", i+1);
        }
    }
    g_string_append(CSV_str,"\n");

    for (interval=0; interval<io->max_interval; interval+=io->interval) {
        print_interval_string (string, sizeof(string), interval, io, FALSE);
        g_string_append_printf(CSV_str, "\"%s\"", string);
        for (i=0; i<MAX_GRAPHS; i++) {
            if (io->graphs[i].display) {
                val = get_it_value(io, i, interval/io->interval);
                g_string_append_printf(CSV_str, ",\"%" G_GINT64_MODIFIER "d\"", val);
            }
        }
        g_string_append(CSV_str,"\n");
    }

    /* Now that we have the CSV data, copy it into the default clipboard */
    cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);    /* Get the default clipboard */
    gtk_clipboard_set_text(cb, CSV_str->str, -1);       /* Copy the CSV data into the clipboard */
    g_string_free(CSV_str, TRUE);               /* Free the memory */
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

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_add(GTK_CONTAINER(io->window), vbox);
    gtk_widget_show(vbox);

    create_draw_area(io, vbox);

    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
    gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
    gtk_widget_show(hbox);

    create_filter_area(io, hbox);
    create_ctrl_area(io, hbox);

    io_stat_set_title(io);

    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_SAVE,
                  GTK_STOCK_COPY, GTK_STOCK_HELP, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(io->window, close_bt, window_cancel_button_cb);
    gtk_widget_set_tooltip_text(close_bt,  "Close this dialog");
    save_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_SAVE);
    gtk_widget_set_sensitive(save_bt, FALSE);
    gtk_widget_set_tooltip_text(save_bt, "Save the displayed graph to a file");
    g_signal_connect(save_bt, "clicked", G_CALLBACK(pixmap_save_cb), NULL);
    g_object_set_data(G_OBJECT(io->window), "save_bt", save_bt);

    copy_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_COPY);
    gtk_widget_set_tooltip_text(copy_bt,
                                "Copy values from selected graphs to the clipboard in"
                                " CSV (Comma Separated Values) format");
    g_signal_connect(copy_bt, "clicked", G_CALLBACK(copy_as_csv_cb), io);

    help_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_IO_GRAPH_DIALOG);
    gtk_widget_set_tooltip_text (help_bt, "Show topic specific help");
    g_signal_connect(io->window, "delete-event", G_CALLBACK(window_delete_event_cb), NULL);

    gtk_widget_show(io->window);
    window_present(io->window);
}

void
gui_iostat_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    iostat_init(NULL,NULL);
}

void
register_tap_listener_gtk_iostat(void)
{
    register_stat_cmd_arg("io,stat", iostat_init,NULL);
}
