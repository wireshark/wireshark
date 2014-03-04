/* memory_dlg.c
 *
 * Based on
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

#include <math.h>
#include <gtk/gtk.h>

#include "ui/gtk/dlg_utils.h"
#include "ui/simple_dialog.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/gui_utils.h"

#include "wsutil/str_util.h"
#include "epan/app_mem_usage.h"

enum {
    MAX_GRAPHS = 10
};

#define MAX_YSCALE          28
static guint32 yscale_max[MAX_YSCALE] = {0, 1, 10, 20,
                                         50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000,
                                         50000, 100000, 200000, 500000, 1000000, 2000000,
                                         5000000, 10000000, 20000000, 50000000, 100000000,
                                         200000000, 500000000, 1000000000, 2000000000};

#define DEFAULT_PIXELS_PER_TICK 5

#define NUM_IO_ITEMS 100000
typedef struct _io_item_t {
    gsize bytes;
} io_item_t;

typedef struct _io_stat_graph_t {
    struct _io_stat_t *io;

    io_item_t         *items[NUM_IO_ITEMS];
    gboolean           display;
    GtkWidget         *display_button;
} io_stat_graph_t;

typedef struct _io_stat_t {
    gboolean       needs_redraw;
    guint32        num_items;   /* total number of items in all intervals (zero relative) */
    guint32        left_x_border;
    guint32        right_x_border;
    nstime_t       start_time;

    struct _io_stat_graph_t graphs[MAX_GRAPHS];
    GtkWidget     *window;
    GtkWidget     *draw_area;
#if GTK_CHECK_VERSION(2,22,0)
    cairo_surface_t *surface;
#else
    GdkPixmap       *pixmap;
#endif
    int            surface_width;
    int            surface_height;
    int            pixels_per_tick;

    guint timer_id;
} io_stat_t;

#define INTERVAL 1000

static void
io_stat_reset(io_stat_t *io)
{
    int i, j;

    io->needs_redraw = TRUE;
    for (i=0; i<MAX_GRAPHS; i++) {
        for (j=0; j<NUM_IO_ITEMS; j++) {
            io_item_t *ioi;
            ioi = (io_item_t *)io->graphs[i].items[j];

            ioi->bytes      = 0;
        }
    }
    io->num_items        = 0;
    io->start_time.secs  = time(NULL);
    io->start_time.nsecs = 0;
}

static guint64
get_it_value(io_stat_t *io, int graph, int idx)
{
    io_item_t *it;

    g_assert(graph < MAX_GRAPHS);
    g_assert(idx < NUM_IO_ITEMS);

    it = (io_item_t *)io->graphs[graph].items[idx];

        return it->bytes;
}

static void
print_interval_string(char *buf, int buf_len, guint32 interval, io_stat_t *io)
{
        struct tm *tmp;
        time_t sec_val = interval/1000 + io->start_time.secs;
        gint32 nsec_val = interval%1000 + io->start_time.nsecs/1000000;

        if (nsec_val >= 1000) {
            sec_val++;
            nsec_val -= 1000;
        }
        tmp = localtime (&sec_val);
        if (INTERVAL >= 1000) {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
        } else if (INTERVAL >= 100) {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d.%1d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val/100);
        } else if (INTERVAL >= 10) {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d.%02d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val/10);
        } else {
            g_snprintf(buf, buf_len, "%02d:%02d:%02d.%03d", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, nsec_val);
        }
}

static void
io_stat_draw(io_stat_t *io)
{
    int            i;
    guint32        last_interval, first_interval, interval_delta;
    gint32         current_interval;
    guint32        top_y_border;
    guint32        bottom_y_border;
    PangoLayout   *layout;
    int            label_width, label_height;
    guint32        draw_width, draw_height;
    GtkAllocation  widget_alloc;

    /* new variables */
    guint32        num_time_intervals; /* number of intervals relative to 1 */
    guint64        max_value;   /* max value of seen data */
    guint32        max_y;       /* max value of the Y scale */
    cairo_t       *cr;

    if (!io->needs_redraw) {
        return;
    }
    io->needs_redraw = FALSE;
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
    max_y = yscale_max[MAX_YSCALE-1];
    for (i=MAX_YSCALE-1; i>1; i--) {
        if (max_value < yscale_max[i]) {
            max_y = yscale_max[i];
        }
    }

    layout = gtk_widget_create_pango_layout(io->draw_area, "99999 T bytes");
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

    /* Draw the y axis and labels
    * (we always draw the y scale with 11 ticks along the axis)
    */
#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create(io->surface);
#else
    cr = gdk_cairo_create(io->pixmap);
#endif
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, io->surface_width-io->right_x_border+1.5, top_y_border + 0.5);
    cairo_line_to(cr, io->surface_width-io->right_x_border+1.5, io->surface_height-bottom_y_border + 0.5);
    cairo_stroke(cr);

    for (i=0; i<=10; i++) {
        int xwidth, lwidth, ypos;

        xwidth = 5;
            if (!(i%5)) {
                /* first, middle and last tick are slightly longer */
                xwidth = 10;
            }
            ypos = io->surface_height-bottom_y_border-draw_height*i/10;
        /* draw the tick */
        cairo_move_to(cr, io->surface_width-io->right_x_border+1.5, ypos+0.5);
        cairo_line_to(cr, io->surface_width-io->right_x_border+1.5+xwidth,ypos+0.5);
        cairo_stroke(cr);
        /* draw the labels */
        if (xwidth == 10) {
            guint32 value = (max_y/10)*i;
            char *label_tmp;

            label_tmp = format_size(value, format_size_unit_bytes);

            pango_layout_set_text(layout, label_tmp, -1);
            pango_layout_get_pixel_size(layout, &lwidth, NULL);

            cairo_move_to (cr, io->surface_width-io->right_x_border+15+label_width-lwidth, ypos-label_height/2);
            pango_cairo_show_layout (cr, layout);

            g_free(label_tmp);
        }
    }

    last_interval = (io->num_items) * INTERVAL;

    /*XXX*/
    /* plot the x-scale */
    cairo_move_to(cr, io->left_x_border+0.5, io->surface_height-bottom_y_border+1.5);
    cairo_line_to(cr, io->surface_width-io->right_x_border+1.5,io->surface_height-bottom_y_border+1.5);
    cairo_stroke(cr);
    if ((last_interval/INTERVAL) >= draw_width/io->pixels_per_tick) {
        first_interval  = (last_interval/INTERVAL)-draw_width/io->pixels_per_tick+1;
        first_interval *= INTERVAL;
    } else {
        first_interval = 0;
    }

    interval_delta = (100/io->pixels_per_tick)*INTERVAL;
    for (current_interval = last_interval;
         current_interval >= (gint32)first_interval;
         current_interval = current_interval-INTERVAL) {
        int x, xlen;

        /* if pixels_per_tick is 1 or 2, only draw every 10 ticks */
        /* if pixels_per_tick is 5, only draw every 5 ticks */
        if (((io->pixels_per_tick < 5) && (current_interval % (10*INTERVAL))) ||
            ((io->pixels_per_tick == 5) && (current_interval % (5*INTERVAL)))) {
                continue;
        }

        if (!(current_interval%interval_delta)) {
            xlen = 10;
        } else if (!(current_interval%(interval_delta/2))) {
            xlen = 8;
        } else {
            xlen = 5;
        }
        x = draw_width+io->left_x_border-((last_interval-current_interval)/INTERVAL)*io->pixels_per_tick;
        cairo_move_to(cr, x-1-io->pixels_per_tick/2+0.5, io->surface_height-bottom_y_border+1.5);
        cairo_line_to(cr, x-1-io->pixels_per_tick/2+0.5, io->surface_height-bottom_y_border+xlen+1.5);
        cairo_stroke(cr);
        if (xlen == 10) {
            char label_string[64];
            int lwidth, x_pos;
            print_interval_string (label_string, sizeof(label_string), current_interval, io);
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

        if (!io->graphs[i].display) {
            continue;
        }

        /* initialize prev x/y to the value of the first interval */
        prev_x_pos = draw_width-1 -
            io->pixels_per_tick * ((last_interval - first_interval) / INTERVAL) +
            io->left_x_border;
        val = get_it_value(io, i, first_interval / INTERVAL);

        if (val>max_y) {
            prev_y_pos = 0;
        } else {
            prev_y_pos = (guint32)(draw_height-1-(val*draw_height)/max_y+top_y_border);
        }

        for (interval = first_interval;
             interval < last_interval;
             interval += INTERVAL) {
                x_pos = draw_width-1-io->pixels_per_tick*((last_interval-interval)/INTERVAL)+io->left_x_border;

                val = get_it_value(io, i, interval/INTERVAL);
                /* Moving average calculation */

                if (val>max_y) {
                    y_pos = 0;
                } else {
                    y_pos = (guint32)(draw_height - 1 -
                        ((val * draw_height) / max_y) +
                        top_y_border);
                }

                    /* Dont draw anything if the segment entirely above the top of the graph
                    */
                    if ( (prev_y_pos != 0) || (y_pos != 0) ) {
                        static GdkRGBA red_color = {1.0, 0.0, 0.1, 1.0};

                        cairo_move_to(cr, prev_x_pos+0.5, prev_y_pos+0.5);
                        cairo_line_to(cr, x_pos+0.5, y_pos+0.5);
                        gdk_cairo_set_source_rgba(cr, &red_color);
                        cairo_stroke(cr);
                    }

                prev_y_pos = y_pos;
                prev_x_pos = x_pos;
        }
    }
    cairo_destroy(cr);

    cr = gdk_cairo_create(gtk_widget_get_window(io->draw_area));

#if GTK_CHECK_VERSION(2,22,0)
    cairo_set_source_surface(cr, io->surface, 0, 0);
#else
    gdk_cairo_set_source_pixmap(cr, io->pixmap, 0, 0);
#endif
    cairo_rectangle(cr, 0, 0, io->surface_width, io->surface_height);
    cairo_fill (cr);

    cairo_destroy (cr);
}

static void
io_stat_redraw(io_stat_t *io)
{
    io->needs_redraw = TRUE;
    io_stat_draw(io);
}


static void
draw_area_destroy_cb(GtkWidget *widget _U_, gpointer user_data)
{
    io_stat_t      *io           = (io_stat_t *)user_data;
    int             i,j;

    for (i=0; i<MAX_GRAPHS; i++) {
        if (io->graphs[i].display) {

            for (j=0; j<NUM_IO_ITEMS; j++) {
                g_free(io->graphs[i].items[j]);
                io->graphs[i].items[j] = NULL;
            }
        }
    }

    g_source_remove(io->timer_id);

    g_free(io);
}

/* create a new backing pixmap of the appropriate size */
static gboolean
draw_area_configure_event(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer user_data)
{
    io_stat_t      *io           = (io_stat_t *)user_data;
    GtkAllocation   widget_alloc;
    cairo_t        *cr;

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

#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create(io->surface);
#else
    cr = gdk_cairo_create(io->pixmap);
#endif
    cairo_rectangle(cr, 0, 0, widget_alloc.width, widget_alloc.height);
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_fill(cr);
    cairo_destroy(cr);

    io_stat_redraw(io);
    return TRUE;
}

#if GTK_CHECK_VERSION(3,0,0)
static gboolean
draw_area_draw(GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
    io_stat_t     *io = (io_stat_t *)user_data;
    GtkAllocation  allocation;

    gtk_widget_get_allocation(widget, &allocation);
    cairo_set_source_surface(cr, io->surface, 0, 0);
    cairo_rectangle(cr, 0, 0, allocation.width, allocation.width);
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

    gtk_widget_show(io->draw_area);
    gtk_box_pack_start(GTK_BOX(box), io->draw_area, TRUE, TRUE, 0);
}

static void
filter_callback(GtkWidget *widget _U_, gpointer user_data)
{
    io_stat_graph_t   *gio   = (io_stat_graph_t *)user_data;

    /* this graph is not active, just update display and redraw */
    if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(gio->display_button))) {
        gio->display = FALSE;
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(gio->display_button), FALSE);
    } else {
        gio->display = TRUE;
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(gio->display_button), TRUE);
    }

    gdk_window_raise(gtk_widget_get_window(gio->io->window));
    io_stat_redraw(gio->io);
}

static void
create_filter_area(io_stat_t *io, GtkWidget *box)
{
    GtkWidget *frame;
    GtkWidget *hbox;
    int i;

    frame = gtk_frame_new("Memory Graphs");
    gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 0);
    gtk_widget_show(frame);

    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
    gtk_container_add(GTK_CONTAINER(frame), hbox);
    gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
    gtk_widget_show(hbox);

    for (i=0; i<MAX_GRAPHS; i++) {
        const char *label = memory_usage_get(i, NULL);
        GtkWidget *display_button;

	if (!label)
	    break;

        display_button = gtk_toggle_button_new_with_label(label);
        gtk_box_pack_start(GTK_BOX(hbox), display_button, FALSE, FALSE, 0);
        g_signal_connect(display_button, "toggled", G_CALLBACK(filter_callback), &io->graphs[i]);
        gtk_widget_show(display_button);

        io->graphs[i].display_button = display_button;
    }
}

static void
init_io_stat_window(io_stat_t *io)
{
    GtkWidget *vbox;
    GtkWidget *hbox;
    GtkWidget *bbox;
    GtkWidget *close_bt;

    /* create the main window, transient_for top_level */
    io->window = dlg_window_new("Wireshark memory usage");
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

    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    close_bt = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(io->window, close_bt, window_cancel_button_cb);
    gtk_widget_set_tooltip_text(close_bt,  "Close this dialog");

    gtk_widget_show(io->window);
    window_present(io->window);
}


static gboolean
call_it(gpointer user_data)
{
    io_stat_t *io = (io_stat_t *) user_data;
    char buf[64];
    char *tmp;
    int idx, i;

    io->needs_redraw = TRUE;

    idx = io->num_items++;

    /* some sanity checks */
    if ((idx < 0) || (idx >= NUM_IO_ITEMS)) {
        io->num_items = NUM_IO_ITEMS-1;
        return FALSE;
    }


    for (i = 0; i < MAX_GRAPHS; i++) {
        const char *label;

	label = memory_usage_get(i, &io->graphs[i].items[idx]->bytes);

	if (!label)
	   break;

        tmp = format_size(io->graphs[i].items[idx]->bytes, format_size_unit_bytes);
        g_snprintf(buf, sizeof(buf), "%s [%s]", label, tmp);
        gtk_button_set_label(GTK_BUTTON(io->graphs[i].display_button), buf);
        g_free(tmp);
    }

    io_stat_draw(io);

    return TRUE;
}

void
memory_stat_init(void)
{
    io_stat_t *io;
    int i = 0, j = 0;

    io = g_new(io_stat_t,1);
    io->needs_redraw         = TRUE;
    io->window               = NULL;
    io->draw_area            = NULL;
#if GTK_CHECK_VERSION(2,22,0)
    io->surface              = NULL;
#else
    io->pixmap               = NULL;
#endif
    io->surface_width        = 500;
    io->surface_height       = 200;
    io->pixels_per_tick      = DEFAULT_PIXELS_PER_TICK;
    io->num_items            = 0;
    io->left_x_border        = 0;
    io->right_x_border       = 500;
    io->start_time.secs      = time(NULL);
    io->start_time.nsecs     = 0;

    for (i=0; i<MAX_GRAPHS; i++) {
        io->graphs[i].display                   = 0;
        io->graphs[i].display_button            = NULL;
        io->graphs[i].io                        = io;

        for (j=0; j<NUM_IO_ITEMS; j++) {
            io->graphs[i].items[j] = g_new(io_item_t,1);
        }
    }
    io_stat_reset(io);

    /* build the GUI */
    init_io_stat_window(io);
    io->graphs[0].display = TRUE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(io->graphs[0].display_button), TRUE);

    gdk_window_raise(gtk_widget_get_window(io->window));
    io_stat_redraw(io);

    io->timer_id = g_timeout_add(INTERVAL, call_it, io);
}

