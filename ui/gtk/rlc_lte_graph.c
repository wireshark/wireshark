/* rlc_lte_graph.c
 * By Martin Mathieson
 * Based upon tcp_graph.c
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

#include "config.h"

#include <math.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/dissectors/packet-rlc-lte.h>
#include <epan/tap.h>

#include "../globals.h"
#include "ui/simple_dialog.h"
#include "../stat_menu.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/tap_param_dlg.h"

#include "ui/gtk/old-gtk-compat.h"

#define AXIS_HORIZONTAL		0
#define AXIS_VERTICAL		1

#define WINDOW_TITLE_LENGTH 256

#define MOUSE_BUTTON_LEFT	1
#define MOUSE_BUTTON_MIDDLE	2
#define MOUSE_BUTTON_RIGHT	3

#define MAX_PIXELS_PER_SN       90
#define MAX_PIXELS_PER_SECOND   50000

extern int proto_rlc_lte;

struct segment {
    struct segment *next;
    guint32 num;            /* framenum */
    guint32 rel_secs;
    guint32 rel_usecs;
    guint32 abs_secs;
    guint32 abs_usecs;

    gboolean        isControlPDU;
    guint16         SN;
    guint16         ACKNo;
    #define MAX_NACKs 128
    guint16         noOfNACKs;
    guint16         NACKs[MAX_NACKs];

    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint8          rlcMode;
    guint8          direction;
};

struct line {
    double x1, y1, x2, y2;
};

struct irect {
    int x, y, width, height;
};

typedef enum {
    ELMT_NONE=0,
    ELMT_LINE=1,
    ELMT_ELLIPSE=2
} ElementType;

struct line_params {
    struct line dim;
};

struct rect {
    double x, y, width, height;
};

struct ellipse_params {
    struct rect dim;
};

struct element {
    ElementType type;
    GdkColor *elment_color_p;
    struct segment *parent;
    union {
        struct line_params line;
        struct ellipse_params ellipse;
    } p;
};

struct element_list {
    struct element_list *next;
    struct element *elements;
};

struct axis {
    struct graph *g;			/* which graph we belong to */
    GtkWidget *drawing_area;
    /* Double-buffering to avoid flicker */
#if GTK_CHECK_VERSION(2,22,0)
    cairo_surface_t *surface[2];
#else
    GdkPixmap *pixmap[2];
#endif
    /* Which of the 2 buffers we are currently showing */
    int displayed;
#define AXIS_ORIENTATION	1 << 0
    int flags;
    /* dim and orig (relative to origin of window) of axis' pixmap */
    struct irect p;
    /* dim and orig (relative to origin of axis' pixmap) of scale itself */
    struct irect s;
    gdouble min, max;
    gdouble major, minor;		/* major and minor ticks */
    const char **label;
};

#define HAXIS_INIT_HEIGHT	70
#define VAXIS_INIT_WIDTH	100
#define TITLEBAR_HEIGHT		50
#define RMARGIN_WIDTH	30

struct style_rlc_lte {
    GdkColor seq_color;
    GdkColor ack_color[2];
    int flags;
};

/* style flags */
#define TIME_ORIGIN			0x10
/* show time from beginning of capture as opposed to time from beginning
 * of the connection */
#define TIME_ORIGIN_CAP		0x10
#define TIME_ORIGIN_CONN	0x00

struct cross {
    int x, y;
    int draw;			/* indicates whether we should draw cross at all */
    int erase_needed;   /* indicates whether currently drawn at recorded position */
};

struct bounds {
    double x0, y0, width, height;
};

struct zoom {
    double x, y;
};

struct zooms {
    double x, y;
    double step_x, step_y;
    struct zoom initial;
#define ZOOM_OUT            (1 << 0)
    int flags;
};

struct grab {
    int grabbed;
    int x, y;
};


struct graph {
#define GRAPH_DESTROYED             (1 << 0)
    int flags;
    GtkWidget *toplevel;	/* keypress handler needs this */
    GtkWidget *drawing_area;
    PangoFontDescription *font;	/* font used for annotations etc. */

    /* Double-buffering */
#if GTK_CHECK_VERSION(2,22,0)
    cairo_surface_t *title_surface;
    cairo_surface_t *surface[2];
#else
    GdkPixmap *title_pixmap;
    GdkPixmap *pixmap[2];
#endif
    int displayed;			/* which of both pixmaps is on screen right now */

    /* Next 4 attribs describe the graph in natural units, before any scaling.
     * For example, if we want to display graph of TCP conversation that
     * started 112.309845 s after beginning of the capture and ran until
     * 479.093582 s, 237019 B went through the connection (in one direction)
     * starting with isn 31934022, then (bounds.x0, bounds.y0)=(112.309845,
     * 31934022) and (bounds.width, bounds.height)=(366.783737, 237019). */
    struct bounds bounds;
    /* dimensions and position of the graph, both expressed already in pixels.
     * x and y give the position of upper left corner of the graph relative
     * to origin of the graph window, size is basically bounds*zoom */
    struct irect geom;
    /* viewport (=graph window area which is reserved for graph itself), its
     * size and position relative to origin of the graph window */
    struct irect wp;
    struct grab grab;
    /* If we need to display 237019 sequence numbers (=bytes) onto say 500
     * pixels, we have to scale the graph down by factor of 0.002109. This
     * number would be zoom.y. Obviously, both directions have separate zooms.*/
    struct zooms zoom;
    struct cross cross;
    struct axis *x_axis, *y_axis;

    /* List of segments to show */
    struct segment *segments;

    /* These are filled in with the channel/direction this graph is showing */
    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint8          rlcMode;
    guint8          direction;

    /* Lists of elements to draw */
    struct element_list *elists;		/* element lists */

    /* Colours, etc to be used in drawing */
    struct style_rlc_lte style;
};

#if !GTK_CHECK_VERSION(3,0,0)
static GdkGC *xor_gc = NULL;
#endif
static int refnum=0;

#define debug(section) if (debugging & section)
/* print function entry points */
#define DBS_FENTRY			(1 << 0)
#define DBS_AXES_TICKS		(1 << 1)
#define DBS_AXES_DRAWING	(1 << 2)
#define DBS_GRAPH_DRAWING	(1 << 3)
#define DBS_TPUT_ELMTS		(1 << 4)
/*int debugging = DBS_FENTRY;*/
/* static int debugging = 1; */
/*int debugging = DBS_AXES_TICKS;*/
/*int debugging = DBS_AXES_DRAWING;*/
/*int debugging = DBS_GRAPH_DRAWING;*/
/*int debugging = DBS_TPUT_ELMTS;*/
int debugging = 0;

static void create_gui(struct graph * );
static void create_drawing_area(struct graph * );
static void callback_toplevel_destroy(GtkWidget * , gpointer );
static void callback_create_help(GtkWidget * , gpointer );
static void get_mouse_position(GtkWidget *, int *pointer_x, int *pointer_y, GdkModifierType *mask);
static rlc_lte_tap_info *select_rlc_lte_session(capture_file *, struct segment * );
static int compare_headers(guint16 ueid1, guint16 channelType1, guint16 channelId1, guint8 rlcMode1, guint8 direction1,
                           guint16 ueid2, guint16 channelType2, guint16 channelId2, guint8 rlcMode2, guint8 direction2,
                           gboolean isControlFrame);
static void get_data_control_counts(struct graph *g, int *data, int *acks, int *nacks);

static struct graph *graph_new(void);
static void graph_destroy(struct graph * );
static void graph_initialize_values(struct graph * );
static void graph_init_sequence(struct graph * );
static void draw_element_line(struct graph * , struct element * ,  cairo_t * , GdkColor *new_color);
static void draw_element_ellipse(struct graph * , struct element * , cairo_t *cr);
static void graph_display(struct graph * );
static void graph_pixmaps_create(struct graph * );
static void graph_pixmaps_switch(struct graph * );
static void graph_pixmap_draw(struct graph * );
static void graph_pixmap_display(struct graph * );
static void graph_element_lists_make(struct graph * );
static void graph_element_lists_free(struct graph * );
static void graph_element_lists_initialize(struct graph * );
static void graph_title_pixmap_create(struct graph * );
static void graph_title_pixmap_draw(struct graph * );
static void graph_title_pixmap_display(struct graph * );
static void graph_segment_list_get(struct graph *, gboolean channel_known );
static void graph_segment_list_free(struct graph * );
static void graph_select_segment(struct graph * , int , int );
static int line_detect_collision(struct element * , int , int );
static int ellipse_detect_collision(struct element *e, int x, int y);
static void axis_pixmaps_create(struct axis * );
static void axis_pixmaps_switch(struct axis * );
static void axis_display(struct axis * );
static void v_axis_pixmap_draw(struct axis * );
static void h_axis_pixmap_draw(struct axis * );
static void axis_pixmap_display(struct axis * );
static void axis_compute_ticks(struct axis * , double , double , int );
static double axis_zoom_get(struct axis * , int );
static void axis_ticks_up(int * , int * );
static void axis_ticks_down(int * , int * );
static void axis_destroy(struct axis * );
static int get_label_dim(struct axis * , int , double );

static void toggle_crosshairs(struct graph *);
static void cross_draw(struct graph * , int x, int y);
static void cross_erase(struct graph * );
static gboolean motion_notify_event(GtkWidget * , GdkEventMotion * , gpointer );

static void toggle_time_origin(struct graph * );
static void restore_initial_graph_view(struct graph *g);
static gboolean configure_event(GtkWidget * , GdkEventConfigure * , gpointer );
#if GTK_CHECK_VERSION(3,0,0)
static gboolean draw_event(GtkWidget *widget, cairo_t *cr, gpointer user_data);
#else
static gboolean expose_event(GtkWidget * , GdkEventExpose * , gpointer );
#endif
static gboolean button_press_event(GtkWidget * , GdkEventButton * , gpointer );
static gboolean button_release_event(GtkWidget * , GdkEventButton * , gpointer );
static gboolean key_press_event(GtkWidget * , GdkEventKey * , gpointer );
static void graph_initialize(struct graph *);
static void graph_get_bounds(struct graph *);
static void graph_read_config(struct graph *);
static void rlc_lte_make_elmtlist(struct graph *);

#if defined(_WIN32) && !defined(__MINGW32__)
static int rint(double );	/* compiler template for Windows */
#endif

/*
 * Uncomment the following define to revert WIN32 to
 * use original mouse button controls
 */

/* XXX - what about OS X? */
static char helptext[] =
    "Here's what you can do:\n"
    "\n"
    "   Left Mouse Button             selects segment under cursor in Wireshark's packet list\n"
    "   Middle Mouse Button           zooms in (towards area under cursor)\n"
    "   Right Mouse Button            moves the graph (if zoomed in)\n"
    "\n"
	"   <Space bar>	toggles crosshairs on/off\n"
    "\n"
    "   'i' or '+'       zoom in (towards area under mouse pointer)\n"
    "   'o' or '-'       zoom out\n"
    "                    (add shift to lock Y axis, control to lock X axis)\n"
    "   'r' or <Home>    restore graph to initial state (zoom out max)\n"
    "   't'              toggle time axis to being at zero, or to use time in capture\n"
    "\n"
    "   <Left>           move view left by 100 pixels (if zoomed in)\n"
    "   <Right>          move view right 100 pixels (if zoomed in)\n"
    "   <Up>             move view up by 100 pixels (if zoomed in)\n"
    "   <Down>           move view down by 100 pixels (if zoomed in)\n"
    "\n"
    "   <Shift><Left>    move view left by 10 pixels (if zoomed in)\n"
    "   <Shift><Right>   move view right 10 pixels (if zoomed in)\n"
    "   <Shift><Up>      move view up by 10 pixels (if zoomed in)\n"
    "   <Shift><Down>    move view down by 10 pixels (if zoomed in)\n"
    "\n"
    "   <Ctrl><Left>     move view left by 1 pixel (if zoomed in)\n"
    "   <Ctrl><Right>    move view right 1 pixel (if zoomed in)\n"
    "   <Ctrl><Up>       move view up by 1 pixel (if zoomed in)\n"
    "   <Ctrl><Down>     move view down by 1 pixel (if zoomed in)\n"
    "\n"
    "   <Page_Up>        move up by a large number of pixels (if zoomed in)\n"
    "   <Page_Down>   move down by a large number of pixels (if zoomed in)\n"
;

static void set_busy_cursor(GdkWindow *w)
{
    GdkCursor* cursor = gdk_cursor_new(GDK_WATCH);
    gdk_window_set_cursor(w, cursor);
    gdk_flush();
#if GTK_CHECK_VERSION(3,0,0)
    g_object_unref(cursor);
#else
    gdk_cursor_unref(cursor);
#endif
}

static void unset_busy_cursor(GdkWindow *w)
{
    gdk_window_set_cursor(w, NULL);
    gdk_flush();
}

void rlc_lte_graph_cb(GtkAction *action _U_, gpointer user_data _U_)
{
    struct segment current;
    struct graph *g;

    debug(DBS_FENTRY) puts("rlc_lte_graph_cb()");

    /* Can we choose an RLC channel from the selected frame? */
    if (!select_rlc_lte_session(&cfile, &current)) {
        return;
    }

    if (!(g = graph_new())) {
        return;
    }

    refnum++;
    graph_initialize_values(g);

    /* Get our list of segments from the packet list */
    graph_segment_list_get(g, FALSE);

    create_gui(g);
    graph_init_sequence(g);
}

void rlc_lte_graph_known_channel_launch(guint16 ueid, guint8 rlcMode,
                                        guint16 channelType, guint16 channelId,
                                        guint8 direction)
{
    struct graph *g;

    debug(DBS_FENTRY) puts("rlc_lte_graph_known_channel()");

    if (!(g = graph_new())) {
        return;
    }

    refnum++;
    graph_initialize_values(g);

    /* Can set channel info for graph now */
    g->ueid = ueid;
    g->rlcMode = rlcMode;
    g->channelType = channelType;
    g->channelId = channelId;
    g->direction = direction;

    /* Get our list of segments from the packet list */
    graph_segment_list_get(g, TRUE);

    create_gui(g);
    graph_init_sequence(g);
}


static void create_gui(struct graph *g)
{
    debug(DBS_FENTRY) puts("create_gui()");
    /* create_text_widget(g); */
    create_drawing_area(g);
}

static void create_drawing_area(struct graph *g)
{
#if GTK_CHECK_VERSION(3,0,0)
    GtkStyleContext *context;
#else
    GdkColormap *colormap;
    GdkColor color;
#endif
    char *display_name;
    char window_title[WINDOW_TITLE_LENGTH];
    GtkAllocation widget_alloc;

    debug(DBS_FENTRY) puts("create_drawing_area()");
    display_name = cf_get_display_name(&cfile);
    /* Set channel details in title */
    g_snprintf(window_title, WINDOW_TITLE_LENGTH, "LTE RLC Graph %d: %s (UE-%u, chan=%s%u %s - %s)",
               refnum, display_name,
               g->ueid, (g->channelType == CHANNEL_TYPE_SRB) ? "SRB" : "DRB",
               g->channelId,
               (g->direction == DIRECTION_UPLINK) ? "UL" : "DL",
               (g->rlcMode == RLC_UM_MODE) ? "UM" : "AM");
    g_free(display_name);
    g->toplevel = dlg_window_new("RLC Graph");
    gtk_window_set_title(GTK_WINDOW(g->toplevel), window_title);
    gtk_widget_set_name(g->toplevel, "Test Graph");

    /* Create the drawing area */
    g->drawing_area = gtk_drawing_area_new();
    g->x_axis->drawing_area = g->y_axis->drawing_area = g->drawing_area;
    gtk_widget_set_size_request(g->drawing_area,
                    g->wp.width + g->wp.x + RMARGIN_WIDTH,
                    g->wp.height + g->wp.y + g->x_axis->s.height);
    gtk_widget_show(g->drawing_area);

#if GTK_CHECK_VERSION(3,0,0)
    g_signal_connect(g->drawing_area, "draw", G_CALLBACK(draw_event), g);
#else
    g_signal_connect(g->drawing_area, "expose_event", G_CALLBACK(expose_event), g);
#endif
    g_signal_connect(g->drawing_area, "button_press_event",
                     G_CALLBACK(button_press_event), g);
    g_signal_connect(g->drawing_area, "button_release_event",
                     G_CALLBACK(button_release_event), g);
    g_signal_connect(g->toplevel, "destroy", G_CALLBACK(callback_toplevel_destroy), g);
    g_signal_connect(g->drawing_area, "motion_notify_event",
                     G_CALLBACK(motion_notify_event), g);

    /* why doesn't drawing area send key_press_signals? */
    g_signal_connect(g->toplevel, "key_press_event", G_CALLBACK(key_press_event), g);
    gtk_widget_set_events(g->toplevel,
                          GDK_KEY_PRESS_MASK|GDK_KEY_RELEASE_MASK);

    gtk_widget_set_events(g->drawing_area,
                               GDK_EXPOSURE_MASK
                               | GDK_LEAVE_NOTIFY_MASK
                               | GDK_ENTER_NOTIFY_MASK
                               | GDK_BUTTON_PRESS_MASK
                               | GDK_BUTTON_RELEASE_MASK
                               | GDK_POINTER_MOTION_MASK
                               | GDK_POINTER_MOTION_HINT_MASK);

    gtk_container_add(GTK_CONTAINER(g->toplevel), g->drawing_area);
    gtk_widget_show(g->toplevel);

    /* In case we didn't get what we asked for */
    gtk_widget_get_allocation(GTK_WIDGET(g->drawing_area), &widget_alloc);
    g->wp.width = widget_alloc.width - g->wp.x - RMARGIN_WIDTH;
    g->wp.height = widget_alloc.height - g->wp.y - g->x_axis->s.height;

#if GTK_CHECK_VERSION(3,0,0)
    context = gtk_widget_get_style_context(g->drawing_area);
    gtk_style_context_get(context, GTK_STATE_FLAG_NORMAL,
                          GTK_STYLE_PROPERTY_FONT, &g->font,
                          NULL);
#else
    g->font = gtk_widget_get_style(g->drawing_area)->font_desc;

    colormap = gtk_widget_get_colormap(GTK_WIDGET(g->drawing_area));
    if (!xor_gc) {
        xor_gc = gdk_gc_new(gtk_widget_get_window(g->drawing_area));
        gdk_gc_set_function(xor_gc, GDK_XOR);
        if (!gdk_color_parse("gray15", &color)) {
            /*
             * XXX - do more than just warn.
             */
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                "Could not parse color gray15.");
        }
        if (!gdk_colormap_alloc_color(colormap, &color, FALSE, TRUE)) {
            /*
             * XXX - do more than just warn.
             */
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                "Could not allocate color gray15.");
        }
        gdk_gc_set_foreground(xor_gc, &color);
    }
#endif

    g_signal_connect(g->drawing_area, "configure_event", G_CALLBACK(configure_event), g);
}

static void callback_toplevel_destroy(GtkWidget *widget _U_, gpointer data)
{
    struct graph *g = (struct graph * )data;

    if (!(g->flags & GRAPH_DESTROYED)) {
        g->flags |= GRAPH_DESTROYED;
        graph_destroy((struct graph * )data);
    }
}

static void callback_create_help(GtkWidget *widget _U_, gpointer data _U_)
{
    GtkWidget *toplevel, *vbox, *text, *scroll, *bbox, *close_bt;
    GtkTextBuffer *buf;

    toplevel = dlg_window_new("Help for LTE RLC graphing");
    gtk_window_set_default_size(GTK_WINDOW(toplevel), 540, 540);

    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);
    gtk_container_add(GTK_CONTAINER(toplevel), vbox);

    scroll = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);
    text = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
    gtk_text_buffer_set_text(buf, helptext, -1);
    gtk_container_add(GTK_CONTAINER(scroll), text);

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
    gtk_widget_show(bbox);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(toplevel, close_bt, window_cancel_button_cb);

    g_signal_connect(toplevel, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

    gtk_widget_show_all(toplevel);
    window_present(toplevel);
}

static void get_mouse_position(GtkWidget *widget, int *pointer_x, int *pointer_y, GdkModifierType *mask)
{
#if GTK_CHECK_VERSION(3,0,0)
	gdk_window_get_device_position (gtk_widget_get_window(widget),
	                                gdk_device_manager_get_client_pointer(
	                                  gdk_display_get_device_manager(
	                                    gtk_widget_get_display(GTK_WIDGET(widget)))),
	                                pointer_x, pointer_y, mask);

#else
	gdk_window_get_pointer (gtk_widget_get_window(widget), pointer_x, pointer_y, mask);
#endif
}

static struct graph *graph_new(void)
{
    struct graph *g;

    g = (struct graph * )g_malloc0(sizeof(struct graph));
    graph_element_lists_initialize(g);

    g->x_axis = (struct axis * )g_malloc0(sizeof(struct axis));
    g->y_axis = (struct axis * )g_malloc0(sizeof(struct axis));

    g->x_axis->g = g;
    g->x_axis->flags = 0;
    g->x_axis->flags |= AXIS_ORIENTATION;
    g->x_axis->s.x = g->x_axis->s.y = 0;
    g->x_axis->s.height = HAXIS_INIT_HEIGHT;
    g->x_axis->p.x = VAXIS_INIT_WIDTH;
    g->x_axis->p.height = HAXIS_INIT_HEIGHT;

    g->y_axis->g = g;
    g->y_axis->flags = 0;
    g->y_axis->flags &= ~AXIS_ORIENTATION;
    g->y_axis->p.x = g->y_axis->p.y = 0;
    g->y_axis->p.width = VAXIS_INIT_WIDTH;
    g->y_axis->s.x = 0;
    g->y_axis->s.y = TITLEBAR_HEIGHT;
    g->y_axis->s.width = VAXIS_INIT_WIDTH;

    return g;
}

static void graph_initialize_values(struct graph *g)
{
    g->geom.width = g->wp.width = 750;
    g->geom.height = g->wp.height = 550;
    g->geom.x = g->wp.x = VAXIS_INIT_WIDTH;
    g->geom.y = g->wp.y = TITLEBAR_HEIGHT;
    g->flags = 0;
    g->zoom.x = g->zoom.y = 1.0;

    /* Zooming in step - set same for both dimensions */
    g->zoom.step_x = g->zoom.step_y = 1.15;
    g->zoom.flags = 0;

    g->cross.draw = g->cross.erase_needed = 0;
    g->grab.grabbed = 0;
}

static void graph_init_sequence(struct graph *g)
{
    debug(DBS_FENTRY) puts("graph_init_sequence()");

    graph_initialize(g);
    g->zoom.initial.x = g->zoom.x;
    g->zoom.initial.y = g->zoom.y;
    graph_element_lists_make(g);
    g->x_axis->s.width = g->wp.width;
    g->x_axis->p.width = g->x_axis->s.width + RMARGIN_WIDTH;
    g->x_axis->p.y = TITLEBAR_HEIGHT + g->wp.height;
    g->x_axis->s.height = g->x_axis->p.height = HAXIS_INIT_HEIGHT;
    g->y_axis->s.height = g->wp.height;
    g->y_axis->p.height = g->wp.height + TITLEBAR_HEIGHT;
    graph_pixmaps_create(g);
    axis_pixmaps_create(g->y_axis);
    axis_pixmaps_create(g->x_axis);
    graph_title_pixmap_create(g);
    graph_title_pixmap_draw(g);
    graph_title_pixmap_display(g);
    graph_display(g);
    axis_display(g->y_axis);
    axis_display(g->x_axis);
}

static void graph_initialize(struct graph *g)
{
    debug(DBS_FENTRY) puts("graph_initialize()");
    graph_get_bounds(g);

    /* Want to start with absolute times, rather than being relative to 0 */
    g->x_axis->min = g->bounds.x0;
    g->y_axis->min = 0;

    graph_read_config(g);
}

static void graph_destroy(struct graph *g)
{
    debug(DBS_FENTRY) puts("graph_destroy()");

    axis_destroy(g->x_axis);
    axis_destroy(g->y_axis);
    /* window_destroy(g->drawing_area); */
    window_destroy(g->toplevel);
    /* window_destroy(g->text); */
#if GTK_CHECK_VERSION(2,22,0)
    if (g->title_surface){
         cairo_surface_destroy(g->title_surface);
    }
    if (g->surface[0]){
         cairo_surface_destroy(g->surface[0]);
    }
    if (g->surface[1]){
         cairo_surface_destroy(g->surface[1]);
    }
#else
    g_object_unref(g->pixmap[0]);
    g_object_unref(g->pixmap[1]);
#endif /* GTK_CHECK_VERSION(2,22,0) */
    g_free(g->x_axis);
    g_free(g->y_axis);
    graph_segment_list_free(g);
    graph_element_lists_free(g);

    g_free(g);
}


typedef struct rlc_scan_t {
    struct graph *g;
    struct segment *last;
} rlc_scan_t;


static int
tapall_rlc_lte_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    rlc_scan_t *ts=(rlc_scan_t *)pct;
    struct graph *g = ts->g;
    rlc_lte_tap_info *rlchdr=(rlc_lte_tap_info*)vip;

    /* See if this one matches current channel */
    if (compare_headers(g->ueid,       g->channelType,       g->channelId,       g->rlcMode,       g->direction,
                        rlchdr->ueid,  rlchdr->channelType,  rlchdr->channelId,  rlchdr->rlcMode,  rlchdr->direction,
                        rlchdr->isControlPDU)) {

        struct segment *segment = g_malloc(sizeof(struct segment));

        /* It matches.  Add to end of segment list */
        segment->next = NULL;
        segment->num = pinfo->fd->num;
        segment->rel_secs = (guint32) pinfo->fd->rel_ts.secs;
        segment->rel_usecs = pinfo->fd->rel_ts.nsecs/1000;
        segment->abs_secs = (guint32) pinfo->fd->abs_ts.secs;
        segment->abs_usecs = pinfo->fd->abs_ts.nsecs/1000;

        segment->ueid = rlchdr->ueid;
        segment->channelType = rlchdr->channelType;
        segment->channelId = rlchdr->channelId;
        segment->direction = rlchdr->direction;

        segment->isControlPDU = rlchdr->isControlPDU;

        if (!rlchdr->isControlPDU) {
            segment->SN = rlchdr->sequenceNumber;
        }
        else {
            gint n;
            segment->ACKNo = rlchdr->ACKNo;
            segment->noOfNACKs = rlchdr->noOfNACKs;
            for (n=0; n < rlchdr->noOfNACKs; n++) {
                segment->NACKs[n] = rlchdr->NACKs[n];
            }
        }

        /* Add to list */
        if (ts->g->segments) {
            /* Add to end of existing last element */
            ts->last->next = segment;
        } else {
            /* Make this the first (only) segment */
            ts->g->segments = segment;
        }

        /* This one is now the last one */
        ts->last = segment;
    }

    return 0;
}


/* Here we collect all the external data we will ever need */
static void graph_segment_list_get(struct graph *g, gboolean channel_known)
{
    struct segment current;
    GString *error_string;
    rlc_scan_t ts;

    debug(DBS_FENTRY) puts("graph_segment_list_get()");

    if (!channel_known) {
        select_rlc_lte_session(&cfile, &current);

        g->ueid = current.ueid;
        g->rlcMode = current.rlcMode;
        g->channelType = current.channelType;
        g->channelId = current.channelId;
        g->direction = (!current.isControlPDU) ? current.direction : !current.direction;
    }

    /* rescan all the packets and pick up all frames for this channel.
     * we only filter for LTE RLC here for speed and do the actual compare
     * in the tap listener
     */

    ts.g = g;
    ts.last = NULL;
    error_string = register_tap_listener("rlc-lte", &ts, "rlc-lte", 0, NULL, tapall_rlc_lte_packet, NULL);
    if (error_string){
        fprintf(stderr, "wireshark: Couldn't register rlc_lte_graph tap: %s\n",
                error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);
    }
    cf_retap_packets(&cfile);
    remove_tap_listener(&ts);
}


typedef struct _th_t {
    int num_hdrs;
    #define MAX_SUPPORTED_CHANNELS 8
    rlc_lte_tap_info *rlchdrs[MAX_SUPPORTED_CHANNELS];
} th_t;


static int
tap_lte_rlc_packet(void *pct, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *vip)
{
    int n;
    gboolean is_unique = TRUE;
    th_t *th = pct;
    rlc_lte_tap_info *header = (rlc_lte_tap_info*)vip;

    /* Check new header details against any/all stored ones */
    for (n=0; n < th->num_hdrs; n++) {
        rlc_lte_tap_info *stored = th->rlchdrs[n];

        if (compare_headers(stored->ueid, stored->channelType, stored->channelId, stored->rlcMode, stored->direction,
                            header->ueid, header->channelType, header->channelId, header->rlcMode, header->direction,
                            header->isControlPDU)) {
            is_unique = FALSE;
            break;
        }
    }

    /* Add address if unique and have space for it */
    if (is_unique && (th->num_hdrs < MAX_SUPPORTED_CHANNELS)) {
        /* Copy the tap stuct in as next header */
		/* Need to take a deep copy of the tap struct, it may not be valid
		   to read after this function returns? */
        th->rlchdrs[th->num_hdrs] = g_malloc(sizeof(rlc_lte_tap_info));
        *(th->rlchdrs[th->num_hdrs]) = *header;

        /* Store in direction of data though... */
        if (th->rlchdrs[th->num_hdrs]->isControlPDU) {
            th->rlchdrs[th->num_hdrs]->direction = !th->rlchdrs[th->num_hdrs]->direction;
        }
        th->num_hdrs++;
    }

    return 0;
}


/* XXX should be enhanced so that if we have multiple RLC channels in the same MAC frame
 * then present the user with a dialog where the user can select WHICH RLC
 * channel to graph.
 */
static rlc_lte_tap_info *select_rlc_lte_session(capture_file *cf, struct segment *hdrs)
{
    frame_data *fdata;
    epan_dissect_t edt;
    dfilter_t *sfcode;
    GString *error_string;
    th_t th = {0, {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}};

    if (cf->state == FILE_CLOSED) {
        return NULL;
    }

    fdata = cf->current_frame;

    /* no real filter yet */
    if (!dfilter_compile("rlc-lte", &sfcode)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", dfilter_error_msg);
        return NULL;
    }

    /* dissect the current frame */
    if (!cf_read_frame(cf, fdata)) {
        return NULL;	/* error reading the frame */
    }

    error_string = register_tap_listener("rlc-lte", &th, NULL, 0, NULL, tap_lte_rlc_packet, NULL);
    if (error_string){
        fprintf(stderr, "wireshark: Couldn't register rlc_lte_graph tap: %s\n",
                error_string->str);
        g_string_free(error_string, TRUE);
        exit(1);
    }

    epan_dissect_init(&edt, TRUE, FALSE);
    epan_dissect_prime_dfilter(&edt, sfcode);
    epan_dissect_run_with_taps(&edt, &cf->phdr, cf->pd, fdata, NULL);
    epan_dissect_cleanup(&edt);
    remove_tap_listener(&th);

    if (th.num_hdrs==0){
        /* This "shouldn't happen", as our menu items shouldn't
         * even be enabled if the selected packet isn't an RLC PDU
         * as rlc_lte_graph_selected_packet_enabled() is used
         * to determine whether to enable any of our menu items. */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Selected packet doesn't have an RLC PDU");
        return NULL;
    }
    /* XXX fix this later, we should show a dialog allowing the user
       to select which session he wants here
         */
    if (th.num_hdrs>1){
        /* can only handle a single RLC channel yet */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "The selected packet has more than one LTE RLC channel "
            "in it.");
        return NULL;
    }

    /* For now, still always choose the first/only one */
    hdrs->num = fdata->num;
    hdrs->rel_secs = (guint32) fdata->rel_ts.secs;
    hdrs->rel_usecs = fdata->rel_ts.nsecs/1000;
    hdrs->abs_secs = (guint32) fdata->abs_ts.secs;
    hdrs->abs_usecs = fdata->abs_ts.nsecs/1000;

    hdrs->ueid = th.rlchdrs[0]->ueid;
    hdrs->channelType = th.rlchdrs[0]->channelType;
    hdrs->channelId = th.rlchdrs[0]->channelId;
    hdrs->rlcMode = th.rlchdrs[0]->rlcMode;
    hdrs->direction = th.rlchdrs[0]->direction;

    return th.rlchdrs[0];
}

static int compare_headers(guint16 ueid1, guint16 channelType1, guint16 channelId1, guint8 rlcMode1, guint8 direction1,
                           guint16 ueid2, guint16 channelType2, guint16 channelId2, guint8 rlcMode2, guint8 direction2,
                           gboolean frameIsControl)
{
    /* Same direction, data - OK. */
    if (!frameIsControl) {
        return (direction1 == direction2) && 
               (ueid1 == ueid2) &&
               (channelType1 == channelType2) &&
               (channelId1 == channelId2) &&
               (rlcMode1 == rlcMode2);
    }
    else {
        if (frameIsControl && (rlcMode1 == RLC_AM_MODE) && (rlcMode2 == RLC_AM_MODE)) {
            return ((direction1 != direction2) &&
                    (ueid1 == ueid2) &&
                    (channelType1 == channelType2) &&
                    (channelId1 == channelId2));
        }
        else {
            return FALSE;
        }
    }
}

/* Free all segments in the graph */
static void graph_segment_list_free(struct graph *g)
{
    struct segment *segment;

    while (g->segments) {
        segment = g->segments->next;
        g_free(g->segments);
        g->segments = segment;
    }
    g->segments = NULL;
}

static void graph_element_lists_initialize(struct graph *g)
{
    g->elists = (struct element_list *)g_malloc0(sizeof(struct element_list));
    g->elists->elements = NULL;
    g->elists->next = NULL;
}

static void graph_element_lists_make(struct graph *g)
{
    debug(DBS_FENTRY) puts("graph_element_lists_make()");
    rlc_lte_make_elmtlist(g);
}

static void graph_element_lists_free(struct graph *g)
{
    struct element_list *list, *next_list;

    for (list=g->elists; list; list=next_list) {
        g_free(list->elements);
        next_list = list->next;
        g_free(list);
    }
    g->elists = NULL;	/* just to make debugging easier */
}

static void graph_title_pixmap_create(struct graph *g)
{
#if GTK_CHECK_VERSION(2,22,0)
    if (g->title_surface){
        cairo_surface_destroy(g->title_surface);
        g->title_surface = NULL;
    }

    g->title_surface = gdk_window_create_similar_surface(gtk_widget_get_window(g->drawing_area),
            CAIRO_CONTENT_COLOR,
            g->x_axis->p.width,
            g->wp.y);

#else
    if (g->title_pixmap)
        g_object_unref(g->title_pixmap);

    g->title_pixmap = gdk_pixmap_new(gtk_widget_get_window(g->drawing_area),
                                     g->x_axis->p.width, g->wp.y, -1);
#endif
}

static void graph_title_pixmap_draw(struct graph *g)
{
    gint w, h;
    PangoLayout *layout;
    cairo_t *cr;

#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create(g->title_surface);
#else
    cr = gdk_cairo_create(g->title_pixmap);
#endif
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, 0, 0,  g->x_axis->p.width, g->wp.y);
    cairo_fill(cr);

    layout = gtk_widget_create_pango_layout(g->drawing_area, "");
    pango_layout_get_pixel_size(layout, &w, &h);
    cairo_move_to(cr, g->wp.width/2 - w/2, 20);
    pango_cairo_show_layout(cr, layout);
    g_object_unref(G_OBJECT(layout));

    cairo_destroy(cr);
}

static void graph_title_pixmap_display(struct graph *g)
{
    cairo_t *cr;

    cr = gdk_cairo_create(gtk_widget_get_window(g->drawing_area));
#if GTK_CHECK_VERSION(2,22,0)
    cairo_set_source_surface(cr, g->title_surface, g->wp.x, 0);
#else
    gdk_cairo_set_source_pixmap(cr, g->title_pixmap, g->wp.x, 0);
#endif
    cairo_rectangle(cr, g->wp.x, 0, g->x_axis->p.width, g->wp.y);
    cairo_fill(cr);
    cairo_destroy(cr);
}

static void graph_pixmaps_create(struct graph *g)
{
    debug(DBS_FENTRY) puts("graph_pixmaps_create()");
#if GTK_CHECK_VERSION(2,22,0)
    if (g->surface[0]){
        cairo_surface_destroy(g->surface[0]);
        g->surface[0] = NULL;
    }

    if (g->surface[1]){
        cairo_surface_destroy(g->surface[1]);
        g->surface[1] = NULL;
    }

    g->surface[0] = gdk_window_create_similar_surface(gtk_widget_get_window(g->drawing_area),
            CAIRO_CONTENT_COLOR,
            g->wp.width,
            g->wp.height);

    g->surface[1] = gdk_window_create_similar_surface(gtk_widget_get_window(g->drawing_area),
            CAIRO_CONTENT_COLOR,
            g->wp.width,
            g->wp.height);

    g->displayed = 0;
#else
    if (g->pixmap[0])
        g_object_unref(g->pixmap[0]);
    if (g->pixmap[1])
        g_object_unref(g->pixmap[1]);

    g->pixmap[0] = gdk_pixmap_new(gtk_widget_get_window(g->drawing_area),
                                    g->wp.width, g->wp.height, -1);
    g->pixmap[1] = gdk_pixmap_new(gtk_widget_get_window(g->drawing_area),
                                    g->wp.width, g->wp.height, -1);

    g->displayed = 0;
#endif /* GTK_CHECK_VERSION(2,22,0) */
}


static void graph_display(struct graph *g)
{
    set_busy_cursor(gtk_widget_get_window(g->drawing_area));
    graph_pixmap_draw(g);
    unset_busy_cursor(gtk_widget_get_window(g->drawing_area));
    graph_pixmaps_switch(g);
    graph_pixmap_display(g);
}

static void graph_pixmap_display(struct graph *g)
{
    cairo_t *cr;

    cr = gdk_cairo_create(gtk_widget_get_window(g->drawing_area));
#if GTK_CHECK_VERSION(2,22,0)
    cairo_set_source_surface(cr, g->surface[g->displayed], g->wp.x, g->wp.y);
#else
    gdk_cairo_set_source_pixmap(cr, g->pixmap[g->displayed], g->wp.x, g->wp.y);
#endif /* GTK_CHECK_VERSION(2,22,0) */
    cairo_rectangle(cr, g->wp.x, g->wp.y, g->wp.width, g->wp.height);
    cairo_fill(cr);
    cairo_destroy(cr);
}

static void graph_pixmaps_switch(struct graph *g)
{
    g->displayed = 1 ^ g->displayed;
}

static void graph_pixmap_draw(struct graph *g)
{
    struct element_list *list;
    struct element *e;
    int not_disp;
    cairo_t *cr;

    cairo_t *cr_elements;
    GdkColor *current_color = NULL;
    GdkColor *color_to_set = NULL;
    gboolean line_stroked = TRUE;

    debug(DBS_FENTRY) puts("graph_display()");
    not_disp = 1 ^ g->displayed;

#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create(g->surface[not_disp]);
#else
    cr = gdk_cairo_create(g->pixmap[not_disp]);
#endif /* GTK_CHECK_VERSION(2,22,0) */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, 0, 0, g->wp.width, g->wp.height);
    cairo_fill(cr);
    cairo_destroy(cr);

    /* Create one cairo_t for use with all of the lines, rather than continually
       creating and destroying one for each line */
#if GTK_CHECK_VERSION(2,22,0)
    cr_elements = cairo_create(g->surface[not_disp]);
#else
    cr_elements = gdk_cairo_create(g->pixmap[not_disp]);
#endif

    /* N.B. This makes drawing circles take half the time of the default setting.
       Changing from the default fill rule didn't make any noticable difference
       though */
    cairo_set_tolerance(cr_elements, 1.0);

    /* Line width is always 1 pixel */
    cairo_set_line_width(cr_elements, 1.0);

    /* Draw all elements */
    for (list=g->elists; list; list=list->next) {
        for (e=list->elements; e->type != ELMT_NONE; e++) {
            switch (e->type) {
                case ELMT_LINE:

                    /* Work out if we need to change colour */
                    if (current_color == e->elment_color_p) {
                        /* No change needed */
                        color_to_set = NULL;
                    }
                    else {
                        /* Changing colour */
                        current_color = color_to_set = e->elment_color_p;
                        cairo_stroke(cr_elements);
                    }

                    /* Draw the line */
                    draw_element_line(g, e, cr_elements, color_to_set);
                    line_stroked = FALSE;
                    break;

                case ELMT_ELLIPSE:
                    if (!line_stroked) {
                        cairo_stroke(cr_elements);
                        line_stroked = TRUE;
                    }

                    draw_element_ellipse(g, e, cr_elements);
                    break;


                default:
                    /* No other element types supported at the moment */
                    break;
            }
        }

        /* Make sure any remaining lines get drawn */
        if (!line_stroked) {
            cairo_stroke(cr_elements);
        }
    }

    cairo_destroy(cr_elements);
}

static void draw_element_line(struct graph *g, struct element *e, cairo_t *cr,
                              GdkColor *new_color)
{
    int xx1, xx2, yy1, yy2;

    debug(DBS_GRAPH_DRAWING)
        printf("\nline element: (%.2f,%.2f)->(%.2f,%.2f), seg %d ...\n",
               e->p.line.dim.x1, e->p.line.dim.y1,
               e->p.line.dim.x2, e->p.line.dim.y2, e->parent->num);

    /* Set our new colour (if changed) */
    if (new_color != NULL) {
        /* First draw any previous lines with old colour */
        gdk_cairo_set_source_color(cr, new_color);
    }

    /* Map point into graph area, and round to nearest int */
    xx1 = (int)rint(e->p.line.dim.x1 + g->geom.x - g->wp.x);
    xx2 = (int)rint(e->p.line.dim.x2 + g->geom.x - g->wp.x);
    yy1 = (int)rint((g->geom.height-1-e->p.line.dim.y1) + g->geom.y-g->wp.y);
    yy2 = (int)rint((g->geom.height-1-e->p.line.dim.y2) + g->geom.y-g->wp.y);

    /* If line completely out of the area, we won't show it  */
    if ((xx1<0 && xx2<0) || (xx1>=g->wp.width  && xx2>=g->wp.width) ||
        (yy1<0 && yy2<0) || (yy1>=g->wp.height && yy2>=g->wp.height)) {
        debug(DBS_GRAPH_DRAWING) printf(" refusing: (%d,%d)->(%d,%d)\n", xx1, yy1, xx2, yy2);
        return;
    }

    /* If one end of the line is out of bounds, don't worry. Cairo will
       clip the line to the outside of g->wp at the correct angle! */

    debug(DBS_GRAPH_DRAWING) printf("line: (%d,%d)->(%d,%d)\n", xx1, yy1, xx2, yy2);

    /* Draw from first position to second */
    cairo_move_to(cr, xx1+0.5, yy1+0.5);
    cairo_line_to(cr, xx2+0.5, yy2+0.5);
}

static void draw_element_ellipse(struct graph *g, struct element *e, cairo_t *cr)
{
    gdouble w = e->p.ellipse.dim.width;
    gdouble h = e->p.ellipse.dim.height;
    gdouble x = e->p.ellipse.dim.x + g->geom.x - g->wp.x;
    gdouble y = g->geom.height-1 - e->p.ellipse.dim.y + g->geom.y - g->wp.y;

    debug(DBS_GRAPH_DRAWING) printf ("ellipse: (x, y) -> (w, h): (%f, %f) -> (%f, %f)\n", x, y, w, h);

    cairo_save(cr);
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_translate(cr, x + w/2.0, y + h/2.0);
    cairo_scale(cr, w/2.0, h/2.0);
    cairo_arc(cr, 0.0, 0.0, 1.0, 0.0, 2*G_PI);
    cairo_fill(cr);
    cairo_restore(cr);
}


static void axis_pixmaps_create(struct axis *axis)
{
    debug(DBS_FENTRY) puts("axis_pixmaps_create()");
#if GTK_CHECK_VERSION(2,22,0)
    if (axis->surface[0]){
        cairo_surface_destroy(axis->surface[0]);
        axis->surface[0] = NULL;
    }
    if (axis->surface[1]){
        cairo_surface_destroy(axis->surface[1]);
        axis->surface[1] = NULL;
    }
    axis->surface[0] = gdk_window_create_similar_surface(gtk_widget_get_window(axis->drawing_area),
            CAIRO_CONTENT_COLOR,
            axis->p.width,
            axis->p.height);

    axis->surface[1] = gdk_window_create_similar_surface(gtk_widget_get_window(axis->drawing_area),
            CAIRO_CONTENT_COLOR,
            axis->p.width,
            axis->p.height);

    axis->displayed = 0;
#else
    if (axis->pixmap[0])
        g_object_unref(axis->pixmap[0]);
    if (axis->pixmap[1])
        g_object_unref(axis->pixmap[1]);

    axis->pixmap[0] = gdk_pixmap_new(gtk_widget_get_window(axis->drawing_area),
                            axis->p.width, axis->p.height, -1);
    axis->pixmap[1] = gdk_pixmap_new(gtk_widget_get_window(axis->drawing_area),
                            axis->p.width, axis->p.height, -1);

    axis->displayed = 0;
#endif
}

static void axis_destroy(struct axis *axis)
{
#if GTK_CHECK_VERSION(2,22,0)
    if (axis->surface[0]){
        cairo_surface_destroy(axis->surface[0]);
        axis->surface[0] = NULL;
    }
    if (axis->surface[1]){
        cairo_surface_destroy(axis->surface[1]);
        axis->surface[1] = NULL;
    }
#else
    g_object_unref(axis->pixmap[0]);
    g_object_unref(axis->pixmap[1]);
#endif
    g_free((gpointer)(axis->label) );
}

static void axis_display(struct axis *axis)
{
    if (axis->flags & AXIS_ORIENTATION)
        h_axis_pixmap_draw(axis);
    else
        v_axis_pixmap_draw(axis);

    axis_pixmaps_switch(axis);
    axis_pixmap_display(axis);
}

/* These show sequence numbers.  Avoid subdividing whole numbers. */
static void v_axis_pixmap_draw(struct axis *axis)
{
    struct graph *g = axis->g;
    int i;
    double major_tick;
    int not_disp, offset, imin, imax;
    double bottom, top, fl, corr;
    PangoLayout *layout;
    cairo_t *cr;

    debug(DBS_FENTRY) puts("v_axis_pixmap_draw()");

    /* Work out extent of axis */
    bottom = (g->geom.height - (g->wp.height + g->wp.y + (-g->geom.y))) /
                    (double )g->geom.height * g->bounds.height;
    bottom += axis->min;
    top = (g->geom.height - (g->wp.y + (-g->geom.y))) /
                    (double )g->geom.height * g->bounds.height;
    top += axis->min;
    axis_compute_ticks(axis, bottom, top, AXIS_VERTICAL);

    not_disp = 1 ^ axis->displayed;

#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create(axis->surface[not_disp]);
#else
    cr = gdk_cairo_create(axis->pixmap[not_disp]);
#endif
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, 0, 0, axis->p.width, axis->p.height);
    cairo_fill(cr);

    /* axis */
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, axis->p.width - 1.5, (axis->p.height-axis->s.height)/2.0);
    cairo_line_to(cr, axis->s.width - 1.5, axis->p.height);

    offset = g->wp.y + (-g->geom.y);
    fl = floor(axis->min / axis->major) * axis->major;
    corr = rint((axis->min - fl) * g->zoom.y);

    /* major ticks */
    major_tick = axis->major * g->zoom.y;
    imin = (int) ((g->geom.height - offset + corr - g->wp.height) / major_tick + 1);
    imax = (int) ((g->geom.height - offset + corr) / major_tick);
    for (i=imin; i <= imax; i++) {
        gint w, h;
        char desc[32];
        int y = (int) (g->geom.height-1 - (int )rint(i * major_tick) -
                        offset + corr + axis->s.y);

        debug(DBS_AXES_DRAWING) printf("%f @ %d\n",
                                               i*axis->major + fl, y);
        if (y < 0 || y > axis->p.height)
            continue;

        cairo_move_to(cr, axis->p.width - 15, y+0.5);
        cairo_line_to(cr, axis->s.width - 1, y+0.5);

        /* Won't be showing any decimal places here... */
        g_snprintf(desc, sizeof(desc), "%u", (unsigned int)(i*axis->major + fl));
        layout = gtk_widget_create_pango_layout(g->drawing_area, desc);
        pango_layout_get_pixel_size(layout, &w, &h);
        cairo_move_to(cr, axis->s.width-14-4-w, y - h/2);
        pango_cairo_show_layout(cr, layout);
        g_object_unref(G_OBJECT(layout));
    }
    /* minor ticks */
    if (axis->minor) {
        double minor_tick = axis->minor * g->zoom.y;
        imin = (int) ((g->geom.height - offset + corr - g->wp.height)/minor_tick + 1);
        imax = (int) ((g->geom.height - offset + corr) / minor_tick);
        for (i=imin; i <= imax; i++) {
            int y = (int) (g->geom.height-1 - (int )rint(i*minor_tick) -
                            offset + corr + axis->s.y);

            if (y > 0 && y < axis->p.height) {
                cairo_set_line_width(cr, 1.0);
                cairo_move_to(cr, axis->s.width - 8, y+0.5);
                cairo_line_to(cr, axis->s.width - 1, y+0.5);
            }
        }
    }
    for (i=0; axis->label[i]; i++) {
        gint w, h;
        layout = gtk_widget_create_pango_layout(g->drawing_area,
                                                axis->label[i]);
        pango_layout_get_pixel_size(layout, &w, &h);
        cairo_move_to(cr, (axis->p.width - w)/2, TITLEBAR_HEIGHT-10 - i*(h+3) - h);
        pango_cairo_show_layout(cr, layout);
        g_object_unref(G_OBJECT(layout));
    }
    cairo_stroke(cr);
    cairo_destroy(cr);
}


/* TODO: natural time units are subframes (ms), so might be good to always
   show 3 decimal places? */
static void h_axis_pixmap_draw(struct axis *axis)
{
    struct graph *g = axis->g;
    int i;
    double major_tick, minor_tick;
    int not_disp, rdigits, offset, imin, imax;
    double left, right, j, fl, corr;
    PangoLayout *layout;
    cairo_t *cr;

    debug(DBS_FENTRY) puts("h_axis_pixmap_draw()");
    left = (g->wp.x-g->geom.x) / (double)g->geom.width * g->bounds.width;
    left += axis->min;
    right = (g->wp.x-g->geom.x+g->wp.width) / (double)g->geom.width * g->bounds.width;
    right += axis->min;
    axis_compute_ticks(axis, left, right, AXIS_HORIZONTAL);

    /* Work out how many decimal places should be shown */
    j = axis->major - floor(axis->major);
    for (rdigits=0; rdigits<=6; rdigits++) {
        j *= 10;
        if (j<=0.000001)
            break;
        j = j - floor(j);
    }

    not_disp = 1 ^ axis->displayed;

#if GTK_CHECK_VERSION(2,22,0)
    cr = cairo_create(axis->surface[not_disp]);
#else
    cr = gdk_cairo_create(axis->pixmap[not_disp]);
#endif
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, 0, 0, axis->p.width, axis->p.height);
    cairo_fill(cr);

    /* axis */
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, 0, 0.5);
    cairo_line_to(cr, axis->s.width + (axis->p.width-axis->s.width)/2.0, 0.5);

    offset = g->wp.x - g->geom.x;

    fl = floor(axis->min / axis->major) * axis->major;
    corr = rint((axis->min - fl) * g->zoom.x);

    /* major ticks */
    major_tick = axis->major*g->zoom.x;
    imin = (int) ((offset + corr) / major_tick + 1);
    imax = (int) ((offset + corr + axis->s.width) / major_tick);
    for (i=imin; i <= imax; i++) {
        char desc[32];
        int w, h;
        int x = (int) (rint(i * major_tick) - offset - corr);

        /* printf("%f @ %d\n", i*axis->major + fl, x); */
        if (x < 0 || x > axis->s.width)
            continue;
        cairo_move_to(cr, x+0.5, 0);
        cairo_line_to(cr, x+0.5, 15);

        g_snprintf(desc, sizeof(desc), "%.*f", rdigits, i*axis->major + fl);
        layout = gtk_widget_create_pango_layout(g->drawing_area, desc);
        pango_layout_get_pixel_size(layout, &w, &h);
        cairo_move_to(cr,  x - w/2, 15+4);
        pango_cairo_show_layout(cr, layout);
        g_object_unref(G_OBJECT(layout));
    }
    if (axis->minor > 0) {
        /* minor ticks */
        minor_tick = axis->minor*g->zoom.x;
        imin = (int) ((offset + corr) / minor_tick + 1);
        imax = (int) ((offset + corr + g->wp.width) / minor_tick);
        for (i=imin; i <= imax; i++) {
            int x = (int) (rint(i * minor_tick) - offset - corr);
            if (x > 0 && x < axis->s.width){
                cairo_move_to(cr, x+0.5, 0);
                cairo_line_to(cr, x+0.5, 8);
            }
        }
    }
    for (i=0; axis->label[i]; i++) {
        gint w, h;
        layout = gtk_widget_create_pango_layout(g->drawing_area,
                                                axis->label[i]);
        pango_layout_get_pixel_size(layout, &w, &h);
        cairo_move_to(cr,  axis->s.width - w - 50, 15+h+15 + i*(h+3));
        pango_cairo_show_layout(cr, layout);
        g_object_unref(G_OBJECT(layout));
    }

    cairo_stroke(cr);
    cairo_destroy(cr);
}

static void axis_pixmaps_switch(struct axis *axis)
{
    axis->displayed = 1 ^ axis->displayed;
}

static void axis_pixmap_display(struct axis *axis)
{
    cairo_t *cr;

    cr = gdk_cairo_create(gtk_widget_get_window(axis->drawing_area));
#if GTK_CHECK_VERSION(2,22,0)
    cairo_set_source_surface(cr, axis->surface[axis->displayed], axis->p.x, axis->p.y);
#else
    gdk_cairo_set_source_pixmap(cr, axis->pixmap[axis->displayed], axis->p.x, axis->p.y);
#endif
    cairo_rectangle(cr, axis->p.x, axis->p.y, axis->p.width, axis->p.height);
    cairo_fill(cr);
    cairo_destroy(cr);
}

static void axis_compute_ticks(struct axis *axis, double x0, double xmax, int dir)
{
    int i, j, ii, jj, ms;
    double zoom, x, steps[3]={ 0.1, 0.5 };
    int dim, check_needed, diminished;
    double majthresh[2]={2.0, 3.0};

    debug((DBS_FENTRY | DBS_AXES_TICKS)) puts("axis_compute_ticks()");
    debug(DBS_AXES_TICKS)
        printf("x0=%f xmax=%f dir=%s\n", x0,xmax, dir? "VERTICAL" : "HORIZONTAL");

    zoom = axis_zoom_get(axis, dir);
    x = xmax-x0;
    for (i=-9; i<=12; i++) {
        if (x / pow(10, i) < 1)
            break;
    }
    --i;
    ms = (int )(x / pow(10, i));

    if (ms > 5) {
        j = 0;
        ++i;
    } else if (ms > 2)
        j = 1;
    else
        j = 0;

    axis->major = steps[j] * pow(10, i);
    if (dir == AXIS_VERTICAL) {
        /* But don't divide further than whole sequence numbers */
        axis->major = MAX(axis->major, 1.0);
    }

    debug(DBS_AXES_TICKS) printf("zoom=%.1f, x=%f -> i=%d -> ms=%d -> j=%d ->"
            " axis->major=%f\n", zoom, x, i, ms, j, axis->major);

    /* Compute minor ticks */
    jj = j;
    ii = i;
    axis_ticks_down(&ii, &jj);

    if ((dir == AXIS_VERTICAL) && (axis->major <= 1)) {
        /* Ddon't subdivide whole sequence numbers */
        axis->minor = 0;
    }
    else {
        axis->minor = steps[jj] * pow(10, ii);
        /* We don't want minors if they would be less than 10 pixels apart */
        if (axis->minor*zoom < 10) {
            debug(DBS_AXES_TICKS) printf("refusing axis->minor of %f: "
                                         "axis->minor*zoom == %f\n",
                                         axis->minor, axis->minor*zoom);
            axis->minor = 0;
        }
    }

    check_needed = TRUE;
    diminished = FALSE;
    while (check_needed) {
        check_needed = FALSE;
        dim = get_label_dim(axis, dir, xmax);
        debug(DBS_AXES_TICKS) printf("axis->major==%.1f, axis->minor==%.1f =>"
                " axis->major*zoom/dim==%f, axis->minor*zoom/dim==%f\n",
                axis->major, axis->minor, axis->major*zoom/dim,
                axis->minor*zoom/dim);

        /* corrections: if majors are less than majthresh[dir] times label
         * dimension apart, we need to use bigger ones */
        if (axis->major*zoom / dim < majthresh[dir]) {
            axis_ticks_up(&ii, &jj);
            axis->minor = axis->major;
            axis_ticks_up(&i, &j);
            axis->major = steps[j] * pow(10, i);
            check_needed = TRUE;
            debug(DBS_AXES_TICKS) printf("axis->major enlarged to %.1f\n",
                                        axis->major);
        }
        /* if minor ticks are bigger than majthresh[dir] times label dimension,
         * we could  promote them to majors as well */
        if (axis->minor*zoom / dim > majthresh[dir] && !diminished) {
            axis_ticks_down(&i, &j);
            axis->major = axis->minor;
            axis_ticks_down(&ii, &jj);
            axis->minor = steps[jj] * pow(10, ii);
            check_needed = TRUE;
            diminished = TRUE;

            debug(DBS_AXES_TICKS) printf("axis->minor diminished to %.1f\n",
                                        axis->minor);

            if (axis->minor*zoom < 10) {
                debug(DBS_AXES_TICKS) printf("refusing axis->minor of %f: "
                    "axis->minor*zoom == %f\n", axis->minor, axis->minor*zoom);
                axis->minor = 0;
            }
        }
    }

    debug(DBS_AXES_TICKS) printf("corrected: axis->major == %.1f -> "
                            "axis->minor == %.1f\n", axis->major, axis->minor);
}

static void axis_ticks_up(int *i, int *j)
{
    (*j)++;
    if (*j>1) {
        (*i)++;
        *j=0;
    }
}

static void axis_ticks_down(int *i, int *j)
{
    (*j)--;
    if (*j<0) {
        (*i)--;
        *j=1;
    }
}

static int get_label_dim(struct axis *axis, int dir, double label)
{
    double y;
    char str[32];
    int rdigits, dim;
    PangoLayout *layout;

    /* First, let's compute how many digits to the right of radix
     * we need to print */
    y = axis->major - floor(axis->major);
    for (rdigits=0; rdigits<=6; rdigits++) {
        y *= 10;
        if (y<=0.000001)
            break;
        y = y - floor(y);
    }
    g_snprintf(str, sizeof(str), "%.*f", rdigits, label);
    switch (dir) {
        case AXIS_HORIZONTAL:
            layout = gtk_widget_create_pango_layout(axis->g->drawing_area, str);
            pango_layout_get_pixel_size(layout, &dim, NULL);
            g_object_unref(G_OBJECT(layout));
            break;
        case AXIS_VERTICAL:
            layout = gtk_widget_create_pango_layout(axis->g->drawing_area, str);
            pango_layout_get_pixel_size(layout, NULL, &dim);
            g_object_unref(G_OBJECT(layout));
            break;
        default:
            puts("initialize axis: an axis must be either horizontal or vertical");
            return -1;
    }
    return dim;
}

static double axis_zoom_get(struct axis *axis, int dir)
{
    switch (dir) {
        case AXIS_HORIZONTAL:
            return axis->g->zoom.x;
        case AXIS_VERTICAL:
            return axis->g->zoom.y;
        default:
            return -1;
    }
}

static void graph_select_segment(struct graph *g, int x, int y)
{
    struct element_list *list;
    struct element *e;
    guint num = 0;

    debug(DBS_FENTRY) puts("graph_select_segment()");

    x -= g->geom.x;
    y = g->geom.height-1 - (y - g->geom.y);

    set_busy_cursor(gtk_widget_get_window(g->drawing_area));

    for (list=g->elists; list; list=list->next) {
        for (e=list->elements; e->type != ELMT_NONE; e++) {
            switch (e->type) {
                case ELMT_LINE:
                    if (line_detect_collision(e, x, y)) {
                        num = e->parent->num;
                    }
                    break;
                case ELMT_ELLIPSE:
                    if (ellipse_detect_collision(e, x, y)) {
                        num = e->parent->num;
                    }
                    break;

                default:
                    break;
            }
        }
    }


    if (num) {
        cf_goto_frame(&cfile, num);
    }
}

static int line_detect_collision(struct element *e, int x, int y)
{
    int xx1, yy1, xx2, yy2;

    /* Get sorted x, y co-ordinates for line */
    if (e->p.line.dim.x1 < e->p.line.dim.x2) {
        xx1 = (int)rint(e->p.line.dim.x1);
        xx2 = (int)rint(e->p.line.dim.x2);
    } else {
        xx1 = (int)rint(e->p.line.dim.x2);
        xx2 = (int)rint(e->p.line.dim.x1);
    }
    if (e->p.line.dim.y1 < e->p.line.dim.y2) {
        yy1 = (int)rint(e->p.line.dim.y1);
        yy2 = (int)rint(e->p.line.dim.y2);
    } else {
        yy1 = (int)rint(e->p.line.dim.y2);
        yy2 = (int)rint(e->p.line.dim.y1);
    }
    /*
    printf("line: (%d,%d)->(%d,%d), clicked: (%d,%d)\n", xx1, yy1, xx2, yy2, x, y);
     */

    /* N.B. won't match with diagonal lines... */
    if ((xx1==x && xx2==x && yy1<=y && y<=yy2)|   /* lies along vertical line */
        (yy1==y && yy2==y && xx1<=x && x<=xx2)) { /* lies along horizontal line */
        return TRUE;
    }
    else {
        return FALSE;
    }
}

static int ellipse_detect_collision(struct element *e, int x, int y)
{
    int xx1, yy1, xx2, yy2;

    xx1 = (int )rint (e->p.ellipse.dim.x);
    xx2 = (int )rint (e->p.ellipse.dim.x + e->p.ellipse.dim.width);
    yy1 = (int )rint (e->p.ellipse.dim.y - e->p.ellipse.dim.height);
    yy2 = (int )rint (e->p.ellipse.dim.y);
    /*
    printf ("ellipse: (%d,%d)->(%d,%d), clicked: (%d,%d)\n", xx1, yy1, xx2, yy2, x, y);
     */
    if (xx1<=x && x<=xx2 && yy1<=y && y<=yy2) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}



static gboolean configure_event(GtkWidget *widget _U_, GdkEventConfigure *event, gpointer user_data)	 
{
    struct graph *g = user_data;
    struct zoom new_zoom;
    int cur_g_width, cur_g_height;
    int cur_wp_width, cur_wp_height;

    debug(DBS_FENTRY) puts("configure_event()");

    cur_wp_width = g->wp.width;
    cur_wp_height = g->wp.height;
    g->wp.width = event->width - g->y_axis->p.width - RMARGIN_WIDTH;
    g->wp.height = event->height - g->x_axis->p.height - g->wp.y;
    g->x_axis->s.width = g->wp.width;
    g->x_axis->p.width = g->wp.width + RMARGIN_WIDTH;
    g->y_axis->p.height = g->wp.height + g->wp.y;
    g->y_axis->s.height = g->wp.height;
    g->x_axis->p.y = g->y_axis->p.height;
    new_zoom.x = (double)g->wp.width / cur_wp_width;
    new_zoom.y = (double)g->wp.height / cur_wp_height;
    cur_g_width = g->geom.width;
    cur_g_height = g->geom.height;
    g->geom.width = (int)rint(g->geom.width * new_zoom.x);
    g->geom.height = (int)rint(g->geom.height * new_zoom.y);
    g->zoom.x = (double)(g->geom.width - 1) / g->bounds.width;
    g->zoom.y = (double)(g->geom.height -1) / g->bounds.height;

    g->geom.x = (int)(g->wp.x - (double)g->geom.width/cur_g_width * (g->wp.x - g->geom.x));	 
    g->geom.y = (int)(g->wp.y - (double)g->geom.height/cur_g_height * (g->wp.y - g->geom.y));
#if 0
    printf("configure: graph: (%d,%d), (%d,%d); viewport: (%d,%d), (%d,%d); "
                 "zooms: (%f,%f)\n", g->geom.x, g->geom.y, g->geom.width,
                 g->geom.height, g->wp.x, g->wp.y, g->wp.width, g->wp.height,
                 g->zoom.x, g->zoom.y);
#endif

    graph_element_lists_make(g);
    graph_pixmaps_create(g);
    graph_title_pixmap_create(g);
    axis_pixmaps_create(g->y_axis);
    axis_pixmaps_create(g->x_axis);
    /* we don't do actual drawing here; we leave it to expose handler */
    graph_pixmap_draw(g);
    graph_pixmaps_switch(g);
    graph_title_pixmap_draw(g);
    h_axis_pixmap_draw(g->x_axis);
    axis_pixmaps_switch(g->x_axis);
    v_axis_pixmap_draw(g->y_axis);
    axis_pixmaps_switch(g->y_axis);

    return TRUE;
}


#if GTK_CHECK_VERSION(3,0,0)
static gboolean
draw_event(GtkWidget *widget _U_, cairo_t *cr, gpointer user_data)
{
    struct graph *g = user_data;

    debug(DBS_FENTRY) puts("draw_event()");

    /* lower left corner */
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, 0, g->wp.y + g->wp.height, g->y_axis->p.width, g->x_axis->p.height);
    cairo_fill(cr);

    /* right margin */
    cairo_rectangle(cr, g->wp.x + g->wp.width, g->wp.y, RMARGIN_WIDTH, g->wp.height);
    cairo_fill(cr);

    /* Should these routines be copied here, or be given the cairo_t ??  */
    graph_pixmap_display(g);
    graph_title_pixmap_display(g);
    axis_pixmap_display(g->x_axis);
    axis_pixmap_display(g->y_axis);

    return TRUE;
}
#else
static gboolean expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer user_data)
{
    struct graph *g = user_data;
    cairo_t *cr;

    debug(DBS_FENTRY) puts("expose_event()");

    if (event->count)
        return TRUE;

    /* lower left corner */
    cr = gdk_cairo_create(gtk_widget_get_window(widget));
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, 0, g->wp.y + g->wp.height, g->y_axis->p.width, g->x_axis->p.height);
    cairo_fill(cr);
    cairo_destroy(cr);
    cr = NULL;

    /* right margin */
    cr = gdk_cairo_create(gtk_widget_get_window(widget));
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_rectangle(cr, g->wp.x + g->wp.width, g->wp.y, RMARGIN_WIDTH, g->wp.height);
    cairo_fill(cr);
    cairo_destroy(cr);
    cr = NULL;

    graph_pixmap_display(g);
    graph_title_pixmap_display(g);
    axis_pixmap_display(g->x_axis);
    axis_pixmap_display(g->y_axis);

    return TRUE;
}
#endif

/* Zoom because of keyboard or mouse press */
static void do_zoom_common(struct graph *g, GdkEventButton *event,
                           gboolean lock_vertical, gboolean lock_horizontal)
{
    int cur_width = g->geom.width, cur_height = g->geom.height;
    struct { double x, y; } factor;
    int pointer_x, pointer_y;

    /* Get mouse position */
    if (event == NULL) {
        /* Keyboard - query it */
        get_mouse_position(g->drawing_area, &pointer_x, &pointer_y, NULL);
    }
    else {
        /* Mouse - just read it from event */
        pointer_x = (int)event->x;
        pointer_y = (int)event->y;
    }


    if (g->zoom.flags & ZOOM_OUT) {

        /* If can't zoom out anymore so don't waste time redrawing the whole graph! */
        if ((g->geom.height <= g->wp.height) &&
            (g->geom.width  <= g->wp.width)) {
            return;
        }

        /* Zoom out */
        if (lock_horizontal) {
            factor.x = 1.0;
        }
        else {
            factor.x = 1 / g->zoom.step_x;
        }

        if (lock_vertical) {
            factor.y = 1.0;
        }
        else {
            factor.y = 1 / g->zoom.step_y;
        }
    } else {
        /* Zoom in */
        if ((lock_horizontal) || (g->geom.width >= (g->bounds.width * MAX_PIXELS_PER_SECOND))) {
            factor.x = 1.0;
        }
        else {
            factor.x = g->zoom.step_x;
        }

        /* Don't zoom in too far vertically */
        if (lock_vertical || (g->geom.height >= (g->bounds.height * MAX_PIXELS_PER_SN))) {
            factor.y = 1.0;
        }
        else {
            factor.y = g->zoom.step_y;
        }
    }

    /* Multiply by x and y factors */
    g->geom.width = (int )rint(g->geom.width * factor.x);
    g->geom.height = (int )rint(g->geom.height * factor.y);

    /* Clip to space if necessary */
    if (g->geom.width < g->wp.width)
        g->geom.width = g->wp.width;
    if (g->geom.height < g->wp.height)
        g->geom.height = g->wp.height;

    /* Work out new zoom */
    g->zoom.x = (g->geom.width - 1) / g->bounds.width;
    g->zoom.y = (g->geom.height- 1) / g->bounds.height;

    /* Move origin to keep mouse position at centre of view */
    g->geom.x -= (int )rint((g->geom.width - cur_width) *
            ((pointer_x - g->geom.x)/(double)cur_width));
    g->geom.y -= (int )rint((g->geom.height - cur_height) *
            ((pointer_y - g->geom.y)/(double)cur_height));

    /* Make sure we haven't moved outside the whole graph */
    if (g->geom.x > g->wp.x)
        g->geom.x = g->wp.x;
    if (g->geom.y > g->wp.y)
        g->geom.y = g->wp.y;
    if (g->wp.x + g->wp.width > g->geom.x + g->geom.width)
        g->geom.x = g->wp.width + g->wp.x - g->geom.width;
    if (g->wp.y + g->wp.height > g->geom.y + g->geom.height)
        g->geom.y = g->wp.height + g->wp.y - g->geom.height;
#if 0
    printf("%s press: graph: (%d,%d), (%d,%d); viewport: (%d,%d), "
            "(%d,%d); zooms: (%f,%f)\n",
            (event != NULL) ? "mouse" : "key", g->geom.x, g->geom.y,
            g->geom.width, g->geom.height, g->wp.x, g->wp.y, g->wp.width,
            g->wp.height, g->zoom.x, g->zoom.y);
#endif

    graph_element_lists_make(g);
    graph_display(g);
    axis_display(g->y_axis);
    axis_display(g->x_axis);

    if (g->cross.draw) {
        g->cross.erase_needed = FALSE;
        cross_draw(g, pointer_x, pointer_y);
    }
}


static void do_zoom_keyboard(struct graph *g,
                             gboolean lock_vertical,
                             gboolean lock_horizontal)
{
    do_zoom_common(g, NULL, lock_vertical, lock_horizontal);
}

static void do_zoom_mouse(struct graph *g, GdkEventButton *event)
{
    do_zoom_common(g, event,
                   event->state & GDK_SHIFT_MASK,
                   event->state & GDK_CONTROL_MASK);
}

static void do_zoom_in_keyboard(struct graph *g,
                                gboolean lock_vertical,
                                gboolean lock_horizontal)
{
    g->zoom.flags &= ~ZOOM_OUT;
    do_zoom_keyboard(g, lock_vertical, lock_horizontal);
}

static void do_zoom_out_keyboard(struct graph *g,
                                 gboolean lock_vertical,
                                 gboolean lock_horizontal)
{
    g->zoom.flags |= ZOOM_OUT;
    do_zoom_keyboard(g, lock_vertical, lock_horizontal);
}

static void do_key_motion(struct graph *g)
{
    if (g->geom.x > g->wp.x) {
        g->geom.x = g->wp.x;
    }
    if (g->geom.y > g->wp.y) {
        g->geom.y = g->wp.y;
    }
    if (g->wp.x + g->wp.width > g->geom.x + g->geom.width) {
        g->geom.x = g->wp.width + g->wp.x - g->geom.width;
    }
    if (g->wp.y + g->wp.height > g->geom.y + g->geom.height) {
        g->geom.y = g->wp.height + g->wp.y - g->geom.height;
    }

    graph_display(g);
    axis_display(g->y_axis);
    axis_display(g->x_axis);

    if (g->cross.draw) {
        int pointer_x, pointer_y;
        get_mouse_position(g->drawing_area, &pointer_x, &pointer_y, NULL);
        g->cross.erase_needed = FALSE;
        cross_draw (g, pointer_x, pointer_y);
    }
}

static void do_key_motion_up(struct graph *g, int step)
{
    g->geom.y += step;
    do_key_motion(g);
}

static void do_key_motion_down(struct graph *g, int step)
{
    g->geom.y -= step;
    do_key_motion(g);
}

static void do_key_motion_left(struct graph *g, int step)
{
    g->geom.x += step;
    do_key_motion(g);
}

static void do_key_motion_right(struct graph *g, int step)
{
    g->geom.x -= step;
    do_key_motion(g);
}

static gboolean button_press_event(GtkWidget *widget _U_, GdkEventButton *event, gpointer user_data)
{
    struct graph *g = user_data;

    debug(DBS_FENTRY) puts("button_press_event()");

    if (event->button == MOUSE_BUTTON_RIGHT) {
        /* Turn on grab.  N.B. using (maybe) approx mouse position from event... */
        g->grab.x = (int )rint (event->x) - g->geom.x;
        g->grab.y = (int )rint (event->y) - g->geom.y;
        g->grab.grabbed = TRUE;
    } else if (event->button == MOUSE_BUTTON_MIDDLE) {
        do_zoom_mouse(g, event);
    } else if (event->button == MOUSE_BUTTON_LEFT) {
        graph_select_segment(g, (int)event->x, (int)event->y);
    }

    unset_busy_cursor(gtk_widget_get_window(g->drawing_area));
    return TRUE;
}

static gboolean button_release_event(GtkWidget *widget _U_, GdkEventButton *event _U_, gpointer user_data)
{
    struct graph *g = user_data;

    /* Turn off grab if right button released */
    if (event->button == MOUSE_BUTTON_RIGHT) {
        g->grab.grabbed = FALSE;
    }

    return TRUE;
}

static gboolean motion_notify_event(GtkWidget *widget _U_, GdkEventMotion *event, gpointer user_data)
{
    struct graph *g = user_data;
    int x, y;
    GdkModifierType state;

    /* debug(DBS_FENTRY) puts ("motion_notify_event()"); */

    /* Make sure we have accurate mouse position */
    if (event->is_hint)
        get_mouse_position(g->drawing_area, &x, &y, &state);
    else {
        x = (int) event->x;
        y = (int) event->y;
        state = event->state;
    }

    if (state & GDK_BUTTON3_MASK) {
        if (g->grab.grabbed) {
            /* Move view by difference between where we grabbed and where we are now */
            g->geom.x = x-g->grab.x;
            g->geom.y = y-g->grab.y;

            /* Limit to outer bounds of graph */
            if (g->geom.x > g->wp.x)
                g->geom.x = g->wp.x;
            if (g->geom.y > g->wp.y)
                g->geom.y = g->wp.y;
            if (g->wp.x + g->wp.width > g->geom.x + g->geom.width)
                g->geom.x = g->wp.width + g->wp.x - g->geom.width;
            if (g->wp.y + g->wp.height > g->geom.y + g->geom.height)
                g->geom.y = g->wp.height + g->wp.y - g->geom.height;

            /* Redraw everything */
            g->cross.erase_needed = 0;
            graph_display(g);
            axis_display(g->y_axis);
            axis_display(g->x_axis);
            if (g->cross.draw) {
                cross_draw(g, x, y);
            }
        }
    }
    else {
        /* Update the cross if its being shown */
        if (g->cross.erase_needed)
            cross_erase(g);
        if (g->cross.draw) {
            cross_draw(g, x, y);
        }
    }

    return TRUE;
}

static gboolean key_press_event(GtkWidget *widget _U_, GdkEventKey *event, gpointer user_data)
{
    struct graph *g = user_data;
    int step;

    debug(DBS_FENTRY) puts("key_press_event()");

    /* Holding down these keys can affect the step used for moving */
    if ((event->state & GDK_CONTROL_MASK) && (event->state & GDK_SHIFT_MASK)) {
        step = 0;
    }
    else if (event->state & GDK_CONTROL_MASK) {
        step = 1;
    }
    else if (event->state & GDK_SHIFT_MASK) {
        step = 10;
    }
    else {
        step = 100;
    }

    switch (event->keyval) {
        case ' ':
            toggle_crosshairs(g);
            break;
        case 't':
            /* Toggle betwee showing the time starting at 0, or time in capture */
            toggle_time_origin(g);
            break;
        case 'r':
        case GDK_Home:
            /* Go back to original view, all zoomed out */
            restore_initial_graph_view(g);
            break;

        /* Zooming in */
        case 'i':
        case 'I':
            do_zoom_in_keyboard(g,
                                event->state & GDK_SHIFT_MASK,
                                event->state & GDK_CONTROL_MASK);
            break;
        case '+':
            do_zoom_in_keyboard(g,
                                FALSE,
                                event->state & GDK_CONTROL_MASK);
            break;

        /* Zooming out */
        case 'o':
        case 'O':
            do_zoom_out_keyboard(g,
                                 event->state & GDK_SHIFT_MASK,
                                 event->state & GDK_CONTROL_MASK);
            break;
        case '-':
            do_zoom_out_keyboard(g,
                                 FALSE,
                                 event->state & GDK_CONTROL_MASK);

        /* Direction keys */
        case GDK_Left:
            do_key_motion_left(g, step);
            break;
        case GDK_Up:
            do_key_motion_up(g, step);
            break;
        case GDK_Right:
            do_key_motion_right(g, step);
            break;
        case GDK_Down:
            do_key_motion_down(g, step);
            break;

        case GDK_Page_Up:
            do_key_motion_up(g, 2000);
            break;
        case GDK_Page_Down:
            do_key_motion_down(g, 2000);
            break;

        /* Help */
        case GDK_F1:
            callback_create_help(NULL, NULL);
            break;

        default:
            break;
    }
    return TRUE;
}

static void toggle_crosshairs(struct graph *g)
{
    /* Toggle state */
    g->cross.draw ^= 1;

    /* Draw or erase as needed */
    if (g->cross.draw) {
        int x, y;
        get_mouse_position(g->drawing_area, &x, &y, NULL);
        cross_draw(g, x, y);
    } else if (g->cross.erase_needed) {
        cross_erase(g);
    }
}

static void cross_draw(struct graph *g, int x, int y)
{
    /* Shouldn't draw twice onto the same position if haven't erased in the
       meantime! */
    if (g->cross.erase_needed && (g->cross.x == x) && (g->cross.y == y)) {
        return;
    }

    /* Draw the cross */
    if (x >  g->wp.x && x < g->wp.x+g->wp.width &&
        y >  g->wp.y && y < g->wp.y+g->wp.height) {

        cairo_t *cr = gdk_cairo_create(gtk_widget_get_window(g->drawing_area));
        gdk_cairo_set_source_color(cr, &g->style.seq_color);
        cairo_set_line_width(cr, 1.0);

        /* Horizonal line */
        cairo_move_to(cr, g->wp.x, y);
        cairo_line_to(cr, g->wp.x + g->wp.width, y);

        /* Vertical line */
        cairo_move_to(cr, x, g->wp.y);
        cairo_line_to(cr, x, g->wp.y + g->wp.height);
        cairo_stroke(cr);
        cairo_destroy(cr);
    }

    /* Update state */
    g->cross.x = x;
    g->cross.y = y;
    g->cross.erase_needed = TRUE;
}

static void cross_erase(struct graph *g)
{
    int x = g->cross.x;
    int y = g->cross.y;

    if (x >  g->wp.x && x < g->wp.x+g->wp.width &&
        y >= g->wp.y && y < g->wp.y+g->wp.height) {

        /* Just redraw what is in the pixmap buffer */
        graph_pixmap_display(g);
    }

    g->cross.erase_needed = FALSE;
}


/* Toggle between showing the time starting at 0, or time in capture */
static void toggle_time_origin(struct graph *g)
{
    g->style.flags ^= TIME_ORIGIN;

    if ((g->style.flags & TIME_ORIGIN) == TIME_ORIGIN_CAP) {
        g->x_axis->min = g->bounds.x0;
    }
    else {
        g->x_axis->min = 0;
    }

    /* Redraw the axis */
    axis_display(g->x_axis);
}

static void restore_initial_graph_view(struct graph *g)
{
    g->geom.width = g->wp.width;
    g->geom.height = g->wp.height;
    g->geom.x = g->wp.x;
    g->geom.y = g->wp.y;
    graph_init_sequence(g);

    /* Set flags so that mouse zoom will zoom in (zooming out is not possible!) */
    g->zoom.flags &= ~ZOOM_OUT;

    if (g->cross.draw) {
        g->cross.erase_needed = FALSE;
    }
}

/* Walk the segment list, totalling up data PDUs, status ACKs and NACKs */
static void get_data_control_counts(struct graph *g, int *data, int *acks, int *nacks)
{
    struct segment *tmp;
    *data = 0;
    *acks = 0;
    *nacks = 0;

    for (tmp=g->segments; tmp; tmp=tmp->next) {
        if (tmp->isControlPDU) {
            (*acks)++;
            (*nacks) += tmp->noOfNACKs;
        }
        else {
            (*data)++;
        }
    }
}

/* Determine "bounds"
 *  Essentially: look for lowest/highest time and seq in the list of segments
 *  Not currently trying to work out the upper bound of the window, as we
 *  don't reliably know the RLC channel state variables...
 */
static void graph_get_bounds(struct graph *g)
{
    struct segment *tmp;
    double   tim;
    gboolean data_frame_seen=FALSE;
    double   data_tim_low=0;
    double   data_tim_high=0;
    guint32  data_seq_cur;
    guint32  data_seq_low=0;
    guint32  data_seq_high=0;
    gboolean ack_frame_seen=FALSE;

    double   ack_tim_low=0;
    double   ack_tim_high=0;
	guint32  ack_seq_cur;
    guint32  ack_seq_low=0;
    guint32  ack_seq_high=0;

    /* Go through all segments to determine "bounds" */
    for (tmp=g->segments; tmp; tmp=tmp->next) {
         if (!tmp->isControlPDU) {

            /* DATA frame */
            tim = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
            data_seq_cur = tmp->SN;

            /* Want to include a little beyond end, so that cross on last SN
               will (more likely) fit within bounds */
            #define A_FEW_SUBFRAMES 0.005

            /* Initialise if first time seen */
            if (!data_frame_seen) {
                data_tim_low    = tim;
                data_tim_high   = tim + A_FEW_SUBFRAMES;
                data_seq_low    = data_seq_cur;
                data_seq_high   = data_seq_cur+1;
                data_frame_seen = TRUE;
            }

            /* Update bounds after this frame */
            if (tim      < data_tim_low)  data_tim_low  = tim;
            if (tim+0.02 > data_tim_high) data_tim_high = tim + A_FEW_SUBFRAMES;
            if (data_seq_cur < data_seq_low)    data_seq_low  = data_seq_cur;
            if (data_seq_cur+1 > data_seq_high) data_seq_high = data_seq_cur+1;
        }
        else {

            /* STATUS PDU */
            int n;
            guint32 nack_seq_cur;

            tim = tmp->rel_secs + tmp->rel_usecs / 1000000.0;
            ack_seq_cur = tmp->ACKNo;

            /* Initialise if first status PDU seen */
            if (!ack_frame_seen) {
                ack_tim_low  = ack_tim_high = tim;
                ack_seq_low  = ack_seq_cur;
                ack_seq_high = ack_seq_cur;
                ack_frame_seen = TRUE;
            }

            /* Update bounds after this frame */
            if (tim         < ack_tim_low)  ack_tim_low  = tim;
            if (tim         > ack_tim_high) ack_tim_high = tim;
            if (ack_seq_cur < ack_seq_low)  ack_seq_low  = ack_seq_cur;
            if (ack_seq_cur > ack_seq_high) ack_seq_high = ack_seq_cur;

            /* Also run through any/all NACKs to see if ack_seq_low/ack_seq_high
               should be extended */
            for (n=0; n < tmp->noOfNACKs; n++) {
                nack_seq_cur = tmp->NACKs[n];

                if (nack_seq_cur < ack_seq_low)  ack_seq_low  = nack_seq_cur;
                if (nack_seq_cur > ack_seq_high) ack_seq_high = nack_seq_cur;
            }
        }
    }

    g->bounds.x0     =  ((data_tim_low <= ack_tim_low   && data_frame_seen) || (!ack_frame_seen)) ? data_tim_low  : ack_tim_low;
    g->bounds.width  = (((data_tim_high >= ack_tim_high && data_frame_seen) || (!ack_frame_seen)) ? data_tim_high : ack_tim_high) - g->bounds.x0;
    g->bounds.y0     =  0;   /* We always want the overal bounds to go back down to SN=0 */
    g->bounds.height = (((data_seq_high >= ack_seq_high && data_frame_seen) || (!ack_frame_seen)) ? data_seq_high : ack_seq_high);

    g->zoom.x = (g->geom.width - 1) / g->bounds.width;
    g->zoom.y = (g->geom.height -1) / g->bounds.height;
}

static void graph_read_config(struct graph *g)
{
    /* Black */
    g->style.seq_color.pixel=0;
    g->style.seq_color.red=0;
    g->style.seq_color.green=0;
    g->style.seq_color.blue=0;

    /* Blueish */
    g->style.ack_color[0].pixel=0;
    g->style.ack_color[0].red=0x2222;
    g->style.ack_color[0].green=0x2222;
    g->style.ack_color[0].blue=0xaaaa;

    /* Reddish */
    g->style.ack_color[1].pixel=0;
    g->style.ack_color[1].red=0xaaaa;
    g->style.ack_color[1].green=0x2222;
    g->style.ack_color[1].blue=0x2222;

    /* Time origin should be shown as time in capture by default */
    g->style.flags = TIME_ORIGIN_CAP;

    g->y_axis->label = (const char ** )g_malloc(3 * sizeof(char * ));
    g->y_axis->label[0] = "Number";
    g->y_axis->label[1] = "Sequence";
    g->y_axis->label[2] = NULL;
    g->x_axis->label = (const char ** )g_malloc(2 * sizeof(char * ));
    g->x_axis->label[0] = "Time[s]";
    g->x_axis->label[1] = NULL;
}

static void rlc_lte_make_elmtlist(struct graph *g)
{
    struct segment *tmp;
    struct element *elements0, *e0;		/* list of elmts showing control */
    struct element *elements1, *e1;		/* list of elmts showing data */
    struct segment *last_status_segment = NULL;
    double xx0, yy0;
    gboolean ack_seen = FALSE;
    guint32 seq_base;
    guint32 seq_cur;
    int n, data, acks, nacks;

    double previous_status_x=0.0, previous_status_y=0.0;

    debug(DBS_FENTRY) puts("rlc_lte_make_elmtlist()");

    /* Allocate all needed elements up-front */
    if (g->elists->elements == NULL) {
        get_data_control_counts(g, &data, &acks, &nacks);

        /* Allocate elements for status */
        n = 2 + (5*acks) + (4*nacks);
        e0 = elements0 = (struct element *)g_malloc(n*sizeof(struct element));

        /* Allocate elements for data */
        n = data+1;
        e1 = elements1 = (struct element *)g_malloc(n*sizeof(struct element));

        /* Allocate container for 2nd list of elements */
        g->elists->next = (struct element_list *)g_malloc0(sizeof(struct element_list));

    } else {
        e0 = elements0 = g->elists->elements;
        e1 = elements1 = g->elists->next->elements;
    }

    xx0 = g->bounds.x0;
    yy0 = g->bounds.y0;
    seq_base = (guint32) yy0;

    for (tmp=g->segments; tmp; tmp=tmp->next) {
        double secs;
        double x, y;

        /****************************************/
        /* X axis is time, Y is sequence number */
        /****************************************/

        secs = tmp->rel_secs + (tmp->rel_usecs / 1000000.0);
        x = secs - xx0;
        x *= g->zoom.x;

        if (!tmp->isControlPDU) {

            /* DATA */

            /* seq_cur is SN */
            seq_cur = tmp->SN - seq_base;

            /* Work out positions around this SN */
            #define DATA_BLOB_SIZE 4
            y = (g->zoom.y * seq_cur);

            /* Circle for data point */
            e1->type = ELMT_ELLIPSE;
            e1->parent = tmp;
            e1->elment_color_p = &g->style.seq_color;
            e1->p.ellipse.dim.width = DATA_BLOB_SIZE;
            e1->p.ellipse.dim.height = DATA_BLOB_SIZE;
            e1->p.ellipse.dim.x = x;
            e1->p.ellipse.dim.y = y;
            e1++;
        } else {

            /* Remember the last status segment */
            last_status_segment = tmp;

            /* -1 so ACK lines up with last data, rather than showing above it... */
            seq_cur = tmp->ACKNo - seq_base - 1;

            /* Work out positions around this SN */
            y = (g->zoom.y * seq_cur);

            if (ack_seen) {

                if (y > previous_status_y) {
                    /* Draw from previous ACK point horizontally to this time */
                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[0];
                    e0->p.line.dim.x1 = previous_status_x;
                    e0->p.line.dim.y1 = previous_status_y;
                    e0->p.line.dim.x2 = x;
                    e0->p.line.dim.y2 = previous_status_y;
                    e0++;
    
                    /* Now draw up to current ACK */
                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[0];
                    e0->p.line.dim.x1 = x;
                    e0->p.line.dim.y1 = previous_status_y;
                    e0->p.line.dim.x2 = x;
                    e0->p.line.dim.y2 = y;
                    e0++;
                }
                else {
                    /* Want to go down, then along in this case... */
                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[0];
                    e0->p.line.dim.x1 = previous_status_x;
                    e0->p.line.dim.y1 = previous_status_y;
                    e0->p.line.dim.x2 = previous_status_x;
                    e0->p.line.dim.y2 = y;
                    e0++;
    
                    /* Now draw up to current ACK */
                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[0];
                    e0->p.line.dim.x1 = previous_status_x;
                    e0->p.line.dim.y1 = y;
                    e0->p.line.dim.x2 = x;
                    e0->p.line.dim.y2 = y;
                    e0++;
                }
            }

            if (tmp->noOfNACKs > 0) {
                for (n=0; n < tmp->noOfNACKs; n++) {
                    double nack_y = (g->zoom.y * tmp->NACKs[n]);

                    /* A red cross to show where the NACK is reported */
                    #define NACK_CROSS_SIZE 8
                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[1];
                    e0->p.line.dim.x1 = x -NACK_CROSS_SIZE;
                    e0->p.line.dim.y1 = nack_y - NACK_CROSS_SIZE;
                    e0->p.line.dim.x2 = x + NACK_CROSS_SIZE;
                    e0->p.line.dim.y2 = nack_y + NACK_CROSS_SIZE;
                    e0++;

                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[1];
                    e0->p.line.dim.x1 = x - NACK_CROSS_SIZE;
                    e0->p.line.dim.y1 = nack_y + NACK_CROSS_SIZE;
                    e0->p.line.dim.x2 = x + NACK_CROSS_SIZE;
                    e0->p.line.dim.y2 = nack_y - NACK_CROSS_SIZE;
                    e0++;

                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[1];
                    e0->p.line.dim.x1 = x;
                    e0->p.line.dim.y1 = nack_y + NACK_CROSS_SIZE;
                    e0->p.line.dim.x2 = x;
                    e0->p.line.dim.y2 = nack_y - NACK_CROSS_SIZE;
                    e0++;

                    e0->type = ELMT_LINE;
                    e0->parent = tmp;
                    e0->elment_color_p = &g->style.ack_color[1];
                    e0->p.line.dim.x1 = x - NACK_CROSS_SIZE;
                    e0->p.line.dim.y1 = nack_y;
                    e0->p.line.dim.x2 = x + NACK_CROSS_SIZE;
                    e0->p.line.dim.y2 = nack_y;
                    e0++;
                }
            }

            ack_seen = TRUE;

            previous_status_x = x;
            previous_status_y = y;
        }
    }

    if (ack_seen) {
        /* Add one more line for status, from the last PDU -> rhs of graph */
        e0->type = ELMT_LINE;
        e0->parent = last_status_segment;
        e0->elment_color_p = &g->style.ack_color[0];
        e0->p.line.dim.x1 = previous_status_x;
        e0->p.line.dim.y1 = previous_status_y;
        e0->p.line.dim.x2 = g->bounds.width * g->zoom.x;  /* right edge of graph area */
        e0->p.line.dim.y2 = previous_status_y;
        e0++;
    }

    /* Complete both element lists */
    e0->type = ELMT_NONE;
    e1->type = ELMT_NONE;
    g->elists->elements = elements0;
    g->elists->next->elements = elements1;
}


#if defined(_WIN32) && !defined(__MINGW32__)
/* replacement of Unix rint() for Windows */
static int rint(double x)
{
    char *buf;
    int i,dec,sig;

    buf = _fcvt(x, 0, &dec, &sig);
    i = atoi(buf);
    if (sig == 1) {
        i = i * -1;
    }
    return i;
}
#endif

