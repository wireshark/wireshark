/* main_statusbar.c
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
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gtk/gtk.h>

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "../cfile.h"
#include "../file.h"
#include "../capture_opts.h"
#include "../capture_ui_utils.h"
#ifdef HAVE_LIBPCAP
#include "../capture.h"
#endif

#include "gtk/recent.h"
#include "gtk/main.h"
#include "gtk/main_statusbar.h"
#include "gtk/main_statusbar_private.h"
#include "gtk/gui_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/expert_comp_dlg.h"
#include "gtk/profile_dlg.h"

#include "../image/expert_error.xpm"
#include "../image/expert_warn.xpm"
#include "../image/expert_note.xpm"
#include "../image/expert_chat.xpm"
#include "../image/expert_none.xpm"

/*
 * The order below defines the priority of info bar contexts.
 */
typedef enum {
    STATUS_LEVEL_MAIN,
    STATUS_LEVEL_FILE,
    STATUS_LEVEL_FILTER,
    STATUS_LEVEL_HELP,
    NUM_STATUS_LEVELS
} status_level_e;


#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE " Ready to load or capture"
#else
#define DEF_READY_MESSAGE " Ready to load file"
#endif


static GtkWidget    *status_pane_left, *status_pane_right;
static GtkWidget    *info_bar, *packets_bar, *profile_bar, *profile_bar_event;
static GtkWidget    *expert_info_error, *expert_info_warn, *expert_info_note;
static GtkWidget    *expert_info_chat, *expert_info_none;

static guint        main_ctx, file_ctx, help_ctx, filter_ctx, packets_ctx, profile_ctx;
static guint        status_levels[NUM_STATUS_LEVELS];
static gchar        *packets_str = NULL;
static gchar        *profile_str = NULL;


static void info_bar_new(void);
static void packets_bar_new(void);
static void profile_bar_new(void);
static void status_expert_new(void);



/*
 * Push a message referring to file access onto the statusbar.
 */
static void
statusbar_push_file_msg(const gchar *msg)
{
    int i;

    /*g_warning("statusbar_push: %s", msg);*/
    for (i = STATUS_LEVEL_FILE + 1; i < NUM_STATUS_LEVELS; i++) {
        if (status_levels[i])
            return;
    }
    status_levels[STATUS_LEVEL_FILE]++;
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, msg);
}

/*
 * Pop a message referring to file access off the statusbar.
 */
static void
statusbar_pop_file_msg(void)
{
    /*g_warning("statusbar_pop");*/
    if (status_levels[STATUS_LEVEL_FILE] > 0) {
        status_levels[STATUS_LEVEL_FILE]--;
    }
    gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);
}

/*
 * Push a message referring to the currently-selected field onto the statusbar.
 */
void
statusbar_push_field_msg(const gchar *msg)
{
    int i;

    for (i = STATUS_LEVEL_HELP + 1; i < NUM_STATUS_LEVELS; i++) {
        if (status_levels[i])
            return;
    }
    status_levels[STATUS_LEVEL_HELP]++;

    gtk_statusbar_push(GTK_STATUSBAR(info_bar), help_ctx, msg);
}

/*
 * Pop a message referring to the currently-selected field off the statusbar.
 */
void
statusbar_pop_field_msg(void)
{
    if (status_levels[STATUS_LEVEL_HELP] > 0) {
        status_levels[STATUS_LEVEL_HELP]--;
    }
    gtk_statusbar_pop(GTK_STATUSBAR(info_bar), help_ctx);
}

/*
 * Push a message referring to the current filter onto the statusbar.
 */
void
statusbar_push_filter_msg(const gchar *msg)
{
    int i;

    for (i = STATUS_LEVEL_FILTER + 1; i < NUM_STATUS_LEVELS; i++) {
        if (status_levels[i])
            return;
    }
    status_levels[STATUS_LEVEL_FILTER]++;

    gtk_statusbar_push(GTK_STATUSBAR(info_bar), filter_ctx, msg);
}

/*
 * Pop a message referring to the current filter off the statusbar.
 */
void
statusbar_pop_filter_msg(void)
{
    if (status_levels[STATUS_LEVEL_FILTER] > 0) {
        status_levels[STATUS_LEVEL_FILTER]--;
    }
    gtk_statusbar_pop(GTK_STATUSBAR(info_bar), filter_ctx);
}


GtkWidget *
statusbar_new(void)
{
    GtkWidget *status_hbox;

    /* Sstatus hbox */
    status_hbox = gtk_hbox_new(FALSE, 1);
    gtk_container_set_border_width(GTK_CONTAINER(status_hbox), 0);

    /* info (main) statusbar */
    info_bar_new();

    /* packets statusbar */
    packets_bar_new();

    /* profile statusbar */
    profile_bar_new();

    /* expert info indicator */
    status_expert_new();

    /* Pane for the statusbar */
    status_pane_left = gtk_hpaned_new();
    gtk_widget_show(status_pane_left);
    status_pane_right = gtk_hpaned_new();
    gtk_widget_show(status_pane_right);

    return status_hbox;
}

void
statusbar_load_window_geometry(void)
{
    if (recent.has_gui_geometry_status_pane && recent.gui_geometry_status_pane_left)
        gtk_paned_set_position(GTK_PANED(status_pane_left), recent.gui_geometry_status_pane_left);
    if (recent.has_gui_geometry_status_pane && recent.gui_geometry_status_pane_right)
        gtk_paned_set_position(GTK_PANED(status_pane_right), recent.gui_geometry_status_pane_right);
}

void
statusbar_save_window_geometry(void)
{
    recent.gui_geometry_status_pane_left    = gtk_paned_get_position(GTK_PANED(status_pane_left));
    recent.gui_geometry_status_pane_right   = gtk_paned_get_position(GTK_PANED(status_pane_right));
}


/*
 * Helper for statusbar_widgets_emptying()
 */
static void
foreach_remove_a_child(GtkWidget *widget, gpointer data) {
    gtk_container_remove(GTK_CONTAINER(data), widget);
}

void
statusbar_widgets_emptying(GtkWidget *statusbar)
{
    gtk_widget_ref(info_bar);
    gtk_widget_ref(packets_bar);
    gtk_widget_ref(profile_bar);
    gtk_widget_ref(profile_bar_event);
    gtk_widget_ref(status_pane_left);
    gtk_widget_ref(status_pane_right);
    gtk_widget_ref(expert_info_error);
    gtk_widget_ref(expert_info_warn);
    gtk_widget_ref(expert_info_note);
    gtk_widget_ref(expert_info_chat);
    gtk_widget_ref(expert_info_none);

    /* empty all containers participating */
    gtk_container_foreach(GTK_CONTAINER(statusbar),     foreach_remove_a_child, statusbar);
    gtk_container_foreach(GTK_CONTAINER(status_pane_left),   foreach_remove_a_child, status_pane_left);
    gtk_container_foreach(GTK_CONTAINER(status_pane_right),   foreach_remove_a_child, status_pane_right);
}

void
statusbar_widgets_pack(GtkWidget *statusbar)
{
    gtk_box_pack_start(GTK_BOX(statusbar), expert_info_error, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(statusbar), expert_info_warn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(statusbar), expert_info_note, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(statusbar), expert_info_chat, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(statusbar), expert_info_none, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(statusbar), status_pane_left, TRUE, TRUE, 0);
    gtk_paned_pack1(GTK_PANED(status_pane_left), info_bar, FALSE, FALSE);
    gtk_paned_pack2(GTK_PANED(status_pane_left), status_pane_right, TRUE, FALSE);
    gtk_paned_pack1(GTK_PANED(status_pane_right), packets_bar, TRUE, FALSE);
    gtk_paned_pack2(GTK_PANED(status_pane_right), profile_bar_event, FALSE, FALSE);
}

void
statusbar_widgets_show_or_hide(GtkWidget *statusbar)
{
    /*
     * Show the status hbox if either:
     *
     *    1) we're showing the filter toolbar and we want it in the status
     *       line
     *
     * or
     *
     *    2) we're showing the status bar.
     */
    if ((recent.filter_toolbar_show && prefs.filter_toolbar_show_in_statusbar) ||
         recent.statusbar_show) {
        gtk_widget_show(statusbar);
    } else {
        gtk_widget_hide(statusbar);
    }

    if (recent.statusbar_show) {
        gtk_widget_show(status_pane_left);
    } else {
        gtk_widget_hide(status_pane_left);
    }
}


static void
info_bar_new(void)
{
    int i;

    /* tip: tooltips don't work on statusbars! */
    info_bar = gtk_statusbar_new();
    main_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "main");
    file_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "file");
    help_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "help");
    filter_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(info_bar), "filter");
    gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), FALSE);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), main_ctx, DEF_READY_MESSAGE);

    for (i = 0; i < NUM_STATUS_LEVELS; i++) {
        status_levels[i] = 0;
    }

    gtk_widget_show(info_bar);
}

static void
packets_bar_new(void)
{
    /* tip: tooltips don't work on statusbars! */
    packets_bar = gtk_statusbar_new();
    packets_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(packets_bar), "packets");
    packets_bar_update();
    gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(packets_bar), FALSE);

    gtk_widget_show(packets_bar);
}

static void
profile_bar_new(void)
{
    GtkTooltips   *tooltips;

    tooltips = gtk_tooltips_new();

    profile_bar_event = gtk_event_box_new();
    profile_bar = gtk_statusbar_new();
    gtk_container_add(GTK_CONTAINER(profile_bar_event), profile_bar);
    g_signal_connect(profile_bar_event, "button_press_event", G_CALLBACK(profile_show_popup_cb), NULL);
    profile_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(profile_bar), "profile");
    gtk_tooltips_set_tip (tooltips, profile_bar_event,
			  "Click to change configuration profile", NULL);
    profile_bar_update();

    gtk_widget_show(profile_bar);
    gtk_widget_show(profile_bar_event);
}


/*
 * update the packets statusbar to the current values
 */
void 
packets_bar_update(void)
{

    if(packets_bar) {
        /* remove old status */
        if(packets_str) {
            g_free(packets_str);
            gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);
        }

        /* do we have any packets? */
        if(cfile.count) {
            if(cfile.drops_known) {
                packets_str = g_strdup_printf(" Packets: %u Displayed: %u Marked: %u Dropped: %u",
                    cfile.count, cfile.displayed_count, cfile.marked_count, cfile.drops);
            } else {
                packets_str = g_strdup_printf(" Packets: %u Displayed: %u Marked: %u",
                    cfile.count, cfile.displayed_count, cfile.marked_count);
            }
        } else {
            packets_str = g_strdup(" No Packets");
        }
        gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, packets_str);
    }
}

/*
 * update the packets statusbar to the current values
 */
void
profile_bar_update(void)
{
    if (profile_bar) {
        /* remove old status */
        if(profile_str) {
            g_free(profile_str);
            gtk_statusbar_pop(GTK_STATUSBAR(profile_bar), profile_ctx);
        }

	profile_str = g_strdup_printf (" Profile: %s", get_profile_name ());

        gtk_statusbar_push(GTK_STATUSBAR(profile_bar), profile_ctx, profile_str);
    }
}


static void
status_expert_new(void)
{
    GtkWidget *expert_image;
    GtkTooltips   *tooltips;

    tooltips = gtk_tooltips_new();

    expert_image = xpm_to_widget_from_parent(top_level, expert_error_xpm);
    gtk_tooltips_set_tip(tooltips, expert_image, "ERROR is the highest expert info level", NULL);
    gtk_widget_show(expert_image);
    expert_info_error = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(expert_info_error), expert_image);
    g_signal_connect(expert_info_error, "button_press_event", G_CALLBACK(expert_comp_dlg_cb), NULL);

    expert_image = xpm_to_widget_from_parent(top_level, expert_warn_xpm);
    gtk_tooltips_set_tip(tooltips, expert_image, "WARNING is the highest expert info level", NULL);
    gtk_widget_show(expert_image);
    expert_info_warn = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(expert_info_warn), expert_image);
    g_signal_connect(expert_info_warn, "button_press_event", G_CALLBACK(expert_comp_dlg_cb), NULL);

    expert_image = xpm_to_widget_from_parent(top_level, expert_note_xpm);
    gtk_tooltips_set_tip(tooltips, expert_image, "NOTE is the highest expert info level", NULL);
    gtk_widget_show(expert_image);
    expert_info_note = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(expert_info_note), expert_image);
    g_signal_connect(expert_info_note, "button_press_event", G_CALLBACK(expert_comp_dlg_cb), NULL);

    expert_image = xpm_to_widget_from_parent(top_level, expert_chat_xpm);
    gtk_tooltips_set_tip(tooltips, expert_image, "CHAT is the highest expert info level", NULL);
    gtk_widget_show(expert_image);
    expert_info_chat = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(expert_info_chat), expert_image);
    g_signal_connect(expert_info_chat, "button_press_event", G_CALLBACK(expert_comp_dlg_cb), NULL);

    expert_image = xpm_to_widget_from_parent(top_level, expert_none_xpm);
    gtk_tooltips_set_tip(tooltips, expert_image, "No expert info", NULL);
    gtk_widget_show(expert_image);
    expert_info_none = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(expert_info_none), expert_image);
    g_signal_connect(expert_info_none, "button_press_event", G_CALLBACK(expert_comp_dlg_cb), NULL);
    gtk_widget_show(expert_info_none);
}

static void
status_expert_hide(void)
{
    /* reset expert info indicator */
    gtk_widget_hide(expert_info_error);
    gtk_widget_hide(expert_info_warn);
    gtk_widget_hide(expert_info_note);
    gtk_widget_hide(expert_info_chat);
    gtk_widget_hide(expert_info_none);
}

void
status_expert_update(void)
{
    status_expert_hide();

    switch(expert_get_highest_severity()) {
        case(PI_ERROR):
        gtk_widget_show(expert_info_error);
        break;
        case(PI_WARN):
        gtk_widget_show(expert_info_warn);
        break;
        case(PI_NOTE):
        gtk_widget_show(expert_info_note);
        break;
        case(PI_CHAT):
        gtk_widget_show(expert_info_chat);
        break;
        default:
        gtk_widget_show(expert_info_none);
        break;
    }
}

static void
statusbar_set_filename(const char *file_name, gint64 file_length, nstime_t *file_elapsed_time)
{
  gchar       *size_str;
  gchar       *status_msg;

  /* expert info indicator */
  status_expert_update();

  /* statusbar */
  /* convert file size */
  if (file_length/1024/1024 > 10) {
    size_str = g_strdup_printf("%" G_GINT64_MODIFIER "d MB", file_length/1024/1024);
  } else if (file_length/1024 > 10) {
    size_str = g_strdup_printf("%" G_GINT64_MODIFIER "d KB", file_length/1024);
  } else {
    size_str = g_strdup_printf("%" G_GINT64_MODIFIER "d Bytes", file_length);
  }

  status_msg = g_strdup_printf(" File: \"%s\" %s %02lu:%02lu:%02lu",
    (file_name) ? file_name : "", size_str,
    (long)file_elapsed_time->secs/3600,
    (long)file_elapsed_time->secs%3600/60,
    (long)file_elapsed_time->secs%60);
  g_free(size_str);
  statusbar_push_file_msg(status_msg);
  g_free(status_msg);
}


static void
statusbar_cf_file_closing_cb(capture_file *cf _U_)
{
    /* Clear any file-related status bar messages.
       XXX - should be "clear *ALL* file-related status bar messages;
       will there ever be more than one on the stack? */
    statusbar_pop_file_msg();

    /* reset expert info indicator */
    status_expert_hide();
    gtk_widget_show(expert_info_none);
}


static void
statusbar_cf_file_closed_cb(capture_file *cf _U_)
{
  /* go back to "No packets" */
  packets_bar_update();
}


static void
statusbar_cf_file_read_start_cb(capture_file *cf)
{
  const gchar *name_ptr;
  gchar       *load_msg;

  /* Ensure we pop any previous loaded filename */
  statusbar_pop_file_msg();

  name_ptr = get_basename(cf->filename);

  load_msg = g_strdup_printf(" Loading: %s", name_ptr);
  statusbar_push_file_msg(load_msg);
  g_free(load_msg);
}


static void
statusbar_cf_file_read_finished_cb(capture_file *cf)
{
    statusbar_pop_file_msg();
    statusbar_set_filename(cf->filename, cf->f_datalen, &(cf->elapsed_time));
}


#ifdef HAVE_LIBPCAP
static void
statusbar_capture_prepared_cb(capture_options *capture_opts _U_)
{
    statusbar_push_file_msg(" Waiting for capture input data ...");
}

static void
statusbar_capture_update_started_cb(capture_options *capture_opts)
{
    gchar *capture_msg;


    statusbar_pop_file_msg();

    if(capture_opts->iface) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> to file: %s",
				      get_iface_description(capture_opts),
				      (capture_opts->save_file) ? capture_opts->save_file : "");
    } else {
        capture_msg = g_strdup_printf(" <live capture in progress> to file: %s",
            (capture_opts->save_file) ? capture_opts->save_file : "");
    }

    statusbar_push_file_msg(capture_msg);

    g_free(capture_msg);
}

static void
statusbar_capture_update_continue_cb(capture_options *capture_opts)
{
    capture_file *cf = capture_opts->cf;
    gchar *capture_msg;


    status_expert_update();

    statusbar_pop_file_msg();

    if (cf->f_datalen/1024/1024 > 10) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %" G_GINT64_MODIFIER "d MB",
				      get_iface_description(capture_opts),
				      capture_opts->save_file,
				      cf->f_datalen/1024/1024);
    } else if (cf->f_datalen/1024 > 10) {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %" G_GINT64_MODIFIER "d KB",
				      get_iface_description(capture_opts),
				      capture_opts->save_file,
				      cf->f_datalen/1024);
    } else {
        capture_msg = g_strdup_printf(" %s: <live capture in progress> File: %s %" G_GINT64_MODIFIER "d Bytes",
				      get_iface_description(capture_opts),
				      capture_opts->save_file,
				      cf->f_datalen);
    }

    statusbar_push_file_msg(capture_msg);
}

static void
statusbar_capture_update_finished_cb(capture_options *capture_opts)
{
    capture_file *cf = capture_opts->cf;

    /* Pop the "<live capture in progress>" message off the status bar. */
    statusbar_pop_file_msg();
    statusbar_set_filename(cf->filename, cf->f_datalen, &(cf->elapsed_time));
}

static void
statusbar_capture_fixed_started_cb(capture_options *capture_opts)
{
    gchar *capture_msg;


    statusbar_pop_file_msg();

    capture_msg = g_strdup_printf(" %s: <live capture in progress> to file: %s",
				  get_iface_description(capture_opts),
				  (capture_opts->save_file) ? capture_opts->save_file : "");

    statusbar_push_file_msg(capture_msg);
    gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, " Packets: 0");

    g_free(capture_msg);
}

static void
statusbar_capture_fixed_continue_cb(capture_options *capture_opts)
{
    capture_file *cf = capture_opts->cf;
    gchar *capture_msg;


    gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);
    capture_msg = g_strdup_printf(" Packets: %u", cf_get_packet_count(cf));
    gtk_statusbar_push(GTK_STATUSBAR(packets_bar), packets_ctx, capture_msg);
    g_free(capture_msg);
}


static void
statusbar_capture_fixed_finished_cb(capture_options *capture_opts _U_)
{
#if 0
    capture_file *cf = capture_opts->cf;
#endif

    /* Pop the "<live capture in progress>" message off the status bar. */
    statusbar_pop_file_msg();

    /* Pop the "<capturing>" message off the status bar */
    gtk_statusbar_pop(GTK_STATUSBAR(packets_bar), packets_ctx);
}

#endif /* HAVE_LIBPCAP */


static void
statusbar_cf_field_unselected_cb(capture_file *cf _U_)
{
    statusbar_pop_field_msg();
}

static void
statusbar_cf_file_safe_started_cb(gchar * filename)
{
    gchar        *save_msg;

    save_msg = g_strdup_printf(" Saving: %s...", get_basename(filename));
    statusbar_push_file_msg(save_msg);
    g_free(save_msg);
}

static void
statusbar_cf_file_safe_finished_cb(gpointer data _U_)
{
    /* Pop the "Saving:" message off the status bar. */
    statusbar_pop_file_msg();
}

static void
statusbar_cf_file_safe_failed_cb(gpointer data _U_)
{
    /* Pop the "Saving:" message off the status bar. */
    statusbar_pop_file_msg();
}



void
statusbar_cf_callback(gint event, gpointer data, gpointer user_data _U_)
{
    switch(event) {
    case(cf_cb_file_closing):
        statusbar_cf_file_closing_cb(data);
        break;
    case(cf_cb_file_closed):
        statusbar_cf_file_closed_cb(data);
        break;
    case(cf_cb_file_read_start):
        statusbar_cf_file_read_start_cb(data);
        break;
    case(cf_cb_file_read_finished):
        statusbar_cf_file_read_finished_cb(data);
        break;
    case(cf_cb_packet_selected):
        break;
    case(cf_cb_packet_unselected):
        break;
    case(cf_cb_field_unselected):
        statusbar_cf_field_unselected_cb(data);
        break;
    case(cf_cb_file_safe_started):
        statusbar_cf_file_safe_started_cb(data);
        break;
    case(cf_cb_file_safe_finished):
        statusbar_cf_file_safe_finished_cb(data);
        break;
    case(cf_cb_file_safe_reload_finished):
        break;
    case(cf_cb_file_safe_failed):
        statusbar_cf_file_safe_failed_cb(data);
        break;
    default:
        g_warning("statusbar_cf_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}

#ifdef HAVE_LIBPCAP
void
statusbar_capture_callback(gint event, capture_options *capture_opts,
                           gpointer user_data _U_)
{
    switch(event) {
    case(capture_cb_capture_prepared):
        statusbar_capture_prepared_cb(capture_opts);
        break;
    case(capture_cb_capture_update_started):
        statusbar_capture_update_started_cb(capture_opts);
        break;
    case(capture_cb_capture_update_continue):
        statusbar_capture_update_continue_cb(capture_opts);
        break;
    case(capture_cb_capture_update_finished):
        statusbar_capture_update_finished_cb(capture_opts);
        break;
    case(capture_cb_capture_fixed_started):
        statusbar_capture_fixed_started_cb(capture_opts);
        break;
    case(capture_cb_capture_fixed_continue):
        statusbar_capture_fixed_continue_cb(capture_opts);
        break;
    case(capture_cb_capture_fixed_finished):
        statusbar_capture_fixed_finished_cb(capture_opts);
        break;
    case(capture_cb_capture_stopping):
        /* Beware: this state won't be called, if the capture child
         * closes the capturing on it's own! */
        break;
    default:
        g_warning("statusbar_capture_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}
#endif
