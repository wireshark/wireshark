/* follow_stream.c
 * Common routines for following data streams
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include <epan/addr_resolv.h>
#include <epan/follow.h>
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>
#include <epan/prefs.h>
#include <epan/charsets.h>
#include <epan/tap.h>

#include <epan/print.h>

#include <ui/alert_box.h>
#include <ui/last_open_dir.h>
#include <ui/simple_dialog.h>

#include <wsutil/file_util.h>
#include <ws_version_info.h>

#include "gtkglobals.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/color_utils.h"
#include "ui/gtk/stock_icons.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/follow_stream.h"
#include "ui/gtk/font_utils.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/old-gtk-compat.h"

#include <wsutil/utf8_entities.h>
#ifdef _WIN32
#include "wsutil/tempfile.h"
#include "ui/win32/print_win32.h"
#endif

/* static variable declarations to speed up the performance
 * of follow_load_text and follow_add_to_gtk_text
 */
static GdkColor server_fg, server_bg;
static GdkColor client_fg, client_bg;
static GtkTextTag *server_tag, *client_tag;

static void follow_find_destroy_cb(GtkWidget * win _U_, gpointer data);
static void follow_find_button_cb(GtkWidget * w, gpointer data);
static void follow_destroy_cb(GtkWidget *w, gpointer data _U_);

static void follow_stream(const gchar *title, follow_info_t *follow_info,
          gchar *both_directions_string, gchar *server_to_client_string, gchar *client_to_server_string);
static frs_return_t follow_show(follow_info_t *follow_info,
            follow_print_line_func follow_print,
            char *buffer, size_t nchars, gboolean is_from_server, void *arg,
            guint32 *global_pos, guint32 *server_packet_count,
            guint32 *client_packet_count);

static GList *follow_infos = NULL;

/*
 * XXX - the routine pointed to by "print_line_fcn_p" doesn't get handed lines,
 * it gets handed bufferfuls.  That's fine for "follow_write_raw()"
 * and "follow_add_to_gtk_text()", but, as "follow_print_text()" calls
 * the "print_line()" routine from "print.c", and as that routine might
 * genuinely expect to be handed a line (if, for example, it's using
 * some OS or desktop environment's printing API, and that API expects
 * to be handed lines), "follow_print_text()" should probably accumulate
 * lines in a buffer and hand them "print_line()".  (If there's a
 * complete line in a buffer - i.e., there's nothing of the line in
 * the previous buffer or the next buffer - it can just hand that to
 * "print_line()" after filtering out non-printables, as an
 * optimization.)
 *
 * This might or might not be the reason why C arrays display
 * correctly but get extra blank lines very other line when printed.
 */
static frs_return_t
follow_common_read_stream(follow_info_t *follow_info,
    follow_print_line_func follow_print,
    void *arg)
{
    guint32 global_client_pos = 0, global_server_pos = 0;
    guint32 server_packet_count = 0;
    guint32 client_packet_count = 0;
    guint32 *global_pos;
    gboolean skip;
    GList* cur;
    frs_return_t frs_return;
    follow_record_t *follow_record;
    GByteArray *buffer = g_byte_array_new();


    for (cur = follow_info->payload; cur; cur = g_list_next(cur)) {
        follow_record = (follow_record_t *)cur->data;
        skip = FALSE;
        if (!follow_record->is_server) {
            global_pos = &global_client_pos;
            if(follow_info->show_stream == FROM_SERVER) {
                skip = TRUE;
            }
        } else {
            global_pos = &global_server_pos;
            if (follow_info->show_stream == FROM_CLIENT) {
                skip = TRUE;
            }
        }

        if (!skip) {
            g_byte_array_set_size(buffer, 0);
            g_byte_array_append(buffer, follow_record->data->data,
                                     follow_record->data->len);

            frs_return = follow_show(follow_info, follow_print,
                                     buffer->data,
                                     follow_record->data->len,
                                     follow_record->is_server, arg,
                                     global_pos,
                                     &server_packet_count,
                                     &client_packet_count);
            if(frs_return == FRS_PRINT_ERROR) {
                g_byte_array_free(buffer, TRUE);
                return frs_return;
            }
        }
    }

    g_byte_array_free(buffer, TRUE);
    return FRS_OK;
}

static void follow_stream_cb(register_follow_t* follower, follow_read_stream_func read_stream_func, GtkWidget * w _U_, gpointer data _U_)
{
    GtkWidget   *filter_cm;
    GtkWidget   *filter_te;
    gchar       *follow_filter;
    const gchar *previous_filter;
    int         filter_out_filter_len;
    const char  *hostname0, *hostname1;
    char        *port0, *port1;
    gchar       *server_to_client_string = NULL;
    gchar       *client_to_server_string = NULL;
    gchar       *both_directions_string = NULL;
    follow_info_t  *follow_info;
    gtk_follow_info_t *gtk_follow_info;
    GString *msg;
    gboolean is_follow = FALSE;
    guint32 ignore_stream;
    char  stream_window_title[256];

    is_follow = proto_is_frame_protocol(cfile.edt->pi.layers, proto_get_protocol_filter_name(get_follow_proto_id(follower)));

    if (!is_follow) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error following stream.  Please make\n"
                      "sure you have a %s packet selected.", proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower))));
        return;
    }

    gtk_follow_info = g_new0(gtk_follow_info_t, 1);
    follow_info = g_new0(follow_info_t, 1);
    gtk_follow_info->read_stream = read_stream_func;
    follow_info->gui_data = gtk_follow_info;

    /* Create a new filter that matches all packets in the TCP stream,
       and set the display filter entry accordingly */
    follow_filter = get_follow_conv_func(follower)(&cfile.edt->pi, &ignore_stream);
    if (!follow_filter) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error creating filter for this stream.\n"
                      "A transport or network layer header is needed");
        g_free(gtk_follow_info);
        g_free(follow_info);
        return;
    }

    /* Set the display filter entry accordingly */
    filter_cm = (GtkWidget *)g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);
    filter_te = gtk_bin_get_child(GTK_BIN(filter_cm));

    /* needed in follow_filter_out_stream(), is there a better way? */
    gtk_follow_info->filter_te = filter_te;

    /* save previous filter, const since we're not supposed to alter */
    previous_filter =
        (const gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));

    /* allocate our new filter. API claims g_malloc terminates program on failure */
    /* my calc for max alloc needed is really +10 but when did a few extra bytes hurt ? */
    filter_out_filter_len = (int)(strlen(follow_filter) + strlen(previous_filter) + 16);
    follow_info->filter_out_filter = (gchar *)g_malloc(filter_out_filter_len);

    /* append the negation */
    if(strlen(previous_filter)) {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
            "%s and !(%s)", previous_filter, follow_filter);
    } else {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
            "!(%s)", follow_filter);
    }

    /* data will be passed via tap callback*/
    msg = register_tap_listener(get_follow_tap_string(follower), follow_info, follow_filter,
                                0, NULL, get_follow_tap_handler(follower), NULL);
    if (msg) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Can't register %s tap: %s\n",
                      get_follow_tap_string(follower), msg->str);
        g_free(gtk_follow_info);
        g_free(follow_info->filter_out_filter);
        g_free(follow_info);
        g_free(follow_filter);
        return;
    }

    gtk_entry_set_text(GTK_ENTRY(filter_te), follow_filter);

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    main_filter_packets(&cfile, follow_filter, TRUE);

    remove_tap_listener(follow_info);

    hostname0 = address_to_name(&follow_info->client_ip);
    hostname1 = address_to_name(&follow_info->server_ip);

    port0 = get_follow_port_to_display(follower)(NULL, follow_info->client_port);
    port1 = get_follow_port_to_display(follower)(NULL, follow_info->server_port);

    /* Both Stream Directions */
    both_directions_string = g_strdup_printf("Entire conversation (%u bytes)", follow_info->bytes_written[0] + follow_info->bytes_written[1]);

    server_to_client_string =
        g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                        hostname0, port0,
                        hostname1, port1,
                        follow_info->bytes_written[0]);

    client_to_server_string =
        g_strdup_printf("%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)",
                        hostname1, port1,
                        hostname0, port0,
                        follow_info->bytes_written[1]);

    g_snprintf(stream_window_title, 256, "Follow %s Stream (%s)",
                    proto_get_protocol_short_name(find_protocol_by_id(get_follow_proto_id(follower))), follow_filter);
    follow_stream(stream_window_title, follow_info, both_directions_string,
                  server_to_client_string, client_to_server_string);

    /* Free the filter string, as we're done with it. */
    g_free(follow_filter);

    wmem_free(NULL, port0);
    wmem_free(NULL, port1);
    g_free(both_directions_string);
    g_free(server_to_client_string);
    g_free(client_to_server_string);

}

static gboolean
follow_add_to_gtk_text(char *buffer, size_t nchars, gboolean is_from_server,
               void *arg)
{
    GtkWidget *text = (GtkWidget *)arg;
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
    GtkTextIter    iter;

    /*
     * have to convert non printable ASCII chars to '.' in order
     * to be able to see the data we *should* see
     * in the GtkText widget.
     */
    size_t i;

    for (i = 0; i < nchars; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r')
            continue;
        if (! g_ascii_isprint(buffer[i])) {
            buffer[i] = '.';
        }
    }

    gtk_text_buffer_get_end_iter(buf, &iter);
    if (is_from_server) {
        gtk_text_buffer_insert_with_tags(buf, &iter, buffer, (gint) nchars,
                         server_tag, NULL);
    } else {
        gtk_text_buffer_insert_with_tags(buf, &iter, buffer, (gint) nchars,
                         client_tag, NULL);
    }
    return TRUE;
}

/*
 * XXX - for text printing, we probably want to wrap lines at 80 characters;
 * (PostScript printing is doing this already), and perhaps put some kind of
 * dingbat (to use the technical term) to indicate a wrapped line, along the
 * lines of what's done when displaying this in a window, as per Warren Young's
 * suggestion.
 */
static gboolean
follow_print_text(char *buffer, size_t nchars, gboolean is_from_server _U_,
          void *arg)
{
    print_stream_t *stream = (print_stream_t *)arg;
    size_t i;
    char *str;

    /* convert non printable characters */
    for (i = 0; i < nchars; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r')
            continue;
        if (! g_ascii_isprint(buffer[i])) {
            buffer[i] = '.';
        }
    }

    /* convert unterminated char array to a zero terminated string */
    str = (char *)g_malloc(nchars + 1);
    memcpy(str, buffer, nchars);
    str[nchars] = 0;
    print_line(stream, /*indent*/ 0, str);
    g_free(str);

    return TRUE;
}

static gboolean
follow_write_raw(char *buffer, size_t nchars, gboolean is_from_server _U_, void *arg)
{
    FILE *fh = (FILE *)arg;
    size_t nwritten;

    nwritten = fwrite(buffer, 1, nchars, fh);
    if (nwritten != nchars)
        return FALSE;

    return TRUE;
}

static void
follow_load_text(follow_info_t *follow_info)
{
    GtkTextBuffer *buf;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(gtk_follow_info->text));

    /* prepare colors one time for repeated use by follow_add_to_gtk_text */
    color_t_to_gdkcolor(&server_fg, &prefs.st_server_fg);
    color_t_to_gdkcolor(&server_bg, &prefs.st_server_bg);
    color_t_to_gdkcolor(&client_fg, &prefs.st_client_fg);
    color_t_to_gdkcolor(&client_bg, &prefs.st_client_bg);

    /* prepare tags one time for repeated use by follow_add_to_gtk_text */
    server_tag = gtk_text_buffer_create_tag(buf, NULL, "foreground-gdk",
                                        &server_fg, "background-gdk",
                                        &server_bg, "font-desc",
                                        user_font_get_regular(), NULL);
    client_tag = gtk_text_buffer_create_tag(buf, NULL, "foreground-gdk",
                                        &client_fg, "background-gdk",
                                        &client_bg, "font-desc",
                                        user_font_get_regular(), NULL);

    /* Delete any info already in text box */
    gtk_text_buffer_set_text(buf, "", -1);

    gtk_follow_info->read_stream(follow_info, follow_add_to_gtk_text,
               gtk_follow_info->text);
}

/* Handles the display style toggling */
static void
follow_charset_toggle_cb(GtkWidget * w _U_, gpointer data)
{
    follow_info_t    *follow_info = (follow_info_t *)data;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    /*
     * A radio button toggles when it goes on and when it goes
     * off, so when you click a radio button two signals are
     * delivered.  We only want to reprocess the display once,
     * so we do it only when the button goes on.
     */
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))) {
        if (w == gtk_follow_info->ebcdic_bt)
            gtk_follow_info->show_type = SHOW_EBCDIC;
        else if (w == gtk_follow_info->hexdump_bt)
            gtk_follow_info->show_type = SHOW_HEXDUMP;
        else if (w == gtk_follow_info->carray_bt)
            gtk_follow_info->show_type = SHOW_CARRAY;
        else if (w == gtk_follow_info->ascii_bt)
            gtk_follow_info->show_type = SHOW_ASCII;
        else if (w == gtk_follow_info->raw_bt)
            gtk_follow_info->show_type = SHOW_RAW;
        follow_load_text(follow_info);
    }
}

static void
follow_filter_out_stream(GtkWidget * w _U_, gpointer data)
{
    follow_info_t    *follow_info = (follow_info_t *)data;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    /* Lock out user from messing with us. (ie. don't free our data!) */
    gtk_widget_set_sensitive(gtk_follow_info->streamwindow, FALSE);

    /* Set the display filter. */
    gtk_entry_set_text(GTK_ENTRY(gtk_follow_info->filter_te),
               follow_info->filter_out_filter);

    /* Run the display filter so it goes in effect. */
    main_filter_packets(&cfile, follow_info->filter_out_filter, FALSE);

    /* we force a subsequent close */
    window_destroy(gtk_follow_info->streamwindow);

    return;
}

static void
follow_find_cb(GtkWidget * w _U_, gpointer data)
{
    follow_info_t       *follow_info = (follow_info_t *)data;
    gtk_follow_info_t   *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;
    GtkWidget           *find_dlg_w, *main_vb, *buttons_row, *find_lb;
    GtkWidget           *find_hb, *find_text_box, *find_bt, *cancel_bt;

    if (gtk_follow_info->find_dlg_w != NULL) {
        /* There's already a dialog box; reactivate it. */
        reactivate_window(gtk_follow_info->find_dlg_w);
        return;
    }

    /* Create the find box */
    find_dlg_w = dlg_window_new("Wireshark: Find text");
    gtk_window_set_transient_for(GTK_WINDOW(find_dlg_w),
                                GTK_WINDOW(gtk_follow_info->streamwindow));
    gtk_widget_set_size_request(find_dlg_w, 225, -1);
    gtk_window_set_destroy_with_parent(GTK_WINDOW(find_dlg_w), TRUE);
    gtk_follow_info->find_dlg_w = find_dlg_w;

    g_signal_connect(find_dlg_w, "destroy", G_CALLBACK(follow_find_destroy_cb),
                    follow_info);
    g_signal_connect(find_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb),
                    NULL);

    /* Main vertical box */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
    gtk_container_add(GTK_CONTAINER(find_dlg_w), main_vb);

    /* Horizontal box for find label, entry field and up/down radio
       buttons */
    find_hb = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
    gtk_box_pack_start(GTK_BOX (main_vb), find_hb, TRUE, TRUE, 0);
    gtk_widget_show(find_hb);

    /* Find label */
    find_lb = gtk_label_new("Find text:");
    gtk_box_pack_start(GTK_BOX(find_hb), find_lb, FALSE, FALSE, 0);
    gtk_widget_show(find_lb);

    /* Find field */
    find_text_box = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(find_hb), find_text_box, FALSE, FALSE, 0);
    gtk_widget_set_tooltip_text(find_text_box, "Text to search for (case sensitive)");
    gtk_widget_show(find_text_box);

    /* Buttons row */
    buttons_row = dlg_button_row_new(GTK_STOCK_FIND, GTK_STOCK_CANCEL,
                                    NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), buttons_row, TRUE, TRUE, 0);
    find_bt   = (GtkWidget *)g_object_get_data(G_OBJECT(buttons_row), GTK_STOCK_FIND);
    cancel_bt = (GtkWidget *)g_object_get_data(G_OBJECT(buttons_row), GTK_STOCK_CANCEL);

    g_signal_connect(find_bt, "clicked", G_CALLBACK(follow_find_button_cb), follow_info);
    g_object_set_data(G_OBJECT(find_bt), "find_string", find_text_box);
    window_set_cancel_button(find_dlg_w, cancel_bt,
                             window_cancel_button_cb);

    /* Hitting return in the find field "clicks" the find button */
    dlg_set_activate(find_text_box, find_bt);

    /* Show the dialog */
    gtk_widget_show_all(find_dlg_w);
    window_present(find_dlg_w);
}

static void
follow_find_button_cb(GtkWidget * w, gpointer data)
{
    gboolean        found;
    const gchar     *find_string;
    follow_info_t   *follow_info = (follow_info_t *)data;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;
    GtkTextBuffer   *buffer;
    GtkTextIter     iter, match_start, match_end;
    GtkTextMark     *last_pos_mark;
    GtkWidget       *find_string_w;

    /* Get the text the user typed into the find field */
    find_string_w = (GtkWidget *)g_object_get_data(G_OBJECT(w), "find_string");
    find_string = gtk_entry_get_text(GTK_ENTRY(find_string_w));

    /* Get the buffer associated with the follow stream */
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(gtk_follow_info->text));
    gtk_text_buffer_get_start_iter(buffer, &iter);

    /* Look for the search string in the buffer */
    last_pos_mark = gtk_text_buffer_get_mark(buffer, "last_position");
    if(last_pos_mark)
        gtk_text_buffer_get_iter_at_mark(buffer, &iter, last_pos_mark);

    found = gtk_text_iter_forward_search(&iter, find_string, (GtkTextSearchFlags)0,
                                         &match_start,
                                         &match_end,
                                         NULL);

    if(found) {
        gtk_text_buffer_select_range(buffer, &match_start, &match_end);
        last_pos_mark = gtk_text_buffer_create_mark (buffer,
                                                     "last_position",
                                                     &match_end, FALSE);
        gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(gtk_follow_info->text), last_pos_mark);
    } else {
        /* We didn't find a match */
        simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
                      "%sFind text has reached the end of the followed "
                      "stream%s\n\nThe next search will start from the "
                      "beginning", simple_dialog_primary_start(),
                      simple_dialog_primary_end());
        if(last_pos_mark)
            gtk_text_buffer_delete_mark(buffer, last_pos_mark);
    }

}

static void
follow_find_destroy_cb(GtkWidget * win _U_, gpointer data)
{
    follow_info_t     *follow_info = (follow_info_t *)data;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    /* Note that we no longer have a dialog box. */
    gtk_follow_info->find_dlg_w = NULL;
}

static void
follow_print_stream(GtkWidget * w _U_, gpointer data)
{
    print_stream_t  *stream;
    gboolean        to_file;
    const char      *print_dest;
    follow_info_t   *follow_info =(follow_info_t *) data;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;
#ifdef _WIN32
    gboolean        win_printer = FALSE;
    int             tmp_fd;
    char            *tmp_namebuf;
#endif

    switch (prefs.pr_dest) {
    case PR_DEST_CMD:
#ifdef _WIN32
        win_printer = TRUE;
        /* (The code for creating a temp filename is adapted from print_dlg.c).   */
        /* We currently don't have a function in util.h to create just a tempfile */
        /* name, so simply create a tempfile using the "official" function,       */
        /* then delete this file again. After this, the name MUST be available.   */
        /* */
        /* Don't use tmpnam() or such, as this will fail under some ACL           */
        /* circumstances: http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=358  */
        /* Also: tmpnam is "insecure" and should not be used.                     */
        tmp_fd = create_tempfile(&tmp_namebuf, "wshprint", NULL);
        if(tmp_fd == -1) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "Couldn't create temporary file for printing:\n%s", tmp_namebuf);
            return;
        }
        ws_close(tmp_fd);
        ws_unlink(tmp_namebuf);
        print_dest = tmp_namebuf;
        to_file = TRUE;
#else
        print_dest = prefs.pr_cmd;
        to_file = FALSE;
#endif
        break;
    case PR_DEST_FILE:
        print_dest = prefs.pr_file;
        to_file = TRUE;
        break;
    default:            /* "Can't happen" */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Couldn't figure out where to send the print "
                      "job. Check your preferences.");
        return;
    }

    switch (prefs.pr_format) {

    case PR_FMT_TEXT:
        stream = print_stream_text_new(to_file, print_dest);
        break;

    case PR_FMT_PS:
        stream = print_stream_ps_new(to_file, print_dest);
        break;

    default:
        g_assert_not_reached();
        stream = NULL;
    }
    if (stream == NULL) {
        if (to_file) {
            open_failure_alert_box(print_dest, errno, TRUE);
        } else {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "Couldn't run print command %s.",
                          prefs.pr_cmd);
        }
        return;
    }

    if (!print_preamble(stream, cfile.filename, get_ws_vcs_version_info()))
        goto print_error;

    switch (gtk_follow_info->read_stream(follow_info, follow_print_text, stream)) {
    case FRS_OK:
        break;
    case FRS_OPEN_ERROR:
    case FRS_READ_ERROR:
        /* XXX - cancel printing? */
        destroy_print_stream(stream);
        return;
    case FRS_PRINT_ERROR:
        goto print_error;
    }

    if (!print_finale(stream))
        goto print_error;

    if (!destroy_print_stream(stream)) {
        if (to_file) {
            write_failure_alert_box(print_dest, errno);
        } else {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                          "Error closing print destination.");
        }
    }
#ifdef _WIN32
    if (win_printer) {
        print_mswin(print_dest);

        /* trash temp file */
        ws_remove(print_dest);
    }
#endif
    return;

 print_error:
    if (to_file) {
        write_failure_alert_box(print_dest, errno);
    } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error writing to print command: %s",
                      g_strerror(errno));
    }
    /* XXX - cancel printing? */
    destroy_print_stream(stream);

#ifdef _WIN32
    if (win_printer) {
        /* trash temp file */
        ws_remove(print_dest);
    }
#endif
}

static char *
gtk_follow_save_as_file(GtkWidget *caller)
{
    GtkWidget   *new_win;
    char        *pathname;

    new_win = file_selection_new("Wireshark: Save Follow Stream As",
                                 GTK_WINDOW(caller),
                                 FILE_SELECTION_SAVE);
    pathname = file_selection_run(new_win);
    if (pathname == NULL) {
        /* User cancelled or closed the dialog. */
        return NULL;
    }

    /* We've crosed the Rubicon; get rid of the dialog box. */
    window_destroy(new_win);

    return pathname;
}

static gboolean
follow_save_as_ok_cb(gchar *to_name, follow_info_t *follow_info)
{
    FILE        *fh;
    print_stream_t    *stream;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    if (gtk_follow_info->show_type == SHOW_RAW) {
        /* Write the data out as raw binary data */
        fh = ws_fopen(to_name, "wb");
    } else {
        /* Write it out as text */
        fh = ws_fopen(to_name, "w");
    }
    if (fh == NULL) {
        open_failure_alert_box(to_name, errno, TRUE);
        return FALSE;
    }

    if (gtk_follow_info->show_type == SHOW_RAW) {
        switch (gtk_follow_info->read_stream(follow_info, follow_write_raw, fh)) {
        case FRS_OK:
            if (fclose(fh) == EOF) {
                write_failure_alert_box(to_name, errno);
                return FALSE;
            }
            break;

        case FRS_OPEN_ERROR:
        case FRS_READ_ERROR:
            fclose(fh);
            return FALSE;

        case FRS_PRINT_ERROR:
            write_failure_alert_box(to_name, errno);
            fclose(fh);
            return FALSE;
        }
    } else {
        stream = print_stream_text_stdio_new(fh);
        switch (gtk_follow_info->read_stream(follow_info, follow_print_text, stream)) {
        case FRS_OK:
            if (!destroy_print_stream(stream)) {
                write_failure_alert_box(to_name, errno);
                return FALSE;
            }
            break;

        case FRS_OPEN_ERROR:
        case FRS_READ_ERROR:
            destroy_print_stream(stream);
            return FALSE;

        case FRS_PRINT_ERROR:
            write_failure_alert_box(to_name, errno);
            destroy_print_stream(stream);
            return FALSE;
        }
    }

    return TRUE;
}

static void
follow_save_as_cmd_cb(GtkWidget *w, gpointer data)
{
    GtkWidget       *caller = gtk_widget_get_toplevel(w);
    follow_info_t   *follow_info = (follow_info_t *)data;
    char            *pathname;

    /*
     * Loop until the user either selects a file or gives up.
     */
    for (;;) {
        pathname = gtk_follow_save_as_file(caller);
        if (pathname == NULL) {
            /* User gave up. */
            break;
        }
        if (follow_save_as_ok_cb(pathname, follow_info)) {
            /* We succeeded. */
            g_free(pathname);
            break;
        }
        /* Dump failed; let the user select another file or give up. */
        g_free(pathname);
    }
}

static void
follow_stream_direction_changed(GtkWidget *w, gpointer data)
{
    follow_info_t *follow_info = (follow_info_t *)data;

    switch(gtk_combo_box_get_active(GTK_COMBO_BOX(w))) {

    case 0 :
        follow_info->show_stream = BOTH_HOSTS;
        follow_load_text(follow_info);
        break;
    case 1 :
        follow_info->show_stream = FROM_SERVER;
        follow_load_text(follow_info);
        break;
    case 2 :
        follow_info->show_stream = FROM_CLIENT;
        follow_load_text(follow_info);
        break;
    }
}

/* Add a "follow_info_t" structure to the list. */
static void
remember_follow_info(follow_info_t *follow_info)
{
    follow_infos = g_list_append(follow_infos, follow_info);
}

#define IS_SHOW_TYPE(x) (gtk_follow_info->show_type == x ? 1 : 0)
/* Remove a "follow_info_t" structure from the list. */
static void
forget_follow_info(follow_info_t *follow_info)
{
    follow_infos = g_list_remove(follow_infos, follow_info);
}

static void
follow_stream(const gchar *title, follow_info_t *follow_info,
          gchar *both_directions_string,
          gchar *server_to_client_string, gchar *client_to_server_string)
{
    GtkWidget    *streamwindow, *vbox, *txt_scrollw, *text;
    GtkWidget    *hbox, *bbox, *button, *radio_bt;
    GtkWidget    *stream_fr, *stream_vb, *direction_hbox;
    GtkWidget    *stream_cmb;
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    gtk_follow_info->show_type = SHOW_RAW;

    streamwindow = dlg_window_new(title);

    /* needed in follow_filter_out_stream(), is there a better way? */
    gtk_follow_info->streamwindow = streamwindow;

    gtk_widget_set_name(streamwindow, title);
    gtk_window_set_default_size(GTK_WINDOW(streamwindow), DEF_WIDTH, DEF_HEIGHT);
    gtk_container_set_border_width(GTK_CONTAINER(streamwindow), 6);

    /* setup the container */
    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 6, FALSE);
    gtk_container_add(GTK_CONTAINER(streamwindow), vbox);

    /* content frame */
    stream_fr = gtk_frame_new("Stream Content");
    gtk_box_pack_start(GTK_BOX (vbox), stream_fr, TRUE, TRUE, 0);
    gtk_widget_show(stream_fr);

    stream_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 6, FALSE);
    gtk_container_set_border_width( GTK_CONTAINER(stream_vb) , 6);
    gtk_container_add(GTK_CONTAINER(stream_fr), stream_vb);

    /* create a scrolled window for the text */
    txt_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw), GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(stream_vb), txt_scrollw, TRUE, TRUE, 0);

    /* create a text box */
    text = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_WORD_CHAR);

    gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
    gtk_follow_info->text = text;

    /* direction hbox */
    direction_hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
    gtk_box_pack_start(GTK_BOX(stream_vb), direction_hbox, FALSE, FALSE, 0);

    stream_cmb = gtk_combo_box_text_new();

    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(stream_cmb), both_directions_string);
    follow_info->show_stream = BOTH_HOSTS;

    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(stream_cmb), client_to_server_string);

    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(stream_cmb), server_to_client_string);

    gtk_combo_box_set_active(GTK_COMBO_BOX(stream_cmb), 0); /* Do this before signal_connect  */
                                                            /*  so callback not triggered     */

    g_signal_connect(stream_cmb, "changed", G_CALLBACK(follow_stream_direction_changed), follow_info);

    gtk_widget_set_tooltip_text(stream_cmb, "Select the stream direction to display");
    gtk_box_pack_start(GTK_BOX(direction_hbox), stream_cmb, TRUE, TRUE, 0);

    /* stream hbox */
    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
    gtk_box_pack_start(GTK_BOX(stream_vb), hbox, FALSE, FALSE, 0);

    /* Create Find Button */
    button = ws_gtk_button_new_from_stock(GTK_STOCK_FIND);
    g_signal_connect(button, "clicked", G_CALLBACK(follow_find_cb), follow_info);
    gtk_widget_set_tooltip_text(button, "Find text in the displayed content");
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

    /* Create Save As Button */
    button = ws_gtk_button_new_from_stock(GTK_STOCK_SAVE_AS);
    g_signal_connect(button, "clicked", G_CALLBACK(follow_save_as_cmd_cb), follow_info);
    gtk_widget_set_tooltip_text(button, "Save the content as currently displayed");
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

    /* Create Print Button */
    button = ws_gtk_button_new_from_stock(GTK_STOCK_PRINT);
    g_signal_connect(button, "clicked", G_CALLBACK(follow_print_stream), follow_info);
    gtk_widget_set_tooltip_text(button, "Print the content as currently displayed");
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

    /* ASCII radio button */
    radio_bt = gtk_radio_button_new_with_label(NULL, "ASCII");
    gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"ASCII\" format");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), IS_SHOW_TYPE(SHOW_ASCII));
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
    g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb), follow_info);
    gtk_follow_info->ascii_bt = radio_bt;

    /* EBCDIC radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_bt)),
                                                "EBCDIC");
    gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"EBCDIC\" format");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), IS_SHOW_TYPE(SHOW_EBCDIC));
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
    g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb), follow_info);
    gtk_follow_info->ebcdic_bt = radio_bt;

    /* HEX DUMP radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_bt)),
                                               "Hex Dump");
    gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"Hexdump\" format");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), IS_SHOW_TYPE(SHOW_HEXDUMP));
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
    g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb),follow_info);
    gtk_follow_info->hexdump_bt = radio_bt;

    /* C Array radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_bt)),
                                               "C Arrays");
    gtk_widget_set_tooltip_text(radio_bt, "Stream data output in \"C Array\" format");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), IS_SHOW_TYPE(SHOW_CARRAY));
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
    g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb), follow_info);
    gtk_follow_info->carray_bt = radio_bt;

    /* Raw radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_bt)),
                                                 "Raw");
    gtk_widget_set_tooltip_text(radio_bt,
                                    "Stream data output in \"Raw\" (binary) format. "
                                    "As this contains non printable characters, "
                                    "the screen output will be in ASCII format");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), IS_SHOW_TYPE(SHOW_RAW));
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, TRUE, TRUE, 0);
    g_signal_connect(radio_bt, "toggled", G_CALLBACK(follow_charset_toggle_cb), follow_info);
    gtk_follow_info->raw_bt = radio_bt;

    /* Button row: help, filter out, close button */
    bbox = dlg_button_row_new(WIRESHARK_STOCK_FILTER_OUT_STREAM, GTK_STOCK_CLOSE, GTK_STOCK_HELP,
                              NULL);
    gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 5);


    button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), WIRESHARK_STOCK_FILTER_OUT_STREAM);
    gtk_widget_set_tooltip_text(button, "Build a display filter which cuts this stream from the capture");
    g_signal_connect(button, "clicked", G_CALLBACK(follow_filter_out_stream), follow_info);

    button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(streamwindow, button, window_cancel_button_cb);
    gtk_widget_set_tooltip_text(button, "Close the dialog and keep the current display filter");
    gtk_widget_grab_default(button);

    button = (GtkWidget *)g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(button, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_FOLLOW_STREAM_DIALOG);

    /* Tuck away the follow_info object into the window */
    g_object_set_data(G_OBJECT(streamwindow), E_FOLLOW_INFO_KEY, follow_info);

    follow_load_text(follow_info);
    remember_follow_info(follow_info);


    g_signal_connect(streamwindow, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(streamwindow, "destroy", G_CALLBACK(follow_destroy_cb), NULL);

    /* Make sure this widget gets destroyed if we quit the main loop,
       so that if we exit, we clean up any temporary files we have
       for "Follow TCP Stream" windows.
       gtk_quit_add_destroy is deprecated and should not be used in newly-written code.
       This function is going to be removed in GTK+ 3.0
       gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(streamwindow));
       */

    gtk_widget_show_all(streamwindow);
    window_present(streamwindow);
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file
 * and freeing the filter_out_filter */
static void
follow_destroy_cb(GtkWidget *w, gpointer data _U_)
{
    follow_info_t *follow_info;
    gtk_follow_info_t *gtk_follow_info;

    follow_info = (follow_info_t *)g_object_get_data(G_OBJECT(w), E_FOLLOW_INFO_KEY);
    gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    forget_follow_info(follow_info);
    g_free(gtk_follow_info);
    follow_info_free(follow_info);
    gtk_widget_destroy(w);
}

static frs_return_t
follow_show(follow_info_t *follow_info,
            follow_print_line_func follow_print,
            char *buffer, size_t nchars, gboolean is_from_server, void *arg,
            guint32 *global_pos, guint32 *server_packet_count,
            guint32 *client_packet_count)
{
    gchar initbuf[256];
    guint32 current_pos;
    static const gchar hexchars[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    gtk_follow_info_t *gtk_follow_info = (gtk_follow_info_t *)follow_info->gui_data;

    switch (gtk_follow_info->show_type) {

    case SHOW_EBCDIC:
        /* If our native arch is ASCII, call: */
        EBCDIC_to_ASCII(buffer, (guint) nchars);
        if (!follow_print(buffer, nchars, is_from_server, arg))
            return FRS_PRINT_ERROR;
        break;

    case SHOW_ASCII:
        /* If our native arch is EBCDIC, call:
         * ASCII_TO_EBCDIC(buffer, nchars);
         */
        if (!follow_print(buffer, nchars, is_from_server, arg))
            return FRS_PRINT_ERROR;
        break;

    case SHOW_RAW:
        /* Don't translate, no matter what the native arch
         * is.
         */
        if (!follow_print(buffer, nchars, is_from_server, arg))
            return FRS_PRINT_ERROR;
        break;

    case SHOW_HEXDUMP:
        current_pos = 0;
        while (current_pos < nchars) {
            gchar hexbuf[256];
            int i;
            gchar *cur = hexbuf, *ascii_start;

            /* is_from_server indentation : put 4 spaces at the
             * beginning of the string */
            /* XXX - We might want to prepend each line with "C" or "S" instead. */
            if (is_from_server && follow_info->show_stream == BOTH_HOSTS) {
                memset(cur, ' ', 4);
                cur += 4;
            }
            cur += g_snprintf(cur, 20, "%08X  ", *global_pos);
            /* 49 is space consumed by hex chars */
            ascii_start = cur + 49;
            for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                *cur++ =
                    hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
                *cur++ =
                    hexchars[buffer[current_pos + i] & 0x0f];
                *cur++ = ' ';
                if (i == 7)
                    *cur++ = ' ';
            }
            /* Fill it up if column isn't complete */
            while (cur < ascii_start)
                *cur++ = ' ';

            /* Now dump bytes as text */
            for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                *cur++ =
                    (g_ascii_isprint(buffer[current_pos + i]) ?
                     buffer[current_pos + i] : '.' );
                if (i == 7) {
                    *cur++ = ' ';
                }
            }
            current_pos += i;
            (*global_pos) += i;
            *cur++ = '\n';
            *cur = 0;
            if (!follow_print(hexbuf, strlen(hexbuf), is_from_server, arg))
                return FRS_PRINT_ERROR;
        }
        break;

    case SHOW_CARRAY:
        current_pos = 0;
        g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = {\n",
               is_from_server ? 1 : 0,
               is_from_server ? (*server_packet_count)++ : (*client_packet_count)++);
        if (!follow_print(initbuf, strlen(initbuf), is_from_server, arg))
            return FRS_PRINT_ERROR;

        while (current_pos < nchars) {
            gchar hexbuf[256];
            int i, cur;

            cur = 0;
            for (i = 0; i < 8 && current_pos + i < nchars; i++) {
                /* Prepend entries with "0x" */
                hexbuf[cur++] = '0';
                hexbuf[cur++] = 'x';
                hexbuf[cur++] = hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
                hexbuf[cur++] = hexchars[buffer[current_pos + i] & 0x0f];

                /* Delimit array entries with a comma */
                if (current_pos + i + 1 < nchars)
                    hexbuf[cur++] = ',';

                hexbuf[cur++] = ' ';
            }

            /* Terminate the array if we are at the end */
            if (current_pos + i == nchars) {
                hexbuf[cur++] = '}';
                hexbuf[cur++] = ';';
            }

            current_pos += i;
            (*global_pos) += i;
            hexbuf[cur++] = '\n';
            hexbuf[cur] = 0;
            if (!follow_print(hexbuf, strlen(hexbuf), is_from_server, arg))
                return FRS_PRINT_ERROR;
        }
        break;

    case SHOW_YAML:
    case SHOW_UTF8:
    case SHOW_UTF16:
        g_assert_not_reached();
        break;
    }

    return FRS_OK;
}

/* Follow the TCP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_tcp_stream_cb(GtkWidget * w _U_, gpointer data _U_)
{
    register_follow_t* follower = get_follow_by_name("TCP");

    follow_stream_cb(follower, follow_common_read_stream, w, data);
}

/* Follow the UDP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_udp_stream_cb(GtkWidget * w _U_, gpointer data _U_)
{
    register_follow_t* follower = get_follow_by_name("UDP");

    follow_stream_cb(follower, follow_common_read_stream, w, data);
}

/* Follow the HTTP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_http_stream_cb(GtkWidget * w _U_, gpointer data _U_)
{
    register_follow_t* follower = get_follow_by_name("HTTP");

    follow_stream_cb(follower, follow_common_read_stream, w, data);
}

/* Follow the SSL stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_ssl_stream_cb(GtkWidget * w _U_, gpointer data _U_)
{
    register_follow_t* follower = get_follow_by_name("SSL");

    follow_stream_cb(follower, follow_common_read_stream, w, data);
}

static void
follow_redraw(gpointer data, gpointer user_data _U_)
{
    follow_load_text((follow_info_t *)data);
}

/* Redraw the text in all "Follow Stream" windows. */
void
follow_stream_redraw_all(void)
{
    g_list_foreach(follow_infos, follow_redraw, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
