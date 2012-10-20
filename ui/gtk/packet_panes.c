/* packet_panes.c
 * Routines for GTK+ packet display (packet details and hex dump panes)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Jeff Foster,    2001/03/12,  added support for displaying named
 *                              data sources as tabbed hex windows
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

#include <ctype.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <string.h>

#include <epan/epan_dissect.h>

#include <epan/packet.h>
#include <epan/charsets.h>
#include <epan/prefs.h>
#include <epan/filesystem.h>

#include "../isprint.h"

#include "ui/alert_box.h"
#include "ui/last_open_dir.h"
#include "ui/progress_dlg.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include <wsutil/file_util.h>

#include "ui/gtk/keys.h"
#include "ui/gtk/color_utils.h"
#include "ui/gtk/packet_win.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/font_utils.h"
#include "ui/gtk/webbrowser.h"
#include "ui/gtk/main.h"
#include "ui/gtk/menus.h"
#include "ui/gtk/packet_panes.h"
#include "ui/gtk/proto_tree_model.h"
#include "ui/gtk/bytes_view.h"

#ifdef _WIN32
#include <gdk/gdkwin32.h>
#include <windows.h>
#include "ui/win32/file_dlg_win32.h"
#endif


#define E_BYTE_VIEW_TREE_PTR      "byte_view_tree_ptr"
#define E_BYTE_VIEW_TREE_VIEW_PTR "byte_view_tree_view_ptr"
#define E_BYTE_VIEW_TVBUFF_KEY    "byte_view_tvbuff"
#define E_BYTE_VIEW_START_KEY     "byte_view_start"
#define E_BYTE_VIEW_END_KEY       "byte_view_end"
#define E_BYTE_VIEW_MASK_KEY      "byte_view_mask"
#define E_BYTE_VIEW_MASKLE_KEY    "byte_view_mask_le"
#define E_BYTE_VIEW_APP_START_KEY "byte_view_app_start"
#define E_BYTE_VIEW_APP_END_KEY   "byte_view_app_end"
#define E_BYTE_VIEW_ENCODE_KEY    "byte_view_encode"

/* Get the current text window for the notebook. */
GtkWidget *
get_notebook_bv_ptr(GtkWidget *nb_ptr)
{
    int num;
    GtkWidget *bv_page;

    num = gtk_notebook_get_current_page(GTK_NOTEBOOK(nb_ptr));
    bv_page = gtk_notebook_get_nth_page(GTK_NOTEBOOK(nb_ptr), num);
    if (bv_page)
        return gtk_bin_get_child(GTK_BIN(bv_page));
    else
        return NULL;
}

/*
 * Get the data and length for a byte view, given the byte view page.
 * Return the pointer, or NULL on error, and set "*data_len" to the length.
 */
const guint8 *
get_byte_view_data_and_length(GtkWidget *byte_view, guint *data_len)
{
    tvbuff_t *byte_view_tvb;
    const guint8 *data_ptr;

    byte_view_tvb = g_object_get_data(G_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY);
    if (byte_view_tvb == NULL)
        return NULL;

    if ((*data_len = tvb_length(byte_view_tvb))) {
        data_ptr = tvb_get_ptr(byte_view_tvb, 0, -1);
        return data_ptr;
    } else
        return "";
}

/*
 * Set the current text window for the notebook to the window that
 * refers to a particular tvbuff.
 */
void
set_notebook_page(GtkWidget *nb_ptr, tvbuff_t *tvb)
{
    int num;
    GtkWidget *bv_page, *bv;
    tvbuff_t *bv_tvb;

    for (num = 0;
         (bv_page = gtk_notebook_get_nth_page(GTK_NOTEBOOK(nb_ptr), num)) != NULL;
         num++) {
        bv = gtk_bin_get_child(GTK_BIN(bv_page));
        bv_tvb = g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_TVBUFF_KEY);
        if (bv_tvb == tvb) {
            /* Found it. */
            gtk_notebook_set_current_page(GTK_NOTEBOOK(nb_ptr), num);
            break;
        }
    }
}

/* Redraw a given byte view window. */
void
redraw_packet_bytes(GtkWidget *nb, frame_data *fd, field_info *finfo)
{
    GtkWidget *bv;
    const guint8 *data;
    guint len;

    bv = get_notebook_bv_ptr(nb);
    if (bv != NULL) {
        data = get_byte_view_data_and_length(bv, &len);
        if (data != NULL)
            packet_hex_print(bv, data, fd, finfo, len);
    }
}

/* Redraw all byte view windows. */
void
redraw_packet_bytes_all(void)
{
    if (cfile.current_frame != NULL)
        redraw_packet_bytes( byte_nb_ptr_gbl, cfile.current_frame, cfile.finfo_selected);

    redraw_packet_bytes_packet_wins();

    /* XXX - this is a hack, to workaround a bug in GTK2.x!
       when changing the font size, even refilling of the corresponding
       gtk_text_buffer doesn't seem to trigger an update.
       The only workaround is to freshly select the frame, which will remove any
       existing notebook tabs and "restart" the whole byte view again. */
    if (cfile.current_frame != NULL) {
        cfile.current_row = -1;
        cf_goto_frame(&cfile, cfile.current_frame->num);
    }
}

static void
expand_tree(GtkTreeView *tree_view, GtkTreeIter *iter,
            GtkTreePath *path _U_, gpointer user_data _U_)
{
    field_info   *finfo;
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(tree_view);
    gtk_tree_model_get(model, iter, 1, &finfo, -1);
    g_assert(finfo);

    /* scroll the expanded item to reduce the need to do a manual scroll down
     * and provide faster navigation of deeper trees */

    if(prefs.gui_auto_scroll_on_expand) 
        gtk_tree_view_scroll_to_cell(tree_view, path, NULL, TRUE, (prefs.gui_auto_scroll_percentage/100.0f), 0.0f);

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be expanded.
     */
    if (finfo->tree_type != -1) {
        g_assert(finfo->tree_type >= 0 &&
                 finfo->tree_type < num_tree_types);
        tree_is_expanded[finfo->tree_type] = TRUE;
    }
}

static void
collapse_tree(GtkTreeView *tree_view, GtkTreeIter *iter,
              GtkTreePath *path _U_, gpointer user_data _U_)
{
    field_info   *finfo;
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(tree_view);
    gtk_tree_model_get(model, iter, 1, &finfo, -1);
    g_assert(finfo);

    /*
     * Nodes with "finfo->tree_type" of -1 have no ett_ value, and
     * are thus presumably leaf nodes and cannot be collapsed.
     */
    if (finfo->tree_type != -1) {
        g_assert(finfo->tree_type >= 0 &&
                 finfo->tree_type < num_tree_types);
        tree_is_expanded[finfo->tree_type] = FALSE;
    }
}

struct field_lookup_info {
    field_info  *fi;
    GtkTreeIter  iter;
};

static gboolean
lookup_finfo(GtkTreeModel *model, GtkTreePath *path _U_, GtkTreeIter *iter,
             gpointer data)
{
    field_info *fi;
    struct field_lookup_info *fli = (struct field_lookup_info *)data;

    gtk_tree_model_get(model, iter, 1, &fi, -1);
    if (fi == fli->fi) {
        fli->iter = *iter;
        return TRUE;
    }
    return FALSE;
}

GtkTreePath
*tree_find_by_field_info(GtkTreeView *tree_view, field_info *finfo)
{
    GtkTreeModel *model;
    struct field_lookup_info fli;

    g_assert(finfo != NULL);

    model = gtk_tree_view_get_model(tree_view);
    fli.fi = finfo;
    gtk_tree_model_foreach(model, lookup_finfo, &fli);

    return gtk_tree_model_get_path(model, &fli.iter);
}

/* If the user selected a certain byte in the byte view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and:
 *
 *    if we succeed, select it, and return TRUE;
 *    if we fail, return FALSE. */
gboolean
byte_view_select(GtkWidget *widget, GdkEventButton *event)
{
    proto_tree   *tree;
    GtkTreeView  *tree_view;
    int           byte = -1;
    tvbuff_t     *tvb;

    tree = g_object_get_data(G_OBJECT(widget), E_BYTE_VIEW_TREE_PTR);
    if (tree == NULL) {
        /*
         * Somebody clicked on the dummy byte view; do nothing.
         */
        return FALSE;
    }
    tree_view = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(widget),
                                              E_BYTE_VIEW_TREE_VIEW_PTR));

    byte = bytes_view_byte_from_xy(BYTES_VIEW(widget), (gint) event->x, (gint) event->y);

    if (byte == -1) {
        return FALSE;
    }

    /* Get the data source tvbuff */
    tvb = g_object_get_data(G_OBJECT(widget), E_BYTE_VIEW_TVBUFF_KEY);

    return highlight_field(tvb, byte, tree_view, tree);
}

/* This highlights the field in the proto tree that is at position byte */
gboolean
highlight_field(tvbuff_t *tvb, gint byte, GtkTreeView *tree_view,
                proto_tree *tree)
{
    GtkTreeModel *model = NULL;
    GtkTreePath  *first_path = NULL, *path = NULL;
    GtkTreeIter   parent;
    field_info   *finfo = NULL;
    match_data    mdata;
    struct field_lookup_info fli;

    if (cfile.search_in_progress && cfile.string && cfile.decode_data) {
        /* The tree where the target string matched one of the labels was discarded in
           match_protocol_tree() so we have to search again in the latest tree. (Uugh) */
        if (cf_find_string_protocol_tree(&cfile, tree, &mdata)) {
            finfo = mdata.finfo;
        }
    } else {
        /* Find the finfo that corresponds to our byte. */
        finfo = proto_find_field_from_offset(tree, byte, tvb);
    }

    if (!finfo) {
        return FALSE;
    }

    model = gtk_tree_view_get_model(tree_view);
    fli.fi = finfo;
    gtk_tree_model_foreach(model, lookup_finfo, &fli);

    /* Expand our field's row */
    first_path = gtk_tree_model_get_path(model, &fli.iter);
    gtk_tree_view_expand_row(tree_view, first_path, FALSE);
    expand_tree(tree_view, &fli.iter, NULL, NULL);

    /* ... and its parents */
    while (gtk_tree_model_iter_parent(model, &parent, &fli.iter)) {
        path = gtk_tree_model_get_path(model, &parent);
        gtk_tree_view_expand_row(tree_view, path, FALSE);
        expand_tree(tree_view, &parent, NULL, NULL);
        fli.iter = parent;
        gtk_tree_path_free(path);
    }

    /* Refresh the display so that the expanded trees are visible */
    proto_tree_draw(tree, GTK_WIDGET(tree_view));

    /* select our field's row */
    gtk_tree_selection_select_path(gtk_tree_view_get_selection(tree_view),
                                   first_path);

    /* If the last search was a string or hex search within "Packet data", the entire field might
       not be highlighted. If the user just clicked on one of the bytes comprising that field, the
       above call didn't trigger a 'gtk_tree_view_get_selection' event. Call redraw_packet_bytes()
       to make the highlighting of the entire field visible. */
    if (!cfile.search_in_progress) {
        if (cfile.hex || (cfile.string && cfile.packet_data)) {
            redraw_packet_bytes(byte_nb_ptr_gbl, cfile.current_frame, cfile.finfo_selected);
        }
    }

    /* And position the window so the selection is visible.
     * Position the selection in the middle of the viewable
     * pane. */
    gtk_tree_view_scroll_to_cell(tree_view, first_path, NULL, TRUE, 0.5f, 0.0f);

    gtk_tree_path_free(first_path);

    return TRUE;
}

/* Calls functions for different mouse-button presses. */
static gboolean
byte_view_button_press_cb(GtkWidget *widget, GdkEvent *event, gpointer data)
{
    GdkEventButton *event_button = NULL;

    if(widget == NULL || event == NULL || data == NULL) {
        return FALSE;
    }

    if(event->type == GDK_BUTTON_PRESS) {
        event_button = (GdkEventButton *) event;

        /* To qoute the "Gdk Event Structures" doc:
         * "Normally button 1 is the left mouse button, 2 is the middle button, and 3 is the right button" */
        switch(event_button->button) {

        case 1:
            return byte_view_select(widget, event_button);
        case 3:
            return popup_menu_handler(widget, event, data);
        default:
            return FALSE;
        }
    }

    return FALSE;
}

GtkWidget *
byte_view_new(void)
{
    GtkWidget *byte_nb;

    byte_nb = gtk_notebook_new();
    gtk_notebook_set_tab_pos(GTK_NOTEBOOK(byte_nb), GTK_POS_BOTTOM);

    /* this will only have an effect, if no tabs are shown */
    gtk_notebook_set_show_border(GTK_NOTEBOOK(byte_nb), FALSE);

    /* set the tabs scrollable, if they don't fit into the pane */
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(byte_nb), TRUE);

    /* enable a popup menu containing the tab labels, will be helpful if tabs don't fit into the pane */
    gtk_notebook_popup_enable(GTK_NOTEBOOK(byte_nb));

    /* Add a placeholder byte view so that there's at least something
       displayed in the byte view notebook. */
    add_byte_tab(byte_nb, "", NULL, NULL, NULL);

    return byte_nb;
}

static void
byte_view_realize_cb(GtkWidget *bv, gpointer data _U_)
{
    const guint8 *byte_data;
    guint byte_len;

    byte_data = get_byte_view_data_and_length(bv, &byte_len);
    if (byte_data == NULL) {
        /* This must be the dummy byte view if no packet is selected. */
        return;
    }
    packet_hex_print(bv, byte_data, cfile.current_frame, NULL, byte_len);
}

GtkWidget *
add_byte_tab(GtkWidget *byte_nb, const char *name, tvbuff_t *tvb,
             proto_tree *tree, GtkWidget *tree_view)
{
    GtkWidget *byte_view, *byte_scrollw, *label;

    /* Byte view.  Create a scrolled window for the text. */
    byte_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(byte_scrollw),
                                        GTK_SHADOW_IN);
    /* Add scrolled pane to tabbed window */
    label = gtk_label_new(name);
    gtk_notebook_append_page(GTK_NOTEBOOK(byte_nb), byte_scrollw, label);

    gtk_widget_show(byte_scrollw);

    byte_view = bytes_view_new();
    bytes_view_set_font(BYTES_VIEW(byte_view), user_font_get_regular());

    g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TVBUFF_KEY, tvb);
    gtk_container_add(GTK_CONTAINER(byte_scrollw), byte_view);

    g_signal_connect(byte_view, "show", G_CALLBACK(byte_view_realize_cb), NULL);
    g_signal_connect(byte_view, "button_press_event", G_CALLBACK(byte_view_button_press_cb),
                     g_object_get_data(G_OBJECT(popup_menu_object), PM_BYTES_VIEW_KEY));

    g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TREE_PTR, tree);
    g_object_set_data(G_OBJECT(byte_view), E_BYTE_VIEW_TREE_VIEW_PTR, tree_view);

    gtk_widget_show(byte_view); /* triggers byte_view_realize_cb which calls packet_hex_print */

    /* no tabs if this is the first page */
    if (!(gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_scrollw)))
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), FALSE);
    else
        gtk_notebook_set_show_tabs(GTK_NOTEBOOK(byte_nb), TRUE);

    /* set this page */
    gtk_notebook_set_current_page(GTK_NOTEBOOK(byte_nb),
                                  gtk_notebook_page_num(GTK_NOTEBOOK(byte_nb), byte_nb));

    return byte_view;
}

void
add_byte_views(epan_dissect_t *edt, GtkWidget *tree_view,
               GtkWidget *byte_nb_ptr)
{
    GSList *src_le;
    struct data_source *src;

    /*
     * Get rid of all the old notebook tabs.
     */
    while (gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0) != NULL)
        gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

    /*
     * Add to the specified byte view notebook tabs for hex dumps
     * of all the data sources for the specified frame.
     */
    for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
        src = src_le->data;
        add_byte_tab(byte_nb_ptr, get_data_source_name(src), get_data_source_tvb(src), edt->tree,
                     tree_view);
    }

    /*
     * Initially select the first byte view.
     */
    gtk_notebook_set_current_page(GTK_NOTEBOOK(byte_nb_ptr), 0);
}



static GtkWidget *savehex_dlg=NULL;

static void
savehex_dlg_destroy_cb(GtkWidget *w _U_, gpointer user_data _U_)
{
    savehex_dlg = NULL;
}


static void
copy_hex_all_info(GString* copy_buffer, const guint8* data_p, int data_len, gboolean append_text)
{
    const int byte_line_length = 16; /* Print out data for 16 bytes on one line */
    int i, j;
    gboolean end_of_line = TRUE; /* Initial state is end of line */
    int byte_line_part_length;

    GString* hex_str;
    GString* char_str;

    /* Write hex data for a line, then ascii data, then concatenate and add to buffer */
    hex_str = g_string_new("");
    char_str= g_string_new("");

    i = 0;
    while (i<data_len) {
        if(end_of_line) {
            g_string_append_printf(hex_str,"%04x  ",i); /* Offset - note that we _append_ here */
        }

        g_string_append_printf(hex_str," %02x",*data_p);
        if(append_text) {
            g_string_append_printf(char_str,"%c",isprint(*data_p) ? *data_p : '.');
        }

        ++data_p;

        /* Look ahead to see if this is the end of the data */
        byte_line_part_length = (++i) % byte_line_length;
        if(i == data_len){
            /* End of data - need to fill in spaces in hex string and then do "end of line".
             *
             */
            for(j = 0; append_text && (j < (byte_line_length - byte_line_part_length)); ++j) {
                g_string_append(hex_str,"   "); /* Three spaces for each missing byte */
            }
            end_of_line = TRUE;
        } else {
            end_of_line = (byte_line_part_length == 0 ? TRUE : FALSE);
        }


        if (end_of_line){
            /* End of line */
            g_string_append(copy_buffer, hex_str->str);
            if(append_text) {
                /* Two spaces between hex and text */
                g_string_append_c(copy_buffer, ' ');
                g_string_append_c(copy_buffer, ' ');
                g_string_append(copy_buffer, char_str->str);
            }
            /* Setup ready for next line */
            g_string_assign(char_str,"");
            g_string_assign(hex_str, "\n");
        }
    }

    g_string_free(hex_str, TRUE);
    g_string_free(char_str, TRUE);
}

static int
copy_hex_bytes_text_only(GString* copy_buffer, const guint8* data_p, int data_len _U_)
{

    gchar to_append;

    /* Copy printable characters, newlines, and (horizontal) tabs. */
    if(isprint(*data_p)) {
        to_append = *data_p;
    } else if(*data_p==0x0a) {
        to_append = '\n';
    } else if(*data_p==0x09) {
        to_append = '\t';
    } else {
        return 1; /* Just ignore non-printable bytes */
    }
    g_string_append_c(copy_buffer,to_append);
    return 1;
}

static
int copy_hex_bytes_hex(GString* copy_buffer, const guint8* data_p, int data_len _U_)
{
    g_string_append_printf(copy_buffer, "%02x", *data_p);
    return 1;
}

void
copy_hex_cb(GtkWidget * w _U_, gpointer data _U_, copy_data_type data_type)
{
    GtkWidget *bv;

    guint len = 0;
    int bytes_consumed = 0;
    int flags;

    const guint8* data_p;

    GString* copy_buffer = g_string_new(""); /* String to copy to clipboard */

    bv = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    if (bv == NULL) {
        /* shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
        return;
    }

    data_p = get_byte_view_data_and_length(bv, &len);
    g_assert(data_p != NULL);

    flags = data_type & CD_FLAGSMASK;
    data_type = data_type & CD_TYPEMASK;

    if(flags & CD_FLAGS_SELECTEDONLY) {
        int start, end;

        /* Get the start and end of the highlighted bytes. */
        start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
        end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));

        if(start >= 0 && end > start && (end - start <= (int)len)) {
            len = end - start;
            data_p += start;
        }
    }

    switch(data_type) {
    case(CD_ALLINFO):
        /* This is too different from other text formats - handle separately */
        copy_hex_all_info(copy_buffer, data_p, len, TRUE);
        break;
    case(CD_HEXCOLUMNS):
        /* This could be done incrementally, but it is easier to mingle with the code for CD_ALLINFO */
        copy_hex_all_info(copy_buffer, data_p, len, FALSE);
        break;
    case(CD_BINARY):
        /* Completely different logic to text copies - leave copy buffer alone */
        copy_binary_to_clipboard(data_p,len);
        break;
    default:
        /* Incrementally write to text buffer in various formats */
        while (len > 0){
            switch(data_type) {
            case (CD_TEXTONLY):
                bytes_consumed = copy_hex_bytes_text_only(copy_buffer, data_p, len);
                break;
            case (CD_HEX):
                bytes_consumed = copy_hex_bytes_hex(copy_buffer, data_p, len);
                break;
            default:
                g_assert_not_reached();
                break;
            }

            g_assert(bytes_consumed>0);
            data_p += bytes_consumed;
            len -= bytes_consumed;
        }
        break;
    }

    if(copy_buffer->len > 0) {
        copy_to_clipboard(copy_buffer);
    }

    g_string_free(copy_buffer, TRUE);
}

/* save the current highlighted hex data */
static gboolean
savehex_save_clicked_cb(GtkWidget * w _U_, gpointer data _U_)
{
    GtkWidget *bv;
    int fd, start, end;
    guint len;
    const guint8 *data_p = NULL;
    char *file;

    file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(savehex_dlg));

#if 0 /* Not req'd: GtkFileChooserWidget currently being used won't return with a Null filename */
    if (!file ||! *file) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Please enter a filename!");
        g_free(file);
        return TRUE;
    }
#endif
    if (test_for_directory(file) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(file);
        g_free(file);
        file_selection_set_current_folder(savehex_dlg, get_last_open_dir());
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(savehex_dlg), "");
        return FALSE; /* do gtk_dialog_run again */
    }

    /* XXX: Must check if file name exists first */

    bv = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    if (bv == NULL) {
        /* shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
        g_free(file);
        return TRUE;
    }
    /*
     * Retrieve the info we need
     */
    start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
    end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));
    data_p = get_byte_view_data_and_length(bv, &len);

    if (data_p == NULL || start == -1 || start > end) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "No data selected to save!");
        g_free(file);
        return TRUE;
    }

    fd = ws_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
    if (fd == -1) {
        open_failure_alert_box(file, errno, TRUE);
        g_free(file);
        return TRUE;
    }
    if (ws_write(fd, data_p + start, end - start) < 0) {
        write_failure_alert_box(file, errno);
        ws_close(fd);
        g_free(file);
        return TRUE;
    }
    if (ws_close(fd) < 0) {
        write_failure_alert_box(file, errno);
        g_free(file);
        return TRUE;
    }

    /* Get rid of the dialog box */
    g_free(file);
#if 0 /* being handled by caller  (for now) */
    window_destroy(GTK_WIDGET(savehex_dlg));
#endif
    return TRUE;
}

/* Launch the dialog box to put up the file selection box etc */
#ifdef _WIN32
void
savehex_cb(GtkWidget * w _U_, gpointer data _U_)
{
    win32_export_raw_file(GDK_WINDOW_HWND(gtk_widget_get_window(top_level)));
    return;
}
#else
void
savehex_cb(GtkWidget * w _U_, gpointer data _U_)
{
    int start, end;
    guint len;
    const guint8 *data_p = NULL;
    gchar *label;
    GtkWidget   *bv;
    GtkWidget   *dlg_lb;

    /* don't show up the dialog, if no data has to be saved */
    bv = get_notebook_bv_ptr(byte_nb_ptr_gbl);
    if (bv == NULL) {
        /* shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not find the corresponding text window!");
        return;
    }
    start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
    end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));
    data_p = get_byte_view_data_and_length(bv, &len);

    if (data_p == NULL || start == -1 || start > end) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No data selected to save!");
        return;
    }

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
    /* if the window is already open, bring it to front */
    if(savehex_dlg){
        reactivate_window(savehex_dlg);
        return;
    }
#endif
    /*
     * Build the dialog box we need.
     */
    savehex_dlg = file_selection_new("Wireshark: Export Selected Packet Bytes", FILE_SELECTION_SAVE);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(savehex_dlg), TRUE);

    /* label */
    label = g_strdup_printf("Will save %u %s of raw binary data to specified file.",
                            end - start, plurality(end - start, "byte", "bytes"));
    dlg_lb = gtk_label_new(label);
    g_free(label);
    file_selection_set_extra_widget(savehex_dlg, dlg_lb);
    gtk_widget_show(dlg_lb);

    g_signal_connect(savehex_dlg, "destroy", G_CALLBACK(savehex_dlg_destroy_cb), NULL);

#if 0
    if (gtk_dialog_run(GTK_DIALOG(savehex_dlg)) == GTK_RESPONSE_ACCEPT) {
        savehex_save_clicked_cb(savehex_dlg, savehex_dlg);
    } else {
        window_destroy(savehex_dlg);
    }
#endif
    /* "Run" the GtkFileChooserDialog.                                              */
    /* Upon exit: If "Accept" run the OK callback.                                  */
    /*            If the OK callback returns with a FALSE status, re-run the dialog.*/
    /*            If not accept (ie: cancel) destroy the window.                    */
    /* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
    /*      return with a TRUE status so that the dialog window will be destroyed.  */
    /*      Trying to re-run the dialog after popping up an alert box will not work */
    /*       since the user will not be able to dismiss the alert box.              */
    /*      The (somewhat unfriendly) effect: the user must re-invoke the           */
    /*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
    /*                                                                              */
    /*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
    /*            GtkFileChooserDialog.                                             */
    while (gtk_dialog_run(GTK_DIALOG(savehex_dlg)) == GTK_RESPONSE_ACCEPT) {
        if (savehex_save_clicked_cb(NULL, savehex_dlg)) {
            break; /* we're done */
        }
    }
    window_destroy(savehex_dlg);
}
#endif

static void
packet_hex_update(GtkWidget *bv, const guint8 *pd, int len, int bstart,
                  int bend, guint32 bmask, int bmask_le,
                  int astart, int aend, int encoding)
{
	bytes_view_set_encoding(BYTES_VIEW(bv), encoding);
	bytes_view_set_format(BYTES_VIEW(bv), recent.gui_bytes_view);
	bytes_view_set_data(BYTES_VIEW(bv), pd, len);
 
	bytes_view_set_highlight_style(BYTES_VIEW(bv), prefs.gui_hex_dump_highlight_style);
 
	bytes_view_set_highlight(BYTES_VIEW(bv), bstart, bend, bmask, bmask_le);
	bytes_view_set_highlight_appendix(BYTES_VIEW(bv), astart, aend);
 
	if (bstart != -1 && bend != -1)
		bytes_view_scroll_to_byte(BYTES_VIEW(bv), bstart);
	bytes_view_refresh(BYTES_VIEW(bv));
}

void
packet_hex_print(GtkWidget *bv, const guint8 *pd, frame_data *fd,
                 field_info *finfo, guint len)
{
    /* do the initial printing and save the information needed  */
    /* to redraw the display if preferences change.             */

    int bstart = -1, bend = -1, blen = -1;
    guint32 bmask = 0x00; int bmask_le = 0;
    int astart = -1, aend = -1, alen = -1;


    if (finfo != NULL) {

        if (cfile.search_in_progress && (cfile.hex || (cfile.string && cfile.packet_data))) {
            /* In the hex view, only highlight the target bytes or string. The entire
               field can then be displayed by clicking on any of the bytes in the field. */
            if (cfile.hex) {
                blen = (int)strlen(cfile.sfilter)/2;
            } else {
                blen = (int)strlen(cfile.sfilter);
            }
            bstart = cfile.search_pos - (blen-1);

        } else {
            blen = finfo->length;
            bstart = finfo->start;
        }

        /* bmask = finfo->hfinfo->bitmask << finfo->hfinfo->bitshift; */ /* (value & mask) >> shift */
        if (finfo->hfinfo) bmask = finfo->hfinfo->bitmask;
        astart = finfo->appendix_start;
        alen = finfo->appendix_length;

        if (FI_GET_FLAG(finfo, FI_LITTLE_ENDIAN))
            bmask_le = 1;
        else if (FI_GET_FLAG(finfo, FI_BIG_ENDIAN))
            bmask_le = 0;
        else { /* unknown endianess - disable mask
                  bmask_le = (G_BYTE_ORDER == G_LITTLE_ENDIAN);
               */
            bmask = 0x00;
        }

        if (bmask == 0x00) {
            int bito = FI_GET_BITS_OFFSET(finfo);
            int bitc = FI_GET_BITS_SIZE(finfo);
            int bitt = bito + bitc;

            /* construct mask using bito & bitc */
            /* XXX, mask has only 32 bit, later we can store bito&bitc, and use them (which should be faster) */
            if (bitt > 0 && bitt < 32) {

                bmask = ((1 << bitc) - 1) << ((8-bitt) & 7);
                bmask_le = 0; /* ? */
            }
        }
    }

    if (bstart >= 0 && blen > 0 && (guint)bstart < len) {
        bend = bstart + blen;
    }
    if (astart >= 0 && alen > 0 && (guint)astart < len) {
        aend = astart + alen;
    }

    if (bend == -1 && aend != -1) {
        bstart = astart;
        bmask = 0x00;
        bend = aend;
        astart = aend = -1;
    }

    /* don't exceed the end of available data */
    if (aend != -1 && (guint)aend > len) aend = len;
    if (bend != -1 && (guint)bend > len) bend = len;

    /* save the information needed to redraw the text */
    /* should we save the fd & finfo pointers instead ?? */
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bstart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASK_KEY, GINT_TO_POINTER(bmask));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASKLE_KEY, GINT_TO_POINTER(bmask_le));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_START_KEY, GINT_TO_POINTER(astart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_END_KEY, GINT_TO_POINTER(aend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY,
                      GUINT_TO_POINTER((guint)fd->flags.encoding));

    /* stig: it should be done only for bitview... */
    if (recent.gui_bytes_view != BYTES_BITS)
        bmask = 0x00;
    packet_hex_update(bv, pd, len, bstart, bend, bmask, bmask_le, astart, aend, fd->flags.encoding);
}

void
packet_hex_editor_print(GtkWidget *bv, const guint8 *pd, frame_data *fd, int offset, int bitoffset, guint len)
{
    /* do the initial printing and save the information needed  */
    /* to redraw the display if preferences change.             */

    int bstart = offset, bend = (bstart != -1) ? offset+1 : -1;
    guint32 bmask=0; int bmask_le = 0;
    int astart = -1, aend = -1;

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        bmask = (bitoffset == 0) ? 0xf0 : (bitoffset == 4) ? 0x0f : 0xff;
        break;

    case BYTES_BITS:
        bmask = (1 << (7-bitoffset));
        break;

    default:
        g_assert_not_reached();
        break;
    }

    /* save the information needed to redraw the text */
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY, GINT_TO_POINTER(bstart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY, GINT_TO_POINTER(bend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASK_KEY, GINT_TO_POINTER(bmask));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_MASKLE_KEY, GINT_TO_POINTER(bmask_le));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_START_KEY, GINT_TO_POINTER(astart));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_APP_END_KEY, GINT_TO_POINTER(aend));
    g_object_set_data(G_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY,
                      GUINT_TO_POINTER((guint)fd->flags.encoding));

    packet_hex_update(bv, pd, len, bstart, bend, bmask, bmask_le, astart, aend, fd->flags.encoding);
}

/*
 * Redraw the text using the saved information; usually called if
 * the preferences have changed.
 */
void
packet_hex_reprint(GtkWidget *bv)
{
    int start, end, mask, mask_le, encoding;
    int astart, aend;
    const guint8 *data;
    guint len = 0;

    start = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_START_KEY));
    end = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_END_KEY));
    mask = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_MASK_KEY));
    mask_le = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_MASKLE_KEY));
    astart = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_APP_START_KEY));
    aend = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_APP_END_KEY));
    data = get_byte_view_data_and_length(bv, &len);
    g_assert(data != NULL);
    encoding = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(bv), E_BYTE_VIEW_ENCODE_KEY));

    /* stig: it should be done only for bitview... */
    if (recent.gui_bytes_view != BYTES_BITS)
        mask = 0x00;
    packet_hex_update(bv, data, len, start, end, mask, mask_le, astart, aend, encoding);
}

/* List of all protocol tree widgets, so we can globally set the selection
   mode and font of all of them. */
static GList *ptree_widgets;

/* Add a protocol tree widget to the list of protocol tree widgets. */
static void forget_ptree_widget(GtkWidget *ptreew, gpointer data);

static void
remember_ptree_widget(GtkWidget *ptreew)
{
    ptree_widgets = g_list_append(ptree_widgets, ptreew);

    /* Catch the "destroy" event on the widget, so that we remove it from
       the list when it's destroyed. */
    g_signal_connect(ptreew, "destroy", G_CALLBACK(forget_ptree_widget), NULL);
}

/* Remove a protocol tree widget from the list of protocol tree widgets. */
static void
forget_ptree_widget(GtkWidget *ptreew, gpointer data _U_)
{
    ptree_widgets = g_list_remove(ptree_widgets, ptreew);
}

/* Set the selection mode of a given packet tree window. */
static void
set_ptree_sel_browse(GtkWidget *tree, gboolean val)
{
    GtkTreeSelection *selection;

    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
    /* Yeah, GTK uses "browse" in the case where we do not, but oh well.
       I think "browse" in Wireshark makes more sense than "SINGLE" in
       GTK+ */
    if (val) {
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);
    }
    else {
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_BROWSE);
    }
}

static void
set_ptree_sel_browse_cb(gpointer data, gpointer user_data)
{
    set_ptree_sel_browse((GtkWidget *)data, *(gboolean *)user_data);
}

/* Set the selection mode of all packet tree windows. */
void
set_ptree_sel_browse_all(gboolean val)
{
    g_list_foreach(ptree_widgets, set_ptree_sel_browse_cb, &val);
}

static void
set_ptree_font_cb(gpointer data, gpointer user_data)
{
#if GTK_CHECK_VERSION(3,0,0)
    gtk_widget_override_font((GtkWidget *)data,
                           (PangoFontDescription *)user_data);
#else
    gtk_widget_modify_font((GtkWidget *)data,
                           (PangoFontDescription *)user_data);
#endif
}

void
set_ptree_font_all(PangoFontDescription *font)
{
    g_list_foreach(ptree_widgets, set_ptree_font_cb, font);
}


/*
 * Each expert_color_* level below should match the light gradient
 * colors in image/expert_indicators.svg.
 */
static gboolean colors_ok = FALSE;

GdkColor        expert_color_comment    = {0,  0x0000, 0xffff, 0x0000 };        /* Green */
GdkColor        expert_color_chat       = { 0, 0x8080, 0xb7b7, 0xf7f7 };        /* light blue */
GdkColor        expert_color_note       = { 0, 0xa0a0, 0xffff, 0xffff };        /* bright turquoise */
GdkColor        expert_color_warn       = { 0, 0xf7f7, 0xf2f2, 0x5353 };        /* yellow */
GdkColor        expert_color_error      = { 0, 0xffff, 0x5c5c, 0x5c5c };        /* pale red */
GdkColor        expert_color_foreground = { 0, 0x0000, 0x0000, 0x0000 };        /* black */
GdkColor        hidden_proto_item       = { 0, 0x4444, 0x4444, 0x4444 };        /* gray */

gchar *expert_color_comment_str;
gchar *expert_color_chat_str;
gchar *expert_color_note_str;
gchar *expert_color_warn_str;
gchar *expert_color_error_str;
gchar *expert_color_foreground_str;

void proto_draw_colors_init(void)
{
    if(colors_ok) {
        return;
    }
#if 0
    /* Allocating collor isn't necessary? */
    get_color(&expert_color_chat);
    get_color(&expert_color_note);
    get_color(&expert_color_warn);
    get_color(&expert_color_error);
    get_color(&expert_color_foreground);
#endif
    expert_color_comment_str = gdk_color_to_string(&expert_color_comment);
    expert_color_chat_str = gdk_color_to_string(&expert_color_chat);
    expert_color_note_str = gdk_color_to_string(&expert_color_note);
    expert_color_warn_str = gdk_color_to_string(&expert_color_warn);
    expert_color_error_str = gdk_color_to_string(&expert_color_error);
    expert_color_foreground_str = gdk_color_to_string(&expert_color_foreground);

#if 0
    get_color(&hidden_proto_item);
#endif
    colors_ok = TRUE;
}


static void
tree_cell_renderer(GtkTreeViewColumn *tree_column _U_, GtkCellRenderer *cell,
                   GtkTreeModel *tree_model, GtkTreeIter *iter,
                   gpointer data _U_)
{
    field_info   *fi;

    gtk_tree_model_get(tree_model, iter, 1, &fi, -1);

    if(!colors_ok) {
        proto_draw_colors_init();
    }

    /* for the various possible attributes, see:
     * http://developer.gnome.org/doc/API/2.0/gtk/GtkCellRendererText.html
     *
     * color definitions can be found at:
     * http://cvs.gnome.org/viewcvs/gtk+/gdk-pixbuf/io-xpm.c?rev=1.42
     * (a good color overview: http://www.computerhope.com/htmcolor.htm)
     *
     * some experiences:
     * background-gdk: doesn't seem to work (probably the GdkColor must be allocated)
     * weight/style: doesn't take any effect
     */

    /* for each field, we have to reset the renderer attributes */
    g_object_set (cell, "foreground-set", FALSE, NULL);

    g_object_set (cell, "background-set", FALSE, NULL);

    g_object_set (cell, "underline", PANGO_UNDERLINE_NONE, NULL);
    g_object_set (cell, "underline-set", FALSE, NULL);

    /*g_object_set (cell, "style", PANGO_STYLE_NORMAL, NULL);
    g_object_set (cell, "style-set", FALSE, NULL);*/

    /*g_object_set (cell, "weight", PANGO_WEIGHT_NORMAL, NULL);
    g_object_set (cell, "weight-set", FALSE, NULL);*/

    if(FI_GET_FLAG(fi, FI_GENERATED)) {
        /* we use "[...]" to mark generated items, no need to change things here */

        /* as some fonts don't support italic, don't use this */
        /*g_object_set (cell, "style", PANGO_STYLE_ITALIC, NULL);
        g_object_set (cell, "style-set", TRUE, NULL);
        */
        /*g_object_set (cell, "weight", PANGO_WEIGHT_BOLD, NULL);
        g_object_set (cell, "weight-set", TRUE, NULL);*/
    }

    if(FI_GET_FLAG(fi, FI_HIDDEN)) {
        g_object_set (cell, "foreground-gdk", &hidden_proto_item, NULL);
        g_object_set (cell, "foreground-set", TRUE, NULL);
    }

    if (fi && fi->hfinfo) {
        if(fi->hfinfo->type == FT_PROTOCOL) {
            g_object_set (cell, "background", "gray90", NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            g_object_set (cell, "foreground", "black", NULL);
            g_object_set (cell, "foreground-set", TRUE, NULL);
            /*g_object_set (cell, "weight", PANGO_WEIGHT_BOLD, NULL);
            g_object_set (cell, "weight-set", TRUE, NULL);*/
        }

        if((fi->hfinfo->type == FT_FRAMENUM) ||
           (FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type))) {
            render_as_url(cell);
        }
    }

    if(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        switch(FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
        case(PI_COMMENT):
            g_object_set (cell, "background-gdk", &expert_color_comment, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_CHAT):
            g_object_set (cell, "background-gdk", &expert_color_chat, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_NOTE):
            g_object_set (cell, "background-gdk", &expert_color_note, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_WARN):
            g_object_set (cell, "background-gdk", &expert_color_warn, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        case(PI_ERROR):
            g_object_set (cell, "background-gdk", &expert_color_error, NULL);
            g_object_set (cell, "background-set", TRUE, NULL);
            break;
        default:
            g_assert_not_reached();
        }
        g_object_set (cell, "foreground", "black", NULL);
        g_object_set (cell, "foreground-set", TRUE, NULL);
    }
}

GtkWidget *
proto_tree_view_new(e_prefs *prefs_p, GtkWidget **tree_view_p)
{
    GtkWidget *tv_scrollw, *tree_view;
    ProtoTreeModel *store;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    gint col_offset;

    /* Tree view */
    tv_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(tv_scrollw),
                                        GTK_SHADOW_IN);

    store = proto_tree_model_new(NULL, prefs.display_hidden_proto_items);
    tree_view = tree_view_new(GTK_TREE_MODEL(store));
    g_object_unref(G_OBJECT(store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree_view), FALSE);
    renderer = gtk_cell_renderer_text_new();
    g_object_set (renderer, "ypad", 0, NULL);
    col_offset = gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tree_view),
                                                             -1, "Name", renderer,
                                                             "text", 0, NULL);
    column = gtk_tree_view_get_column(GTK_TREE_VIEW(tree_view),
                                      col_offset - 1);
    gtk_tree_view_column_set_cell_data_func(column, renderer, tree_cell_renderer,
                                            NULL, NULL);

    gtk_tree_view_column_set_sizing(GTK_TREE_VIEW_COLUMN(column),
                                    GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    g_signal_connect(tree_view, "row-expanded", G_CALLBACK(expand_tree), NULL);
    g_signal_connect(tree_view, "row-collapsed", G_CALLBACK(collapse_tree), NULL);
    gtk_container_add( GTK_CONTAINER(tv_scrollw), tree_view );
    set_ptree_sel_browse(tree_view, prefs_p->gui_ptree_sel_browse);
#if GTK_CHECK_VERSION(3,0,0)
    gtk_widget_override_font(tree_view, user_font_get_regular());
#else
    gtk_widget_modify_font(tree_view, user_font_get_regular());
#endif
    remember_ptree_widget(tree_view);

    *tree_view_p = tree_view;

    return tv_scrollw;
}

void
expand_all_tree(proto_tree *protocol_tree _U_, GtkWidget *tree_view)
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_is_expanded[i] = TRUE;
    }
    gtk_tree_view_expand_all(GTK_TREE_VIEW(tree_view));
}

void
collapse_all_tree(proto_tree *protocol_tree _U_, GtkWidget *tree_view)
{
    int i;
    for(i=0; i < num_tree_types; i++) {
        tree_is_expanded[i] = FALSE;
    }
    gtk_tree_view_collapse_all(GTK_TREE_VIEW(tree_view));
}

static void
tree_view_follow_link(field_info   *fi)
{
    gchar *url;

    if(fi->hfinfo->type == FT_FRAMENUM) {
        cf_goto_frame(&cfile, fi->value.value.uinteger);
    }
    if(FI_GET_FLAG(fi, FI_URL) && IS_FT_STRING(fi->hfinfo->type)) {
        url = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, NULL);
        if(url){
            browser_open_url(url);
            g_free(url);
        }
    }
}


/* If the user selected a position in the tree view, try to find
 * the item in the GUI proto_tree that corresponds to that byte, and
 * select it. */
gboolean
tree_view_select(GtkWidget *widget, GdkEventButton *event)
{
    GtkTreeSelection    *sel;
    GtkTreePath         *path;

    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
                                      (gint) (((GdkEventButton *)event)->x),
                                      (gint) (((GdkEventButton *)event)->y),
                                      &path, NULL, NULL, NULL))
    {
        sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(widget));

        /* if that's a doubleclick, try to follow the link */
        if(event->type == GDK_2BUTTON_PRESS) {
            GtkTreeModel *model;
            GtkTreeIter iter;
            field_info   *fi;

            if(gtk_tree_selection_get_selected (sel, &model, &iter)) {
                gtk_tree_model_get(model, &iter, 1, &fi, -1);
                tree_view_follow_link(fi);
            }
        }
        else if (((GdkEventButton *)event)->button != 1) {
            /* if button == 1 gtk_tree_selection_select_path is already (or will be) called by the widget */
            gtk_tree_selection_select_path(sel, path);
        }
    } else {
        return FALSE;
    }
    return TRUE;
}

static gboolean
expand_finfos(GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
    GtkTreeView *tree_view = (GtkTreeView *) data;
    field_info *fi;

    if (!gtk_tree_model_iter_has_child(model, iter))
        return FALSE;

    gtk_tree_model_get(model, iter, 1, &fi, -1);

    g_assert(fi->tree_type >= 0 && fi->tree_type < num_tree_types);

    if (tree_is_expanded[fi->tree_type])
        gtk_tree_view_expand_to_path(tree_view, path);
    else
        gtk_tree_view_collapse_row(tree_view, path);
    return FALSE;
}

void 
proto_tree_draw_resolve(proto_tree *protocol_tree, GtkWidget *tree_view, const e_addr_resolve *resolv)
{
    ProtoTreeModel *model;

    model = proto_tree_model_new(protocol_tree, prefs.display_hidden_proto_items);
    if (resolv)
        proto_tree_model_force_resolv(PROTO_TREE_MODEL(model), resolv);
    gtk_tree_view_set_model(GTK_TREE_VIEW(tree_view), GTK_TREE_MODEL(model));

    gtk_tree_model_foreach(GTK_TREE_MODEL(model), expand_finfos, GTK_TREE_VIEW(tree_view));
    g_object_unref(G_OBJECT(model));
}

/* fill the whole protocol tree with the string values */
void
proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view)
{
    proto_tree_draw_resolve(protocol_tree, tree_view, NULL);
}

void
select_bytes_view (GtkWidget *w _U_, gpointer data _U_, gint view)
{
    if (recent.gui_bytes_view != view) {
        recent.gui_bytes_view = view;
        redraw_packet_bytes_all();
    }
}
