/* fileset_dialog.cpp
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

#include <glib.h>

#include "fileset_dialog.h"

#include "fileset.h"

/* this file is a part of the current file set, add it to the dialog */
void
fileset_dlg_add_file(fileset_entry *entry) {
//    char *created;
//    char *modified;
//    char *size;
//    struct tm *local;
//    GtkWidget     *fs_lb;
//    GtkWidget     *fs_rb;
//    gchar *title;


    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: fileset_dlg_add_file: %s", entry->name);
//    if (fs_w == NULL) {
//        return;
//    }

//    created = fileset_dlg_name2date_dup(entry->name);
//    if(!created) {
//        /* if this file doesn't follow the file set pattern, */
//        /* use the creation time of that file */
//        local = localtime(&entry->ctime);
//        created = g_strdup_printf("%04u.%02u.%02u %02u:%02u:%02u",
//                                  local->tm_year+1900, local->tm_mon+1, local->tm_mday,
//                                  local->tm_hour, local->tm_min, local->tm_sec);
//    }

//    local = localtime(&entry->mtime);
//    modified = g_strdup_printf("%04u.%02u.%02u %02u:%02u:%02u",
//                               local->tm_year+1900, local->tm_mon+1, local->tm_mday,
//                               local->tm_hour, local->tm_min, local->tm_sec);
//    size = g_strdup_printf("%" G_GINT64_MODIFIER "d Bytes", entry->size);

//    fs_rb = gtk_radio_button_new_with_label_from_widget(
//            fs_first_rb ? GTK_RADIO_BUTTON(fs_first_rb) : NULL, entry->name);
//    if(row == 1) {
//        fs_first_rb = fs_rb;
//    }
//    if(entry->current) {
//        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (fs_rb), entry->current);
//    }
//    gtk_tooltips_set_tip(tooltips, fs_rb, "Open this capture file", NULL);
//    gtk_table_attach_defaults(GTK_TABLE(fs_tb), fs_rb, 0, 1, row, row+1);
//    g_signal_connect(fs_rb, "toggled", G_CALLBACK(fs_rb_cb), entry);
//    gtk_widget_show(fs_rb);

//    fs_lb = gtk_label_new(created);
//    gtk_table_attach_defaults(GTK_TABLE(fs_tb), fs_lb, 1, 2, row, row+1);
//    gtk_widget_set_sensitive(fs_lb, entry->current);
//    gtk_widget_show(fs_lb);

//    fs_lb = gtk_label_new(modified);
//    gtk_table_attach_defaults(GTK_TABLE(fs_tb), fs_lb, 2, 3, row, row+1);
//    gtk_widget_set_sensitive(fs_lb, entry->current);
//    gtk_widget_show(fs_lb);

//    fs_lb = gtk_label_new(size);
//    gtk_table_attach_defaults(GTK_TABLE(fs_tb), fs_lb, 3, 4, row, row+1);
//    gtk_widget_set_sensitive(fs_lb, entry->current);
//    gtk_widget_show(fs_lb);

//    title = g_strdup_printf("Wireshark: %u File%s in Set", row, plurality(row, "", "s"));
//    gtk_window_set_title(GTK_WINDOW(fs_w), title);
//    g_free(title);

//    title = g_strdup_printf("... in directory: %s", fileset_get_dirname());
//    gtk_label_set_text(GTK_LABEL(fs_dir_lb), title);
//    g_free(title);

//    gtk_widget_show_all(fs_tb);

//    /* resize the table until we use 18 rows (fits well into 800*600), if it's bigger use a scrollbar */
//    /* XXX - I didn't found a way to automatically shrink the table size again */
//    if(row <= 18) {
//        GtkRequisition requisition;

//        gtk_widget_size_request(fs_tb, &requisition);
//        gtk_widget_set_size_request(fs_sw, -1, requisition.height);
//        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(fs_sw), GTK_POLICY_NEVER, GTK_POLICY_NEVER);
//    }

//    if(row == 18) {
//        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(fs_sw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
//    }

//    row++;

//    g_free(created);
//    g_free(modified);
//    g_free(size);
}

/* a new capture file was opened, browse the dir and look for files matching the given file set */
void
fileset_file_opened(const char *fname) {
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: fileset_file_opened: %s", fname);
//    fileset_add_dir(fname);
//    if(fs_w) {
//        window_present(fs_w);
//    }

//    /* update the menu */
//    set_menus_for_file_set(TRUE /* file_set */,
//                           fileset_get_previous() != NULL, fileset_get_next() != NULL );
}


/* the capture file was closed */
void
fileset_file_closed(void)
{
    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: fileset_file_closed");
//    if(fs_w) {
//        /* reinit the table, title and alike */
//        g_object_ref(G_OBJECT(fs_tb_vb));
//        gtk_widget_destroy(fs_tb);
//        fileset_delete();
//        fileset_init_table(fs_tb_vb);
//        window_present(fs_w);
//    } else {
//        fileset_delete();
//    }

//    /* update the menu */
//    set_menus_for_file_set(FALSE /* file_set */,
//                           fileset_get_previous() != NULL,
//                           fileset_get_next() != NULL );
}

FilesetDialog::FilesetDialog(QWidget *parent) :
    QDialog(parent)
{
}
