/* text_page_utils.c
 *  Construct a simple text page widget from a file.
 *
 * Ulf Lamping
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
#include <string.h>
#include <errno.h>

#include <gtk/gtk.h>


#include "ui/simple_dialog.h"
#include <wsutil/file_util.h>

#include "ui/gtk/text_page_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/font_utils.h"


#define TEXT_KEY        "txt_key"

static void text_page_insert(GtkWidget *page, const char *buffer, int nchars);
static void text_page_set_text(GtkWidget *page, const char *absolute_path);


/*
 * Construct a simple text page widget from a file.
 */
GtkWidget * text_page_new(const char *absolute_path)
{
    GtkWidget *page_vb, *txt_scrollw, *txt;

    page_vb =ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(page_vb), 1);
    txt_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
                                   GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(page_vb), txt_scrollw, TRUE, TRUE, 0);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    txt = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(txt), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(txt), GTK_WRAP_WORD);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(txt), FALSE);
    /* XXX: there seems to be no way to add a small border *around* the whole text,
     * so the text will be "bump" against the edges.
     * the following is only working for left and right edges,
     * there is no such thing for top and bottom :-( */
    /* gtk_text_view_set_left_margin(GTK_TEXT_VIEW(txt), 3); */
    /* gtk_text_view_set_right_margin(GTK_TEXT_VIEW(txt), 3); */

    g_object_set_data(G_OBJECT(page_vb), TEXT_KEY, txt);

    text_page_set_text(page_vb, absolute_path);
    gtk_container_add(GTK_CONTAINER(txt_scrollw), txt);
    gtk_widget_show(txt_scrollw);
    gtk_widget_show(txt);

    return page_vb;
}


/*
 * Insert some text to a text page.
 */
static void text_page_insert(GtkWidget *page, const char *buffer, int nchars)
{
    GtkWidget *txt = (GtkWidget *)g_object_get_data(G_OBJECT(page), TEXT_KEY);

    GtkTextBuffer *buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt));
    GtkTextIter    iter;

    gtk_text_buffer_get_end_iter(buf, &iter);
#if GTK_CHECK_VERSION(3,0,0)
    gtk_widget_override_font(GTK_WIDGET(txt), user_font_get_regular());
#else
    gtk_widget_modify_font(GTK_WIDGET(txt), user_font_get_regular());
#endif
    if (!g_utf8_validate(buffer, -1, NULL))
        printf("Invalid utf8 encoding: %s\n", buffer);
    gtk_text_buffer_insert(buf, &iter, buffer, nchars);
}


/*
 * Put the complete text file into a text page.
 */
static void text_page_set_text(GtkWidget *page, const char *absolute_path)
{
    FILE *text_file;
    char line[4096+1];  /* XXX - size? */

    text_file = ws_fopen(absolute_path, "r");
    if (text_file != NULL) {
        while (fgets(line, sizeof line, text_file) != NULL) {
            text_page_insert(page, line, (int) strlen(line));
        }
        if(ferror(text_file)) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Error reading file \"%s\": %s",
                          absolute_path, g_strerror(errno));
        }
        fclose(text_file);
    } else {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not open file \"%s\": %s",
                      absolute_path, g_strerror(errno));
    }
}


/**
 * Clear the text from the text page.
 */
static void text_page_clear(GtkWidget *page)
{
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_object_get_data(G_OBJECT(page), TEXT_KEY)));

    gtk_text_buffer_set_text(buf, "", 0);
}


/**
 * Redraw a single text page, e.g. to use a new font.
 */
void text_page_redraw(GtkWidget *page, const char *absolute_path)
{
    text_page_clear(page);
    text_page_set_text(page, absolute_path);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
