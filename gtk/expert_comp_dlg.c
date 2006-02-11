/* expert_comp_dlg.c
 * expert_comp_dlg   2005 Greg Morris
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
#include <gtk/gtk.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include "../register.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "../globals.h"
#include "expert_comp_table.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <epan/stat_cmd_args.h>

/* used to keep track of the statistics for an entire program interface */
typedef struct _expert_comp_dlg_t {
    GtkWidget *win;
    GtkWidget *chat_label;
    GtkWidget *note_label;
    GtkWidget *warn_label;
    GtkWidget *error_label;
    error_equiv_table chat_table;
    error_equiv_table note_table;
    error_equiv_table warn_table;
    error_equiv_table error_table;
} expert_comp_dlg_t;

static void
error_set_title(expert_comp_dlg_t *ss)
{
    char *title;

    title = g_strdup_printf("Expert Info Composite: %s",
        cf_get_display_name(&cfile));
    gtk_window_set_title(GTK_WINDOW(ss->win), title);
    g_free(title);
}

static void
error_reset(void *pss)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)pss;

    reset_error_table_data(&ss->error_table);
    gtk_label_set_text( GTK_LABEL(ss->error_label), g_strdup_printf("Errors: %u", ss->error_table.num_procs));
    reset_error_table_data(&ss->warn_table);
    gtk_label_set_text( GTK_LABEL(ss->warn_label), g_strdup_printf("Warnings: %u", ss->warn_table.num_procs));
    reset_error_table_data(&ss->note_table);
    gtk_label_set_text( GTK_LABEL(ss->note_label), g_strdup_printf("Notes: %u", ss->note_table.num_procs));
    reset_error_table_data(&ss->chat_table);
    gtk_label_set_text( GTK_LABEL(ss->chat_label), g_strdup_printf("Chats: %u", ss->chat_table.num_procs));
    error_set_title(ss);
}

static int
error_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)pss;
    const expert_info_t *error_pkt=prv;

    /* if return value is 0 then no error */
    if(error_pkt==NULL){
        return 0;
    }
    switch (error_pkt->severity) {
    case PI_ERROR:
        init_error_table_row(&ss->error_table, error_pkt);
        add_error_table_data(&ss->error_table, error_pkt);
        gtk_label_set_text( GTK_LABEL(ss->error_label), g_strdup_printf("Errors: %u", ss->error_table.num_procs));
        break;
    case PI_WARN:
        init_error_table_row(&ss->warn_table, error_pkt);
        add_error_table_data(&ss->warn_table, error_pkt);
        gtk_label_set_text( GTK_LABEL(ss->warn_label), g_strdup_printf("Warnings: %u", ss->warn_table.num_procs));
        break;
    case PI_NOTE:
        init_error_table_row(&ss->note_table, error_pkt);
        add_error_table_data(&ss->note_table, error_pkt);
        gtk_label_set_text( GTK_LABEL(ss->note_label), g_strdup_printf("Notes: %u", ss->note_table.num_procs));
        break;
    case PI_CHAT:
        init_error_table_row(&ss->chat_table, error_pkt);
        add_error_table_data(&ss->chat_table, error_pkt);
        gtk_label_set_text( GTK_LABEL(ss->chat_label), g_strdup_printf("Chats: %u", ss->chat_table.num_procs));
        break;
    default:
        return 0; /* Don't draw */
    }
    return 1; /* Draw */
}



static void
error_draw(void *pss)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)pss;

    draw_error_table_data(&ss->error_table);
    draw_error_table_data(&ss->warn_table);
    draw_error_table_data(&ss->note_table);
    draw_error_table_data(&ss->chat_table);
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    expert_comp_dlg_t *ss=(expert_comp_dlg_t *)data;

    protect_thread_critical_region();
    remove_tap_listener(ss);
    unprotect_thread_critical_region();

    free_error_table_data(&ss->error_table);
    free_error_table_data(&ss->warn_table);
    free_error_table_data(&ss->note_table);
    free_error_table_data(&ss->chat_table);
    g_free(ss);
}

static void
expert_comp_init(const char *optarg, void* userdata _U_)
{
    expert_comp_dlg_t *ss;
    const char *filter=NULL;
    GString *error_string;
    GtkWidget *temp_page;
    GtkWidget *main_nb;
    GtkWidget *vbox;
    GtkWidget *bbox;
    GtkWidget *close_bt;
    
    ss=g_malloc(sizeof(expert_comp_dlg_t));

    ss->win=window_new(GTK_WINDOW_TOPLEVEL, "err");
    gtk_window_set_default_size(GTK_WINDOW(ss->win), 700, 300);

    error_set_title(ss);

    vbox=gtk_vbox_new(FALSE, 3);
    gtk_container_add(GTK_CONTAINER(ss->win), vbox);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    main_nb = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), main_nb, TRUE, TRUE, 0);
    /* Errors */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->error_label = gtk_label_new("Errors: 0");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, ss->error_label);

    /* We must display TOP LEVEL Widget before calling init_srt_table() */
    gtk_widget_show_all(ss->win);
    init_error_table(&ss->error_table, 0, temp_page);
    /* Warnings */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->warn_label = gtk_label_new("Warnings: 0");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, ss->warn_label);
    init_error_table(&ss->warn_table, 0, temp_page);
    /* Notes */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->note_label = gtk_label_new("Notes: 0");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, ss->note_label);
    init_error_table(&ss->note_table, 0, temp_page);
    /* Chat */
    temp_page = gtk_vbox_new(FALSE, 6);
    ss->chat_label = gtk_label_new("Chats: 0");
    gtk_notebook_append_page(GTK_NOTEBOOK(main_nb), temp_page, ss->chat_label);
    init_error_table(&ss->chat_table, 0, temp_page);

    /* Register the tap listener */
    error_string=register_tap_listener("expert", ss, filter, error_reset, error_packet, error_draw);
    if(error_string){
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
        g_string_free(error_string, TRUE);
        g_free(ss);
        return;
    }

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(ss->win, close_bt, window_cancel_button_cb);

    SIGNAL_CONNECT(ss->win, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(ss->win, "destroy", win_destroy_cb, ss);

    gtk_widget_show_all(ss->win);
    window_present(ss->win);
    
    /* We currently cannot just retap the packets because we will not be able
     * to acquire the fvalue data. The expert items would already have been
     * cleared and we will not be able to perform any filtering of data.
     * So we force a redissect so that all data is valid.
     * If someone can figure out why the expert_item value is null when 
     * performing a retap then this call to 
     * cf_redissect_packets(&cfile);
     * can be changed to...
     * cf_retap_packets(&cfile, NULL);
     * which would be much faster.
     */
    cf_redissect_packets(&cfile);
}

static void 
expert_comp_dlg_cb(GtkWidget *w _U_, gpointer d _U_)
{
    expert_comp_init("", NULL);
}

void
register_tap_listener_expert_comp(void)
{
    register_stat_cmd_arg("expert_comp", expert_comp_init,NULL);
    register_stat_menu_item("Expert Info _Composite", REGISTER_ANALYZE_GROUP_NONE,
        expert_comp_dlg_cb, NULL, NULL, NULL);
}
