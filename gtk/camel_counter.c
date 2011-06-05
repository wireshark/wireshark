/* camel_counter.c
 * camel message counter for Wireshark
 * Copyright 2006 Florent Drouin (based on h225_counter.c from Lars Roland)
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <gtk/gtk.h>

#include <epan/epan.h>
#include <epan/packet_info.h>
#include <epan/value_string.h>
#include <epan/tap.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/camel-persistentdata.h>

#include "../stat_menu.h"
#include "../timestats.h"
#include "../simple_dialog.h"

#include "gtk/main.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/gui_stat_util.h"
#include "gtk/tap_param_dlg.h"


static void gtk_camelcounter_reset(void *phs);
static int gtk_camelcounter_packet(void *phs,
				   packet_info *pinfo _U_,
				   epan_dissect_t *edt _U_,
				   const void *phi);
static void gtk_camelcounter_draw(void *phs);
static void win_destroy_cb(GtkWindow *win _U_, gpointer data);
static void gtk_camelcounter_init(const char *optarg, void *userdata _U_);
void register_tap_listener_gtk_camelcounter(void);

/* following values represent the size of their valuestring arrays */

struct camelcounter_t {
  GtkWidget *win;
  GtkWidget *vbox;
  char *filter;
  GtkWidget *scrolled_window;
  GtkTreeView *table;
  guint32 camel_msg[camel_MAX_NUM_OPR_CODES];
};

static void gtk_camelcounter_reset(void *phs)
{
  struct camelcounter_t * p_counter= ( struct camelcounter_t *) phs;
  int i;

  /* Erase Message Type count */
  for(i=0;i<camel_MAX_NUM_OPR_CODES;i++) {
    p_counter->camel_msg[i]=0;
  }
}


/*
 * If there is a valid camel operation, increase the value in the array of counter
 */
static int gtk_camelcounter_packet(void *phs,
				   packet_info *pinfo _U_,
				   epan_dissect_t *edt _U_,
				   const void *phi)
{
  struct camelcounter_t * p_counter =(struct camelcounter_t *)phs;
  const struct camelsrt_info_t * pi=phi;
  if (pi->opcode != 255)
    p_counter->camel_msg[pi->opcode]++;

  return 1;
}

static void gtk_camelcounter_draw(void *phs)
{
  struct camelcounter_t *p_counter=(struct camelcounter_t *)phs;
  int i;
  char str[256];
  GtkListStore *store;
  GtkTreeIter iter;

  /* Now print Message and Reason Counter Table */
  /* clear list before printing */
  store = GTK_LIST_STORE(gtk_tree_view_get_model(p_counter->table));
  gtk_list_store_clear(store);

  for(i=0;i<camel_MAX_NUM_OPR_CODES;i++) {
    /* Message counter */
    if(p_counter->camel_msg[i]!=0) {
      g_snprintf(str, 256, "Request %s", val_to_str(i,camel_opr_code_strings,"Unknown message "));

      gtk_list_store_append(store, &iter);
      gtk_list_store_set(store, &iter,
				   0, str,
				   1, p_counter->camel_msg[i],
				   -1);
    }
  } /* Message Type */
}

static void win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
  struct camelcounter_t *hs=(struct camelcounter_t *)data;

  protect_thread_critical_region();
  remove_tap_listener(hs);
  unprotect_thread_critical_region();

  if(hs->filter){
    g_free(hs->filter);
    hs->filter=NULL;
  }
  g_free(hs);
}

static const stat_column titles[]={
  {G_TYPE_STRING, LEFT, "Message Type or Reason"},
  {G_TYPE_UINT, RIGHT, "Count" }
};

static void gtk_camelcounter_init(const char *optarg, void *userdata _U_)
{
  struct camelcounter_t *p_camelcounter;
  const char *filter=NULL;
  GString *error_string;
  GtkWidget *bbox;
  GtkWidget *close_bt;

  if(strncmp(optarg,"camel,counter,",14) == 0){
    filter=optarg+14;
  } else {
    filter=NULL;
  }

  p_camelcounter=g_malloc(sizeof(struct camelcounter_t));
  p_camelcounter->filter=g_strdup(filter);

  gtk_camelcounter_reset(p_camelcounter);

  /* transient_for top_level */
  p_camelcounter->win=dlg_window_new("Wireshark: CAMEL counters");
  gtk_window_set_destroy_with_parent (GTK_WINDOW(p_camelcounter->win), TRUE);

	gtk_window_set_default_size(GTK_WINDOW(p_camelcounter->win), 500, 300);

  p_camelcounter->vbox=gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(p_camelcounter->vbox), 12);

  init_main_stat_window(p_camelcounter->win, p_camelcounter->vbox, "CAMEL Messages Counters", filter);

  /* init a scrolled window*/
  p_camelcounter->scrolled_window = scrolled_window_new(NULL, NULL);

  p_camelcounter->table = create_stat_table(p_camelcounter->scrolled_window, p_camelcounter->vbox, 2, titles);

  error_string=register_tap_listener("CAMEL", p_camelcounter, filter, 0,
				       gtk_camelcounter_reset,
				       gtk_camelcounter_packet,
				       gtk_camelcounter_draw);

  if(error_string){
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
    g_string_free(error_string, TRUE);
    g_free(p_camelcounter);
    return;
  }

  /* Button row. */
  bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
  gtk_box_pack_end(GTK_BOX(p_camelcounter->vbox), bbox, FALSE, FALSE, 0);

  close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
  window_set_cancel_button(p_camelcounter->win, close_bt, window_cancel_button_cb);

  g_signal_connect(p_camelcounter->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
  g_signal_connect(p_camelcounter->win, "destroy", G_CALLBACK(win_destroy_cb), p_camelcounter);

  gtk_widget_show_all(p_camelcounter->win);
  window_present(p_camelcounter->win);

  cf_retap_packets(&cfile);
  gdk_window_raise(p_camelcounter->win->window);
}

static tap_param camel_counter_params[] = {
  { PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg camel_counter_dlg = {
  "CAMEL Messages and Response Status",
  "camel,counter",
  gtk_camelcounter_init,
  -1,
  G_N_ELEMENTS(camel_counter_params),
  camel_counter_params
};

void  /* Next line mandatory */
register_tap_listener_gtk_camelcounter(void)
{
  register_dfilter_stat(&camel_counter_dlg, "_GSM/CAMEL",
  			REGISTER_STAT_GROUP_TELEPHONY);

}
