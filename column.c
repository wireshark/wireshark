/* column.c
 * Routines for handling column preferences
 *
 * $Id: column.c,v 1.6 1998/12/22 07:07:09 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include <sys/types.h>
#endif

#include <gtk/gtk.h>

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ethereal.h"
#include "prefs.h"
#include "column.h"

extern e_prefs prefs;

static GtkWidget *column_l, *chg_bt, *del_bt, *title_te, *fmt_m, *up_bt,
                 *dn_bt;
static gint       cur_fmt;

#define E_COL_NAME_KEY "column_name"
#define E_COL_LBL_KEY  "column_label"
#define E_COL_CM_KEY   "in_col_cancel_mode"

static gchar *col_format_to_string(gint);
static gchar *col_format_desc(gint);
static gint   get_column_format_from_str(gchar *str);
static void   column_sel_list_cb(GtkWidget *, gpointer);
static void   column_sel_new_cb(GtkWidget *, gpointer);
static void   column_sel_chg_cb(GtkWidget *, gpointer);
static void   column_sel_del_cb(GtkWidget *, gpointer);
static void   column_sel_arrow_cb(GtkWidget *, gpointer);
static void   column_set_fmt_cb(GtkWidget *, gpointer);

/* Given a format number (as defined in ethereal.h), returns its equivalent
   string */
static gchar *
col_format_to_string(gint fmt) {
  gchar *slist[] = { "%m", "%t", "%t", "%t", "%s", "%rs", "%us", "%hs",
                     "%rhs", "%uhs", "%ns", "%rns", "%uns", "%d", "%rd",
                     "%ud", "%hd", "%rhd", "%uhd", "%nd", "%rnd", "%und",
                     "%S", "%rS", "%uS", "%D", "%rD", "%uD", "%p", "%i" };
  
  if (fmt < 0 || fmt > NUM_COL_FMTS)
    return NULL;
  
  return(slist[fmt]);
}

/* Given a format number (as defined in ethereal.h), returns its
  description */
static gchar *
col_format_desc(gint fmt) {
  gchar *dlist[] = { "Number", "Relative time", "Absolute time",
                     "Delta time", "Source address", "Src addr (resolved)",
                     "Src addr (unresolved)", "Hardware src addr",
                     "Hw src addr (resolved)", "Hw src addr (unresolved)",
                     "Network src addr", "Net scr addr (resolved)",
                     "Net src addr (unresolved)", "Destination address",
                     "Dest addr (resolved)", "Dest addr (unresolved)",
                     "Hardware dest addr", "Hw dest addr (resolved)",
                     "Hw dest addr (unresolved)", "Network dest addr",
                     "Net dest addr (resolved)", "Net dest addr (unresolved)",
                     "Source port", "Src port (resolved)",
                     "Src port (unresolved)", "Destination port",
                     "Dest port (resolved)", "Dest port (unresolved)",
                     "Protocol", "Information" };
  
  if (fmt < 0 || fmt > NUM_COL_FMTS)
    return NULL;
  
  return(dlist[fmt]);
}

/* Marks each array element true if it can be substituted for the given
   column format */
void
get_column_format_matches(gboolean *fmt_list, gint format) {
  int i;
  
  for (i = 0; i < NUM_COL_FMTS; i++) {
    /* Get the obvious: the format itself */
    if (i == format)
      fmt_list[i] = TRUE;
    /* Get any formats lower down on the chain */
    switch (format) {
      case COL_DEF_SRC:
        fmt_list[COL_RES_DL_SRC] = TRUE;
        fmt_list[COL_RES_NET_SRC] = TRUE;
        break;
      case COL_RES_SRC:
        fmt_list[COL_RES_DL_SRC] = TRUE;
        fmt_list[COL_RES_NET_SRC] = TRUE;
        break;
      case COL_UNRES_SRC:
        fmt_list[COL_UNRES_DL_SRC] = TRUE;
        fmt_list[COL_UNRES_NET_SRC] = TRUE;
        break;
      case COL_DEF_DST:
        fmt_list[COL_RES_DL_DST] = TRUE;
        fmt_list[COL_RES_NET_DST] = TRUE;
        break;
      case COL_RES_DST:
        fmt_list[COL_RES_DL_DST] = TRUE;
        fmt_list[COL_RES_NET_DST] = TRUE;
        break;
      case COL_UNRES_DST:
        fmt_list[COL_UNRES_DL_DST] = TRUE;
        fmt_list[COL_UNRES_NET_DST] = TRUE;
        break;
      case COL_DEF_DL_SRC:
        fmt_list[COL_RES_DL_SRC] = TRUE;
        break;
      case COL_DEF_DL_DST:
        fmt_list[COL_RES_DL_DST] = TRUE;
        break;
      case COL_DEF_NET_SRC:
        fmt_list[COL_RES_NET_SRC] = TRUE;
        break;
      case COL_DEF_NET_DST:
        fmt_list[COL_RES_NET_DST] = TRUE;
        break;
      case COL_DEF_SRC_PORT:
        fmt_list[COL_RES_SRC_PORT] = TRUE;
        break;
      case COL_DEF_DST_PORT:
        fmt_list[COL_RES_DST_PORT] = TRUE;
        break;
      default:
        break;
    }
  }
}

/* Returns the longest possible width for a particular column type */
/* XXX - this is somewhat fragile; we should probably generate */
/* the summary lines for all the packets first, and compute the */
/* maximum column width as the maximum string width of all the */
/* values in that column. */
gint
get_column_width(gint format, GdkFont *font) {
  switch (format) {
    case COL_NUMBER:
      return (gdk_string_width(font, "0") * 7);
      break;
    case COL_ABS_TIME:
      return (gdk_string_width(font, "00:00:00.000000"));
      break;
    case COL_REL_TIME:
    case COL_DELTA_TIME:
      return (gdk_string_width(font, "0000.000000"));
      break;
    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      return (gdk_string_width(font, "00:00:00:00:00:00"));
      break;
    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:
    case COL_UNRES_SRC_PORT:
    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:
    case COL_UNRES_DST_PORT:
      return (gdk_string_width(font, "0") * 6);
      break;
    case COL_PROTOCOL:
      return (gdk_string_width(font, "NBNS (UDP)"));
      break;
    default: /* COL_INFO */
      return (gdk_string_width(font, "Source port: kerberos-master  "
        "Destination port: kerberos-master"));
      break;
  }
}
    
#define RES_DEF  0
#define RES_DO   1
#define RES_DONT 2

#define ADDR_DEF 0
#define ADDR_DL  3
#define ADDR_NET 6

gint
get_column_format(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;
  
  cfmt = (fmt_data *) clp->data;
  
  return(get_column_format_from_str(cfmt->fmt));
}

static gint
get_column_format_from_str(gchar *str) {
  gchar *cptr = str;
  gint      res_off = RES_DEF, addr_off = ADDR_DEF;

  /* To do: Make this parse %-formatted strings "for real" */
  while (*cptr != '\0') {
    switch (*cptr) {
      case 't':  /* To do: fix for absolute and delta */
        return COL_REL_TIME;
        break;
      case 'm':
        return COL_NUMBER;
        break;
      case 's':
        return COL_DEF_SRC + res_off + addr_off;
        break;
      case 'd':
        return COL_DEF_DST + res_off + addr_off;
        break;
      case 'S':
        return COL_DEF_SRC_PORT + res_off;
        break;
      case 'D':
        return COL_DEF_DST_PORT + res_off;
        break;
      case 'p':
        return COL_PROTOCOL;
        break;
      case 'i':
        return COL_INFO;
        break;
      case 'r':
        res_off = RES_DO;
        break;
      case 'u':
        res_off = RES_DONT;
        break;
      case 'h':
        addr_off = ADDR_DL;
        break;
      case 'n':
        addr_off = ADDR_NET;
        break;
    }
    cptr++;
  }
  return COL_NUMBER;
}

gchar *
get_column_title(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;
  
  cfmt = (fmt_data *) clp->data;

  return(cfmt->title);  
}

#define MAX_FMT_PREF_LEN      1024
#define MAX_FMT_PREF_LINE_LEN   60
gchar *
col_format_to_pref_str() {
  static gchar  pref_str[MAX_FMT_PREF_LEN] = "";
  GList        *clp = g_list_first(prefs.col_list);
  fmt_data     *cfmt;
  int           cur_pos = 0, cur_len = 0, fmt_len;
  
  while (clp) {
    cfmt = (fmt_data *) clp->data;
    
    fmt_len = strlen(cfmt->title) + 4;
    if ((fmt_len + cur_len) < (MAX_FMT_PREF_LEN - 1)) {
      if ((fmt_len + cur_pos) > MAX_FMT_PREF_LINE_LEN) {
        cur_len--;
        cur_pos = 0;
        pref_str[cur_len] = '\n'; cur_len++;
        pref_str[cur_len] = '\t'; cur_len++;
      }
      sprintf(&pref_str[cur_len], "\"%s\", ", cfmt->title);
      cur_len += fmt_len;
      cur_pos += fmt_len;
    }

    fmt_len = strlen(cfmt->fmt) + 4;
    if ((fmt_len + cur_len) < (MAX_FMT_PREF_LEN - 1)) {
      if ((fmt_len + cur_pos) > MAX_FMT_PREF_LINE_LEN) {
        cur_len--;
        cur_pos = 0;
        pref_str[cur_len] = '\n'; cur_len++;
        pref_str[cur_len] = '\t'; cur_len++;
      }
      sprintf(&pref_str[cur_len], "\"%s\", ", cfmt->fmt);
      cur_len += fmt_len;
      cur_pos += fmt_len;
    }
    
    clp = clp->next;
  }
  
  if (cur_len > 2)
    pref_str[cur_len - 2] = '\0';

  return(pref_str);
}    

/* Create and display the column selection widgets. */
/* Called when the 'Columns' preference notebook page is selected. */
GtkWidget *
column_prefs_show() {
  GtkWidget   *main_vb, *top_hb, *list_bb, *new_bt, *column_sc, *nl_item,
              *nl_lb, *tb, *lb, *menu, *mitem, *arrow_hb;
  GList       *clp = NULL;
  fmt_data    *cfmt;
  gint         i;

  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_widget_show(main_vb);
  gtk_object_set_data(GTK_OBJECT(main_vb), E_COL_CM_KEY, (gpointer)FALSE);
  
  /* Top row: Column list and buttons */
  top_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(main_vb), top_hb);
  gtk_widget_show(top_hb);
  
  list_bb = gtk_vbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (list_bb), GTK_BUTTONBOX_START);
  gtk_container_add(GTK_CONTAINER(top_hb), list_bb);
  gtk_widget_show(list_bb);

  new_bt = gtk_button_new_with_label ("New");
  gtk_signal_connect(GTK_OBJECT(new_bt), "clicked",
    GTK_SIGNAL_FUNC(column_sel_new_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), new_bt);
  gtk_widget_show(new_bt);
  
  chg_bt = gtk_button_new_with_label ("Change");
  gtk_widget_set_sensitive(chg_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(chg_bt), "clicked",
    GTK_SIGNAL_FUNC(column_sel_chg_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), chg_bt);
  gtk_widget_show(chg_bt);
  
  del_bt = gtk_button_new_with_label ("Delete");
  gtk_widget_set_sensitive(del_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(del_bt), "clicked",
    GTK_SIGNAL_FUNC(column_sel_del_cb), NULL);
  gtk_container_add(GTK_CONTAINER(list_bb), del_bt);
  gtk_widget_show(del_bt);
  
  arrow_hb = gtk_hbox_new(TRUE, 3);
  gtk_container_add(GTK_CONTAINER(list_bb), arrow_hb);
  gtk_widget_show(arrow_hb);
  
  up_bt = gtk_button_new_with_label("Up");
  gtk_widget_set_sensitive(up_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(up_bt), "clicked",
    GTK_SIGNAL_FUNC(column_sel_arrow_cb), NULL);
  gtk_box_pack_start(GTK_BOX(arrow_hb), up_bt, TRUE, TRUE, 0);
  gtk_widget_show(up_bt);
  
  dn_bt = gtk_button_new_with_label("Down");
  gtk_widget_set_sensitive(dn_bt, FALSE);
  gtk_signal_connect(GTK_OBJECT(dn_bt), "clicked",
    GTK_SIGNAL_FUNC(column_sel_arrow_cb), NULL);
  gtk_box_pack_start(GTK_BOX(arrow_hb), dn_bt, TRUE, TRUE, 0);
  gtk_widget_show(dn_bt);
  
  column_sc = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(column_sc),
    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_widget_set_usize(column_sc, 250, 150);
  gtk_container_add(GTK_CONTAINER(top_hb), column_sc);
  gtk_widget_show(column_sc);

  column_l = gtk_list_new();
  gtk_list_set_selection_mode(GTK_LIST(column_l), GTK_SELECTION_SINGLE);
  gtk_signal_connect(GTK_OBJECT(column_l), "selection_changed",
    GTK_SIGNAL_FUNC(column_sel_list_cb), main_vb);
#ifdef GTK_HAVE_FEATURES_1_1_4
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(column_sc), column_l);
#else
  gtk_container_add(GTK_CONTAINER(column_sc), column_l);
#endif
  gtk_widget_show(column_l);

  clp = g_list_first(prefs.col_list);
  while (clp) {
    cfmt    = (fmt_data *) clp->data;
    nl_lb   = gtk_label_new(cfmt->title);
    nl_item = gtk_list_item_new();
    gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
    gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
    gtk_widget_show(nl_lb);
    gtk_container_add(GTK_CONTAINER(column_l), nl_item);
    gtk_widget_show(nl_item);
    gtk_object_set_data(GTK_OBJECT(nl_item), E_COL_LBL_KEY, nl_lb);
    gtk_object_set_data(GTK_OBJECT(nl_item), E_COL_NAME_KEY, clp);
 
    clp = clp->next;
  }
  
  /* Colunm name entry and format selection */
  tb = gtk_table_new(2, 2, FALSE);
  gtk_container_add(GTK_CONTAINER(main_vb), tb);
  gtk_table_set_row_spacings(GTK_TABLE(tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(tb), 15);
  gtk_widget_show(tb);
  
  lb = gtk_label_new("Column title:");
  gtk_misc_set_alignment(GTK_MISC(lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), lb, 0, 1, 0, 1);
  gtk_widget_show(lb);
  
  title_te = gtk_entry_new();
  gtk_table_attach_defaults(GTK_TABLE(tb), title_te, 1, 2, 0, 1);
  gtk_widget_show(title_te);

  lb = gtk_label_new("Column format:");
  gtk_misc_set_alignment(GTK_MISC(lb), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(tb), lb, 0, 1, 1, 2);
  gtk_widget_show(lb);

  fmt_m = gtk_option_menu_new();
  menu  = gtk_menu_new();
  for (i = 0; i < NUM_COL_FMTS; i++) {
    mitem = gtk_menu_item_new_with_label(col_format_desc(i));
    gtk_menu_append(GTK_MENU(menu), mitem);
    gtk_signal_connect_object( GTK_OBJECT(mitem), "activate",
      GTK_SIGNAL_FUNC(column_set_fmt_cb), (gpointer) i);
    gtk_widget_show(mitem);
  }
  gtk_option_menu_set_menu(GTK_OPTION_MENU(fmt_m), menu);
  cur_fmt = 0;
  gtk_option_menu_set_history(GTK_OPTION_MENU(fmt_m), cur_fmt);
  gtk_table_attach_defaults(GTK_TABLE(tb), fmt_m, 1, 2, 1, 2);
  gtk_widget_show(fmt_m);  
      
  return(main_vb);
}

static void
column_sel_list_cb(GtkWidget *l, gpointer data) {
  fmt_data   *cfmt;
  gchar      *title = "";
  GList      *sl, *clp;
  GtkObject  *l_item;
  gint        sensitivity = FALSE, up_sens = FALSE, dn_sens = FALSE;

  sl = GTK_LIST(l)->selection;
          
  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    clp    = (GList *) gtk_object_get_data(l_item, E_COL_NAME_KEY);
    if (clp) {
      cfmt   = (fmt_data *) clp->data;
      title   = cfmt->title;
      cur_fmt = get_column_format_from_str(cfmt->fmt);
      gtk_option_menu_set_history(GTK_OPTION_MENU(fmt_m), cur_fmt);
      sensitivity = TRUE;
      if (clp != g_list_first(prefs.col_list))
        up_sens = TRUE;
      if (clp != g_list_last(prefs.col_list))
        dn_sens = TRUE;
    }
  }

  /* Did you know that this function is called when the window is destroyed? */
  /* Funny, that. */
  if (!gtk_object_get_data(GTK_OBJECT(data), E_COL_CM_KEY)) {
    gtk_entry_set_text(GTK_ENTRY(title_te), title);
    gtk_widget_set_sensitive(chg_bt, sensitivity);
    gtk_widget_set_sensitive(del_bt, sensitivity);
    gtk_widget_set_sensitive(up_bt, up_sens);
    gtk_widget_set_sensitive(dn_bt, dn_sens);
  }
}

/* To do: add input checking to each of these callbacks */
 
static void
column_sel_new_cb(GtkWidget *w, gpointer data) {
  fmt_data   *cfmt;
  gchar      *title;
  GtkWidget  *nl_item, *nl_lb;
  
  title = gtk_entry_get_text(GTK_ENTRY(title_te));
  
  if (strlen(title) > 0) {
    cfmt           = (fmt_data *) g_malloc(sizeof(fmt_data));
    cfmt->title    = g_strdup(title);
    cfmt->fmt      = g_strdup(col_format_to_string(cur_fmt));
    prefs.col_list = g_list_append(prefs.col_list, cfmt);
    nl_lb          = gtk_label_new(cfmt->title);
    nl_item        = gtk_list_item_new();
    gtk_misc_set_alignment (GTK_MISC (nl_lb), 0.0, 0.5);
    gtk_container_add(GTK_CONTAINER(nl_item), nl_lb);
    gtk_widget_show(nl_lb);
    gtk_container_add(GTK_CONTAINER(column_l), nl_item);
    gtk_widget_show(nl_item);
    gtk_object_set_data(GTK_OBJECT(nl_item), E_COL_LBL_KEY, nl_lb);
    gtk_object_set_data(GTK_OBJECT(nl_item), E_COL_NAME_KEY,
      g_list_last(prefs.col_list));
    gtk_list_select_child(GTK_LIST(column_l), nl_item);
  }
}

static void
column_sel_chg_cb(GtkWidget *w, gpointer data) {
  fmt_data   *cfmt;
  gchar      *title = "";
  GList      *sl, *clp;
  GtkObject  *l_item;
  GtkLabel   *nl_lb;

  sl     = GTK_LIST(column_l)->selection;
  title  = gtk_entry_get_text(GTK_ENTRY(title_te));

  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    clp    = (GList *) gtk_object_get_data(l_item, E_COL_NAME_KEY);
    nl_lb  = (GtkLabel *) gtk_object_get_data(l_item, E_COL_LBL_KEY);
    if (clp && nl_lb) {
      cfmt = (fmt_data *) clp->data;
      
      if (strlen(title) > 0 && cfmt) {
        g_free(cfmt->title);
        g_free(cfmt->fmt);
        cfmt->title = g_strdup(title);
        cfmt->fmt   = g_strdup(col_format_to_string(cur_fmt));
        gtk_label_set(nl_lb, cfmt->title);
      }
    }
  }
}

static void
column_sel_del_cb(GtkWidget *w, gpointer data) {
  GList      *sl, *clp;
  fmt_data   *cfmt;
  GtkObject  *l_item;
  gint        pos;
  
  sl = GTK_LIST(column_l)->selection;
  if (sl) {  /* Something was selected */
    l_item = GTK_OBJECT(sl->data);
    pos    = gtk_list_child_position(GTK_LIST(column_l), GTK_WIDGET(l_item));
    clp    = (GList *) gtk_object_get_data(l_item, E_COL_NAME_KEY);
    if (clp) {
      cfmt = (fmt_data *) clp->data;
      g_free(cfmt->title);
      g_free(cfmt->fmt);
      g_free(cfmt);
      prefs.col_list = g_list_remove_link(prefs.col_list, clp);
      gtk_list_clear_items(GTK_LIST(column_l), pos, pos + 1);
    } 
  }
}

static void
column_sel_arrow_cb(GtkWidget *w, gpointer data) {
  GList      *sl, *clp, *il;
  fmt_data   *cfmt;
  GtkObject  *l_item;
  gint        pos, inc = 1;
  
  if (w == up_bt)
    inc = -1;
  
  sl = GTK_LIST(column_l)->selection;
  if (sl) {  /* Something was selected */
    l_item  = GTK_OBJECT(sl->data);
    pos     = gtk_list_child_position(GTK_LIST(column_l), GTK_WIDGET(l_item));
    clp     = (GList *) gtk_object_get_data(l_item, E_COL_NAME_KEY);
    if (clp) {
      cfmt = (fmt_data *) clp->data;
      prefs.col_list = g_list_remove(prefs.col_list, cfmt);
      g_list_insert(prefs.col_list, cfmt, pos + inc);
      il = (GList *) g_malloc(sizeof(GList));
      il->next = NULL;
      il->prev = NULL;
      il->data = l_item;
      gtk_widget_ref(GTK_WIDGET(l_item));
      gtk_list_clear_items(GTK_LIST(column_l), pos, pos + 1);
      gtk_list_insert_items(GTK_LIST(column_l), il, pos + inc);
      gtk_widget_unref(GTK_WIDGET(l_item));
      gtk_list_select_item(GTK_LIST(column_l), pos + inc);
    } 
  }
}

void
column_set_fmt_cb(GtkWidget *w, gpointer data) {
  cur_fmt = (gint) data;
}

void
column_prefs_ok(GtkWidget *w) {

  column_prefs_cancel(w);
}

void
column_prefs_save(GtkWidget *w) {
}

void
column_prefs_cancel(GtkWidget *w) {
 
  /* Let the list cb know we're about to destroy the widget tree, so it */
  /* doesn't operate on widgets that don't exist. */  
  gtk_object_set_data(GTK_OBJECT(w), E_COL_CM_KEY, (gpointer)TRUE);
  gtk_widget_destroy(GTK_WIDGET(w));
} 
