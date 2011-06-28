/* profile_dlg.c
 * Dialog box for profiles editing
 * Stig Bjorlykke <stig@bjorlykke.org>, 2008
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

#include <string.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <epan/filesystem.h>
#include <epan/prefs.h>

#include "../simple_dialog.h"
#include <wsutil/file_util.h>

#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/profile_dlg.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/help_dlg.h"
#include "gtk/recent.h"

enum {
  NAME_COLUMN,
  GLOBAL_COLUMN,
  DATA_COLUMN,
  NUM_COLUMNS
};

#define E_PROF_PROFILE_L_KEY        "profile_profile_l"
#define E_PROF_DEL_BT_KEY           "profile_del_bt"
#define E_PROF_NAME_TE_KEY          "profile_name_te"

static GtkWidget *global_profile_w = NULL;
static GList *current_profiles = NULL;
static GList *edited_profiles = NULL;

#define PROF_STAT_DEFAULT  1
#define PROF_STAT_EXISTS   2
#define PROF_STAT_NEW      3
#define PROF_STAT_CHANGED  4
#define PROF_STAT_COPY     5

#define PROF_OPERATION_NEW  1
#define PROF_OPERATION_EDIT 2

typedef struct {
  char *name;           /* profile name */
  char *reference;      /* profile reference */
  int   status;
  gboolean is_global;
  gboolean from_global;
} profile_def;

static GList *
add_profile_entry(GList *fl, const char *profilename, const char *reference, int status, 
		  gboolean is_global, gboolean from_global)
{
    profile_def *profile;

    profile = (profile_def *) g_malloc(sizeof(profile_def));
    profile->name = g_strdup(profilename);
    profile->reference = g_strdup(reference);
    profile->status = status;
    profile->is_global = is_global;
    profile->from_global = from_global;
    return g_list_append(fl, profile);
}

static GList *
remove_profile_entry(GList *fl, GList *fl_entry)
{
  profile_def *profile;

  profile = (profile_def *) fl_entry->data;
  g_free(profile->name);
  g_free(profile->reference);
  g_free(profile);
  return g_list_remove_link(fl, fl_entry);
}

static const gchar *
get_profile_parent (const gchar *profilename)
{
  GList *fl_entry = g_list_first(edited_profiles);
  guint no_edited = g_list_length(edited_profiles);
  profile_def *profile;
  guint i;

  if (fl_entry) {
    /* We have edited profiles, find parent */
    for (i = 0; i < no_edited; i++) {
      while (fl_entry) {
	profile = (profile_def *) fl_entry->data;
	if (strcmp (profile->name, profilename) == 0) {
	  if ((profile->status == PROF_STAT_NEW) ||
	      (profile->reference == NULL)) {
	    /* Copy from a new profile */
	    return NULL;
	  } else {
	    /* Found a parent, use this */
	    profilename = profile->reference;
	  }
	}
	fl_entry = g_list_next(fl_entry);
      }
      fl_entry = g_list_first(edited_profiles);
    }
  }

  return profilename;
}

static GList *
add_to_profile_list(const char *name, const char *expression, int status, 
		    gboolean is_global, gboolean from_global)
{
  edited_profiles = add_profile_entry(edited_profiles, name, expression, status,
				      is_global, from_global);

  return g_list_last(edited_profiles);
}

static void
remove_from_profile_list(GList *fl_entry)
{
  edited_profiles = remove_profile_entry(edited_profiles, fl_entry);
}

static void
empty_profile_list(gboolean edit_list)
{
  GList **flpp;

  if (edit_list) {
    flpp = &edited_profiles;

    while(*flpp) {
      *flpp = remove_profile_entry(*flpp, g_list_first(*flpp));
    }

    g_assert(g_list_length(*flpp) == 0);
  }

  flpp = &current_profiles;

  while(*flpp) {
    *flpp = remove_profile_entry(*flpp, g_list_first(*flpp));
  }

  g_assert(g_list_length(*flpp) == 0);
}

static void
copy_profile_list(void)
{
    GList      *flp_src;
    profile_def *profile;

    flp_src = edited_profiles;

    /* throw away the "old" destination list - a NULL list is ok here */
    empty_profile_list(FALSE);

    /* copy the list entries */
    while(flp_src) {
        profile = (flp_src)->data;

        current_profiles = add_profile_entry(current_profiles, profile->name,
					     profile->reference, profile->status, 
					     profile->is_global, profile->from_global);
        flp_src = g_list_next(flp_src);
    }
}


static GtkTreeIter *
fill_list(GtkWidget *main_w)
{
  WS_DIR        *dir;             /* scanned directory */
  WS_DIRENT     *file;            /* current file */
  GList         *fl_entry;
  profile_def   *profile;
  GtkTreeView   *profile_l;
  GtkListStore  *store;
  GtkTreeIter    iter, *l_select = NULL;
  const gchar   *profile_name = get_profile_name ();
  const gchar   *profiles_dir, *name;
  gchar         *filename;

  profile_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY));
  store = GTK_LIST_STORE(gtk_tree_view_get_model(profile_l));

  fl_entry = add_to_profile_list(DEFAULT_PROFILE, DEFAULT_PROFILE, PROF_STAT_DEFAULT, FALSE, FALSE);
  gtk_list_store_append(store, &iter);
  gtk_list_store_set(store, &iter, NAME_COLUMN, DEFAULT_PROFILE, GLOBAL_COLUMN, FALSE, DATA_COLUMN, fl_entry, -1);
  if (strcmp (profile_name, DEFAULT_PROFILE)==0) {
    l_select = g_memdup(&iter, sizeof(iter));
  }

  /* fill in data */
  profiles_dir = get_profiles_dir();
  if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
    while ((file = ws_dir_read_name(dir)) != NULL) {
      name = ws_dir_get_name(file);
      filename = g_strdup_printf ("%s%s%s", profiles_dir, G_DIR_SEPARATOR_S, name);

      if (test_for_directory(filename) == EISDIR) {
	fl_entry = add_to_profile_list(name, name, PROF_STAT_EXISTS, FALSE, FALSE);
	profile = (profile_def *) fl_entry->data;
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, NAME_COLUMN, profile->name, GLOBAL_COLUMN, FALSE, DATA_COLUMN, fl_entry, -1);

	if (profile->name) {
	  if (strcmp(profile_name, profile->name) == 0) {
	    /*
	     * XXX - We're assuming that we can just copy a GtkTreeIter
	     * and use it later without any crashes.  This may not be a
	     * valid assumption.
	     */
	    l_select = g_memdup(&iter, sizeof(iter));
	  }
	}
      }
      g_free (filename);
    }
    ws_dir_close (dir);
  }

  profiles_dir = get_global_profiles_dir();
  if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
    while ((file = ws_dir_read_name(dir)) != NULL) {
      name = ws_dir_get_name(file);
      filename = g_strdup_printf ("%s%s%s", profiles_dir, G_DIR_SEPARATOR_S, name);

      if (test_for_directory(filename) == EISDIR) {
	fl_entry = add_to_profile_list(name, name, PROF_STAT_EXISTS, TRUE, TRUE);
	profile = (profile_def *) fl_entry->data;
	gtk_list_store_append(store, &iter);
	gtk_list_store_set(store, &iter, NAME_COLUMN, profile->name, GLOBAL_COLUMN, TRUE, DATA_COLUMN, fl_entry, -1);
      }
      g_free (filename);
    }
    ws_dir_close (dir);
  }

  /* Make the current list and the edited list equal */
  copy_profile_list ();

  return l_select;
}

static gboolean
profile_is_invalid_name(const gchar *name)
{
  gchar  *message = NULL;

#ifdef _WIN32
  char *invalid_dir_char = "\\/:*?\"<>|";
  gboolean invalid = FALSE;
  int i;

  for (i = 0; i < 9; i++) {
    if (strchr(name, invalid_dir_char[i])) {
      /* Invalid character in directory */
      invalid = TRUE;
    }
  }
  if (name[0] == '.' || name[strlen(name)-1] == '.') {
    /* Profile name cannot start or end with period */
    invalid = TRUE;
  }
  if (invalid) {
    message = g_strdup_printf("start or end with period (.), or contain any of the following characters:\n"
			      "   \\ / : * ? \" &lt; &gt; |");
  }
#else
  if (strchr(name, '/')) {
    /* Invalid character in directory */
    message = g_strdup_printf("contain the '/' character.");
  }
#endif

  if (message) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "A profile name cannot %s\nProfiles unchanged.", message);
    g_free(message);
    return TRUE;
  }

  return FALSE;
}

static void
profile_select(GtkWidget *main_w, GtkTreeView *profile_l, gboolean destroy)
{
  GList            *fl_entry;
  profile_def      *profile;
  GtkTreeSelection *sel;
  GtkTreeModel     *model;
  GtkTreeIter       iter;

  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(profile_l));

  if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fl_entry, -1);
    if (fl_entry) {
      profile = (profile_def *) fl_entry->data;
      if (profile_exists (profile->name, FALSE) || profile_exists (profile->name, TRUE)) {
	/* The new profile exists, change */
	change_configuration_profile (profile->name);
      } else if (!profile_exists (get_profile_name(), FALSE)) {
	/* The new profile does not exist, and the previous profile has
	   been deleted.  Change to the default profile */
	change_configuration_profile (NULL);
      }
    }
  }

  if (destroy) {
    /*
     * Destroy the profile dialog box.
     */
    empty_profile_list (TRUE);
    window_destroy(main_w);
  }
}

static void
profile_apply(GtkWidget *main_w, GtkTreeView *profile_l, gboolean destroy)
{
  char        *pf_dir_path, *pf_dir_path2, *pf_filename;
  GList       *fl1, *fl2;
  profile_def *profile1, *profile2;
  gboolean     found;

  /* First validate all profile names */
  fl1 = g_list_first(edited_profiles);
  while (fl1) {
    profile1 = (profile_def *) fl1->data;
    g_strstrip(profile1->name);
    if (profile_is_invalid_name(profile1->name)) {
      return;
    }
    fl1 = g_list_next(fl1);
  }

  /* Then do all copy profiles */
  fl1 = g_list_first(edited_profiles);
  while (fl1) {
    profile1 = (profile_def *) fl1->data;
    g_strstrip(profile1->name);
    if (profile1->status == PROF_STAT_COPY) {
      if (create_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Can't create directory\n\"%s\":\n%s.",
                      pf_dir_path, g_strerror(errno));
        
        g_free(pf_dir_path);
      }
      profile1->status = PROF_STAT_EXISTS;

      if (profile1->reference) {
        if (copy_persconffile_profile(profile1->name, profile1->reference, profile1->from_global,
				      &pf_filename, &pf_dir_path, &pf_dir_path2) == -1) {
          simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                        pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

          g_free(pf_filename);
          g_free(pf_dir_path);
          g_free(pf_dir_path2);
        }
      }

      g_free (profile1->reference);
      profile1->reference = g_strdup(profile1->name);
    }
    fl1 = g_list_next(fl1);
  }


  /* Then create new and rename changed */
  fl1 = g_list_first(edited_profiles);
  while (fl1) {
    profile1 = (profile_def *) fl1->data;
    g_strstrip(profile1->name);
    if (profile1->status == PROF_STAT_NEW) {
      /* We do not create a directory for the default profile */
      if (strcmp(profile1->name, DEFAULT_PROFILE)!=0) {
	if (create_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
	  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't create directory\n\"%s\":\n%s.",
			pf_dir_path, g_strerror(errno));

	  g_free(pf_dir_path);
	}
	profile1->status = PROF_STAT_EXISTS;

	g_free (profile1->reference);
	profile1->reference = g_strdup(profile1->name);
      }
    } else if (profile1->status == PROF_STAT_CHANGED) {
      if (strcmp(profile1->reference, profile1->name)!=0) {
	/* Rename old profile directory to new */
	if (rename_persconffile_profile(profile1->reference, profile1->name,
					&pf_dir_path, &pf_dir_path2) == -1) {
	  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Can't rename directory\n\"%s\" to\n\"%s\":\n%s.",
			pf_dir_path, pf_dir_path2, g_strerror(errno));

	  g_free(pf_dir_path);
	  g_free(pf_dir_path2);
	}
	profile1->status = PROF_STAT_EXISTS;
	g_free (profile1->reference);
	profile1->reference = g_strdup(profile1->name);
      }
    }
    fl1 = g_list_next(fl1);
  }

  /* Last remove deleted */
  fl1 = g_list_first(current_profiles);
  while (fl1) {
    found = FALSE;
    profile1 = (profile_def *) fl1->data;
    fl2 = g_list_first(edited_profiles);
    while (fl2) {
      profile2 = (profile_def *) fl2->data;
      if (!profile2->is_global) {
	if (strcmp(profile1->name, profile2->name)==0) {
	  /* Profile exists in both lists */
	  found = TRUE;
	} else if (strcmp(profile1->name, profile2->reference)==0) {
	  /* Profile has been renamed */
	  found = TRUE;
	}
      }
      fl2 = fl2->next;
    }
    if (!found) {
      /* Exists in existing list and not in edited, this is a deleted profile */
      if (delete_persconffile_profile(profile1->name, &pf_dir_path) == -1) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Can't delete profile directory\n\"%s\":\n%s.",
		      pf_dir_path, g_strerror(errno));

	g_free(pf_dir_path);
      }
    }
    fl1 = g_list_next(fl1);
  }

  copy_profile_list();
  profile_select(main_w, profile_l, destroy);
}

static void
profile_dlg_ok_cb(GtkWidget *ok_bt, gpointer data _U_)
{
  GtkWidget    *main_w = gtk_widget_get_toplevel(ok_bt);
  GtkTreeView  *profile_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY));

  /*
   * Apply the profile and destroy the dialog box.
   */
  profile_apply(main_w, profile_l, TRUE);
}

static void
profile_dlg_apply_cb(GtkWidget *apply_bt, gpointer data _U_)
{
  GtkWidget    *main_w    = gtk_widget_get_toplevel(apply_bt);
  GtkTreeView  *profile_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY));

  /*
   * Apply the profile, but don't destroy the dialog box.
   */
  profile_apply(main_w, profile_l, FALSE);
}

/* cancel button pressed, revert changes and exit dialog */
static void
profile_dlg_cancel_cb(GtkWidget *cancel_bt, gpointer data _U_)
{
  GtkWidget  *main_w = gtk_widget_get_toplevel(cancel_bt);

  empty_profile_list (TRUE);
  window_destroy(GTK_WIDGET(main_w));
}

/* Treat this as a cancel, by calling "profile_dlg_cancel_cb()" */
static gboolean
profile_dlg_delete_event_cb(GtkWidget *main_w, GdkEvent *event _U_,
			    gpointer data)
{
  profile_dlg_cancel_cb(main_w, data);
  return FALSE;
}

static void
profile_dlg_destroy_cb(GtkWidget *w _U_, gpointer data _U_)
{
  global_profile_w = NULL;
}


static gboolean
profile_button_press_cb(GtkWidget *list, GdkEventButton *event, gpointer data _U_)
{
  if (event->type == GDK_2BUTTON_PRESS) {
    GtkWidget *main_w = gtk_widget_get_toplevel(list);

    profile_apply (main_w, GTK_TREE_VIEW(list), TRUE);
  }

  return FALSE;
}

static gboolean
profile_key_release_cb(GtkWidget *list, GdkEventKey *event, gpointer data _U_)
{
  if (event->keyval == GDK_Return || event->keyval == GDK_KP_Enter) {
    GtkWidget    *main_w = gtk_widget_get_toplevel(list);

    profile_apply (main_w, GTK_TREE_VIEW(list), TRUE);
  }

  return FALSE;
}

static void
profile_sel_list_cb(GtkTreeSelection *sel, gpointer data _U_)
{
  GtkWidget    *profile_l   = GTK_WIDGET(gtk_tree_selection_get_tree_view(sel));
  GtkWidget    *main_w      = gtk_widget_get_toplevel(profile_l);
  GtkTreeModel *model;
  GtkTreeIter   iter;
  GtkWidget    *name_te     = g_object_get_data(G_OBJECT(main_w), E_PROF_NAME_TE_KEY);
  GtkWidget    *del_bt      = g_object_get_data(G_OBJECT(main_w), E_PROF_DEL_BT_KEY);
  profile_def  *profile;
  gchar        *name        = NULL;
  GList        *fl_entry;
  gint          sensitivity = FALSE;

  if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fl_entry, -1);
    if (fl_entry) {
      profile = (profile_def *) fl_entry->data;
      name = g_strdup(profile->name);
      if ((profile->status != PROF_STAT_DEFAULT) && !profile->is_global) {
	sensitivity = TRUE;
      }
    }
  }

  /*
   * Did you know that this function is called when the window is destroyed?
   * Funny, that.
   * This means that we have to:
   *
   *	attach to the top-level window data items containing pointers to
   *	the widgets we affect here;
   *
   *	give each of those widgets their own destroy callbacks;
   *
   *	clear that pointer when the widget is destroyed;
   *
   *	don't do anything to the widget if the pointer we get back is
   *	null;
   *
   * so that if we're called after any of the widgets we'd affect are
   * destroyed, we know that we shouldn't do anything to those widgets.
   */
  if (name_te != NULL) {
    gtk_entry_set_text(GTK_ENTRY(name_te), name ? name : "");
    gtk_widget_set_sensitive(name_te, sensitivity);
  }
  if (del_bt != NULL)
    gtk_widget_set_sensitive(del_bt, sensitivity);
  g_free(name);
}

static void
profile_new_bt_clicked_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget    *main_w = gtk_widget_get_toplevel(w);
  GtkWidget    *name_te = g_object_get_data(G_OBJECT(main_w), E_PROF_NAME_TE_KEY);
  GtkTreeView  *profile_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY));
  GtkListStore *store;
  GtkTreeIter   iter;
  GList        *fl_entry;
  const gchar  *name = "New profile";

  /* Add a new entry to the profile list. */
  fl_entry = add_to_profile_list(name, "", PROF_STAT_NEW, FALSE, FALSE);

  store = GTK_LIST_STORE(gtk_tree_view_get_model(profile_l));
  gtk_list_store_append(store, &iter);
  gtk_list_store_set(store, &iter, NAME_COLUMN, name, GLOBAL_COLUMN, FALSE, DATA_COLUMN, fl_entry, -1);
  /* Select the item. */
  gtk_tree_selection_select_iter(gtk_tree_view_get_selection(profile_l), &iter);

  gtk_editable_select_region(GTK_EDITABLE(name_te), 0, -1);
  gtk_widget_grab_focus(name_te);
}

static void
profile_copy_bt_clicked_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget    *main_w = gtk_widget_get_toplevel(w);
  GtkWidget    *name_te = g_object_get_data(G_OBJECT(main_w), E_PROF_NAME_TE_KEY);
  GtkTreeView  *profile_l = GTK_TREE_VIEW(g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY));
  GtkListStore *store;
  GtkTreeIter   iter;
  GList        *fl_entry;
  const gchar  *name = gtk_entry_get_text(GTK_ENTRY(name_te));
  const gchar  *parent = NULL;
  gchar        *new_name;

  GtkTreeSelection *sel;
  GtkTreeModel     *model;
  profile_def   *profile = NULL;

  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(profile_l));
  if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fl_entry, -1);
    if (fl_entry) {
      profile = (profile_def *) fl_entry->data;
    }
  }

  if (profile && profile->is_global) {
    parent = profile->name;
  } else {
    parent = get_profile_parent (name);
  }

  if (profile && profile->is_global && !profile_exists (parent, FALSE)) {
    new_name = g_strdup (name);
  } else {
    new_name = g_strdup_printf ("%s (copy)", name);
  }

  /* Add a new entry to the profile list. */
  fl_entry = add_to_profile_list(new_name, parent, PROF_STAT_COPY, FALSE, profile ? profile->from_global : FALSE);

  store = GTK_LIST_STORE(gtk_tree_view_get_model(profile_l));
  gtk_list_store_append(store, &iter);
  gtk_list_store_set(store, &iter, NAME_COLUMN, new_name, GLOBAL_COLUMN, FALSE, DATA_COLUMN, fl_entry, -1);
  /* Select the item. */
  gtk_tree_selection_select_iter(gtk_tree_view_get_selection(profile_l), &iter);

  gtk_editable_select_region(GTK_EDITABLE(name_te), 0, -1);
  gtk_widget_grab_focus(name_te);

  g_free (new_name);
}

static void
profile_name_te_changed_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget   *main_w = gtk_widget_get_toplevel(w);
  GtkWidget   *name_te = g_object_get_data(G_OBJECT(main_w), E_PROF_NAME_TE_KEY);
  GtkWidget   *profile_l = g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY);
  profile_def *profile;
  GList       *fl_entry;
  const gchar *name = "";

  GtkTreeSelection  *sel;
  GtkTreeModel      *model;
  GtkTreeIter        iter;

  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(profile_l));
  name   = gtk_entry_get_text(GTK_ENTRY(name_te));

  /* if something was selected */
  if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fl_entry, -1);
    if (fl_entry != NULL) {
      profile = (profile_def *) fl_entry->data;

      if (strlen(name) > 0 && profile && !profile->is_global) {
	if (profile->status != PROF_STAT_DEFAULT) {
	  g_free(profile->name);
	  profile->name = g_strdup(name);
	  if ((profile->status != PROF_STAT_NEW) &&
	      (profile->status != PROF_STAT_COPY)) {
	    profile->status = PROF_STAT_CHANGED;
	  }
	  gtk_list_store_set(GTK_LIST_STORE(model), &iter, NAME_COLUMN, name, -1);
	}
      }
    }
  }
}

static void
profile_del_bt_clicked_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget  *main_w = gtk_widget_get_toplevel(w);
  GtkWidget  *profile_l = g_object_get_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY);
  GList      *fl_entry;

  GtkTreeSelection  *sel;
  GtkTreeModel      *model;
  GtkTreeIter        iter;

  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(profile_l));
  /* If something was selected */
  if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
    gtk_tree_model_get(model, &iter, DATA_COLUMN, &fl_entry, -1);

    if (fl_entry != NULL) {
      remove_from_profile_list (fl_entry);
      gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    }
  }

  if (gtk_tree_model_get_iter_first (model, &iter)) {
    gtk_tree_selection_select_iter(sel, &iter);
  }
}

static GtkWidget *
profile_dialog_new(void)
{
  GtkWidget  *main_w,  /* main window */
    *main_vb,          /* main container */
    *bbox,             /* button container */
    *ok_bt,            /* "OK" button */
    *apply_bt,         /* "Apply" button */
    *cancel_bt,        /* "Cancel" button */
    *help_bt;          /* "Help" button */
  GtkWidget  *profile_vb,        /* profile settings box */
    *props_vb;
  GtkWidget  *top_hb,
    *list_bb,
    *new_bt,
    *copy_bt,
    *del_bt,
    *profile_sc,
    *profile_l,
    *middle_hb,
    *name_lb,
    *name_te,
    *profile_fr,
    *edit_fr,
    *props_fr;
  GtkTooltips       *tooltips;
  GtkListStore      *store;
  GtkCellRenderer   *renderer;
  GtkTreeViewColumn *column;
  GtkTreeSelection  *sel;
  GtkTreeIter       *l_select;
  gboolean           has_global = has_global_profiles();
  
  /* Get a pointer to a static variable holding the type of profile on
     which we're working, so we can pass that pointer to callback
     routines. */

  tooltips = gtk_tooltips_new ();

  main_w = dlg_conf_window_new("Wireshark: Configuration Profiles");
  gtk_window_set_default_size(GTK_WINDOW(main_w), 400, 400);

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(main_w), main_vb);
  gtk_widget_show(main_vb);

  /* Container for each row of widgets */
  profile_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(profile_vb), 0);
  gtk_container_add(GTK_CONTAINER(main_vb), profile_vb);
  gtk_widget_show(profile_vb);

  /* Top row: Buttons and profile list */
  top_hb = gtk_hbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(profile_vb), top_hb);
  gtk_widget_show(top_hb);

  edit_fr = gtk_frame_new("Edit");
  gtk_box_pack_start(GTK_BOX(top_hb), edit_fr, FALSE, FALSE, 0);
  gtk_widget_show(edit_fr);

  list_bb = gtk_vbox_new(TRUE, 0);
  gtk_container_set_border_width(GTK_CONTAINER(list_bb), 5);
  gtk_container_add(GTK_CONTAINER(edit_fr), list_bb);
  gtk_widget_show(list_bb);

  new_bt = gtk_button_new_from_stock(GTK_STOCK_NEW);
  g_signal_connect(new_bt, "clicked", G_CALLBACK(profile_new_bt_clicked_cb), NULL);
  gtk_widget_show(new_bt);
  gtk_box_pack_start (GTK_BOX (list_bb), new_bt, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, new_bt,
			"Create a new profile (with default properties)", NULL);

  copy_bt = gtk_button_new_from_stock(GTK_STOCK_COPY);
  g_signal_connect(copy_bt, "clicked", G_CALLBACK(profile_copy_bt_clicked_cb), NULL);
  gtk_widget_show(copy_bt);
  gtk_box_pack_start (GTK_BOX (list_bb), copy_bt, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, copy_bt,
			"Copy the selected profile", NULL);

  del_bt = gtk_button_new_from_stock(GTK_STOCK_DELETE);
  gtk_widget_set_sensitive(del_bt, FALSE);
  g_signal_connect(del_bt, "clicked", G_CALLBACK(profile_del_bt_clicked_cb), NULL);
  g_object_set_data(G_OBJECT(main_w), E_PROF_DEL_BT_KEY, del_bt);
  gtk_widget_show(del_bt);
  gtk_box_pack_start (GTK_BOX (list_bb), del_bt, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, del_bt, "Delete the selected profile", NULL);

  profile_fr = gtk_frame_new("Configuration Profiles");
  gtk_box_pack_start(GTK_BOX(top_hb), profile_fr, TRUE, TRUE, 0);
  gtk_widget_show(profile_fr);

  profile_sc = scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(profile_sc),
				      GTK_SHADOW_IN);

  gtk_container_set_border_width  (GTK_CONTAINER (profile_sc), 5);
  gtk_container_add(GTK_CONTAINER(profile_fr), profile_sc);
  gtk_widget_show(profile_sc);

  store = gtk_list_store_new(NUM_COLUMNS, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_POINTER);
  profile_l = tree_view_new(GTK_TREE_MODEL(store));
  /* Only show headers if having more than one column */
  gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(profile_l), has_global);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", NAME_COLUMN, NULL);
  gtk_tree_view_column_set_expand(column, TRUE);
  gtk_tree_view_column_set_sort_column_id(column, NAME_COLUMN);
  gtk_tree_view_append_column(GTK_TREE_VIEW(profile_l), column);

  renderer = gtk_cell_renderer_toggle_new();
  column = gtk_tree_view_column_new_with_attributes("Global", renderer, "active", GLOBAL_COLUMN, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(profile_l), column);
  gtk_tooltips_set_tip(tooltips, column->button, "Global profiles will be copied to users profiles when used", NULL);
  gtk_tree_view_column_set_visible(column, has_global);

  sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(profile_l));
  gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
  g_signal_connect(sel, "changed", G_CALLBACK(profile_sel_list_cb), profile_vb);
  g_signal_connect(profile_l, "button_press_event", G_CALLBACK(profile_button_press_cb), NULL);
  g_signal_connect(profile_l, "key_release_event", G_CALLBACK(profile_key_release_cb), NULL);
  g_object_set_data(G_OBJECT(main_w), E_PROF_PROFILE_L_KEY, profile_l);
  gtk_container_add(GTK_CONTAINER(profile_sc), profile_l);
  gtk_widget_show(profile_l);

  /* fill in data */
  l_select = fill_list(main_w);

  g_object_unref(G_OBJECT(store));

  props_fr = gtk_frame_new("Properties");
  gtk_box_pack_start(GTK_BOX(profile_vb), props_fr, FALSE, FALSE, 0);
  gtk_widget_show(props_fr);

  props_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_set_border_width(GTK_CONTAINER(props_vb), 5);
  gtk_container_add(GTK_CONTAINER(props_fr), props_vb);
  gtk_widget_show(props_vb);

  /* row: Profile name entry */
  middle_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(props_vb), middle_hb);
  gtk_widget_show(middle_hb);

  name_lb = gtk_label_new("Profile name:");
  gtk_box_pack_start(GTK_BOX(middle_hb), name_lb, FALSE, FALSE, 0);
  gtk_widget_show(name_lb);

  name_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(middle_hb), name_te, TRUE, TRUE, 0);
  g_object_set_data(G_OBJECT(main_w), E_PROF_NAME_TE_KEY, name_te);
  g_signal_connect(name_te, "changed", G_CALLBACK(profile_name_te_changed_cb), NULL);
#ifdef _WIN32
  gtk_tooltips_set_tip (tooltips, name_te, "A profile name cannot start or end with a period (.), and cannot contain any of the following characters:\n   \\ / : * ? \" < > |", NULL);
#else
  gtk_tooltips_set_tip (tooltips, name_te, "A profile name cannot contain the '/' character", NULL);
#endif
  gtk_widget_show(name_te);

  /* button row (create all possible buttons and hide the unrequired later - it's a lot easier) */
  bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);
  gtk_widget_show(bbox);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(profile_dlg_ok_cb), NULL);
  gtk_tooltips_set_tip (tooltips, ok_bt, "Apply the profiles and close this dialog", NULL);

  /* Catch the "activate" signal on the profile name and profile
     list entries, so that if the user types Return
     there, we act as if the "OK" button had been selected, as
     happens if Return is typed if some widget that *doesn't*
     handle the Return key has the input focus. */
  dlg_set_activate(name_te, ok_bt);

  apply_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_APPLY);
  g_signal_connect(apply_bt, "clicked", G_CALLBACK(profile_dlg_apply_cb), NULL);
  gtk_tooltips_set_tip (tooltips, apply_bt, "Apply the profiles and keep this dialog open", NULL);

  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  gtk_tooltips_set_tip (tooltips, cancel_bt, "Cancel the changes", NULL);
  g_signal_connect(cancel_bt, "clicked", G_CALLBACK(profile_dlg_cancel_cb), NULL);
  window_set_cancel_button(main_w, cancel_bt, NULL);

  help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
  g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_CONFIG_PROFILES_DIALOG);
  gtk_tooltips_set_tip (tooltips, help_bt, "Show topic specific help", NULL);

  if(ok_bt) {
    gtk_widget_grab_default(ok_bt);
  }


  /* DO SELECTION THINGS *AFTER* SHOWING THE DIALOG! */
  /* otherwise the updatings can get confused */
  if (l_select) {
    gtk_tree_selection_select_iter(sel, l_select);
    g_free(l_select);
  }

  if (profile_l) {
    gtk_widget_grab_focus(profile_l);
  }

  g_signal_connect(main_w, "delete_event", G_CALLBACK(profile_dlg_delete_event_cb), NULL);
  g_signal_connect(main_w, "destroy", G_CALLBACK(profile_dlg_destroy_cb), NULL);

  gtk_widget_show(main_w);

  window_present(main_w);

  return main_w;
}


static void
select_profile_cb (GtkWidget *w _U_, gpointer data)
{
  const gchar *current_profile = get_profile_name ();
  gchar       *selected_profile = (gchar *) data;

  if (strcmp (selected_profile, current_profile) != 0) {
    change_configuration_profile (selected_profile);
  }
}

gboolean
profile_show_popup_cb (GtkWidget *w _U_, GdkEvent *event, gpointer user_data _U_)
{
  GdkEventButton *bevent = (GdkEventButton *)event;
  const gchar    *profile_name = get_profile_name ();
  const gchar    *profiles_dir, *name;
  WS_DIR         *dir;             /* scanned directory */
  WS_DIRENT      *file;            /* current file */
  GtkWidget      *menu;
  GtkWidget      *menu_item;

  menu = gtk_menu_new ();

  if (bevent->button != 1) {
    GtkWidget *change_menu = menus_get_profiles_change_menu ();

#if GTK_CHECK_VERSION(2,16,0)
    GtkWidget *edit_menu = menus_get_profiles_edit_menu ();
    GtkWidget *delete_menu = menus_get_profiles_delete_menu ();
    if (strcmp (profile_name, DEFAULT_PROFILE) != 0) {
      gchar *label;
      label = g_strdup_printf ("Edit \"%s\"...", profile_name);
      gtk_menu_item_set_label (GTK_MENU_ITEM(edit_menu), label);
      g_free (label);
      label = g_strdup_printf ("Delete \"%s\"", profile_name);
      gtk_menu_item_set_label (GTK_MENU_ITEM(delete_menu), label);
      g_free (label);
    } else {
      gtk_menu_item_set_label (GTK_MENU_ITEM(edit_menu), "Edit...");
      gtk_menu_item_set_label (GTK_MENU_ITEM(delete_menu), "Delete");
    }
#endif
    gtk_menu_item_set_submenu (GTK_MENU_ITEM(change_menu), menu);
  }

  /* Add a menu item for the Default profile */
  menu_item = gtk_check_menu_item_new_with_label (DEFAULT_PROFILE);
  if (strcmp (profile_name, DEFAULT_PROFILE) == 0) {
    /* Check current profile */
    gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_item), TRUE);
  }
  g_object_set (G_OBJECT(menu_item), "draw-as-radio", TRUE, NULL);
  g_signal_connect (menu_item, "activate", G_CALLBACK(select_profile_cb), g_strdup (DEFAULT_PROFILE));
  gtk_menu_shell_append (GTK_MENU_SHELL(menu), menu_item);
  gtk_widget_show (menu_item);

  profiles_dir = get_profiles_dir();
  if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
    while ((file = ws_dir_read_name(dir)) != NULL) {
      name = ws_dir_get_name(file);

      if (profile_exists(name, FALSE)) {
	menu_item = gtk_check_menu_item_new_with_label (name);
	if (strcmp (name, profile_name)==0) {
	  /* Check current profile */
	  gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_item), TRUE);
	}
	g_object_set (G_OBJECT(menu_item), "draw-as-radio", TRUE, NULL);
	g_signal_connect (menu_item, "activate", G_CALLBACK(select_profile_cb), g_strdup (name));
	gtk_menu_shell_append  (GTK_MENU_SHELL (menu), menu_item);
	gtk_widget_show (menu_item);
      }
    }
    ws_dir_close (dir);
  }

  profiles_dir = get_global_profiles_dir();
  if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
    GtkWidget *sub_menu = NULL;
    gboolean   added_submenu = FALSE;
  
    while ((file = ws_dir_read_name(dir)) != NULL) {
      name = ws_dir_get_name(file);

      if (profile_exists(name, TRUE)) {
	if (!added_submenu) {
	  menu_item =  gtk_separator_menu_item_new ();
	  gtk_menu_shell_append  (GTK_MENU_SHELL (menu), menu_item);
	  gtk_widget_show (menu_item);
	  
	  menu_item = gtk_menu_item_new_with_label ("New from Global");
	  gtk_menu_shell_append  (GTK_MENU_SHELL (menu), menu_item);
	  gtk_widget_show (menu_item);

	  sub_menu = gtk_menu_new ();
	  gtk_menu_item_set_submenu (GTK_MENU_ITEM(menu_item), sub_menu);

	  added_submenu = TRUE;
	}

	menu_item = gtk_menu_item_new_with_label (name);
	g_signal_connect (menu_item, "activate", G_CALLBACK(select_profile_cb), g_strdup (name));
	if (profile_exists(name, FALSE)) {
	  gtk_widget_set_sensitive(menu_item, FALSE);
	}
	gtk_menu_shell_append  (GTK_MENU_SHELL (sub_menu), menu_item);
	gtk_widget_show (menu_item);
      }
    }
    ws_dir_close (dir);
  }

  if (bevent->button != 1) {
    /* Second-click is handled in popup_menu_handler() */
    return FALSE;
  }

  gtk_menu_popup (GTK_MENU(menu), NULL, NULL, NULL, NULL,
		  bevent->button, bevent->time);

  return TRUE;
}

static void
profile_name_edit_ok (GtkWidget *w _U_, gpointer parent_w)
{
  gint operation = GPOINTER_TO_INT(g_object_get_data (G_OBJECT(w), "operation"));
  GtkComboBox  *combo_box = g_object_get_data (G_OBJECT(w), "create_from");
  GtkWidget    *entry = g_object_get_data (G_OBJECT(w), "entry");
  GtkTreeStore *store;
  GtkTreeIter iter;
  const gchar *new_name =  gtk_entry_get_text(GTK_ENTRY(entry));
  const gchar *profile_name = "";
  gboolean     from_global = FALSE;
  char        *pf_dir_path, *pf_dir_path2, *pf_filename;

  if (strlen(new_name) == 0 || profile_is_invalid_name(new_name)) {
    return;
  }

  switch (operation) {
  case PROF_OPERATION_NEW:
    if (gtk_combo_box_get_active_iter(combo_box, &iter)) {
      store = GTK_TREE_STORE(gtk_combo_box_get_model(combo_box));
      gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &profile_name, 1, &from_global, -1);
    }
    break;
  case PROF_OPERATION_EDIT:
    profile_name = get_profile_name();
    if (strcmp(new_name, profile_name) == 0) {
      /* Rename without a change, do nothing */
      window_destroy(GTK_WIDGET(parent_w));
      return;
    }
    break;
  default:
    g_assert_not_reached();
  }

  if (profile_exists (new_name, FALSE)) {
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		  "The profile already exists:\n%s.", new_name);
    return;
  }

  /* Write recent file for profile we are leaving */
  write_profile_recent();

  switch (operation) {
  case PROF_OPERATION_NEW:
    if (create_persconffile_profile(new_name, &pf_dir_path) == -1) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't create directory\n\"%s\":\n%s.",
		    pf_dir_path, g_strerror(errno));
      
      g_free(pf_dir_path);
    } else if (strlen (profile_name) && 
	       copy_persconffile_profile(new_name, profile_name, from_global, &pf_filename,
					 &pf_dir_path, &pf_dir_path2) == -1)
    {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
		    pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));
	
      g_free(pf_filename);
      g_free(pf_dir_path);
      g_free(pf_dir_path2);
    } else {
      change_configuration_profile (new_name);
    }
    break;
  case PROF_OPERATION_EDIT:
    if (rename_persconffile_profile(profile_name, new_name,
				    &pf_dir_path, &pf_dir_path2) == -1) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't rename directory\n\"%s\" to\n\"%s\":\n%s.",
		    pf_dir_path, pf_dir_path2, g_strerror(errno));
      
      g_free(pf_dir_path);
      g_free(pf_dir_path2);
    } else {
      change_configuration_profile (new_name);
    }
    break;
  default:
    g_assert_not_reached();
  }

  window_destroy(GTK_WIDGET(parent_w));
}

static void
profile_name_edit_cancel (GtkWidget *w _U_, gpointer parent_w)
{
  window_destroy(GTK_WIDGET(parent_w));
}

static void
profile_name_edit_dlg (gint operation)
{
  WS_DIR      *dir;             /* scanned directory */
  WS_DIRENT   *file;            /* current file */
  GtkWidget   *win, *main_tb, *main_vb, *bbox, *cancel_bt, *ok_bt;
  GtkWidget   *entry, *label, *combo_box=NULL;
  GtkCellRenderer *cell;
  GtkTreeStore    *store;
  GtkTreeIter   iter, parent;
  gchar       *window_title=NULL;
  const gchar *profile_name, *profiles_dir, *name;
  GtkTooltips *tooltips;
  gboolean     has_global = has_global_profiles();

  tooltips = gtk_tooltips_new();
  profile_name = get_profile_name();

  switch (operation) {
  case PROF_OPERATION_NEW:
    window_title = g_strdup ("Create New Profile");
    break;
  case PROF_OPERATION_EDIT:
    window_title = g_strdup_printf ("Edit: %s", profile_name);
    break;
  default:
    g_assert_not_reached();
  }

  win = dlg_window_new(window_title);
  g_free (window_title);

  gtk_window_set_resizable(GTK_WINDOW(win),FALSE);
  gtk_window_resize(GTK_WINDOW(win), 400, 100);

  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_add(GTK_CONTAINER(win), main_vb);
  gtk_container_set_border_width(GTK_CONTAINER(main_vb), 6);

  main_tb = gtk_table_new(2, 2, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 5);

  if (operation == PROF_OPERATION_NEW) {
    label = gtk_label_new("Create from:");
    gtk_tooltips_set_tip (tooltips, label, "All configuration files will be copied from this profile", NULL);
    gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 0, 1);
    gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);

    store = gtk_tree_store_new(3, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);
    combo_box = gtk_combo_box_new_with_model(GTK_TREE_MODEL (store));
    gtk_tooltips_set_tip (tooltips, combo_box, "All configuration files will be copied from this profile", NULL);

    cell = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo_box), cell, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo_box), cell,
                                   "text", 0, "sensitive", 2,
                                   NULL);

    gtk_tree_store_append(store, &iter, NULL);
    gtk_tree_store_set(store, &iter, 0, "", 1, FALSE, 2, TRUE, -1);

    if (has_global) {
      gtk_tree_store_append(store, &parent, NULL);
      gtk_tree_store_set(store, &parent, 0, "Personal", 1, FALSE, 2, FALSE, -1);
    }

    gtk_tree_store_append(store, &iter, has_global ? &parent : NULL);
    gtk_tree_store_set(store, &iter, 0, DEFAULT_PROFILE, 1, FALSE, 2, TRUE, -1);
    profiles_dir = get_profiles_dir();
    if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
      while ((file = ws_dir_read_name(dir)) != NULL) {
	name = ws_dir_get_name(file);
	if (profile_exists(name, FALSE)) {
	  gtk_tree_store_append(store, &iter, has_global ? &parent : NULL);
	  gtk_tree_store_set(store, &iter, 0, name, 1, FALSE, 2, TRUE, -1);
	}
      }
      ws_dir_close (dir);
    }

    if (has_global) {
      gtk_tree_store_append(store, &parent, NULL);
      gtk_tree_store_set(store, &parent, 0, "Global", 1, FALSE, 2, FALSE, -1);
      profiles_dir = get_global_profiles_dir();
      if ((dir = ws_dir_open(profiles_dir, 0, NULL)) != NULL) {
	while ((file = ws_dir_read_name(dir)) != NULL) {
	  name = ws_dir_get_name(file);
	  if (profile_exists(name, TRUE)) {
	    gtk_tree_store_append(store, &iter, &parent);
	    gtk_tree_store_set(store, &iter, 0, name, 1, TRUE, 2, TRUE, -1);
	  }
	}
	ws_dir_close (dir);
      }
    }
    gtk_table_attach_defaults(GTK_TABLE(main_tb), combo_box, 1, 2, 0, 1);
    g_object_unref(store);
  }

  label = gtk_label_new("Profile name:");
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 1, 2);
  gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);

  entry = gtk_entry_new();
  gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, 1, 2);
  switch (operation) {
  case PROF_OPERATION_NEW:
    gtk_entry_set_text(GTK_ENTRY(entry), "New profile");
    break;
  case PROF_OPERATION_EDIT:
    gtk_entry_set_text(GTK_ENTRY(entry), profile_name);
    break;
  default:
    g_assert_not_reached();
    break;
  }
#ifdef _WIN32
  gtk_tooltips_set_tip (tooltips, entry, "A profile name cannot start or end with a period (.), and cannot contain any of the following characters:\n   \\ / : * ? \" < > |", NULL);
#else
  gtk_tooltips_set_tip (tooltips, entry, "A profile name cannot contain the '/' character", NULL);
#endif

  bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

  ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
  g_object_set_data (G_OBJECT(ok_bt), "entry", entry);
  g_object_set_data (G_OBJECT(ok_bt), "create_from", combo_box);
  g_object_set_data (G_OBJECT(ok_bt), "operation", GINT_TO_POINTER(operation));
  g_signal_connect(ok_bt, "clicked", G_CALLBACK(profile_name_edit_ok), win);

  dlg_set_activate(entry, ok_bt);
  gtk_widget_grab_focus(entry);

  cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
  g_signal_connect(cancel_bt, "clicked", G_CALLBACK(profile_name_edit_cancel), win);
  window_set_cancel_button(win, cancel_bt, NULL);

  gtk_widget_grab_default(ok_bt);
  gtk_widget_show_all(win);
}

void
profile_new_cb (GtkWidget *w _U_, gpointer data _U_)
{
  profile_name_edit_dlg (PROF_OPERATION_NEW);
}

void
profile_delete_cb (GtkWidget *w _U_, gpointer data _U_)
{
  const gchar *name = get_profile_name();
  char        *pf_dir_path;

  if (profile_exists(name, FALSE) && strcmp (name, DEFAULT_PROFILE) != 0) {
    if (delete_persconffile_profile(name, &pf_dir_path) == -1) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't delete profile directory\n\"%s\":\n%s.",
		    pf_dir_path, g_strerror(errno));
      
      g_free(pf_dir_path);
    }

    /* Change to the default profile */
    change_configuration_profile (NULL);
  }
}

void
profile_edit_cb (GtkWidget *w _U_, gpointer data _U_)
{
  profile_name_edit_dlg (PROF_OPERATION_EDIT);
}

/* Create a profile dialog for editing display profiles; this is to be used
   as a callback for menu items, toolbars, etc.. */
void
profile_dialog_cb(GtkWidget *w _U_)
{
  /* Has a profiles dialog box already been opened */
  if (global_profile_w != NULL) {
    /* Yes.  Just reactivate it. */
    reactivate_window(global_profile_w);
  } else {
    global_profile_w = profile_dialog_new ();
  }
}

