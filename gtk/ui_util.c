/* ui_util.c
 * UI utility routines
 *
 * $Id: ui_util.c,v 1.18 2004/02/06 19:19:11 ulfl Exp $
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

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef HAVE_IO_H
# include <io.h>
#endif

#include <gtk/gtk.h>

#include "gtkglobals.h"
#include "ui_util.h"
#include "prefs.h"
#include "epan/epan.h"
#include "../ui_util.h"
#include "compat_macros.h"

#include "image/eicon3d16.xpm"


/* Set the name of the top-level window and its icon to the specified
   string. */
void
set_main_window_name(gchar *window_name)
{
  gtk_window_set_title(GTK_WINDOW(top_level), window_name);
  gdk_window_set_icon_name(top_level->window, window_name);
}


#ifdef HAVE_LIBPCAP

/* update the main window */
void main_window_update(void)
{
  while (gtk_events_pending()) gtk_main_iteration();
}

/* exit the main window */
void main_window_exit(void)
{
  gtk_exit(0);
}

/* quit a nested main window */
void main_window_nested_quit(void)
{
  if (gtk_main_level() > 0)
    gtk_main_quit();
}

/* quit the main window */
void main_window_quit(void)
{
  gtk_main_quit();
}




typedef struct pipe_input_tag {
    gint                source;
    gpointer            user_data;
    int                 *child_process;
    pipe_input_cb_t     input_cb;
    guint               pipe_input_id;
} pipe_input_t;


#ifdef _WIN32
/* The timer has expired, see if there's stuff to read from the pipe,
   if so, do the callback */
static gint
pipe_timer_cb(gpointer data)
{
  HANDLE handle;
  DWORD avail = 0;
  gboolean result, result1;
  DWORD childstatus;
  pipe_input_t *pipe_input = data;


  /* Oddly enough although Named pipes don't work on win9x,
     PeekNamedPipe does !!! */
  handle = (HANDLE) _get_osfhandle (pipe_input->source);
  result = PeekNamedPipe(handle, NULL, 0, NULL, &avail, NULL);

  /* Get the child process exit status */
  result1 = GetExitCodeProcess((HANDLE)*(pipe_input->child_process),
                               &childstatus);

  /* If the Peek returned an error, or there are bytes to be read
     or the childwatcher thread has terminated then call the normal
     callback */
  if (!result || avail > 0 || childstatus != STILL_ACTIVE) {

    /* avoid reentrancy problems and stack overflow */
    gtk_timeout_remove(pipe_input->pipe_input_id);

    /* And call the real handler */
    if (pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
        /* restore pipe handler */
        pipe_input->pipe_input_id = gtk_timeout_add(200, pipe_timer_cb, data);
    }

    /* Return false so that this timer is not run again */
    return FALSE;
  }
  else {
    /* No data so let timer run again */
    return TRUE;
  }
}

#else /* _WIN32 */

/* There's stuff to read from the sync pipe, meaning the child has sent
   us a message, or the sync pipe has closed, meaning the child has
   closed it (perhaps because it exited). */
static void
pipe_input_cb(gpointer data, gint source _U_,
  GdkInputCondition condition _U_)
{
  pipe_input_t *pipe_input = data;


  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(pipe_input->pipe_input_id);

  if (pipe_input->input_cb(source, pipe_input->user_data)) {
    /* restore pipe handler */
    pipe_input->pipe_input_id = gtk_input_add_full (source,
				     GDK_INPUT_READ|GDK_INPUT_EXCEPTION,
				     pipe_input_cb,
				     NULL,
				     data,
				     NULL);
  }
}
#endif

void pipe_input_set_handler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb)
{
    static pipe_input_t pipe_input;

    pipe_input.source        = source;
    pipe_input.child_process = child_process;
    pipe_input.user_data     = user_data;
    pipe_input.input_cb      = input_cb;

#ifdef _WIN32
    /* Tricky to use pipes in win9x, as no concept of wait.  NT can
       do this but that doesn't cover all win32 platforms.  GTK can do
       this but doesn't seem to work over processes.  Attempt to do
       something similar here, start a timer and check for data on every
       timeout. */
    pipe_input.pipe_input_id = gtk_timeout_add(200, pipe_timer_cb, &pipe_input);
#else
    pipe_input.pipe_input_id = gtk_input_add_full(source,
				      GDK_INPUT_READ|GDK_INPUT_EXCEPTION,
				      pipe_input_cb,
				      NULL,
				      &pipe_input,
				      NULL);
#endif
}


#endif /* HAVE_LIBPCAP */

/* Given a pointer to a GtkWidget for a top-level window, raise it and
   de-iconify it.  This routine is used if the user has done something to
   ask that a window of a certain type be popped up when there can be only
   one such window and such a window has already been popped up - we
   pop up the existing one rather than creating a new one.

   XXX - we should request that it be given the input focus, too.  Alas,
   GDK has nothing to do that, e.g. by calling "XSetInputFocus()" in a
   window in X.  Besides, using "XSetInputFocus()" doesn't work anyway,
   apparently due to the way GTK+/GDK manages the input focus.

   The X Desktop Group's Window Manager Standard specifies, in the section
   on Root Window Properties, an _NET_ACTIVE_WINDOW client message that
   can be sent to the root window, containing the window ID of the
   window to activate; I infer that this might be the way to give the
   window the input focus - I assume that means it's also de-iconified,
   but I wouldn't assume it'd raise it.

   XXX - will this do the right thing on window systems other than X? */
void
reactivate_window(GtkWidget *win)
{
  gdk_window_show(win->window);
  gdk_window_raise(win->window);
}

/* Set our window icon.  The GDK documentation doesn't provide any
   actual documentation for gdk_window_set_icon(), so we'll steal
   libgimp/gimpdialog.c:gimp_dialog_realize_callback() from the Gimp
   sources and assume it's safe.

   XXX - The current icon size is fixed at 16x16 pixels, which looks fine
   with kwm (KDE 1.x's window manager), Sawfish (the "default" window
   manager for GNOME?), and under Windows with Exceed putting X windows
   on the Windows desktop, using Exceed as the window manager, as those
   window managers put a 16x16 icon on the title bar.

   The window managers in some windowing environments (e.g. dtwm in CDE)
   and some stand-alone window managers have larger icon sizes (many window
   managers put the window icon on the desktop, in the Windows 3.x style,
   rather than in the titlebar, in the Windows 4.x style), so we need to
   find a way to size our icon appropriately.

   The X11 Inter-Client Communications Conventions Manual, Version 1.1,
   in X11R5, specifies that "a window manager that wishes to place
   constraints on the sizes of icon pixmaps and/or windows should
   place a property called WM_ICON_SIZE on the root"; that property
   contains minimum width and height, maximum width and height, and
   width and height increment values.  "XGetIconSizes()" retrieves
   that property; unfortunately, I've yet to find a window manager
   that sets it on the root window (kwm, AfterStep, and Exceed don't
   appear to set it).

   The X Desktop Group's Window Manager Standard specifies, in the section
   on Application Window Properties, an _NET_WM_ICON property, presumably
   set by the window manager, which is an array of possible icon sizes
   for the client.  There's no API in GTK+ 1.2[.x] for this; there may
   eventually be one either in GTK+ 2.0 or GNOME 2.0.

   Some window managers can be configured to take the window name
   specified by the WM_NAME property of a window or the resource
   or class name specified by the WM_CLASS property and base the
   choice of icon for the window on one of those; WM_CLASS for
   Ethereal's windows has a resource name of "ethereal" and a class
   name of "Ethereal".  However, the way that's done is window-manager-
   specific, and there's no way to determine what size a particular
   window manager would want, so there's no way to automate this as
   part of the installation of Ethereal.
   */
void
window_icon_realize_cb (GtkWidget *win, gpointer data _U_)
{
#ifndef WIN32
  static GdkPixmap *icon_pmap = NULL;
  static GdkBitmap *icon_mask = NULL;
  GtkStyle         *style;

  style = gtk_widget_get_style (win);

  if (icon_pmap == NULL) {
    icon_pmap = gdk_pixmap_create_from_xpm_d (win->window,
		&icon_mask, &style->bg[GTK_STATE_NORMAL], eicon3d16_xpm);
  }

  gdk_window_set_icon (win->window, NULL, icon_pmap, icon_mask);
#endif
}

/* List of all GtkScrolledWindows, so we can globally set the scrollbar
   placement of all of them. */
static GList *scrolled_windows;

static void setup_scrolled_window(GtkWidget *scrollw);
static void forget_scrolled_window(GtkWidget *scrollw, gpointer data);
static void set_scrollbar_placement_scrollw(GtkWidget *scrollw);

/* Create a GtkScrolledWindow, set its scrollbar placement appropriately,
   and remember it. */
GtkWidget *
scrolled_window_new(GtkAdjustment *hadjustment, GtkAdjustment *vadjustment)
{
  GtkWidget *scrollw;

  scrollw = gtk_scrolled_window_new(hadjustment, vadjustment);
  setup_scrolled_window(scrollw);
  return scrollw;
}

/* Set a GtkScrolledWindow's scrollbar placement and add it to the list
   of GtkScrolledWindows. */
static void
setup_scrolled_window(GtkWidget *scrollw)
{
  set_scrollbar_placement_scrollw(scrollw);

  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

  scrolled_windows = g_list_append(scrolled_windows, scrollw);

  /* Catch the "destroy" event on the widget, so that we remove it from
     the list when it's destroyed. */
  SIGNAL_CONNECT(scrollw, "destroy", forget_scrolled_window, NULL);
}

/* Remove a GtkScrolledWindow from the list of GtkScrolledWindows. */
static void
forget_scrolled_window(GtkWidget *scrollw, gpointer data _U_)
{
  scrolled_windows = g_list_remove(scrolled_windows, scrollw);
}

/* Set the scrollbar placement of a GtkScrolledWindow based upon user
   preference. */
static void
set_scrollbar_placement_scrollw(GtkWidget *scrollw)
{
  if (prefs.gui_scrollbar_on_right) {
    gtk_scrolled_window_set_placement(GTK_SCROLLED_WINDOW(scrollw),
				      GTK_CORNER_TOP_LEFT);
  } else {
    gtk_scrolled_window_set_placement(GTK_SCROLLED_WINDOW(scrollw),
				      GTK_CORNER_TOP_RIGHT);
  }
}

static void
set_scrollbar_placement_cb(gpointer data, gpointer user_data _U_)
{
  set_scrollbar_placement_scrollw((GtkWidget *)data);
}

/* Set the scrollbar placement of all GtkScrolledWindows based on
   user preference. */
void
set_scrollbar_placement_all(void)
{
  g_list_foreach(scrolled_windows, set_scrollbar_placement_cb, NULL);
}

/* List of all CTrees/TreeViews, so we can globally set the line and
 * expander style of all of them. */
static GList *trees;

static void setup_tree(GtkWidget *tree);
static void forget_tree(GtkWidget *tree, gpointer data);
static void set_tree_styles(GtkWidget *tree);

/* Create a Tree, give it the right styles, and remember it. */
#if GTK_MAJOR_VERSION < 2
GtkWidget *
ctree_new(gint columns, gint tree_column)
#else
GtkWidget *
tree_view_new(GtkTreeModel *model)
#endif
{
  GtkWidget *tree;

#if GTK_MAJOR_VERSION < 2
  tree = gtk_ctree_new(columns, tree_column);
#else
  tree = gtk_tree_view_new_with_model(model);
#endif
  setup_tree(tree);
  return tree;
}

#if GTK_MAJOR_VERSION < 2
GtkWidget *
ctree_new_with_titles(gint columns, gint tree_column, gchar *titles[])
{
  GtkWidget *tree;

  tree = gtk_ctree_new_with_titles(columns, tree_column, titles);
  setup_tree(tree);
  return tree;
}
#endif

/* Set a Tree's styles and add it to the list of Trees. */
static void
setup_tree(GtkWidget *tree)
{
  set_tree_styles(tree);

  trees = g_list_append(trees, tree);

  /* Catch the "destroy" event on the widget, so that we remove it from
     the list when it's destroyed. */
  SIGNAL_CONNECT(tree, "destroy", forget_tree, NULL);
}

/* Remove a Tree from the list of Trees. */
static void
forget_tree(GtkWidget *tree, gpointer data _U_)
{
  trees = g_list_remove(trees, tree);
}

/* Set the styles of a Tree based upon user preferences. */
static void
set_tree_styles(GtkWidget *tree)
{
#if GTK_MAJOR_VERSION < 2
  g_assert(prefs.gui_ptree_line_style >= GTK_CTREE_LINES_NONE &&
	   prefs.gui_ptree_line_style <= GTK_CTREE_LINES_TABBED);
  gtk_ctree_set_line_style(GTK_CTREE(tree), prefs.gui_ptree_line_style);
  g_assert(prefs.gui_ptree_expander_style >= GTK_CTREE_EXPANDER_NONE &&
	   prefs.gui_ptree_expander_style <= GTK_CTREE_EXPANDER_CIRCULAR);
  gtk_ctree_set_expander_style(GTK_CTREE(tree),
      prefs.gui_ptree_expander_style);
#else
  g_assert(prefs.gui_altern_colors >= 0 && prefs.gui_altern_colors <= 1);
  gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(tree),
                               prefs.gui_altern_colors);
#endif
}

static void
set_tree_styles_cb(gpointer data, gpointer user_data _U_)
{
  set_tree_styles((GtkWidget *)data);
}

/* Set the styles of all Trees based upon style values. */
void
set_tree_styles_all(void)
{
  g_list_foreach(trees, set_tree_styles_cb, NULL);
}
