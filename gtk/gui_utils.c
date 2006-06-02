/* gui_utils.c
 * UI utility routines, some GTK+-specific (declared in gtk/gui_utils.h)
 * and some with GUI-independent APIs, with this file containing the GTK+
 * implementations of them (declared in ui_util.h)
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

#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif


#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include "file_util.h"
#include "gtkglobals.h"
#include "gui_utils.h"
#include <epan/prefs.h>
#include "epan/epan.h"
#include "../ui_util.h"
#include "compat_macros.h"
#include "recent.h"


#include "image/wsicon16.xpm"

/* XXX - remove this later again, when dlg_xx function cleanup done */
#include "dlg_utils.h"


#define WINDOW_GEOM_KEY "window_geom"


/* load the geometry values for a window from previously saved values */
static gboolean window_geom_load(const gchar *name, window_geometry_t *geom);



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
   Wireshark's windows has a resource name of "ethereal" and a class
   name of "Wireshark".  However, the way that's done is window-manager-
   specific, and there's no way to determine what size a particular
   window manager would want, so there's no way to automate this as
   part of the installation of Wireshark.
   */
static void
window_icon_realize_cb (GtkWidget *win, gpointer data _U_)
{
#ifndef _WIN32
  static GdkPixmap *icon_pmap = NULL;
  static GdkBitmap *icon_mask = NULL;
  GtkStyle         *style;

  style = gtk_widget_get_style (win);

  if (icon_pmap == NULL) {
    icon_pmap = gdk_pixmap_create_from_xpm_d (win->window,
		&icon_mask, &style->bg[GTK_STATE_NORMAL], wsicon16_xpm);
  }

  gdk_window_set_icon (win->window, NULL, icon_pmap, icon_mask);
#endif
}


/* Create a new window, of the specified type, with the specified title
   (if any) and the Wireshark icon. */
GtkWidget *
window_new(GtkWindowType type, const gchar *title)
{
  GtkWidget *win;

  win = gtk_window_new(type);
  if (title != NULL)
    gtk_window_set_title(GTK_WINDOW(win), title);
  SIGNAL_CONNECT(win, "realize", window_icon_realize_cb, NULL);

  /* XXX - which one is the correct default policy? or use a preference for this? */
  /* GTK_WIN_POS_NONE, GTK_WIN_POS_CENTER or GTK_WIN_POS_MOUSE */
  /* a lot of people dislike GTK_WIN_POS_MOUSE */

  /* set the initial position (must be done, before show is called!) */
#if GTK_MAJOR_VERSION >= 2 	 
/*  gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER_ON_PARENT);*/
#else	 
/*  gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);*/
#endif
  gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_NONE);

#if GTK_MAJOR_VERSION < 2
  /* allow window to be shrinked by user, as gtk_widget_set_usize() will set minimum size and */
  /* the user never could shrink the window again */
  gtk_window_set_policy(GTK_WINDOW(win), TRUE, TRUE, FALSE);
#endif

  return win;
}


/* Same as window_new(), but will keep it's geometry values (size, position, ...).
 * Be sure to use window_present() and window_destroy() appropriately! */
GtkWidget *
window_new_with_geom(GtkWindowType type, const gchar *title, const gchar *geom_name)
{
  window_geometry_t geom;
  GtkWidget *win = window_new(type, title);

  OBJECT_SET_DATA(win, WINDOW_GEOM_KEY, (gpointer)g_strdup(geom_name));

  /* do we have a previously saved size and position of this window? */
  if(geom_name) {
    /* It's a good idea to set the position and size of the window already here,
     * as it's still invisible and won't "flicker the screen" while initially resizing. */
    if(window_geom_load(geom_name, &geom)) {
      /* XXX - use prefs to select which values to set? */
      geom.set_pos        = TRUE;
      geom.set_size       = TRUE;
      geom.set_maximized  = FALSE;  /* don't maximize until window is shown */
      window_set_geometry(win, &geom);
    }
  }

  return win;
}


#if GTK_MAJOR_VERSION < 2
/* We can't set the decorations until the window is realized. */
static void
window_notitle_realize_cb (GtkWidget *win, gpointer data _U_)
{
  gdk_window_set_decorations(win->window, 0);
}
#endif


/* Create a new window for a splash screen; it's a main window, with no title,
   positioned in the center of the screen. */
GtkWidget *
splash_window_new(void)
{
  GtkWidget *win;

  win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#if GTK_MAJOR_VERSION >= 2
  gtk_window_set_decorated(GTK_WINDOW(win), FALSE);
#else
  SIGNAL_CONNECT(win, "realize", window_notitle_realize_cb, NULL);
#endif

  /* set the initial position (must be done, before show is called!) */
  gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);

  return win;
}


/* Present the created window on the screen. */
void
window_present(GtkWidget *win)
{
  window_geometry_t geom;
  const gchar *name;

#if GTK_MAJOR_VERSION >= 2
  /* present this window */
  gtk_window_present(GTK_WINDOW(win));
#endif

  /* do we have a previously saved size and position of this window? */
  name = OBJECT_GET_DATA(win, WINDOW_GEOM_KEY);
  if(name) {
    if(window_geom_load(name, &geom)) {
      /* XXX - use prefs to select which values to set? */
      geom.set_pos        = TRUE;
      geom.set_size       = TRUE;
      geom.set_maximized  = TRUE;
      window_set_geometry(win, &geom);
    }
  }
}


static gint
window_key_press_cb (GtkWidget *widget, GdkEventKey *event, gpointer cancel_button)
{
  g_return_val_if_fail (widget != NULL, FALSE);
  g_return_val_if_fail (event != NULL, FALSE);

  if (event->keyval == GDK_Escape) {
    gtk_widget_activate(GTK_WIDGET(cancel_button));
    return TRUE;
  }

  return FALSE;
}


/* Set the "key_press_event" signal for a top-level dialog window to
   call a routine to activate the "Cancel" button for a dialog box if
   the key being pressed is the <Esc> key.

   XXX - there should be a GTK+ widget that'll do that for you, and
   let you specify a "Cancel" button.  It should also not impose
   a requirement that there be a separator in the dialog box, as
   the GtkDialog widget does; the visual convention that there's
   such a separator between the rest of the dialog boxes and buttons
   such as "OK" and "Cancel" is, for better or worse, not universal
   (not even in GTK+ - look at the GtkFileSelection dialog!). */
static void
window_set_cancel(GtkWidget *widget, GtkWidget *cancel_button)
{
  SIGNAL_CONNECT(widget, "key_press_event", window_key_press_cb, cancel_button);
}


/* set the actions needed for the cancel "Close"/"Ok"/"Cancel" button that closes the window */
void window_set_cancel_button(GtkWidget *win, GtkWidget *bt, window_cancel_button_fct cb)
{
  if(cb)
    SIGNAL_CONNECT(bt, "clicked", cb, win);

  gtk_widget_grab_default(bt);

  window_set_cancel(win, bt);
}


/* default callback handler for cancel button "clicked" signal */
void window_cancel_button_cb(GtkWidget *w _U_, gpointer data)
{
  window_destroy(GTK_WIDGET(data));
}


/* default callback handler: the window managers X of the window was clicked (delete_event) */
gboolean
window_delete_event_cb(GtkWidget *win, GdkEvent *event _U_, gpointer user_data _U_)
{
    window_destroy(win);

    /* event handled, don't do anything else */
    return TRUE;
}


/* get the geometry of a window from window_new() */
void
window_get_geometry(GtkWidget *widget, window_geometry_t *geom)
{
	gint desk_x, desk_y;
#if GTK_MAJOR_VERSION >= 2
    GdkWindowState state;
#endif

	/* Try to grab our geometry.

	   GTK+ provides two routines to get a window's position relative
	   to the X root window.  If I understand the documentation correctly,
	   gdk_window_get_deskrelative_origin applies mainly to Enlightenment
	   and gdk_window_get_root_origin applies for all other WMs.

	   The code below tries both routines, and picks the one that returns
	   the upper-left-most coordinates.

	   More info at:

	http://mail.gnome.org/archives/gtk-devel-list/2001-March/msg00289.html
	http://www.gtk.org/faq/#AEN606
    */

	gdk_window_get_root_origin(widget->window, 
        &geom->x, 
        &geom->y);
	if (gdk_window_get_deskrelative_origin(widget->window,
				&desk_x, &desk_y)) {
		if (desk_x <= geom->x && 
            desk_y <= geom->y)
        {
			geom->x = desk_x;
			geom->y = desk_y;
		}
	}

	/* XXX - Is this the "approved" method? */
	gdk_window_get_size(widget->window, 
        &geom->width, 
        &geom->height);

#if GTK_MAJOR_VERSION >= 2
    state = gdk_window_get_state(widget->window);
    geom->maximized = (state == GDK_WINDOW_STATE_MAXIMIZED);
#endif
}


/* set the geometry of a window from window_new() */
void
window_set_geometry(GtkWidget *widget, window_geometry_t *geom)
{
    /* as we now have the geometry from the recent file, set it */
    if (geom->set_pos) {
#if GTK_MAJOR_VERSION >= 2
        gtk_window_move(GTK_WINDOW(widget),
                        geom->x,
                        geom->y);
#else
        gtk_widget_set_uposition(widget,
                                 geom->x,
                                 geom->y);
#endif
    }

    if (geom->set_size) {
#if GTK_MAJOR_VERSION >= 2
        gtk_window_resize(GTK_WINDOW(widget),
#else
        gtk_window_set_default_size(GTK_WINDOW(widget), 
                                geom->width, 
                                geom->height);
        gtk_widget_set_usize(widget,
#endif
        /*WIDGET_SET_SIZE(widget,*/
                                geom->width,
                                geom->height);
    }

#if GTK_MAJOR_VERSION >= 2
    if(geom->set_maximized) {
        if (geom->maximized) {
            gdk_window_maximize(widget->window);
        } else {
            gdk_window_unmaximize(widget->window);
        }
    }
#endif
}


/* the geometry hashtable for all known window classes,
 * the window name is the key, and the geometry struct is the value */
GHashTable *window_geom_hash = NULL;


/* save the window and it's current geometry into the geometry hashtable */
static void
window_geom_save(const gchar *name, window_geometry_t *geom)
{
    gchar *key;
    window_geometry_t *work;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }
    /* if we have an old one, remove and free it first */
    work = g_hash_table_lookup(window_geom_hash, name);
    if(work) {
        g_hash_table_remove(window_geom_hash, name);
        g_free(work->key);
        g_free(work);
    }

    /* g_malloc and insert the new one */
    work = g_malloc(sizeof(*geom));
    *work = *geom;
    key = g_strdup(name);
    work->key = key;
    g_hash_table_insert(window_geom_hash, key, work);
}


/* load the desired geometry for this window from the geometry hashtable */
static gboolean
window_geom_load(const gchar *name, window_geometry_t *geom)
{
    window_geometry_t *p;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }

    p = g_hash_table_lookup(window_geom_hash, name);
    if(p) {
        *geom = *p;
        return TRUE;
    } else {
        return FALSE;
    }
}


/* read in a single key value pair from the recent file into the geometry hashtable */
void
window_geom_recent_read_pair(const char *name, const char *key, const char *value)
{
    window_geometry_t geom;


    /* find window geometry maybe already in hashtable */
    if(!window_geom_load(name, &geom)) {
        /* not in table, init geom with "basic" values */
        geom.key        = g_strdup(name);
        geom.set_pos    = FALSE;
        geom.x          = -1;
        geom.y          = -1;
        geom.set_size   = FALSE;
        geom.width      = -1;
        geom.height     = -1;

        geom.set_maximized = FALSE;/* this is valid in GTK2 only */
        geom.maximized  = FALSE;   /* this is valid in GTK2 only */
    }
    
    if (strcmp(key, "x") == 0) {
        geom.x = strtol(value, NULL, 10);
        geom.set_pos = TRUE;
    } else if (strcmp(key, "y") == 0) {
        geom.y = strtol(value, NULL, 10);
        geom.set_pos = TRUE;
    } else if (strcmp(key, "width") == 0) {
        geom.width = strtol(value, NULL, 10);
        geom.set_size = TRUE;
    } else if (strcmp(key, "height") == 0) {
        geom.height = strtol(value, NULL, 10);
        geom.set_size = TRUE;
    } else if (strcmp(key, "maximized") == 0) {
        if (strcasecmp(value, "true") == 0) {
            geom.maximized = TRUE;
        }
        else {
            geom.maximized = FALSE;
        }
        geom.set_maximized = TRUE;
    } else {
        g_assert_not_reached();
    }

    /* save / replace geometry in hashtable */
    window_geom_save(name, &geom);
}


/* write all geometry values of all windows from the hashtable to the recent file */
void
window_geom_recent_write_all(gpointer rf)
{
    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }

    g_hash_table_foreach(window_geom_hash, write_recent_geom, rf);
}


void
window_destroy(GtkWidget *win)
{
  window_geometry_t geom;
  const gchar *name;

  /* get_geometry must be done *before* destroy is running, as the window geometry
   * cannot be retrieved at destroy time (so don't use event "destroy" for this) */
  /* ...and don't do this at all, if we currently have no GdkWindow (e.g. if the 
   * GtkWidget is hidden) */
  if(!GTK_WIDGET_NO_WINDOW(win) && GTK_WIDGET_VISIBLE(win)) {
      window_get_geometry(win, &geom);

      name = OBJECT_GET_DATA(win, WINDOW_GEOM_KEY);
      if(name) {
        window_geom_save(name, &geom);
        g_free((gpointer)name);
      }
  }

  gtk_widget_destroy(win);
}


/* convert an xpm to a GtkWidget, using the window settings from it's parent */
/* (be sure that the parent window is already being displayed) */
GtkWidget *xpm_to_widget_from_parent(GtkWidget *parent, const char ** xpm) {
#if GTK_MAJOR_VERSION < 2
    GdkPixmap *icon;
    GdkBitmap * mask;


    icon = gdk_pixmap_create_from_xpm_d(parent->window, &mask, &parent->style->white, (char **) xpm);
    return gtk_pixmap_new(icon, mask);
#else
    GdkPixbuf * pixbuf;
    GdkPixmap * pixmap;
    GdkBitmap * bitmap;


    pixbuf = gdk_pixbuf_new_from_xpm_data(xpm);
    gdk_pixbuf_render_pixmap_and_mask_for_colormap (pixbuf, gtk_widget_get_colormap(parent), &pixmap, &bitmap, 128);

    return gtk_image_new_from_pixmap (pixmap, bitmap);
#endif
}


/* convert an xpm to a GtkWidget, using the top_level window settings */
/* (be sure that the top_level window is already being displayed) */
GtkWidget *xpm_to_widget(const char ** xpm) {
    return xpm_to_widget_from_parent(top_level, xpm);
}


/* Set the name of the top-level window and its icon to the specified
   string. */
void
set_main_window_name(gchar *window_name)
{
  gchar *title;

  /* use user-defined window title if preference is set */
  title = create_user_window_title(window_name);
  gtk_window_set_title(GTK_WINDOW(top_level), title);
  gdk_window_set_icon_name(top_level->window, title);
  g_free(title);
}


/* update the main window */
void main_window_update(void)
{
  while (gtk_events_pending()) gtk_main_iteration();
}

#ifdef HAVE_LIBPCAP

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
  gint iterations = 0;


  /* try to read data from the pipe only 5 times, to avoid blocking */
  while(iterations < 5) {
	  /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: new iteration");*/

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

		/*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: data avail");*/

		if(pipe_input->pipe_input_id != 0) {
		  /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: stop timer");*/
		  /* avoid reentrancy problems and stack overflow */
		  gtk_timeout_remove(pipe_input->pipe_input_id);
		  pipe_input->pipe_input_id = 0;
		}

		/* And call the real handler */
		if (!pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
			g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: input pipe closed, iterations: %u", iterations);
			/* pipe closed, return false so that the old timer is not run again */
			return FALSE;
		}
	  }
	  else {
		/*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: no data avail");*/
		/* No data, stop now */
		break;
	  }

	  iterations++;
  }

  if(pipe_input->pipe_input_id == 0) {
	/* restore pipe handler */
	pipe_input->pipe_input_id = gtk_timeout_add(200, pipe_timer_cb, data);
	/*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: finished with iterations: %u, new timer", iterations);*/

	/* Return false so that the old timer is not run again */
	return FALSE;
  } else {
	/*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: finished with iterations: %u, old timer", iterations);*/

	/* we didn't stopped the old timer, so let it run */
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
	/*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/
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
ctree_new_with_titles(gint columns, gint tree_column, const gchar *titles[])
{
  GtkWidget *tree;

  tree = gtk_ctree_new_with_titles(columns, tree_column, (gchar **) titles);
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




#if GTK_MAJOR_VERSION < 2
/* convert variable argument list of values to array of strings (GTK2 -> GTK1) */
static void
simple_list_convert(gchar **ent, va_list ap)
{
    int i;
    char *s;

    while( (i = va_arg(ap, int)) != -1 ) {
        s = va_arg(ap, char *);
        ent[i] = s;
    }
}
#endif


/* append a row to the simple list */
/* use it like: simple_list_append(list, 0, "first", 1, "second", -1) */
void
simple_list_append(GtkWidget *list, ...)
{
    va_list ap;

#if GTK_MAJOR_VERSION < 2
    gchar      *ent[10];               /* new entry added in clist */
#else
    GtkTreeIter iter;
    GtkListStore *store;
#endif

    va_start(ap, list);
#if GTK_MAJOR_VERSION < 2
    simple_list_convert(ent, ap);
    gtk_clist_append(GTK_CLIST(list), ent);
#else
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
    gtk_list_store_append(store, &iter);
    gtk_list_store_set_valist(store, &iter, ap);
#endif
    va_end(ap);
}

/* create a simple list widget */
GtkWidget *
simple_list_new(gint cols, const gchar **titles) {
    GtkWidget *plugins_list;
#if GTK_MAJOR_VERSION >= 2
    int i;
    GtkListStore *store;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
#endif


#if GTK_MAJOR_VERSION < 2
    plugins_list = gtk_clist_new_with_titles(cols, (gchar **) titles);
    gtk_clist_set_selection_mode(GTK_CLIST(plugins_list), GTK_SELECTION_SINGLE);
    gtk_clist_column_titles_passive(GTK_CLIST(plugins_list));
    if(titles) {
        gtk_clist_column_titles_show(GTK_CLIST(plugins_list));
    } else {
        gtk_clist_column_titles_hide(GTK_CLIST(plugins_list));
    }
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_list), 0, TRUE);
    gtk_clist_set_column_auto_resize(GTK_CLIST(plugins_list), 1, TRUE);
#else
    g_assert(cols <= 10);
    store = gtk_list_store_new(cols,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    plugins_list = tree_view_new(GTK_TREE_MODEL(store));
    g_object_unref(G_OBJECT(store));
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(plugins_list), (titles != NULL));
    for(i=0; i<cols; i++) {
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes(titles ? titles[i] : "", renderer,
                                                          "text", i, NULL);
        gtk_tree_view_column_set_sort_column_id(column, i);
        gtk_tree_view_append_column(GTK_TREE_VIEW(plugins_list), column);
    }
#endif

    return plugins_list;
}

void
copy_to_clipboard(GString *str)  
{
#if (GTK_MAJOR_VERSION >= 2)
        GtkClipboard    *cb;

      	cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);     /* Get the default clipboard */
	gtk_clipboard_set_text(cb, str->str, -1);            /* Copy the byte data into the clipboard */
#else
        GtkWidget *window;
        GtkWidget *text;

        window = window_new (GTK_WINDOW_TOPLEVEL,"");
        text = gtk_text_new (NULL, NULL);                 /* Create the GtkText widget */
        gtk_container_add (GTK_CONTAINER (window), text); /* Avoid a GTK assertion */
        gtk_widget_realize (text);   /* Realizing a widget creates a window for it, ready for us to insert some text */
        gtk_text_insert (GTK_TEXT (text), NULL, NULL, NULL, str->str, -1);
        gtk_editable_select_region((GtkEditable *)text, 0, -1); /* Select ALL text */
        gtk_editable_copy_clipboard((GtkEditable *)text); /* Copy the byte data into the clipboard */
#endif
}

/*
 * Create a new window title string with user-defined title preference.
 * (Or ignore it if unspecified).
 */
gchar *
create_user_window_title(const gchar *caption)
{
	/* fail-safe */
	if (caption == NULL)
		return g_strdup("");

	/* no user-defined title specified */
	if ((prefs.gui_window_title == NULL) || (*prefs.gui_window_title == '\0'))
		return g_strdup(caption);

	return g_strdup_printf("%s %s", prefs.gui_window_title, caption);
}
