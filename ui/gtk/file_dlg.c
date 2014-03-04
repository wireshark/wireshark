/* file_dlg.c
 * Utilities to use when constructing file selection dialogs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Code to handle Windows shortcuts courtesy of:
 *
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2012 Hiroyuki Yamamoto
 *
 * licensed under the GPL2 or later.
 */

#include "config.h"
#include <string.h>
#include <errno.h>

#include <gtk/gtk.h>

#ifdef _WIN32
#  define COBJMACROS
#  include <windows.h>
#  include <objbase.h>
#  include <objidl.h>
#  include <shlobj.h>
#endif

#include <wsutil/file_util.h>

#include <wsutil/filesystem.h>

#include "ui/last_open_dir.h"
#include "ui/util.h"

#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/stock_icons.h"


static gchar *last_open_dir = NULL;
static gboolean updated_last_open_dir = FALSE;

static void file_selection_browse_destroy_cb(GtkWidget *win, GtkWidget* file_te);

/* Keys ... */
#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"

/* Create a file selection dialog box window that belongs to a top-level
   window. */
GtkWidget *
file_selection_new(const gchar *title, GtkWindow *parent,
                   file_selection_action_t action)
{
    GtkWidget *win;
    GtkFileChooserAction gtk_action;
#ifdef _WIN32
    char *u3devicedocumentpath;
#endif
    const gchar *ok_button_text;

    switch (action) {

    case FILE_SELECTION_OPEN:
        gtk_action = GTK_FILE_CHOOSER_ACTION_OPEN;
        ok_button_text = GTK_STOCK_OPEN;
        break;

    case FILE_SELECTION_READ_BROWSE:
        gtk_action = GTK_FILE_CHOOSER_ACTION_OPEN;
        ok_button_text = GTK_STOCK_OK;
        break;

    case FILE_SELECTION_SAVE:
        gtk_action = GTK_FILE_CHOOSER_ACTION_SAVE;
        ok_button_text = WIRESHARK_STOCK_SAVE;
        break;

    case FILE_SELECTION_WRITE_BROWSE:
        gtk_action = GTK_FILE_CHOOSER_ACTION_SAVE;
        ok_button_text = GTK_STOCK_OK;
        break;

    case FILE_SELECTION_CREATE_FOLDER:
        gtk_action = GTK_FILE_CHOOSER_ACTION_CREATE_FOLDER;
        ok_button_text = GTK_STOCK_OK;
        break;

    default:
        g_assert_not_reached();
        gtk_action = (GtkFileChooserAction)-1;
        ok_button_text = NULL;
        break;
    }
    win = gtk_file_chooser_dialog_new(title, parent, gtk_action,
                                      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                      ok_button_text, GTK_RESPONSE_ACCEPT,
                                      NULL);
    gtk_dialog_set_alternative_button_order(GTK_DIALOG(win),
                                            GTK_RESPONSE_ACCEPT,
                                            GTK_RESPONSE_CANCEL,
                                            -1);
    if (action == FILE_SELECTION_SAVE)
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(win), TRUE);

    /* If we've opened a file before, start out by showing the files in the directory
       in which that file resided. */
    if (last_open_dir)
        file_selection_set_current_folder(win, last_open_dir);
#ifdef _WIN32
    else {
        u3devicedocumentpath = getenv_utf8("U3_DEVICE_DOCUMENT_PATH");
        if(u3devicedocumentpath != NULL)
            file_selection_set_current_folder(win, u3devicedocumentpath);

    }
#endif
    return win;
}

/* Set the current folder for a file selection dialog. */
gboolean
file_selection_set_current_folder(GtkWidget *fs, const gchar *filename)
{
    gboolean ret;
    size_t filename_len = strlen(filename);
    gchar *new_filename;

    /* trim filename, so gtk_file_chooser_set_current_folder() likes it, see below */
    if (filename[filename_len -1] == G_DIR_SEPARATOR
#ifdef _WIN32
        && filename_len > 3)    /* e.g. "D:\" */
#else
        && filename_len > 1)    /* e.g. "/" */
#endif
    {
        new_filename = g_strdup(filename);
        new_filename[filename_len-1] = '\0';
    } else {
        new_filename = g_strdup(filename);
    }

    /* this function is very pedantic about its filename parameter */
    /* no trailing '\' allowed, unless a win32 root dir "D:\" */
    ret = gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(fs), new_filename);
    g_free(new_filename);
    return ret;
}

/* Set the "extra" widget for a file selection dialog, with user-supplied
   options. */
void
file_selection_set_extra_widget(GtkWidget *fs, GtkWidget *extra)
{
  gtk_file_chooser_set_extra_widget(GTK_FILE_CHOOSER(fs), extra);
}

#ifdef _WIN32
static gchar *filesel_get_link(const gchar *link_file)
{
  WIN32_FIND_DATAW wfd;
  IShellLinkW *psl;
  IPersistFile *ppf;
  wchar_t *wlink_file;
  wchar_t wtarget[MAX_PATH];
  gchar *target = NULL;

  wtarget[0] = 0L;

  CoInitialize(NULL);
  if (S_OK == CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                               &IID_IShellLinkW, (void **)&psl)) {
    if (S_OK == IShellLinkW_QueryInterface(psl, &IID_IPersistFile,
                                           (void **)&ppf)) {
      wlink_file = g_utf8_to_utf16(link_file, -1, NULL, NULL, NULL);
      if (S_OK == IPersistFile_Load(ppf, wlink_file, STGM_READ)) {
        if (S_OK == IShellLinkW_GetPath(psl, wtarget, MAX_PATH, &wfd,
                                        SLGP_UNCPRIORITY)) {
          target = g_utf16_to_utf8(wtarget, -1, NULL, NULL, NULL);
        }
      }
      IPersistFile_Release(ppf);
      g_free(wlink_file);
    }
    IShellLinkW_Release(psl);
  }
  CoUninitialize();

  return target;
}
#endif /* _WIN32 */

/* Run the dialog, and handle some common operations, such as, if the
   user selects a directory, browsing that directory, and handling
   shortcuts on Windows.

   Returns NULL if the user decided not to open/write to a file,
   returns the pathname of the selected file if they selected a
   file. */
gchar *
file_selection_run(GtkWidget *fs)
{
  gchar *cf_name;
#ifdef _WIN32
  gchar *target;
  const gchar *ext;
#endif

  for (;;) {
    if (gtk_dialog_run(GTK_DIALOG(fs)) != GTK_RESPONSE_ACCEPT) {
      /* They clicked "Cancel" or closed the dialog or...;
         destroy the dialog and tell our caller the user decided
         not to do anything with the file. */
      window_destroy(fs);
      return NULL;
    }

    cf_name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs));

    /* Perhaps the user specified a directory instead of a file.
       Check whether they did. */
    if (test_for_directory(cf_name) == EISDIR) {
      /* It's a directory - set the file selection box to display that
         directory, and go back and re-run it; don't try to open the
         directory as a file (you'll get crap if you get anything) or
         write to it (which won't work anyway). */
      set_last_open_dir(cf_name);
      g_free(cf_name);
      file_selection_set_current_folder(fs, get_last_open_dir());
      continue;
    }

#ifdef _WIN32
    /* Perhaps the user specified a "shortcut" instead of a file.
       Check whether they did. */
    if ((ext = strrchr(cf_name, '.')) && g_ascii_strcasecmp(ext, ".lnk") == 0) {
      /* It ends with ".lnk", so it might be a shortcut. */
      target = filesel_get_link(cf_name);
      if (target != NULL) {
        /* We resolved it, so it must've been a shortcut. */
        g_free(cf_name);
        if (test_for_directory(target)) {
          /* It's a shortcut that points to a directory; treat it the same
             way we treat a directory. */
          set_last_open_dir(target);
          g_free(target);
          file_selection_set_current_folder(fs, get_last_open_dir());
          continue;
        }
        /* It's a shortcut that points to a file; act as if the target
           is what's selected. */
        cf_name = target;
      }
    }
#endif
    break;
  }

  return cf_name;
}

#ifndef _WIN32
/* If the specified file doesn't exist, return TRUE.
   If it exists and is neither user-immutable nor not writable, return
   TRUE.
   Otherwise, as the user whether they want to overwrite it anyway, and
   return TRUE if the file should be overwritten and FALSE otherwise. */
gboolean
file_target_unwritable_ui(GtkWidget *chooser_w, char *cf_name)
{
  GtkWidget     *msg_dialog;
  gchar         *display_basename;
  gint           response;
  ws_statb64     statbuf;

  /* Check whether the file has all the write permission bits clear
     and, on systems that have the 4.4-Lite file flags, whether it
     has the "user immutable" flag set.  Treat both of those as an
     indication that the user wants to protect the file from
     casual overwriting, and ask the user if they want to override
     that.

     (Linux's "immutable" flag, as fetched and set by the appropriate
     ioctls (FS_IOC_GETFLAGS/FS_IOC_SETFLAGS in newer kernels,
     EXT2_IOC_GETFLAGS/EXT2_IOC_SETFLAGS in older kernels - non-ext2
     file systems that support those ioctls use the same values as ext2
     does), appears to be more like the *BSD/OS X "system immutable"
     flag, as it can be set only by the superuser or by processes with
     CAP_LINUX_IMMUTABLE, so it sounds as if it's not intended for
     arbitrary users to set or clear. */
  if (ws_stat64(cf_name, &statbuf) == -1) {
    /* Either the file doesn't exist or we can't get its attributes.
       In the former case, we have no reason to bother the user.
       In the latter case, we don't have enough information to
       know whether to bother the user, so we don't. */
    return TRUE;
  }

  /* OK, we have the permission bits and, if HAVE_ST_FLAGS is defined,
     the flags.  (If we don't, we don't worry about it.) */
#ifdef HAVE_ST_FLAGS
  if (statbuf.st_flags & UF_IMMUTABLE) {
    display_basename = g_filename_display_basename(cf_name);
    msg_dialog = gtk_message_dialog_new(GTK_WINDOW(chooser_w),
                                        (GtkDialogFlags)(GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT),
                                        GTK_MESSAGE_QUESTION,
                                        GTK_BUTTONS_NONE,
#ifdef __APPLE__
    /* Stuff in the OS X UI calls files with the "user immutable" bit
       "locked"; pre-OS X Mac software might have had that notion and
       called it "locked". */
                                        "The file \"%s\" is locked.",
#else /* __APPLE__ */
    /* Just call it "immutable" in *BSD. */
                                        "The file \"%s\" is immutable.",
#endif /* __APPLE__ */
                                        display_basename);
    g_free(display_basename);
  } else
#endif /* HAVE_ST_FLAGS */
  if ((statbuf.st_mode & (S_IWUSR|S_IWGRP|S_IWOTH)) == 0) {
    display_basename = g_filename_display_basename(cf_name);
    msg_dialog = gtk_message_dialog_new(GTK_WINDOW(chooser_w),
                                        (GtkDialogFlags)(GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT),
                                        GTK_MESSAGE_QUESTION,
                                        GTK_BUTTONS_NONE,
                                        "The file \"%s\" is read-only.",
                                        display_basename);
    g_free(display_basename);
  } else {
    /* No problem, just drive on. */
    msg_dialog = NULL;
  }
  if (msg_dialog != NULL) {
    /* OK, ask the user if they want to overwrite the file. */
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg_dialog),
        "Do you want to overwrite it anyway?");

    gtk_dialog_add_buttons(GTK_DIALOG(msg_dialog),
                           "Overwrite", GTK_RESPONSE_ACCEPT,
                           "Don't overwrite", GTK_RESPONSE_REJECT,
                           NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(msg_dialog), GTK_RESPONSE_REJECT);

    response = gtk_dialog_run(GTK_DIALOG(msg_dialog));
    gtk_widget_destroy(msg_dialog);

    if (response != GTK_RESPONSE_ACCEPT) {
      /* The user doesn't want to overwrite this file. */
      return FALSE;
    }

#ifdef HAVE_ST_FLAGS
    /* OK, they want to overwrite the file.  If it has the "user
       immutable" flag, we have to turn that off first, so we
       can move on top of, or overwrite, the file. */
    if (statbuf.st_flags & UF_IMMUTABLE) {
      /* If this fails, the attempt to save will fail, so just
         let that happen and pop up a "you lose" dialog. */
      chflags(cf_name, statbuf.st_flags & ~UF_IMMUTABLE);
    }
#endif
  }
  return TRUE;
}
#endif

/*
 * A generic select_file routine that is intended to be connected to
 * a Browse button on other dialog boxes. This allows the user to browse
 * for a file and select it. We fill in the text_entry that is given to us.
 *
 * We display the window label specified in our args.
 */
void
file_selection_browse(GtkWidget *file_bt, GtkWidget *file_te, const char *label, file_selection_action_t action)
{
    GtkWidget *caller = gtk_widget_get_toplevel(file_bt);
    GtkWidget *fs;
    gchar     *f_name;

    fs = file_selection_new(label, GTK_WINDOW(caller), action);

    g_object_set_data(G_OBJECT(fs), PRINT_FILE_TE_KEY, file_te);

    /* Set the E_FS_CALLER_PTR_KEY for the new dialog to point to our caller. */
    g_object_set_data(G_OBJECT(fs), E_FS_CALLER_PTR_KEY, caller);

    /* Set the E_FILE_SEL_DIALOG_PTR_KEY for the caller to point to us */
    g_object_set_data(G_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY, fs);

    /* Call a handler when the file selection box is destroyed, so we can inform
       our caller, if any, that it's been destroyed. */
    g_signal_connect(fs, "destroy", G_CALLBACK(file_selection_browse_destroy_cb),
                     file_te);

    if (gtk_dialog_run(GTK_DIALOG(fs)) == GTK_RESPONSE_ACCEPT)
    {
        f_name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs));
        gtk_entry_set_text(GTK_ENTRY(file_te), f_name);
        g_free(f_name);
    }
    window_destroy(fs);
}


static void
file_selection_browse_destroy_cb(GtkWidget *win, GtkWidget* parent_te)
{
    GtkWidget *caller;

    /* Get the widget that requested that we be popped up.
       (It should arrange to destroy us if it's destroyed, so
       that we don't get a pointer to a non-existent window here.) */
    caller = (GtkWidget *)g_object_get_data(G_OBJECT(win), E_FS_CALLER_PTR_KEY);

    /* Tell it we no longer exist. */
    g_object_set_data(G_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY, NULL);

    /* Give the focus to the file text entry widget so the user can just press
       Return to print to the file. */
    gtk_widget_grab_focus(parent_te);
}


void
set_last_open_dir(const char *dirname)
{
    size_t len;
    gchar *new_last_open_dir;

    if (dirname) {
        len = strlen(dirname);
        if (dirname[len-1] == G_DIR_SEPARATOR) {
            new_last_open_dir = g_strconcat(dirname, NULL);
        }
        else {
            new_last_open_dir = g_strconcat(dirname,
                                            G_DIR_SEPARATOR_S, NULL);
        }

        if (last_open_dir == NULL ||
            strcmp(last_open_dir, new_last_open_dir) != 0)
            updated_last_open_dir = TRUE;
    }
    else {
        new_last_open_dir = NULL;
        if (last_open_dir != NULL)
            updated_last_open_dir = TRUE;
    }

    g_free(last_open_dir);
    last_open_dir = new_last_open_dir;
}

char *
get_last_open_dir(void)
{
    return last_open_dir;
}
