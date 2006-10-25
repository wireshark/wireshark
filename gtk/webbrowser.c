/* The GIMP -- an image manipulation program
 * Copyright (C) 1995 Spencer Kimball and Peter Mattis
 *
 * Web Browser Plug-in
 * Copyright (C) 2003  Henrik Brix Andersen <brix@gimp.org>
 *
 * $Id$
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* Wireshark - this file is copied from "The GIMP" V2.0.2
 * You will find the original file in the gimp distribution zip under:
 * \plug-ins\common\webbrowser.c
 *
 * It was modified to suit the Wireshark environment (#if 0)!
 */

#include "config.h"

#include <string.h> /* strlen, strstr */

#include <gtk/gtk.h>

#include <epan/filesystem.h>

#include <epan/prefs.h>
#include "webbrowser.h"
#include "compat_macros.h"
#include "simple_dialog.h"

/*
 * For GNOME 2.x, we might be able to use "gnome_url_show()" (when we offer
 * the ability to build a GNOMEified Wireshark as well as a GTK+-only
 * Wireshark).
 */

#if defined(G_OS_WIN32)
/* Win32 - use Windows shell services to start a browser */
#include <windows.h>
/* We're using Unicode */
#include <tchar.h>
#include <epan/unicode-utils.h>
/* if WIN32_LEAN_AND_MEAN is defined, shellapi.h is needed too */
#include <shellapi.h>
#elif defined (HAVE_OS_X_FRAMEWORKS)
/* Mac OS X - use Launch Services to start a browser */
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
#else
/* Everything else - launch the browser ourselves */
#define MUST_LAUNCH_BROWSER_OURSELVES
#endif

/*
 * XXX - we use GLib 2.x routines to launch the browser ourselves, so we
 * can't do it if we're using GLib 1.2[.x].
 */
#ifdef MUST_LAUNCH_BROWSER_OURSELVES
#if (GLIB_MAJOR_VERSION < 2)
#undef MUST_LAUNCH_BROWSER_OURSELVES	/* *can't* launch browser ourselves */
#endif /* (GLIB_MAJOR_VERSION < 2) */
#endif /* MUST_LAUNCH_BROWSER_OURSELVES */

#ifdef MUST_LAUNCH_BROWSER_OURSELVES
static gchar*   strreplace       (const gchar      *string,
                                  const gchar      *delimiter,
                                  const gchar      *replacement);
#endif

gboolean
browser_needs_pref(void)
{
#ifdef MUST_LAUNCH_BROWSER_OURSELVES
    return TRUE;
#else
    return FALSE;
#endif
}


gboolean
browser_open_url (const gchar *url)
{
#if defined(G_OS_WIN32)

  return ((gint) ShellExecute (HWND_DESKTOP, _T("open"), utf_8to16(url), NULL, NULL, SW_SHOWNORMAL) > 32);

#elif defined(HAVE_OS_X_FRAMEWORKS)

  CFStringRef url_CFString;
  CFURLRef url_CFURL;
  OSStatus status;

  /*
   * XXX - if URLs passed to "browser_open_url()" contain non-ASCII
   * characters, we'd have to choose an appropriate value from the
   * CFStringEncodings enum.
   */
  url_CFString = CFStringCreateWithCString(NULL, url, kCFStringEncodingASCII);
  url_CFURL = CFURLCreateWithString(NULL, url_CFString, NULL);
  /*
   * XXX - this is a Launch Services result code, and we should probably
   * display a dialog box if it's not 0, describing what the error was.
   * Then again, we should probably do the same for the ShellExecute call,
   * unless that call itself happens to pop up a dialog box for all errors.
   */
  status = LSOpenCFURLRef(url_CFURL, NULL);
  CFRelease(url_CFURL);
  CFRelease(url_CFString);
  return (status == 0);

#elif defined(MUST_LAUNCH_BROWSER_OURSELVES)

  GError    *error = NULL;
  gchar     *browser;
  gchar     *argument;
  gchar     *cmd;
  gchar    **argv;
  gboolean   retval;

  g_return_val_if_fail (url != NULL, FALSE);

  /*  browser = gimp_gimprc_query ("web-browser");*/
  browser = g_strdup(prefs.gui_webbrowser);

  if (browser == NULL || ! strlen (browser))
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          "Web browser not specified.\n"
          "Please correct the web browser setting in the Preferences dialog.");
      g_free (browser);
      return FALSE;
    }

  /* quote the url since it might contains special chars */
  argument = g_shell_quote (url);

  /* replace %s with URL */
  if (strstr (browser, "%s"))
    cmd = strreplace (browser, "%s", argument);
  else
    cmd = g_strconcat (browser, " ", argument, NULL);

  g_free (argument);

  /* parse the cmd line */
  if (! g_shell_parse_argv (cmd, NULL, &argv, &error))
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          PRIMARY_TEXT_START "Could not parse web browser command: \"%s\"" PRIMARY_TEXT_END
          "\n\n\"%s\"\n\n%s",
          browser, error->message,
          "Please correct the web browser setting in the Preferences dialog.");
      g_error_free (error);
      return FALSE;
    }

  retval = g_spawn_async (NULL, argv, NULL,
                          G_SPAWN_SEARCH_PATH,
                          NULL, NULL,
                          NULL, &error);

  if (! retval)
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          PRIMARY_TEXT_START "Could not execute web browser: \"%s\"" PRIMARY_TEXT_END
          "\n\n\"%s\"\n\n%s",
          browser, error->message,
          "Please correct the web browser setting in the Preferences dialog.");
      g_error_free (error);
    }

  g_free (browser);
  g_free (cmd);
  g_strfreev (argv);

  return retval;

#else
  /* GLIB version 1.x doesn't support the functions used above,
     so simply do nothing for now, to be able to compile.
     XXX - has to be improved */
  simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
      PRIMARY_TEXT_START "Web browser access not implemented." PRIMARY_TEXT_END
      "\n\nThis Wireshark version (using the GLib 1.x toolkit) can't access web browsers. "
      "\n\nYou may try to open the following URL in your web browser: \n\n"
      "%s",
      url);
  return FALSE;
#endif
}

#ifdef MUST_LAUNCH_BROWSER_OURSELVES

static gchar*
strreplace (const gchar *string,
            const gchar *delimiter,
            const gchar *replacement)
{
  gchar  *ret;
  gchar **tmp;

  g_return_val_if_fail (string != NULL, NULL);
  g_return_val_if_fail (delimiter != NULL, NULL);
  g_return_val_if_fail (replacement != NULL, NULL);

  tmp = g_strsplit (string, delimiter, 0);
  ret = g_strjoinv (replacement, tmp);
  g_strfreev (tmp);

  return ret;
}

#endif /* MUST_LAUNCH_BROWSER_OURSELVES */

/** Convert local absolute path to uri.
 *
 * @param filename to (absolute pathed) filename to convert
 * @return a newly allocated uri, you must g_free it later
 */
static gchar *
filename2uri(gchar *filename)
{
    int i = 0;
    gchar *file_tmp;
    GString *filestr;


    filestr = g_string_sized_new(200);

    /* this escaping is somewhat slow but should working fine */
    for(i=0; filename[i]; i++) {
        switch(filename[i]) {
        case(' '):
            g_string_append(filestr, "%20");
            break;
        case('%'):
            g_string_append(filestr, "%%");
            break;
        case('\\'):
            g_string_append_c(filestr, '/');
            break;
            /* XXX - which other chars need to be escaped? */
        default:
            g_string_append_c(filestr, filename[i]);
        }
    }


    /* prepend URI header "file:" appropriate for the system */
#ifdef G_OS_WIN32
    /* XXX - how do we handle UNC names (e.g. //servername/sharename/dir1/dir2/capture-file.cap) */
    g_string_prepend(filestr, "file:///");
#else
    g_string_prepend(filestr, "file://");
#endif

    file_tmp = filestr->str;

    g_string_free(filestr, FALSE /* don't free segment data */);

    return file_tmp;
}

/* browse a file relative to the data dir */
void
browser_open_data_file(const gchar *filename)
{
    gchar *file_path;
    gchar *uri;

    /* build filename */
    file_path = g_strdup_printf("%s/%s", get_datafile_dir(), filename);

    /* XXX - check, if the file is really existing, otherwise display a simple_dialog about the problem */

    /* convert filename to uri */
    uri = filename2uri(file_path);

    /* show the uri */
    browser_open_url (uri);

    g_free(file_path);
    g_free(uri);
}
