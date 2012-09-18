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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Wireshark - this file is copied from "The GIMP" V2.0.2
 * You will find the original file in the gimp distribution zip under:
 * \plug-ins\common\webbrowser.c
 *
 * It was modified to suit the Wireshark environment (#if 0)!
 *
 * For the UNIX+X11 launcher, see this blog post:
 *
 * http://blogs.gnome.org/timj/2006/11/24/24112006-how-to-start-a-web-browser/
 *
 * for a discussion of how Beast launches a browser, a link that shows
 * the rather complicated code it uses, and some information on why it
 * goes through all that pain.  See also Kevin Krammer's comment, which
 * notes that the problem might be that the GNOME, KDE, and XFCE
 * launcher programs always cause the window to be opened in the background,
 * regardless of whether an instance of the app is running or not (the
 * app gets launched - in the background - if it's not already running,
 * and is told to open a new window/tab if it's already running), while
 * launchers such as sensible-browser, which xdg-open falls back to,
 * launch the app in the foreground if it's not already running, leading
 * to the "first window is in the foreground, subsequent windows are in
 * the background" behavior in non-GNOME/KDE/XFCE environments.
 *
 * Perhaps the right strategy is to:
 *
 *	Check whether we're in a GNOME/KDE/XFCE session and, if
 *	we are, try xdg-open, as it works around, among other things,
 *	some kfmclient bugs, and run it synchronously (that will fail
 *	if we detect a GNOME/KDE/XFCE session but the launcher is
 *	missing, but so it goes).  If we don't have xdg-open, try
 *	the appropriate launcher for the environment, but ignore
 *	the return code from kfmclient, as it might be bogus (that's
 *	the bug xdg-open works around).
 *
 *	Otherwise, try the "broken/unpredictable browser launchers",
 *	but run them in the background and leave them running, and
 *	ignore the exit code, and then try x-www-browser, and then
 *	try directly launching a user-specified browser.  (Beast tries
 *	a bunch of browsers, with the user not being allowed to
 *	specify which one they want.)
 *
 * On the other hand, see bug 2699, in which xdg-open is itself buggy.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <string.h> /* strlen, strstr */

#include <gtk/gtk.h>

#include <epan/filesystem.h>
#include <epan/prefs.h>

#include "ui/simple_dialog.h"
#include "ui/help_url.h"

#include "ui/gtk/webbrowser.h"

#if defined(G_OS_WIN32)
/* Win32 - use Windows shell services to start a browser */
#include <windows.h>
/* We're using Unicode */
#include <tchar.h>
#include <wsutil/unicode-utils.h>
/* if WIN32_LEAN_AND_MEAN is defined, shellapi.h is needed too */
#include <shellapi.h>
#elif defined (HAVE_OS_X_FRAMEWORKS)
/* Mac OS X - use Launch Services to start a browser */
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
#elif defined(HAVE_XDG_OPEN)
/* UNIX+X11 desktop with Portland Group stuff - use xdg-open to start a browser */
#else
/* Everything else - launch the browser ourselves */
#define MUST_LAUNCH_BROWSER_OURSELVES
#endif

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
  if (url_CFString == NULL)
    return (FALSE);
  url_CFURL = CFURLCreateWithString(NULL, url_CFString, NULL);
  CFRelease(url_CFString);
  if (url_CFURL == NULL) {
    /*
     * XXX - this could mean that the url_CFString wasn't a valid URL,
     * or that memory allocation failed.  We can't determine which,
     * except perhaps by providing our own allocator and somehow
     * flagging allocation failures.
     */
    return (FALSE);
  }
  /*
   * XXX - this is a Launch Services result code, and we should probably
   * display a dialog box if it's not 0, describing what the error was.
   * Then again, we should probably do the same for the ShellExecute call,
   * unless that call itself happens to pop up a dialog box for all errors.
   */
  status = LSOpenCFURLRef(url_CFURL, NULL);
  CFRelease(url_CFURL);
  return (status == 0);

#elif defined(HAVE_XDG_OPEN)

  GError   *error = NULL;
  gchar    *argv[3];
  gboolean  retval;

  g_return_val_if_fail (url != NULL, FALSE);

  argv[0] = "xdg-open";
  argv[1] = (char *)url;	/* Grr - g_spawn_async() shouldn't modify this */
  argv[2] = NULL;

  /*
   * XXX - use g_spawn_on_screen() so the browser window shows up on
   * the same screen?
   */
  retval = g_spawn_async (NULL, argv, NULL,
                          G_SPAWN_SEARCH_PATH,
                          NULL, NULL,
                          NULL, &error);

  if (! retval)
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          "%sCould not execute xdg-open: %s\n\n\"%s\"",
          simple_dialog_primary_start(), simple_dialog_primary_end(),
          error->message);
      g_error_free (error);
    }

  return retval;

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
          "%sCould not parse web browser command: \"%s\"%s\n\n\"%s\"\n\n%s",
          simple_dialog_primary_start(), browser, simple_dialog_primary_end(),
          error->message,
          "Please correct the web browser setting in the Preferences dialog.");
      g_error_free (error);
      return FALSE;
    }

  /*
   * XXX - use g_spawn_on_screen() so the browser window shows up on
   * the same screen?
   */
  retval = g_spawn_async (NULL, argv, NULL,
                          G_SPAWN_SEARCH_PATH,
                          NULL, NULL,
                          NULL, &error);

  if (! retval)
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          "%sCould not execute web browser: \"%s\"%s\n\n\"%s\"\n\n%s",
          simple_dialog_primary_start(), browser, simple_dialog_primary_end(),
          error->message,
          "Please correct the web browser setting in the Preferences dialog.");
      g_error_free (error);
    }

  g_free (browser);
  g_free (cmd);
  g_strfreev (argv);

  return retval;
#endif
}

gboolean
filemanager_open_directory (const gchar *path)
{
#if defined(G_OS_WIN32)
  /* ShellExecute(...,"explore",...) needs path to be explicitly a directory;
     Otherwise 'explore' will fail if a file exists with a basename matching
     the provided directory path.
     (eg: wireshak-gtk2.exe exists in the same directory as  a wireshark-gtk2
          directory entry).
  */
  gint   ret;
  gchar *xpath;
  xpath = g_strconcat(path,
                      g_str_has_suffix(path, "\\") ? "" : "\\",
                      NULL);
  ret = (gint) ShellExecute (HWND_DESKTOP, _T("explore"), utf_8to16(xpath), NULL, NULL, SW_SHOWNORMAL);
  g_free(xpath);
  return (ret > 32);

#elif defined(HAVE_OS_X_FRAMEWORKS)

  CFStringRef path_CFString;
  CFURLRef path_CFURL;
  OSStatus status;

  path_CFString = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
  if (path_CFString == NULL)
    return (FALSE);
  path_CFURL = CFURLCreateWithFileSystemPath(NULL, path_CFString,
                                             kCFURLPOSIXPathStyle, true);
  CFRelease(path_CFString);
  if (path_CFURL == NULL) {
    /*
     * XXX - does this always mean that that memory allocation failed?
     */
    return (FALSE);
  }
  /*
   * XXX - this is a Launch Services result code, and we should probably
   * display a dialog box if it's not 0, describing what the error was.
   * Then again, we should probably do the same for the ShellExecute call,
   * unless that call itself happens to pop up a dialog box for all errors.
   */
  status = LSOpenCFURLRef(path_CFURL, NULL);
  CFRelease(path_CFURL);
  return (status == 0);

#elif defined(HAVE_XDG_OPEN)

  GError   *error = NULL;
  gchar    *argv[3];
  gboolean  retval;

  g_return_val_if_fail (path != NULL, FALSE);

  argv[0] = "xdg-open";
  argv[1] = (char *)path;	/* Grr - g_spawn_async() shouldn't modify this */
  argv[2] = NULL;

  /*
   * XXX - use g_spawn_on_screen() so the file managaer window shows up on
   * the same screen?
   */
  retval = g_spawn_async (NULL, argv, NULL,
                          G_SPAWN_SEARCH_PATH,
                          NULL, NULL,
                          NULL, &error);

  if (! retval)
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          "%sCould not execute xdg-open: %s\n\n\"%s\"",
          simple_dialog_primary_start(), simple_dialog_primary_end(),
          error->message);
      g_error_free (error);
    }

  return retval;

#elif defined(MUST_LAUNCH_BROWSER_OURSELVES)

  GError    *error;
  gchar     *browser;
  gchar     *argument;
  gchar     *cmd;
  gchar    **argv;
  gboolean   retval;

  g_return_val_if_fail (path != NULL, FALSE);

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

  /* conver the path to a URI */
  argument = g_filename_to_uri(path, NULL, &error);
  if (argument == NULL)
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          "%sCould not convert \"%s\" to a URI: \"%s\"%s\"",
          simple_dialog_primary_start(), path, simple_dialog_primary_end(),
          error->message);
      g_error_free (error);
      return FALSE;
    }

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
          "%sCould not parse web browser command: \"%s\"%s\n\n\"%s\"\n\n%s",
          simple_dialog_primary_start(), browser, simple_dialog_primary_end(),
          error->message,
          "Please correct the web browser setting in the Preferences dialog.");
      g_error_free (error);
      return FALSE;
    }

  /*
   * XXX - use g_spawn_on_screen() so the browser window shows up on
   * the same screen?
   */
  retval = g_spawn_async (NULL, argv, NULL,
                          G_SPAWN_SEARCH_PATH,
                          NULL, NULL,
                          NULL, &error);

  if (! retval)
    {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
          "%sCould not execute web browser: \"%s\"%s\n\n\"%s\"\n\n%s",
          simple_dialog_primary_start(), browser, simple_dialog_primary_end(),
          error->message,
          "Please correct the web browser setting in the Preferences dialog.");
      g_error_free (error);
    }

  g_free (browser);
  g_free (cmd);
  g_strfreev (argv);

  return retval;
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


/* browse a file relative to the data dir */
void
browser_open_data_file(const gchar *filename)
{
    gchar *uri;

    /* XXX - check, if the file is really existing, otherwise display a simple_dialog about the problem */

    uri = data_file_url(filename);

    /* show the uri */
    browser_open_url (uri);

    g_free(uri);
}
