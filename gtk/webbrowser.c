/* The GIMP -- an image manipulation program
 * Copyright (C) 1995 Spencer Kimball and Peter Mattis
 *
 * Web Browser Plug-in
 * Copyright (C) 2003  Henrik Brix Andersen <brix@gimp.org>
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

/* Ethereal - this file is copied from "The GIMP" V2.0.2
 * You will find the original file in the gimp distribution zip under:
 * \plug-ins\common\webbrowser.c
 *
 * It was modified to suit the Ethereal environment (#if 0)!
 */

#include "config.h"

#include <string.h> /* strlen, strstr */

#include <glib.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif



#ifndef G_OS_WIN32
static gchar*   strreplace       (const gchar      *string,
                                  const gchar      *delimiter,
                                  const gchar      *replacement);
#endif


gboolean
browser_open_url (const gchar *url)
{
#ifdef G_OS_WIN32

  return ((gint) ShellExecute (HWND_DESKTOP, "open", url, NULL, NULL, SW_SHOWNORMAL) > 32);

#else

  GError    *error = NULL;
  gchar     *browser;
  gchar     *argument;
  gchar     *cmd;
  gchar    **argv;
  gboolean   retval;

  g_return_val_if_fail (url != NULL, FALSE);

/*  browser = gimp_gimprc_query ("web-browser");*/
  browser = g_strdup("mozilla %s");

  if (browser == NULL || ! strlen (browser))
    {
      g_message (("Web browser not specified.\n"
                   "Please specify a web browser using the Preferences Dialog."));
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
      g_message (("Could not parse specified web browser command:\n%s"),
                 error->message);
      g_error_free (error);
      return FALSE;
    }

  retval = g_spawn_async (NULL, argv, NULL,
                          G_SPAWN_SEARCH_PATH,
                          NULL, NULL,
                          NULL, &error);

  if (! retval)
    {
      g_message (("Could not execute specified web browser:\n%s"),
                 error->message);
      g_error_free (error);
    }

  g_free (browser);
  g_free (cmd);
  g_strfreev (argv);

  return retval;

#endif
}

#ifndef G_OS_WIN32

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

#endif /* !G_OS_WIN32 */
