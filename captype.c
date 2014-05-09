/* captype.c
 * Reports capture file type
 *
 * Based on capinfos.c
 * Copyright 2004 Ian Schorr
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <glib.h>

#include <wsutil/privileges.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include "wtap.h"
#include <wsutil/report_err.h>
#include <wsutil/privileges.h>
#include <wsutil/str_util.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */

#include "version.h"

static void
usage(void)
{
  fprintf(stderr, "Captype %s"
#ifdef GITVERSION
      " (" GITVERSION " from " GITBRANCH ")"
#endif
      "\n", VERSION);
  fprintf(stderr, "Prints the file types of capture files.\n");
  fprintf(stderr, "See http://www.wireshark.org for more information.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: captype <infile> ...\n");
}

#ifdef HAVE_PLUGINS
/*
 *  Don't report failures to load plugins because most (non-wiretap) plugins
 *  *should* fail to load (because we're not linked against libwireshark and
 *  dissector plugins need libwireshark).
 */
static void
failure_message(const char *msg_format _U_, va_list ap _U_)
{
  return;
}
#endif

int
main(int argc, char *argv[])
{
  wtap  *wth;
  int    err;
  gchar *err_info;
  int    i;
  int    overall_error_status;

#ifdef HAVE_PLUGINS
  char  *init_progfile_dir_error;
#endif

#ifdef _WIN32
  arg_list_utf_16to8(argc, argv);
  create_app_running_mutex();
#endif /* _WIN32 */

  /*
   * Get credential information for later use.
   */
  init_process_policies();
  init_open_routines();

#ifdef HAVE_PLUGINS
  if ((init_progfile_dir_error = init_progfile_dir(argv[0], main))) {
    g_warning("captype: init_progfile_dir(): %s", init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  } else {
    /* Register all the plugin types we have. */
    wtap_register_plugin_types(); /* Types known to libwiretap */

    init_report_err(failure_message,NULL,NULL,NULL);

    /* Scan for plugins.  This does *not* call their registration routines;
       that's done later. */
    scan_plugins();

    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();
  }
#endif

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  if (argc < 2) {
    usage();
    return 1;
  }

  overall_error_status = 0;

  for (i = 1; i < argc; i++) {
    wth = wtap_open_offline(argv[i], WTAP_TYPE_AUTO, &err, &err_info, FALSE);

    if(wth) {
      printf("%s: %s\n", argv[i], wtap_file_type_subtype_short_string(wtap_file_type_subtype(wth)));
      wtap_close(wth);
    } else {
      if (err == WTAP_ERR_FILE_UNKNOWN_FORMAT)
        printf("%s: unknown\n", argv[i]);
      else {
        fprintf(stderr, "captype: Can't open %s: %s\n", argv[i],
                wtap_strerror(err));
        switch (err) {

        case WTAP_ERR_UNSUPPORTED:
        case WTAP_ERR_UNSUPPORTED_ENCAP:
        case WTAP_ERR_BAD_FILE:
          fprintf(stderr, "(%s)\n", err_info);
          g_free(err_info);
          break;
        }
        overall_error_status = 1; /* remember that an error has occurred */
      }
    }

  }

  return overall_error_status;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
