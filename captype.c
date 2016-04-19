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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>
#include <errno.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <glib.h>

#include <wiretap/wtap.h>

#include <wsutil/crash_info.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <ws_version_info.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_err.h>
#include <wsutil/str_util.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

static void
print_usage(FILE *output)
{
  fprintf(output, "\n");
  fprintf(output, "Usage: captype <infile> ...\n");
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
  GString *comp_info_str;
  GString *runtime_info_str;
  wtap  *wth;
  int    err;
  gchar *err_info;
  int    i;
  int    opt;
  int    overall_error_status;
  static const struct option long_options[] = {
      {"help", no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 'v'},
      {0, 0, 0, 0 }
  };

#ifdef HAVE_PLUGINS
  char  *init_progfile_dir_error;
#endif

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  /* Get the compile-time version information string */
  comp_info_str = get_compiled_version_info(NULL, NULL);

  /* Get the run-time version information string */
  runtime_info_str = get_runtime_version_info(NULL);

  /* Add it to the information to be reported on a crash. */
  ws_add_crash_info("Captype (Wireshark) %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);

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

  /* Process the options */
  while ((opt = getopt_long(argc, argv, "hv", long_options, NULL)) !=-1) {

    switch (opt) {

      case 'h':
        printf("Captype (Wireshark) %s\n"
               "Print the file types of capture files.\n"
               "See https://www.wireshark.org for more information.\n",
               get_ws_vcs_version_info());
        print_usage(stdout);
        exit(0);
        break;

      case 'v':
        show_version("Captype (Wireshark)", comp_info_str, runtime_info_str);
        g_string_free(comp_info_str, TRUE);
        g_string_free(runtime_info_str, TRUE);
        exit(0);
        break;

      case '?':              /* Bad flag - print usage message */
        print_usage(stderr);
        exit(1);
        break;
    }
  }

  if (argc < 2) {
    print_usage(stderr);
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
        if (err_info != NULL) {
          fprintf(stderr, "(%s)\n", err_info);
          g_free(err_info);
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
