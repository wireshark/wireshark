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
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <ui/cmdarg_err.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <cli_main.h>
#include <version_info.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>
#include <wsutil/str_util.h>

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include "ui/failure_message.h"

static void
print_usage(FILE *output)
{
  fprintf(output, "\n");
  fprintf(output, "Usage: captype <infile> ...\n");
}

/*
 * General errors and warnings are reported with an console message
 * in captype.
 */
static void
failure_warning_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "captype: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
  char  *init_progfile_dir_error;
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

  /*
   * Set the C-language locale to the native environment and set the
   * code page to UTF-8 on Windows.
   */
#ifdef _WIN32
  setlocale(LC_ALL, ".UTF-8");
#else
  setlocale(LC_ALL, "");
#endif

  cmdarg_err_init(failure_warning_message, failure_message_cont);

  /* Initialize the version information. */
  ws_init_version_info("Captype (Wireshark)", NULL, NULL, NULL);

#ifdef _WIN32
  create_app_running_mutex();
#endif /* _WIN32 */

  /*
   * Get credential information for later use.
   */
  init_process_policies();

  /*
   * Attempt to get the pathname of the directory containing the
   * executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0]);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr,
            "captype: Can't get pathname of directory containing the captype program: %s.\n",
            init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  }

  init_report_message(failure_warning_message, failure_warning_message,
                      NULL, NULL, NULL);

  wtap_init(TRUE);

  /* Process the options */
  while ((opt = getopt_long(argc, argv, "hv", long_options, NULL)) !=-1) {

    switch (opt) {

      case 'h':
        show_help_header("Print the file types of capture files.");
        print_usage(stdout);
        exit(0);
        break;

      case 'v':
        show_version();
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
        cfile_open_failure_message("captype", argv[i], err, err_info);
        overall_error_status = 2; /* remember that an error has occurred */
      }
    }

  }

  wtap_cleanup();
  free_progdirs();
  return overall_error_status;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
