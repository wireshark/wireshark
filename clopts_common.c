/* clopts_common.c
 * Handle command-line arguments common to Ethereal and Tethereal
 *
 * $Id$
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

#include <stdio.h>
#include <string.h>

#include <epan/proto.h>

#include "clopts_common.h"

/*
 * Handle the "-G" option, to cause protocol field, etc. information
 * to be printed.
 */
void
handle_dashG_option(int argc, char **argv, char *progname)
{
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    if (argc == 2)
      proto_registrar_dump_fields(1);
    else {
      if (strcmp(argv[2], "fields") == 0)
        proto_registrar_dump_fields(1);
      else if (strcmp(argv[2], "fields2") == 0)
        proto_registrar_dump_fields(2);
      else if (strcmp(argv[2], "protocols") == 0)
        proto_registrar_dump_protocols();
      else if (strcmp(argv[2], "values") == 0)
        proto_registrar_dump_values();
      else {
        fprintf(stderr, "%s: Invalid \"%s\" option for -G flag\n", progname,
                argv[2]);
        exit(1);
      }
    }
    exit(0);
  }
}
