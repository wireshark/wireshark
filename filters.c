/* filters.c
 * Code for reading and writing the filters file.
 *
 * $Id: filters.c,v 1.2 2001/01/28 04:52:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include <ctype.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <epan.h>

#include "filters.h"
#include "util.h"

#define	FILTER_LINE_SIZE	2048

/*
 * List of filters.
 */
GList       *fl = NULL;

void
get_filter_list(void)
{
  GList      *flp;
  filter_def *filt;
  FILE       *ff;
  gchar      *ff_path, *ff_name = PF_DIR "/filters", f_buf[FILTER_LINE_SIZE];
  gchar      *name_begin, *name_end, *filt_begin;
  int         len, line = 0;

  /* If we already have a list of filters, discard it. */
  if (fl != NULL) {
    flp = g_list_first(fl);
    while (flp) {
      filt = (filter_def *) flp->data;
      g_free(filt->name);
      g_free(filt->strval);
      g_free(filt);
      flp = flp->next;
    }
    g_list_free(fl);
    fl = NULL;
  }

  /* To do: generalize this */
  ff_path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(ff_name) +  4);
  sprintf(ff_path, "%s/%s", get_home_dir(), ff_name);

  if ((ff = fopen(ff_path, "r")) == NULL) {
    g_free(ff_path);
    return;
  }

  while (fgets(f_buf, FILTER_LINE_SIZE, ff)) {
    line++;
    len = strlen(f_buf);
    if (f_buf[len - 1] == '\n') {
      len--;
      f_buf[len] = '\0';
    }
    name_begin = strchr(f_buf, '"');
    /* Empty line */
    if (name_begin == NULL)
      continue;
    name_end = strchr(name_begin + 1, '"');
    /* No terminating quote */
    if (name_end == NULL) {
      g_warning("Malformed filter in '%s' line %d.", ff_path, line);
      continue;
    }
    name_begin++;
    name_end[0] = '\0';
    filt_begin  = name_end + 1;
    while(isspace((guchar)filt_begin[0])) filt_begin++;
    /* No filter string */
    if (filt_begin[0] == '\0') {
      g_warning("Malformed filter in '%s' line %d.", ff_path, line);
      continue;
    }
    filt         = (filter_def *) g_malloc(sizeof(filter_def));
    filt->name   = g_strdup(name_begin);
    filt->strval = g_strdup(filt_begin);
    fl = g_list_append(fl, filt);
  }
  fclose(ff);
  g_free(ff_path);
}

void
save_filter_list(void)
{
  GList      *flp;
  filter_def *filt;
  gchar      *ff_path, *ff_dir = PF_DIR, *ff_name = "filters";
  FILE       *ff;
  struct stat s_buf;
  
  ff_path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(ff_dir) +  
    strlen(ff_name) + 4);
  sprintf(ff_path, "%s/%s", get_home_dir(), ff_dir);

  if (stat(ff_path, &s_buf) != 0)
#ifdef WIN32
    mkdir(ff_path);
#else
    mkdir(ff_path, 0755);
#endif
    
  sprintf(ff_path, "%s/%s/%s", get_home_dir(), ff_dir, ff_name);

  if ((ff = fopen(ff_path, "w")) != NULL) {
    flp = g_list_first(fl);
    while (flp) {
      filt = (filter_def *) flp->data;
      fprintf(ff, "\"%s\" %s\n", filt->name, filt->strval);
      flp = flp->next;
    }
    fclose(ff);
  }

  g_free(ff_path);
}
