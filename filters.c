/* filters.c
 * Code for reading and writing the filters file.
 *
 * $Id: filters.c,v 1.4 2001/01/28 22:28:31 guy Exp $
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
#include <errno.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>		/* to declare "mkdir()" on Windows */
#endif

#include <glib.h>

#include <epan.h>

#include "filters.h"
#include "util.h"

/*
 * Old filter file name.
 */
#define FILTER_FILE_NAME	"filters"

/*
 * Capture filter file name.
 */
#define CFILTER_FILE_NAME	"cfilters"

/*
 * Display filter file name.
 */
#define DFILTER_FILE_NAME	"dfilters"

#define	FILTER_LINE_SIZE	2048

/*
 * List of capture filters.
 */
static GList *capture_filters = NULL;

/*
 * List of display filters.
 */
static GList *display_filters = NULL;

/*
 * Read in a list of filters.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
void
read_filter_list(filter_list_type_t list, char **pref_path_return,
    int *errno_return)
{
  char       *ff_path, *ff_dir = PF_DIR, *ff_name;
  FILE       *ff;
  GList      **flp;
  GList      *fl_ent;
  filter_def *filt;
  char       f_buf[FILTER_LINE_SIZE];
  char       *name_begin, *name_end, *filt_begin;
  int         len, line = 0;

  *pref_path_return = NULL;	/* assume no error */

  switch (list) {

  case CFILTER_LIST:
    ff_name = CFILTER_FILE_NAME;
    flp = &capture_filters;
    break;

  case DFILTER_LIST:
    ff_name = DFILTER_FILE_NAME;
    flp = &display_filters;
    break;

  default:
    g_assert_not_reached();
    return;
  }

  /* To do: generalize this */
  ff_path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(ff_dir) +  
    strlen(ff_name) + 4);
  sprintf(ff_path, "%s/%s/%s", get_home_dir(), ff_dir, ff_name);

  if ((ff = fopen(ff_path, "r")) == NULL) {
    /*
     * Did that fail because we the file didn't exist?
     */
    if (errno != ENOENT) {
      /*
       * No.  Just give up.
       */
      *pref_path_return = ff_path;
      *errno_return = errno;
      return;
    }

    /*
     * Yes.  See if there's a "filters" file; if so, read it.
     * This means that a user will start out with their capture and
     * display filter lists being identical; each list may contain
     * filters that don't belong in that list.  The user can edit
     * the filter lists, and delete the ones that don't belong in
     * a particular list.
     */
    sprintf(ff_path, "%s/%s/%s", get_home_dir(), ff_dir, FILTER_FILE_NAME);
    if ((ff = fopen(ff_path, "r")) == NULL) {
      /*
       * Well, that didn't work, either.  Just give up.
       * Return an error if the file existed but we couldn't open it.
       */
      if (errno != ENOENT) {
	*pref_path_return = ff_path;
	*errno_return = errno;
      }
      return;
    }
  }

  /* If we already have a list of filters, discard it. */
  if (*flp != NULL) {
    fl_ent = g_list_first(*flp);
    while (fl_ent != NULL) {
      filt = (filter_def *) fl_ent->data;
      g_free(filt->name);
      g_free(filt->strval);
      g_free(filt);
      fl_ent = fl_ent->next;
    }
    g_list_free(*flp);
    *flp = NULL;
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
    *flp = g_list_append(*flp, filt);
  }
  if (ferror(ff)) {
    *pref_path_return = ff_path;
    *errno_return = errno;
  } else
    g_free(ff_path);
  fclose(ff);
}

/*
 * Get a pointer to a list of filters.
 */
static GList **
get_filter_list(filter_list_type_t list)
{
  GList **flp;

  switch (list) {

  case CFILTER_LIST:
    flp = &capture_filters;
    break;

  case DFILTER_LIST:
    flp = &display_filters;
    break;

  default:
    g_assert_not_reached();
    flp = NULL;
  }
  return flp;
}

/*
 * Get a pointer to the first entry in a filter list.
 */
GList *
get_filter_list_first(filter_list_type_t list)
{
  GList      **flp;
  
  flp = get_filter_list(list);
  return g_list_first(*flp);
}

/*
 * Add a new filter to the end of a list.
 * Returns a pointer to the newly-added entry.
 */
GList *
add_to_filter_list(filter_list_type_t list, char *name, char *expression)
{
  GList      **flp;
  filter_def *filt;
  
  flp = get_filter_list(list);
  filt = (filter_def *) g_malloc(sizeof(filter_def));
  filt->name = g_strdup(name);
  filt->strval = g_strdup(expression);
  *flp = g_list_append(*flp, filt);
  return g_list_last(*flp);
}

/*
 * Remove a filter from a list.
 */
void
remove_from_filter_list(filter_list_type_t list, GList *fl_entry)
{
  GList      **flp;
  filter_def *filt;
  
  flp = get_filter_list(list);
  filt = (filter_def *) fl_entry->data;
  g_free(filt->name);
  g_free(filt->strval);
  g_free(filt);
  *flp = g_list_remove_link(*flp, fl_entry);
}

/*
 * Write out a list of filters.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
void
save_filter_list(filter_list_type_t list, char **pref_path_return,
    int *errno_return)
{
  gchar      *ff_path, *ff_path_new, *ff_dir = PF_DIR, *ff_name;
  int         path_length;
  GList      *fl;
  GList      *flp;
  filter_def *filt;
  FILE       *ff;
  struct stat s_buf;
  
  *pref_path_return = NULL;	/* assume no error */

  switch (list) {

  case CFILTER_LIST:
    ff_name = CFILTER_FILE_NAME;
    fl = capture_filters;
    break;

  case DFILTER_LIST:
    ff_name = DFILTER_FILE_NAME;
    fl = display_filters;
    break;

  default:
    g_assert_not_reached();
    return;
  }

  path_length = strlen(get_home_dir()) + strlen(ff_dir) + strlen(ff_name)
  		+ 4 + 4;
  ff_path = (gchar *) g_malloc(path_length);
  sprintf(ff_path, "%s/%s", get_home_dir(), ff_dir);

  if (stat(ff_path, &s_buf) != 0)
#ifdef WIN32
    mkdir(ff_path);
#else
    mkdir(ff_path, 0755);
#endif
    
  sprintf(ff_path, "%s/%s/%s", get_home_dir(), ff_dir, ff_name);

  /* Write to "XXX.new", and rename if that succeeds.
     That means we don't trash the file if we fail to write it out
     completely. */
  ff_path_new = (gchar *) g_malloc(path_length);
  sprintf(ff_path_new, "%s/%s/%s.new", get_home_dir(), ff_dir, ff_name);

  if ((ff = fopen(ff_path_new, "w")) == NULL) {
    *pref_path_return = ff_path;
    *errno_return = errno;
    g_free(ff_path_new);
    return;
  }
  flp = g_list_first(fl);
  while (flp) {
    filt = (filter_def *) flp->data;
    fprintf(ff, "\"%s\" %s\n", filt->name, filt->strval);
    if (ferror(ff)) {
      *pref_path_return = ff_path;
      *errno_return = errno;
      fclose(ff);
      unlink(ff_path_new);
      g_free(ff_path_new);
      return;
    }
    flp = flp->next;
  }
  if (fclose(ff) == EOF) {
    *pref_path_return = ff_path;
    *errno_return = errno;
    unlink(ff_path_new);
    g_free(ff_path_new);
    return;
  }

  /* XXX - does "rename()" exist on Win32?  If so, does it remove the
     target first?  If so, does that mean it's not atomic? */
  if (rename(ff_path_new, ff_path) < 0) {
    *pref_path_return = ff_path;
    *errno_return = errno;
    unlink(ff_path_new);
    g_free(ff_path);
    g_free(ff_path_new);
    return;
  }
  g_free(ff_path_new);
  g_free(ff_path);
}
