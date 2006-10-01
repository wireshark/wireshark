/* filters.c
 * Code for reading and writing the filters file.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <epan/filesystem.h>

#include "filters.h"
#include "file_util.h"

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

/*
 * List of capture filters - saved.
 */
static GList *capture_filters = NULL;

/*
 * List of display filters - saved.
 */
static GList *display_filters = NULL;

/*
 * List of capture filters - currently edited.
 */
static GList *capture_edited_filters = NULL;

/*
 * List of display filters - currently edited.
 */
static GList *display_edited_filters = NULL;

/*
 * Read in a list of filters.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */

#define INIT_BUF_SIZE	128

GList *
add_filter_entry(GList *fl, const char *filt_name, const char *filt_expr)
{
    filter_def *filt;

    filt         = (filter_def *) g_malloc(sizeof(filter_def));
    filt->name   = g_strdup(filt_name);
    filt->strval = g_strdup(filt_expr);
    return g_list_append(fl, filt);
}

GList *
remove_filter_entry(GList *fl, GList *fl_entry)
{
  filter_def *filt;

  filt = (filter_def *) fl_entry->data;
  g_free(filt->name);
  g_free(filt->strval);
  g_free(filt);
  return g_list_remove_link(fl, fl_entry);
}

void
read_filter_list(filter_list_type_t list_type, char **pref_path_return,
    int *errno_return)
{
  const char *ff_name;
  char       *ff_path;
  FILE       *ff;
  GList      **flpp;
  int         c;
  char       *filt_name, *filt_expr;
  int         filt_name_len, filt_expr_len;
  int         filt_name_index, filt_expr_index;
  int         line = 1;

  *pref_path_return = NULL;	/* assume no error */

  switch (list_type) {

  case CFILTER_LIST:
    ff_name = CFILTER_FILE_NAME;
    flpp = &capture_filters;
    break;

  case DFILTER_LIST:
    ff_name = DFILTER_FILE_NAME;
    flpp = &display_filters;
    break;

  default:
    g_assert_not_reached();
    return;
  }

  /* try to open personal "cfilters"/"dfilters" file */
  ff_path = get_persconffile_path(ff_name, FALSE);
  if ((ff = eth_fopen(ff_path, "r")) == NULL) {
    /*
     * Did that fail because the file didn't exist?
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
     * Yes.  See if there's an "old style" personal "filters" file; if so, read it.
     * This means that a user will start out with their capture and
     * display filter lists being identical; each list may contain
     * filters that don't belong in that list.  The user can edit
     * the filter lists, and delete the ones that don't belong in
     * a particular list.
     */
    g_free(ff_path);
    ff_path = get_persconffile_path(FILTER_FILE_NAME, FALSE);
    if ((ff = eth_fopen(ff_path, "r")) == NULL) {
    /*
     * Did that fail because the file didn't exist?
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
     * Try to open the global "cfilters/dfilters" file */
    ff_path = get_datafile_path(ff_name);
    if ((ff = eth_fopen(ff_path, "r")) == NULL) {

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
  }

  /* If we already have a list of filters, discard it. */
  /* this should never happen - this function is called only once for each list! */
  while(*flpp) {
    *flpp = remove_filter_entry(*flpp, g_list_first(*flpp));        
  }

  /* Allocate the filter name buffer. */
  filt_name_len = INIT_BUF_SIZE;
  filt_name = g_malloc(filt_name_len + 1);
  filt_expr_len = INIT_BUF_SIZE;
  filt_expr = g_malloc(filt_expr_len + 1);

  for (line = 1; ; line++) {
    /* Lines in a filter file are of the form

	"name" expression

       where "name" is a name, in quotes - backslashes in the name
       escape the next character, so quotes and backslashes can appear
       in the name - and "expression" is a filter expression, not in
       quotes, running to the end of the line. */

    /* Skip over leading white space, if any. */
    while ((c = getc(ff)) != EOF && isspace(c)) {
      if (c == '\n') {
	/* Blank line. */
	continue;
      }
    }

    if (c == EOF)
      break;	/* Nothing more to read */

    /* "c" is the first non-white-space character.
       If it's not a quote, it's an error. */
    if (c != '"') {
      g_warning("'%s' line %d doesn't have a quoted filter name.", ff_path,
		line);
      while (c != '\n')
	c = getc(ff);	/* skip to the end of the line */
      continue;
    }

    /* Get the name of the filter. */
    filt_name_index = 0;
    for (;;) {
      c = getc(ff);
      if (c == EOF || c == '\n')
	break;	/* End of line - or end of file */
      if (c == '"') {
	/* Closing quote. */
	if (filt_name_index >= filt_name_len) {
	  /* Filter name buffer isn't long enough; double its length. */
	  filt_name_len *= 2;
	  filt_name = g_realloc(filt_name, filt_name_len + 1);
	}
	filt_name[filt_name_index] = '\0';
	break;
      }
      if (c == '\\') {
	/* Next character is escaped */
	c = getc(ff);
	if (c == EOF || c == '\n')
	  break;	/* End of line - or end of file */
      }
      /* Add this character to the filter name string. */
      if (filt_name_index >= filt_name_len) {
	/* Filter name buffer isn't long enough; double its length. */
	filt_name_len *= 2;
	filt_name = g_realloc(filt_name, filt_name_len + 1);
      }
      filt_name[filt_name_index] = c;
      filt_name_index++;
    }

    if (c == EOF) {
      if (!ferror(ff)) {
	/* EOF, not error; no newline seen before EOF */
	g_warning("'%s' line %d doesn't have a newline.", ff_path,
		  line);
      }
      break;	/* nothing more to read */
    }

    if (c != '"') {
      /* No newline seen before end-of-line */
      g_warning("'%s' line %d doesn't have a closing quote.", ff_path,
		line);
      continue;
    }

    /* Skip over separating white space, if any. */
    while ((c = getc(ff)) != EOF && isspace(c)) {
      if (c == '\n')
	break;
    }

    if (c == EOF) {
      if (!ferror(ff)) {
	/* EOF, not error; no newline seen before EOF */
	g_warning("'%s' line %d doesn't have a newline.", ff_path,
		  line);
      }
      break;	/* nothing more to read */
    }

    if (c == '\n') {
      /* No filter expression */
      g_warning("'%s' line %d doesn't have a filter expression.", ff_path,
		line);
      continue;
    }

    /* "c" is the first non-white-space character; it's the first
       character of the filter expression. */
    filt_expr_index = 0;
    for (;;) {
      /* Add this character to the filter expression string. */
      if (filt_expr_index >= filt_expr_len) {
	/* Filter expressioin buffer isn't long enough; double its length. */
	filt_expr_len *= 2;
	filt_expr = g_realloc(filt_expr, filt_expr_len + 1);
      }
      filt_expr[filt_expr_index] = c;
      filt_expr_index++;

      /* Get the next character. */
      c = getc(ff);
      if (c == EOF || c == '\n')
	break;
    }

    if (c == EOF) {
      if (!ferror(ff)) {
	/* EOF, not error; no newline seen before EOF */
	g_warning("'%s' line %d doesn't have a newline.", ff_path,
		  line);
      }
      break;	/* nothing more to read */
    }

    /* We saw the ending newline; terminate the filter expression string */
    if (filt_expr_index >= filt_expr_len) {
      /* Filter expressioin buffer isn't long enough; double its length. */
      filt_expr_len *= 2;
      filt_expr = g_realloc(filt_expr, filt_expr_len + 1);
    }
    filt_expr[filt_expr_index] = '\0';

    /* Add the new filter to the list of filters */
    *flpp = add_filter_entry(*flpp, filt_name, filt_expr);
  }
  if (ferror(ff)) {
    *pref_path_return = ff_path;
    *errno_return = errno;
  } else
    g_free(ff_path);
  fclose(ff);
  g_free(filt_name);
  g_free(filt_expr);
  
  /* init the corresponding edited list */
  switch (list_type) {
  case CFILTER_LIST:
    copy_filter_list(CFILTER_EDITED_LIST, CFILTER_LIST);
    break;
  case DFILTER_LIST:
    copy_filter_list(DFILTER_EDITED_LIST, DFILTER_LIST);
    break;
  default:
    g_assert_not_reached();
    return;
  }
}

/*
 * Get a pointer to a list of filters.
 */
static GList **
get_filter_list(filter_list_type_t list_type)
{
  GList **flpp;

  switch (list_type) {

  case CFILTER_LIST:
    flpp = &capture_filters;
    break;

  case DFILTER_LIST:
    flpp = &display_filters;
    break;

  case CFILTER_EDITED_LIST:
    flpp = &capture_edited_filters;
    break;

  case DFILTER_EDITED_LIST:
    flpp = &display_edited_filters;
    break;

  default:
    g_assert_not_reached();
    flpp = NULL;
  }
  return flpp;
}

/*
 * Get a pointer to the first entry in a filter list.
 */
GList *
get_filter_list_first(filter_list_type_t list_type)
{
  GList      **flpp;

  flpp = get_filter_list(list_type);
  return g_list_first(*flpp);
}

/*
 * Add a new filter to the end of a list.
 * Returns a pointer to the newly-added entry.
 */
GList *
add_to_filter_list(filter_list_type_t list_type, const char *name,
    const char *expression)
{
  GList      **flpp;

  flpp = get_filter_list(list_type);
  *flpp = add_filter_entry(*flpp, name, expression);

  return g_list_last(*flpp);
}

/*
 * Remove a filter from a list.
 */
void
remove_from_filter_list(filter_list_type_t list_type, GList *fl_entry)
{
  GList      **flpp;

  flpp = get_filter_list(list_type);
  *flpp = remove_filter_entry(*flpp, fl_entry);
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
save_filter_list(filter_list_type_t list_type, char **pref_path_return,
    int *errno_return)
{
  const gchar *ff_name;
  gchar      *ff_path, *ff_path_new;
  GList      *fl;
  GList      *flpp;
  filter_def *filt;
  FILE       *ff;
  guchar     *p, c;

  *pref_path_return = NULL;	/* assume no error */

  switch (list_type) {

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

  ff_path = get_persconffile_path(ff_name, TRUE);

  /* Write to "XXX.new", and rename if that succeeds.
     That means we don't trash the file if we fail to write it out
     completely. */
  ff_path_new = g_strdup_printf("%s.new", ff_path);

  if ((ff = eth_fopen(ff_path_new, "w")) == NULL) {
    *pref_path_return = ff_path;
    *errno_return = errno;
    g_free(ff_path_new);
    return;
  }
  flpp = g_list_first(fl);
  while (flpp) {
    filt = (filter_def *) flpp->data;

    /* Write out the filter name as a quoted string; escape any quotes
       or backslashes. */
    putc('"', ff);
    for (p = (guchar *)filt->name; (c = *p) != '\0'; p++) {
      if (c == '"' || c == '\\')
        putc('\\', ff);
      putc(c, ff);
    }
    putc('"', ff);

    /* Separate the filter name and value with a space. */
    putc(' ', ff);

    /* Write out the filter expression and a newline. */
    fprintf(ff, "%s\n", filt->strval);
    if (ferror(ff)) {
      *pref_path_return = ff_path;
      *errno_return = errno;
      fclose(ff);
      eth_unlink(ff_path_new);
      g_free(ff_path_new);
      return;
    }
    flpp = flpp->next;
  }
  if (fclose(ff) == EOF) {
    *pref_path_return = ff_path;
    *errno_return = errno;
    eth_unlink(ff_path_new);
    g_free(ff_path_new);
    return;
  }

#ifdef _WIN32
  /* ANSI C doesn't say whether "rename()" removes the target if it
     exists; the Win32 call to rename files doesn't do so, which I
     infer is the reason why the MSVC++ "rename()" doesn't do so.
     We must therefore remove the target file first, on Windows. */
  if (eth_remove(ff_path) < 0 && errno != ENOENT) {
    /* It failed for some reason other than "it's not there"; if
       it's not there, we don't need to remove it, so we just
       drive on. */
    *pref_path_return = ff_path;
    *errno_return = errno;
    eth_unlink(ff_path_new);
    g_free(ff_path_new);
    return;
  }
#endif

  if (eth_rename(ff_path_new, ff_path) < 0) {
    *pref_path_return = ff_path;
    *errno_return = errno;
    eth_unlink(ff_path_new);
    g_free(ff_path_new);
    return;
  }
  g_free(ff_path_new);
  g_free(ff_path);
}

/*
 * Copy a filter list into another.
 */
void copy_filter_list(filter_list_type_t dest_type, filter_list_type_t src_type)
{
    GList      **flpp_dest;
    GList      **flpp_src;
    GList      *flp_src;
    filter_def *filt;

    g_assert(dest_type != src_type);

    flpp_dest = get_filter_list(dest_type);
    flpp_src = get_filter_list(src_type);
    flp_src = *flpp_src;

    /* throw away the "old" destination list - a NULL list is ok here */
    while(*flpp_dest) {
        *flpp_dest = remove_filter_entry(*flpp_dest, g_list_first(*flpp_dest));        
    }
    g_assert(g_list_length(*flpp_dest) == 0);

    /* copy the list entries */
    while(flp_src) {
        filt = (flp_src)->data;

        *flpp_dest = add_filter_entry(*flpp_dest, filt->name, filt->strval);
        flp_src = g_list_next(flp_src);
    }
}

