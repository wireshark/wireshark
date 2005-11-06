/* disabled_protos.c
 * Code for reading and writing the disabled protocols file.
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
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <epan/filesystem.h>
#include <epan/proto.h>

#include "disabled_protos.h"
#include "file_util.h"

#define GLOBAL_PROTOCOLS_FILE_NAME	"disabled_protos"
#define PROTOCOLS_FILE_NAME		"disabled_protos"

/*
 * List of disabled protocols
 */
static GList *global_disabled_protos = NULL;
static GList *disabled_protos = NULL;

#define INIT_BUF_SIZE	128

/*
 * Read in a list of disabled protocols.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*open_errno_return" is set to the error if an open failed
 * or "*read_errno_return" is set to the error if a read failed.
 */

static int read_disabled_protos_list_file(const char *ff_path, FILE *ff,
					  GList **flp);

void
read_disabled_protos_list(char **gpath_return, int *gopen_errno_return,
			  int *gread_errno_return,
			  char **path_return, int *open_errno_return,
                          int *read_errno_return)
{
  int         err;
  char       *gff_path, *ff_path;
  FILE       *ff;

  /* Construct the pathname of the global disabled protocols file. */
  gff_path = get_datafile_path(GLOBAL_PROTOCOLS_FILE_NAME);

  /* Read the global disabled protocols file, if it exists. */
  *gpath_return = NULL;
  if ((ff = eth_fopen(gff_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    err = read_disabled_protos_list_file(gff_path, ff,
					 &global_disabled_protos);
    if (err != 0) {
      /* We had an error reading the file; return the errno and the
         pathname, so our caller can report the error. */
      *gopen_errno_return = 0;
      *gread_errno_return = err;
      *gpath_return = gff_path;
    } else
      g_free(gff_path);
    fclose(ff);
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *gopen_errno_return = errno;
      *gread_errno_return = 0;
      *gpath_return = gff_path;
    } else
      g_free(gff_path);
  }

  /* Construct the pathname of the user's disabled protocols file. */
  ff_path = get_persconffile_path(PROTOCOLS_FILE_NAME, FALSE);

  /* Read the user's disabled protocols file, if it exists. */
  *path_return = NULL;
  if ((ff = eth_fopen(ff_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    err = read_disabled_protos_list_file(ff_path, ff, &disabled_protos);
    if (err != 0) {
      /* We had an error reading the file; return the errno and the
         pathname, so our caller can report the error. */
      *open_errno_return = 0;
      *read_errno_return = err;
      *path_return = ff_path;
    } else
      g_free(ff_path);
    fclose(ff);
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *open_errno_return = errno;
      *read_errno_return = 0;
      *path_return = ff_path;
    } else
      g_free(ff_path);
  }
}

static int
read_disabled_protos_list_file(const char *ff_path, FILE *ff,
			       GList **flp)
{
  GList      *fl_ent;
  protocol_def *prot;
  int         c;
  char       *prot_name;
  int         prot_name_len;
  int         prot_name_index;
  int         line = 1;

  /* If we already have a list of protocols, discard it. */
  if (*flp != NULL) {
    fl_ent = g_list_first(*flp);
    while (fl_ent != NULL) {
      prot = (protocol_def *) fl_ent->data;
      g_free(prot->name);
      g_free(prot);
      fl_ent = fl_ent->next;
    }
    g_list_free(*flp);
    *flp = NULL;
  }

  /* Allocate the protocol name buffer. */
  prot_name_len = INIT_BUF_SIZE;
  prot_name = g_malloc(prot_name_len + 1);

  for (line = 1; ; line++) {
    /* Lines in a disabled protocol file contain the "filter name" of
       a protocol to be disabled. */

    /* Skip over leading white space, if any. */
    while ((c = getc(ff)) != EOF && isspace(c)) {
      if (c == '\n') {
	/* Blank line. */
	continue;
      }
    }

    if (c == EOF) {
      if (ferror(ff))
        goto error;	/* I/O error */
      else
        break;	/* Nothing more to read */
    }
    ungetc(c, ff);	/* Unread the non-white-space character. */

    /* Get the name of the protocol. */
    prot_name_index = 0;
    for (;;) {
      c = getc(ff);
      if (c == EOF)
	break;	/* End of file, or I/O error */
      if (isspace(c))
        break;	/* Trailing white space, or end of line. */
      if (c == '#')
        break;	/* Start of comment, running to end of line. */
      /* Add this character to the protocol name string. */
      if (prot_name_index >= prot_name_len) {
	/* protocol name buffer isn't long enough; double its length. */
	prot_name_len *= 2;
	prot_name = g_realloc(prot_name, prot_name_len + 1);
      }
      prot_name[prot_name_index] = c;
      prot_name_index++;
    }

    if (isspace(c) && c != '\n') {
      /* Skip over trailing white space. */
      while ((c = getc(ff)) != EOF && c != '\n' && isspace(c))
        ;
      if (c != EOF && c != '\n' && c != '#') {
	/* Non-white-space after the protocol name; warn about it,
	   in case we come up with a reason to use it. */
	g_warning("'%s' line %d has extra stuff after the protocol name.",
	          ff_path, line);
      }
    }
    if (c != EOF && c != '\n') {
      /* Skip to end of line. */
      while ((c = getc(ff)) != EOF && c != '\n')
        ;
    }

    if (c == EOF) {
      if (ferror(ff))
        goto error;	/* I/O error */
      else {
	/* EOF, not error; no newline seen before EOF */
	g_warning("'%s' line %d doesn't have a newline.", ff_path,
		  line);
      }
      break;	/* nothing more to read */
    }

    /* Null-terminate the protocol name. */
    if (prot_name_index >= prot_name_len) {
      /* protocol name buffer isn't long enough; double its length. */
      prot_name_len *= 2;
      prot_name = g_realloc(prot_name, prot_name_len + 1);
    }
    prot_name[prot_name_index] = '\0';

    /* Add the new protocol to the list of disabled protocols */
    prot         = (protocol_def *) g_malloc(sizeof(protocol_def));
    prot->name   = g_strdup(prot_name);
    *flp = g_list_append(*flp, prot);
  }
  g_free(prot_name);
  return 0;

error:
  return errno;
}

/*
 * Disable protocols as per the stored configuration
 */
void
set_disabled_protos_list(void)
{
  gint i;
  GList *fl_ent;
  protocol_def *prot;

  /*
   * assume all protocols are enabled by default
   */
  if (disabled_protos == NULL)
    goto skip;

  fl_ent = g_list_first(disabled_protos);

  while (fl_ent != NULL) {
    prot = (protocol_def *) fl_ent->data;
    i = proto_get_id_by_filter_name(prot->name);
    if (i == -1) {
      /* XXX - complain here? */
    } else {
      if (proto_can_toggle_protocol(i))
	proto_set_decoding(i, FALSE);
    }

    fl_ent = fl_ent->next;
  }

skip:
  if (global_disabled_protos == NULL)
    return;

  fl_ent = g_list_first(global_disabled_protos);

  while (fl_ent != NULL) {
    prot = (protocol_def *) fl_ent->data;
    i = proto_get_id_by_filter_name(prot->name);
    if (i == -1) {
      /* XXX - complain here? */
    } else {
      if (proto_can_toggle_protocol(i)) {
	proto_set_decoding(i, FALSE);
	proto_set_cant_toggle(i);
      }
    }

    fl_ent = fl_ent->next;
  }
}

/*
 * Write out a list of disabled protocols.
 *
 * On success, "*pref_path_return" is set to NULL.
 * On error, "*pref_path_return" is set to point to the pathname of
 * the file we tried to read - it should be freed by our caller -
 * and "*errno_return" is set to the error.
 */
void
save_disabled_protos_list(char **pref_path_return, int *errno_return)
{
  gchar       *ff_path, *ff_path_new;
  const gchar *ff_name;
  FILE        *ff;
  gint         i;
  protocol_t  *protocol;
  void        *cookie;

  *pref_path_return = NULL;	/* assume no error */

  ff_name = PROTOCOLS_FILE_NAME;

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

  /* Iterate over all the protocols */

  for (i = proto_get_first_protocol(&cookie); i != -1;
       i = proto_get_next_protocol(&cookie)) {

    if (!proto_can_toggle_protocol(i)) {
      continue;
    }

    protocol = find_protocol_by_id(i);
    if (proto_is_protocol_enabled(protocol)) {
      continue;
    }

    /* Write out the protocol name. */
    fprintf(ff, "%s\n", proto_get_protocol_filter_name(i));
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
