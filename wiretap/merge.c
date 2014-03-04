/* Combine multiple dump files, either by appending or by merging by timestamp
 *
 * Written by Scott Renfro <scott@renfro.org> based on
 * editcap by Richard Sharpe and Guy Harris
 *
 * Copyright 2013, Scott Renfro <scott[AT]renfro.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <string.h>
#include "merge.h"

/*
 * Scan through the arguments and open the input files
 */
gboolean
merge_open_in_files(int in_file_count, char *const *in_file_names,
                    merge_in_file_t **in_files, int *err, gchar **err_info,
                    int *err_fileno)
{
  int i, j;
  size_t files_size = in_file_count * sizeof(merge_in_file_t);
  merge_in_file_t *files;
  gint64 size;

  files = (merge_in_file_t *)g_malloc(files_size);
  *in_files = files;

  for (i = 0; i < in_file_count; i++) {
    files[i].filename    = in_file_names[i];
    files[i].wth         = wtap_open_offline(in_file_names[i], WTAP_TYPE_AUTO, err, err_info, FALSE);
    files[i].data_offset = 0;
    files[i].state       = PACKET_NOT_PRESENT;
    files[i].packet_num  = 0;
    if (!files[i].wth) {
      /* Close the files we've already opened. */
      for (j = 0; j < i; j++)
        wtap_close(files[j].wth);
      *err_fileno = i;
      return FALSE;
    }
    size = wtap_file_size(files[i].wth, err);
    if (size == -1) {
      for (j = 0; j <= i; j++)
        wtap_close(files[j].wth);
      *err_fileno = i;
      return FALSE;
    }
    files[i].size = size;
  }
  return TRUE;
}

/*
 * Scan through and close each input file
 */
void
merge_close_in_files(int count, merge_in_file_t in_files[])
{
  int i;
  for (i = 0; i < count; i++) {
    wtap_close(in_files[i].wth);
  }
}

/*
 * Select an output frame type based on the input files
 * From Guy: If all files have the same frame type, then use that.
 *           Otherwise select WTAP_ENCAP_PER_PACKET.  If the selected
 *           output file type doesn't support per packet frame types,
 *           then the wtap_dump_open call will fail with a reasonable
 *           error condition.
 */
int
merge_select_frame_type(int count, merge_in_file_t files[])
{
  int i;
  int selected_frame_type;

  selected_frame_type = wtap_file_encap(files[0].wth);

  for (i = 1; i < count; i++) {
    int this_frame_type = wtap_file_encap(files[i].wth);
    if (selected_frame_type != this_frame_type) {
      selected_frame_type = WTAP_ENCAP_PER_PACKET;
      break;
    }
  }

  return selected_frame_type;
}

/*
 * Scan through input files and find maximum snapshot length
 */
int
merge_max_snapshot_length(int count, merge_in_file_t in_files[])
{
  int i;
  int max_snapshot = 0;
  int snapshot_length;

  for (i = 0; i < count; i++) {
    snapshot_length = wtap_snapshot_length(in_files[i].wth);
    if (snapshot_length == 0) {
      /* Snapshot length of input file not known. */
      snapshot_length = WTAP_MAX_PACKET_SIZE;
    }
    if (snapshot_length > max_snapshot)
      max_snapshot = snapshot_length;
  }
  return max_snapshot;
}

/*
 * returns TRUE if first argument is earlier than second
 */
static gboolean
is_earlier(nstime_t *l, nstime_t *r) /* XXX, move to nstime.c */
{
  if (l->secs > r->secs) {  /* left is later */
    return FALSE;
  } else if (l->secs < r->secs) { /* left is earlier */
    return TRUE;
  } else if (l->nsecs > r->nsecs) { /* tv_sec equal, l.usec later */
    return FALSE;
  }
  /* either one < two or one == two
   * either way, return one
   */
  return TRUE;
}

/*
 * Read the next packet, in chronological order, from the set of files
 * to be merged.
 *
 * On success, set *err to 0 and return a pointer to the merge_in_file_t
 * for the file from which the packet was read.
 *
 * On a read error, set *err to the error and return a pointer to the
 * merge_in_file_t for the file on which we got an error.
 *
 * On an EOF (meaning all the files are at EOF), set *err to 0 and return
 * NULL.
 */
merge_in_file_t *
merge_read_packet(int in_file_count, merge_in_file_t in_files[],
                  int *err, gchar **err_info)
{
  int i;
  int ei = -1;
  nstime_t tv = { sizeof(time_t) > sizeof(int) ? LONG_MAX : INT_MAX, INT_MAX };
  struct wtap_pkthdr *phdr;

  /*
   * Make sure we have a packet available from each file, if there are any
   * packets left in the file in question, and search for the packet
   * with the earliest time stamp.
   */
  for (i = 0; i < in_file_count; i++) {
    if (in_files[i].state == PACKET_NOT_PRESENT) {
      /*
       * No packet available, and we haven't seen an error or EOF yet,
       * so try to read the next packet.
       */
      if (!wtap_read(in_files[i].wth, err, err_info, &in_files[i].data_offset)) {
        if (*err != 0) {
          in_files[i].state = GOT_ERROR;
          return &in_files[i];
        }
        in_files[i].state = AT_EOF;
      } else
        in_files[i].state = PACKET_PRESENT;
    }

    if (in_files[i].state == PACKET_PRESENT) {
      phdr = wtap_phdr(in_files[i].wth);
      if (is_earlier(&phdr->ts, &tv)) {
        tv = phdr->ts;
        ei = i;
      }
    }
  }

  if (ei == -1) {
    /* All the streams are at EOF.  Return an EOF indication. */
    *err = 0;
    return NULL;
  }

  /* We'll need to read another packet from this file. */
  in_files[ei].state = PACKET_NOT_PRESENT;

  /* Count this packet. */
  in_files[ei].packet_num++;

  /*
   * Return a pointer to the merge_in_file_t of the file from which the
   * packet was read.
   */
  *err = 0;
  return &in_files[ei];
}

/*
 * Read the next packet, in file sequence order, from the set of files
 * to be merged.
 *
 * On success, set *err to 0 and return a pointer to the merge_in_file_t
 * for the file from which the packet was read.
 *
 * On a read error, set *err to the error and return a pointer to the
 * merge_in_file_t for the file on which we got an error.
 *
 * On an EOF (meaning all the files are at EOF), set *err to 0 and return
 * NULL.
 */
merge_in_file_t *
merge_append_read_packet(int in_file_count, merge_in_file_t in_files[],
                         int *err, gchar **err_info)
{
  int i;

  /*
   * Find the first file not at EOF, and read the next packet from it.
   */
  for (i = 0; i < in_file_count; i++) {
    if (in_files[i].state == AT_EOF)
      continue; /* This file is already at EOF */
    if (wtap_read(in_files[i].wth, err, err_info, &in_files[i].data_offset))
      break; /* We have a packet */
    if (*err != 0) {
      /* Read error - quit immediately. */
      in_files[i].state = GOT_ERROR;
      return &in_files[i];
    }
    /* EOF - flag this file as being at EOF, and try the next one. */
    in_files[i].state = AT_EOF;
  }
  if (i == in_file_count) {
    /* All the streams are at EOF.  Return an EOF indication. */
    *err = 0;
    return NULL;
  }

  /*
   * Return a pointer to the merge_in_file_t of the file from which the
   * packet was read.
   */
  *err = 0;
  return &in_files[i];
}
