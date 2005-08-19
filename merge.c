/* Combine multiple dump files, either by appending or by merging by timestamp
 *
 * $Id$
 *
 * Written by Scott Renfro <scott@renfro.org> based on
 * editcap by Richard Sharpe and Guy Harris
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include "wtap.h"
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
  int files_size = in_file_count * sizeof(merge_in_file_t);
  merge_in_file_t *files;
  gint64 size;

  files = g_malloc(files_size);
  *in_files = files;

  for (i = 0; i < in_file_count; i++) {
    files[i].filename    = in_file_names[i];
    files[i].wth         = wtap_open_offline(in_file_names[i], err, err_info, FALSE);
    files[i].data_offset = 0;
    files[i].state       = PACKET_NOT_PRESENT;
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
is_earlier(struct timeval *l, struct timeval *r) {
  if (l->tv_sec > r->tv_sec) {  /* left is later */
    return FALSE;
  } else if (l->tv_sec < r->tv_sec) { /* left is earlier */
    return TRUE;
  } else if (l->tv_usec > r->tv_usec) { /* tv_sec equal, l.usec later */
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
 */
wtap *
merge_read_packet(int in_file_count, merge_in_file_t in_files[], int *err,
                  gchar **err_info)
{
  int i;
  int ei = -1;
  struct timeval tv = {LONG_MAX, LONG_MAX};
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
          return NULL;
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

  /* Return a pointer to the wtap structure for the file with that frame. */
  return in_files[ei].wth;
}

/*
 * Read the next packet, in file sequence order, from the set of files
 * to be merged.
 */
wtap *
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
      return NULL;
    }
    /* EOF - flag this file as being at EOF, and try the next one. */
    in_files[i].state = AT_EOF;
  }
  if (i == in_file_count) {
    /* All the streams are at EOF.  Return an EOF indication. */
    *err = 0;
    return NULL;
  }

  /* Return a pointer to the wtap structure for the file with that frame. */
  return in_files[i].wth;
}
