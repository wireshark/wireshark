/* Combine two dump files, either by appending or by merging by timestamp
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

  files = g_malloc(files_size);
  *in_files = files;

  for (i = 0; i < in_file_count; i++) {
    files[i].filename    = in_file_names[i];
    files[i].wth         = wtap_open_offline(in_file_names[i], err, err_info, FALSE);
    files[i].err         = 0;
    files[i].data_offset = 0;
    files[i].ok          = TRUE;
    if (!files[i].wth) {
      /* Close the files we've already opened. */
      for (j = 0; j < i; j++)
        wtap_close(files[j].wth);
      *err_fileno = i;
      return FALSE;
    }
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
 * Open the output file
 *
 * Return FALSE if file cannot be opened (so caller can report an error
 * and clean up)
 */
gboolean
merge_open_outfile(merge_out_file_t *out_file, int fd, int file_type,
                   int frame_type, int snapshot_len, int *err)
{
  out_file->pdh = wtap_dump_fdopen(fd, file_type, frame_type, snapshot_len,
                                   err);
  if (!out_file->pdh)
    return FALSE;

  out_file->snaplen = snapshot_len;
  out_file->count = 1;
  return TRUE;
}

/*
 * Close the output file
 */
gboolean
merge_close_outfile(merge_out_file_t *out_file, int *err)
{
  if (!wtap_dump_close(out_file->pdh, err))
    return FALSE;
  return TRUE;
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
 * Routine to write frame to output file
 */
static gboolean
write_frame(wtap *wth, merge_out_file_t *out_file, int *err)
{
  const struct wtap_pkthdr *phdr = wtap_phdr(wth);
  struct wtap_pkthdr snap_phdr;

  /* We simply write it, perhaps after truncating it; we could do other
   * things, like modify it. */
  if (out_file->snaplen != 0 && phdr->caplen > out_file->snaplen) {
    snap_phdr = *phdr;
    snap_phdr.caplen = out_file->snaplen;
    phdr = &snap_phdr;
  }

  if (!wtap_dump(out_file->pdh, phdr, wtap_pseudoheader(wth), wtap_buf_ptr(wth), err))
    return FALSE;

  return TRUE;
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
 * returns index of earliest timestamp in set of input files
 * or -1 if no valid files remain
 */
static int
earliest(int count, merge_in_file_t in_files[]) {
  int i;
  int ei = -1;
  struct timeval tv = {LONG_MAX, LONG_MAX};

  for (i = 0; i < count; i++) {
    struct wtap_pkthdr *phdr = wtap_phdr(in_files[i].wth);

    if (in_files[i].ok && is_earlier(&(phdr->ts), &tv)) {
      tv = phdr->ts;
      ei = i;
    }
  }
  return ei;
}

/*
 * actually merge the files
 */
gboolean
merge_files(int count, merge_in_file_t in_files[], merge_out_file_t *out_file, int *err)
{
  int i;

  /* prime the pump (read in first frame from each file) */
  for (i = 0; i < count; i++) {
    in_files[i].ok = wtap_read(in_files[i].wth, &(in_files[i].err),
                               &(in_files[i].err_info),
                               &(in_files[i].data_offset));
    if (!in_files[i].ok) {
      /* Read failure, not write failure. */
      return TRUE;
    }
  }

  /* now keep writing the earliest frame until we're out of frames */
  while ( -1 != (i = earliest(count, in_files))) {

    /* write out earliest frame, and fetch another from its
     * input file
     */
    if(!write_frame(in_files[i].wth, out_file, err))
        return FALSE;
    in_files[i].ok = wtap_read(in_files[i].wth, &(in_files[i].err),
                               &(in_files[i].err_info),
                               &(in_files[i].data_offset));
    if (!in_files[i].ok) {
      /* Read failure, not write failure. */
      return TRUE;
    }
  }

  return TRUE;
}

static gboolean
append_loop(merge_in_file_t in_files[], int i, int count,
            merge_out_file_t *out_file, int *err)
{
  gchar        *err_info;
  long		data_offset;
  int		loop = 0;

  /* Start by clearing error flag */
  *err = 0;

  while ( (wtap_read(in_files[i].wth, err, &err_info, &data_offset)) ) {
    if(!write_frame(in_files[i].wth, out_file, err))
      return FALSE;   /* failure */
    if (count > 0 && ++loop >= count)
      break;
  }

  if (*err != 0) {
    /* Read failure, not write failure. */
    in_files[i].ok = FALSE;
    in_files[i].err = *err;
    in_files[i].err_info = err_info;
  }
  return TRUE;
}

/*
 * routine to concatenate files
 */
gboolean
merge_append_files(int count, merge_in_file_t in_files[],
                   merge_out_file_t *out_file, int *err)
{
  int i;

  for (i = 0; i < count; i++) {
    if (!append_loop(in_files, i, 0, out_file, err))
      return FALSE;
  }

  return TRUE;
}
