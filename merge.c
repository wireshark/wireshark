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
 * Global variables
 */
int merge_verbose = VERBOSE_NONE;


/*
 * Routine to write frame to output file
 */
static gboolean
write_frame(wtap *wth, merge_out_file_t *out_file, int *err)
{
  const struct wtap_pkthdr *phdr = wtap_phdr(wth);
  struct wtap_pkthdr snap_phdr;

  if (merge_verbose == VERBOSE_ALL)
    fprintf(stderr, "Record: %u\n", out_file->count++);

  /* We simply write it, perhaps after truncating it; we could do other
   * things, like modify it. */
  if (out_file->snaplen != 0 && phdr->caplen > out_file->snaplen) {
    snap_phdr = *phdr;
    snap_phdr.caplen = out_file->snaplen;
    phdr = &snap_phdr;
  }

  if (!wtap_dump(out_file->pdh, phdr, wtap_pseudoheader(wth), wtap_buf_ptr(wth), err)) {
    if (merge_verbose == VERBOSE_ERRORS)
      fprintf(stderr, "mergecap: Error writing to outfile: %s\n",
            wtap_strerror(*err));
    return FALSE;
  }

  return TRUE;
}


static gboolean
append_loop(wtap *wth, int count, merge_out_file_t *out_file, int *err,
    gchar **err_info)
{
	long		data_offset;
	int		loop = 0;

	/* Start by clearing error flag */
	*err = 0;

	while ( (wtap_read(wth, err, err_info, &data_offset)) ) {
		if(!write_frame(wth, out_file, err))
            return FALSE;   /* failure */
		if (count > 0 && ++loop >= count)
			break;
	}

    if (*err == 0) {
		return TRUE;	/* success */
    } else {
		return FALSE;	/* failure */
    }
}



/*
 * routine to concatenate files
 */
gboolean
merge_append_files(int count, merge_in_file_t in_files[], merge_out_file_t *out_file, int *err)
{
  int i;
  gchar *err_info;

  for (i = 0; i < count; i++) {
    if (!append_loop(in_files[i].wth, 0, out_file, err, &err_info)) {
        if (merge_verbose == VERBOSE_ERRORS)
          fprintf(stderr, "mergecap: Error appending %s to outfile: %s\n",
                  in_files[i].filename, wtap_strerror(*err));
          switch (*err) {

          case WTAP_ERR_UNSUPPORTED:
          case WTAP_ERR_UNSUPPORTED_ENCAP:
          case WTAP_ERR_BAD_RECORD:
	      fprintf(stderr, "(%s)\n", err_info);

	    break;
      }
      return FALSE;
    }
  }

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
  }

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
      if (merge_verbose == VERBOSE_ALL) {
        fprintf(stderr, "mergecap: multiple frame encapsulation types detected\n");
        fprintf(stderr, "          defaulting to WTAP_ENCAP_PER_PACKET\n");
        fprintf(stderr, "          %s had type %s (%s)\n",
                files[0].filename,
                wtap_encap_string(selected_frame_type),
                wtap_encap_short_string(selected_frame_type));
        fprintf(stderr, "          %s had type %s (%s)\n",
                files[i].filename,
                wtap_encap_string(this_frame_type),
                wtap_encap_short_string(this_frame_type));
      }
      break;
    }
  }

  if (merge_verbose == VERBOSE_ALL) {
      fprintf(stderr, "mergecap: selected frame_type %s (%s)\n",
              wtap_encap_string(selected_frame_type),
              wtap_encap_short_string(selected_frame_type));
  }

  return selected_frame_type;
}


/*
 * Close the output file
 */
void
merge_close_outfile(merge_out_file_t *out_file)
{
  int err;
  if (!wtap_dump_close(out_file->pdh, &err)) {
    if (merge_verbose == VERBOSE_ERRORS)
        fprintf(stderr, "mergecap: Error closing output file: %s\n",
            wtap_strerror(err));
  }
}


/*
 * Open the output file
 *
 * Return FALSE if file cannot be opened (so caller can clean up)
 */
gboolean
merge_open_outfile(merge_out_file_t *out_file, int snapshot_len, int *err)
{

  if (!out_file) {
    if (merge_verbose == VERBOSE_ERRORS)
        fprintf(stderr, "mergecap: internal error (null out_file)\n");
    return FALSE;
  }


  out_file->pdh = wtap_dump_fdopen(out_file->fd, out_file->file_type,
                                 out_file->frame_type, snapshot_len, err);
  if (!out_file->pdh) {
    if (merge_verbose == VERBOSE_ERRORS) {
        fprintf(stderr, "mergecap: Can't open/create output file:\n");
        fprintf(stderr, "          %s\n", wtap_strerror(*err));
    }
    return FALSE;
  }
  return TRUE;
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
 * Scan through the arguments and open the input files
 */
int
merge_open_in_files(int in_file_count, char *in_file_names[], merge_in_file_t *in_files[], int *err)
{
  int i;
  int count = 0;
  gchar *err_info;
  int files_size = in_file_count * sizeof(merge_in_file_t);
  merge_in_file_t *files;


  files = g_malloc(files_size);
  *in_files = files;

  for (i = 0; i < in_file_count; i++) {
    files[count].filename    = in_file_names[i];
    files[count].wth         = wtap_open_offline(in_file_names[i], err, &err_info, FALSE);
    files[count].err         = 0;
    files[count].data_offset = 0;
    files[count].ok          = TRUE;
    if (!files[count].wth) {
      if (merge_verbose == VERBOSE_ERRORS) {
        fprintf(stderr, "mergecap: skipping %s: %s\n", in_file_names[i],
              wtap_strerror(*err));
      switch (*err) {

      case WTAP_ERR_UNSUPPORTED:
      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_BAD_RECORD:
        fprintf(stderr, "(%s)\n", err_info);
        g_free(err_info);
        break;
      }
      }
    } else {
      if (merge_verbose == VERBOSE_ALL) {
        fprintf(stderr, "mergecap: %s is type %s.\n", in_file_names[i],
                wtap_file_type_string(wtap_file_type(files[count].wth)));
      }
      count++;
    }
  }
  if (merge_verbose == VERBOSE_ALL)
    fprintf(stderr, "mergecap: opened %d of %d input files\n", count,
    in_file_count);

  return count;
}


/*
 * Convenience function: merge two files into one.
 */
gboolean
merge_n_files(int out_fd, int in_file_count, char **in_filenames, int filetype, gboolean do_append, int *err)
{
  extern char *optarg;
  extern int   optind;
  merge_in_file_t   *in_files      = NULL;
  merge_out_file_t   out_file;
  gboolean     ret;

  /* initialize out_file */
  out_file.fd         = out_fd;
  out_file.pdh        = NULL;              /* wiretap dumpfile */
  out_file.file_type  = filetype;
  out_file.frame_type = -2;                /* leave type alone */
  out_file.snaplen    = 0;                 /* no limit */
  out_file.count      = 1;                 /* frames output */

  /* open the input files */
  in_file_count = merge_open_in_files(in_file_count, in_filenames, &in_files, err);
  if (in_file_count < 2) {
    if (merge_verbose == VERBOSE_ALL)
        fprintf(stderr, "mergecap: Not all input files valid\n");
    return FALSE;
  }

  /* set the outfile frame type */
  if (out_file.frame_type == -2)
    out_file.frame_type = merge_select_frame_type(in_file_count, in_files);

  /* open the outfile */
  if (!merge_open_outfile(&out_file, merge_max_snapshot_length(in_file_count, in_files), err)) {
    merge_close_in_files(in_file_count, in_files);
    return FALSE;
  }

  /* do the merge (or append) */
  if (do_append)
    ret = merge_append_files(in_file_count, in_files, &out_file, err);
  else
    ret = merge_files(in_file_count, in_files, &out_file, err);

  merge_close_in_files(in_file_count, in_files);
  merge_close_outfile(&out_file);

  free(in_files);

  return ret;
}
