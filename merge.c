/* Combine two dump files, either by appending or by merging by timestamp
 *
 * $Id: merge.c,v 1.1 2004/06/17 21:53:25 ulfl Exp $
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

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include "cvsversion.h"

/*
 * Global variables
 */
static int verbose = 0;                      /* Not so verbose         */

/*
 * Structures to manage our files
 */
typedef struct in_file_t {
  const char *filename;
  wtap       *wth;
  int         err;
  gchar      *err_info;
  long        data_offset;
  gboolean    ok;
} in_file_t;

typedef struct out_file_t {
  const char  *filename;
  wtap_dumper *pdh;
  int          file_type;
  int          frame_type;
  unsigned int snaplen;
  int          count;
} out_file_t;
static out_file_t out_file;

/*
 * Routine to write frame to output file
 */
static gboolean
write_frame(guchar *user, const struct wtap_pkthdr *phdr, long offset _U_,
            union wtap_pseudo_header *pseudo_header, const guchar *buf)
{
  wtap_dumper *pdh = (wtap_dumper*)user;
  int err;
  struct wtap_pkthdr snap_phdr;

  if (verbose)
    printf("Record: %u\n", out_file.count++);

  /* We simply write it, perhaps after truncating it; we could do other
   * things, like modify it. */
  if (out_file.snaplen != 0 && phdr->caplen > out_file.snaplen) {
    snap_phdr = *phdr;
    snap_phdr.caplen = out_file.snaplen;
    phdr = &snap_phdr;
  }

  if (!wtap_dump(pdh, phdr, pseudo_header, buf, &err)) {
    fprintf(stderr, "mergecap: Error writing to %s: %s\n",
            out_file.filename, wtap_strerror(err));
    return FALSE;
  }

  return TRUE;
}


static gboolean
append_loop(wtap *wth, int count, wtap_handler callback, guchar* user, int *err,
    gchar **err_info)
{
	long		data_offset;
	int		loop = 0;

	/* Start by clearing error flag */
	*err = 0;

	while ( (wtap_read(wth, err, err_info, &data_offset)) ) {
		if(!write_frame(user, wtap_phdr(wth), data_offset,
		    wtap_pseudoheader(wth), wtap_buf_ptr(wth)))
            return FALSE;
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
static void
append_files(int count, in_file_t in_files[], out_file_t *out_file)
{
  int i;
  int err;
  gchar *err_info;

  for (i = 0; i < count; i++) {
    if (!append_loop(in_files[i].wth, 0, write_frame,
                   (guchar*)out_file->pdh, &err, &err_info)) {
          fprintf(stderr, "mergecap: Error appending %s to %s: %s\n",
                  in_files[i].filename, out_file->filename, wtap_strerror(err));
          switch (err) {

          case WTAP_ERR_UNSUPPORTED:
          case WTAP_ERR_UNSUPPORTED_ENCAP:
          case WTAP_ERR_BAD_RECORD:
	    fprintf(stderr, "(%s)\n", err_info);

	    break;
      }
    }
  }
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
earliest(int count, in_file_t in_files[]) {
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
static gboolean
merge(int count, in_file_t in_files[], out_file_t *out_file)
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
    if(!write_frame((guchar*)out_file->pdh,
                wtap_phdr(in_files[i].wth),
                in_files[i].data_offset,
                wtap_pseudoheader(in_files[i].wth),
                wtap_buf_ptr(in_files[i].wth)))
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
static int
select_frame_type(int count, in_file_t files[])
{
  int i;
  int selected_frame_type;

  selected_frame_type = wtap_file_encap(files[0].wth);

  for (i = 1; i < count; i++) {
    int this_frame_type = wtap_file_encap(files[i].wth);
    if (selected_frame_type != this_frame_type) {
      selected_frame_type = WTAP_ENCAP_PER_PACKET;
      if (verbose) {
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

  if (verbose) {
      fprintf(stderr, "mergecap: selected frame_type %s (%s)\n",
              wtap_encap_string(selected_frame_type),
              wtap_encap_short_string(selected_frame_type));
  }

  return selected_frame_type;
}


/*
 * Close the output file
 */
static void
close_outfile(out_file_t *out_file)
{
  int err;
  if (!wtap_dump_close(out_file->pdh, &err)) {
    fprintf(stderr, "mergecap: Error closing file %s: %s\n",
            out_file->filename, wtap_strerror(err));
  }
}


/*
 * Open the output file
 *
 * Return FALSE if file cannot be opened (so caller can clean up)
 */
static gboolean
open_outfile(out_file_t *out_file, int snapshot_len)
{
  int err;

  if (!out_file) {
    fprintf(stderr, "mergecap: internal error (null out_file)\n");
    return FALSE;
  }

  /* Allow output to stdout by using - */
  if (strncmp(out_file->filename, "-", 2) == 0)
    out_file->filename = "";


  out_file->pdh = wtap_dump_open(out_file->filename, out_file->file_type,
                                 out_file->frame_type, snapshot_len, &err);
  if (!out_file->pdh) {
    fprintf(stderr, "mergecap: Can't open/create %s:\n", out_file->filename);
    fprintf(stderr, "          %s\n", wtap_strerror(err));
    return FALSE;
  }
  return TRUE;
}


/*
 * Scan through input files and find maximum snapshot length
 */
static int
max_snapshot_length(int count, in_file_t in_files[])
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
static void
close_in_files(int count, in_file_t in_files[])
{
  int i;
  for (i = 0; i < count; i++) {
    wtap_close(in_files[i].wth);
  }
}


/*
 * Scan through the arguments and open the input files
 */
static int
open_in_files(int in_file_count, char *argv[], in_file_t *in_files[])
{
  int i;
  int count = 0;
  int err;
  gchar *err_info;
  in_file_t *files;
  int files_size = in_file_count * sizeof(in_file_t);


  files = g_malloc(files_size);
  *in_files = files;

  for (i = 0; i < in_file_count; i++) {
    files[count].filename    = argv[i];
    files[count].wth         = wtap_open_offline(argv[i], &err, &err_info, FALSE);
    files[count].err         = 0;
    files[count].data_offset = 0;
    files[count].ok          = TRUE;
    if (!files[count].wth) {
      fprintf(stderr, "mergecap: skipping %s: %s\n", argv[i],
              wtap_strerror(err));
      switch (err) {

      case WTAP_ERR_UNSUPPORTED:
      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_BAD_RECORD:
        fprintf(stderr, "(%s)\n", err_info);
        g_free(err_info);
        break;
      }
    } else {
      if (verbose) {
        fprintf(stderr, "mergecap: %s is type %s.\n", argv[i],
                wtap_file_type_string(wtap_file_type(files[count].wth)));
      }
      count++;
    }
  }
  if (verbose)
    fprintf(stderr, "mergecap: opened %d of %d input files\n", count,
    in_file_count);

  return count;
}


gboolean
merge_two_files(char *out_filename, char *in_file0, char *in_file1, gboolean do_append)
{
  extern char *optarg;
  extern int   optind;
  int          in_file_count = 0;
  in_file_t   *in_files      = NULL;
  char        *in_filenames[2];

  /* initialize out_file */
  out_file.filename   = out_filename;
  out_file.pdh        = NULL;              /* wiretap dumpfile */
  out_file.file_type  = WTAP_FILE_PCAP;    /* default to "libpcap" */
  out_file.frame_type = -2;                /* leave type alone */
  out_file.snaplen    = 0;                 /* no limit */
  out_file.count      = 1;                 /* frames output */

  /* check for proper args; at a minimum, must have an output
   * filename and one input file
   */
  in_file_count = 2;

  in_filenames[0] = in_file0;
  in_filenames[1] = in_file1;

  /* open the input files */
  in_file_count = open_in_files(in_file_count, in_filenames, &in_files);
  if (in_file_count < 1) {
    fprintf(stderr, "mergecap: No valid input files\n");
    return FALSE;
  }

  /* set the outfile frame type */
  if (out_file.frame_type == -2)
    out_file.frame_type = select_frame_type(in_file_count, in_files);

  /* open the outfile */
  if (!open_outfile(&out_file, max_snapshot_length(in_file_count, in_files))) {
    close_in_files(in_file_count, in_files);
    return FALSE;
  }

  /* do the merge (or append) */
  if (do_append)
    append_files(in_file_count, in_files, &out_file);
  else
    merge(in_file_count, in_files, &out_file);

  close_in_files(in_file_count, in_files);
  close_outfile(&out_file);

  free(in_files);

  return TRUE;
}
