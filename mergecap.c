/* Combine two dump files, either by appending or by merging by timestamp
 *
 * $Id: mergecap.c,v 1.5 2001/10/04 08:30:33 guy Exp $
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

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <string.h>
#include "wtap.h"

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif


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
static void
write_frame(u_char *user, const struct wtap_pkthdr *phdr, long offset,
            union wtap_pseudo_header *pseudo_header, const u_char *buf) 
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
    exit(1);
  }
}


/*
 * routine to concatenate files
 */
static void
append(int count, in_file_t in_files[], out_file_t *out_file)
{
  int i;
  int err;

  for (i = 0; i < count; i++) {
    if (!wtap_loop(in_files[i].wth, 0, write_frame,
                   (u_char*)out_file->pdh, &err)) {
    fprintf(stderr, "mergecap: Error appending from %s to %s: %s\n",
            in_files[i].filename, out_file->filename, wtap_strerror(err));
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
static void
merge(int count, in_file_t in_files[], out_file_t *out_file)
{
  int i;

  /* prime the pump (read in first frame from each file) */
  for (i = 0; i < count; i++) {
    in_files[i].ok = wtap_read(in_files[i].wth, &(in_files[i].err),
                               &(in_files[i].data_offset));
  }

  /* now keep writing the earliest frame until we're out of frames */
  while ( -1 != (i = earliest(count, in_files))) {
    
    /* write out earliest frame, and fetch another from its
     * input file
     */
    write_frame((u_char*)out_file->pdh,
                wtap_phdr(in_files[i].wth),
                in_files[i].data_offset,
                wtap_pseudoheader(in_files[i].wth),
                wtap_buf_ptr(in_files[i].wth));
    in_files[i].ok = wtap_read(in_files[i].wth, &(in_files[i].err),
                                &(in_files[i].data_offset));
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
    exit(1);
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
    exit(1);
  }

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

  for (i = 0; i < count; i++) {
    if (wtap_snapshot_length(in_files[i].wth) > max_snapshot)
      max_snapshot = wtap_snapshot_length(in_files[i].wth);
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
open_in_files(int argc, char *argv[], in_file_t *in_files[])
{
  int i;
  int count = 0;
  int err;
  in_file_t *files;
  int files_size = argc * sizeof(in_file_t);
  

  files = malloc(files_size);
  if (!files) {
    fprintf(stderr, "mergecap: error allocating %d bytes of memory\n",
            files_size);
    exit(1);
  }
  *in_files = files;

  for (i = 0; i < argc; i++) {
    files[count].filename    = argv[i];
    files[count].wth         = wtap_open_offline(argv[i], &err, FALSE);
    files[count].err         = 0;
    files[count].data_offset = 0;
    files[count].ok          = TRUE;
    if (!files[count].wth) {
      fprintf(stderr, "mergecap: skipping %s: %s\n", argv[i],
              wtap_strerror(err));
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
    argc);

  return count;
}


/*
 * Show the usage
 */  
static void
usage()
{
  int i;
  const char *string;

  fprintf(stderr, "Usage: mergecap [-hva] [-s <snaplen>] [-T <encap type>]\n");
  fprintf(stderr, "          [-F <capture type>] -w <outfile> <infile> [...]\n\n");
  fprintf(stderr, "  where\t-h produces this help listing.\n");
  fprintf(stderr, "       \t-v verbose operation, default is silent\n");
  fprintf(stderr, "       \t-a files should be concatenated, not merged\n");
  fprintf(stderr, "       \t     Default merges based on frame timestamps\n");
  fprintf(stderr, "       \t-s <snaplen>: truncate packets to <snaplen> bytes of data\n");
  fprintf(stderr, "       \t-w <outfile>: sets output filename to <outfile>\n");
  fprintf(stderr, "       \t-T <encap type> encapsulation type to use:\n");
  for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
      string = wtap_encap_short_string(i);
      if (string != NULL)
        fprintf(stderr, "       \t     %s - %s\n",
          string, wtap_encap_string(i));
  }
  fprintf(stderr, "       \t     default is the same as the first input file\n");
  fprintf(stderr, "       \t-F <capture type> capture file type to write:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(stderr, "       \t     %s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(stderr, "       \t     default is libpcap\n");
}



int
main(int argc, char *argv[])
{
  extern char *optarg;
  extern int   optind;
  int          opt;
  char        *p;
  gboolean     do_append     = FALSE;
  int          in_file_count = 0;
  in_file_t   *in_files      = NULL;
  
  /* initialize out_file */
  out_file.filename   = NULL;   
  out_file.pdh        = NULL;              /* wiretap dumpfile */
  out_file.file_type  = WTAP_FILE_PCAP;    /* default to "libpcap" */
  out_file.frame_type = -2;                /* leave type alone */
  out_file.snaplen    = 0;                 /* no limit */
  out_file.count      = 1;                 /* frames output */

  /* Process the options first */
  while ((opt = getopt(argc, argv, "hvas:T:F:w:")) != EOF) {

    switch (opt) {
    case 'w':
      out_file.filename = optarg;
      break;
        
    case 'a':
      do_append = !do_append;
      break;
    
    case 'T':
      out_file.frame_type = wtap_short_string_to_encap(optarg);
      if (out_file.frame_type < 0) {
      	fprintf(stderr, "mergecap: \"%s\" is not a valid encapsulation type\n",
      	    optarg);
      	exit(1);
      }
      break;

    case 'F':
      out_file.file_type = wtap_short_string_to_file_type(optarg);
      if (out_file.file_type < 0) {
      	fprintf(stderr, "mergecap: \"%s\" is not a valid capture file type\n",
      	    optarg);
      	exit(1);
      }
      break;

    case 'v':
      verbose = !verbose;  /* Just invert */
      break;

    case 's':
      out_file.snaplen = strtol(optarg, &p, 10);
      if (p == optarg || *p != '\0') {
      	fprintf(stderr, "mergecap: \"%s\" is not a valid snapshot length\n",
      	    optarg);
      	exit(1);
      }
      break;

    case 'h':
      fprintf(stderr, "mergecap version %s\n", VERSION);
      usage();
      exit(1);
      break;

    case '?':              /* Bad options if GNU getopt */
      usage();
      exit(1);
      break;

    }

  }

  /* check for proper args; at a minimum, must have an output
   * filename and one input file
   */
  in_file_count = argc - optind;
  if (!out_file.filename) {
    fprintf(stderr, "mergecap: an output filename must be set with -w\n");
    usage();
    exit(1);
  }

  /* open the input files */
  in_file_count = open_in_files(in_file_count, &argv[optind], &in_files);
  if (in_file_count < 1) {
    fprintf(stderr, "mergecap: No valid input files\n");
    exit(1);
  }

  /* set the outfile frame type */
  if (out_file.frame_type == -2)
    out_file.frame_type = select_frame_type(in_file_count, in_files);
  
  /* open the outfile */
  if (!open_outfile(&out_file, max_snapshot_length(in_file_count, in_files))) {
    close_in_files(in_file_count, in_files);
    exit(1);
  }

  /* do the merge (or append) */
  if (do_append)
    append(in_file_count, in_files, &out_file);
  else
    merge(in_file_count, in_files, &out_file);

  close_in_files(in_file_count, in_files);
  close_outfile(&out_file);

  free(in_files);

  return 0;
}
