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
#include <errno.h>
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

#include "svnversion.h"
#include "merge.h"

#ifdef HAVE_IO_H
# include <io.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY 	0
#endif

/*
 * Show the usage
 */
static void
usage(void)
{
  int i;
  const char *string;

  printf("Usage: mergecap [-hva] [-s <snaplen>] [-T <encap type>]\n");
  printf("          [-F <capture type>] -w <outfile> <infile> [...]\n\n");
  printf("  where\t-h produces this help listing.\n");
  printf("       \t-v verbose operation, default is silent\n");
  printf("       \t-a files should be concatenated, not merged\n");
  printf("       \t     Default merges based on frame timestamps\n");
  printf("       \t-s <snaplen>: truncate packets to <snaplen> bytes of data\n");
  printf("       \t-w <outfile>: sets output filename to <outfile>\n");
  printf("       \t-T <encap type> encapsulation type to use:\n");
  for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
      string = wtap_encap_short_string(i);
      if (string != NULL)
        printf("       \t     %s - %s\n",
          string, wtap_encap_string(i));
  }
  printf("       \t     default is the same as the first input file\n");
  printf("       \t-F <capture type> capture file type to write:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      printf("       \t     %s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  printf("       \t     default is libpcap\n");
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
  merge_in_file_t   *in_files      = NULL;
  merge_out_file_t   out_file;
  int          err;
  char        *out_filename = NULL;

  /* initialize out_file */
  out_file.fd         = 0;
  out_file.pdh        = NULL;              /* wiretap dumpfile */
  out_file.file_type  = WTAP_FILE_PCAP;    /* default to "libpcap" */
  out_file.frame_type = -2;                /* leave type alone */
  out_file.snaplen    = 0;                 /* no limit */
  out_file.count      = 1;                 /* frames output */

  merge_verbose = VERBOSE_ERRORS;

  /* Process the options first */
  while ((opt = getopt(argc, argv, "hvas:T:F:w:")) != -1) {

    switch (opt) {
    case 'w':
      out_filename = optarg;
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
      merge_verbose = VERBOSE_ALL;
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
      printf("mergecap version %s"
#ifdef SVNVERSION
	  " (" SVNVERSION ")"
#endif
	  "\n", VERSION);
      usage();
      exit(0);
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
  if (!out_filename) {
    fprintf(stderr, "mergecap: an output filename must be set with -w\n");
    fprintf(stderr, "          run with -h for help\n");
    exit(1);
  }

  /* open the input files */
  in_file_count = merge_open_in_files(in_file_count, &argv[optind], &in_files, &err);
  if (in_file_count < 1) {
    fprintf(stderr, "mergecap: No valid input files\n");
    exit(1);
  }

  /* set the outfile frame type */
  if (out_file.frame_type == -2)
    out_file.frame_type = merge_select_frame_type(in_file_count, in_files);

  /* open the outfile */
  if (strncmp(out_filename, "-", 2) == 0) {  
    /* use stdout as the outfile */
    out_file.fd = 1 /*stdout*/;
  } else {
    /* open the outfile */
    out_file.fd = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
  }
  if (out_file.fd == -1) {
    fprintf(stderr, "mergecap: Couldn't open output file %s: %s\n",
            out_filename, strerror(errno));
    exit(1);
  }  
    
  /* prepare the outfile */
  if (!merge_open_outfile(&out_file, merge_max_snapshot_length(in_file_count, in_files), &err)) {
    merge_close_in_files(in_file_count, in_files);
    exit(1);
  }

  /* do the merge (or append) */
  if (do_append)
    merge_append_files(in_file_count, in_files, &out_file, &err);
  else
    merge_files(in_file_count, in_files, &out_file, &err);

  merge_close_in_files(in_file_count, in_files);
  merge_close_outfile(&out_file);

  free(in_files);

  return 0;
}
