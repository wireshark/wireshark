/* Combine two dump files, either by appending or by merging by timestamp
 *
 * $Id: mergecap.c,v 1.1 2001/07/12 19:59:39 guy Exp $
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

#ifndef MAX
# define MAX(a,b) ((a)>(b))?(a):(b)
#endif

/*
 * Some globals so we can pass things to various routines
 */
static int count = 1;
static int out_file_type = WTAP_FILE_PCAP;   /* default to "libpcap"   */
static int out_frame_type = -2;              /* Leave frame type alone */
static int verbose = 0;                      /* Not so verbose         */
static int do_append  = 0;                   /* append, don't merge */
static unsigned int snaplen = 0;             /* No limit               */


/*
 * Routine to write frame to output file
 */
static void
write_frame(u_char *user, const struct wtap_pkthdr *phdr, int offset,
            union wtap_pseudo_header *pseudo_header, const u_char *buf) 
{
  wtap_dumper *pdh = (wtap_dumper*)user;
  int err;
  struct wtap_pkthdr snap_phdr;

  if (verbose)
    printf("Record: %u\n", count++);

  /* We simply write it, perhaps after truncating it; we could do other
   * things, like modify it. */
  if (snaplen != 0 && phdr->caplen > snaplen) {
    snap_phdr = *phdr;
    snap_phdr.caplen = snaplen;
    phdr = &snap_phdr;
  }

  if (!wtap_dump(pdh, phdr, pseudo_header, buf, &err)) {
    fprintf(stderr, "editcap: Error writing to output: %s\n",
            wtap_strerror(err));
    exit(1);
  }
}

/*
 * routine to append file2 to file1
 */
static void
append(wtap *wth_1, wtap *wth_2, wtap_dumper *pdh)
{
  int err;
  
  if (!wtap_loop(wth_1, 0, write_frame, (u_char*)pdh, &err)) {
    fprintf(stderr, "mergecap: Error appending: %s\n",
            wtap_strerror(err));
  }
  if (!wtap_loop(wth_2, 0, write_frame, (u_char*)pdh, &err)) {
    fprintf(stderr, "mergecap: Error appending: %s\n",
            wtap_strerror(err));
  }
}

/*
 * judges whether the first argument has an earlier
 * timestamp than the second
 */
static gboolean
is_earlier(struct wtap_pkthdr *one, struct wtap_pkthdr *two)
{
  if (one->ts.tv_sec > two->ts.tv_sec) {
    return FALSE;
  } else if (one->ts.tv_sec < two->ts.tv_sec) {
    return TRUE;
  } else if (one->ts.tv_usec > two->ts.tv_usec) {
    return FALSE;
  }
  /* either one < two or one == two
   * either way, return one
   */
  return TRUE;    
}

/*
 * actually merge the files
 */
static void
merge(wtap *wth_1, wtap *wth_2, wtap_dumper *pdh)
{
  int err;
  int data_offset_1, data_offset_2, loop = 0;
  gboolean ok_1, ok_2;

  ok_1 = wtap_read(wth_1, &err, &data_offset_1);
  ok_2 = wtap_read(wth_2, &err, &data_offset_2);

  while (ok_1 && ok_2) {

    /* if wth_1 is earlier, then write it and fetch another
     * otherwise, write wth_2 and increment it
     */
    if (is_earlier(wtap_phdr(wth_1), wtap_phdr(wth_2))) {
      write_frame((u_char*)pdh, wtap_phdr(wth_1), data_offset_1,
                  wtap_pseudoheader(wth_1), wtap_buf_ptr(wth_1));
      ok_1 = wtap_read(wth_1, &err, &data_offset_1);
    } else{
      write_frame((u_char*)pdh, wtap_phdr(wth_2), data_offset_2,
                  wtap_pseudoheader(wth_2), wtap_buf_ptr(wth_2));
      ok_2 = wtap_read(wth_2, &err, &data_offset_2);
    }
  }
  
  while (ok_1) {
    write_frame((u_char*)pdh, wtap_phdr(wth_1), data_offset_1,
                wtap_pseudoheader(wth_1), wtap_buf_ptr(wth_1));
    ok_1 = wtap_read(wth_1, &err, &data_offset_1);
  }
  while (ok_2) {
    write_frame((u_char*)pdh, wtap_phdr(wth_2), data_offset_2,
                wtap_pseudoheader(wth_2), wtap_buf_ptr(wth_2));
    ok_2 = wtap_read(wth_2, &err, &data_offset_2);
  }
}

/*
 * routine to open the input and output files, then call the merge
 */
static void
merge_files(const char *from1, const char *from2, const char *into)
{
  int err;
  wtap *wth_1, *wth_2;
  wtap_dumper *pdh;
  
  /* open the input files */
  wth_1 = wtap_open_offline(from1, &err, FALSE);
  if (!wth_1) {
    fprintf(stderr, "mergecap: Can't open %s: %s\n", from1,
            wtap_strerror(err));
    exit(1);
  }
  
  wth_2 = wtap_open_offline(from2, &err, FALSE);
  if (!wth_2) {
    fprintf(stderr, "mergecap: Can't open %s: %s\n", from2,
            wtap_strerror(err));
    wtap_close(wth_1);
    exit(1); 
  }

  if (verbose) {
    fprintf(stderr, "File %s is a %s capture file.\n", from1,
            wtap_file_type_string(wtap_file_type(wth_1)));
    fprintf(stderr, "File %s is a %s capture file.\n", from2,
            wtap_file_type_string(wtap_file_type(wth_2)));
  }
    
  /* open the output file */
  if (out_frame_type == -2)
    out_frame_type = wtap_file_encap(wth_1);
  pdh = wtap_dump_open(into, out_file_type, out_frame_type,
                       MAX(wtap_snapshot_length(wth_1),
                           wtap_snapshot_length(wth_2)), &err);
  if (!pdh) {
    fprintf(stderr, "mergecap: Can't open/create %s: %s\n", into,
            wtap_strerror(err));
    wtap_close(wth_1);
    wtap_close(wth_2);
    exit(1);
  }
  
  if (do_append)
    append(wth_1, wth_2, pdh);
  else
    merge(wth_1, wth_2, pdh);
  
  wtap_close(wth_1);
  wtap_close(wth_2);
  if (!wtap_dump_close(pdh, &err)) {
    fprintf(stderr, "mergecap: Error writing to %s: %s\n", into,
            wtap_strerror(err));
    exit(1);
  }
}

void usage()
{
  int i;
  const char *string;

  fprintf(stderr, "Usage: mergecap [-v] [-a] [-s <snaplen>]\n");
  fprintf(stderr, "                [-T <encap type>] [-F <capture type>]\n");
  fprintf(stderr, "                <infile1> <infile2> <outfile>\n\n");
  fprintf(stderr, "  where\t-a infile2 should be appended, not merged.\n");
  fprintf(stderr, "       \t   Default merges based on frame timestamps.\n");
  fprintf(stderr, "       \t-s <snaplen> truncate packets to <snaplen>\n");
  fprintf(stderr, "       \t   bytes of data\n");
  fprintf(stderr, "       \t-v verbose operation, default is silent\n");
  fprintf(stderr, "       \t-h produces this help listing.\n");
  fprintf(stderr, "       \t-T <encap type> encapsulation type to use:\n");
  for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
      string = wtap_encap_short_string(i);
      if (string != NULL)
        fprintf(stderr, "       \t    %s - %s\n",
          string, wtap_encap_string(i));
  }
  fprintf(stderr, "       \t    default is the same as the first input file\n");
  fprintf(stderr, "       \t-F <capture type> capture file type to write:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(stderr, "       \t    %s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(stderr, "       \t    default is libpcap\n");
}

int
main(int argc, char *argv[])
{
  wtap *wth;
  int i, err;
  extern char *optarg;
  extern int optind;
  char opt;
  char *p;

  /* Process the options first */
  while ((opt = getopt(argc, argv, "aT:F:vs:h")) != EOF) {

    switch (opt) {
    case 'a':
      do_append = !do_append;
      break;
    
    case 'T':
      out_frame_type = wtap_short_string_to_encap(optarg);
      if (out_frame_type < 0) {
      	fprintf(stderr, "mergecap: \"%s\" is not a valid encapsulation type\n",
      	    optarg);
      	exit(1);
      }
      break;

    case 'F':
      out_file_type = wtap_short_string_to_file_type(optarg);
      if (out_file_type < 0) {
      	fprintf(stderr, "editcap: \"%s\" is not a valid capture file type\n",
      	    optarg);
      	exit(1);
      }
      break;

    case 'v':
      verbose = !verbose;  /* Just invert */
      break;

    case 's':
      snaplen = strtol(optarg, &p, 10);
      if (p == optarg || *p != '\0') {
      	fprintf(stderr, "editcap: \"%s\" is not a valid snapshot length\n",
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

  /* should now have three arguments left: infile1, infile2, outfile */
#ifdef DEBUG
  printf("Optind = %i, argc = %i\n", optind, argc);
#endif

  if ((argc - optind) < 3) {
    usage();
    exit(1);
  }

  merge_files(argv[optind], argv[optind+1], argv[optind+2]);

  return 0;
}
  
