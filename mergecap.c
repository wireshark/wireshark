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

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "wsutil/wsgetopt.h"
#endif

#include "svnversion.h"
#include "merge.h"
#include "wsutil/file_util.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */

static int
get_natural_int(const char *string, const char *name)
{
  int number;
  char *p;

  number = (int) strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    fprintf(stderr, "mergecap: The specified %s \"%s\" isn't a decimal number\n",
	    name, string);
    exit(1);
  }
  if (number < 0) {
    fprintf(stderr, "mergecap: The specified %s is a negative number\n",
	    name);
    exit(1);
  }
  if (number > INT_MAX) {
    fprintf(stderr, "mergecap: The specified %s is too large (greater than %d)\n",
	    name, INT_MAX);
    exit(1);
  }
  return number;
}

static int
get_positive_int(const char *string, const char *name)
{
  int number;

  number = get_natural_int(string, name);

  if (number == 0) {
    fprintf(stderr, "mergecap: The specified %s is zero\n",
	    name);
    exit(1);
  }

  return number;
}

/*
 * Show the usage
 */
static void
usage(void)
{

  fprintf(stderr, "Mergecap %s"
#ifdef SVNVERSION
	  " (" SVNVERSION " from " SVNPATH ")"
#endif
	  "\n", VERSION);
  fprintf(stderr, "Merge two or more capture files into one.\n");
  fprintf(stderr, "See http://www.wireshark.org for more information.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: mergecap [options] -w <outfile>|- <infile> ...\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Output:\n");
  fprintf(stderr, "  -a                concatenate rather than merge files.\n");
  fprintf(stderr, "                    default is to merge based on frame timestamps.\n");
  fprintf(stderr, "  -s <snaplen>      truncate packets to <snaplen> bytes of data.\n");
  fprintf(stderr, "  -w <outfile>|-    set the output filename to <outfile> or '-' for stdout.\n");
  fprintf(stderr, "  -F <capture type> set the output file type; default is libpcap.\n");
  fprintf(stderr, "                    an empty \"-F\" option will list the file types.\n");
  fprintf(stderr, "  -T <encap type>   set the output file encapsulation type;\n");
  fprintf(stderr, "                    default is the same as the first input file.\n");
  fprintf(stderr, "                    an empty \"-T\" option will list the encapsulation types.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Miscellaneous:\n");
  fprintf(stderr, "  -h                display this help and exit.\n");
  fprintf(stderr, "  -v                verbose output.\n");
}

static void list_capture_types(void) {
    int i;

    fprintf(stderr, "mergecap: The available capture file types for \"F\":\n");
    for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
      if (wtap_dump_can_open(i))
        fprintf(stderr, "    %s - %s\n",
          wtap_file_type_short_string(i), wtap_file_type_string(i));
    }
}

static void list_encap_types(void) {
    int i;
    const char *string;

    fprintf(stderr, "mergecap: The available encapsulation types for \"T\":\n");
    for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
        string = wtap_encap_short_string(i);
        if (string != NULL)
          fprintf(stderr, "    %s - %s\n",
            string, wtap_encap_string(i));
    }
}

int
main(int argc, char *argv[])
{
  int          opt;

  gboolean     do_append     = FALSE;
  gboolean     verbose       = FALSE;
  int          in_file_count = 0;
  guint        snaplen = 0;
#ifdef PCAP_NG_DEFAULT
  int          file_type = WTAP_FILE_PCAPNG;	/* default to pcap format */
#else
  int          file_type = WTAP_FILE_PCAP;	/* default to pcapng format */
#endif
  int          frame_type = -2;
  int          out_fd;
  merge_in_file_t   *in_files      = NULL;
  int          i;
  wtap        *wth;
  struct wtap_pkthdr *phdr, snap_phdr;
  wtap_dumper *pdh;
  int          open_err, read_err, write_err, close_err;
  gchar       *err_info;
  int          err_fileno;
  char        *out_filename = NULL;
  gboolean     got_read_error = FALSE, got_write_error = FALSE;
  int          count;

#ifdef _WIN32
  arg_list_utf_16to8(argc, argv);
#endif /* _WIN32 */

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
      frame_type = wtap_short_string_to_encap(optarg);
      if (frame_type < 0) {
      	fprintf(stderr, "mergecap: \"%s\" isn't a valid encapsulation type\n",
      	    optarg);
        list_encap_types();
      	exit(1);
      }
      break;

    case 'F':
      file_type = wtap_short_string_to_file_type(optarg);
      if (file_type < 0) {
      	fprintf(stderr, "mergecap: \"%s\" isn't a valid capture file type\n",
      	    optarg);
        list_capture_types();
      	exit(1);
      }
      break;

    case 'v':
      verbose = TRUE;
      break;

    case 's':
      snaplen = get_positive_int(optarg, "snapshot length");
      break;

    case 'h':
      usage();
      exit(0);
      break;

    case '?':              /* Bad options if GNU getopt */
      switch(optopt) {
      case'F':
        list_capture_types();
        break;
      case'T':
        list_encap_types();
        break;
      default:
        usage();
      }
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
    return 1;
  }
  if (in_file_count < 1) {
    fprintf(stderr, "mergecap: No input files were specified\n");
    return 1;
  }

  /* open the input files */
  if (!merge_open_in_files(in_file_count, &argv[optind], &in_files,
                           &open_err, &err_info, &err_fileno)) {
    fprintf(stderr, "mergecap: Can't open %s: %s\n", argv[optind + err_fileno],
        wtap_strerror(open_err));
    switch (open_err) {

    case WTAP_ERR_UNSUPPORTED:
    case WTAP_ERR_UNSUPPORTED_ENCAP:
    case WTAP_ERR_BAD_RECORD:
      fprintf(stderr, "(%s)\n", err_info);
      g_free(err_info);
      break;
    }
    return 2;
  }

  if (verbose) {
    for (i = 0; i < in_file_count; i++)
      fprintf(stderr, "mergecap: %s is type %s.\n", argv[optind + i],
              wtap_file_type_string(wtap_file_type(in_files[i].wth)));
  }

  if (snaplen == 0) {
    /*
     * Snapshot length not specified - default to the maximum of the
     * snapshot lengths of the input files.
     */
    snaplen = merge_max_snapshot_length(in_file_count, in_files);
  }

  /* set the outfile frame type */
  if (frame_type == -2) {
    /*
     * Default to the appropriate frame type for the input files.
     */
    frame_type = merge_select_frame_type(in_file_count, in_files);
    if (verbose) {
      if (frame_type == WTAP_ENCAP_PER_PACKET) {
        /*
         * Find out why we had to choose WTAP_ENCAP_PER_PACKET.
         */
        int first_frame_type, this_frame_type;

        first_frame_type = wtap_file_encap(in_files[0].wth);
        for (i = 1; i < in_file_count; i++) {
          this_frame_type = wtap_file_encap(in_files[i].wth);
          if (first_frame_type != this_frame_type) {
            fprintf(stderr, "mergecap: multiple frame encapsulation types detected\n");
            fprintf(stderr, "          defaulting to WTAP_ENCAP_PER_PACKET\n");
            fprintf(stderr, "          %s had type %s (%s)\n",
                    in_files[0].filename,
                    wtap_encap_string(first_frame_type),
                    wtap_encap_short_string(first_frame_type));
            fprintf(stderr, "          %s had type %s (%s)\n",
                    in_files[i].filename,
                    wtap_encap_string(this_frame_type),
                    wtap_encap_short_string(this_frame_type));
            break;
          }
        }
      }
      fprintf(stderr, "mergecap: selected frame_type %s (%s)\n",
              wtap_encap_string(frame_type),
              wtap_encap_short_string(frame_type));
    }
  }

  /* open the outfile */
  if (strncmp(out_filename, "-", 2) == 0) {
    /* use stdout as the outfile */
    out_fd = 1 /*stdout*/;
  } else {
    /* open the outfile */
    out_fd = ws_open(out_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (out_fd == -1) {
      fprintf(stderr, "mergecap: Couldn't open output file %s: %s\n",
              out_filename, strerror(errno));
      exit(1);
    }
  }

  /* prepare the outfile */
  pdh = wtap_dump_fdopen(out_fd, file_type, frame_type, snaplen, FALSE /* compressed */, &open_err);
  if (pdh == NULL) {
    merge_close_in_files(in_file_count, in_files);
    g_free(in_files);
    fprintf(stderr, "mergecap: Can't open or create %s: %s\n", out_filename,
            wtap_strerror(open_err));
    exit(1);
  }

  /* do the merge (or append) */
  count = 1;
  for (;;) {
    if (do_append)
      wth = merge_append_read_packet(in_file_count, in_files, &read_err,
                                     &err_info);
    else
      wth = merge_read_packet(in_file_count, in_files, &read_err,
                              &err_info);
    if (wth == NULL) {
      if (read_err != 0)
        got_read_error = TRUE;
      break;
    }

    if (verbose)
      fprintf(stderr, "Record: %u\n", count++);

    /* We simply write it, perhaps after truncating it; we could do other
     * things, like modify it. */
    phdr = wtap_phdr(wth);
    if (snaplen != 0 && phdr->caplen > snaplen) {
      snap_phdr = *phdr;
      snap_phdr.caplen = snaplen;
      phdr = &snap_phdr;
    }

    if (!wtap_dump(pdh, phdr, wtap_pseudoheader(wth),
         wtap_buf_ptr(wth), &write_err)) {
      got_write_error = TRUE;
      break;
    }
  }

  merge_close_in_files(in_file_count, in_files);
  if (!got_read_error && !got_write_error) {
    if (!wtap_dump_close(pdh, &write_err))
      got_write_error = TRUE;
  } else
    wtap_dump_close(pdh, &close_err);

  if (got_read_error) {
    /*
     * Find the file on which we got the error, and report the error.
     */
    for (i = 0; i < in_file_count; i++) {
      if (in_files[i].state == GOT_ERROR) {
        fprintf(stderr, "mergecap: Error reading %s: %s\n",
                in_files[i].filename, wtap_strerror(read_err));
        switch (read_err) {

        case WTAP_ERR_UNSUPPORTED:
        case WTAP_ERR_UNSUPPORTED_ENCAP:
        case WTAP_ERR_BAD_RECORD:
          fprintf(stderr, "(%s)\n", err_info);
          g_free(err_info);
          break;
        }
      }
    }
  }

  if (got_write_error) {
    fprintf(stderr, "mergecap: Error writing to outfile: %s\n",
            wtap_strerror(write_err));
  }

  g_free(in_files);

  return (!got_read_error && !got_write_error) ? 0 : 2;
}
