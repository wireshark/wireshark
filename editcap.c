/* Edit capture files.  We can delete records, or simply convert from one 
 * format to another format.
 *
 * $Id: editcap.c,v 1.3 1999/12/05 01:27:14 guy Exp $
 *
 * Originally written by Richard Sharpe.
 * Improved by Guy Harris.
 */

#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <sys/time.h>
#include "wtap.h"

/*
 * Some globals so we can pass things to various routines
 */

int selectfrm[100], max_selected = -1;
static int count = 1;
static int keep_em = 0;
static int out_file_type = WTAP_FILE_PCAP;	/* default to "libpcap" */
static int out_frame_type = -2;   /* Leave frame type alone */

/* Was the record selected? */

int selected(int recno)
{
  int i = 0;

  for (i = 0; i<= max_selected; i++) {

    if (recno == selectfrm[i]) return 1;

  }

  return 0;

}

/* An argument to the callback routine */

typedef struct {
	char	*filename;
	wtap_dumper *pdh;
} callback_arg;

/*
 *The callback routine that is called for each frame in the input file
 */

static void
edit_callback(u_char *user, const struct wtap_pkthdr *phdr, int offset,
    const u_char *buf) 
{
  callback_arg *argp = (callback_arg *)user;
  int err;

  if ((!selected(count) && !keep_em) ||
      (selected(count) && keep_em)) {

    printf("Record: %u\n", count);

    /* We simply write it, we could do other things, like modify it */

    if (!wtap_dump(argp->pdh, phdr, buf, &err)) {

      fprintf(stderr, "editcap: Error writing to %s: %s\n", argp->filename,
        wtap_strerror(err));
      exit(1);

    }

  }

  count++;

}

void usage()
{
  int i;
  char *string;

  fprintf(stderr, "Usage: editcap [-r] [-T <encap type>] [-F <capture type>] <infile> <outfile>\\\n");
  fprintf(stderr, "                [ <record#> ... ]\n");
  fprintf(stderr, "  where\t-r specifies that the records specified should be kept, not deleted, \n");
  fprintf(stderr, "                           default is to delete\n");
  fprintf(stderr, "       \t-T <encap type> specifies the encapsulation type to use:\n");
  for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
      string = wtap_encap_short_string(i);
      if (string != NULL)
        fprintf(stderr, "       \t    %s - %s\n",
          string, wtap_encap_string(i));
  }
  fprintf(stderr, "       \t   default is the same as the input file\n");
  fprintf(stderr, "       \t-F <capture type> specifies the capture file type to write:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(stderr, "       \t    %s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(stderr, "       \t   default is libpcap\n");
}

int main(int argc, char *argv[])

{
  wtap *wth;
  int read_bytes, pcnt = 0, i, err;
  callback_arg args;
  extern char *optarg;
  extern int optind, opterr, optopt;
  char opt;

  /* Process the options first */

  while ((opt = getopt(argc, argv, "T:F:r")) != EOF) {

    switch (opt) {

    case 'T':
      out_frame_type = wtap_short_string_to_encap(optarg);
      if (out_frame_type < 0) {
      	fprintf(stderr, "editcap: \"%s\" is not a valid encapsulation type\n",
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

    case 'r':
      keep_em = !keep_em;  /* Just invert */
      break;

    case '?':              /* Bad options if GNU getopt */
      usage();
      exit(1);
      break;

    }

  }

  printf("Optind = %i, argc = %i\n", optind, argc);

  if ((argc - optind) < 2) {

    usage();
    exit(1);

  }

  wth = wtap_open_offline(argv[optind], &err);

  if (!wth) {

    fprintf(stderr, "editcap: Can't open %s: %s\n", argv[optind],
        wtap_strerror(err));
    exit(1);

  }

  args.filename = argv[optind + 1];
  if (out_frame_type == -2)
    out_frame_type = wtap_file_encap(wth);

  args.pdh = wtap_dump_open(argv[optind + 1], out_file_type,
		out_frame_type, wtap_snapshot_length(wth), &err);
  if (args.pdh == NULL) {

    fprintf(stderr, "editcap: Can't open or create %s: %s\n", argv[optind+1],
        wtap_strerror(err));
    exit(1);

  }

  for (i = optind + 2; i < argc; i++)
    selectfrm[++max_selected] = atoi(argv[i]);

  wtap_loop(wth, 0, edit_callback, (char *)&args, &err);

  if (!wtap_dump_close(args.pdh, &err)) {

    fprintf(stderr, "editcap: Error writing to %s: %s\n", argv[2],
        wtap_strerror(err));
    exit(1);

  }
  exit(0);
}
  
