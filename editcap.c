/* Edit capture files.  We can delete records, or simply convert from one 
 * format to another format.
 *
 * $Id: editcap.c,v 1.13 2000/12/03 21:11:05 guy Exp $
 *
 * Originally written by Richard Sharpe.
 * Improved by Guy Harris.
 * Further improved by Richard Sharpe.
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
 * Some globals so we can pass things to various routines
 */

struct select_item {

  int inclusive;
  int first, second;

} select_item;

struct select_item selectfrm[100];
int max_selected = -1;
static int count = 1;
static int keep_em = 0;
static int out_file_type = WTAP_FILE_PCAP;   /* default to "libpcap"   */
static int out_frame_type = -2;              /* Leave frame type alone */
static int verbose = 0;                      /* Not so verbose         */
static int snaplen = 0;                      /* No limit               */

/* Add a selection item, a simple parser for now */

void add_selection(char *sel) 
{
  char *locn;
  char *next;

  if (max_selected == (sizeof(selectfrm)/sizeof(struct select_item)) - 1)
    return;

  printf("Add_Selected: %s\n", sel);

  if ((locn = strchr(sel, '-')) == NULL) { /* No dash, so a single number? */

    printf("Not inclusive ...");

    max_selected++;
    selectfrm[max_selected].inclusive = 0;
    selectfrm[max_selected].first = atoi(sel);

    printf(" %i\n", selectfrm[max_selected].first);

  }
  else {

    printf("Inclusive ...");

    next = locn + 1;
    max_selected++;
    selectfrm[max_selected].inclusive = 1;
    selectfrm[max_selected].first = atoi(sel);
    selectfrm[max_selected].second = atoi(next);

    printf(" %i, %i\n", selectfrm[max_selected].first, selectfrm[max_selected].second);

  }


}

/* Was the record selected? */

int selected(int recno)
{
  int i = 0;

  for (i = 0; i<= max_selected; i++) {

    if (selectfrm[i].inclusive) {
      if (selectfrm[i].first <= recno && selectfrm[i].second >= recno)
	return 1;
    }
    else {
      if (recno == selectfrm[i].first)
	return 1;
    }
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
    union wtap_pseudo_header *pseudo_header, const u_char *buf) 
{
  callback_arg *argp = (callback_arg *)user;
  int err;
  struct wtap_pkthdr snap_phdr;

  if ((!selected(count) && !keep_em) ||
      (selected(count) && keep_em)) {

    if (verbose)
      printf("Record: %u\n", count);

    /* We simply write it, perhaps after truncating it; we could do other
       things, like modify it. */

    if (snaplen != 0 && phdr->caplen > snaplen) {
      snap_phdr = *phdr;
      snap_phdr.caplen = snaplen;
      phdr = &snap_phdr;
    }

    if (!wtap_dump(argp->pdh, phdr, pseudo_header, buf, &err)) {

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
  const char *string;

  fprintf(stderr, "Usage: editcap [-r] [-h] [-v] [-T <encap type>] [-F <capture type>]\n");
  fprintf(stderr, "               [-s <snaplen>] <infile> <outfile> [ <record#>[-<record#>] ... ]\n");
  fprintf(stderr, "  where\t-r specifies that the records specified should be kept, not deleted, \n");
  fprintf(stderr, "                           default is to delete\n");
  fprintf(stderr, "       \t-v specifies verbose operation, default is silent\n");
  fprintf(stderr, "       \t-h produces this help listing.\n");
  fprintf(stderr, "       \t-T <encap type> specifies the encapsulation type to use:\n");
  for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
      string = wtap_encap_short_string(i);
      if (string != NULL)
        fprintf(stderr, "       \t    %s - %s\n",
          string, wtap_encap_string(i));
  }
  fprintf(stderr, "       \t    default is the same as the input file\n");
  fprintf(stderr, "       \t-F <capture type> specifies the capture file type to write:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(stderr, "       \t    %s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(stderr, "       \t    default is libpcap\n");
  fprintf(stderr, "       \t-s <snaplen> specifies that packets should be truncated to\n");
  fprintf(stderr, "       \t   <snaplen> bytes of data\n");
  fprintf(stderr, "\n      \t    A range of records can be specified as well\n");
}

int main(int argc, char *argv[])

{
  wtap *wth;
  int i, err;
  callback_arg args;
  extern char *optarg;
  extern int optind;
  char opt;
  char *p;

  /* Process the options first */

  while ((opt = getopt(argc, argv, "T:F:rvs:h")) != EOF) {

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

    case 'v':
      verbose = !verbose;  /* Just invert */
      break;

    case 'r':
      keep_em = !keep_em;  /* Just invert */
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
      usage();
      exit(1);
      break;

    case '?':              /* Bad options if GNU getopt */
      usage();
      exit(1);
      break;

    }

  }

#ifdef DEBUG
  printf("Optind = %i, argc = %i\n", optind, argc);
#endif

  if ((argc - optind) < 1) {

    usage();
    exit(1);

  }

  wth = wtap_open_offline(argv[optind], &err, FALSE);

  if (!wth) {

    fprintf(stderr, "editcap: Can't open %s: %s\n", argv[optind],
        wtap_strerror(err));
    exit(1);

  }

  if (verbose) {

    fprintf(stderr, "File %s is a %s capture file.\n", argv[optind],
	    wtap_file_type_string(wtap_file_type(wth)));

  }

  /*
   * Now, process the rest, if any ... we only write if there is an extra
   * argument or so ...
   */

  if ((argc - optind) >= 2) {

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
      add_selection(argv[i]);

    wtap_loop(wth, 0, edit_callback, (char *)&args, &err);

    if (!wtap_dump_close(args.pdh, &err)) {

      fprintf(stderr, "editcap: Error writing to %s: %s\n", argv[2],
	      wtap_strerror(err));
      exit(1);

    }
  }

  exit(0);
  return 0;  /* Silence compiler warnings */
}
  
