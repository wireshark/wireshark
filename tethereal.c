/* tethereal.c
 *
 * $Id: tethereal.c,v 1.14 2000/01/24 04:53:54 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Text-mode variant, by Gilbert Ramirez <gram@xiexie.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#if defined(HAVE_UCD_SNMP_SNMP_H)
#ifdef HAVE_UCD_SNMP_VERSION_H
#include <ucd-snmp/version.h>
#endif /* HAVE_UCD_SNMP_VERSION_H */
#elif defined(HAVE_SNMP_SNMP_H)
#ifdef HAVE_SNMP_VERSION_H
#include <snmp/version.h>
#endif /* HAVE_SNMP_VERSION_H */
#endif /* SNMP */

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include "globals.h"
#include "timestamp.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "follow.h"
#include "util.h"
#include "ui_util.h"
#include "conversation.h"
#include "plugins.h"

static guint32 firstsec, firstusec;
static guint32 prevsec, prevusec;
static gchar   comp_info_str[256];
static gboolean verbose;
static gboolean print_hex;

#ifdef HAVE_LIBPCAP
typedef struct _loop_data {
  gint           linktype;
  pcap_t        *pch;
  wtap_dumper   *pdh;
} loop_data;

static loop_data ld;

static int capture(int, int);
static void capture_pcap_cb(u_char *, const struct pcap_pkthdr *,
  const u_char *);
static void capture_cleanup(int);
#endif

typedef struct {
  capture_file *cf;
  wtap_dumper *pdh;
} cb_args_t;

static int load_cap_file(capture_file *, int);
static void wtap_dispatch_cb_write(u_char *, const struct wtap_pkthdr *, int,
    const u_char *);
static void wtap_dispatch_cb_print(u_char *, const struct wtap_pkthdr *, int,
    const u_char *);
static gchar *col_info(frame_data *, gint);

packet_info  pi;
capture_file cf;
FILE        *data_out_file = NULL;
guint        main_ctx, file_ctx;
ts_type timestamp_type = RELATIVE;

/* call initialization routines at program startup time */
static void
ethereal_proto_init(void) {
  init_dissect_rpc();
  proto_init();
  init_dissect_udp();
  dfilter_init();
#ifdef HAVE_PLUGINS
  init_plugins();
#endif
}

static void
ethereal_proto_cleanup(void) {
	proto_cleanup();
	dfilter_cleanup();
}

static void 
print_usage(void)
{
  int i;

  fprintf(stderr, "This is GNU t%s %s, compiled with %s\n", PACKAGE,
	  VERSION, comp_info_str);

  fprintf(stderr, "t%s [ -vVh ] [ -c count ] [ -D ] [ -f <filter expression> ]\n", PACKAGE);
  fprintf(stderr, "\t[ -F <capture type> ] [ -i iface ] [ -n ] [ -r infile ]\n");
  fprintf(stderr, "\t[ -R <filter expression> ] [ -s snaplen ] [ -t <time stamp format> ]\n");
  fprintf(stderr, "\t[ -w savefile ] [ -x ]\n");
  fprintf(stderr, "Valid file type arguments to the \"-F\" flag:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(stderr, "\t%s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(stderr, "\tdefault is libpcap\n");
}

int
main(int argc, char *argv[])
{
  int                  opt, i;
  extern char         *optarg;
  gboolean             arg_error = FALSE;
#ifdef HAVE_LIBPCAP
  extern char          pcap_version[];
#endif
  char                *pf_path;
  int                  err;
#ifdef HAVE_LIBPCAP
  int                  packet_count = 0;
  GList               *if_list;
  gchar                err_str[PCAP_ERRBUF_SIZE];
#else
  gboolean             capture_option_specified = FALSE;
#endif
  int                 out_file_type = WTAP_FILE_PCAP;
  gchar               *cf_name = NULL, *rfilter = NULL;
  dfilter             *rfcode = NULL;
  e_prefs             *prefs;

  /* If invoked with the "-G" flag, we dump out a glossary of
     display filter symbols.

     We do this here to mirror what happens in the GTK+ version, although
     it's not necessary here. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    ethereal_proto_init();
    proto_registrar_dump();
    exit(0);
  }

  prefs = read_prefs(&pf_path);
  if (pf_path != NULL) {
    fprintf(stderr, "Can't open preferences file \"%s\": %s.\n", pf_path,
        strerror(errno));
  }
    
  /* Initialize the capture file struct */
  cf.plist		= NULL;
  cf.plist_end		= NULL;
  cf.wth		= NULL;
  cf.fh			= NULL;
  cf.filename		= NULL;
  cf.user_saved		= FALSE;
  cf.is_tempfile	= FALSE;
  cf.rfcode		= NULL;
  cf.dfilter		= NULL;
  cf.dfcode		= NULL;
#ifdef HAVE_LIBPCAP
  cf.cfilter		= g_strdup("");
#endif
  cf.iface		= NULL;
  cf.save_file		= NULL;
  cf.save_file_fd	= -1;
  cf.snap		= WTAP_MAX_PACKET_SIZE;
  cf.count		= 0;
  cf.cinfo.num_cols	= prefs->num_cols;
  cf.cinfo.col_fmt      = (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);
  cf.cinfo.fmt_matx	= (gboolean **) g_malloc(sizeof(gboolean *) * cf.cinfo.num_cols);
  cf.cinfo.col_width	= (gint *) g_malloc(sizeof(gint) * cf.cinfo.num_cols);
  cf.cinfo.col_title    = (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);
  cf.cinfo.col_data	= (gchar **) g_malloc(sizeof(gchar *) * cf.cinfo.num_cols);

  /* Assemble the compile-time options */
  snprintf(comp_info_str, 256,
#ifdef GTK_MAJOR_VERSION
    "GTK+ %d.%d.%d, %s%s, %s%s, %s%s", GTK_MAJOR_VERSION, GTK_MINOR_VERSION,
    GTK_MICRO_VERSION,
#else
    "GTK+ (version unknown), %s%s, %s%s, %s%s",
#endif

#ifdef HAVE_LIBPCAP
   "with libpcap ", pcap_version,
#else
   "without libpcap", "",
#endif

#ifdef HAVE_LIBZ
#ifdef ZLIB_VERSION
   "with libz ", ZLIB_VERSION,
#else /* ZLIB_VERSION */
   "with libz ", "(version unknown)",
#endif /* ZLIB_VERSION */
#else /* HAVE_LIBZ */
   "without libz", "",
#endif /* HAVE_LIBZ */

/* Oh, this is pretty */
#if defined(HAVE_UCD_SNMP_SNMP_H)
#ifdef HAVE_UCD_SNMP_VERSION_H
   "with UCD SNMP ", VersionInfo
#else /* HAVE_UCD_SNMP_VERSION_H */
   "with UCD SNMP ", "(version unknown)"
#endif /* HAVE_UCD_SNMP_VERSION_H */
#elif defined(HAVE_SNMP_SNMP_H)
#ifdef HAVE_SNMP_VERSION_H
   "with CMU SNMP ", snmp_Version()
#else /* HAVE_SNMP_VERSION_H */
   "with CMU SNMP ", "(version unknown)"
#endif /* HAVE_SNMP_VERSION_H */
#else /* no SNMP */
   "without SNMP", ""
#endif
   );
    
  /* Now get our args */
  while ((opt = getopt(argc, argv, "c:Df:F:hi:nr:R:s:t:vw:Vx")) != EOF) {
    switch (opt) {
      case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
        packet_count = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'D':        /* Turn off DSCP printing */
	g_ip_dscp_actif = FALSE;
	break;
      case 'f':
#ifdef HAVE_LIBPCAP
	cf.cfilter = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'F':
        out_file_type = wtap_short_string_to_file_type(optarg);
        if (out_file_type < 0) {
          fprintf(stderr, "tethereal: \"%s\" is not a valid capture file type\n",
			optarg);
          exit(1);
        }
        break;
      case 'h':        /* Print help and exit */
	print_usage();
	exit(0);
        break;
      case 'i':        /* Use interface xxx */
#ifdef HAVE_LIBPCAP
        cf.iface = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'n':        /* No name resolution */
	g_resolving_actif = 0;
	break;
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 's':        /* Set the snapshot (capture) length */
#ifdef HAVE_LIBPCAP
        cf.snap = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_type = RELATIVE;
        else if (strcmp(optarg, "a") == 0)
          timestamp_type = ABSOLUTE;
        else if (strcmp(optarg, "d") == 0)
          timestamp_type = DELTA;
        else {
          fprintf(stderr, "tethereal: Invalid time stamp type \"%s\"\n",
            optarg);
          fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
          fprintf(stderr, "or \"d\" for delta.\n");
          exit(1);
        }
        break;
      case 'v':        /* Show version and exit */
        printf("t%s %s, with %s\n", PACKAGE, VERSION, comp_info_str);
        exit(0);
        break;
      case 'w':        /* Write to capture file xxx */
        cf.save_file = g_strdup(optarg);
	break;
      case 'V':        /* Verbose */
        verbose = TRUE;
        break;
      case 'x':        /* Print packet data in hex (and ASCII) */
        print_hex = TRUE;
        break;
    }
  }
  
#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    fprintf(stderr, "This version of Ethereal was not built with support for capturing packets.\n");
#endif
  if (arg_error)
    print_usage();

  /* Build the column format array */  
  for (i = 0; i < cf.cinfo.num_cols; i++) {
    cf.cinfo.col_fmt[i] = get_column_format(i);
    cf.cinfo.col_title[i] = g_strdup(get_column_title(i));
    cf.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cf.cinfo.fmt_matx[i], cf.cinfo.col_fmt[i]);
    if (cf.cinfo.col_fmt[i] == COL_INFO)
      cf.cinfo.col_data[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      cf.cinfo.col_data[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  if (cf.snap < 1)
    cf.snap = WTAP_MAX_PACKET_SIZE;
  else if (cf.snap < MIN_PACKET_SIZE)
    cf.snap = MIN_PACKET_SIZE;
  
  ethereal_proto_init();   /* Init anything that needs initializing */

  if (rfilter != NULL) {
    if (dfilter_compile(rfilter, &rfcode) != 0) {
      fprintf(stderr, "tethereal: %s\n", dfilter_error_msg);
      ethereal_proto_cleanup();
      exit(2);
    }
  }
  cf.rfcode = rfcode;
  if (cf_name) {
    err = open_cap_file(cf_name, FALSE, &cf);
    if (err != 0) {
      ethereal_proto_cleanup();
      exit(2);
    }
    err = load_cap_file(&cf, out_file_type);
    if (err != 0) {
      ethereal_proto_cleanup();
      exit(2);
    }
    cf_name[0] = '\0';
  } else {
    /* No capture file specified, so we're supposed to do a live capture;
       do we have support for live captures? */
#ifdef HAVE_LIBPCAP
    /* Yes; did the user specify an interface to use? */
    if (cf.iface == NULL) {
        /* No - pick the first one from the list of interfaces. */
        if_list = get_interface_list(&err, err_str);
        if (if_list == NULL) {
            switch (err) {

            case CANT_GET_INTERFACE_LIST:
                fprintf(stderr, "tethereal: Can't get list of interfaces: %s\n",
			err_str);
                break;

            case NO_INTERFACES_FOUND:
                fprintf(stderr, "tethereal: There are no interfaces on which a capture can be done\n");
                break;
            }
            exit(2);
        }
        cf.iface = g_strdup(if_list->data);	/* first interface */
        free_interface_list(if_list);
    }
    capture(packet_count, out_file_type);
#else
    /* No - complain. */
    fprintf(stderr, "This version of Tethereal was not built with support for capturing packets.\n");
    exit(2);
#endif
  }

  ethereal_proto_cleanup();

  exit(0);
}

#ifdef HAVE_LIBPCAP
/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
static int
capture(int packet_count, int out_file_type)
{
  gchar       err_str[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netnum, netmask;
  void        (*oldhandler)(int);
  int         err, inpkts;
  char        errmsg[1024+1];

  ld.linktype       = WTAP_ENCAP_UNKNOWN;
  ld.pdh            = NULL;

  /* Open the network interface to capture from it. */
  ld.pch = pcap_open_live(cf.iface, cf.snap, 1, 1000, err_str);

  if (ld.pch == NULL) {
    /* Well, we couldn't start the capture.
       If this is a child process that does the capturing in sync
       mode or fork mode, it shouldn't do any UI stuff until we pop up the
       capture-progress window, and, since we couldn't start the
       capture, we haven't popped it up. */
    snprintf(errmsg, sizeof errmsg,
      "The capture session could not be initiated (%s).\n"
      "Please check to make sure you have sufficient permissions, and that\n"
      "you have the proper interface specified.", err_str);
    goto error;
  }

  if (cf.cfilter) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet (cf.iface, &netnum, &netmask, err_str) < 0) {
      snprintf(errmsg, sizeof errmsg,
        "Can't use filter:  Couldn't obtain netmask info (%s).", err_str);
      goto error;
    }
    if (pcap_compile(ld.pch, &cf.fcode, cf.cfilter, 1, netmask) < 0) {
      snprintf(errmsg, sizeof errmsg, "Unable to parse filter string (%s).",
	pcap_geterr(ld.pch));
      goto error;
    }
    if (pcap_setfilter(ld.pch, &cf.fcode) < 0) {
      snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(ld.pch));
      goto error;
    }
  }

  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_datalink(ld.pch));
  if (cf.save_file != NULL) {
    /* Set up to write to the capture file. */
    if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
      strcpy(errmsg, "The network you're capturing from is of a type"
               " that Ethereal doesn't support.");
      goto error;
    }
    ld.pdh = wtap_dump_open(cf.save_file, out_file_type,
		ld.linktype, pcap_snapshot(ld.pch), &err);

    if (ld.pdh == NULL) {
      /* We couldn't set up to write to the capture file. */
      switch (err) {

      case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
        strcpy(errmsg, "Tethereal does not support writing capture files in that format.");
        break;

      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
        strcpy(errmsg, "Tethereal cannot save this capture in that format.");
        break;

      case WTAP_ERR_CANT_OPEN:
        strcpy(errmsg, "The file to which the capture would be written"
                 " couldn't be created for some unknown reason.");
        break;

      case WTAP_ERR_SHORT_WRITE:
        strcpy(errmsg, "A full header couldn't be written to the file"
                 " to which the capture would be written.");
        break;

      default:
        if (err < 0) {
          sprintf(errmsg, "The file to which the capture would be"
                       " written (\"%s\") could not be opened: Error %d.",
   			cf.save_file, err);
        } else {
          sprintf(errmsg, "The file to which the capture would be"
                       " written (\"%s\") could not be opened: %s.",
 			cf.save_file, strerror(err));
        }
        break;
      }
      goto error;
    }
  }

  /* Catch SIGINT and SIGTERM and, if we get either of them, clean up
     and exit.
     XXX - deal with signal semantics on various platforms.  Or just
     use "sigaction()" and be done with it? */
  signal(SIGTERM, capture_cleanup);
  signal(SIGINT, capture_cleanup);
  if ((oldhandler = signal(SIGHUP, capture_cleanup)) != SIG_DFL)
    signal(SIGHUP, oldhandler);

  /* Let the user know what interface was chosen. */
  printf("Capturing on %s\n", cf.iface);

  inpkts = pcap_loop(ld.pch, packet_count, capture_pcap_cb, (u_char *) &ld);
  pcap_close(ld.pch);

  return TRUE;

error:
  g_free(cf.save_file);
  cf.save_file = NULL;
  fprintf(stderr, "tethereal: %s\n", errmsg);
  if (ld.pch != NULL)
    pcap_close(ld.pch);

  return FALSE;
}

static void
capture_pcap_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd)
{
  struct wtap_pkthdr whdr;
  loop_data *ld = (loop_data *) user;
  cb_args_t args;

  whdr.ts = phdr->ts;
  whdr.caplen = phdr->caplen;
  whdr.len = phdr->len;
  whdr.pkt_encap = ld->linktype;

  args.cf = &cf;
  args.pdh = ld->pdh;
  if (ld->pdh) {
    wtap_dispatch_cb_write((u_char *)&args, &whdr, 0, pd);
    cf.count++;
    printf("\r%u ", cf.count);
    fflush(stdout);
  } else {
    wtap_dispatch_cb_print((u_char *)&args, &whdr, 0, pd);
  }
}

static void
capture_cleanup(int signum)
{
  int err;

  printf("\n");
  pcap_close(ld.pch);
  if (ld.pdh != NULL)
    wtap_dump_close(ld.pdh, &err);
  /* XXX - complain if this fails */
  exit(0);
}
#endif /* HAVE_LIBPCAP */

static int
load_cap_file(capture_file *cf, int out_file_type)
{
  gint         linktype;
  wtap_dumper *pdh;
  int          err;
  int          success;
  cb_args_t    args;

  linktype = wtap_file_encap(cf->wth);
  if (cf->save_file != NULL) {
    /* Set up to write to the capture file. */
    pdh = wtap_dump_open(cf->save_file, out_file_type,
		linktype, wtap_snapshot_length(cf->wth), &err);

    if (pdh == NULL) {
      /* We couldn't set up to write to the capture file. */
      switch (err) {

      case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
        fprintf(stderr,
		"tethereal: Capture files can't be written in that format.\n");
        break;

      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
        fprintf(stderr,
"tethereal: The capture file being read cannot be written in that format.\n");
        break;

      case WTAP_ERR_CANT_OPEN:
        fprintf(stderr,
"tethereal: The file \"%s\" couldn't be created for some unknown reason.\n",
                 cf->save_file);
        break;

      case WTAP_ERR_SHORT_WRITE:
        fprintf(stderr,
"tethereal: A full header couldn't be written to the file \"%s\".\n",
		cf->save_file);
        break;

      default:
        if (err < 0) {
          fprintf(stderr,
		"tethereal: The file \"%s\" could not be opened: Error %d.\n",
   		cf->save_file, err);
        } else {
          fprintf(stderr,
		"tethereal: The file \"%s\" could not be opened: %s\n.",
 		cf->save_file, strerror(err));
        }
        break;
      }
      goto out;
    }
    args.cf = cf;
    args.pdh = pdh;
    success = wtap_loop(cf->wth, 0, wtap_dispatch_cb_write, (u_char *) &args,
 			&err);
  } else {
    args.cf = cf;
    args.pdh = NULL;
    success = wtap_loop(cf->wth, 0, wtap_dispatch_cb_print, (u_char *) &args,
 			&err);
  }
  if (!success) {
    /* Print up a message box noting that the read failed somewhere along
       the line. */
    switch (err) {

    case WTAP_ERR_CANT_READ:
      fprintf(stderr,
"tethereal: An attempt to read from the file failed for some unknown reason.\n");
      break;

    case WTAP_ERR_SHORT_READ:
      fprintf(stderr,
"tethereal: The capture file appears to have been cut short in the middle of a packet.\n");
      break;

    case WTAP_ERR_BAD_RECORD:
      fprintf(stderr,
"tethereal: The capture file appears to be damaged or corrupt.\n");
      break;

    default:
      fprintf(stderr,
"tethereal: An error occurred while reading the capture file: %s.\n",
	wtap_strerror(err));
      break;
    }
  }

out:
  wtap_close(cf->wth);
  cf->wth = NULL;

  return err;
}

static void
fill_in_fdata(frame_data *fdata, capture_file *cf,
	const struct wtap_pkthdr *phdr, int offset)
{
  int i;

  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pkt_len  = phdr->len;
  fdata->cap_len  = phdr->caplen;
  fdata->file_off = offset;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_secs  = phdr->ts.tv_sec;
  fdata->abs_usecs = phdr->ts.tv_usec;
  fdata->encoding = CHAR_ASCII;
  fdata->pseudo_header = phdr->pseudo_header;
  fdata->cinfo = NULL;

  fdata->num = cf->count;

  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (!firstsec && !firstusec) {
    firstsec  = fdata->abs_secs;
    firstusec = fdata->abs_usecs;
  }

  /* Get the time elapsed between the first packet and this packet. */
  cf->esec = fdata->abs_secs - firstsec;
  if (firstusec <= fdata->abs_usecs) {
    cf->eusec = fdata->abs_usecs - firstusec;
  } else {
    cf->eusec = (fdata->abs_usecs + 1000000) - firstusec;
    cf->esec--;
  }
  
  /* If we don't have the time stamp of the previous displayed packet,
     it's because this is the first displayed packet.  Save the time
     stamp of this packet as the time stamp of the previous displayed
     packet. */
  if (!prevsec && !prevusec) {
    prevsec  = fdata->abs_secs;
    prevusec = fdata->abs_usecs;
  }

  /* Get the time elapsed between the first packet and this packet. */
  fdata->rel_secs = cf->esec;
  fdata->rel_usecs = cf->eusec;
  
  /* Get the time elapsed between the previous displayed packet and
     this packet. */
  fdata->del_secs = fdata->abs_secs - prevsec;
  if (prevusec <= fdata->abs_usecs) {
    fdata->del_usecs = fdata->abs_usecs - prevusec;
  } else {
    fdata->del_usecs = (fdata->abs_usecs + 1000000) - prevusec;
    fdata->del_secs--;
  }
  prevsec = fdata->abs_secs;
  prevusec = fdata->abs_usecs;

  fdata->cinfo = &cf->cinfo;
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    fdata->cinfo->col_data[i][0] = '\0';
  }
}

static void
wtap_dispatch_cb_write(u_char *user, const struct wtap_pkthdr *phdr, int offset,
  const u_char *buf)
{
  cb_args_t    *args = (cb_args_t *) user;
  capture_file *cf = args->cf;
  wtap_dumper  *pdh = args->pdh;
  frame_data    fdata;
  proto_tree   *protocol_tree;
  int           err;
  gboolean      passed;

  cf->count++;
  if (cf->rfcode) {
    fill_in_fdata(&fdata, cf, phdr, offset);
    protocol_tree = proto_tree_create_root();
    dissect_packet(buf, &fdata, protocol_tree);
    passed = dfilter_apply(cf->rfcode, protocol_tree, buf);
  } else {
    protocol_tree = NULL;
    passed = TRUE;
  }
  if (passed) {
    /* XXX - do something if this fails */
    wtap_dump(pdh, phdr, buf, &err);
  }
  if (protocol_tree != NULL)
    proto_tree_free(protocol_tree);
}

static void
wtap_dispatch_cb_print(u_char *user, const struct wtap_pkthdr *phdr, int offset,
  const u_char *buf)
{
  cb_args_t    *args = (cb_args_t *) user;
  capture_file *cf = args->cf;
  frame_data    fdata;
  proto_tree   *protocol_tree;
  gboolean      passed;
  print_args_t print_args;

  cf->count++;

  fill_in_fdata(&fdata, cf, phdr, offset);

  passed = TRUE;
  if (cf->rfcode || verbose)
    protocol_tree = proto_tree_create_root();
  else
    protocol_tree = NULL;
  dissect_packet(buf, &fdata, protocol_tree);
  if (cf->rfcode)
    passed = dfilter_apply(cf->rfcode, protocol_tree, buf);
  if (passed) {
    /* The packet passed the read filter. */
    if (verbose) {
      /* Print the information in the protocol tree. */
      print_args.to_file = TRUE;
      print_args.format = PR_FMT_TEXT;
      print_args.print_summary = FALSE;
      print_args.print_hex = print_hex;
      print_args.expand_all = TRUE;
      proto_tree_print(FALSE, &print_args, (GNode *)protocol_tree,
			buf, &fdata, stdout);
      if (!print_hex) {
        /* "print_hex_data()" will put out a leading blank line, as well
	   as a trailing one; print one here, to separate the packets,
	   only if "print_hex_data()" won't be called. */
        printf("\n");
      }
    } else {
      /* Just fill in the columns. */
      fill_in_columns(&fdata);
      if (cf->iface == NULL) {
         printf("%3s %10s %12s -> %-12s %s %s\n",
    		  col_info(&fdata, COL_NUMBER),
		  col_info(&fdata, COL_CLS_TIME),
		  col_info(&fdata, COL_DEF_SRC),
		  col_info(&fdata, COL_DEF_DST),
		  col_info(&fdata, COL_PROTOCOL),
		  col_info(&fdata, COL_INFO));
      } else {
        printf("%12s -> %-12s %s %s\n",
		  col_info(&fdata, COL_DEF_SRC),
		  col_info(&fdata, COL_DEF_DST),
		  col_info(&fdata, COL_PROTOCOL),
		  col_info(&fdata, COL_INFO));
      }
    }
    if (print_hex) {
      print_hex_data(stdout, print_args.format, buf,
			fdata.cap_len, fdata.encoding);
      printf("\n");
    }
    fdata.cinfo = NULL;
  }
  if (protocol_tree != NULL)
    proto_tree_free(protocol_tree);
}

char *
file_open_error_message(int err, int for_writing)
{
  char *errmsg;
  static char errmsg_errno[1024+1];

  switch (err) {

  case WTAP_ERR_NOT_REGULAR_FILE:
    errmsg = "The file \"%s\" is invalid.";
    break;

  case WTAP_ERR_FILE_UNKNOWN_FORMAT:
  case WTAP_ERR_UNSUPPORTED:
    /* Seen only when opening a capture file for reading. */
    errmsg = "The file \"%s\" is not a capture file in a format Ethereal understands.";
    break;

  case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
    /* Seen only when opening a capture file for writing. */
    errmsg = "Ethereal does not support writing capture files in that format.";
    break;

  case WTAP_ERR_UNSUPPORTED_ENCAP:
  case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
    /* Seen only when opening a capture file for writing. */
    errmsg = "Ethereal cannot save this capture in that format.";
    break;

  case WTAP_ERR_BAD_RECORD:
    errmsg = "The file \"%s\" appears to be damaged or corrupt.";
    break;

  case WTAP_ERR_CANT_OPEN:
    if (for_writing)
      errmsg = "The file \"%s\" could not be created for some unknown reason.";
    else
      errmsg = "The file \"%s\" could not be opened for some unknown reason.";
    break;

  case WTAP_ERR_SHORT_READ:
    errmsg = "The file \"%s\" appears to have been cut short"
             " in the middle of a packet.";
    break;

  case WTAP_ERR_SHORT_WRITE:
    errmsg = "A full header couldn't be written to the file \"%s\".";
    break;

  case ENOENT:
    if (for_writing)
      errmsg = "The path to the file \"%s\" does not exist.";
    else
      errmsg = "The file \"%s\" does not exist.";
    break;

  case EACCES:
    if (for_writing)
      errmsg = "You do not have permission to create or write to the file \"%s\".";
    else
      errmsg = "You do not have permission to read the file \"%s\".";
    break;

  default:
    sprintf(errmsg_errno, "The file \"%%s\" could not be opened: %s.",
				wtap_strerror(err));
    errmsg = errmsg_errno;
    break;
  }
  return errmsg;
}

int
open_cap_file(char *fname, gboolean is_tempfile, capture_file *cf)
{
  wtap       *wth;
  int         err;
  FILE_T      fh;
  int         fd;
  struct stat cf_stat;
  char        err_msg[2048+1];

  wth = wtap_open_offline(fname, &err);
  if (wth == NULL)
    goto fail;

  /* Find the size of the file. */
  fh = wtap_file(wth);
  fd = wtap_fd(wth);
  if (fstat(fd, &cf_stat) < 0) {
    err = errno;
    wtap_close(wth);
    goto fail;
  }

  /* The open succeeded.  Fill in the information for this file. */

  /* Initialize the table of conversations. */
  conversation_init();

  /* Initialize protocol-specific variables */
  init_all_protocols();

  cf->wth = wth;
  cf->fh = fh;
  cf->filed = fd;
  cf->f_len = cf_stat.st_size;

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* If it's a temporary capture buffer file, mark it as not saved. */
  cf->user_saved = !is_tempfile;

  cf->cd_t      = wtap_file_type(cf->wth);
  cf->count     = 0;
  cf->drops     = 0;
  cf->esec      = 0;
  cf->eusec     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  cf->update_progbar = FALSE;
  cf->progbar_quantum = 0;
  cf->progbar_nextstep = 0;
  firstsec = 0, firstusec = 0;
  prevsec = 0, prevusec = 0;
 
  return (0);

fail:
  snprintf(err_msg, sizeof err_msg, file_open_error_message(err, FALSE), fname);
  fprintf(stderr, "tethereal: %s\n", err_msg);
  return (err);
}

/* Get the text in a given column */
static gchar *
col_info(frame_data *fd, gint el) {
  int i;
  
  if (fd->cinfo) {
    for (i = 0; i < fd->cinfo->num_cols; i++) {
      if (fd->cinfo->fmt_matx[i][el])
        return fd->cinfo->col_data[i];
    }
  }
  return NULL;
}
