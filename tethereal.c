/* tethereal.c
 *
 * $Id: tethereal.c,v 1.65 2001/02/10 09:08:14 guy Exp $
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
#include <locale.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#ifdef NEED_SNPRINTF_H
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

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include <glib.h>
#include <epan.h>

#include "globals.h"
#include "timestamp.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "util.h"
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
    union wtap_pseudo_header *, const u_char *);
static void show_capture_file_io_error(const char *, int, gboolean);
static void wtap_dispatch_cb_print(u_char *, const struct wtap_pkthdr *, int,
    union wtap_pseudo_header *, const u_char *);

packet_info  pi;
capture_file cfile;
FILE        *data_out_file = NULL;
guint        main_ctx, file_ctx;
ts_type timestamp_type = RELATIVE;
#ifdef HAVE_LIBPCAP
static int promisc_mode = TRUE;
#endif

static void 
print_usage(void)
{
  int i;

  fprintf(stderr, "This is GNU t%s %s, compiled with %s\n", PACKAGE,
	  VERSION, comp_info_str);
#ifdef HAVE_LIBPCAP
  fprintf(stderr, "t%s [ -vVhlp ] [ -c count ] [ -f <capture filter> ]\n", PACKAGE);
  fprintf(stderr, "\t[ -F <capture file type> ] [ -i interface ] [ -n ]\n");
  fprintf(stderr, "\t[ -o <preference setting> ] ... [ -r infile ] [ -R <read filter> ]\n");
  fprintf(stderr, "\t[ -s snaplen ] [ -t <time stamp format> ] [ -w savefile ] [ -x ]\n");
#else
  fprintf(stderr, "t%s [ -vVhl ] [ -F <capture file type> ] [ -n ]\n", PACKAGE);
  fprintf(stderr, "\t[ -o <preference setting> ] ... [ -r infile ] [ -R <read filter> ]\n");
  fprintf(stderr, "\t[ -t <time stamp format> ] [ -w savefile ] [ -x ]\n");
#endif
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
#ifdef WIN32
  char pcap_version[] = "0.4a6";
#else
  extern char          pcap_version[];
#endif
#endif

#ifdef WIN32
  WSADATA		wsaData;
#endif

  char                *gpf_path, *pf_path;
  int                  gpf_open_errno, pf_open_errno;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             capture_filter_specified = FALSE;
  int                  packet_count = 0;
  GList               *if_list;
  gchar                err_str[PCAP_ERRBUF_SIZE];
#else
  gboolean             capture_option_specified = FALSE;
#endif
  int                 out_file_type = WTAP_FILE_PCAP;
  gchar               *cf_name = NULL, *rfilter = NULL;
  dfilter_t           *rfcode = NULL;
  e_prefs             *prefs;

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps a list of fields registered
     by the dissectors, and we must do it before we read the preferences,
     in case any dissectors register preferences. */
  epan_init(PLUGIN_DIR);

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  /* If invoked with the "-G" flag, we dump out a glossary of
     display filter symbols.

     We do this here to mirror what happens in the GTK+ version, although
     it's not necessary here. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    proto_registrar_dump();
    exit(0);
  }

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  prefs = read_prefs(&gpf_open_errno, &gpf_path, &pf_open_errno, &pf_path);
  if (gpf_path != NULL) {
    fprintf(stderr, "Can't open global preferences file \"%s\": %s.\n", pf_path,
        strerror(gpf_open_errno));
  }
  if (pf_path != NULL) {
    fprintf(stderr, "Can't open your preferences file \"%s\": %s.\n", pf_path,
        strerror(pf_open_errno));
  }
    
  /* Initialize the capture file struct */
  cfile.plist		= NULL;
  cfile.plist_end	= NULL;
  cfile.wth		= NULL;
  cfile.filename	= NULL;
  cfile.user_saved	= FALSE;
  cfile.is_tempfile	= FALSE;
  cfile.rfcode		= NULL;
  cfile.dfilter		= NULL;
  cfile.dfcode		= NULL;
#ifdef HAVE_LIBPCAP
  cfile.cfilter		= g_strdup("");
#endif
  cfile.iface		= NULL;
  cfile.save_file	= NULL;
  cfile.save_file_fd	= -1;
  cfile.snap		= WTAP_MAX_PACKET_SIZE;
  cfile.count		= 0;
  col_init(&cfile.cinfo, prefs->num_cols);

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
  while ((opt = getopt(argc, argv, "c:Df:F:hi:lno:pr:R:s:t:vw:Vx")) != EOF) {
    switch (opt) {
      case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
        packet_count = atoi(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'f':
#ifdef HAVE_LIBPCAP
        capture_filter_specified = TRUE;
	cfile.cfilter = g_strdup(optarg);
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
        cfile.iface = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'l':        /* Line-buffer standard output */
	setvbuf(stdout, NULL, _IOLBF, 0);
	break;
      case 'n':        /* No name resolution */
	g_resolving_actif = 0;
	break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {

	case PREFS_SET_SYNTAX_ERR:
          fprintf(stderr, "tethereal: Invalid -o flag \"%s\"\n", optarg);
          exit(1);
          break;

        case PREFS_SET_NO_SUCH_PREF:
          fprintf(stderr, "tethereal: -o flag \"%s\" specifies unknown preference\n",
			optarg);
          exit(1);
          break;
        }
        break;
      case 'p':        /* Don't capture in promiscuous mode */
#ifdef HAVE_LIBPCAP
	promisc_mode = 0;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 's':        /* Set the snapshot (capture) length */
#ifdef HAVE_LIBPCAP
        cfile.snap = atoi(optarg);
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
        else if (strcmp(optarg, "ad") == 0)
          timestamp_type = ABSOLUTE_WITH_DATE;
        else if (strcmp(optarg, "d") == 0)
          timestamp_type = DELTA;
        else {
          fprintf(stderr, "tethereal: Invalid time stamp type \"%s\"\n",
            optarg);
          fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
          fprintf(stderr, "\"ad\" for absolute with date, or \"d\" for delta.\n");
          exit(1);
        }
        break;
      case 'v':        /* Show version and exit */
        printf("t%s %s, with %s\n", PACKAGE, VERSION, comp_info_str);
        exit(0);
        break;
      case 'w':        /* Write to capture file xxx */
        cfile.save_file = g_strdup(optarg);
	break;
      case 'V':        /* Verbose */
        verbose = TRUE;
        break;
      case 'x':        /* Print packet data in hex (and ASCII) */
        print_hex = TRUE;
        break;
    }
  }
  
  /* If no capture filter or read filter has been specified, and there are
     still command-line arguments, treat them as the tokens of a capture
     filter (if no "-r" flag was specified) or a read filter (if a "-r"
     flag was specified. */
  if (optind < argc) {
    if (cf_name != NULL) {
      if (rfilter != NULL) {
        fprintf(stderr,
"tethereal: Read filters were specified both with \"-R\" and with additional command-line arguments\n");
        exit(2);
      }
      rfilter = get_args_as_string(argc, argv, optind);
    } else {
#ifdef HAVE_LIBPCAP
      if (capture_filter_specified) {
        fprintf(stderr,
"tethereal: Capture filters were specified both with \"-f\" and with additional command-line arguments\n");
        exit(2);
      }
      cfile.cfilter = get_args_as_string(argc, argv, optind);
#else
      capture_option_specified = TRUE;
#endif
    }
  }

#ifdef WIN32
  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that its preferences have changed. */
  prefs_apply_all();

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    fprintf(stderr, "This version of Tethereal was not built with support for capturing packets.\n");
#endif
  if (arg_error)
    print_usage();

  /* Build the column format array */  
  for (i = 0; i < cfile.cinfo.num_cols; i++) {
    cfile.cinfo.col_fmt[i] = get_column_format(i);
    cfile.cinfo.col_title[i] = g_strdup(get_column_title(i));
    cfile.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
      NUM_COL_FMTS);
    get_column_format_matches(cfile.cinfo.fmt_matx[i], cfile.cinfo.col_fmt[i]);
    cfile.cinfo.col_data[i] = NULL;
    if (cfile.cinfo.col_fmt[i] == COL_INFO)
      cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
    else
      cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  if (cfile.snap < 1)
    cfile.snap = WTAP_MAX_PACKET_SIZE;
  else if (cfile.snap < MIN_PACKET_SIZE)
    cfile.snap = MIN_PACKET_SIZE;
  
  if (rfilter != NULL) {
    if (!dfilter_compile(rfilter, &rfcode)) {
      fprintf(stderr, "tethereal: %s\n", dfilter_error_msg);
      epan_cleanup();
      exit(2);
    }
  }
  cfile.rfcode = rfcode;
  if (cf_name) {
    err = open_cap_file(cf_name, FALSE, &cfile);
    if (err != 0) {
      epan_cleanup();
      exit(2);
    }
    err = load_cap_file(&cfile, out_file_type);
    if (err != 0) {
      epan_cleanup();
      exit(2);
    }
    cf_name[0] = '\0';
  } else {
    /* No capture file specified, so we're supposed to do a live capture;
       do we have support for live captures? */
#ifdef HAVE_LIBPCAP
    /* Yes; did the user specify an interface to use? */
    if (cfile.iface == NULL) {
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
        cfile.iface = g_strdup(if_list->data);	/* first interface */
        free_interface_list(if_list);
    }
    capture(packet_count, out_file_type);
#else
    /* No - complain. */
    fprintf(stderr, "This version of Tethereal was not built with support for capturing packets.\n");
    exit(2);
#endif
  }

  epan_cleanup();

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
  struct bpf_program fcode;
  void        (*oldhandler)(int);
  int         err, inpkts;
  char        errmsg[1024+1];
#ifndef _WIN32
  static const char ppamsg[] = "can't find PPA for ";
  char       *libpcap_warn;
#endif

  /* Initialize the table of conversations. */
  epan_conversation_init();

  /* Initialize protocol-specific variables */
  init_all_protocols();

  ld.linktype       = WTAP_ENCAP_UNKNOWN;
  ld.pdh            = NULL;

  /* Open the network interface to capture from it. */
  ld.pch = pcap_open_live(cfile.iface, cfile.snap, promisc_mode, 1000, err_str);

  if (ld.pch == NULL) {
    /* Well, we couldn't start the capture. */
#ifdef _WIN32
    /* On Win32 OSes, the capture devices are probably available to all
       users; don't warn about permissions problems.

       Do, however, warn that Token Ring and PPP devices aren't supported. */
    snprintf(errmsg, sizeof errmsg,
	"The capture session could not be initiated (%s).\n"
	"Please check that you have the proper interface specified.\n"
	"\n"
	"Note that the driver Tethereal uses for packet capture on Windows\n"
	"doesn't support capturing on Token Ring interfaces, and doesn't\n"
	"support capturing on PPP/WAN interfaces in Windows NT/2000.\n",
	err_str);
#else
      /* If we got a "can't find PPA for XXX" message, warn the user (who
         is running Ethereal on HP-UX) that they don't have a version
	 of libpcap patched to properly handle HP-UX (the patched version
	 says "can't find /dev/dlpi PPA for XXX" rather than "can't find
	 PPA for XXX"). */
      if (strncmp(err_str, ppamsg, sizeof ppamsg - 1) == 0)
	libpcap_warn =
	  "\n\n"
	  "You are running Tethereal with a version of the libpcap library\n"
	  "that doesn't handle HP-UX network devices well; this means that\n"
	  "Tethereal may not be able to capture packets.\n"
	  "\n"
	  "To fix this, you will need to download the source to Tethereal\n"
	  "from www.ethereal.com if you have not already done so, read\n"
	  "the instructions in the \"README.hpux\" file in the source\n"
	  "distribution, download the source to libpcap if you have not\n"
	  "already done so, patch libpcap as per the instructions, rebuild\n"
	  "and install libpcap, and then build Tethereal (if you have already\n"
	  "built Tethereal from source, do a \"make distclean\" and re-run\n"
	  "configure before building).";
      else
	libpcap_warn = "";
    snprintf(errmsg, sizeof errmsg,
      "The capture session could not be initiated (%s).\n"
      "Please check to make sure you have sufficient permissions, and that\n"
      "you have the proper interface specified.%s", err_str, libpcap_warn);
#endif
    goto error;
  }

  if (cfile.cfilter) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet (cfile.iface, &netnum, &netmask, err_str) < 0) {
      /*
       * Well, we can't get the netmask for this interface; it's used
       * only for filters that check for broadcast IP addresses, so
       * we just warn the user, and punt and use 0.
       */
      fprintf(stderr, 
        "Warning:  Couldn't obtain netmask info (%s)\n.", err_str);
      netmask = 0;
    }
    if (pcap_compile(ld.pch, &fcode, cfile.cfilter, 1, netmask) < 0) {
      snprintf(errmsg, sizeof errmsg, "Unable to parse filter string (%s).",
	pcap_geterr(ld.pch));
      goto error;
    }
    if (pcap_setfilter(ld.pch, &fcode) < 0) {
      snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(ld.pch));
      goto error;
    }
  }

  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_datalink(ld.pch));
  if (cfile.save_file != NULL) {
    /* Set up to write to the capture file. */
    if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
      strcpy(errmsg, "The network you're capturing from is of a type"
               " that Tethereal doesn't support.");
      goto error;
    }
    ld.pdh = wtap_dump_open(cfile.save_file, out_file_type,
		ld.linktype, pcap_snapshot(ld.pch), &err);

    if (ld.pdh == NULL) {
      snprintf(errmsg, sizeof errmsg, file_open_error_message(errno, TRUE),
		cfile.save_file);
      goto error;
    }
  }

  /* Catch SIGINT and SIGTERM and, if we get either of them, clean up
     and exit.
     XXX - deal with signal semantics on various platforms.  Or just
     use "sigaction()" and be done with it? */
  signal(SIGTERM, capture_cleanup);
  signal(SIGINT, capture_cleanup);
#if !defined(WIN32)
  if ((oldhandler = signal(SIGHUP, capture_cleanup)) != SIG_DFL)
    signal(SIGHUP, oldhandler);
#endif

  /* Let the user know what interface was chosen. */
  printf("Capturing on %s\n", cfile.iface);

  inpkts = pcap_loop(ld.pch, packet_count, capture_pcap_cb, (u_char *) &ld);
  pcap_close(ld.pch);

  /* Send a newline if we were printing packet counts to stdout */
  if (cfile.save_file != NULL) {
    printf("\n");
  }

  return TRUE;

error:
  g_free(cfile.save_file);
  cfile.save_file = NULL;
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

  whdr.ts.tv_sec = phdr->ts.tv_sec;
  whdr.ts.tv_usec = phdr->ts.tv_usec;
  whdr.caplen = phdr->caplen;
  whdr.len = phdr->len;
  whdr.pkt_encap = ld->linktype;

  args.cf = &cfile;
  args.pdh = ld->pdh;
  if (ld->pdh) {
    wtap_dispatch_cb_write((u_char *)&args, &whdr, 0, NULL, pd);
    printf("\r%u ", cfile.count);
    fflush(stdout);
  } else {
    wtap_dispatch_cb_print((u_char *)&args, &whdr, 0, NULL, pd);
  }
}

static void
capture_cleanup(int signum)
{
  int err;

  printf("\n");
  pcap_close(ld.pch);
  if (ld.pdh != NULL) {
    if (!wtap_dump_close(ld.pdh, &err)) {
      show_capture_file_io_error(cfile.save_file, err, TRUE);
      exit(2);
    }
  }
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

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      fprintf(stderr,
"tethereal: \"%s\" is a capture file is for a network type that Tethereal doesn't support.\n",
	cf->filename);
      break;

    case WTAP_ERR_CANT_READ:
      fprintf(stderr,
"tethereal: An attempt to read from \"%s\" failed for some unknown reason.\n",
	cf->filename);
      break;

    case WTAP_ERR_SHORT_READ:
      fprintf(stderr,
"tethereal: \"%s\" appears to have been cut short in the middle of a packet.\n",
	cf->filename);
      break;

    case WTAP_ERR_BAD_RECORD:
      fprintf(stderr,
"tethereal: \"%s\" appears to be damaged or corrupt.\n",
	cf->filename);
      break;

    default:
      fprintf(stderr,
"tethereal: An error occurred while reading \"%s\": %s.\n",
	cf->filename, wtap_strerror(err));
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
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header, int offset)
{
  int i;

  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pfd = NULL;
  fdata->num = cf->count;
  fdata->pkt_len = phdr->len;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  fdata->cinfo = NULL;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_secs  = phdr->ts.tv_sec;
  fdata->abs_usecs = phdr->ts.tv_usec;
  fdata->flags.passed_dfilter = 0;
  fdata->flags.encoding = CHAR_ASCII;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;

  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (!firstsec && !firstusec) {
    firstsec  = fdata->abs_secs;
    firstusec = fdata->abs_usecs;
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
  compute_timestamp_diff(&fdata->rel_secs, &fdata->rel_usecs,
		fdata->abs_secs, fdata->abs_usecs, firstsec, firstusec);

  /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
  if (cf->esec < fdata->rel_secs
	|| (cf->esec == fdata->rel_secs && cf->eusec < fdata->rel_usecs)) {
    cf->esec = fdata->rel_secs;
    cf->eusec = fdata->rel_usecs;
  }
  
  /* Get the time elapsed between the previous displayed packet and
     this packet. */
  compute_timestamp_diff(&fdata->del_secs, &fdata->del_usecs,
		fdata->abs_secs, fdata->abs_usecs, prevsec, prevusec);
  prevsec = fdata->abs_secs;
  prevusec = fdata->abs_usecs;

  fdata->cinfo = &cf->cinfo;
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    fdata->cinfo->col_buf[i][0] = '\0';
    fdata->cinfo->col_data[i] = fdata->cinfo->col_buf[i];
  }
}

static void
wtap_dispatch_cb_write(u_char *user, const struct wtap_pkthdr *phdr, int offset,
  union wtap_pseudo_header *pseudo_header, const u_char *buf)
{
  cb_args_t    *args = (cb_args_t *) user;
  capture_file *cf = args->cf;
  wtap_dumper  *pdh = args->pdh;
  frame_data    fdata;
  proto_tree   *protocol_tree;
  int           err;
  gboolean      passed;
  epan_dissect_t *edt;

  cf->count++;
  if (cf->rfcode) {
    fill_in_fdata(&fdata, cf, phdr, pseudo_header, offset);
    protocol_tree = proto_tree_create_root();
    edt = epan_dissect_new(pseudo_header, buf, &fdata, protocol_tree);
    passed = dfilter_apply_edt(cf->rfcode, edt);
  } else {
    protocol_tree = NULL;
    passed = TRUE;
    edt = NULL;
  }
  if (passed) {
    if (!wtap_dump(pdh, phdr, pseudo_header, buf, &err)) {
#ifdef HAVE_LIBPCAP
      if (ld.pch != NULL) {
      	/* We're capturing packets, so we're printing a count of packets
	   captured; move to the line after the count. */
        printf("\n");
      }
#endif
      show_capture_file_io_error(cf->save_file, err, FALSE);
#ifdef HAVE_LIBPCAP
      if (ld.pch != NULL)
        pcap_close(ld.pch);
#endif
      wtap_dump_close(pdh, &err);
      exit(2);
    }
  }
  if (protocol_tree != NULL)
    proto_tree_free(protocol_tree);
  if (edt != NULL)
    epan_dissect_free(edt);
}

static void
show_capture_file_io_error(const char *fname, int err, gboolean is_close)
{
  switch (err) {

  case ENOSPC:
    fprintf(stderr,
"tethereal: Not all the packets could be written to \"%s\" because there is "
"no space left on the file system.\n",
	fname);
    break;

#ifdef EDQUOT
  case EDQUOT:
    fprintf(stderr,
"tethereal: Not all the packets could be written to \"%s\" because you are "
"too close to, or over your disk quota.\n",
	fname);
  break;
#endif

  case WTAP_ERR_CANT_CLOSE:
    fprintf(stderr,
"tethereal: \"%s\" couldn't be closed for some unknown reason.\n",
	fname);
    break;

  case WTAP_ERR_SHORT_WRITE:
    fprintf(stderr,
"tethereal: Not all the packets could be written to \"%s\".\n",
	fname);
    break;

  default:
    if (is_close) {
      fprintf(stderr,
"tethereal: \"%s\" could not be closed: %s.\n",
	fname, wtap_strerror(err));
    } else {
      fprintf(stderr,
"tethereal: An error occurred while writing to \"%s\": %s.\n",
	fname, wtap_strerror(err));
    }
    break;
  }
}

static void
wtap_dispatch_cb_print(u_char *user, const struct wtap_pkthdr *phdr, int offset,
  union wtap_pseudo_header *pseudo_header, const u_char *buf)
{
  cb_args_t    *args = (cb_args_t *) user;
  capture_file *cf = args->cf;
  frame_data    fdata;
  proto_tree   *protocol_tree;
  gboolean      passed;
  print_args_t  print_args;
  epan_dissect_t *edt;
  int           i;

  cf->count++;

  /* The protocol tree will be "visible", i.e., printed, only if we're
     not printing a summary. */
  proto_tree_is_visible = verbose;

  fill_in_fdata(&fdata, cf, phdr, pseudo_header, offset);

  passed = TRUE;
  if (cf->rfcode || verbose)
    protocol_tree = proto_tree_create_root();
  else
    protocol_tree = NULL;
  edt = epan_dissect_new(pseudo_header, buf, &fdata, protocol_tree);
  if (cf->rfcode)
    passed = dfilter_apply_edt(cf->rfcode, edt);
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

      /* Now print them. */
      for (i = 0; i < cf->cinfo.num_cols; i++) {
        switch (cf->cinfo.col_fmt[i]) {
	case COL_NUMBER:
	  /*
	   * Don't print this if we're doing a live capture from a network
	   * interface - if we're doing a live capture, you won't be
	   * able to look at the capture in the future (it's not being
	   * saved anywhere), so the frame numbers are unlikely to be
	   * useful.
	   *
	   * (XXX - it might be nice to be able to save and print at
	   * the same time, sort of like an "Update list of packets
	   * in real time" capture in Ethereal.)
	   */
          if (cf->iface != NULL)
            continue;
          printf("%3s", cf->cinfo.col_data[i]);
          break;

        case COL_CLS_TIME:
        case COL_REL_TIME:
        case COL_ABS_TIME:
        case COL_ABS_DATE_TIME:	/* XXX - wider */
          printf("%10s", cf->cinfo.col_data[i]);
          break;

        case COL_DEF_SRC:
        case COL_RES_SRC:
        case COL_UNRES_SRC:
        case COL_DEF_DL_SRC:
        case COL_RES_DL_SRC:
        case COL_UNRES_DL_SRC:
        case COL_DEF_NET_SRC:
        case COL_RES_NET_SRC:
        case COL_UNRES_NET_SRC:
          printf("%12s", cf->cinfo.col_data[i]);
          break;

        case COL_DEF_DST:
        case COL_RES_DST:
        case COL_UNRES_DST:
        case COL_DEF_DL_DST:
        case COL_RES_DL_DST:
        case COL_UNRES_DL_DST:
        case COL_DEF_NET_DST:
        case COL_RES_NET_DST:
        case COL_UNRES_NET_DST:
          printf("%-12s", cf->cinfo.col_data[i]);
          break;

        default:
          printf("%s", cf->cinfo.col_data[i]);
          break;
        }
        if (i != cf->cinfo.num_cols - 1) {
          /*
	   * This isn't the last column, so we need to print a
	   * separator between this column and the next.
	   *
	   * If we printed a network source and are printing a
	   * network destination of the same type next, separate
	   * them with "->"; if we printed a network destination
	   * and are printing a network source of the same type
	   * next, separate them with "<-"; otherwise separate them
	   * with a space.
	   */
	  switch (cf->cinfo.col_fmt[i]) {

	  case COL_DEF_SRC:
	  case COL_RES_SRC:
	  case COL_UNRES_SRC:
	    switch (cf->cinfo.col_fmt[i + 1]) {

	    case COL_DEF_DST:
	    case COL_RES_DST:
	    case COL_UNRES_DST:
	      printf(" -> ");
	      break;

	    default:
	      putchar(' ');
	      break;
	    }
	    break;

	  case COL_DEF_DL_SRC:
	  case COL_RES_DL_SRC:
	  case COL_UNRES_DL_SRC:
	    switch (cf->cinfo.col_fmt[i + 1]) {

	    case COL_DEF_DL_DST:
	    case COL_RES_DL_DST:
	    case COL_UNRES_DL_DST:
	      printf(" -> ");
	      break;

	    default:
	      putchar(' ');
	      break;
	    }
	    break;

	  case COL_DEF_NET_SRC:
	  case COL_RES_NET_SRC:
	  case COL_UNRES_NET_SRC:
	    switch (cf->cinfo.col_fmt[i + 1]) {

	    case COL_DEF_NET_DST:
	    case COL_RES_NET_DST:
	    case COL_UNRES_NET_DST:
	      printf(" -> ");
	      break;

	    default:
	      putchar(' ');
	      break;
	    }
	    break;

	  case COL_DEF_DST:
	  case COL_RES_DST:
	  case COL_UNRES_DST:
	    switch (cf->cinfo.col_fmt[i + 1]) {

	    case COL_DEF_SRC:
	    case COL_RES_SRC:
	    case COL_UNRES_SRC:
	      printf(" <- ");
	      break;

	    default:
	      putchar(' ');
	      break;
	    }
	    break;

	  case COL_DEF_DL_DST:
	  case COL_RES_DL_DST:
	  case COL_UNRES_DL_DST:
	    switch (cf->cinfo.col_fmt[i + 1]) {

	    case COL_DEF_DL_SRC:
	    case COL_RES_DL_SRC:
	    case COL_UNRES_DL_SRC:
	      printf(" <- ");
	      break;

	    default:
	      putchar(' ');
	      break;
	    }
	    break;

	  case COL_DEF_NET_DST:
	  case COL_RES_NET_DST:
	  case COL_UNRES_NET_DST:
	    switch (cf->cinfo.col_fmt[i + 1]) {

	    case COL_DEF_NET_SRC:
	    case COL_RES_NET_SRC:
	    case COL_UNRES_NET_SRC:
	      printf(" <- ");
	      break;

	    default:
	      putchar(' ');
	      break;
	    }
	    break;

	  default:
	    putchar(' ');
	    break;
	  }
	}
      }
      putchar('\n');
    }
    if (print_hex) {
      print_hex_data(stdout, print_args.format, buf,
			fdata.cap_len, fdata.flags.encoding);
      putchar('\n');
    }
    fdata.cinfo = NULL;
  }
  if (protocol_tree != NULL)
    proto_tree_free(protocol_tree);

  epan_dissect_free(edt);

  proto_tree_is_visible = FALSE;
}

char *
file_open_error_message(int err, gboolean for_writing)
{
  char *errmsg;
  static char errmsg_errno[1024+1];

  switch (err) {

  case WTAP_ERR_NOT_REGULAR_FILE:
    errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
    break;

  case WTAP_ERR_FILE_UNKNOWN_FORMAT:
  case WTAP_ERR_UNSUPPORTED:
    /* Seen only when opening a capture file for reading. */
    errmsg = "The file \"%s\" is not a capture file in a format Tethereal understands.";
    break;

  case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
    /* Seen only when opening a capture file for writing. */
    errmsg = "Tethereal does not support writing capture files in that format.";
    break;

  case WTAP_ERR_UNSUPPORTED_ENCAP:
  case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
    if (for_writing)
      errmsg = "Tethereal cannot save this capture in that format.";
    else
      errmsg = "The file \"%s\" is a capture for a network type that Tethereal doesn't support.";
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

  case EISDIR:
    errmsg = "\"%s\" is a directory (folder), not a file.";
    break;

  default:
    snprintf(errmsg_errno, sizeof(errmsg_errno),
	     "The file \"%%s\" could not be opened: %s.",
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

  wth = wtap_open_offline(fname, &err, FALSE);
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
  epan_conversation_init();

  /* Initialize protocol-specific variables */
  init_all_protocols();

  cf->wth = wth;
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
