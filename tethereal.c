/* tethereal.c
 *
 * $Id: tethereal.c,v 1.135 2002/03/31 20:56:59 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Text-mode variant, by Gilbert Ramirez <gram@alumni.rice.edu>
 * and Guy Harris <guy@alum.mit.edu>.
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>

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
#include <setjmp.h>
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>	/* to get the libz version number */
#endif

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef HAVE_UCD_SNMP_VERSION_H
#include <ucd-snmp/version.h>
#endif /* HAVE_UCD_SNMP_VERSION_H */

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include <glib.h>
#include <epan/epan.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "file.h"
#include "prefs.h"
#include "column.h"
#include "print.h"
#include <epan/resolv.h>
#include "util.h"
#ifdef HAVE_LIBPCAP
#include "pcap-util.h"
#endif
#include <epan/conversation.h>
#include <epan/plugins.h>
#include "register.h"
#include "conditions.h"
#include "capture_stop_conditions.h"
#include "ringbuffer.h"
#include <epan/epan_dissect.h>

#ifdef WIN32
#include "capture-wpcap.h"
#endif

static guint32 firstsec, firstusec;
static guint32 prevsec, prevusec;
static GString *comp_info_str;
static gboolean quiet;
static gboolean verbose;
static gboolean print_hex;
static gboolean line_buffered;

#ifdef HAVE_LIBPCAP
typedef struct _loop_data {
  gboolean       go;           /* TRUE as long as we're supposed to keep capturing */
  gint           linktype;
  pcap_t        *pch;
  wtap_dumper   *pdh;
  jmp_buf        stopenv;
} loop_data;

static loop_data ld;

static int capture(volatile int, int);
static void capture_pcap_cb(u_char *, const struct pcap_pkthdr *,
  const u_char *);
static void capture_cleanup(int);
#endif

typedef struct {
  capture_file *cf;
  wtap_dumper *pdh;
} cb_args_t;

static int load_cap_file(capture_file *, int);
static void wtap_dispatch_cb_write(u_char *, const struct wtap_pkthdr *, long,
    union wtap_pseudo_header *, const u_char *);
static void show_capture_file_io_error(const char *, int, gboolean);
static void wtap_dispatch_cb_print(u_char *, const struct wtap_pkthdr *, long,
    union wtap_pseudo_header *, const u_char *);

capture_file cfile;
ts_type timestamp_type = RELATIVE;
#ifdef HAVE_LIBPCAP
typedef struct {
	int snaplen;			/* Maximum captured packet length */
	int promisc_mode;		/* Capture in promiscuous mode */
	int autostop_count;		/* Maximum packet count */
	gboolean has_autostop_duration;	/* TRUE if maximum capture duration
					   is specified */
	gint32 autostop_duration;	/* Maximum capture duration */
	gboolean has_autostop_filesize;	/* TRUE if maximum capture file size
					   is specified */
	gint32 autostop_filesize;	/* Maximum capture file size */
	gboolean ringbuffer_on;		/* TRUE if ring buffer in use */
	guint32 ringbuffer_num_files;	/* Number of ring buffer files */
} capture_options;

static capture_options capture_opts = {
	WTAP_MAX_PACKET_SIZE,		/* snapshot length - default is
					   infinite, in effect */
	TRUE,				/* promiscuous mode is the default */
	0,				/* max packet count - default is 0,
					   meaning infinite */
	FALSE,				/* maximum capture duration not
					   specified by default */
	0,				/* maximum capture duration */
	FALSE,				/* maximum capture file size not
					   specified by default */
	0,				/* maximum capture file size */
	FALSE,				/* ring buffer off by default */
	RINGBUFFER_MIN_NUM_FILES	/* default number of ring buffer
					   files */
};
#endif

static void 
print_usage(void)
{
  int i;

  fprintf(stderr, "This is GNU t%s %s, compiled %s\n", PACKAGE, VERSION,
	comp_info_str->str);
#ifdef HAVE_LIBPCAP
  fprintf(stderr, "t%s [ -DvVhlp ] [ -a <capture autostop condition> ] ...\n",
	  PACKAGE);
  fprintf(stderr, "\t[ -b <number of ring buffer files> ] [ -c <count> ]\n");
  fprintf(stderr, "\t[ -f <capture filter> ] [ -F <capture file type> ]\n");
  fprintf(stderr, "\t[ -i <interface> ] [ -n ] [ -N <resolving> ]\n");
  fprintf(stderr, "\t[ -o <preference setting> ] ... [ -r <infile> ] [ -R <read filter> ]\n");
  fprintf(stderr, "\t[ -s <snaplen> ] [ -t <time stamp format> ] [ -w <savefile> ] [ -x ]\n");
#else
  fprintf(stderr, "t%s [ -qvVhl ] [ -F <capture file type> ] [ -n ] [ -N <resolving> ]\n", PACKAGE);
  fprintf(stderr, "\t[ -o <preference setting> ] ... [ -r <infile> ] [ -R <read filter> ]\n");
  fprintf(stderr, "\t[ -t <time stamp format> ] [ -w <savefile> ] [ -x ]\n");
#endif
  fprintf(stderr, "Valid file type arguments to the \"-F\" flag:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(stderr, "\t%s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(stderr, "\tdefault is libpcap\n");
}

static int
get_positive_int(const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    fprintf(stderr, "tethereal: The specified %s \"%s\" is not a decimal number\n",
	    name, string);
    exit(1);
  }
  if (number < 0) {
    fprintf(stderr, "tethereal: The specified %s is a negative number\n",
	    name);
    exit(1);
  }
  if (number == 0) {
    fprintf(stderr, "tethereal: The specified %s is zero\n",
	    name);
    exit(1);
  }
  if (number > INT_MAX) {
    fprintf(stderr, "tethereal: The specified %s is too large (greater than %d)\n",
	    name, INT_MAX);
    exit(1);
  }
  return number;
}

#ifdef HAVE_LIBPCAP
/*
 * Given a string of the form "<autostop criterion>:<value>", as might appear
 * as an argument to a "-a" option, parse it and set the criterion in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
static gboolean
set_autostop_criterion(const char *autostoparg)
{
  u_char *p, *colonp;

  colonp = strchr(autostoparg, ':');
  if (colonp == NULL)
    return FALSE;

  p = colonp;
  *p++ = '\0';

  /*
   * Skip over any white space (there probably won't be any, but
   * as we allow it in the preferences file, we might as well
   * allow it here).
   */
  while (isspace(*p))
    p++;
  if (*p == '\0') {
    /*
     * Put the colon back, so if our caller uses, in an
     * error message, the string they passed us, the message
     * looks correct.
     */
    *colonp = ':';
    return FALSE;
  }
  if (strcmp(autostoparg,"duration") == 0) {
    capture_opts.has_autostop_duration = TRUE;
    capture_opts.autostop_duration = get_positive_int(p,"autostop duration");
  } else if (strcmp(autostoparg,"filesize") == 0) {
    capture_opts.has_autostop_filesize = TRUE;
    capture_opts.autostop_filesize = get_positive_int(p,"autostop filesize");
  } else {
    return FALSE;
  }
  *colonp = ':';	/* put the colon back */
  return TRUE;
}
#endif

int
main(int argc, char *argv[])
{
  int                  opt, i;
  extern char         *optarg;
  gboolean             arg_error = FALSE;
#ifdef HAVE_LIBPCAP
#ifdef HAVE_PCAP_VERSION
  extern char          pcap_version[];
#endif /* HAVE_PCAP_VERSION */
#endif /* HAVE_LIBPCAP */

#ifdef WIN32
  WSADATA		wsaData;
#endif

  char                *gpf_path;
  const char          *pf_path;
  int                  gpf_open_errno, pf_open_errno;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             capture_filter_specified = FALSE;
  GList               *if_list, *if_entry;
  gchar                err_str[PCAP_ERRBUF_SIZE];
#else
  gboolean             capture_option_specified = FALSE;
#endif
  int                  out_file_type = WTAP_FILE_PCAP;
  gchar               *cf_name = NULL, *rfilter = NULL;
  dfilter_t           *rfcode = NULL;
  e_prefs             *prefs;
  char                 badopt;

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps a list of fields registered
     by the dissectors, and we must do it before we read the preferences,
     in case any dissectors register preferences. */
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs);

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

  /* Set the name resolution code's flags from the preferences. */
  g_resolv_flags = prefs->name_resolve;

#ifdef WIN32
  /* Load Wpcap, if possible */
  load_wpcap();
#endif
    
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
  cfile.has_snap	= FALSE;
  cfile.snap		= WTAP_MAX_PACKET_SIZE;
  cfile.count		= 0;
  col_init(&cfile.cinfo, prefs->num_cols);

  /* Assemble the compile-time options */
  comp_info_str = g_string_new("");

  g_string_append(comp_info_str, "with ");
  g_string_sprintfa(comp_info_str,
#ifdef GLIB_MAJOR_VERSION
    "GLib %d.%d.%d", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
    GLIB_MICRO_VERSION);
#else
    "GLib (version unknown)");
#endif

#ifdef HAVE_LIBPCAP
  g_string_append(comp_info_str, ", with libpcap ");
#ifdef HAVE_PCAP_VERSION
  g_string_append(comp_info_str, pcap_version);
#else /* HAVE_PCAP_VERSION */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* HAVE_PCAP_VERSION */
#else /* HAVE_LIBPCAP */
  g_string_append(comp_info_str, ", without libpcap");
#endif /* HAVE_LIBPCAP */

#ifdef HAVE_LIBZ
  g_string_append(comp_info_str, ", with libz ");
#ifdef ZLIB_VERSION
  g_string_append(comp_info_str, ZLIB_VERSION);
#else /* ZLIB_VERSION */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* ZLIB_VERSION */
#else /* HAVE_LIBZ */
  g_string_append(comp_info_str, ", without libz");
#endif /* HAVE_LIBZ */

/* Oh, this is pretty */
#ifdef HAVE_UCD_SNMP
  g_string_append(comp_info_str, ", with UCD SNMP ");
#ifdef HAVE_UCD_SNMP_VERSION_H
  g_string_append(comp_info_str, VersionInfo);
#else /* HAVE_UCD_SNMP_VERSION_H */
  g_string_append(comp_info_str, "(version unknown)");
#endif /* HAVE_UCD_SNMP_VERSION_H */
#else /* no SNMP library */
  g_string_append(comp_info_str, ", without UCD SNMP");
#endif
    
  /* Now get our args */
  while ((opt = getopt(argc, argv, "a:b:c:Df:F:hi:lnN:o:pqr:R:s:t:vw:Vx")) != -1) {
    switch (opt) {
      case 'a':        /* autostop criteria */
#ifdef HAVE_LIBPCAP
        if (set_autostop_criterion(optarg) == FALSE) {
          fprintf(stderr, "ethereal: Invalid or unknown -a flag \"%s\"\n", optarg);
          exit(1);          
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'b':        /* Ringbuffer option */
#ifdef HAVE_LIBPCAP
        capture_opts.ringbuffer_on = TRUE;
        capture_opts.ringbuffer_num_files =
            get_positive_int(optarg, "number of ring buffer files");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
        capture_opts.autostop_count =
            get_positive_int(optarg, "packet count");
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'D':        /* Print a list of capture devices */
#ifdef HAVE_LIBPCAP
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
        for (if_entry = g_list_first(if_list); if_entry != NULL;
		if_entry = g_list_next(if_entry))
          printf("%s\n", (char *)if_entry->data);
        free_interface_list(if_list);
        exit(0);
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
      case 'l':        /* "Line-buffer" standard output */
	/* This isn't line-buffering, strictly speaking, it's just
	   flushing the standard output after the information for
	   each packet is printed; however, that should be good
	   enough for all the purposes to which "-l" is put.

	   See the comment in "wtap_dispatch_cb_print()" for an
	   explanation of why we do that, and why we don't just
	   use "setvbuf()" to make the standard output line-buffered
	   (short version: in Windows, "line-buffered" is the same
	   as "fully-buffered", and the output buffer is only flushed
	   when it fills up). */
	line_buffered = TRUE;
	break;
      case 'n':        /* No name resolution */
        g_resolv_flags = RESOLV_NONE;
        break;
      case 'N':        /* Select what types of addresses/port #s to resolve */
        if (g_resolv_flags == RESOLV_ALL)
          g_resolv_flags = RESOLV_NONE;
        badopt = string_to_name_resolve(optarg, &g_resolv_flags);
        if (badopt != '\0') {
          fprintf(stderr, "tethereal: -N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'\n",
			badopt);
          exit(1);
        }
        break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {

	case PREFS_SET_SYNTAX_ERR:
          fprintf(stderr, "tethereal: Invalid -o flag \"%s\"\n", optarg);
          exit(1);
          break;

        case PREFS_SET_NO_SUCH_PREF:
        case PREFS_SET_OBSOLETE:
          fprintf(stderr, "tethereal: -o flag \"%s\" specifies unknown preference\n",
			optarg);
          exit(1);
          break;
        }
        break;
      case 'p':        /* Don't capture in promiscuous mode */
#ifdef HAVE_LIBPCAP
	capture_opts.promisc_mode = FALSE;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
	break;
      case 'q':        /* Quiet */
        quiet = TRUE;
        break;
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 's':        /* Set the snapshot (capture) length */
#ifdef HAVE_LIBPCAP
        capture_opts.snaplen = get_positive_int(optarg, "snapshot length");
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
        printf("t%s %s, %s\n", PACKAGE, VERSION, comp_info_str->str);
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

#ifdef HAVE_LIBPCAP
  /* If they didn't specify a "-w" flag, but specified a maximum capture
     file size, tell them that this doesn't work, and exit. */
  if (capture_opts.has_autostop_filesize && cfile.save_file == NULL) {
    fprintf(stderr, "tethereal: Maximum capture file size specified, but capture isn't being saved to a file.\n");
    exit(2);
  }

  if (capture_opts.ringbuffer_on) {
    /* Ring buffer works only under certain conditions:
       a) ring buffer does not work if you're not saving the capture to
          a file;
       b) ring buffer only works if you're saving in libpcap format;
       c) it makes no sense to enable the ring buffer if the maximum
          file size is set to "infinite". */
    if (cfile.save_file == NULL) {
      fprintf(stderr, "tethereal: Ring buffer requested, but capture isn't being saved to a file.\n");
      exit(2);
    }
    if (out_file_type != WTAP_FILE_PCAP) {
      fprintf(stderr, "tethereal: Ring buffer requested, but capture isn't being saved in libpcap format.\n");
      exit(2);
    }
    if (!capture_opts.has_autostop_filesize) {
      fprintf(stderr, "tethereal: Ring buffer requested, but no maximum capture file size was specified.\n");
      exit(2);
    }
  }
#endif

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

    cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

#ifdef HAVE_LIBPCAP
  if (capture_opts.snaplen < 1)
    capture_opts.snaplen = WTAP_MAX_PACKET_SIZE;
  else if (capture_opts.snaplen < MIN_PACKET_SIZE)
    capture_opts.snaplen = MIN_PACKET_SIZE;
  
  /* Check the value range of the ringbuffer_num_files parameter */
  if (capture_opts.ringbuffer_num_files < RINGBUFFER_MIN_NUM_FILES)
    capture_opts.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
  else if (capture_opts.ringbuffer_num_files > RINGBUFFER_MAX_NUM_FILES)
    capture_opts.ringbuffer_num_files = RINGBUFFER_MAX_NUM_FILES;
#endif
  
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

#ifdef _WIN32
    if (!has_wpcap) {
	fprintf(stderr, "tethereal: Could not load wpcap.dll.\n");
	exit(2);
    }
#endif

    /* Yes; did the user specify an interface to use? */
    if (cfile.iface == NULL) {
        /* No - is a default specified in the preferences file? */
        if (prefs->capture_device != NULL) {
            /* Yes - use it. */
            cfile.iface	= g_strdup(prefs->capture_device);
        } else {
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
    }
    capture(capture_opts.autostop_count, out_file_type);

    if (capture_opts.ringbuffer_on) {
      ringbuf_free();
    }
#else
    /* No - complain. */
    fprintf(stderr, "This version of Tethereal was not built with support for capturing packets.\n");
    exit(2);
#endif
  }

  epan_cleanup();

  return 0;
}

#ifdef HAVE_LIBPCAP
/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
static int
capture(volatile int packet_count, int out_file_type)
{
  gchar       open_err_str[PCAP_ERRBUF_SIZE];
  gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netnum, netmask;
  struct bpf_program fcode;
  void        (*oldhandler)(int);
  int         err;
  volatile int inpkts = 0;
  char        errmsg[1024+1];
  condition  *volatile cnd_stop_capturesize = NULL;
  condition  *volatile cnd_stop_timeout = NULL;
#ifndef _WIN32
  static const char ppamsg[] = "can't find PPA for ";
  char       *libpcap_warn;
#endif
  struct pcap_stat stats;
  gboolean    dump_ok;

  /* Initialize all data structures used for dissection. */
  init_dissection();

  ld.linktype       = WTAP_ENCAP_UNKNOWN;
  ld.pdh            = NULL;

  /* Open the network interface to capture from it.
     Some versions of libpcap may put warnings into the error buffer
     if they succeed; to tell if that's happened, we have to clear
     the error buffer, and check if it's still a null string.  */
  open_err_str[0] = '\0';
  ld.pch = pcap_open_live(cfile.iface, capture_opts.snaplen,
			  capture_opts.promisc_mode, 1000, open_err_str);

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
	open_err_str);
#else
      /* If we got a "can't find PPA for XXX" message, warn the user (who
         is running Ethereal on HP-UX) that they don't have a version
	 of libpcap that properly handles HP-UX (libpcap 0.6.x and later
	 versions, which properly handle HP-UX, say "can't find /dev/dlpi
	 PPA for XXX" rather than "can't find PPA for XXX"). */
      if (strncmp(open_err_str, ppamsg, sizeof ppamsg - 1) == 0)
	libpcap_warn =
	  "\n\n"
	  "You are running Tethereal with a version of the libpcap library\n"
	  "that doesn't handle HP-UX network devices well; this means that\n"
	  "Tethereal may not be able to capture packets.\n"
	  "\n"
	  "To fix this, you should install libpcap 0.6.2, or a later version\n"
	  "of libpcap, rather than libpcap 0.4 or 0.5.x.  It is available in\n"
	  "packaged binary form from the Software Porting And Archive Centre\n"
	  "for HP-UX; the Centre is at http://hpux.connect.org.uk/ - the page\n"
	  "at the URL lists a number of mirror sites.";
      else
	libpcap_warn = "";
    snprintf(errmsg, sizeof errmsg,
      "The capture session could not be initiated (%s).\n"
      "Please check to make sure you have sufficient permissions, and that\n"
      "you have the proper interface specified.%s", open_err_str, libpcap_warn);
#endif
    goto error;
  }

  if (cfile.cfilter) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet(cfile.iface, &netnum, &netmask, lookup_net_err_str) < 0) {
      /*
       * Well, we can't get the netmask for this interface; it's used
       * only for filters that check for broadcast IP addresses, so
       * we just warn the user, and punt and use 0.
       */
      fprintf(stderr, 
        "Warning:  Couldn't obtain netmask info (%s).\n", lookup_net_err_str);
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

  ld.linktype = wtap_pcap_encap_to_wtap_encap(get_pcap_linktype(ld.pch,
	cfile.iface));
  if (cfile.save_file != NULL) {
    /* Set up to write to the capture file. */
    if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
      strcpy(errmsg, "The network you're capturing from is of a type"
               " that Tethereal doesn't support.");
      goto error;
    }
    if (capture_opts.ringbuffer_on) {
      cfile.save_file_fd = ringbuf_init(cfile.save_file,
        capture_opts.ringbuffer_num_files);
      if (cfile.save_file_fd != -1) {
        ld.pdh = ringbuf_init_wtap_dump_fdopen(out_file_type, ld.linktype,
          pcap_snapshot(ld.pch), &err);
      } else {
        ld.pdh = NULL;
      }
    } else {
      ld.pdh = wtap_dump_open(cfile.save_file, out_file_type,
		 ld.linktype, pcap_snapshot(ld.pch), &err);
    }

    if (ld.pdh == NULL) {
      snprintf(errmsg, sizeof errmsg, file_open_error_message(errno, TRUE),
		cfile.save_file);
      goto error;
    }
  }

  /* Does "open_err_str" contain a non-empty string?  If so, "pcap_open_live()"
     returned a warning; print it, but keep capturing. */
  if (open_err_str[0] != '\0')
    fprintf(stderr, "tethereal: WARNING: %s.\n", open_err_str);

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
  fprintf(stderr, "Capturing on %s\n", cfile.iface);
  fflush(stderr);

  /* initialize capture stop conditions */ 
  init_capture_stop_conditions();
  /* create stop conditions */
  if (capture_opts.has_autostop_filesize)
    cnd_stop_capturesize = cnd_new((char*)CND_CLASS_CAPTURESIZE,
                                   (long)capture_opts.autostop_filesize * 1000);
  if (capture_opts.has_autostop_duration)
    cnd_stop_timeout = cnd_new((char*)CND_CLASS_TIMEOUT,
                               (gint32)capture_opts.autostop_duration);

  if (packet_count == 0)
    packet_count = -1; /* infinite capturng */
  if (!setjmp(ld.stopenv))
    ld.go = TRUE;
  else
    ld.go = FALSE;
  while (ld.go) {
    if (packet_count > 0)
      packet_count--;
    inpkts = pcap_dispatch(ld.pch, 1, capture_pcap_cb, (u_char *) &ld);
    if (packet_count == 0 || inpkts < 0) {
      ld.go = FALSE;
    } else if (cnd_stop_timeout != NULL && cnd_eval(cnd_stop_timeout)) {
      /* The specified capture time has elapsed; stop the capture. */
      ld.go = FALSE;
    } else if (ld.pdh != NULL && cnd_stop_capturesize != NULL &&
                  cnd_eval(cnd_stop_capturesize, 
                            (guint32)wtap_get_bytes_dumped(ld.pdh))) {
      /* We're saving the capture to a file, and the capture file reached
         its maximum size. */
      if (capture_opts.ringbuffer_on) {
        /* Switch to the next ringbuffer file */
        if (ringbuf_switch_file(&cfile, &ld.pdh, &err) == TRUE) {
          /* File switch failed: reset the condition */
          cnd_reset(cnd_stop_capturesize);
        } else {
          /* File switch failed: stop here */
          ld.go = FALSE;
          continue;
        }
      } else {
        /* No ringbuffer - just stop. */
        ld.go = FALSE;
      }
    }
  }
  
  /* delete stop conditions */
  if (cnd_stop_capturesize != NULL)
    cnd_delete(cnd_stop_capturesize);
  if (cnd_stop_timeout != NULL)
    cnd_delete(cnd_stop_timeout);

  if ((cfile.save_file != NULL) && !quiet) {
    /* We're saving to a file, which means we're printing packet counts
       to the standard output if we are not running silent and deep.
       Send a newline so that we move to the line after the packet count. */
    fprintf(stderr, "\n");
  }

  /* If we got an error while capturing, report it. */
  if (inpkts < 0) {
    fprintf(stderr, "tethereal: Error while capturing packets: %s\n",
	pcap_geterr(ld.pch));
  }

  /* Get the capture statistics, and, if any packets were dropped, report
     that. */
  if (pcap_stats(ld.pch, &stats) >= 0) {
    if (stats.ps_drop != 0) {
      fprintf(stderr, "%u packets dropped\n", stats.ps_drop);
    }
  } else {
    fprintf(stderr, "tethereal: Can't get packet-drop statistics: %s\n",
	pcap_geterr(ld.pch));
  }
/* Report the number of captured packets if not reported during capture and
   we are not saving to a file. */
  if (quiet && (cfile.save_file != NULL)) {
    fprintf(stderr, "\r%u packets captured\n", cfile.count);
  }

  pcap_close(ld.pch);

  if (cfile.save_file != NULL) {
    /* We're saving to a file or files; close all files. */
    if (capture_opts.ringbuffer_on) {
      dump_ok = ringbuf_wtap_dump_close(&cfile, &err);
    } else {
      dump_ok = wtap_dump_close(ld.pdh, &err);
    }
    if (!dump_ok)
      show_capture_file_io_error(cfile.save_file, err, TRUE);
  }

  return TRUE;

error:
  if (capture_opts.ringbuffer_on) {
    ringbuf_error_cleanup();
  }
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
/* Report packet capture count if not quiet */
    if (!quiet) {
      fprintf(stderr, "\r%u ", cfile.count);
      fflush(stdout);
    }
  } else {
    wtap_dispatch_cb_print((u_char *)&args, &whdr, 0, NULL, pd);
  }
}

static void
capture_cleanup(int signum _U_)
{
  /* Longjmp back to the starting point; "pcap_dispatch()", on many
     platforms, just keeps looping if it gets EINTR, so if we set
     "ld.go" to FALSE and return, we won't break out of it and quit
     capturing. */
  longjmp(ld.stopenv, 1);
}
#endif /* HAVE_LIBPCAP */

static int
load_cap_file(capture_file *cf, int out_file_type)
{
  gint         linktype;
  int          snapshot_length;
  wtap_dumper *pdh;
  int          err;
  int          success;
  cb_args_t    args;

  linktype = wtap_file_encap(cf->wth);
  if (cf->save_file != NULL) {
    /* Set up to write to the capture file. */
    snapshot_length = wtap_snapshot_length(cf->wth);
    if (snapshot_length == 0) {
      /* Snapshot length of input file not known. */
      snapshot_length = WTAP_MAX_PACKET_SIZE;
    }
    pdh = wtap_dump_open(cf->save_file, out_file_type,
		linktype, snapshot_length, &err);

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

    /* Now close the capture file. */
    if (!wtap_dump_close(pdh, &err))
      show_capture_file_io_error(cfile.save_file, err, TRUE);
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
	const struct wtap_pkthdr *phdr, long offset)
{
  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pfd = NULL;
  fdata->data_src	 = NULL;
  fdata->num = cf->count;
  fdata->pkt_len = phdr->len;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
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
  if ((gint32)cf->esec < fdata->rel_secs
	|| ((gint32)cf->esec == fdata->rel_secs && (gint32)cf->eusec < fdata->rel_usecs)) {
    cf->esec = fdata->rel_secs;
    cf->eusec = fdata->rel_usecs;
  }
  
  /* Get the time elapsed between the previous displayed packet and
     this packet. */
  compute_timestamp_diff(&fdata->del_secs, &fdata->del_usecs,
		fdata->abs_secs, fdata->abs_usecs, prevsec, prevusec);
  prevsec = fdata->abs_secs;
  prevusec = fdata->abs_usecs;
}

/* Free up all data attached to a "frame_data" structure. */
static void
clear_fdata(frame_data *fdata)
{
  if (fdata->pfd)
    g_slist_free(fdata->pfd);
  free_data_sources(fdata);	/* release data source list */
}

static void
wtap_dispatch_cb_write(u_char *user, const struct wtap_pkthdr *phdr,
  long offset, union wtap_pseudo_header *pseudo_header, const u_char *buf)
{
  cb_args_t    *args = (cb_args_t *) user;
  capture_file *cf = args->cf;
  wtap_dumper  *pdh = args->pdh;
  frame_data    fdata;
  int           err;
  gboolean      passed;
  epan_dissect_t *edt;

  cf->count++;
  if (cf->rfcode) {
    fill_in_fdata(&fdata, cf, phdr, offset);
    edt = epan_dissect_new(TRUE, FALSE);
    epan_dissect_prime_dfilter(edt, cf->rfcode);
    epan_dissect_run(edt, pseudo_header, buf, &fdata, NULL);
    passed = dfilter_apply_edt(cf->rfcode, edt);
  } else {
    passed = TRUE;
    edt = NULL;
  }
  if (passed) {
    if (!wtap_dump(pdh, phdr, pseudo_header, buf, &err)) {
#ifdef HAVE_LIBPCAP
      if (ld.pch != NULL) {
      	/* We're capturing packets, so we're printing a count of packets
	   captured; move to the line after the count. */
        fprintf(stderr, "\n");
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
  if (edt != NULL)
    epan_dissect_free(edt);
  if (cf->rfcode)
    clear_fdata(&fdata);
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
wtap_dispatch_cb_print(u_char *user, const struct wtap_pkthdr *phdr,
  long offset, union wtap_pseudo_header *pseudo_header, const u_char *buf)
{
  cb_args_t    *args = (cb_args_t *) user;
  capture_file *cf = args->cf;
  frame_data    fdata;
  gboolean      passed;
  print_args_t  print_args;
  epan_dissect_t *edt;
  gboolean      create_proto_tree;
  int           i;

  cf->count++;

  fill_in_fdata(&fdata, cf, phdr, offset);

  passed = TRUE;
  if (cf->rfcode || verbose)
    create_proto_tree = TRUE;
  else
    create_proto_tree = FALSE;
  /* The protocol tree will be "visible", i.e., printed, only if we're
     not printing a summary.

     We only need the columns if we're *not* verbose; in verbose mode,
     we print the protocol tree, not the protocol summary. */
  edt = epan_dissect_new(create_proto_tree, verbose);
  if (cf->rfcode) {
    epan_dissect_prime_dfilter(edt, cf->rfcode);
  }
  epan_dissect_run(edt, pseudo_header, buf, &fdata, verbose ? NULL : &cf->cinfo);
  if (cf->rfcode) {
    passed = dfilter_apply_edt(cf->rfcode, edt);
  }
  if (passed) {
    /* The packet passed the read filter. */
    if (verbose) {
      /* Print the information in the protocol tree. */
      print_args.to_file = TRUE;
      print_args.format = PR_FMT_TEXT;
      print_args.print_summary = FALSE;
      print_args.print_hex = print_hex;
      print_args.expand_all = TRUE;
      print_args.suppress_unmarked = FALSE;
      proto_tree_print(&print_args, (GNode *)edt->tree,
			&fdata, stdout);
      if (!print_hex) {
        /* "print_hex_data()" will put out a leading blank line, as well
	   as a trailing one; print one here, to separate the packets,
	   only if "print_hex_data()" won't be called. */
        printf("\n");
      }
    } else {
      /* Just fill in the columns. */
      epan_dissect_fill_in_columns(edt);

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
      print_hex_data(stdout, print_args.format, &fdata);
      putchar('\n');
    }
  }

  /* The ANSI C standard does not appear to *require* that a line-buffered
     stream be flushed to the host environment whenever a newline is
     written, it just says that, on such a stream, characters "are
     intended to be transmitted to or from the host environment as a
     block when a new-line character is encountered".

     The Visual C++ 6.0 C implementation doesn't do what is intended;
     even if you set a stream to be line-buffered, it still doesn't
     flush the buffer at the end of every line.

     So, if the "-l" flag was specified, we flush the standard output
     at the end of a packet.  This will do the right thing if we're
     printing packet summary lines, and, as we print the entire protocol
     tree for a single packet without waiting for anything to happen,
     it should be as good as line-buffered mode if we're printing
     protocol trees.  (The whole reason for the "-l" flag in either
     tcpdump or Tethereal is to allow the output of a live capture to
     be piped to a program or script and to have that script see the
     information for the packet as soon as it's printed, rather than
     having to wait until a standard I/O buffer fills up. */
  if (line_buffered)
    fflush(stdout);

  epan_dissect_free(edt);

  clear_fdata(&fdata);
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
             " in the middle of a packet or other data.";
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
  int         fd;
  struct stat cf_stat;
  char        err_msg[2048+1];

  wth = wtap_open_offline(fname, &err, FALSE);
  if (wth == NULL)
    goto fail;

  /* Find the size of the file. */
  fd = wtap_fd(wth);
  if (fstat(fd, &cf_stat) < 0) {
    err = errno;
    wtap_close(wth);
    goto fail;
  }

  /* The open succeeded.  Fill in the information for this file. */

  /* Initialize all data structures used for dissection. */
  init_dissection();

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
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->esec      = 0;
  cf->eusec     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = WTAP_MAX_PACKET_SIZE;
  } else
    cf->has_snap = TRUE;
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
