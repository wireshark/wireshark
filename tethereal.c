/* tethereal.c
 *
 * $Id$
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

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include <glib.h>
#include <epan/epan.h>
#include <epan/filesystem.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "file.h"
#include "disabled_protos.h"
#include <epan/prefs.h>
#include <epan/column.h>
#include "print.h"
#include <epan/addr_resolv.h>
#include "util.h"
#include "clopts_common.h"
#include "version_info.h"
#include <epan/conversation.h>
#include <epan/plugins.h>
#include "register.h"
#include "conditions.h"
#include "capture_stop_conditions.h"
#include "ringbuffer.h"
#include "capture_ui_utils.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/timestamp.h>

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#include <setjmp.h>
#include "pcap-util.h"
#include <wiretap/wtap-capture.h>
#include <wiretap/libpcap.h>
#ifdef _WIN32
#include "capture-wpcap.h"
#endif /* _WIN32 */
#include "capture.h"
#endif /* HAVE_LIBPCAP */
#include "epan/emem.h"

/*
 * This is the template for the decode as option; it is shared between the
 * various functions that output the usage for this parameter.
 */
static const gchar decode_as_arg_template[] = "<layer_type>==<selector>,<decode_as_protocol>";

static nstime_t first_ts;
static nstime_t prev_ts;
static GString *comp_info_str, *runtime_info_str;

static gboolean print_packet_info;	/* TRUE if we're to print packet information */
/*
 * The way the packet decode is to be written.
 */
typedef enum {
	WRITE_TEXT,	/* summary or detail text */
	WRITE_XML	/* PDML or PSML */
	/* Add CSV and the like here */
} output_action_e;
static output_action_e output_action;
static gboolean do_dissection;	/* TRUE if we have to dissect each packet */
static gboolean verbose;
static gboolean print_hex;
static gboolean line_buffered;
static guint32 cum_bytes = 0;
static print_format_e print_format = PR_FMT_TEXT;
static print_stream_t *print_stream;

#ifdef HAVE_LIBPCAP
/*
 * TRUE if we're to print packet counts to keep track of captured packets.
 */
static gboolean print_packet_counts;

typedef struct _loop_data {
  gboolean       go;           /* TRUE as long as we're supposed to keep capturing */
  gint           linktype;
  gboolean       from_pipe;    /* TRUE if we are capturing data from a pipe */
  pcap_t        *pch;
  char          *save_file;    /* Name of file to which we're writing */
  wtap_dumper   *pdh;
  jmp_buf        stopenv;
  gboolean       output_to_pipe;
  int            packet_count;
#ifndef _WIN32
  gboolean       modified;     /* TRUE if data in the pipe uses modified pcap headers */
  gboolean       byte_swapped; /* TRUE if data in the pipe is byte swapped */
  unsigned int   bytes_to_read, bytes_read; /* Used by pipe_dispatch */
  enum {
         STATE_EXPECT_REC_HDR, STATE_READ_REC_HDR,
         STATE_EXPECT_DATA,     STATE_READ_DATA
       } pipe_state;
  enum { PIPOK, PIPEOF, PIPERR, PIPNEXIST } pipe_err;
#endif
} loop_data;

static loop_data ld;

#ifdef HAVE_LIBPCAP
static capture_options capture_opts;


#ifdef SIGINFO
static gboolean infodelay;	/* if TRUE, don't print capture info in SIGINFO handler */
static gboolean infoprint;	/* if TRUE, print capture info after clearing infodelay */
#endif /* SIGINFO */
#endif /* HAVE_LIBPCAP */


static int capture(char *, int);
static void capture_pcap_cb(guchar *, const struct pcap_pkthdr *,
  const guchar *);
static void report_counts(void);
#ifdef _WIN32
static BOOL WINAPI capture_cleanup(DWORD);
#else /* _WIN32 */
static void capture_cleanup(int);
#ifdef SIGINFO
static void report_counts_siginfo(int);
#endif /* SIGINFO */
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

static int load_cap_file(capture_file *, char *, int);
static gboolean process_packet(capture_file *cf, wtap_dumper *pdh, long offset,
    const struct wtap_pkthdr *whdr, union wtap_pseudo_header *pseudo_header,
    const guchar *pd, int *err);
static void show_capture_file_io_error(const char *, int, gboolean);
static void show_print_file_io_error(int err);
static gboolean write_preamble(capture_file *cf);
static gboolean print_packet(capture_file *cf, epan_dissect_t *edt);
static gboolean write_finale(void);
static const char *cf_open_error_message(int err, gchar *err_info,
    gboolean for_writing, int file_type);
#ifdef HAVE_LIBPCAP
#ifndef _WIN32
static void adjust_header(loop_data *, struct pcap_hdr *, struct pcaprec_hdr *);
static int pipe_open_live(char *, struct pcap_hdr *, loop_data *, char *, int);
static int pipe_dispatch(int, loop_data *, struct pcap_hdr *, \
                struct pcaprec_modified_hdr *, guchar *, char *, int);
#endif /* _WIN32 */
#endif

static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void failure_message(const char *msg_format, va_list ap);
static void read_failure_message(const char *filename, int err);

capture_file cfile;


static void
print_usage(gboolean print_ver)
{
  int i;
  FILE *output;

  if (print_ver) {
    output = stdout;
    fprintf(output, "This is t" PACKAGE " " VERSION "%s"
        "\n (C) 1998-2005 Gerald Combs <gerald@ethereal.com>"
	"\n%s\n%s\n",

	svnversion, comp_info_str->str, runtime_info_str->str);
  } else {
    output = stderr;
  }
#ifdef HAVE_LIBPCAP
  fprintf(output, "\nt%s [ -vh ] [ -DlLnpqSVx ] [ -a <capture autostop condition> ] ...\n",
	  PACKAGE);
  fprintf(output, "\t[ -b <capture ring buffer option> ] ... [ -c <capture packet count> ]\n");
  fprintf(output, "\t[ -d %s ] ...\n", decode_as_arg_template);
  fprintf(output, "\t[ -f <capture filter> ] [ -F <output file type> ]\n");
  fprintf(output, "\t[ -i <capture interface> ] [ -N <name resolving flags> ]\n");
  fprintf(output, "\t[ -o <preference setting> ] ... [ -r <infile> ]\n");
  fprintf(output, "\t[ -R <read (display) filter> ] [ -s <capture snaplen> ]\n");
  fprintf(output, "\t[ -t <time stamp format> ] [ -T pdml|ps|psml|text ]\n");
  fprintf(output, "\t[ -w <savefile> ] [ -y <capture link type> ] [ -z <statistics> ]\n");
#else
  fprintf(output, "\nt%s [ -vh ] [ -lnVx ]\n", PACKAGE);
  fprintf(output, "\t[ -d %s ] ...\n", decode_as_arg_template);
  fprintf(output, "\t[ -F <output file type> ] [ -N <name resolving flags> ]\n");
  fprintf(output, "\t[ -o <preference setting> ] ... [ -r <infile> ]\n");
  fprintf(output, "\t[ -R <read (display) filter> ] \t[ -t <time stamp format> ]\n");
  fprintf(output, "\t[ -T pdml|ps|psml|text ] [ -w <savefile> ] [ -z <statistics ]\n");
#endif
  fprintf(output, "Valid file type arguments to the \"-F\" flag:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
    if (wtap_dump_can_open(i))
      fprintf(output, "\t%s - %s\n",
        wtap_file_type_short_string(i), wtap_file_type_string(i));
  }
  fprintf(output, "\tdefault is libpcap\n");
}

/*
 * For a dissector table, print on the stream described by output,
 * its short name (which is what's used in the "-d" option) and its
 * descriptive name.
 */
static void
display_dissector_table_names(char *table_name, const char *ui_name,
                              gpointer output)
{
  fprintf((FILE *)output, "\t%s (%s)\n", table_name, ui_name);
}

/*
 * For a dissector handle, print on the stream described by output,
 * the filter name (which is what's used in the "-d" option) and the full
 * name for the protocol that corresponds to this handle.
 */
static void
display_dissector_names(const gchar *table _U_, gpointer handle, gpointer output)
{
  int                proto_id;
  const gchar*       proto_filter_name;
  const gchar*       proto_ui_name;

  proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);

  if (proto_id != -1) {
    proto_filter_name = proto_get_protocol_filter_name(proto_id);
    proto_ui_name =  proto_get_protocol_name(proto_id);
    g_assert(proto_filter_name != NULL);
    g_assert(proto_ui_name != NULL);

    fprintf((FILE *)output, "\t%s (%s)\n",
            proto_filter_name,
            proto_ui_name);
  }
}

/*
 * The protocol_name_search structure is used by find_protocol_name_func()
 * to pass parameters and store results
 */
struct protocol_name_search{
  gchar              *searched_name;  /* Protocol filter name we are looking for */
  dissector_handle_t  matched_handle; /* Handle for a dissector whose protocol has the specified filter name */
  guint               nb_match;       /* How many dissectors matched searched_name */
};
typedef struct protocol_name_search *protocol_name_search_t;

/*
 * This function parses all dissectors associated with a table to find the
 * one whose protocol has the specified filter name.  It is called
 * as a reference function in a call to dissector_table_foreach_handle.
 * The name we are looking for, as well as the results, are stored in the
 * protocol_name_search struct pointed to by user_data.
 * If called using dissector_table_foreach_handle, we actually parse the
 * whole list of dissectors.
 */
static void
find_protocol_name_func(const gchar *table _U_, gpointer handle, gpointer user_data)

{
  int                         proto_id;
  const gchar                *protocol_filter_name;
  protocol_name_search_t      search_info;

  g_assert(handle);

  search_info = (protocol_name_search_t)user_data;

  proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);
  if (proto_id != -1) {
    protocol_filter_name = proto_get_protocol_filter_name(proto_id);
    g_assert(protocol_filter_name != NULL);
    if (strcmp(protocol_filter_name, search_info->searched_name) == 0) {
      /* Found a match */
      if (search_info->nb_match == 0) {
        /* Record this handle only if this is the first match */
        search_info->matched_handle = (dissector_handle_t)handle; /* Record the handle for this matching dissector */
      }
      search_info->nb_match++;
    }
  }
}

/*
 * Print all layer type names supported.
 * We send the output to the stream described by the handle output.
 */

static void
fprint_all_layer_types(FILE *output)

{
  dissector_all_tables_foreach_table(display_dissector_table_names, (gpointer)output);
}

/*
 * Print all protocol names supported for a specific layer type.
 * table_name contains the layer type name in which the search is performed.
 * We send the output to the stream described by the handle output.
 */

static void
fprint_all_protocols_for_layer_types(FILE *output, gchar *table_name)

{
  dissector_table_foreach_handle(table_name,
                                 display_dissector_names,
                                 (gpointer)output);
}

/*
 * The function below parses the command-line parameters for the decode as
 * feature (a string pointer by cl_param).
 * It checks the format of the command-line, searches for a matching table
 * and dissector.  If a table/dissector match is not found, we display a
 * summary of the available tables/dissectors (on stderr) and return FALSE.
 * If everything is fine, we get the "Decode as" preference activated,
 * then we return TRUE.
 */
static gboolean
add_decode_as(const gchar *cl_param)
{
  gchar                        *table_name;
  guint32                       selector;
  gchar                        *decoded_param;
  gchar                        *remaining_param;
  gchar                        *selector_str;
  gchar                        *dissector_str;
  dissector_handle_t            dissector_matching;
  dissector_table_t             table_matching;
  ftenum_t                      dissector_table_selector_type;
  struct protocol_name_search   user_protocol_name;

/* The following code will allocate and copy the command-line options in a string pointed by decoded_param */

  g_assert(cl_param);
  decoded_param = g_malloc( sizeof(gchar) * (strlen(cl_param) + 1) ); /* Allocate enough space to have a working copy of the command-line parameter */
  g_assert(decoded_param);
  strcpy(decoded_param, cl_param);


  /* The lines below will parse this string (modifying it) to extract all
    necessary information.  Note that decoded_param is still needed since
    strings are not copied - we just save pointers. */

  /* This section extracts a layer type (table_name) from decoded_param */
  table_name = decoded_param; /* Layer type string starts from beginning */

  remaining_param = strchr(table_name, '=');
  if (remaining_param == NULL) {
    fprintf(stderr, "tethereal: Parameter \"%s\" doesn't follow the template \"%s\"\n", cl_param, decode_as_arg_template);
    /* If the argument does not follow the template, carry on anyway to check
       if the table name is at least correct.  If remaining_param is NULL,
       we'll exit anyway further down */
  }
  else {
    *remaining_param = '\0'; /* Terminate the layer type string (table_name) where '=' was detected */
  }

  /* Remove leading and trailing spaces from the table name */
  while ( table_name[0] == ' ' )
    table_name++; 
  while ( table_name[strlen(table_name) - 1] == ' ' )
    table_name[strlen(table_name) - 1] = '\0'; /* Note: if empty string, while loop will eventually exit */

/* The following part searches a table matching with the layer type specified */
  table_matching = NULL;

/* Look for the requested table */
  if ( !(*(table_name)) ) { /* Is the table name empty, if so, don't even search for anything, display a message */
    fprintf(stderr, "tethereal: No layer type specified\n"); /* Note, we don't exit here, but table_matching will remain NULL, so we exit below */
  }
  else {
    table_matching = find_dissector_table(table_name);
    if (!table_matching) {
      fprintf(stderr, "tethereal: Unknown layer type -- %s\n", table_name); /* Note, we don't exit here, but table_matching will remain NULL, so we exit below */
    }
  }

  if (!table_matching) {
    /* Display a list of supported layer types to help the user, if the 
       specified layer type was not found */
    fprintf(stderr, "tethereal: Valid layer types are:\n");
    fprint_all_layer_types(stderr);
  }
  if (remaining_param == NULL || !table_matching) {
    /* Exit if the layer type was not found, or if no '=' separator was found
       (see above) */
    g_free(decoded_param); 
    return FALSE;
  }
  
  if (*(remaining_param + 1) != '=') { /* Check for "==" and not only '=' */
    fprintf(stderr, "tethereal: WARNING: -d requires \"==\" instead of \"=\". Option will be treated as \"%s==%s\"\n", table_name, remaining_param + 1);
  }
  else {
    remaining_param++; /* Move to the second '=' */
    *remaining_param = '\0'; /* Remove the second '=' */
  }
  remaining_param++; /* Position after the layer type string */

  /* This section extracts a selector value (selector_str) from decoded_param */

  selector_str = remaining_param; /* Next part starts with the selector number */

  remaining_param = strchr(selector_str, ',');
  if (remaining_param == NULL) {
    fprintf(stderr, "tethereal: Parameter \"%s\" doesn't follow the template \"%s\"\n", cl_param, decode_as_arg_template);
    /* If the argument does not follow the template, carry on anyway to check
       if the selector value is at least correct.  If remaining_param is NULL,
       we'll exit anyway further down */
  }
  else {
    *remaining_param = '\0'; /* Terminate the selector number string (selector_str) where ',' was detected */
  }

  dissector_table_selector_type = get_dissector_table_selector_type(table_name);

  switch (dissector_table_selector_type) {

  case FT_UINT8:
  case FT_UINT16:
  case FT_UINT24:
  case FT_UINT32:
    /* The selector for this table is an unsigned number.  Parse it as such.
       There's no need to remove leading and trailing spaces from the
       selector number string, because sscanf will do that for us. */
    if ( sscanf(selector_str, "%u", &selector) != 1 ) {
      fprintf(stderr, "tethereal: Invalid selector number \"%s\"\n", selector_str);
      g_free(decoded_param);
      return FALSE;
    }
    break;

  case FT_STRING:
  case FT_STRINGZ:
    /* The selector for this table is a string. */
    break;

  default:
    /* There are currently no dissector tables with any types other
       than the ones listed above. */
    g_assert_not_reached();
  }

  if (remaining_param == NULL) {
    /* Exit if no ',' separator was found (see above) */
    fprintf(stderr, "tethereal: Valid protocols for layer type \"%s\" are:\n", table_name);
    fprint_all_protocols_for_layer_types(stderr, table_name);
    g_free(decoded_param); 
    return FALSE;
  }

  remaining_param++; /* Position after the selector number string */

  /* This section extracts a protocol filter name (dissector_str) from decoded_param */

  dissector_str = remaining_param; /* All the rest of the string is the dissector (decode as protocol) name */
  
  /* Remove leading and trailing spaces from the dissector name */
  while ( dissector_str[0] == ' ' )
    dissector_str++; 
  while ( dissector_str[strlen(dissector_str) - 1] == ' ' )
    dissector_str[strlen(dissector_str) - 1] = '\0'; /* Note: if empty string, while loop will eventually exit */

  dissector_matching = NULL;
  
  /* We now have a pointer to the handle for the requested table inside the variable table_matching */
  if ( ! (*dissector_str) ) { /* Is the dissector name empty, if so, don't even search for a matching dissector and display all dissectors found for the selected table */
    fprintf(stderr, "tethereal: No protocol name specified\n"); /* Note, we don't exit here, but dissector_matching will remain NULL, so we exit below */
  }
  else {
    user_protocol_name.nb_match = 0;
    user_protocol_name.searched_name = dissector_str;
    user_protocol_name.matched_handle = NULL;
    
    dissector_table_foreach_handle(table_name, find_protocol_name_func, &user_protocol_name); /* Go and perform the search for this dissector in the this table's dissectors' names and shortnames */
    
    if (user_protocol_name.nb_match != 0) {
      dissector_matching = user_protocol_name.matched_handle;
      if (user_protocol_name.nb_match > 1) {
        fprintf(stderr, "tethereal: WARNING: Protocol \"%s\" matched %u dissectors, first one will be used\n", dissector_str, user_protocol_name.nb_match);
      }
    }
    else {
      /* OK, check whether the problem is that there isn't any such
         protocol, or that there is but it's not specified as a protocol
         that's valid for that dissector table.
         Note, we don't exit here, but dissector_matching will remain NULL,
         so we exit below */
      if (proto_get_id_by_filter_name(dissector_str) == -1) {
        /* No such protocol */
        fprintf(stderr, "tethereal: Unknown protocol -- \"%s\"\n", dissector_str);
      } else {
        fprintf(stderr, "tethereal: Protocol \"%s\" isn't valid for layer type \"%s\"\n",
		dissector_str, table_name);
      }
    }
  }

  if (!dissector_matching) {
    fprintf(stderr, "tethereal: Valid protocols for layer type \"%s\" are:\n", table_name);
    fprint_all_protocols_for_layer_types(stderr, table_name);
    g_free(decoded_param); 
    return FALSE;
  }

/* This is the end of the code that parses the command-line options.
   All information is now stored in the variables:
   table_name
   selector
   dissector_matching
   The above variables that are strings are still pointing to areas within
   decoded_parm.  decoded_parm thus still needs to be kept allocated in 
   until we stop needing these variables
   decoded_param will be deallocated at each exit point of this function */


  /* We now have a pointer to the handle for the requested dissector
     (requested protocol) inside the variable dissector_matching */
  switch (dissector_table_selector_type) {

  case FT_UINT8:
  case FT_UINT16:
  case FT_UINT24:
  case FT_UINT32:
    /* The selector for this table is an unsigned number. */
    dissector_change(table_name, selector, dissector_matching);
    break;

  case FT_STRING:
  case FT_STRINGZ:
    /* The selector for this table is a string. */
    dissector_change_string(table_name, selector_str, dissector_matching);
    break;

  default:
    /* There are currently no dissector tables with any types other
       than the ones listed above. */
    g_assert_not_reached();
  }
  g_free(decoded_param); /* "Decode As" rule has been succesfully added */
  return TRUE;
}

int
main(int argc, char *argv[])
{
  int                  opt, i;
  extern char         *optarg;
  gboolean             arg_error = FALSE;

#ifdef _WIN32
  WSADATA		wsaData;
#endif	/* _WIN32 */

  char                *gpf_path, *pf_path;
  char                *gdp_path, *dp_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  int                  err;
#ifdef HAVE_LIBPCAP
  gboolean             capture_filter_specified = FALSE;
  GList               *if_list, *if_entry;
  if_info_t           *if_info;
  long                 adapter_index;
  char                *p;
  gchar                err_str[PCAP_ERRBUF_SIZE];
  gchar               *cant_get_if_list_errstr;
  gboolean             list_link_layer_types = FALSE;
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gboolean             quiet = FALSE;
  gchar               *save_file = NULL;
  int                  out_file_type = WTAP_FILE_PCAP;
  gchar               *cf_name = NULL, *rfilter = NULL;
#ifdef HAVE_LIBPCAP
  gboolean             start_capture = FALSE;
  gchar               *if_text;
  GList               *lt_list, *lt_entry;
  data_link_info_t    *data_link_info;
#endif
#ifdef HAVE_PCAP_OPEN_DEAD
  struct bpf_program   fcode;
#endif
  dfilter_t           *rfcode = NULL;
  e_prefs             *prefs;
  char                 badopt;

  /* initialize memory allocation subsystem */
  ep_init_chunk();
  se_init_chunk();
  
#ifdef HAVE_LIBPCAP
  capture_opts_init(&capture_opts, NULL /* cfile */);
#endif

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs,
            failure_message,open_failure_message,read_failure_message);

  /* Register all tap listeners; we do this before we parse the arguments,
     as the "-z" argument can specify a registered tap. */
  
  /* we register the plugin taps before the other taps because
	  stats_tree taps plugins will be registered as tap listeners
	  by stats_tree_stat.c and need to registered before that */
#ifdef HAVE_PLUGINS
  register_all_plugin_tap_listeners();
#endif
  register_all_tap_listeners();

  /* Now register the preferences for any non-dissector modules.
     We must do that before we read the preferences as well. */
  prefs_register_modules();

  /* If invoked with the "-G" flag, we dump out information based on
     the argument to the "-G" flag; if no argument is specified,
     for backwards compatibility we dump out a glossary of display
     filter symbols.

     We do this here to mirror what happens in the GTK+ version, although
     it's not necessary here. */
  handle_dashG_option(argc, argv, "tethereal");

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);
  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      fprintf(stderr, "Can't open global preferences file \"%s\": %s.\n",
              pf_path, strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      fprintf(stderr, "I/O error reading global preferences file \"%s\": %s.\n",
              pf_path, strerror(gpf_read_errno));
    }
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      fprintf(stderr, "Can't open your preferences file \"%s\": %s.\n", pf_path,
              strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      fprintf(stderr, "I/O error reading your preferences file \"%s\": %s.\n",
              pf_path, strerror(pf_read_errno));
    }
    g_free(pf_path);
    pf_path = NULL;
  }

  /* Set the name resolution code's flags from the preferences. */
  g_resolv_flags = prefs->name_resolve;

  /* Read the disabled protocols file. */
  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
			    &dp_path, &dp_open_errno, &dp_read_errno);
  if (gdp_path != NULL) {
    if (gdp_open_errno != 0) {
      fprintf(stderr,
        "Could not open global disabled protocols file\n\"%s\": %s.\n",
	gdp_path, strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      fprintf(stderr,
        "I/O error reading global disabled protocols file\n\"%s\": %s.\n",
	gdp_path, strerror(gdp_read_errno));
    }
    g_free(gdp_path);
  }
  if (dp_path != NULL) {
    if (dp_open_errno != 0) {
      fprintf(stderr,
        "Could not open your disabled protocols file\n\"%s\": %s.\n", dp_path,
        strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      fprintf(stderr,
        "I/O error reading your disabled protocols file\n\"%s\": %s.\n", dp_path,
        strerror(dp_read_errno));
    }
    g_free(dp_path);
  }

#ifdef _WIN32
  /* Load Wpcap, if possible */
  load_wpcap();
#endif

  init_cap_file(&cfile);

  /* Assemble the compile-time version information string */
  comp_info_str = g_string_new("Compiled ");
  get_compiled_version_info(comp_info_str);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str);

  /* Print format defaults to this. */
  print_format = PR_FMT_TEXT;

  /* Now get our args */
  while ((opt = getopt(argc, argv, "a:b:c:d:Df:F:hi:lLnN:o:pqr:R:s:St:T:vw:Vxy:z:")) != -1) {
    switch (opt) {
      case 'a':        /* autostop criteria */
      case 'b':        /* Ringbuffer option */
      case 'c':        /* Capture xxx packets */
      case 'f':        /* capture filter */
      case 'p':        /* Don't capture in promiscuous mode */
      case 's':        /* Set the snapshot (capture) length */
      case 'y':        /* Set the pcap data link type */
#ifdef HAVE_LIBPCAP
        capture_opts_add_opt(&capture_opts, "tethereal", opt, optarg, &start_capture);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'd':        /* Decode as rule */
        if (!add_decode_as(optarg))
          exit(1);
	break;
      case 'D':        /* Print a list of capture devices */
#ifdef HAVE_LIBPCAP
        if_list = get_interface_list(&err, err_str);
        if (if_list == NULL) {
            switch (err) {

            case CANT_GET_INTERFACE_LIST:
                cant_get_if_list_errstr =
                    cant_get_if_list_error_message(err_str);
                fprintf(stderr, "tethereal: %s\n", cant_get_if_list_errstr);
                g_free(cant_get_if_list_errstr);
                break;

            case NO_INTERFACES_FOUND:
                fprintf(stderr, "tethereal: There are no interfaces on which a capture can be done\n");
                break;
            }
            exit(2);
        }
        i = 1;  /* Interface id number */
        for (if_entry = g_list_first(if_list); if_entry != NULL;
		if_entry = g_list_next(if_entry)) {
	  if_info = if_entry->data;
          printf("%d. %s", i++, if_info->name);
          if (if_info->description != NULL)
            printf(" (%s)", if_info->description);
          printf("\n");
        }
        free_interface_list(if_list);
        exit(0);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'F':
        out_file_type = wtap_short_string_to_file_type(optarg);
        if (out_file_type < 0) {
          fprintf(stderr, "tethereal: \"%s\" isn't a valid capture file type\n",
			optarg);
          exit(1);
        }
        break;
      case 'h':        /* Print help and exit */
	print_usage(TRUE);
	exit(0);
        break;
      case 'i':        /* Use interface xxx */
#ifdef HAVE_LIBPCAP
        /*
         * If the argument is a number, treat it as an index into the list
         * of adapters, as printed by "tethereal -D".
         *
         * This should be OK on UNIX systems, as interfaces shouldn't have
         * names that begin with digits.  It can be useful on Windows, where
         * more than one interface can have the same name.
         */
        adapter_index = strtol(optarg, &p, 10);
        if (p != NULL && *p == '\0') {
          if (adapter_index < 0) {
            fprintf(stderr,
                "tethereal: The specified adapter index is a negative number\n");
           exit(1);
          }
          if (adapter_index > INT_MAX) {
            fprintf(stderr,
                "tethereal: The specified adapter index is too large (greater than %d)\n",
                INT_MAX);
            exit(1);
          }
          if (adapter_index == 0) {
            fprintf(stderr, "tethereal: there is no interface with that adapter index\n");
            exit(1);
          }
          if_list = get_interface_list(&err, err_str);
          if (if_list == NULL) {
            switch (err) {

            case CANT_GET_INTERFACE_LIST:
                cant_get_if_list_errstr =
                    cant_get_if_list_error_message(err_str);
                fprintf(stderr, "tethereal: %s\n", cant_get_if_list_errstr);
                g_free(cant_get_if_list_errstr);
                break;

            case NO_INTERFACES_FOUND:
                fprintf(stderr, "tethereal: There are no interfaces on which a capture can be done\n");
                break;
            }
            exit(2);
          }
          if_info = g_list_nth_data(if_list, adapter_index - 1);
          if (if_info == NULL) {
            fprintf(stderr, "tethereal: there is no interface with that adapter index\n");
            exit(1);
          }
          capture_opts.iface = g_strdup(if_info->name);
          free_interface_list(if_list);
        } else
          capture_opts.iface = g_strdup(optarg);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'l':        /* "Line-buffer" standard output */
	/* This isn't line-buffering, strictly speaking, it's just
	   flushing the standard output after the information for
	   each packet is printed; however, that should be good
	   enough for all the purposes to which "-l" is put (and
	   is probably actually better for "-V", as it does fewer
	   writes).

	   See the comment in "process_packet()" for an explanation of
	   why we do that, and why we don't just use "setvbuf()" to
	   make the standard output line-buffered (short version: in
	   Windows, "line-buffered" is the same as "fully-buffered",
	   and the output buffer is only flushed when it fills up). */
	line_buffered = TRUE;
	break;
      case 'L':        /* Print list of link-layer types and exit */
#ifdef HAVE_LIBPCAP
        list_link_layer_types = TRUE;
        break;
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
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
      case 'q':        /* Quiet */
        quiet = TRUE;
        break;
      case 'r':        /* Read capture file xxx */
        cf_name = g_strdup(optarg);
        break;
      case 'R':        /* Read file filter */
        rfilter = optarg;
        break;
      case 'S':        /* show packets in real time */
        print_packet_info = TRUE;
        break;
      case 't':        /* Time stamp type */
        if (strcmp(optarg, "r") == 0)
          timestamp_set_type(TS_RELATIVE);
        else if (strcmp(optarg, "a") == 0)
          timestamp_set_type(TS_ABSOLUTE);
        else if (strcmp(optarg, "ad") == 0)
          timestamp_set_type(TS_ABSOLUTE_WITH_DATE);
        else if (strcmp(optarg, "d") == 0)
          timestamp_set_type(TS_DELTA);
        else {
          fprintf(stderr, "tethereal: Invalid time stamp type \"%s\"\n",
            optarg);
          fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
          fprintf(stderr, "\"ad\" for absolute with date, or \"d\" for delta.\n");
          exit(1);
        }
        break;
      case 'T':        /* printing Type */
        if (strcmp(optarg, "text") == 0) {
	  output_action = WRITE_TEXT;
	  print_format = PR_FMT_TEXT;
	} else if (strcmp(optarg, "ps") == 0) {
	  output_action = WRITE_TEXT;
	  print_format = PR_FMT_PS;
	} else if (strcmp(optarg, "pdml") == 0) {
	  output_action = WRITE_XML;
	  verbose = TRUE;
	} else if (strcmp(optarg, "psml") == 0) {
	  output_action = WRITE_XML;
	  verbose = FALSE;
	} else {
	  fprintf(stderr, "tethereal: Invalid -T parameter.\n");
	  fprintf(stderr, "It must be \"ps\", \"text\", \"pdml\", or \"psml\".\n");
	  exit(1);
	}
	break;
      case 'v':        /* Show version and exit */
        printf("t" PACKAGE " " VERSION "%s\n%s\n%s\n",
	    svnversion, comp_info_str->str, runtime_info_str->str);
        exit(0);
        break;
      case 'w':        /* Write to capture file xxx */
        save_file = g_strdup(optarg);
	break;
      case 'V':        /* Verbose */
        verbose = TRUE;
        break;
      case 'x':        /* Print packet data in hex (and ASCII) */
        print_hex = TRUE;
        break;
      case 'z':
        /* We won't call the init function for the stat this soon
           as it would disallow MATE's fields (which are registered
           by the preferences set callback) from being used as
           part of a tap filter.  Instead, we just add the argument
           to a list of stat arguments. */
        if (!process_stat_cmd_arg(optarg)) {
	  fprintf(stderr,"tethereal: invalid -z argument.\n");
	  fprintf(stderr,"  -z argument must be one of :\n");
	  list_stat_cmd_args();
	  exit(1);
	}
        break;
      default:
      case '?':        /* Bad flag - print usage message */
        arg_error = TRUE;
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
      capture_opts.cfilter = get_args_as_string(argc, argv, optind);
#else
      capture_option_specified = TRUE;
#endif
    }
  }

  /* See if we're writing a capture file and the file is a pipe */
#ifdef HAVE_LIBPCAP
  ld.output_to_pipe = FALSE;
#endif
  if (save_file != NULL) {
    /* We're writing to a capture file. */
    if (strcmp(save_file, "-") == 0) {
      /* Write to the standard output. */
      g_free(save_file);
      save_file = g_strdup("");
#ifdef HAVE_LIBPCAP
      /* XXX - should we check whether it's a pipe?  It's arguably
         silly to do "-w - >output_file" rather than "-w output_file",
         but by not checking we might be violating the Principle Of
         Least Astonishment. */
      ld.output_to_pipe = TRUE;
#endif
    }
#ifdef HAVE_LIBPCAP
    else {
      err = test_for_fifo(save_file);
      switch (err) {

      case ENOENT:	/* it doesn't exist, so we'll be creating it,
      			   and it won't be a FIFO */
      case 0:		/* found it, but it's not a FIFO */
        break;

      case ESPIPE:	/* it is a FIFO */
        ld.output_to_pipe = TRUE;
        break;

      default:		/* couldn't stat it */
        fprintf(stderr,
                "tethereal: Error testing whether capture file is a pipe: %s\n",
                strerror(errno));
        exit(2);
      }
    }
#endif
  } else {
    /* We're not writing to a file, so we should print packet information
       unless "-q" was specified. */
    if (!quiet)
      print_packet_info = TRUE;
  }

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    fprintf(stderr, "This version of Tethereal was not built with support for capturing packets.\n");
#endif
  if (arg_error) {
    print_usage(FALSE);
    exit(1);
  }

  /* We don't support capture filters when reading from a capture file
     (the BPF compiler doesn't support all link-layer types that we
     support in capture files we read). */
#ifdef HAVE_LIBPCAP
  if (cf_name != NULL) {
    if (capture_filter_specified) {
      fprintf(stderr,
"tethereal: Only read filters, not capture filters, can be specified when reading a capture file.\n");
      exit(2);
    }
  }
#endif

  if (print_hex) {
    if (output_action != WRITE_TEXT) {
      fprintf(stderr, "tethereal: Raw packet hex data can only be printed as text or PostScript\n");
      exit(1);
    }
  }

#ifdef HAVE_LIBPCAP
  if (list_link_layer_types) {
    /* We're supposed to list the link-layer types for an interface;
       did the user also specify a capture file to be read? */
    if (cf_name) {
      /* Yes - that's bogus. */
      fprintf(stderr, "tethereal: You can't specify -L and a capture file to be read.\n");
      exit(1);
    }
    /* No - did they specify a ring buffer option? */
    if (capture_opts.multi_files_on) {
      fprintf(stderr, "tethereal: Ring buffer requested, but a capture isn't being done.\n");
      exit(1);
    }
  } else {
    /* If they didn't specify a "-w" flag, but specified a maximum capture
       file size, tell them that this doesn't work, and exit. */
    if (capture_opts.has_autostop_filesize && save_file == NULL) {
      fprintf(stderr, "tethereal: Maximum capture file size specified, but "
        "capture isn't being saved to a file.\n");
      exit(1);
    }

    if (capture_opts.multi_files_on) {
      /* Ring buffer works only under certain conditions:
	 a) ring buffer does not work if you're not saving the capture to
	    a file;
	 b) ring buffer only works if you're saving in libpcap format;
	 c) it makes no sense to enable the ring buffer if the maximum
	    file size is set to "infinite";
	 d) file must not be a pipe. */
      if (save_file == NULL) {
	fprintf(stderr, "tethereal: Ring buffer requested, but "
	  "capture isn't being saved to a file.\n");
	exit(1);
      }
      if (out_file_type != WTAP_FILE_PCAP) {
	fprintf(stderr, "tethereal: Ring buffer requested, but "
	  "capture isn't being saved in libpcap format.\n");
	exit(2);
      }
      if (!capture_opts.has_autostop_filesize) {
	fprintf(stderr, "tethereal: Ring buffer requested, but "
	  "no maximum capture file size was specified.\n");
	exit(2);
      }
      if (ld.output_to_pipe) {
	fprintf(stderr, "tethereal: Ring buffer requested, but "
	  "capture file is a pipe.\n");
	exit(2);
      }
    }
  }
#endif

#ifdef _WIN32
  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif	/* _WIN32 */

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that their preferences have changed. */
  prefs_apply_all();

  /* At this point MATE will have registered its field array so we can
     have a tap filter with one of MATE's late-registered fields as part
     of the filter.  We can now process all the "-z" arguments. */
  start_requested_stats();
  
  /* disabled protocols as per configuration file */
  if (gdp_path == NULL && dp_path == NULL) {
    set_disabled_protos_list();
  }

  /* Build the column format array */
  col_setup(&cfile.cinfo, prefs->num_cols);
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
    cfile.cinfo.col_fence[i] = 0;
    cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  }

  for (i = 0; i < cfile.cinfo.num_cols; i++) {
      int j;

      for (j = 0; j < NUM_COL_FMTS; j++) {
         if (!cfile.cinfo.fmt_matx[i][j])
             continue;
         
         if (cfile.cinfo.col_first[j] == -1)
             cfile.cinfo.col_first[j] = i;
         cfile.cinfo.col_last[j] = i;
      }
  }

#ifdef HAVE_LIBPCAP
  if (capture_opts.snaplen < 1)
    capture_opts.snaplen = WTAP_MAX_PACKET_SIZE;
  else if (capture_opts.snaplen < MIN_PACKET_SIZE)
    capture_opts.snaplen = MIN_PACKET_SIZE;

  /* Check the value range of the ring_num_files parameter */
  if (capture_opts.ring_num_files > RINGBUFFER_MAX_NUM_FILES)
    capture_opts.ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
  else if (capture_opts.ring_num_files < RINGBUFFER_MIN_NUM_FILES)
    capture_opts.ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
#endif

  if (rfilter != NULL) {
    if (!dfilter_compile(rfilter, &rfcode)) {
      fprintf(stderr, "tethereal: %s\n", dfilter_error_msg);
      epan_cleanup();
#ifdef HAVE_PCAP_OPEN_DEAD
      {
        pcap_t *pc;

        pc = pcap_open_dead(DLT_EN10MB, MIN_PACKET_SIZE);
        if (pc != NULL) {
          if (pcap_compile(pc, &fcode, rfilter, 0, 0) != -1) {
            fprintf(stderr,
              "  Note: That display filter code looks like a valid capture filter;\n"
              "        maybe you mixed them up?\n");
          }
          pcap_close(pc);
        }
      }
#endif
      exit(2);
    }
  }
  cfile.rfcode = rfcode;

  if (print_packet_info) {
    /* If we're printing as text or PostScript, we have
       to create a print stream. */
    if (output_action == WRITE_TEXT) {
      switch (print_format) {

      case PR_FMT_TEXT:
        print_stream = print_stream_text_stdio_new(stdout);
        break;

      case PR_FMT_PS:
        print_stream = print_stream_ps_stdio_new(stdout);
        break;

      default:
        g_assert_not_reached();
      }
    }
  }

  /* We have to dissect each packet if:

	we're printing information about each packet;

	we're using a read filter on the packets;

	we're using any taps. */
  do_dissection = print_packet_info || rfcode || have_tap_listeners();

  if (cf_name) {
    /*
     * We're reading a capture file.
     */

#ifndef _WIN32
    /*
     * Immediately relinquish any set-UID or set-GID privileges we have;
     * we must not be allowed to read any capture files the user running
     * Tethereal can't open.
     */
    setuid(getuid());
    setgid(getgid());
#endif

    if (cf_open(&cfile, cf_name, FALSE, &err) != CF_OK) {
      epan_cleanup();
      exit(2);
    }

    /* Set timestamp precision; there should arguably be a command-line
       option to let the user set this. */
    switch(wtap_file_tsprecision(cfile.wth)) {
    case(WTAP_FILE_TSPREC_SEC):
      timestamp_set_precision(TS_PREC_AUTO_SEC);
      break;
    case(WTAP_FILE_TSPREC_DSEC):
      timestamp_set_precision(TS_PREC_AUTO_DSEC);
      break;
    case(WTAP_FILE_TSPREC_CSEC):
      timestamp_set_precision(TS_PREC_AUTO_CSEC);
      break;
    case(WTAP_FILE_TSPREC_MSEC):
      timestamp_set_precision(TS_PREC_AUTO_MSEC);
      break;
    case(WTAP_FILE_TSPREC_USEC):
      timestamp_set_precision(TS_PREC_AUTO_USEC);
      break;
    case(WTAP_FILE_TSPREC_NSEC):
      timestamp_set_precision(TS_PREC_AUTO_NSEC);
      break;
    default:
      g_assert_not_reached();
    }

    /* Process the packets in the file */
    err = load_cap_file(&cfile, save_file, out_file_type);
    if (err != 0) {
      epan_cleanup();
      exit(2);
    }
    cf_name[0] = '\0';
  } else {
    /* No capture file specified, so we're supposed to do a live capture
       (or get a list of link-layer types for a live capture device);
       do we have support for live captures? */
#ifdef HAVE_LIBPCAP

#ifdef _WIN32
    if (!has_wpcap) {
      fprintf(stderr, "tethereal: Could not load wpcap.dll.\n");
      exit(2);
    }
#endif

    /* Yes; did the user specify an interface to use? */
    if (capture_opts.iface == NULL) {
      /* No - is a default specified in the preferences file? */
      if (prefs->capture_device != NULL) {
        /* Yes - use it. */
        if_text = strrchr(prefs->capture_device, ' ');
	if (if_text == NULL) {
          capture_opts.iface = g_strdup(prefs->capture_device);
	} else {
          capture_opts.iface = g_strdup(if_text + 1); /* Skip over space */
	}
      } else {
        /* No - pick the first one from the list of interfaces. */
        if_list = get_interface_list(&err, err_str);
        if (if_list == NULL) {
          switch (err) {

          case CANT_GET_INTERFACE_LIST:
            cant_get_if_list_errstr = cant_get_if_list_error_message(err_str);
            fprintf(stderr, "tethereal: %s\n", cant_get_if_list_errstr);
            g_free(cant_get_if_list_errstr);
            break;

          case NO_INTERFACES_FOUND:
            fprintf(stderr, "tethereal: There are no interfaces on which a capture can be done\n");
            break;
	  }
          exit(2);
	}
        if_info = if_list->data;	/* first interface */
	capture_opts.iface = g_strdup(if_info->name);
        free_interface_list(if_list);
      }
    }

    if (list_link_layer_types) {
      /* We were asked to list the link-layer types for an interface.
         Get the list of link-layer types for the capture device. */
      lt_list = get_pcap_linktype_list(capture_opts.iface, err_str);
      if (lt_list == NULL) {
	if (err_str[0] != '\0') {
	  fprintf(stderr, "tethereal: The list of data link types for the capture device could not be obtained (%s).\n"
	    "Please check to make sure you have sufficient permissions, and that\n"
	    "you have the proper interface or pipe specified.\n", err_str);
	} else
	  fprintf(stderr, "tethereal: The capture device has no data link types.\n");
	exit(2);
      }
      fprintf(stderr, "Data link types (use option -y to set):\n");
      for (lt_entry = lt_list; lt_entry != NULL;
	   lt_entry = g_list_next(lt_entry)) {
	data_link_info = lt_entry->data;
	fprintf(stderr, "  %s", data_link_info->name);
	if (data_link_info->description != NULL)
	  fprintf(stderr, " (%s)", data_link_info->description);
	else
	  fprintf(stderr, " (not supported)");
	putchar('\n');
      }
      free_pcap_linktype_list(lt_list);
      exit(0);
    }

    if (!quiet) {
      /*
       * The user didn't ask us not to print a count of packets as
       * they arrive, so do so.
       */
      print_packet_counts = TRUE;
    }

    /* For now, assume libpcap gives microsecond precision. */
    timestamp_set_precision(TS_PREC_AUTO_USEC);

    capture(save_file, out_file_type);

    if (capture_opts.multi_files_on) {
      ringbuf_free();
    }
#else
    /* No - complain. */
    fprintf(stderr, "This version of Tethereal was not built with support for capturing packets.\n");
    exit(2);
#endif
  }

  draw_tap_listeners(TRUE);
  epan_cleanup();

  return 0;
}

#ifdef HAVE_LIBPCAP
/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */

static condition  *volatile cnd_ring_timeout = NULL; /* this must be visible in process_packet */

static int
capture(char *save_file, int out_file_type)
{
  int         pcap_encap;
  int         file_snaplen;
  gchar       open_err_str[PCAP_ERRBUF_SIZE];
  gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netnum, netmask;
  struct bpf_program fcode;
  const char *set_linktype_err_str;
  int         err = 0;
  int         volatile volatile_err = 0;
  int         volatile inpkts = 0;
  int         pcap_cnt;
  char        errmsg[1024+1];
  condition  *volatile cnd_stop_capturesize = NULL;
  condition  *volatile cnd_stop_timeout = NULL;
  char       *descr;
#ifndef _WIN32
  void        (*oldhandler)(int);
  static const char ppamsg[] = "can't find PPA for ";
  const char  *libpcap_warn;
  volatile int pipe_fd = -1;
  struct pcap_hdr hdr;
  struct pcaprec_modified_hdr rechdr;
  guchar pcap_data[WTAP_MAX_PACKET_SIZE];
#endif
  struct pcap_stat stats;
  gboolean    write_err;
  gboolean    dump_ok;
  dfilter_t   *rfcode = NULL;
  int         save_file_fd;

  /* Initialize all data structures used for dissection. */
  init_dissection();

  ld.linktype       = WTAP_ENCAP_UNKNOWN;
  ld.pdh            = NULL;

  /* Open the network interface to capture from it.
     Some versions of libpcap may put warnings into the error buffer
     if they succeed; to tell if that's happened, we have to clear
     the error buffer, and check if it's still a null string.  */
  open_err_str[0] = '\0';
  ld.pch = pcap_open_live(capture_opts.iface, capture_opts.snaplen,
			  capture_opts.promisc_mode, 1000, open_err_str);

  if (ld.pch != NULL) {
    /* setting the data link type only works on real interfaces */
    if (capture_opts.linktype != -1) {
      set_linktype_err_str = set_pcap_linktype(ld.pch, capture_opts.iface,
	capture_opts.linktype);
      if (set_linktype_err_str != NULL) {
	g_snprintf(errmsg, sizeof errmsg, "Unable to set data link type (%s).",
	  set_linktype_err_str);
	goto error;
      }
    }
  } else {
    /* We couldn't open "cfile.iface" as a network device. */
#ifdef _WIN32
    /* On Windows, we don't support capturing on pipes, so we give up. */

    /* On Win32 OSes, the capture devices are probably available to all
       users; don't warn about permissions problems.

       Do, however, warn that WAN devices aren't supported. */
    g_snprintf(errmsg, sizeof errmsg,
	"The capture session could not be initiated (%s).\n"
	"Please check that you have the proper interface specified.\n"
	"\n"
	"Note that the WinPcap 2.x version of the driver Ethereal uses for packet\n"
	"capture on Windows doesn't support capturing on PPP/WAN interfaces in\n"
	"Windows NT/2000/XP/2003 Server, and that the WinPcap 3.0 and later versions\n"
	"don't support capturing on PPP/WAN interfaces at all.\n",
	open_err_str);
    goto error;
#else
    /* try to open cfile.iface as a pipe */
    pipe_fd = pipe_open_live(capture_opts.iface, &hdr, &ld, errmsg,
                             sizeof errmsg);

    if (pipe_fd == -1) {

      if (ld.pipe_err == PIPNEXIST) {
	/* Pipe doesn't exist, so output message for interface */

	/* If we got a "can't find PPA for XXX" message, warn the user (who
           is running Tethereal on HP-UX) that they don't have a version
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
	g_snprintf(errmsg, sizeof errmsg,
	  "The capture session could not be initiated (%s).\n"
	  "Please check to make sure you have sufficient permissions, and that\n"
	  "you have the proper interface or pipe specified.%s", open_err_str,
	  libpcap_warn);
      }
      /*
       * Else pipe (or file) does exist and pipe_open_live() has
       * filled in errmsg
       */
      goto error;
    } else
      /* pipe_open_live() succeeded; don't want
         error message from pcap_open_live() */
      open_err_str[0] = '\0';
#endif
  }

#ifndef _WIN32
  /*
   * We've opened the capture device, so, if we're set-UID or set-GID,
   * relinquish those privileges.
   *
   * XXX - if we have saved set-user-ID support, we should give up those
   * privileges immediately, and then reclaim them long enough to get
   * a list of network interfaces and to open one, and then give them
   * up again, so that stuff we do while processing the argument list,
   * reading the user's preferences, etc. is done as the real user and
   * group, not the effective user and group.
   */
  setuid(getuid());
  setgid(getgid());
#endif

  if (capture_opts.cfilter && !ld.from_pipe) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet(capture_opts.iface, &netnum, &netmask, lookup_net_err_str) < 0) {
      /*
       * Well, we can't get the netmask for this interface; it's used
       * only for filters that check for broadcast IP addresses, so
       * we just warn the user, and punt and use 0.
       */
      fprintf(stderr,
        "Warning:  Couldn't obtain netmask info (%s).\n", lookup_net_err_str);
      netmask = 0;
    }
    if (pcap_compile(ld.pch, &fcode, capture_opts.cfilter, 1, netmask) < 0) {
      if (dfilter_compile(capture_opts.cfilter, &rfcode)) {
        g_snprintf(errmsg, sizeof errmsg,
	  "Unable to parse capture filter string (%s).\n"
          "  Interestingly enough, this looks like a valid display filter\n"
	  "  Are you sure you didn't mix them up?",
	  pcap_geterr(ld.pch));
      } else {
        g_snprintf(errmsg, sizeof errmsg,
	  "Unable to parse capture filter string (%s).",
	  pcap_geterr(ld.pch));
      }
      goto error;
    }
    if (pcap_setfilter(ld.pch, &fcode) < 0) {
      g_snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(ld.pch));
#ifdef HAVE_PCAP_FREECODE
      pcap_freecode(&fcode);
#endif
      goto error;
    }
#ifdef HAVE_PCAP_FREECODE
    pcap_freecode(&fcode);
#endif
  }

  /* Set up to write to the capture file. */
#ifndef _WIN32
  if (ld.from_pipe) {
    pcap_encap = hdr.network;
    file_snaplen = hdr.snaplen;
  } else
#endif
  {
    pcap_encap = get_pcap_linktype(ld.pch, capture_opts.iface);
    file_snaplen = pcap_snapshot(ld.pch);
  }
  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_encap);
  if (save_file != NULL) {
    /* Set up to write to the capture file. */
    if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
      strcpy(errmsg, "The network you're capturing from is of a type"
               " that Tethereal doesn't support.");
      goto error;
    }
    ld.save_file = save_file;
    if (capture_opts.multi_files_on) {
      save_file_fd = ringbuf_init(save_file,
        capture_opts.ring_num_files);
      if (save_file_fd != -1) {
        ld.pdh = ringbuf_init_wtap_dump_fdopen(out_file_type, ld.linktype,
          file_snaplen, &err);
      } else {
      	err = errno;	/* "ringbuf_init()" failed */
        ld.pdh = NULL;
      }
    } else {
      ld.pdh = wtap_dump_open(save_file, out_file_type,
		 ld.linktype, file_snaplen, FALSE /* compress */, &err);
    }

    if (ld.pdh == NULL) {
      g_snprintf(errmsg, sizeof errmsg,
	       cf_open_error_message(err, NULL, TRUE, out_file_type),
	       *save_file == '\0' ? "stdout" : save_file);
      goto error;
    }
  }

  /* Does "open_err_str" contain a non-empty string?  If so, "pcap_open_live()"
     returned a warning; print it, but keep capturing. */
  if (open_err_str[0] != '\0')
    fprintf(stderr, "tethereal: WARNING: %s.\n", open_err_str);

#ifdef _WIN32
  /* Catch a CTRL+C event and, if we get it, clean up and exit. */
  SetConsoleCtrlHandler(capture_cleanup, TRUE);
#else /* _WIN32 */
  /* Catch SIGINT and SIGTERM and, if we get either of them, clean up
     and exit.
     XXX - deal with signal semantics on various UNIX platforms.  Or just
     use "sigaction()" and be done with it? */
  signal(SIGTERM, capture_cleanup);
  signal(SIGINT, capture_cleanup);
  if ((oldhandler = signal(SIGHUP, capture_cleanup)) != SIG_DFL)
    signal(SIGHUP, oldhandler);

#ifdef SIGINFO
  /* Catch SIGINFO and, if we get it and we're capturing to a file in
     quiet mode, report the number of packets we've captured. */
  signal(SIGINFO, report_counts_siginfo);
#endif /* SIGINFO */
#endif /* _WIN32 */

  /* Let the user know what interface was chosen. */
  descr = get_interface_descriptive_name(capture_opts.iface);
  fprintf(stderr, "Capturing on %s\n", descr);
  g_free(descr);

  /* initialize capture stop conditions */
  init_capture_stop_conditions();
  /* create stop conditions */
  if (capture_opts.has_autostop_filesize)
    cnd_stop_capturesize = cnd_new((const char*)CND_CLASS_CAPTURESIZE,
                                   (long)capture_opts.autostop_filesize * 1000);
  if (capture_opts.has_autostop_duration)
    cnd_stop_timeout = cnd_new((const char*)CND_CLASS_TIMEOUT,
                               (gint32)capture_opts.autostop_duration);

  if (capture_opts.multi_files_on && capture_opts.has_file_duration)
    cnd_ring_timeout = cnd_new(CND_CLASS_TIMEOUT, 
			       capture_opts.file_duration);

  if (!setjmp(ld.stopenv)) {
    ld.go = TRUE;
    ld.packet_count = 0;
  } else
    ld.go = FALSE;
  while (ld.go) {
    /* We need to be careful with automatic variables defined in the
       outer scope which are changed inside the loop.  Most compilers
       don't try to roll them back to their original values after the
       longjmp which causes the loop to finish, but all that the
       standards say is that their values are indeterminate.  If we
       don't want them to be rolled back, we should define them with the
       volatile attribute (paraphrasing W. Richard Stevens, Advanced
       Programming in the UNIX Environment, p. 178).

       The "err" variable causes a particular problem.  If we give it
       the volatile attribute, then when we pass a reference to it (as
       in "&err") to a function, GCC warns: "passing arg <n> of
       <function> discards qualifiers from pointer target type".
       Therefore within the loop and just beyond we don't use "err".
       Within the loop we define "loop_err", and assign its value to
       "volatile_err", which is in the outer scope and is checked when
       the loop finishes.

       We also define "packet_count_prev" here to keep things tidy,
       since it's used only inside the loop.  If it were defined in the
       outer scope, GCC would give a warning (unnecessary in this case)
       that it might be clobbered, and we'd need to give it the volatile
       attribute to suppress the warning. */

    int loop_err = 0;
    int packet_count_prev = 0;

    if (cnd_stop_capturesize == NULL && cnd_stop_timeout == NULL) {
      /* We're not stopping at a particular capture file size, and we're
         not stopping after some particular amount of time has expired,
         so either we have no stop condition or the only stop condition
         is a maximum packet count.

         If there's no maximum packet count, pass it -1, meaning "until
         you run out of packets in the bufferful you read".  Otherwise,
         pass it the number of packets we have left to capture.

         We don't call "pcap_loop()" as, if we're saving to a file that's
         a FIFO, we want to flush the FIFO after we're done processing
         this libpcap bufferful of packets, so that the program
         reading the FIFO sees the packets immediately and doesn't get
         any partial packet, forcing it to block in the middle of reading
         that packet. */
      if (capture_opts.autostop_packets == 0)
        pcap_cnt = -1;
      else {
        if (ld.packet_count >= capture_opts.autostop_packets) {
          /* XXX do we need this test here? */
          /* It appears there's nothing more to capture. */
          break;
        }
        pcap_cnt = capture_opts.autostop_packets - ld.packet_count;
      }
    } else {
      /* We need to check the capture file size or the timeout after
         each packet. */
      pcap_cnt = 1;
    }
#ifndef _WIN32
    if (ld.from_pipe) {
      inpkts = pipe_dispatch(pipe_fd, &ld, &hdr, &rechdr, pcap_data,
        errmsg, sizeof errmsg);
    } else
#endif
      inpkts = pcap_dispatch(ld.pch, pcap_cnt, capture_pcap_cb, (guchar *) &ld);
    if (inpkts < 0) {
      /* Error from "pcap_dispatch()", or error or "no more packets" from
         "pipe_dispatch(). */
      ld.go = FALSE;
    } else if (cnd_stop_timeout != NULL && cnd_eval(cnd_stop_timeout)) {
      /* The specified capture time has elapsed; stop the capture. */
      ld.go = FALSE;
    } else if (inpkts > 0) {
      if (capture_opts.autostop_packets != 0 &&
                 ld.packet_count >= capture_opts.autostop_packets) {
        /* The specified number of packets have been captured and have
           passed both any capture filter in effect and any read filter
           in effect. */
        ld.go = FALSE;
      } else if (cnd_stop_capturesize != NULL &&
                    cnd_eval(cnd_stop_capturesize,
                              (guint32)wtap_get_bytes_dumped(ld.pdh))) {
        /* We're saving the capture to a file, and the capture file reached
           its maximum size. */
        if (capture_opts.multi_files_on) {
          /* Switch to the next ringbuffer file */
          if (ringbuf_switch_file(&ld.pdh, &save_file, &save_file_fd, &loop_err)) {
            /* File switch succeeded: reset the condition */
            cnd_reset(cnd_stop_capturesize);
	    if (cnd_ring_timeout) {
	      cnd_reset(cnd_ring_timeout);
	    }
          } else {
            /* File switch failed: stop here */
            volatile_err = loop_err;
            ld.go = FALSE;
          }
        } else {
          /* No ringbuffer - just stop. */
          ld.go = FALSE;
        }
      }
      if (ld.output_to_pipe) {
        if (ld.packet_count > packet_count_prev) {
          if (wtap_dump_file_flush(ld.pdh)) {
            volatile_err = errno;
            ld.go = FALSE;
          }
          packet_count_prev = ld.packet_count;
        }
      }
    } /* inpkts > 0 */
  } /* while (ld.go) */

  /* delete stop conditions */
  if (cnd_stop_capturesize != NULL)
    cnd_delete(cnd_stop_capturesize);
  if (cnd_stop_timeout != NULL)
    cnd_delete(cnd_stop_timeout);
  if (cnd_ring_timeout != NULL)
    cnd_delete(cnd_ring_timeout);

  if (print_packet_counts) {
    /* We're printing packet counts to stderr.
       Send a newline so that we move to the line after the packet count. */
    fprintf(stderr, "\n");
  }

  /* If we got an error while capturing, report it. */
  if (inpkts < 0) {
#ifndef _WIN32
    if (ld.from_pipe) {
      if (ld.pipe_err == PIPERR) {
        fprintf(stderr, "tethereal: Error while capturing packets: %s\n",
	  errmsg);
      }
    } else
#endif
    {
      fprintf(stderr, "tethereal: Error while capturing packets: %s\n",
	  pcap_geterr(ld.pch));
    }
  }

  if (volatile_err == 0)
    write_err = FALSE;
  else {
    show_capture_file_io_error(save_file, volatile_err, FALSE);
    write_err = TRUE;
  }

  if (save_file != NULL) {
    /* We're saving to a file or files; close all files. */
    if (capture_opts.multi_files_on) {
      dump_ok = ringbuf_wtap_dump_close(&save_file, &err);
    } else {
      dump_ok = wtap_dump_close(ld.pdh, &err);
    }
    /* If we've displayed a message about a write error, there's no point
       in displaying another message about an error on close. */
    if (!dump_ok && !write_err)
      show_capture_file_io_error(save_file, err, TRUE);
  }

#ifndef _WIN32
  if (ld.from_pipe && pipe_fd >= 0)
    close(pipe_fd);
  else
#endif
  {
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
    pcap_close(ld.pch);
  }

  /* Report the number of captured packets if not reported during capture
     and we are saving to a file. */
  report_counts();

  return TRUE;

error:
  if (capture_opts.multi_files_on) {
    ringbuf_error_cleanup();
  }
  g_free(save_file);
  save_file = NULL;
  fprintf(stderr, "tethereal: %s\n", errmsg);
#ifndef _WIN32
  if (ld.from_pipe) {
    if (pipe_fd >= 0)
      close(pipe_fd);
  } else
#endif
  {
  if (ld.pch != NULL)
    pcap_close(ld.pch);
  }

  return FALSE;
}

static void
capture_pcap_cb(guchar *user, const struct pcap_pkthdr *phdr,
  const guchar *pd)
{
  struct wtap_pkthdr whdr;
  union wtap_pseudo_header pseudo_header;
  loop_data *ldat = (loop_data *) user;
  int loop_err;
  int err;
  int save_file_fd;

  /* Convert from libpcap to Wiretap format.
     If that fails, ignore the packet (wtap_process_pcap_packet has
     written an error message). */
  pd = wtap_process_pcap_packet(ldat->linktype, phdr, pd, &pseudo_header,
				&whdr, &err);
  if (pd == NULL)
    return;

#ifdef SIGINFO
  /*
   * Prevent a SIGINFO handler from writing to stdout while we're
   * doing so; instead, have it just set a flag telling us to print
   * that information when we're done.
   */
  infodelay = TRUE;
#endif /* SIGINFO */

  /* The current packet may have arrived after a very long silence,
   * way past the time to switch files.  In order not to have
   * the first packet of a new series of events as the last
   * [or only] packet in the file, switch before writing!
   */
  if (cnd_ring_timeout != NULL && cnd_eval(cnd_ring_timeout)) {
    /* time elapsed for this ring file, switch to the next */
    if (ringbuf_switch_file(&ldat->pdh, &ldat->save_file, &save_file_fd, &loop_err)) {
      /* File switch succeeded: reset the condition */
      cnd_reset(cnd_ring_timeout);
    } else {
      /* File switch failed: stop here */
      /* XXX - we should do something with "loop_err" */
      ldat->go = FALSE;
    }
  }

  if (!process_packet(&cfile, ldat->pdh, 0, &whdr, &pseudo_header, pd, &err)) {
    /* Error writing to a capture file */
    if (print_packet_counts) {
      /* We're printing counts of packets captured; move to the line after
         the count. */
      fprintf(stderr, "\n");
    }
    show_capture_file_io_error(ldat->save_file, err, FALSE);
    pcap_close(ldat->pch);
    wtap_dump_close(ldat->pdh, &err);
    exit(2);
  }

#ifdef SIGINFO
  /*
   * Allow SIGINFO handlers to write.
   */
  infodelay = FALSE;

  /*
   * If a SIGINFO handler asked us to write out capture counts, do so.
   */
  if (infoprint)
    report_counts();
#endif /* SIGINFO */
}

#ifdef _WIN32
static BOOL WINAPI
capture_cleanup(DWORD ctrltype _U_)
{
  /* CTRL_C_EVENT is sort of like SIGINT, CTRL_BREAK_EVENT is unique to
     Windows, CTRL_CLOSE_EVENT is sort of like SIGHUP, CTRL_LOGOFF_EVENT
     is also sort of like SIGHUP, and CTRL_SHUTDOWN_EVENT is sort of
     like SIGTERM at least when the machine's shutting down.

     For now, we handle them all as indications that we should clean up
     and quit, just as we handle SIGINT, SIGHUP, and SIGTERM in that
     way on UNIX.

     However, as handlers run in a new thread, we can't just longjmp
     out; we have to set "ld.go" to FALSE, and must return TRUE so that
     no other handler - such as one that would terminate the process -
     gets called.

     XXX - for some reason, typing ^C to Tethereal, if you run this in
     a Cygwin console window in at least some versions of Cygwin,
     causes Tethereal to terminate immediately; this routine gets
     called, but the main loop doesn't get a chance to run and
     exit cleanly, at least if this is compiled with Microsoft Visual
     C++ (i.e., it's a property of the Cygwin console window or Bash;
     it happens if Tethereal is not built with Cygwin - for all I know,
     building it with Cygwin may make the problem go away). */
  ld.go = FALSE;
  return TRUE;
}
#else
static void
capture_cleanup(int signum _U_)
{
  /* Longjmp back to the starting point; "pcap_dispatch()", on many
     UNIX platforms, just keeps looping if it gets EINTR, so if we set
     "ld.go" to FALSE and return, we won't break out of it and quit
     capturing. */
  longjmp(ld.stopenv, 1);
}
#endif /* _WIN32 */

static void
report_counts(void)
{
#ifdef SIGINFO
  /* XXX - if we use sigaction, this doesn't have to be done.
     (Yes, this isn't necessary on BSD, but just in case a system
     where "signal()" has AT&T semantics adopts SIGINFO....) */
  signal(SIGINFO, report_counts_siginfo);
#endif /* SIGINFO */

  if (!print_packet_counts) {
    /* Report the count only if we aren't printing a packet count
       as packets arrive. */
    fprintf(stderr, "%u packets captured\n", ld.packet_count);
  }
#ifdef SIGINFO
  infoprint = FALSE;	/* we just reported it */
#endif /* SIGINFO */
}

#ifdef SIGINFO
static void
report_counts_siginfo(int signum _U_)
{
  int sav_errno = errno;
  /* If we've been told to delay printing, just set a flag asking
     that we print counts (if we're supposed to), otherwise print
     the count of packets captured (if we're supposed to). */
  if (infodelay)
    infoprint = TRUE;
  else
    report_counts();
  errno = sav_errno;
}
#endif /* SIGINFO */
#endif /* HAVE_LIBPCAP */

static int
load_cap_file(capture_file *cf, char *save_file, int out_file_type)
{
  gint         linktype;
  int          snapshot_length;
  wtap_dumper *pdh;
  int          err;
  gchar        *err_info;
  long         data_offset;

  linktype = wtap_file_encap(cf->wth);
  if (save_file != NULL) {
    /* Set up to write to the capture file. */
    snapshot_length = wtap_snapshot_length(cf->wth);
    if (snapshot_length == 0) {
      /* Snapshot length of input file not known. */
      snapshot_length = WTAP_MAX_PACKET_SIZE;
    }
    pdh = wtap_dump_open(save_file, out_file_type,
		linktype, snapshot_length, FALSE /* compressed */, &err);

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
          "tethereal: The capture file being read can't be written in "
          "that format.\n");
        break;

      case WTAP_ERR_CANT_OPEN:
        fprintf(stderr,
          "tethereal: The file \"%s\" couldn't be created for some "
          "unknown reason.\n",
            *save_file == '\0' ? "stdout" : save_file);
        break;

      case WTAP_ERR_SHORT_WRITE:
        fprintf(stderr,
          "tethereal: A full header couldn't be written to the file \"%s\".\n",
		*save_file == '\0' ? "stdout" : save_file);
        break;

      default:
        fprintf(stderr,
          "tethereal: The file \"%s\" could not be created: %s\n.",
 		*save_file == '\0' ? "stdout" : save_file,
		wtap_strerror(err));
        break;
      }
      goto out;
    }
  } else {
    if (print_packet_info) {
      if (!write_preamble(cf)) {
        err = errno;
        show_print_file_io_error(err);
        goto out;
      }
    }
    pdh = NULL;
  }
  while (wtap_read(cf->wth, &err, &err_info, &data_offset)) {
    if (!process_packet(cf, pdh, data_offset, wtap_phdr(cf->wth),
                        wtap_pseudoheader(cf->wth), wtap_buf_ptr(cf->wth),
                        &err)) {
      /* Error writing to a capture file */
      show_capture_file_io_error(save_file, err, FALSE);
      wtap_dump_close(pdh, &err);
      exit(2);
    }
  }
  if (err != 0) {
    /* Print a message noting that the read failed somewhere along the line. */
    switch (err) {

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      fprintf(stderr,
"tethereal: \"%s\" has a packet with a network type that Tethereal doesn't support.\n(%s)\n",
	cf->filename, err_info);
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
"tethereal: \"%s\" appears to be damaged or corrupt.\n(%s)\n",
	cf->filename, err_info);
      break;

    default:
      fprintf(stderr,
"tethereal: An error occurred while reading \"%s\": %s.\n",
	cf->filename, wtap_strerror(err));
      break;
    }
    if (save_file != NULL) {
      /* Now close the capture file. */
      if (!wtap_dump_close(pdh, &err))
        show_capture_file_io_error(save_file, err, TRUE);
    }
  } else {
    if (save_file != NULL) {
      /* Now close the capture file. */
      if (!wtap_dump_close(pdh, &err))
        show_capture_file_io_error(save_file, err, TRUE);
    } else {
      if (print_packet_info) {
        if (!write_finale()) {
          err = errno;
          show_print_file_io_error(err);
        }
      }
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
  fdata->num = cf->count;
  fdata->pkt_len = phdr->len;
  cum_bytes += phdr->len;
  fdata->cum_bytes  = cum_bytes;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_ts = *((nstime_t *) &phdr->ts);
  fdata->flags.passed_dfilter = 0;
  fdata->flags.encoding = CHAR_ASCII;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;

  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (nstime_is_zero(&first_ts)) {
    first_ts = fdata->abs_ts;
  }

  /* If we don't have the time stamp of the previous displayed packet,
     it's because this is the first displayed packet.  Save the time
     stamp of this packet as the time stamp of the previous displayed
     packet. */
  if (nstime_is_zero(&prev_ts)) {
    prev_ts = fdata->abs_ts;
  }

  /* Get the time elapsed between the first packet and this packet. */
  nstime_delta(&fdata->rel_ts, &fdata->abs_ts, &first_ts);

  /* If it's greater than the current elapsed time, set the elapsed time
     to it (we check for "greater than" so as not to be confused by
     time moving backwards). */
  if ((gint32)cf->elapsed_time.secs < fdata->rel_ts.secs
	|| ((gint32)cf->elapsed_time.secs == fdata->rel_ts.secs && (gint32)cf->elapsed_time.nsecs < fdata->rel_ts.nsecs)) {
    cf->elapsed_time = fdata->rel_ts;
  }

  /* Get the time elapsed between the previous displayed packet and
     this packet. */
  nstime_delta(&fdata->del_ts, &fdata->abs_ts, &prev_ts);
  prev_ts = fdata->abs_ts;
}

/* Free up all data attached to a "frame_data" structure. */
static void
clear_fdata(frame_data *fdata)
{
  if (fdata->pfd)
    g_slist_free(fdata->pfd);
}

static gboolean
process_packet(capture_file *cf, wtap_dumper *pdh, long offset,
               const struct wtap_pkthdr *whdr,
               union wtap_pseudo_header *pseudo_header, const guchar *pd,
               int *err)
{
  frame_data fdata;
  gboolean create_proto_tree;
  epan_dissect_t *edt;
  gboolean passed;

  /* Count this packet. */
  cf->count++;

  /* If we're going to print packet information, or we're going to
     run a read filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (do_dissection) {
    fill_in_fdata(&fdata, cf, whdr, offset);

    if (print_packet_info) {
      /* Grab any resolved addresses */
    
      if (g_resolv_flags) {
        host_name_lookup_process(NULL);
      }
    }

    passed = TRUE;
    if (cf->rfcode || verbose || num_tap_filters!=0)
      create_proto_tree = TRUE;
    else
      create_proto_tree = FALSE;
    /* The protocol tree will be "visible", i.e., printed, only if we're
       printing packet details, which is true if we're printing stuff
       ("print_packet_info" is true) and we're in verbose mode ("verbose"
       is true). */
    edt = epan_dissect_new(create_proto_tree, print_packet_info && verbose);

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_dfilter(edt, cf->rfcode);

    tap_queue_init(edt);

    /* We only need the columns if we're printing packet info but we're
       *not* verbose; in verbose mode, we print the protocol tree, not
       the protocol summary. */
    epan_dissect_run(edt, pseudo_header, pd, &fdata,
                     (print_packet_info && !verbose) ? &cf->cinfo : NULL);

    tap_push_tapped_queue(edt);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
    else
      passed = TRUE;
  } else {
    /* We're not running a display filter and we're not printing any
       packet information, so we don't need to do a dissection, and all
       packets are processed. */
    edt = NULL;
    passed = TRUE;
  }

  if (passed) {
    /* Count this packet. */
#ifdef HAVE_LIBPCAP
    ld.packet_count++;
#endif

    /* Process this packet. */
    if (pdh != NULL) {
      /* We're writing to a capture file; write this packet. */
      if (!wtap_dump(pdh, whdr, pseudo_header, pd, err))
        return FALSE;
#ifdef HAVE_LIBPCAP
      if (print_packet_counts) {
      	/* We're printing packet counts. */
        if (ld.packet_count != 0) {
          fprintf(stderr, "\r%u ", ld.packet_count);
          /* stderr could be line buffered */
          fflush(stderr);
        }
      }
#endif
    }
    if (print_packet_info) {
      /* We're printing packet information; print the information for
         this packet. */
      print_packet(cf, edt);

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

      if (ferror(stdout)) {
        show_print_file_io_error(errno);
        exit(2);
      }
    }
  }

  if (do_dissection) {
    epan_dissect_free(edt);
    clear_fdata(&fdata);
  }
  return TRUE;
}

static void
show_capture_file_io_error(const char *fname, int err, gboolean is_close)
{
  if (*fname == '\0')
    fname = "stdout";

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

static gboolean
write_preamble(capture_file *cf)
{
  switch (output_action) {

  case WRITE_TEXT:
    return print_preamble(print_stream, cf->filename);
    break;

  case WRITE_XML:
    if (verbose)
      write_pdml_preamble(stdout);
    else
      write_psml_preamble(stdout);
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

static char *
get_line_buf(size_t len)
{
  static char *line_bufp = NULL;
  static size_t line_buf_len = 256;
  size_t new_line_buf_len;

  for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
       new_line_buf_len *= 2)
    ;
  if (line_bufp == NULL) {
    line_buf_len = new_line_buf_len;
    line_bufp = g_malloc(line_buf_len + 1);
  } else {
    if (new_line_buf_len > line_buf_len) {
      line_buf_len = new_line_buf_len;
      line_bufp = g_realloc(line_bufp, line_buf_len + 1);
    }
  }
  return line_bufp;
}

static gboolean
print_columns(capture_file *cf)
{
  char *line_bufp;
  int i;
  size_t buf_offset;
  size_t column_len;

  line_bufp = get_line_buf(256);
  buf_offset = 0;
  *line_bufp = '\0';
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    switch (cf->cinfo.col_fmt[i]) {
    case COL_NUMBER:
#ifdef HAVE_LIBPCAP
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
      if (capture_opts.iface != NULL)
        continue;
#endif
      column_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 3)
        column_len = 3;
      line_bufp = get_line_buf(buf_offset + column_len);
      sprintf(line_bufp + buf_offset, "%3s", cf->cinfo.col_data[i]);
      break;

    case COL_CLS_TIME:
    case COL_REL_TIME:
    case COL_ABS_TIME:
    case COL_ABS_DATE_TIME:	/* XXX - wider */
      column_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 10)
        column_len = 10;
      line_bufp = get_line_buf(buf_offset + column_len);
      sprintf(line_bufp + buf_offset, "%10s", cf->cinfo.col_data[i]);
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
      column_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      sprintf(line_bufp + buf_offset, "%12s", cf->cinfo.col_data[i]);
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
      column_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      sprintf(line_bufp + buf_offset, "%-12s", cf->cinfo.col_data[i]);
      break;

    default:
      column_len = strlen(cf->cinfo.col_data[i]);
      line_bufp = get_line_buf(buf_offset + column_len);
      strcat(line_bufp + buf_offset, cf->cinfo.col_data[i]);
      break;
    }
    buf_offset += column_len;
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
       *
       * We add enough space to the buffer for " <- " or " -> ",
       * even if we're only adding " ".
       */
      line_bufp = get_line_buf(buf_offset + 4);
      switch (cf->cinfo.col_fmt[i]) {

      case COL_DEF_SRC:
      case COL_RES_SRC:
      case COL_UNRES_SRC:
        switch (cf->cinfo.col_fmt[i + 1]) {

        case COL_DEF_DST:
        case COL_RES_DST:
        case COL_UNRES_DST:
          strcat(line_bufp + buf_offset, " -> ");
          buf_offset += 4;
          break;

        default:
          strcat(line_bufp + buf_offset, " ");
          buf_offset += 1;
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
          strcat(line_bufp + buf_offset, " -> ");
          buf_offset += 4;
          break;

        default:
          strcat(line_bufp + buf_offset, " ");
          buf_offset += 1;
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
          strcat(line_bufp + buf_offset, " -> ");
          buf_offset += 4;
          break;

        default:
          strcat(line_bufp + buf_offset, " ");
          buf_offset += 1;
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
          strcat(line_bufp + buf_offset, " <- ");
          buf_offset += 4;
          break;

        default:
          strcat(line_bufp + buf_offset, " ");
          buf_offset += 1;
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
          strcat(line_bufp + buf_offset, " <- ");
          buf_offset += 4;
          break;

        default:
          strcat(line_bufp + buf_offset, " ");
          buf_offset += 1;
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
          strcat(line_bufp + buf_offset, " <- ");
          buf_offset += 4;
          break;

        default:
          strcat(line_bufp + buf_offset, " ");
          buf_offset += 1;
          break;
        }
        break;

      default:
        strcat(line_bufp + buf_offset, " ");
        buf_offset += 1;
        break;
      }
    }
  }
  return print_line(print_stream, 0, line_bufp);
}

static gboolean
print_packet(capture_file *cf, epan_dissect_t *edt)
{
  print_args_t  print_args;

  if (verbose) {
    /* Print the information in the protocol tree. */
    switch (output_action) {

    case WRITE_TEXT:
      print_args.to_file = TRUE;
      print_args.format = print_format;
      print_args.print_summary = !verbose;
      print_args.print_hex = verbose && print_hex;
      print_args.print_formfeed = FALSE;
      print_args.print_dissections = verbose ? print_dissections_expanded : print_dissections_none;

      /* init the packet range */
      packet_range_init(&print_args.range);

      if (!proto_tree_print(&print_args, edt, print_stream))
        return FALSE;
      if (!print_hex) {
        /* "print_hex_data()" will put out a leading blank line, as well
         as a trailing one; print one here, to separate the packets,
         only if "print_hex_data()" won't be called. */
        if (!print_line(print_stream, 0, ""))
          return FALSE;
      }
      break;

    case WRITE_XML:
      proto_tree_write_pdml(edt, stdout);
      printf("\n");
      return !ferror(stdout);
    }
  } else {
    /* Just fill in the columns. */
    epan_dissect_fill_in_columns(edt);

    /* Now print them. */
    switch (output_action) {

    case WRITE_TEXT:
        if (!print_columns(cf))
          return FALSE;
        break;

    case WRITE_XML:
        proto_tree_write_psml(edt, stdout);
        return !ferror(stdout);
    }
  }
  if (print_hex) {
    if (!print_hex_data(print_stream, edt))
      return FALSE;
    if (!print_line(print_stream, 0, ""))
      return FALSE;
  }
  return TRUE;
}

static gboolean
write_finale(void)
{
  switch (output_action) {

  case WRITE_TEXT:
    return print_finale(print_stream);
    break;

  case WRITE_XML:
    if (verbose)
      write_pdml_finale(stdout);
    else
      write_psml_finale(stdout);
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

static void
show_print_file_io_error(int err)
{
  switch (err) {

  case ENOSPC:
    fprintf(stderr,
"tethereal: Not all the packets could be printed because there is "
"no space left on the file system.\n");
    break;

#ifdef EDQUOT
  case EDQUOT:
    fprintf(stderr,
"tethereal: Not all the packets could be printed because you are "
"too close to, or over your disk quota.\n");
  break;
#endif

  default:
    fprintf(stderr,
"tethereal: An error occurred while printing packets: %s.\n",
      strerror(err));
    break;
  }
}

static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
                      int file_type)
{
  const char *errmsg;
  static char errmsg_errno[1024+1];

  if (err < 0) {
    /* Wiretap error. */
    switch (err) {

    case WTAP_ERR_NOT_REGULAR_FILE:
      errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
      break;

    case WTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" isn't a capture file in a format Tethereal understands.";
      break;

    case WTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
               "The file \"%%s\" isn't a capture file in a format Tethereal understands.\n"
               "(%s)", err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
	       "The file \"%%s\" is a pipe, and %s capture files can't be "
	       "written to a pipe.", wtap_file_type_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      errmsg = "Tethereal doesn't support writing capture files in that format.";
      break;

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      if (for_writing)
        errmsg = "Tethereal can't save this capture in that format.";
      else {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" is a capture for a network type that Tethereal doesn't support.\n"
                 "(%s)", err_info);
        g_free(err_info);
        errmsg = errmsg_errno;
      }
      break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
      if (for_writing)
        errmsg = "Tethereal can't save this capture in that format.";
      else
        errmsg = "The file \"%s\" is a capture for a network type that Tethereal doesn't support.";
      break;

    case WTAP_ERR_BAD_RECORD:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
               "The file \"%%s\" appears to be damaged or corrupt.\n"
               "(%s)", err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
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

    default:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
	       "The file \"%%s\" could not be %s: %s.",
	       for_writing ? "created" : "opened",
	       wtap_strerror(err));
      errmsg = errmsg_errno;
      break;
    }
  } else
    errmsg = file_open_error_message(err, for_writing);
  return errmsg;
}

/*
 * Open/create errors are reported with an console message in Tethereal.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "tethereal: ");
  fprintf(stderr, file_open_error_message(err, for_writing), filename);
  fprintf(stderr, "\n");
}

cf_status_t
cf_open(capture_file *cf, const char *fname, gboolean is_tempfile, int *err)
{
  wtap       *wth;
  gchar       *err_info;
  char        err_msg[2048+1];

  wth = wtap_open_offline(fname, err, &err_info, FALSE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

  /* Initialize all data structures used for dissection. */
  init_dissection();

  cf->wth = wth;
  cf->f_datalen = 0;	/* not used, but set it anyway */

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
  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = WTAP_MAX_PACKET_SIZE;
  } else
    cf->has_snap = TRUE;
  nstime_set_zero(&cf->elapsed_time);
  nstime_set_zero(&first_ts);
  nstime_set_zero(&prev_ts);

  return CF_OK;

fail:
  g_snprintf(err_msg, sizeof err_msg,
           cf_open_error_message(*err, err_info, FALSE, 0), fname);
  fprintf(stderr, "tethereal: %s\n", err_msg);
  return CF_ERROR;
}

#ifdef HAVE_LIBPCAP
#ifndef _WIN32
/* Take care of byte order in the libpcap headers read from pipes.
 * (function taken from wiretap/libpcap.c) */
static void
adjust_header(loop_data *ldat, struct pcap_hdr *hdr, struct pcaprec_hdr *rechdr)
{
  if (ldat->byte_swapped) {
    /* Byte-swap the record header fields. */
    rechdr->ts_sec = BSWAP32(rechdr->ts_sec);
    rechdr->ts_usec = BSWAP32(rechdr->ts_usec);
    rechdr->incl_len = BSWAP32(rechdr->incl_len);
    rechdr->orig_len = BSWAP32(rechdr->orig_len);
  }

  /* In file format version 2.3, the "incl_len" and "orig_len" fields were
     swapped, in order to match the BPF header layout.

     Unfortunately, some files were, according to a comment in the "libpcap"
     source, written with version 2.3 in their headers but without the
     interchanged fields, so if "incl_len" is greater than "orig_len" - which
     would make no sense - we assume that we need to swap them.  */
  if (hdr->version_major == 2 &&
      (hdr->version_minor < 3 ||
       (hdr->version_minor == 3 && rechdr->incl_len > rechdr->orig_len))) {
    guint32 temp;

    temp = rechdr->orig_len;
    rechdr->orig_len = rechdr->incl_len;
    rechdr->incl_len = temp;
  }
}

/* Mimic pcap_open_live() for pipe captures
 * We check if "pipename" is "-" (stdin) or a FIFO, open it, and read the
 * header.
 * N.B. : we can't read the libpcap formats used in RedHat 6.1 or SuSE 6.3
 * because we can't seek on pipes (see wiretap/libpcap.c for details) */
static int
pipe_open_live(char *pipename, struct pcap_hdr *hdr, loop_data *ldat,
                 char *errmsg, int errmsgl)
{
  struct stat pipe_stat;
  int         fd;
  guint32     magic;
  int         b;
  unsigned int bytes_read;

  /*
   * XXX Tethereal blocks until we return
   */
  if (strcmp(pipename, "-") == 0)
    fd = 0; /* read from stdin */
  else {
    if (stat(pipename, &pipe_stat) < 0) {
      if (errno == ENOENT || errno == ENOTDIR)
        ldat->pipe_err = PIPNEXIST;
      else {
        g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe: %s", strerror(errno));
        ldat->pipe_err = PIPERR;
      }
      return -1;
    }
    if (! S_ISFIFO(pipe_stat.st_mode)) {
      if (S_ISCHR(pipe_stat.st_mode)) {
        /*
         * Assume the user specified an interface on a system where
         * interfaces are in /dev.  Pretend we haven't seen it.
         */
         ldat->pipe_err = PIPNEXIST;
      } else {
        g_snprintf(errmsg, errmsgl,
            "The capture session could not be initiated because\n"
            "\"%s\" is neither an interface nor a pipe", pipename);
        ldat->pipe_err = PIPERR;
      }
      return -1;
    }
    fd = open(pipename, O_RDONLY);
    if (fd == -1) {
      g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe open: %s", strerror(errno));
      ldat->pipe_err = PIPERR;
      return -1;
    }
  }

  ldat->from_pipe = TRUE;

  /* read the pcap header */
  bytes_read = 0;
  while (bytes_read < sizeof magic) {
    b = read(fd, ((char *)&magic)+bytes_read, sizeof magic-bytes_read);
    if (b <= 0) {
      if (b == 0)
        g_snprintf(errmsg, errmsgl, "End of file on pipe during open");
      else
        g_snprintf(errmsg, errmsgl, "Error on pipe during open: %s",
          strerror(errno));
      goto error;
    }
    bytes_read += b;
  }

  switch (magic) {
  case PCAP_MAGIC:
    /* Host that wrote it has our byte order, and was running
       a program using either standard or ss990417 libpcap. */
    ldat->byte_swapped = FALSE;
    ldat->modified = FALSE;
    break;
  case PCAP_MODIFIED_MAGIC:
    /* Host that wrote it has our byte order, but was running
       a program using either ss990915 or ss991029 libpcap. */
    ldat->byte_swapped = FALSE;
    ldat->modified = TRUE;
    break;
  case PCAP_SWAPPED_MAGIC:
    /* Host that wrote it has a byte order opposite to ours,
       and was running a program using either standard or
       ss990417 libpcap. */
    ldat->byte_swapped = TRUE;
    ldat->modified = FALSE;
    break;
  case PCAP_SWAPPED_MODIFIED_MAGIC:
    /* Host that wrote it out has a byte order opposite to
       ours, and was running a program using either ss990915
       or ss991029 libpcap. */
    ldat->byte_swapped = TRUE;
    ldat->modified = TRUE;
    break;
  default:
    /* Not a "libpcap" type we know about. */
    g_snprintf(errmsg, errmsgl, "Unrecognized libpcap format");
    goto error;
  }

  /* Read the rest of the header */
  bytes_read = 0;
  while (bytes_read < sizeof(struct pcap_hdr)) {
    b = read(fd, ((char *)hdr)+bytes_read,
          sizeof(struct pcap_hdr) - bytes_read);
    if (b <= 0) {
      if (b == 0)
        g_snprintf(errmsg, errmsgl, "End of file on pipe during open");
      else
        g_snprintf(errmsg, errmsgl, "Error on pipe during open: %s",
          strerror(errno));
      goto error;
    }
    bytes_read += b;
  }

  if (ldat->byte_swapped) {
    /* Byte-swap the header fields about which we care. */
    hdr->version_major = BSWAP16(hdr->version_major);
    hdr->version_minor = BSWAP16(hdr->version_minor);
    hdr->snaplen = BSWAP32(hdr->snaplen);
    hdr->network = BSWAP32(hdr->network);
  }

  if (hdr->version_major < 2) {
    g_snprintf(errmsg, errmsgl, "Unable to read old libpcap format");
    goto error;
  }

  ldat->pipe_state = STATE_EXPECT_REC_HDR;
  ldat->pipe_err = PIPOK;
  return fd;

error:
  ldat->pipe_err = PIPERR;
  close(fd);
  return -1;

}
/* We read one record from the pipe, take care of byte order in the record
 * header, write the record in the capture file, and update capture statistics. */

static int
pipe_dispatch(int fd, loop_data *ldat, struct pcap_hdr *hdr,
                struct pcaprec_modified_hdr *rechdr, guchar *data,
                char *errmsg, int errmsgl)
{
  struct pcap_pkthdr phdr;
  int b;
  enum { PD_REC_HDR_READ, PD_DATA_READ, PD_PIPE_EOF, PD_PIPE_ERR,
          PD_ERR } result;

  switch (ldat->pipe_state) {

  case STATE_EXPECT_REC_HDR:
    ldat->bytes_to_read = ldat->modified ?
      sizeof(struct pcaprec_modified_hdr) : sizeof(struct pcaprec_hdr);
    ldat->bytes_read = 0;
    ldat->pipe_state = STATE_READ_REC_HDR;
    /* Fall through */

  case STATE_READ_REC_HDR:
    b = read(fd, ((char *)rechdr)+ldat->bytes_read,
      ldat->bytes_to_read - ldat->bytes_read);
    if (b <= 0) {
      if (b == 0)
        result = PD_PIPE_EOF;
      else
        result = PD_PIPE_ERR;
      break;
    }
    if ((ldat->bytes_read += b) < ldat->bytes_to_read)
        return 0;
    result = PD_REC_HDR_READ;
    break;

  case STATE_EXPECT_DATA:
    ldat->bytes_read = 0;
    ldat->pipe_state = STATE_READ_DATA;
    /* Fall through */

  case STATE_READ_DATA:
    b = read(fd, data+ldat->bytes_read, rechdr->hdr.incl_len - ldat->bytes_read);
    if (b <= 0) {
      if (b == 0)
        result = PD_PIPE_EOF;
      else
        result = PD_PIPE_ERR;
      break;
    }
    if ((ldat->bytes_read += b) < rechdr->hdr.incl_len)
      return 0;
    result = PD_DATA_READ;
    break;

  default:
    g_snprintf(errmsg, errmsgl, "pipe_dispatch: invalid state");
    result = PD_ERR;

  } /* switch (ldat->pipe_state) */

  /*
   * We've now read as much data as we were expecting, so process it.
   */
  switch (result) {

  case PD_REC_HDR_READ:
    /* We've read the header. Take care of byte order. */
    adjust_header(ldat, hdr, &rechdr->hdr);
    if (rechdr->hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
      g_snprintf(errmsg, errmsgl, "Frame %u too long (%d bytes)",
        ldat->packet_count+1, rechdr->hdr.incl_len);
      break;
    }
    ldat->pipe_state = STATE_EXPECT_DATA;
    return 0;

  case PD_DATA_READ:
    /* Fill in a "struct pcap_pkthdr", and process the packet. */
    phdr.ts.tv_sec = rechdr->hdr.ts_sec;
    phdr.ts.tv_usec = rechdr->hdr.ts_usec;
    phdr.caplen = rechdr->hdr.incl_len;
    phdr.len = rechdr->hdr.orig_len;

    capture_pcap_cb((guchar *)ldat, &phdr, data);

    ldat->pipe_state = STATE_EXPECT_REC_HDR;
    return 1;

  case PD_PIPE_EOF:
    ldat->pipe_err = PIPEOF;
    return -1;

  case PD_PIPE_ERR:
    g_snprintf(errmsg, errmsgl, "Error reading from pipe: %s",
      strerror(errno));
    /* Fall through */
  case PD_ERR:
    break;
  }

  ldat->pipe_err = PIPERR;
  /* Return here rather than inside the switch to prevent GCC warning */
  return -1;
}
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

/*
 * General errors are reported with an console message in Tethereal.
 */
static void
failure_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "tethereal: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in Tethereal.
 */
static void
read_failure_message(const char *filename, int err)
{
  fprintf(stderr, "tethereal: An error occurred while reading from the file \"%s\": %s.\n",
          filename, strerror(err));
}
