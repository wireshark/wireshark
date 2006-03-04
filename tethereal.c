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
#include <epan/privileges.h>
#include <wiretap/file_util.h>

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
#include "cmdarg_err.h"
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
#include <epan/ex-opt.h>

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#include <setjmp.h>
#include "capture-pcap-util.h"
#include "pcapio.h"
#include <wiretap/wtap-capture.h>
#ifdef _WIN32
#include "capture-wpcap.h"
#include "capture_errs.h"
#endif /* _WIN32 */
#include "capture.h"
#include "capture_loop.h"
#endif /* HAVE_LIBPCAP */
#include "epan/emem.h"
#include "log.h"
#include <epan/funnel.h>

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


static loop_data ld;

#ifdef HAVE_LIBPCAP
static capture_options capture_opts;


#ifdef SIGINFO
static gboolean infodelay;	/* if TRUE, don't print capture info in SIGINFO handler */
static gboolean infoprint;	/* if TRUE, print capture info after clearing infodelay */
#endif /* SIGINFO */
#endif /* HAVE_LIBPCAP */


static int capture(void);
static void capture_pcap_cb(u_char *, const struct pcap_pkthdr *,
  const u_char *);
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
static gboolean process_packet(capture_file *cf, long offset,
    const struct wtap_pkthdr *whdr, union wtap_pseudo_header *pseudo_header,
    const guchar *pd);
static void show_capture_file_io_error(const char *, int, gboolean);
static void show_print_file_io_error(int err);
static gboolean write_preamble(capture_file *cf);
static gboolean print_packet(capture_file *cf, epan_dissect_t *edt);
static gboolean write_finale(void);
static const char *cf_open_error_message(int err, gchar *err_info,
    gboolean for_writing, int file_type);

static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void failure_message(const char *msg_format, va_list ap);
static void read_failure_message(const char *filename, int err);

capture_file cfile;


static void list_capture_types(void) {
    int i;

    fprintf(stderr, "editcap: The available capture file types for \"F\":\n");
    for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
      if (wtap_dump_can_open(i))
        fprintf(stderr, "    %s - %s\n",
          wtap_file_type_short_string(i), wtap_file_type_string(i));
    }
}

static void
print_usage(gboolean print_ver)
{
  FILE *output;

  if (print_ver) {
    output = stdout;
    fprintf(output, 
        "Tethereal " VERSION "%s\n"
        "Dump and analyze network traffic.\n"
        "See http://www.ethereal.com for more information.\n"
        "\n"
        "%s",
	svnversion, get_copyright_info());
  } else {
    output = stderr;
  }
  fprintf(output, "\n");
  fprintf(output, "Usage: tethereal [options] ...\n");
  fprintf(output, "\n");

#ifdef HAVE_LIBPCAP
  fprintf(output, "Capture interface:\n");
  fprintf(output, "  -i <interface>           name or idx of interface (def: first none loopback)\n");
  fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
  fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
  fprintf(output, "  -p                       don't capture in promiscuous mode\n");
#ifdef _WIN32
  fprintf(output, "  -B <buffer size>         size of kernel buffer (def: 1MB)\n");
#endif
  fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
  fprintf(output, "  -D                       print list of interfaces and exit\n");
  fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
  fprintf(output, "\n");
  fprintf(output, "Capture stop conditions:\n");
  fprintf(output, "  -c <packet count>        stop after n packets (def: infinite)\n");
  fprintf(output, "  -a <autostop cond.> ...  duration:NUM - stop after NUM seconds\n");
  fprintf(output, "                           filesize:NUM - stop this file after NUM KB\n");
  fprintf(output, "                              files:NUM - stop after NUM files\n");
  /*fprintf(output, "\n");*/
  fprintf(output, "Capture output:\n");
  fprintf(output, "  -b <ringbuffer opt.> ... duration:NUM - switch to next file after NUM secs\n");
  fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
  fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
#endif  /* HAVE_LIBPCAP */

  /*fprintf(output, "\n");*/
  fprintf(output, "Input file:\n");
  fprintf(output, "  -r <infile>              set the filename to read from (no pipes or stdin!)\n");

  fprintf(output, "\n");
  fprintf(output, "Processing:\n");
  fprintf(output, "  -R <read filter>         packet filter in Ethereal display filter syntax\n");
  fprintf(output, "  -n                       disable all name resolutions (def: all enabled)\n");
  fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mntC\"\n");
  fprintf(output, "  -d %s ...\n", decode_as_arg_template);
  fprintf(output, "                           \"Decode As\", see the man page for details\n");
  fprintf(output, "                           Example: tcp.port==8888,http\n");

  /*fprintf(output, "\n");*/
  fprintf(output, "Output:\n");
  fprintf(stderr, "  -w <outfile|->           set the output filename (or '-' for stdout)\n");
  fprintf(stderr, "  -F <output file type>    set the output file type, default is libpcap\n");
  fprintf(stderr, "                           an empty \"-F\" option will list the file types\n");
  fprintf(output, "  -V                       add output of packet tree        (Packet Details)\n");
  fprintf(output, "  -x                       add output of hex and ASCII dump (Packet Bytes)\n");
  fprintf(output, "  -T pdml|ps|psml|text     output format of text output (def: text)\n");
  fprintf(output, "  -t ad|a|r|d              output format of time stamps (def: r: rel. to first)\n");
  fprintf(output, "  -l                       flush output after each packet\n");
  fprintf(output, "  -q                       be more quiet on stdout (e.g. when using statistics)\n");
  fprintf(output, "  -X <key>:<value>         eXtension options, see the man page for details\n");
  fprintf(output, "  -z <statistics>          various statistics, see the man page for details\n");

  fprintf(output, "\n");
  fprintf(stderr, "Miscellaneous:\n");
  fprintf(stderr, "  -h                       display this help and exit\n");
  fprintf(stderr, "  -v                       display version info and exit\n");
  fprintf(output, "  -o <name>:<value> ...   override preference setting\n");
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
    cmdarg_err("Parameter \"%s\" doesn't follow the template \"%s\"", cl_param, decode_as_arg_template);
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
    cmdarg_err("No layer type specified"); /* Note, we don't exit here, but table_matching will remain NULL, so we exit below */
  }
  else {
    table_matching = find_dissector_table(table_name);
    if (!table_matching) {
      cmdarg_err("Unknown layer type -- %s", table_name); /* Note, we don't exit here, but table_matching will remain NULL, so we exit below */
    }
  }

  if (!table_matching) {
    /* Display a list of supported layer types to help the user, if the 
       specified layer type was not found */
    cmdarg_err("Valid layer types are:");
    fprint_all_layer_types(stderr);
  }
  if (remaining_param == NULL || !table_matching) {
    /* Exit if the layer type was not found, or if no '=' separator was found
       (see above) */
    g_free(decoded_param); 
    return FALSE;
  }
  
  if (*(remaining_param + 1) != '=') { /* Check for "==" and not only '=' */
    cmdarg_err("WARNING: -d requires \"==\" instead of \"=\". Option will be treated as \"%s==%s\"", table_name, remaining_param + 1);
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
    cmdarg_err("Parameter \"%s\" doesn't follow the template \"%s\"", cl_param, decode_as_arg_template);
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
      cmdarg_err("Invalid selector number \"%s\"", selector_str);
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
    cmdarg_err("Valid protocols for layer type \"%s\" are:", table_name);
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
    cmdarg_err("No protocol name specified"); /* Note, we don't exit here, but dissector_matching will remain NULL, so we exit below */
  }
  else {
    user_protocol_name.nb_match = 0;
    user_protocol_name.searched_name = dissector_str;
    user_protocol_name.matched_handle = NULL;
    
    dissector_table_foreach_handle(table_name, find_protocol_name_func, &user_protocol_name); /* Go and perform the search for this dissector in the this table's dissectors' names and shortnames */
    
    if (user_protocol_name.nb_match != 0) {
      dissector_matching = user_protocol_name.matched_handle;
      if (user_protocol_name.nb_match > 1) {
        cmdarg_err("WARNING: Protocol \"%s\" matched %u dissectors, first one will be used", dissector_str, user_protocol_name.nb_match);
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
        cmdarg_err("Unknown protocol -- \"%s\"", dissector_str);
      } else {
        cmdarg_err("Protocol \"%s\" isn't valid for layer type \"%s\"",
		dissector_str, table_name);
      }
    }
  }

  if (!dissector_matching) {
    cmdarg_err("Valid protocols for layer type \"%s\" are:", table_name);
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

static void
log_func_ignore (const gchar *log_domain _U_, GLogLevelFlags log_level _U_,
    const gchar *message _U_, gpointer user_data _U_)
{
}

static char *
output_file_description(const char *fname)
{
  char *save_file_string;

  /* Get a string that describes what we're writing to */
  if (strcmp(fname, "-") == 0) {
    /* We're writing to the standard output */
    save_file_string = g_strdup("standard output");
  } else {
    /* We're writing to a file with the name in save_file */
    save_file_string = g_strdup_printf("file \"%s\"", fname);
  }
  return save_file_string;
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
  gboolean             list_link_layer_types = FALSE;
  gboolean             start_capture = FALSE;
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gboolean             quiet = FALSE;
  int                  out_file_type = WTAP_FILE_PCAP;
  gchar               *cf_name = NULL, *rfilter = NULL;
#ifdef HAVE_PCAP_OPEN_DEAD
  struct bpf_program   fcode;
#endif
  dfilter_t           *rfcode = NULL;
  e_prefs             *prefs;
  char                 badopt;
  GLogLevelFlags       log_flags;
  int                  status;

#define OPTSTRING_INIT "a:b:c:d:Df:F:hi:lLnN:o:pqr:R:s:St:T:vVw:xX:y:z:"
#ifdef HAVE_LIBPCAP
#ifdef _WIN32
#define OPTSTRING_WIN32 "B:"
#else
#define OPTSTRING_WIN32 ""
#endif  /* _WIN32 */
#else
#define OPTSTRING_WIN32 ""
#endif  /* HAVE_LIBPCAP */

  static const char    optstring[] = OPTSTRING_INIT OPTSTRING_WIN32;

  /*
   * Get credential information for later use.
   */
  get_credential_info();

  /* nothing more than the standard GLib handler, but without a warning */
  log_flags = 
		    G_LOG_LEVEL_ERROR|
		    G_LOG_LEVEL_CRITICAL|
		    G_LOG_LEVEL_WARNING|
		    G_LOG_LEVEL_MESSAGE|
		    G_LOG_LEVEL_INFO|
		    G_LOG_LEVEL_DEBUG|
		    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION;

  g_log_set_handler(NULL,
		    log_flags,
		    log_func_ignore, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
		    log_flags,
		    log_func_ignore, NULL /* user_data */);

  /* initialize memory allocation subsystem */
  ep_init_chunk();
  se_init_chunk();
  
  initialize_funnel_ops();
  
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

     XXX - we do this here, for now, to support "-G" with no arguments.
     If none of our build or other processes uses "-G" with no arguments,
     we can just process it with the other arguments. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    if (argc == 2)
      proto_registrar_dump_fields(1);
    else {
      if (strcmp(argv[2], "fields") == 0)
        proto_registrar_dump_fields(1);
      else if (strcmp(argv[2], "fields2") == 0)
        proto_registrar_dump_fields(2);
      else if (strcmp(argv[2], "fields3") == 0)
        proto_registrar_dump_fields(3);
      else if (strcmp(argv[2], "protocols") == 0)
        proto_registrar_dump_protocols();
      else if (strcmp(argv[2], "values") == 0)
        proto_registrar_dump_values();
      else if (strcmp(argv[2], "decodes") == 0)
        dissector_dump_decodes();
      else if (strcmp(argv[2], "defaultprefs") == 0)
        write_prefs(NULL);
      else if (strcmp(argv[2], "currentprefs") == 0) {
        read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
            &pf_open_errno, &pf_read_errno, &pf_path);
        write_prefs(NULL);
      } else {
        cmdarg_err("Invalid \"%s\" option for -G flag", argv[2]);
        exit(1);
      }
    }
    exit(0);
  }

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);
  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      cmdarg_err("Can't open global preferences file \"%s\": %s.",
              pf_path, strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      cmdarg_err("I/O error reading global preferences file \"%s\": %s.",
              pf_path, strerror(gpf_read_errno));
    }
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      cmdarg_err("Can't open your preferences file \"%s\": %s.", pf_path,
              strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      cmdarg_err("I/O error reading your preferences file \"%s\": %s.",
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
      cmdarg_err("Could not open global disabled protocols file\n\"%s\": %s.",
                 gdp_path, strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      cmdarg_err("I/O error reading global disabled protocols file\n\"%s\": %s.",
                 gdp_path, strerror(gdp_read_errno));
    }
    g_free(gdp_path);
  }
  if (dp_path != NULL) {
    if (dp_open_errno != 0) {
      cmdarg_err(
        "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
        strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      cmdarg_err(
        "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
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
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'a':        /* autostop criteria */
      case 'b':        /* Ringbuffer option */
      case 'c':        /* Capture xxx packets */
      case 'f':        /* capture filter */
      case 'i':        /* Use interface xxx */
      case 'p':        /* Don't capture in promiscuous mode */
      case 's':        /* Set the snapshot (capture) length */
      case 'w':        /* Write to capture file xxx */
      case 'y':        /* Set the pcap data link type */
#ifdef _WIN32
      case 'B':        /* Buffer size */
#endif /* _WIN32 */
#ifdef HAVE_LIBPCAP
        status = capture_opts_add_opt(&capture_opts, opt, optarg, &start_capture);
        if(status != 0) {
            exit(status);
        }
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'd':        /* Decode as rule */
        if (!add_decode_as(optarg))
          exit(1);
        break;
      case 'D':        /* Print a list of capture devices and exit */
#ifdef HAVE_LIBPCAP
        status = capture_opts_list_interfaces();
        exit(status);
#else
        capture_option_specified = TRUE;
        arg_error = TRUE;
#endif
        break;
      case 'F':
        out_file_type = wtap_short_string_to_file_type(optarg);
        if (out_file_type < 0) {
          cmdarg_err("\"%s\" isn't a valid capture file type", optarg);
          list_capture_types();
          exit(1);
        }
        break;
      case 'h':        /* Print help and exit */
        print_usage(TRUE);
        exit(0);
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
          cmdarg_err("-N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'",
                     badopt);
          exit(1);
        }
        break;
      case 'o':        /* Override preference from command line */
        switch (prefs_set_pref(optarg)) {

        case PREFS_SET_SYNTAX_ERR:
          cmdarg_err("Invalid -o flag \"%s\"", optarg);
          exit(1);
          break;

        case PREFS_SET_NO_SUCH_PREF:
        case PREFS_SET_OBSOLETE:
          cmdarg_err("-o flag \"%s\" specifies unknown preference", optarg);
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
          cmdarg_err("Invalid time stamp type \"%s\"",
            optarg);
          cmdarg_err_cont("It must be \"r\" for relative, \"a\" for absolute,");
          cmdarg_err_cont("\"ad\" for absolute with date, or \"d\" for delta.");
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
          cmdarg_err("Invalid -T parameter.");
          cmdarg_err_cont("It must be \"ps\", \"text\", \"pdml\", or \"psml\".");
          exit(1);
        }
        break;
      case 'v':        /* Show version and exit */
        printf("Tethereal " VERSION "%s\n"
               "\n"
               "%s"
               "\n"
               "%s"
               "\n"
               "%s",
               svnversion, get_copyright_info(), comp_info_str->str,
               runtime_info_str->str);
        exit(0);
        break;
      case 'V':        /* Verbose */
        verbose = TRUE;
        break;
      case 'x':        /* Print packet data in hex (and ASCII) */
          print_hex = TRUE;
          break;
      case 'X':
          ex_opt_add(optarg);
          break;
      case 'z':
        /* We won't call the init function for the stat this soon
           as it would disallow MATE's fields (which are registered
           by the preferences set callback) from being used as
           part of a tap filter.  Instead, we just add the argument
           to a list of stat arguments. */
        if (!process_stat_cmd_arg(optarg)) {
          cmdarg_err("invalid -z argument.");
          cmdarg_err_cont("  -z argument must be one of :");
          list_stat_cmd_args();
          exit(1);
        }
        break;
      default:
      case '?':        /* Bad flag - print usage message */
        switch(optopt) {
        case'F':
          list_capture_types();
          break;
        default:
          print_usage(TRUE);
        }
        exit(1);
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
        cmdarg_err("Read filters were specified both with \"-R\" "
            "and with additional command-line arguments");
        exit(1);
      }
      rfilter = get_args_as_string(argc, argv, optind);
    } else {
#ifdef HAVE_LIBPCAP
      if (capture_filter_specified) {
        cmdarg_err("Capture filters were specified both with \"-f\""
            " and with additional command-line arguments");
        exit(1);
      }
      capture_opts.cfilter = get_args_as_string(argc, argv, optind);
#else
      capture_option_specified = TRUE;
#endif
    }
  }

  /* If we're not writing to a file and "-q" wasn't specified
     we should print packet information */
  if (capture_opts.save_file == NULL && !quiet)
    print_packet_info = TRUE;

  if (capture_opts.save_file != NULL && 
      strcmp(capture_opts.save_file, "-") == 0 
      && print_packet_info) {
      /* If we're writing to the standard output.
         and we'll also be writing dissected packets to the standard
         output, reject the request.  At best, we could redirect that
         to the standard error; we *can't* write both to the standard
         output and have either of them be useful. */
      cmdarg_err("You can't write both raw packet data and dissected packets"
          " to the standard output.");
      exit(1);
  }

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    cmdarg_err("This version of Tethereal was not built with support for capturing packets.");
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
      cmdarg_err("Only read filters, not capture filters, "
          "can be specified when reading a capture file.");
      exit(1);
    }
  }
#endif

  if (print_hex) {
    if (output_action != WRITE_TEXT) {
      cmdarg_err("Raw packet hex data can only be printed as text or PostScript");
      exit(1);
    }
  }

#ifdef HAVE_LIBPCAP
  if (list_link_layer_types) {
    /* We're supposed to list the link-layer types for an interface;
       did the user also specify a capture file to be read? */
    if (cf_name) {
      /* Yes - that's bogus. */
      cmdarg_err("You can't specify -L and a capture file to be read.");
      exit(1);
    }
    /* No - did they specify a ring buffer option? */
    if (capture_opts.multi_files_on) {
      cmdarg_err("Ring buffer requested, but a capture isn't being done.");
      exit(1);
    }
  } else {
    /* If they didn't specify a "-w" flag, but specified a maximum capture
       file size, tell them that this doesn't work, and exit. */
    if (capture_opts.has_autostop_filesize && capture_opts.save_file == NULL) {
      cmdarg_err("Maximum capture file size specified, but "
        "capture isn't being saved to a file.");
      exit(1);
    }

    if (cf_name) {
      /*
       * "-r" was specified, so we're reading a capture file.
       * Capture options don't apply here.
       */
      if (capture_opts.multi_files_on) {
        cmdarg_err("Multiple capture files requested, but "
                   "a capture isn't being done.");
        exit(1);
      }
      if (capture_opts.has_file_duration) {
        cmdarg_err("Switching capture files after a time interval was specified, but "
                   "a capture isn't being done.");
        exit(1);
      }
      if (capture_opts.has_ring_num_files) {
        cmdarg_err("A ring buffer of capture files was specified, but "
          "a capture isn't being done.");
        exit(1);
      }
      if (capture_opts.has_autostop_files) {
        cmdarg_err("A maximum number of capture files was specified, but "
          "a capture isn't being done.");
        exit(1);
      }
      if (capture_opts.has_autostop_packets) {
        cmdarg_err("A maximum number of captured packets was specified, but "
          "a capture isn't being done.");
        exit(1);
      }
      if (capture_opts.has_autostop_filesize) {
        cmdarg_err("A maximum capture file size was specified, but "
          "a capture isn't being done.");
        exit(1);
      }
      if (capture_opts.has_autostop_duration) {
        cmdarg_err("A maximum capture time was specified, but "
          "a capture isn't being done.");
        exit(1);
      }
    } else {
      /*
       * "-r" wasn't specified, so we're doing a live capture.
       */
      if (capture_opts.save_file != NULL) {
        /* They specified a "-w" flag, so we'll be saving to a capture file. */
  
        /* When capturing, we only support writing libpcap format. */
        if (out_file_type != WTAP_FILE_PCAP) {
          cmdarg_err("Live captures can only be saved in libpcap format.");
          exit(1);
        }
        if (capture_opts.multi_files_on) {
          /* Multiple-file mode works only under certain conditions:
             a) it doesn't work if you're writing to the standard output;
             b) it doesn't work if you're writing to a pipe;
             c) it makes no sense if the maximum file size is set to "infinite"
                (XXX - shouldn't that be "if there is no stop criterion",
                as you might want to switch files based on a packet count
                or a time). */
          if (strcmp(capture_opts.save_file, "-") == 0) {
            cmdarg_err("Multiple capture files requested, but "
              "the capture is being written to the standard output.");
            exit(1);
          }
          if (capture_opts.output_to_pipe) {
            cmdarg_err("Multiple capture files requested, but "
              "the capture file is a pipe.");
            exit(1);
          }
          if (!capture_opts.has_autostop_filesize) {
            cmdarg_err("Multiple capture files requested, but "
              "no maximum capture file size was specified.");
            exit(1);
          }
        }
      } else {
        /* They didn't specify a "-w" flag, so we won't be saving to a
           capture file.  Check for options that only make sense if
           we're saving to a file. */
        if (capture_opts.has_autostop_filesize) {
          cmdarg_err("Maximum capture file size specified, but "
           "capture isn't being saved to a file.");
          exit(1);
        }
        if (capture_opts.multi_files_on) {
          cmdarg_err("Multiple capture files requested, but "
            "the capture isn't being saved to a file.");
          exit(1);
        }
      }
    }
  }
#endif

#ifdef _WIN32
  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif /* _WIN32 */

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
  capture_opts_trim_snaplen(&capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(&capture_opts);
#endif

  if (rfilter != NULL) {
    if (!dfilter_compile(rfilter, &rfcode)) {
      cmdarg_err("%s", dfilter_error_msg);
      epan_cleanup();
#ifdef HAVE_PCAP_OPEN_DEAD
      {
        pcap_t *pc;

        pc = pcap_open_dead(DLT_EN10MB, MIN_PACKET_SIZE);
        if (pc != NULL) {
          if (pcap_compile(pc, &fcode, rfilter, 0, 0) != -1) {
            cmdarg_err_cont(
              "  Note: That display filter code looks like a valid capture filter;");
            cmdarg_err_cont(
              "        maybe you mixed them up?");
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

    /*
     * Immediately relinquish any special privileges we have; we must not
     * be allowed to read any capture files the user running Tethereal
     * can't open.
     */
    relinquish_special_privs_perm();

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
    err = load_cap_file(&cfile, capture_opts.save_file, out_file_type);
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
      char *detailed_err;

      cmdarg_err("WinPcap couldn't be found.");
      detailed_err = cant_load_winpcap_err("Tethereal");
      cmdarg_err_cont("%s", detailed_err);
      g_free(detailed_err);
      exit(2);
    }
#endif

    /* trim the interface name and exit if that failed */
    if (!capture_opts_trim_iface(&capture_opts, 
        (prefs->capture_device) ? get_if_name(prefs->capture_device) : NULL)) {
        exit(2);
    }

    /* if requested, list the link layer types and exit */
    if (list_link_layer_types) {
        status = capture_opts_list_link_layer_types(&capture_opts);
        exit(status);
    }

    if (!print_packet_info && !quiet) {
      /*
       * We're not printing information for each packet, and the user
       * didn't ask us not to print a count of packets as they arrive,
       * so print that count so the user knows that packets are arriving.
       *
       * XXX - what if the user wants to do a live capture, doesn't want
       * to save it to a file, doesn't want information printed for each
       * packet, does want some "-z" statistic, and wants packet counts
       * so they know whether they're seeing any packets?
       */
      print_packet_counts = TRUE;
    }

    /* For now, assume libpcap gives microsecond precision. */
    timestamp_set_precision(TS_PREC_AUTO_USEC);

    capture();

    if (capture_opts.multi_files_on) {
      ringbuf_free();
    }
#else
    /* No - complain. */
    cmdarg_err("This version of Tethereal was not built with support for capturing packets.");
    exit(2);
#endif
  }

  draw_tap_listeners(TRUE);
  funnel_dump_all_text_windows();
  epan_cleanup();

  return 0;
}

#ifdef HAVE_LIBPCAP
/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */

static condition  *volatile cnd_file_duration = NULL; /* this must be visible in process_packet */

static int
capture(void)
{
  int         err = 0;
  int         volatile volatile_err = 0;
  int         volatile inpkts = 0;
  int         pcap_cnt;
  char        errmsg[1024+1];
  condition  *volatile cnd_autostop_size = NULL;
  condition  *volatile cnd_autostop_duration = NULL;
  char       *descr;
#ifndef _WIN32
  void        (*oldhandler)(int);
  guchar pcap_data[WTAP_MAX_PACKET_SIZE];
#endif
  struct pcap_stat stats;
  gboolean    write_ok;
  gboolean    close_ok;
  int         save_file_fd;

  /* Initialize all data structures used for dissection. */
  init_dissection();

  ld.wtap_linktype  = WTAP_ENCAP_UNKNOWN;
  ld.pdh            = NULL;
  ld.packet_cb      = capture_pcap_cb;


  /* open the "input file" from network interface or capture pipe */
  if (!capture_loop_open_input(&capture_opts, &ld, errmsg, sizeof(errmsg)))
  {
    goto error;
  }

  /*
   * We've opened the capture device, so we shouldn't need any special
   * privileges any more; relinquish those privileges.
   *
   * XXX - if we have saved set-user-ID support, we should give up those
   * privileges immediately, and then reclaim them long enough to get
   * a list of network interfaces and to open one, and then give them
   * up again, so that stuff we do while processing the argument list,
   * reading the user's preferences, loading and starting plugins
   * (especially *user* plugins), etc. is done with the user's privileges,
   * not special privileges.
   */
  relinquish_special_privs_perm();

  /* open the output file (temporary/specified name/ringbuffer/named pipe/stdout) */
  if (!capture_loop_open_output(&capture_opts, &save_file_fd, errmsg, sizeof(errmsg))) {
    goto error;    
  }

  /* init the input filter from the network interface (capture pipe will do nothing) */
  if(!capture_loop_init_filter(ld.pcap_h, ld.from_cap_pipe, 
      capture_opts.iface, capture_opts.cfilter, errmsg, sizeof errmsg)) 
  {
      goto error;
  }

  /* set up to write to the already-opened capture output file/files */
  if(!capture_loop_init_output(&capture_opts, save_file_fd, &ld, errmsg, sizeof errmsg))
  {
      goto error;
  }

  ld.wtap_linktype = wtap_pcap_encap_to_wtap_encap(ld.linktype);

  /* Save the capture file name. */
  ld.save_file = capture_opts.save_file;

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
    cnd_autostop_size = cnd_new((const char*)CND_CLASS_CAPTURESIZE,
                                   (long)capture_opts.autostop_filesize * 1024);
  if (capture_opts.has_autostop_duration)
    cnd_autostop_duration = cnd_new((const char*)CND_CLASS_TIMEOUT,
                               (gint32)capture_opts.autostop_duration);

  if (capture_opts.multi_files_on && capture_opts.has_file_duration)
    cnd_file_duration = cnd_new(CND_CLASS_TIMEOUT, capture_opts.file_duration);

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

    if (cnd_autostop_size == NULL && cnd_autostop_duration == NULL) {
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
    if (ld.from_cap_pipe) {
      inpkts = cap_pipe_dispatch(ld.cap_pipe_fd, &ld, &ld.cap_pipe_hdr, &ld.cap_pipe_rechdr, pcap_data,
        errmsg, sizeof errmsg);
    } else
#endif
      inpkts = pcap_dispatch(ld.pcap_h, pcap_cnt, capture_pcap_cb, (u_char *) &ld);
    if (inpkts < 0) {
      /* Error from "pcap_dispatch()", or error or "no more packets" from
         "cap_pipe_dispatch(). */
      ld.go = FALSE;
    } else if (cnd_autostop_duration != NULL && cnd_eval(cnd_autostop_duration)) {
      /* The specified capture time has elapsed; stop the capture. */
      ld.go = FALSE;
    } else if (inpkts > 0) {
      if (capture_opts.autostop_packets != 0 &&
                 ld.packet_count >= capture_opts.autostop_packets) {
        /* The specified number of packets have been captured and have
           passed both any capture filter in effect and any read filter
           in effect. */
        ld.go = FALSE;
      } else if (cnd_autostop_size != NULL &&
                    cnd_eval(cnd_autostop_size, (guint32)ld.bytes_written)) {
        /* We're saving the capture to a file, and the capture file reached
           its maximum size. */
        if (capture_opts.multi_files_on) {
          /* Switch to the next ringbuffer file */
          if (ringbuf_switch_file(&ld.pdh, &capture_opts.save_file, &save_file_fd, &loop_err)) {
            /* File switch succeeded: reset the condition */
            cnd_reset(cnd_autostop_size);
            if (cnd_file_duration) {
              cnd_reset(cnd_file_duration);
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
      if (capture_opts.output_to_pipe) {
        if (ld.packet_count > packet_count_prev) {
          libpcap_dump_flush(ld.pdh, NULL);
          packet_count_prev = ld.packet_count;
        }
      }
    } /* inpkts > 0 */
  } /* while (ld.go) */

  /* delete stop conditions */
  if (cnd_autostop_size != NULL)
    cnd_delete(cnd_autostop_size);
  if (cnd_autostop_duration != NULL)
    cnd_delete(cnd_autostop_duration);
  if (cnd_file_duration != NULL)
    cnd_delete(cnd_file_duration);

  if (print_packet_counts) {
    /* We're printing packet counts to stderr.
       Send a newline so that we move to the line after the packet count. */
    fprintf(stderr, "\n");
  }

  /* If we got an error while capturing, report it. */
  if (inpkts < 0) {
#ifndef _WIN32
    if (ld.from_cap_pipe) {
      if (ld.cap_pipe_err == PIPERR) {
        cmdarg_err("Error while capturing packets: %s", errmsg);
      }
    } else
#endif
    {
      cmdarg_err("Error while capturing packets: %s", pcap_geterr(ld.pcap_h));
    }
  }

  if (volatile_err == 0)
    write_ok = TRUE;
  else {
    show_capture_file_io_error(capture_opts.save_file, volatile_err, FALSE);
    write_ok = FALSE;
  }

  if (capture_opts.save_file != NULL) {
    /* We're saving to a file or files; close all files. */
    close_ok = capture_loop_close_output(&capture_opts, &ld, &err);

    /* If we've displayed a message about a write error, there's no point
       in displaying another message about an error on close. */
    if (!close_ok && write_ok)
      show_capture_file_io_error(capture_opts.save_file, err, TRUE);
  }

#ifndef _WIN32
  if (ld.from_cap_pipe && ld.cap_pipe_fd >= 0)
    eth_close(ld.cap_pipe_fd);
  else
#endif
  {
    /* Get the capture statistics, and, if any packets were dropped, report
       that. */
    if (pcap_stats(ld.pcap_h, &stats) >= 0) {
      if (stats.ps_drop != 0) {
        fprintf(stderr, "%u packets dropped\n", stats.ps_drop);
      }
    } else {
      cmdarg_err("Can't get packet-drop statistics: %s", pcap_geterr(ld.pcap_h));
    }
    pcap_close(ld.pcap_h);
  }

  /* Report the number of captured packets if not reported during capture
     and we are saving to a file. */
  report_counts();

  return TRUE;

error:
  if (capture_opts.multi_files_on) {
    ringbuf_error_cleanup();
  }
  g_free(capture_opts.save_file);
  capture_opts.save_file = NULL;
  cmdarg_err("%s", errmsg);
#ifndef _WIN32
  if (ld.from_cap_pipe) {
    if (ld.cap_pipe_fd >= 0)
      eth_close(ld.cap_pipe_fd);
  } else
#endif
  {
  if (ld.pcap_h != NULL)
    pcap_close(ld.pcap_h);
  }

  return FALSE;
}

static void
capture_pcap_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd)
{
  struct wtap_pkthdr whdr;
  union wtap_pseudo_header pseudo_header;
  const guchar *wtap_pd;
  loop_data *ld = (loop_data *) user;
  int loop_err;
  int err;
  int save_file_fd;
  gboolean packet_accepted;

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
  if (cnd_file_duration != NULL && cnd_eval(cnd_file_duration)) {
    /* time elapsed for this ring file, switch to the next */
    if (ringbuf_switch_file(&ld->pdh, &ld->save_file, &save_file_fd, &loop_err)) {
      /* File switch succeeded: reset the condition */
      cnd_reset(cnd_file_duration);
    } else {
      /* File switch failed: stop here */
      /* XXX - we should do something with "loop_err" */
      ld->go = FALSE;
    }
  }

  if (do_dissection) {
    /* We're goint to print packet information, run a read filter, or
       process taps.  Use process_packet() to handle that; in order
       to do that, we need to convert from libpcap to Wiretap format.
       If that fails, ignore the packet (wtap_process_pcap_packet has
       written an error message). */
    wtap_pd = wtap_process_pcap_packet(ld->wtap_linktype, phdr, pd,
                                       &pseudo_header, &whdr, &err);
    if (wtap_pd == NULL)
      return;

    packet_accepted = process_packet(&cfile, 0, &whdr, &pseudo_header, wtap_pd);
  } else {
    /* We're just writing out packets. */
    packet_accepted = TRUE;
  }

  if (packet_accepted) {
    /* Count this packet. */
#ifdef HAVE_LIBPCAP
    ld->packet_count++;
#endif

    if (ld->pdh != NULL) {
      if (!libpcap_write_packet(ld->pdh, phdr, pd, &ld->bytes_written, &err)) {
        /* Error writing to a capture file */
        if (print_packet_counts) {
          /* We're printing counts of packets captured; move to the line after
             the count. */
          fprintf(stderr, "\n");
        }
        show_capture_file_io_error(ld->save_file, err, FALSE);
        pcap_close(ld->pcap_h);
        libpcap_dump_close(ld->pdh, &err);
        exit(2);
      }
    }
    if (print_packet_counts) {
      /* We're printing packet counts. */
      if (ld->packet_count != 0) {
        fprintf(stderr, "\r%u ", ld->packet_count);
        /* stderr could be line buffered */
        fflush(stderr);
      }
    }
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
  infoprint = FALSE; /* we just reported it */
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
  char         *save_file_string = NULL;

  linktype = wtap_file_encap(cf->wth);
  if (save_file != NULL) {
    /* Get a string that describes what we're writing to */
    save_file_string = output_file_description(save_file);

    /* Set up to write to the capture file. */
    snapshot_length = wtap_snapshot_length(cf->wth);
    if (snapshot_length == 0) {
      /* Snapshot length of input file not known. */
      snapshot_length = WTAP_MAX_PACKET_SIZE;
    }
    pdh = wtap_dump_open(save_file, out_file_type, linktype, snapshot_length,
                         FALSE /* compressed */, &err);

    if (pdh == NULL) {
      /* We couldn't set up to write to the capture file. */
      switch (err) {

      case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
        cmdarg_err("Capture files can't be written in that format.");
        break;

      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
        cmdarg_err("The capture file being read can't be written in "
          "that format.");
        break;

      case WTAP_ERR_CANT_OPEN:
        cmdarg_err("The %s couldn't be created for some "
          "unknown reason.", save_file_string);
        break;

      case WTAP_ERR_SHORT_WRITE:
        cmdarg_err("A full header couldn't be written to the %s.",
                   save_file_string);
        break;

      default:
        cmdarg_err("The %s could not be created: %s.", save_file_string,
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
    if (process_packet(cf, data_offset, wtap_phdr(cf->wth),
                       wtap_pseudoheader(cf->wth), wtap_buf_ptr(cf->wth))) {
      /* Either there's no read filtering or this packet passed the
         filter, so, if we're writing to a capture file, write
         this packet out. */
      if (pdh != NULL) {
        if (!wtap_dump(pdh, wtap_phdr(cf->wth),
                       wtap_pseudoheader(cf->wth), wtap_buf_ptr(cf->wth),
                       &err)) {
          /* Error writing to a capture file */
          show_capture_file_io_error(save_file, err, FALSE);
          wtap_dump_close(pdh, &err);
          exit(2);
        }
      }
    }
  }
  if (err != 0) {
    /* Print a message noting that the read failed somewhere along the line. */
    switch (err) {

    case WTAP_ERR_UNSUPPORTED_ENCAP:
      cmdarg_err("\"%s\" has a packet with a network type that Tethereal doesn't support.\n(%s)",
                 cf->filename, err_info);
      break;

    case WTAP_ERR_CANT_READ:
      cmdarg_err("An attempt to read from \"%s\" failed for some unknown reason.",
                 cf->filename);
      break;

    case WTAP_ERR_SHORT_READ:
      cmdarg_err("\"%s\" appears to have been cut short in the middle of a packet.",
                 cf->filename);
      break;

    case WTAP_ERR_BAD_RECORD:
      cmdarg_err("\"%s\" appears to be damaged or corrupt.\n(%s)",
                 cf->filename, err_info);
      break;

    default:
      cmdarg_err("An error occurred while reading \"%s\": %s.",
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

  if (save_file_string != NULL)
    g_free(save_file_string);

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
  fdata->color_filter = NULL;

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
process_packet(capture_file *cf, long offset, const struct wtap_pkthdr *whdr,
               union wtap_pseudo_header *pseudo_header, const guchar *pd)
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
    /* Process this packet. */
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
  return passed;
}

static void
show_capture_file_io_error(const char *fname, int err, gboolean is_close)
{
  char *save_file_string;

  save_file_string = output_file_description(fname);

  switch (err) {

  case ENOSPC:
    cmdarg_err("Not all the packets could be written to the %s because there is "
               "no space left on the file system.",
               save_file_string);
    break;

#ifdef EDQUOT
  case EDQUOT:
    cmdarg_err("Not all the packets could be written to the %s because you are "
               "too close to, or over your disk quota.",
               save_file_string);
  break;
#endif

  case WTAP_ERR_CANT_CLOSE:
    cmdarg_err("The %s couldn't be closed for some unknown reason.",
               save_file_string);
    break;

  case WTAP_ERR_SHORT_WRITE:
    cmdarg_err("Not all the packets could be written to the %s.",
               save_file_string);
    break;

  default:
    if (is_close) {
      cmdarg_err("The %s could not be closed: %s.", save_file_string,
                 wtap_strerror(err));
    } else {
      cmdarg_err("An error occurred while writing to the %s: %s.",
                 save_file_string, wtap_strerror(err));
    }
    break;
  }
  g_free(save_file_string);
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
    case COL_ABS_DATE_TIME: /* XXX - wider */
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
    cmdarg_err("Not all the packets could be printed because there is "
"no space left on the file system.");
    break;

#ifdef EDQUOT
  case EDQUOT:
    cmdarg_err("Not all the packets could be printed because you are "
"too close to, or over your disk quota.");
  break;
#endif

  default:
    cmdarg_err("An error occurred while printing packets: %s.",
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
  cf->f_datalen = 0; /* not used, but set it anyway */

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
             cf_open_error_message(*err, err_info, FALSE, cf->cd_t), fname);
  cmdarg_err("%s", err_msg);
  return CF_ERROR;
}


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
  cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
          filename, strerror(err));
}

/*
 * Report an error in command-line arguments.
 */
void
cmdarg_err(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  fprintf(stderr, "tethereal: ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

/*
 * Report additional information for an error in command-line arguments.
 */
void
cmdarg_err_cont(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}


/****************************************************************************************************************/
/* sync pipe "dummies", needed for capture_loop.c */

#ifdef HAVE_LIBPCAP

/** the child has opened a new capture file, notify the parent */
void
sync_pipe_filename_to_parent(const char *filename)
{
    /* shouldn't happen */
    g_assert(0);
}

/** the child captured some new packets, notify the parent */
void
sync_pipe_packet_count_to_parent(int packet_count)
{
    /* shouldn't happen */
    g_assert(0);
}

/** the child stopped capturing, notify the parent */
void
sync_pipe_drops_to_parent(int drops)
{
    /* shouldn't happen */
    g_assert(0);
}

/** the child encountered an error, notify the parent */
void 
sync_pipe_errmsg_to_parent(const char *errmsg)
{
    cmdarg_err(errmsg);
}

#endif /* HAVE_LIBPCAP */


/****************************************************************************************************************/
/* signal pipe "dummies", needed for capture_loop.c */

#ifdef HAVE_LIBPCAP

#ifdef _WIN32
gboolean
signal_pipe_check_running(void)
{
    /* currently, no check required */
    return TRUE;
}
#endif  /* _WIN32 */

#endif /* HAVE_LIBPCAP */


/****************************************************************************************************************/
/* simple_dialog "dummies", needed for capture_loop.c */


#ifdef HAVE_LIBPCAP

char *simple_dialog_primary_start(void)
{
    return "";
}

char *simple_dialog_primary_end(void)
{
    return "";
}


/* XXX - do we need to convert the string for the console? */
char *
simple_dialog_format_message(const char *msg)
{
    char *str;


    if (msg) {
#if GTK_MAJOR_VERSION < 2
	str = g_strdup(msg);
#else
	str = xml_escape(msg);
#endif
    } else {
	str = NULL;
    }
    return str;
}

#endif /* HAVE_LIBPCAP */


