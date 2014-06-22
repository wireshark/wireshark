/* tfshark.c
 *
 * Text-mode variant of Fileshark, based off of TShark,
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <errno.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifndef HAVE_GETOPT
#include "wsutil/wsgetopt.h"
#endif

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan-int.h>
#include <epan/epan.h>
#include <wsutil/crash_info.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_err.h>
#include <wsutil/copyright_info.h>
#include <wsutil/ws_version_info.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif
#include "file.h"
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#include "ui/util.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"
#include "register.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/timestamp.h>
#include <epan/ex-opt.h>
#include <filetap/ftap.h>
#include <wiretap/wtap-int.h>
#include <wiretap/file_wrappers.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */

#include "log.h"
#include <epan/funnel.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

/*
 * This is the template for the decode as option; it is shared between the
 * various functions that output the usage for this parameter.
 */
static const gchar decode_as_arg_template[] = "<layer_type>==<selector>,<decode_as_protocol>";

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data prev_dis_frame;
static frame_data *prev_cap;
static frame_data prev_cap_frame;

static const char* prev_display_dissector_name = NULL;

static gboolean perform_two_pass_analysis;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
  WRITE_TEXT,   /* summary or detail text */
  WRITE_XML,    /* PDML or PSML */
  WRITE_FIELDS  /* User defined list of fields */
  /* Add CSV and the like here */
} output_action_e;

static output_action_e output_action;
static gboolean do_dissection;     /* TRUE if we have to dissect each packet */
static gboolean print_packet_info; /* TRUE if we're to print packet information */
static gint print_summary = -1;    /* TRUE if we're to print packet summary information */
static gboolean print_details;     /* TRUE if we're to print packet details information */
static gboolean print_hex;         /* TRUE if we're to print hex/ascci information */
static gboolean line_buffered;
static gboolean really_quiet = FALSE;

static print_format_e print_format = PR_FMT_TEXT;
static print_stream_t *print_stream;

static output_fields_t* output_fields  = NULL;

/* The line separator used between packets, changeable via the -S option */
static const char *separator = "";

static int load_cap_file(capture_file *, int, gint64);
static gboolean process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset,
    struct wtap_pkthdr *whdr, const guchar *pd, guint tap_flags);
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
static void write_failure_message(const char *filename, int err);

capture_file cfile;

#if 0
struct string_elem {
  const char *sstr;   /* The short string */
  const char *lstr;   /* The long string */
};

static gint
string_compare(gconstpointer a, gconstpointer b)
{
  return strcmp(((const struct string_elem *)a)->sstr,
                ((const struct string_elem *)b)->sstr);
}

static void
string_elem_print(gpointer data, gpointer not_used _U_)
{
  fprintf(stderr, "    %s - %s\n",
          ((struct string_elem *)data)->sstr,
          ((struct string_elem *)data)->lstr);
}
#endif

static void
print_usage(gboolean print_ver)
{
  FILE *output;

  if (print_ver) {
    output = stdout;
    fprintf(output,
        "TFShark %s\n"
        "Dump and analyze network traffic.\n"
        "See http://www.wireshark.org for more information.\n"
        "\n"
        "%s",
        get_ws_vcs_version_info(), get_copyright_info());
  } else {
    output = stderr;
  }
  fprintf(output, "\n");
  fprintf(output, "Usage: tfshark [options] ...\n");
  fprintf(output, "\n");

  /*fprintf(output, "\n");*/
  fprintf(output, "Input file:\n");
  fprintf(output, "  -r <infile>              set the filename to read from (no pipes or stdin!)\n");

  fprintf(output, "\n");
  fprintf(output, "Processing:\n");
  fprintf(output, "  -2                       perform a two-pass analysis\n");
  fprintf(output, "  -R <read filter>         packet Read filter in Wireshark display filter syntax\n");
  fprintf(output, "  -Y <display filter>      packet displaY filter in Wireshark display filter\n");
  fprintf(output, "                           syntax\n");
  fprintf(output, "  -d %s ...\n", decode_as_arg_template);
  fprintf(output, "                           \"Decode As\", see the man page for details\n");
  fprintf(output, "                           Example: tcp.port==8888,http\n");

  /*fprintf(output, "\n");*/
  fprintf(output, "Output:\n");
  fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
  fprintf(output, "  -V                       add output of packet tree        (Packet Details)\n");
  fprintf(output, "  -O <protocols>           Only show packet details of these protocols, comma\n");
  fprintf(output, "                           separated\n");
  fprintf(output, "  -S <separator>           the line separator to print between packets\n");
  fprintf(output, "  -x                       add output of hex and ASCII dump (Packet Bytes)\n");
  fprintf(output, "  -T pdml|ps|psml|text|fields\n");
  fprintf(output, "                           format of text output (def: text)\n");
  fprintf(output, "  -e <field>               field to print if -Tfields selected (e.g. tcp.port,\n");
  fprintf(output, "                           _ws.col.Info)\n");
  fprintf(output, "                           this option can be repeated to print multiple fields\n");
  fprintf(output, "  -E<fieldsoption>=<value> set options for output when -Tfields selected:\n");
  fprintf(output, "     header=y|n            switch headers on and off\n");
  fprintf(output, "     separator=/t|/s|<char> select tab, space, printable character as separator\n");
  fprintf(output, "     occurrence=f|l|a      print first, last or all occurrences of each field\n");
  fprintf(output, "     aggregator=,|/s|<char> select comma, space, printable character as\n");
  fprintf(output, "                           aggregator\n");
  fprintf(output, "     quote=d|s|n           select double, single, no quotes for values\n");
  fprintf(output, "  -t a|ad|d|dd|e|r|u|ud    output format of time stamps (def: r: rel. to first)\n");
  fprintf(output, "  -u s|hms                 output format of seconds (def: s: seconds)\n");
  fprintf(output, "  -l                       flush standard output after each packet\n");
  fprintf(output, "  -q                       be more quiet on stdout (e.g. when using statistics)\n");
  fprintf(output, "  -Q                       only log true errors to stderr (quieter than -q)\n");
  fprintf(output, "  -X <key>:<value>         eXtension options, see the man page for details\n");
  fprintf(output, "  -z <statistics>          various statistics, see the man page for details\n");

  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h                       display this help and exit\n");
  fprintf(output, "  -v                       display version info and exit\n");
  fprintf(output, "  -o <name>:<value> ...    override preference setting\n");
  fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
  fprintf(output, "  -G [report]              dump one of several available reports and exit\n");
  fprintf(output, "                           default report=\"fields\"\n");
  fprintf(output, "                           use \"-G ?\" for more help\n");
}

static void
glossary_option_help(void)
{
  FILE *output;

  output = stdout;

  fprintf(output, "TFShark %s\n", get_ws_vcs_version_info());

  fprintf(output, "\n");
  fprintf(output, "Usage: tfshark -G [report]\n");
  fprintf(output, "\n");
  fprintf(output, "Glossary table reports:\n");
  fprintf(output, "  -G column-formats        dump column format codes and exit\n");
  fprintf(output, "  -G decodes               dump \"layer type\"/\"decode as\" associations and exit\n");
  fprintf(output, "  -G fields                dump fields glossary and exit\n");
  fprintf(output, "  -G ftypes                dump field type basic and descriptive names\n");
  fprintf(output, "  -G heuristic-decodes     dump heuristic dissector tables\n");
  fprintf(output, "  -G plugins               dump installed plugins and exit\n");
  fprintf(output, "  -G protocols             dump protocols in registration database and exit\n");
  fprintf(output, "  -G values                dump value, range, true/false strings and exit\n");
  fprintf(output, "\n");
  fprintf(output, "Preference reports:\n");
  fprintf(output, "  -G currentprefs          dump current preferences and exit\n");
  fprintf(output, "  -G defaultprefs          dump default preferences and exit\n");
  fprintf(output, "\n");
}

/*
 * For a dissector table, print on the stream described by output,
 * its short name (which is what's used in the "-d" option) and its
 * descriptive name.
 */
static void
display_dissector_table_names(const char *table_name, const char *ui_name,
                              gpointer output)
{
  if ((prev_display_dissector_name == NULL) ||
      (strcmp(prev_display_dissector_name, table_name) != 0)) {
     fprintf((FILE *)output, "\t%s (%s)\n", table_name, ui_name);
     prev_display_dissector_name = table_name;
  }
}

/*
 * For a dissector handle, print on the stream described by output,
 * the filter name (which is what's used in the "-d" option) and the full
 * name for the protocol that corresponds to this handle.
 */
static void
display_dissector_names(const gchar *table _U_, gpointer handle, gpointer output)
{
  int          proto_id;
  const gchar *proto_filter_name;
  const gchar *proto_ui_name;

  proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);

  if (proto_id != -1) {
    proto_filter_name = proto_get_protocol_filter_name(proto_id);
    proto_ui_name =  proto_get_protocol_name(proto_id);
    g_assert(proto_filter_name != NULL);
    g_assert(proto_ui_name != NULL);

    if ((prev_display_dissector_name == NULL) ||
        (strcmp(prev_display_dissector_name, proto_filter_name) != 0)) {
      fprintf((FILE *)output, "\t%s (%s)\n",
              proto_filter_name,
              proto_ui_name);
       prev_display_dissector_name = proto_filter_name;
    }
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
  int                     proto_id;
  const gchar            *protocol_filter_name;
  protocol_name_search_t  search_info;

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
 * Allow dissector key names to be sorted alphabetically
 */

static gint
compare_dissector_key_name(gconstpointer dissector_a, gconstpointer dissector_b)
{
  return strcmp((const char*)dissector_a, (const char*)dissector_b);
}

/*
 * Print all layer type names supported.
 * We send the output to the stream described by the handle output.
 */

static void
fprint_all_layer_types(FILE *output)

{
  prev_display_dissector_name = NULL;
  dissector_all_tables_foreach_table(display_dissector_table_names, (gpointer)output, (GCompareFunc)compare_dissector_key_name);
}

/*
 * Print all protocol names supported for a specific layer type.
 * table_name contains the layer type name in which the search is performed.
 * We send the output to the stream described by the handle output.
 */

static void
fprint_all_protocols_for_layer_types(FILE *output, gchar *table_name)

{
  prev_display_dissector_name = NULL;
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
  guint32                       selector, selector2;
  gchar                        *decoded_param;
  gchar                        *remaining_param;
  gchar                        *selector_str;
  gchar                        *dissector_str;
  dissector_handle_t            dissector_matching;
  dissector_table_t             table_matching;
  ftenum_t                      dissector_table_selector_type;
  struct protocol_name_search   user_protocol_name;
  guint64                       i;
  char                          op;

  /* The following code will allocate and copy the command-line options in a string pointed by decoded_param */

  g_assert(cl_param);
  decoded_param = g_strdup(cl_param);
  g_assert(decoded_param);


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
    switch (sscanf(selector_str, "%u%c%u", &selector, &op, &selector2)) {
      case 1:
        op = '\0';
        break;
      case 3:
        if (op != ':' && op != '-') {
            cmdarg_err("Invalid selector numeric range \"%s\"", selector_str);
            g_free(decoded_param);
            return FALSE;
        }
        if (op == ':') {
            if ((selector2 == 0) || ((guint64)selector + selector2 - 1) > G_MAXUINT32) {
                cmdarg_err("Invalid selector numeric range \"%s\"", selector_str);
                g_free(decoded_param);
                return FALSE;
            }
        }
        else if (selector2 < selector) {
            /* We could swap them for the user, but maybe it's better to call
             * this out as an error in case it's not what was intended? */
            cmdarg_err("Invalid selector numeric range \"%s\"", selector_str);
            g_free(decoded_param);
            return FALSE;
        }
        break;
      default:
        cmdarg_err("Invalid selector number \"%s\"", selector_str);
        g_free(decoded_param);
        return FALSE;
    }
    break;

  case FT_STRING:
  case FT_STRINGZ:
  case FT_UINT_STRING:
  case FT_STRINGZPAD:
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
    if (op == '\0') {
      dissector_change_uint(table_name, selector, dissector_matching);
    } else if (op == ':') {
      for (i = selector; i < (guint64)selector + selector2; i++) {
        dissector_change_uint(table_name, (guint32)i, dissector_matching);
      }
    } else { /* op == '-' */
      for (i = selector; i <= selector2; i++) {
        dissector_change_uint(table_name, (guint32)i, dissector_matching);
      }
    }
    break;

  case FT_STRING:
  case FT_STRINGZ:
  case FT_UINT_STRING:
  case FT_STRINGZPAD:
    /* The selector for this table is a string. */
    dissector_change_string(table_name, selector_str, dissector_matching);
    break;

  default:
    /* There are currently no dissector tables with any types other
       than the ones listed above. */
    g_assert_not_reached();
  }
  g_free(decoded_param); /* "Decode As" rule has been successfully added */
  return TRUE;
}

static void
tfshark_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
    const gchar *message, gpointer user_data)
{
  /* ignore log message, if log_level isn't interesting based
     upon the console log preferences.
     If the preferences haven't been loaded loaded yet, display the
     message anyway.

     The default console_log_level preference value is such that only
       ERROR, CRITICAL and WARNING level messages are processed;
       MESSAGE, INFO and DEBUG level messages are ignored.

     XXX: Aug 07, 2009: Prior tshark g_log code was hardwired to process only
           ERROR and CRITICAL level messages so the current code is a behavioral
           change.  The current behavior is the same as in Wireshark.
  */
  if ((log_level & G_LOG_LEVEL_MASK & prefs.console_log_level) == 0 &&
     prefs.console_log_level != 0) {
    return;
  }

  g_log_default_handler(log_domain, log_level, message, user_data);

}

static void
print_current_user(void) {
  gchar *cur_user, *cur_group;

  if (started_with_special_privs()) {
    cur_user = get_cur_username();
    cur_group = get_cur_groupname();
    fprintf(stderr, "Running as user \"%s\" and group \"%s\".",
      cur_user, cur_group);
    g_free(cur_user);
    g_free(cur_group);
    if (running_with_special_privs()) {
      fprintf(stderr, " This could be dangerous.");
    }
    fprintf(stderr, "\n");
  }
}

static void
show_version(GString *comp_info_str, GString *runtime_info_str)
{
  printf("TFShark %s\n"
         "\n"
         "%s"
         "\n"
         "%s"
         "\n"
         "%s",
         get_ws_vcs_version_info(), get_copyright_info(), comp_info_str->str,
         runtime_info_str->str);
}

int
main(int argc, char *argv[])
{
  GString             *comp_info_str;
  GString             *runtime_info_str;
  char                *init_progfile_dir_error;
  int                  opt;
  gboolean             arg_error = FALSE;

  char                *gpf_path, *pf_path;
  char                *gdp_path, *dp_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  int                  err;
  volatile int         exit_status = 0;
  gboolean             quiet = FALSE;
  gchar               *volatile cf_name = NULL;
  gchar               *rfilter = NULL;
  gchar               *dfilter = NULL;
  dfilter_t           *rfcode = NULL;
  dfilter_t           *dfcode = NULL;
  e_prefs             *prefs_p;
  int                  log_flags;
  int                  optind_initial;
  gchar               *output_only = NULL;

/* the leading - ensures that getopt() does not permute the argv[] entries
   we have to make sure that the first getopt() preserves the content of argv[]
   for the subsequent getopt_long() call */
#define OPTSTRING "-2C:d:e:E:hK:lo:O:qQr:R:S:t:T:u:vVxX:Y:z:"

  static const char    optstring[] = OPTSTRING;

  /* Assemble the compile-time version information string */
  comp_info_str = g_string_new("Compiled ");
  get_compiled_version_info(comp_info_str, NULL, epan_get_compiled_version_info);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str, NULL);

  /* Add it to the information to be reported on a crash. */
  ws_add_crash_info("TFShark %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);

#ifdef _WIN32
  arg_list_utf_16to8(argc, argv);
  create_app_running_mutex();
#if !GLIB_CHECK_VERSION(2,31,0)
  g_thread_init(NULL);
#endif
#endif /* _WIN32 */

  /*
   * Get credential information for later use.
   */
  init_process_policies();

  /*
   * Attempt to get the pathname of the executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0], main);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr, "tfshark: Can't get pathname of tfshark program: %s.\n",
            init_progfile_dir_error);
  }

  /*
   * In order to have the -X opts assigned before the wslua machine starts
   * we need to call getopts before epan_init() gets called.
   */
  opterr = 0;
  optind_initial = optind;

  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
    case 'C':        /* Configuration Profile */
      if (profile_exists (optarg, FALSE)) {
        set_profile_name (optarg);
      } else {
        cmdarg_err("Configuration Profile \"%s\" does not exist", optarg);
        return 1;
      }
      break;
    case 'O':        /* Only output these protocols */
      output_only = g_strdup(optarg);
      /* FALLTHROUGH */
    case 'V':        /* Verbose */
      print_details = TRUE;
      print_packet_info = TRUE;
      break;
    case 'x':        /* Print packet data in hex (and ASCII) */
      print_hex = TRUE;
      /*  The user asked for hex output, so let's ensure they get it,
       *  even if they're writing to a file.
       */
      print_packet_info = TRUE;
      break;
    case 'X':
      ex_opt_add(optarg);
      break;
    default:
      break;
    }
  }

  /*
   * Print packet summary information is the default, unless either -V or -x
   * were specified.  Note that this is new behavior, which
   * allows for the possibility of printing only hex/ascii output without
   * necessarily requiring that either the summary or details be printed too.
   */
  if (print_summary == -1)
    print_summary = (print_details || print_hex) ? FALSE : TRUE;

  optind = optind_initial;
  opterr = 1;



/** Send All g_log messages to our own handler **/

  log_flags =
                    G_LOG_LEVEL_ERROR|
                    G_LOG_LEVEL_CRITICAL|
                    G_LOG_LEVEL_WARNING|
                    G_LOG_LEVEL_MESSAGE|
                    G_LOG_LEVEL_INFO|
                    G_LOG_LEVEL_DEBUG|
                    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION;

  g_log_set_handler(NULL,
                    (GLogLevelFlags)log_flags,
                    tfshark_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_MAIN,
                    (GLogLevelFlags)log_flags,
                    tfshark_log_handler, NULL /* user_data */);

  initialize_funnel_ops();

  init_report_err(failure_message, open_failure_message, read_failure_message,
                  write_failure_message);

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

  init_open_routines();

#ifdef HAVE_PLUGINS
  /* Register all the plugin types we have. */
  epan_register_plugin_types(); /* Types known to libwireshark */
  ftap_register_plugin_types(); /* Types known to libfiletap */

  /* Scan for plugins.  This does *not* call their registration routines;
     that's done later. */
  scan_plugins();

  /* Register all libfiletap plugin modules. */
  register_all_filetap_modules();

#endif

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);

  /* Register all tap listeners; we do this before we parse the arguments,
     as the "-z" argument can specify a registered tap. */

  /* we register the plugin taps before the other taps because
     stats_tree taps plugins will be registered as tap listeners
     by stats_tree_stat.c and need to registered before that */

  /* XXX Disable tap registration for now until we can get tfshark set up with
   * its own set of taps and the necessary registration function etc.
#ifdef HAVE_PLUGINS
  register_all_plugin_tap_listeners();
#endif
  register_all_tap_listeners();
  */

  /* If invoked with the "-G" flag, we dump out information based on
     the argument to the "-G" flag; if no argument is specified,
     for backwards compatibility we dump out a glossary of display
     filter symbols.

     XXX - we do this here, for now, to support "-G" with no arguments.
     If none of our build or other processes uses "-G" with no arguments,
     we can just process it with the other arguments. */
  if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
    proto_initialize_all_prefixes();

    if (argc == 2)
      proto_registrar_dump_fields();
    else {
      if (strcmp(argv[2], "column-formats") == 0)
        column_dump_column_formats();
      else if (strcmp(argv[2], "currentprefs") == 0) {
        read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
            &pf_open_errno, &pf_read_errno, &pf_path);
        write_prefs(NULL);
      }
      else if (strcmp(argv[2], "decodes") == 0)
        dissector_dump_decodes();
      else if (strcmp(argv[2], "defaultprefs") == 0)
        write_prefs(NULL);
      else if (strcmp(argv[2], "fields") == 0)
        proto_registrar_dump_fields();
      else if (strcmp(argv[2], "ftypes") == 0)
        proto_registrar_dump_ftypes();
      else if (strcmp(argv[2], "heuristic-decodes") == 0)
        dissector_dump_heur_decodes();
      else if (strcmp(argv[2], "plugins") == 0) {
#ifdef HAVE_PLUGINS
        plugins_dump_all();
#endif
#ifdef HAVE_LUA
        wslua_plugins_dump_all();
#endif
      }
      else if (strcmp(argv[2], "protocols") == 0)
        proto_registrar_dump_protocols();
      else if (strcmp(argv[2], "values") == 0)
        proto_registrar_dump_values();
      else if (strcmp(argv[2], "?") == 0)
        glossary_option_help();
      else if (strcmp(argv[2], "-?") == 0)
        glossary_option_help();
      else {
        cmdarg_err("Invalid \"%s\" option for -G flag, enter -G ? for more help.", argv[2]);
        return 1;
      }
    }
    return 0;
  }

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);
  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      cmdarg_err("Can't open global preferences file \"%s\": %s.",
              pf_path, g_strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      cmdarg_err("I/O error reading global preferences file \"%s\": %s.",
              pf_path, g_strerror(gpf_read_errno));
    }
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      cmdarg_err("Can't open your preferences file \"%s\": %s.", pf_path,
              g_strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      cmdarg_err("I/O error reading your preferences file \"%s\": %s.",
              pf_path, g_strerror(pf_read_errno));
    }
    g_free(pf_path);
    pf_path = NULL;
  }

  /* Read the disabled protocols file. */
  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                            &dp_path, &dp_open_errno, &dp_read_errno);
  if (gdp_path != NULL) {
    if (gdp_open_errno != 0) {
      cmdarg_err("Could not open global disabled protocols file\n\"%s\": %s.",
                 gdp_path, g_strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      cmdarg_err("I/O error reading global disabled protocols file\n\"%s\": %s.",
                 gdp_path, g_strerror(gdp_read_errno));
    }
    g_free(gdp_path);
  }
  if (dp_path != NULL) {
    if (dp_open_errno != 0) {
      cmdarg_err(
        "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
        g_strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      cmdarg_err(
        "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
        g_strerror(dp_read_errno));
    }
    g_free(dp_path);
  }

  cap_file_init(&cfile);

  /* Print format defaults to this. */
  print_format = PR_FMT_TEXT;

  output_fields = output_fields_new();

  /* Now get our args */
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
    case '2':        /* Perform two pass analysis */
      perform_two_pass_analysis = TRUE;
      break;
    case 'C':
      /* Configuration profile settings were already processed just ignore them this time*/
      break;
    case 'd':        /* Decode as rule */
      if (!add_decode_as(optarg))
        return 1;
      break;
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
    case 'K':        /* Kerberos keytab file */
      read_keytab_file(optarg);
      break;
#endif
    case 'e':
      /* Field entry */
      output_fields_add(output_fields, optarg);
      break;
    case 'E':
      /* Field option */
      if (!output_fields_set_option(output_fields, optarg)) {
        cmdarg_err("\"%s\" is not a valid field output option=value pair.", optarg);
        output_fields_list_options(stderr);
        return 1;
      }
      break;

    case 'h':        /* Print help and exit */
      print_usage(TRUE);
      return 0;
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
    case 'o':        /* Override preference from command line */
      switch (prefs_set_pref(optarg)) {

      case PREFS_SET_OK:
        break;

      case PREFS_SET_SYNTAX_ERR:
        cmdarg_err("Invalid -o flag \"%s\"", optarg);
        return 1;
        break;

      case PREFS_SET_NO_SUCH_PREF:
      case PREFS_SET_OBSOLETE:
        cmdarg_err("-o flag \"%s\" specifies unknown preference", optarg);
        return 1;
        break;
      }
      break;
    case 'q':        /* Quiet */
      quiet = TRUE;
      break;
    case 'Q':        /* Really quiet */
      quiet = TRUE;
      really_quiet = TRUE;
      break;
    case 'r':        /* Read capture file x */
      cf_name = g_strdup(optarg);
      break;
    case 'R':        /* Read file filter */
      rfilter = optarg;
      break;
    case 'S':        /* Set the line Separator to be printed between packets */
      separator = strdup(optarg);
      break;
    case 't':        /* Time stamp type */
      if (strcmp(optarg, "r") == 0)
        timestamp_set_type(TS_RELATIVE);
      else if (strcmp(optarg, "a") == 0)
        timestamp_set_type(TS_ABSOLUTE);
      else if (strcmp(optarg, "ad") == 0)
        timestamp_set_type(TS_ABSOLUTE_WITH_YMD);
      else if (strcmp(optarg, "adoy") == 0)
        timestamp_set_type(TS_ABSOLUTE_WITH_YDOY);
      else if (strcmp(optarg, "d") == 0)
        timestamp_set_type(TS_DELTA);
      else if (strcmp(optarg, "dd") == 0)
        timestamp_set_type(TS_DELTA_DIS);
      else if (strcmp(optarg, "e") == 0)
        timestamp_set_type(TS_EPOCH);
      else if (strcmp(optarg, "u") == 0)
        timestamp_set_type(TS_UTC);
      else if (strcmp(optarg, "ud") == 0)
        timestamp_set_type(TS_UTC_WITH_YMD);
      else if (strcmp(optarg, "udoy") == 0)
        timestamp_set_type(TS_UTC_WITH_YDOY);
      else {
        cmdarg_err("Invalid time stamp type \"%s\"; it must be one of:", optarg);
        cmdarg_err_cont("\t\"a\"    for absolute\n"
                        "\t\"ad\"   for absolute with YYYY-MM-DD date\n"
                        "\t\"adoy\" for absolute with YYYY/DOY date\n"
                        "\t\"d\"    for delta\n"
                        "\t\"dd\"   for delta displayed\n"
                        "\t\"e\"    for epoch\n"
                        "\t\"r\"    for relative\n"
                        "\t\"u\"    for absolute UTC\n"
                        "\t\"ud\"   for absolute UTC with YYYY-MM-DD date\n"
                        "\t\"udoy\" for absolute UTC with YYYY/DOY date");
        return 1;
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
        print_details = TRUE;   /* Need details */
        print_summary = FALSE;  /* Don't allow summary */
      } else if (strcmp(optarg, "psml") == 0) {
        output_action = WRITE_XML;
        print_details = FALSE;  /* Don't allow details */
        print_summary = TRUE;   /* Need summary */
      } else if (strcmp(optarg, "fields") == 0) {
        output_action = WRITE_FIELDS;
        print_details = TRUE;   /* Need full tree info */
        print_summary = FALSE;  /* Don't allow summary */
      } else {
        cmdarg_err("Invalid -T parameter \"%s\"; it must be one of:", optarg);                   /* x */
        cmdarg_err_cont("\t\"fields\" The values of fields specified with the -e option, in a form\n"
                        "\t         specified by the -E option.\n"
                        "\t\"pdml\"   Packet Details Markup Language, an XML-based format for the\n"
                        "\t         details of a decoded packet. This information is equivalent to\n"
                        "\t         the packet details printed with the -V flag.\n"
                        "\t\"ps\"     PostScript for a human-readable one-line summary of each of\n"
                        "\t         the packets, or a multi-line view of the details of each of\n"
                        "\t         the packets, depending on whether the -V flag was specified.\n"
                        "\t\"psml\"   Packet Summary Markup Language, an XML-based format for the\n"
                        "\t         summary information of a decoded packet. This information is\n"
                        "\t         equivalent to the information shown in the one-line summary\n"
                        "\t         printed by default.\n"
                        "\t\"text\"   Text of a human-readable one-line summary of each of the\n"
                        "\t         packets, or a multi-line view of the details of each of the\n"
                        "\t         packets, depending on whether the -V flag was specified.\n"
                        "\t         This is the default.");
        return 1;
      }
      break;
    case 'u':        /* Seconds type */
      if (strcmp(optarg, "s") == 0)
        timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
      else if (strcmp(optarg, "hms") == 0)
        timestamp_set_seconds_type(TS_SECONDS_HOUR_MIN_SEC);
      else {
        cmdarg_err("Invalid seconds type \"%s\"; it must be one of:", optarg);
        cmdarg_err_cont("\t\"s\"   for seconds\n"
                        "\t\"hms\" for hours, minutes and seconds");
        return 1;
      }
      break;
    case 'v':         /* Show version and exit */
    {
      show_version(comp_info_str, runtime_info_str);
      g_string_free(comp_info_str, TRUE);
      g_string_free(runtime_info_str, TRUE);
      /* We don't really have to cleanup here, but it's a convenient way to test
       * start-up and shut-down of the epan library without any UI-specific
       * cruft getting in the way. Makes the results of running
       * $ ./tools/valgrind-wireshark -n
       * much more useful. */
      epan_cleanup();
      return 0;
    }
    case 'O':        /* Only output these protocols */
      /* already processed; just ignore it now */
      break;
    case 'V':        /* Verbose */
      /* already processed; just ignore it now */
      break;
    case 'x':        /* Print packet data in hex (and ASCII) */
      /* already processed; just ignore it now */
      break;
    case 'X':
      break;
    case 'Y':
      dfilter = optarg;
      break;
    case 'z':
      /* We won't call the init function for the stat this soon
         as it would disallow MATE's fields (which are registered
         by the preferences set callback) from being used as
         part of a tap filter.  Instead, we just add the argument
         to a list of stat arguments. */
      if (!process_stat_cmd_arg(optarg)) {
        if (strcmp("help", optarg)==0) {
          fprintf(stderr, "tfshark: The available statistics for the \"-z\" option are:\n");
          list_stat_cmd_args();
          return 0;
        }
        cmdarg_err("Invalid -z argument \"%s\"; it must be one of:", optarg);
        list_stat_cmd_args();
        return 1;
      }
      break;
    default:
    case '?':        /* Bad flag - print usage message */
      print_usage(TRUE);
      return 1;
      break;
    }
  }

  /* If we specified output fields, but not the output field type... */
  if (WRITE_FIELDS != output_action && 0 != output_fields_num_fields(output_fields)) {
        cmdarg_err("Output fields were specified with \"-e\", "
            "but \"-Tfields\" was not specified.");
        return 1;
  } else if (WRITE_FIELDS == output_action && 0 == output_fields_num_fields(output_fields)) {
        cmdarg_err("\"-Tfields\" was specified, but no fields were "
                    "specified with \"-e\".");

        return 1;
  }

  /* If no capture filter or display filter has been specified, and there are
     still command-line arguments, treat them as the tokens of a capture
     filter (if no "-r" flag was specified) or a display filter (if a "-r"
     flag was specified. */
  if (optind < argc) {
    if (cf_name != NULL) {
      if (dfilter != NULL) {
        cmdarg_err("Display filters were specified both with \"-d\" "
            "and with additional command-line arguments.");
        return 1;
      }
      dfilter = get_args_as_string(argc, argv, optind);
    }
  }

  /* if "-q" wasn't specified, we should print packet information */
  if (!quiet)
    print_packet_info = TRUE;

  if (arg_error) {
    print_usage(FALSE);
    return 1;
  }

  if (print_hex) {
    if (output_action != WRITE_TEXT) {
      cmdarg_err("Raw packet hex data can only be printed as text or PostScript");
      return 1;
    }
  }

  if (output_only != NULL) {
    char *ps;

    if (!print_details) {
      cmdarg_err("-O requires -V");
      return 1;
    }

    output_only_tables = g_hash_table_new (g_str_hash, g_str_equal);
    for (ps = strtok (output_only, ","); ps; ps = strtok (NULL, ",")) {
      g_hash_table_insert(output_only_tables, (gpointer)ps, (gpointer)ps);
    }
  }

  if (rfilter != NULL && !perform_two_pass_analysis) {
    cmdarg_err("-R without -2 is deprecated. For single-pass filtering use -Y.");
    return 1;
  }

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
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

  if (rfilter != NULL) {
    if (!dfilter_compile(rfilter, &rfcode)) {
      cmdarg_err("%s", dfilter_error_msg);
      epan_cleanup();
      return 2;
    }
  }
  cfile.rfcode = rfcode;

  if (dfilter != NULL) {
    if (!dfilter_compile(dfilter, &dfcode)) {
      cmdarg_err("%s", dfilter_error_msg);
      epan_cleanup();
      return 2;
    }
  }
  cfile.dfcode = dfcode;

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

        we're using a display filter on the packets;

        we're using any taps that need dissection. */
  do_dissection = print_packet_info || rfcode || dfcode || tap_listeners_require_dissection();

  if (cf_name) {
    /*
     * We're reading a capture file.
     */

    /*
     * Immediately relinquish any special privileges we have; we must not
     * be allowed to read any capture files the user running TShark
     * can't open.
     */
    relinquish_special_privs_perm();
    print_current_user();

    /* TODO: if tfshark is ever changed to give the user a choice of which
       open_routine reader to use, then the following needs to change. */
    if (cf_open(&cfile, cf_name, WTAP_TYPE_AUTO, FALSE, &err) != CF_OK) {
      epan_cleanup();
      return 2;
    }

    /* Process the packets in the file */
    TRY {
      /* XXX - for now there is only 1 packet */
      err = load_cap_file(&cfile, 1, 0);
    }
    CATCH(OutOfMemoryError) {
      fprintf(stderr,
              "Out Of Memory!\n"
              "\n"
              "Sorry, but TFShark has to terminate now!\n"
              "\n"
              "Some infos / workarounds can be found at:\n"
              "http://wiki.wireshark.org/KnownBugs/OutOfMemory\n");
      err = ENOMEM;
    }
    ENDTRY;

    if (err != 0) {
      /* We still dump out the results of taps, etc., as we might have
         read some packets; however, we exit with an error status. */
      exit_status = 2;
    }
  }

  g_free(cf_name);

  if (cfile.frames != NULL) {
    free_frame_data_sequence(cfile.frames);
    cfile.frames = NULL;
  }

  draw_tap_listeners(TRUE);
  funnel_dump_all_text_windows();
  epan_free(cfile.epan);
  epan_cleanup();

  output_fields_free(output_fields);
  output_fields = NULL;

  return exit_status;
}

static const nstime_t *
tfshark_get_frame_ts(void *data, guint32 frame_num)
{
  capture_file *cf = (capture_file *) data;

  if (ref && ref->num == frame_num)
    return &ref->abs_ts;

  if (prev_dis && prev_dis->num == frame_num)
    return &prev_dis->abs_ts;

  if (prev_cap && prev_cap->num == frame_num)
    return &prev_cap->abs_ts;

  if (cf->frames) {
     frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static const char *
no_interface_name(void *data _U_, guint32 interface_id _U_)
{
    return "";
}

static epan_t *
tfshark_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = tfshark_get_frame_ts;
  epan->get_interface_name = no_interface_name;
  epan->get_user_comment = NULL;

  return epan;
}

static gboolean
process_packet_first_pass(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, struct wtap_pkthdr *whdr,
               const guchar *pd)
{
  frame_data     fdlocal;
  guint32        framenum;
  gboolean       passed;

  /* The frame number of this packet is one more than the count of
     frames in this packet. */
  framenum = cf->count + 1;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  frame_data_init(&fdlocal, framenum, whdr, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or display filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt) {
    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_dfilter(edt, cf->rfcode);

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == &fdlocal) {
      ref_frame = fdlocal;
      ref = &ref_frame;
    }

    epan_dissect_file_run(edt, whdr, file_tvbuff_new(&fdlocal, pd), &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    prev_cap = prev_dis = frame_data_sequence_add(cf->frames, &fdlocal);

    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     */
    if (edt) {
      g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->frames);
    }

    cf->count++;
  } else {
    /* if we don't add it to the frame_data_sequence, clean it up right now
     * to avoid leaks */
    frame_data_destroy(&fdlocal);
  }

  if (edt)
    epan_dissect_reset(edt);

  return passed;
}

static gboolean
process_packet_second_pass(capture_file *cf, epan_dissect_t *edt, frame_data *fdata,
               struct wtap_pkthdr *phdr, Buffer *buf,
               guint tap_flags)
{
  column_info    *cinfo;
  gboolean        passed;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  /* If we're going to print packet information, or we're going to
     run a read filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt) {

    /* If we're running a display filter, prime the epan_dissect_t with that
       filter. */
    if (cf->dfcode)
      epan_dissect_prime_dfilter(edt, cf->dfcode);

    col_custom_prime_edt(edt, &cf->cinfo);

    /* We only need the columns if either
         1) some tap needs the columns
       or
         2) we're printing packet info but we're *not* verbose; in verbose
            mode, we print the protocol tree, not the protocol summary.
     */
    if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary))
      cinfo = &cf->cinfo;
    else
      cinfo = NULL;

    frame_data_set_before_dissect(fdata, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == fdata) {
      ref_frame = *fdata;
      ref = &ref_frame;
    }

    epan_dissect_file_run_with_taps(edt, phdr, file_tvbuff_new_buffer(fdata, buf), fdata, cinfo);

    /* Run the read/display filter if we have one. */
    if (cf->dfcode)
      passed = dfilter_apply_edt(cf->dfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(fdata, &cum_bytes);
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
         tcpdump or TShark is to allow the output of a live capture to
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
    prev_dis = fdata;
  }
  prev_cap = fdata;

  if (edt) {
    epan_dissect_reset(edt);
  }
  return passed || fdata->flags.dependent_of_displayed;
}

gboolean
local_wtap_read(capture_file *cf, struct wtap_pkthdr* file_phdr, int *err, gchar **err_info, gint64 *data_offset _U_, guint8** data_buffer)
{
    int bytes_read;
    gint64 packet_size = wtap_file_size(cf->wth, err);

    *data_buffer = (guint8*)g_malloc((gsize)packet_size);
    bytes_read = file_read(*data_buffer, (unsigned int)packet_size, cf->wth->fh);

    if (bytes_read < 0) {
        *err = file_error(cf->wth->fh, err_info);
        if (*err == 0)
            *err = FTAP_ERR_SHORT_READ;
        return FALSE;
    } else if (bytes_read == 0) {
        /* Done with file, no error */
        return FALSE;
    }


    /* XXX - SET FRAME SIZE EQUAL TO TOTAL FILE SIZE */
    file_phdr->caplen = (guint32)packet_size;
    file_phdr->len = (guint32)packet_size;

#if 0
    /*
     * Set the packet encapsulation to the file's encapsulation
     * value; if that's not WTAP_ENCAP_PER_PACKET, it's the
     * right answer (and means that the read routine for this
     * capture file type doesn't have to set it), and if it
     * *is* WTAP_ENCAP_PER_PACKET, the caller needs to set it
     * anyway.
     */
    wth->phdr.pkt_encap = wth->file_encap;

    if (!wth->subtype_read(wth, err, err_info, data_offset)) {
        /*
         * If we didn't get an error indication, we read
         * the last packet.  See if there's any deferred
         * error, as might, for example, occur if we're
         * reading a compressed file, and we got an error
         * reading compressed data from the file, but
         * got enough compressed data to decompress the
         * last packet of the file.
         */
        if (*err == 0)
            *err = file_error(wth->fh, err_info);
        return FALSE;    /* failure */
    }

    /*
     * It makes no sense for the captured data length to be bigger
     * than the actual data length.
     */
    if (wth->phdr.caplen > wth->phdr.len)
        wth->phdr.caplen = wth->phdr.len;

    /*
     * Make sure that it's not WTAP_ENCAP_PER_PACKET, as that
     * probably means the file has that encapsulation type
     * but the read routine didn't set this packet's
     * encapsulation type.
     */
    g_assert(wth->phdr.pkt_encap != WTAP_ENCAP_PER_PACKET);
#endif

    return TRUE; /* success */
}

static int
load_cap_file(capture_file *cf, int max_packet_count, gint64 max_byte_count)
{
  guint32      framenum;
  int          err;
  gchar       *err_info = NULL;
  gint64       data_offset = 0;
  gboolean     filtering_tap_listeners;
  guint        tap_flags;
  Buffer       buf;
  epan_dissect_t *edt = NULL;
  struct wtap_pkthdr file_phdr;
  guint8* raw_data;

  if (print_packet_info) {
    if (!write_preamble(cf)) {
      err = errno;
      show_print_file_io_error(err);
      goto out;
    }
  }

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  memset(&file_phdr, 0, sizeof(file_phdr));

  /* XXX - TEMPORARY HACK TO ELF DISSECTOR */
  file_phdr.pkt_encap = 1234;

  if (perform_two_pass_analysis) {
    frame_data *fdata;

    /* Allocate a frame_data_sequence for all the frames. */
    cf->frames = new_frame_data_sequence();

    if (do_dissection) {
       gboolean create_proto_tree = FALSE;

      /* If we're going to be applying a filter, we'll need to
         create a protocol tree against which to apply the filter. */
      if (cf->rfcode)
        create_proto_tree = TRUE;

      /* We're not going to display the protocol tree on this pass,
         so it's not going to be "visible". */
      edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
    }
    while (local_wtap_read(cf, &file_phdr, &err, &err_info, &data_offset, &raw_data)) {
      if (process_packet_first_pass(cf, edt, data_offset, &file_phdr/*wtap_phdr(cf->wth)*/,
                         wtap_buf_ptr(cf->wth))) {

        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
          err = 0; /* This is not an error */
          break;
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

#if 0
    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->wth);
#endif

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    prev_dis = NULL;
    prev_cap = NULL;
    buffer_init(&buf, 1500);

    if (do_dissection) {
      gboolean create_proto_tree;

      if (cf->dfcode || print_details || filtering_tap_listeners ||
         (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
           create_proto_tree = TRUE;
      else
           create_proto_tree = FALSE;

      /* The protocol tree will be "visible", i.e., printed, only if we're
         printing packet details, which is true if we're printing stuff
         ("print_packet_info" is true) and we're in verbose mode
         ("packet_details" is true). */
      edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
    }

    for (framenum = 1; err == 0 && framenum <= cf->count; framenum++) {
      fdata = frame_data_sequence_find(cf->frames, framenum);
#if 0
      if (wtap_seek_read(cf->wth, fdata->file_off,
          &buf, fdata->cap_len, &err, &err_info)) {
        process_packet_second_pass(cf, edt, fdata, &cf->phdr, &buf, tap_flags);
      }
#else
        process_packet_second_pass(cf, edt, fdata, &cf->phdr, &buf, tap_flags);
#endif
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    buffer_free(&buf);
  }
  else {
    framenum = 0;

    if (do_dissection) {
      gboolean create_proto_tree;

      if (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
          (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
        create_proto_tree = TRUE;
      else
        create_proto_tree = FALSE;

      /* The protocol tree will be "visible", i.e., printed, only if we're
         printing packet details, which is true if we're printing stuff
         ("print_packet_info" is true) and we're in verbose mode
         ("packet_details" is true). */
      edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
    }

    while (local_wtap_read(cf, &file_phdr, &err, &err_info, &data_offset, &raw_data)) {

      framenum++;

      process_packet(cf, edt, data_offset, &file_phdr/*wtap_phdr(cf->wth)*/,
                             raw_data, tap_flags);

        /* Stop reading if we have the maximum number of packets;
        * When the -c option has not been used, max_packet_count
        * starts at 0, which practically means, never stop reading.
        * (unless we roll over max_packet_count ?)
        */
        if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
            err = 0; /* This is not an error */
            break;
        }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }
  }

  if (err != 0) {
    /*
     * Print a message noting that the read failed somewhere along the line.
     *
     * If we're printing packet data, and the standard output and error are
     * going to the same place, flush the standard output, so everything
     * buffered up is written, and then print a newline to the standard error
     * before printing the error message, to separate it from the packet
     * data.  (Alas, that only works on UN*X; st_dev is meaningless, and
     * the _fstat() documentation at Microsoft doesn't indicate whether
     * st_ino is even supported.)
     */
#ifndef _WIN32
    if (print_packet_info) {
      struct stat stat_stdout, stat_stderr;

      if (fstat(1, &stat_stdout) == 0 && fstat(2, &stat_stderr) == 0) {
        if (stat_stdout.st_dev == stat_stderr.st_dev &&
            stat_stdout.st_ino == stat_stderr.st_ino) {
          fflush(stdout);
          fprintf(stderr, "\n");
        }
      }
    }
#endif
    switch (err) {

    case FTAP_ERR_UNSUPPORTED:
      cmdarg_err("The file \"%s\" contains record data that TFShark doesn't support.\n(%s)",
                 cf->filename, err_info);
      g_free(err_info);
      break;

    case FTAP_ERR_UNSUPPORTED_ENCAP:
      cmdarg_err("The file \"%s\" has a packet with a network type that TFShark doesn't support.\n(%s)",
                 cf->filename, err_info);
      g_free(err_info);
      break;

    case FTAP_ERR_CANT_READ:
      cmdarg_err("An attempt to read from the file \"%s\" failed for some unknown reason.",
                 cf->filename);
      break;

    case FTAP_ERR_SHORT_READ:
      cmdarg_err("The file \"%s\" appears to have been cut short in the middle of a packet.",
                 cf->filename);
      break;

    case FTAP_ERR_BAD_FILE:
      cmdarg_err("The file \"%s\" appears to be damaged or corrupt.\n(%s)",
                 cf->filename, err_info);
      g_free(err_info);
      break;

    case FTAP_ERR_DECOMPRESS:
      cmdarg_err("The compressed file \"%s\" appears to be damaged or corrupt.\n"
                 "(%s)", cf->filename, err_info);
      break;

    default:
      cmdarg_err("An error occurred while reading the file \"%s\": %s.",
                 cf->filename, ftap_strerror(err));
      break;
    }
  } else {
    if (print_packet_info) {
      if (!write_finale()) {
        err = errno;
        show_print_file_io_error(err);
      }
    }
  }

out:
  wtap_close(cf->wth);
  cf->wth = NULL;

  return err;
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset,
               struct wtap_pkthdr *whdr, const guchar *pd, guint tap_flags)
{
  frame_data      fdata;
  column_info    *cinfo;
  gboolean        passed;

  /* Count this packet. */
  cf->count++;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  frame_data_init(&fdata, cf->count, whdr, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt) {
    /* If we're running a filter, prime the epan_dissect_t with that
       filter. */
    if (cf->dfcode)
      epan_dissect_prime_dfilter(edt, cf->dfcode);

    col_custom_prime_edt(edt, &cf->cinfo);

    /* We only need the columns if either
         1) some tap needs the columns
       or
         2) we're printing packet info but we're *not* verbose; in verbose
            mode, we print the protocol tree, not the protocol summary.
       or
         3) there is a column mapped as an individual field */
    if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary) || output_fields_has_cols(output_fields))
      cinfo = &cf->cinfo;
    else
      cinfo = NULL;

    frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == &fdata) {
      ref_frame = fdata;
      ref = &ref_frame;
    }

    epan_dissect_file_run_with_taps(edt, whdr, frame_tvbuff_new(&fdata, pd), &fdata, cinfo);

    /* Run the filter if we have it. */
    if (cf->dfcode)
      passed = dfilter_apply_edt(cf->dfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdata, &cum_bytes);

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
         tcpdump or TShark is to allow the output of a live capture to
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

    /* this must be set after print_packet() [bug #8160] */
    prev_dis_frame = fdata;
    prev_dis = &prev_dis_frame;
  }

  prev_cap_frame = fdata;
  prev_cap = &prev_cap_frame;

  if (edt) {
    epan_dissect_reset(edt);
    frame_data_destroy(&fdata);
  }
  return passed;
}

static gboolean
write_preamble(capture_file *cf)
{
  switch (output_action) {

  case WRITE_TEXT:
    return print_preamble(print_stream, cf ? cf->filename : NULL, get_ws_vcs_version_info());

  case WRITE_XML:
    if (print_details)
      write_pdml_preamble(stdout, cf ? cf->filename : NULL);
    else
      write_psml_preamble(stdout);
    return !ferror(stdout);

  case WRITE_FIELDS:
    write_fields_preamble(output_fields, stdout);
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

static char *
get_line_buf(size_t len)
{
  static char   *line_bufp    = NULL;
  static size_t  line_buf_len = 256;
  size_t         new_line_buf_len;

  for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
       new_line_buf_len *= 2)
    ;
  if (line_bufp == NULL) {
    line_buf_len = new_line_buf_len;
    line_bufp = (char *)g_malloc(line_buf_len + 1);
  } else {
    if (new_line_buf_len > line_buf_len) {
      line_buf_len = new_line_buf_len;
      line_bufp = (char *)g_realloc(line_bufp, line_buf_len + 1);
    }
  }
  return line_bufp;
}

static inline void
put_string(char *dest, const char *str, size_t str_len)
{
  memcpy(dest, str, str_len);
  dest[str_len] = '\0';
}

static inline void
put_spaces_string(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
  size_t i;

  for (i = str_len; i < str_with_spaces; i++)
    *dest++ = ' ';

  put_string(dest, str, str_len);
}

static inline void
put_string_spaces(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
  size_t i;

  memcpy(dest, str, str_len);
  for (i = str_len; i < str_with_spaces; i++)
    dest[i] = ' ';

  dest[str_with_spaces] = '\0';
}

static gboolean
print_columns(capture_file *cf)
{
  char   *line_bufp;
  int     i;
  size_t  buf_offset;
  size_t  column_len;
  size_t  col_len;

  line_bufp = get_line_buf(256);
  buf_offset = 0;
  *line_bufp = '\0';
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    /* Skip columns not marked as visible. */
    if (!get_column_visible(i))
      continue;
    switch (cf->cinfo.col_fmt[i]) {
    case COL_NUMBER:
      column_len = col_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 3)
        column_len = 3;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, cf->cinfo.col_data[i], col_len, column_len);
      break;

    case COL_CLS_TIME:
    case COL_REL_TIME:
    case COL_ABS_TIME:
    case COL_ABS_YMD_TIME:  /* XXX - wider */
    case COL_ABS_YDOY_TIME: /* XXX - wider */
    case COL_UTC_TIME:
    case COL_UTC_YMD_TIME:  /* XXX - wider */
    case COL_UTC_YDOY_TIME: /* XXX - wider */
      column_len = col_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 10)
        column_len = 10;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, cf->cinfo.col_data[i], col_len, column_len);
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
      column_len = col_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, cf->cinfo.col_data[i], col_len, column_len);
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
      column_len = col_len = strlen(cf->cinfo.col_data[i]);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string_spaces(line_bufp + buf_offset, cf->cinfo.col_data[i], col_len, column_len);
      break;

    default:
      column_len = strlen(cf->cinfo.col_data[i]);
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string(line_bufp + buf_offset, cf->cinfo.col_data[i], column_len);
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
       * them with " -> "; if we printed a network destination
       * and are printing a network source of the same type
       * next, separate them with " <- "; otherwise separate them
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
          put_string(line_bufp + buf_offset, " -> ", 4);
          buf_offset += 4;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
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
          put_string(line_bufp + buf_offset, " -> ", 4);
          buf_offset += 4;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
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
          put_string(line_bufp + buf_offset, " -> ", 4);
          buf_offset += 4;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
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
          put_string(line_bufp + buf_offset, " <- ", 4);
          buf_offset += 4;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
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
          put_string(line_bufp + buf_offset, " <- ", 4);
          buf_offset += 4;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
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
          put_string(line_bufp + buf_offset, " <- ", 4);
          buf_offset += 4;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      default:
        put_string(line_bufp + buf_offset, " ", 1);
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
  print_args_t print_args;

  if (print_summary || output_fields_has_cols(output_fields)) {
    /* Just fill in the columns. */
    epan_dissect_fill_in_columns(edt, FALSE, TRUE);

    if (print_summary) {
      /* Now print them. */
      switch (output_action) {

      case WRITE_TEXT:
        if (!print_columns(cf))
          return FALSE;
        break;

      case WRITE_XML:
        proto_tree_write_psml(edt, stdout);
        return !ferror(stdout);
      case WRITE_FIELDS: /*No non-verbose "fields" format */
        g_assert_not_reached();
        break;
      }
    }
  }
  if (print_details) {
    /* Print the information in the protocol tree. */
    switch (output_action) {

    case WRITE_TEXT:
      /* Only initialize the fields that are actually used in proto_tree_print.
       * This is particularly important for .range, as that's heap memory which
       * we would otherwise have to g_free().
      print_args.to_file = TRUE;
      print_args.format = print_format;
      print_args.print_summary = print_summary;
      print_args.print_formfeed = FALSE;
      packet_range_init(&print_args.range, &cfile);
      */
      print_args.print_hex = print_hex;
      print_args.print_dissections = print_details ? print_dissections_expanded : print_dissections_none;

      if (!proto_tree_print(&print_args, edt, print_stream))
        return FALSE;
      if (!print_hex) {
        if (!print_line(print_stream, 0, separator))
          return FALSE;
      }
      break;

    case WRITE_XML:
      proto_tree_write_pdml(edt, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_FIELDS:
      proto_tree_write_fields(output_fields, edt, &cf->cinfo, stdout);
      printf("\n");
      return !ferror(stdout);
    }
  }
  if (print_hex) {
    if (print_summary || print_details) {
      if (!print_line(print_stream, 0, ""))
        return FALSE;
    }
    if (!print_hex_data(print_stream, edt))
      return FALSE;
    if (!print_line(print_stream, 0, separator))
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

  case WRITE_XML:
    if (print_details)
      write_pdml_finale(stdout);
    else
      write_psml_finale(stdout);
    return !ferror(stdout);

  case WRITE_FIELDS:
    write_fields_finale(output_fields, stdout);
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
#if USE_FTAP
  ftap  *fth;
#else
  wtap  *wth;
#endif
  gchar *err_info;
  char   err_msg[2048+1];

#if USE_FTAP
  fth = ftap_open_offline(fname, err, &err_info, perform_two_pass_analysis);
  if (fth == NULL)
    goto fail;
#else
  wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
  if (wth == NULL)
    goto fail;
#endif

  /* The open succeeded.  Fill in the information for this file. */

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = tfshark_epan_new(cf);

#if USE_FTAP
  cf->wth = (struct wtap*)fth; /**** XXX - DOESN'T WORK RIGHT NOW!!!! */
#else
  cf->wth = wth;
#endif
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t      = ftap_file_type_subtype((struct ftap*)cf->wth); /**** XXX - DOESN'T WORK RIGHT NOW!!!! */
  cf->open_type = type;
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = ftap_snapshot_length((struct ftap*)cf->wth); /**** XXX - DOESN'T WORK RIGHT NOW!!!! */
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = FTAP_MAX_RECORD_SIZE;
  } else
    cf->has_snap = TRUE;
  nstime_set_zero(&cf->elapsed_time);
  ref = NULL;
  prev_dis = NULL;
  prev_cap = NULL;

  cf->state = FILE_READ_IN_PROGRESS;

  return CF_OK;

fail:
  g_snprintf(err_msg, sizeof err_msg,
             cf_open_error_message(*err, err_info, FALSE, cf->cd_t), fname);
  cmdarg_err("%s", err_msg);
  return CF_ERROR;
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
      g_strerror(err));
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

    case FTAP_ERR_NOT_REGULAR_FILE:
      errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
      break;

    case FTAP_ERR_RANDOM_OPEN_PIPE:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" is a pipe or FIFO; TFShark can't read pipe or FIFO files in two-pass mode.";
      break;

    case FTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" isn't a capture file in a format TFShark understands.";
      break;

    case FTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
               "The file \"%%s\" isn't a capture file in a format TFShark understands.\n"
               "(%s)", err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case FTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
                 "written to a pipe.", ftap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case FTAP_ERR_UNSUPPORTED_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      errmsg = "TFShark doesn't support writing capture files in that format.";
      break;

    case FTAP_ERR_UNSUPPORTED_ENCAP:
      if (for_writing) {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                   "TFShark can't save this capture as a \"%s\" file.",
                   ftap_file_type_subtype_short_string(file_type));
      } else {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" is a capture for a network type that TFShark doesn't support.\n"
                 "(%s)", err_info);
        g_free(err_info);
      }
      errmsg = errmsg_errno;
      break;

    case FTAP_ERR_ENCAP_PER_RECORD_UNSUPPORTED:
      if (for_writing) {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                   "TFShark can't save this capture as a \"%s\" file.",
                   ftap_file_type_subtype_short_string(file_type));
        errmsg = errmsg_errno;
      } else
        errmsg = "The file \"%s\" is a capture for a network type that TFShark doesn't support.";
      break;

    case FTAP_ERR_BAD_FILE:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
               "The file \"%%s\" appears to be damaged or corrupt.\n"
               "(%s)", err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case FTAP_ERR_CANT_OPEN:
      if (for_writing)
        errmsg = "The file \"%s\" could not be created for some unknown reason.";
      else
        errmsg = "The file \"%s\" could not be opened for some unknown reason.";
      break;

    case FTAP_ERR_SHORT_READ:
      errmsg = "The file \"%s\" appears to have been cut short"
               " in the middle of a packet or other data.";
      break;

    case FTAP_ERR_SHORT_WRITE:
      errmsg = "A full header couldn't be written to the file \"%s\".";
      break;

    case FTAP_ERR_COMPRESSION_NOT_SUPPORTED:
      errmsg = "This file type cannot be written as a compressed file.";
      break;

    case FTAP_ERR_DECOMPRESS:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)", err_info);
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    default:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" could not be %s: %s.",
                 for_writing ? "created" : "opened",
                 ftap_strerror(err));
      errmsg = errmsg_errno;
      break;
    }
  } else
    errmsg = file_open_error_message(err, for_writing);
  return errmsg;
}

/*
 * Open/create errors are reported with an console message in TFShark.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "tfshark: ");
  fprintf(stderr, file_open_error_message(err, for_writing), filename);
  fprintf(stderr, "\n");
}


/*
 * General errors are reported with an console message in TFShark.
 */
static void
failure_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "tfshark: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in TFShark.
 */
static void
read_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in TFShark.
 */
static void
write_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Report an error in command-line arguments.
 */
void
cmdarg_err(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  failure_message(fmt, ap);
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


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
