/* tshark.c
 *
 * Text-mode variant of Wireshark, along the lines of tcpdump and snoop,
 * by Gilbert Ramirez <gram@alumni.rice.edu> and Guy Harris <guy@alum.mit.edu>.
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <errno.h>

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan-int.h>
#include <epan/epan.h>

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_err.h>
#include <ws_version_info.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/util.h"
#include "ui/ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/cli/tshark-tap.h"
#include "ui/tap_export_pdu.h"
#include "register.h"
#include "filter_files.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/srt_table.h>
#include <epan/rtd_table.h>
#include <epan/ex-opt.h>
#include <epan/exported_pdu.h>

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#include <epan/asn1.h>
#include <epan/dissectors/packet-kerberos.h>
#endif

#include "capture_opts.h"

#include "caputils/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP
#include "caputils/capture_ifinfo.h"
#ifdef _WIN32
#include "caputils/capture-wpcap.h"
#include <wsutil/os_version_info.h>
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */
#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>
#include <capture_info.h>
#endif /* HAVE_LIBPCAP */
#include "log.h"
#include <epan/funnel.h>

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif


#if 0
#define tshark_debug(...) g_warning(__VA_ARGS__)
#else
#define tshark_debug(...)
#endif

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data prev_dis_frame;
static frame_data *prev_cap;
static frame_data prev_cap_frame;

static gboolean perform_two_pass_analysis;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
  WRITE_TEXT,   /* summary or detail text */
  WRITE_XML,    /* PDML or PSML */
  WRITE_FIELDS, /* User defined list of fields */
  WRITE_JSON,    /* JSON */
  WRITE_EK      /* JSON bulk insert to Elasticsearch */
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
static gchar **protocolfilter = NULL;

/* The line separator used between packets, changeable via the -S option */
static const char *separator = "";

#ifdef HAVE_LIBPCAP
/*
 * TRUE if we're to print packet counts to keep track of captured packets.
 */
static gboolean print_packet_counts;

static capture_options global_capture_opts;
static capture_session global_capture_session;
static info_data_t global_info_data;

#ifdef SIGINFO
static gboolean infodelay;      /* if TRUE, don't print capture info in SIGINFO handler */
static gboolean infoprint;      /* if TRUE, print capture info after clearing infodelay */
#endif /* SIGINFO */

static gboolean capture(void);
static void report_counts(void);
#ifdef _WIN32
static BOOL WINAPI capture_cleanup(DWORD);
#else /* _WIN32 */
static void capture_cleanup(int);
#ifdef SIGINFO
static void report_counts_siginfo(int);
#endif /* SIGINFO */
#endif /* _WIN32 */

#else /* HAVE_LIBPCAP */

static char *output_file_name;

#endif /* HAVE_LIBPCAP */

static int load_cap_file(capture_file *, char *, int, gboolean, int, gint64);
static gboolean process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset,
    struct wtap_pkthdr *whdr, const guchar *pd,
    guint tap_flags);
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
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

capture_file cfile;

static GHashTable *output_only_tables = NULL;

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

static void
list_capture_types(void) {
  int                 i;
  struct string_elem *captypes;
  GSList             *list = NULL;

  captypes = g_new(struct string_elem, WTAP_NUM_FILE_TYPES_SUBTYPES);

  fprintf(stderr, "tshark: The available capture file types for the \"-F\" flag are:\n");
  for (i = 0; i < WTAP_NUM_FILE_TYPES_SUBTYPES; i++) {
    if (wtap_dump_can_open(i)) {
      captypes[i].sstr = wtap_file_type_subtype_short_string(i);
      captypes[i].lstr = wtap_file_type_subtype_string(i);
      list = g_slist_insert_sorted(list, &captypes[i], string_compare);
    }
  }
  g_slist_foreach(list, string_elem_print, NULL);
  g_slist_free(list);
  g_free(captypes);
}

static void
list_read_capture_types(void) {
  int                 i;
  struct string_elem *captypes;
  GSList             *list = NULL;
  const char *magic = "Magic-value-based";
  const char *heuristic = "Heuristics-based";

  /* this is a hack, but WTAP_NUM_FILE_TYPES_SUBTYPES is always >= number of open routines so we're safe */
  captypes = g_new(struct string_elem, WTAP_NUM_FILE_TYPES_SUBTYPES);

  fprintf(stderr, "tshark: The available read file types for the \"-X read_format:\" option are:\n");
  for (i = 0; open_routines[i].name != NULL; i++) {
    captypes[i].sstr = open_routines[i].name;
    captypes[i].lstr = (open_routines[i].type == OPEN_INFO_MAGIC) ? magic : heuristic;
    list = g_slist_insert_sorted(list, &captypes[i], string_compare);
  }
  g_slist_foreach(list, string_elem_print, NULL);
  g_slist_free(list);
  g_free(captypes);
}

static void
print_usage(FILE *output)
{
  fprintf(output, "\n");
  fprintf(output, "Usage: tshark [options] ...\n");
  fprintf(output, "\n");

#ifdef HAVE_LIBPCAP
  fprintf(output, "Capture interface:\n");
  fprintf(output, "  -i <interface>           name or idx of interface (def: first non-loopback)\n");
  fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
  fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
  fprintf(output, "  -p                       don't capture in promiscuous mode\n");
#ifdef HAVE_PCAP_CREATE
  fprintf(output, "  -I                       capture in monitor mode, if available\n");
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
  fprintf(output, "  -B <buffer size>         size of kernel buffer (def: %dMB)\n", DEFAULT_CAPTURE_BUFFER_SIZE);
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
#ifdef HAVE_PCAP_REMOTE
  fprintf(output, "RPCAP options:\n");
  fprintf(output, "  -A <user>:<password>     use RPCAP password authentication\n");
#endif
  /*fprintf(output, "\n");*/
  fprintf(output, "Input file:\n");
  fprintf(output, "  -r <infile>              set the filename to read from (- to read from stdin)\n");

  fprintf(output, "\n");
  fprintf(output, "Processing:\n");
  fprintf(output, "  -2                       perform a two-pass analysis\n");
  fprintf(output, "  -R <read filter>         packet Read filter in Wireshark display filter syntax\n");
  fprintf(output, "  -Y <display filter>      packet displaY filter in Wireshark display filter\n");
  fprintf(output, "                           syntax\n");
  fprintf(output, "  -n                       disable all name resolutions (def: all enabled)\n");
  fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mnNtCd\"\n");
  fprintf(output, "  -d %s ...\n", DECODE_AS_ARG_TEMPLATE);
  fprintf(output, "                           \"Decode As\", see the man page for details\n");
  fprintf(output, "                           Example: tcp.port==8888,http\n");
  fprintf(output, "  -H <hosts file>          read a list of entries from a hosts file, which will\n");
  fprintf(output, "                           then be written to a capture file. (Implies -W n)\n");
  fprintf(output, "  --disable-protocol <proto_name>\n");
  fprintf(output, "                           disable dissection of proto_name\n");
  fprintf(output, "  --enable-heuristic <short_name>\n");
  fprintf(output, "                           enable dissection of heuristic protocol\n");
  fprintf(output, "  --disable-heuristic <short_name>\n");
  fprintf(output, "                           disable dissection of heuristic protocol\n");

  /*fprintf(output, "\n");*/
  fprintf(output, "Output:\n");
  fprintf(output, "  -w <outfile|->           write packets to a pcap-format file named \"outfile\"\n");
  fprintf(output, "                           (or to the standard output for \"-\")\n");
  fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
  fprintf(output, "  -F <output file type>    set the output file type, default is pcapng\n");
  fprintf(output, "                           an empty \"-F\" option will list the file types\n");
  fprintf(output, "  -V                       add output of packet tree        (Packet Details)\n");
  fprintf(output, "  -O <protocols>           Only show packet details of these protocols, comma\n");
  fprintf(output, "                           separated\n");
  fprintf(output, "  -P                       print packet summary even when writing to a file\n");
  fprintf(output, "  -S <separator>           the line separator to print between packets\n");
  fprintf(output, "  -x                       add output of hex and ASCII dump (Packet Bytes)\n");
  fprintf(output, "  -T pdml|ps|psml|json|ek|text|fields\n");
  fprintf(output, "                           format of text output (def: text)\n");
  fprintf(output, "  -j <protocolfilter>      protocols layers filter if -T ek|pdml|json selected,\n");
  fprintf(output, "                           (e.g. \"http tcp ip\",\n");
  fprintf(output, "  -e <field>               field to print if -Tfields selected (e.g. tcp.port,\n");
  fprintf(output, "                           _ws.col.Info)\n");
  fprintf(output, "                           this option can be repeated to print multiple fields\n");
  fprintf(output, "  -E<fieldsoption>=<value> set options for output when -Tfields selected:\n");
  fprintf(output, "     bom=y|n               print a UTF-8 BOM\n");
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
  fprintf(output, "  -g                       enable group read access on the output file(s)\n");
  fprintf(output, "  -W n                     Save extra information in the file, if supported.\n");
  fprintf(output, "                           n = write network address resolution information\n");
  fprintf(output, "  -X <key>:<value>         eXtension options, see the man page for details\n");
  fprintf(output, "  -U tap_name              PDUs export mode, see the man page for details\n");
  fprintf(output, "  -z <statistics>          various statistics, see the man page for details\n");
  fprintf(output, "  --capture-comment <comment>\n");
  fprintf(output, "                           add a capture comment to the newly created\n");
  fprintf(output, "                           output file (only for pcapng)\n");

  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h                       display this help and exit\n");
  fprintf(output, "  -v                       display version info and exit\n");
  fprintf(output, "  -o <name>:<value> ...    override preference setting\n");
  fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
  fprintf(output, "  -G [report]              dump one of several available reports and exit\n");
  fprintf(output, "                           default report=\"fields\"\n");
  fprintf(output, "                           use \"-G ?\" for more help\n");
#ifdef __linux__
  fprintf(output, "\n");
  fprintf(output, "WARNING: dumpcap will enable kernel BPF JIT compiler if available.\n");
  fprintf(output, "You might want to reset it\n");
  fprintf(output, "By doing \"echo 0 > /proc/sys/net/core/bpf_jit_enable\"\n");
  fprintf(output, "\n");
#endif

}

static void
glossary_option_help(void)
{
  FILE *output;

  output = stdout;

  fprintf(output, "TShark (Wireshark) %s\n", get_ws_vcs_version_info());

  fprintf(output, "\n");
  fprintf(output, "Usage: tshark -G [report]\n");
  fprintf(output, "\n");
  fprintf(output, "Glossary table reports:\n");
  fprintf(output, "  -G column-formats        dump column format codes and exit\n");
  fprintf(output, "  -G decodes               dump \"layer type\"/\"decode as\" associations and exit\n");
  fprintf(output, "  -G dissector-tables      dump dissector table names, types, and properties\n");
  fprintf(output, "  -G fieldcount            dump count of header fields and exit\n");
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

static void
tshark_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
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
get_tshark_compiled_version_info(GString *str)
{
  /* Capture libraries */
  get_compiled_caplibs_version(str);
}

static void
get_tshark_runtime_version_info(GString *str)
{
#ifdef HAVE_LIBPCAP
    /* Capture libraries */
    g_string_append(str, ", ");
    get_runtime_caplibs_version(str);
#endif

    /* stuff used by libwireshark */
    epan_get_runtime_version_info(str);
}

int
main(int argc, char *argv[])
{
  GString             *comp_info_str;
  GString             *runtime_info_str;
  char                *init_progfile_dir_error;
  int                  opt;
  static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    LONGOPT_CAPTURE_COMMON
    {0, 0, 0, 0 }
  };
  gboolean             arg_error = FALSE;

#ifdef _WIN32
  WSADATA              wsaData;
#endif  /* _WIN32 */

  char                *gpf_path, *pf_path;
  char                *gdp_path, *dp_path;
  char                *cf_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  int                  cf_open_errno;
  int                  err;
  volatile int         exit_status = 0;
#ifdef HAVE_LIBPCAP
  gboolean             list_link_layer_types = FALSE;
  gboolean             start_capture = FALSE;
  int                  status;
  GList               *if_list;
  gchar               *err_str;
#else
  gboolean             capture_option_specified = FALSE;
#endif
  gboolean             quiet = FALSE;
#ifdef PCAP_NG_DEFAULT
  volatile int         out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;
#else
  volatile int         out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAP;
#endif
  volatile gboolean    out_file_name_res = FALSE;
  volatile int         in_file_type = WTAP_TYPE_AUTO;
  gchar               *volatile cf_name = NULL;
  gchar               *rfilter = NULL;
  gchar               *dfilter = NULL;
#ifdef HAVE_PCAP_OPEN_DEAD
  struct bpf_program   fcode;
#endif
  dfilter_t           *rfcode = NULL;
  dfilter_t           *dfcode = NULL;
  gchar               *err_msg;
  e_prefs             *prefs_p;
  char                 badopt;
  int                  log_flags;
  gchar               *output_only = NULL;
  GSList              *disable_protocol_slist = NULL;
  GSList              *enable_heur_slist = NULL;
  GSList              *disable_heur_slist = NULL;
  gchar               *volatile pdu_export_arg = NULL;
  exp_pdu_t            exp_pdu_tap_data;

/*
 * The leading + ensures that getopt_long() does not permute the argv[]
 * entries.
 *
 * We have to make sure that the first getopt_long() preserves the content
 * of argv[] for the subsequent getopt_long() call.
 *
 * We use getopt_long() in both cases to ensure that we're using a routine
 * whose permutation behavior we can control in the same fashion on all
 * platforms, and so that, if we ever need to process a long argument before
 * doing further initialization, we can do so.
 *
 * Glibc and Solaris libc document that a leading + disables permutation
 * of options, regardless of whether POSIXLY_CORRECT is set or not; *BSD
 * and OS X don't document it, but do so anyway.
 *
 * We do *not* use a leading - because the behavior of a leading - is
 * platform-dependent.
 */
#define OPTSTRING "+2" OPTSTRING_CAPTURE_COMMON "C:d:e:E:F:gG:hH:j:" "K:lnN:o:O:PqQr:R:S:t:T:u:U:vVw:W:xX:Y:z:"

  static const char    optstring[] = OPTSTRING;

  tshark_debug("tshark started with %d args", argc);

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  cmdarg_err_init(failure_message, failure_message_cont);

#ifdef _WIN32
  arg_list_utf_16to8(argc, argv);
  create_app_running_mutex();
#if !GLIB_CHECK_VERSION(2,31,0)
  g_thread_init(NULL);
#endif
#endif /* _WIN32 */

  /*
   * Get credential information for later use, and drop privileges
   * before doing anything else.
   * Let the user know if anything happened.
   */
  init_process_policies();
  relinquish_special_privs_perm();
  print_current_user();

  /*
   * Attempt to get the pathname of the directory containing the
   * executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0], main);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr,
            "tshark: Can't get pathname of directory containing the tshark program: %s.\n"
            "It won't be possible to capture traffic.\n"
            "Report this to the Wireshark developers.",
            init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  }

  initialize_funnel_ops();

#ifdef _WIN32
  ws_init_dll_search_path();
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* Warn the user if npf.sys isn't loaded. */
  if (!npf_sys_is_running() && get_windows_major_version() >= 6) {
    fprintf(stderr, "The NPF driver isn't running.  You may have trouble "
      "capturing or\nlisting interfaces.\n");
  }
#endif

  /* Get the compile-time version information string */
  comp_info_str = get_compiled_version_info(get_tshark_compiled_version_info,
                                            epan_get_compiled_version_info);

  /* Get the run-time version information string */
  runtime_info_str = get_runtime_version_info(get_tshark_runtime_version_info);

  /* Add it to the information to be reported on a crash. */
  ws_add_crash_info("TShark (Wireshark) %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);
  g_string_free(comp_info_str, TRUE);
  g_string_free(runtime_info_str, TRUE);

  /* Fail sometimes. Useful for testing fuzz scripts. */
  /* if (g_random_int_range(0, 100) < 5) abort(); */

  /*
   * In order to have the -X opts assigned before the wslua machine starts
   * we need to call getopt_long before epan_init() gets called.
   *
   * In order to handle, for example, -o options, we also need to call it
   * *after* epan_init() gets called, so that the dissectors have had a
   * chance to register their preferences.
   *
   * XXX - can we do this all with one getopt_long() call, saving the
   * arguments we can't handle until after initializing libwireshark,
   * and then process them after initializing libwireshark?
   */
  opterr = 0;

  while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
    switch (opt) {
    case 'C':        /* Configuration Profile */
      if (profile_exists (optarg, FALSE)) {
        set_profile_name (optarg);
      } else {
        cmdarg_err("Configuration Profile \"%s\" does not exist", optarg);
        return 1;
      }
      break;
    case 'P':        /* Print packet summary info even when writing to a file */
      print_packet_info = TRUE;
      print_summary = TRUE;
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
   * were specified and -P was not.  Note that this is new behavior, which
   * allows for the possibility of printing only hex/ascii output without
   * necessarily requiring that either the summary or details be printed too.
   */
  if (print_summary == -1)
    print_summary = (print_details || print_hex) ? FALSE : TRUE;

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
                    tshark_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_MAIN,
                    (GLogLevelFlags)log_flags,
                    tshark_log_handler, NULL /* user_data */);

#ifdef HAVE_LIBPCAP
  g_log_set_handler(LOG_DOMAIN_CAPTURE,
                    (GLogLevelFlags)log_flags,
                    tshark_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
                    (GLogLevelFlags)log_flags,
                    tshark_log_handler, NULL /* user_data */);
#endif

  init_report_err(failure_message, open_failure_message, read_failure_message,
                  write_failure_message);

#ifdef HAVE_LIBPCAP
  capture_opts_init(&global_capture_opts);
  capture_session_init(&global_capture_session, &cfile);
#endif

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

  wtap_init();

#ifdef HAVE_PLUGINS
  /* Register all the plugin types we have. */
  epan_register_plugin_types(); /* Types known to libwireshark */

  /* Scan for plugins.  This does *not* call their registration routines;
     that's done later. */
  scan_plugins();

  /* Register all libwiretap plugin modules. */
  register_all_wiretap_modules();
#endif

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL,
                 NULL))
    return 2;

  /* Register all tap listeners; we do this before we parse the arguments,
     as the "-z" argument can specify a registered tap. */

  /* we register the plugin taps before the other taps because
     stats_tree taps plugins will be registered as tap listeners
     by stats_tree_stat.c and need to registered before that */
#ifdef HAVE_PLUGINS
  register_all_plugin_tap_listeners();
#endif
#ifdef HAVE_EXTCAP
  extcap_register_preferences();
#endif
  register_all_tap_listeners();
  conversation_table_set_gui_info(init_iousers);
  hostlist_table_set_gui_info(init_hostlists);
  srt_table_iterate_tables(register_srt_tables, NULL);
  rtd_table_iterate_tables(register_rtd_tables, NULL);
  new_stat_tap_iterate_tables(register_simple_stat_tables, NULL);

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
      else if (strcmp(argv[2], "dissector-tables") == 0)
        dissector_dump_dissector_tables();
      else if (strcmp(argv[2], "fieldcount") == 0) {
        /* return value for the test suite */
        return proto_registrar_dump_fieldcount();
      } else if (strcmp(argv[2], "fields") == 0)
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

  /* load the decode as entries of this profile */
  load_decode_as_entries();

  tshark_debug("tshark reading preferences");

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

  read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);
  if (cf_path != NULL) {
      cmdarg_err("Could not open your capture filter file\n\"%s\": %s.",
          cf_path, g_strerror(cf_open_errno));
      g_free(cf_path);
  }

  /* Read the disabled protocols file. */
  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                            &dp_path, &dp_open_errno, &dp_read_errno);
  read_disabled_heur_dissector_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
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

  /*
   * To reset the options parser, set optreset to 1 on platforms that
   * have optreset (documented in *BSD and OS X, apparently present but
   * not documented in Solaris - the Illumos repository seems to
   * suggest that the first Solaris getopt_long(), at least as of 2004,
   * was based on the NetBSD one, it had optreset) and set optind to 1,
   * and set optind to 0 otherwise (documented as working in the GNU
   * getopt_long().  Setting optind to 0 didn't originally work in the
   * NetBSD one, but that was added later - we don't want to depend on
   * it if we have optreset).
   *
   * Also reset opterr to 1, so that error messages are printed by
   * getopt_long().
   */
#ifdef HAVE_OPTRESET
  optreset = 1;
  optind = 1;
#else
  optind = 0;
#endif
  opterr = 1;

  /* Now get our args */
  while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
    switch (opt) {
    case '2':        /* Perform two pass analysis */
      perform_two_pass_analysis = TRUE;
      break;
    case 'a':        /* autostop criteria */
    case 'b':        /* Ringbuffer option */
    case 'c':        /* Capture x packets */
    case 'f':        /* capture filter */
    case 'g':        /* enable group read access on file(s) */
    case 'i':        /* Use interface x */
    case 'p':        /* Don't capture in promiscuous mode */
#ifdef HAVE_PCAP_REMOTE
    case 'A':        /* Authentication */
#endif
#ifdef HAVE_PCAP_CREATE
    case 'I':        /* Capture in monitor mode, if available */
#endif
    case 's':        /* Set the snapshot (capture) length */
    case 'w':        /* Write to capture file x */
    case 'y':        /* Set the pcap data link type */
    case  LONGOPT_NUM_CAP_COMMENT: /* add a capture comment */
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    case 'B':        /* Buffer size */
#endif
#ifdef HAVE_LIBPCAP
      status = capture_opts_add_opt(&global_capture_opts, opt, optarg, &start_capture);
      if (status != 0) {
        return status;
      }
#else
      if (opt == 'w') {
        /*
         * Output file name, if we're reading a file and writing to another
         * file.
         */
        output_file_name = optarg;
      } else {
        capture_option_specified = TRUE;
        arg_error = TRUE;
      }
#endif
      break;
    case 'C':
      /* already processed; just ignore it now */
      break;
    case 'd':        /* Decode as rule */
      if (!decode_as_command_option(optarg))
        return 1;
      break;
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
    case 'K':        /* Kerberos keytab file */
      read_keytab_file(optarg);
      break;
#endif
    case 'D':        /* Print a list of capture devices and exit */
#ifdef HAVE_LIBPCAP
      if_list = capture_interface_list(&err, &err_str,NULL);
      if (if_list == NULL) {
        if (err == 0)
          cmdarg_err("There are no interfaces on which a capture can be done");
        else {
          cmdarg_err("%s", err_str);
          g_free(err_str);
        }
        return 2;
      }
      capture_opts_print_interfaces(if_list);
      free_interface_list(if_list);
      return 0;
#else
      capture_option_specified = TRUE;
      arg_error = TRUE;
#endif
      break;
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
    case 'F':
      out_file_type = wtap_short_string_to_file_type_subtype(optarg);
      if (out_file_type < 0) {
        cmdarg_err("\"%s\" isn't a valid capture file type", optarg);
        list_capture_types();
        return 1;
      }
      break;
    case 'j':
      protocolfilter = wmem_strsplit(wmem_epan_scope(), optarg, " ", -1);
      break;
    case 'W':        /* Select extra information to save in our capture file */
      /* This is patterned after the -N flag which may not be the best idea. */
      if (strchr(optarg, 'n')) {
        out_file_name_res = TRUE;
      } else {
        cmdarg_err("Invalid -W argument \"%s\"; it must be one of:", optarg);
        cmdarg_err_cont("\t'n' write network address resolution information (pcapng only)");
        return 1;
      }
      break;
    case 'H':        /* Read address to name mappings from a hosts file */
      if (! add_hosts_file(optarg))
      {
        cmdarg_err("Can't read host entries from \"%s\"", optarg);
        return 1;
      }
      out_file_name_res = TRUE;
      break;

    case 'h':        /* Print help and exit */
      printf("TShark (Wireshark) %s\n"
             "Dump and analyze network traffic.\n"
             "See https://www.wireshark.org for more information.\n",
             get_ws_vcs_version_info());
      print_usage(stdout);
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
    case 'L':        /* Print list of link-layer types and exit */
#ifdef HAVE_LIBPCAP
      list_link_layer_types = TRUE;
#else
      capture_option_specified = TRUE;
      arg_error = TRUE;
#endif
      break;
    case 'n':        /* No name resolution */
      disable_name_resolution();
      break;
    case 'N':        /* Select what types of addresses/port #s to resolve */
      badopt = string_to_name_resolve(optarg, &gbl_resolv_flags);
      if (badopt != '\0') {
        cmdarg_err("-N specifies unknown resolving option '%c'; valid options are:",
                   badopt);
        cmdarg_err_cont("\t'd' to enable address resolution from captured DNS packets\n"
                        "\t'm' to enable MAC address resolution\n"
                        "\t'n' to enable network address resolution\n"
                        "\t'N' to enable using external resolvers (e.g., DNS)\n"
                        "\t    for network address resolution\n"
                        "\t't' to enable transport-layer port number resolution");
        return 1;
      }
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
    case 'P':
        /* already processed; just ignore it now */
        break;
    case 'S':        /* Set the line Separator to be printed between packets */
      separator = optarg;
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
      print_packet_info = TRUE;
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
      } else if (strcmp(optarg, "json") == 0) {
        output_action = WRITE_JSON;
        print_details = TRUE;   /* Need details */
        print_summary = FALSE;  /* Don't allow summary */
      } else if (strcmp(optarg, "ek") == 0) {
        output_action = WRITE_EK;
        print_details = TRUE;   /* Need details */
        print_summary = FALSE;  /* Don't allow summary */
      }
      else {
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
                        "\t\"json\"   Packet Summary, an JSON-based format for the details\n"
                        "\t         summary information of a decoded packet. This information is \n"
                        "\t         equivalent to the packet details printed with the -V flag.\n"
                        "\t\"ek\"     Packet Summary, an EK JSON-based format for the bulk insert \n"
                        "\t         into elastic search cluster. This information is \n"
                        "\t         equivalent to the packet details printed with the -V flag.\n"
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
    case 'U':        /* Export PDUs to file */
    {
        GSList *export_pdu_tap_name_list = NULL;

        if (!*optarg) {
            cmdarg_err("Tap name is required! Valid names are:");
            for (export_pdu_tap_name_list = get_export_pdu_tap_list(); export_pdu_tap_name_list; export_pdu_tap_name_list = g_slist_next(export_pdu_tap_name_list)) {
                cmdarg_err("%s\n", (const char*)(export_pdu_tap_name_list->data));
            }
            return 1;
        }
        pdu_export_arg = g_strdup(optarg);
        break;
    }
    case 'v':         /* Show version and exit */
      comp_info_str = get_compiled_version_info(get_tshark_compiled_version_info,
                                                epan_get_compiled_version_info);
      runtime_info_str = get_runtime_version_info(get_tshark_runtime_version_info);
      show_version("TShark (Wireshark)", comp_info_str, runtime_info_str);
      g_string_free(comp_info_str, TRUE);
      g_string_free(runtime_info_str, TRUE);
      /* We don't really have to cleanup here, but it's a convenient way to test
       * start-up and shut-down of the epan library without any UI-specific
       * cruft getting in the way. Makes the results of running
       * $ ./tools/valgrind-wireshark -n
       * much more useful. */
      epan_cleanup();
#ifdef HAVE_EXTCAP
      extcap_cleanup();
#endif
      return 0;
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
      /* already processed; just ignore it now */
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
      if (strcmp("help", optarg) == 0) {
        fprintf(stderr, "tshark: The available statistics for the \"-z\" option are:\n");
        list_stat_cmd_args();
        return 0;
      }
      if (!process_stat_cmd_arg(optarg)) {
        cmdarg_err("Invalid -z argument \"%s\"; it must be one of:", optarg);
        list_stat_cmd_args();
        return 1;
      }
      break;
    case LONGOPT_DISABLE_PROTOCOL: /* disable dissection of protocol */
      disable_protocol_slist = g_slist_append(disable_protocol_slist, optarg);
      break;
    case LONGOPT_ENABLE_HEURISTIC: /* enable heuristic dissection of protocol */
      enable_heur_slist = g_slist_append(enable_heur_slist, optarg);
      break;
    case LONGOPT_DISABLE_HEURISTIC: /* disable heuristic dissection of protocol */
      disable_heur_slist = g_slist_append(disable_heur_slist, optarg);
      break;

    default:
    case '?':        /* Bad flag - print usage message */
      switch(optopt) {
      case 'F':
        list_capture_types();
        break;
      default:
        print_usage(stderr);
      }
      return 1;
      break;
    }
  }

  /* If we specified output fields, but not the output field type... */
  if ((WRITE_FIELDS != output_action && WRITE_XML != output_action && WRITE_JSON != output_action && WRITE_EK != output_action) && 0 != output_fields_num_fields(output_fields)) {
        cmdarg_err("Output fields were specified with \"-e\", "
            "but \"-Tek, -Tfields, -Tjson or -Tpdml\" was not specified.");
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
    } else {
#ifdef HAVE_LIBPCAP
      guint i;

      if (global_capture_opts.default_options.cfilter) {
        cmdarg_err("A default capture filter was specified both with \"-f\""
            " and with additional command-line arguments.");
        return 1;
      }
      for (i = 0; i < global_capture_opts.ifaces->len; i++) {
        interface_options interface_opts;
        interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
        if (interface_opts.cfilter == NULL) {
          interface_opts.cfilter = get_args_as_string(argc, argv, optind);
          global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, i);
          g_array_insert_val(global_capture_opts.ifaces, i, interface_opts);
        } else {
          cmdarg_err("A capture filter was specified both with \"-f\""
              " and with additional command-line arguments.");
          return 1;
        }
      }
      global_capture_opts.default_options.cfilter = get_args_as_string(argc, argv, optind);
#else
      capture_option_specified = TRUE;
#endif
    }
  }

#ifdef HAVE_LIBPCAP
  if (!global_capture_opts.saving_to_file) {
    /* We're not saving the capture to a file; if "-q" wasn't specified,
       we should print packet information */
    if (!quiet)
      print_packet_info = TRUE;
  } else {
    /* We're saving to a file; if we're writing to the standard output.
       and we'll also be writing dissected packets to the standard
       output, reject the request.  At best, we could redirect that
       to the standard error; we *can't* write both to the standard
       output and have either of them be useful. */
    if (strcmp(global_capture_opts.save_file, "-") == 0 && print_packet_info) {
      cmdarg_err("You can't write both raw packet data and dissected packets"
          " to the standard output.");
      return 1;
    }
  }
#else
  /* We're not saving the capture to a file; if "-q" wasn't specified,
     we should print packet information */
  if (!quiet)
    print_packet_info = TRUE;
#endif

#ifndef HAVE_LIBPCAP
  if (capture_option_specified)
    cmdarg_err("This version of TShark was not built with support for capturing packets.");
#endif
  if (arg_error) {
    print_usage(stderr);
    return 1;
  }

  if (print_hex) {
    if (output_action != WRITE_TEXT && output_action != WRITE_JSON && output_action != WRITE_EK) {
      cmdarg_err("Raw packet hex data can only be printed as text, PostScript, JSON or EK JSON");
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

#ifdef HAVE_LIBPCAP
  if (list_link_layer_types) {
    /* We're supposed to list the link-layer types for an interface;
       did the user also specify a capture file to be read? */
    if (cf_name) {
      /* Yes - that's bogus. */
      cmdarg_err("You can't specify -L and a capture file to be read.");
      return 1;
    }
    /* No - did they specify a ring buffer option? */
    if (global_capture_opts.multi_files_on) {
      cmdarg_err("Ring buffer requested, but a capture isn't being done.");
      return 1;
    }
  } else {
    if (cf_name) {
      /*
       * "-r" was specified, so we're reading a capture file.
       * Capture options don't apply here.
       */

      /* We don't support capture filters when reading from a capture file
         (the BPF compiler doesn't support all link-layer types that we
         support in capture files we read). */
      if (global_capture_opts.default_options.cfilter) {
        cmdarg_err("Only read filters, not capture filters, "
          "can be specified when reading a capture file.");
        return 1;
      }
      if (global_capture_opts.multi_files_on) {
        cmdarg_err("Multiple capture files requested, but "
                   "a capture isn't being done.");
        return 1;
      }
      if (global_capture_opts.has_file_duration) {
        cmdarg_err("Switching capture files after a time interval was specified, but "
                   "a capture isn't being done.");
        return 1;
      }
      if (global_capture_opts.has_ring_num_files) {
        cmdarg_err("A ring buffer of capture files was specified, but "
          "a capture isn't being done.");
        return 1;
      }
      if (global_capture_opts.has_autostop_files) {
        cmdarg_err("A maximum number of capture files was specified, but "
          "a capture isn't being done.");
        return 1;
      }
      if (global_capture_opts.capture_comment) {
        cmdarg_err("A capture comment was specified, but "
          "a capture isn't being done.\nThere's no support for adding "
          "a capture comment to an existing capture file.");
        return 1;
      }

      /* Note: TShark now allows the restriction of a _read_ file by packet count
       * and byte count as well as a write file. Other autostop options remain valid
       * only for a write file.
       */
      if (global_capture_opts.has_autostop_duration) {
        cmdarg_err("A maximum capture time was specified, but "
          "a capture isn't being done.");
        return 1;
      }
    } else {
      /*
       * "-r" wasn't specified, so we're doing a live capture.
       */
      if (perform_two_pass_analysis) {
        /* Two-pass analysis doesn't work with live capture since it requires us
         * to buffer packets until we've read all of them, but a live capture
         * has no useful/meaningful definition of "all" */
        cmdarg_err("Live captures do not support two-pass analysis.");
        return 1;
      }

      if (global_capture_opts.saving_to_file) {
        /* They specified a "-w" flag, so we'll be saving to a capture file. */

        /* When capturing, we only support writing pcap or pcap-ng format. */
        if (out_file_type != WTAP_FILE_TYPE_SUBTYPE_PCAP &&
            out_file_type != WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
          cmdarg_err("Live captures can only be saved in pcap or pcapng format.");
          return 1;
        }
        if (global_capture_opts.capture_comment &&
            out_file_type != WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
          cmdarg_err("A capture comment can only be written to a pcapng file.");
          return 1;
        }
        if (global_capture_opts.multi_files_on) {
          /* Multiple-file mode doesn't work under certain conditions:
             a) it doesn't work if you're writing to the standard output;
             b) it doesn't work if you're writing to a pipe;
          */
          if (strcmp(global_capture_opts.save_file, "-") == 0) {
            cmdarg_err("Multiple capture files requested, but "
              "the capture is being written to the standard output.");
            return 1;
          }
          if (global_capture_opts.output_to_pipe) {
            cmdarg_err("Multiple capture files requested, but "
              "the capture file is a pipe.");
            return 1;
          }
          if (!global_capture_opts.has_autostop_filesize &&
              !global_capture_opts.has_file_duration) {
            cmdarg_err("Multiple capture files requested, but "
              "no maximum capture file size or duration was specified.");
            return 1;
          }
        }
        /* Currently, we don't support read or display filters when capturing
           and saving the packets. */
        if (rfilter != NULL) {
          cmdarg_err("Read filters aren't supported when capturing and saving the captured packets.");
          return 1;
        }
        if (dfilter != NULL) {
          cmdarg_err("Display filters aren't supported when capturing and saving the captured packets.");
          return 1;
        }
        global_capture_opts.use_pcapng = (out_file_type == WTAP_FILE_TYPE_SUBTYPE_PCAPNG) ? TRUE : FALSE;
      } else {
        /* They didn't specify a "-w" flag, so we won't be saving to a
           capture file.  Check for options that only make sense if
           we're saving to a file. */
        if (global_capture_opts.has_autostop_filesize) {
          cmdarg_err("Maximum capture file size specified, but "
           "capture isn't being saved to a file.");
          return 1;
        }
        if (global_capture_opts.multi_files_on) {
          cmdarg_err("Multiple capture files requested, but "
            "the capture isn't being saved to a file.");
          return 1;
        }
        if (global_capture_opts.capture_comment) {
          cmdarg_err("A capture comment was specified, but "
            "the capture isn't being saved to a file.");
          return 1;
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

  /* At this point MATE will have registered its field array so we can
     check if the fields specified by the user are all good.
   */
  {
    GSList* it = NULL;
    GSList *invalid_fields = output_fields_valid(output_fields);
    if (invalid_fields != NULL) {

      cmdarg_err("Some fields aren't valid:");
      for (it=invalid_fields; it != NULL; it = g_slist_next(it)) {
        cmdarg_err_cont("\t%s", (gchar *)it->data);
      }
      g_slist_free(invalid_fields);
      return 1;
    }
  }
#ifdef HAVE_LIBPCAP
  /* We currently don't support taps, or printing dissected packets,
     if we're writing to a pipe. */
  if (global_capture_opts.saving_to_file &&
      global_capture_opts.output_to_pipe) {
    if (tap_listeners_require_dissection()) {
      cmdarg_err("Taps aren't supported when saving to a pipe.");
      return 1;
    }
    if (print_packet_info) {
      cmdarg_err("Printing dissected packets isn't supported when saving to a pipe.");
      return 1;
    }
  }
#endif

  if (ex_opt_count("read_format") > 0) {
    const gchar* name = ex_opt_get_next("read_format");
    in_file_type = open_info_name_to_type(name);
    if (in_file_type == WTAP_TYPE_AUTO) {
      cmdarg_err("\"%s\" isn't a valid read file format type", name? name : "");
      list_read_capture_types();
      return 1;
    }
  }

  /* disabled protocols as per configuration file */
  if (gdp_path == NULL && dp_path == NULL) {
    set_disabled_protos_list();
    set_disabled_heur_dissector_list();
  }

  if(disable_protocol_slist) {
      GSList *proto_disable;
      for (proto_disable = disable_protocol_slist; proto_disable != NULL; proto_disable = g_slist_next(proto_disable))
      {
          proto_disable_proto_by_name((char*)proto_disable->data);
      }
  }

  if(enable_heur_slist) {
      GSList *heur_enable;
      for (heur_enable = enable_heur_slist; heur_enable != NULL; heur_enable = g_slist_next(heur_enable))
      {
          proto_enable_heuristic_by_name((char*)heur_enable->data, TRUE);
      }
  }

  if(disable_heur_slist) {
      GSList *heur_disable;
      for (heur_disable = disable_heur_slist; heur_disable != NULL; heur_disable = g_slist_next(heur_disable))
      {
          proto_enable_heuristic_by_name((char*)heur_disable->data, FALSE);
      }
  }

  /* Build the column format array */
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

#ifdef HAVE_LIBPCAP
  capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(&global_capture_opts);
#endif

  if (rfilter != NULL) {
    tshark_debug("Compiling read filter: '%s'", rfilter);
    if (!dfilter_compile(rfilter, &rfcode, &err_msg)) {
      cmdarg_err("%s", err_msg);
      g_free(err_msg);
      epan_cleanup();
#ifdef HAVE_EXTCAP
      extcap_cleanup();
#endif
#ifdef HAVE_PCAP_OPEN_DEAD
      {
        pcap_t *pc;

        pc = pcap_open_dead(DLT_EN10MB, MIN_PACKET_SIZE);
        if (pc != NULL) {
          if (pcap_compile(pc, &fcode, rfilter, 0, 0) != -1) {
            cmdarg_err_cont(
              "  Note: That read filter code looks like a valid capture filter;\n"
              "        maybe you mixed them up?");
          }
          pcap_close(pc);
        }
      }
#endif
      return 2;
    }
  }
  cfile.rfcode = rfcode;

  if (dfilter != NULL) {
    tshark_debug("Compiling display filter: '%s'", dfilter);
    if (!dfilter_compile(dfilter, &dfcode, &err_msg)) {
      cmdarg_err("%s", err_msg);
      g_free(err_msg);
      epan_cleanup();
#ifdef HAVE_EXTCAP
      extcap_cleanup();
#endif
#ifdef HAVE_PCAP_OPEN_DEAD
      {
        pcap_t *pc;

        pc = pcap_open_dead(DLT_EN10MB, MIN_PACKET_SIZE);
        if (pc != NULL) {
          if (pcap_compile(pc, &fcode, dfilter, 0, 0) != -1) {
            cmdarg_err_cont(
              "  Note: That display filter code looks like a valid capture filter;\n"
              "        maybe you mixed them up?");
          }
          pcap_close(pc);
        }
      }
#endif
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

  /* PDU export requested. Take the ownership of the '-w' file, apply tap
  * filters and start tapping. */
  if (pdu_export_arg) {
      const char *exp_pdu_filename;
      const char *exp_pdu_tap_name = pdu_export_arg;
      const char *exp_pdu_filter = dfilter; /* may be NULL to disable filter */
      char       *exp_pdu_error;
      int         exp_fd;

      if (!cf_name) {
          cmdarg_err("PDUs export requires a capture file (specify with -r).");
          return 1;
      }
      /* Take ownership of the '-w' output file. */
#ifdef HAVE_LIBPCAP
      exp_pdu_filename = global_capture_opts.save_file;
      global_capture_opts.save_file = NULL;
#else
      exp_pdu_filename = output_file_name;
      output_file_name = NULL;
#endif
      if (exp_pdu_filename == NULL) {
          cmdarg_err("PDUs export requires an output file (-w).");
          return 1;
      }

      exp_pdu_error = exp_pdu_pre_open(exp_pdu_tap_name, exp_pdu_filter,
          &exp_pdu_tap_data);
      if (exp_pdu_error) {
          cmdarg_err("Cannot register tap: %s", exp_pdu_error);
          g_free(exp_pdu_error);
          return 2;
      }

      exp_fd = ws_open(exp_pdu_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
      if (exp_fd == -1) {
          cmdarg_err("%s: %s", exp_pdu_filename, file_open_error_message(errno, TRUE));
          return 2;
      }

      /* Activate the export PDU tap */
      err = exp_pdu_open(&exp_pdu_tap_data, exp_fd,
          g_strdup_printf("Dump of PDUs from %s", cf_name));
      if (err != 0) {
          cmdarg_err("Failed to start the PDU export: %s", g_strerror(err));
          return 2;
      }
  }

  /* We have to dissect each packet if:

        we're printing information about each packet;

        we're using a read filter on the packets;

        we're using a display filter on the packets;

        we're exporting PDUs;

        we're using any taps that need dissection. */
  do_dissection = print_packet_info || rfcode || dfcode || pdu_export_arg ||
      tap_listeners_require_dissection();
  tshark_debug("tshark: do_dissection = %s", do_dissection ? "TRUE" : "FALSE");

  if (cf_name) {
    tshark_debug("tshark: Opening capture file: %s", cf_name);
    /*
     * We're reading a capture file.
     */
    if (cf_open(&cfile, cf_name, in_file_type, FALSE, &err) != CF_OK) {
      epan_cleanup();
#ifdef HAVE_EXTCAP
      extcap_cleanup();
#endif
      return 2;
    }

    /* Process the packets in the file */
    tshark_debug("tshark: invoking load_cap_file() to process the packets");
    TRY {
#ifdef HAVE_LIBPCAP
      err = load_cap_file(&cfile, global_capture_opts.save_file, out_file_type, out_file_name_res,
          global_capture_opts.has_autostop_packets ? global_capture_opts.autostop_packets : 0,
          global_capture_opts.has_autostop_filesize ? global_capture_opts.autostop_filesize : 0);
#else
      err = load_cap_file(&cfile, output_file_name, out_file_type, out_file_name_res, 0, 0);
#endif
    }
    CATCH(OutOfMemoryError) {
      fprintf(stderr,
              "Out Of Memory.\n"
              "\n"
              "Sorry, but TShark has to terminate now.\n"
              "\n"
              "More information and workarounds can be found at\n"
              "https://wiki.wireshark.org/KnownBugs/OutOfMemory\n");
      err = ENOMEM;
    }
    ENDTRY;
    if (err != 0) {
      /* We still dump out the results of taps, etc., as we might have
         read some packets; however, we exit with an error status. */
      exit_status = 2;
    }

    if (pdu_export_arg) {
        err = exp_pdu_close(&exp_pdu_tap_data);
        if (err) {
            cmdarg_err("%s", wtap_strerror(err));
            exit_status = 2;
        }
        g_free(pdu_export_arg);
    }
  } else {
    tshark_debug("tshark: no capture file specified");
    /* No capture file specified, so we're supposed to do a live capture
       or get a list of link-layer types for a live capture device;
       do we have support for live captures? */
#ifdef HAVE_LIBPCAP
    /* if no interface was specified, pick a default */
    exit_status = capture_opts_default_iface_if_necessary(&global_capture_opts,
        ((prefs_p->capture_device) && (*prefs_p->capture_device != '\0')) ? get_if_name(prefs_p->capture_device) : NULL);
    if (exit_status != 0)
        return exit_status;

    /* if requested, list the link layer types and exit */
    if (list_link_layer_types) {
        guint i;

        /* Get the list of link-layer types for the capture devices. */
        for (i = 0; i < global_capture_opts.ifaces->len; i++) {
          interface_options  interface_opts;
          if_capabilities_t *caps;
          char *auth_str = NULL;

          interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
#ifdef HAVE_PCAP_REMOTE
          if (interface_opts.auth_type == CAPTURE_AUTH_PWD) {
              auth_str = g_strdup_printf("%s:%s", interface_opts.auth_username, interface_opts.auth_password);
          }
#endif
          caps = capture_get_if_capabilities(interface_opts.name, interface_opts.monitor_mode, auth_str, &err_str, NULL);
          g_free(auth_str);
          if (caps == NULL) {
            cmdarg_err("%s", err_str);
            g_free(err_str);
            return 2;
          }
          if (caps->data_link_types == NULL) {
            cmdarg_err("The capture device \"%s\" has no data link types.", interface_opts.name);
            return 2;
          }
          capture_opts_print_if_capabilities(caps, interface_opts.name, interface_opts.monitor_mode);
          free_if_capabilities(caps);
        }
        return 0;
    }

    /*
     * If the standard error isn't a terminal, don't print packet counts,
     * as they won't show up on the user's terminal and they'll get in
     * the way of error messages in the file (to which we assume the
     * standard error was redirected; if it's redirected to the null
     * device, there's no point in printing packet counts anyway).
     *
     * Otherwise, if we're printing packet information and the standard
     * output is a terminal (which we assume means the standard output and
     * error are going to the same terminal), don't print packet counts,
     * as they'll get in the way of the packet information.
     *
     * Otherwise, if the user specified -q, don't print packet counts.
     *
     * Otherwise, print packet counts.
     *
     * XXX - what if the user wants to do a live capture, doesn't want
     * to save it to a file, doesn't want information printed for each
     * packet, does want some "-z" statistic, and wants packet counts
     * so they know whether they're seeing any packets?  -q will
     * suppress the information printed for each packet, but it'll
     * also suppress the packet counts.
     */
    if (!ws_isatty(ws_fileno(stderr)))
      print_packet_counts = FALSE;
    else if (print_packet_info && ws_isatty(ws_fileno(stdout)))
      print_packet_counts = FALSE;
    else if (quiet)
      print_packet_counts = FALSE;
    else
      print_packet_counts = TRUE;

    if (print_packet_info) {
      if (!write_preamble(&cfile)) {
        show_print_file_io_error(errno);
        return 2;
      }
    }

    tshark_debug("tshark: performing live capture");
    /*
     * XXX - this returns FALSE if an error occurred, but it also
     * returns FALSE if the capture stops because a time limit
     * was reached (and possibly other limits), so we can't assume
     * it means an error.
     *
     * The capture code is a bit twisty, so it doesn't appear to
     * be an easy fix.  We just ignore the return value for now.
     * Instead, pass on the exit status from the capture child.
     */
    capture();
    exit_status = global_capture_session.fork_child_status;

    if (print_packet_info) {
      if (!write_finale()) {
        err = errno;
        show_print_file_io_error(err);
      }
    }
#else
    /* No - complain. */
    cmdarg_err("This version of TShark was not built with support for capturing packets.");
    return 2;
#endif
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
#ifdef HAVE_EXTCAP
  extcap_cleanup();
#endif

  output_fields_free(output_fields);
  output_fields = NULL;

  return exit_status;
}

/*#define USE_BROKEN_G_MAIN_LOOP*/

#ifdef USE_BROKEN_G_MAIN_LOOP
  GMainLoop *loop;
#else
  gboolean loop_running = FALSE;
#endif
  guint32 packet_count = 0;


typedef struct pipe_input_tag {
  gint             source;
  gpointer         user_data;
  ws_process_id   *child_process;
  pipe_input_cb_t  input_cb;
  guint            pipe_input_id;
#ifdef _WIN32
  GMutex          *callback_running;
#endif
} pipe_input_t;

static pipe_input_t pipe_input;

#ifdef _WIN32
/* The timer has expired, see if there's stuff to read from the pipe,
   if so, do the callback */
static gint
pipe_timer_cb(gpointer data)
{
  HANDLE        handle;
  DWORD         avail        = 0;
  gboolean      result;
  DWORD         childstatus;
  pipe_input_t *pipe_input_p = data;
  gint          iterations   = 0;

  g_mutex_lock (pipe_input_p->callback_running);

  /* try to read data from the pipe only 5 times, to avoid blocking */
  while(iterations < 5) {
    /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: new iteration");*/

    /* Oddly enough although Named pipes don't work on win9x,
       PeekNamedPipe does !!! */
    handle = (HANDLE) _get_osfhandle (pipe_input_p->source);
    result = PeekNamedPipe(handle, NULL, 0, NULL, &avail, NULL);

    /* Get the child process exit status */
    GetExitCodeProcess((HANDLE)*(pipe_input_p->child_process),
                       &childstatus);

    /* If the Peek returned an error, or there are bytes to be read
       or the childwatcher thread has terminated then call the normal
       callback */
    if (!result || avail > 0 || childstatus != STILL_ACTIVE) {

      /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: data avail");*/

      /* And call the real handler */
      if (!pipe_input_p->input_cb(pipe_input_p->source, pipe_input_p->user_data)) {
        g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: input pipe closed, iterations: %u", iterations);
        /* pipe closed, return false so that the timer is stopped */
        g_mutex_unlock (pipe_input_p->callback_running);
        return FALSE;
      }
    }
    else {
      /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: no data avail");*/
      /* No data, stop now */
      break;
    }

    iterations++;
  }

  /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: finished with iterations: %u, new timer", iterations);*/

  g_mutex_unlock (pipe_input_p->callback_running);

  /* we didn't stopped the timer, so let it run */
  return TRUE;
}
#endif


void
pipe_input_set_handler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
{

  pipe_input.source         = source;
  pipe_input.child_process  = child_process;
  pipe_input.user_data      = user_data;
  pipe_input.input_cb       = input_cb;

#ifdef _WIN32
#if GLIB_CHECK_VERSION(2,31,0)
  pipe_input.callback_running = g_malloc(sizeof(GMutex));
  g_mutex_init(pipe_input.callback_running);
#else
  pipe_input.callback_running = g_mutex_new();
#endif
  /* Tricky to use pipes in win9x, as no concept of wait.  NT can
     do this but that doesn't cover all win32 platforms.  GTK can do
     this but doesn't seem to work over processes.  Attempt to do
     something similar here, start a timer and check for data on every
     timeout. */
  /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/
  pipe_input.pipe_input_id = g_timeout_add(200, pipe_timer_cb, &pipe_input);
#endif
}

static const nstime_t *
tshark_get_frame_ts(void *data, guint32 frame_num)
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

static epan_t *
tshark_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = tshark_get_frame_ts;
  epan->get_interface_name = cap_file_get_interface_name;
  epan->get_user_comment = NULL;

  return epan;
}

#ifdef HAVE_LIBPCAP
static gboolean
capture(void)
{
  gboolean          ret;
  guint             i;
  GString          *str;
#ifdef USE_TSHARK_SELECT
  fd_set            readfds;
#endif
#ifndef _WIN32
  struct sigaction  action, oldaction;
#endif

  /* Create new dissection section. */
  epan_free(cfile.epan);
  cfile.epan = tshark_epan_new(&cfile);

#ifdef _WIN32
  /* Catch a CTRL+C event and, if we get it, clean up and exit. */
  SetConsoleCtrlHandler(capture_cleanup, TRUE);
#else /* _WIN32 */
  /* Catch SIGINT and SIGTERM and, if we get either of them,
     clean up and exit.  If SIGHUP isn't being ignored, catch
     it too and, if we get it, clean up and exit.

     We restart any read that was in progress, so that it doesn't
     disrupt reading from the sync pipe.  The signal handler tells
     the capture child to finish; it will report that it finished,
     or will exit abnormally, so  we'll stop reading from the sync
     pipe, pick up the exit status, and quit. */
  memset(&action, 0, sizeof(action));
  action.sa_handler = capture_cleanup;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGHUP, NULL, &oldaction);
  if (oldaction.sa_handler == SIG_DFL)
    sigaction(SIGHUP, &action, NULL);

#ifdef SIGINFO
  /* Catch SIGINFO and, if we get it and we're capturing to a file in
     quiet mode, report the number of packets we've captured.

     Again, restart any read that was in progress, so that it doesn't
     disrupt reading from the sync pipe. */
  action.sa_handler = report_counts_siginfo;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  sigaction(SIGINFO, &action, NULL);
#endif /* SIGINFO */
#endif /* _WIN32 */

  global_capture_session.state = CAPTURE_PREPARING;

  /* Let the user know which interfaces were chosen. */
  for (i = 0; i < global_capture_opts.ifaces->len; i++) {
    interface_options interface_opts;

    interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
    interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
    global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, i);
    g_array_insert_val(global_capture_opts.ifaces, i, interface_opts);
  }
  str = get_iface_list_string(&global_capture_opts, IFLIST_QUOTE_IF_DESCRIPTION);
  if (really_quiet == FALSE)
    fprintf(stderr, "Capturing on %s\n", str->str);
  fflush(stderr);
  g_string_free(str, TRUE);

  ret = sync_pipe_start(&global_capture_opts, &global_capture_session, &global_info_data, NULL);

  if (!ret)
    return FALSE;

  /* the actual capture loop
   *
   * XXX - glib doesn't seem to provide any event based loop handling.
   *
   * XXX - for whatever reason,
   * calling g_main_loop_new() ends up in 100% cpu load.
   *
   * But that doesn't matter: in UNIX we can use select() to find an input
   * source with something to do.
   *
   * But that doesn't matter because we're in a CLI (that doesn't need to
   * update a GUI or something at the same time) so it's OK if we block
   * trying to read from the pipe.
   *
   * So all the stuff in USE_TSHARK_SELECT could be removed unless I'm
   * wrong (but I leave it there in case I am...).
   */

#ifdef USE_TSHARK_SELECT
  FD_ZERO(&readfds);
  FD_SET(pipe_input.source, &readfds);
#endif

  loop_running = TRUE;

  TRY
  {
    while (loop_running)
    {
#ifdef USE_TSHARK_SELECT
      ret = select(pipe_input.source+1, &readfds, NULL, NULL, NULL);

      if (ret == -1)
      {
        fprintf(stderr, "%s: %s\n", "select()", g_strerror(errno));
        return TRUE;
      } else if (ret == 1) {
#endif
        /* Call the real handler */
        if (!pipe_input.input_cb(pipe_input.source, pipe_input.user_data)) {
          g_log(NULL, G_LOG_LEVEL_DEBUG, "input pipe closed");
          return FALSE;
        }
#ifdef USE_TSHARK_SELECT
      }
#endif
    }
  }
  CATCH(OutOfMemoryError) {
    fprintf(stderr,
            "Out Of Memory.\n"
            "\n"
            "Sorry, but TShark has to terminate now.\n"
            "\n"
            "More information and workarounds can be found at\n"
            "https://wiki.wireshark.org/KnownBugs/OutOfMemory\n");
    exit(1);
  }
  ENDTRY;
  return TRUE;
}

/* capture child detected an error */
void
capture_input_error_message(capture_session *cap_session _U_, char *error_msg, char *secondary_error_msg)
{
  cmdarg_err("%s", error_msg);
  cmdarg_err_cont("%s", secondary_error_msg);
}


/* capture child detected an capture filter related error */
void
capture_input_cfilter_error_message(capture_session *cap_session, guint i, char *error_message)
{
  capture_options *capture_opts = cap_session->capture_opts;
  dfilter_t         *rfcode = NULL;
  interface_options  interface_opts;

  g_assert(i < capture_opts->ifaces->len);
  interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);

  if (dfilter_compile(interface_opts.cfilter, &rfcode, NULL) && rfcode != NULL) {
    cmdarg_err(
      "Invalid capture filter \"%s\" for interface '%s'.\n"
      "\n"
      "That string looks like a valid display filter; however, it isn't a valid\n"
      "capture filter (%s).\n"
      "\n"
      "Note that display filters and capture filters don't have the same syntax,\n"
      "so you can't use most display filter expressions as capture filters.\n"
      "\n"
      "See the User's Guide for a description of the capture filter syntax.",
      interface_opts.cfilter, interface_opts.descr, error_message);
    dfilter_free(rfcode);
  } else {
    cmdarg_err(
      "Invalid capture filter \"%s\" for interface '%s'.\n"
      "\n"
      "That string isn't a valid capture filter (%s).\n"
      "See the User's Guide for a description of the capture filter syntax.",
      interface_opts.cfilter, interface_opts.descr, error_message);
  }
}


/* capture child tells us we have a new (or the first) capture file */
gboolean
capture_input_new_file(capture_session *cap_session, gchar *new_file)
{
  capture_options *capture_opts = cap_session->capture_opts;
  capture_file *cf = (capture_file *) cap_session->cf;
  gboolean is_tempfile;
  int      err;

  if (cap_session->state == CAPTURE_PREPARING) {
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture started.");
  }
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "File: \"%s\"", new_file);

  g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

  /* free the old filename */
  if (capture_opts->save_file != NULL) {

    /* we start a new capture file, close the old one (if we had one before) */
    if (cf->state != FILE_CLOSED) {
      if (cf->wth != NULL) {
        wtap_close(cf->wth);
        cf->wth = NULL;
      }
      cf->state = FILE_CLOSED;
    }

    g_free(capture_opts->save_file);
    is_tempfile = FALSE;

    epan_free(cf->epan);
    cf->epan = tshark_epan_new(cf);
  } else {
    /* we didn't had a save_file before, must be a tempfile */
    is_tempfile = TRUE;
  }

  /* save the new filename */
  capture_opts->save_file = g_strdup(new_file);

  /* if we are in real-time mode, open the new file now */
  if (do_dissection) {
    /* this is probably unecessary, but better safe than sorry */
    ((capture_file *)cap_session->cf)->open_type = WTAP_TYPE_AUTO;
    /* Attempt to open the capture file and set up to read from it. */
    switch(cf_open((capture_file *)cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err)) {
    case CF_OK:
      break;
    case CF_ERROR:
      /* Don't unlink (delete) the save file - leave it around,
         for debugging purposes. */
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      return FALSE;
    }
  }

  cap_session->state = CAPTURE_RUNNING;

  return TRUE;
}


/* capture child tells us we have new packets to read */
void
capture_input_new_packets(capture_session *cap_session, int to_read)
{
  gboolean      ret;
  int           err;
  gchar        *err_info;
  gint64        data_offset;
  capture_file *cf = (capture_file *)cap_session->cf;
  gboolean      filtering_tap_listeners;
  guint         tap_flags;

#ifdef SIGINFO
  /*
   * Prevent a SIGINFO handler from writing to the standard error while
   * we're doing so or writing to the standard output; instead, have it
   * just set a flag telling us to print that information when we're done.
   */
  infodelay = TRUE;
#endif /* SIGINFO */

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  if (do_dissection) {
    gboolean create_proto_tree;
    epan_dissect_t *edt;

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

    while (to_read-- && cf->wth) {
      wtap_cleareof(cf->wth);
      ret = wtap_read(cf->wth, &err, &err_info, &data_offset);
      if (ret == FALSE) {
        /* read from file failed, tell the capture child to stop */
        sync_pipe_stop(cap_session);
        wtap_close(cf->wth);
        cf->wth = NULL;
      } else {
        ret = process_packet(cf, edt, data_offset, wtap_phdr(cf->wth),
                             wtap_buf_ptr(cf->wth),
                             tap_flags);
      }
      if (ret != FALSE) {
        /* packet successfully read and gone through the "Read Filter" */
        packet_count++;
      }
    }

    epan_dissect_free(edt);

  } else {
    /*
     * Dumpcap's doing all the work; we're not doing any dissection.
     * Count all the packets it wrote.
     */
    packet_count += to_read;
  }

  if (print_packet_counts) {
      /* We're printing packet counts. */
      if (packet_count != 0) {
        fprintf(stderr, "\r%u ", packet_count);
        /* stderr could be line buffered */
        fflush(stderr);
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

static void
report_counts(void)
{
  if ((print_packet_counts == FALSE) && (really_quiet == FALSE)) {
    /* Report the count only if we aren't printing a packet count
       as packets arrive. */
      fprintf(stderr, "%u packet%s captured\n", packet_count,
            plurality(packet_count, "", "s"));
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


/* capture child detected any packet drops? */
void
capture_input_drops(capture_session *cap_session _U_, guint32 dropped)
{
  if (print_packet_counts) {
    /* We're printing packet counts to stderr.
       Send a newline so that we move to the line after the packet count. */
    fprintf(stderr, "\n");
  }

  if (dropped != 0) {
    /* We're printing packet counts to stderr.
       Send a newline so that we move to the line after the packet count. */
    fprintf(stderr, "%u packet%s dropped\n", dropped, plurality(dropped, "", "s"));
  }
}


/*
 * Capture child closed its side of the pipe, report any error and
 * do the required cleanup.
 */
void
capture_input_closed(capture_session *cap_session, gchar *msg)
{
  capture_file *cf = (capture_file *) cap_session->cf;

  if (msg != NULL)
    fprintf(stderr, "tshark: %s\n", msg);

  report_counts();

  if (cf != NULL && cf->wth != NULL) {
    wtap_close(cf->wth);
    if (cf->is_tempfile) {
      ws_unlink(cf->filename);
    }
  }
#ifdef USE_BROKEN_G_MAIN_LOOP
  /*g_main_loop_quit(loop);*/
  g_main_loop_quit(loop);
#else
  loop_running = FALSE;
#endif
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

     We must return TRUE so that no other handler - such as one that would
     terminate the process - gets called.

     XXX - for some reason, typing ^C to TShark, if you run this in
     a Cygwin console window in at least some versions of Cygwin,
     causes TShark to terminate immediately; this routine gets
     called, but the main loop doesn't get a chance to run and
     exit cleanly, at least if this is compiled with Microsoft Visual
     C++ (i.e., it's a property of the Cygwin console window or Bash;
     it happens if TShark is not built with Cygwin - for all I know,
     building it with Cygwin may make the problem go away). */

  /* tell the capture child to stop */
  sync_pipe_stop(&global_capture_session);

  /* don't stop our own loop already here, otherwise status messages and
   * cleanup wouldn't be done properly. The child will indicate the stop of
   * everything by calling capture_input_closed() later */

  return TRUE;
}
#else
static void
capture_cleanup(int signum _U_)
{
  /* tell the capture child to stop */
  sync_pipe_stop(&global_capture_session);

  /* don't stop our own loop already here, otherwise status messages and
   * cleanup wouldn't be done properly. The child will indicate the stop of
   * everything by calling capture_input_closed() later */
}
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

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
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_dfilter(edt, cf->rfcode);

    if (cf->dfcode)
      epan_dissect_prime_dfilter(edt, cf->dfcode);

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == &fdlocal) {
      ref_frame = fdlocal;
      ref = &ref_frame;
    }

    epan_dissect_run(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdlocal, pd), &fdlocal, NULL);

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
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode) {
      if (dfilter_apply_edt(cf->dfcode, edt)) {
        g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->frames);
      }
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
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

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
    if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary) || output_fields_has_cols(output_fields))
      cinfo = &cf->cinfo;
    else
      cinfo = NULL;

    frame_data_set_before_dissect(fdata, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == fdata) {
      ref_frame = *fdata;
      ref = &ref_frame;
    }

    epan_dissect_run_with_taps(edt, cf->cd_t, phdr, frame_tvbuff_new_buffer(fdata, buf), fdata, cinfo);

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

static int
load_cap_file(capture_file *cf, char *save_file, int out_file_type,
    gboolean out_file_name_res, int max_packet_count, gint64 max_byte_count)
{
  gint         linktype;
  int          snapshot_length;
  wtap_dumper *pdh;
  guint32      framenum;
  int          err;
  gchar       *err_info = NULL;
  gint64       data_offset;
  char        *save_file_string = NULL;
  gboolean     filtering_tap_listeners;
  guint        tap_flags;
  GArray                      *shb_hdrs = NULL;
  wtapng_iface_descriptions_t *idb_inf = NULL;
  GArray                      *nrb_hdrs = NULL;
  struct wtap_pkthdr phdr;
  Buffer       buf;
  epan_dissect_t *edt = NULL;
  char                        *shb_user_appl;

  wtap_phdr_init(&phdr);

  idb_inf = wtap_file_get_idb_info(cf->wth);
#ifdef PCAP_NG_DEFAULT
  if (idb_inf->interface_data->len > 1) {
    linktype = WTAP_ENCAP_PER_PACKET;
  } else {
    linktype = wtap_file_encap(cf->wth);
  }
#else
  linktype = wtap_file_encap(cf->wth);
#endif
  if (save_file != NULL) {
    /* Get a string that describes what we're writing to */
    save_file_string = output_file_description(save_file);

    /* Set up to write to the capture file. */
    snapshot_length = wtap_snapshot_length(cf->wth);
    if (snapshot_length == 0) {
      /* Snapshot length of input file not known. */
      snapshot_length = WTAP_MAX_PACKET_SIZE;
    }
    tshark_debug("tshark: snapshot_length = %d", snapshot_length);

    shb_hdrs = wtap_file_get_shb_for_new_file(cf->wth);
    nrb_hdrs = wtap_file_get_nrb_for_new_file(cf->wth);

    /* If we don't have an application name add Tshark */
    if (wtap_block_get_string_option_value(g_array_index(shb_hdrs, wtap_block_t, 0), OPT_SHB_USERAPPL, &shb_user_appl) != WTAP_OPTTYPE_SUCCESS) {
        /* this is free'd by wtap_block_free() later */
        wtap_block_add_string_option_format(g_array_index(shb_hdrs, wtap_block_t, 0), OPT_SHB_USERAPPL, "TShark (Wireshark) %s", get_ws_vcs_version_info());
    }

    if (linktype != WTAP_ENCAP_PER_PACKET &&
        out_file_type == WTAP_FILE_TYPE_SUBTYPE_PCAP) {
        tshark_debug("tshark: writing PCAP format to %s", save_file);
        if (strcmp(save_file, "-") == 0) {
          /* Write to the standard output. */
          pdh = wtap_dump_open_stdout(out_file_type, linktype,
              snapshot_length, FALSE /* compressed */, &err);
        } else {
          pdh = wtap_dump_open(save_file, out_file_type, linktype,
              snapshot_length, FALSE /* compressed */, &err);
        }
    }
    else {
        tshark_debug("tshark: writing format type %d, to %s", out_file_type, save_file);
        if (strcmp(save_file, "-") == 0) {
          /* Write to the standard output. */
          pdh = wtap_dump_open_stdout_ng(out_file_type, linktype,
              snapshot_length, FALSE /* compressed */, shb_hdrs, idb_inf, nrb_hdrs, &err);
        } else {
          pdh = wtap_dump_open_ng(save_file, out_file_type, linktype,
              snapshot_length, FALSE /* compressed */, shb_hdrs, idb_inf, nrb_hdrs, &err);
        }
    }

    g_free(idb_inf);
    idb_inf = NULL;

    if (pdh == NULL) {
      /* We couldn't set up to write to the capture file. */
      switch (err) {

      case WTAP_ERR_UNWRITABLE_FILE_TYPE:
        cmdarg_err("Capture files can't be written in that format.");
        break;

      case WTAP_ERR_UNWRITABLE_ENCAP:
      case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
        cmdarg_err("The capture file being read can't be written as a "
          "\"%s\" file.", wtap_file_type_subtype_short_string(out_file_type));
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
    g_free(idb_inf);
    idb_inf = NULL;
    pdh = NULL;
  }

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  if (perform_two_pass_analysis) {
    frame_data *fdata;

    tshark_debug("tshark: perform_two_pass_analysis, do_dissection=%s", do_dissection ? "TRUE" : "FALSE");

    /* Allocate a frame_data_sequence for all the frames. */
    cf->frames = new_frame_data_sequence();

    if (do_dissection) {
       gboolean create_proto_tree = FALSE;

      /* If we're going to be applying a filter, we'll need to
         create a protocol tree against which to apply the filter. */
      if (cf->rfcode || cf->dfcode)
        create_proto_tree = TRUE;

      tshark_debug("tshark: create_proto_tree = %s", create_proto_tree ? "TRUE" : "FALSE");

      /* We're not going to display the protocol tree on this pass,
         so it's not going to be "visible". */
      edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
    }

    tshark_debug("tshark: reading records for first pass");
    while (wtap_read(cf->wth, &err, &err_info, &data_offset)) {
      if (process_packet_first_pass(cf, edt, data_offset, wtap_phdr(cf->wth),
                         wtap_buf_ptr(cf->wth))) {
        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
          tshark_debug("tshark: max_packet_count (%d) or max_byte_count (%" G_GINT64_MODIFIER "d/%" G_GINT64_MODIFIER "d) reached",
                        max_packet_count, data_offset, max_byte_count);
          err = 0; /* This is not an error */
          break;
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->wth);

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    prev_dis = NULL;
    prev_cap = NULL;
    ws_buffer_init(&buf, 1500);

    tshark_debug("tshark: done with first pass");

    if (do_dissection) {
      gboolean create_proto_tree;

      if (cf->dfcode || print_details || filtering_tap_listeners ||
         (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
           create_proto_tree = TRUE;
      else
           create_proto_tree = FALSE;

      tshark_debug("tshark: create_proto_tree = %s", create_proto_tree ? "TRUE" : "FALSE");

      /* The protocol tree will be "visible", i.e., printed, only if we're
         printing packet details, which is true if we're printing stuff
         ("print_packet_info" is true) and we're in verbose mode
         ("packet_details" is true). */
      edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
    }

    for (framenum = 1; err == 0 && framenum <= cf->count; framenum++) {
      fdata = frame_data_sequence_find(cf->frames, framenum);
      if (wtap_seek_read(cf->wth, fdata->file_off, &phdr, &buf, &err,
                         &err_info)) {
        tshark_debug("tshark: invoking process_packet_second_pass() for frame #%d", framenum);
        if (process_packet_second_pass(cf, edt, fdata, &phdr, &buf,
                                       tap_flags)) {
          /* Either there's no read filtering or this packet passed the
             filter, so, if we're writing to a capture file, write
             this packet out. */
          if (pdh != NULL) {
            tshark_debug("tshark: writing packet #%d to outfile", framenum);
            if (!wtap_dump(pdh, &phdr, ws_buffer_start_ptr(&buf), &err, &err_info)) {
              /* Error writing to a capture file */
              tshark_debug("tshark: error writing to a capture file (%d)", err);
              switch (err) {

              case WTAP_ERR_UNWRITABLE_ENCAP:
                /*
                 * This is a problem with the particular frame we're writing
                 * and the file type and subtype we're writing; note that,
                 * and report the frame number and file type/subtype.
                 *
                 * XXX - framenum is not necessarily the frame number in
                 * the input file if there was a read filter.
                 */
                fprintf(stderr,
                        "Frame %u of \"%s\" has a network type that can't be saved in a \"%s\" file.\n",
                        framenum, cf->filename,
                        wtap_file_type_subtype_short_string(out_file_type));
                break;

              case WTAP_ERR_PACKET_TOO_LARGE:
                /*
                 * This is a problem with the particular frame we're writing
                 * and the file type and subtype we're writing; note that,
                 * and report the frame number and file type/subtype.
                 *
                 * XXX - framenum is not necessarily the frame number in
                 * the input file if there was a read filter.
                 */
                fprintf(stderr,
                        "Frame %u of \"%s\" is too large for a \"%s\" file.\n",
                        framenum, cf->filename,
                        wtap_file_type_subtype_short_string(out_file_type));
                break;

              case WTAP_ERR_UNWRITABLE_REC_TYPE:
                /*
                 * This is a problem with the particular record we're writing
                 * and the file type and subtype we're writing; note that,
                 * and report the record number and file type/subtype.
                 *
                 * XXX - framenum is not necessarily the record number in
                 * the input file if there was a read filter.
                 */
                fprintf(stderr,
                        "Record %u of \"%s\" has a record type that can't be saved in a \"%s\" file.\n",
                        framenum, cf->filename,
                        wtap_file_type_subtype_short_string(out_file_type));
                break;

              case WTAP_ERR_UNWRITABLE_REC_DATA:
                /*
                 * This is a problem with the particular record we're writing
                 * and the file type and subtype we're writing; note that,
                 * and report the record number and file type/subtype.
                 *
                 * XXX - framenum is not necessarily the record number in
                 * the input file if there was a read filter.
                 */
                fprintf(stderr,
                        "Record %u of \"%s\" has data that can't be saved in a \"%s\" file.\n(%s)\n",
                        framenum, cf->filename,
                        wtap_file_type_subtype_short_string(out_file_type),
                        err_info != NULL ? err_info : "no information supplied");
                g_free(err_info);
                break;

              default:
                show_capture_file_io_error(save_file, err, FALSE);
                break;
              }
              wtap_dump_close(pdh, &err);
              wtap_block_array_free(shb_hdrs);
              wtap_block_array_free(nrb_hdrs);
              exit(2);
            }
          }
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    ws_buffer_free(&buf);

    tshark_debug("tshark: done with second pass");
  }
  else {
    /* !perform_two_pass_analysis */
    framenum = 0;

    tshark_debug("tshark: perform one pass analysis, do_dissection=%s", do_dissection ? "TRUE" : "FALSE");

    if (do_dissection) {
      gboolean create_proto_tree;

      if (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
          (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
        create_proto_tree = TRUE;
      else
        create_proto_tree = FALSE;

      tshark_debug("tshark: create_proto_tree = %s", create_proto_tree ? "TRUE" : "FALSE");

      /* The protocol tree will be "visible", i.e., printed, only if we're
         printing packet details, which is true if we're printing stuff
         ("print_packet_info" is true) and we're in verbose mode
         ("packet_details" is true). */
      edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
    }

    while (wtap_read(cf->wth, &err, &err_info, &data_offset)) {
      framenum++;

      tshark_debug("tshark: processing packet #%d", framenum);

      if (process_packet(cf, edt, data_offset, wtap_phdr(cf->wth),
                         wtap_buf_ptr(cf->wth),
                         tap_flags)) {
        /* Either there's no read filtering or this packet passed the
           filter, so, if we're writing to a capture file, write
           this packet out. */
        if (pdh != NULL) {
          tshark_debug("tshark: writing packet #%d to outfile", framenum);
          if (!wtap_dump(pdh, wtap_phdr(cf->wth), wtap_buf_ptr(cf->wth), &err, &err_info)) {
            /* Error writing to a capture file */
            tshark_debug("tshark: error writing to a capture file (%d)", err);
            switch (err) {

            case WTAP_ERR_UNWRITABLE_ENCAP:
              /*
               * This is a problem with the particular frame we're writing
               * and the file type and subtype we're writing; note that,
               * and report the frame number and file type/subtype.
               */
              fprintf(stderr,
                      "Frame %u of \"%s\" has a network type that can't be saved in a \"%s\" file.\n",
                      framenum, cf->filename,
                      wtap_file_type_subtype_short_string(out_file_type));
              break;

            case WTAP_ERR_PACKET_TOO_LARGE:
              /*
               * This is a problem with the particular frame we're writing
               * and the file type and subtype we're writing; note that,
               * and report the frame number and file type/subtype.
               */
              fprintf(stderr,
                      "Frame %u of \"%s\" is too large for a \"%s\" file.\n",
                      framenum, cf->filename,
                      wtap_file_type_subtype_short_string(out_file_type));
              break;

            case WTAP_ERR_UNWRITABLE_REC_TYPE:
              /*
               * This is a problem with the particular record we're writing
               * and the file type and subtype we're writing; note that,
               * and report the record number and file type/subtype.
               */
              fprintf(stderr,
                      "Record %u of \"%s\" has a record type that can't be saved in a \"%s\" file.\n",
                      framenum, cf->filename,
                      wtap_file_type_subtype_short_string(out_file_type));
              break;

            case WTAP_ERR_UNWRITABLE_REC_DATA:
              /*
               * This is a problem with the particular record we're writing
               * and the file type and subtype we're writing; note that,
               * and report the record number and file type/subtype.
               */
              fprintf(stderr,
                      "Record %u of \"%s\" has data that can't be saved in a \"%s\" file.\n(%s)\n",
                      framenum, cf->filename,
                      wtap_file_type_subtype_short_string(out_file_type),
                      err_info != NULL ? err_info : "no information supplied");
              g_free(err_info);
              break;

            default:
              show_capture_file_io_error(save_file, err, FALSE);
              break;
            }
            wtap_dump_close(pdh, &err);
            wtap_block_array_free(shb_hdrs);
            wtap_block_array_free(nrb_hdrs);
            exit(2);
          }
        }
      }
      /* Stop reading if we have the maximum number of packets;
       * When the -c option has not been used, max_packet_count
       * starts at 0, which practically means, never stop reading.
       * (unless we roll over max_packet_count ?)
       */
      if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
        tshark_debug("tshark: max_packet_count (%d) or max_byte_count (%" G_GINT64_MODIFIER "d/%" G_GINT64_MODIFIER "d) reached",
                      max_packet_count, data_offset, max_byte_count);
        err = 0; /* This is not an error */
        break;
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }
  }

  wtap_phdr_cleanup(&phdr);

  if (err != 0) {
    tshark_debug("tshark: something failed along the line (%d)", err);
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
      ws_statb64 stat_stdout, stat_stderr;

      if (ws_fstat64(1, &stat_stdout) == 0 && ws_fstat64(2, &stat_stderr) == 0) {
        if (stat_stdout.st_dev == stat_stderr.st_dev &&
            stat_stdout.st_ino == stat_stderr.st_ino) {
          fflush(stdout);
          fprintf(stderr, "\n");
        }
      }
    }
#endif
    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
      cmdarg_err("The file \"%s\" contains record data that TShark doesn't support.\n(%s)",
                 cf->filename,
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_SHORT_READ:
      cmdarg_err("The file \"%s\" appears to have been cut short in the middle of a packet.",
                 cf->filename);
      break;

    case WTAP_ERR_BAD_FILE:
      cmdarg_err("The file \"%s\" appears to be damaged or corrupt.\n(%s)",
                 cf->filename,
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_DECOMPRESS:
      cmdarg_err("The compressed file \"%s\" appears to be damaged or corrupt.\n"
                 "(%s)", cf->filename,
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    default:
      cmdarg_err("An error occurred while reading the file \"%s\": %s.",
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
      if (pdh && out_file_name_res) {
        if (!wtap_dump_set_addrinfo_list(pdh, get_addrinfo_list())) {
          cmdarg_err("The file format \"%s\" doesn't support name resolution information.",
                     wtap_file_type_subtype_short_string(out_file_type));
        }
      }
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

  g_free(save_file_string);
  wtap_block_array_free(shb_hdrs);
  wtap_block_array_free(nrb_hdrs);

  return err;
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset, struct wtap_pkthdr *whdr,
               const guchar *pd, guint tap_flags)
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
    if (print_packet_info && (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name))
      /* Grab any resolved addresses */
      host_name_lookup_process();

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

    epan_dissect_run_with_taps(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdata, pd), &fdata, cinfo);

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
    return print_preamble(print_stream, cf->filename, get_ws_vcs_version_info());

  case WRITE_XML:
    if (print_details)
      write_pdml_preamble(stdout, cf->filename);
    else
      write_psml_preamble(&cf->cinfo, stdout);
    return !ferror(stdout);

  case WRITE_FIELDS:
    write_fields_preamble(output_fields, stdout);
    return !ferror(stdout);

  case WRITE_JSON:
    write_json_preamble(stdout);
    return !ferror(stdout);

  case WRITE_EK:
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
  col_item_t* col_item;

  line_bufp = get_line_buf(256);
  buf_offset = 0;
  *line_bufp = '\0';
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    col_item = &cf->cinfo.columns[i];
    /* Skip columns not marked as visible. */
    if (!get_column_visible(i))
      continue;
    switch (col_item->col_fmt) {
    case COL_NUMBER:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 5)
        column_len = 5;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_CLS_TIME:
    case COL_REL_TIME:
    case COL_ABS_TIME:
    case COL_ABS_YMD_TIME:  /* XXX - wider */
    case COL_ABS_YDOY_TIME: /* XXX - wider */
    case COL_UTC_TIME:
    case COL_UTC_YMD_TIME:  /* XXX - wider */
    case COL_UTC_YDOY_TIME: /* XXX - wider */
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 10)
        column_len = 10;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
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
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
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
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string_spaces(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    default:
      column_len = strlen(col_item->col_data);
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string(line_bufp + buf_offset, col_item->col_data, column_len);
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
       * them with a UTF-8 right arrow; if we printed a network
       * destination and are printing a network source of the same
       * type next, separate them with a UTF-8 left arrow;
       * otherwise separate them with a space.
       *
       * We add enough space to the buffer for " \xe2\x86\x90 "
       * or " \xe2\x86\x92 ", even if we're only adding " ".
       */
      line_bufp = get_line_buf(buf_offset + 5);
      switch (col_item->col_fmt) {

      case COL_DEF_SRC:
      case COL_RES_SRC:
      case COL_UNRES_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DST:
        case COL_RES_DST:
        case COL_UNRES_DST:
          put_string(line_bufp + buf_offset, " " UTF8_RIGHTWARDS_ARROW " ", 5);
          buf_offset += 5;
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
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_DST:
        case COL_RES_DL_DST:
        case COL_UNRES_DL_DST:
          put_string(line_bufp + buf_offset, " " UTF8_RIGHTWARDS_ARROW " ", 5);
          buf_offset += 5;
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
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_DST:
        case COL_RES_NET_DST:
        case COL_UNRES_NET_DST:
          put_string(line_bufp + buf_offset, " " UTF8_RIGHTWARDS_ARROW " ", 5);
          buf_offset += 5;
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
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_SRC:
        case COL_RES_SRC:
        case COL_UNRES_SRC:
          put_string(line_bufp + buf_offset, " " UTF8_LEFTWARDS_ARROW " ", 5);
          buf_offset += 5;
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
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_SRC:
        case COL_RES_DL_SRC:
        case COL_UNRES_DL_SRC:
          put_string(line_bufp + buf_offset, " " UTF8_LEFTWARDS_ARROW " ", 5);
          buf_offset += 5;
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
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_SRC:
        case COL_RES_NET_SRC:
        case COL_UNRES_NET_SRC:
          put_string(line_bufp + buf_offset, " " UTF8_LEFTWARDS_ARROW " ", 5);
          buf_offset += 5;
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
        write_psml_columns(edt, stdout);
        return !ferror(stdout);
      case WRITE_FIELDS: /*No non-verbose "fields" format */
      case WRITE_JSON:
      case WRITE_EK:
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

      if (!proto_tree_print(&print_args, edt, output_only_tables, print_stream))
        return FALSE;
      if (!print_hex) {
        if (!print_line(print_stream, 0, separator))
          return FALSE;
      }
      break;

    case WRITE_XML:
      write_pdml_proto_tree(output_fields, protocolfilter, edt, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_FIELDS:
      write_fields_proto_tree(output_fields, edt, &cf->cinfo, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_JSON:
      print_args.print_hex = print_hex;
      write_json_proto_tree(output_fields, &print_args, protocolfilter, edt, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_EK:
      print_args.print_hex = print_hex;
      write_ek_proto_tree(output_fields, &print_args, protocolfilter, edt, stdout);
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

  case WRITE_JSON:
    write_json_finale(stdout);
    return !ferror(stdout);

  case WRITE_EK:
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap  *wth;
  gchar *err_info;
  char   err_msg[2048+1];

  wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = tshark_epan_new(cf);

  cf->wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t      = wtap_file_type_subtype(cf->wth);
  cf->open_type = type;
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
  ref = NULL;
  prev_dis = NULL;
  prev_cap = NULL;

  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);

  return CF_OK;

fail:
  g_snprintf(err_msg, sizeof err_msg,
             cf_open_error_message(*err, err_info, FALSE, cf->cd_t), fname);
  cmdarg_err("%s", err_msg);
  return CF_ERROR;
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

    case WTAP_ERR_NOT_REGULAR_FILE:
      errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
      break;

    case WTAP_ERR_RANDOM_OPEN_PIPE:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" is a pipe or FIFO; TShark can't read pipe or FIFO files in two-pass mode.";
      break;

    case WTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" isn't a capture file in a format TShark understands.";
      break;

    case WTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" contains record data that TShark doesn't support.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
                 "written to a pipe.", wtap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_UNWRITABLE_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      errmsg = "TShark doesn't support writing capture files in that format.";
      break;

    case WTAP_ERR_UNWRITABLE_ENCAP:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "TShark can't save this capture as a \"%s\" file.",
                 wtap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
      if (for_writing) {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                   "TShark can't save this capture as a \"%s\" file.",
                   wtap_file_type_subtype_short_string(file_type));
        errmsg = errmsg_errno;
      } else
        errmsg = "The file \"%s\" is a capture for a network type that TShark doesn't support.";
      break;

    case WTAP_ERR_BAD_FILE:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
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

    case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
      errmsg = "This file type cannot be written as a compressed file.";
      break;

    case WTAP_ERR_DECOMPRESS:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
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
 * Open/create errors are reported with an console message in TShark.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "tshark: ");
  fprintf(stderr, file_open_error_message(err, for_writing), filename);
  fprintf(stderr, "\n");
}

/*
 * General errors are reported with an console message in TShark.
 */
static void
failure_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "tshark: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in TShark.
 */
static void
read_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in TShark.
 */
static void
write_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
