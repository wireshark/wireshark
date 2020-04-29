/* capinfos.c
 * Reports capture file information including # of packets, duration, others
 *
 * Copyright 2004 Ian Schorr
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * 2009-09-19: jyoung
 *
 * New capinfos features
 *
 * Continue processing additional files after
 * a wiretap open failure.  The new -C option
 * reverts to capinfos' original behavior which
 * is to cancel any further file processing at
 * first file open failure.
 *
 * Change the behavior of how the default display
 * of all infos is initiated.  This gets rid of a
 * special post getopt() argument count test.
 *
 * Add new table output format (with related options)
 * This feature allows outputting the various infos
 * into a tab delimited text file, or to a comma
 * separated variables file (*.csv) instead of the
 * original "long" format.
 *
 * 2011-04-05: wmeier
 * behaviour changed: Upon exit capinfos will return
 *  an error status if an error occurred at any
 *  point during "continuous" file processing.
 *  (Previously a success status was always
 *   returned if the -C option was not used).
 *

 */


#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>
#include <errno.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <glib.h>

#include <wiretap/wtap.h>

#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <cli_main.h>
#include <version_info.h>
#include <wiretap/wtap_opttypes.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>
#include <wsutil/str_util.h>
#include <wsutil/file_util.h>

#include <wsutil/wsgcrypt.h>

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include "ui/failure_message.h"

#define INVALID_OPTION 1
#define BAD_FLAG 1

/*
 * By default capinfos now continues processing
 * the next filename if and when wiretap detects
 * a problem opening or reading a file.
 * Use the '-C' option to revert back to original
 * capinfos behavior which is to abort any
 * additional file processing at the first file
 * open or read failure.
 */

static gboolean stop_after_failure = FALSE;

/*
 * table report variables
 */

static gboolean long_report        = TRUE;  /* By default generate long report       */
static gchar table_report_header   = TRUE;  /* Generate column header by default     */
static gchar field_separator       = '\t';  /* Use TAB as field separator by default */
static gchar quote_char            = '\0';  /* Do NOT quote fields by default        */
static gboolean machine_readable   = FALSE; /* Display machine-readable numbers      */

/*
 * capinfos has the ability to report on a number of
 * various characteristics ("infos") for each input file.
 *
 * By default reporting of all info fields is enabled.
 *
 * Optionally the reporting of any specific info field
 * or combination of info fields can be enabled with
 * individual options.
 */

static gboolean report_all_infos   = TRUE;  /* Report all infos           */

static gboolean cap_file_type      = TRUE;  /* Report capture type        */
static gboolean cap_file_encap     = TRUE;  /* Report encapsulation       */
static gboolean cap_snaplen        = TRUE;  /* Packet size limit (snaplen)*/
static gboolean cap_packet_count   = TRUE;  /* Report packet count        */
static gboolean cap_file_size      = TRUE;  /* Report file size           */
static gboolean cap_comment        = TRUE;  /* Display the capture comment */
static gboolean cap_file_more_info = TRUE;  /* Report more file info      */
static gboolean cap_file_idb       = TRUE;  /* Report Interface info      */
static gboolean cap_file_nrb       = TRUE;  /* Report Name Resolution Block info      */
static gboolean cap_file_dsb       = TRUE;  /* Report Decryption Secrets Block info      */

static gboolean cap_data_size      = TRUE;  /* Report packet byte size    */
static gboolean cap_duration       = TRUE;  /* Report capture duration    */
static gboolean cap_start_time     = TRUE;  /* Report capture start time  */
static gboolean cap_end_time       = TRUE;  /* Report capture end time    */
static gboolean time_as_secs       = FALSE; /* Report time values as raw seconds */

static gboolean cap_data_rate_byte = TRUE;  /* Report data rate bytes/sec */
static gboolean cap_data_rate_bit  = TRUE;  /* Report data rate bites/sec */
static gboolean cap_packet_size    = TRUE;  /* Report average packet size */
static gboolean cap_packet_rate    = TRUE;  /* Report average packet rate */
static gboolean cap_order          = TRUE;  /* Report if packets are in chronological order (True/False) */

static gboolean cap_file_hashes    = TRUE;  /* Calculate file hashes */

// Strongest to weakest
#define HASH_SIZE_SHA256 32
#define HASH_SIZE_RMD160 20
#define HASH_SIZE_SHA1   20

#define HASH_STR_SIZE (65) /* Max hash size * 2 + '\0' */
#define HASH_BUF_SIZE (1024 * 1024)


static gchar file_sha256[HASH_STR_SIZE];
static gchar file_rmd160[HASH_STR_SIZE];
static gchar file_sha1[HASH_STR_SIZE];

static guint num_ipv4_addresses;
static guint num_ipv6_addresses;
static guint num_decryption_secrets;

/*
 * If we have at least two packets with time stamps, and they're not in
 * order - i.e., the later packet has a time stamp older than the earlier
 * packet - the time stamps are known not to be in order.
 *
 * If every packet has a time stamp, and they're all in order, the time
 * stamp is known to be in order.
 *
 * Otherwise, we have no idea.
 */
typedef enum {
  IN_ORDER,
  NOT_IN_ORDER,
  ORDER_UNKNOWN
} order_t;

typedef struct _capture_info {
  const char           *filename;
  guint16               file_type;
  wtap_compression_type compression_type;
  int                   file_encap;
  int                   file_tsprec;
  gint64                filesize;
  wtap_block_t          shb;
  guint64               packet_bytes;
  gboolean              times_known;
  nstime_t              start_time;
  int                   start_time_tsprec;
  nstime_t              stop_time;
  int                   stop_time_tsprec;
  guint32               packet_count;
  gboolean              snap_set;                 /* If set in capture file header      */
  guint32               snaplen;                  /* value from the capture file header */
  guint32               snaplen_min_inferred;     /* If caplen < len for 1 or more rcds */
  guint32               snaplen_max_inferred;     /*  ...                               */
  gboolean              drops_known;
  guint32               drop_count;

  nstime_t              duration;
  int                   duration_tsprec;
  double                packet_rate;
  double                packet_size;
  double                data_rate;                /* in bytes/s */
  gboolean              know_order;
  order_t               order;

  int                  *encap_counts;             /* array of per_packet encap counts; array has one entry per wtap_encap type */

  guint                 num_interfaces;           /* number of IDBs, and thus size of interface_packet_counts array */
  GArray               *interface_packet_counts;  /* array of per_packet interface_id counts; one entry per file IDB */
  guint32               pkt_interface_id_unknown; /* counts if packet interface_id didn't match a known one */
  GArray               *idb_info_strings;         /* array of IDB info strings */
} capture_info;

static char *decimal_point;

static void
enable_all_infos(void)
{
  report_all_infos   = TRUE;

  cap_file_type      = TRUE;
  cap_file_encap     = TRUE;
  cap_snaplen        = TRUE;
  cap_packet_count   = TRUE;
  cap_file_size      = TRUE;
  cap_comment        = TRUE;
  cap_file_more_info = TRUE;
  cap_file_idb       = TRUE;
  cap_file_nrb       = TRUE;
  cap_file_dsb       = TRUE;

  cap_data_size      = TRUE;
  cap_duration       = TRUE;
  cap_start_time     = TRUE;
  cap_end_time       = TRUE;
  cap_order          = TRUE;

  cap_data_rate_byte = TRUE;
  cap_data_rate_bit  = TRUE;
  cap_packet_size    = TRUE;
  cap_packet_rate    = TRUE;

  cap_file_hashes    = TRUE;
}

static void
disable_all_infos(void)
{
  report_all_infos   = FALSE;

  cap_file_type      = FALSE;
  cap_file_encap     = FALSE;
  cap_snaplen        = FALSE;
  cap_packet_count   = FALSE;
  cap_file_size      = FALSE;
  cap_comment        = FALSE;
  cap_file_more_info = FALSE;
  cap_file_idb       = FALSE;
  cap_file_nrb       = FALSE;
  cap_file_dsb       = FALSE;

  cap_data_size      = FALSE;
  cap_duration       = FALSE;
  cap_start_time     = FALSE;
  cap_end_time       = FALSE;
  cap_order          = FALSE;

  cap_data_rate_byte = FALSE;
  cap_data_rate_bit  = FALSE;
  cap_packet_size    = FALSE;
  cap_packet_rate    = FALSE;

  cap_file_hashes    = FALSE;
}

static const gchar *
order_string(order_t order)
{
  switch (order) {

    case IN_ORDER:
      return "True";

    case NOT_IN_ORDER:
      return "False";

    case ORDER_UNKNOWN:
      return "Unknown";

    default:
      return "???";  /* "cannot happen" (the next step is "Profit!") */
  }
}

static gchar *
absolute_time_string(nstime_t *timer, int tsprecision, capture_info *cf_info)
{
  /*
   *    https://web.archive.org/web/20120513133703/http://www.idrbt.ac.in/publications/workingpapers/Working%20Paper%20No.%209.pdf
   *
   * says:
   *
   *    A 64-bit Unix time would be safe for the indefinite future, as
   *    this variable would not overflow until 2**63 or
   *    9,223,372,036,854,775,808 (over nine quintillion) seconds
   *    after the beginning of the Unix epoch - corresponding to
   *    GMT 15:30:08, Sunday, 4th December, 292,277,026,596.
   *
   * So, if we're displaying the time as YYYY-MM-DD HH:MM:SS.SSSSSSSSS,
   * we'll have the buffer be large enouth for a date of the format
   * 292277026596-MM-DD HH:MM:SS.SSSSSSSSS, which is the biggest value
   * you'll get with a 64-bit time_t and a nanosecond-resolution
   * fraction-of-a-second.
   *
   * That's 12+1+2+1+2+1+2+1+2+2+2+1+9+1, including the terminating
   * \0, or 39.
   *
   * If we're displaying the time as epoch time, and the time is
   * unsigned, 2^64-1 is 18446744073709551615, so the buffer has
   * to be big enough for 18446744073709551615.999999999.  That's
   * 20+1+9+1, including the terminating '\0', or 31.  If it's
   * signed, 2^63 is 9223372036854775808, so the buffer has to
   * be big enough for -9223372036854775808.999999999, which is
   * again 20+1+9+1, or 31.
   *
   * So we go with 39.
   */
  static gchar time_string_buf[39];
  struct tm *ti_tm;

  if (cf_info->times_known && cf_info->packet_count > 0) {
    if (time_as_secs) {
      switch (tsprecision) {

      case WTAP_TSPREC_SEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%"G_GINT64_MODIFIER"d",
                   (gint64)timer->secs);
        break;

      case WTAP_TSPREC_DSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%"G_GINT64_MODIFIER"d%s%01d",
                   (gint64)timer->secs,
                   decimal_point,
                   timer->nsecs / 100000000);
        break;

      case WTAP_TSPREC_CSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%"G_GINT64_MODIFIER"d%s%02d",
                   (gint64)timer->secs,
                   decimal_point,
                   timer->nsecs / 10000000);
        break;

      case WTAP_TSPREC_MSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%"G_GINT64_MODIFIER"d%s%03d",
                   (gint64)timer->secs,
                   decimal_point,
                   timer->nsecs / 1000000);
        break;

      case WTAP_TSPREC_USEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%"G_GINT64_MODIFIER"d%s%06d",
                   (gint64)timer->secs,
                   decimal_point,
                   timer->nsecs / 1000);
        break;

      case WTAP_TSPREC_NSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%"G_GINT64_MODIFIER"d%s%09d",
                   (gint64)timer->secs,
                   decimal_point,
                   timer->nsecs);
        break;

      default:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "Unknown precision %d",
                   tsprecision);
        break;
      }
      return time_string_buf;
    } else {
      ti_tm = localtime(&timer->secs);
      if (ti_tm == NULL) {
        g_snprintf(time_string_buf, sizeof time_string_buf, "Not representable");
        return time_string_buf;
      }
      switch (tsprecision) {

      case WTAP_TSPREC_SEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%04d-%02d-%02d %02d:%02d:%02d",
                   ti_tm->tm_year + 1900,
                   ti_tm->tm_mon + 1,
                   ti_tm->tm_mday,
                   ti_tm->tm_hour,
                   ti_tm->tm_min,
                   ti_tm->tm_sec);
        break;

      case WTAP_TSPREC_DSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%04d-%02d-%02d %02d:%02d:%02d%s%01d",
                   ti_tm->tm_year + 1900,
                   ti_tm->tm_mon + 1,
                   ti_tm->tm_mday,
                   ti_tm->tm_hour,
                   ti_tm->tm_min,
                   ti_tm->tm_sec,
                   decimal_point,
                   timer->nsecs / 100000000);
        break;

      case WTAP_TSPREC_CSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%04d-%02d-%02d %02d:%02d:%02d%s%02d",
                   ti_tm->tm_year + 1900,
                   ti_tm->tm_mon + 1,
                   ti_tm->tm_mday,
                   ti_tm->tm_hour,
                   ti_tm->tm_min,
                   ti_tm->tm_sec,
                   decimal_point,
                   timer->nsecs / 10000000);
        break;

      case WTAP_TSPREC_MSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%04d-%02d-%02d %02d:%02d:%02d%s%03d",
                   ti_tm->tm_year + 1900,
                   ti_tm->tm_mon + 1,
                   ti_tm->tm_mday,
                   ti_tm->tm_hour,
                   ti_tm->tm_min,
                   ti_tm->tm_sec,
                   decimal_point,
                   timer->nsecs / 1000000);
        break;

      case WTAP_TSPREC_USEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%04d-%02d-%02d %02d:%02d:%02d%s%06d",
                   ti_tm->tm_year + 1900,
                   ti_tm->tm_mon + 1,
                   ti_tm->tm_mday,
                   ti_tm->tm_hour,
                   ti_tm->tm_min,
                   ti_tm->tm_sec,
                   decimal_point,
                   timer->nsecs / 1000);
        break;

      case WTAP_TSPREC_NSEC:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "%04d-%02d-%02d %02d:%02d:%02d%s%09d",
                   ti_tm->tm_year + 1900,
                   ti_tm->tm_mon + 1,
                   ti_tm->tm_mday,
                   ti_tm->tm_hour,
                   ti_tm->tm_min,
                   ti_tm->tm_sec,
                   decimal_point,
                   timer->nsecs);
        break;

      default:
        g_snprintf(time_string_buf, sizeof time_string_buf,
                   "Unknown precision %d",
                   tsprecision);
        break;
      }
      return time_string_buf;
    }
  }

  g_snprintf(time_string_buf, sizeof time_string_buf, "n/a");
  return time_string_buf;
}

static gchar *
relative_time_string(nstime_t *timer, int tsprecision, capture_info *cf_info, gboolean want_seconds)
{
  const gchar  *second = want_seconds ? " second" : "";
  const gchar  *plural = want_seconds ? "s" : "";
  /*
   * If we're displaying the time as epoch time, and the time is
   * unsigned, 2^64-1 is 18446744073709551615, so the buffer has
   * to be big enough for "18446744073709551615.999999999 seconds".
   * That's 20+1+9+1+7+1, including the terminating '\0', or 39.
   * If it'ssigned, 2^63 is 9223372036854775808, so the buffer has to
   * be big enough for "-9223372036854775808.999999999 seconds",
   * which is again 20+1+9+1+7+1, or 39.
   */
  static gchar  time_string_buf[39];

  if (cf_info->times_known && cf_info->packet_count > 0) {
    switch (tsprecision) {

    case WTAP_TSPREC_SEC:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "%"G_GINT64_MODIFIER"d%s%s",
                 (gint64)timer->secs,
                 second,
                 timer->secs == 1 ? "" : plural);
      break;

    case WTAP_TSPREC_DSEC:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "%"G_GINT64_MODIFIER"d%s%01d%s%s",
                 (gint64)timer->secs,
                 decimal_point,
                 timer->nsecs / 100000000,
                 second,
                 (timer->secs == 1 && timer->nsecs == 0) ? "" : plural);
      break;

    case WTAP_TSPREC_CSEC:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "%"G_GINT64_MODIFIER"d%s%02d%s%s",
                 (gint64)timer->secs,
                 decimal_point,
                 timer->nsecs / 10000000,
                 second,
                 (timer->secs == 1 && timer->nsecs == 0) ? "" : plural);
      break;

    case WTAP_TSPREC_MSEC:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "%"G_GINT64_MODIFIER"d%s%03d%s%s",
                 (gint64)timer->secs,
                 decimal_point,
                 timer->nsecs / 1000000,
                 second,
                 (timer->secs == 1 && timer->nsecs == 0) ? "" : plural);
      break;

    case WTAP_TSPREC_USEC:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "%"G_GINT64_MODIFIER"d%s%06d%s%s",
                 (gint64)timer->secs,
                 decimal_point,
                 timer->nsecs / 1000,
                 second,
                 (timer->secs == 1 && timer->nsecs == 0) ? "" : plural);
      break;

    case WTAP_TSPREC_NSEC:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "%"G_GINT64_MODIFIER"d%s%09d%s%s",
                 (gint64)timer->secs,
                 decimal_point,
                 timer->nsecs,
                 second,
                 (timer->secs == 1 && timer->nsecs == 0) ? "" : plural);
      break;

    default:
      g_snprintf(time_string_buf, sizeof time_string_buf,
                 "Unknown precision %d",
                 tsprecision);
      break;
    }
    return time_string_buf;
  }

  g_snprintf(time_string_buf, sizeof time_string_buf, "n/a");
  return time_string_buf;
}

static void print_value(const gchar *text_p1, gint width, const gchar *text_p2, double value) {
  if (value > 0.0)
    printf("%s%.*f%s\n", text_p1, width, value, text_p2);
  else
    printf("%sn/a\n", text_p1);
}

/* multi-line comments would conflict with the formatting that capinfos uses
   we replace linefeeds with spaces */
static void
string_replace_newlines(gchar *str)
{
  gchar *p;

  if (str) {
    p = str;
    while (*p != '\0') {
      if (*p == '\n')
        *p = ' ';
      if (*p == '\r')
        *p = ' ';
      p++;
    }
  }
}

static void
show_option_string(const char *prefix, const char *option_str)
{
  char *str;

  if (option_str != NULL && option_str[0] != '\0') {
    str = g_strdup(option_str);
    string_replace_newlines(str);
    printf("%s%s\n", prefix, str);
    g_free(str);
  }
}

static void
print_stats(const gchar *filename, capture_info *cf_info)
{
  const gchar           *file_type_string, *file_encap_string;
  gchar                 *size_string;

  /* Build printable strings for various stats */
  file_type_string = wtap_file_type_subtype_string(cf_info->file_type);
  file_encap_string = wtap_encap_description(cf_info->file_encap);

  if (filename)           printf     ("File name:           %s\n", filename);
  if (cap_file_type) {
    const char *compression_type_description;
    compression_type_description = wtap_compression_type_description(cf_info->compression_type);
    if (compression_type_description == NULL)
      printf     ("File type:           %s\n",
        file_type_string);
    else
      printf     ("File type:           %s (%s)\n",
        file_type_string, compression_type_description);
  }
  if (cap_file_encap) {
    printf      ("File encapsulation:  %s\n", file_encap_string);
    if (cf_info->file_encap == WTAP_ENCAP_PER_PACKET) {
      int i;
      printf    ("Encapsulation in use by packets (# of pkts):\n");
      for (i=0; i<WTAP_NUM_ENCAP_TYPES; i++) {
        if (cf_info->encap_counts[i] > 0)
          printf("                     %s (%d)\n",
                 wtap_encap_description(i), cf_info->encap_counts[i]);
      }
    }
  }
  if (cap_file_more_info) {
    printf      ("File timestamp precision:  %s (%d)\n",
      wtap_tsprec_string(cf_info->file_tsprec), cf_info->file_tsprec);
  }

  if (cap_snaplen && cf_info->snap_set)
    printf     ("Packet size limit:   file hdr: %u bytes\n", cf_info->snaplen);
  else if (cap_snaplen && !cf_info->snap_set)
    printf     ("Packet size limit:   file hdr: (not set)\n");
  if (cf_info->snaplen_max_inferred > 0) {
    if (cf_info->snaplen_min_inferred == cf_info->snaplen_max_inferred)
      printf     ("Packet size limit:   inferred: %u bytes\n", cf_info->snaplen_min_inferred);
    else
      printf     ("Packet size limit:   inferred: %u bytes - %u bytes (range)\n",
          cf_info->snaplen_min_inferred, cf_info->snaplen_max_inferred);
  }
  if (cap_packet_count) {
    printf     ("Number of packets:   ");
    if (machine_readable) {
      printf ("%u\n", cf_info->packet_count);
    } else {
      size_string = format_size(cf_info->packet_count, format_size_unit_none);
      printf ("%s\n", size_string);
      g_free(size_string);
    }
  }
  if (cap_file_size) {
    printf     ("File size:           ");
    if (machine_readable) {
      printf     ("%" G_GINT64_MODIFIER "d bytes\n", cf_info->filesize);
    } else {
      size_string = format_size(cf_info->filesize, format_size_unit_bytes);
      printf ("%s\n", size_string);
      g_free(size_string);
    }
  }
  if (cap_data_size) {
    printf     ("Data size:           ");
    if (machine_readable) {
      printf     ("%" G_GINT64_MODIFIER "u bytes\n", cf_info->packet_bytes);
    } else {
      size_string = format_size(cf_info->packet_bytes, format_size_unit_bytes);
      printf ("%s\n", size_string);
      g_free(size_string);
    }
  }
  if (cf_info->times_known) {
    if (cap_duration) /* XXX - shorten to hh:mm:ss */
                          printf("Capture duration:    %s\n", relative_time_string(&cf_info->duration, cf_info->duration_tsprec, cf_info, TRUE));
    if (cap_start_time)
                          printf("First packet time:   %s\n", absolute_time_string(&cf_info->start_time, cf_info->start_time_tsprec, cf_info));
    if (cap_end_time)
                          printf("Last packet time:    %s\n", absolute_time_string(&cf_info->stop_time, cf_info->stop_time_tsprec, cf_info));
    if (cap_data_rate_byte) {
                          printf("Data byte rate:      ");
      if (machine_readable) {
        print_value("", 2, " bytes/sec",   cf_info->data_rate);
      } else {
        size_string = format_size((gint64)cf_info->data_rate, format_size_unit_bytes_s);
        printf ("%s\n", size_string);
        g_free(size_string);
      }
    }
    if (cap_data_rate_bit) {
                          printf("Data bit rate:       ");
      if (machine_readable) {
        print_value("", 2, " bits/sec",    cf_info->data_rate*8);
      } else {
        size_string = format_size((gint64)(cf_info->data_rate*8), format_size_unit_bits_s);
        printf ("%s\n", size_string);
        g_free(size_string);
      }
    }
  }
  if (cap_packet_size)    printf("Average packet size: %.2f bytes\n",        cf_info->packet_size);
  if (cf_info->times_known) {
    if (cap_packet_rate) {
                          printf("Average packet rate: ");
      if (machine_readable) {
        print_value("", 2, " packets/sec", cf_info->packet_rate);
      } else {
        size_string = format_size((gint64)cf_info->packet_rate, format_size_unit_packets_s);
        printf ("%s\n", size_string);
        g_free(size_string);
      }
    }
  }
  if (cap_file_hashes) {
    printf     ("SHA256:              %s\n", file_sha256);
    printf     ("RIPEMD160:           %s\n", file_rmd160);
    printf     ("SHA1:                %s\n", file_sha1);
  }
  if (cap_order)          printf     ("Strict time order:   %s\n", order_string(cf_info->order));

  if (cf_info->shb != NULL) {
    if (cap_file_more_info) {
      char *str;

      if (wtap_block_get_string_option_value(cf_info->shb, OPT_SHB_HARDWARE, &str) == WTAP_OPTTYPE_SUCCESS)
        show_option_string("Capture hardware:    ", str);
      if (wtap_block_get_string_option_value(cf_info->shb, OPT_SHB_OS, &str) == WTAP_OPTTYPE_SUCCESS)
        show_option_string("Capture oper-sys:    ", str);
      if (wtap_block_get_string_option_value(cf_info->shb, OPT_SHB_USERAPPL, &str) == WTAP_OPTTYPE_SUCCESS)
        show_option_string("Capture application: ", str);
    }
    if (cap_comment) {
      unsigned int i;
      char *str;

      for (i = 0; wtap_block_get_nth_string_option_value(cf_info->shb, OPT_COMMENT, i, &str) == WTAP_OPTTYPE_SUCCESS; i++) {
        show_option_string("Capture comment:     ", str);
      }
    }

    if (cap_file_idb && cf_info->num_interfaces != 0) {
      guint i;
      g_assert(cf_info->num_interfaces == cf_info->idb_info_strings->len);
      printf     ("Number of interfaces in file: %u\n", cf_info->num_interfaces);
      for (i = 0; i < cf_info->idb_info_strings->len; i++) {
        gchar *s = g_array_index(cf_info->idb_info_strings, gchar*, i);
        guint32 packet_count = 0;
        if (i < cf_info->interface_packet_counts->len)
          packet_count = g_array_index(cf_info->interface_packet_counts, guint32, i);
        printf   ("Interface #%u info:\n", i);
        printf   ("%s", s);
        printf   ("                     Number of packets = %u\n", packet_count);
      }
    }

    if (cap_file_nrb) {
      if (num_ipv4_addresses != 0)
        printf   ("Number of resolved IPv4 addresses in file: %u\n", num_ipv4_addresses);
      if (num_ipv6_addresses != 0)
        printf   ("Number of resolved IPv6 addresses in file: %u\n", num_ipv6_addresses);
    }
    if (cap_file_dsb) {
      if (num_decryption_secrets != 0)
        printf   ("Number of decryption secrets in file: %u\n", num_decryption_secrets);
    }
  }
}

static void
putsep(void)
{
  if (field_separator) putchar(field_separator);
}

static void
putquote(void)
{
  if (quote_char) putchar(quote_char);
}

static void
print_stats_table_header_label(const gchar *label)
{
  putsep();
  putquote();
  printf("%s", label);
  putquote();
}

static void
print_stats_table_header(void)
{
  putquote();
  printf("File name");
  putquote();

  if (cap_file_type)      print_stats_table_header_label("File type");
  if (cap_file_encap)     print_stats_table_header_label("File encapsulation");
  if (cap_file_more_info) print_stats_table_header_label("File time precision");
  if (cap_snaplen)        print_stats_table_header_label("Packet size limit");
  if (cap_snaplen)        print_stats_table_header_label("Packet size limit min (inferred)");
  if (cap_snaplen)        print_stats_table_header_label("Packet size limit max (inferred)");
  if (cap_packet_count)   print_stats_table_header_label("Number of packets");
  if (cap_file_size)      print_stats_table_header_label("File size (bytes)");
  if (cap_data_size)      print_stats_table_header_label("Data size (bytes)");
  if (cap_duration)       print_stats_table_header_label("Capture duration (seconds)");
  if (cap_start_time)     print_stats_table_header_label("Start time");
  if (cap_end_time)       print_stats_table_header_label("End time");
  if (cap_data_rate_byte) print_stats_table_header_label("Data byte rate (bytes/sec)");
  if (cap_data_rate_bit)  print_stats_table_header_label("Data bit rate (bits/sec)");
  if (cap_packet_size)    print_stats_table_header_label("Average packet size (bytes)");
  if (cap_packet_rate)    print_stats_table_header_label("Average packet rate (packets/sec)");
  if (cap_file_hashes) {
    print_stats_table_header_label("SHA256");
    print_stats_table_header_label("RIPEMD160");
    print_stats_table_header_label("SHA1");
  }
  if (cap_order)          print_stats_table_header_label("Strict time order");
  if (cap_file_more_info) {
    print_stats_table_header_label("Capture hardware");
    print_stats_table_header_label("Capture oper-sys");
    print_stats_table_header_label("Capture application");
  }
  if (cap_comment)        print_stats_table_header_label("Capture comment");

  printf("\n");
}

static void
print_stats_table(const gchar *filename, capture_info *cf_info)
{
  const gchar           *file_type_string, *file_encap_string;

  /* Build printable strings for various stats */
  file_type_string = wtap_file_type_subtype_string(cf_info->file_type);
  file_encap_string = wtap_encap_description(cf_info->file_encap);

  if (filename) {
    putquote();
    printf("%s", filename);
    putquote();
  }

  if (cap_file_type) {
    putsep();
    putquote();
    printf("%s", file_type_string);
    putquote();
  }

  /* ToDo: If WTAP_ENCAP_PER_PACKET, show the list of encapsulations encountered;
   *       Output a line for each different encap with all fields repeated except
   *        the encapsulation field which has "Per Packet: ..." for each
   *        encapsulation type seen ?
   */
  if (cap_file_encap) {
    putsep();
    putquote();
    printf("%s", file_encap_string);
    putquote();
  }

  if (cap_file_more_info) {
    putsep();
    putquote();
    printf("%s", wtap_tsprec_string(cf_info->file_tsprec));
    putquote();
  }

  if (cap_snaplen) {
    putsep();
    putquote();
    if (cf_info->snap_set)
      printf("%u", cf_info->snaplen);
    else
      printf("(not set)");
    putquote();
    if (cf_info->snaplen_max_inferred > 0) {
      putsep();
      putquote();
      printf("%u", cf_info->snaplen_min_inferred);
      putquote();
      putsep();
      putquote();
      printf("%u", cf_info->snaplen_max_inferred);
      putquote();
    }
    else {
      putsep();
      putquote();
      printf("n/a");
      putquote();
      putsep();
      putquote();
      printf("n/a");
      putquote();
    }
  }

  if (cap_packet_count) {
    putsep();
    putquote();
    printf("%u", cf_info->packet_count);
    putquote();
  }

  if (cap_file_size) {
    putsep();
    putquote();
    printf("%" G_GINT64_MODIFIER "d", cf_info->filesize);
    putquote();
  }

  if (cap_data_size) {
    putsep();
    putquote();
    printf("%" G_GINT64_MODIFIER "u", cf_info->packet_bytes);
    putquote();
  }

  if (cap_duration) {
    putsep();
    putquote();
    printf("%s", relative_time_string(&cf_info->duration, cf_info->duration_tsprec, cf_info, FALSE));
    putquote();
  }

  if (cap_start_time) {
    putsep();
    putquote();
    printf("%s", absolute_time_string(&cf_info->start_time, cf_info->start_time_tsprec, cf_info));
    putquote();
  }

  if (cap_end_time) {
    putsep();
    putquote();
    printf("%s", absolute_time_string(&cf_info->stop_time, cf_info->stop_time_tsprec, cf_info));
    putquote();
  }

  if (cap_data_rate_byte) {
    putsep();
    putquote();
    if (cf_info->times_known)
      printf("%.2f", cf_info->data_rate);
    else
      printf("n/a");
    putquote();
  }

  if (cap_data_rate_bit) {
    putsep();
    putquote();
    if (cf_info->times_known)
      printf("%.2f", cf_info->data_rate*8);
    else
      printf("n/a");
    putquote();
  }

  if (cap_packet_size) {
    putsep();
    putquote();
    printf("%.2f", cf_info->packet_size);
    putquote();
  }

  if (cap_packet_rate) {
    putsep();
    putquote();
    if (cf_info->times_known)
      printf("%.2f", cf_info->packet_rate);
    else
      printf("n/a");
    putquote();
  }

  if (cap_file_hashes) {
    putsep();
    putquote();
    printf("%s", file_sha256);
    putquote();

    putsep();
    putquote();
    printf("%s", file_rmd160);
    putquote();

    putsep();
    putquote();
    printf("%s", file_sha1);
    putquote();
  }

  if (cap_order) {
    putsep();
    putquote();
    printf("%s", order_string(cf_info->order));
    putquote();
  }

  if (cf_info->shb != NULL) {
    if (cap_file_more_info) {
      char *str;

      putsep();
      putquote();
      if (wtap_block_get_string_option_value(cf_info->shb, OPT_SHB_HARDWARE, &str) == WTAP_OPTTYPE_SUCCESS) {
        printf("%s", str);
      }
      putquote();

      putsep();
      putquote();
      if (wtap_block_get_string_option_value(cf_info->shb, OPT_SHB_OS, &str) == WTAP_OPTTYPE_SUCCESS) {
        printf("%s", str);
      }
      putquote();

      putsep();
      putquote();
      if (wtap_block_get_string_option_value(cf_info->shb, OPT_SHB_USERAPPL, &str) == WTAP_OPTTYPE_SUCCESS) {
        printf("%s", str);
      }
      putquote();
    }

    /*
     * One might argue that the following is silly to put into a table format,
     * but oh well note that there may be *more than one* of each of these types
     * of options.  To mitigate some of the potential silliness the if(cap_comment)
     * block is moved AFTER the if(cap_file_more_info) block.  This will make any
     * comments the last item(s) in each row.  We now have a new -K option to
     * disable cap_comment to more easily manage the potential silliness.
     * Potential silliness includes multiple comments (therefore resulting in
     * more than one additional column and/or comments with embeded newlines
     * and/or possible delimiters).
     */
    if (cap_comment) {
      unsigned int i;
      char *opt_comment;
      gboolean have_cap = FALSE;

      for (i = 0; wtap_block_get_nth_string_option_value(cf_info->shb, OPT_COMMENT, i, &opt_comment) == WTAP_OPTTYPE_SUCCESS; i++) {
        have_cap = TRUE;
        putsep();
        putquote();
        printf("%s", opt_comment);
        putquote();
      }
      if(!have_cap) {
        /* Maintain column alignment when we have no OPT_COMMENT */
        putsep();
        putquote();
        putquote();
      }
    }

  }

  printf("\n");
}

static void
cleanup_capture_info(capture_info *cf_info)
{
  guint i;
  g_assert(cf_info != NULL);

  g_free(cf_info->encap_counts);
  cf_info->encap_counts = NULL;

  g_array_free(cf_info->interface_packet_counts, TRUE);
  cf_info->interface_packet_counts = NULL;

  if (cf_info->idb_info_strings) {
    for (i = 0; i < cf_info->idb_info_strings->len; i++) {
      gchar *s = g_array_index(cf_info->idb_info_strings, gchar*, i);
      g_free(s);
    }
    g_array_free(cf_info->idb_info_strings, TRUE);
  }
  cf_info->idb_info_strings = NULL;
}

static void
count_ipv4_address(const guint addr _U_, const gchar *name _U_)
{
  num_ipv4_addresses++;
}

static void
count_ipv6_address(const void *addrp _U_, const gchar *name _U_)
{
  num_ipv6_addresses++;
}

static void
count_decryption_secret(guint32 secrets_type _U_, const void *secrets _U_, guint size _U_)
{
  /* XXX - count them based on the secrets type (which is an opaque code,
     not a small integer)? */
  num_decryption_secrets++;
}

static int
process_cap_file(const char *filename, gboolean need_separator)
{
  int                   status = 0;
  wtap                 *wth;
  int                   err;
  gchar                *err_info;
  gint64                size;
  gint64                data_offset;

  guint32               packet = 0;
  gint64                bytes  = 0;
  guint32               snaplen_min_inferred = 0xffffffff;
  guint32               snaplen_max_inferred =          0;
  wtap_rec              rec;
  Buffer                buf;
  capture_info          cf_info;
  gboolean              have_times = TRUE;
  nstime_t              start_time;
  int                   start_time_tsprec;
  nstime_t              stop_time;
  int                   stop_time_tsprec;
  nstime_t              cur_time;
  nstime_t              prev_time;
  gboolean              know_order = FALSE;
  order_t               order = IN_ORDER;
  guint                 i;
  wtapng_iface_descriptions_t *idb_info;

  wth = wtap_open_offline(filename, WTAP_TYPE_AUTO, &err, &err_info, FALSE);
  if (!wth) {
    cfile_open_failure_message("capinfos", filename, err, err_info);
    return 2;
  }

  if (need_separator && long_report) {
    printf("\n");
  }

  nstime_set_zero(&start_time);
  start_time_tsprec = WTAP_TSPREC_UNKNOWN;
  nstime_set_zero(&stop_time);
  stop_time_tsprec = WTAP_TSPREC_UNKNOWN;
  nstime_set_zero(&cur_time);
  nstime_set_zero(&prev_time);

  cf_info.shb = wtap_file_get_shb(wth);

  cf_info.encap_counts = g_new0(int,WTAP_NUM_ENCAP_TYPES);

  idb_info = wtap_file_get_idb_info(wth);

  g_assert(idb_info->interface_data != NULL);

  cf_info.num_interfaces = idb_info->interface_data->len;
  cf_info.interface_packet_counts  = g_array_sized_new(FALSE, TRUE, sizeof(guint32), cf_info.num_interfaces);
  g_array_set_size(cf_info.interface_packet_counts, cf_info.num_interfaces);
  cf_info.pkt_interface_id_unknown = 0;

  g_free(idb_info);
  idb_info = NULL;

  /* Register callbacks for new name<->address maps from the file and
     decryption secrets from the file. */
  wtap_set_cb_new_ipv4(wth, count_ipv4_address);
  wtap_set_cb_new_ipv6(wth, count_ipv6_address);
  wtap_set_cb_new_secrets(wth, count_decryption_secret);

  /* Zero out the counters for the callbacks. */
  num_ipv4_addresses = 0;
  num_ipv6_addresses = 0;
  num_decryption_secrets = 0;

  /* Tally up data that we need to parse through the file to find */
  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  while (wtap_read(wth, &rec, &buf, &err, &err_info, &data_offset))  {
    if (rec.presence_flags & WTAP_HAS_TS) {
      prev_time = cur_time;
      cur_time = rec.ts;
      if (packet == 0) {
        start_time = rec.ts;
        start_time_tsprec = rec.tsprec;
        stop_time  = rec.ts;
        stop_time_tsprec = rec.tsprec;
        prev_time  = rec.ts;
      }
      if (nstime_cmp(&cur_time, &prev_time) < 0) {
        order = NOT_IN_ORDER;
      }
      if (nstime_cmp(&cur_time, &start_time) < 0) {
        start_time = cur_time;
        start_time_tsprec = rec.tsprec;
      }
      if (nstime_cmp(&cur_time, &stop_time) > 0) {
        stop_time = cur_time;
        stop_time_tsprec = rec.tsprec;
      }
    } else {
      have_times = FALSE; /* at least one packet has no time stamp */
      if (order != NOT_IN_ORDER)
        order = ORDER_UNKNOWN;
    }

    if (rec.rec_type == REC_TYPE_PACKET) {
      bytes += rec.rec_header.packet_header.len;
      packet++;

      /* If caplen < len for a rcd, then presumably           */
      /* 'Limit packet capture length' was done for this rcd. */
      /* Keep track as to the min/max actual snapshot lengths */
      /*  seen for this file.                                 */
      if (rec.rec_header.packet_header.caplen < rec.rec_header.packet_header.len) {
        if (rec.rec_header.packet_header.caplen < snaplen_min_inferred)
          snaplen_min_inferred = rec.rec_header.packet_header.caplen;
        if (rec.rec_header.packet_header.caplen > snaplen_max_inferred)
          snaplen_max_inferred = rec.rec_header.packet_header.caplen;
      }

      if ((rec.rec_header.packet_header.pkt_encap > 0) &&
          (rec.rec_header.packet_header.pkt_encap < WTAP_NUM_ENCAP_TYPES)) {
        cf_info.encap_counts[rec.rec_header.packet_header.pkt_encap] += 1;
      } else {
        fprintf(stderr, "capinfos: Unknown packet encapsulation %d in frame %u of file \"%s\"\n",
                rec.rec_header.packet_header.pkt_encap, packet, filename);
      }

      /* Packet interface_id info */
      if (rec.presence_flags & WTAP_HAS_INTERFACE_ID) {
        /* cf_info.num_interfaces is size, not index, so it's one more than max index */
        if (rec.rec_header.packet_header.interface_id >= cf_info.num_interfaces) {
          /*
           * OK, re-fetch the number of interfaces, as there might have
           * been an interface that was in the middle of packets, and
           * grow the array to be big enough for the new number of
           * interfaces.
           */
          idb_info = wtap_file_get_idb_info(wth);

          cf_info.num_interfaces = idb_info->interface_data->len;
          g_array_set_size(cf_info.interface_packet_counts, cf_info.num_interfaces);

          g_free(idb_info);
          idb_info = NULL;
        }
        if (rec.rec_header.packet_header.interface_id < cf_info.num_interfaces) {
          g_array_index(cf_info.interface_packet_counts, guint32,
                        rec.rec_header.packet_header.interface_id) += 1;
        }
        else {
          cf_info.pkt_interface_id_unknown += 1;
        }
      }
      else {
        /* it's for interface_id 0 */
        if (cf_info.num_interfaces != 0) {
          g_array_index(cf_info.interface_packet_counts, guint32, 0) += 1;
        }
        else {
          cf_info.pkt_interface_id_unknown += 1;
        }
      }
    }

  } /* while */
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);

  /*
   * Get IDB info strings.
   * We do this at the end, so we can get information for all IDBs in
   * the file, even those that come after packet records.
   */
  idb_info = wtap_file_get_idb_info(wth);

  cf_info.idb_info_strings = g_array_sized_new(FALSE, FALSE, sizeof(gchar*), cf_info.num_interfaces);
  cf_info.num_interfaces = idb_info->interface_data->len;
  for (i = 0; i < cf_info.num_interfaces; i++) {
    const wtap_block_t if_descr = g_array_index(idb_info->interface_data, wtap_block_t, i);
    gchar *s = wtap_get_debug_if_descr(if_descr, 21, "\n");
    g_array_append_val(cf_info.idb_info_strings, s);
  }

  g_free(idb_info);
  idb_info = NULL;

  if (err != 0) {
    fprintf(stderr,
        "capinfos: An error occurred after reading %u packets from \"%s\".\n",
        packet, filename);
    cfile_read_failure_message("capinfos", filename, err, err_info);
    if (err == WTAP_ERR_SHORT_READ) {
        /* Don't give up completely with this one. */
        status = 1;
        fprintf(stderr,
          "  (will continue anyway, checksums might be incorrect)\n");
    } else {
        cleanup_capture_info(&cf_info);
        wtap_close(wth);
        return 2;
    }
  }

  /* File size */
  size = wtap_file_size(wth, &err);
  if (size == -1) {
    fprintf(stderr,
        "capinfos: Can't get size of \"%s\": %s.\n",
        filename, g_strerror(err));
    cleanup_capture_info(&cf_info);
    wtap_close(wth);
    return 2;
  }

  cf_info.filesize = size;

  /* File Type */
  cf_info.file_type = wtap_file_type_subtype(wth);
  cf_info.compression_type = wtap_get_compression_type(wth);

  /* File Encapsulation */
  cf_info.file_encap = wtap_file_encap(wth);

  cf_info.file_tsprec = wtap_file_tsprec(wth);

  /* Packet size limit (snaplen) */
  cf_info.snaplen = wtap_snapshot_length(wth);
  if (cf_info.snaplen > 0)
    cf_info.snap_set = TRUE;
  else
    cf_info.snap_set = FALSE;

  cf_info.snaplen_min_inferred = snaplen_min_inferred;
  cf_info.snaplen_max_inferred = snaplen_max_inferred;

  /* # of packets */
  cf_info.packet_count = packet;

  /* File Times */
  cf_info.times_known = have_times;
  cf_info.start_time = start_time;
  cf_info.start_time_tsprec = start_time_tsprec;
  cf_info.stop_time = stop_time;
  cf_info.stop_time_tsprec = stop_time_tsprec;
  nstime_delta(&cf_info.duration, &stop_time, &start_time);
  /* Duration precision is the higher of the start and stop time precisions. */
  if (cf_info.stop_time_tsprec > cf_info.start_time_tsprec)
    cf_info.duration_tsprec = cf_info.stop_time_tsprec;
  else
    cf_info.duration_tsprec = cf_info.start_time_tsprec;
  cf_info.know_order = know_order;
  cf_info.order = order;

  /* Number of packet bytes */
  cf_info.packet_bytes = bytes;

  cf_info.data_rate   = 0.0;
  cf_info.packet_rate = 0.0;
  cf_info.packet_size = 0.0;

  if (packet > 0) {
    double delta_time = nstime_to_sec(&stop_time) - nstime_to_sec(&start_time);
    if (delta_time > 0.0) {
      cf_info.data_rate   = (double)bytes  / delta_time; /* Data rate per second */
      cf_info.packet_rate = (double)packet / delta_time; /* packet rate per second */
    }
    cf_info.packet_size = (double)bytes / packet;                  /* Avg packet size      */
  }

  if (long_report) {
    print_stats(filename, &cf_info);
  } else {
    print_stats_table(filename, &cf_info);
  }

  cleanup_capture_info(&cf_info);
  wtap_close(wth);

  return status;
}

static void
print_usage(FILE *output)
{
  fprintf(output, "\n");
  fprintf(output, "Usage: capinfos [options] <infile> ...\n");
  fprintf(output, "\n");
  fprintf(output, "General infos:\n");
  fprintf(output, "  -t display the capture file type\n");
  fprintf(output, "  -E display the capture file encapsulation\n");
  fprintf(output, "  -I display the capture file interface information\n");
  fprintf(output, "  -F display additional capture file information\n");
  fprintf(output, "  -H display the SHA256, RMD160, and SHA1 hashes of the file\n");
  fprintf(output, "  -k display the capture comment\n");
  fprintf(output, "\n");
  fprintf(output, "Size infos:\n");
  fprintf(output, "  -c display the number of packets\n");
  fprintf(output, "  -s display the size of the file (in bytes)\n");
  fprintf(output, "  -d display the total length of all packets (in bytes)\n");
  fprintf(output, "  -l display the packet size limit (snapshot length)\n");
  fprintf(output, "\n");
  fprintf(output, "Time infos:\n");
  fprintf(output, "  -u display the capture duration (in seconds)\n");
  fprintf(output, "  -a display the capture start time\n");
  fprintf(output, "  -e display the capture end time\n");
  fprintf(output, "  -o display the capture file chronological status (True/False)\n");
  fprintf(output, "  -S display start and end times as seconds\n");
  fprintf(output, "\n");
  fprintf(output, "Statistic infos:\n");
  fprintf(output, "  -y display average data rate (in bytes/sec)\n");
  fprintf(output, "  -i display average data rate (in bits/sec)\n");
  fprintf(output, "  -z display average packet size (in bytes)\n");
  fprintf(output, "  -x display average packet rate (in packets/sec)\n");
  fprintf(output, "\n");
  fprintf(output, "Metadata infos:\n");
  fprintf(output, "  -n display number of resolved IPv4 and IPv6 addresses\n");
  fprintf(output, "  -D display number of decryption secrets\n");
  fprintf(output, "\n");
  fprintf(output, "Output format:\n");
  fprintf(output, "  -L generate long report (default)\n");
  fprintf(output, "  -T generate table report\n");
  fprintf(output, "  -M display machine-readable values in long reports\n");
  fprintf(output, "\n");
  fprintf(output, "Table report options:\n");
  fprintf(output, "  -R generate header record (default)\n");
  fprintf(output, "  -r do not generate header record\n");
  fprintf(output, "\n");
  fprintf(output, "  -B separate infos with TAB character (default)\n");
  fprintf(output, "  -m separate infos with comma (,) character\n");
  fprintf(output, "  -b separate infos with SPACE character\n");
  fprintf(output, "\n");
  fprintf(output, "  -N do not quote infos (default)\n");
  fprintf(output, "  -q quote infos with single quotes (')\n");
  fprintf(output, "  -Q quote infos with double quotes (\")\n");
  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h display this help and exit\n");
  fprintf(output, "  -C cancel processing if file open fails (default is to continue)\n");
  fprintf(output, "  -A generate all infos (default)\n");
  fprintf(output, "  -K disable displaying the capture comment\n");
  fprintf(output, "\n");
  fprintf(output, "Options are processed from left to right order with later options superseding\n");
  fprintf(output, "or adding to earlier options.\n");
  fprintf(output, "\n");
  fprintf(output, "If no options are given the default is to display all infos in long report\n");
  fprintf(output, "output format.\n");
}

/*
 * General errors and warnings are reported with an console message
 * in capinfos.
 */
static void
failure_warning_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "capinfos: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
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

static void
hash_to_str(const unsigned char *hash, size_t length, char *str) {
  int i;

  for (i = 0; i < (int) length; i++) {
    g_snprintf(str+(i*2), 3, "%02x", hash[i]);
  }
}

int
main(int argc, char *argv[])
{
  char  *init_progfile_dir_error;
  gboolean need_separator = FALSE;
  int    opt;
  int    overall_error_status = EXIT_SUCCESS;
  static const struct option long_options[] = {
      {"help", no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 'v'},
      {0, 0, 0, 0 }
  };

  int status = 0;
  FILE  *fh;
  char  *hash_buf = NULL;
  gcry_md_hd_t hd = NULL;
  size_t hash_bytes;

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  cmdarg_err_init(failure_warning_message, failure_message_cont);

  /* Get the decimal point. */
  decimal_point = g_strdup(localeconv()->decimal_point);

  /* Initialize the version information. */
  ws_init_version_info("Capinfos (Wireshark)", NULL, NULL, NULL);

#ifdef _WIN32
  create_app_running_mutex();
#endif /* _WIN32 */

  /*
   * Get credential information for later use.
   */
  init_process_policies();

  /*
   * Attempt to get the pathname of the directory containing the
   * executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0]);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr,
            "capinfos: Can't get pathname of directory containing the capinfos program: %s.\n",
            init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  }

  init_report_message(failure_warning_message, failure_warning_message,
                      NULL, NULL, NULL);

  wtap_init(TRUE);

  /* Process the options */
  while ((opt = getopt_long(argc, argv, "abcdehiklmnoqrstuvxyzABCDEFHIKLMNQRST", long_options, NULL)) !=-1) {

    switch (opt) {

      case 't':
        if (report_all_infos) disable_all_infos();
        cap_file_type = TRUE;
        break;

      case 'E':
        if (report_all_infos) disable_all_infos();
        cap_file_encap = TRUE;
        break;

      case 'l':
        if (report_all_infos) disable_all_infos();
        cap_snaplen = TRUE;
        break;

      case 'c':
        if (report_all_infos) disable_all_infos();
        cap_packet_count = TRUE;
        break;

      case 's':
        if (report_all_infos) disable_all_infos();
        cap_file_size = TRUE;
        break;

      case 'd':
        if (report_all_infos) disable_all_infos();
        cap_data_size = TRUE;
        break;

      case 'u':
        if (report_all_infos) disable_all_infos();
        cap_duration = TRUE;
        break;

      case 'a':
        if (report_all_infos) disable_all_infos();
        cap_start_time = TRUE;
        break;

      case 'e':
        if (report_all_infos) disable_all_infos();
        cap_end_time = TRUE;
        break;

      case 'S':
        time_as_secs = TRUE;
        break;

      case 'y':
        if (report_all_infos) disable_all_infos();
        cap_data_rate_byte = TRUE;
        break;

      case 'i':
        if (report_all_infos) disable_all_infos();
        cap_data_rate_bit = TRUE;
        break;

      case 'z':
        if (report_all_infos) disable_all_infos();
        cap_packet_size = TRUE;
        break;

      case 'x':
        if (report_all_infos) disable_all_infos();
        cap_packet_rate = TRUE;
        break;

      case 'H':
        if (report_all_infos) disable_all_infos();
        cap_file_hashes = TRUE;
        break;

      case 'o':
        if (report_all_infos) disable_all_infos();
        cap_order = TRUE;
        break;

      case 'k':
        if (report_all_infos) disable_all_infos();
        cap_comment = TRUE;
        break;

      case 'K':
        cap_comment = FALSE;
        break;

      case 'F':
        if (report_all_infos) disable_all_infos();
        cap_file_more_info = TRUE;
        break;

      case 'I':
        if (report_all_infos) disable_all_infos();
        cap_file_idb = TRUE;
        break;

      case 'n':
        if (report_all_infos) disable_all_infos();
        cap_file_nrb = TRUE;
        break;

      case 'D':
        if (report_all_infos) disable_all_infos();
        cap_file_dsb = TRUE;
        break;

      case 'C':
        stop_after_failure = TRUE;
        break;

      case 'A':
        enable_all_infos();
        break;

      case 'L':
        long_report = TRUE;
        break;

      case 'T':
        long_report = FALSE;
        break;

      case 'M':
        machine_readable = TRUE;
        break;

      case 'R':
        table_report_header = TRUE;
        break;

      case 'r':
        table_report_header = FALSE;
        break;

      case 'N':
        quote_char = '\0';
        break;

      case 'q':
        quote_char = '\'';
        break;

      case 'Q':
        quote_char = '"';
        break;

      case 'B':
        field_separator = '\t';
        break;

      case 'm':
        field_separator = ',';
        break;

      case 'b':
        field_separator = ' ';
        break;

      case 'h':
        show_help_header("Print various information (infos) about capture files.");
        print_usage(stdout);
        goto exit;
        break;

      case 'v':
        show_version();
        goto exit;
        break;

      case '?':              /* Bad flag - print usage message */
        print_usage(stderr);
        overall_error_status = BAD_FLAG;
        goto exit;
        break;
    }
  }

  if ((argc - optind) < 1) {
    print_usage(stderr);
    overall_error_status = INVALID_OPTION;
    goto exit;
  }

  if (!long_report && table_report_header) {
    print_stats_table_header();
  }

  if (cap_file_hashes) {
    gcry_check_version(NULL);
    gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    if (hd) {
      gcry_md_enable(hd, GCRY_MD_RMD160);
      gcry_md_enable(hd, GCRY_MD_SHA1);
    }
    hash_buf = (char *)g_malloc(HASH_BUF_SIZE);
  }

  overall_error_status = 0;

  for (opt = optind; opt < argc; opt++) {

    g_strlcpy(file_sha256, "<unknown>", HASH_STR_SIZE);
    g_strlcpy(file_rmd160, "<unknown>", HASH_STR_SIZE);
    g_strlcpy(file_sha1, "<unknown>", HASH_STR_SIZE);

    if (cap_file_hashes) {
      fh = ws_fopen(argv[opt], "rb");
      if (fh && hd) {
        while((hash_bytes = fread(hash_buf, 1, HASH_BUF_SIZE, fh)) > 0) {
          gcry_md_write(hd, hash_buf, hash_bytes);
        }
        gcry_md_final(hd);
        hash_to_str(gcry_md_read(hd, GCRY_MD_SHA256), HASH_SIZE_SHA256, file_sha256);
        hash_to_str(gcry_md_read(hd, GCRY_MD_RMD160), HASH_SIZE_RMD160, file_rmd160);
        hash_to_str(gcry_md_read(hd, GCRY_MD_SHA1), HASH_SIZE_SHA1, file_sha1);
      }
      if (fh) fclose(fh);
      if (hd) gcry_md_reset(hd);
    }

    status = process_cap_file(argv[opt], need_separator);
    if (status) {
      /* Something failed.  It's been reported; remember that processing
         one file failed and, if -C was specified, stop. */
      overall_error_status = status;
      if (stop_after_failure)
        goto exit;
    }
    if (status != 2) {
      /* Either it succeeded or it got a "short read" but printed
         information anyway.  Note that we need a blank line before
         the next file's information, to separate it from the
         previous file. */
      need_separator = TRUE;
    }
  }

exit:
  g_free(hash_buf);
  gcry_md_close(hd);
  wtap_cleanup();
  free_progdirs();
  return overall_error_status;
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
