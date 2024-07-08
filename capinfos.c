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
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>

#include <ws_exit_codes.h>
#include <wsutil/ws_getopt.h>

#include <glib.h>

#include <wiretap/wtap.h>

#include <wsutil/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <cli_main.h>
#include <wsutil/version_info.h>
#include <wiretap/wtap_opttypes.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>
#include <wsutil/str_util.h>
#include <wsutil/to_str.h>
#include <wsutil/file_util.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#include <gcrypt.h>

#include "ui/failure_message.h"

/*
 * By default capinfos now continues processing
 * the next filename if and when wiretap detects
 * a problem opening or reading a file.
 * Use the '-C' option to revert back to original
 * capinfos behavior which is to abort any
 * additional file processing at the first file
 * open or read failure.
 */

static bool stop_after_failure;

/*
 * table report variables
 */

static bool long_report               = true;  /* By default generate long report       */
static bool table_report_header       = true;  /* Generate column header by default     */
static char field_separator           = '\t';  /* Use TAB as field separator by default */
static char quote_char                = '\0';  /* Do NOT quote fields by default        */
static bool machine_readable; /* Display machine-readable numbers      */

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

static bool report_all_infos   = true;  /* Report all infos           */

static bool cap_file_type      = true;  /* Report capture type        */
static bool cap_file_encap     = true;  /* Report encapsulation       */
static bool cap_snaplen        = true;  /* Packet size limit (snaplen)*/
static bool cap_packet_count   = true;  /* Report packet count        */
static bool cap_file_size      = true;  /* Report file size           */
static bool cap_comment        = true;  /* Display the capture comment */
static bool cap_file_more_info = true;  /* Report more file info      */
static bool cap_file_idb       = true;  /* Report Interface info      */
static bool cap_file_nrb       = true;  /* Report Name Resolution Block info      */
static bool cap_file_dsb       = true;  /* Report Decryption Secrets Block info      */

static bool cap_data_size      = true;  /* Report packet byte size    */
static bool cap_duration       = true;  /* Report capture duration    */
static bool cap_earliest_packet_time = true;  /* Report timestamp of earliest packet */
static bool cap_latest_packet_time = true;  /* Report timestamp of latest packet */
static bool time_as_secs; /* Report time values as raw seconds */

static bool cap_data_rate_byte = true;  /* Report data rate bytes/sec */
static bool cap_data_rate_bit  = true;  /* Report data rate bites/sec */
static bool cap_packet_size    = true;  /* Report average packet size */
static bool cap_packet_rate    = true;  /* Report average packet rate */
static bool cap_order          = true;  /* Report if packets are in chronological order (True/False) */
static bool pkt_comments       = true;  /* Report individual packet comments */

static bool cap_file_hashes    = true;  /* Calculate file hashes */

// Strongest to weakest
#define HASH_SIZE_SHA256 32
#define HASH_SIZE_SHA1   20

#define HASH_STR_SIZE (65) /* Max hash size * 2 + '\0' */
#define HASH_BUF_SIZE (1024 * 1024)


static char file_sha256[HASH_STR_SIZE];
static char file_sha1[HASH_STR_SIZE];

static char  *hash_buf;
static gcry_md_hd_t hd;

static unsigned int num_ipv4_addresses;
static unsigned int num_ipv6_addresses;
static unsigned int num_decryption_secrets;

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

typedef struct _pkt_cmt {
  int recno;
  char *cmt;
  struct _pkt_cmt *next;
} pkt_cmt;

typedef struct _capture_info {
    const char           *filename;
    uint16_t              file_type;
    wtap_compression_type compression_type;
    int                   file_encap;
    int                   file_tsprec;
    wtap                 *wth;
    int64_t               filesize;
    uint64_t              packet_bytes;
    bool                  times_known;
    nstime_t              earliest_packet_time;
    int                   earliest_packet_time_tsprec;
    nstime_t              latest_packet_time;
    int                   latest_packet_time_tsprec;
    uint32_t              packet_count;
    bool                  snap_set;                 /* If set in capture file header      */
    uint32_t              snaplen;                  /* value from the capture file header */
    uint32_t              snaplen_min_inferred;     /* If caplen < len for 1 or more rcds */
    uint32_t              snaplen_max_inferred;     /*  ...                               */
    bool                  drops_known;
    uint32_t              drop_count;

    nstime_t              duration;
    int                   duration_tsprec;
    double                packet_rate;
    double                packet_size;
    double                data_rate;                /* in bytes/s */
    bool                  know_order;
    order_t               order;

    int                  *encap_counts;             /* array of per_packet encap counts; array has one entry per wtap_encap type */
    pkt_cmt              *pkt_cmts;                 /* list of packet comments */

    unsigned int                 num_interfaces;           /* number of IDBs, and thus size of interface_packet_counts array */
    GArray               *interface_packet_counts;  /* array of per_packet interface_id counts; one entry per file IDB */
    uint32_t              pkt_interface_id_unknown; /* counts if packet interface_id didn't match a known one */
    GArray               *idb_info_strings;         /* array of IDB info strings */
} capture_info;

static char *decimal_point;

static void
enable_all_infos(void)
{
    report_all_infos   = true;

    cap_file_type      = true;
    cap_file_encap     = true;
    cap_snaplen        = true;
    cap_packet_count   = true;
    cap_file_size      = true;
    cap_comment        = true;
    pkt_comments       = true;
    cap_file_more_info = true;
    cap_file_idb       = true;
    cap_file_nrb       = true;
    cap_file_dsb       = true;

    cap_data_size      = true;
    cap_duration       = true;
    cap_earliest_packet_time = true;
    cap_latest_packet_time = true;
    cap_order          = true;

    cap_data_rate_byte = true;
    cap_data_rate_bit  = true;
    cap_packet_size    = true;
    cap_packet_rate    = true;

    cap_file_hashes    = true;
}

static void
disable_all_infos(void)
{
    report_all_infos   = false;

    cap_file_type      = false;
    cap_file_encap     = false;
    cap_snaplen        = false;
    cap_packet_count   = false;
    cap_file_size      = false;
    cap_comment        = false;
    pkt_comments       = false;
    cap_file_more_info = false;
    cap_file_idb       = false;
    cap_file_nrb       = false;
    cap_file_dsb       = false;

    cap_data_size      = false;
    cap_duration       = false;
    cap_earliest_packet_time = false;
    cap_latest_packet_time = false;
    cap_order          = false;

    cap_data_rate_byte = false;
    cap_data_rate_bit  = false;
    cap_packet_size    = false;
    cap_packet_rate    = false;

    cap_file_hashes    = false;
}

static const char *
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

static char *
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
     * we'll have the buffer be large enough for a date of the format
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
    static char time_string_buf[39];

    if (cf_info->times_known && cf_info->packet_count > 0) {
        if (time_as_secs) {
            display_epoch_time(time_string_buf, sizeof time_string_buf, timer, tsprecision);
        } else {
            format_nstime_as_iso8601(time_string_buf, sizeof time_string_buf, timer, decimal_point, true, tsprecision);
        }
    } else {
        snprintf(time_string_buf, sizeof time_string_buf, "n/a");
    }
    return time_string_buf;
}

static char *
relative_time_string(nstime_t *timer, int tsprecision, capture_info *cf_info, bool want_seconds)
{
    const char  *second = want_seconds ? " second" : "";
    const char  *plural = want_seconds ? "s" : "";
    /*
     * If we're displaying the time as epoch time, and the time is
     * unsigned, 2^64-1 is 18446744073709551615, so the buffer has
     * to be big enough for "18446744073709551615.999999999 seconds".
     * That's 20+1+9+1+7+1, including the terminating '\0', or 39.
     * If it'ssigned, 2^63 is 9223372036854775808, so the buffer has to
     * be big enough for "-9223372036854775808.999999999 seconds",
     * which is again 20+1+9+1+7+1, or 39.
     */
    static char  time_string_buf[39];

    if (cf_info->times_known && cf_info->packet_count > 0) {
        char *ptr;
        size_t remaining;
        int num_bytes;

        ptr = time_string_buf;
        remaining = sizeof time_string_buf;
        num_bytes = snprintf(ptr, remaining,
                             "%"PRId64,
                             (int64_t)timer->secs);
        if (num_bytes < 0) {
            /*
             * That got an error.
             * Not much else we can do.
             */
            snprintf(ptr, remaining, "snprintf() failed");
            return time_string_buf;
        }
        if ((unsigned int)num_bytes >= remaining) {
            /*
             * That filled up or would have overflowed the buffer.
             * Nothing more we can do.
             */
            return time_string_buf;
        }
        ptr += num_bytes;
        remaining -= num_bytes;

        if (tsprecision != 0) {
            /*
             * Append the fractional part.
             */
            num_bytes = format_fractional_part_nsecs(ptr, remaining, timer->nsecs, decimal_point, tsprecision);
            if ((unsigned int)num_bytes >= remaining) {
                /*
                 * That filled up or would have overflowed the buffer.
                 * Nothing more we can do.
                 */
                return time_string_buf;
            }
            ptr += num_bytes;
            remaining -= num_bytes;
        }

        /*
         * Append the units.
         */
        snprintf(ptr, remaining, "%s%s",
                 second,
                 timer->secs == 1 ? "" : plural);

        return time_string_buf;
    }

    snprintf(time_string_buf, sizeof time_string_buf, "n/a");
    return time_string_buf;
}

static void print_value(const char *text_p1, int width, const char *text_p2, double value)
{
    if (value > 0.0)
        printf("%s%.*f%s\n", text_p1, width, value, text_p2);
    else
        printf("%sn/a\n", text_p1);
}

/* multi-line comments would conflict with the formatting that capinfos uses
   we replace linefeeds with spaces */
static void
string_replace_newlines(char *str)
{
    char *p;

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
print_stats(const char *filename, capture_info *cf_info)
{
    const char           *file_type_string, *file_encap_string;
    char                 *size_string;
    pkt_cmt               *p, *prev;

    /* Build printable strings for various stats */
    if (machine_readable) {
        file_type_string = wtap_file_type_subtype_name(cf_info->file_type);
        file_encap_string = wtap_encap_name(cf_info->file_encap);
    }
    else {
        file_type_string = wtap_file_type_subtype_description(cf_info->file_type);
        file_encap_string = wtap_encap_description(cf_info->file_encap);
    }

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
            size_string = format_size(cf_info->packet_count, FORMAT_SIZE_UNIT_NONE, 0);
            printf ("%s\n", size_string);
            g_free(size_string);
        }
    }
    if (cap_file_size) {
        printf     ("File size:           ");
        if (machine_readable) {
            printf     ("%" PRId64 " bytes\n", cf_info->filesize);
        } else {
            size_string = format_size(cf_info->filesize, FORMAT_SIZE_UNIT_BYTES, 0);
            printf ("%s\n", size_string);
            g_free(size_string);
        }
    }
    if (cap_data_size) {
        printf     ("Data size:           ");
        if (machine_readable) {
            printf     ("%" PRIu64 " bytes\n", cf_info->packet_bytes);
        } else {
            size_string = format_size(cf_info->packet_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
            printf ("%s\n", size_string);
            g_free(size_string);
        }
    }
    if (cf_info->times_known) {
        if (cap_duration) /* XXX - shorten to hh:mm:ss */
            printf("Capture duration:    %s\n", relative_time_string(&cf_info->duration, cf_info->duration_tsprec, cf_info, true));
        if (cap_earliest_packet_time)
            printf("Earliest packet time: %s\n", absolute_time_string(&cf_info->earliest_packet_time, cf_info->earliest_packet_time_tsprec, cf_info));
        if (cap_latest_packet_time)
            printf("Latest packet time:   %s\n", absolute_time_string(&cf_info->latest_packet_time, cf_info->latest_packet_time_tsprec, cf_info));
        if (cap_data_rate_byte) {
            printf("Data byte rate:      ");
            if (machine_readable) {
                print_value("", 2, " bytes/sec",   cf_info->data_rate);
            } else {
                size_string = format_size((int64_t)cf_info->data_rate, FORMAT_SIZE_UNIT_BYTES_S, 0);
                printf ("%s\n", size_string);
                g_free(size_string);
            }
        }
        if (cap_data_rate_bit) {
            printf("Data bit rate:       ");
            if (machine_readable) {
                print_value("", 2, " bits/sec",    cf_info->data_rate*8);
            } else {
                size_string = format_size((int64_t)(cf_info->data_rate*8), FORMAT_SIZE_UNIT_BITS_S, 0);
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
                size_string = format_size((int64_t)cf_info->packet_rate, FORMAT_SIZE_UNIT_PACKETS_S, 0);
                printf ("%s\n", size_string);
                g_free(size_string);
            }
        }
    }
    if (cap_file_hashes) {
        printf     ("SHA256:              %s\n", file_sha256);
        printf     ("SHA1:                %s\n", file_sha1);
    }
    if (cap_order)          printf     ("Strict time order:   %s\n", order_string(cf_info->order));

    bool has_multiple_sections = (wtap_file_get_num_shbs(cf_info->wth) > 1);

    for (unsigned int section_number = 0;
            section_number < wtap_file_get_num_shbs(cf_info->wth);
            section_number++) {
        wtap_block_t shb;

        // If we have more than one section, add headers for each section.
        if (has_multiple_sections)
            printf("Section %u:\n\n", section_number);

        shb = wtap_file_get_shb(cf_info->wth, section_number);
        if (shb != NULL) {
            if (cap_file_more_info) {
                char *str;

                if (wtap_block_get_string_option_value(shb, OPT_SHB_HARDWARE, &str) == WTAP_OPTTYPE_SUCCESS)
                    show_option_string("Capture hardware:    ", str);
                if (wtap_block_get_string_option_value(shb, OPT_SHB_OS, &str) == WTAP_OPTTYPE_SUCCESS)
                    show_option_string("Capture oper-sys:    ", str);
                if (wtap_block_get_string_option_value(shb, OPT_SHB_USERAPPL, &str) == WTAP_OPTTYPE_SUCCESS)
                    show_option_string("Capture application: ", str);
            }
            if (cap_comment) {
                unsigned int i;
                char *str;

                for (i = 0; wtap_block_get_nth_string_option_value(shb, OPT_COMMENT, i, &str) == WTAP_OPTTYPE_SUCCESS; i++) {
                    show_option_string("Capture comment:     ", str);
                }
            }

            if (pkt_comments && cf_info->pkt_cmts != NULL) {
              for (p = cf_info->pkt_cmts; p != NULL; prev = p, p = p->next, g_free(prev)) {
                if (machine_readable){
                  printf("Packet %d Comment:    %s\n", p->recno, g_strescape(p->cmt, NULL));
                } else {
                  printf("Packet %d Comment:    %s\n", p->recno, p->cmt);
                }
                g_free(p->cmt);
              }
            }

            if (cap_file_idb && cf_info->num_interfaces != 0) {
                unsigned int i;
                ws_assert(cf_info->num_interfaces == cf_info->idb_info_strings->len);
                printf     ("Number of interfaces in file: %u\n", cf_info->num_interfaces);
                for (i = 0; i < cf_info->idb_info_strings->len; i++) {
                    char *s = g_array_index(cf_info->idb_info_strings, char*, i);
                    uint32_t packet_count = 0;
                    if (i < cf_info->interface_packet_counts->len)
                        packet_count = g_array_index(cf_info->interface_packet_counts, uint32_t, i);
                    printf   ("Interface #%u info:\n", i);
                    printf   ("%s", s);
                    printf   ("                     Number of packets = %u\n", packet_count);
                }
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
print_stats_table_header_label(const char *label)
{
    putsep();
    putquote();
    printf("%s", label);
    putquote();
}

static void
print_stats_table_header(capture_info *cf_info)
{
    pkt_cmt *p;
    char    *buf;
    size_t   buf_len;

    putquote();
    printf("File name");
    putquote();

    if (cap_file_type)      print_stats_table_header_label("File type");
    if (cap_file_encap)     print_stats_table_header_label("File encapsulation");
    if (cap_file_more_info) print_stats_table_header_label("File time precision");
    if (cap_snaplen) {
        print_stats_table_header_label("Packet size limit");
        print_stats_table_header_label("Packet size limit min (inferred)");
        print_stats_table_header_label("Packet size limit max (inferred)");
    }
    if (cap_packet_count)   print_stats_table_header_label("Number of packets");
    if (cap_file_size)      print_stats_table_header_label("File size (bytes)");
    if (cap_data_size)      print_stats_table_header_label("Data size (bytes)");
    if (cap_duration)       print_stats_table_header_label("Capture duration (seconds)");
    if (cap_earliest_packet_time) print_stats_table_header_label("Start time");
    if (cap_latest_packet_time) print_stats_table_header_label("End time");
    if (cap_data_rate_byte) print_stats_table_header_label("Data byte rate (bytes/sec)");
    if (cap_data_rate_bit)  print_stats_table_header_label("Data bit rate (bits/sec)");
    if (cap_packet_size)    print_stats_table_header_label("Average packet size (bytes)");
    if (cap_packet_rate)    print_stats_table_header_label("Average packet rate (packets/sec)");
    if (cap_file_hashes) {
        print_stats_table_header_label("SHA256");
        print_stats_table_header_label("SHA1");
    }
    if (cap_order)          print_stats_table_header_label("Strict time order");
    if (cap_file_more_info) {
        print_stats_table_header_label("Capture hardware");
        print_stats_table_header_label("Capture oper-sys");
        print_stats_table_header_label("Capture application");
    }
    if (cap_comment)        print_stats_table_header_label("Capture comment");

    if (pkt_comments && cf_info->pkt_cmts != NULL) {
      /* Packet 2^64 Comment" + NULL */
      buf_len = strlen("Packet 18446744073709551616 Comment") + 1;
      buf = (char *)g_malloc0(buf_len);

      for (p = cf_info->pkt_cmts; p != NULL; p = p->next) {
        snprintf(buf, buf_len, "Packet %d Comment", p->recno);
        print_stats_table_header_label(buf);
      }
    }

    printf("\n");
}

static void
print_stats_table(const char *filename, capture_info *cf_info)
{
    const char           *file_type_string, *file_encap_string;
    pkt_cmt               *p, *prev;

    /* Build printable strings for various stats */
    file_type_string = wtap_file_type_subtype_name(cf_info->file_type);
    file_encap_string = wtap_encap_name(cf_info->file_encap);

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
        printf("%" PRId64, cf_info->filesize);
        putquote();
    }

    if (cap_data_size) {
        putsep();
        putquote();
        printf("%" PRIu64, cf_info->packet_bytes);
        putquote();
    }

    if (cap_duration) {
        putsep();
        putquote();
        printf("%s", relative_time_string(&cf_info->duration, cf_info->duration_tsprec, cf_info, false));
        putquote();
    }

    if (cap_earliest_packet_time) {
        putsep();
        putquote();
        printf("%s", absolute_time_string(&cf_info->earliest_packet_time, cf_info->earliest_packet_time_tsprec, cf_info));
        putquote();
    }

    if (cap_latest_packet_time) {
        putsep();
        putquote();
        printf("%s", absolute_time_string(&cf_info->latest_packet_time, cf_info->latest_packet_time_tsprec, cf_info));
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
        printf("%s", file_sha1);
        putquote();
    }

    if (cap_order) {
        putsep();
        putquote();
        printf("%s", order_string(cf_info->order));
        putquote();
    }

    for (unsigned section_number = 0;
            section_number < wtap_file_get_num_shbs(cf_info->wth);
            section_number++) {
        wtap_block_t shb;

        shb = wtap_file_get_shb(cf_info->wth, section_number);
        if (cap_file_more_info) {
            char *str;

            putsep();
            putquote();
            if (wtap_block_get_string_option_value(shb, OPT_SHB_HARDWARE, &str) == WTAP_OPTTYPE_SUCCESS) {
                printf("%s", str);
            }
            putquote();

            putsep();
            putquote();
            if (wtap_block_get_string_option_value(shb, OPT_SHB_OS, &str) == WTAP_OPTTYPE_SUCCESS) {
                printf("%s", str);
            }
            putquote();

            putsep();
            putquote();
            if (wtap_block_get_string_option_value(shb, OPT_SHB_USERAPPL, &str) == WTAP_OPTTYPE_SUCCESS) {
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
         * more than one additional column and/or comments with embedded newlines
         * and/or possible delimiters).
         *
         * To mitigate embedded newlines and other special characters, use -M
         */
        if (cap_comment) {
            unsigned int i;
            char *opt_comment;
            bool have_cap = false;

            for (i = 0; wtap_block_get_nth_string_option_value(shb, OPT_COMMENT, i, &opt_comment) == WTAP_OPTTYPE_SUCCESS; i++) {
                have_cap = true;
                putsep();
                putquote();
                if (machine_readable){
                  printf("%s", g_strescape(opt_comment, NULL));
                } else {
                  printf("%s", opt_comment);
                }
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

    if (pkt_comments && cf_info->pkt_cmts != NULL) {
      for(p = cf_info->pkt_cmts; p != NULL; prev = p, p = p->next, g_free(prev)) {
        putsep();
        putquote();
        if (machine_readable) {
          printf("%s", g_strescape(p->cmt, NULL));
        } else {
          printf("%s", p->cmt);
        }
        g_free(p->cmt);
        putquote();
      }
    }

    printf("\n");
}

static void
cleanup_capture_info(capture_info *cf_info)
{
    unsigned int i;
    ws_assert(cf_info != NULL);

    g_free(cf_info->encap_counts);
    cf_info->encap_counts = NULL;

    g_array_free(cf_info->interface_packet_counts, true);
    cf_info->interface_packet_counts = NULL;

    if (cf_info->idb_info_strings) {
        for (i = 0; i < cf_info->idb_info_strings->len; i++) {
            char *s = g_array_index(cf_info->idb_info_strings, char*, i);
            g_free(s);
        }
        g_array_free(cf_info->idb_info_strings, true);
    }
    cf_info->idb_info_strings = NULL;
}

static void
count_ipv4_address(const unsigned int addr _U_, const char *name _U_, const bool static_entry _U_)
{
    num_ipv4_addresses++;
}

static void
count_ipv6_address(const void *addrp _U_, const char *name _U_, const bool static_entry _U_)
{
    num_ipv6_addresses++;
}

static void
count_decryption_secret(uint32_t secrets_type _U_, const void *secrets _U_, unsigned int size _U_)
{
    /* XXX - count them based on the secrets type (which is an opaque code,
       not a small integer)? */
    num_decryption_secrets++;
}

static void
hash_to_str(const unsigned char *hash, size_t length, char *str)
{
    int i;

    for (i = 0; i < (int) length; i++) {
        snprintf(str+(i*2), 3, "%02x", hash[i]);
    }
}

static void
calculate_hashes(const char *filename)
{
    FILE  *fh;
    size_t hash_bytes;

    (void) g_strlcpy(file_sha256, "<unknown>", HASH_STR_SIZE);
    (void) g_strlcpy(file_sha1, "<unknown>", HASH_STR_SIZE);

    if (cap_file_hashes) {
        fh = ws_fopen(filename, "rb");
        if (fh && hd) {
            while((hash_bytes = fread(hash_buf, 1, HASH_BUF_SIZE, fh)) > 0) {
                gcry_md_write(hd, hash_buf, hash_bytes);
            }
            gcry_md_final(hd);
            hash_to_str(gcry_md_read(hd, GCRY_MD_SHA256), HASH_SIZE_SHA256, file_sha256);
            hash_to_str(gcry_md_read(hd, GCRY_MD_SHA1), HASH_SIZE_SHA1, file_sha1);
        }
        if (fh) fclose(fh);
        if (hd) gcry_md_reset(hd);
    }
}

static int
process_cap_file(const char *filename, bool need_separator)
{
    int                   status = 0;
    int                   err;
    char                 *err_info;
    int64_t               size;
    int64_t               data_offset;

    uint32_t              packet = 0;
    int64_t               bytes  = 0;
    uint32_t              snaplen_min_inferred = 0xffffffff;
    uint32_t              snaplen_max_inferred =          0;
    wtap_rec              rec;
    Buffer                buf;
    capture_info          cf_info;
    bool                  have_times = true;
    nstime_t              earliest_packet_time;
    int                   earliest_packet_time_tsprec;
    nstime_t              latest_packet_time;
    int                   latest_packet_time_tsprec;
    nstime_t              cur_time;
    nstime_t              prev_time;
    bool                  know_order = false;
    order_t               order = IN_ORDER;
    unsigned int                 i;
    wtapng_iface_descriptions_t *idb_info;

    pkt_cmt *pc = NULL, *prev = NULL;

    cf_info.wth = wtap_open_offline(filename, WTAP_TYPE_AUTO, &err, &err_info, false);
    if (!cf_info.wth) {
        cfile_open_failure_message(filename, err, err_info);
        return 2;
    }

    /*
     * Calculate the checksums. Do this after wtap_open_offline, so we don't
     * bother calculating them for files that are not known capture types
     * where we wouldn't print them anyway.
     */
    calculate_hashes(filename);

    if (need_separator && long_report) {
        printf("\n");
    }

    nstime_set_zero(&earliest_packet_time);
    earliest_packet_time_tsprec = WTAP_TSPREC_UNKNOWN;
    nstime_set_zero(&latest_packet_time);
    latest_packet_time_tsprec = WTAP_TSPREC_UNKNOWN;
    nstime_set_zero(&cur_time);
    nstime_set_zero(&prev_time);

    cf_info.encap_counts = g_new0(int,WTAP_NUM_ENCAP_TYPES);

    idb_info = wtap_file_get_idb_info(cf_info.wth);

    ws_assert(idb_info->interface_data != NULL);

    cf_info.pkt_cmts = NULL;
    cf_info.num_interfaces = idb_info->interface_data->len;
    cf_info.interface_packet_counts  = g_array_sized_new(false, true, sizeof(uint32_t), cf_info.num_interfaces);
    g_array_set_size(cf_info.interface_packet_counts, cf_info.num_interfaces);
    cf_info.pkt_interface_id_unknown = 0;

    g_free(idb_info);
    idb_info = NULL;

    /* Zero out the counters for the callbacks. */
    num_ipv4_addresses = 0;
    num_ipv6_addresses = 0;
    num_decryption_secrets = 0;

    /* Register callbacks for new name<->address maps from the file and
       decryption secrets from the file. */
    wtap_set_cb_new_ipv4(cf_info.wth, count_ipv4_address);
    wtap_set_cb_new_ipv6(cf_info.wth, count_ipv6_address);
    wtap_set_cb_new_secrets(cf_info.wth, count_decryption_secret);

    /* Tally up data that we need to parse through the file to find */
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    while (wtap_read(cf_info.wth, &rec, &buf, &err, &err_info, &data_offset))  {
        if (rec.presence_flags & WTAP_HAS_TS) {
            prev_time = cur_time;
            cur_time = rec.ts;
            if (packet == 0) {
                earliest_packet_time = rec.ts;
                earliest_packet_time_tsprec = rec.tsprec;
                latest_packet_time  = rec.ts;
                latest_packet_time_tsprec = rec.tsprec;
                prev_time  = rec.ts;
            }
            if (nstime_cmp(&cur_time, &prev_time) < 0) {
                order = NOT_IN_ORDER;
            }
            if (nstime_cmp(&cur_time, &earliest_packet_time) < 0) {
                earliest_packet_time = cur_time;
                earliest_packet_time_tsprec = rec.tsprec;
            }
            if (nstime_cmp(&cur_time, &latest_packet_time) > 0) {
                latest_packet_time = cur_time;
                latest_packet_time_tsprec = rec.tsprec;
            }
        } else {
            have_times = false; /* at least one packet has no time stamp */
            if (order != NOT_IN_ORDER)
                order = ORDER_UNKNOWN;
        }

        if (rec.rec_type == REC_TYPE_PACKET) {
            bytes += rec.rec_header.packet_header.len;
            packet++;
            /* packet comments */
            if (pkt_comments && wtap_block_count_option(rec.block, OPT_COMMENT) > 0) {
              char *cmt_buff;
              for (i = 0; wtap_block_get_nth_string_option_value(rec.block, OPT_COMMENT, i, &cmt_buff) == WTAP_OPTTYPE_SUCCESS; i++) {
                pc = g_new0(pkt_cmt, 1);

                pc->recno = packet;
                pc->cmt = g_strdup(cmt_buff);
                pc->next = NULL;

                if (prev == NULL)
                  cf_info.pkt_cmts = pc;
                else
                  prev->next = pc;

                prev = pc;
              }
            }

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
                    idb_info = wtap_file_get_idb_info(cf_info.wth);

                    cf_info.num_interfaces = idb_info->interface_data->len;
                    g_array_set_size(cf_info.interface_packet_counts, cf_info.num_interfaces);

                    g_free(idb_info);
                    idb_info = NULL;
                }
                if (rec.rec_header.packet_header.interface_id < cf_info.num_interfaces) {
                    g_array_index(cf_info.interface_packet_counts, uint32_t,
                            rec.rec_header.packet_header.interface_id) += 1;
                }
                else {
                    cf_info.pkt_interface_id_unknown += 1;
                }
            }
            else {
                /* it's for interface_id 0 */
                if (cf_info.num_interfaces != 0) {
                    g_array_index(cf_info.interface_packet_counts, uint32_t, 0) += 1;
                }
                else {
                    cf_info.pkt_interface_id_unknown += 1;
                }
            }
        }

        wtap_rec_reset(&rec);
    } /* while */
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    /*
     * Get IDB info strings.
     * We do this at the end, so we can get information for all IDBs in
     * the file, even those that come after packet records, and so that
     * we get, for example, a count of the number of statistics entries
     * for each interface as of the *end* of the file.
     */
    idb_info = wtap_file_get_idb_info(cf_info.wth);

    cf_info.idb_info_strings = g_array_sized_new(false, false, sizeof(char*), cf_info.num_interfaces);
    cf_info.num_interfaces = idb_info->interface_data->len;
    for (i = 0; i < cf_info.num_interfaces; i++) {
        const wtap_block_t if_descr = g_array_index(idb_info->interface_data, wtap_block_t, i);
        char *s = wtap_get_debug_if_descr(if_descr, 21, "\n");
        g_array_append_val(cf_info.idb_info_strings, s);
    }

    g_free(idb_info);
    idb_info = NULL;

    if (err != 0) {
        fprintf(stderr,
                "capinfos: An error occurred after reading %u packets from \"%s\".\n",
                packet, filename);
        cfile_read_failure_message(filename, err, err_info);
        if (err == WTAP_ERR_SHORT_READ) {
            /* Don't give up completely with this one. */
            status = 1;
            fprintf(stderr,
                    "  (will continue anyway, checksums might be incorrect)\n");
        } else {
            cleanup_capture_info(&cf_info);
            wtap_close(cf_info.wth);
            return 2;
        }
    }

    /* File size */
    size = wtap_file_size(cf_info.wth, &err);
    if (size == -1) {
        fprintf(stderr,
                "capinfos: Can't get size of \"%s\": %s.\n",
                filename, g_strerror(err));
        cleanup_capture_info(&cf_info);
        wtap_close(cf_info.wth);
        return 2;
    }

    cf_info.filesize = size;

    /* File Type */
    cf_info.file_type = wtap_file_type_subtype(cf_info.wth);
    cf_info.compression_type = wtap_get_compression_type(cf_info.wth);

    /* File Encapsulation */
    cf_info.file_encap = wtap_file_encap(cf_info.wth);

    cf_info.file_tsprec = wtap_file_tsprec(cf_info.wth);

    /* Packet size limit (snaplen) */
    cf_info.snaplen = wtap_snapshot_length(cf_info.wth);
    if (cf_info.snaplen > 0)
        cf_info.snap_set = true;
    else
        cf_info.snap_set = false;

    cf_info.snaplen_min_inferred = snaplen_min_inferred;
    cf_info.snaplen_max_inferred = snaplen_max_inferred;

    /* # of packets */
    cf_info.packet_count = packet;

    /* File Times */
    cf_info.times_known = have_times;
    cf_info.earliest_packet_time = earliest_packet_time;
    cf_info.earliest_packet_time_tsprec = earliest_packet_time_tsprec;
    cf_info.latest_packet_time = latest_packet_time;
    cf_info.latest_packet_time_tsprec = latest_packet_time_tsprec;
    nstime_delta(&cf_info.duration, &latest_packet_time, &earliest_packet_time);
    /* Duration precision is the higher of the earliest and latest packet timestamp precisions. */
    if (cf_info.latest_packet_time_tsprec > cf_info.earliest_packet_time_tsprec)
        cf_info.duration_tsprec = cf_info.latest_packet_time_tsprec;
    else
        cf_info.duration_tsprec = cf_info.earliest_packet_time_tsprec;
    cf_info.know_order = know_order;
    cf_info.order = order;

    /* Number of packet bytes */
    cf_info.packet_bytes = bytes;

    cf_info.data_rate   = 0.0;
    cf_info.packet_rate = 0.0;
    cf_info.packet_size = 0.0;

    if (packet > 0) {
        double delta_time = nstime_to_sec(&latest_packet_time) - nstime_to_sec(&earliest_packet_time);
        if (delta_time > 0.0) {
            cf_info.data_rate   = (double)bytes  / delta_time; /* Data rate per second */
            cf_info.packet_rate = (double)packet / delta_time; /* packet rate per second */
        }
        cf_info.packet_size = (double)bytes / packet;                  /* Avg packet size      */
    }

    if (!long_report && table_report_header) {
      print_stats_table_header(&cf_info);
    }

    if (long_report) {
        print_stats(filename, &cf_info);
    } else {
        print_stats_table(filename, &cf_info);
    }

    cleanup_capture_info(&cf_info);
    wtap_close(cf_info.wth);

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
    fprintf(output, "  -H display the SHA256 and SHA1 hashes of the file\n");
    fprintf(output, "  -k display the capture comment\n");
    fprintf(output, "  -p display individual packet comments\n");
    fprintf(output, "\n");
    fprintf(output, "Size infos:\n");
    fprintf(output, "  -c display the number of packets\n");
    fprintf(output, "  -s display the size of the file (in bytes)\n");
    fprintf(output, "  -d display the total length of all packets (in bytes)\n");
    fprintf(output, "  -l display the packet size limit (snapshot length)\n");
    fprintf(output, "\n");
    fprintf(output, "Time infos:\n");
    fprintf(output, "  -u display the capture duration (in seconds)\n");
    fprintf(output, "  -a display the timestamp of the earliest packet\n");
    fprintf(output, "  -e display the timestamp of the latest packet\n");
    fprintf(output, "  -o display the capture file chronological status (True/False)\n");
    fprintf(output, "  -S display earliest and latest packet timestamps as seconds\n");
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
    fprintf(output, "  -h, --help               display this help and exit\n");
    fprintf(output, "  -v, --version            display version info and exit\n");
    fprintf(output, "  -C cancel processing if file open fails (default is to continue)\n");
    fprintf(output, "  -A generate all infos (default)\n");
    fprintf(output, "  -K disable displaying the capture comment\n");
    fprintf(output, "  -P disable displaying individual packet comments\n");
    fprintf(output, "\n");
    fprintf(output, "Options are processed from left to right order with later options superseding\n");
    fprintf(output, "or adding to earlier options.\n");
    fprintf(output, "\n");
    fprintf(output, "If no options are given the default is to display all infos in long report\n");
    fprintf(output, "output format.\n");
}

/*
 * Report an error in command-line arguments.
 */
static void
capinfos_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "capinfos: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
capinfos_cmdarg_err_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
    char  *configuration_init_error;
    static const struct report_message_routines capinfos_report_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };
    bool need_separator = false;
    int    opt;
    int    overall_error_status = EXIT_SUCCESS;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {0, 0, 0, 0 }
    };

    int status = 0;

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    cmdarg_err_init(capinfos_cmdarg_err, capinfos_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("capinfos", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, WS_EXIT_INVALID_OPTION);

    ws_noisy("Finished log init and parsing command line log arguments");

    /* Get the decimal point. */
    decimal_point = g_strdup(localeconv()->decimal_point);

    /* Initialize the version information. */
    ws_init_version_info("Capinfos", NULL, NULL);

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
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        fprintf(stderr,
                "capinfos: Can't get pathname of directory containing the capinfos program: %s.\n",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("capinfos", &capinfos_report_routines);

    wtap_init(true);

    /* Process the options */
    while ((opt = ws_getopt_long(argc, argv, "abcdehiklmnopqrstuvxyzABCDEFHIKLMNPQRST", long_options, NULL)) !=-1) {

        switch (opt) {

            case 't':
                if (report_all_infos) disable_all_infos();
                cap_file_type = true;
                break;

            case 'E':
                if (report_all_infos) disable_all_infos();
                cap_file_encap = true;
                break;

            case 'l':
                if (report_all_infos) disable_all_infos();
                cap_snaplen = true;
                break;

            case 'c':
                if (report_all_infos) disable_all_infos();
                cap_packet_count = true;
                break;

            case 's':
                if (report_all_infos) disable_all_infos();
                cap_file_size = true;
                break;

            case 'd':
                if (report_all_infos) disable_all_infos();
                cap_data_size = true;
                break;

            case 'u':
                if (report_all_infos) disable_all_infos();
                cap_duration = true;
                break;

            case 'a':
                if (report_all_infos) disable_all_infos();
                cap_earliest_packet_time = true;
                break;

            case 'e':
                if (report_all_infos) disable_all_infos();
                cap_latest_packet_time = true;
                break;

            case 'S':
                time_as_secs = true;
                break;

            case 'y':
                if (report_all_infos) disable_all_infos();
                cap_data_rate_byte = true;
                break;

            case 'i':
                if (report_all_infos) disable_all_infos();
                cap_data_rate_bit = true;
                break;

            case 'z':
                if (report_all_infos) disable_all_infos();
                cap_packet_size = true;
                break;

            case 'x':
                if (report_all_infos) disable_all_infos();
                cap_packet_rate = true;
                break;

            case 'H':
                if (report_all_infos) disable_all_infos();
                cap_file_hashes = true;
                break;

            case 'o':
                if (report_all_infos) disable_all_infos();
                cap_order = true;
                break;

            case 'k':
                if (report_all_infos) disable_all_infos();
                cap_comment = true;
                break;

            case 'p':
                if (report_all_infos) disable_all_infos();
                pkt_comments = true;
                break;

            case 'K':
                cap_comment = false;
                break;

            case 'P':
                pkt_comments = false;
                break;

            case 'F':
                if (report_all_infos) disable_all_infos();
                cap_file_more_info = true;
                break;

            case 'I':
                if (report_all_infos) disable_all_infos();
                cap_file_idb = true;
                break;

            case 'n':
                if (report_all_infos) disable_all_infos();
                cap_file_nrb = true;
                break;

            case 'D':
                if (report_all_infos) disable_all_infos();
                cap_file_dsb = true;
                break;

            case 'C':
                stop_after_failure = true;
                break;

            case 'A':
                enable_all_infos();
                break;

            case 'L':
                long_report = true;
                break;

            case 'T':
                long_report = false;
                break;

            case 'M':
                machine_readable = true;
                break;

            case 'R':
                table_report_header = true;
                break;

            case 'r':
                table_report_header = false;
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
                overall_error_status = WS_EXIT_INVALID_OPTION;
                goto exit;
                break;
        }
    }

    if ((argc - ws_optind) < 1) {
        print_usage(stderr);
        overall_error_status = WS_EXIT_INVALID_OPTION;
        goto exit;
    }

    if (cap_file_hashes) {
        gcry_check_version(NULL);
        gcry_md_open(&hd, GCRY_MD_SHA256, 0);
        if (hd)
            gcry_md_enable(hd, GCRY_MD_SHA1);

        hash_buf = (char *)g_malloc(HASH_BUF_SIZE);
    }

    overall_error_status = 0;

    for (opt = ws_optind; opt < argc; opt++) {

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
            need_separator = true;
        }
    }

exit:
    g_free(hash_buf);
    gcry_md_close(hd);
    wtap_cleanup();
    free_progdirs();
    return overall_error_status;
}
