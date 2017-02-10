/* editcap.c
 * Edit capture files.  We can delete packets, adjust timestamps, or
 * simply convert from one format to another format.
 *
 * Originally written by Richard Sharpe.
 * Improved by Guy Harris.
 * Further improved by Richard Sharpe.
 *
 * Copyright 2013, Richard Sharpe <realrichardsharpe[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2) but make sure we do this only if not
 * yet defined.
 */

#ifndef __USE_XOPEN
#  define __USE_XOPEN
#endif

#include <time.h>
#include <glib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <wiretap/wtap.h>

#include "epan/etypes.h"

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#include <process.h>    /* getpid */
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#endif

#ifndef HAVE_STRPTIME
# include "wsutil/strptime.h"
#endif

#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/md5.h>
#include <wsutil/plugins.h>
#include <wsutil/privileges.h>
#include <wsutil/report_err.h>
#include <wsutil/strnatcmp.h>
#include <wsutil/str_util.h>
#include <ws_version_info.h>
#include <wsutil/pint.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include "ringbuffer.h" /* For RINGBUFFER_MAX_NUM_FILES */

/*
 * Some globals so we can pass things to various routines
 */

struct select_item {
    gboolean inclusive;
    guint first, second;
};

/*
 * Duplicate frame detection
 */
typedef struct _fd_hash_t {
    md5_byte_t digest[16];
    guint32    len;
    nstime_t   frame_time;
} fd_hash_t;

#define DEFAULT_DUP_DEPTH       5   /* Used with -d */
#define MAX_DUP_DEPTH     1000000   /* the maximum window (and actual size of fd_hash[]) for de-duplication */

static fd_hash_t fd_hash[MAX_DUP_DEPTH];
static int       dup_window    = DEFAULT_DUP_DEPTH;
static int       cur_dup_entry = 0;

static int       ignored_bytes  = 0;  /* Used with -I */

#define ONE_BILLION 1000000000

/* Weights of different errors we can introduce */
/* We should probably make these command-line arguments */
/* XXX - Should we add a bit-level error? */
#define ERR_WT_BIT      5   /* Flip a random bit */
#define ERR_WT_BYTE     5   /* Substitute a random byte */
#define ERR_WT_ALNUM    5   /* Substitute a random character in [A-Za-z0-9] */
#define ERR_WT_FMT      2   /* Substitute "%s" */
#define ERR_WT_AA       1   /* Fill the remainder of the buffer with 0xAA */
#define ERR_WT_TOTAL    (ERR_WT_BIT + ERR_WT_BYTE + ERR_WT_ALNUM + ERR_WT_FMT + ERR_WT_AA)

#define ALNUM_CHARS     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define ALNUM_LEN       (sizeof(ALNUM_CHARS) - 1)

struct time_adjustment {
    nstime_t tv;
    int is_negative;
};

typedef struct _chop_t {
    int len_begin;
    int off_begin_pos;
    int off_begin_neg;
    int len_end;
    int off_end_pos;
    int off_end_neg;
} chop_t;


/* Table of user comments */
GTree *frames_user_comments = NULL;

#define MAX_SELECTIONS 512
static struct select_item     selectfrm[MAX_SELECTIONS];
static guint                  max_selected              = 0;
static int                    keep_em                   = 0;
#ifdef PCAP_NG_DEFAULT
static int                    out_file_type_subtype     = WTAP_FILE_TYPE_SUBTYPE_PCAPNG; /* default to pcapng   */
#else
static int                    out_file_type_subtype     = WTAP_FILE_TYPE_SUBTYPE_PCAP; /* default to pcap     */
#endif
static int                    out_frame_type            = -2; /* Leave frame type alone */
static int                    verbose                   = 0;  /* Not so verbose         */
static struct time_adjustment time_adj                  = {{0, 0}, 0}; /* no adjustment */
static nstime_t               relative_time_window      = {0, 0}; /* de-dup time window */
static double                 err_prob                  = 0.0;
static time_t                 starttime                 = 0;
static time_t                 stoptime                  = 0;
static gboolean               check_startstop           = FALSE;
static gboolean               rem_vlan                  = FALSE;
static gboolean               dup_detect                = FALSE;
static gboolean               dup_detect_by_time        = FALSE;

static int                    do_strict_time_adjustment = FALSE;
static struct time_adjustment strict_time_adj           = {{0, 0}, 0}; /* strict time adjustment */
static nstime_t               previous_time             = {0, 0}; /* previous time */

static int find_dct2000_real_data(guint8 *buf);
static void handle_chopping(chop_t chop, struct wtap_pkthdr *out_phdr,
                            const struct wtap_pkthdr *in_phdr, guint8 **buf,
                            gboolean adjlen);

static gchar *
abs_time_to_str_with_sec_resolution(const nstime_t *abs_time)
{
    struct tm *tmp;
    gchar     *buf = (gchar *)g_malloc(16);

    tmp = localtime(&abs_time->secs);

    if (tmp) {
        g_snprintf(buf, 16, "%d%02d%02d%02d%02d%02d",
            tmp->tm_year + 1900,
            tmp->tm_mon+1,
            tmp->tm_mday,
            tmp->tm_hour,
            tmp->tm_min,
            tmp->tm_sec);
    } else {
        buf[0] = '\0';
    }

    return buf;
}

static gchar *
fileset_get_filename_by_pattern(guint idx, const struct wtap_pkthdr *phdr,
                                gchar *fprefix, gchar *fsuffix)
{
    gchar  filenum[5+1];
    gchar *timestr;
    gchar *abs_str;

    g_snprintf(filenum, sizeof(filenum), "%05u", idx % RINGBUFFER_MAX_NUM_FILES);
    if (phdr->presence_flags & WTAP_HAS_TS) {
        timestr = abs_time_to_str_with_sec_resolution(&phdr->ts);
        abs_str = g_strconcat(fprefix, "_", filenum, "_", timestr, fsuffix, NULL);
        g_free(timestr);
    } else
        abs_str = g_strconcat(fprefix, "_", filenum, fsuffix, NULL);

    return abs_str;
}

static gboolean
fileset_extract_prefix_suffix(const char *fname, gchar **fprefix, gchar **fsuffix)
{
    char  *pfx, *last_pathsep;
    gchar *save_file;

    save_file = g_strdup(fname);
    if (save_file == NULL) {
        fprintf(stderr, "editcap: Out of memory\n");
        return FALSE;
    }

    last_pathsep = strrchr(save_file, G_DIR_SEPARATOR);
    pfx = strrchr(save_file,'.');
    if (pfx != NULL && (last_pathsep == NULL || pfx > last_pathsep)) {
        /* The pathname has a "." in it, and it's in the last component
         * of the pathname (because there is either only one component,
         * i.e. last_pathsep is null as there are no path separators,
         * or the "." is after the path separator before the last
         * component.

         * Treat it as a separator between the rest of the file name and
         * the file name suffix, and arrange that the names given to the
         * ring buffer files have the specified suffix, i.e. put the
         * changing part of the name *before* the suffix. */
        pfx[0] = '\0';
        *fprefix = g_strdup(save_file);
        pfx[0] = '.'; /* restore capfile_name */
        *fsuffix = g_strdup(pfx);
    } else {
        /* Either there's no "." in the pathname, or it's in a directory
         * component, so the last component has no suffix. */
        *fprefix = g_strdup(save_file);
        *fsuffix = NULL;
    }
    g_free(save_file);
    return TRUE;
}

/* Add a selection item, a simple parser for now */
static gboolean
add_selection(char *sel, guint* max_selection)
{
    char *locn;
    char *next;

    if (max_selected >= MAX_SELECTIONS) {
        /* Let the user know we stopped selecting */
        fprintf(stderr, "Out of room for packet selections!\n");
        return(FALSE);
    }

    if (verbose)
        fprintf(stderr, "Add_Selected: %s\n", sel);

    if ((locn = strchr(sel, '-')) == NULL) { /* No dash, so a single number? */
        if (verbose)
            fprintf(stderr, "Not inclusive ...");

        selectfrm[max_selected].inclusive = FALSE;
        selectfrm[max_selected].first = (guint)strtoul(sel, NULL, 10);
        if (selectfrm[max_selected].first > *max_selection)
            *max_selection = selectfrm[max_selected].first;

        if (verbose)
            fprintf(stderr, " %u\n", selectfrm[max_selected].first);
    } else {
        if (verbose)
            fprintf(stderr, "Inclusive ...");

        next = locn + 1;
        selectfrm[max_selected].inclusive = TRUE;
        selectfrm[max_selected].first = (guint)strtoul(sel, NULL, 10);
        selectfrm[max_selected].second = (guint)strtoul(next, NULL, 10);

        if (selectfrm[max_selected].second == 0)
        {
            /* Not a valid number, presume all */
            selectfrm[max_selected].second = *max_selection = G_MAXUINT;
        }
        else if (selectfrm[max_selected].second > *max_selection)
            *max_selection = selectfrm[max_selected].second;

        if (verbose)
            fprintf(stderr, " %u, %u\n", selectfrm[max_selected].first,
                   selectfrm[max_selected].second);
    }

    max_selected++;
    return(TRUE);
}

/* Was the packet selected? */

static int
selected(guint recno)
{
    guint i;

    for (i = 0; i < max_selected; i++) {
        if (selectfrm[i].inclusive) {
            if (selectfrm[i].first <= recno && selectfrm[i].second >= recno)
                return 1;
        } else {
            if (recno == selectfrm[i].first)
                return 1;
        }
    }

  return 0;
}

static void
set_time_adjustment(char *optarg_str_p)
{
    char   *frac, *end;
    long    val;
    size_t  frac_digits;

    if (!optarg_str_p)
        return;

    /* skip leading whitespace */
    while (*optarg_str_p == ' ' || *optarg_str_p == '\t')
        optarg_str_p++;

    /* check for a negative adjustment */
    if (*optarg_str_p == '-') {
        time_adj.is_negative = 1;
        optarg_str_p++;
    }

    /* collect whole number of seconds, if any */
    if (*optarg_str_p == '.') {         /* only fractional (i.e., .5 is ok) */
        val  = 0;
        frac = optarg_str_p;
    } else {
        val = strtol(optarg_str_p, &frac, 10);
        if (frac == NULL || frac == optarg_str_p
            || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            exit(1);
        }
        if (val < 0) {            /* implies '--' since we caught '-' above  */
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            exit(1);
        }
    }
    time_adj.tv.secs = val;

    /* now collect the partial seconds, if any */
    if (*frac != '\0') {             /* chars left, so get fractional part */
        val = strtol(&(frac[1]), &end, 10);
        /* if more than 9 fractional digits truncate to 9 */
        if ((end - &(frac[1])) > 9) {
            frac[10] = 't'; /* 't' for truncate */
            val = strtol(&(frac[1]), &end, 10);
        }
        if (*frac != '.' || end == NULL || end == frac || val < 0
            || val > ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            exit(1);
        }
    } else {
        return;                     /* no fractional digits */
    }

    /* adjust fractional portion from fractional to numerator
     * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
        val *= 10;
        frac_digits++;
    }

    time_adj.tv.nsecs = (int)val;
}

static void
set_strict_time_adj(char *optarg_str_p)
{
    char   *frac, *end;
    long    val;
    size_t  frac_digits;

    if (!optarg_str_p)
        return;

    /* skip leading whitespace */
    while (*optarg_str_p == ' ' || *optarg_str_p == '\t')
        optarg_str_p++;

    /*
     * check for a negative adjustment
     * A negative strict adjustment value is a flag
     * to adjust all frames by the specifed delta time.
     */
    if (*optarg_str_p == '-') {
        strict_time_adj.is_negative = 1;
        optarg_str_p++;
    }

    /* collect whole number of seconds, if any */
    if (*optarg_str_p == '.') {         /* only fractional (i.e., .5 is ok) */
        val  = 0;
        frac = optarg_str_p;
    } else {
        val = strtol(optarg_str_p, &frac, 10);
        if (frac == NULL || frac == optarg_str_p
            || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            exit(1);
        }
        if (val < 0) {            /* implies '--' since we caught '-' above  */
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            exit(1);
        }
    }
    strict_time_adj.tv.secs = val;

    /* now collect the partial seconds, if any */
    if (*frac != '\0') {             /* chars left, so get fractional part */
        val = strtol(&(frac[1]), &end, 10);
        /* if more than 9 fractional digits truncate to 9 */
        if ((end - &(frac[1])) > 9) {
            frac[10] = 't'; /* 't' for truncate */
            val = strtol(&(frac[1]), &end, 10);
        }
        if (*frac != '.' || end == NULL || end == frac || val < 0
            || val > ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            exit(1);
        }
    } else {
        return;                     /* no fractional digits */
    }

    /* adjust fractional portion from fractional to numerator
     * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
        val *= 10;
        frac_digits++;
    }

    strict_time_adj.tv.nsecs = (int)val;
}

static void
set_rel_time(char *optarg_str_p)
{
    char   *frac, *end;
    long    val;
    size_t  frac_digits;

    if (!optarg_str_p)
        return;

    /* skip leading whitespace */
    while (*optarg_str_p == ' ' || *optarg_str_p == '\t')
        optarg_str_p++;

    /* ignore negative adjustment  */
    if (*optarg_str_p == '-')
        optarg_str_p++;

    /* collect whole number of seconds, if any */
    if (*optarg_str_p == '.') {         /* only fractional (i.e., .5 is ok) */
        val  = 0;
        frac = optarg_str_p;
    } else {
        val = strtol(optarg_str_p, &frac, 10);
        if (frac == NULL || frac == optarg_str_p
            || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "1: editcap: \"%s\" isn't a valid rel time value\n",
                    optarg_str_p);
            exit(1);
        }
        if (val < 0) {            /* implies '--' since we caught '-' above  */
            fprintf(stderr, "2: editcap: \"%s\" isn't a valid rel time value\n",
                    optarg_str_p);
            exit(1);
        }
    }
    relative_time_window.secs = val;

    /* now collect the partial seconds, if any */
    if (*frac != '\0') {             /* chars left, so get fractional part */
        val = strtol(&(frac[1]), &end, 10);
        /* if more than 9 fractional digits truncate to 9 */
        if ((end - &(frac[1])) > 9) {
            frac[10] = 't'; /* 't' for truncate */
            val = strtol(&(frac[1]), &end, 10);
        }
        if (*frac != '.' || end == NULL || end == frac || val < 0
            || val > ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "3: editcap: \"%s\" isn't a valid rel time value\n",
                    optarg_str_p);
            exit(1);
        }
    } else {
        return;                     /* no fractional digits */
    }

    /* adjust fractional portion from fractional to numerator
     * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
        val *= 10;
        frac_digits++;
    }

    relative_time_window.nsecs = (int)val;
}

#define LINUX_SLL_OFFSETP 14
#define VLAN_SIZE 4
static void
sll_remove_vlan_info(guint8* fd, guint32* len) {
    if (pntoh16(fd + LINUX_SLL_OFFSETP) == ETHERTYPE_VLAN) {
        int rest_len;
        /* point to start of vlan */
        fd = fd + LINUX_SLL_OFFSETP;
        /* bytes to read after vlan info */
        rest_len = *len - (LINUX_SLL_OFFSETP + VLAN_SIZE);
        /* remove vlan info from packet */
        memmove(fd, fd + VLAN_SIZE, rest_len);
        *len -= 4;
    }
}

static void
remove_vlan_info(const struct wtap_pkthdr *phdr, guint8* fd, guint32* len) {
    switch (phdr->pkt_encap) {
        case WTAP_ENCAP_SLL:
            sll_remove_vlan_info(fd, len);
            break;
        default:
            /* no support for current pkt_encap */
            break;
    }
}

static gboolean
is_duplicate(guint8* fd, guint32 len) {
    int i;
    md5_state_t ms;

    /*Hint to ignore some bytes at the start of the frame for the digest calculation(-I option) */
    guint32 offset = ignored_bytes;
    guint32 new_len;
    guint8 *new_fd;

    if (len <= (guint32)ignored_bytes) {
        offset = 0;
    }

    new_fd  = &fd[offset];
    new_len = len - (offset);

    cur_dup_entry++;
    if (cur_dup_entry >= dup_window)
        cur_dup_entry = 0;

    /* Calculate our digest */
    md5_init(&ms);
    md5_append(&ms, new_fd, new_len);
    md5_finish(&ms, fd_hash[cur_dup_entry].digest);

    fd_hash[cur_dup_entry].len = len;

    /* Look for duplicates */
    for (i = 0; i < dup_window; i++) {
        if (i == cur_dup_entry)
            continue;

        if (fd_hash[i].len == fd_hash[cur_dup_entry].len
            && memcmp(fd_hash[i].digest, fd_hash[cur_dup_entry].digest, 16) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static gboolean
is_duplicate_rel_time(guint8* fd, guint32 len, const nstime_t *current) {
    int i;
    md5_state_t ms;

    /*Hint to ignore some bytes at the start of the frame for the digest calculation(-I option) */
    guint32 offset = ignored_bytes;
    guint32 new_len;
    guint8 *new_fd;

    if (len <= (guint32)ignored_bytes) {
        offset = 0;
    }

    new_fd  = &fd[offset];
    new_len = len - (offset);

    cur_dup_entry++;
    if (cur_dup_entry >= dup_window)
        cur_dup_entry = 0;

    /* Calculate our digest */
    md5_init(&ms);
    md5_append(&ms, new_fd, new_len);
    md5_finish(&ms, fd_hash[cur_dup_entry].digest);

    fd_hash[cur_dup_entry].len = len;
    fd_hash[cur_dup_entry].frame_time.secs = current->secs;
    fd_hash[cur_dup_entry].frame_time.nsecs = current->nsecs;

    /*
     * Look for relative time related duplicates.
     * This is hopefully a reasonably efficient mechanism for
     * finding duplicates by rel time in the fd_hash[] cache.
     * We check starting from the most recently added hash
     * entries and work backwards towards older packets.
     * This approach allows the dup test to be terminated
     * when the relative time of a cached entry is found to
     * be beyond the dup time window.
     *
     * Of course this assumes that the input trace file is
     * "well-formed" in the sense that the packet timestamps are
     * in strict chronologically increasing order (which is NOT
     * always the case!!).
     *
     * The fd_hash[] table was deliberately created large (1,000,000).
     * Looking for time related duplicates in large trace files with
     * non-fractional dup time window values can potentially take
     * a long time to complete.
     */

    for (i = cur_dup_entry - 1;; i--) {
        nstime_t delta;
        int cmp;

        if (i < 0)
            i = dup_window - 1;

        if (i == cur_dup_entry) {
            /*
             * We've decremented back to where we started.
             * Check no more!
             */
            break;
        }

        if (nstime_is_unset(&(fd_hash[i].frame_time))) {
            /*
             * We've decremented to an unused fd_hash[] entry.
             * Check no more!
             */
            break;
        }

        nstime_delta(&delta, current, &fd_hash[i].frame_time);

        if (delta.secs < 0 || delta.nsecs < 0) {
            /*
             * A negative delta implies that the current packet
             * has an absolute timestamp less than the cached packet
             * that it is being compared to.  This is NOT a normal
             * situation since trace files usually have packets in
             * chronological order (oldest to newest).
             *
             * There are several possible ways to deal with this:
             * 1. 'continue' dup checking with the next cached frame.
             * 2. 'break' from looking for a duplicate of the current frame.
             * 3. Take the absolute value of the delta and see if that
             * falls within the specifed dup time window.
             *
             * Currently this code does option 1.  But it would pretty
             * easy to add yet-another-editcap-option to select one of
             * the other behaviors for dealing with out-of-sequence
             * packets.
             */
            continue;
        }

        cmp = nstime_cmp(&delta, &relative_time_window);

        if (cmp > 0) {
            /*
             * The delta time indicates that we are now looking at
             * cached packets beyond the specified dup time window.
             * Check no more!
             */
            break;
        } else if (fd_hash[i].len == fd_hash[cur_dup_entry].len
                   && memcmp(fd_hash[i].digest, fd_hash[cur_dup_entry].digest, 16) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: editcap [options] ... <infile> <outfile> [ <packet#>[-<packet#>] ... ]\n");
    fprintf(output, "\n");
    fprintf(output, "<infile> and <outfile> must both be present.\n");
    fprintf(output, "A single packet or a range of packets can be selected.\n");
    fprintf(output, "\n");
    fprintf(output, "Packet selection:\n");
    fprintf(output, "  -r                     keep the selected packets; default is to delete them.\n");
    fprintf(output, "  -A <start time>        only output packets whose timestamp is after (or equal\n");
    fprintf(output, "                         to) the given time (format as YYYY-MM-DD hh:mm:ss).\n");
    fprintf(output, "  -B <stop time>         only output packets whose timestamp is before the\n");
    fprintf(output, "                         given time (format as YYYY-MM-DD hh:mm:ss).\n");
    fprintf(output, "\n");
    fprintf(output, "Duplicate packet removal:\n");
    fprintf(output, "  --novlan                remove vlan info from packets before checking for duplicates.\n");
    fprintf(output, "  -d                     remove packet if duplicate (window == %d).\n", DEFAULT_DUP_DEPTH);
    fprintf(output, "  -D <dup window>        remove packet if duplicate; configurable <dup window>\n");
    fprintf(output, "                         Valid <dup window> values are 0 to %d.\n", MAX_DUP_DEPTH);
    fprintf(output, "                         NOTE: A <dup window> of 0 with -v (verbose option) is\n");
    fprintf(output, "                         useful to print MD5 hashes.\n");
    fprintf(output, "  -w <dup time window>   remove packet if duplicate packet is found EQUAL TO OR\n");
    fprintf(output, "                         LESS THAN <dup time window> prior to current packet.\n");
    fprintf(output, "                         A <dup time window> is specified in relative seconds\n");
    fprintf(output, "                         (e.g. 0.000001).\n");
    fprintf(output, "  -a <framenum>:<comment>  Add or replace comment for given frame number\n");
    fprintf(output, "\n");
    fprintf(output, "  -I <bytes to ignore>   ignore the specified number of bytes at the beginning\n");
    fprintf(output, "                         of the frame during MD5 hash calculation, unless the\n");
    fprintf(output, "                         frame is too short, then the full frame is used.\n");
    fprintf(output, "                         Useful to remove duplicated packets taken on\n");
    fprintf(output, "                         several routers(differents mac addresses for \n");
    fprintf(output, "                         example)\n");
    fprintf(output, "                         e.g. -I 26 in case of Ether/IP/ will ignore \n");
    fprintf(output, "                         ether(14) and IP header(20 - 4(src ip) - 4(dst ip)).\n");
    fprintf(output, "\n");
    fprintf(output, "           NOTE: The use of the 'Duplicate packet removal' options with\n");
    fprintf(output, "           other editcap options except -v may not always work as expected.\n");
    fprintf(output, "           Specifically the -r, -t or -S options will very likely NOT have the\n");
    fprintf(output, "           desired effect if combined with the -d, -D or -w.\n");
    fprintf(output, "\n");
    fprintf(output, "Packet manipulation:\n");
    fprintf(output, "  -s <snaplen>           truncate each packet to max. <snaplen> bytes of data.\n");
    fprintf(output, "  -C [offset:]<choplen>  chop each packet by <choplen> bytes. Positive values\n");
    fprintf(output, "                         chop at the packet beginning, negative values at the\n");
    fprintf(output, "                         packet end. If an optional offset precedes the length,\n");
    fprintf(output, "                         then the bytes chopped will be offset from that value.\n");
    fprintf(output, "                         Positive offsets are from the packet beginning,\n");
    fprintf(output, "                         negative offsets are from the packet end. You can use\n");
    fprintf(output, "                         this option more than once, allowing up to 2 chopping\n");
    fprintf(output, "                         regions within a packet provided that at least 1\n");
    fprintf(output, "                         choplen is positive and at least 1 is negative.\n");
    fprintf(output, "  -L                     adjust the frame (i.e. reported) length when chopping\n");
    fprintf(output, "                         and/or snapping\n");
    fprintf(output, "  -t <time adjustment>   adjust the timestamp of each packet;\n");
    fprintf(output, "                         <time adjustment> is in relative seconds (e.g. -0.5).\n");
    fprintf(output, "  -S <strict adjustment> adjust timestamp of packets if necessary to insure\n");
    fprintf(output, "                         strict chronological increasing order. The <strict\n");
    fprintf(output, "                         adjustment> is specified in relative seconds with\n");
    fprintf(output, "                         values of 0 or 0.000001 being the most reasonable.\n");
    fprintf(output, "                         A negative adjustment value will modify timestamps so\n");
    fprintf(output, "                         that each packet's delta time is the absolute value\n");
    fprintf(output, "                         of the adjustment specified. A value of -0 will set\n");
    fprintf(output, "                         all packets to the timestamp of the first packet.\n");
    fprintf(output, "  -E <error probability> set the probability (between 0.0 and 1.0 incl.) that\n");
    fprintf(output, "                         a particular packet byte will be randomly changed.\n");
    fprintf(output, "  -o <change offset>     When used in conjunction with -E, skip some bytes from the\n");
    fprintf(output, "                         beginning of the packet. This allows one to preserve some\n");
    fprintf(output, "                         bytes, in order to have some headers untouched.\n");
    fprintf(output, "\n");
    fprintf(output, "Output File(s):\n");
    fprintf(output, "  -c <packets per file>  split the packet output to different files based on\n");
    fprintf(output, "                         uniform packet counts with a maximum of\n");
    fprintf(output, "                         <packets per file> each.\n");
    fprintf(output, "  -i <seconds per file>  split the packet output to different files based on\n");
    fprintf(output, "                         uniform time intervals with a maximum of\n");
    fprintf(output, "                         <seconds per file> each.\n");
    fprintf(output, "  -F <capture type>      set the output file type; default is pcapng. An empty\n");
    fprintf(output, "                         \"-F\" option will list the file types.\n");
    fprintf(output, "  -T <encap type>        set the output file encapsulation type; default is the\n");
    fprintf(output, "                         same as the input file. An empty \"-T\" option will\n");
    fprintf(output, "                         list the encapsulation types.\n");
    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h                     display this help and exit.\n");
    fprintf(output, "  -v                     verbose output.\n");
    fprintf(output, "                         If -v is used with any of the 'Duplicate Packet\n");
    fprintf(output, "                         Removal' options (-d, -D or -w) then Packet lengths\n");
    fprintf(output, "                         and MD5 hashes are printed to standard-error.\n");
    fprintf(output, "\n");
}

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

static gint
string_nat_compare(gconstpointer a, gconstpointer b)
{
    return ws_ascii_strnatcmp(((const struct string_elem *)a)->sstr,
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
    int i;
    struct string_elem *captypes;
    GSList *list = NULL;

    captypes = g_new(struct string_elem,WTAP_NUM_FILE_TYPES_SUBTYPES);
    fprintf(stderr, "editcap: The available capture file types for the \"-F\" flag are:\n");
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
list_encap_types(void) {
    int i;
    struct string_elem *encaps;
    GSList *list = NULL;

    encaps = (struct string_elem *)g_malloc(sizeof(struct string_elem) * WTAP_NUM_ENCAP_TYPES);
    fprintf(stderr, "editcap: The available encapsulation types for the \"-T\" flag are:\n");
    for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
        encaps[i].sstr = wtap_encap_short_string(i);
        if (encaps[i].sstr != NULL) {
            encaps[i].lstr = wtap_encap_string(i);
            list = g_slist_insert_sorted(list, &encaps[i], string_nat_compare);
        }
    }
    g_slist_foreach(list, string_elem_print, NULL);
    g_slist_free(list);
    g_free(encaps);
}

static int
framenum_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
    if (GPOINTER_TO_UINT(a) < GPOINTER_TO_UINT(b))
        return -1;

    if (GPOINTER_TO_UINT(a) > GPOINTER_TO_UINT(b))
        return 1;

    return 0;
}

#ifdef HAVE_PLUGINS
/*
 *  Don't report failures to load plugins because most (non-wiretap) plugins
 *  *should* fail to load (because we're not linked against libwireshark and
 *  dissector plugins need libwireshark).
 */
static void
failure_message(const char *msg_format _U_, va_list ap _U_)
{
}
#endif

static wtap_dumper *
editcap_dump_open(const char *filename, guint32 snaplen,
                  GArray* shb_hdrs,
                  wtapng_iface_descriptions_t *idb_inf,
                  GArray* nrb_hdrs, int *write_err)
{
  wtap_dumper *pdh;

  if (strcmp(filename, "-") == 0) {
    /* Write to the standard output. */
    pdh = wtap_dump_open_stdout_ng(out_file_type_subtype, out_frame_type,
                                   snaplen, FALSE /* compressed */,
                                   shb_hdrs, idb_inf, nrb_hdrs, write_err);
  } else {
    pdh = wtap_dump_open_ng(filename, out_file_type_subtype, out_frame_type,
                            snaplen, FALSE /* compressed */,
                            shb_hdrs, idb_inf, nrb_hdrs, write_err);
  }
  return pdh;
}

int
main(int argc, char *argv[])
{
    GString      *comp_info_str;
    GString      *runtime_info_str;
    char         *init_progfile_dir_error;
    wtap         *wth;
    int           i, j, read_err, write_err;
    gchar        *read_err_info, *write_err_info;
    int           opt;
    static const struct option long_options[] = {
        {"novlan", no_argument, NULL, 0x8100},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {0, 0, 0, 0 }
    };

    char         *p;
    guint32       snaplen            = 0; /* No limit               */
    chop_t        chop               = {0, 0, 0, 0, 0, 0}; /* No chop */
    gboolean      adjlen             = FALSE;
    wtap_dumper  *pdh                = NULL;
    unsigned int  count              = 1;
    unsigned int  duplicate_count    = 0;
    gint64        data_offset;
    int           err_type;
    guint8       *buf;
    guint32       read_count         = 0;
    int           split_packet_count = 0;
    int           written_count      = 0;
    char         *filename           = NULL;
    gboolean      ts_okay;
    int           secs_per_block     = 0;
    int           block_cnt          = 0;
    nstime_t      block_start;
    gchar        *fprefix            = NULL;
    gchar        *fsuffix            = NULL;
    guint32       change_offset      = 0;
    guint         max_packet_number  = 0;
    const struct wtap_pkthdr    *phdr;
    struct wtap_pkthdr           temp_phdr;
    wtapng_iface_descriptions_t *idb_inf = NULL;
    GArray                      *shb_hdrs = NULL;
    GArray                      *nrb_hdrs = NULL;
    char                        *shb_user_appl;


#ifdef _WIN32
    arg_list_utf_16to8(argc, argv);
    create_app_running_mutex();
#endif /* _WIN32 */

    /* Get the compile-time version information string */
    comp_info_str = get_compiled_version_info(NULL, NULL);

    /* Get the run-time version information string */
    runtime_info_str = get_runtime_version_info(NULL);

    /* Add it to the information to be reported on a crash. */
    ws_add_crash_info("Editcap (Wireshark) %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    init_progfile_dir_error = init_progfile_dir(argv[0], main);
    if (init_progfile_dir_error != NULL) {
        fprintf(stderr,
                "editcap: Can't get pathname of directory containing the editcap program: %s.\n",
                init_progfile_dir_error);
        g_free(init_progfile_dir_error);
    }

    wtap_init();

#ifdef HAVE_PLUGINS
    /* Register wiretap plugins */
    init_report_err(failure_message,NULL,NULL,NULL);

    /* Scan for plugins.  This does *not* call their registration routines;
        that's done later. */
    scan_plugins();

    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();
#endif

    /* Process the options */
    while ((opt = getopt_long(argc, argv, "a:A:B:c:C:dD:E:F:hi:I:Lo:rs:S:t:T:vVw:", long_options, NULL)) != -1) {
        switch (opt) {
        case 0x8100:
        {
            rem_vlan = TRUE;
            break;
        }

        case 'a':
        {
            guint frame_number;
            gint string_start_index = 0;

            if ((sscanf(optarg, "%u:%n", &frame_number, &string_start_index) < 1) || (string_start_index == 0)) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid <frame>:<comment>\n\n",
                        optarg);
                exit(1);
            }

            /* Lazily create the table */
            if (!frames_user_comments) {
                frames_user_comments = g_tree_new_full(framenum_compare, NULL, NULL, g_free);
            }

            /* Insert this entry (framenum -> comment) */
            g_tree_replace(frames_user_comments, GUINT_TO_POINTER(frame_number), g_strdup(optarg+string_start_index));
            break;
        }

        case 'A':
        {
            struct tm starttm;

            memset(&starttm,0,sizeof(struct tm));

            if (!strptime(optarg,"%Y-%m-%d %T", &starttm)) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid time format\n\n",
                        optarg);
                exit(1);
            }

            check_startstop = TRUE;
            starttm.tm_isdst = -1;

            starttime = mktime(&starttm);
            break;
        }

        case 'B':
        {
            struct tm stoptm;

            memset(&stoptm,0,sizeof(struct tm));

            if (!strptime(optarg,"%Y-%m-%d %T", &stoptm)) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid time format\n\n",
                        optarg);
                exit(1);
            }
            check_startstop = TRUE;
            stoptm.tm_isdst = -1;
            stoptime = mktime(&stoptm);
            break;
        }

        case 'c':
            split_packet_count = (int)strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "editcap: \"%s\" isn't a valid packet count\n",
                        optarg);
                exit(1);
            }
            if (split_packet_count <= 0) {
                fprintf(stderr, "editcap: \"%d\" packet count must be larger than zero\n",
                        split_packet_count);
                exit(1);
            }
            break;

        case 'C':
        {
            int choplen = 0, chopoff = 0;

            switch (sscanf(optarg, "%d:%d", &chopoff, &choplen)) {
            case 1: /* only the chop length was specififed */
                choplen = chopoff;
                chopoff = 0;
                break;

            case 2: /* both an offset and chop length was specified */
                break;

            default:
                fprintf(stderr, "editcap: \"%s\" isn't a valid chop length or offset:length\n",
                        optarg);
                exit(1);
                break;
            }

            if (choplen > 0) {
                chop.len_begin += choplen;
                if (chopoff > 0)
                    chop.off_begin_pos += chopoff;
                else
                    chop.off_begin_neg += chopoff;
            } else if (choplen < 0) {
                chop.len_end += choplen;
                if (chopoff > 0)
                    chop.off_end_pos += chopoff;
                else
                    chop.off_end_neg += chopoff;
            }
            break;
        }

        case 'd':
            dup_detect = TRUE;
            dup_detect_by_time = FALSE;
            dup_window = DEFAULT_DUP_DEPTH;
            break;

        case 'D':
            dup_detect = TRUE;
            dup_detect_by_time = FALSE;
            dup_window = (int)strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "editcap: \"%s\" isn't a valid duplicate window value\n",
                        optarg);
                exit(1);
            }
            if (dup_window < 0 || dup_window > MAX_DUP_DEPTH) {
                fprintf(stderr, "editcap: \"%d\" duplicate window value must be between 0 and %d inclusive.\n",
                        dup_window, MAX_DUP_DEPTH);
                exit(1);
            }
            break;

        case 'E':
            err_prob = g_ascii_strtod(optarg, &p);
            if (p == optarg || err_prob < 0.0 || err_prob > 1.0) {
                fprintf(stderr, "editcap: probability \"%s\" must be between 0.0 and 1.0\n",
                        optarg);
                exit(1);
            }
            srand( (unsigned int) (time(NULL) + ws_getpid()) );
            break;

        case 'F':
            out_file_type_subtype = wtap_short_string_to_file_type_subtype(optarg);
            if (out_file_type_subtype < 0) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid capture file type\n\n",
                        optarg);
                list_capture_types();
                exit(1);
            }
            break;

        case 'h':
            printf("Editcap (Wireshark) %s\n"
                   "Edit and/or translate the format of capture files.\n"
                   "See https://www.wireshark.org for more information.\n",
               get_ws_vcs_version_info());
            print_usage(stdout);
            exit(0);
            break;

        case 'i': /* break capture file based on time interval */
            secs_per_block = atoi(optarg);
            if (secs_per_block <= 0) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid time interval\n\n",
                        optarg);
                exit(1);
            }
            break;

        case 'I': /* ignored_bytes at the beginning of the frame for duplications removal */
            ignored_bytes = atoi(optarg);
            if(ignored_bytes <= 0) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid number of bytes to ignore\n", optarg);
                exit(1);
            }
            break;

        case 'L':
            adjlen = TRUE;
            break;

        case 'o':
            change_offset = (guint32)strtol(optarg, &p, 10);
            break;

        case 'r':
            keep_em = !keep_em;  /* Just invert */
            break;

        case 's':
            snaplen = (guint32)strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "editcap: \"%s\" isn't a valid snapshot length\n",
                        optarg);
                exit(1);
            }
            break;

        case 'S':
            set_strict_time_adj(optarg);
            do_strict_time_adjustment = TRUE;
            break;

        case 't':
            set_time_adjustment(optarg);
            break;

        case 'T':
            out_frame_type = wtap_short_string_to_encap(optarg);
            if (out_frame_type < 0) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid encapsulation type\n\n",
                        optarg);
                list_encap_types();
                exit(1);
            }
            break;

        case 'v':
            verbose = !verbose;  /* Just invert */
            break;

        case 'V':
            show_version("Editcap (Wireshark)", comp_info_str, runtime_info_str);
            g_string_free(comp_info_str, TRUE);
            g_string_free(runtime_info_str, TRUE);
            exit(0);
            break;

        case 'w':
            dup_detect = FALSE;
            dup_detect_by_time = TRUE;
            dup_window = MAX_DUP_DEPTH;
            set_rel_time(optarg);
            break;

        case '?':              /* Bad options if GNU getopt */
            switch(optopt) {
            case'F':
                list_capture_types();
                break;
            case'T':
                list_encap_types();
                break;
            default:
                print_usage(stderr);
                break;
            }
            exit(1);
            break;
        }
    } /* processing commmand-line options */

#ifdef DEBUG
    fprintf(stderr, "Optind = %i, argc = %i\n", optind, argc);
#endif

    if ((argc - optind) < 1) {
        print_usage(stderr);
        exit(1);
    }

    if (check_startstop && !stoptime) {
        struct tm stoptm;

        /* XXX: will work until 2035 */
        memset(&stoptm,0,sizeof(struct tm));
        stoptm.tm_year = 135;
        stoptm.tm_mday = 31;
        stoptm.tm_mon = 11;

        stoptime = mktime(&stoptm);
    }

    nstime_set_unset(&block_start);

    if (starttime > stoptime) {
        fprintf(stderr, "editcap: start time is after the stop time\n");
        exit(1);
    }

    if (split_packet_count > 0 && secs_per_block > 0) {
        fprintf(stderr, "editcap: can't split on both packet count and time interval\n");
        fprintf(stderr, "editcap: at the same time\n");
        exit(1);
    }

    wth = wtap_open_offline(argv[optind], WTAP_TYPE_AUTO, &read_err, &read_err_info, FALSE);

    if (!wth) {
        fprintf(stderr, "editcap: Can't open %s: %s\n", argv[optind],
                wtap_strerror(read_err));
        if (read_err_info != NULL) {
            fprintf(stderr, "(%s)\n", read_err_info);
            g_free(read_err_info);
        }
        exit(2);
    }

    if (verbose) {
        fprintf(stderr, "File %s is a %s capture file.\n", argv[optind],
                wtap_file_type_subtype_string(wtap_file_type_subtype(wth)));
    }

    shb_hdrs = wtap_file_get_shb_for_new_file(wth);
    idb_inf = wtap_file_get_idb_info(wth);
    nrb_hdrs = wtap_file_get_nrb_for_new_file(wth);

    /*
     * Now, process the rest, if any ... we only write if there is an extra
     * argument or so ...
     */

    if ((argc - optind) >= 2) {
        if (out_frame_type == -2)
            out_frame_type = wtap_file_encap(wth);

        for (i = optind + 2; i < argc; i++)
            if (add_selection(argv[i], &max_packet_number) == FALSE)
                break;

        if (keep_em == FALSE)
            max_packet_number = G_MAXUINT;

        if (dup_detect || dup_detect_by_time) {
            for (i = 0; i < dup_window; i++) {
                memset(&fd_hash[i].digest, 0, 16);
                fd_hash[i].len = 0;
                nstime_set_unset(&fd_hash[i].frame_time);
            }
        }

        /* Read all of the packets in turn */
        while (wtap_read(wth, &read_err, &read_err_info, &data_offset)) {
            if (max_packet_number <= read_count)
                break;

            read_count++;

            phdr = wtap_phdr(wth);

            /* Extra actions for the first packet */
            if (read_count == 1) {
                if (split_packet_count > 0 || secs_per_block > 0) {
                    if (!fileset_extract_prefix_suffix(argv[optind+1], &fprefix, &fsuffix))
                        goto error_on_exit;

                    filename = fileset_get_filename_by_pattern(block_cnt++, phdr, fprefix, fsuffix);
                } else {
                    filename = g_strdup(argv[optind+1]);
                }
                g_assert(filename);

                /* If we don't have an application name add Editcap */
                if (wtap_block_get_string_option_value(g_array_index(shb_hdrs, wtap_block_t, 0), OPT_SHB_USERAPPL, &shb_user_appl) != WTAP_OPTTYPE_SUCCESS) {
                    wtap_block_add_string_option_format(g_array_index(shb_hdrs, wtap_block_t, 0), OPT_SHB_USERAPPL, "Editcap " VERSION);
                }

                pdh = editcap_dump_open(filename,
                                        snaplen ? MIN(snaplen, wtap_snapshot_length(wth)) : wtap_snapshot_length(wth),
                                        shb_hdrs, idb_inf, nrb_hdrs, &write_err);

                if (pdh == NULL) {
                    fprintf(stderr, "editcap: Can't open or create %s: %s\n",
                            filename, wtap_strerror(write_err));
                    goto error_on_exit;
                }
            } /* first packet only handling */


            buf = wtap_buf_ptr(wth);

            /*
             * Not all packets have time stamps. Only process the time
             * stamp if we have one.
             */
            if (phdr->presence_flags & WTAP_HAS_TS) {
                if (nstime_is_unset(&block_start)) {
                    block_start = phdr->ts;
                }

                if (secs_per_block > 0) {
                    while ((phdr->ts.secs - block_start.secs >  secs_per_block)
                           || (phdr->ts.secs - block_start.secs == secs_per_block
                               && phdr->ts.nsecs >= block_start.nsecs )) { /* time for the next file */

                        if (!wtap_dump_close(pdh, &write_err)) {
                            fprintf(stderr, "editcap: Error writing to %s: %s\n",
                                    filename, wtap_strerror(write_err));
                            goto error_on_exit;
                        }
                        block_start.secs = block_start.secs +  secs_per_block; /* reset for next interval */
                        g_free(filename);
                        filename = fileset_get_filename_by_pattern(block_cnt++, phdr, fprefix, fsuffix);
                        g_assert(filename);

                        if (verbose)
                            fprintf(stderr, "Continuing writing in file %s\n", filename);

                        pdh = editcap_dump_open(filename,
                                                snaplen ? MIN(snaplen, wtap_snapshot_length(wth)) : wtap_snapshot_length(wth),
                                                shb_hdrs, idb_inf, nrb_hdrs, &write_err);

                        if (pdh == NULL) {
                            fprintf(stderr, "editcap: Can't open or create %s: %s\n",
                                    filename, wtap_strerror(write_err));
                            goto error_on_exit;
                        }
                    }
                }
            }  /* time stamp handling */

            if (split_packet_count > 0) {
                /* time for the next file? */
                if (written_count > 0 && written_count % split_packet_count == 0) {
                    if (!wtap_dump_close(pdh, &write_err)) {
                        fprintf(stderr, "editcap: Error writing to %s: %s\n",
                                filename, wtap_strerror(write_err));
                        goto error_on_exit;
                    }

                    g_free(filename);
                    filename = fileset_get_filename_by_pattern(block_cnt++, phdr, fprefix, fsuffix);
                    g_assert(filename);

                    if (verbose)
                        fprintf(stderr, "Continuing writing in file %s\n", filename);

                    pdh = editcap_dump_open(filename,
                                            snaplen ? MIN(snaplen, wtap_snapshot_length(wth)) : wtap_snapshot_length(wth),
                                            shb_hdrs, idb_inf, nrb_hdrs, &write_err);
                    if (pdh == NULL) {
                        fprintf(stderr, "editcap: Can't open or create %s: %s\n",
                                filename, wtap_strerror(write_err));
                        goto error_on_exit;
                    }
                }
            } /* split packet handling */

            if (check_startstop) {
                /*
                 * Is the packet in the selected timeframe?
                 * If the packet has no time stamp, the answer is "no".
                 */
                if (phdr->presence_flags & WTAP_HAS_TS)
                    ts_okay = (phdr->ts.secs >= starttime) && (phdr->ts.secs < stoptime);
                else
                    ts_okay = FALSE;
            } else {
                /*
                 * No selected timeframe, so all packets are "in the
                 * selected timeframe".
                 */
                ts_okay = TRUE;
            }

            if (ts_okay && ((!selected(count) && !keep_em)
                            || (selected(count) && keep_em))) {

                if (verbose && !dup_detect && !dup_detect_by_time)
                    fprintf(stderr, "Packet: %u\n", count);

                /* We simply write it, perhaps after truncating it; we could
                 * do other things, like modify it. */

                phdr = wtap_phdr(wth);

                if (snaplen != 0) {
                    /* Limit capture length to snaplen */
                    if (phdr->caplen > snaplen) {
                        /* Copy and change rather than modify returned phdr */
                        temp_phdr = *phdr;
                        temp_phdr.caplen = snaplen;
                        phdr = &temp_phdr;
                    }
                    /* If -L, also set reported length to snaplen */
                    if (adjlen && phdr->len > snaplen) {
                        /* Copy and change rather than modify returned phdr */
                        temp_phdr = *phdr;
                        temp_phdr.len = snaplen;
                        phdr = &temp_phdr;
                    }
                }

                /* CHOP */
                temp_phdr = *phdr;
                handle_chopping(chop, &temp_phdr, phdr, &buf, adjlen);
                phdr = &temp_phdr;

                if (phdr->presence_flags & WTAP_HAS_TS) {
                    /* Do we adjust timestamps to ensure strict chronological
                     * order? */
                    if (do_strict_time_adjustment) {
                        if (previous_time.secs || previous_time.nsecs) {
                            if (!strict_time_adj.is_negative) {
                                nstime_t current;
                                nstime_t delta;

                                current = phdr->ts;

                                nstime_delta(&delta, &current, &previous_time);

                                if (delta.secs < 0 || delta.nsecs < 0) {
                                    /*
                                     * A negative delta indicates that the current packet
                                     * has an absolute timestamp less than the previous packet
                                     * that it is being compared to.  This is NOT a normal
                                     * situation since trace files usually have packets in
                                     * chronological order (oldest to newest).
                                     */
                                    /* fprintf(stderr, "++out of order, need to adjust this packet!\n"); */
                                    temp_phdr = *phdr;
                                    temp_phdr.ts.secs = previous_time.secs + strict_time_adj.tv.secs;
                                    temp_phdr.ts.nsecs = previous_time.nsecs;
                                    if (temp_phdr.ts.nsecs + strict_time_adj.tv.nsecs > ONE_BILLION) {
                                        /* carry */
                                        temp_phdr.ts.secs++;
                                        temp_phdr.ts.nsecs += strict_time_adj.tv.nsecs - ONE_BILLION;
                                    } else {
                                        temp_phdr.ts.nsecs += strict_time_adj.tv.nsecs;
                                    }
                                    phdr = &temp_phdr;
                                }
                            } else {
                                /*
                                 * A negative strict time adjustment is requested.
                                 * Unconditionally set each timestamp to previous
                                 * packet's timestamp plus delta.
                                 */
                                temp_phdr = *phdr;
                                temp_phdr.ts.secs = previous_time.secs + strict_time_adj.tv.secs;
                                temp_phdr.ts.nsecs = previous_time.nsecs;
                                if (temp_phdr.ts.nsecs + strict_time_adj.tv.nsecs > ONE_BILLION) {
                                    /* carry */
                                    temp_phdr.ts.secs++;
                                    temp_phdr.ts.nsecs += strict_time_adj.tv.nsecs - ONE_BILLION;
                                } else {
                                    temp_phdr.ts.nsecs += strict_time_adj.tv.nsecs;
                                }
                                phdr = &temp_phdr;
                            }
                        }
                        previous_time = phdr->ts;
                    }

                    if (time_adj.tv.secs != 0) {
                        temp_phdr = *phdr;
                        if (time_adj.is_negative)
                            temp_phdr.ts.secs -= time_adj.tv.secs;
                        else
                            temp_phdr.ts.secs += time_adj.tv.secs;
                        phdr = &temp_phdr;
                    }

                    if (time_adj.tv.nsecs != 0) {
                        temp_phdr = *phdr;
                        if (time_adj.is_negative) { /* subtract */
                            if (temp_phdr.ts.nsecs < time_adj.tv.nsecs) { /* borrow */
                                temp_phdr.ts.secs--;
                                temp_phdr.ts.nsecs += ONE_BILLION;
                            }
                            temp_phdr.ts.nsecs -= time_adj.tv.nsecs;
                        } else {                  /* add */
                            if (temp_phdr.ts.nsecs + time_adj.tv.nsecs > ONE_BILLION) {
                                /* carry */
                                temp_phdr.ts.secs++;
                                temp_phdr.ts.nsecs += time_adj.tv.nsecs - ONE_BILLION;
                            } else {
                                temp_phdr.ts.nsecs += time_adj.tv.nsecs;
                            }
                        }
                        phdr = &temp_phdr;
                    }
                } /* time stamp adjustment */

                /* remove vlan info */
                if (rem_vlan) {
                    /* TODO: keep casting const like this? change pointer instead of value? */
                    remove_vlan_info(phdr, buf, (guint32 *) &phdr->caplen);
                }

                /* suppress duplicates by packet window */
                if (dup_detect) {
                    if (is_duplicate(buf, phdr->caplen)) {
                        if (verbose) {
                            fprintf(stderr, "Skipped: %u, Len: %u, MD5 Hash: ",
                                    count, phdr->caplen);
                            for (i = 0; i < 16; i++)
                                fprintf(stderr, "%02x",
                                        (unsigned char)fd_hash[cur_dup_entry].digest[i]);
                            fprintf(stderr, "\n");
                        }
                        duplicate_count++;
                        count++;
                        continue;
                    } else {
                        if (verbose) {
                            fprintf(stderr, "Packet: %u, Len: %u, MD5 Hash: ",
                                    count, phdr->caplen);
                            for (i = 0; i < 16; i++)
                                fprintf(stderr, "%02x",
                                        (unsigned char)fd_hash[cur_dup_entry].digest[i]);
                            fprintf(stderr, "\n");
                        }
                    }
                } /* suppression of duplicates */

                if (phdr->presence_flags & WTAP_HAS_TS) {
                    /* suppress duplicates by time window */
                    if (dup_detect_by_time) {
                        nstime_t current;

                        current.secs  = phdr->ts.secs;
                        current.nsecs = phdr->ts.nsecs;

                        if (is_duplicate_rel_time(buf, phdr->caplen, &current)) {
                            if (verbose) {
                                fprintf(stderr, "Skipped: %u, Len: %u, MD5 Hash: ",
                                        count, phdr->caplen);
                                for (i = 0; i < 16; i++)
                                    fprintf(stderr, "%02x",
                                            (unsigned char)fd_hash[cur_dup_entry].digest[i]);
                                fprintf(stderr, "\n");
                            }
                            duplicate_count++;
                            count++;
                            continue;
                        } else {
                            if (verbose) {
                                fprintf(stderr, "Packet: %u, Len: %u, MD5 Hash: ",
                                        count, phdr->caplen);
                                for (i = 0; i < 16; i++)
                                    fprintf(stderr, "%02x",
                                            (unsigned char)fd_hash[cur_dup_entry].digest[i]);
                                fprintf(stderr, "\n");
                            }
                        }
                    }
                } /* suppress duplicates by time window */

                if (change_offset > phdr->caplen) {
                    fprintf(stderr, "change offset %u is longer than caplen %u in packet %u\n",
                        change_offset, phdr->caplen, count);
                }

                /* Random error mutation */
                if (err_prob > 0.0 && change_offset <= phdr->caplen) {
                    int real_data_start = 0;

                    /* Protect non-protocol data */
                    if (wtap_file_type_subtype(wth) == WTAP_FILE_TYPE_SUBTYPE_CATAPULT_DCT2000)
                        real_data_start = find_dct2000_real_data(buf);

                    real_data_start += change_offset;

                    for (i = real_data_start; i < (int) phdr->caplen; i++) {
                        if (rand() <= err_prob * RAND_MAX) {
                            err_type = rand() / (RAND_MAX / ERR_WT_TOTAL + 1);

                            if (err_type < ERR_WT_BIT) {
                                buf[i] ^= 1 << (rand() / (RAND_MAX / 8 + 1));
                                err_type = ERR_WT_TOTAL;
                            } else {
                                err_type -= ERR_WT_BYTE;
                            }

                            if (err_type < ERR_WT_BYTE) {
                                buf[i] = rand() / (RAND_MAX / 255 + 1);
                                err_type = ERR_WT_TOTAL;
                            } else {
                                err_type -= ERR_WT_BYTE;
                            }

                            if (err_type < ERR_WT_ALNUM) {
                                buf[i] = ALNUM_CHARS[rand() / (RAND_MAX / ALNUM_LEN + 1)];
                                err_type = ERR_WT_TOTAL;
                            } else {
                                err_type -= ERR_WT_ALNUM;
                            }

                            if (err_type < ERR_WT_FMT) {
                                if ((unsigned int)i < phdr->caplen - 2)
                                    g_strlcpy((char*) &buf[i], "%s", 2);
                                err_type = ERR_WT_TOTAL;
                            } else {
                                err_type -= ERR_WT_FMT;
                            }

                            if (err_type < ERR_WT_AA) {
                                for (j = i; j < (int) phdr->caplen; j++)
                                    buf[j] = 0xAA;
                                i = phdr->caplen;
                            }
                        }
                    }
                } /* random error mutation */

                /* Find a packet comment we may need to write */
                if (frames_user_comments) {
                    const char *comment =
                        (const char*)g_tree_lookup(frames_user_comments, GUINT_TO_POINTER(read_count));
                    if (comment != NULL) {
                        /* Copy and change rather than modify returned phdr */
                        temp_phdr = *phdr;
                        temp_phdr.opt_comment = g_strdup(comment);
                        phdr = &temp_phdr;
                    }
                }

                /* Attempt to dump out current frame to the output file */
                if (!wtap_dump(pdh, phdr, buf, &write_err, &write_err_info)) {
                    switch (write_err) {
                    case WTAP_ERR_UNWRITABLE_ENCAP:
                        /*
                         * This is a problem with the particular frame we're
                         * writing and the file type and subtype we're
                         * writing; note that, and report the frame number
                         * and file type/subtype.
                         */
                        fprintf(stderr,
                                "editcap: Frame %u of \"%s\" has a network type that can't be saved in a \"%s\" file.\n",
                                read_count, argv[optind],
                                wtap_file_type_subtype_string(out_file_type_subtype));
                        break;

                    case WTAP_ERR_PACKET_TOO_LARGE:
                        /*
                         * This is a problem with the particular frame we're
                         * writing and the file type and subtype we're
                         * writing; note that, and report the frame number
                         * and file type/subtype.
                         */
                        fprintf(stderr,
                                "editcap: Frame %u of \"%s\" is too large for a \"%s\" file.\n",
                                read_count, argv[optind],
                                wtap_file_type_subtype_string(out_file_type_subtype));
                        break;

                    case WTAP_ERR_UNWRITABLE_REC_TYPE:
                        /*
                         * This is a problem with the particular record we're
                         * writing and the file type and subtype we're
                         * writing; note that, and report the record number
                         * and file type/subtype.
                         */
                        fprintf(stderr,
                                "editcap: Record %u of \"%s\" has a record type that can't be saved in a \"%s\" file.\n",
                                read_count, argv[optind],
                                wtap_file_type_subtype_string(out_file_type_subtype));
                        break;

                    case WTAP_ERR_UNWRITABLE_REC_DATA:
                        /*
                         * This is a problem with the particular record we're
                         * writing and the file type and subtype we're
                         * writing; note that, and report the record number
                         * and file type/subtype.
                         */
                        fprintf(stderr,
                                "editcap: Record %u of \"%s\" has data that can't be saved in a \"%s\" file.\n(%s)\n",
                                read_count, argv[optind],
                                wtap_file_type_subtype_string(out_file_type_subtype),
                                write_err_info != NULL ? write_err_info : "no information supplied");
                        g_free(write_err_info);
                        break;

                    default:
                        fprintf(stderr, "editcap: Error writing to %s: %s\n",
                                filename, wtap_strerror(write_err));
                        break;
                    }
                    goto error_on_exit;
                }
                written_count++;
            }
            count++;
        }

        g_free(fprefix);
        g_free(fsuffix);

        if (read_err != 0) {
            /* Print a message noting that the read failed somewhere along the
             * line. */
            fprintf(stderr,
                    "editcap: An error occurred while reading \"%s\": %s.\n",
                    argv[optind], wtap_strerror(read_err));
            if (read_err_info != NULL) {
                fprintf(stderr, "(%s)\n", read_err_info);
                g_free(read_err_info);
            }
        }

        if (!pdh) {
            /* No valid packages found, open the outfile so we can write an
             * empty header */
            g_free (filename);
            filename = g_strdup(argv[optind+1]);

            pdh = editcap_dump_open(filename,
                                    snaplen ? MIN(snaplen, wtap_snapshot_length(wth)): wtap_snapshot_length(wth),
                                    shb_hdrs, idb_inf, nrb_hdrs, &write_err);
            if (pdh == NULL) {
                fprintf(stderr, "editcap: Can't open or create %s: %s\n",
                        filename, wtap_strerror(write_err));
                goto error_on_exit;
            }
        }

        g_free(idb_inf);
        idb_inf = NULL;

        if (!wtap_dump_close(pdh, &write_err)) {
            fprintf(stderr, "editcap: Error writing to %s: %s\n", filename,
                    wtap_strerror(write_err));
            goto error_on_exit;
        }
        wtap_block_array_free(shb_hdrs);
        shb_hdrs = NULL;
        wtap_block_array_free(nrb_hdrs);
        nrb_hdrs = NULL;
        g_free(filename);

        if (frames_user_comments) {
            g_tree_destroy(frames_user_comments);
        }
    }

    if (dup_detect) {
        fprintf(stderr, "%u packet%s seen, %u packet%s skipped with duplicate window of %i packets.\n",
                count - 1, plurality(count - 1, "", "s"), duplicate_count,
                plurality(duplicate_count, "", "s"), dup_window);
    } else if (dup_detect_by_time) {
        fprintf(stderr, "%u packet%s seen, %u packet%s skipped with duplicate time window equal to or less than %ld.%09ld seconds.\n",
                count - 1, plurality(count - 1, "", "s"), duplicate_count,
                plurality(duplicate_count, "", "s"),
                (long)relative_time_window.secs,
                (long int)relative_time_window.nsecs);
    }

    return 0;

error_on_exit:
    wtap_block_array_free(shb_hdrs);
    wtap_block_array_free(nrb_hdrs);
    g_free(idb_inf);
    exit(2);
}

/* Skip meta-information read from file to return offset of real
 * protocol data */
static int
find_dct2000_real_data(guint8 *buf)
{
    int n = 0;

    for (n = 0; buf[n] != '\0'; n++);   /* Context name */
    n++;
    n++;                                /* Context port number */
    for (; buf[n] != '\0'; n++);        /* Timestamp */
    n++;
    for (; buf[n] != '\0'; n++);        /* Protocol name */
    n++;
    for (; buf[n] != '\0'; n++);        /* Variant number (as string) */
    n++;
    for (; buf[n] != '\0'; n++);        /* Outhdr (as string) */
    n++;
    n += 2;                             /* Direction & encap */

    return n;
}

/*
 * We support up to 2 chopping regions in a single pass: one specified by the
 * positive chop length, and one by the negative chop length.
 */
static void
handle_chopping(chop_t chop, struct wtap_pkthdr *out_phdr,
                const struct wtap_pkthdr *in_phdr, guint8 **buf,
                gboolean adjlen)
{
    /* Only packets can be chopped. */
    if (in_phdr->rec_type != REC_TYPE_PACKET)
        return;

    /* If we're not chopping anything from one side, then the offset for that
     * side is meaningless. */
    if (chop.len_begin == 0)
        chop.off_begin_pos = chop.off_begin_neg = 0;
    if (chop.len_end == 0)
        chop.off_end_pos = chop.off_end_neg = 0;

    if (chop.off_begin_neg < 0) {
        chop.off_begin_pos += in_phdr->caplen + chop.off_begin_neg;
        chop.off_begin_neg = 0;
    }
    if (chop.off_end_pos > 0) {
        chop.off_end_neg += chop.off_end_pos - in_phdr->caplen;
        chop.off_end_pos = 0;
    }

    /* If we've crossed chopping regions, swap them */
    if (chop.len_begin && chop.len_end) {
        if (chop.off_begin_pos > ((int)in_phdr->caplen + chop.off_end_neg)) {
            int tmp_len, tmp_off;

            tmp_off = in_phdr->caplen + chop.off_end_neg + chop.len_end;
            tmp_len = -chop.len_end;

            chop.off_end_neg = chop.len_begin + chop.off_begin_pos - in_phdr->caplen;
            chop.len_end = -chop.len_begin;

            chop.len_begin = tmp_len;
            chop.off_begin_pos = tmp_off;
        }
    }

    /* Make sure we don't chop off more than we have available */
    if (in_phdr->caplen < (guint32)(chop.off_begin_pos - chop.off_end_neg)) {
        chop.len_begin = 0;
        chop.len_end = 0;
    }
    if ((guint32)(chop.len_begin - chop.len_end) >
        (in_phdr->caplen - (guint32)(chop.off_begin_pos - chop.off_end_neg))) {
        chop.len_begin = in_phdr->caplen - (chop.off_begin_pos - chop.off_end_neg);
        chop.len_end = 0;
    }

    /* Handle chopping from the beginning.  Note that if a beginning offset
     * was specified, we need to keep that piece */
    if (chop.len_begin > 0) {
        *out_phdr = *in_phdr;

        if (chop.off_begin_pos > 0) {
            memmove(*buf + chop.off_begin_pos,
                    *buf + chop.off_begin_pos + chop.len_begin,
                    out_phdr->caplen - chop.len_begin);
        } else {
            *buf += chop.len_begin;
        }
        out_phdr->caplen -= chop.len_begin;

        if (adjlen) {
            if (in_phdr->len > (guint32)chop.len_begin)
                out_phdr->len -= chop.len_begin;
            else
                out_phdr->len = 0;
        }
        in_phdr = out_phdr;
    }

    /* Handle chopping from the end.  Note that if an ending offset was
     * specified, we need to keep that piece */
    if (chop.len_end < 0) {
        *out_phdr = *in_phdr;

        if (chop.off_end_neg < 0) {
            memmove(*buf + (gint)out_phdr->caplen + (chop.len_end + chop.off_end_neg),
                    *buf + (gint)out_phdr->caplen + chop.off_end_neg,
                    -chop.off_end_neg);
        }
        out_phdr->caplen += chop.len_end;

        if (adjlen) {
            if (((signed int) in_phdr->len + chop.len_end) > 0)
                out_phdr->len += chop.len_end;
            else
                out_phdr->len = 0;
        }
        /*in_phdr = out_phdr;*/
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
