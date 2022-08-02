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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include <time.h>
#include <glib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <wsutil/ws_getopt.h>

#include <wiretap/secrets-types.h>
#include <wiretap/wtap.h>

#include "epan/etypes.h"
#include "epan/dissectors/packet-ieee80211-radiotap-defs.h"

#ifdef _WIN32
#include <process.h>    /* getpid */
#include <winsock2.h>
#endif

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <ui/exit_codes.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/plugins.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/strnatcmp.h>
#include <wsutil/str_util.h>
#include <cli_main.h>
#include <ui/version_info.h>
#include <wsutil/pint.h>
#include <wsutil/strtoi.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>
#include <wiretap/wtap_opttypes.h>

#include "ui/failure_message.h"

#include "ringbuffer.h" /* For RINGBUFFER_MAX_NUM_FILES */

/* Additional exit codes */
#define CANT_EXTRACT_PREFIX 2
#define WRITE_ERROR         2
#define DUMP_ERROR          2

#define NANOSECS_PER_SEC 1000000000

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
    guint8     digest[16];
    guint32    len;
    nstime_t   frame_time;
} fd_hash_t;

#define DEFAULT_DUP_DEPTH       5   /* Used with -d */
#define MAX_DUP_DEPTH     1000000   /* the maximum window (and actual size of fd_hash[]) for de-duplication */

static fd_hash_t fd_hash[MAX_DUP_DEPTH];
static int       dup_window    = DEFAULT_DUP_DEPTH;
static int       cur_dup_entry = 0;

static guint32   ignored_bytes  = 0;  /* Used with -I */

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
GPtrArray *capture_comments = NULL;

#define MAX_SELECTIONS 512
static struct select_item     selectfrm[MAX_SELECTIONS];
static guint                  max_selected              = 0;
static gboolean               keep_em                   = FALSE;
static int                    out_file_type_subtype     = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
static int                    out_frame_type            = -2; /* Leave frame type alone */
static gboolean               verbose                   = FALSE; /* Not so verbose         */
static struct time_adjustment time_adj                  = {NSTIME_INIT_ZERO, 0}; /* no adjustment */
static nstime_t               relative_time_window      = NSTIME_INIT_ZERO; /* de-dup time window */
static double                 err_prob                  = -1.0;
static nstime_t               starttime                 = NSTIME_INIT_ZERO;
static gboolean               have_starttime            = FALSE;
static nstime_t               stoptime                  = NSTIME_INIT_ZERO;
static gboolean               have_stoptime             = FALSE;
static gboolean               check_startstop           = FALSE;
static gboolean               rem_vlan                  = FALSE;
static gboolean               dup_detect                = FALSE;
static gboolean               dup_detect_by_time        = FALSE;
static gboolean               skip_radiotap             = FALSE;
static gboolean               discard_all_secrets       = FALSE;
static gboolean               discard_cap_comments      = FALSE;

static int                    do_strict_time_adjustment = FALSE;
static struct time_adjustment strict_time_adj           = {NSTIME_INIT_ZERO, 0}; /* strict time adjustment */
static nstime_t               previous_time             = NSTIME_INIT_ZERO; /* previous time */

static const struct {
    const char *str;
    guint32     id;
} secrets_types[] = {
    { "tls",    SECRETS_TYPE_TLS },
    { "ssh",    SECRETS_TYPE_SSH },
    { "wg",     SECRETS_TYPE_WIREGUARD },
};

static int find_dct2000_real_data(guint8 *buf);
static void handle_chopping(chop_t chop, wtap_packet_header *out_phdr,
                            const wtap_packet_header *in_phdr, guint8 **buf,
                            gboolean adjlen);

static gchar *
abs_time_to_str_with_sec_resolution(const nstime_t *abs_time)
{
    struct tm *tmp;
    gchar     *buf = (gchar *)g_malloc(16);

    tmp = localtime(&abs_time->secs);

    if (tmp) {
        snprintf(buf, 16, "%d%02d%02d%02d%02d%02d",
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
fileset_get_filename_by_pattern(guint idx, const wtap_rec *rec,
                                gchar *fprefix, gchar *fsuffix)
{
    gchar  filenum[5+1];
    gchar *timestr;
    gchar *abs_str;

    snprintf(filenum, sizeof(filenum), "%05u", idx % RINGBUFFER_MAX_NUM_FILES);
    if (rec->presence_flags & WTAP_HAS_TS) {
        timestr = abs_time_to_str_with_sec_resolution(&rec->ts);
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
        fprintf(stderr, "Out of room for packet selections.\n");
        return(FALSE);
    }

    if (verbose)
        fprintf(stderr, "Add_Selected: %s\n", sel);

    if ((locn = strchr(sel, '-')) == NULL) { /* No dash, so a single number? */
        if (verbose)
            fprintf(stderr, "Not inclusive ...");

        selectfrm[max_selected].inclusive = FALSE;
        selectfrm[max_selected].first = get_guint32(sel, "packet number");
        if (selectfrm[max_selected].first > *max_selection)
            *max_selection = selectfrm[max_selected].first;

        if (verbose)
            fprintf(stderr, " %u\n", selectfrm[max_selected].first);
    } else {
        if (verbose)
            fprintf(stderr, "Inclusive ...");

        *locn = '\0';    /* split the range */
        next = locn + 1;
        selectfrm[max_selected].inclusive = TRUE;
        selectfrm[max_selected].first = get_guint32(sel, "beginning of packet range");
        selectfrm[max_selected].second = get_guint32(next, "end of packet range");

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

static gboolean
selected(guint recno)
{
    guint i;

    for (i = 0; i < max_selected; i++) {
        if (selectfrm[i].inclusive) {
            if (selectfrm[i].first <= recno && selectfrm[i].second >= recno)
                return TRUE;
        } else {
            if (recno == selectfrm[i].first)
                return TRUE;
        }
    }

    return FALSE;
}

static gboolean
set_time_adjustment(char *optarg_str_p)
{
    char   *frac, *end;
    long    val;
    size_t  frac_digits;

    if (!optarg_str_p)
        return TRUE;

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
            return FALSE;
        }
        if (val < 0) {            /* implies '--' since we caught '-' above  */
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            return FALSE;
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
            || val >= ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            return FALSE;
        }
    } else {
        return TRUE;                     /* no fractional digits */
    }

    /* adjust fractional portion from fractional to numerator
     * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
        val *= 10;
        frac_digits++;
    }

    time_adj.tv.nsecs = (int)val;
    return TRUE;
}

static gboolean
set_strict_time_adj(char *optarg_str_p)
{
    char   *frac, *end;
    long    val;
    size_t  frac_digits;

    if (!optarg_str_p)
        return TRUE;

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
            return FALSE;
        }
        if (val < 0) {            /* implies '--' since we caught '-' above  */
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            return FALSE;
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
            || val >= ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
                    optarg_str_p);
            return FALSE;
        }
    } else {
        return TRUE;                     /* no fractional digits */
    }

    /* adjust fractional portion from fractional to numerator
     * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
        val *= 10;
        frac_digits++;
    }

    strict_time_adj.tv.nsecs = (int)val;
    return TRUE;
}

static gboolean
set_rel_time(char *optarg_str_p)
{
    char   *frac, *end;
    long    val;
    size_t  frac_digits;

    if (!optarg_str_p)
        return TRUE;

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
            return FALSE;
        }
        if (val < 0) {            /* implies '--' since we caught '-' above  */
            fprintf(stderr, "2: editcap: \"%s\" isn't a valid rel time value\n",
                    optarg_str_p);
            return FALSE;
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
            || val >= ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
            fprintf(stderr, "3: editcap: \"%s\" isn't a valid rel time value\n",
                    optarg_str_p);
            return FALSE;
        }
    } else {
        return TRUE;                     /* no fractional digits */
    }

    /* adjust fractional portion from fractional to numerator
     * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
        val *= 10;
        frac_digits++;
    }

    relative_time_window.nsecs = (int)val;
    return TRUE;
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
remove_vlan_info(const wtap_packet_header *phdr, guint8* fd, guint32* len) {
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
    const struct ieee80211_radiotap_header* tap_header;

    /*Hint to ignore some bytes at the start of the frame for the digest calculation(-I option) */
    guint32 offset = ignored_bytes;
    guint32 new_len;
    guint8 *new_fd;

    if (len <= ignored_bytes) {
        offset = 0;
    }

    /* Get the size of radiotap header and use that as offset (-p option) */
    if (skip_radiotap == TRUE) {
        tap_header = (const struct ieee80211_radiotap_header*)fd;
        offset = pletoh16(&tap_header->it_len);
        if (offset >= len)
            offset = 0;
    }

    new_fd  = &fd[offset];
    new_len = len - (offset);

    cur_dup_entry++;
    if (cur_dup_entry >= dup_window)
        cur_dup_entry = 0;

    /* Calculate our digest */
    gcry_md_hash_buffer(GCRY_MD_MD5, fd_hash[cur_dup_entry].digest, new_fd, new_len);

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

    /*Hint to ignore some bytes at the start of the frame for the digest calculation(-I option) */
    guint32 offset = ignored_bytes;
    guint32 new_len;
    guint8 *new_fd;

    if (len <= ignored_bytes) {
        offset = 0;
    }

    new_fd  = &fd[offset];
    new_len = len - (offset);

    cur_dup_entry++;
    if (cur_dup_entry >= dup_window)
        cur_dup_entry = 0;

    /* Calculate our digest */
    gcry_md_hash_buffer(GCRY_MD_MD5, fd_hash[cur_dup_entry].digest, new_fd, new_len);

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
    fprintf(output, "<infile> and <outfile> must both be present; use '-' for stdin or stdout.\n");
    fprintf(output, "A single packet or a range of packets can be selected.\n");
    fprintf(output, "\n");
    fprintf(output, "Packet selection:\n");
    fprintf(output, "  -r                     keep the selected packets; default is to delete them.\n");
    fprintf(output, "  -A <start time>        only read packets whose timestamp is after (or equal\n");
    fprintf(output, "                         to) the given time.\n");
    fprintf(output, "  -B <stop time>         only read packets whose timestamp is before the\n");
    fprintf(output, "                         given time.\n");
    fprintf(output, "                         Time format for -A/-B options is\n");
    fprintf(output, "                         YYYY-MM-DDThh:mm:ss[.nnnnnnnnn][Z|+-hh:mm]\n");
    fprintf(output, "                         Unix epoch timestamps are also supported.\n");
    fprintf(output, "\n");
    fprintf(output, "Duplicate packet removal:\n");
    fprintf(output, "  --novlan               remove vlan info from packets before checking for duplicates.\n");
    fprintf(output, "  -d                     remove packet if duplicate (window == %d).\n", DEFAULT_DUP_DEPTH);
    fprintf(output, "  -D <dup window>        remove packet if duplicate; configurable <dup window>.\n");
    fprintf(output, "                         Valid <dup window> values are 0 to %d.\n", MAX_DUP_DEPTH);
    fprintf(output, "                         NOTE: A <dup window> of 0 with -V (verbose option) is\n");
    fprintf(output, "                         useful to print MD5 hashes.\n");
    fprintf(output, "  -w <dup time window>   remove packet if duplicate packet is found EQUAL TO OR\n");
    fprintf(output, "                         LESS THAN <dup time window> prior to current packet.\n");
    fprintf(output, "                         A <dup time window> is specified in relative seconds\n");
    fprintf(output, "                         (e.g. 0.000001).\n");
    fprintf(output, "           NOTE: The use of the 'Duplicate packet removal' options with\n");
    fprintf(output, "           other editcap options except -V may not always work as expected.\n");
    fprintf(output, "           Specifically the -r, -t or -S options will very likely NOT have the\n");
    fprintf(output, "           desired effect if combined with the -d, -D or -w.\n");
    fprintf(output, "  --skip-radiotap-header skip radiotap header when checking for packet duplicates.\n");
    fprintf(output, "                         Useful when processing packets captured by multiple radios\n");
    fprintf(output, "                         on the same channel in the vicinity of each other.\n");
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
    fprintf(output, "                         and/or snapping.\n");
    fprintf(output, "  -t <time adjustment>   adjust the timestamp of each packet.\n");
    fprintf(output, "                         <time adjustment> is in relative seconds (e.g. -0.5).\n");
    fprintf(output, "  -S <strict adjustment> adjust timestamp of packets if necessary to ensure\n");
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
    fprintf(output, "  --seed <seed>          When used in conjunction with -E, set the seed to use for\n");
    fprintf(output, "                         the pseudo-random number generator. This allows one to\n");
    fprintf(output, "                         repeat a particular sequence of errors.\n");
    fprintf(output, "  -I <bytes to ignore>   ignore the specified number of bytes at the beginning\n");
    fprintf(output, "                         of the frame during MD5 hash calculation, unless the\n");
    fprintf(output, "                         frame is too short, then the full frame is used.\n");
    fprintf(output, "                         Useful to remove duplicated packets taken on\n");
    fprintf(output, "                         several routers (different mac addresses for\n");
    fprintf(output, "                         example).\n");
    fprintf(output, "                         e.g. -I 26 in case of Ether/IP will ignore\n");
    fprintf(output, "                         ether(14) and IP header(20 - 4(src ip) - 4(dst ip)).\n");
    fprintf(output, "  -a <framenum>:<comment> Add or replace comment for given frame number\n");
    fprintf(output, "\n");
    fprintf(output, "Output File(s):\n");
    fprintf(output, "  -c <packets per file>  split the packet output to different files based on\n");
    fprintf(output, "                         uniform packet counts with a maximum of\n");
    fprintf(output, "                         <packets per file> each.\n");
    fprintf(output, "  -i <seconds per file>  split the packet output to different files based on\n");
    fprintf(output, "                         uniform time intervals with a maximum of\n");
    fprintf(output, "                         <seconds per file> each.\n");
    fprintf(output, "  -F <capture type>      set the output file type; default is pcapng.\n");
    fprintf(output, "                         An empty \"-F\" option will list the file types.\n");
    fprintf(output, "  -T <encap type>        set the output file encapsulation type; default is the\n");
    fprintf(output, "                         same as the input file. An empty \"-T\" option will\n");
    fprintf(output, "                         list the encapsulation types.\n");
    fprintf(output, "  --inject-secrets <type>,<file>  Insert decryption secrets from <file>. List\n");
    fprintf(output, "                         supported secret types with \"--inject-secrets help\".\n");
    fprintf(output, "  --discard-all-secrets  Discard all decryption secrets from the input file\n");
    fprintf(output, "                         when writing the output file.  Does not discard\n");
    fprintf(output, "                         secrets added by \"--inject-secrets\" in the same\n");
    fprintf(output, "                         command line.\n");
    fprintf(output, "  --capture-comment <comment>\n");
    fprintf(output, "                         Add a capture file comment, if supported.\n");
    fprintf(output, "  --discard-capture-comment\n");
    fprintf(output, "                         Discard capture file comments from the input file\n");
    fprintf(output, "                         when writing the output file.  Does not discard\n");
    fprintf(output, "                         comments added by \"--capture-comment\" in the same\n");
    fprintf(output, "                         command line.\n");
    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h, --help             display this help and exit.\n");
    fprintf(output, "  -V                     verbose output.\n");
    fprintf(output, "                         If -V is used with any of the 'Duplicate Packet\n");
    fprintf(output, "                         Removal' options (-d, -D or -w) then Packet lengths\n");
    fprintf(output, "                         and MD5 hashes are printed to standard-error.\n");
    fprintf(output, "  -v, --version          print version information and exit.\n");
}

struct string_elem {
    const char *sstr;   /* The short string */
    const char *lstr;   /* The long string */
};

static gint
string_nat_compare(gconstpointer a, gconstpointer b)
{
    return ws_ascii_strnatcmp(((const struct string_elem *)a)->sstr,
        ((const struct string_elem *)b)->sstr);
}

static void
string_elem_print(gpointer data, gpointer stream_ptr)
{
    fprintf((FILE *) stream_ptr, "    %s - %s\n",
        ((struct string_elem *)data)->sstr,
        ((struct string_elem *)data)->lstr);
}

static void
list_capture_types(FILE *stream) {
    GArray *writable_type_subtypes;

    fprintf(stream, "editcap: The available capture file types for the \"-F\" flag are:\n");
    writable_type_subtypes = wtap_get_writable_file_types_subtypes(FT_SORT_BY_NAME);
    for (guint i = 0; i < writable_type_subtypes->len; i++) {
        int ft = g_array_index(writable_type_subtypes, int, i);
        fprintf(stream, "    %s - %s\n", wtap_file_type_subtype_name(ft),
                wtap_file_type_subtype_description(ft));
    }
    g_array_free(writable_type_subtypes, TRUE);
}

static void
list_encap_types(FILE *stream) {
    int i;
    struct string_elem *encaps;
    GSList *list = NULL;

    encaps = g_new(struct string_elem, WTAP_NUM_ENCAP_TYPES);
    fprintf(stream, "editcap: The available encapsulation types for the \"-T\" flag are:\n");
    for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
        encaps[i].sstr = wtap_encap_name(i);
        if (encaps[i].sstr != NULL) {
            encaps[i].lstr = wtap_encap_description(i);
            list = g_slist_insert_sorted(list, &encaps[i], string_nat_compare);
        }
    }
    g_slist_foreach(list, string_elem_print, stream);
    g_slist_free(list);
    g_free(encaps);
}

static void
list_secrets_types(FILE *stream)
{
    for (guint i = 0; i < G_N_ELEMENTS(secrets_types); i++) {
        fprintf(stream, "    %s\n", secrets_types[i].str);
    }
}

static guint32
lookup_secrets_type(const char *type)
{
    for (guint i = 0; i < G_N_ELEMENTS(secrets_types); i++) {
        if (!strcmp(secrets_types[i].str, type)) {
            return secrets_types[i].id;
        }
    }
    return 0;
}

static void
validate_secrets_file(const char *filename, guint32 secrets_type, const char *data)
{
    if (secrets_type == SECRETS_TYPE_TLS) {
        /*
         * A key log file is unlikely going to look like either:
         * - a PEM-encoded private key file.
         * - a BER-encoded PKCS #12 file ("PFX file"). (Look for a Constructed
         *   SEQUENCE tag, e.g. bytes 0x30 which happens to be ASCII '0'.)
         */
        if (g_str_has_prefix(data, "-----BEGIN ") || data[0] == 0x30) {
            fprintf(stderr,
                    "editcap: Warning: \"%s\" is not a key log file, but an unsupported private key file. Decryption will not work.\n",
                    filename);
        }
    }
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

/*
 * Report an error in command-line arguments.
 */
static void
editcap_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "editcap: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
editcap_cmdarg_err_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

static wtap_dumper *
editcap_dump_open(const char *filename, const wtap_dump_params *params,
                  GArray *idbs_seen, int *err, gchar **err_info)
{
    wtap_dumper *pdh;

    if (strcmp(filename, "-") == 0) {
        /* Write to the standard output. */
        pdh = wtap_dump_open_stdout(out_file_type_subtype, WTAP_UNCOMPRESSED,
                                    params, err, err_info);
    } else {
        pdh = wtap_dump_open(filename, out_file_type_subtype, WTAP_UNCOMPRESSED,
                             params, err, err_info);
    }
    if (pdh == NULL)
        return NULL;

    /*
     * If the output file supporst identifying the interfaces on which
     * packets arrive, add all the IDBs we've seen so far.
     *
     * That mean that the abstract interface provided by libwiretap
     * involves WTAP_BLOCK_IF_ID_AND_INFO blocks.
     */
    if (wtap_file_type_subtype_supports_block(wtap_dump_file_type_subtype(pdh),
                                              WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
        for (guint i = 0; i < idbs_seen->len; i++) {
            wtap_block_t if_data = g_array_index(idbs_seen, wtap_block_t, i);
            wtap_block_t if_data_copy;

            /*
             * Make a copy of this IDB, so that we can change the
             * encapsulation type without trashing the original.
             */
            if_data_copy = wtap_block_make_copy(if_data);

            /*
             * If an encapsulation type was specified, override the
             * encapsulation type of the interface.
             */
            if (out_frame_type != -2) {
                wtapng_if_descr_mandatory_t *if_mand;

                if_mand = (wtapng_if_descr_mandatory_t *)wtap_block_get_mandatory_data(if_data_copy);
                if_mand->wtap_encap = out_frame_type;
            }

            /*
             * Add this possibly-modified IDB to the file to which
             * we're currently writing.
             */
            if (!wtap_dump_add_idb(pdh, if_data_copy, err, err_info)) {
                int close_err;
                gchar *close_err_info;

                wtap_dump_close(pdh, NULL, &close_err, &close_err_info);
                g_free(close_err_info);
                wtap_block_unref(if_data_copy);
                return NULL;
            }

            /*
             * Release the copy - wtap_dump_add_idb() makes its own copy.
             */
            wtap_block_unref(if_data_copy);
        }
    }

    return pdh;
}

static gboolean
process_new_idbs(wtap *wth, wtap_dumper *pdh, GArray *idbs_seen,
                 int *err, gchar **err_info)
{
    wtap_block_t if_data;

    while ((if_data = wtap_get_next_interface_description(wth)) != NULL) {
        /*
         * Only add interface blocks if the output file supports (meaning
         * *requires*) them.
         *
         * That mean that the abstract interface provided by libwiretap
         * involves WTAP_BLOCK_IF_ID_AND_INFO blocks.
         */
        if (wtap_file_type_subtype_supports_block(wtap_dump_file_type_subtype(pdh),
                                                  WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
            wtap_block_t if_data_copy;

            /*
             * Make a copy of this IDB, so that we can change the
             * encapsulation type without trashing the original.
             */
            if_data_copy = wtap_block_make_copy(if_data);

            /*
             * If an encapsulation type was specified, override the
             * encapsulation type of the interface.
             */
            if (out_frame_type != -2) {
                wtapng_if_descr_mandatory_t *if_mand;

                if_mand = (wtapng_if_descr_mandatory_t *)wtap_block_get_mandatory_data(if_data_copy);
                if_mand->wtap_encap = out_frame_type;
            }

            /*
             * Add this possibly-modified IDB to the file to which
             * we're currently writing.
             */
            if (!wtap_dump_add_idb(pdh, if_data_copy, err, err_info))
                return FALSE;

            /*
             * Release the copy - wtap_dump_add_idb() makes its own copy.
             */
            wtap_block_unref(if_data_copy);

            /*
             * Also add an unmodified copy to the set of IDBs we've seen,
             * in case we start writing to another file (which would be
             * of the same type as the current file, and thus will also
             * require interface IDs).
             */
            if_data_copy = wtap_block_make_copy(if_data);
            g_array_append_val(idbs_seen, if_data_copy);
        }
    }
    return TRUE;
}

int
main(int argc, char *argv[])
{
    char         *configuration_init_error;
    static const struct report_message_routines editcap_report_routines = {
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
    wtap         *wth = NULL;
    int           i, j, read_err, write_err;
    gchar        *read_err_info, *write_err_info;
    int           opt;

#define LONGOPT_NO_VLAN              LONGOPT_BASE_APPLICATION+1
#define LONGOPT_SKIP_RADIOTAP_HEADER LONGOPT_BASE_APPLICATION+2
#define LONGOPT_SEED                 LONGOPT_BASE_APPLICATION+3
#define LONGOPT_INJECT_SECRETS       LONGOPT_BASE_APPLICATION+4
#define LONGOPT_DISCARD_ALL_SECRETS  LONGOPT_BASE_APPLICATION+5
#define LONGOPT_CAPTURE_COMMENT      LONGOPT_BASE_APPLICATION+6
#define LONGOPT_DISCARD_CAPTURE_COMMENT LONGOPT_BASE_APPLICATION+7

    static const struct ws_option long_options[] = {
        {"novlan", ws_no_argument, NULL, LONGOPT_NO_VLAN},
        {"skip-radiotap-header", ws_no_argument, NULL, LONGOPT_SKIP_RADIOTAP_HEADER},
        {"seed", ws_required_argument, NULL, LONGOPT_SEED},
        {"inject-secrets", ws_required_argument, NULL, LONGOPT_INJECT_SECRETS},
        {"discard-all-secrets", ws_no_argument, NULL, LONGOPT_DISCARD_ALL_SECRETS},
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {"capture-comment", ws_required_argument, NULL, LONGOPT_CAPTURE_COMMENT},
        {"discard-capture-comment", ws_no_argument, NULL, LONGOPT_DISCARD_CAPTURE_COMMENT},
        {0, 0, 0, 0 }
    };

    char         *p;
    guint32       snaplen            = 0; /* No limit               */
    chop_t        chop               = {0, 0, 0, 0, 0, 0}; /* No chop */
    gboolean      adjlen             = FALSE;
    wtap_dumper  *pdh                = NULL;
    GArray       *idbs_seen          = NULL;
    unsigned int  count              = 1;
    unsigned int  duplicate_count    = 0;
    gint64        data_offset;
    int           err_type;
    guint8       *buf;
    guint32       read_count         = 0;
    guint32       split_packet_count = 0;
    int           written_count      = 0;
    char         *filename           = NULL;
    gboolean      ts_okay;
    nstime_t      secs_per_block     = NSTIME_INIT_UNSET;
    int           block_cnt          = 0;
    nstime_t      block_next         = NSTIME_INIT_UNSET;
    gchar        *fprefix            = NULL;
    gchar        *fsuffix            = NULL;
    guint32       change_offset      = 0;
    guint         max_packet_number  = 0;
    GArray       *dsb_types          = NULL;
    GPtrArray    *dsb_filenames      = NULL;
    wtap_rec                     read_rec;
    Buffer                       read_buf;
    const wtap_rec              *rec;
    wtap_rec                     temp_rec;
    wtap_dump_params             params = WTAP_DUMP_PARAMS_INIT;
    char                        *shb_user_appl;
    gboolean                     do_mutation;
    guint32                      caplen;
    int                          ret = EXIT_SUCCESS;
    gboolean                     valid_seed = FALSE;
    unsigned int                 seed = 0;

    cmdarg_err_init(editcap_cmdarg_err, editcap_cmdarg_err_cont);
    memset(&read_rec, 0, sizeof *rec);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("editcap", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, INVALID_OPTION);

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    /* Initialize the version information. */
    ws_init_version_info("Editcap", NULL, NULL);

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
                "editcap: Can't get pathname of directory containing the editcap program: %s.\n",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("editcap", &editcap_report_routines);

    wtap_init(TRUE);

    /* Process the options */
    while ((opt = ws_getopt_long(argc, argv, ":a:A:B:c:C:dD:E:F:hi:I:Lo:rs:S:t:T:vVw:", long_options, NULL)) != -1) {
        switch (opt) {
        case LONGOPT_NO_VLAN:
        {
            rem_vlan = TRUE;
            break;
        }

        case LONGOPT_SKIP_RADIOTAP_HEADER:
        {
            skip_radiotap = TRUE;
            break;
        }

        case LONGOPT_SEED:
        {
            if (sscanf(ws_optarg, "%u", &seed) != 1) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid seed\n\n",
                        ws_optarg);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            valid_seed = TRUE;
            break;
        }

        case LONGOPT_INJECT_SECRETS:
        {
            guint32 secrets_type_id = 0;
            const char *secrets_filename = NULL;
            if (strcmp("help", ws_optarg) == 0) {
                list_secrets_types(stdout);
                goto clean_exit;
            }
            gchar **splitted = g_strsplit(ws_optarg, ",", 2);
            if (splitted[0] && splitted[0][0] != '\0') {
                secrets_type_id = lookup_secrets_type(splitted[0]);
                if (secrets_type_id == 0) {
                    fprintf(stderr, "editcap: \"%s\" isn't a valid secrets type\n", splitted[0]);
                    g_strfreev(splitted);
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                secrets_filename = splitted[1];
            } else {
                fprintf(stderr, "editcap: no secrets type was specified for --inject-secrets\n");
                g_strfreev(splitted);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            if (!dsb_filenames) {
                dsb_types = g_array_new(FALSE, FALSE, sizeof(guint32));
                dsb_filenames = g_ptr_array_new_with_free_func(g_free);
            }
            g_array_append_val(dsb_types, secrets_type_id);
            g_ptr_array_add(dsb_filenames, g_strdup(secrets_filename));
            g_strfreev(splitted);
            break;
        }

        case LONGOPT_DISCARD_ALL_SECRETS:
        {
            discard_all_secrets = TRUE;
            break;
        }

        case LONGOPT_CAPTURE_COMMENT:
        {
            /*
             * Make sure this would fit in a pcapng option.
             *
             * XXX - 65535 is the maximum size for an option in pcapng;
             * what if another capture file format supports larger
             * comments?
             */
            if (strlen(ws_optarg) > 65535) {
                /* It doesn't fit.  Tell the user and give up. */
                cmdarg_err("Capture comment %u is too large to save in a capture file.",
                           capture_comments->len + 1);
                ret = INVALID_OPTION;
                goto clean_exit;
            }

            /* pcapng supports multiple comments, so support them here too.
             */
            if (!capture_comments) {
                capture_comments = g_ptr_array_new_with_free_func(g_free);
            }
            g_ptr_array_add(capture_comments, g_strdup(ws_optarg));
            break;
        }

        case LONGOPT_DISCARD_CAPTURE_COMMENT:
        {
            discard_cap_comments = TRUE;
            break;
        }

        case 'a':
        {
            guint frame_number;
            gint string_start_index = 0;

            if ((sscanf(ws_optarg, "%u:%n", &frame_number, &string_start_index) < 1) || (string_start_index == 0)) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid <frame>:<comment>\n\n",
                        ws_optarg);
                ret = INVALID_OPTION;
                goto clean_exit;
            }

            /*
             * Make sure this would fit in a pcapng option.
             *
             * XXX - 65535 is the maximum size for an option in pcapng;
             * what if another capture file format supports larger
             * comments?
             */
            if (strlen(ws_optarg+string_start_index) > 65535) {
                /* It doesn't fit.  Tell the user and give up. */
                cmdarg_err("A comment for frame %u is too large to save in a capture file.",
                           frame_number);
                ret = INVALID_OPTION;
                goto clean_exit;
            }

            /* Lazily create the table */
            if (!frames_user_comments) {
                frames_user_comments = g_tree_new_full(framenum_compare, NULL, NULL, g_free);
            }

            /* Insert this entry (framenum -> comment) */
            g_tree_replace(frames_user_comments, GUINT_TO_POINTER(frame_number), g_strdup(ws_optarg+string_start_index));
            break;
        }

        case 'A':
        case 'B':
        {
            nstime_t in_time;

            check_startstop = TRUE;
            if ((0 < iso8601_to_nstime(&in_time, ws_optarg, ISO8601_DATETIME)) || (0 < unix_epoch_to_nstime(&in_time, ws_optarg))) {
                if (opt == 'A') {
                    nstime_copy(&starttime, &in_time);
                    have_starttime = TRUE;
                } else {
                    nstime_copy(&stoptime, &in_time);
                    have_stoptime = TRUE;
                }
                break;
            }
            else {
                fprintf(stderr, "editcap: \"%s\" isn't a valid date and time\n\n",
                        ws_optarg);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
        }

        case 'c':
            split_packet_count = get_nonzero_guint32(ws_optarg, "packet count");
            break;

        case 'C':
        {
            int choplen = 0, chopoff = 0;

            switch (sscanf(ws_optarg, "%d:%d", &chopoff, &choplen)) {
            case 1: /* only the chop length was specififed */
                choplen = chopoff;
                chopoff = 0;
                break;

            case 2: /* both an offset and chop length was specified */
                break;

            default:
                fprintf(stderr, "editcap: \"%s\" isn't a valid chop length or offset:length\n",
                        ws_optarg);
                ret = INVALID_OPTION;
                goto clean_exit;
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
            dup_window = get_guint32(ws_optarg, "duplicate window");
            if (dup_window > MAX_DUP_DEPTH) {
                fprintf(stderr, "editcap: \"%d\" duplicate window value must be between 0 and %d inclusive.\n",
                        dup_window, MAX_DUP_DEPTH);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            break;

        case 'E':
            err_prob = g_ascii_strtod(ws_optarg, &p);
            if (p == ws_optarg || err_prob < 0.0 || err_prob > 1.0) {
                fprintf(stderr, "editcap: probability \"%s\" must be between 0.0 and 1.0\n",
                        ws_optarg);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            break;

        case 'F':
            out_file_type_subtype = wtap_name_to_file_type_subtype(ws_optarg);
            if (out_file_type_subtype < 0) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid capture file type\n\n",
                        ws_optarg);
                list_capture_types(stderr);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            break;

        case 'h':
            show_help_header("Edit and/or translate the format of capture files.");
            print_usage(stdout);
            goto clean_exit;
            break;

        case 'i': /* break capture file based on time interval */
        {
            double spb = get_positive_double(ws_optarg, "time interval");
            if (spb == 0.0) {
              cmdarg_err("The specified interval is zero");
              ret = INVALID_OPTION;
              goto clean_exit;
            }

            double spb_int, spb_frac;
            spb_frac = modf(spb, &spb_int);
            secs_per_block.secs = (time_t) spb_int;
            secs_per_block.nsecs = (int) (NANOSECS_PER_SEC * spb_frac);
        }
            break;

        case 'I': /* ignored_bytes at the beginning of the frame for duplications removal */
            ignored_bytes = get_guint32(ws_optarg, "number of bytes to ignore");
            break;

        case 'L':
            adjlen = TRUE;
            break;

        case 'o':
            change_offset = get_guint32(ws_optarg, "change offset");
            break;

        case 'r':
            if (keep_em) {
                cmdarg_err("-r was specified twice");
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            keep_em = TRUE;
            break;

        case 's':
            snaplen = get_nonzero_guint32(ws_optarg, "snapshot length");
            break;

        case 'S':
            if (!set_strict_time_adj(ws_optarg)) {
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            do_strict_time_adjustment = TRUE;
            break;

        case 't':
            if (!set_time_adjustment(ws_optarg)) {
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            break;

        case 'T':
            out_frame_type = wtap_name_to_encap(ws_optarg);
            if (out_frame_type < 0) {
                fprintf(stderr, "editcap: \"%s\" isn't a valid encapsulation type\n\n",
                        ws_optarg);
                list_encap_types(stderr);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            break;

        case 'V':
            if (verbose) {
                cmdarg_err("-V was specified twice");
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            verbose = TRUE;
            break;

        case 'v':
            show_version();
            goto clean_exit;
            break;

        case 'w':
            dup_detect = FALSE;
            dup_detect_by_time = TRUE;
            dup_window = MAX_DUP_DEPTH;
            if (!set_rel_time(ws_optarg)) {
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            break;

        case '?':              /* Bad options if GNU getopt */
        case ':':              /* missing option argument */
            switch(ws_optopt) {
            case'F':
                list_capture_types(stdout);
                break;
            case'T':
                list_encap_types(stdout);
                break;
            default:
                if (opt == '?') {
                    fprintf(stderr, "editcap: invalid option -- '%c'\n", ws_optopt);
                } else {
                    fprintf(stderr, "editcap: option requires an argument -- '%c'\n", ws_optopt);
                }
                print_usage(stderr);
                ret = INVALID_OPTION;
                break;
            }
            goto clean_exit;
            break;
        }
    } /* processing commmand-line options */

#ifdef DEBUG
    fprintf(stderr, "Optind = %i, argc = %i\n", ws_optind, argc);
#endif

    if ((argc - ws_optind) < 2) {
        print_usage(stderr);
        ret = INVALID_OPTION;
        goto clean_exit;
    }

    if (out_file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
      /* default to pcapng   */
      out_file_type_subtype = wtap_pcapng_file_type_subtype();
    }

    if (err_prob >= 0.0) {
        if (!valid_seed) {
            seed = (unsigned int) (time(NULL) + ws_getpid());
        }
        if (verbose) {
            fprintf(stderr, "Using seed %u\n", seed);
        }
        srand(seed);
    }

    if (have_starttime && have_stoptime &&
        nstime_cmp(&starttime, &stoptime) > 0) {
        fprintf(stderr, "editcap: start time is after the stop time\n");
        ret = INVALID_OPTION;
        goto clean_exit;
    }

    if (split_packet_count != 0 && !nstime_is_unset(&secs_per_block)) {
        fprintf(stderr, "editcap: can't split on both packet count and time interval\n");
        fprintf(stderr, "editcap: at the same time\n");
        ret = INVALID_OPTION;
        goto clean_exit;
    }

    wth = wtap_open_offline(argv[ws_optind], WTAP_TYPE_AUTO, &read_err, &read_err_info, FALSE);

    if (!wth) {
        cfile_open_failure_message(argv[ws_optind], read_err, read_err_info);
        ret = INVALID_FILE;
        goto clean_exit;
    }

    if (verbose) {
        fprintf(stderr, "File %s is a %s capture file.\n", argv[ws_optind],
                wtap_file_type_subtype_description(wtap_file_type_subtype(wth)));
    }

    if (skip_radiotap) {
        if (ignored_bytes != 0) {
            fprintf(stderr, "editcap: can't skip radiotap headers and %d byte(s)\n", ignored_bytes);
            fprintf(stderr, "editcap: at the start of packet at the same time\n");
            ret = INVALID_OPTION;
            goto clean_exit;
        }

        if (wtap_file_encap(wth) != WTAP_ENCAP_IEEE_802_11_RADIOTAP) {
            fprintf(stderr, "editcap: can't skip radiotap header because input file has non-radiotap packets\n");
            if (wtap_file_encap(wth) == WTAP_ENCAP_PER_PACKET) {
                fprintf(stderr, "editcap: expected '%s', not all packets are necessarily that type\n",
                        wtap_encap_description(WTAP_ENCAP_IEEE_802_11_RADIOTAP));
            } else {
                fprintf(stderr, "editcap: expected '%s', packets are '%s'\n",
                        wtap_encap_description(WTAP_ENCAP_IEEE_802_11_RADIOTAP),
                        wtap_encap_description(wtap_file_encap(wth)));
            }
            ret = INVALID_OPTION;
            goto clean_exit;
        }
    }

    wtap_dump_params_init_no_idbs(&params, wth);

    /*
     * Discard any secrets we read in while opening the file.
     */
    if (discard_all_secrets) {
        wtap_dump_params_discard_decryption_secrets(&params);
    }

    /*
     * Discard capture file comments.
     */
    if (discard_cap_comments) {
        for (guint b = 0; b < params.shb_hdrs->len; b++) {
            wtap_block_t shb = g_array_index(params.shb_hdrs, wtap_block_t, b);
            while (WTAP_OPTTYPE_SUCCESS == wtap_block_remove_nth_option_instance(shb, OPT_COMMENT, 0)) {
                continue;
            }
        }
    }

    /*
     * Add new capture file comments.
     */
    if (capture_comments != NULL) {
        for (guint b = 0; b < params.shb_hdrs->len; b++) {
            wtap_block_t shb = g_array_index(params.shb_hdrs, wtap_block_t, b);
            for (guint c = 0; c < capture_comments->len; c++) {
                char *comment = (char *)g_ptr_array_index(capture_comments, c);
                wtap_block_add_string_option(shb, OPT_COMMENT, comment, strlen(comment));
            }
        }
    }

    if (dsb_filenames) {
        for (guint k = 0; k < dsb_filenames->len; k++) {
            guint32 secrets_type_id = g_array_index(dsb_types, guint32, k);
            const char *secrets_filename = (const char *)g_ptr_array_index(dsb_filenames, k);
            char *data;
            gsize data_len;
            wtap_block_t block;
            wtapng_dsb_mandatory_t *dsb;
            GError *err = NULL;

            if (!g_file_get_contents(secrets_filename, &data, &data_len, &err)) {
                fprintf(stderr, "editcap: \"%s\" could not be read: %s\n", secrets_filename, err->message);
                g_clear_error(&err);
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            if (data_len == 0) {
                fprintf(stderr, "editcap: \"%s\" is an empty file, ignoring\n", secrets_filename);
                g_free(data);
                continue;
            }
            if (data_len >= G_MAXINT) {
                fprintf(stderr, "editcap: \"%s\" is too large, ignoring\n", secrets_filename);
                g_free(data);
                continue;
            }

            /* Warn for badly formatted files, but proceed anyway. */
            validate_secrets_file(secrets_filename, secrets_type_id, data);

            block = wtap_block_create(WTAP_BLOCK_DECRYPTION_SECRETS);
            dsb = (wtapng_dsb_mandatory_t *)wtap_block_get_mandatory_data(block);
            dsb->secrets_type = secrets_type_id;
            dsb->secrets_len = (guint)data_len;
            dsb->secrets_data = data;
            if (params.dsbs_initial == NULL) {
                params.dsbs_initial = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
            }
            g_array_append_val(params.dsbs_initial, block);
        }
    }

    /*
     * If an encapsulation type was specified, override the encapsulation
     * type of the input file.
     */
    if (out_frame_type != -2)
        params.encap = out_frame_type;

    /*
     * If a snapshot length was specified, and it's less than the snapshot
     * length of the input file, override the snapshot length of the input
     * file.
     */
    if (snaplen != 0 && snaplen < wtap_snapshot_length(wth))
        params.snaplen = snaplen;

    /*
     * Now process the arguments following the input and output file
     * names, if any; they specify packets to include/exclude.
     */
    for (i = ws_optind + 2; i < argc; i++)
        if (add_selection(argv[i], &max_packet_number) == FALSE)
            break;

    if (!keep_em)
        max_packet_number = G_MAXUINT;

    if (dup_detect || dup_detect_by_time) {
        for (i = 0; i < dup_window; i++) {
            memset(&fd_hash[i].digest, 0, 16);
            fd_hash[i].len = 0;
            nstime_set_unset(&fd_hash[i].frame_time);
        }
    }

    /* Set up an array of all IDBs seen */
    idbs_seen = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

    /* Read all of the packets in turn */
    wtap_rec_init(&read_rec);
    ws_buffer_init(&read_buf, 1514);
    while (wtap_read(wth, &read_rec, &read_buf, &read_err, &read_err_info, &data_offset)) {
        /*
         * XXX - what about non-packet records in the file after this?
         * We can *probably* ignore IDBs after this point, as they
         * presumably indicate that we weren't capturing on that
         * interface at this point, but what about, for example, NRBs?
         */
        if (max_packet_number <= read_count)
            break;

        read_count++;

        rec = &read_rec;

        /* Extra actions for the first packet */
        if (read_count == 1) {
            if (split_packet_count != 0 || !nstime_is_unset(&secs_per_block)) {
                if (!fileset_extract_prefix_suffix(argv[ws_optind+1], &fprefix, &fsuffix)) {
                    ret = CANT_EXTRACT_PREFIX;
                    goto clean_exit;
                }

                filename = fileset_get_filename_by_pattern(block_cnt++, rec, fprefix, fsuffix);
            } else {
                filename = g_strdup(argv[ws_optind+1]);
            }
            ws_assert(filename);

            /* If we don't have an application name add one */
            if (wtap_block_get_string_option_value(g_array_index(params.shb_hdrs, wtap_block_t, 0), OPT_SHB_USERAPPL, &shb_user_appl) != WTAP_OPTTYPE_SUCCESS) {
                wtap_block_add_string_option_format(g_array_index(params.shb_hdrs, wtap_block_t, 0), OPT_SHB_USERAPPL, "%s", get_appname_and_version());
            }

            pdh = editcap_dump_open(filename, &params, idbs_seen, &write_err,
                                    &write_err_info);

            if (pdh == NULL) {
                cfile_dump_open_failure_message(filename,
                                                write_err, write_err_info,
                                                out_file_type_subtype);
                ret = INVALID_FILE;
                goto clean_exit;
            }
        } /* first packet only handling */

        /*
         * Process whatever IDBs we haven't seen yet.
         */
        if (!process_new_idbs(wth, pdh, idbs_seen, &write_err, &write_err_info)) {
            cfile_write_failure_message(argv[ws_optind], filename,
                                        write_err, write_err_info,
                                        read_count,
                                        out_file_type_subtype);
            ret = DUMP_ERROR;
            goto clean_exit;
        }

        buf = ws_buffer_start_ptr(&read_buf);

        /*
         * Not all packets have time stamps. Only process the time
         * stamp if we have one.
         */
        if (rec->presence_flags & WTAP_HAS_TS) {
            if (!nstime_is_unset(&secs_per_block)) {
                if (nstime_is_unset(&block_next)) {
                    block_next = rec->ts;
                    nstime_add(&block_next, &secs_per_block);
                }
                while (nstime_cmp(&rec->ts, &block_next) > 0) { /* time for the next file */

                    if (!wtap_dump_close(pdh, NULL, &write_err, &write_err_info)) {
                        cfile_close_failure_message(filename, write_err,
                                                    write_err_info);
                        ret = WRITE_ERROR;
                        goto clean_exit;
                    }
                    nstime_add(&block_next, &secs_per_block); /* reset for next interval */
                    g_free(filename);
                    filename = fileset_get_filename_by_pattern(block_cnt++, rec, fprefix, fsuffix);
                    ws_assert(filename);

                    if (verbose)
                        fprintf(stderr, "Continuing writing in file %s\n", filename);

                    pdh = editcap_dump_open(filename, &params, idbs_seen,
                                            &write_err, &write_err_info);

                    if (pdh == NULL) {
                        cfile_dump_open_failure_message(filename,
                                                        write_err,
                                                        write_err_info,
                                                        out_file_type_subtype);
                        ret = INVALID_FILE;
                        goto clean_exit;
                    }
                }
            }
        }  /* time stamp handling */

        if (split_packet_count != 0) {
            /* time for the next file? */
            if (written_count > 0 && (written_count % split_packet_count) == 0) {
                if (!wtap_dump_close(pdh, NULL, &write_err, &write_err_info)) {
                    cfile_close_failure_message(filename, write_err,
                                                write_err_info);
                    ret = WRITE_ERROR;
                    goto clean_exit;
                }

                g_free(filename);
                filename = fileset_get_filename_by_pattern(block_cnt++, rec, fprefix, fsuffix);
                ws_assert(filename);

                if (verbose)
                    fprintf(stderr, "Continuing writing in file %s\n", filename);

                pdh = editcap_dump_open(filename, &params, idbs_seen,
                                        &write_err, &write_err_info);
                if (pdh == NULL) {
                    cfile_dump_open_failure_message(filename,
                                                    write_err, write_err_info,
                                                    out_file_type_subtype);
                    ret = INVALID_FILE;
                    goto clean_exit;
                }
            }
        } /* split packet handling */

        if (check_startstop) {
            ts_okay = FALSE;
            /*
             * Is the packet in the selected timeframe?
             * If the packet has no time stamp, the answer is "no".
             */
            if (rec->presence_flags & WTAP_HAS_TS) {
                if (have_starttime && have_stoptime) {
                    ts_okay = nstime_cmp(&rec->ts, &starttime) >= 0 &&
                              nstime_cmp(&rec->ts, &stoptime) < 0;
                } else if (have_starttime) {
                    ts_okay = nstime_cmp(&rec->ts, &starttime) >= 0;
                } else if (have_stoptime) {
                    ts_okay = nstime_cmp(&rec->ts, &stoptime) < 0;
                }
            }
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

            rec = &read_rec;

            if (rec->presence_flags & WTAP_HAS_TS) {
                /* Do we adjust timestamps to ensure strict chronological
                 * order? */
                if (do_strict_time_adjustment) {
                    if (previous_time.secs || previous_time.nsecs) {
                        if (!strict_time_adj.is_negative) {
                            nstime_t current;
                            nstime_t delta;

                            current = rec->ts;

                            nstime_delta(&delta, &current, &previous_time);

                            if (delta.secs < 0 || delta.nsecs < 0) {
                                /*
                                 * A negative delta indicates that the current packet
                                 * has an absolute timestamp less than the previous packet
                                 * that it is being compared to.  This is NOT a normal
                                 * situation since trace files usually have packets in
                                 * chronological order (oldest to newest).
                                 * Copy and change rather than modify
                                 * returned rec.
                                 */
                                /* fprintf(stderr, "++out of order, need to adjust this packet!\n"); */
                                temp_rec = *rec;
                                temp_rec.ts.secs = previous_time.secs + strict_time_adj.tv.secs;
                                temp_rec.ts.nsecs = previous_time.nsecs;
                                if (temp_rec.ts.nsecs + strict_time_adj.tv.nsecs >= ONE_BILLION) {
                                    /* carry */
                                    temp_rec.ts.secs++;
                                    temp_rec.ts.nsecs += strict_time_adj.tv.nsecs - ONE_BILLION;
                                } else {
                                    temp_rec.ts.nsecs += strict_time_adj.tv.nsecs;
                                }
                                rec = &temp_rec;
                            }
                        } else {
                            /*
                             * A negative strict time adjustment is requested.
                             * Unconditionally set each timestamp to previous
                             * packet's timestamp plus delta.
                             * Copy and change rather than modify returned
                             * rec.
                             */
                            temp_rec = *rec;
                            temp_rec.ts.secs = previous_time.secs + strict_time_adj.tv.secs;
                            temp_rec.ts.nsecs = previous_time.nsecs;
                            if (temp_rec.ts.nsecs + strict_time_adj.tv.nsecs >= ONE_BILLION) {
                                /* carry */
                                temp_rec.ts.secs++;
                                temp_rec.ts.nsecs += strict_time_adj.tv.nsecs - ONE_BILLION;
                            } else {
                                temp_rec.ts.nsecs += strict_time_adj.tv.nsecs;
                            }
                            rec = &temp_rec;
                        }
                    }
                    previous_time = rec->ts;
                }

                if (time_adj.tv.secs != 0) {
                    /* Copy and change rather than modify returned rec */
                    temp_rec = *rec;
                    if (time_adj.is_negative)
                        temp_rec.ts.secs -= time_adj.tv.secs;
                    else
                        temp_rec.ts.secs += time_adj.tv.secs;
                    rec = &temp_rec;
                }

                if (time_adj.tv.nsecs != 0) {
                    /* Copy and change rather than modify returned rec */
                    temp_rec = *rec;
                    if (time_adj.is_negative) { /* subtract */
                        if (temp_rec.ts.nsecs < time_adj.tv.nsecs) { /* borrow */
                            temp_rec.ts.secs--;
                            temp_rec.ts.nsecs += ONE_BILLION;
                        }
                        temp_rec.ts.nsecs -= time_adj.tv.nsecs;
                    } else {                  /* add */
                        if (temp_rec.ts.nsecs + time_adj.tv.nsecs >= ONE_BILLION) {
                            /* carry */
                            temp_rec.ts.secs++;
                            temp_rec.ts.nsecs += time_adj.tv.nsecs - ONE_BILLION;
                        } else {
                            temp_rec.ts.nsecs += time_adj.tv.nsecs;
                        }
                    }
                    rec = &temp_rec;
                }
            } /* time stamp adjustment */

            if (rec->rec_type == REC_TYPE_PACKET) {
                if (snaplen != 0) {
                    /* Limit capture length to snaplen */
                    if (rec->rec_header.packet_header.caplen > snaplen) {
                        /* Copy and change rather than modify returned rec */
                        temp_rec = *rec;
                        temp_rec.rec_header.packet_header.caplen = snaplen;
                        rec = &temp_rec;
                    }
                    /* If -L, also set reported length to snaplen */
                    if (adjlen && rec->rec_header.packet_header.len > snaplen) {
                        /* Copy and change rather than modify returned rec */
                        temp_rec = *rec;
                        temp_rec.rec_header.packet_header.len = snaplen;
                        rec = &temp_rec;
                    }
                }

                /*
                 * If an encapsulation type was specified, override the
                 * encapsulation type of the packet.
                 * Copy and change rather than modify returned rec.
                 */
                if (out_frame_type != -2) {
                    temp_rec = *rec;
                    temp_rec.rec_header.packet_header.pkt_encap = out_frame_type;
                    rec = &temp_rec;
                }

                /*
                 * CHOP
                 * Copy and change rather than modify returned rec.
                 */
                temp_rec = *rec;
                handle_chopping(chop, &temp_rec.rec_header.packet_header,
                                &rec->rec_header.packet_header, &buf,
                                adjlen);
                rec = &temp_rec;

                /* remove vlan info */
                if (rem_vlan) {
                    /* Copy and change rather than modify returned rec */
                    temp_rec = *rec;
                    remove_vlan_info(&rec->rec_header.packet_header, buf,
                                     &temp_rec.rec_header.packet_header.caplen);
                    rec = &temp_rec;
                }

                /* suppress duplicates by packet window */
                if (dup_detect) {
                    if (is_duplicate(buf, rec->rec_header.packet_header.caplen)) {
                        if (verbose) {
                            fprintf(stderr, "Skipped: %u, Len: %u, MD5 Hash: ",
                                    count,
                                    rec->rec_header.packet_header.caplen);
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
                                    count,
                                    rec->rec_header.packet_header.caplen);
                            for (i = 0; i < 16; i++)
                                fprintf(stderr, "%02x",
                                        (unsigned char)fd_hash[cur_dup_entry].digest[i]);
                            fprintf(stderr, "\n");
                        }
                    }
                } /* suppression of duplicates */

                if (rec->presence_flags & WTAP_HAS_TS) {
                    /* suppress duplicates by time window */
                    if (dup_detect_by_time) {
                        nstime_t current;

                        current.secs  = rec->ts.secs;
                        current.nsecs = rec->ts.nsecs;

                        if (is_duplicate_rel_time(buf,
                                                  rec->rec_header.packet_header.caplen,
                                                  &current)) {
                            if (verbose) {
                                fprintf(stderr, "Skipped: %u, Len: %u, MD5 Hash: ",
                                        count,
                                        rec->rec_header.packet_header.caplen);
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
                                        count,
                                        rec->rec_header.packet_header.caplen);
                                for (i = 0; i < 16; i++)
                                    fprintf(stderr, "%02x",
                                            (unsigned char)fd_hash[cur_dup_entry].digest[i]);
                                fprintf(stderr, "\n");
                            }
                        }
                    }
                } /* suppress duplicates by time window */
            }

            /* Random error mutation */
            do_mutation = FALSE;
            caplen = 0;
            if (err_prob > 0.0) {
                switch (rec->rec_type) {

                case REC_TYPE_PACKET:
                    caplen = rec->rec_header.packet_header.caplen;
                    do_mutation = TRUE;
                    break;

                case REC_TYPE_FT_SPECIFIC_EVENT:
                case REC_TYPE_FT_SPECIFIC_REPORT:
                    caplen = rec->rec_header.ft_specific_header.record_len;
                    do_mutation = TRUE;
                    break;

                case REC_TYPE_SYSCALL:
                    caplen = rec->rec_header.syscall_header.event_filelen;
                    do_mutation = TRUE;
                    break;

                case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
                    caplen = rec->rec_header.systemd_journal_export_header.record_len;
                    do_mutation = TRUE;
                    break;
                }

                if (change_offset > caplen) {
                    fprintf(stderr, "change offset %u is longer than caplen %u in packet %u\n",
                        change_offset, caplen, count);
                    do_mutation = FALSE;
                }
            }

            if (do_mutation) {
                int real_data_start = 0;

                /* Protect non-protocol data */
                switch (rec->rec_type) {

                case REC_TYPE_PACKET:
                    /*
                     * XXX - any reason not to fuzz this part?
                     */
                    if (rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_CATAPULT_DCT2000)
                        real_data_start = find_dct2000_real_data(buf);
                    break;
                }

                real_data_start += change_offset;

                for (i = real_data_start; i < (int) caplen; i++) {
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
                            if ((unsigned int)i < caplen - 2)
                                (void) g_strlcpy((char*) &buf[i], "%s", 2);
                            err_type = ERR_WT_TOTAL;
                        } else {
                            err_type -= ERR_WT_FMT;
                        }

                        if (err_type < ERR_WT_AA) {
                            for (j = i; j < (int) caplen; j++)
                                buf[j] = 0xAA;
                            i = caplen;
                        }
                    }
                }
            } /* random error mutation */

            /* Find a packet comment we may need to write */
            if (frames_user_comments) {
                const char *comment =
                    (const char*)g_tree_lookup(frames_user_comments, GUINT_TO_POINTER(read_count));
                /* XXX: What about comment changed to no comment? */
                if (comment != NULL) {
                    /* Copy and change rather than modify returned rec */
                    temp_rec = *rec;
                    /* The comment is not modified by dumper, cast away. */
                    wtap_block_add_string_option(rec->block, OPT_COMMENT, (char *)comment, strlen((char *)comment));
                    temp_rec.block_was_modified = TRUE;
                    rec = &temp_rec;
                } else {
                    /* Copy and change rather than modify returned rec */
                    temp_rec = *rec;
                    temp_rec.block_was_modified = FALSE;
                    rec = &temp_rec;
                }
            }

            if (discard_all_secrets) {
                /*
                 * Discard any secrets we've read since the last packet
                 * we wrote.
                 */
                wtap_dump_discard_decryption_secrets(pdh);
            }

            /* Attempt to dump out current frame to the output file */
            if (!wtap_dump(pdh, rec, buf, &write_err, &write_err_info)) {
                cfile_write_failure_message(argv[ws_optind], filename,
                                            write_err, write_err_info,
                                            read_count,
                                            out_file_type_subtype);
                ret = DUMP_ERROR;
                goto clean_exit;
            }
            written_count++;
        }
        count++;
        wtap_rec_reset(&read_rec);
    }
    wtap_rec_cleanup(&read_rec);
    ws_buffer_free(&read_buf);

    g_free(fprefix);
    g_free(fsuffix);

    if (read_err != 0) {
        /* Print a message noting that the read failed somewhere along the
         * line. */
        cfile_read_failure_message(argv[ws_optind], read_err, read_err_info);
    }

    if (!pdh) {
        /* No valid packages found, open the outfile so we can write an
         * empty header */
        g_free (filename);
        filename = g_strdup(argv[ws_optind+1]);

        pdh = editcap_dump_open(filename, &params, idbs_seen, &write_err,
                                &write_err_info);
        if (pdh == NULL) {
            cfile_dump_open_failure_message(filename,
                                            write_err, write_err_info,
                                            out_file_type_subtype);
            ret = INVALID_FILE;
            goto clean_exit;
        }
    }

    if (!wtap_dump_close(pdh, NULL, &write_err, &write_err_info)) {
        cfile_close_failure_message(filename, write_err, write_err_info);
        ret = WRITE_ERROR;
        goto clean_exit;
    }
    g_free(filename);

    if (frames_user_comments) {
        g_tree_destroy(frames_user_comments);
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

clean_exit:
    if (dsb_filenames) {
        g_array_free(dsb_types, TRUE);
        g_ptr_array_free(dsb_filenames, TRUE);
    }
    if (idbs_seen != NULL) {
        for (guint b = 0; b < idbs_seen->len; b++) {
            wtap_block_t if_data = g_array_index(idbs_seen, wtap_block_t, b);
            wtap_block_unref(if_data);
        }
        g_array_free(idbs_seen, TRUE);
    }
    g_free(params.idb_inf);
    wtap_dump_params_cleanup(&params);
    if (wth != NULL)
        wtap_close(wth);
    wtap_rec_reset(&read_rec);
    wtap_cleanup();
    free_progdirs();
    if (capture_comments != NULL) {
        g_ptr_array_free(capture_comments, TRUE);
        capture_comments = NULL;
    }
    return ret;
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
handle_chopping(chop_t chop, wtap_packet_header *out_phdr,
                const wtap_packet_header *in_phdr, guint8 **buf,
                gboolean adjlen)
{
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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
