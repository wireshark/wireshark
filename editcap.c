/* Edit capture files.  We can delete packets, adjust timestamps, or
 * simply convert from one format to another format.
 *
 * $Id$
 *
 * Originally written by Richard Sharpe.
 * Improved by Guy Harris.
 * Further improved by Richard Sharpe.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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



#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "wtap.h"

#ifndef HAVE_GETOPT
#include "wsutil/wsgetopt.h"
#endif

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#include <process.h>    /* getpid */
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#endif

#ifdef NEED_STRPTIME_H
# include "wsutil/strptime.h"
#endif

#include "epan/crypt/md5.h"
#include "epan/plugins.h"
#include "epan/report_err.h"
#include "epan/filesystem.h"
#include <wsutil/privileges.h>
#include "epan/nstime.h"

#include "svnversion.h"

/*
 * Some globals so we can pass things to various routines
 */

struct select_item {

  int inclusive;
  int first, second;

};


/*
 * Duplicate frame detection
 */
typedef struct _fd_hash_t {
  md5_byte_t digest[16];
  guint32 len;
  nstime_t time;
} fd_hash_t;

#define DEFAULT_DUP_DEPTH 5     /* Used with -d */
#define MAX_DUP_DEPTH 1000000   /* the maximum window (and actual size of fd_hash[]) for de-duplication */

fd_hash_t fd_hash[MAX_DUP_DEPTH];
int dup_window = DEFAULT_DUP_DEPTH;
int cur_dup_entry = 0;

#define ONE_MILLION 1000000
#define ONE_BILLION 1000000000

/* Weights of different errors we can introduce */
/* We should probably make these command-line arguments */
/* XXX - Should we add a bit-level error? */
#define ERR_WT_BIT   5  /* Flip a random bit */
#define ERR_WT_BYTE  5  /* Substitute a random byte */
#define ERR_WT_ALNUM 5  /* Substitute a random character in [A-Za-z0-9] */
#define ERR_WT_FMT   2  /* Substitute "%s" */
#define ERR_WT_AA    1  /* Fill the remainder of the buffer with 0xAA */
#define ERR_WT_TOTAL (ERR_WT_BIT + ERR_WT_BYTE + ERR_WT_ALNUM + ERR_WT_FMT + ERR_WT_AA)

#define ALNUM_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define ALNUM_LEN (sizeof(ALNUM_CHARS) - 1)


struct time_adjustment {
  struct timeval tv;
  int is_negative;
};

#define MAX_SELECTIONS 512
static struct select_item selectfrm[MAX_SELECTIONS];
static int max_selected = -1;
static int keep_em = 0;
#ifdef PCAP_NG_DEFAULT
static int out_file_type = WTAP_FILE_PCAPNG; /* default to pcapng   */
#else
static int out_file_type = WTAP_FILE_PCAP;   /* default to pcap     */
#endif
static int out_frame_type = -2;              /* Leave frame type alone */
static int verbose = 0;                      /* Not so verbose         */
static struct time_adjustment time_adj = {{0, 0}, 0}; /* no adjustment */
static nstime_t relative_time_window = {0, 0}; /* de-dup time window */
static double err_prob = 0.0;
static time_t starttime = 0;
static time_t stoptime = 0;
static gboolean check_startstop = FALSE;
static gboolean dup_detect = FALSE;
static gboolean dup_detect_by_time = FALSE;

static int do_strict_time_adjustment = FALSE;
static struct time_adjustment strict_time_adj = {{0, 0}, 0}; /* strict time adjustment */
static nstime_t previous_time = {0, 0}; /* previous time */

static int find_dct2000_real_data(guint8 *buf);

static gchar *
abs_time_to_str_with_sec_resolution(const struct wtap_nstime *abs_time)
{
    struct tm *tmp;
    gchar *buf = g_malloc(16);

#ifdef _MSC_VER
    /* calling localtime() on MSVC 2005 with huge values causes it to crash */
    /* XXX - find the exact value that still does work */
    /* XXX - using _USE_32BIT_TIME_T might be another way to circumvent this problem */
    if(abs_time->secs > 2000000000) {
        tmp = NULL;
    } else
#endif
    tmp = localtime(&abs_time->secs);
    if (tmp) {
        g_snprintf(buf, 16, "%d%02d%02d%02d%02d%02d",
            tmp->tm_year + 1900,
            tmp->tm_mon+1,
            tmp->tm_mday,
            tmp->tm_hour,
            tmp->tm_min,
            tmp->tm_sec);
    } else
        buf[0] = '\0';

    return buf;
}

static gchar*
fileset_get_filename_by_pattern(guint idx,    const struct wtap_nstime *time_val,
                                gchar *fprefix, gchar *fsuffix)
{
    gchar filenum[5+1];
    gchar *timestr;
    gchar *abs_str;

    timestr = abs_time_to_str_with_sec_resolution(time_val);
    g_snprintf(filenum, sizeof(filenum), "%05u", idx);
    abs_str = g_strconcat(fprefix, "_", filenum, "_", timestr, fsuffix, NULL);
    g_free(timestr);

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
         of the pathname (because there is either only one component,
         i.e. last_pathsep is null as there are no path separators,
         or the "." is after the path separator before the last
         component.

         Treat it as a separator between the rest of the file name and
         the file name suffix, and arrange that the names given to the
         ring buffer files have the specified suffix, i.e. put the
         changing part of the name *before* the suffix. */
      pfx[0] = '\0';
      *fprefix = g_strdup(save_file);
      pfx[0] = '.'; /* restore capfile_name */
      *fsuffix = g_strdup(pfx);
    } else {
      /* Either there's no "." in the pathname, or it's in a directory
         component, so the last component has no suffix. */
      *fprefix = g_strdup(save_file);
      *fsuffix = NULL;
    }
    g_free(save_file);
    return TRUE;
}

/* Add a selection item, a simple parser for now */
static gboolean
add_selection(char *sel)
{
  char *locn;
  char *next;

  if (++max_selected >= MAX_SELECTIONS) {
    /* Let the user know we stopped selecting */
    printf("Out of room for packet selections!\n");
    return(FALSE);
  }

  printf("Add_Selected: %s\n", sel);

  if ((locn = strchr(sel, '-')) == NULL) { /* No dash, so a single number? */

    printf("Not inclusive ...");

    selectfrm[max_selected].inclusive = 0;
    selectfrm[max_selected].first = atoi(sel);

    printf(" %i\n", selectfrm[max_selected].first);

  }
  else {

    printf("Inclusive ...");

    next = locn + 1;
    selectfrm[max_selected].inclusive = 1;
    selectfrm[max_selected].first = atoi(sel);
    selectfrm[max_selected].second = atoi(next);

    printf(" %i, %i\n", selectfrm[max_selected].first, selectfrm[max_selected].second);

  }

  return(TRUE);
}

/* Was the packet selected? */

static int
selected(int recno)
{
  int i = 0;

  for (i = 0; i<= max_selected; i++) {

    if (selectfrm[i].inclusive) {
      if (selectfrm[i].first <= recno && selectfrm[i].second >= recno)
        return 1;
    }
    else {
      if (recno == selectfrm[i].first)
        return 1;
    }
  }

  return 0;

}

/* is the packet in the selected timeframe */
static gboolean
check_timestamp(wtap *wth)
{
  struct wtap_pkthdr* pkthdr = wtap_phdr(wth);

  return ( pkthdr->ts.secs >= starttime ) && ( pkthdr->ts.secs < stoptime );
}

static void
set_time_adjustment(char *optarg_str_p)
{
  char *frac, *end;
  long val;
  size_t frac_digits;

  if (!optarg_str_p)
    return;

  /* skip leading whitespace */
  while (*optarg_str_p == ' ' || *optarg_str_p == '\t') {
      optarg_str_p++;
  }

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
      if (frac == NULL || frac == optarg_str_p || val == LONG_MIN || val == LONG_MAX) {
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
  time_adj.tv.tv_sec = val;

  /* now collect the partial seconds, if any */
  if (*frac != '\0') {             /* chars left, so get fractional part */
    val = strtol(&(frac[1]), &end, 10);
    /* if more than 6 fractional digits truncate to 6 */
    if((end - &(frac[1])) > 6) {
        frac[7] = 't'; /* 't' for truncate */
        val = strtol(&(frac[1]), &end, 10);
    }
    if (*frac != '.' || end == NULL || end == frac
        || val < 0 || val > ONE_MILLION || val == LONG_MIN || val == LONG_MAX) {
      fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
              optarg_str_p);
      exit(1);
    }
  }
  else {
    return;                     /* no fractional digits */
  }

  /* adjust fractional portion from fractional to numerator
   * e.g., in "1.5" from 5 to 500000 since .5*10^6 = 500000 */
  if (frac && end) {            /* both are valid */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 6) {    /* this is frac of 10^6 */
      val *= 10;
      frac_digits++;
    }
  }
  time_adj.tv.tv_usec = val;
}

static void
set_strict_time_adj(char *optarg_str_p)
{
  char *frac, *end;
  long val;
  size_t frac_digits;

  if (!optarg_str_p)
    return;

  /* skip leading whitespace */
  while (*optarg_str_p == ' ' || *optarg_str_p == '\t') {
      optarg_str_p++;
  }

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
      if (frac == NULL || frac == optarg_str_p || val == LONG_MIN || val == LONG_MAX) {
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
  strict_time_adj.tv.tv_sec = val;

  /* now collect the partial seconds, if any */
  if (*frac != '\0') {             /* chars left, so get fractional part */
    val = strtol(&(frac[1]), &end, 10);
    /* if more than 6 fractional digits truncate to 6 */
    if((end - &(frac[1])) > 6) {
        frac[7] = 't'; /* 't' for truncate */
        val = strtol(&(frac[1]), &end, 10);
    }
    if (*frac != '.' || end == NULL || end == frac
        || val < 0 || val > ONE_MILLION || val == LONG_MIN || val == LONG_MAX) {
      fprintf(stderr, "editcap: \"%s\" isn't a valid time adjustment\n",
              optarg_str_p);
      exit(1);
    }
  }
  else {
    return;                     /* no fractional digits */
  }

  /* adjust fractional portion from fractional to numerator
   * e.g., in "1.5" from 5 to 500000 since .5*10^6 = 500000 */
  if (frac && end) {            /* both are valid */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 6) {    /* this is frac of 10^6 */
      val *= 10;
      frac_digits++;
    }
  }
  strict_time_adj.tv.tv_usec = val;
}

static void
set_rel_time(char *optarg_str_p)
{
  char *frac, *end;
  long val;
  size_t frac_digits;

  if (!optarg_str_p)
    return;

  /* skip leading whitespace */
  while (*optarg_str_p == ' ' || *optarg_str_p == '\t') {
      optarg_str_p++;
  }

  /* ignore negative adjustment  */
  if (*optarg_str_p == '-') {
      optarg_str_p++;
  }

  /* collect whole number of seconds, if any */
  if (*optarg_str_p == '.') {         /* only fractional (i.e., .5 is ok) */
      val  = 0;
      frac = optarg_str_p;
  } else {
      val = strtol(optarg_str_p, &frac, 10);
      if (frac == NULL || frac == optarg_str_p || val == LONG_MIN || val == LONG_MAX) {
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
    if((end - &(frac[1])) > 9) {
        frac[10] = 't'; /* 't' for truncate */
        val = strtol(&(frac[1]), &end, 10);
    }
    if (*frac != '.' || end == NULL || end == frac
        || val < 0 || val > ONE_BILLION || val == LONG_MIN || val == LONG_MAX) {
      fprintf(stderr, "3: editcap: \"%s\" isn't a valid rel time value\n",
              optarg_str_p);
      exit(1);
    }
  }
  else {
    return;                     /* no fractional digits */
  }

  /* adjust fractional portion from fractional to numerator
   * e.g., in "1.5" from 5 to 500000000 since .5*10^9 = 500000000 */
  if (frac && end) {            /* both are valid */
    frac_digits = end - frac - 1;   /* fractional digit count (remember '.') */
    while(frac_digits < 9) {    /* this is frac of 10^9 */
      val *= 10;
      frac_digits++;
    }
  }
  relative_time_window.nsecs = val;
}

static gboolean
is_duplicate(guint8* fd, guint32 len) {
  int i;
  md5_state_t ms;

  cur_dup_entry++;
  if (cur_dup_entry >= dup_window)
    cur_dup_entry = 0;

  /* Calculate our digest */
  md5_init(&ms);
  md5_append(&ms, fd, len);
  md5_finish(&ms, fd_hash[cur_dup_entry].digest);

  fd_hash[cur_dup_entry].len = len;

  /* Look for duplicates */
  for (i = 0; i < dup_window; i++) {
    if (i == cur_dup_entry)
      continue;

    if (fd_hash[i].len == fd_hash[cur_dup_entry].len &&
        memcmp(fd_hash[i].digest, fd_hash[cur_dup_entry].digest, 16) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
is_duplicate_rel_time(guint8* fd, guint32 len, const nstime_t *current) {
  int i;
  md5_state_t ms;

  cur_dup_entry++;
  if (cur_dup_entry >= dup_window)
    cur_dup_entry = 0;

  /* Calculate our digest */
  md5_init(&ms);
  md5_append(&ms, fd, len);
  md5_finish(&ms, fd_hash[cur_dup_entry].digest);

  fd_hash[cur_dup_entry].len = len;
  fd_hash[cur_dup_entry].time.secs = current->secs;
  fd_hash[cur_dup_entry].time.nsecs = current->nsecs;

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
   * The fd_hash[] table was deliberatly created large (1,000,000).
   * Looking for time related duplicates in large trace files with
   * non-fractional dup time window values can potentially take
   * a long time to complete.
   */

  for (i = cur_dup_entry - 1;; i--) {
    nstime_t delta;
    int cmp;

    if (i < 0) {
      i = dup_window - 1;
    }

    if (i == cur_dup_entry) {
      /*
       * We've decremented back to where we started.
       * Check no more!
       */
      break;
    }

    if (nstime_is_unset(&(fd_hash[i].time))) {
      /*
       * We've decremented to an unused fd_hash[] entry.
       * Check no more!
       */
      break;
    }

    nstime_delta(&delta, current, &fd_hash[i].time);

    if(delta.secs < 0 || delta.nsecs < 0)
    {
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

    if(cmp > 0) {
      /*
       * The delta time indicates that we are now looking at
       * cached packets beyond the specified dup time window.
       * Check no more!
       */
      break;
    } else if (fd_hash[i].len == fd_hash[cur_dup_entry].len &&
          memcmp(fd_hash[i].digest, fd_hash[cur_dup_entry].digest, 16) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

static void
usage(gboolean is_error)
{
  FILE *output;

  if (!is_error)
    output = stdout;
  else
    output = stderr;

  fprintf(output, "Editcap %s"
#ifdef SVNVERSION
    " (" SVNVERSION " from " SVNPATH ")"
#endif
    "\n", VERSION);
  fprintf(output, "Edit and/or translate the format of capture files.\n");
  fprintf(output, "See http://www.wireshark.org for more information.\n");
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
  fprintf(output, "  -d                     remove packet if duplicate (window == %d).\n", DEFAULT_DUP_DEPTH);
  fprintf(output, "  -D <dup window>        remove packet if duplicate; configurable <dup window>\n");
  fprintf(output, "                         Valid <dup window> values are 0 to %d.\n", MAX_DUP_DEPTH);
  fprintf(output, "                         NOTE: A <dup window> of 0 with -v (verbose option) is\n");
  fprintf(output, "                         useful to print MD5 hashes.\n");
  fprintf(output, "  -w <dup time window>   remove packet if duplicate packet is found EQUAL TO OR\n");
  fprintf(output, "                         LESS THAN <dup time window> prior to current packet.\n");
  fprintf(output, "                         A <dup time window> is specified in relative seconds\n");
  fprintf(output, "                         (e.g. 0.000001).\n");
  fprintf(output, "\n");
  fprintf(output, "           NOTE: The use of the 'Duplicate packet removal' options with\n");
  fprintf(output, "           other editcap options except -v may not always work as expected.\n");
  fprintf(output, "           Specifically the -r, -t or -S options will very likely NOT have the\n");
  fprintf(output, "           desired effect if combined with the -d, -D or -w.\n");
  fprintf(output, "\n");
  fprintf(output, "Packet manipulation:\n");
  fprintf(output, "  -s <snaplen>           truncate each packet to max. <snaplen> bytes of data.\n");
  fprintf(output, "  -C <choplen>           chop each packet by <choplen> bytes. Positive values\n");
  fprintf(output, "                         chop at the packet beginning, negative values at the\n");
  fprintf(output, "                         packet end.\n");
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
  fprintf(output, "  -E <error probability> set the probability (between 0.0 and 1.0 incl.)\n");
  fprintf(output, "                         that a particular packet byte will be randomly changed.\n");
  fprintf(output, "\n");
  fprintf(output, "Output File(s):\n");
  fprintf(output, "  -c <packets per file>  split the packet output to different files\n");
  fprintf(output, "                         based on uniform packet counts\n");
  fprintf(output, "                         with a maximum of <packets per file> each.\n");
  fprintf(output, "  -i <seconds per file>  split the packet output to different files\n");
  fprintf(output, "                         based on uniform time intervals\n");
  fprintf(output, "                         with a maximum of <seconds per file> each.\n");
  fprintf(output, "  -F <capture type>      set the output file type; default is pcapng.\n");
  fprintf(output, "                         an empty \"-F\" option will list the file types.\n");
  fprintf(output, "  -T <encap type>        set the output file encapsulation type;\n");
  fprintf(output, "                         default is the same as the input file.\n");
  fprintf(output, "                         an empty \"-T\" option will list the encapsulation types.\n");
  fprintf(output, "\n");
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -h                     display this help and exit.\n");
  fprintf(output, "  -v                     verbose output.\n");
  fprintf(output, "                         If -v is used with any of the 'Duplicate Packet\n");
  fprintf(output, "                         Removal' options (-d, -D or -w) then Packet lengths\n");
  fprintf(output, "                         and MD5 hashes are printed to standard-out.\n");
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

    captypes = g_malloc(sizeof(struct string_elem) * WTAP_NUM_FILE_TYPES);
    fprintf(stderr, "editcap: The available capture file types for the \"-F\" flag are:\n");
    for (i = 0; i < WTAP_NUM_FILE_TYPES; i++) {
      if (wtap_dump_can_open(i)) {
        captypes[i].sstr = wtap_file_type_short_string(i);
        captypes[i].lstr = wtap_file_type_string(i);
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

    encaps = g_malloc(sizeof(struct string_elem) * WTAP_NUM_ENCAP_TYPES);
    fprintf(stderr, "editcap: The available encapsulation types for the \"-T\" flag are:\n");
    for (i = 0; i < WTAP_NUM_ENCAP_TYPES; i++) {
        encaps[i].sstr = wtap_encap_short_string(i);
        if (encaps[i].sstr != NULL) {
            encaps[i].lstr = wtap_encap_string(i);
            list = g_slist_insert_sorted(list, &encaps[i], string_compare);
        }
    }
    g_slist_foreach(list, string_elem_print, NULL);
    g_slist_free(list);
    g_free(encaps);
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
    return;
}
#endif

int
main(int argc, char *argv[])
{
  wtap *wth;
  int i, j, err;
  gchar *err_info;
  int opt;

  char *p;
  guint32 snaplen = 0;                  /* No limit               */
  int choplen = 0;                      /* No chop                */
  wtap_dumper *pdh = NULL;
  int count = 1;
  unsigned duplicate_count = 0;
  gint64 data_offset;
  struct wtap_pkthdr snap_phdr;
  const struct wtap_pkthdr *phdr;
  int err_type;
  wtapng_section_t *shb_hdr;
  wtapng_iface_descriptions_t *idb_inf;
  guint8 *buf;
  guint32 read_count = 0;
  int split_packet_count = 0;
  int written_count = 0;
  char *filename = NULL;
  gboolean ts_okay = TRUE;
  int secs_per_block = 0;
  int block_cnt = 0;
  nstime_t block_start;
  gchar *fprefix = NULL;
  gchar *fsuffix = NULL;

#ifdef HAVE_PLUGINS
  char* init_progfile_dir_error;
#endif

#ifdef _WIN32
  arg_list_utf_16to8(argc, argv);
#endif /* _WIN32 */

  /*
   * Get credential information for later use.
   */
  init_process_policies();

#ifdef HAVE_PLUGINS
  /* Register wiretap plugins */
  if ((init_progfile_dir_error = init_progfile_dir(argv[0], main))) {
    g_warning("capinfos: init_progfile_dir(): %s", init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  } else {
    init_report_err(failure_message,NULL,NULL,NULL);
    init_plugins();
  }
#endif

  /* Process the options */
  while ((opt = getopt(argc, argv, "A:B:c:C:dD:E:F:hrs:i:t:S:T:vw:")) !=-1) {

    switch (opt) {

    case 'E':
      err_prob = strtod(optarg, &p);
      if (p == optarg || err_prob < 0.0 || err_prob > 1.0) {
        fprintf(stderr, "editcap: probability \"%s\" must be between 0.0 and 1.0\n",
            optarg);
        exit(1);
      }
      srand( (unsigned int) (time(NULL) + getpid()) );
      break;

    case 'F':
      out_file_type = wtap_short_string_to_file_type(optarg);
      if (out_file_type < 0) {
        fprintf(stderr, "editcap: \"%s\" isn't a valid capture file type\n\n",
            optarg);
        list_capture_types();
        exit(1);
      }
      break;

    case 'c':
      split_packet_count = strtol(optarg, &p, 10);
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
      choplen = strtol(optarg, &p, 10);
      if (p == optarg || *p != '\0') {
        fprintf(stderr, "editcap: \"%s\" isn't a valid chop length\n",
            optarg);
        exit(1);
      }
      break;

    case 'd':
      dup_detect = TRUE;
      dup_detect_by_time = FALSE;
      dup_window = DEFAULT_DUP_DEPTH;
      break;

    case 'D':
      dup_detect = TRUE;
      dup_detect_by_time = FALSE;
      dup_window = strtol(optarg, &p, 10);
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
        usage(TRUE);
      }
      exit(1);
      break;

    case 'h':
      usage(FALSE);
      exit(1);
      break;

    case 'r':
      keep_em = !keep_em;  /* Just invert */
      break;

    case 's':
      snaplen = strtol(optarg, &p, 10);
      if (p == optarg || *p != '\0') {
        fprintf(stderr, "editcap: \"%s\" isn't a valid snapshot length\n",
                optarg);
        exit(1);
      }
      break;

    case 't':
      set_time_adjustment(optarg);
      break;

    case 'S':
      set_strict_time_adj(optarg);
      do_strict_time_adjustment = TRUE;
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

    case 'i': /* break capture file based on time interval */
      secs_per_block = atoi(optarg);
      if(secs_per_block <= 0) {
        fprintf(stderr, "editcap: \"%s\" isn't a valid time interval\n\n", optarg);
        exit(1);
        }
      break;

    case 'A':
    {
      struct tm starttm;

      memset(&starttm,0,sizeof(struct tm));

      if(!strptime(optarg,"%Y-%m-%d %T",&starttm)) {
        fprintf(stderr, "editcap: \"%s\" isn't a valid time format\n\n", optarg);
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

      if(!strptime(optarg,"%Y-%m-%d %T",&stoptm)) {
        fprintf(stderr, "editcap: \"%s\" isn't a valid time format\n\n", optarg);
        exit(1);
      }
      check_startstop = TRUE;
      stoptm.tm_isdst = -1;
      stoptime = mktime(&stoptm);
      break;
    }
    }

  }

#ifdef DEBUG
  printf("Optind = %i, argc = %i\n", optind, argc);
#endif

  if ((argc - optind) < 1) {

    usage(TRUE);
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

  wth = wtap_open_offline(argv[optind], &err, &err_info, FALSE);

  if (!wth) {
    fprintf(stderr, "editcap: Can't open %s: %s\n", argv[optind],
        wtap_strerror(err));
    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
    case WTAP_ERR_UNSUPPORTED_ENCAP:
    case WTAP_ERR_BAD_FILE:
      fprintf(stderr, "(%s)\n", err_info);
      g_free(err_info);
      break;
    }
    exit(2);

  }

  if (verbose) {
    fprintf(stderr, "File %s is a %s capture file.\n", argv[optind],
            wtap_file_type_string(wtap_file_type(wth)));
  }

  shb_hdr = wtap_file_get_shb_info(wth);
  idb_inf = wtap_file_get_idb_info(wth);

  /*
   * Now, process the rest, if any ... we only write if there is an extra
   * argument or so ...
   */

  if ((argc - optind) >= 2) {

    if (out_frame_type == -2)
      out_frame_type = wtap_file_encap(wth);

    for (i = optind + 2; i < argc; i++)
      if (add_selection(argv[i]) == FALSE)
        break;

    if (dup_detect || dup_detect_by_time) {
      for (i = 0; i < dup_window; i++) {
        memset(&fd_hash[i].digest, 0, 16);
        fd_hash[i].len = 0;
        nstime_set_unset(&fd_hash[i].time);
      }
    }

    while (wtap_read(wth, &err, &err_info, &data_offset)) {
      read_count++;

      phdr = wtap_phdr(wth);
      buf = wtap_buf_ptr(wth);

      if (nstime_is_unset(&block_start)) {  /* should only be the first packet */
        block_start.secs = phdr->ts.secs;
        block_start.nsecs = phdr->ts.nsecs;

        if (split_packet_count > 0 || secs_per_block > 0) {
          if (!fileset_extract_prefix_suffix(argv[optind+1], &fprefix, &fsuffix))
              exit(2);

          filename = fileset_get_filename_by_pattern(block_cnt++, &phdr->ts, fprefix, fsuffix);
        } else
          filename = g_strdup(argv[optind+1]);

        pdh = wtap_dump_open_ng(filename, out_file_type, out_frame_type,
          snaplen ? MIN(snaplen, wtap_snapshot_length(wth)) : wtap_snapshot_length(wth),
          FALSE /* compressed */, shb_hdr, idb_inf, &err);
        if (pdh == NULL) {
          fprintf(stderr, "editcap: Can't open or create %s: %s\n", filename,
                  wtap_strerror(err));
          exit(2);
        }
      }

      g_assert(filename);

      if (secs_per_block > 0) {
        while ((phdr->ts.secs - block_start.secs >  secs_per_block) ||
               (phdr->ts.secs - block_start.secs == secs_per_block &&
                phdr->ts.nsecs >= block_start.nsecs )) { /* time for the next file */

          if (!wtap_dump_close(pdh, &err)) {
            fprintf(stderr, "editcap: Error writing to %s: %s\n", filename,
                wtap_strerror(err));
            exit(2);
          }
          block_start.secs = block_start.secs +  secs_per_block; /* reset for next interval */
          g_free(filename);
          filename = fileset_get_filename_by_pattern(block_cnt++, &phdr->ts, fprefix, fsuffix);
          g_assert(filename);

          if (verbose) {
            fprintf(stderr, "Continuing writing in file %s\n", filename);
          }

          pdh = wtap_dump_open(filename, out_file_type, out_frame_type,
            snaplen ? MIN(snaplen, wtap_snapshot_length(wth)) : wtap_snapshot_length(wth),
            FALSE /* compressed */, &err);

          if (pdh == NULL) {
            fprintf(stderr, "editcap: Can't open or create %s: %s\n", filename,
              wtap_strerror(err));
            exit(2);
          }
        }
      }

      if (split_packet_count > 0) {

        /* time for the next file? */
        if (written_count > 0 &&
            written_count % split_packet_count == 0) {
          if (!wtap_dump_close(pdh, &err)) {
            fprintf(stderr, "editcap: Error writing to %s: %s\n", filename,
                wtap_strerror(err));
            exit(2);
          }

          g_free(filename);
          filename = fileset_get_filename_by_pattern(block_cnt++, &phdr->ts, fprefix, fsuffix);
          g_assert(filename);

          if (verbose) {
            fprintf(stderr, "Continuing writing in file %s\n", filename);
          }

          pdh = wtap_dump_open(filename, out_file_type, out_frame_type,
            snaplen ? MIN(snaplen, wtap_snapshot_length(wth)) : wtap_snapshot_length(wth),
            FALSE /* compressed */, &err);
          if (pdh == NULL) {
            fprintf(stderr, "editcap: Can't open or create %s: %s\n", filename,
                wtap_strerror(err));
            exit(2);
          }
        }
      }

      if (check_startstop)
        ts_okay = check_timestamp(wth);

      if ( ts_okay && ((!selected(count) && !keep_em) || (selected(count) && keep_em)) ) {

        if (verbose && !dup_detect && !dup_detect_by_time)
          printf("Packet: %u\n", count);

        /* We simply write it, perhaps after truncating it; we could do other
           things, like modify it. */

        phdr = wtap_phdr(wth);

        if (snaplen != 0 && phdr->caplen > snaplen) {
          snap_phdr = *phdr;
          snap_phdr.caplen = snaplen;
          phdr = &snap_phdr;
        }

        if (choplen < 0) {
          snap_phdr = *phdr;
          if (((signed int) phdr->caplen + choplen) > 0)
            snap_phdr.caplen += choplen;
          else
            snap_phdr.caplen = 0;
          phdr = &snap_phdr;
        } else if (choplen > 0) {
          snap_phdr = *phdr;
          if (phdr->caplen > (unsigned int) choplen) {
            snap_phdr.caplen -= choplen;
            buf += choplen;
          } else
            snap_phdr.caplen = 0;
          phdr = &snap_phdr;
        }

        /*
         *  Do we adjust timestamps to insure strict chronologically order?
         */

        if (do_strict_time_adjustment) {
          if (previous_time.secs || previous_time.nsecs) {
            if (!strict_time_adj.is_negative) {
              nstime_t current;
              nstime_t delta;

              current.secs = phdr->ts.secs;
              current.nsecs = phdr->ts.nsecs;

              nstime_delta(&delta, &current, &previous_time);

              if (delta.secs < 0 || delta.nsecs < 0)
              {
                /*
                 * A negative delta indicates that the current packet
                 * has an absolute timestamp less than the previous packet
                 * that it is being compared to.  This is NOT a normal
                 * situation since trace files usually have packets in
                 * chronological order (oldest to newest).
                 */
                /* printf("++out of order, need to adjust this packet!\n"); */
                snap_phdr = *phdr;
                snap_phdr.ts.secs = previous_time.secs + strict_time_adj.tv.tv_sec;
                snap_phdr.ts.nsecs = previous_time.nsecs;
                if (snap_phdr.ts.nsecs + strict_time_adj.tv.tv_usec * 1000 > ONE_MILLION * 1000) {
                  /* carry */
                  snap_phdr.ts.secs++;
                  snap_phdr.ts.nsecs += (strict_time_adj.tv.tv_usec - ONE_MILLION) * 1000;
                } else {
                  snap_phdr.ts.nsecs += strict_time_adj.tv.tv_usec * 1000;
                }
                phdr = &snap_phdr;
              }
            } else {
              /*
               * A negative strict time adjustment is requested.
               * Unconditionally set each timestamp to previous
               * packet's timestamp plus delta.
               */
              snap_phdr = *phdr;
              snap_phdr.ts.secs = previous_time.secs + strict_time_adj.tv.tv_sec;
              snap_phdr.ts.nsecs = previous_time.nsecs;
              if (snap_phdr.ts.nsecs + strict_time_adj.tv.tv_usec * 1000 > ONE_MILLION * 1000) {
                /* carry */
                snap_phdr.ts.secs++;
                snap_phdr.ts.nsecs += (strict_time_adj.tv.tv_usec - ONE_MILLION) * 1000;
              } else {
                snap_phdr.ts.nsecs += strict_time_adj.tv.tv_usec * 1000;
              }
              phdr = &snap_phdr;
            }
          }
          previous_time.secs = phdr->ts.secs;
          previous_time.nsecs = phdr->ts.nsecs;
        }

        /* assume that if the frame's tv_sec is 0, then
         * the timestamp isn't supported */
        if (phdr->ts.secs > 0 && time_adj.tv.tv_sec != 0) {
          snap_phdr = *phdr;
          if (time_adj.is_negative)
            snap_phdr.ts.secs -= time_adj.tv.tv_sec;
          else
            snap_phdr.ts.secs += time_adj.tv.tv_sec;
          phdr = &snap_phdr;
        }

        /* assume that if the frame's tv_sec is 0, then
         * the timestamp isn't supported */
        if (phdr->ts.secs > 0 && time_adj.tv.tv_usec != 0) {
          snap_phdr = *phdr;
          if (time_adj.is_negative) { /* subtract */
            if (snap_phdr.ts.nsecs/1000 < time_adj.tv.tv_usec) { /* borrow */
              snap_phdr.ts.secs--;
              snap_phdr.ts.nsecs += ONE_MILLION * 1000;
            }
            snap_phdr.ts.nsecs -= time_adj.tv.tv_usec * 1000;
          } else {                  /* add */
            if (snap_phdr.ts.nsecs + time_adj.tv.tv_usec * 1000 > ONE_MILLION * 1000) {
              /* carry */
              snap_phdr.ts.secs++;
              snap_phdr.ts.nsecs += (time_adj.tv.tv_usec - ONE_MILLION) * 1000;
            } else {
              snap_phdr.ts.nsecs += time_adj.tv.tv_usec * 1000;
            }
          }
          phdr = &snap_phdr;
        }

        /* suppress duplicates by packet window */
        if (dup_detect) {
          if (is_duplicate(buf, phdr->caplen)) {
            if (verbose) {
              fprintf(stdout, "Skipped: %u, Len: %u, MD5 Hash: ", count, phdr->caplen);
              for (i = 0; i < 16; i++) {
                fprintf(stdout, "%02x", (unsigned char)fd_hash[cur_dup_entry].digest[i]);
              }
              fprintf(stdout, "\n");
            }
            duplicate_count++;
            count++;
            continue;
          } else {
            if (verbose) {
              fprintf(stdout, "Packet: %u, Len: %u, MD5 Hash: ", count, phdr->caplen);
              for (i = 0; i < 16; i++) {
                fprintf(stdout, "%02x", (unsigned char)fd_hash[cur_dup_entry].digest[i]);
              }
              fprintf(stdout, "\n");
            }
          }
        }

        /* suppress duplicates by time window */
        if (dup_detect_by_time) {
          nstime_t current;

          current.secs = phdr->ts.secs;
          current.nsecs = phdr->ts.nsecs;

          if (is_duplicate_rel_time(buf, phdr->caplen, &current)) {
            if (verbose) {
              fprintf(stdout, "Skipped: %u, Len: %u, MD5 Hash: ", count, phdr->caplen);
              for (i = 0; i < 16; i++) {
                fprintf(stdout, "%02x", (unsigned char)fd_hash[cur_dup_entry].digest[i]);
              }
              fprintf(stdout, "\n");
            }
            duplicate_count++;
            count++;
            continue;
          } else {
            if (verbose) {
              fprintf(stdout, "Packet: %u, Len: %u, MD5 Hash: ", count, phdr->caplen);
              for (i = 0; i < 16; i++) {
                fprintf(stdout, "%02x", (unsigned char)fd_hash[cur_dup_entry].digest[i]);
              }
              fprintf(stdout, "\n");
            }
          }
        }

        /* Random error mutation */
        if (err_prob > 0.0) {
          int real_data_start = 0;
          /* Protect non-protocol data */
          if (wtap_file_type(wth) == WTAP_FILE_CATAPULT_DCT2000) {
            real_data_start = find_dct2000_real_data(buf);
          }
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
                for (j = i; j < (int) phdr->caplen; j++) {
                  buf[j] = 0xAA;
                }
                i = phdr->caplen;
              }
            }
          }
        }

        if (!wtap_dump(pdh, phdr, wtap_pseudoheader(wth), buf, &err)) {
          switch (err) {

          case WTAP_ERR_UNSUPPORTED_ENCAP:
            /*
             * This is a problem with the particular frame we're writing;
             * note that, and give the frame number.
             */
            fprintf(stderr, "editcap: Frame %u of \"%s\" has a network type that can't be saved in a file with that format\n.",
                    read_count, argv[optind]);
            break;

          default:
            fprintf(stderr, "editcap: Error writing to %s: %s\n",
                    filename, wtap_strerror(err));
            break;
          }
          exit(2);
        }
        written_count++;
      }
      count++;
    }

    g_free(fprefix);
    g_free(fsuffix);

    if (err != 0) {
      /* Print a message noting that the read failed somewhere along the line. */
      fprintf(stderr,
              "editcap: An error occurred while reading \"%s\": %s.\n",
              argv[optind], wtap_strerror(err));
      switch (err) {

      case WTAP_ERR_UNSUPPORTED:
      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_BAD_FILE:
        fprintf(stderr, "(%s)\n", err_info);
        g_free(err_info);
        break;
      }
    }

    if (!pdh) {
      /* No valid packages found, open the outfile so we can write an empty header */
      g_free (filename);
      filename = g_strdup(argv[optind+1]);

      pdh = wtap_dump_open(filename, out_file_type, out_frame_type,
        snaplen ? MIN(snaplen, wtap_snapshot_length(wth)): wtap_snapshot_length(wth),
        FALSE /* compressed */, &err);
      if (pdh == NULL) {
        fprintf(stderr, "editcap: Can't open or create %s: %s\n", filename,
        wtap_strerror(err));
        exit(2);
      }
    }

    if (!wtap_dump_close(pdh, &err)) {

      fprintf(stderr, "editcap: Error writing to %s: %s\n", filename,
          wtap_strerror(err));
      exit(2);

    }
    g_free(filename);
  }

  if (dup_detect) {
    fprintf(stdout, "%u packet%s seen, %u packet%s skipped with duplicate window of %u packets.\n",
                count - 1, plurality(count - 1, "", "s"),
                duplicate_count, plurality(duplicate_count, "", "s"), dup_window);
  } else if (dup_detect_by_time) {
    fprintf(stdout, "%u packet%s seen, %u packet%s skipped with duplicate time window equal to or less than %ld.%09ld seconds.\n",
                count - 1, plurality(count - 1, "", "s"),
                duplicate_count, plurality(duplicate_count, "", "s"),
                (long)relative_time_window.secs, (long int)relative_time_window.nsecs);
  }

  return 0;
}

/* Skip meta-information read from file to return offset of real
   protocol data */
static int find_dct2000_real_data(guint8 *buf)
{
  int n=0;

  for (n=0; buf[n] != '\0'; n++);   /* Context name */
  n++;
  n++;                              /* Context port number */
  for (; buf[n] != '\0'; n++);      /* Timestamp */
  n++;
  for (; buf[n] != '\0'; n++);      /* Protocol name */
  n++;
  for (; buf[n] != '\0'; n++);      /* Variant number (as string) */
  n++;
  for (; buf[n] != '\0'; n++);      /* Outhdr (as string) */
  n++;
  n += 2;                           /* Direction & encap */

  return n;
}
