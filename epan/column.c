/* column.c
 * Routines for handling column preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>
#include <epan/column.h>
#include <epan/column-info.h>
#include <epan/packet.h>
#include <wsutil/ws_assert.h>

static int proto_cols;
static hf_register_info *hf_cols;
static unsigned int hf_cols_cleanup;

/* Given a format number (as defined in column-utils.h), returns its equivalent
   string */
const char *
col_format_to_string(const int fmt) {
  static const char *const slist[NUM_COL_FMTS] = {
    "%Yt",                                      /* 0) COL_ABS_YMD_TIME */
    "%YDOYt",                                   /* 1) COL_ABS_YDOY_TIME */
    "%At",                                      /* 2) COL_ABS_TIME */
    "%B",                                       /* 3) COL_CUMULATIVE_BYTES */
    "%Cus",                                     /* 4) COL_CUSTOM */
    "%Tt",                                      /* 5) COL_DELTA_TIME */
    "%Gt",                                      /* 6) COL_DELTA_TIME_DIS */
    "%rd",                                      /* 7) COL_RES_DST */
    "%ud",                                      /* 8) COL_UNRES_DST */
    "%rD",                                      /* 9) COL_RES_DST_PORT */
    "%uD",                                      /* 10) COL_UNRES_DST_PORT */
    "%d",                                       /* 11) COL_DEF_DST */
    "%D",                                       /* 12) COL_DEF_DST_PORT */
    "%a",                                       /* 13) COL_EXPERT */
    "%I",                                       /* 14) COL_IF_DIR */
    "%F",                                       /* 15) COL_FREQ_CHAN */
    "%hd",                                      /* 16) COL_DEF_DL_DST */
    "%hs",                                      /* 17) COL_DEF_DL_SRC */
    "%rhd",                                     /* 18) COL_RES_DL_DST */
    "%uhd",                                     /* 19) COL_UNRES_DL_DST */
    "%rhs",                                     /* 20) COL_RES_DL_SRC*/
    "%uhs",                                     /* 21) COL_UNRES_DL_SRC */
    "%e",                                       /* 22) COL_RSSI */
    "%x",                                       /* 23) COL_TX_RATE */
    "%f",                                       /* 24) COL_DSCP_VALUE */
    "%i",                                       /* 25) COL_INFO */
    "%rnd",                                     /* 26) COL_RES_NET_DST */
    "%und",                                     /* 27) COL_UNRES_NET_DST */
    "%rns",                                     /* 28) COL_RES_NET_SRC */
    "%uns",                                     /* 29) COL_UNRES_NET_SRC */
    "%nd",                                      /* 30) COL_DEF_NET_DST */
    "%ns",                                      /* 31) COL_DEF_NET_SRC */
    "%m",                                       /* 32) COL_NUMBER */
    "%L",                                       /* 33) COL_PACKET_LENGTH */
    "%p",                                       /* 34) COL_PROTOCOL */
    "%Rt",                                      /* 35) COL_REL_TIME */
    "%s",                                       /* 36) COL_DEF_SRC */
    "%S",                                       /* 37) COL_DEF_SRC_PORT */
    "%rs",                                      /* 38) COL_RES_SRC */
    "%us",                                      /* 39) COL_UNRES_SRC */
    "%rS",                                      /* 40) COL_RES_SRC_PORT */
    "%uS",                                      /* 41) COL_UNRES_SRC_PORT */
    "%Yut",                                     /* 42) COL_UTC_YMD_TIME */
    "%YDOYut",                                  /* 43) COL_UTC_YDOY_TIME */
    "%Aut",                                     /* 44) COL_UTC_TIME */
    "%t"                                        /* 45) COL_CLS_TIME */
  };

 /* Note the formats in migrated_columns[] below have been used in deprecated
  * columns, and avoid reusing them.
  */
  if (fmt < 0 || fmt >= NUM_COL_FMTS)
    return NULL;

  return(slist[fmt]);
}

/* Given a format number (as defined in column-utils.h), returns its
  description */
const char *
col_format_desc(const int fmt_num) {

  /* This should be sorted alphabetically, e.g. `sort -t, -k2` */
  /*
   * This is currently used in the preferences UI, so out-of-numeric-order
   * performance shouldn't be an issue.
   */
  static const value_string dlist_vals[] = {

    { COL_ABS_YMD_TIME, "Absolute date, as YYYY-MM-DD, and time" },
    { COL_ABS_YDOY_TIME, "Absolute date, as YYYY/DOY, and time" },
    { COL_ABS_TIME, "Absolute time" },
    { COL_CUMULATIVE_BYTES, "Cumulative Bytes" },
    { COL_CUSTOM, "Custom" },
    { COL_DELTA_TIME_DIS, "Delta time displayed" },
    { COL_DELTA_TIME, "Delta time" },
    { COL_RES_DST, "Dest addr (resolved)" },
    { COL_UNRES_DST, "Dest addr (unresolved)" },
    { COL_RES_DST_PORT, "Dest port (resolved)" },
    { COL_UNRES_DST_PORT, "Dest port (unresolved)" },
    { COL_DEF_DST, "Destination address" },
    { COL_DEF_DST_PORT, "Destination port" },
    { COL_EXPERT, "Expert Info Severity" },
    { COL_IF_DIR, "FW-1 monitor if/direction" },
    { COL_FREQ_CHAN, "Frequency/Channel" },
    { COL_DEF_DL_DST, "Hardware dest addr" },
    { COL_DEF_DL_SRC, "Hardware src addr" },
    { COL_RES_DL_DST, "Hw dest addr (resolved)" },
    { COL_UNRES_DL_DST, "Hw dest addr (unresolved)" },
    { COL_RES_DL_SRC, "Hw src addr (resolved)" },
    { COL_UNRES_DL_SRC, "Hw src addr (unresolved)" },
    { COL_RSSI, "IEEE 802.11 RSSI" },
    { COL_TX_RATE, "IEEE 802.11 TX rate" },
    { COL_DSCP_VALUE, "IP DSCP Value" },
    { COL_INFO, "Information" },
    { COL_RES_NET_DST, "Net dest addr (resolved)" },
    { COL_UNRES_NET_DST, "Net dest addr (unresolved)" },
    { COL_RES_NET_SRC, "Net src addr (resolved)" },
    { COL_UNRES_NET_SRC, "Net src addr (unresolved)" },
    { COL_DEF_NET_DST, "Network dest addr" },
    { COL_DEF_NET_SRC, "Network src addr" },
    { COL_NUMBER, "Number" },
    { COL_PACKET_LENGTH, "Packet length (bytes)" },
    { COL_PROTOCOL, "Protocol" },
    { COL_REL_TIME, "Relative time" },
    { COL_DEF_SRC, "Source address" },
    { COL_DEF_SRC_PORT, "Source port" },
    { COL_RES_SRC, "Src addr (resolved)" },
    { COL_UNRES_SRC, "Src addr (unresolved)" },
    { COL_RES_SRC_PORT, "Src port (resolved)" },
    { COL_UNRES_SRC_PORT, "Src port (unresolved)" },
    { COL_CLS_TIME, "Time (format as specified)" },
    { COL_UTC_YMD_TIME, "UTC date, as YYYY-MM-DD, and time" },
    { COL_UTC_YDOY_TIME, "UTC date, as YYYY/DOY, and time" },
    { COL_UTC_TIME, "UTC time" },

    { 0, NULL }
  };

  const char *val_str = try_val_to_str(fmt_num, dlist_vals);
  ws_assert(val_str != NULL);
  return val_str;
}

/* Given a format number (as defined in column-utils.h), returns its
  filter abbreviation */
const char *
col_format_abbrev(const int fmt_num) {

  static const value_string alist_vals[] = {

    { COL_ABS_YMD_TIME, COLUMN_FIELD_FILTER"abs_ymd_time" },
    { COL_ABS_YDOY_TIME, COLUMN_FIELD_FILTER"abs_ydoy_time" },
    { COL_ABS_TIME, COLUMN_FIELD_FILTER"abs_time" },
    { COL_CUMULATIVE_BYTES, COLUMN_FIELD_FILTER"cumulative_bytes" },
    { COL_CUSTOM, COLUMN_FIELD_FILTER"custom" },
    { COL_DELTA_TIME_DIS, COLUMN_FIELD_FILTER"delta_time_dis" },
    { COL_DELTA_TIME, COLUMN_FIELD_FILTER"delta_time" },
    { COL_RES_DST, COLUMN_FIELD_FILTER"res_dst" },
    { COL_UNRES_DST, COLUMN_FIELD_FILTER"unres_dst" },
    { COL_RES_DST_PORT, COLUMN_FIELD_FILTER"res_dst_port" },
    { COL_UNRES_DST_PORT, COLUMN_FIELD_FILTER"unres_dst_port" },
    { COL_DEF_DST, COLUMN_FIELD_FILTER"def_dst" },
    { COL_DEF_DST_PORT, COLUMN_FIELD_FILTER"def_dst_port" },
    { COL_EXPERT, COLUMN_FIELD_FILTER"expert" },
    { COL_IF_DIR, COLUMN_FIELD_FILTER"if_dir" },
    { COL_FREQ_CHAN, COLUMN_FIELD_FILTER"freq_chan" },
    { COL_DEF_DL_DST, COLUMN_FIELD_FILTER"def_dl_dst" },
    { COL_DEF_DL_SRC, COLUMN_FIELD_FILTER"def_dl_src" },
    { COL_RES_DL_DST, COLUMN_FIELD_FILTER"res_dl_dst" },
    { COL_UNRES_DL_DST, COLUMN_FIELD_FILTER"unres_dl_dst" },
    { COL_RES_DL_SRC, COLUMN_FIELD_FILTER"res_dl_src" },
    { COL_UNRES_DL_SRC, COLUMN_FIELD_FILTER"unres_dl_src" },
    { COL_RSSI, COLUMN_FIELD_FILTER"rssi" },
    { COL_TX_RATE, COLUMN_FIELD_FILTER"tx_rate" },
    { COL_DSCP_VALUE, COLUMN_FIELD_FILTER"dscp" },
    { COL_INFO, COLUMN_FIELD_FILTER"info" },
    { COL_RES_NET_DST, COLUMN_FIELD_FILTER"res_net_dst" },
    { COL_UNRES_NET_DST, COLUMN_FIELD_FILTER"unres_net_dst" },
    { COL_RES_NET_SRC, COLUMN_FIELD_FILTER"res_net_src" },
    { COL_UNRES_NET_SRC, COLUMN_FIELD_FILTER"unres_net_src" },
    { COL_DEF_NET_DST, COLUMN_FIELD_FILTER"def_net_dst" },
    { COL_DEF_NET_SRC, COLUMN_FIELD_FILTER"def_net_src" },
    { COL_NUMBER, COLUMN_FIELD_FILTER"number" },
    { COL_PACKET_LENGTH, COLUMN_FIELD_FILTER"packet_length" },
    { COL_PROTOCOL, COLUMN_FIELD_FILTER"protocol" },
    { COL_REL_TIME, COLUMN_FIELD_FILTER"rel_time" },
    { COL_DEF_SRC, COLUMN_FIELD_FILTER"def_src" },
    { COL_DEF_SRC_PORT, COLUMN_FIELD_FILTER"def_src_port" },
    { COL_RES_SRC, COLUMN_FIELD_FILTER"res_src" },
    { COL_UNRES_SRC, COLUMN_FIELD_FILTER"unres_src" },
    { COL_RES_SRC_PORT, COLUMN_FIELD_FILTER"res_src_port" },
    { COL_UNRES_SRC_PORT, COLUMN_FIELD_FILTER"unres_src_port" },
    { COL_CLS_TIME, COLUMN_FIELD_FILTER"cls_time" },
    { COL_UTC_YMD_TIME, COLUMN_FIELD_FILTER"utc_ymc_time" },
    { COL_UTC_YDOY_TIME, COLUMN_FIELD_FILTER"utc_ydoy_time" },
    { COL_UTC_TIME, COLUMN_FIELD_FILTER"utc_time" },

    { 0, NULL }
  };

  const char *val_str = try_val_to_str(fmt_num, alist_vals);
  ws_assert(val_str != NULL);
  return val_str;
}
/* Array of columns that have been migrated to custom columns */
struct deprecated_columns {
    const char *col_fmt;
    const char *col_expr;
};

static struct deprecated_columns migrated_columns[] = {
    { /* COL_COS_VALUE */ "%U", "vlan.priority" },
    { /* COL_CIRCUIT_ID */ "%c", "iax2.call" },
    { /* COL_BSSGP_TLLI */ "%l", "bssgp.tlli" },
    { /* COL_HPUX_SUBSYS */ "%H", "nettl.subsys" },
    { /* COL_HPUX_DEVID */ "%P", "nettl.devid" },
    { /* COL_FR_DLCI */ "%C", "fr.dlci" },
    { /* COL_REL_CONV_TIME */ "%rct", "tcp.time_relative" },
    { /* COL_DELTA_CONV_TIME */ "%dct", "tcp.time_delta" },
    { /* COL_OXID */ "%XO", "fc.ox_id" },
    { /* COL_RXID */ "%XR", "fc.rx_id" },
    { /* COL_SRCIDX */ "%Xd", "mdshdr.srcidx" },
    { /* COL_DSTIDX */ "%Xs", "mdshdr.dstidx" },
    { /* COL_DCE_CTX */ "%z", "dcerpc.cn_ctx_id" },
    /* The columns above here have been migrated since August 2009 and all
     * completely removed since January 2016. At some point we could remove
     * these; how many people have a preference file that they haven't opened
     * and saved since then?
     */
    { /* COL_8021Q_VLAN_ID */ "%q", "vlan.id||nstrace.vlan" },
    { /* COL_VSAN */ "%V", "mdshdr.vsan||brdwlk.vsan||fc.vft.vf_id" },
    { /* COL_DCE_CALL */ "%y", "dcerpc.cn_call_id||dcerpc.dg_seqnum" },
    { /* COL_TEI */ "%E", "lapd.tei" },
};

const char*
try_convert_to_column_field(const char *field)
{
    static const value_string migrated_fields[] = {
        { COL_NUMBER, COLUMN_FIELD_FILTER"No." },
        { COL_CLS_TIME, COLUMN_FIELD_FILTER"Time" },
        { COL_DEF_SRC, COLUMN_FIELD_FILTER"Source" },
        { COL_DEF_DST, COLUMN_FIELD_FILTER"Destination" },
        { COL_PROTOCOL, COLUMN_FIELD_FILTER"Protocol" },
        { COL_PACKET_LENGTH, COLUMN_FIELD_FILTER"Length" },
        { COL_INFO, COLUMN_FIELD_FILTER"Info" },
        { 0, NULL },
    };

    int idx;

    idx = str_to_val_idx(field, migrated_fields);

    if (idx >= 0) {
        return col_format_abbrev(migrated_fields[idx].value);
    }

    return NULL;
}

/*
 * Parse a column format, filling in the relevant fields of a fmt_data.
 */
bool
parse_column_format(fmt_data *cfmt, const char *fmt)
{
    const char *cust_format = col_format_to_string(COL_CUSTOM);
    size_t cust_format_len = strlen(cust_format);
    GPtrArray *cust_format_info;
    char *p;
    int col_fmt;
    char *col_custom_fields = NULL;
    long col_custom_occurrence = 0;
    bool col_resolved = true;

    /*
     * Is this a custom column?
     */
    if ((strlen(fmt) > cust_format_len) && (fmt[cust_format_len] == ':') &&
        strncmp(fmt, cust_format, cust_format_len) == 0) {
        /* Yes. */
        col_fmt = COL_CUSTOM;
        cust_format_info = g_ptr_array_new();
        char *fmt_copy = g_strdup(&fmt[cust_format_len + 1]);
        p = strrchr(fmt_copy, ':');
        /* Pull off the two right most tokens for occurrences and
         * "show resolved". We do it this way because the filter might
         * have a ':' in it, e.g. for slices.
         */
        for (int token = 2; token > 0 && p != NULL; token--) {
            g_ptr_array_insert(cust_format_info, 0, &p[1]);
            *p = '\0';
            p = strrchr(fmt_copy, ':');
        }
        g_ptr_array_insert(cust_format_info, 0, fmt_copy);
        /* XXX - The last two tokens have been written since at least 1.6.x
         * (commit f5ab6c1930d588f9f0be453a7be279150922b347). We could
         * just fail at this point if cust_format_info->len < 3
         */
        if (cust_format_info->len > 0) {
            col_custom_fields = g_strdup(cust_format_info->pdata[0]);
        }
        if (cust_format_info->len > 1) {
            col_custom_occurrence = strtol(cust_format_info->pdata[1], &p, 10);
            if (p == cust_format_info->pdata[1] || *p != '\0') {
                /* Not a valid number. */
                g_free(fmt_copy);
                g_ptr_array_unref(cust_format_info);
                return false;
            }
        }
        if (cust_format_info->len > 2) {
            p = cust_format_info->pdata[2];
            col_resolved = (p[0] == 'U') ? false : true;
        }
        g_free(fmt_copy);
        g_ptr_array_unref(cust_format_info);
    } else {
        col_fmt = get_column_format_from_str(fmt);
        if (col_fmt == -1)
            return false;
    }

    cfmt->fmt = col_fmt;
    cfmt->custom_fields = col_custom_fields;
    cfmt->custom_occurrence = (int)col_custom_occurrence;
    cfmt->resolved = col_resolved;
    return true;
}

void
try_convert_to_custom_column(char **fmt)
{
    unsigned haystack_idx;

    for (haystack_idx = 0;
         haystack_idx < G_N_ELEMENTS(migrated_columns);
         ++haystack_idx) {

        if (strcmp(migrated_columns[haystack_idx].col_fmt, *fmt) == 0) {
            char *cust_col = ws_strdup_printf("%%Cus:%s:0",
                                migrated_columns[haystack_idx].col_expr);

            g_free(*fmt);
            *fmt = cust_col;
        }
    }
}

void
column_dump_column_formats(void)
{
  int fmt;

  for (fmt = 0; fmt < NUM_COL_FMTS; fmt++) {
    printf("%s\t%s\n", col_format_to_string(fmt), col_format_desc(fmt));
  }

  printf("\nFor example, to print Wireshark's default columns with tshark:\n\n"
#ifdef _WIN32
  "tshark.exe -o \"gui.column.format:"
    "\\\"No.\\\",\\\"%%m\\\","
    "\\\"Time\\\",\\\"%%t\\\","
    "\\\"Source\\\",\\\"%%s\\\","
    "\\\"Destination\\\",\\\"%%d\\\","
    "\\\"Protocol\\\",\\\"%%p\\\","
    "\\\"Length\\\",\\\"%%L\\\","
    "\\\"Info\\\",\\\"%%i\\\"\"\n");
#else
  "tshark -o 'gui.column.format:"
    "\"No.\",\"%%m\","
    "\"Time\",\"%%t\","
    "\"Source\",\"%%s\","
    "\"Destination\",\"%%d\","
    "\"Protocol\",\"%%p\","
    "\"Length\",\"%%L\","
    "\"Info\",\"%%i\"'\n");
#endif
}

/* Marks each array element true if it can be substituted for the given
   column format */
void
get_column_format_matches(bool *fmt_list, const int format) {

  /* Get the obvious: the format itself */
  if ((format >= 0) && (format < NUM_COL_FMTS))
    fmt_list[format] = true;

  /* Get any formats lower down on the chain */
  switch (format) {
    case COL_DEF_SRC:
      fmt_list[COL_RES_DL_SRC] = true;
      fmt_list[COL_RES_NET_SRC] = true;
      break;
    case COL_RES_SRC:
      fmt_list[COL_RES_DL_SRC] = true;
      fmt_list[COL_RES_NET_SRC] = true;
      break;
    case COL_UNRES_SRC:
      fmt_list[COL_UNRES_DL_SRC] = true;
      fmt_list[COL_UNRES_NET_SRC] = true;
      break;
    case COL_DEF_DST:
      fmt_list[COL_RES_DL_DST] = true;
      fmt_list[COL_RES_NET_DST] = true;
      break;
    case COL_RES_DST:
      fmt_list[COL_RES_DL_DST] = true;
      fmt_list[COL_RES_NET_DST] = true;
      break;
    case COL_UNRES_DST:
      fmt_list[COL_UNRES_DL_DST] = true;
      fmt_list[COL_UNRES_NET_DST] = true;
      break;
    case COL_DEF_DL_SRC:
      fmt_list[COL_RES_DL_SRC] = true;
      break;
    case COL_DEF_DL_DST:
      fmt_list[COL_RES_DL_DST] = true;
      break;
    case COL_DEF_NET_SRC:
      fmt_list[COL_RES_NET_SRC] = true;
      break;
    case COL_DEF_NET_DST:
      fmt_list[COL_RES_NET_DST] = true;
      break;
    case COL_DEF_SRC_PORT:
      fmt_list[COL_RES_SRC_PORT] = true;
      break;
    case COL_DEF_DST_PORT:
      fmt_list[COL_RES_DST_PORT] = true;
      break;
    default:
      break;
  }
}

/*
 * These tables are indexed by the number of digits of precision for
 * time stamps; all TS_PREC_FIXED_ types have values equal to the
 * number of digits of precision, and NUM_WS_TSPREC_VALS is the
 * total number of such values as there's a one-to-one correspondence
 * between WS_TSPREC_ values and TS_PREC_FIXED_ values.
 */

/*
 * Strings for YYYY-MM-DD HH:MM:SS.SSSS dates and times.
 * (Yes, we know, this has a Y10K problem.)
 */
static const char *ts_ymd[NUM_WS_TSPREC_VALS] = {
    "0000-00-00 00:00:00",
    "0000-00-00 00:00:00.0",
    "0000-00-00 00:00:00.00",
    "0000-00-00 00:00:00.000",
    "0000-00-00 00:00:00.0000",
    "0000-00-00 00:00:00.00000",
    "0000-00-00 00:00:00.000000",
    "0000-00-00 00:00:00.0000000",
    "0000-00-00 00:00:00.00000000",
    "0000-00-00 00:00:00.000000000",
};

/*
 * Strings for YYYY/DOY HH:MM:SS.SSSS dates and times.
 * (Yes, we know, this also has a Y10K problem.)
 */
static const char *ts_ydoy[NUM_WS_TSPREC_VALS] = {
    "0000/000 00:00:00",
    "0000/000 00:00:00.0",
    "0000/000 00:00:00.00",
    "0000/000 00:00:00.000",
    "0000/000 00:00:00.0000",
    "0000/000 00:00:00.00000",
    "0000/000 00:00:00.000000",
    "0000/000 00:00:00.0000000",
    "0000/000 00:00:00.00000000",
    "0000/000 00:00:00.000000000",
};

/*
 * Strings for HH:MM:SS.SSSS absolute times without dates.
 */
static const char *ts_abstime[NUM_WS_TSPREC_VALS] = {
    "00:00:00",
    "00:00:00.0",
    "00:00:00.00",
    "00:00:00.000",
    "00:00:00.0000",
    "00:00:00.00000",
    "00:00:00.000000",
    "00:00:00.0000000",
    "00:00:00.00000000",
    "00:00:00.000000000",
};

/*
 * Strings for SSSS.S relative and delta times.
 * (Yes, this has s 10,000-seconds problem.)
 */
static const char *ts_rel_delta_time[NUM_WS_TSPREC_VALS] = {
    "0000",
    "0000.0",
    "0000.00",
    "0000.000",
    "0000.0000",
    "0000.00000",
    "0000.000000",
    "0000.0000000",
    "0000.00000000",
    "0000.000000000",
};

/*
 * Strings for UN*X/POSIX Epoch times.
 */
static const char *ts_epoch_time[NUM_WS_TSPREC_VALS] = {
    "0000000000000000000",
    "0000000000000000000.0",
    "0000000000000000000.00",
    "0000000000000000000.000",
    "0000000000000000000.0000",
    "0000000000000000000.00000",
    "0000000000000000000.000000",
    "0000000000000000000.0000000",
    "0000000000000000000.00000000",
    "0000000000000000000.000000000",
};

/* Returns a string representing the longest possible value for
   a timestamp column type. */
static const char *
get_timestamp_column_longest_string(const int type, const int precision)
{

    switch(type) {
    case(TS_ABSOLUTE_WITH_YMD):
    case(TS_UTC_WITH_YMD):
        if(precision == TS_PREC_AUTO) {
            /*
             * Return the string for the maximum precision, so that
             * our caller leaves room for that string.
             */
            return ts_ymd[WS_TSPREC_MAX];
        } else if(precision >= 0 && precision < NUM_WS_TSPREC_VALS)
            return ts_ymd[precision];
        else
            ws_assert_not_reached();
        break;
    case(TS_ABSOLUTE_WITH_YDOY):
    case(TS_UTC_WITH_YDOY):
        if(precision == TS_PREC_AUTO) {
            /*
             * Return the string for the maximum precision, so that
             * our caller leaves room for that string.
             */
            return ts_ydoy[WS_TSPREC_MAX];
        } else if(precision >= 0 && precision < NUM_WS_TSPREC_VALS)
            return ts_ydoy[precision];
        else
            ws_assert_not_reached();
        break;
    case(TS_ABSOLUTE):
    case(TS_UTC):
        if(precision == TS_PREC_AUTO) {
            /*
             * Return the string for the maximum precision, so that
             * our caller leaves room for that string.
             */
            return ts_abstime[WS_TSPREC_MAX];
        } else if(precision >= 0 && precision < NUM_WS_TSPREC_VALS)
            return ts_abstime[precision];
        else
            ws_assert_not_reached();
        break;
    case(TS_RELATIVE):  /* fallthrough */
    case(TS_DELTA):
    case(TS_DELTA_DIS):
        if(precision == TS_PREC_AUTO) {
            /*
             * Return the string for the maximum precision, so that
             * our caller leaves room for that string.
             */
            return ts_rel_delta_time[WS_TSPREC_MAX];
        } else if(precision >= 0 && precision < NUM_WS_TSPREC_VALS)
            return ts_rel_delta_time[precision];
        else
            ws_assert_not_reached();
        break;
    case(TS_EPOCH):
        /* This is enough to represent 2^63 (signed 64-bit integer) + fractions */
        if(precision == TS_PREC_AUTO) {
            /*
             * Return the string for the maximum precision, so that
             * our caller leaves room for that string.
             */
            return ts_epoch_time[WS_TSPREC_MAX];
        } else if(precision >= 0 && precision < NUM_WS_TSPREC_VALS)
            return ts_epoch_time[precision];
        else
            ws_assert_not_reached();
        break;
    case(TS_NOT_SET):
        /* This should not happen. */
        return "0000.000000";
    default:
        ws_assert_not_reached();
    }

    /* never reached, satisfy compiler */
    return "";
}

/* Returns a string representing the longest possible value for a
   particular column type.  See also get_column_width_string() above.

   Except for the COL...SRC and COL...DST columns, these are used
   only when a capture is being displayed while it's taking place;
   they are arguably somewhat fragile, as changes to the code that
   generates them don't cause these widths to change, but that's
   probably not too big a problem, given that the sizes are
   recomputed based on the actual data in the columns when the capture
   is done, and given that the width for COL...SRC and COL...DST columns
   is somewhat arbitrary in any case.  We should probably clean
   that up eventually, though. */
const char *
get_column_longest_string(const int format)
{
  switch (format) {
    case COL_NUMBER:
      return "0000000";
    case COL_CLS_TIME:
      return get_timestamp_column_longest_string(timestamp_get_type(), timestamp_get_precision());
    case COL_ABS_YMD_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE_WITH_YMD, timestamp_get_precision());
    case COL_ABS_YDOY_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE_WITH_YDOY, timestamp_get_precision());
    case COL_UTC_YMD_TIME:
      return get_timestamp_column_longest_string(TS_UTC_WITH_YMD, timestamp_get_precision());
    case COL_UTC_YDOY_TIME:
      return get_timestamp_column_longest_string(TS_UTC_WITH_YDOY, timestamp_get_precision());
    case COL_ABS_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE, timestamp_get_precision());
    case COL_UTC_TIME:
      return get_timestamp_column_longest_string(TS_UTC, timestamp_get_precision());
    case COL_REL_TIME:
      return get_timestamp_column_longest_string(TS_RELATIVE, timestamp_get_precision());
    case COL_DELTA_TIME:
      return get_timestamp_column_longest_string(TS_DELTA, timestamp_get_precision());
    case COL_DELTA_TIME_DIS:
      return get_timestamp_column_longest_string(TS_DELTA_DIS, timestamp_get_precision());
    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      return "00000000.000000000000"; /* IPX-style */
    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:
    case COL_UNRES_SRC_PORT:
    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:
    case COL_UNRES_DST_PORT:
      return "000000";
    case COL_PROTOCOL:
      return "Protocol";    /* not the longest, but the longest is too long */
    case COL_PACKET_LENGTH:
      return "00000";
    case COL_CUMULATIVE_BYTES:
      return "00000000";
    case COL_IF_DIR:
      return "i 00000000 I";
    case COL_TX_RATE:
      return "108.0";
    case COL_RSSI:
      return "100";
    case COL_DSCP_VALUE:
      return "AAA BBB";    /* not the longest, but the longest is too long */
    case COL_EXPERT:
      return "ERROR";
    case COL_FREQ_CHAN:
      return "9999 MHz [A 999]";
    case COL_CUSTOM:
      return "0000000000";  /* not the longest, but the longest is too long */
    default: /* COL_INFO */
      return "Source port: kerberos-master  Destination port: kerberos-master";
  }
}

/* Returns the longer string of the column title or the hard-coded width of
 * its contents for building the packet list layout. */
const char *
get_column_width_string(const int format, const int col)
{
    if(strlen(get_column_longest_string(format)) >
       strlen(get_column_title(col)))
        return get_column_longest_string(format);
    else
        return get_column_title(col);
}

/* Returns the longest possible width, in characters, for a particular
   column type. */
int
get_column_char_width(const int format)
{
  return (int)strlen(get_column_longest_string(format));
}

int
get_column_format(const int col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return -1;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->fmt);
}

void
set_column_format(const int col, const int fmt)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->fmt = fmt;
}

int
get_column_format_from_str(const char *str)
{
  int i;

  for (i = 0; i < NUM_COL_FMTS; i++) {
    if (strcmp(str, col_format_to_string(i)) == 0)
      return i;
  }
  return -1;    /* illegal */
}

char *
get_column_title(const int col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return NULL;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->title);
}

void
set_column_title(const int col, const char *title)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  g_free (cfmt->title);
  cfmt->title = g_strdup (title);
}

bool
get_column_visible(const int col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return true;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->visible);
}

void
set_column_visible(const int col, bool visible)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->visible = visible;
}

bool
get_column_resolved(const int col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return true;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->resolved);
}

void
set_column_resolved(const int col, bool resolved)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->resolved = resolved;
}

const char *
get_column_custom_fields(const int col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return NULL;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->custom_fields);
}

void
set_column_custom_fields(const int col, const char *custom_fields)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  g_free (cfmt->custom_fields);
  cfmt->custom_fields = g_strdup (custom_fields);
}

int
get_column_custom_occurrence(const int col)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return 0;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->custom_occurrence);
}

void
set_column_custom_occurrence(const int col, const int custom_occurrence)
{
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  if (!clp)  /* Invalid column requested */
    return;

  cfmt = (fmt_data *) clp->data;

  cfmt->custom_occurrence = custom_occurrence;
}

static char *
get_custom_field_tooltip (char *custom_field, int occurrence)
{
    header_field_info *hfi = proto_registrar_get_byname(custom_field);
    if (hfi == NULL) {
        /* Not a valid field */
        dfilter_t *dfilter;
        if (dfilter_compile(custom_field, &dfilter, NULL)) {
            dfilter_free(dfilter);
            return ws_strdup_printf("Expression: %s", custom_field);
        }
        return ws_strdup_printf("Unknown Field: %s", custom_field);
    }

    if (hfi->parent == -1) {
        /* Protocol */
        return ws_strdup_printf("%s (%s)", hfi->name, hfi->abbrev);
    }

    if (occurrence == 0) {
        /* All occurrences */
        return ws_strdup_printf("%s\n%s (%s)", proto_get_protocol_name(hfi->parent), hfi->name, hfi->abbrev);
    }

    /* One given occurrence */
    return ws_strdup_printf("%s\n%s (%s#%d)", proto_get_protocol_name(hfi->parent), hfi->name, hfi->abbrev, occurrence);
}

char *
get_column_tooltip(const int col)
{
    GList    *clp = g_list_nth(prefs.col_list, col);
    fmt_data *cfmt;
    char    **fields;
    bool      first = true;
    GString  *column_tooltip;
    unsigned  i;

    if (!clp)  /* Invalid column requested */
        return NULL;

    cfmt = (fmt_data *) clp->data;

    if (cfmt->fmt != COL_CUSTOM) {
        /* Use format description */
        return g_strdup(col_format_desc(cfmt->fmt));
    }

    fields = g_regex_split_simple(COL_CUSTOM_PRIME_REGEX, cfmt->custom_fields,
                                  (GRegexCompileFlags) (G_REGEX_RAW),
                                  0);
    column_tooltip = g_string_new("");

    for (i = 0; i < g_strv_length(fields); i++) {
        if (fields[i] && *fields[i]) {
            char *field_tooltip = get_custom_field_tooltip(fields[i], cfmt->custom_occurrence);
            if (!first) {
                g_string_append(column_tooltip, "\n\nOR\n\n");
            }
            g_string_append(column_tooltip, field_tooltip);
            g_free (field_tooltip);
            first = false;
        }
    }

    g_strfreev(fields);

    return g_string_free (column_tooltip, FALSE);
}

const char*
get_column_text(column_info *cinfo, const int col)
{
  ws_assert(cinfo);
  ws_assert(col < cinfo->num_cols);

  if (!get_column_resolved(col) && cinfo->col_expr.col_expr_val[col]) {
      /* Use the unresolved value in col_expr_val */
      return cinfo->col_expr.col_expr_val[col];
  }

  return cinfo->columns[col].col_data;
}

void
col_finalize(column_info *cinfo)
{
  int i;
  col_item_t* col_item;
  dfilter_t *dfilter;

  for (i = 0; i < cinfo->num_cols; i++) {
    col_item = &cinfo->columns[i];

    if (col_item->col_fmt == COL_CUSTOM) {
      if(!dfilter_compile(col_item->col_custom_fields, &col_item->col_custom_dfilter, NULL)) {
        /* XXX: Should we issue a warning? */
        g_free(col_item->col_custom_fields);
        col_item->col_custom_fields = NULL;
        col_item->col_custom_occurrence = 0;
        col_item->col_custom_dfilter = NULL;
      }
      if (col_item->col_custom_fields) {
        char **fields = g_regex_split(cinfo->prime_regex, col_item->col_custom_fields,
                                       0);
        unsigned i_field;

        for (i_field = 0; i_field < g_strv_length(fields); i_field++) {
          if (fields[i_field] && *fields[i_field]) {
            if (dfilter_compile_full(fields[i_field], &dfilter, NULL, DF_EXPAND_MACROS|DF_OPTIMIZE|DF_RETURN_VALUES, __func__)) {
              col_custom_t *custom_info = g_new0(col_custom_t, 1);
              custom_info->dftext = g_strdup(fields[i_field]);
              custom_info->dfilter = dfilter;
              header_field_info *hfinfo = proto_registrar_get_byname(fields[i_field]);
              if (hfinfo) {
                custom_info->field_id = hfinfo->id;
              }
              col_item->col_custom_fields_ids = g_slist_append(col_item->col_custom_fields_ids, custom_info);
            }
          }
        }
        g_strfreev(fields);
      }
    } else {
      col_item->col_custom_fields = NULL;
      col_item->col_custom_occurrence = 0;
      col_item->col_custom_dfilter = NULL;
    }

    col_item->fmt_matx = g_new0(bool, NUM_COL_FMTS);
    get_column_format_matches(col_item->fmt_matx, col_item->col_fmt);
    col_item->col_data = NULL;

    if (col_item->col_fmt == COL_INFO) {
      col_item->col_buf = g_new(char, COL_MAX_INFO_LEN);
      cinfo->col_expr.col_expr_val[i] = g_new(char, COL_MAX_INFO_LEN);
    } else {
      col_item->col_buf = g_new(char, COL_MAX_LEN);
      cinfo->col_expr.col_expr_val[i] = g_new(char, COL_MAX_LEN);
    }

    cinfo->col_expr.col_expr[i] = "";
  }

  cinfo->col_expr.col_expr[i] = NULL;
  cinfo->col_expr.col_expr_val[i] = NULL;

  for (i = 0; i < cinfo->num_cols; i++) {
    int j;

    for (j = 0; j < NUM_COL_FMTS; j++) {
      if (!cinfo->columns[i].fmt_matx[j])
          continue;

      if (cinfo->col_first[j] == -1)
        cinfo->col_first[j] = i;

      cinfo->col_last[j] = i;
    }
  }
}

void
build_column_format_array(column_info *cinfo, const int num_cols, const bool reset_fences)
{
  int i;
  col_item_t* col_item;

  /* Build the column format array */
  col_setup(cinfo, num_cols);

  for (i = 0; i < cinfo->num_cols; i++) {
    col_item = &cinfo->columns[i];
    col_item->col_fmt = get_column_format(i);
    col_item->col_title = g_strdup(get_column_title(i));
    if (col_item->col_fmt == COL_CUSTOM) {
      col_item->col_custom_fields = g_strdup(get_column_custom_fields(i));
      col_item->col_custom_occurrence = get_column_custom_occurrence(i);
    }
    col_item->hf_id = proto_registrar_get_id_byname(col_format_abbrev(col_item->col_fmt));

    if(reset_fences)
      col_item->col_fence = 0;
  }

  col_finalize(cinfo);
}

static void
column_deregister_fields(void)
{
  if (hf_cols) {
    for (unsigned int i = 0; i < hf_cols_cleanup; ++i) {
      proto_deregister_field(proto_cols, *(hf_cols[i].p_id));
      g_free(hf_cols[i].p_id);
    }
    proto_add_deregistered_data(hf_cols);
    hf_cols = NULL;
    hf_cols_cleanup = 0;
  }
}

void
column_register_fields(void)
{

  int* hf_id;
  GArray *hf_col_array;
  hf_register_info new_hf;
  fmt_data *cfmt;
  bool *used_fmts;
  if (proto_cols <= 0) {
    proto_cols = proto_get_id_by_filter_name("_ws.col");
  }
  if (proto_cols <= 0) {
    proto_cols = proto_register_protocol("Wireshark Columns", "Columns", "_ws.col");
  }
  column_deregister_fields();
  if (prefs.col_list != NULL) {
    prefs.num_cols = g_list_length(prefs.col_list);
    hf_col_array = g_array_new(false, true, sizeof(hf_register_info));
    used_fmts = g_new0(bool, NUM_COL_FMTS);
    /* Only register a field for each format type once, but don't register
     * these at all. The first two behave oddly (because they depend on
     * whether the current field and previous fields are displayed). We
     * might want to do custom columns in the future, though.
     */
    used_fmts[COL_DELTA_TIME_DIS] = 1;
    used_fmts[COL_CUMULATIVE_BYTES] = 1;
    used_fmts[COL_CUSTOM] = 1;

    for (GList *elem = g_list_first(prefs.col_list); elem != NULL; elem = elem->next) {
      cfmt = (fmt_data*)elem->data;
      if (!used_fmts[cfmt->fmt]) {
        used_fmts[cfmt->fmt] = true;
        hf_id = g_new(int, 1);
        *hf_id = -1;
        new_hf.p_id = hf_id;
        new_hf.hfinfo.name = g_strdup(col_format_desc(cfmt->fmt));
        new_hf.hfinfo.abbrev = g_strdup(col_format_abbrev(cfmt->fmt));
        new_hf.hfinfo.type = FT_STRING;
        new_hf.hfinfo.display = BASE_NONE;
        new_hf.hfinfo.strings = NULL;
        new_hf.hfinfo.bitmask = 0;
        new_hf.hfinfo.blurb = NULL;
        HFILL_INIT(new_hf);
        g_array_append_vals(hf_col_array, &new_hf, 1);
      }
    }
    g_free(used_fmts);
    hf_cols_cleanup = hf_col_array->len;

    proto_register_field_array(proto_cols, (hf_register_info*)hf_col_array->data, hf_col_array->len);
    hf_cols = (hf_register_info*)g_array_free(hf_col_array, false);
  }
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

