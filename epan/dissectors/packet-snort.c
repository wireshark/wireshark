/* packet-snort.c
 *
 * Copyright 2011, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 * Copyright 2016, Martin Mathieson
 *
 * Google Summer of Code 2011 for The Honeynet Project
 * Mentors:
 *    Guillaume Arcas <guillaume.arcas (at) retiaire.org>
 *    Jeff Nathan <jeffnathan (at) gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* TODO:
 * - sort out threading/channel-sync so works reliably in tshark
 *    - postponed for now, as Qt crashes if call g_main_context_iteration()
 *      at an inopportune time
 * - have looked into writing a tap that could provide an interface for error messages/events and snort stats,
 *   but not easy as taps are not usually listening when alerts are detected
 * - for a content/pcre match, find all protocol fields that cover same bytes and show in tree
 * - other use-cases as suggested in https://sharkfesteurope.wireshark.org/assets/presentations16eu/14.pptx
 */


#include "config.h"

#include <errno.h>
#include <ctype.h>

#include <epan/epan.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem_scopes.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>
#include <wiretap/wtap-int.h>

#include "packet-snort-config.h"

/* Forward declarations */
void proto_register_snort(void);
void proto_reg_handoff_snort(void);


static int proto_snort = -1;

/* These are from parsing snort fast_alert output and/or looking up snort config */
static int hf_snort_raw_alert = -1;
static int hf_snort_classification = -1;
static int hf_snort_rule = -1;
static int hf_snort_msg = -1;
static int hf_snort_rev = -1;
static int hf_snort_sid = -1;
static int hf_snort_generator = -1;
static int hf_snort_priority = -1;
static int hf_snort_rule_string = -1;
static int hf_snort_rule_protocol = -1;
static int hf_snort_rule_filename = -1;
static int hf_snort_rule_line_number = -1;
static int hf_snort_rule_ip_var = -1;
static int hf_snort_rule_port_var = -1;

static int hf_snort_reassembled_in = -1;
static int hf_snort_reassembled_from = -1;

/* Patterns to match */
static int hf_snort_content = -1;
static int hf_snort_uricontent = -1;
static int hf_snort_pcre = -1;

/* Web links */
static int hf_snort_reference = -1;

/* General stats about the rule set */
static int hf_snort_global_stats = -1;
static int hf_snort_global_stats_rule_file_count = -1;     /* number of rules files */
static int hf_snort_global_stats_rule_count = -1;          /* number of rules in config */

static int hf_snort_global_stats_total_alerts_count = -1;
static int hf_snort_global_stats_alert_match_number = -1;

static int hf_snort_global_stats_rule_alerts_count = -1;
static int hf_snort_global_stats_rule_match_number = -1;


/* Subtrees */
static int ett_snort = -1;
static int ett_snort_rule = -1;
static int ett_snort_global_stats = -1;

/* Expert info */
static expert_field ei_snort_alert = EI_INIT;
static expert_field ei_snort_content_not_matched = EI_INIT;

static dissector_handle_t snort_handle;


/*****************************************/
/* Preferences                           */

/* Where to look for alerts. */
enum alerts_source {
    FromNowhere,      /* disabled */
    FromRunningSnort,
    FromUserComments  /* see https://blog.packet-foo.com/2015/08/verifying-iocs-with-snort-and-tracewrangler/ */
};
/* By default, dissector is effectively disabled */
static gint pref_snort_alerts_source = (gint)FromNowhere;

/* Snort binary and config file */
#ifndef _WIN32
static const char *pref_snort_binary_filename = "/usr/sbin/snort";
static const char *pref_snort_config_filename = "/etc/snort/snort.conf";
#else
/* Default locations from Snort Windows installer */
static const char *pref_snort_binary_filename = "C:\\Snort\\bin\\snort.exe";
static const char *pref_snort_config_filename = "C:\\Snort\\etc\\snort.conf";
#endif

/* Should rule stats be shown in protocol tree? */
static gboolean snort_show_rule_stats = FALSE;

/* Should alerts be added as expert info? */
static gboolean snort_show_alert_expert_info = FALSE;

/* Should we try to attach the alert to the tcp.reassembled_in frame instead of current one? */
static gboolean snort_alert_in_reassembled_frame = FALSE;

/* Should Snort ignore checksum errors (as will likely be seen because of check offloading or
 * possibly if trying to capture live in a container)? */
static gboolean snort_ignore_checksum_errors = TRUE;


/********************************************************/
/* Global variable with single parsed snort config      */
static SnortConfig_t *g_snort_config = NULL;


/******************************************************/
/* This is to keep track of the running Snort process */
typedef struct {
    gboolean running;
    gboolean working;

    GPid pid;
    int in, out, err;   /* fds for talking to snort process */

    GString *buf;       /* Incomplete alert output that has been read */
    wtap_dumper *pdh;   /* wiretap dumper used to deliver packets to 'in' */

    GIOChannel *channel; /* IO channel used for readimg stdout (alerts) */

    wmem_tree_t *alerts_tree;  /* Lookup from frame-number -> Alerts_t* */
} snort_session_t;

/* Global instance of the snort session */
static snort_session_t current_session;

static int snort_config_ok = TRUE;   /* N.B. Not running test at the moment... */



/*************************************************/
/* An alert.
   Created by parsing alert from snort, hopefully with more details linked from matched_rule. */
typedef struct Alert_t {
    /* Rule */
    guint32       sid;             /* Rule identifier */
    guint32       rev;             /* Revision number of rule */
    guint32       gen;             /* Which engine generated alert (not often interesting) */
    int           prio;            /* Priority as reported in alert (not usually interesting) */

    char       *raw_alert;         /* The whole alert string as reported by snort */
    gboolean   raw_alert_ts_fixed; /* Set when correct timestamp is restored before displaying */

    char       *msg;               /* Rule msg/description as it appears in the alert */
    char       *classification;    /* Classification type of rule */

    Rule_t     *matched_rule;      /* Link to corresponding rule from snort config */

    guint32    original_frame;
    guint32    reassembled_frame;

    /* Stats for this alert among the capture file. */
    unsigned int overall_match_number;
    unsigned int rule_match_number;
} Alert_t;

/* Can have multiple alerts fire on same frame, so define this container */
typedef struct Alerts_t {
/* N.B. Snort limit appears to be 6 (at least with default config..) */
#define MAX_ALERTS_PER_FRAME 8
    Alert_t alerts[MAX_ALERTS_PER_FRAME];
    guint num_alerts;
} Alerts_t;


/* Add an alert to the map stored in current_session.
 * N.B. even if preference 'snort_alert_in_reassembled_frame' is set,
 * need to set to original frame now, and try to update it in the 2nd pass... */
static void add_alert_to_session_tree(guint frame_number, Alert_t *alert)
{
    /* First look up tree to see if there is an existing entry */
    Alerts_t *alerts = (Alerts_t*)wmem_tree_lookup32(current_session.alerts_tree, frame_number);
    if (alerts == NULL) {
        /* Create a new entry for the table */
        alerts = g_new(Alerts_t, 1);
        /* Deep copy of alert */
        alerts->alerts[0] = *alert;
        alerts->num_alerts = 1;
        wmem_tree_insert32(current_session.alerts_tree, frame_number, alerts);
    }
    else {
        /* See if there is room in the existing Alerts_t struct for this frame */
        if (alerts->num_alerts < MAX_ALERTS_PER_FRAME) {
            /* Deep copy of alert */
            alerts->alerts[alerts->num_alerts++] = *alert;
        }
    }
}


/******************************************************************/

/* Given an alert struct, look up by Snort ID (sid) and try to fill in other details to display. */
static void fill_alert_config(SnortConfig_t *snort_config, Alert_t *alert)
{
    guint global_match_number=0, rule_match_number=0;

    /* Look up rule by sid */
    alert->matched_rule = get_rule(snort_config, alert->sid);

    /* Classtype usually filled in from alert rather than rule, but missing for supsported
       comment format. */
    if (pref_snort_alerts_source == FromUserComments) {
        alert->classification = g_strdup(alert->matched_rule->classtype);
    }

    /* Inform the config/rule about the alert */
    rule_set_alert(snort_config, alert->matched_rule,
                   &global_match_number, &rule_match_number);

    /* Copy updated counts into the alert */
    alert->overall_match_number = global_match_number;
    alert->rule_match_number = rule_match_number;
}


/* Helper functions for matching expected bytes against the packet buffer.
  Case-sensitive comparison - can just memcmp().
  Case-insensitive comparison - need to look at each byte and compare uppercase version */
static gboolean content_compare_case_sensitive(const guint8* memory, const char* target, guint length)
{
    return (memcmp(memory, target, length) == 0);
}

static gboolean content_compare_case_insensitive(const guint8* memory, const char* target, guint length)
{
    for (guint n=0; n < length; n++) {
        if (g_ascii_isalpha(target[n])) {
            if (g_ascii_toupper(memory[n]) != g_ascii_toupper(target[n])) {
                return FALSE;
            }
        }
        else {
           if ((guint8)memory[n] != (guint8)target[n]) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/* Move through the bytes of the tvbuff, looking for a match against the
 * regexp from the given content.
 */
static gboolean look_for_pcre(content_t *content, tvbuff_t *tvb, guint start_offset, guint *match_offset, guint *match_length)
{
    /* Create a regex object for the pcre in the content. */
    GRegex *regex;
    GMatchInfo *match_info;
    gboolean match_found = FALSE;
    GRegexCompileFlags regex_compile_flags = (GRegexCompileFlags)0;

    /* Make sure pcre string is ready for regex library. */
    if (!content_convert_pcre_for_regex(content)) {
        return FALSE;
    }

    /* Copy remaining bytes into NULL-terminated string. Unfortunately, this interface does't allow
       us to find patterns that involve bytes with value 0.. */
    int length_remaining = tvb_captured_length_remaining(tvb, start_offset);
    gchar *string = (gchar*)g_malloc(length_remaining + 1);
    tvb_memcpy(tvb, (void*)string, start_offset, length_remaining);
    string[length_remaining] = '\0';

    /* For pcre, translated_str already has / /[modifiers] removed.. */

    /* Apply any set modifier flags */
    if (content->pcre_case_insensitive) {
        regex_compile_flags = (GRegexCompileFlags)(regex_compile_flags | G_REGEX_CASELESS);
    }
    if (content->pcre_dot_includes_newline) {
        regex_compile_flags = (GRegexCompileFlags)(regex_compile_flags | G_REGEX_DOTALL);
    }
    if (content->pcre_raw) {
        regex_compile_flags = (GRegexCompileFlags)(regex_compile_flags | G_REGEX_RAW);
    }
    if (content->pcre_multiline) {
        regex_compile_flags = (GRegexCompileFlags)(regex_compile_flags | G_REGEX_MULTILINE);
    }

    /* Create regex */
    regex = g_regex_new(content->translated_str,
                        regex_compile_flags,
                        (GRegexMatchFlags)0, NULL);

    /* Lookup PCRE match */
    g_regex_match(regex, string, (GRegexMatchFlags)0, &match_info);
    /* Only first match needed */
    /* TODO: need to restart at any NULL before the final end? */
    if (g_match_info_matches(match_info)) {
        gint start_pos, end_pos;

        /* Find out where the match is */
        g_match_info_fetch_pos(match_info,
                               0, /* match_num */
                               &start_pos, &end_pos);

        *match_offset = start_offset + start_pos;
        *match_length = end_pos - start_pos;
        match_found = TRUE;
    }

    g_match_info_free(match_info);
    g_regex_unref(regex);
    g_free(string);

    return match_found;
}

/* Move through the bytes of the tvbuff, looking for a match against the expanded
   binary contents of this content object.
 */
static gboolean look_for_content(content_t *content, tvbuff_t *tvb, guint start_offset, guint *match_offset, guint *match_length)
{
    gint tvb_len = tvb_captured_length(tvb);

    /* Make sure content has been translated into binary string. */
    guint converted_content_length = content_convert_to_binary(content);

    /* Look for a match at each position. */
    for (guint m=start_offset; m <= (tvb_len-converted_content_length); m++) {
        const guint8 *ptr = tvb_get_ptr(tvb, m, converted_content_length);
        if (content->nocase) {
            if (content_compare_case_insensitive(ptr, content->translated_str, content->translated_length)) {
                *match_offset = m;
                *match_length = content->translated_length;
                return TRUE;
            }
        }
        else {
            if (content_compare_case_sensitive(ptr, content->translated_str, content->translated_length)) {
                *match_offset = m;
                *match_length = content->translated_length;
                return TRUE;
            }
        }
    }

    return FALSE;
}




/* Look for where the content match happens within the tvb.
 * Set out parameters match_offset and match_length */
static gboolean get_content_match(Alert_t *alert, guint content_idx,
                                  tvbuff_t *tvb, guint content_start_match,
                                  guint *match_offset, guint *match_length)
{
    content_t *content;
    Rule_t *rule = alert->matched_rule;

    /* Can't match if don't know rule */
    if (rule == NULL) {
        return FALSE;
    }

    /* Get content object. */
    content = &(rule->contents[content_idx]);

    /* Look for content match in the packet */
    if (content->content_type == Pcre) {
        return look_for_pcre(content, tvb, content_start_match, match_offset, match_length);
    }
    else {
        return look_for_content(content, tvb, content_start_match, match_offset, match_length);
    }
}


/* Gets called when snort process has died */
static void snort_reaper(GPid pid, gint status _U_, gpointer data)
{
    snort_session_t *session = (snort_session_t *)data;
    if (session->running && session->pid == pid) {
        session->working = session->running = FALSE;
        /* XXX, cleanup */
    } else {
        g_print("Errrrmm snort_reaper() %d != %d\n", session->pid, pid);
    }

    /* Close the snort pid (may only make a difference on Windows?) */
    g_spawn_close_pid(pid);
}

/* Parse timestamp line of output.  This is done in part to get the packet_number back out of usec field...
 * Return value is the input stream moved onto the next field following the timestamp */
static const char* snort_parse_ts(const char *ts, guint32 *frame_number)
{
    struct tm tm;
    unsigned int usec;

    /* Timestamp */
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    if (sscanf(ts, "%02d/%02d/%02d-%02d:%02d:%02d.%06u ",
               &(tm.tm_mon), &(tm.tm_mday), &(tm.tm_year), &(tm.tm_hour), &(tm.tm_min), &(tm.tm_sec), &usec) != 7) {
        return NULL;
    }
    tm.tm_mon -= 1;
    tm.tm_year += 100;

    /* Store frame number (which was passed into this position when packet was submitted to snort) */
    *frame_number = usec;

    return strchr(ts, ' ');
}

/* Parse a fast output alert string */
static gboolean snort_parse_fast_line(const char *line, Alert_t *alert)
{
    static const char stars[] = " [**] ";

    static const char classification[] = "[Classification: ";
    static const char priority[] = "[Priority: ";
    const char *tmp_msg;

    /* Look for timestamp/frame-number */
    if (!(line = snort_parse_ts(line, &(alert->original_frame)))) {
        return FALSE;
    }

    /* [**] */
    if (!g_str_has_prefix(line+1, stars)) {
        return FALSE;
    }
    line += sizeof(stars);

    /* [%u:%u:%u] */
    if (sscanf(line, "[%u:%u:%u] ", &(alert->gen), &(alert->sid), &(alert->rev)) != 3) {
        return FALSE;
    }
    if (!(line = strchr(line, ' '))) {
        return FALSE;
    }

    /* [**] again */
    tmp_msg = line+1;
    if (!(line = strstr(line, stars))) {
        return FALSE;
    }

    /* msg */
    alert->msg = g_strndup(tmp_msg, line - tmp_msg);
    line += (sizeof(stars)-1);

    /* [Classification: Attempted Administrator Privilege Gain] [Priority: 10] */

    if (g_str_has_prefix(line, classification)) {
        /* [Classification: %s] */
        char *tmp;
        line += (sizeof(classification)-1);

        if (!(tmp = (char*)strstr(line, "] [Priority: "))) {
            return FALSE;
        }

        /* assume "] [Priority: " is not inside classification text :) */
        alert->classification = g_strndup(line, tmp - line);

        line = tmp+2;
    } else
        alert->classification = NULL;

    /* Optimized: if al->classification we already checked this in strstr() above */
    if (alert->classification || g_str_has_prefix(line, priority)) {
        /* [Priority: %d] */
        line += (sizeof(priority)-1);

        if ((sscanf(line, "%d", &(alert->prio))) != 1) {
            return FALSE;
        }

        if (!strstr(line, "] ")) {
            return FALSE;
        }
    } else {
        alert->prio = -1; /* XXX */
    }

    return TRUE;
}

/**
 * snort_parse_user_comment()
 *
 * Parse line as written by TraceWranger
 * e.g. "1:2011768:4 - ET WEB_SERVER PHP tags in HTTP POST"
 */
static gboolean snort_parse_user_comment(const char *line, Alert_t *alert)
{
    /* %u:%u:%u */
    if (sscanf(line, "%u:%u:%u", &(alert->gen), &(alert->sid), &(alert->rev)) != 3) {
        return FALSE;
    }

    /* Skip separator between numbers and msg */
    if (!(line = strstr(line, " - "))) {
        return FALSE;
    }

    /* Copy to be consistent with other use of Alert_t */
    alert->msg = g_strdup(line);

    /* No need to set other fields as assume zero'd out before this call.. */
    return TRUE;
}

/* Output data has been received from snort.  Read from channel and look for whole alerts. */
static gboolean snort_fast_output(GIOChannel *source, GIOCondition condition, gpointer data)
{
    snort_session_t *session = (snort_session_t *)data;

    /* Loop here until all available input read */
    while (condition & G_IO_IN) {
        GIOStatus status;
        char _buf[1024];
        gsize len = 0;

        char *old_buf = NULL;
        char *buf = _buf;
        char *line;

        /* Try to read snort output info _buf */
        status = g_io_channel_read_chars(source, _buf, sizeof(_buf)-1, &len, NULL);
        if (status != G_IO_STATUS_NORMAL) {
            if (status == G_IO_STATUS_AGAIN) {
                /* Blocked, so unset G_IO_IN and get out of this function */
                condition = (GIOCondition)(condition & ~G_IO_IN);
                break;
            }
            /* Other conditions here could be G_IO_STATUS_ERROR, G_IO_STATUS_EOF */
            return FALSE;
        }
        /* Terminate buffer */
        buf[len] = '\0';

        /* If we previously had part of a line, append the new bit we just saw */
        if (session->buf) {
            g_string_append(session->buf, buf);
            buf = old_buf = g_string_free(session->buf, FALSE);
            session->buf = NULL;
        }

        /* Extract every complete line we find in the output */
        while ((line = strchr(buf, '\n'))) {
            /* Have a whole line, so can parse */
            Alert_t alert;
            memset(&alert, 0, sizeof(alert));

            /* Terminate received line */
            *line = '\0';

            if (snort_parse_fast_line(buf, &alert)) {
                /*******************************************************/
                /* We have an alert line.                              */
#if 0
                g_print("%ld.%lu [%u,%u,%u] %s {%s} [%d]\n",
                        alert.tv.tv_sec, alert.tv.tv_usec,
                        alert.gen, alert.sid, alert.rev,
                        alert.msg,
                        alert.classification ? alert.classification : "(null)",
                        alert.prio);
#endif

                /* Copy the raw alert string itself */
                alert.raw_alert = g_strdup(buf);

                /* See if we can get more info from the parsed config details */
                fill_alert_config(g_snort_config, &alert);

                /* Add parsed alert into session->tree */
                /* Store in tree. Frame number hidden in fraction of second field, so associate
                   alert with that frame. */
                add_alert_to_session_tree((guint)alert.original_frame, &alert);
            }
            else {
                g_print("snort_fast_output() line: '%s'\n", buf);
            }

            buf = line+1;
        }

        if (buf[0]) {
            /* Only had part of a line - store it */
            /* N.B. typically happens maybe once every 5-6 alerts. */
            session->buf = g_string_new(buf);
        }

        g_free(old_buf);
    }

    if ((condition == G_IO_ERR) || (condition == G_IO_HUP) || (condition == G_IO_NVAL)) {
        /* Will report errors (hung-up, or error) */

        /* g_print("snort_fast_output() cond: (h:%d,e:%d,r:%d)\n",
         *         !!(condition & G_IO_HUP), !!(condition & G_IO_ERR), condition); */
        return FALSE;
    }

    return TRUE;
}


/* Return the offset in the frame where snort should begin looking inside payload. */
static guint get_protocol_payload_start(const char *protocol, proto_tree *tree)
{
    guint value = 0;

    /* For icmp, look from start, whereas for others start after them. */
    gboolean look_after_protocol = (strcmp(protocol, "icmp") != 0);

    if (tree != NULL) {
        GPtrArray *items = proto_all_finfos(tree);
        if (items) {
            guint i;
            for (i=0; i< items->len; i++) {
                field_info *field = (field_info *)g_ptr_array_index(items,i);
                if (strcmp(field->hfinfo->abbrev, protocol) == 0) {
                    value = field->start;
                    if (look_after_protocol) {
                        value += field->length;
                    }
                    break;
                }
            }
            g_ptr_array_free(items,TRUE);
        }
    }
    return value;
}


/* Return offset that application layer traffic will begin from. */
static guint get_content_start_match(Rule_t *rule, proto_tree *tree)
{
    /* Work out where snort would start looking for data in the frame */
    return get_protocol_payload_start(rule->protocol, tree);
}

/* Where this frame is later part of a reassembled complete PDU running over TCP, look up
   and return that frame number. */
static guint get_reassembled_in_frame(proto_tree *tree)
{
    guint value = 0;

    if (tree != NULL) {
        GPtrArray *items = proto_all_finfos(tree);
        if (items) {
            guint i;
            for (i=0; i< items->len; i++) {
                field_info *field = (field_info *)g_ptr_array_index(items,i);
                if (strcmp(field->hfinfo->abbrev, "tcp.reassembled_in") == 0) {
                    value = field->value.value.uinteger;
                    break;
                }
            }
            g_ptr_array_free(items,TRUE);
        }
    }
    return value;
}


/* Show the Snort protocol tree based on the info in alert */
static void snort_show_alert(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, Alert_t *alert)
{
    proto_tree *snort_tree = NULL;
    guint n;
    proto_item *ti, *rule_ti;
    proto_tree *rule_tree;
    Rule_t *rule = alert->matched_rule;

    /* May need to move to reassembled frame to show there instead of here */

    if (snort_alert_in_reassembled_frame && pinfo->fd->visited && (tree != NULL)) {
        guint reassembled_frame = get_reassembled_in_frame(tree);

        if (reassembled_frame && (reassembled_frame != pinfo->num)) {
            Alerts_t *alerts;

            /* Look up alerts for this frame */
            alerts = (Alerts_t*)wmem_tree_lookup32(current_session.alerts_tree, pinfo->num);

            if (!alerts->alerts[0].reassembled_frame) {
                /* Update all alerts from this frame! */
                for (n=0; n < alerts->num_alerts; n++) {

                    /* Set forward/back frame numbers */
                    alerts->alerts[n].original_frame = pinfo->num;
                    alerts->alerts[n].reassembled_frame = reassembled_frame;

                    /* Add these alerts to reassembled frame */
                    add_alert_to_session_tree(reassembled_frame, &alerts->alerts[n]);
                }
            }
        }
    }

    /* Can only find start if we have the rule and know the protocol */
    guint content_start_match = 0;
    guint payload_start = 0;
    if (rule) {
        payload_start = content_start_match = get_content_start_match(rule, tree);
    }

    /* Snort output arrived and was previously stored - so add to tree */
    /* Take care not to try to highlight bytes that aren't there.. */
    proto_item *alert_ti = proto_tree_add_protocol_format(tree, proto_snort, tvb,
                                                          content_start_match >= tvb_captured_length(tvb) ? 0 : content_start_match,
                                                          content_start_match >= tvb_captured_length(tvb) ? 0 : -1,
                                                          "Snort: (msg: \"%s\" sid: %u rev: %u) [from %s]",
                                                          alert->msg, alert->sid, alert->rev,
                                                          (pref_snort_alerts_source == FromUserComments) ?
                                                              "User Comment" :
                                                              "Running Snort");
    snort_tree = proto_item_add_subtree(alert_ti, ett_snort);

    if (snort_alert_in_reassembled_frame && (alert->reassembled_frame != 0)) {
        if (alert->original_frame == pinfo->num) {
            /* Show link forward to where alert is now shown! */
            ti = proto_tree_add_uint(tree, hf_snort_reassembled_in, tvb, 0, 0,
                                     alert->reassembled_frame);
            proto_item_set_generated(ti);
            return;
        }
        else {
            tvbuff_t *reassembled_tvb;
            /* Show link back to segment where alert was detected. */
            ti = proto_tree_add_uint(tree, hf_snort_reassembled_from, tvb, 0, 0,
                                     alert->original_frame);
            proto_item_set_generated(ti);

            /* Should find this if look late enough.. */
            reassembled_tvb = get_data_source_tvb_by_name(pinfo, "Reassembled TCP");
            if (reassembled_tvb) {
                /* Will look for content using the TVB instead of just this frame's one */
                tvb = reassembled_tvb;
            }
            /* TODO: for correctness, would be good to lookup + remember the offset of the source
             * frame within the reassembled PDU frame, to make sure we find the content in the
             * correct place for every alert */
        }
    }

    snort_debug_printf("Showing alert (sid=%u) in frame %u\n", alert->sid, pinfo->num);

    /* Show in expert info if configured to. */
    if (snort_show_alert_expert_info) {
        expert_add_info_format(pinfo, alert_ti, &ei_snort_alert, "Alert %u: \"%s\"", alert->sid, alert->msg);
    }

    /* Show the 'raw' alert string. */
    if (rule) {
        /* Fix up alert->raw_alert if not already done so first. */
        if (!alert->raw_alert_ts_fixed) {
            /* Write 6 figures to position after decimal place in timestamp. Must have managed to
               parse out fields already, so will definitely be long enough for memcpy() to succeed. */
            char digits[7];
            snprintf(digits, 7, "%06d", pinfo->abs_ts.nsecs / 1000);
            memcpy(alert->raw_alert+18, digits, 6);
            alert->raw_alert_ts_fixed = TRUE;
        }
        ti = proto_tree_add_string(snort_tree, hf_snort_raw_alert, tvb, 0, 0, alert->raw_alert);
        proto_item_set_generated(ti);
    }

    /* Rule classification */
    if (alert->classification) {
        ti = proto_tree_add_string(snort_tree, hf_snort_classification, tvb, 0, 0, alert->classification);
        proto_item_set_generated(ti);
    }

    /* Put rule fields under a rule subtree */

    rule_ti = proto_tree_add_string_format(snort_tree, hf_snort_rule, tvb, 0, 0, "", "Rule");
    proto_item_set_generated(rule_ti);
    rule_tree = proto_item_add_subtree(rule_ti, ett_snort_rule);

    /* msg/description */
    ti = proto_tree_add_string(rule_tree, hf_snort_msg, tvb, 0, 0, alert->msg);
    proto_item_set_generated(ti);
    /* Snort ID */
    ti = proto_tree_add_uint(rule_tree, hf_snort_sid, tvb, 0, 0, alert->sid);
    proto_item_set_generated(ti);
    /* Rule revision */
    ti = proto_tree_add_uint(rule_tree, hf_snort_rev, tvb, 0, 0, alert->rev);
    proto_item_set_generated(ti);
    /* Generator seems to correspond to gid. */
    ti = proto_tree_add_uint(rule_tree, hf_snort_generator, tvb, 0, 0, alert->gen);
    proto_item_set_generated(ti);
    /* Default priority is 2 - very few rules have a different priority... */
    ti = proto_tree_add_uint(rule_tree, hf_snort_priority, tvb, 0, 0, alert->prio);
    proto_item_set_generated(ti);

    /* If we know the rule for this alert, show some of the rule fields */
    if (rule && rule->rule_string) {
        size_t rule_string_length = strlen(rule->rule_string);

        /* Show rule string itself. Add it as a separate data source so can read it all */
        if (rule_string_length > 60) {
            tvbuff_t *rule_string_tvb = tvb_new_child_real_data(tvb, rule->rule_string,
                                                                (guint)rule_string_length,
                                                                (guint)rule_string_length);
            add_new_data_source(pinfo, rule_string_tvb, "Rule String");
            ti = proto_tree_add_string(rule_tree, hf_snort_rule_string, rule_string_tvb, 0,
                                       (gint)rule_string_length,
                                       rule->rule_string);
        }
        else {
            ti = proto_tree_add_string(rule_tree, hf_snort_rule_string, tvb, 0, 0,
                                       rule->rule_string);
        }
        proto_item_set_generated(ti);

        /* Protocol from rule */
        ti = proto_tree_add_string(rule_tree, hf_snort_rule_protocol, tvb, 0, 0, rule->protocol);
        proto_item_set_generated(ti);

        /* Show file alert came from */
        ti = proto_tree_add_string(rule_tree, hf_snort_rule_filename, tvb, 0, 0, rule->file);
        proto_item_set_generated(ti);
        /* Line number within file */
        ti = proto_tree_add_uint(rule_tree, hf_snort_rule_line_number, tvb, 0, 0, rule->line_number);
        proto_item_set_generated(ti);

        /* Show IP vars */
        for (n=0; n < rule->relevant_vars.num_ip_vars; n++) {
            ti = proto_tree_add_none_format(rule_tree, hf_snort_rule_ip_var, tvb, 0, 0, "IP Var: ($%s -> %s)",
                                            rule->relevant_vars.ip_vars[n].name,
                                            rule->relevant_vars.ip_vars[n].value);
            proto_item_set_generated(ti);
        }
        /* Show Port vars */
        for (n=0; n < rule->relevant_vars.num_port_vars; n++) {
            ti = proto_tree_add_none_format(rule_tree, hf_snort_rule_port_var, tvb, 0, 0, "Port Var: ($%s -> %s)",
                                            rule->relevant_vars.port_vars[n].name,
                                            rule->relevant_vars.port_vars[n].value);
            proto_item_set_generated(ti);
        }
    }


    /* Show summary information in rule tree root */
    proto_item_append_text(rule_ti, " %s (sid=%u, rev=%u)",
                           alert->msg, alert->sid, alert->rev);

    /* More fields retrieved from the parsed config */
    if (rule) {
        guint content_last_match_end = 0;

        /* Work out which ip and port vars are relevant */
        rule_set_relevant_vars(g_snort_config, rule);

        /* Contents */
        for (n=0; n < rule->number_contents; n++) {

            /* Search for string among tvb contents so we can highlight likely bytes. */
            unsigned int content_offset = 0;
            gboolean match_found = FALSE;
            unsigned int converted_content_length = 0;
            int content_hf_item;
            char *content_text_template;

            /* Choose type of content field to add */
            switch (rule->contents[n].content_type) {
                case Content:
                    content_hf_item = hf_snort_content;
                    content_text_template = "Content: \"%s\"";
                    break;
                case UriContent:
                    content_hf_item = hf_snort_uricontent;
                    content_text_template = "Uricontent: \"%s\"";
                    break;
                case Pcre:
                    content_hf_item = hf_snort_pcre;
                    content_text_template = "Pcre: \"%s\"";
                    break;
                default:
                    continue;
            }

            /* Will only try to look for content in packet ourselves if not
               a negated content entry (i.e. beginning with '!') */
            if (!rule->contents[n].negation) {
                /* Look up offset of match. N.B. would only expect to see on first content... */
                guint distance_to_add = 0;

                /* May need to start looking from absolute offset into packet... */
                if (rule->contents[n].offset_set) {
                    content_start_match = payload_start + rule->contents[n].offset;
                }
                /* ... or a number of bytes beyond the previous content match */
                else if (rule->contents[n].distance_set) {
                    distance_to_add = (content_last_match_end-content_start_match) + rule->contents[n].distance;
                }
                else {
                    /* No constraints about where it appears - go back to the start of the frame. */
                    content_start_match = payload_start;
                }


                /* Now actually look for match from calculated position */
                /* TODO: could take 'depth' and 'within' into account to limit extent of search,
                   but OK if just trying to verify what Snort already found. */
                match_found = get_content_match(alert, n,
                                                tvb, content_start_match+distance_to_add,
                                                &content_offset, &converted_content_length);
                if (match_found) {
                    content_last_match_end = content_offset + converted_content_length;
                }
            }


            /* Show content in tree (showing position if known) */
            ti = proto_tree_add_string_format(snort_tree, content_hf_item, tvb,
                                              (match_found) ? content_offset : 0,
                                              (match_found) ? converted_content_length : 0,
                                              rule->contents[n].str,
                                              content_text_template,
                                              rule->contents[n].str);

            /* Next match position will be after this one */
            if (match_found) {
                content_start_match = content_last_match_end;
            }

            /* Show (only as text) attributes of content field */
            if (rule->contents[n].fastpattern) {
                proto_item_append_text(ti, " (fast_pattern)");
            }
            if (rule->contents[n].rawbytes) {
                proto_item_append_text(ti, " (rawbytes)");
            }
            if (rule->contents[n].nocase) {
                proto_item_append_text(ti, " (nocase)");
            }
            if (rule->contents[n].negation) {
                proto_item_append_text(ti, " (negated)");
            }
            if (rule->contents[n].offset_set) {
                proto_item_append_text(ti, " (offset=%d)", rule->contents[n].offset);
            }
            if (rule->contents[n].depth != 0) {
                proto_item_append_text(ti, " (depth=%u)", rule->contents[n].depth);
            }
            if (rule->contents[n].distance_set) {
                proto_item_append_text(ti, " (distance=%d)", rule->contents[n].distance);
            }
            if (rule->contents[n].within != 0) {
                proto_item_append_text(ti, " (within=%u)", rule->contents[n].within);
            }

            /* HTTP preprocessor modifiers */
            if (rule->contents[n].http_method != 0) {
                proto_item_append_text(ti, " (http_method)");
            }
            if (rule->contents[n].http_client_body != 0) {
                proto_item_append_text(ti, " (http_client_body)");
            }
            if (rule->contents[n].http_cookie != 0) {
                proto_item_append_text(ti, " (http_cookie)");
            }
            if (rule->contents[n].http_user_agent != 0) {
                proto_item_append_text(ti, " (http_user_agent)");
            }

            if (!rule->contents[n].negation && !match_found) {
                /* Useful for debugging, may also happen when Snort is reassembling.. */
                /* TODO: not sure why, but PCREs might not be found first time through, but will be
                 * found later, with the result that there will be 'not located' expert warnings,
                 * but when you click on the packet, it is matched after all... */
                proto_item_append_text(ti, " - not located");
                expert_add_info_format(pinfo, ti, &ei_snort_content_not_matched,
                                       "%s   \"%s\"   not found in frame",
                                       rule->contents[n].content_type==Pcre ? "PCRE" : "Content",
                                       rule->contents[n].str);
            }
        }

        /* References */
        for (n=0; n < rule->number_references; n++) {
            /* Substitute prefix and add to tree as clickable web links */
            ti = proto_tree_add_string(snort_tree, hf_snort_reference, tvb, 0, 0,
                                       expand_reference(g_snort_config, rule->references[n]));
            /* Make clickable */
            proto_item_set_url(ti);
            proto_item_set_generated(ti);
        }
    }

    /* Global rule stats if configured to. */
    if (snort_show_rule_stats) {
        unsigned int number_rule_files, number_rules, alerts_detected, this_rule_alerts_detected;
        proto_item *stats_ti;
        proto_tree *stats_tree;

        /* Create tree for these items */
        stats_ti = proto_tree_add_string_format(snort_tree, hf_snort_global_stats, tvb, 0, 0, "", "Global Stats");
        proto_item_set_generated(rule_ti);
        stats_tree = proto_item_add_subtree(stats_ti, ett_snort_global_stats);

        /* Get overall number of rules */
        get_global_rule_stats(g_snort_config, alert->sid, &number_rule_files, &number_rules, &alerts_detected,
                              &this_rule_alerts_detected);
        ti = proto_tree_add_uint(stats_tree, hf_snort_global_stats_rule_file_count, tvb, 0, 0, number_rule_files);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(stats_tree, hf_snort_global_stats_rule_count, tvb, 0, 0, number_rules);
        proto_item_set_generated(ti);

        /* Overall alert stats (total, and where this one comes in order) */
        ti = proto_tree_add_uint(stats_tree, hf_snort_global_stats_total_alerts_count, tvb, 0, 0, alerts_detected);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(stats_tree, hf_snort_global_stats_alert_match_number, tvb, 0, 0, alert->overall_match_number);
        proto_item_set_generated(ti);

        if (rule) {
            /* Stats just for this rule (overall, and where this one comes in order) */
            ti = proto_tree_add_uint(stats_tree, hf_snort_global_stats_rule_alerts_count, tvb, 0, 0, this_rule_alerts_detected);
            proto_item_set_generated(ti);
            ti = proto_tree_add_uint(stats_tree, hf_snort_global_stats_rule_match_number, tvb, 0, 0, alert->rule_match_number);
            proto_item_set_generated(ti);

            /* Add a summary to the stats root */
            proto_item_append_text(stats_ti, " (%u rules from %u files, #%u of %u alerts seen (%u/%u for sid %u))",
                                   number_rules, number_rule_files, alert->overall_match_number, alerts_detected,
                                   alert->rule_match_number, this_rule_alerts_detected, alert->sid);
        }
        else {
            /* Add a summary to the stats root */
            proto_item_append_text(stats_ti, " (%u rules from %u files, #%u of %u alerts seen)",
                                   number_rules, number_rule_files, alert->overall_match_number, alerts_detected);
        }
    }
}

/* Look for, and return, any user comment set for this packet.
   Currently used for fetching alerts in the format TraceWrangler can write out to */
static const char *get_user_comment_string(proto_tree *tree)
{
    const char *value = NULL;

    if (tree != NULL) {
        GPtrArray *items = proto_all_finfos(tree);
        if (items) {
            guint i;

            for (i=0; i< items->len; i++) {
                field_info *field = (field_info *)g_ptr_array_index(items,i);
                if (strcmp(field->hfinfo->abbrev, "frame.comment") == 0) {
                    value = fvalue_get_string(&field->value);
                    break;
                }
                /* This is the only item that can come before "frame.comment", so otherwise break out */
                if (strncmp(field->hfinfo->abbrev, "pkt_comment", 11) != 0) {
                    break;
                }
            }
            g_ptr_array_free(items,TRUE);
        }
    }
    return value;
}


/********************************************************************************/
/* Main (post-)dissector function.                                              */
static int
snort_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    Alerts_t *alerts;

    /* If not looking for alerts, return quickly */
    if (pref_snort_alerts_source == FromNowhere) {
        return 0;
    }

    /* Are we looking for alerts in user comments? */
    else if (pref_snort_alerts_source == FromUserComments) {
        /* Look for user comments containing alerts */
        const char *alert_string = get_user_comment_string(tree);
        if (alert_string) {
            alerts = (Alerts_t*)wmem_tree_lookup32(current_session.alerts_tree, pinfo->num);
            if (!alerts) {
                Alert_t alert;
                memset(&alert, 0, sizeof(alert));
                if (snort_parse_user_comment(alert_string, &alert)) {
                    /* Copy the raw alert itself */
                    alert.raw_alert = g_strdup(alert_string);

                    /* See if we can get more info from the parsed config details */
                    fill_alert_config(g_snort_config, &alert);

                    /* Add parsed alert into session->tree */
                    add_alert_to_session_tree(pinfo->num, &alert);
                }
            }
        }
    }
    else {
        /* We expect alerts from Snort.  Pass frame into snort on first pass. */
        if (!pinfo->fd->visited && current_session.working) {
            int write_err = 0;
            gchar *err_info;
            wtap_rec rec;

            /* First time, open current_session.in to write to for dumping into snort with */
            if (!current_session.pdh) {
                wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;
                int open_err;
                gchar *open_err_info;

                /* Older versions of Snort don't support capture file with several encapsulations (like pcapng),
                 * so write in pcap format and hope we have just one encap.
                 * Newer versions of Snort can read pcapng now, but still
                 * write in pcap format; if "newer versions of Snort" really
                 * means "Snort, when using newer versions of libpcap", then,
                 * yes, they can read pcapng, but they can't read pcapng
                 * files with more than one encapsulation type, as libpcap's
                 * API currently can't handle that, so even those "newer
                 * versions of Snort" wouldn't handle multiple encapsulation
                 * types.
                 */
                params.encap = pinfo->rec->rec_header.packet_header.pkt_encap;
                params.snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
                current_session.pdh = wtap_dump_fdopen(current_session.in,
                                                       wtap_pcap_file_type_subtype(),
                                                       WTAP_UNCOMPRESSED,
                                                       &params,
                                                       &open_err,
                                                       &open_err_info);
                if (!current_session.pdh) {
                    /* XXX - report the error somehow? */
                    g_free(open_err_info);
                    current_session.working = FALSE;
                    return 0;
                }
            }

            /* Start with all same values... */
            rec = *pinfo->rec;

            /* Copying packet details into wtp for writing */
            rec.ts = pinfo->abs_ts;

            /* NB: overwriting the time stamp so we can see packet number back if an alert is written for this frame!!!! */
            /* TODO: does this seriously affect snort's ability to reason about time?
             * At least all packets will still be in order... */
            rec.ts.nsecs = pinfo->fd->num * 1000;    /* XXX, max 999'999 frames */

            rec.rec_header.packet_header.caplen = tvb_captured_length(tvb);
            rec.rec_header.packet_header.len = tvb_reported_length(tvb);
            if (current_session.pdh->encap != rec.rec_header.packet_header.pkt_encap) {
                /* XXX, warning! convert? */
            }

            /* Dump frame into snort's stdin */
            if (!wtap_dump(current_session.pdh, &rec, tvb_get_ptr(tvb, 0, tvb_reported_length(tvb)), &write_err, &err_info)) {
                /* XXX - report the error somehow? */
                g_free(err_info);
                current_session.working = FALSE;
                return 0;
            }
            if (!wtap_dump_flush(current_session.pdh, &write_err)) {
                /* XXX - report the error somehow? */
                current_session.working = FALSE;
                return 0;
            }

            /* Give the io channel a chance to deliver alerts.
               TODO: g_main_context_iteration(NULL, FALSE); causes crashes sometimes when Qt events get to execute.. */
        }
    }

    /* Now look up stored alerts for this packet number, and display if found */
    if (current_session.alerts_tree && (alerts = (Alerts_t*)wmem_tree_lookup32(current_session.alerts_tree, pinfo->fd->num))) {
        guint n;

        for (n=0; n < alerts->num_alerts; n++) {
            snort_show_alert(tree, tvb, pinfo, &(alerts->alerts[n]));
        }
    } else {
        /* XXX, here either this frame doesn't generate alerts or we haven't received data from snort (async)
         *
         *      It's problem when user want to filter tree on initial run, or is running one-pass tshark.
         */
    }

    return tvb_reported_length(tvb);
}


/*------------------------------------------------------------------*/
/* Start up Snort. */
static void snort_start(void)
{
    GIOChannel *channel;
    /* int snort_output_id; */
    const gchar *argv[] = {
        pref_snort_binary_filename, "-c", pref_snort_config_filename,
        /* read from stdin */
        "-r", "-",
        /* don't log */
        "-N",
        /* output to console and silence snort */
        "-A", "console", "-q",
        /* normalize time */
        "-y", /* -U", */
        /* Optionally ignore checksum errors */
        "-k", "none",
        NULL
    };

    /* Truncate command to before -k if this pref off */
    if (!snort_ignore_checksum_errors) {
        argv[10] = NULL;
    }

    /* Enable field priming if required. */
    if (snort_alert_in_reassembled_frame) {
        /* Add items we want to try to get to find before we get called.
           For now, just ask for tcp.reassembled_in, which won't be seen
           on the first pass through the packets. */
        GArray *wanted_hfids = g_array_new(FALSE, FALSE, (guint)sizeof(int));
        int id = proto_registrar_get_id_byname("tcp.reassembled_in");
        g_array_append_val(wanted_hfids, id);
        set_postdissector_wanted_hfids(snort_handle, wanted_hfids);
    }

    /* Nothing to do if not enabled, but registered init function gets called anyway */
    if ((pref_snort_alerts_source == FromNowhere) ||
        !proto_is_protocol_enabled(find_protocol_by_id(proto_snort))) {
        return;
    }

    /* Create tree mapping packet_number -> Alerts_t*.  It will get recreated when packet list is reloaded */
    current_session.alerts_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    /* Create afresh the config object by parsing the same file that snort uses */
    if (g_snort_config) {
        delete_config(&g_snort_config);
    }
    create_config(&g_snort_config, pref_snort_config_filename);

    /* Don't run Snort if not configured to */
    if (pref_snort_alerts_source == FromUserComments) {
        return;
    }

    /* Don't start if already running */
    if (current_session.running) {
        return;
    }

    /* Reset global stats */
    reset_global_rule_stats(g_snort_config);

    /* Need to test that we can run snort --version and that config can be parsed... */
    /* Does nothing at present */
    if (!snort_config_ok) {
        /* Can carry on without snort... */
        return;
    }

    /* About to run snort, so check that configured files exist, and that binary could be executed. */
    ws_statb64 binary_stat, config_stat;

    if (ws_stat64(pref_snort_binary_filename, &binary_stat) != 0) {
        snort_debug_printf("Can't run snort - executable '%s' not found\n", pref_snort_binary_filename);
        report_failure("Snort dissector: Can't run snort - executable '%s' not found\n", pref_snort_binary_filename);
        return;
    }

    if (ws_stat64(pref_snort_config_filename, &config_stat) != 0) {
        snort_debug_printf("Can't run snort - config file '%s' not found\n", pref_snort_config_filename);
        report_failure("Snort dissector: Can't run snort - config file '%s' not found\n", pref_snort_config_filename);
        return;
    }

#ifdef S_IXUSR
    if (!(binary_stat.st_mode & S_IXUSR)) {
        snort_debug_printf("Snort binary '%s' is not executable\n", pref_snort_binary_filename);
        report_failure("Snort dissector: Snort binary '%s' is not executable\n", pref_snort_binary_filename);
        return;
    }
#endif

#ifdef _WIN32
    report_failure("Snort dissector: not yet able to launch Snort process under Windows");
    current_session.working = FALSE;
    return;
#endif

    /* Create snort process and set up pipes */
    snort_debug_printf("\nRunning %s with config file %s\n", pref_snort_binary_filename, pref_snort_config_filename);
    if (!g_spawn_async_with_pipes(NULL,          /* working_directory */
                                  (char **)argv,
                                  NULL,          /* envp */
                                  (GSpawnFlags)( G_SPAWN_DO_NOT_REAP_CHILD), /* Leave out G_SPAWN_SEARCH_PATH */
                                  NULL,                   /* child setup - not supported in Windows, so we can't use it */
                                  NULL,                   /* user-data */
                                  &current_session.pid,   /* PID */
                                  &current_session.in,    /* stdin */
                                  &current_session.out,   /* stdout */
                                  &current_session.err,   /* stderr */
                                  NULL))                  /* error */
    {
        current_session.running = FALSE;
        current_session.working = FALSE;
        return;
    }
    else {
        current_session.running = TRUE;
        current_session.working = TRUE;
    }

    /* Setup handler for when process goes away */
    g_child_watch_add(current_session.pid, snort_reaper, &current_session);

    /******************************************************************/
    /* Create channel to get notified of snort alert output on stdout */

    /* Create channel itself */
    channel = g_io_channel_unix_new(current_session.out);
    current_session.channel = channel;

    /* NULL encoding supports binary or whatever the application outputs */
    g_io_channel_set_encoding(channel, NULL, NULL);
    /* Don't buffer the channel (settable because encoding set to NULL). */
    g_io_channel_set_buffered(channel, FALSE);
    /* Set flags */
    /* TODO: could set to be blocking and get sync that way? */
    g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);
    /* Try setting a large buffer here. */
    g_io_channel_set_buffer_size(channel, 256000);

    current_session.buf = NULL;

    /* Set callback for receiving data from the channel */
    g_io_add_watch_full(channel,
                        G_PRIORITY_HIGH,
                        (GIOCondition)(G_IO_IN|G_IO_ERR|G_IO_HUP),
                        snort_fast_output,  /* Callback upon data being written by snort */
                        &current_session,   /* User data */
                        NULL);              /* Destroy notification callback */

    current_session.working = TRUE;
}

/* This is the cleanup routine registered with register_postseq_cleanup_routine() */
static void snort_cleanup(void)
{
    /* Only close if we think its running */
    if (!current_session.running) {
        return;
    }

    /* Close dumper writing into snort's stdin.  This will cause snort to exit! */
    if (current_session.pdh) {
        int write_err;
        gchar *write_err_info;
        if (!wtap_dump_close(current_session.pdh, NULL, &write_err, &write_err_info)) {
            /* XXX - somehow report the error? */
            g_free(write_err_info);
        }
        current_session.pdh = NULL;
    }
}

static void snort_file_cleanup(void)
{
    if (g_snort_config) {
        delete_config(&g_snort_config);
    }

    /* Disable field priming that got enabled in the init routine. */
    set_postdissector_wanted_hfids(snort_handle, NULL);
}

void
proto_reg_handoff_snort(void)
{
    /* N.B. snort self-test here deleted, as I was struggling to get it to
     * work as a non-root user (couldn't read stdin)
     * TODO: could run snort just to get the version number and check the config file is readable?
     * TODO: could make snort config parsing less forgiving and use that as a test? */
}

void
proto_register_snort(void)
{
    static hf_register_info hf[] = {
        { &hf_snort_sid,
            { "Rule SID", "snort.sid", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Snort Rule identifier", HFILL }},
        { &hf_snort_raw_alert,
            { "Raw Alert", "snort.raw-alert", FT_STRING, BASE_NONE, NULL, 0x00,
            "Full text of Snort alert", HFILL }},
        { &hf_snort_rule,
            { "Rule", "snort.rule", FT_STRING, BASE_NONE, NULL, 0x00,
            "Entire Snort rule string", HFILL }},
        { &hf_snort_msg,
            { "Alert Message", "snort.msg", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Description of what the rule detects", HFILL }},
        { &hf_snort_classification,
            { "Alert Classification", "snort.class", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_priority,
            { "Alert Priority", "snort.priority", FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_generator,
            { "Rule Generator", "snort.generator", FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_rev,
            { "Rule Revision", "snort.rev", FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_rule_string,
            { "Rule String", "snort.rule-string", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Full text of Snort rule", HFILL }},
        { &hf_snort_rule_protocol,
            { "Protocol", "snort.protocol", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Protocol name as given in the rule", HFILL }},
        { &hf_snort_rule_filename,
            { "Rule Filename", "snort.rule-filename", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Rules file where Snort rule was parsed from", HFILL }},
        { &hf_snort_rule_line_number,
            { "Line number within rules file where rule was parsed from", "snort.rule-line-number", FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_rule_ip_var,
            { "IP variable", "snort.rule-ip-var", FT_NONE, BASE_NONE, NULL, 0x00,
            "IP variable used in rule", HFILL }},
        { &hf_snort_rule_port_var,
            { "Port variable used in rule", "snort.rule-port-var", FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_reassembled_in,
            { "Reassembled frame where alert is shown", "snort.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_reassembled_from,
            { "Segment where alert was triggered", "snort.reassembled_from", FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},
        { &hf_snort_content,
            { "Content", "snort.content", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Snort content field", HFILL }},
        { &hf_snort_uricontent,
            { "URI Content", "snort.uricontent", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Snort URI content field", HFILL }},
        { &hf_snort_pcre,
            { "PCRE", "snort.pcre", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Perl Compatible Regular Expression", HFILL }},
        { &hf_snort_reference,
            { "Reference", "snort.reference", FT_STRINGZ, BASE_NONE, NULL, 0x00,
            "Web reference provided as part of rule", HFILL }},

        /* Global stats */
        { &hf_snort_global_stats,
            { "Global Stats", "snort.global-stats", FT_STRING, BASE_NONE, NULL, 0x00,
            "Global statistics for rules and alerts", HFILL }},
        { &hf_snort_global_stats_rule_file_count,
            { "Number of rule files", "snort.global-stats.rule-file-count", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Total number of rules files found in Snort config", HFILL }},
        { &hf_snort_global_stats_rule_count,
            { "Number of rules", "snort.global-stats.rule-count", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Total number of rules found in Snort config", HFILL }},
        { &hf_snort_global_stats_total_alerts_count,
            { "Number of alerts detected", "snort.global-stats.total-alerts", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Total number of alerts detected in this capture", HFILL }},
        { &hf_snort_global_stats_alert_match_number,
            { "Match number", "snort.global-stats.match-number", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Number of match for this alert among all alerts", HFILL }},

        { &hf_snort_global_stats_rule_alerts_count,
            { "Number of alerts for this rule", "snort.global-stats.rule.alerts-count", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Number of alerts detected for this rule", HFILL }},
        { &hf_snort_global_stats_rule_match_number,
            { "Match number for this rule", "snort.global-stats.rule.match-number", FT_UINT32, BASE_DEC, NULL, 0x00,
            "Number of match for this alert among those for this rule", HFILL }}
    };
    static gint *ett[] = {
        &ett_snort,
        &ett_snort_rule,
        &ett_snort_global_stats
    };

    static const enum_val_t alerts_source_vals[] = {
        {"from-nowhere",            "Not looking for Snort alerts",        FromNowhere},
        {"from-running-snort",      "From running Snort",                  FromRunningSnort},
        {"from-user-comments",      "From user packet comments",           FromUserComments},
        {NULL, NULL, -1}
    };

    static ei_register_info ei[] = {
        { &ei_snort_alert, { "snort.alert.expert", PI_SECURITY, PI_WARN, "Snort alert detected", EXPFILL }},
        { &ei_snort_content_not_matched, { "snort.content.not-matched", PI_PROTOCOL, PI_NOTE, "Failed to find content field of alert in frame", EXPFILL }},
    };

    expert_module_t* expert_snort;

    module_t *snort_module;

    proto_snort = proto_register_protocol("Snort Alerts", "Snort", "snort");

    proto_register_field_array(proto_snort, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Expert info */
    expert_snort = expert_register_protocol(proto_snort);
    expert_register_field_array(expert_snort, ei, array_length(ei));

    snort_module = prefs_register_protocol(proto_snort, NULL);

    prefs_register_obsolete_preference(snort_module, "enable_snort_dissector");

    prefs_register_enum_preference(snort_module, "alerts_source",
        "Source of Snort alerts",
        "Set whether dissector should run Snort and pass frames into it, or read alerts from user packet comments",
        &pref_snort_alerts_source, alerts_source_vals, FALSE);

    prefs_register_filename_preference(snort_module, "binary",
                                       "Snort binary",
                                       "The name of the snort binary file to run",
                                       &pref_snort_binary_filename, FALSE);
    prefs_register_filename_preference(snort_module, "config",
                                       "Configuration filename",
                                       "The name of the file containing the snort IDS configuration.  Typically snort.conf",
                                       &pref_snort_config_filename, FALSE);

    prefs_register_bool_preference(snort_module, "show_rule_set_stats",
                                   "Show rule stats in protocol tree",
                                   "Whether or not information about the rule set and detected alerts should "
                                   "be shown in the tree of every snort PDU tree",
                                   &snort_show_rule_stats);
    prefs_register_bool_preference(snort_module, "show_alert_expert_info",
                                   "Show alerts in expert info",
                                   "Whether or not expert info should be used to highlight fired alerts",
                                   &snort_show_alert_expert_info);
    prefs_register_bool_preference(snort_module, "show_alert_in_reassembled_frame",
                                   "Try to show alerts in reassembled frame",
                                   "Attempt to show alert in reassembled frame where possible.  Note that this won't work during live capture",
                                   &snort_alert_in_reassembled_frame);
    prefs_register_bool_preference(snort_module, "ignore_checksum_errors",
                                   "Tell Snort to ignore checksum errors",
                                   "When enabled, will run Snort with '-k none'",
                                   &snort_ignore_checksum_errors);


    snort_handle = create_dissector_handle(snort_dissector, proto_snort);

    register_init_routine(snort_start);
    register_postdissector(snort_handle);

    /* Callback to make sure we cleanup dumper being used to deliver packets to snort (this will tsnort). */
    register_postseq_cleanup_routine(snort_cleanup);
    /* Callback to allow us to delete snort config */
    register_cleanup_routine(snort_file_cleanup);
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
