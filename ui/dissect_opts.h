/** @file
 *
 * Dissection options (parameters that affect dissection)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/** @file
 *
 *  Dissection options (parameters that affect dissection)
 *
 */

#ifndef __DISSECT_OPTS_H__
#define __DISSECT_OPTS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Long options.
 * We do not currently have long options corresponding to all short
 * options; we should probably pick appropriate option names for them.
 */

#define LONGOPT_DISABLE_PROTOCOL      LONGOPT_BASE_DISSECTOR+1
#define LONGOPT_ENABLE_HEURISTIC      LONGOPT_BASE_DISSECTOR+2
#define LONGOPT_DISABLE_HEURISTIC     LONGOPT_BASE_DISSECTOR+3
#define LONGOPT_ENABLE_PROTOCOL       LONGOPT_BASE_DISSECTOR+4
#define LONGOPT_ONLY_PROTOCOLS        LONGOPT_BASE_DISSECTOR+5
#define LONGOPT_DISABLE_ALL_PROTOCOLS LONGOPT_BASE_DISSECTOR+6

/*
 * Options for dissecting common to all dissecting programs.
 */
#define LONGOPT_DISSECT_COMMON \
    {"disable-protocol", ws_required_argument, NULL, LONGOPT_DISABLE_PROTOCOL }, \
    {"enable-heuristic", ws_required_argument, NULL, LONGOPT_ENABLE_HEURISTIC }, \
    {"disable-heuristic", ws_required_argument, NULL, LONGOPT_DISABLE_HEURISTIC }, \
    {"enable-protocol", ws_required_argument, NULL, LONGOPT_ENABLE_PROTOCOL }, \
    {"only-protocols", ws_required_argument, NULL, LONGOPT_ONLY_PROTOCOLS }, \
    {"disable-all-protocols", ws_no_argument, NULL, LONGOPT_DISABLE_ALL_PROTOCOLS }, \
    {"read-filter", ws_required_argument, NULL, 'R' }, \
    {"display-filter", ws_required_argument, NULL, 'Y' }, \

#define OPTSTRING_DISSECT_COMMON \
    "d:K:nN:R:t:u:Y:"

/** Capture options coming from user interface */
typedef struct dissect_options_tag {
    ts_type time_format;
    ts_precision time_precision;
    GSList *enable_protocol_slist; //enable protocols that are disabled by default
    GSList *disable_protocol_slist;
    GSList *enable_heur_slist;
    GSList *disable_heur_slist;
} dissect_options;

extern dissect_options global_dissect_options;

/*
 * Handle a command line option.
 * Returns true if the option is valid, false if not; an error message
 * is reported with cmdarg_err() if it's not valid.
 */
extern bool
dissect_opts_handle_opt(int opt, char *optarg_str_p);

/*
 * Set up disabled protocols and enabled/disabled heuristic protocols
 * as per specified command-line options.
 *
 * Returns true if all specified heuristic protocols exist, false
 * otherwise.
 */
extern bool
setup_enabled_and_disabled_protocols(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* dissect_opts.h */
