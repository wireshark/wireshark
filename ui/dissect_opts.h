/* dissect_opts.h
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

#define LONGOPT_DISABLE_PROTOCOL  LONGOPT_BASE_DISSECTOR+1
#define LONGOPT_ENABLE_HEURISTIC  LONGOPT_BASE_DISSECTOR+2
#define LONGOPT_DISABLE_HEURISTIC LONGOPT_BASE_DISSECTOR+3
#define LONGOPT_ENABLE_PROTOCOL   LONGOPT_BASE_DISSECTOR+4

/*
 * Options for dissecting common to all dissecting programs.
 */
#define LONGOPT_DISSECT_COMMON \
    {"disable-protocol", required_argument, NULL, LONGOPT_DISABLE_PROTOCOL }, \
    {"enable-heuristic", required_argument, NULL, LONGOPT_ENABLE_HEURISTIC }, \
    {"disable-heuristic", required_argument, NULL, LONGOPT_DISABLE_HEURISTIC }, \
    {"enable-protocol", required_argument, NULL, LONGOPT_ENABLE_PROTOCOL }, \

#define OPTSTRING_DISSECT_COMMON \
    "d:K:nN:t:u:"

/** Capture options coming from user interface */
typedef struct dissect_options_tag {
    ts_type time_format;
    GSList *enable_protocol_slist; //enable protocols that are disabled by default
    GSList *disable_protocol_slist;
    GSList *enable_heur_slist;
    GSList *disable_heur_slist;
} dissect_options;

extern dissect_options global_dissect_options;

/* initialize the dissect_options with some reasonable values */
extern void
dissect_opts_init(void);

/*
 * Handle a command line option.
 * Returns TRUE if the option is valid, FALSE if not; an error message
 * is reported with cmdarg_err() if it's not valid.
 */
extern gboolean
dissect_opts_handle_opt(int opt, char *optarg_str_p);

/*
 * Set up disabled protocols and enabled/disabled heuristic protocols
 * as per specified command-line options.
 *
 * Returns TRUE if all specified heuristic protocols exist, FALSE
 * otherwise.
 */
extern gboolean
setup_enabled_and_disabled_protocols(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* dissect_opts.h */

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
