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

/** @brief Long option value for disabling a protocol */
#define LONGOPT_DISABLE_PROTOCOL      LONGOPT_BASE_DISSECTOR+1
/** @brief Long option value for enabling a heuristic */
#define LONGOPT_ENABLE_HEURISTIC      LONGOPT_BASE_DISSECTOR+2
/** @brief Long option value for disabling a heuristic */
#define LONGOPT_DISABLE_HEURISTIC     LONGOPT_BASE_DISSECTOR+3
/** @brief Long option value for enabling a protocol */
#define LONGOPT_ENABLE_PROTOCOL       LONGOPT_BASE_DISSECTOR+4
/** @brief Long option value for exclusively enabling specified protocols */
#define LONGOPT_ONLY_PROTOCOLS        LONGOPT_BASE_DISSECTOR+5
/** @brief Long option value for disabling all protocols */
#define LONGOPT_DISABLE_ALL_PROTOCOLS LONGOPT_BASE_DISSECTOR+6

/**
 * @brief Options for dissecting common to all dissecting programs.
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

/**
 * @brief Short options string for dissecting common to all dissecting programs.
 */
#define OPTSTRING_DISSECT_COMMON \
    "d:K:nN:R:t:u:Y:"

/**
 * @brief Capture options coming from user interface.
 */
typedef struct dissect_options_tag {
    ts_type time_format;            /**< The time format to use for packet timestamps. */
    ts_precision time_precision;    /**< The time precision (e.g., microseconds, nanoseconds). */
    GSList *enable_protocol_slist;  /**< List of protocols to enable (that are disabled by default). */
    GSList *disable_protocol_slist; /**< List of protocols to explicitly disable. */
    GSList *enable_heur_slist;      /**< List of heuristic dissectors to enable. */
    GSList *disable_heur_slist;     /**< List of heuristic dissectors to explicitly disable. */
} dissect_options;

/**
 * @brief Global dissection options instance.
 */
extern dissect_options global_dissect_options;

/**
 * @brief Handle a command line option.
 *
 * An error message is reported with cmdarg_err() if it's not valid.
 *
 * @param opt The option character or integer value.
 * @param optarg_str_p The string argument provided with the option, if any.
 * @return True if the option is valid, false if not.
 */
extern bool
dissect_opts_handle_opt(int opt, char *optarg_str_p);

/**
 * @brief Set up disabled protocols and enabled/disabled heuristic protocols
 * as per specified command-line options.
 *
 * @return True if all specified heuristic protocols exist, false otherwise.
 */
extern bool
setup_enabled_and_disabled_protocols(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* dissect_opts.h */
