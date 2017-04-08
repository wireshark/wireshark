/* dissect_opts.h
 * Dissection options (parameters that affect dissection)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
 *
 * For long options with no corresponding short options, we define values
 * outside the range of ASCII graphic characters, make that the last
 * component of the entry for the long option, and have a case for that
 * option in the switch statement.
 *
 * We also pick values >= 4096, so as not to collide with capture options,
 * and <= 65535, so as to leave values > 65535 for options specific to a
 * program.
 */

/*
 * Non-capture long-only options should start here, to avoid collision
 * with capture options.
 */
#define LONGOPT_DISABLE_PROTOCOL  4096
#define LONGOPT_ENABLE_HEURISTIC  4097
#define LONGOPT_DISABLE_HEURISTIC 4098
#define LONGOPT_ENABLE_PROTOCOL   4099

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
