/** @file
 *
 * Common command line handling between GUIs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COMMANDLINE_H__
#define __COMMANDLINE_H__

#include "cfile.h" /* For search_direction */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern int commandline_early_options(int argc, char *argv[]);


extern const struct ws_option* commandline_long_options(void);

extern const char* commandline_optstring(void);

extern void commandline_override_prefs(int argc, char *argv[], bool opt_reset);

extern void commandline_other_options(int argc, char *argv[], bool opt_reset);

extern void commandline_options_drop(const char *module_name, const char *pref_name);

extern void commandline_options_reapply(void);

extern void commandline_options_apply_extcap(void);

extern void commandline_options_free(void);

extern bool commandline_is_full_screen(void);

extern char* commandline_get_cf_name(void);

extern char* commandline_get_rfilter(void);

extern char* commandline_get_dfilter(void);

extern char* commandline_get_jfilter(void);

extern search_direction commandline_get_jump_direction(void);

extern uint32_t commandline_get_go_to_packet(void);

#ifdef HAVE_LIBPCAP
extern bool commandline_is_start_capture(void);

extern bool commandline_is_quit_after_capture(void);

extern char* commandline_get_first_capture_comment(void);

extern int commandline_get_caps_queries(void);

extern GPtrArray* commandline_get_capture_comments(void);

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COMMANDLINE_H__ */
