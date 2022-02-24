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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern void commandline_print_usage(gboolean for_help_option);

extern void commandline_early_options(int argc, char *argv[]);

/* Command-line options that don't have direct API calls to handle the data */
typedef struct commandline_param_info
{
#ifdef HAVE_LIBPCAP
    gboolean list_link_layer_types;
    gboolean list_timestamp_types;
    gboolean start_capture;
    gboolean quit_after_cap;

    /*
     * We currently don't support this as a way to add file comments
     * to an existing capture file in Wireshark; we only support it
     * for adding comments to live captures.
     */
    GPtrArray *capture_comments;
#endif
    e_prefs *prefs_p;
    search_direction jump_backwards;
    guint32 go_to_packet;
    gchar* jfilter;
    gchar* cf_name;
    gchar* rfilter;
    gchar* dfilter;
    gboolean full_screen;
    GSList *user_opts;

} commandline_param_info_t;

extern void commandline_other_options(int argc, char *argv[], gboolean opt_reset);

extern void commandline_options_drop(const char *module_name, const char *pref_name);

extern void commandline_options_reapply(void);

extern void commandline_options_free(void);

extern commandline_param_info_t global_commandline_info;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COMMANDLINE_H__ */
