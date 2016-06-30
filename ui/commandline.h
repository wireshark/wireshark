/* commandline.h
 * Common command line handling between GUIs
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

#ifndef __COMMANDLINE_H__
#define __COMMANDLINE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern void commandline_print_usage(gboolean for_help_option);

extern void commandline_early_options(int argc, char *argv[], 
    GString *comp_info_str, GString *runtime_info_str);

/* Command-line options that don't have direct API calls to handle the data */
typedef struct commandline_param_info
{
#ifdef HAVE_LIBPCAP
    gboolean list_link_layer_types;
    gboolean start_capture;
    gboolean quit_after_cap;
#endif
    e_prefs *prefs_p;
    search_direction jump_backwards;
    guint go_to_packet;
    gchar* jfilter;
    gchar* cf_name;
    gchar* rfilter;
    gchar* dfilter;
    ts_type time_format;
    GSList *disable_protocol_slist;
    GSList *enable_heur_slist;
    GSList *disable_heur_slist;

} commandline_param_info_t;

extern void commandline_other_options(int argc, char *argv[], gboolean opt_reset);

extern commandline_param_info_t global_commandline_info;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COMMANDLINE_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
