/* rtd_table.h
 * GUI independent helper routines common to all Response Time Delay (RTD) taps.
 * Based on srt_table.h
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

#ifndef __RTD_TABLE_H__
#define __RTD_TABLE_H__

#include "tap.h"
#include "timestats.h"
#include "value_string.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _rtd_timestat {
	guint num_timestat;              /**< number of elements on rtd array */
	timestat_t* rtd;
	guint32 open_req_num;
	guint32 disc_rsp_num;
	guint32 req_dup_num;
	guint32 rsp_dup_num;
} rtd_timestat;

/** Statistics table */
typedef struct _rtd_stat_table {
	char *filter;
	guint num_rtds;              /**< number of elements on time_stats array */
	rtd_timestat* time_stats;
} rtd_stat_table;

/** tap data
 */
typedef struct _rtd_data_t {
	rtd_stat_table  stat_table;  /**< RTD table data */
	void        *user_data;       /**< "GUI" specifics (GTK+ only) */
} rtd_data_t;

/** Structure for information about a registered service response table */
struct register_rtd;
typedef struct register_rtd register_rtd_t;

typedef void (*rtd_gui_init_cb)(rtd_stat_table* rtd, void* gui_data);
typedef void (*rtd_gui_reset_cb)(rtd_stat_table* rtd, void* gui_data); /* GTK+ only. */
typedef void (*rtd_gui_free_cb)(rtd_stat_table* rtd, void* gui_data); /* GTK+ only. */
typedef void (*rtd_init_cb)(struct register_rtd* rtd, rtd_gui_init_cb gui_callback, void* gui_data); /* GTK+ only. */
typedef void (*rtd_filter_check_cb)(const char *opt_arg, const char **filter, char** err);

/** Register the response time delay table.
 *
 * @param proto_id is the protocol with conversation
 * @param tap_listener string for register_tap_listener (NULL to just use protocol name)
 * @param num_tables number of tables
 * @param num_timestats number of timestamps in the table
 * @param vs_type value_string for the stat types
 * @param rtd_packet_func the tap processing function
 * @param filter_check_cb callback for verification of filter or other dissector checks
 */
WS_DLL_PUBLIC void register_rtd_table(const int proto_id, const char* tap_listener, guint num_tables, guint num_timestats, const value_string* vs_type,
                                      tap_packet_cb rtd_packet_func, rtd_filter_check_cb filter_check_cb);

/** Get protocol ID from RTD
 *
 * @param rtd Registered RTD
 * @return protocol id of RTD
 */
WS_DLL_PUBLIC int get_rtd_proto_id(register_rtd_t* rtd);

/** Get string for register_tap_listener call. Typically just dissector name
 *
 * @param rtd Registered RTD
 * @return string for register_tap_listener call
 */
WS_DLL_PUBLIC const char* get_rtd_tap_listener_name(register_rtd_t* rtd);

/** Get tap function handler from RTD
 *
 * @param rtd Registered RTD
 * @return tap function handler of RTD
 */
WS_DLL_PUBLIC tap_packet_cb get_rtd_packet_func(register_rtd_t* rtd);

/** Get the number of RTD tables
 *
 * @param rtd Registered RTD
 * @return The number of registered tables.
 */
WS_DLL_PUBLIC guint get_rtd_num_tables(register_rtd_t* rtd);

/** Get value_string used for RTD
 *
 * @param rtd Registered RTD
 * @return value_string of RTD
 */
WS_DLL_PUBLIC const value_string* get_rtd_value_string(register_rtd_t* rtd);

/** Get RTD table by its dissector name
 *
 * @param name dissector name to fetch.
 * @return RTD table pointer or NULL.
 */
WS_DLL_PUBLIC register_rtd_t* get_rtd_table_by_name(const char* name);

/** Free the RTD table data.
 *
 * @param table RTD stat table array
 * @param gui_callback optional callback from GUI
 * @param callback_data callback data needed for GUI
 */
WS_DLL_PUBLIC void free_rtd_table(rtd_stat_table* table, rtd_gui_free_cb gui_callback, void *callback_data);

/** Reset table data in the RTD.
 *
 * @param table RTD table
 * @param gui_callback optional callback from GUI
 * @param callback_data callback data needed for GUI
 */
WS_DLL_PUBLIC void reset_rtd_table(rtd_stat_table* table, rtd_gui_reset_cb gui_callback, void *callback_data);

/** Interator to walk RTD tables and execute func
 * Used for initialization
 *
 * @param func action to be performed on all converation tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void rtd_table_iterate_tables(GFunc func, gpointer user_data);

/** Return filter used for register_tap_listener
 *
 * @param rtd Registered RTD
 * @param opt_arg passed in opt_arg from GUI
 * @param filter returned filter string to be used for registering tap
 * @param err returned error if opt_arg string can't be successfully handled. Caller must free memory
 */
WS_DLL_PUBLIC void rtd_table_get_filter(register_rtd_t* rtd, const char *opt_arg, const char **filter, char** err);

/** "Common" initialization function for all GUIs
 *
 * @param rtd Registered RTD
 * @param table RTD table
 * @param gui_callback optional GUI callback function
 * @param callback_data optional GUI callback data
 */
WS_DLL_PUBLIC void rtd_table_dissector_init(register_rtd_t* rtd, rtd_stat_table* table, rtd_gui_init_cb gui_callback, void *callback_data);

/** Helper function to get tap string name
 * Caller is responsible for freeing returned string
 *
 * @param rtd Registered RTD
 * @return RTD tap string
 */
WS_DLL_PUBLIC gchar* rtd_table_get_tap_string(register_rtd_t* rtd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTD_TABLE_H__ */

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
