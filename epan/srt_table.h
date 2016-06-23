/* srt_table.h
 * GUI independent helper routines common to all service response time (SRT) taps.
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

#ifndef __SRT_TABLE_H__
#define __SRT_TABLE_H__

#include "tap.h"
#include "timestats.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Procedure data */
typedef struct _srt_procedure_t {
	int  proc_index;
	timestat_t stats;   /**< stats */
	char *procedure;   /**< column entries */
} srt_procedure_t;

/** Statistics table */
typedef struct _srt_stat_table {
	const char *name;   /**< table name */
	const char *short_name;   /**< tab name */
	char *filter_string;        /**< append procedure number (%d) to this string
				to create a display filter */
	int num_procs;              /**< number of elements on procedures array */
	const char *proc_column_name;   /**< procedure column name (if different from default) */
	srt_procedure_t *procedures;/**< the procedures array */
    void* table_specific_data; /** any dissector/table specific data needed for packet filtering */
} srt_stat_table;

struct register_srt;
struct _srt_data_t;
typedef void (*srt_gui_init_cb)(srt_stat_table* rst, void* gui_data); /* GTK+ only? */
typedef void (*srt_gui_reset_cb)(srt_stat_table* rst, void* gui_data);  /* GTK+ only? */
typedef void (*srt_gui_free_cb)(srt_stat_table* rst, void* gui_data);  /* GTK+ only? */
typedef void (*srt_proc_table_cb)(srt_stat_table* rst, int indx, struct _srt_data_t* gui_data);
typedef void (*srt_init_cb)(struct register_srt* srt, GArray* srt_array, srt_gui_init_cb gui_callback, void* gui_data);
typedef guint (*srt_param_handler_cb)(struct register_srt* srt, const char* opt_arg, char** err);

/** tap data
 */
typedef struct _srt_data_t {
    GArray      *srt_array;      /**< array of srt_stat_table */
    void        *user_data;       /**< "GUI" specifics (if necessary) */
} srt_data_t;

/** Structure for information about a registered service response table */
typedef struct register_srt register_srt_t;

/** Register the service response time table for the srt windows.
 *
 * @param proto_id is the protocol with conversation
 * @param tap_listener string for register_tap_listener (NULL to just use protocol name)
 * @param max_tables maximum number of tables
 * @param srt_packet_func the tap processing function
 * @param init_cb initialize dissector SRT function
 * @param param_cb handles dissection of parameters to optional arguments of tap string
 */
WS_DLL_PUBLIC void register_srt_table(const int proto_id, const char* tap_listener, int max_tables,
                                       tap_packet_cb srt_packet_func, srt_init_cb init_cb, srt_param_handler_cb param_cb);

/** Get protocol ID from SRT
 *
 * @param srt Registered SRT
 * @return protocol id of SRT
 */
WS_DLL_PUBLIC int get_srt_proto_id(register_srt_t* srt);

/** Get string for register_tap_listener call.  Typically just dissector name
 *
 * @param srt Registered SRT
 * @return string for register_tap_listener call
 */
WS_DLL_PUBLIC const char* get_srt_tap_listener_name(register_srt_t* srt);

/** Get maximum number of tables from SRT
 *
 * @param srt Registered SRT
 * @return maximum number of tables of SRT
 */
WS_DLL_PUBLIC int get_srt_max_tables(register_srt_t* srt);

/** Get tap function handler from SRT
 *
 * @param srt Registered SRT
 * @return tap function handler of SRT
 */
WS_DLL_PUBLIC tap_packet_cb get_srt_packet_func(register_srt_t* srt);

/** Set parameter data from SRT parsed from tap string. Data will be
 * freed on tap reset
 *
 * @param srt Registered SRT
 * @param data Parameter data
 */
WS_DLL_PUBLIC void set_srt_table_param_data(register_srt_t* srt, void* data);

/** Get parameter data from SRT
 *
 * @param srt Registered SRT
 * @return Parameter data
 */
WS_DLL_PUBLIC void* get_srt_table_param_data(register_srt_t* srt);

/** Get SRT table by its dissector name
 *
 * @param name dissector name to fetch.
 * @return SRT table pointer or NULL.
 */
WS_DLL_PUBLIC register_srt_t* get_srt_table_by_name(const char* name);

/** Free the srt table data.
 *
 * @param rst the srt table
 */
WS_DLL_PUBLIC void free_srt_table_data(srt_stat_table *rst);

/** Free the srt table data.
 *
 * @param srt Registered SRT
 * @param srt_array SRT table array
 * @param gui_callback optional callback from GUI
 * @param callback_data callback data needed for GUI
 */
WS_DLL_PUBLIC void free_srt_table(register_srt_t *srt, GArray* srt_array, srt_gui_free_cb gui_callback, void *callback_data);

/** Reset ALL tables in the srt.
 *
 * @param srt_array SRT table array
 * @param gui_callback optional callback from GUI
 * @param callback_data callback data needed for GUI
 */
WS_DLL_PUBLIC void reset_srt_table(GArray* srt_array, srt_gui_reset_cb gui_callback, void *callback_data);

/** Interator to walk srt tables and execute func
 * Used for initialization
 *
 * @param func action to be performed on all converation tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void srt_table_iterate_tables(GFunc func, gpointer user_data);

/** Return filter used for register_tap_listener
 *
 * @param srt Registered SRT
 * @param opt_arg passed in opt_arg from GUI
 * @param filter returned filter string to be used for registering tap
 * @param err returned error if opt_arg string can't be successfully parsed. Caller must free memory
 */
WS_DLL_PUBLIC void srt_table_get_filter(register_srt_t* srt, const char *opt_arg, const char **filter, char** err);

/** "Common" initialization function for all GUIs
 *
 * @param srt Registered SRT
 * @param srt_array SRT table array
 * @param gui_callback optional callback from GUI
 * @param callback_data callback data needed for GUI
 */
WS_DLL_PUBLIC void srt_table_dissector_init(register_srt_t* srt, GArray* srt_array, srt_gui_init_cb gui_callback, void *callback_data);

/** Helper function to get tap string name
 * Caller is responsible for freeing returned string
 *
 * @param srt Registered SRT
 * @return SRT tap string
 */
WS_DLL_PUBLIC gchar* srt_table_get_tap_string(register_srt_t* srt);

/** Init an srt table data structure.
 *
 * @param name the table name
 * @param short_name the name used in a tab display
 * @param srt_array the srt table array to add to
 * @param num_procs number of procedures
 * @param proc_column_name procedure column name (if different from "Procedure")
 * @param filter_string table filter string or NULL
 * @param gui_callback optional GUI callback
 * @param gui_data GUI content data
 * @param table_specific_data Table specific data
 * @return newly created srt_stat_table
 */
WS_DLL_PUBLIC srt_stat_table* init_srt_table(const char *name, const char *short_name, GArray *srt_array, int num_procs, const char* proc_column_name,
                const char *filter_string, srt_gui_init_cb gui_callback, void* gui_data, void* table_specific_data);

/** Init an srt table row data structure.
 *
 * @param rst the srt table
 * @param proc_index number of procedure
 * @param procedure the procedures name
 */
WS_DLL_PUBLIC void init_srt_table_row(srt_stat_table *rst, int proc_index, const char *procedure);

/** Add srt response to table row data.
 *
 * @param rst the srt table
 * @param proc_index number of procedure
 * @param req_time the time of the corresponding request
 * @param pinfo current packet info
 */
WS_DLL_PUBLIC void add_srt_table_data(srt_stat_table *rst, int proc_index, const nstime_t *req_time, packet_info *pinfo);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SRT_TABLE_H__ */

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
