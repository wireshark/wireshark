/* echld-util.h
 *  utility for echld
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright (c) 2013 by Luis Ontanon <luis@ontanon.org>
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
#ifndef __ECHLD_UTIL
#define __ECHLD_UTIL

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*echld_close_cb_t)(const char* error, void* data);
WS_DLL_PUBLIC echld_state_t echld_close(int child_id, echld_close_cb_t pcb, void* cb_data);


typedef void (*echld_ping_cb_t)(long usec, void* data);
WS_DLL_PUBLIC echld_state_t echld_ping(int child_id, echld_ping_cb_t pcb, void* cb_data);

typedef void (*echld_param_cb_t)(const char* param, const char* value, const char* error, void* data);
WS_DLL_PUBLIC echld_state_t echld_get_param(int chld_id, const char* param, echld_param_cb_t cb, void* cb_data);
WS_DLL_PUBLIC echld_state_t echld_set_param(int chld_id, const char* param, const char* value, echld_param_cb_t acb, void* cb_data);

typedef void (*echild_get_packet_summary_cb_t)(char* summary, void* data);
WS_DLL_PUBLIC echld_state_t echld_open_file(int child_id, const char* filename,echild_get_packet_summary_cb_t,void*);



WS_DLL_PUBLIC echld_state_t echld_open_interface(int child_id, const char* intf_name, const char* params);
WS_DLL_PUBLIC echld_state_t echld_start_capture(int child_id, echild_get_packet_summary_cb_t);
WS_DLL_PUBLIC echld_state_t echld_stop_capture(int child_id);

typedef void (*echild_get_packets_cb)(char* tree_text,void* data);
typedef void (*echild_get_buffer_cb)(char* buffer_text, void* data);
WS_DLL_PUBLIC echld_state_t echld_get_packets_range(int child_id, const char* range, echild_get_packets_cb, echild_get_buffer_cb, void* data);

#ifdef __cplusplus
};
#endif

#endif
