/* echld_child.h
 *  epan working child API internals
 *
 * $Id$
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

#ifndef __ECHLD_H
#define __ECHLD_H


typedef enum _echld_msg_type_t {
	ECHLD_ERROR, /* Child <-> Parent */
	ECHLD_HELLO,

	ECHLD_CLOSE_CHILD, /* Parent -> Child  */
	ECHLD_CLOSING, /* Child -> Parent */

	ECHLD_CHDIR,  /* Parent -> Child  : change dir */
	ECHLD_CWD, /* Child -> Parent */
	
	ECHLD_LIST_FILES, /* Parent -> Child  */
	ECHLD_FILE_INFO, /* Parent -> Child  */

	ECHLD_OPEN_FILE, /* Parent -> Child  */
	ECHLD_FILE_OPENED, /* Child -> Parent */

	ECHLD_LIST_INTERFACES, /* Parent -> Child  */
	ECHLD_INTERFACE_INFO, /* Child -> Parent */

	ECHLD_OPEN_INTERFACE,  /* Parent -> Child  */
	ECHLD_INTERFACE_OPENED, /* Child -> Parent */

	ECHLD_START_CAPTURE,  /* Parent -> Child  */
	ECHLD_CAPTURE_STARTED,  /* Child -> Parent */

	ECHLD_STOP_CAPTURE,  /* Parent -> Child  */
	ECHLD_CAPTURE_STOPPED,  /* Child -> Parent */

	ECHLD_PACKET_SUM, /* Child -> Parent */

	ECHLD_GET_PACKETS, /* Parent -> Child  */
	ECHLD_PACKET, /* Child -> Parent */
	ECHLD_BUFFER, /* Child -> Parent */

	ECHLD_ADD_NOTE, /* Parent -> Child  */
	ECHLD_NOTE_ADDED, /* Child -> Parent */
	
	ECHLD_SET_FILTER, /* Parent -> Child  */
	ECHLD_PACKET_LIST, /* Child -> Parent */
	
	ECHLD_SAVE_FILE, /* Parent -> Child  */
	ECHLD_FILE_SAVED, /* Parent -> Child  */

	ECHLD_EOF, /* Child -> Parent  */

	ECHLD_PING, /* Parent <-> Child  */
	ECHLD_PONG, /* Parent <-> Child  */

} echld_msg_type_t;

typedef enum _echld_state_t {	
	ECHLD_OK,
	ECHLD_KO
} echld_state_t;

echld_state_t (echld_msg_cb_t*)(echld_msg_type_t type, guchar*, size_t len, void* data);
echld_state_t (echld_iter_cb_t*)(echld_t* c, void* data);

typedef struct echld_resp_actions_t {
	echld_resp_type_t type,
	echld_cb_t action,
};

typedef struct _echld_child echld_t;

typedef enum _echld_encoding {
	ECHLD_CHLD_ENC_PSML,
	ECHLD_CHLD_ENC_TXT,
	ECHLD_CHLD_ENC_JSON
} echld_encoding_t;

/* will initialize epan registering protocols and taps */
int echld_initialize(echld_encoding_t enc);

/* cleans up (?) echld and exits */
int echld_terminate(void);

/* new worker process */
echld_t* echld_new(void* child_data);
void* echld_get_data(echld_t* c);
void echld_set_data(echld_t* c, void* data);

void echld_send_msg(echld_t* c, echld_msg_type_t snd_type, guchar* snd_buf, size_t snd_buf_len, echld_cb_t resp_cb, void* cb_data);

int echld_msg_hdl_attach(echld_t* c, echld_msg_type_t, echld_msg_cb_t resp_cb, void* msg_data);
int echld_get_attached_msg_hdl(echld_t* c, int id, echld_msg_type_t*, echld_msg_cb_t*, void**);
void* echld_get_attached_msg_hdl_data(echld_t* c, int id);
echld_msg_cb_t echld_get_attached_msg_hdl_cb(echld_t* c, int id);
echld_msg_type_t echld_get_attached_msg_hdl_type(echld_t* c, int id);

int echld_msg_hdl_detach(echld_t* c, int id); 

int echld_parent_msg_attach(echld_t* c, echld_msg_type_t, echld_msg_cb_t resp_cb, void* resp_data);
int echld_parent_msg_detach(echld_t* c, int id);


const echld_t** echld_parent_get_children();
#define echld_foreach(C, cb, data) do {echld_t** c = C; for(;*c;c++) cb(*c,data);  } while(0)
#define echld_foreach_child(cb,data) echld_foreach(echld_parent_get_children(),cb,data)


/* message encoders */
int echld_enc_error(guint8*, size_t , int err, const char* text);
int echld_enc_close_child(guint8*, size_t, int mode);
/* echld_closing */
int echld_enc_chdir(guint8*, size_t, const char* new_dir);
int echld_enc_cwd(guint8*, size_t, const char* cur_dir);
int echld_enc_list_files(guint8*, size_t, const char* glob);
int echld_enc_open_file(guint8*, size_t, const gchar* filename);
/* echld_list_interfaces */
int echld_enc_interface_info(guint8*, size_t, const char* intf_name, ...); /* params ??? */
int echld_enc_open_interface(guint8*, size_t, const char* intf_name, ...); /* params ??? */ 
/* echld_interface_opened */
/* echld_start_capture */
/* echld_capture_started */
/* echld_stop_capture */
/* echld_capture_stopped */
int echld_packet_summary(guint8*, size_t, column_info* );
int echld_enc_get_packets_range(guint8*, size_t, int from, int to);
int echld_enc_get_packets_list(guint8*, size_t, const int* packet_numbers); /* zero terminated */
int echld_enc_tree(guint8*, size_t, proto_tree* tree);
int echld_enc_buffer(guint8*, size_t, tvb_t*, char* name);
int echld_enc_add_note(guint8*, size_t, int packet_number, gchar* note);
/* echld_note_added */
int echld_enc_file(guint8*, size_t, gchar* note);
int echld_enc_file_not_opened(guint8*, size_t, int err, gchar* text);
int echld_enc_apply_filter(guint8*, size_t, const char* filter);
int echld_enc_packet_list(guint8*, size_t , const char* name, int* packet_numbers); /* NULL term */
int echld_enc_save_file(guint8*, size_t , const char* filename, ....); /* opts ??? */
/* echld_file_saved */


/* message decoders */
int echld_dec_error(guint8*, size_t , int err, Gstring* text);
int echld_dec_close_child(guint8*, size_t buflen, int* mode);
/* echld_closing */
int echld_dec_chdir(guint8*, size_t, Gstring* new_dir);
int echld_dec_cwd(guint8*, size_t, Gstring* cur_dir);
int echld_enc_list_files(guint8*, size_t, Gstring* glob);
int echld_dec_open_file(guint8*, size_t, GString* filename);
/* echld_list_interfaces */
int echld_dec_cwd(guint8*, size_t buflen, GString* cwd);
int echld_dec_file_info(guint8*, size_t buflen, GString* file_info);
int echld_dec_open_interface(guint8*, size_t buflen, GString* interface_name, GString* params);
/* echld_interface_opened */
/* echld_start_capture */
/* echld_capture_started */
/* echld_stop_capture */
/* echld_capture_stopped */
int echld_packet_summary(guint8*, size_t, GString* );

int echld_dec_get_packets(guint8*, size_t, GArray* list);
int echld_dec_add_note(guint8*, size_t , int packet_number, Gstring* note);
int echld_dec_file(guint8*, size_t , Gstring* note);
int echld_dec_intf_info(guint8*, size_t , ...); /* params ??? */ 
int echld_dec_packet_sum(guint8*, size_t , gchar* packet_sum);
int echld_dec_tree(guint8*, size_t , GString* tree);
int echld_dec_resp_packet_list(guint8*, size_t , int* packet_numbers); /* NULL term */
int echld_dec_resp_buffer(guint8*, size_t , guint8* bbuf, size_t bbuflen);

#endif