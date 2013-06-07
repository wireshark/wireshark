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
typedef enum _echld_msg_type_t {
	ECHLD_CLOSING, // C>P
	ECHLD_CLOSE_CHILD, // P>C
	// ECHLD_PWD, // P>>C
	// ECHLD_CD,  // P>>C
	// ECHLD_CURDIR, // C>>P
	// ECHLD_CANNOT_CD, // C>>P
	// ECHLD_LIST_FILES, // P>>C
	// ECHLD_FILE_INFO, // P>>C
	ECHLD_OPEN_FILE, // P>>C
	ECHLD_FILE_OPENED, // C>>P
	ECHLD_ERROR, // C>>P
	ECHLD_CLOSE_FILE, // P>>C
	ECHLD_FILE_CLOSED, // C>>P
	ECHLD_LIST_INTERFACES, // P>>C
	ECHLD_INTERFACE_INFO, // C>>P

	ECHLD_OPEN_INTERFACE,  // P>>C
	ECHLD_INTERFACE_OPENED, // C>>P
	ECHLD_INTERFACE_NOT_OPENED,	// C>>P
	ECHLD_START_CAPTURE,  // P>>C
	ECHLD_CAPTURE_STARTED,  // C>>P
	ECHLD_STOP_CAPTURE,  // P>>C
	ECHLD_CAPTURE_STOPPED,  // C>>P

	ECHLD_GET_PACKETS, // P>>C
	ECHLD_ADD_NOTE, // P>>C
	ECHLD_SET_FILTER, // P>>C
	ECHLD_PACKET_LIST, // C<<P
	ECHLD_SAVE_FILE, // P>>C
	ECHLD_PACKET_SUM, // C>>P
	ECHLD_PACKET, //C>>P
	ECHLD_BUFFER, //C>>P
	ECHLD_NOTE_ADDED, //C>>P
	ECHLD_GENERIC_MSG
} echld_msg_type_t;

typedef enum _echld_state_t {	
	ECHLD_OK,
	ECHLD_KO
} echld_state_t;

echld_state_t (echld_msg_cb_t*)(echld_msg_type_t type, guchar* buf, size_t len, void* data);
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
int echld_msg_attach(echld_t* c, echld_msg_type_t, echld_msg_cb_t resp_cb, void* msg_data);

void* echld_get_attached_msg_data(int id);
int echld_msg_detach(echld_t* c, int id);
int echld_parent_msg_attach(echld_t* c, echld_msg_type_t, echld_msg_cb_t resp_cb, void* resp_data);
int echld_parent_msg_detach(echld_t* c, int id);



const echld_t** echld_parent_get_children();
#define echld_foreach(C, cb, data) do {echld_t** c = C; for(;*c;c++) cb(*c,data);  } while(0)
#define echld_foreach_child(cb,data) echld_foreach(echld_parent_get_children(),cb,data)




/* message encoders */
int echld_enc_close_child(void* buf, size_t max_len, int mode);
int echld_enc_open_interface(void* buf, size_t max_len, char* intf_name, ...);
int echld_enc_open_file(void* buf, size_t max_len, gchar* filename); 
int echld_enc_get_packets(void* buf, size_t max_len, int* packet_numbers); /* zero terminated */
int echld_enc_add_note(void* buf, size_t max_len, int packet_number, gchar* note);
int echld_enc_file(void* buf, size_t max_len, gchar* note);
int echld_enc_file_not_opened(void* buf, size_t max_len, int err, gchar* text);
int echld_enc_resp_intf_info(void* buf, size_t max_len, ...);
int echld_enc_resp_packet_sum(void* buf, size_t max_len, * packet_sum);
int echld_enc_tree(void* buf, size_t max_len, proto_tree* tree);
int echld_enc_buffer(void* buf, size_t max_len, tvb_t* tvb);
int echld_enc_packet_list(void* buf, size_t max_len, int* packet_numbers); /*NULL term*/


/* message decoders */
int echld_dec_close_child(void* buf, size_t buflen, int* mode);
int echld_dec_open_interface(void* buf, size_t buflen, char** intf_name, ...); // NULL term param interface
int echld_dec_open_file(void* buf, size_t max_len, gchar* filename);
int echld_dec_get_packets(void* buf, size_t max_len, int* packet_numbers);
int echld_dec_add_note(void* buf, size_t max_len, int packet_number, gchar* note);
int echld_dec_file(void* buf, size_t max_len, gchar* note);
int echld_dec_file_not_opened(void* buf, size_t max_len, int err, gchar* text);
int echld_dec_resp_intf_info(void* buf, size_t max_len, ...);
int echld_dec_resp_packet_sum(void* buf, size_t max_len, gchar* packet_sum);
int echld_dec_tree(void* buf, size_t max_len, GString* tree);
int echld_dec_resp_packet_list(void* buf, size_t max_len, int* packet_numbers); /*NULL term*/
int echld_dec_resp_buffer(void* buf, size_t max_len, guchar* bbuf, size_t bbuflen);







