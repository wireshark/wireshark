/* echld_child.h
 *  epan working child API
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
	ECHLD_ERROR = 'E', /* Child <-> Parent */
	ECHLD_HELLO '0',

	ECHLD_CLOSE_CHILD = 'Q', /* Parent -> Child  */
	ECHLD_CLOSING = 'q', /* Child -> Parent */

	ECHLD_CHDIR = 'D',  /* Parent -> Child  : change dir */
	ECHLD_CWD = 'd', /* Child -> Parent */
	
	ECHLD_LIST_FILES = 'L', /* Parent -> Child  */
	ECHLD_FILE_INFO = 'f', /* Parent -> Child  */

	ECHLD_OPEN_FILE = 'O', /* Parent -> Child  */
	ECHLD_FILE_OPENED = 'o', /* Child -> Parent */

	ECHLD_LIST_INTERFACES = 'I', /* Parent -> Child  */
	ECHLD_INTERFACE_INFO = 'i', /* Child -> Parent */

	ECHLD_OPEN_INTERFACE = 'C',  /* Parent -> Child  */
	ECHLD_INTERFACE_OPENED = 'c', /* Child -> Parent */

	ECHLD_SET_FILTER = 'F', /* Parent -> Child  */
	ECHLD_FILTER_SET = 'y',  /* Child -> Parent */

	ECHLD_START_CAPTURE = 'G',  /* Parent -> Child  */
	ECHLD_CAPTURE_STARTED = 'g',  /* Child -> Parent */

	ECHLD_STOP_CAPTURE = 'X',  /* Parent -> Child  */
	ECHLD_CAPTURE_STOPPED = 'x',  /* Child -> Parent */

	ECHLD_PACKET_SUM = 's', /* Child -> Parent */

	ECHLD_GET_PACKETS = 'G', /* Parent -> Child  */
	ECHLD_PACKET = 'p', /* Child -> Parent */
	ECHLD_BUFFER = 'b', /* Child -> Parent */

	ECHLD_ADD_NOTE = 'N', /* Parent -> Child  */
	ECHLD_NOTE_ADDED = 'n', /* Child -> Parent */
	

	ECHLD_APPLY_FILTER = 'A', /* Parent -> Child  */
	ECHLD_PACKET_LIST = 'l', /* Child -> Parent */
	
	ECHLD_SAVE_FILE = 'W', /* Parent -> Child  */
	ECHLD_FILE_SAVED = 'w', /* Parent -> Child  */

	ECHLD_EOF = 'z', /* Child -> Parent  */

	ECHLD_PING = '1', /* Parent <-> Child  */
	ECHLD_PONG = '2', /* Parent <-> Child  */
} echld_msg_type_t;

int (*echld_msg_cb_t)(echld_msg_type_t type, GByteArray*, void* data);
int (*echld_iter_cb_t)(echld_t* c, void* data);

typedef struct _echld_child echld_t;
typedef struct _echld_external_codec echld_external_codec_t;

typedef int echld_msg_id_t;
typedef int echld_state_t;

/* gets a codec set by name */
echld_external_codec_t* echld_find_codec(const char* name);
#define ECHLD_CODEC_TEXT "text"
#define ECHLD_CODEC_XML "xml"

/* will initialize epan registering protocols and taps */
echld_state_t echld_initialize(echld_external_codec_t*);

/* cleans up (?) echld and exits */
echld_state_t echld_terminate(void);

/* new worker process */
echld_t* echld_new(void* child_data);
void* echld_get_data(echld_t* c);
echld_state_t echld_set_data(echld_t* c, void* data);

/* send a message */
/* optional response handler */
/* */
echld_state_t echld_send_msg(echld_t* c, echld_msg_type_t, GByteArray*, echld_msg_cb_t resp_cb, void* cb_data);

/* start receiving a message type */
echld_msg_id_t echld_msg_attach(echld_t* c, echld_msg_type_t, echld_msg_cb_t resp_cb, void* msg_data);

/* stop receiving it */
echld_state_t echld_msg_detach(echld_t* c, echld_msg_id_t); 

/* manage the receiver's info */
void* echld_get_attached_msg_hdl_data(echld_t* c, echld_msg_id_t);
echld_msg_cb_t echld_get_attached_msg_hdl_cb(echld_t* c, echld_msg_id_t);
echld_msg_type_t echld_get_attached_msg_hdl_type(echld_t* c, echld_msg_id_t);
gboolean echld_get_attached_msg_hdl(echld_t* c, echld_msg_id_t, echld_msg_type_t*, echld_msg_cb_t*);

/* iterate between childred */
echld_t** echld_parent_get_all_children();
echld_t* echld_parent_get_child(int id);
#define echld_foreach(C, cb, data) do {echld_t** c = (C); for(;*c;c++) (cb)(*c,(data));  } while(0)
#define echld_foreach_child(cb,data) echld_foreach(echld_parent_get_children(),(cb),(data))

/*
   to be used in place of select() in the main loop of the parent code
   it will serve the children pipes and return as if select() was called.
*/
int echld_select(int nfds, int* rfds, int* wfds, int* efds, struct timeval* timeout);

#endif