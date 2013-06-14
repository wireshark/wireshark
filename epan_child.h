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

/*
 * You should take a look to doc/README.epan_child before reading this
 */

/* message types */
typedef enum _echld_msg_type_t echld_msg_type_t;

/* error types */
typedef enum _echld_error echld_error_t;

/* return codes */
 /* 0 is ok, everything else is ko, or timeout where applicable. */
typedef int echld_state_t;
#define ECHLD_OK 0
#define ECHLD_TIMEOUT -222

/* id for child working processes, a negative value is an error */
typedef int echld_chld_id_t;

/* id of requests, a negative value is an error */
typedef int echld_reqh_id_t;

/* id of message handlers, a negative value is an error */
typedef int echld_msgh_id_t;

/* sets the codec set by name */
typedef enum _echld_encoding { 
	ECHLD_ENCODING_TEXT = 'T',
	ECHLD_ENCODING_XML  = 'X',
	ECHLD_ENCODING_JSON = 'J' 
} echld_encoding_t;

typedef int echld_bool_t;

/* typedef for a GByteArray so that glib.h is not required in the client */
typedef struct GByteArray bytearray_t;

/* typedef for a GByteArray so that sys/time.h is not required in the client */
typedef struct timeval tv_t;

/* will initialize epan registering protocols and taps */
echld_state_t echld_initialize(echld_encoding_t);

/* cleans up (?) echld and kills the server process(es) */
echld_state_t echld_terminate(void);

/*
 * returning ECHLD_NO_ERROR means there has being no error
 *
 * errstr_ptr is a ptr to  the error message string, will give NULL if no error
 *    usable only after the last API call, doesn't have to be freed.
 *
 * for managing asyncronous errors use a msgh for ECHLD_ERROR
 * the response cb of reqh might be a ECHLD_ERROR message
 */
echld_error_t echld_get_error(const char** errstr_ptr);

/*
 *  Children Management Operations
 */

/* create a new worker process */
echld_chld_id_t echld_new(void* child_data);

/* will return NULL on error, if NULL is also ok for you use echld_get_error() */
void* echld_get_data(echld_chld_id_t);

echld_state_t echld_set_data(echld_chld_id_t, void* child_data);

/* for each child call cb(id,child_data,cb_data) */
typedef echld_bool_t (*echld_iter_cb_t)(echld_chld_id_t, void* child_data, void* cb_data);
void echld_foreach_child(echld_iter_cb_t cb, void* cb_data);


/*
 * prototype of message callbacks passed to echld_reqh() and echld_msgh()
 *
 * type: for reqh it might be ECHLD_ERROR, ECHLD_TIMEOUT or what you expect,
 *        in msgh it's always the message for which it was set
 * msg_buff: the encoded message
 * cb_data: arbitrary data passed by the user in echld_reqh() or echld_msgh()
 * 
 * returns TRUE if other potential handlers are to be run, false otherwise
 */
typedef echld_bool_t (*echld_msg_cb_t)(echld_msg_type_t type, bytearray_t* msg_buff, void* cb_data);

/*
 * encoders
 * the returned bytearray will be destroyed internally by the req handler
 * the resulting bytearray can be used just once in a reqh.
 */

bytearray_t* echld_encode_close_child(int mode);
bytearray_t* echld_encode_set_param(const char* param, const char* value);
bytearray_t* echld_encode_chdir(char* new_dir);
bytearray_t* echld_encode_list_files(const char* glob);
bytearray_t* echld_encode_open_file(const char* filename);
bytearray_t* echld_encode_open_interface(const char* intf_name, const char* params);
bytearray_t* echld_encode_get_packets(const char* range);
bytearray_t* echld_encode_add_note(int packet_number, const char* note);
bytearray_t* echld_encode_apply_filter(const char* filter);
bytearray_t* echld_encode_set_filter(const char* filter);
bytearray_t* echld_encode_save_file(const char* filename, const char* params);

/*
 * decoder
 * it returns an allocated string with the decoded response of the message, you free it.
 * it destroys the bytearray_t as well.
 */
char* echld_decode(echld_msg_type_t, bytearray_t*);

/*
 *  Request Handlers
 *
 */

/* send a request with an optional response handler 
 *
 * ba is a bytearray_t that contains the encoded message
 * resp_cb is the callback and cb_data the data it is going to be passed if executed
 * 
 * returns the reqh id */
echld_reqh_id_t echld_reqh(echld_chld_id_t, echld_msg_type_t, bytearray_t*, echld_msg_cb_t, void*);

/* get callback data for a live request */
void* echld_reqh_get_data(echld_chld_id_t, echld_reqh_id_t);

/* get the callback for a live request */
echld_msg_cb_t echld_reqh_get_cb(echld_chld_id_t, echld_reqh_id_t);

/* set callback data for a live request */
echld_state_t echld_reqh_set_data(echld_chld_id_t, echld_reqh_id_t, void* );

/* get the callback for a live request */
echld_state_t echld_reqh_set_cb(echld_chld_id_t, echld_reqh_id_t, echld_msg_cb_t);

/* stop receiving a live request */
echld_state_t echld_reqh_detach(echld_chld_id_t, echld_reqh_id_t);


/*
 *  Message Handlers
 *
 */

/* start a message handler */
echld_msgh_id_t echld_msgh(echld_chld_id_t, echld_msg_type_t, echld_msg_cb_t resp_cb, void* msg_data);

/* stop it */
echld_state_t echld_msgh_detach(echld_chld_id_t, echld_msgh_id_t); 

/* get a msgh's data */
void* echld_msgh_get_data(echld_chld_id_t, echld_msgh_id_t);

/* get a msgh's cb */
echld_msg_cb_t echld_msgh_get_cb(echld_chld_id_t, echld_msgh_id_t);

/* get a msgh's type */
echld_msg_type_t echld_msgh_get_type(echld_chld_id_t, echld_msgh_id_t);

/* get it all from a msgh */
echld_state_t echld_msgh_get_all(echld_chld_id_t, int msgh_id, echld_msg_type_t*, echld_msg_cb_t*, void**);

/* set a msgh's data */
echld_state_t echld_msgh_set_data(echld_chld_id_t, int msgh_id, void* );

/* set a msgh's cb */
echld_state_t echld_msgh_set_cb(echld_chld_id_t, int msgh_id, echld_msg_cb_t);

/* set a msgh's type */
echld_state_t echld_msgh_set_type(echld_chld_id_t, int msgh_id, echld_msg_type_t);

/* set all elements of a msgh */
echld_state_t echld_msgh_set_all(echld_chld_id_t, int msgh_id, echld_msg_type_t, echld_msg_cb_t, void*);


/*
 * "Simple" API
 * these calls require you looping on echld_select() or calling echld_wait() until you get your answer.
 * see bellow
 */

typedef void (*echld_ping_cb_t)(int usec, void* data);
echld_state_t echld_ping(int child_id, echld_ping_cb_t cb, void* cb_data);

typedef void (*echld_list_interface_cb_t)(char* intf_name, char* params, void* cb_data);
echld_state_t echld_list_interfaces(int child_id, echld_list_interface_cb_t, void* cb_data);

typedef void (*echild_get_packet_summary_cb_t)(char* summary, void* data);
echld_state_t echld_open_file(int child_id, const char* filename,echild_get_packet_summary_cb_t,void*);


echld_state_t echld_open_interface(int child_id, const char* intf_name, const char* params);
echld_state_t echld_start_capture(int child_id, echild_get_packet_summary_cb_t);
echld_state_t echld_stop_capture(int child_id);

typedef void (*echild_get_packets_cb)(char* tree_text,void* data);
typedef void (*echild_get_buffer_cb)(char* buffer_text, void* data);
echld_state_t echld_get_packets_range(int child_id, const char* range, echild_get_packets_cb, echild_get_buffer_cb, void* data);


/*
 * Server routines
 */

/*
 * waits until something gets done
 *
 * returns ECHLD_TIMEOUT or ECHLD_OK if something was done
 */
echld_state_t echld_wait(tv_t* timeout);


/*
   to be used in place of select() in the main loop of the parent code
   it will serve the children pipes and return as if select() was called.
*/
int echld_select(int nfds, int* rfds, int* wfds, int* efds, tv_t* timeout);

/* or fit these two in your select loop */

/* returns nfds set */
int echld_fdset(int* rfds, int* efds);

int echld_fd_read(int* rfds, int* efds);


#define ECHLD_MAX_CHILDREN 32

enum _echld_msg_type_t {
	ECHLD_ERROR = 'E', /* Child <-> Parent */
	ECHLD_TIMED_OUT='T', /* -> Parent Note the D in timeD out */

	ECHLD_NEW_CHILD = '*', /* Parent -> Child  */
	ECHLD_HELLO = '@', /* Child -> Parent */
	ECHLD_CHILD_DEAD = '#', /* Child -> Parent */

	ECHLD_NOTIFY = '%', /* Parent <-> Child  */

	ECHLD_SET_PARAM = 'P', /* Parent -> Child  */
	ECHLD_PARAM_SET = 'p', /* Parent <- Child  */

	ECHLD_PING = '>', /* Parent <-> Child  */
	ECHLD_PONG = '<', /* Parent <-> Child  */

	ECHLD_CLOSE_CHILD = 'Q', /* Parent -> Child  */
	ECHLD_CLOSING = 'q', /* Child -> Parent */

	ECHLD_PWD = 'P',  /* Parent -> Child  : show dir */
	ECHLD_CHDIR = 'D',  /* Parent -> Child  : change dir */
	ECHLD_CWD = 'd', /* Child -> Parent */
	
	ECHLD_LIST_FILES = 'L', /* Parent -> Child  */
	ECHLD_FILE_INFO = 'f', /* Parent -> Child  */

	ECHLD_CHK_FILTER = 'K',	
	ECHLD_FILTER_CKD = 'k',

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
	ECHLD_PACKET = 't', /* Child -> Parent */
	ECHLD_BUFFER = 'b', /* Child -> Parent */

	ECHLD_ADD_NOTE = 'N', /* Parent -> Child  */
	ECHLD_NOTE_ADDED = 'n', /* Child -> Parent */
	

	ECHLD_APPLY_FILTER = 'A', /* Parent -> Child  */
	ECHLD_PACKET_LIST = 'l', /* Child -> Parent */
	
	ECHLD_SAVE_FILE = 'W', /* Parent -> Child  */
	ECHLD_FILE_SAVED = 'w', /* Parent -> Child  */

	ECHLD_EOF = 'z', /* Child -> Parent  */

	EC_ACTUAL_ERROR

};

enum _echld_error {
	ECHLD_NO_ERROR = 0,
	ECHLD_ERR_UNIMPLEMENTED,
	ECHLD_ERR_WRONG_MSG,
	ECHLD_ERR_NO_SUCH_CHILD,
	ECHLD_ERR_UNKNOWN_PID,
	ECHLD_ERR_CANNOT_FORK,
	ECHLD_ERR_CANNOT_CHDIR,
	ECHLD_ERR_SET_FILTER,
	ECHLD_ERR_CANNOT_OPEN_FILE,
	ECHLD_ERR_CANNOT_OPEN_INTERFACE,
	ECHLD_ERR_CANNOT_START_CAPTURE,
	ECHLD_ERR_CANNOT_LIST_INTERFACES,
	ECHLD_ERR_CRASHED_CHILD,
	ECHLD_ERR_OTHER
};


#endif
