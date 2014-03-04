/* echld.h
 *  epan working child API
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

#ifndef __ECHLD_H
#define __ECHLD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ws_symbol_export.h"

#define ECHLD_VERSION "0.0"
#define ECHLD_MAJOR_VERSION 0 /* increases when existing things change */
							  /* if this changes an old client may or may not work */

#define ECHLD_MINOR_VERSION 0 /* increases when new things are added */
							  /* if just this one changes an old client will still work */

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

/* enc_msg_t is an obscure object for an encoded message (a GbyteArray for now)*/
typedef struct _GByteArray enc_msg_t;

/* sets the codec set by name */
typedef enum _echld_encoding {
	ECHLD_ENCODING_TEXT = 'T',
	ECHLD_ENCODING_XML  = 'X',
	ECHLD_ENCODING_JSON = 'J'
} echld_encoding_t;

typedef int echld_bool_t;

/* typedef for a timeval so that sys/time.h is not required in the client */
typedef struct timeval tv_t;

typedef void (*cleanup_cb_t)(void*);
typedef int (*main_t)(int, char**); /* a pointer to main() */

/* these are called after a new child is created.
 * chld_id = -1 on error/timeout
 */
typedef void (*echld_new_cb_t)(void* child_data, const char* err);

/* I will be passed to echld_initialize() */
typedef struct _echld_init {
	echld_encoding_t encoding; /* only JSON for now */

	char* argv0; /* the value of argv[0] */
	main_t main;

	echld_new_cb_t dispatcher_hello_cb; /* child_data will be a pointer to this echld_init_t */

	cleanup_cb_t after_fork_cb; /* to be called by dispatcher just after fork to free
								   the child processes from entities of the parent */
	void* after_fork_cb_data;

	cleanup_cb_t at_term_cb; /* to be called after echld_terminate() is done */
	void* at_term_cb_data;

	void* user_data; /* free for you to use */
} echld_init_t;

/* will initialize echld forking the dispatcher and registering protocols and taps */
WS_DLL_PUBLIC void echld_initialize(echld_init_t*);

/* cleans up echld and kills the server process(es) */
WS_DLL_PUBLIC echld_state_t echld_terminate(void);


/*
 * returning ECHLD_NO_ERROR means there has being no error
 *
 * errstr_ptr is a ptr to  the error message string, will give NULL if no error
 *    usable only after the last API call, doesn't have to be freed.
 *
 * for managing asyncronous errors use a msgh for ECHLD_ERROR
 * the response cb of reqh might be a ECHLD_ERROR message
 */
WS_DLL_PUBLIC echld_error_t echld_get_error(const char** errstr_ptr);


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
typedef echld_bool_t (*echld_msg_cb_t)(echld_msg_type_t type, enc_msg_t* msg_buff, void* cb_data);


/* encoding and decoding */


/*
 * encoder
 * the enc_msg_t will be destroyed internally by the req handler
 * the resulting enc_msg_t can be used in a reqh just once.
 */

typedef struct _parent_out {
	enc_msg_t* (*error)(int err, const char* text);
	enc_msg_t* (*get_param)(const char* param);
	enc_msg_t* (*set_param)(const char* param,  const char* value);
	enc_msg_t* (*close_child)(int mode);
	enc_msg_t* (*open_file)(const char* filename);
	enc_msg_t* (*open_interface)(const char* intf_name, const char* params);
	enc_msg_t* (*get_sum)(const char* range);
	enc_msg_t* (*get_tree)(const char* range);
	enc_msg_t* (*get_bufer)(const char* name);
	enc_msg_t* (*add_note)(int packet_number, const char* note);
	enc_msg_t* (*apply_filter)(const char* filter);
	enc_msg_t* (*save_file)(const char* filename, const char* params);
} echld_parent_encoder_t;


WS_DLL_PUBLIC echld_parent_encoder_t* echld_get_encoder(void);


/*
 * decoder
 * it returns an allocated string with the decoded response of the message, you free it.
 * it destroys the enc_msg_t as well.
 */
WS_DLL_PUBLIC char* echld_decode(echld_msg_type_t, enc_msg_t*);

/*
 *  Children Management Operations
 */

WS_DLL_PUBLIC enc_msg_t* echld_new_child_params(void);



/* takes the em, and param=value pairs of strings, NULL to end.
    echld_new_child_params_add_params(em,param1_str,val1_str,param2_str,val2_str,NULL);  */
WS_DLL_PUBLIC void echld_new_child_params_add_params(enc_msg_t*, ...);

WS_DLL_PUBLIC enc_msg_t* echld_new_child_params_merge(enc_msg_t*, enc_msg_t*);

#define ECHLD_NC_PARAMS_FMT "  %s='%s',\n" /* param='value' */
/* truncate takes off last N chars from the last item's fmt or prefix on empty */
WS_DLL_PUBLIC char* echld_new_child_params_str(enc_msg_t* em, const char* prefix, const char* postfix, int truncate, const char* fmt);


/* create a new worker process */
WS_DLL_PUBLIC echld_chld_id_t echld_new(enc_msg_t* new_child_parameters, echld_new_cb_t cb, void* child_data);

/* will return NULL on error, if NULL is also ok for you use echld_get_error() */
WS_DLL_PUBLIC void* echld_get_data(echld_chld_id_t);

WS_DLL_PUBLIC echld_state_t echld_set_data(echld_chld_id_t id, void* child_data);

/* for each child call cb(id,child_data,cb_data) */
typedef echld_bool_t (*echld_iter_cb_t)(echld_chld_id_t, void* child_data, void* cb_data);
WS_DLL_PUBLIC void echld_foreach_child(echld_iter_cb_t cb, void* cb_data);

/*
 *  Request Handlers
 *
 */

/* send a request with an optional response handler
 *
 * ba is a enc_msg_t that contains the encoded message
 * resp_cb is the callback and cb_data the data it is going to be passed if executed
 *
 * returns the reqh id */
WS_DLL_PUBLIC echld_reqh_id_t echld_reqh(echld_chld_id_t, echld_msg_type_t, int usecs_timeout, enc_msg_t*, echld_msg_cb_t, void*);

/* get callback data for a live request */
WS_DLL_PUBLIC void* echld_reqh_get_data(echld_chld_id_t, echld_reqh_id_t);

/* get the total timeout time for a live request, -1 is err */
WS_DLL_PUBLIC int echld_reqh_get_to(echld_chld_id_t, echld_reqh_id_t);

/* get the remaining timeout time for a live request, -1 is err */
WS_DLL_PUBLIC int echld_reqh_get_remaining_to(echld_chld_id_t, echld_reqh_id_t);

/* get the callback for a live request */
WS_DLL_PUBLIC echld_msg_cb_t echld_reqh_get_cb(echld_chld_id_t, echld_reqh_id_t);

/* set callback data for a live request */
WS_DLL_PUBLIC echld_state_t echld_reqh_set_data(echld_chld_id_t, echld_reqh_id_t, void* );

/* get the callback for a live request */
WS_DLL_PUBLIC echld_state_t echld_reqh_set_cb(echld_chld_id_t, echld_reqh_id_t, echld_msg_cb_t);

/* stop receiving a live request */
WS_DLL_PUBLIC echld_state_t echld_reqh_detach(echld_chld_id_t, echld_reqh_id_t);


/*
 *  Message Handlers
 *
 */

/* start a message handler */
WS_DLL_PUBLIC echld_msgh_id_t echld_msgh(echld_chld_id_t, echld_msg_type_t, echld_msg_cb_t resp_cb, void* msg_data);

/* stop it */
WS_DLL_PUBLIC echld_state_t echld_msgh_detach(echld_chld_id_t, echld_msgh_id_t);

/* get a msgh's data */
WS_DLL_PUBLIC void* echld_msgh_get_data(echld_chld_id_t, echld_msgh_id_t);

/* get a msgh's cb */
WS_DLL_PUBLIC echld_msg_cb_t echld_msgh_get_cb(echld_chld_id_t, echld_msgh_id_t);

/* get a msgh's type */
WS_DLL_PUBLIC echld_msg_type_t echld_msgh_get_type(echld_chld_id_t, echld_msgh_id_t);

/* get it all from a msgh */
WS_DLL_PUBLIC echld_state_t echld_msgh_get_all(echld_chld_id_t, int msgh_id, echld_msg_type_t*, echld_msg_cb_t*, void**);

/* set a msgh's data */
WS_DLL_PUBLIC echld_state_t echld_msgh_set_data(echld_chld_id_t, int msgh_id, void* );

/* set a msgh's cb */
WS_DLL_PUBLIC echld_state_t echld_msgh_set_cb(echld_chld_id_t, int msgh_id, echld_msg_cb_t);

/* set a msgh's type */
WS_DLL_PUBLIC echld_state_t echld_msgh_set_type(echld_chld_id_t, int msgh_id, echld_msg_type_t);

/* set all elements of a msgh */
WS_DLL_PUBLIC echld_state_t echld_msgh_set_all(echld_chld_id_t, int msgh_id, echld_msg_type_t, echld_msg_cb_t, void*);




/*
 * Server routines
 */

/*
 * waits until something gets done
 *
 * returns ECHLD_TIMEOUT or ECHLD_OK if something was done
 */
WS_DLL_PUBLIC echld_state_t echld_wait(tv_t* timeout);

#define ECHLD_WAIT() do { struct timeval tv; int rfds,  efds; \
	echld_select(echld_fdset(&rfds, &efds),&rfds, NULL, &efds, NULL) \
	&& echld_fd_read(&rfds, &efds); } while(0)

/*
   to be used in place of select() in the main loop of the parent code
   it will serve the children pipes and return as if select() was called.
*/
WS_DLL_PUBLIC int echld_select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds, tv_t* timeout);

/* or fit these two in your select loop */

/* returns nfds set */
WS_DLL_PUBLIC int echld_fdset(fd_set* rfds, fd_set* efds);

WS_DLL_PUBLIC int echld_fd_read(fd_set* rfds, fd_set* efds);

WS_DLL_PUBLIC void echld_set_parent_dbg_level(int lvl);


#define ECHLD_MAX_CHILDREN 32

enum _echld_msg_type_t {
	/*  in = child to parent */
	/* out = parent to child */

	ECHLD_NULL ='\0',  /* To terminate array */
	ECHLD_ERROR = '!', /* in: an error has occurred,
						*	this can be a response to most messages
						*   some errors are sent asyncronously (some are handled internally, some are then passed)
						*/
	ECHLD_TIMED_OUT='/', /* in: A reqh has timed out (TO from now on)
						*	this can be a response to some messages
						*   some TOs are sent asyncronously (some are handled internally, some are then passed)
						*/

	ECHLD_NEW_CHILD = '*', /* out: creates a new working child  (handled internally)  */
	ECHLD_HELLO = '@', /* in: the working child has being created (handled internally, then passed to msgh) */

	ECHLD_CHILD_DEAD = '#', /* in: a child has dead (handled internally, then passed to msgh) */

	ECHLD_CLOSE_CHILD = 'Q', /* out: close the child  */
	ECHLD_CLOSING = 'q', /* in: the child is closing, error otherwise  */
						 /* this handled internally as msgh, if your reqh_cb uses it make sure to return TRUE */

	ECHLD_SET_PARAM = '>', /* out: set a parameter of a child  */
	ECHLD_GET_PARAM = '<', /* out: set a parameter of a child  */
	ECHLD_PARAM = 'p', /* in: the parameter's new/current value, error otherwise  */

						/* capture_filter string RO: set at open_capture */
						/* monitor_mode string RW: use monitor mode if possible, error otherwise */
						/* inc_pkt_ntfy_timeout number_string RW: timeout in usec after which notification is sent if no maxpackets have arrived yet */
						/* inc_pkt_ntfy_maxpackets number_string RW: number of packets after which send a notification */
						/* auto_sum RW: get summaries automatically (without a reqh, as msgh) */
						/* auto_tree RW: get trees automatically (without a reqh, as msgh)   */
						/* auto_buffer RW: get buffers automatically (without a reqh, as msgh) */
						/* cwd RW: the current working directory */
						/* list_files WO: a file listing of the current dir */
						/* interfaces RO: the interface listing */
						/* dfilter RW:  initial display filter*/
						/* dfilter_chk WO: check a display filter */
						/* ... */

	ECHLD_PING = '}', /* out: ping the child  */
	ECHLD_PONG = '{', /* out: ping's response, error or TO otherwise */

	ECHLD_OPEN_FILE = 'O', /* out: open a file  */
	ECHLD_FILE_OPENED = 'o', /* in: the file has being open, error otherwise */

	ECHLD_OPEN_INTERFACE = 'C',  /* out: request an interface to be open (get ready for capture)  */
	ECHLD_INTERFACE_OPENED = 'c', /* in: ready to start_capture, error otherwise */

	ECHLD_START_CAPTURE = 'R',  /* out: start capturing */
	ECHLD_CAPTURE_STARTED = 'r',  /* in: the capture has started, error otherwise */

	ECHLD_NOTIFY = '%', /* in: many things can be notified by the child:
	  						 	number of packets captured/read
								other events in the future (?)
	  						 	*/

	ECHLD_GET_SUM = 'S', /* out: get the summaries of a range of packets (even before they are notify'd) */
	ECHLD_PACKET_SUM = 's', /* in: a packet's summary (when it arrives for a reqh) (in msgh if auto_sum )*/
								/* no timeout, the request hangs until the packets in the range are available */
								/* error at EOF or CAPTURE_STOPPED if the request is still hanging */

	ECHLD_GET_TREE = 'G', /* out: get the decoded version of the packet  */
	ECHLD_TREE = 't', /* Child -> Parent */
								/* no timeout, the request hangs until the packets in the range are available */
								/* error at EOF or CAPTURE_STOPPED if the request is still hanging */


	ECHLD_GET_BUFFER = 'B', /* out: get the decoded version of the packet  */
	ECHLD_BUFFER = 'b', /* in: get a buffer (or what we have of it... or the next part... same reqh_id) */
								/* no timeout, the request hangs until the packets in the range are available */
								/* error at EOF or CAPTURE_STOPPED if the request is still hanging */

	ECHLD_EOF = 'z', /* in: will be delivered when a file has being read and all pendin ntfy,sums,trees and buffs have being passed
	 						or after capture has stopped and all pending stuff is done */

	ECHLD_STOP_CAPTURE = 'X',  /* out: stop capturing  */
	ECHLD_CAPTURE_STOPPED = 'x',  /* in: capture has stopped, error otherwise */

	ECHLD_ADD_NOTE = 'N', /* out: add a note to the capture  */
	ECHLD_NOTE_ADDED = 'n', /* in: a note has being added */

	ECHLD_APPLY_FILTER = 'A', /* in: apply a filter on the open file/capture */
	ECHLD_PACKET_LIST = 'l', /* out: a packet list, or error or timeout */
							/*(or what we have of it... or the next part... same reqh_id) */

	ECHLD_SAVE_FILE = 'W', /* out: save the open file/capture  */
	ECHLD_FILE_SAVED = 'w', /* in: the file was saved */


	EC_ACTUAL_ERROR = 0 /* this is not used in the protocol,
	                        it is returned for an error in calls returning a message type  */
};

enum _echld_error {
	ECHLD_NO_ERROR = 0,
	ECHLD_ERR_UNIMPLEMENTED,
	ECHLD_ERR_WRONG_MSG,
	ECHLD_ERR_NO_SUCH_CHILD,
	ECHLD_ERR_CHILD_EXISTS,
	ECHLD_ERR_UNKNOWN_PID,
	ECHLD_ERR_CANNOT_FORK,
	ECHLD_ERR_SET_FILTER,
	ECHLD_ERR_CANNOT_OPEN_FILE,
	ECHLD_ERR_CANNOT_OPEN_INTERFACE,
	ECHLD_ERR_CANNOT_START_CAPTURE,
	ECHLD_ERR_CANNOT_LIST_INTERFACES,
	ECHLD_CANNOT_SET_PARAM,
	ECHLD_CANNOT_GET_PARAM,
	ECHLD_ERR_CRASHED_CHILD,
	ECHLD_DECODE_ERROR,
	ECHLD_ERR_OTHER
};

#ifdef __cplusplus
};
#endif

#endif
