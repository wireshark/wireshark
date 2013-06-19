/* echld_child-int.h
 *  epan working child API internals
 *
 * $Id$
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
#ifndef __ECHLD_HDR_INT_
#define __ECHLD_HDR_INT_

#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include "capture_ifinfo.h"


#include "echld.h"

/* XXX these shouldn't be needed */
typedef struct _column_info column_info;
typedef struct _proto_node proto_tree;
typedef struct tvbuff tvb_t;


struct _hdr {
	guint32 type_len;
	guint16 chld_id;
	guint16 reqh_id;
};


#define ECHLD_HDR_LEN (sizeof(struct _hdr))

typedef union _hdr_t {
	struct _hdr h;
	guint8 b[ECHLD_HDR_LEN]; 
} hdr_t;

#define HDR_TYPE(H) ((((H)->h.type_len)&0xff000000)>>24)
#define HDR_LEN(H) ((((H)->h.type_len)&0x00ffffff))

#define GET_HDR_ELEMS(H,T,L,C,R) do { guint32 tl = H->h.type_len; \
	T=HDR_TYPE(H); L=HDR_LEN(H); C=H->h.chld_id; R=H->h.req_id; } while(0)


typedef enum _cst {
	FREE=0,
	CREATING,
	IDLE,
	READY,
	READING,
	CAPTURING,
	DONE,
	CLOSED=-1,
	ERRORED=-2
} child_state_t;


/* these manage the de-framing machine in the receiver side */
typedef struct _echld_reader {
	guint8* rp; /* the read pointer*/
	guint  len;  /* the used size = (.wp - .rp) */

	guint8* wp; /* the write pointer */
	int fd; /* the filedesc is serving */

	guint8* data; /* the allocated read buffer */
	size_t  actual_len; /* the actual len of the allocated buffer */
} echld_reader_t;


#define reader_is_empty(R) ( (R)->len == 0 )
#define reader_has_header(R) ((R)->len >= ECHLD_HDR_LEN) 
#define reader_has_frame(R) ( reader_has_header(R) && ( (HDR_LEN( (hdr_t*)((R)->rp) ) + ECHLD_HDR_LEN) >= ((R)->len )))

#define READER_FD_SET(R,fdset_p) FD_SET(R.fd,&(fdset_p))
#define READER_FD_ISSET(R,fdset_p) READER_FD_ISSET(R.fd,&(fdset_p))
#define READER_FD_CLEAR(R,fdset_p) READER_FD_CLEAR(R.fd,&(fdset_p))

void echld_init_reader(echld_reader_t* r, int fd, size_t initial);
void echld_reset_reader(echld_reader_t* r, int fd, size_t initial);

typedef struct _param {
	char* name;
	char* (*get)(char** err );
	echld_bool_t (*set)(char* val , char** err);	
} param_t;

/* the call_back used by read_frame() */
typedef int (*read_cb_t)(guint8*, size_t, echld_chld_id_t, echld_msg_type_t, echld_reqh_id_t, void*);


typedef struct _child_in {
	echld_bool_t (*error)			(guint8*, size_t, int* , char**);
	echld_bool_t (*set_param)		(guint8*, size_t, char** param,  char** value);
	echld_bool_t (*get_param)		(guint8*, size_t, char** param);
	echld_bool_t (*close_child)		(guint8*, size_t, int* mode);
	echld_bool_t (*chk_filter)		(guint8*, size_t, char** flt);
	echld_bool_t (*list_files)		(guint8*, size_t, char** glob);
	echld_bool_t (*open_file)		(guint8*, size_t, char** filename);
	echld_bool_t (*open_interface)	(guint8*, size_t, char** intf_name, char** params);
	echld_bool_t (*get_sum)			(guint8*, size_t, char** range);
	echld_bool_t (*get_tree)		(guint8*, size_t, char** range);
	echld_bool_t (*add_note)		(guint8*, size_t, int* packet_number, char** note);
	echld_bool_t (*apply_filter)	(guint8*, size_t, char** filter);
	echld_bool_t (*save_file)		(guint8*, size_t, char** filename, char** params);
} child_decoder_t;

typedef struct _child_out {
	enc_msg_t* (*error) 		(int , const char*);
	enc_msg_t* (*child_dead) 	(const char*);
	enc_msg_t* (*param) 		(const char*, const char*);
	enc_msg_t* (*file_info) 	(const char*); // pre-encoded
	enc_msg_t* (*filter_chk) 	(int , const char*);
	enc_msg_t* (*intf_info) 	(const char*); // pre-encoded
	enc_msg_t* (*notify) 		(const char*); // pre-encoded
	enc_msg_t* (*packet_sum) 	(int, const char*); // framenum, sum(pre-encoded)
	enc_msg_t* (*tree) 		(int, const char*); // framenum, tree(pre-encoded)
	enc_msg_t* (*buffer) 		(int , const char*, const char*, const char*); // totlen,name,range,data
	enc_msg_t* (*packet_list) 	(const char*, const char*, const char*); // name, filter, range
} child_encoder_t;


typedef struct _parent_in {
	echld_bool_t (*error) 		(enc_msg_t*, int* , char**);
	echld_bool_t (*child_dead) 	(enc_msg_t*, char**);
	echld_bool_t (*param) 		(enc_msg_t*, char**, char**);
	echld_bool_t (*file_info) 	(enc_msg_t*, char**); // pre-encoded
	echld_bool_t (*filter_chk) 	(enc_msg_t*, int* , char**);
	echld_bool_t (*intf_info) 	(enc_msg_t*, char**); // pre-encoded
	echld_bool_t (*notify) 		(enc_msg_t*, char**); // pre-encoded
	echld_bool_t (*packet_sum) 	(enc_msg_t*, int*, char**); // framenum, sum(pre-encoded)
	echld_bool_t (*packet) 		(enc_msg_t*, int*, char**); // framenum, tree(pre-encoded)
	echld_bool_t (*buffer) 		(enc_msg_t*, int*, char**, char**, char**); // totlen,name,range,data
	echld_bool_t (*packet_list) (enc_msg_t*, char**, char**, char**); // name, filter, range
} parent_decoder_t;

void echld_get_all_codecs(child_encoder_t**, child_decoder_t**, echld_parent_encoder_t**, parent_decoder_t**);

void echld_init_reader(echld_reader_t* r, int fd, size_t initial);
void free_reader(echld_reader_t* r);

int echld_read_frame(echld_reader_t* r, read_cb_t cb, void* cb_data);
int echld_write_frame(int fd, GByteArray* ba, guint16 chld_id, echld_msg_type_t type, guint16 reqh_id, void* data);


void echld_child_initialize(int pipe_from_parent, int pipe_to_parent, int reqh_id);
int echld_child_loop(void);

/* never returns*/
void echld_dispatcher_start(int* in_pipe_fds, int* out_pipe_fds);


extern void dummy_switch(echld_msg_type_t type); 

#define DEBUG_CHILD 5
#define DEBUG_DISPATCHER 5
#define DEBUG_PARENT 5

#define BROKEN_PARENT_PIPE 3333
#define BROKEN_DUMPCAP_PIPE 4444
#define BROKEN_READFILE 5555

#endif
