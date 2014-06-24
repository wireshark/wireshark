/* echld_child-int.h
 *  epan working child API internals
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

#include "config.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#include <sys/time.h>
#include <sys/uio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <locale.h>

#include <arpa/inet.h>


#include <glib.h>
#include <glib/gprintf.h>



#include "capture_opts.h"
#include "capture_session.h"
#include <capchild/capture_ifinfo.h>
#include <capchild/capture_sync.h>
#include "version_info.h"
#include "cfile.h"
#include "wsutil/crash_info.h"
#include "wsutil/privileges.h"
#include "wsutil/filesystem.h"
#include "wsutil/copyright_info.h"
#include "wsutil/ws_version_info.h"
#include "epan/addr_resolv.h"
#include "epan/epan.h"
#include "epan/prefs.h"
#include "epan/ex-opt.h"
#include "epan/funnel.h"
#include "epan/prefs.h"
#include "epan/timestamp.h"
#include "epan/disabled_protos.h"
#include "echld.h"

#ifdef __cplusplus
extern "C" {
#endif

/* XXX these shouldn't be needed */
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
	CLOSING,
	CLOSED=-1,
	ERRORED=-2
} child_state_t;

extern const char* echld_state_str(child_state_t);
extern const char* echld_msg_type_str(echld_msg_type_t id);
#define ST(st) echld_state_str(st)
#define TY(ty) echld_msg_type_str(ty)

/* these manage the de-framing machine in the receiver side */
typedef struct _echld_reader {
	guint8* rp; /* the read pointer*/
	size_t  len;  /* the used size = (.wp - .rp) */

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

extern void echld_common_set_dbg(int level, FILE* fp, const char* prefix);

extern void echld_init_reader(echld_reader_t* r, int fd, size_t initial);
extern void echld_reset_reader(echld_reader_t* r, int fd, size_t initial);

typedef struct _param {
	const char* name;
	char* (*get)(char** err );
	echld_bool_t (*set)(char* val , char** err);
	const char* desc;
} param_t;

extern param_t* paramset_find (param_t* paramsets, char* name, char** err);

extern char* paramset_apply_get (param_t* paramsets, char* name, char** err);
extern echld_bool_t paramset_apply_set (param_t* paramsets, char* name, char* val, char** err);
extern echld_bool_t paramset_apply_em(param_t* paramset, enc_msg_t* em, char** err);

#define PARAM_LIST_FMT "%s(%s): %s\n" /* name, rw|ro|wo, desc */
char* paramset_get_params_list(param_t* paramsets,const char* fmt);

#define PARAM_STR(Name, Default) static char* param_ ## Name = Default;  \
 static char* param_get_ ## Name (char** err _U_ ) { return  (param_ ## Name) ? g_strdup(param_ ## Name) : (*err = g_strdup( #Name " not set"), NULL); } \
 static echld_bool_t param_set_ ## Name (char* val , char** err _U_) { if (param_ ## Name) g_free(param_ ## Name); param_ ## Name = g_strdup(val); return TRUE; } \

#define PARAM_INT(Name, Default) static int param_ ## Name = Default;  \
 static char* param_get_ ## Name (char** err _U_ ) { return  g_strdup_printf("%d",param_ ## Name); } \
 static echld_bool_t param_set_ ## Name (char* val , char** err _U_) {  char* p; int temp = (int)strtol(val, &p, 10); if (p<=val) { *err = g_strdup("not an integer"); return FALSE; } else {	param_ ## Name = temp; return TRUE; } }

#define PARAM_BOOL(Name, Default) static gboolean param_ ## Name = Default;  \
 static char* param_get_ ## Name (char** err _U_ ) { return  g_strdup_printf("%s",param_ ## Name ? "TRUE" : "FALSE"); } \
 static echld_bool_t param_set_ ## Name (char* val , char** err _U_) { param_ ## Name = (*val == 'T' || *val == 't') ? TRUE : FALSE; return TRUE;}

#define PARAM(Name,Desc) {#Name, param_get_ ## Name, param_set_ ## Name, Desc}
#define RO_PARAM(Name,Desc) {#Name, param_get_ ## Name, NULL, Desc}
#define WO_PARAM(Name,Desc) {#Name, NULL, param_set_ ## Name, Desc}

typedef struct _echld_epan_stuff_t {
#ifdef HAVE_LIBPCAP
	capture_session cap_sess;
	capture_options cap_opts;
	capture_file cfile;
#endif
	e_prefs* prefs;
} echld_epan_stuff_t;

/* the call_back used by read_frame() */
typedef long (*read_cb_t)(guint8*, size_t, echld_chld_id_t, echld_msg_type_t, echld_reqh_id_t, void*);


typedef struct _child_in {
	echld_bool_t (*error)			(guint8*, size_t, int* , char**);
	echld_bool_t (*set_param)		(guint8*, size_t, char** param,  char** value);
	echld_bool_t (*get_param)		(guint8*, size_t, char** param);
	echld_bool_t (*close_child)		(guint8*, size_t, int* mode);
	echld_bool_t (*open_file)		(guint8*, size_t, char** filename);
	echld_bool_t (*open_interface)	(guint8*, size_t, char** intf_name, char** params);
	echld_bool_t (*get_sum)			(guint8*, size_t, char** range);
	echld_bool_t (*get_tree)		(guint8*, size_t, char** range);
	echld_bool_t (*get_buffer)		(guint8*, size_t, char** name);
	echld_bool_t (*add_note)		(guint8*, size_t, int* packet_number, char** note);
	echld_bool_t (*apply_filter)	(guint8*, size_t, char** filter);
	echld_bool_t (*save_file)		(guint8*, size_t, char** filename, char** params);
} child_decoder_t;

typedef struct _child_out {
	enc_msg_t* (*error)		(int , const char*);
	enc_msg_t* (*child_dead)	(const char*);
	enc_msg_t* (*param)		(const char*, const char*);
	enc_msg_t* (*notify)		(const char*); // pre-encoded
	enc_msg_t* (*packet_sum)	(int, const char*); // framenum, sum(pre-encoded)
	enc_msg_t* (*tree)		(int, const char*); // framenum, tree(pre-encoded)
	enc_msg_t* (*buffer)		(int , const char*, const char*, const char*); // totlen,name,range,data
	enc_msg_t* (*packet_list)	(const char*, const char*, const char*); // name, filter, range
} child_encoder_t;


typedef struct _parent_in {
	echld_bool_t (*error)		(enc_msg_t*, int* , char**);
	echld_bool_t (*child_dead)	(enc_msg_t*, char**);
	echld_bool_t (*param)		(enc_msg_t*, char**, char**);
	echld_bool_t (*notify)		(enc_msg_t*, char**); // pre-encoded
	echld_bool_t (*packet_sum)	(enc_msg_t*, int*, char**); // framenum, sum(pre-encoded)
	echld_bool_t (*packet)		(enc_msg_t*, int*, char**); // framenum, tree(pre-encoded)
	echld_bool_t (*buffer)		(enc_msg_t*, int*, char**, char**, char**); // totlen,name,range,data
	echld_bool_t (*packet_list) (enc_msg_t*, char**, char**, char**); // name, filter, range
} parent_decoder_t;

extern void echld_get_all_codecs(child_encoder_t**, child_decoder_t**, echld_parent_encoder_t**, parent_decoder_t**);

extern void echld_init_reader(echld_reader_t* r, int fd, size_t initial);
extern void free_reader(echld_reader_t* r);

extern long echld_read_frame(echld_reader_t* r, read_cb_t cb, void* cb_data);
extern long echld_write_frame(int fd, GByteArray* ba, guint16 chld_id, echld_msg_type_t type, guint16 reqh_id, void* data);


extern void echld_child_initialize(echld_chld_id_t chld_id, int pipe_from_parent, int pipe_to_parent, int reqh_id, echld_epan_stuff_t* es);
extern int echld_child_loop(void);

/* never returns*/
extern void echld_dispatcher_start(int* in_pipe_fds, int* out_pipe_fds,	char* argv0, int (*main)(int, char **));


extern void dummy_switch(echld_msg_type_t type);
extern void echld_unused(void);

/* config stuff */

/* initial debug levels */
/* undefine to avoid debugging */
#define DEBUG_BASE 5
#define DEBUG_CHILD 5
#define DEBUG_DISPATCHER 5
#define DEBUG_PARENT 5

/* timers */
#define DISPATCHER_WAIT_INITIAL 5000000 /* 5s */
#define CHILD_CLOSE_SLEEP_TIME 2000000 /* 2s */
#define CHILD_START_WAIT_TIME 100000 /* 0.1s */
#define DISP_KILLED_CHILD_WAIT 100000 /* 0.1s */

/* fatalities */
#define BROKEN_PARENT_PIPE 9
#define BROKEN_DUMPCAP_PIPE 10
#define BROKEN_READFILE 11
#define DISPATCHER_DEAD 12
#define UNIMPLEMENTED 13
#define CANNOT_FORK 14
#define SHOULD_HAVE_EXITED_BEFORE 15
#define DISPATCHER_PIPE_FAILED 16
#define TERMINATED 17
#define CANNOT_PREINIT_EPAN 18
#define NO_INITIALIZER 19

#ifndef DEBUG_BASE
#define echld_common_set_dbg(a,b,c)
#endif




#ifdef __cplusplus
extern "C" {
#endif

#endif
