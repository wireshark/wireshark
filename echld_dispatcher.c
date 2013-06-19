/* echld_dispatcher.c
 *  epan working child API internals
 *  Dispatcher process routines and definitions
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

#include "echld-int.h"
/** 
  DISPATCHER
  **/

struct dispatcher_child {
	unsigned chld_id;
	child_state_t state;
	echld_reader_t reader;
	int write_fd;
	int pid;
	gboolean closing;
};

struct dispatcher {
	int parent_out;
	echld_reader_t parent_in;
	struct dispatcher_child* children;
	int max_children;
	int nchildren;
	int reqh_id;
	int pid;
	int ppid;
	struct _encs {
		child_encoder_t* to_parent;
		echld_parent_encoder_t* to_child;
	} enc;
	struct _decs {
		child_decoder_t* from_parent;
		parent_decoder_t* from_child;
	} dec;

	gboolean closing;
};

struct dispatcher* dispatcher;

#define DISP_RESP(B,T) (echld_write_frame( dispatcher->parent_out, (B), 0, (T), dispatcher->reqh_id, NULL))

#ifdef DEBUG_DISPATCHER
static int dbg_level = 0;

void dispatcher_debug(int level, char* fmt, ...) {
	va_list ap;
	char* str;

	if (dbg_level<level) return;

    va_start(ap, fmt);
	str = g_strdup_vprintf(fmt,ap);
	va_end(ap);

	fprintf(stderr, "dispatcher[%d]: reqh_id=%d dbg_level=%d message='%s'", dispatcher->pid, dispatcher->reqh_id, level, str);
	g_free(str);
}

static char* param_get_dbg_level(char** err ) {
	return g_strdup_printf("%d",dbg_level);
}

static echld_bool_t param_set_dbg_level(char* val , char** err ) {
	char* p;
	int lvl = strtol(val, &p, 10);

	if (p<=val) {
		*err = g_strdup("not an integer");
		return FALSE;
	} else if (lvl < 0 || lvl > 5) {
		*err = g_strdup_printf("invalid level=%d (min=0 max=5)",lvl);
		return FALSE;
	}

	dbg_level = lvl;
	return TRUE;
}

#define DISP_DBG(attrs) ( dispatcher_debug attrs )
#else
#define DISP_DBG(attrs)
#endif


/* parameters */

int wait_chldn = 0;

static char* param_get_wait_chldn(char** err ) {
	return g_strdup_printf("%d",wait_chldn);
}

static echld_bool_t param_set_wait_chldn(char* val , char** err ) {
	char* p;
	int lvl = strtol(val, &p, 10);

	if (p<=val) {
		*err = g_strdup("not an integer");
		return FALSE;
	} else if (lvl < 0 || lvl > 10) {
		*err = g_strdup_printf("invalid level=%d (min=0 max=5)",lvl);
		return FALSE;
	}

	wait_chldn = lvl;
	return TRUE;
}

static param_t disp_params[] = {
#ifdef DEBUG_DISPATCHER
	{"dbg_level", param_get_dbg_level, param_set_dbg_level},
# endif
	{"wait_chldn",param_get_wait_chldn,param_set_wait_chldn},
	{NULL,NULL,NULL} };

static param_t* get_paramset(char* name) {
	int i;
	for (i = 0; disp_params[i].name != NULL;i++) {
		if (strcmp(name,disp_params[i].name) == 0 ) return &(disp_params[i]);
	}
	return NULL;
} 

void dispatcher_err(int err, const char* fmt, ...) {
	size_t len= 1024;
	guint8* b[len];
	char err_str[len];
	GByteArray* em;
	va_list ap;


	va_start(ap, fmt);
	g_vsnprintf(err_str,len,fmt,ap);
	va_end(ap);

	fprintf(stderr, "%s[%d]: error=%d '%s'\n", "dispatcher", dispatcher->pid, err, err_str);

	em = (void*)dispatcher->enc.to_parent->error(err, err_str);
	echld_write_frame(dispatcher->parent_out, em, 0, ECHLD_ERROR, dispatcher->reqh_id, NULL);
	g_ptr_array_free((void*)em,TRUE);
}

static struct dispatcher_child* dispatcher_get_child(struct dispatcher* d, guint16 chld_id) {
	int i;
	struct dispatcher_child* cc = d->children;
	int max_children = d->max_children;

	for(i = 0; i < max_children; i++) {
		struct dispatcher_child* c = &(c[i]);
		if (c->chld_id == chld_id) return c;
	}

	return NULL;
}


static void dispatcher_clear_child(struct dispatcher_child* c) {
	echld_reset_reader(&(c->reader), -1, 4096);
	c->chld_id = 0;
	c->write_fd = 0;
	c->pid = 0;
	c->closing = 0;
}

static void preinit_epan() {
  /* Here we do initialization of parts of epan that will be the same for every child we fork */
}


static void dispatcher_clear() {
	/* remove unnecessary stuff for the working child */
}

void dispatcher_reaper(int sig) {
    int    status;
	int i;
	struct dispatcher_child* cc = dispatcher->children;
	int max_children = dispatcher->max_children;
	int pid =  waitpid(-1, &status, WNOHANG);
	size_t len= 1024;
	guint8* b[len];
	GByteArray* em;

	for(i = 0; i < max_children; i++) {
		struct dispatcher_child* c = &(cc[i]);
		if ( c->pid == pid ) {
			if (c->closing || dispatcher->closing) {
				em = (void*)dispatcher->enc.to_parent->child_dead("OK");
			} else {
				/* here we do collect crash data !!! */
				em = (void*)dispatcher->enc.to_parent->child_dead("Unexpected, probably crashed");
				dispatcher_err(ECHLD_ERR_CRASHED_CHILD, "Unexpected dead: pid=%d chld_id=%d", pid, c->chld_id);
			}

			echld_write_frame(dispatcher->parent_out, em, c->chld_id, ECHLD_CHILD_DEAD, 0, NULL);
			dispatcher_clear_child(c);
			g_byte_array_free(em,TRUE);
			return;
		}
	}

	dispatcher_err(ECHLD_ERR_UNKNOWN_PID, "Unkown child pid: %d", pid);
}



static void dispatcher_destroy() {
	int i;
	int max_children = dispatcher->max_children;
	struct dispatcher_child* cc = dispatcher->children;
	/* destroy the dispatcher stuff at closing */

	dispatcher->closing = TRUE;

	/* kill all alive children */
	for(i = 0; i < max_children; i++) {
		struct dispatcher_child* c = &(cc[i]);
		if ( c->chld_id ) {
			kill(c->pid,SIGTERM);
			DISP_DBG((1,"Killing chld_id=%d pid=%d"));
			continue;
		}
	}

	exit(6666);
}

/* stuff coming from child going to parent */
static int dispatch_to_parent(guint8* b, size_t len, echld_chld_id_t chld_id, echld_msg_type_t type, echld_reqh_id_t reqh_id, void* data) {
	struct dispatcher_child* c = data;
	dispatcher->reqh_id  = reqh_id;
	/* TODO: timeouts, clear them */
	/* TODO: keep stats */
	GByteArray in_ba;

	in_ba.data = b;
	in_ba.len = len;

	if (chld_id != c->chld_id) {
		goto misbehabing;
	}

	switch(type) {
		case ECHLD_ERROR: break;
		case ECHLD_TIMED_OUT: break;
		case ECHLD_HELLO: c->state = IDLE; break;
		case ECHLD_CLOSING: c->closing = TRUE; c->state = CLOSED; break;
		case ECHLD_PARAM: break;
		case ECHLD_PONG: break;
		case ECHLD_FILE_INFO: break;  // file_info(pre_encoded)
		case ECHLD_FILTER_CKD: break; // filter_ckd(ok,df)
		case ECHLD_FILE_OPENED: c->state = READING; break;
		case ECHLD_INTERFACE_INFO: break; // intf_info(pre-encoded)
		case ECHLD_INTERFACE_OPENED: c->state = READY; break;
		case ECHLD_CAPTURE_STARTED: c->state = CAPTURING; break;
		case ECHLD_NOTIFY: break; // notify(pre-encoded) 
		case ECHLD_PACKET_SUM: break; // packet_sum(pre-encoded)
		case ECHLD_TREE: break; //tree(framenum, tree(pre-encoded) ) 
		case ECHLD_BUFFER: break; // buffer (name,range,totlen,data)
		case ECHLD_EOF: c->state = DONE; break; 
		case ECHLD_CAPTURE_STOPPED: c->state = DONE; break; 
		case ECHLD_NOTE_ADDED: break; 
		case ECHLD_PACKET_LIST: break; // packet_list(name,filter,range);
		case ECHLD_FILE_SAVED: break;

		default:
			goto misbehabing;
	}

	return echld_write_frame(dispatcher->parent_out, &in_ba, chld_id, type, reqh_id, NULL);

misbehabing:
	c->state = ERRORED;
	c->closing = TRUE;
	kill(c->pid,SIGTERM);
	dispatcher_err(ECHLD_ERR_CRASHED_CHILD,"chld_id=%d",chld_id);
	return 0;

}

void dispatch_new_child(struct dispatcher* dd) {
	struct dispatcher_child* c = dispatcher_get_child(dd, 0);
	int reqh_id = dd->reqh_id;
	int pid; 

	if ( c ) {
		int parent_pipe_fds[2];
		int child_pipe_fds[2];

		int pipe_to_parent;
		int pipe_from_parent;
		int pipe_to_child;
		int pipe_from_child;

		if( pipe(parent_pipe_fds) < 0) {
			dispatcher_err(ECHLD_ERR_CANNOT_FORK,"CANNOT OPEN PARENT PIPE: %s",strerror(errno));
			return;
		}

		pipe_from_parent = parent_pipe_fds[0];
		pipe_to_child = parent_pipe_fds[1];

		if( pipe(child_pipe_fds) < 0) {
			close(pipe_from_parent);
			close(pipe_to_child);
			dispatcher_err(ECHLD_ERR_CANNOT_FORK,"CANNOT OPEN CHILD PIPE: %s",strerror(errno));
			return;
		}

		pipe_from_child = child_pipe_fds[0];
		pipe_to_parent = child_pipe_fds[1];

		switch (( pid = fork() )) {
			case -1: {
				close(pipe_to_child);
				close(pipe_to_parent);
				close(pipe_from_child);
				close(pipe_from_parent);
				dispatcher_err(ECHLD_ERR_CANNOT_FORK,"CANNOT FORK: %s",strerror(errno));
				return;
			}
			case 0: { /* I'm the child */
				int i;
				int fdt_len = getdtablesize();

				dispatcher_clear(dd);

				for(i=0;i<fdt_len;i++) {
					if ( i != pipe_from_parent 
						&& i != pipe_to_parent
						&& i != STDERR_FILENO ) {
						close(i);
					}
				}

				echld_child_initialize(pipe_from_parent,pipe_to_parent,reqh_id);

				exit( echld_child_loop() );

				/* it won't */
				return; 
			}
			default: {
				/* I'm the parent */
				guint8 buf[4];
				GByteArray out_ba;

				out_ba.data = buf;
				out_ba.len = 0;

				close(pipe_to_parent);
				close(pipe_from_parent);

				echld_reset_reader(&(c->reader), pipe_from_child,4096);
				c->write_fd = pipe_to_child;
				c->pid = pid;
				dispatcher->nchildren++;

				/* configure child */
				echld_write_frame(pipe_to_child, &out_ba, c->chld_id, ECHLD_NEW_CHILD, dispatcher->reqh_id, NULL);
				return;
			}
		}
	} else {
		dispatcher_err(ECHLD_ERR_CANNOT_FORK, "MAX CHILDREN REACHED: max_children=%d",dispatcher->max_children);
		return;
	}
}


/* process signals sent from parent */
static int dispatch_to_child(guint8* b, size_t len, echld_chld_id_t chld_id, echld_msg_type_t type, echld_reqh_id_t reqh_id, void* data) {
	struct dispatcher* disp = data;
	disp->reqh_id = reqh_id;
	GByteArray in_ba;

	in_ba.data = b;
	in_ba.len = len;

	if (chld_id == 0) { /* these are messages to the dispatcher itself */
		switch(type) {
			case ECHLD_CLOSE_CHILD:
				dispatcher_destroy();
				return 0;
			case ECHLD_PING: 
				echld_write_frame(disp->parent_out, &in_ba, chld_id, ECHLD_PONG, reqh_id, NULL);

				return 0;
			case ECHLD_NEW_CHILD:
				dispatch_new_child(disp);
				return 0;
			case ECHLD_SET_PARAM:{
				char* param;
				char* value;
				if ( disp->dec.from_parent->set_param(b,len,&param,&value) ) {
					GByteArray* ba;
					param_t* p = get_paramset(param);
					char* err;
					if (!p) {
						dispatcher_err(ECHLD_CANNOT_SET_PARAM,"no such param='%s'",param);					
						return 0;
					}

					if (! p->set ) {
						dispatcher_err(ECHLD_CANNOT_SET_PARAM,"reason='read only'");
						return 0;
					}

					if (! p->set(value,&err) ) {
						dispatcher_err(ECHLD_CANNOT_SET_PARAM,"reason='%s'",err);
						g_free(err);
						return 0;
					}

					ba = (void*)disp->enc.to_parent->param(param,value);
					DISP_RESP(ba,ECHLD_PARAM);
					g_byte_array_free(ba,TRUE);
					DISP_DBG((1,"Set Param: param='%s' value='%s'",param,value));

					return 0;
				} else {
					dispatcher_err(ECHLD_CANNOT_SET_PARAM,"reason='decoder error'");
					return 0;
				}
			}
			case ECHLD_GET_PARAM: {
				GByteArray* ba;
				char* param;
				if ( disp->dec.from_parent->get_param(b,len,&param) ) {
					char* err;
					char* val;

					param_t* p = get_paramset(param);

					if (!p) {
						dispatcher_err(ECHLD_CANNOT_GET_PARAM,"no such param='%s'",param);					
						return 0;
					}

					if (! p->get ) {
						dispatcher_err(ECHLD_CANNOT_SET_PARAM,"reason='write only'");
						return 0;
					}

					if (!(val = p->get(&err))) {
						dispatcher_err(ECHLD_CANNOT_GET_PARAM,"reason='%s'",err);
						g_free(err);
						return 0;
					}
					
					ba = (void*)disp->enc.to_parent->param(param,val);
					DISP_RESP(ba,ECHLD_PARAM);
					g_byte_array_free(ba,TRUE);
					DISP_DBG((2,"Get Param: param='%s' value='%s'",param,val));
					return 0;
				} else {
					dispatcher_err(ECHLD_CANNOT_GET_PARAM,"reason='decoder error'");
					return 0;
				}
			}
			default:
				dispatcher_err(ECHLD_ERR_WRONG_MSG, "wrong message to dispatcher type='%c'", type);
				return 0;
		}
	} else {
		struct dispatcher_child* c;

		if (! (c = dispatcher_get_child(dispatcher, chld_id)) ) {
			dispatcher_err(ECHLD_ERR_NO_SUCH_CHILD, "wrong chld_id %d", chld_id);
			return 0;
		}

		switch(type) {
			case ECHLD_CLOSE_CHILD: 
				c->closing = TRUE;
				c->state = CLOSED;
				goto relay_frame;

			case ECHLD_OPEN_FILE:
				c->state = READING;
				goto relay_frame;

			case ECHLD_OPEN_INTERFACE:
				c->state = READY;
				goto relay_frame;

			case ECHLD_START_CAPTURE:
				c->state = CAPTURING;
				goto relay_frame;

			case ECHLD_STOP_CAPTURE:
				c->state = DONE;
				goto relay_frame;

			case ECHLD_SAVE_FILE:
			case ECHLD_APPLY_FILTER:
			case ECHLD_SET_PARAM:
			case ECHLD_GET_PARAM:
			case ECHLD_PING:
			case ECHLD_LIST_FILES:
			case ECHLD_CHK_FILTER:
			case ECHLD_LIST_INTERFACES:
			case ECHLD_GET_SUM:
			case ECHLD_GET_TREE:
			case ECHLD_GET_BUFFER:
			case ECHLD_ADD_NOTE:
			relay_frame:
				return echld_write_frame(c->write_fd, &in_ba, chld_id, type, reqh_id, NULL);

			default:
				dispatcher_err(ECHLD_ERR_WRONG_MSG, "wrong message %d %c", reqh_id, type);
				return 0;
		}
	}
}


int dispatcher_loop() {
	int parent_out = dispatcher->parent_out;
	int parent_in = dispatcher->parent_in.fd;

	struct dispatcher_child* children = dispatcher->children;

	do {
		fd_set rfds;
		fd_set efds;
		struct timeval timeout;
		struct dispatcher_child* c;
		int nfds;

		FD_ZERO(&rfds);
		FD_ZERO(&efds);

		FD_SET(parent_in,&rfds);
		FD_SET(parent_in,&efds);
		FD_SET(parent_out,&efds);

		for (c = children, nfds = 0; c->pid; c++) {
			if (c->chld_id) {
				FD_SET(c->reader.fd, &rfds);
				FD_SET(c->reader.fd, &efds);
			}
			nfds++;
		}

		nfds = select(nfds, &rfds, NULL, &efds, &timeout);

		if ( FD_ISSET(parent_in, &efds) || FD_ISSET(parent_out, &efds) ) {
			/* XXX deep shit */
			break;
		}

		if (FD_ISSET(parent_in, &rfds)) {
			int st = echld_read_frame(&(dispatcher->parent_in), dispatch_to_child, dispatcher);

			if (st < 0) {
				/* XXX */
				continue;
			}
		}

		for (c=children; c->pid; c++) {
			if (c->chld_id) {
				if ( FD_ISSET(c->reader.fd,&efds) ) {
					/* XXX cleanup child and report */
					continue;
				}

				if (FD_ISSET(c->reader.fd,&rfds)) {
					int st = echld_read_frame(&(c->reader), dispatch_to_parent, c);

					if (st < 0) {
						/* XXX cleanup child and report */
						continue;
					}
					continue;
				}
			}
		}
	} while(1);

	/* won't */
	return 1;
}

void echld_dispatcher_start(int* in_pipe_fds, int* out_pipe_fds) {
	static struct dispatcher d;
	int fdt_len = getdtablesize();
	int i;

	preinit_epan();

	signal(SIGCHLD,dispatcher_reaper);

	dispatcher = &d;

	echld_init_reader(&(d.parent_in),in_pipe_fds[0],4096);
	d.parent_out = out_pipe_fds[1];
	d.children = g_malloc0(ECHLD_MAX_CHILDREN * sizeof(struct dispatcher_child));
	d.max_children = ECHLD_MAX_CHILDREN;
	d.nchildren = 0;
	d.reqh_id = -1;
	d.pid = getpid();

	echld_get_all_codecs(&(d.enc.to_parent), &(d.dec.from_parent), &(d.enc.to_child), &(d.dec.from_child));

	dispatcher_clear();

	/* close all fds but those used */
	for(i=0;i<fdt_len;i++) {
		if ( i != d.parent_in.fd
			&& i != d.parent_out
			&& i != STDERR_FILENO ) {
			close(i);
		}
	}

	exit(dispatcher_loop());
}

