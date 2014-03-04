/* parent.c
 *  epan working child API internals
 *  Parent process routines and definitions
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

#include "config.h"

#include "echld-int.h"

/**
 PARENT and API
 **/

#define MAX_PENDING_REQS 16;

typedef struct _req {
	int reqh_id;
	echld_msg_cb_t cb;
	void* cb_data;
	struct timeval tv;
} reqh_t;

typedef struct _hdlr {
	int id;
	echld_msg_type_t type;
	echld_msg_cb_t cb;
	void* cb_data;
} hdlr_t;

typedef struct _echld_child {
	int chld_id;
	void* data;
	echld_new_cb_t cb;
	child_state_t state;
	GArray* handlers;
	GArray* reqs;
} echld_t;

struct _echld_parent {
	echld_t* children;
	echld_reader_t reader;
	int dispatcher_fd;
	int dispatcher_pid;
	int reqh_id;
	GByteArray* snd;
	int closing;
	echld_parent_encoder_t* enc;
	parent_decoder_t* dec;
} parent  = {NULL,{NULL,0,NULL,-1,NULL,0},-1,-1,1,NULL,0,NULL,NULL};


static int reqh_ids = 1;


#ifdef DEBUG_PARENT

static int dbg_level = DEBUG_PARENT;

static void parent_dbg(int level, const char* fmt, ...) {
	va_list ap;
	char str[1024];

	if (level > dbg_level) return;

	va_start(ap,fmt);
	g_vsnprintf(str,1024,fmt,ap);
	va_end(ap);

	fprintf(stderr,"ParentDebug: level=%d msg='%s'\n",level,str);
	fflush(stderr);
}

#define PARENT_DBG(attrs) parent_dbg attrs
#define PARENT_SEND(BYTEARR,CHILDNUM,TYPE,R_ID) do {  long st = echld_write_frame(parent.dispatcher_fd, BYTEARR, CHILDNUM, TYPE, R_ID, NULL); PARENT_DBG((1,"SEND type='%s' chld_id=%d reqh_id=%d err_msg='%s'",TY(TYPE),CHILDNUM,R_ID, ( st >= 8 ? "ok" : ((st<0)?strerror(errno):"?") )  )); } while(0)

#else
#define PARENT_DBG(attrs)
#define PARENT_SEND(BYTEARR,CHILDNUM,TYPE,R_ID) echld_write_frame(parent.dispatcher_fd, BYTEARR, CHILDNUM, TYPE, R_ID, NULL)
#endif

extern void echld_set_parent_dbg_level(int lvl) {
	(dbg_level = lvl);
	if (lvl > 6) {
		echld_common_set_dbg(lvl,stderr,"parent");
	}
	PARENT_DBG((0,"Debug Level Set: %d",lvl));
}


#define PARENT_FATAL(attrs) parent_fatal attrs

static void parent_fatal(int exit_code, const char* fmt, ...) {
	va_list ap;
	char str[1024];

	va_start(ap,fmt);
	g_vsnprintf(str,1024,fmt,ap);
	va_end(ap);

#ifdef DEBUG_PARENT
	PARENT_DBG((0,"Fatal error: exit_code=%d str=%s",exit_code,str));
#else
	fprintf(stderr,"Fatal error: exit_code=%d str=%s",exit_code,str);
#endif

	kill(parent.dispatcher_pid,SIGTERM);
	exit(exit_code);
}

static void echld_cleanup(void) {
	// int i;

	PARENT_DBG((4,"echld_cleanup starting"));

	// for (i=0;i<ECHLD_MAX_CHILDREN;i++) {
	// 	if ( parent.children[i].handlers ) g_array_free(parent.children[i].handlers,TRUE);
	// 	if ( parent.children[i].reqs ) g_array_free(parent.children[i].reqs,TRUE);
	// };

	// g_free(parent.children);

	// g_byte_array_free(parent.snd,TRUE);

	PARENT_DBG((3,"echld_cleanup done"));

}

static void parent_child_cleanup(echld_t* c) {

	PARENT_DBG((2,"cleanup chld_id=%d",c->chld_id));
	c->chld_id = -1;
	c->data = NULL;
	c->state = FREE;
	g_array_set_size(c->handlers,0);
	g_array_set_size(c->reqs,0);
}


void parent_reaper(int sig) {
	int pid;
	int status;

	if (sig == SIGCHLD) {
		PARENT_FATAL((3333,"Must be SIGCHLD!"));
	}

	pid =  waitpid(-1, &status, WNOHANG);
	PARENT_DBG((2,"SIGCHLD pid=%d",pid));

	if (pid == parent.dispatcher_pid) {

		if (! parent.closing) {
			/* crashed */
			sleep(120);
			PARENT_FATAL((DISPATCHER_DEAD,"Dispatcher process dead"));
		}

		return;
	} else {
		/* XXX: do we care? */
		return;
	}

	return;
}

static echld_bool_t hello_cb(echld_msg_type_t type, enc_msg_t* msg_buff, void* ud) {
	echld_init_t* init = (echld_init_t*)ud;
	char* err = NULL;
	int errnum = 0;

	if (init && init->dispatcher_hello_cb) {
		switch(type) {
			case ECHLD_ERROR:
				parent.dec->error(msg_buff, &errnum ,&err);
				break;
			case ECHLD_TIMED_OUT:
				err = g_strdup("timedout");
				break;
			default:
				err = g_strdup_printf("Wrong MSG 'HELLO' expected, got '%s",TY(type));
				break;
			case ECHLD_HELLO:
				break;
		}

		init->dispatcher_hello_cb(ud,err);
		if (err) g_free(err);
	}

	return TRUE;
}



/* will initialize epan registering protocols and taps */
void echld_initialize(echld_init_t* init) {
	int from_disp[2];
	int to_disp[2];
	PARENT_DBG((1,"Echld Starting"));

	if (!init) {
		PARENT_FATAL((NO_INITIALIZER,"Missing Initializer"));
	}

	if (init->encoding != ECHLD_ENCODING_JSON) {
		PARENT_FATAL((UNIMPLEMENTED,"Only JSON implemented"));
	}

	if ( pipe(to_disp) ) {
		PARENT_FATAL((DISPATCHER_PIPE_FAILED,"Failed to open pipe to dispatcher"));
	} else if( pipe(from_disp) )  {
		PARENT_FATAL((DISPATCHER_PIPE_FAILED,"Failed to open pipe from dispatcher"));
	} else {
		int pid;
		int i;

		PARENT_DBG((3,"Pipes Opened fr[0]=%d fr[1]=%d to[0]=%d to[1]=%d",from_disp[0],from_disp[1],to_disp[0],to_disp[1]));

		pid = fork();

		if ( pid < 0 ) {
			PARENT_FATAL((CANNOT_FORK,"Failed to fork() reason='%s'",strerror(errno)));
		} else if ( pid == 0) {
#ifdef PARENT_THREADS
			reader_realloc_buf =  child_realloc_buff;
#endif
			/* child code */
			echld_cleanup();

			if (init->after_fork_cb)
				init->after_fork_cb(init->after_fork_cb_data);

			echld_dispatcher_start(to_disp,from_disp,init->argv0,init->main);

			PARENT_FATAL((SHOULD_HAVE_EXITED_BEFORE,"This shouldn't happen"));
		} else {
			/* parent code */
	#ifdef PARENT_THREADS
			reader_realloc_buf =  parent_realloc_buff;
	#endif

			/* echld_common_set_dbg(9,stderr,"parent"); */

			PARENT_DBG((3,"Dispatcher forked"));

			echld_get_all_codecs(NULL, NULL, &parent.enc, &parent.dec);
			parent.children = g_new0(echld_t,ECHLD_MAX_CHILDREN);
			parent.snd = g_byte_array_new();
			parent.dispatcher_fd = to_disp[1];
			parent.dispatcher_pid = pid;

			echld_init_reader(&(parent.reader),from_disp[0],4096);


			for (i=0;i<ECHLD_MAX_CHILDREN;i++) {
				parent.children[i].chld_id = -1;
				parent.children[i].data = NULL;
				parent.children[i].state = FREE;
				parent.children[i].handlers = g_array_new(TRUE,TRUE,sizeof(hdlr_t));
				parent.children[i].reqs = g_array_new(TRUE,TRUE,sizeof(reqh_t));
			}

			parent.children[0].chld_id = 0;
			parent.children[0].state = IDLE;

			signal(SIGCHLD,parent_reaper);
			//close(to_disp[0]);
			//close(from_disp[1]);
			if (init->dispatcher_hello_cb) echld_msgh(0, ECHLD_HELLO, hello_cb, init);

			PARENT_DBG((3,"Ready"));
		}
	}
}


extern echld_state_t echld_terminate(void) {

	parent.closing = TRUE;
	PARENT_SEND(NULL,0,ECHLD_CLOSE_CHILD,++reqh_ids);

	do {;} while(sleep(1)); /* wait a full sec without signals */

	echld_cleanup();
	close(parent.dispatcher_fd);
	kill(parent.dispatcher_pid,SIGTERM);
	return TRUE;
}




static echld_t* get_child(int id) {
	int i;
	for (i=0;i<ECHLD_MAX_CHILDREN;i++) {
		if (parent.children[i].chld_id == id) return &(parent.children[i]);
	};

	return NULL;
}


/* send a request */

int reqh_id_idx(echld_t* c, int reqh_id) {
	int i;
	int imax = c->reqs->len;
	reqh_t* rr = (reqh_t*)c->reqs->data;

	for(i=0; i < imax ; i++) {
		if (rr[i].reqh_id == reqh_id)
			return i;
	}

	return -1;
}


static echld_state_t reqh_snd(echld_t* c, echld_msg_type_t t, GByteArray* ba, echld_msg_cb_t resp_cb, void* cb_data) {
	int idx;
	reqh_t* r;
	int reqh_id = reqh_ids++;

	if (!c) {
		PARENT_DBG((1,"REQH_SND: No such child"));
		return 1;
	}

	idx = reqh_id_idx(c,-1);
	if (idx < 0) {
		reqh_t req;
		idx = c->reqs->len;
		g_array_append_val(c->reqs,req);
	}

	r = &(((reqh_t*)c->reqs->data)[idx]);

	r->reqh_id = reqh_id;
	r->cb = resp_cb;
	r->cb_data = cb_data;

	gettimeofday(&(r->tv),NULL);

	PARENT_DBG((4,"reqh_add: idx='%d'",idx));

	PARENT_DBG((3,"REQH_SND: type='%s' chld_id=%d reqh_id=%d",TY(t), c->chld_id,reqh_id));

	PARENT_SEND(ba,c->chld_id,t,reqh_id);

	if (ba) g_byte_array_free(ba,TRUE); /* do we? */

	return reqh_id;
}


extern echld_reqh_id_t echld_reqh(
		echld_chld_id_t child_id,
		echld_msg_type_t t,
		int usecs_timeout _U_,
		enc_msg_t* ba,
		echld_msg_cb_t resp_cb,
		void* cb_data) {
	return reqh_snd(get_child(child_id),t,ba,resp_cb,cb_data);
}

/* get callback data for a live request */
extern void* echld_reqh_get_data(int child_id, int reqh_id) {
	echld_t* c = get_child(child_id);
	int idx;

	if (!c) return NULL;

	idx = reqh_id_idx(c,reqh_id);

	if (idx >= 0)
		return g_array_index(c->reqs, reqh_t, idx).cb_data;
	else
		return NULL;
}

/* get the callback for a live request */
extern echld_msg_cb_t echld_reqh_get_cb(int child_id, int reqh_id) {
	echld_t* c = get_child(child_id);
	int idx;

	if (!c) return NULL;

	idx = reqh_id_idx(c,reqh_id);

	if (idx >= 0)
		return g_array_index(c->reqs, reqh_t, idx).cb;
	else
		return NULL;
}

/* set callback data for a live request */
extern gboolean echld_reqh_set_data(int child_id, int reqh_id, void* cb_data) {
	echld_t* c = get_child(child_id);
	int idx;

	if (!c) return FALSE;

	idx = reqh_id_idx(c,reqh_id);

	if (idx < 0) return FALSE;

	g_array_index(c->reqs, reqh_t, idx).cb_data = cb_data;

	return TRUE;
}

/* get the callback for a live request */
extern gboolean echld_reqh_set_cb(int child_id, int reqh_id, echld_msg_cb_t cb){
	echld_t* c = get_child(child_id);
	int idx;

	if (!c) return FALSE;

	idx = reqh_id_idx(c,reqh_id);

	if (idx < 0) return FALSE;

	g_array_index(c->reqs, reqh_t, idx).cb = cb;
	return TRUE;
}


/* stop receiving a live request */
extern gboolean echld_reqh_detach(int child_id, int reqh_id) {
	echld_t* c = get_child(child_id);
	int idx;

	if (!c) return FALSE;

	idx = reqh_id_idx(c,reqh_id);

	if (idx < 0) return FALSE;

	g_array_remove_index(c->reqs,idx);

	return TRUE;
}


static echld_bool_t parent_dead_child(echld_msg_type_t type, enc_msg_t* ba, void* data) {
	echld_t* c = (echld_t*)data;
	char* s;

	if (type !=  ECHLD_CHILD_DEAD) {
		PARENT_DBG((1, "Must Be ECHLD_CHILD_DEAD"));
		return 1;
	}

	if ( parent.dec->child_dead(ba,&s) ) {
		PARENT_DBG((1,"Dead Child[%d]: %s",c->chld_id,s));
		g_free(s);
	}

	parent_child_cleanup(c);
	return 0;
}

static echld_bool_t parent_get_hello(echld_msg_type_t type, enc_msg_t* ba, void* data) {
	echld_t* c = (echld_t*)data;
	int err_id;
	char* err = NULL;

	switch (type) {
		case  ECHLD_HELLO:
			PARENT_DBG((1,"Child[%d]: =>IDLE",c->chld_id));
			c->state = IDLE;
			break;
		case ECHLD_ERROR:
			parent.dec->error(ba,&err_id,&err);
			break;
		case ECHLD_TIMED_OUT:
			err = g_strdup("timedout");
			break;
		default:
			err = g_strdup_printf("Wrong MSG 'HELLO' expected, got '%s",TY(type));
			break;
	}

	if (c->cb)
		c->cb(c->data,err);

	if (err) g_free(err);

	return TRUE;
}





int chld_cmp(const void *a, const void *b) {
	return ((echld_t*)b)->chld_id - ((echld_t*)a)->chld_id;
}

static int msgh_attach(echld_t* c, echld_msg_type_t t, echld_msg_cb_t resp_cb, void* cb_data);

static int next_chld_id = 1;

extern int echld_new(enc_msg_t* new_child_em, echld_new_cb_t cb, void* child_data) {
	echld_t* c = get_child(-1);

	if (!c) return -1;

	c->chld_id = (next_chld_id++);
	c->data = child_data;
	c->state = CREATING;
	c->cb = cb;

	PARENT_DBG((1,"Child[%d]: =>CREATING",c->chld_id));

	msgh_attach(c,ECHLD_CHILD_DEAD, parent_dead_child , c);
    reqh_snd(c, ECHLD_NEW_CHILD, (GByteArray*)new_child_em, parent_get_hello, c);

	return c->chld_id;
}



/* XXX these fail silently */
extern void* echld_get_data(int child_id) {
	echld_t* c = get_child(child_id);
	return c ? c->data : NULL;
}

extern echld_state_t echld_set_data(echld_chld_id_t chld_id, void* data) {
	echld_t* c = get_child(chld_id);
	if (c) {
		c->data = data;
		return TRUE;
	}

	return FALSE;
}

static int msgh_idx(echld_t* c, int msgh_id) {
	int i  = 0;
	int imax = c->handlers->len;

	for (i=0;i<imax;i++) {
		if (((hdlr_t*)(c->handlers->data))[i].id == msgh_id) return i;
	}

	return -1;
}

/* start a message handler */
static int msgh_attach(echld_t* c, echld_msg_type_t t, echld_msg_cb_t resp_cb, void* cb_data) {
	hdlr_t h;
	static int msgh_id = 1;

	h.id = msgh_id++;
	h.type = t;
	h.cb = resp_cb;
	h.cb_data = cb_data;

	g_array_append_val(c->handlers,h);
	return 0;
}

extern int echld_msgh(int child_id, echld_msg_type_t t, echld_msg_cb_t resp_cb, void* cb_data) {
	echld_t* c = get_child(child_id);

	if (c) return msgh_attach(c,t,resp_cb,cb_data);
	else return -1;
}


/* stop it */
static echld_state_t msgh_detach(echld_t* c, int msgh_id) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return -1;

	g_array_remove_index(c->handlers,idx);

	return 1;
}

extern echld_state_t echld_msgh_detach(int child_id, int msgh_id) {
	echld_t* c = get_child(child_id);
	return msgh_detach(c,msgh_id);
}

/* get a msgh's data */

static void* msgh_get_data(echld_t* c, int msgh_id) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return NULL;

	return ((hdlr_t*)(c->handlers->data))[idx].cb_data;
}

extern void* echld_msgh_get_data(int child_id, int msgh_id) {
	echld_t* c = get_child(child_id);
	return msgh_get_data(c,msgh_id);
}

/* get a msgh's cb */
static echld_msg_cb_t msgh_get_cb(echld_t* c, int msgh_id) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return NULL;

	return ((hdlr_t*)(c->handlers->data))[idx].cb;
}

extern echld_msg_cb_t echld_msgh_get_cb(int child_id, int msgh_id) {
	echld_t* c = get_child(child_id);
	return msgh_get_cb(c,msgh_id);
}

/* get a msgh's type */
static echld_msg_type_t msgh_get_type(echld_t* c, int msgh_id) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return EC_ACTUAL_ERROR;

	return ((hdlr_t*)(c->handlers->data))[idx].type;
}

extern echld_msg_type_t echld_msgh_get_type(int child_id, int msgh_id) {
	echld_t* c = get_child(child_id);
	return c ? msgh_get_type(c,msgh_id) : EC_ACTUAL_ERROR;
}

/* get it all from a msgh */
static echld_state_t msgh_get_all(echld_t* c, int msgh_id, echld_msg_type_t* t, echld_msg_cb_t* cb, void** data) {
	int idx = msgh_idx(c,msgh_id);
	hdlr_t* h;

	if (idx < 0) return -1;

	h = &(((hdlr_t*)(c->handlers->data))[idx]);

	if (t) *t = h->type;
	if (cb) *cb = h->cb;
	if (data) *data = h->cb_data;

	return 0;
}

extern gboolean echld_msgh_get_all(int child_id, int msgh_id, echld_msg_type_t* t, echld_msg_cb_t* cb, void** data) {
	echld_t* c = get_child(child_id);
	return c && msgh_get_all(c,msgh_id,t,cb,data);
}

static echld_state_t msgh_set_all(echld_t* c, int msgh_id, echld_msg_type_t t, echld_msg_cb_t cb, void* data) {
	int idx = msgh_idx(c,msgh_id);
	hdlr_t* h;

	if (idx < 0) return -1;

	h = &(((hdlr_t*)(c->handlers->data))[idx]);

	h->type = t;
	h->cb = cb;
	h->cb_data = data;

	return 0;
}

extern gboolean echld_msgh_set_all(int child_id, int msgh_id, echld_msg_type_t t, echld_msg_cb_t cb, void* data) {
	echld_t* c = get_child(child_id);
	return c ? msgh_set_all(c,msgh_id,t,cb,data) : FALSE;
}

/* set a msgh's data */
static gboolean msgh_set_data(echld_t* c, int msgh_id, void* data) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return FALSE;

	((hdlr_t*)(c->handlers->data))[idx].cb_data = data;

	return TRUE;

}

extern gboolean echld_msgh_set_data(int child_id, int msgh_id, void* data){
	echld_t* c = get_child(child_id);
	return c ? msgh_set_data(c,msgh_id,data) : FALSE;
}

/* set a msgh's cb */
extern gboolean msgh_set_cb(echld_t* c, int msgh_id, echld_msg_cb_t cb) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return FALSE;

	((hdlr_t*)(c->handlers->data))[idx].cb = cb;

	return TRUE;
}

extern gboolean echld_msgh_set_cb(int child_id, int msgh_id, echld_msg_cb_t cb) {
	echld_t* c = get_child(child_id);
	return c ? msgh_set_cb(c,msgh_id,cb) : FALSE;
}

/* set a msgh's type */

static gboolean msgh_set_type(echld_t* c, int msgh_id, echld_msg_type_t t) {
	int idx = msgh_idx(c,msgh_id);

	if (idx < 0) return FALSE;

	((hdlr_t*)(c->handlers->data))[idx].type = t;

	return TRUE;
}

extern gboolean echld_msgh_set_type(int child_id, int msgh_id, echld_msg_type_t t) {
	echld_t* c = get_child(child_id);
	return c ? msgh_set_type(c,msgh_id,t) : FALSE;
}


/* call cb(id,child_data,cb_data) for each child*/
extern void echld_foreach_child(echld_iter_cb_t cb, void* cb_data) {
	int i;
	for(i=0;i<ECHLD_MAX_CHILDREN;i++) {
		echld_t* c = &(parent.children[i]);
		cb(c->chld_id,c->data,cb_data);
	}
}

static reqh_t* get_req(echld_t* c, int reqh_id) {
	int idx = reqh_id_idx(c,reqh_id);
	if(idx < 0) return NULL;

	return ((reqh_t*)(c->reqs->data))+idx;
}

static hdlr_t* get_next_hdlr_for_type(echld_t* c, echld_msg_type_t t, int* cookie) {
	int imax = c->handlers->len;
	hdlr_t* r = NULL;

	for (;(*cookie)<imax;(*cookie)++) {
		if (((hdlr_t*)(c->handlers->data))[*cookie].type == t) {
			r =  &( ((hdlr_t*)(c->handlers->data))[*cookie] );
			(*cookie)++;
			break;
		}
	}

	return r;
}

static long parent_read_frame(guint8* b, size_t len, echld_chld_id_t chld_id, echld_msg_type_t t, echld_reqh_id_t reqh_id, void* data _U_) {
	echld_t* c = get_child(chld_id);
	GByteArray* ba = g_byte_array_new();

	PARENT_DBG((1,"MSG_IN<- ch=%d t='%s' rh=%d",chld_id,TY(t),reqh_id));
	g_byte_array_append(ba,b, (guint)len);

	if (c) {
		reqh_t* r = get_req(c, reqh_id);
		int i;
		hdlr_t* h;
		gboolean go_ahead = TRUE;

		if (r) { /* got that reqh_id */
			if (r->cb)  {
				go_ahead = r->cb(t,ba,r->cb_data);
			}

			r->reqh_id = -1;
			r->cb = NULL;
			r->cb_data = 0;
			r->tv.tv_sec = 0;
			r->tv.tv_usec = 0;

			PARENT_DBG((2,"handled by reqh_id=%d msg='%s'",reqh_id,go_ahead?"retrying":"done"));
		}

		i=0;
		while(go_ahead && ( h = get_next_hdlr_for_type(c,t,&i))) {
				if (h->cb)
					go_ahead = h->cb(t,ba,h->cb_data);

				PARENT_DBG((2,"handled by t='%s' msgh_id=%d msg='%s'",TY(h->type), h->id,go_ahead?"retrying":"done"));
		}
	} else {
		PARENT_DBG((1,"parent_read_frame: No such child"));
	}

	g_byte_array_free(ba,TRUE);
	return 1;
}

extern int echld_fdset(fd_set* rfds, fd_set* efds) {
	FD_SET(parent.reader.fd, rfds);
	FD_SET(parent.reader.fd, efds);
	FD_SET(parent.dispatcher_fd, efds);
	return 2;
}

extern int echld_fd_read(fd_set* rfds, fd_set* efds) {
	int r_nfds=0;
	if (FD_ISSET(parent.reader.fd,efds) || FD_ISSET(parent.dispatcher_fd,efds) ) {
		/* Handle errored dispatcher */
		PARENT_DBG((1,"parent errored"));
		return -1;
	}

	if (FD_ISSET(parent.reader.fd,rfds)) {
		PARENT_DBG((3,"reading from dispatcher"));
		echld_read_frame(&(parent.reader),parent_read_frame,&(parent));
	}

	return r_nfds;
}

extern int echld_select(int nfds _U_, fd_set* rfds, fd_set* wfds, fd_set* efds, struct timeval* timeout) {
	fd_set my_rfds, my_wfds, my_efds;
	int r_nfds;


	if (rfds == NULL) { rfds = &my_rfds; FD_ZERO(rfds); }
	if (wfds == NULL) { wfds = &my_wfds; FD_ZERO(wfds); }
	if (efds == NULL) { efds = &my_efds; FD_ZERO(efds); }

	echld_fdset(rfds,efds);

	PARENT_DBG((5,"Select()"));
	r_nfds = select(FD_SETSIZE, rfds, wfds, efds, timeout);

	echld_fd_read(rfds,efds);

	return r_nfds ;
}

extern echld_state_t echld_wait(struct timeval* timeout) {
	if ( echld_select(0, NULL, NULL, NULL, timeout) < 0) {
		return -1;
	} else {
		return ECHLD_OK;
	}
}

enc_msg_t* echld_new_child_params(void) {
	return (enc_msg_t*)g_byte_array_new();
}

enc_msg_t* echld_new_child_params_merge(enc_msg_t* em1, enc_msg_t* em2) {
	GByteArray* ba = g_byte_array_new();
	GByteArray* b1 = (GByteArray*)em1;
	GByteArray* b2 = (GByteArray*)em2;

	g_byte_array_append(ba,b1->data,b1->len);
	g_byte_array_append(ba,b2->data,b2->len);

	return (enc_msg_t*)ba;
}

char* echld_new_child_params_str(enc_msg_t* em, const char* prefix, const char* postfix, int trunc_n, const char* fmt) {
	GByteArray* ba = (GByteArray*)em;
	GString* str = g_string_new(prefix);
	char* p = (char*) ba->data;
	int tot_len = ba->len;
	long rem = tot_len;
	p[rem-1] = '\0'; /* make sure last char is null */

	while(rem > 2) {
		char* param = p;
		long param_len = strlen(param)+1;
		char* value = p + param_len;
		long value_len;

		rem -= param_len;

		if (rem < 0) {
			g_string_free(str,TRUE);
			return NULL;
		}

		value_len = strlen(value)+1;

		rem -= value_len;
		p = value + value_len;

		if (rem < 0) {
			g_string_free(str,TRUE);
			return NULL;
		}

		g_string_append_printf(str,fmt,param,value);
	}
	g_string_truncate(str, str->len - trunc_n);
	g_string_append(str,postfix);
	p = str->str;
	g_string_free(str,FALSE);
	return p;
}

void echld_new_child_params_add_params(enc_msg_t* em, ...) {
	GByteArray* ba = (GByteArray*) em;
	va_list ap;

	va_start(ap,em);
	do {
		char* param_str = va_arg(ap, char*);

		if (param_str) {
			char* val_str = va_arg(ap, char*);

			g_byte_array_append(ba, (guint8*) param_str, (guint)strlen(param_str)+1);
			g_byte_array_append(ba, (guint8*) val_str, (guint)strlen(val_str)+1);
			continue;
		}

		break;
	} while(1);
	va_end(ap);

}


