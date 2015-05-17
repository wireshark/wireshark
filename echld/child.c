/* echld_child.c
 *  epan working child internals
 *  Child process routines and definitions
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

typedef struct _child {
	child_state_t state;

	int pid;
	int dispatcher_pid;
	int chld_id;
	int reqh_id;
	echld_reader_t parent;
	struct _fds {
		int pipe_to_parent;
		int pipe_from_dumpcap;
		int pipe_to_dumpcap;
		int file_being_read;
	} fds;

	struct timeval started;
	struct timeval now;

	child_encoder_t* enc;
	child_decoder_t* dec;

	/* epan stuff */
	char* cf_name;
	char* cfilter;
	char* dfilter;


#if 0
	capture_file cfile;
#endif
	dfilter_t* df;

} echld_child_t;

static echld_epan_stuff_t* stuff = NULL;

static echld_child_t child;

struct _st_map {
	child_state_t id;
	const char* str;
};


#ifdef DEBUG_CHILD
static int debug_lvl = DEBUG_CHILD;
static FILE* debug_fp = NULL;
#define DBG_BUF_LEN 1024

#define DCOM()

int child_debug(int level, const char* fmt, ...) {
	va_list ap;
	char str[DBG_BUF_LEN];

	if (debug_lvl<level) return 1;

    va_start(ap, fmt);
	vsnprintf(str,DBG_BUF_LEN,fmt,ap);
	va_end(ap);

	fprintf(debug_fp, "child[%d-%d]: reqh_id=%d debug_lvl=%d message='%s'\n",
		child.chld_id, child.pid, child.reqh_id, level, str);

	return 1;
}

static char* param_get_dbg_level(char** err _U_) {
	return g_strdup_printf("%d",debug_lvl);
}

static echld_bool_t param_set_dbg_level(char* val , char** err ) {
	char* p;
	int lvl = (int)strtol(val, &p, 10);

	if (p<=val) {
		*err = g_strdup("not an integer");
		return FALSE;
	} else if (lvl < 0 || lvl > 5) {
		*err = g_strdup_printf("invalid level=%d (min=0 max=5)",lvl);
		return FALSE;
	}

	debug_lvl = lvl;
	DCOM();
	return TRUE;
}


static long dbg_resp(GByteArray* em, echld_msg_type_t t) {
	long st = echld_write_frame(child.fds.pipe_to_parent, em, child.chld_id, t, child.reqh_id, NULL);
	child_debug(1, "SND fd=%d ch=%d ty='%s' rh=%d msg='%s'",
		child.fds.pipe_to_parent, child.chld_id, TY(t), child.reqh_id, (st>0?"ok":g_strerror(errno)) );
	return st;
}

#define CHILD_DBG(attrs) ( child_debug attrs )
#define CHILD_DBG_INIT() do { debug_fp = stderr;  DCOM(); } while(0)
#define CHILD_DBG_START(fname) do { debug_fp = ws_fopen(fname,"a"); DCOM(); CHILD_DBG((0,"Log Started"));  } while(0)
#define CHILD_RESP(BA,T) dbg_resp(BA,T)
#define CHILD_STATE(ST) do { DISP_DBG((0,"State %s => %s")) } while(0)
#else
#define CHILD_DBG(attrs)
#define CHILD_DBG_INIT()
#define CHILD_DBG_START(fname)
#define CHILD_RESP(BA,T) echld_write_frame(child.fds.pipe_to_parent,(BA),child.chld_id,T,child.reqh_id,NULL)
#endif


static struct timeval close_sleep_time;


static void sig_term(int sig _U_) {
	CHILD_DBG((3,"Terminated, Closing"));
	exit(0);
}

extern void echld_child_initialize(echld_chld_id_t chld_id, int pipe_from_parent, int pipe_to_parent, int reqh_id, echld_epan_stuff_t* es) {
	stuff = es;

	close_sleep_time.tv_sec = CHILD_CLOSE_SLEEP_TIME / 1000000;
	close_sleep_time.tv_usec = CHILD_CLOSE_SLEEP_TIME % 1000000;

	child.chld_id = chld_id;
	child.state = IDLE;
	child.pid = getpid();
	child.dispatcher_pid = getppid();
	child.reqh_id = reqh_id;
	echld_init_reader( &(child.parent), pipe_from_parent,4096);
	child.fds.pipe_to_parent = pipe_to_parent;
	child.fds.pipe_from_dumpcap = -1;
	child.fds.pipe_to_dumpcap = -1;
	child.fds.file_being_read = -1;
	gettimeofday(&child.started,NULL);
	child.now.tv_sec = child.started.tv_sec;
	child.now.tv_usec = child.started.tv_usec;

	echld_get_all_codecs(&(child.enc), &(child.dec), NULL, NULL);

	CHILD_DBG_INIT();
	CHILD_DBG((5,"Child Initialized ch=%d from=%d to=%d rq=%d",chld_id, pipe_from_parent, pipe_to_parent, reqh_id));

	/*clear signal handlers */
	signal(SIGALRM,SIG_DFL);
	signal(SIGTERM,sig_term);
	signal(SIGPIPE,SIG_DFL);
	signal(SIGINT,SIG_DFL);
	signal(SIGABRT,SIG_DFL);
	signal(SIGHUP,SIG_DFL);

	/* epan stuff */
}



void child_err(int e, unsigned reqh_id, const char* fmt, ...) {
	size_t len= 1024;
	gchar err_str[len];
	va_list ap;
	static GByteArray* ba;

	va_start(ap, fmt);
	g_vsnprintf(err_str,len,fmt,ap);
	va_end(ap);

	CHILD_DBG((0,"error='%s'",err_str));

	ba = child.enc->error(e, err_str);
	echld_write_frame(child.fds.pipe_to_parent, ba, child.chld_id, ECHLD_ERROR, reqh_id, NULL);
	g_byte_array_free(ba,TRUE);
}


static char* param_get_cwd(char** err ) {
	char* pwd = getcwd(NULL, 128);

	if (!pwd) {
		*err = g_strdup(g_strerror(errno));
	}
	return pwd;
}

static echld_bool_t param_set_cwd(char* val , char** err ) {
	/* XXX SANITIZE */
	if (chdir(val) != 0) {
		*err = g_strdup_printf("cannot chdir reas='%s'",g_strerror(errno));
		return FALSE;
	}

	return TRUE;
}


static unsigned packet_count = 0;
static char* param_get_packet_count(char** err) {

	if (child.state != CAPTURING && child.state != READING) {
		*err = g_strdup("Must be reading or in-capture for packet_count");
		return NULL;
	}
	return g_strdup_printf("%d",packet_count);
}



static echld_bool_t param_set_dfilter(char* val , char** err) {
	dfilter_t *dfn = NULL;

	if (child.state != IDLE && child.state != DONE ) {
		*err = g_strdup("Only while idle or done");
		return FALSE;
	} else {
		if ( dfilter_compile(val, &dfn, err) ) {
			if (child.dfilter) g_free(child.dfilter);
			if (child.df) dfilter_free(child.df);
			child.df = dfn;
			child.dfilter = g_strdup(val);
			return TRUE;
		} else {
			return FALSE;
		}
	}
}

static char* param_get_dfilter(char** err _U_) { return g_strdup(child.dfilter ? child.dfilter : ""); }

char* param_profile = NULL;

static echld_bool_t param_set_profile(char* val , char** err ) {

	if (child.state != IDLE) {
		*err = g_strdup_printf("Cannot set Profile \"%s\", too late.", val);
		return FALSE;
	}

	if (profile_exists (val, FALSE)) {
		set_profile_name (val);
		if (param_profile) g_free(param_profile);
		param_profile = g_strdup(val);
		return TRUE;
	} else {
		*err = g_strdup_printf("Configuration Profile \"%s\" does not exist", val);
		return FALSE;
	}
}

static char* param_get_profile(char** err _U_) { return g_strdup(param_profile ? param_profile : ""); }

static char* param_get_file_list(char** err) {
	GError* gerror  = NULL;
	GDir* dir = g_dir_open(".", 0, &gerror);
	GString* str = g_string_new("{ what='file_list', files=[");
	const char* file;

	if (gerror) {
		*err = g_strdup_printf("Failed to open curr dir reason='%s'",gerror->message);
		return NULL;
	}

	while(( file = g_dir_read_name(dir) )) {
		g_string_append_printf(str,"{filename='%s'},\n",file);
	}
	g_dir_close(dir);

	g_string_truncate(str, str->len-2); /* ',\n' */
	g_string_append(str, "]}");

	return g_string_free(str,FALSE);
}

#ifdef PCAP_NG_DEFAULT
static int out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;
#else
static int out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAP;
#endif

static echld_bool_t param_set_out_file_type(char* val, char** err) {
      int oft = wtap_short_string_to_file_type_subtype(val);

      if (oft < 0) {
        *err = g_strdup_printf("\"%s\" isn't a valid capture file type", val);
        return FALSE;
      } else {
		out_file_type = oft;
		return TRUE;
	  }
}

static char* param_get_out_file_type(char** err _U_) {
	return g_strdup_printf("%s(%d): %s",
		wtap_file_type_subtype_short_string(out_file_type),
		out_file_type, wtap_file_type_subtype_string(out_file_type));
}


static echld_bool_t param_set_add_hosts_file(char* val, char** err) {
	if (add_hosts_file(val)) {
		return TRUE;
	} else {
		*err = g_strdup_printf("Can't read host entries from \"%s\"",val);
		return FALSE;
	}
}

PARAM_BOOL(quiet,FALSE);
PARAM_BOOL(start_capture,FALSE);
PARAM_BOOL(push_details,FALSE);
PARAM_BOOL(print_hex,FALSE);

static char* param_get_params(char** err _U_);

static param_t child_params[] = {
#ifdef DEBUG_CHILD
	PARAM(dbg_level,"Debug Level (0<int<5)"),
# endif
	PARAM(profile,"Configuration Profile (str)"),
	PARAM(cwd,"Current Directory (str)"),
	PARAM(dfilter,"Dispay Filter (str)"),
	RO_PARAM(packet_count,"Packets Read/Captured So Far (str)"),
	RO_PARAM(file_list,"List of Files in the Current Dir"),
	PARAM(start_capture,"Automatically start capture"),
	PARAM(quiet,"Quiet Mode"),
	PARAM(push_details,"Whether details of dissection should be passed"),
	PARAM(print_hex,"Output in hex"),
	PARAM(out_file_type,"Output File Type"),
	WO_PARAM(add_hosts_file,"Add a Hosts File"),
	RO_PARAM(params,"This List"),
	{NULL,NULL,NULL,NULL}
};

static char* param_get_params(char** err _U_) {
	return paramset_get_params_list(child_params,PARAM_LIST_FMT);
}

static void child_open_file(char* filename) {
	CHILD_DBG((2,"CMD open file filename='%s'",filename));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"open file not implemented yet!");
	child.state = READING;
}

static void child_open_interface(char* intf, char* pars) {
	CHILD_DBG((2,"CMD open interface intf='%s', params='%s'",intf,pars));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"open interface not implemented yet!");
	child.state = READY;
}

static void child_start_capture(void) {
	CHILD_DBG((2,"CMD start capture"));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"start capture not implemented yet!");
	child.state = CAPTURING;
}

static void child_stop_capure(void) {
	CHILD_DBG((2,"CMD stop capture"));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"stop capture not implemented yet!");
	child.state = DONE;
}

static void child_get_summary(char* range) {
	CHILD_DBG((2,"CMD get summary range='%s'",range));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"get_summary not implemented yet!");
}

static void child_get_tree(char* range)  {
	CHILD_DBG((2,"CMD get tree range='%s'",range));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"get_tree not implemented yet!");
}

static void child_get_buffer(char* name)  {
	CHILD_DBG((2,"CMD get buffer name='%s'",name));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"get_buffer not implemented yet!");
}

static void child_add_note(int framenum, char* note)  {
	CHILD_DBG((2,"CMD add note framenum=%d note='%s'",framenum,note));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"add_note not implemented yet!");
}

static void child_apply_filter(char* filter) {
	CHILD_DBG((2,"CMD apply filter filter='%s'",filter));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"apply_filter not implemented yet!");
}

static void child_save_file(char* filename, char* pars) {
	CHILD_DBG((2,"CMD save file filename='%s' params='%s'",filename,pars));
	child_err(ECHLD_ERR_UNIMPLEMENTED,child.reqh_id,"save_file not implemented yet!");
}

static long child_receive(guint8* b, size_t len, echld_chld_id_t chld_id, echld_msg_type_t type, echld_reqh_id_t reqh_id, void* data _U_) {
	GByteArray ba;
	GByteArray* gba;
	char* err = NULL;

	child.reqh_id = reqh_id;

	CHILD_DBG((2,"RCVD type='%s' len='%d'",TY(type),len));

#if 0
	gettimeofday(&(child.now), NULL);
#endif

	if (child.chld_id != chld_id) {
		child_err(ECHLD_ERR_WRONG_MSG,reqh_id,
			"chld_id: own:%d given:%d msg_type='%s'",child.chld_id,chld_id,TY(type));
		return 0;
	}

	ba.data = b;
	ba.len = (guint)len;

	switch(type) {
		case ECHLD_NEW_CHILD: {
			child.state = CREATING;
			if ( !paramset_apply_em(child_params,(enc_msg_t*)&ba, &err) ) {
				child_err(ECHLD_ERR_CRASHED_CHILD,reqh_id,
					"Initial Paramset Error '%s'",err);
			} else {
				child.state = IDLE;
				CHILD_RESP(NULL,ECHLD_HELLO);
			}
			break;
		}
		case ECHLD_PING:
			CHILD_DBG((1,"PONG"));
			CHILD_RESP(&ba,ECHLD_PONG);
			break;
		case ECHLD_SET_PARAM:{
			char* param;
			char* value;

			if ( child.dec->set_param && child.dec->set_param(b,len,&param,&value) ) {
				if (! paramset_apply_set (child_params, param, value, &err) ) {
					child_err(ECHLD_CANNOT_SET_PARAM,reqh_id,"%s",err);
					g_free(err);
					return 0;
				}

				gba = child.enc->param(param,value);
				CHILD_RESP(gba,ECHLD_PARAM);
				g_byte_array_free(gba,TRUE);
				CHILD_DBG((1,"Set Param: param='%s' value='%s'",param,value));

				break;
			} else {
				goto misencoded;
			}
		}
		case ECHLD_GET_PARAM: {
			char* param;
			if ( child.dec->get_param && child.dec->get_param(b,len,&param) ) {
				char* val;

				if (! (val = paramset_apply_get (child_params, param, &err)) ) {
					child_err(ECHLD_CANNOT_GET_PARAM,reqh_id,"%s",err);
					g_free(err);
					return 0;
				}

				gba = child.enc->param(param,val);
				CHILD_RESP(gba,ECHLD_PARAM);
				g_byte_array_free(gba,TRUE);
				CHILD_DBG((2,"Get Param: param='%s' value='%s'",param,val));
				break;
			} else {
				goto misencoded;
			}
		}
		case ECHLD_CLOSE_CHILD:
			CHILD_RESP(NULL,ECHLD_CLOSING);
			CHILD_DBG((3,"Closing"));
			select(0,NULL,NULL,NULL,&close_sleep_time);
			CHILD_DBG((1,"Bye"));
			exit(0);
			break;
		case ECHLD_OPEN_FILE: {
			char* filename;
			if (child.state != IDLE) goto wrong_state;

			if ( child.dec->open_file(b,len,&filename) ) {
				child_open_file(filename);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode open_file");
			}
			break;
		}
		case ECHLD_OPEN_INTERFACE: {
			char* intf;
			char* pars;

			if (child.state != IDLE) goto wrong_state;

			if ( child.dec->open_interface(b,len,&intf,&pars) ) {
				child_open_interface(intf,pars);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id, "cannot decode open_interface");
			}
			break;
		}
		case ECHLD_START_CAPTURE:{
			if (child.state != READY) goto wrong_state;
			child_start_capture();
			break;
		}
		case ECHLD_STOP_CAPTURE: {
			if (child.state != CAPTURING) goto wrong_state;
			child_stop_capure();
			break;
		}
		case ECHLD_GET_SUM: {
			char* range;

			if (child.state != CAPTURING && child.state != READING && child.state != DONE) goto wrong_state;

			if ( child.dec->get_sum(b,len,&range) ) {
				child_get_summary(range);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode get_summary");
			}
			break;
		}
		case ECHLD_GET_TREE:{
			char* range;

			if (child.state != CAPTURING && child.state != READING && child.state != DONE) goto wrong_state;

			if ( child.dec->get_tree(b,len,&range) ) {
				child_get_tree(range);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode get_tree");
			}
			break;
		}
		case ECHLD_GET_BUFFER:{
			char* name;

			if (child.state != CAPTURING && child.state != READING && child.state != DONE) goto wrong_state;

			if ( child.dec->get_buffer(b,len,&name) ) {
				child_get_buffer(name);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode get_buffer");
			}
			break;
		}
		case ECHLD_ADD_NOTE: {
			int framenum;
			char* note;

			if (child.state != CAPTURING && child.state != READING && child.state != DONE) goto wrong_state;

			if ( child.dec->add_note(b,len,&framenum,&note) ) {
				child_add_note(framenum,note);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode get_buffer");
			}
			break;
		}
		case ECHLD_APPLY_FILTER: {
			char* filter;

			if (child.state != DONE) goto wrong_state;

			if ( child.dec->apply_filter(b,len,&filter) ) {
				child_apply_filter(filter);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode apply_filter");
			}
			break;
		}
		case ECHLD_SAVE_FILE: {
			char* filename;
			char* pars;

			if (child.state != DONE) goto wrong_state;

			if ( child.dec->save_file(b,len,&filename,&pars) ) {
				child_save_file(filename,pars);
			} else {
				child_err(ECHLD_DECODE_ERROR,reqh_id,"cannot decode save_file");
			}
			break;
		}
		default:
			child_err(ECHLD_ERR_WRONG_MSG,reqh_id,"wrong message: chld_id=%d msg_type='%s'",chld_id,TY(type));
			break;
	}

	return 0;

	misencoded:
	/* dump the misencoded message (b,blen) */
	child_err(ECHLD_ERR_WRONG_MSG,reqh_id,"misencoded msg msg_type='%s'",TY(type));
	return 0;

	wrong_state:
	child_err(ECHLD_ERR_WRONG_MSG,reqh_id,"unexpected message: received in wrong state='%s', msg_type='%s'",ST(child.state),TY(type));
	return 0;

}

static int child_dumpcap_read(void) {
	/* this folk manages the reading of dumpcap's pipe
	 * it has to read interface descriptions when doing so
	 * and managing capture during capture
	 */
	CHILD_DBG((2,"child_dumpcap_read"));
	return FALSE;
}

static void child_file_read(void) {

}

int echld_child_loop(void) {
	int disp_from = child.parent.fd;
	int disp_to = child.fds.pipe_to_parent;

#ifdef DEBUG_CHILD
	int step = 0;
#endif

	CHILD_DBG((0,"entering child_loop()"));

	do {
		fd_set rfds;
		fd_set wfds;
		fd_set efds;
		struct timeval timeout;
		int nfds;
		gboolean captured = FALSE;

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);

		FD_SET(disp_from,&rfds);
		FD_SET(disp_from,&efds);
		FD_SET(disp_to,&efds);


		if (child.fds.pipe_from_dumpcap > 0) {
			FD_SET(child.fds.pipe_from_dumpcap,&rfds);
		}

#ifdef DEBUG_CHILD
		if (step <= 20) CHILD_DBG((4,"child_loop: select()ing step=%d",step++));
#endif
		timeout.tv_sec = 0;
		timeout.tv_usec = 999999;

		nfds = select(FD_SETSIZE, &rfds, &wfds, &efds, &timeout);
#ifdef DEBUG_CHILD
		if (step <= 20) CHILD_DBG((4,"child_loop: select()ed nfds=%d",nfds));
#endif

		if ( FD_ISSET(disp_from,&efds) ) {
			CHILD_DBG((0,"Broken Parent Pipe 'From' step=%d",step));
			break;
		}

		if ( FD_ISSET(disp_to,&efds) ) {
			CHILD_DBG((0,"Broken Parent Pipe 'To' step=%d",step));
			break;
		}

		if (child.fds.pipe_from_dumpcap > 0 &&  FD_ISSET(child.fds.pipe_from_dumpcap,&efds) ) {
			CHILD_DBG((0,"Broken Dumpcap Pipe step=%d",step));
			break;
		}

		if (FD_ISSET(disp_from, &rfds)) {
			long st = echld_read_frame(&(child.parent), child_receive, &child);

#ifdef DEBUG_CHILD
			step = 0;
#endif

			if (st < 0) {
				CHILD_DBG((0,"Read Frame Failed step=%d",step));
				return (int)st;
			}
		}

		if (child.fds.pipe_from_dumpcap > 0 && FD_ISSET(child.fds.pipe_from_dumpcap,&rfds) ) {

#ifdef DEBUG_CHILD
			step = 0;
#endif
			captured = child_dumpcap_read();
		}

		if ( child.state == READING || captured ) {
			child_file_read();
		}
	} while(1);


	CHILD_RESP(NULL,ECHLD_CLOSING);
	CHILD_DBG((3,"Closing"));
	return 222;
}


