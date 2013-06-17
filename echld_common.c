/**
 the "epan pipe" protocol 
**/

#include "echld-int.h"

#include <arpa/inet.h>
#include "capture_ifinfo.h"

static void child_realloc_buff(echld_reader_t* r, size_t needed)

{
	size_t a = r->actual_len;
	size_t s = r->len;
	int rp_off = r->rp - r->data;

	if ( a < (s + needed) ) {
		guint8* data = r->data;
	
	   	do { 
			a *= 2;
		} while( a < (s + needed) );

	   data = g_realloc(data,a);

	   r->actual_len = a;
	   r->len = s;
	   r->data = data;
	   r->wp = data + s;
	   r->rp = data + rp_off;
	}
}

typedef void (*realloc_t)(echld_reader_t*, size_t); 
static realloc_t reader_realloc_buf = child_realloc_buff;

#ifdef PARENT_THREADS
static void parent_realloc_buff(echld_reader_t* b, size_t needed) {
	// parent thread: obtain malloc mutex
	child_realloc_buff
	// parent thread: release malloc mutex
}	
#endif



static void init_reader(echld_reader_t* r, int fd, size_t initial) {
	r->fd = fd;
	fcntl(fd, F_SETFL, O_NONBLOCK);

	if (r->data == NULL) {
		r->actual_len = initial;
		r->data = g_malloc0(initial);
		r->wp = r->data;
		r->rp = NULL;
		r->len = 0;
	}
}

static void free_reader(echld_reader_t* r) {
	free(r->data);
}

static int reader_readv(echld_reader_t* r, size_t len) {
	struct iovec iov;
	int nread;

	if ( (r->actual_len - r->len) < len ) 
		reader_realloc_buff(r, len);

	iov.iov_base = r->wp;
	iov.iov_len = len;

	nread = readv(0, &iov, len);

	if (nread >= 0) {
		r->wp += nread;
		r->len += nread;
	}

	return nread;
};


static int read_frame(echld_reader_t* r, read_cb_t cb, void* cb_data) {

    // it will use shared memory instead of inband communication
	do {
		hdr_t* h = (hdr_t*)r->rp;
		int nread;
		size_t fr_len;
		size_t missing;
		int off;

		if ( r->len < ECHLD_HDR_LEN) {
			/* read the header */
			goto incomplete_header;
		} else if ( ! reader_has_frame(r) ) {
			/* read the (rest of) the frame */
			goto incomplete_frame;
		}

		/* we've got a frame! */
		
		off = (fr_len = HDR_LEN(h)) + ECHLD_HDR_LEN;
			
		cb( &(r->rp[sizeof(hdr_t)]), HDR_LEN(h), h->h.chld_id, HDR_TYPE(h), h->h.reqh_id, cb_data);

		if ( r->len >= off ) {
			/* shift the consumed frame */
			r->len -= off;
			memcpy(r->rp ,r->rp + off ,r->len);
			r->wp -= off;
			r->rp -= off;
		}

		continue;
		
	incomplete_header:
		missing = ECHLD_HDR_LEN - (r->len);

		nread = reader_readv(r,missing);


		if (nread < 0) {
			goto kaput; /*XXX*/
		} else /* if (nread == 0) {
			break;
		} else */ if (nread < missing) {
			goto again;
		} else {
			goto incomplete_frame;
		}

	incomplete_frame:
		fr_len = HDR_LEN(h) + ECHLD_HDR_LEN;
		missing = fr_len  - r->len;

		nread = reader_readv(r,missing);


		if (nread < 0) {
			goto kaput; /*XXX*/
		} else if (nread <= missing) {
			goto again;
		}

	} while(1);

	return 0;
	again:	return 1;
	kaput:  return -1;
}




static int write_frame(int fd, GByteArray* ba, guint16 chld_id, echld_msg_type_t type, guint16 reqh_id, void* data) {
	static guint8* write_buf = NULL;
	static size_t wb_len = 4096;
	hdr_t* h;
	struct iovec iov;
	int fr_len = ba->len+ECHLD_HDR_LEN;

	data = data; //

    // it will use shared memory instead of inband communication

	if (! write_buf) {
		// lock if needed
		write_buf = g_malloc0(wb_len);
		// unlock if needed
	}

	if (fr_len > wb_len) {
		do {
			wb_len *= 2;
		} while (fr_len > wb_len);

		// lock if needed
		write_buf = g_realloc(write_buf,wb_len);
		// unlock if needed
	}

	h = (void*)write_buf;
	h->h.type_len  = (type<<24) | (((guint32)ba->len) & 0x00ffffff) ;
	h->h.chld_id = chld_id;
	h->h.reqh_id = reqh_id;

	memcpy(write_buf+ECHLD_HDR_LEN,ba->data,ba->len);

	iov.iov_base = write_buf;
	iov.iov_len = fr_len;

	return (int) writev(fd, &iov, fr_len);
}



/* encoders and decoders */





/* binary encoders and decoders used for parent->child communication */

static enc_msg_t* str_enc(const char* s) {
	GByteArray* ba = g_byte_array_new();
	g_byte_array_append(ba,s,strlen(s)+1);
	return (enc_msg_t*)ba;
}

static gboolean str_dec(guint8* b, size_t bs, char** text) {
	guint8* end = b+bs;
	b[bs-1] = '\0'; /* null terminate the buffer to avoid strlen running */
	*text = (char*)b;
	if (b+(strlen(b)+1) > end) return FALSE;
	return TRUE;
}

static gboolean str_deca(enc_msg_t* e, char** text) {
	GByteArray* ba = (void*)e;
	return str_dec(ba->data,ba->len,text);

}

static enc_msg_t* int_str_enc(int i, const char* s) {
	GByteArray* ba = g_byte_array_new();
	g_array_append(ba,&i,sizeof(int));
	g_array_append(ba,s,strlen(s)+1);
	return (enc_msg_t*)ba;
}

static gboolean int_str_dec(guint8* b, size_t bs, int* ip, char** text) {
	guint8* end = b+bs;
	b[bs-1] = '\0'; /* null terminate the buffer to avoid strlen running */

	if ((sizeof(int)) > bs) return FALSE;
	*ip = *((int*)b);
	b += (sizeof(int));
	*text = (char*)b;
	if ((b += (strlen(b)+1)) > end) return FALSE;

	return TRUE;
}

static gboolean int_str_deca(enc_msg_t* e, int* ip, char** text) {
	GByteArray* ba = (void*)e;
	return int_str_dec(ba->data,ba->len,ip,text);
}

static enc_msg_t* int_enc(int i) {
	GByteArray* ba = g_byte_array_new();
	g_array_append(ba,&i,sizeof(int));
	return (enc_msg_t*)ba;
}

static gboolean int_dec(guint8* b, size_t bs, int* ip) {
	if ((sizeof(int)) > bs) return FALSE;
	*ip = *((int*)b);
	return TRUE;
}

static gboolean int_deca(enc_msg_t* e, int* ip) {
	GByteArray* ba = (void*)e;
	return int_dec(ba->data,ba->len,ip);
}

static enc_msg_t* x2str_enc(const char* s1, const char* s2) {
	GByteArray* ba = g_byte_array_new();
	g_array_append(ba,s1,strlen(s1)+1);
	g_array_append(ba,s2,strlen(s2)+1);
	return (enc_msg_t*)ba;
}

static gboolean x2str_dec(guint8* b, size_t blen, char** str1, char** str2) {
	guint8* end = b+blen;
	b[blen-1] = '\0'; /* null terminate the buffer to avoid strlen running */

	*str1  = (char*)b;
	if ((b += (strlen(b)+1)) > end) return FALSE;
	*str2 = (char*)(b);
	if ((b += (strlen(b)+1)) > end) return FALSE;
	return TRUE;
}

static gboolean x2str_deca(enc_msg_t* e, char** str1, char** str2) {
	GByteArray* ba = (void*)e;
	return x2str_dec(ba->data,ba->len,str1,str2);
}

static gboolean int_3str_dec (guint8* b, size_t len, int* i, char** s1, char** s2, char** s3) {
	guint8* end = b+len;
	b[len-1] = '\0';

	if ((sizeof(int)) > len) return FALSE;
	*i = *((int*)b);
	b += sizeof(int);

	*s1 = (char*)b;
	if ((b += (strlen(b)+1)) > end) return FALSE;
	*s2 = (char*)(b);
	if ((b += (strlen(b)+1)) > end) return FALSE;
	*s3 = (char*)b;
	if ((b += (strlen(b)+1)) > end) return FALSE;
	return TRUE;
}

static enc_msg_t* int_3str_enc(int i,  const char* s1, const char* s2, const char* s3) {
	GByteArray* ba = g_byte_array_new();
	g_array_append(ba,&i,sizeof(int));
	g_array_append(ba,s1,strlen(s1)+1);
	g_array_append(ba,s2,strlen(s2)+1);
	g_array_append(ba,s3,strlen(s3)+1);
	return (enc_msg_t*)ba;
}

static gboolean int_3str_deca (enc_msg_t* e, int* i, char** s1, char** s2, char** s3) {
	GByteArray* ba = (void*)e;
	return int_3str_dec(ba->data,ba->len,i,s1,s2,s3);
}

static gboolean x3str_dec (guint8* b, size_t len, char** s1, char** s2, char** s3) {
	guint8* end = b+len;
	b[len-1] = '\0';


	*s1 = (char*)b;
	if ((b += (strlen(b)+1)) > end) return FALSE;
	*s2 = (char*)(b);
	if ((b += (strlen(b)+1)) > end) return FALSE;
	*s3 = (char*)b;
	if ((b += (strlen(b)+1)) > end) return FALSE;
	return TRUE;
}

static gboolean x3str_deca (enc_msg_t* e, char** s1, char** s2, char** s3) {
	GByteArray* ba = (void*)e;
	return x3str_dec(ba->data,ba->len,s1,s2,s3);
}


static enc_msg_t* x3str_enc(const char* s1, const char* s2, const char* s3) {
	GByteArray* ba = g_byte_array_new();
	g_array_append(ba,s1,strlen(s1)+1);
	g_array_append(ba,s2,strlen(s2)+1);
	g_array_append(ba,s3,strlen(s3)+1);
	return (enc_msg_t*)ba;
}

static echld_parent_encoder_t parent_encoder = {
	int_str_enc,
	x2str_enc,
	int_enc,
	str_enc,
	str_enc,
	x2str_enc,
	str_enc,
	str_enc,
	str_enc,
	int_str_enc,
	str_enc,
	str_enc,
	str_enc,
	x2str_enc
};

echld_parent_encoder_t* echld_get_encoder() {
	return &parent_encoder;
}

static child_decoder_t child_decoder = {
	int_str_dec,
	x2str_dec,
	int_dec,
	str_dec,
	str_dec,
	str_dec,
	x2str_dec,
	str_dec,
	str_dec,
	int_str_dec,
	str_dec,
	str_dec,
	x2str_dec 
};

static child_encoder_t  child_encoder = {
	int_str_enc,
	str_enc,
	x2str_enc,
	str_enc,
	int_str_enc,
	str_enc,
	str_enc,
	str_enc,
	int_str_enc,
	int_str_enc,
	int_3str_enc,
	x3str_enc
};

static parent_decoder_t parent_decoder = {
	int_str_deca,
	str_deca,
	x2str_deca,
	str_deca,
	int_str_deca,
	str_deca,
	str_deca,
	str_deca,
	int_str_deca,
	int_str_deca,
	int_3str_deca,
	x3str_deca
};

void echld_get_all_codecs( child_encoder_t **e, child_decoder_t **d, echld_parent_encoder_t **pe, parent_decoder_t** pd) {
	e && (*e = &child_encoder);
	d && (*d = &child_decoder);
	pe && (*pe = &parent_encoder);
	pd && (*pd = &parent_decoder);
}



/* output encoders, used in the switch */


static char* encode_intf_info_json(GList* if_list) {
	/* blatantly stolen from print_machine_readable_interfaces in dumpcap.c */
#define ADDRSTRLEN 46 /* Covers IPv4 & IPv6 */

    int         i;
    GList       *if_entry;
    if_info_t   *if_info;
    GSList      *addr;
    if_addr_t   *if_addr;
    char        addr_str[ADDRSTRLEN];
    GString     *str = g_string_new("={ ");
    char* s;

    i = 1;  /* Interface id number */
    for (if_entry = g_list_first(if_list); if_entry != NULL;
         if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        g_string_append_printf(str,"%d={ intf='%s',", i++, if_info->name);

        /*
         * Print the contents of the if_entry struct in a parseable format.
         * Each if_entry element is tab-separated.  Addresses are comma-
         * separated.
         */
        /* XXX - Make sure our description doesn't contain a tab */
        if (if_info->vendor_description != NULL)
            g_string_append_printf(str," vnd_desc='%s',", if_info->vendor_description);

        /* XXX - Make sure our friendly name doesn't contain a tab */
        if (if_info->friendly_name != NULL)
            g_string_append_printf(str," name='%s', addrs=[ ", if_info->friendly_name);

        for (addr = g_slist_nth(if_info->addrs, 0); addr != NULL;
                    addr = g_slist_next(addr)) {

            if_addr = (if_addr_t *)addr->data;
            switch(if_addr->ifat_type) {
            case IF_AT_IPv4:
                if (inet_ntop(AF_INET, &if_addr->addr.ip4_addr, addr_str,
                              ADDRSTRLEN)) {
                    g_string_append_printf(str,"%s", addr_str);
                } else {
                    g_string_append(str,"<unknown IPv4>");
                }
                break;
            case IF_AT_IPv6:
                if (inet_ntop(AF_INET6, &if_addr->addr.ip6_addr,
                              addr_str, ADDRSTRLEN)) {
                    g_string_append_printf(str,"%s", addr_str);
                } else {
                    g_string_append(str,"<unknown IPv6>");
                }
                break;
            default:
                g_string_append_printf(str,"<type unknown %u>", if_addr->ifat_type);
            }
        }

        g_string_append(str," ]"); /* addrs */


        if (if_info->loopback)
            g_string_append(str,", loopback=1");
        else
            g_string_append(str,", loopback=0");

        g_string_append(str,"}, ");
    }

    g_string_truncate(str,str->len - 2); /* the comma and space */
    g_string_append(str,"}");

    s=str->str;
    g_string_free(str,FALSE);
    return s;
}

static char* packet_summary_json(GByteArray* ba) {
	/* dummy */
	return g_strdup("{type='packet_summary', packet_summary={}");
}

static char* tree_json(GByteArray* ba) {
	/* dummy */
	return g_strdup("{type='tree', tree={}");
}

static char* tvb_json(GByteArray* ba, tvb_t* tvb, const char* name) {
	/* dummy */
	return g_strdup_printf("{type='buffer', buffer={name='%s', range='0-2', data=[0x12,0xff] }",name);
}

static char* error_json(GByteArray* ba) {
	char* s = (char*)(ba->data + sizeof(int));
	int i = *((int*)s);

	s = g_strdup_printf("{type='error', error={errnum=%d, message='%s'}}",i,s);

	return s;
}

static char* child_dead_json(GByteArray* ba) {
	char* s = (char*)(ba->data + sizeof(int));
	int i = *((int*)s);

	s = g_strdup_printf("{type='child_dead', child_dead={childnum=%d, message='%s'}}",i,s);

	return s;
}

static char* closing_json(GByteArray* ba) {
	char* s = (char*)(ba->data);
	s = g_strdup_printf("{type='closing', closing={reason='%s'}}",s);

	return s;
}

static char* cwd_json(GByteArray* ba) {
	char* s = (char*)(ba->data);
	s = g_strdup_printf("{type='cwd', cwd={dir='%s'}}",s);

	return s;
}

static char* file_info_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);
	char* s2 = ((char*)(ba->data)) + strlen(s1);

	s1 = g_strdup_printf("{type='file', file={filename='%s' info='%s'}}",s1,s2);

	return s1;
}


static char* note_added_json(GByteArray* ba) {
	char* s = (char*)(ba->data);
	s = g_strdup_printf("{ type='note_added', note_added={msg='%s'}}",s);

	return s;
}

static char* packet_list_json(GByteArray* ba) {
	return g_strdup("{}");
}

static char* file_saved_json(GByteArray* ba) {
	char* s = (char*)(ba->data);

	s = g_strdup_printf("{ type='file_saved', file_saved={msg='%s'}}",s);

	return s;
}



static char* param_set_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);
	char* s2 = ((char*)(ba->data)) + strlen(s1);

	s1 = g_strdup_printf("{type='param_set', param_set={param='%s' value='%s'}}",s1,s2);


	return s1;
}

static char* set_param_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);
	char* s2 = ((char*)(ba->data)) + strlen(s1);

	s1 = g_strdup_printf("{type='set_param', set_param={param='%s' value='%s'}}",s1,s2);


	return s1;
}

static char* get_param_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);

	s1 = g_strdup_printf("{type='get_param', get_param={param='%s'}}",s1);


	return s1;
}

static char* list_files_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);

	s1 = g_strdup_printf("{type='list_files', list_files={glob='%s'}}",s1);


	return s1;
}


static char* chk_filter_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);

	s1 = g_strdup_printf("{type='chk_filter', chk_filter={filter='%s'}}",s1);

	return s1;
}

static char* filter_ckd_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data + sizeof(int));
	int i = *((int*)ba->data);

	s1 = g_strdup_printf("{type='filter_ckd', filter_ckd={filter='%s',ok=%s}}",ba->data,i?"true":"false");

	return s1;
}

static char* set_filter_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);

	s1 = g_strdup_printf("{type='chk_filter', chk_filter={filter='%s'}}",s1);
	
	return s1;
}

static char* filter_set_json(GByteArray* ba) {
	char* s1 = (char*)(ba->data);

	s1 = g_strdup_printf("{type='filter_set', filter_set={filter='%s'}}",s1);
	
	return s1;
}


static char* file_opened_json(GByteArray* ba) {
	return g_strdup("");
}

static char* open_file_json(GByteArray* ba) {
	return g_strdup("");
}

static char* intf_info_json(GByteArray* ba) {
	return g_strdup("");
}

static char* open_interface_json(GByteArray* ba) {
	return g_strdup("");
}


static char* interface_opened_json(GByteArray* ba) {
	return g_strdup("");
}

static char* notify_json(GByteArray* ba) {
	return g_strdup("");
}

static char* get_tree_json(GByteArray* ba) {
	return g_strdup("");
}

static char* get_sum_json(GByteArray* ba) {
	return g_strdup("");
}

static char* get_buffer_json(GByteArray* ba) {
	return g_strdup("");
}

static char* buffer_json(GByteArray* ba) {
	return g_strdup("");
}

static char* add_note_json(GByteArray* ba) {
	return g_strdup("");
}

static char* apply_filter_json(GByteArray* ba) {
	return g_strdup("");
}

static char* save_file_json(GByteArray* ba) {
	return g_strdup("");
}


/* this to be used only at the parent */
char* echld_decode_json(echld_msg_type_t type, enc_msg_t* m) {
  	GByteArray* ba = (GByteArray*)m;

	switch(type) {
		case ECHLD_ERROR: return error_json(ba);
		case ECHLD_TIMED_OUT: return g_strdup("{type='timed_out'}");
		case ECHLD_NEW_CHILD: return g_strdup("{type='new_child'}");
		case ECHLD_HELLO: return g_strdup("{type='helo'}");
		case ECHLD_CHILD_DEAD: return child_dead_json(ba);
		case ECHLD_CLOSE_CHILD: return g_strdup("{type='close_child'}");
		case ECHLD_CLOSING: return g_strdup("{type='closing'}");
		case ECHLD_SET_PARAM: return set_param_json(ba);
		case ECHLD_GET_PARAM: return get_param_json(ba);
		case ECHLD_PARAM: return param_set_json(ba);
		case ECHLD_PING: return g_strdup("{type='ping'}");
		case ECHLD_PONG: return g_strdup("{type='pong'}");
		case ECHLD_LIST_FILES: return list_files_json(ba);
		case ECHLD_FILE_INFO: return file_info_json(ba);
		case ECHLD_CHK_FILTER: return chk_filter_json(ba);
		case ECHLD_FILTER_CKD: return filter_ckd_json(ba);
		case ECHLD_SET_FILTER: return set_filter_json(ba);
		case ECHLD_FILTER_SET: return filter_set_json(ba);
		case ECHLD_OPEN_FILE: return open_file_json(ba);
		case ECHLD_FILE_OPENED: return file_opened_json(ba);
		case ECHLD_LIST_INTERFACES: return g_strdup("{type='list_interfaces'}");
		case ECHLD_INTERFACE_INFO: return intf_info_json(ba);
		case ECHLD_OPEN_INTERFACE: return open_interface_json(ba);
		case ECHLD_INTERFACE_OPENED: return interface_opened_json(ba);
		case ECHLD_START_CAPTURE: return g_strdup("{type='start_capture'}");
		case ECHLD_CAPTURE_STARTED: return g_strdup("{type='capture_started'}");
		case ECHLD_NOTIFY: return notify_json(ba);
		case ECHLD_GET_SUM: return get_sum_json(ba);
		case ECHLD_PACKET_SUM: return packet_summary_json(ba);
		case ECHLD_GET_TREE: return get_tree_json(ba);
		case ECHLD_TREE: return tree_json(ba);
		case ECHLD_GET_BUFFER: return get_buffer_json(ba);
		case ECHLD_BUFFER: return buffer_json(ba);
		case ECHLD_EOF: return g_strdup("{type='eof'}");
		case ECHLD_STOP_CAPTURE: return g_strdup("{type='stop_capture'}");
		case ECHLD_CAPTURE_STOPPED: return g_strdup("{type='capture_stopped'}");
		case ECHLD_ADD_NOTE: return add_note_json(ba);
		case ECHLD_NOTE_ADDED: return note_added_json(ba);
		case ECHLD_APPLY_FILTER: return apply_filter_json(ba);
		case ECHLD_PACKET_LIST: return packet_list_json(ba);
		case ECHLD_SAVE_FILE: return save_file_json(ba);
		case ECHLD_FILE_SAVED: return g_strdup("{type='file_saved'}");
		case EC_ACTUAL_ERROR: return g_strdup("{type='actual_error'}");
		default: break;
	}

	return NULL;
}

extern void dummy_switch(echld_msg_type_t type) {
	switch(type) {
		case ECHLD_ERROR: break; //
		case ECHLD_TIMED_OUT: break;
		case ECHLD_NEW_CHILD: break;
		case ECHLD_HELLO: break; 
		case ECHLD_CHILD_DEAD: break; //S msg
		case ECHLD_CLOSE_CHILD: break;
		case ECHLD_CLOSING: break; //
		case ECHLD_SET_PARAM: break; 
		case ECHLD_GET_PARAM: break;
		case ECHLD_PARAM: break; //SS param,val
		case ECHLD_PING: break;
		case ECHLD_PONG: break; //
		case ECHLD_LIST_FILES: break;
		case ECHLD_FILE_INFO: break;  //SS info (pre-encoded)
		case ECHLD_CHK_FILTER: break;
		case ECHLD_FILTER_CKD: break; //IS ok,filter
		case ECHLD_SET_FILTER: break;
		case ECHLD_FILTER_SET: break; //S filter
		case ECHLD_OPEN_FILE: break; 
		case ECHLD_FILE_OPENED: break; //
		case ECHLD_LIST_INTERFACES: break;
		case ECHLD_INTERFACE_INFO: break; //S intf_list (pre-encoded)
		case ECHLD_OPEN_INTERFACE: break;
		case ECHLD_INTERFACE_OPENED: break; //
		case ECHLD_START_CAPTURE: break;
		case ECHLD_CAPTURE_STARTED: break; //
		case ECHLD_NOTIFY: break; //S notification (pre-encoded) 
		case ECHLD_GET_SUM: break;
		case ECHLD_PACKET_SUM: break; //S (pre-encoded)
		case ECHLD_GET_TREE: break;
		case ECHLD_TREE: break; //IS framenum,tree (pre-encoded)
		case ECHLD_GET_BUFFER: break;
		case ECHLD_BUFFER: break; //SSIS name,range,totlen,data
		case ECHLD_EOF: break; //
		case ECHLD_STOP_CAPTURE: break;
		case ECHLD_CAPTURE_STOPPED: break; //
		case ECHLD_ADD_NOTE: break;
		case ECHLD_NOTE_ADDED: break; //IS
		case ECHLD_APPLY_FILTER: break;
		case ECHLD_PACKET_LIST: break; //SS name,range
		case ECHLD_SAVE_FILE: break;
		case ECHLD_FILE_SAVED: break;
		case EC_ACTUAL_ERROR: break;
	}
}
