/*
 * k12.c
 *
 *  routines for importing tektronix k12xx *.rf5 files
 *
 *  Copyright (c) 2005, Luis E. Garia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "wtap-int.h"
#include "wtap.h"
#include "file_wrappers.h"
#include "buffer.h"

/*
 * the 32 bits .rf5 file contains:
 *  an 8 byte magic number
 *  32bit lenght
 *  32bit number of records
 *  other 0x200 bytes bytes of uncharted territory
 *     1 or more copies of the num_of_records in there
 *  the records whose first 32bits word is the length
 *     they are stuffed by one to four words every 0x2000 bytes
 *  and a 2 byte terminator FFFF
 */

static const guint8 k12_file_magic[] = { 0x00, 0x00, 0x02, 0x00 ,0x12, 0x05, 0x00, 0x10 };

struct _k12_t {
	guint32 file_len;
	guint32 num_of_records; /* XXX: not sure about this */
	
	GHashTable* src_by_id; /* k12_srcdsc_recs by src_id */
	GHashTable* src_by_name; /* k12_srcdsc_recs by stack_name */
};

#define K12_HDR_LEN 0x10

typedef struct _k12_record_hdr_t {
	guint32 len;
	guint32 type;
	guint32 frame_len;
	guint32 input;
} k12_record_hdr_t;

/* so far we've seen only 7 types of records */
#define K12_REC_PACKET		0x00010020
#define K12_REC_SRCDSC		0x00070041 /* port-stack mapping + more, the key of the whole thing */
#define K12_REC_SCENARIO	0x00070040 /* what appears as the window's title */
#define K12_REC_70042		0x00070042 /* XXX: ??? */ 
#define K12_REC_70044		0x00070044 /* text with a grammar (conditions/responses) */
#define K12_REC_20030		0x00020030 /* human readable start time  */ 
#define K12_REC_20032		0x00020031 /* human readable stop time */

typedef struct _k12_src_desc_t {
	k12_record_hdr_t hdr;

	struct _record {
		guint32 unk_10;
		guint32 unk_14;
		guint16 unk_18;
		guint16 extra_len;
		guint16 name_len;
		guint16 stack_len;
	} record;
	
	struct _variable {
		guint8* extra_blob;
		gchar* port_name;
		gchar* stack_file;
	} variable;
} k12_src_desc_t;

typedef struct {
	k12_record_hdr_t hdr;

	struct {
		guint32 unk_10; /* some bit of the second nibble is set in some frames */
		guint32 unk_14; /* made of several fields, it increases always, 
							in consecutive packets from the same port it increases by one.
						*/
		guint64 ts;
	} record;	
	
	guint8* variable;
} k12_packet_t;



/*
 * get_k12_hdr:  hunt for the next valid header in the file.
 *   will return:
 *      -2 on I/O errors
 *		-1 at EOF
 *       the lenght of the preamble (0 if none) if OK.
 *
 *   Every about 0x2000 bytes up to 4 words are inserted in the file,
 *   not being able yet to understand *exactly* how and where these
 *   are inserted we need to scan the file for the next valid header.
 *
 */
gboolean get_k12_hdr(k12_record_hdr_t* hdr, wtap* wth, int* err) {
	guint32 hdr_buf[5];
	guint32 magic;
	guint i;
	guint len;
#if 0
	/*
	 * XXX: as most records are contiguous we could
	 * avoid hunting when not in the "risky zones".
	 */
	
	gboolean risky = (  (wth->data_offset-0x210) % 0x2000 > 0x1e00 || 
						(wth->data_offset-0x210) % 0x2000 < 0x0200   );
	if (! risky) {
		if ( file_read(hdr, 1, sizeof(*hdr), wth->fh) != sizeof(*hdr) ) {
			if (! (*err = file_error(wth->fh) ) ) 
				*err = WTAP_ERR_SHORT_READ;
			return -1;
		} else {
			hdr->len = 0x0000FFFF & pntohl(hdr->len);
			hdr->type = pntohl(hdr->type);
			hdr->frame_len = 0x0000FFFF & pntohl(hdr->frame_len);
			hdr->input = pntohl( hdr->input );
			return 0;
		}
	}
	
	/*
	 * We'll take the conservative approach and avoid trouble altogether.
	 */
#endif
	
	/*
	 *  we'll hunt for valid headers by loading the candidate header
	 *  in a buffer one word longer, and checking it.
	 *  If it is ok we'll copy it and return ok.
	 *  If it doesn't we'll load the next word shinfting and trying again
	 */
	
	/* read the first three words inserting them from the second slot on */
	if ((len = file_read(hdr_buf + 1, 1, 0xC, wth->fh)) != 0xC) {
		if (len == 2) {
			if ( hdr_buf[1] >> 16 == 0xffff ) {
				/* EOF */
				*err = 0;
				return -1;
			}
		}
		
		if (! (*err = file_error(wth->fh) ) ) 
			*err = WTAP_ERR_SHORT_READ;
		
		return -2;
	}

	do {
		
		/*
		 * XXX: The stuffing should be be at most 0x10.
		 *
		 * We do not know if the record types we know are all of them.
		 *
		 * Instead of failing we could try to skip a record whose type we do
		 * not know yet. In that case however it is possible that a "magic"
		 * number appears in the record and unpredictable things would happen.
		 * We won't try, we'll fail and ask for feedback.
		 */
		if ( len > 0x20) {
			 g_warning("get_k12_hdr: found more than 4 words of stuffing, this should not happen!\n"
					   "please report this issue to ethereal-dev@ethereal.com");
			return -2;
		}
		
		/* read the next word into the last slot */
		if ( file_read( hdr_buf + 4 , 1, 0x4, wth->fh) != 0x4 ) {
			*err = WTAP_ERR_SHORT_READ;
			return -2;
		}
		
		len += 0x4;
		
		for ( i = 0 ; i < 4 ; i++ )
			hdr_buf[i] = hdr_buf[i + 1]; 
		
		/* we'll be done if the second word is a magic number */
		magic = pntohl( hdr_buf + 1 );
		
	} while (magic != K12_REC_PACKET &&
			 magic != K12_REC_SRCDSC &&
			 magic != K12_REC_SCENARIO &&
			 magic != K12_REC_70042 &&
			 magic != K12_REC_70044 &&
			 magic != K12_REC_20030 &&
			 magic != K12_REC_20032 );
	
	hdr->len = 0x0000FFFF & hdr_buf[0]; 	/* the first two bytes off the record len may be altered */
	hdr->type = magic;
	hdr->frame_len = 0x0000FFFF & pntohl( hdr_buf + 2 ); /* play defensive */
	hdr->input = pntohl( hdr_buf + 3 );
		
	return len - K12_HDR_LEN;
}

static gboolean k12_read(wtap *wth, int *err, gchar **err_info, long *data_offset) {
	guint8* b[0x1000];
	k12_packet_t pkt;
	gint stuffing = -1;
	gint read_len;
	k12_src_desc_t* src_desc;
	
	*data_offset = wth->data_offset;
	
	/* ignore the record if it isn't a packet */	
	do {
		gint s;
		
		if (stuffing >= 0) {
			stuffing += pkt.hdr.len;
			
			/* skip the whole record */
			
			if ( file_read(b,1, pkt.hdr.len - K12_HDR_LEN , wth->fh) != (gint) (pkt.hdr.len - K12_HDR_LEN) ) {
				*err = WTAP_ERR_SHORT_READ;
				*err_info = "record too short while reading .rf5 file";
				return FALSE; 		
			}
			
		} else if (stuffing < 0) {
			stuffing = 0;
		}
		
		switch ( s = get_k12_hdr(&pkt.hdr, wth, err) ) {
			case -1:
				/* eof */
				*err = 0;
				*data_offset = wth->data_offset = wth->capture.k12->file_len;
				return FALSE;
			case -2:
				/* io_error */
				return FALSE;
			default:
				break;
		}
		
		stuffing += s;
		
	} while ( pkt.hdr.type != K12_REC_PACKET
			  || pkt.hdr.len < pkt.hdr.frame_len + 0x20 );
	wth->data_offset += stuffing + 0x10;

	
	if ( file_read(&pkt.record,1,sizeof(pkt.record),wth->fh) != sizeof(pkt.record) ) {
		*err = WTAP_ERR_SHORT_READ;
		return FALSE; 
	}
	
	wth->data_offset += sizeof(pkt.record);
		
	pkt.record.ts = pntohll(&pkt.record.ts);
	
	wth->phdr.ts.tv_usec = (guint32) ( (pkt.record.ts % 2000000) / 2);
	wth->phdr.ts.tv_sec = (guint32) ((pkt.record.ts / 2000000) + 631152000);
	
	wth->phdr.caplen = wth->phdr.len = pkt.hdr.frame_len;
	
	/* the frame */
	buffer_assure_space(wth->frame_buffer, pkt.hdr.frame_len);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer), pkt.hdr.frame_len, wth->fh, err);
	wth->data_offset += pkt.hdr.frame_len;
	
	/*  (undef,$vp,$vc) = unpack "C12SS";  */
	
	read_len = pkt.hdr.len - ( pkt.hdr.frame_len + 0x20);
	
	if ( file_read(b,1, read_len , wth->fh) != read_len ) {
		*err = WTAP_ERR_SHORT_READ;
		return FALSE; 		
	}
	
	wth->data_offset += read_len;
	
	src_desc = g_hash_table_lookup(wth->capture.k12->src_by_id,GUINT_TO_POINTER(pkt.hdr.input));
	
	wth->pseudo_header.k12.src_id = pkt.hdr.input;
	wth->pseudo_header.k12.src_name = src_desc ? src_desc->variable.port_name : "unknown port";
	wth->pseudo_header.k12.stack_file = src_desc ? src_desc->variable.stack_file : "unknown port";
	
	return TRUE;
}

static gboolean k12_seek_read(wtap *wth, long seek_off, union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err _U_, gchar **err_info _U_) {
	guint8 read_buffer[0x20];
	k12_src_desc_t* src_desc;
	guint32 input;
	
	if ( file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;
	
	if( file_read(read_buffer,1,0x20,wth->random_fh) != 0x20 )
		return FALSE;
	
	input = pntohl(read_buffer + 0xC);
	
	src_desc = g_hash_table_lookup(wth->capture.k12->src_by_id,GUINT_TO_POINTER(input));
	
	pseudo_header->k12.src_id = input;
	pseudo_header->k12.src_name = src_desc ? src_desc->variable.port_name : "unknown port";
	pseudo_header->k12.stack_file = src_desc ? src_desc->variable.stack_file : "unknown stack_file";
	
	if ( file_read(pd, 1, length, wth->random_fh) != length) {
		*err = file_error(wth->random_fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	
	return TRUE;
}

static k12_t* new_k12_file_data() {
	k12_t* fd = g_malloc(sizeof(k12_t));
	
	fd->file_len = 0;
	fd->num_of_records = 0;
	fd->src_by_name = g_hash_table_new(g_str_hash,g_str_equal);
	fd->src_by_id = g_hash_table_new(g_direct_hash,g_direct_equal);
	
	return fd;
}

static gboolean destroy_srcdsc(gpointer k _U_, gpointer v, gpointer p _U_) {
	k12_src_desc_t* rec = v;
	
	if(rec->variable.extra_blob)
		g_free(rec->variable.extra_blob);
	
	if(rec->variable.port_name)
		g_free(rec->variable.port_name);
	
	if(rec->variable.stack_file)
		g_free(rec->variable.stack_file);
	
	g_free(rec);
	
	return TRUE;
}

static void destroy_k12_file_data(k12_t* fd) {
	g_hash_table_destroy(fd->src_by_id);
	g_hash_table_foreach_remove(fd->src_by_name,destroy_srcdsc,NULL);	
	g_hash_table_destroy(fd->src_by_name);
	g_free(fd);
}

static void k12_close(wtap *wth) {
	destroy_k12_file_data(wth->capture.k12);
}

static void add_k12_src(k12_t* fd, k12_src_desc_t* rec) {
	k12_src_desc_t* r = g_memdup(rec,sizeof(k12_src_desc_t));
	
	g_hash_table_insert(fd->src_by_id,GUINT_TO_POINTER(r->hdr.input),r);
	g_hash_table_insert(fd->src_by_name,r->variable.stack_file,r);
}



static int get_srcdsc_record(k12_src_desc_t* rec, FILE* fp, int *err) {
	gchar read_buffer[0x1000];
	
	if ( file_read( read_buffer, 1, 0x14, fp) != 0x14 ) {
		*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	
	/*	XXX missing some  */
	rec->record.extra_len = pntohs( read_buffer + 0xE );
	rec->record.name_len = pntohs( read_buffer + 0x10 );
	rec->record.stack_len = pntohs( read_buffer + 0x12 );
	
	if (file_read(read_buffer,1, rec->hdr.len - 0x24,fp) != (gint)rec->hdr.len - 0x24 ) {
		*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	
	rec->variable.extra_blob = g_memdup(read_buffer, rec->record.extra_len);
	rec->variable.port_name = g_memdup(read_buffer + rec->record.extra_len,rec->record.name_len);
	rec->variable.stack_file = g_memdup(read_buffer + rec->record.extra_len + rec->record.name_len,rec->record.stack_len);
	
	return TRUE;
}

/*
 * The first few records of a file contain a description of the file:
 *   - the description of the sources (ports or circuits)
 *   - some other useless or yet unknown data.
 *
 * After that we'll find the packet records. At the end sometimes we find
 * some other (summary?) records.
 */

int k12_open(wtap *wth, int *err, gchar **err_info _U_) {
	gchar read_buffer[0x1000];
	long offset = 0;
	k12_t* file_data;
	k12_src_desc_t rec;
	gint stuffing;
	
	/*
	 *  let's check the magic number.
	 */
	if ( file_read(read_buffer,1,8,wth->fh) != 8 ) {
		return -1;
	} else {
		if ( memcmp(read_buffer,k12_file_magic,8) != 0 )
			return 0;
	}
	
	/* the lenght of the file is in the next 4byte word */
	if ( file_read(read_buffer,1,8,wth->fh) != 8 ) {
		return -1;
	} 
	file_data = new_k12_file_data();

	file_data->file_len = pntohl( read_buffer );
	file_data->num_of_records = pntohl( read_buffer + 4 );
	
	/*
	 * we don't know yet what's in the file header
	 */
	if (file_read(read_buffer,1,0x200,wth->fh) != 0x200 ) {
		destroy_k12_file_data(file_data);
		return -1;
	}
	
	wth->data_offset = offset = 0x210;
	
	/*
	 * start reading the records until we hit the first packet record
	 */
	
	do {
		memset(&rec,0,sizeof(k12_src_desc_t));

		if (offset > 0x10000) {
			/* too much to be ok. */
			return 0;
		}
		
		stuffing = get_k12_hdr(&(rec.hdr), wth, err);
		
		if ( stuffing < 0) {
			return 0;
		}
		
		offset += stuffing;
		
		if ( rec.hdr.type == K12_REC_PACKET) {
			/*
			 * we are at the first packet record, rewind and leave.
			 */
			if (file_seek(wth->fh, -0x10, SEEK_CUR, err) == -1) {
				destroy_k12_file_data(file_data);
				return -1;
			}
			
			break;
		} else if (rec.hdr.type == K12_REC_SRCDSC) {
			
			if(!get_srcdsc_record(&rec, wth->fh, err)) {
				destroy_k12_file_data(file_data);
				return -1;
			}

			offset += rec.hdr.len;
			
			add_k12_src(file_data,&rec);
			
			continue;
		} else {
			if (file_read(read_buffer,1, rec.hdr.len - K12_HDR_LEN, wth->fh) != (int) rec.hdr.len - K12_HDR_LEN ) {
				destroy_k12_file_data(file_data);
				return -1;
			}
			
			offset += rec.hdr.len;
			
			continue;
		}
	} while(1);
	
	wth->data_offset = offset;
	wth->file_type = WTAP_FILE_K12;
	wth->file_encap = WTAP_ENCAP_K12;
	wth->snapshot_length = 0;
	wth->subtype_read = k12_read;
	wth->subtype_seek_read = k12_seek_read;
	wth->subtype_close = k12_close;
	wth->capture.k12 = file_data;
	
	/* if we use just one encapsulation for all the file
		we will use that for the whole file so we can
		use more formats to save to */
	
	
	return 1;
}

