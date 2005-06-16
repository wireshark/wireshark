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
	
	GHashTable* src_by_id; /* k12_srcdsc_recs by input */
	GHashTable* src_by_name; /* k12_srcdsc_recs by stack_name */
};

typedef struct _k12_src_desc_t {
	guint32 input;
	guint32 input_type;
	gchar* input_name;
	gchar* stack_file;
	k12_input_info_t input_info;
} k12_src_desc_t;


/* so far we've seen only 7 types of records */
#define K12_REC_PACKET		0x00010020
#define K12_REC_SRCDSC		0x00070041 /* port-stack mapping + more, the key of the whole thing */
#define K12_REC_SCENARIO	0x00070040 /* what appears as the window's title */
#define K12_REC_70042		0x00070042 /* XXX: ??? */ 
#define K12_REC_70044		0x00070044 /* text with a grammar (conditions/responses) */
#define K12_REC_20030		0x00020030 /* human readable start time  */ 
#define K12_REC_20032		0x00020031 /* human readable stop time */

#define K12_RECORD_LEN         0x0
#define K12_RECORD_TYPE        0x4
#define K12_RECORD_FRAME_LEN   0x8
#define K12_RECORD_INPUT      0xc

#define K12_PACKET_TIMESTAMP  0x18
#define K12_PACKET_FRAME      0x20

#define K12_SRCDESC_EXTRALEN   0x1e
#define K12_SRCDESC_NAMELEN    0x20
#define K12_SRCDESC_STACKLEN   0x22

#define K12_SRCDESC_EXTRATYPE  0x24
#define K12_SRCDESC_ATM_VPI    0x38
#define K12_SRCDESC_ATM_VCI    0x3a
#define K12_SRCDESC_DS0_MASK   0x3c



/*
 * get_record: Get the next record into a buffer
 *   Every about 0x2000 bytes 0x10 bytes are inserted in the file,
 *   even in the middle of a record.
 *   This reads the next record without the eventual 0x10 bytes.
 *   returns the lenght of the record + the stuffing (if any)
 *
 * XXX: works at most with 0x1FFF bytes per record 
 */
static gint get_record(guint8* buffer, FILE* fh, guint file_offset) {
	long read;
	long len;
	int i;
	long junky_offset = 0x2000 - ( (file_offset - 0x200) % 0x2000 );

	if  ( junky_offset != 0x2000 ) {
		
		/* safe header */
		read = file_read(buffer,1, 0x4,fh);
		
		if (read == 2 && buffer[0] == 0xff && buffer[1] == 0xff) {
			return 0;
		} else if ( read != 0x4 ) {
			return -1;
		}
		
		len = pntohl(buffer) & 0x00001FFF;
		
		if (junky_offset > len) {
			/* safe body */
			if (len - 0x4 <= 0)
				return -1;
			
			if ( file_read(buffer+0x4, 1, len - 0x4, fh) < len - 0x4 ) {
				return -1;
			} else {
				return len;
			}
		} else {
			if ( file_read(buffer+0x4, 1, len + 0xC, fh) < len ) {
				return -1;
			}
			
			for (i = junky_offset; i < len; i++) {
				buffer[i] = buffer[i+0x10];
			}
			
			return len + 0x10;
		}
	} else {
		/* unsafe header */
		
		read = file_read(buffer,1,0x14,fh);
		
		if (read == 2 && buffer[0] == 0xff && buffer[1] == 0xff) {
			return 0;
		} else if ( read < 0x14 ){
			return -1;
		}
		
		for (i = 0; i < 0x10; i++) {
			buffer[i] = buffer[i+0x10];
		}
		
		len = pntohl(buffer) & 0x00001FFF;
		
		if (len - 0x4 <= 0)
			return -1;

		/* safe body */
		if ( file_read(buffer + 0x4, 1, len - 0x4,fh) < len - 0x4 ) {
			return -1;
		} else {
			return len + 0x10;
		}
	}
}

static gboolean k12_read(wtap *wth, int *err, gchar **err_info _U_, long *data_offset) {
	k12_src_desc_t* src_desc;
	guint8 buffer[0x2000];
	long offset;
	long len;
	guint32 type;
	guint64 ts;
	
	offset = wth->data_offset;

	/* ignore the record if it isn't a packet */	
	do {
		*data_offset = offset;
		
		len = get_record(buffer, wth->fh, offset);
		
		if (len < 0) {
			*err = WTAP_ERR_SHORT_READ;
			return FALSE;
		} else if (len == 0) {
			*err = 0;
			return FALSE;
		}
		
		type = pntohl(buffer + K12_RECORD_TYPE);
		
		offset += len;
		
	} while ( type != K12_REC_PACKET );
	
	wth->data_offset = offset;
	
	ts = pntohll(buffer + K12_PACKET_TIMESTAMP);
	
	wth->phdr.ts.tv_usec = (guint32) ( (ts % 2000000) / 2);
	wth->phdr.ts.tv_sec = (guint32) ((ts / 2000000) + 631152000);
	
	wth->phdr.len = wth->phdr.caplen = pntohl(buffer + K12_RECORD_FRAME_LEN) & 0x00001FFF;
	
	/* the frame */
	buffer_assure_space(wth->frame_buffer, wth->phdr.caplen);
	memcpy(buffer_start_ptr(wth->frame_buffer), buffer + K12_PACKET_FRAME, wth->phdr.caplen);
	
	wth->pseudo_header.k12.input = pntohl(buffer + K12_RECORD_INPUT);

	src_desc = g_hash_table_lookup(wth->capture.k12->src_by_id,GUINT_TO_POINTER(wth->pseudo_header.k12.input));
	
	if (src_desc) {
		wth->pseudo_header.k12.input_name = src_desc->input_name;
		wth->pseudo_header.k12.stack_file = src_desc->stack_file;
		wth->pseudo_header.k12.input_type = src_desc->input_type;
	
		memcpy(&(wth->pseudo_header.k12.input_info),&(src_desc->input_info),sizeof(src_desc->input_info));
	} else {
		memset(&(wth->pseudo_header),0,sizeof(wth->pseudo_header));
		wth->pseudo_header.k12.input_name = "unknown port";
		wth->pseudo_header.k12.stack_file = "unknown stack file";
	}
	
	return TRUE;
}


static gboolean k12_seek_read(wtap *wth, long seek_off, union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err _U_, gchar **err_info _U_) {
	k12_src_desc_t* src_desc;
	guint8 buffer[0x2000];

	if ( file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;
	
	get_record(buffer, wth->random_fh, seek_off);

	memcpy(pd, buffer + K12_PACKET_FRAME, length);
	
	pseudo_header->k12.input = pntohl(buffer + K12_RECORD_INPUT);
	
	src_desc = g_hash_table_lookup(wth->capture.k12->src_by_id,GUINT_TO_POINTER(wth->pseudo_header.k12.input));
	
	if (src_desc) {
		pseudo_header->k12.input_name = src_desc->input_name;
		pseudo_header->k12.stack_file = src_desc->stack_file;
		pseudo_header->k12.input_type = src_desc->input_type;
		
		memcpy(&(pseudo_header->k12.input_info),&(src_desc->input_info),sizeof(src_desc->input_info));
	} else {
		memset(&(wth->pseudo_header),0,sizeof(wth->pseudo_header));
		pseudo_header->k12.input_name = "unknown port";
		pseudo_header->k12.stack_file = "unknown stack file";
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
	
	if(rec->input_name)
		g_free(rec->input_name);
	
	if(rec->stack_file)
		g_free(rec->stack_file);
	
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


int k12_open(wtap *wth, int *err, gchar **err_info _U_) {
	k12_src_desc_t* rec;
	guint8 read_buffer[0x2000];
	guint32 type;
	long offset;
	long len;
	guint32 extra_len;
	guint32 name_len;
	guint32 stack_len;
	guint i;
	k12_t* file_data;
	
	if ( file_read(read_buffer,1,0x200,wth->fh) != 0x200 ) {
		return 0;
	} else {
		if ( memcmp(read_buffer,k12_file_magic,8) != 0 )
			return 0;
	}
	
	offset = 0x200;
	
	file_data = new_k12_file_data();
	
	file_data->file_len = pntohl( read_buffer + 0x8);
	file_data->num_of_records = pntohl( read_buffer + 0xC );
	
	do {
		
		len = get_record(read_buffer, wth->fh, offset);
	
		if ( len <= 0 ) {
			return -1;
		}


		type = pntohl( read_buffer + K12_RECORD_TYPE );
		
		if ( type == K12_REC_PACKET) {
			/*
			 * we are at the first packet record, rewind and leave.
			 */
			if (file_seek(wth->fh, offset, SEEK_SET, err) == -1) {
				destroy_k12_file_data(file_data);
				return -1;
			}
			
			break;
		} else if (type == K12_REC_SRCDSC) {
			rec = g_malloc0(sizeof(k12_src_desc_t));
			
			rec->input = pntohl( read_buffer + K12_RECORD_INPUT );
			extra_len = pntohs( read_buffer + K12_SRCDESC_EXTRALEN );
			name_len = pntohs( read_buffer + K12_SRCDESC_NAMELEN );
			stack_len = pntohs( read_buffer + K12_SRCDESC_STACKLEN );
			
			switch(( rec->input_type = pntohl( read_buffer + K12_SRCDESC_EXTRATYPE ) )) {
				case K12_PORT_DS0S:
					rec->input_info.ds0mask = 0x00000000;
					
					for (i = 0; i < 32; i++) {
						rec->input_info.ds0mask |= ( *(read_buffer + K12_SRCDESC_DS0_MASK + i) == 0xff ) ? 0x1<<(31-i) : 0x0; 
					}
						
						break;
				case K12_PORT_ATMPVC:
					rec->input_info.atm.vp = pntohs( read_buffer + K12_SRCDESC_ATM_VPI );
					rec->input_info.atm.vc = pntohs( read_buffer + K12_SRCDESC_ATM_VCI );
					break;
				default:
					break;
			}
			
			rec->input_name = g_memdup(read_buffer + K12_SRCDESC_EXTRATYPE + extra_len, name_len);
			rec->stack_file = g_memdup(read_buffer + K12_SRCDESC_EXTRATYPE + extra_len + name_len, stack_len);
			
			g_hash_table_insert(file_data->src_by_id,GUINT_TO_POINTER(rec->input),rec);
			g_hash_table_insert(file_data->src_by_name,rec->stack_file,rec);
			
			offset += len;
			continue;
		} else {
			offset += len;
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
