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


static const guint8 k12_file_magic[] = { 0x00, 0x00, 0x02, 0x00 ,0x12, 0x05, 0x00, 0x10 };

#define K12_REC_PACKET  0x00010020
#define K12_REC_SRCDSC	0x00070041

/* XXX: we don't know what is in these type of records */
#define K12_REC_UNK001	0x00070040
#define K12_REC_UNK002	0x00070042
#define K12_REC_UNK003	0x00070044

/* So far we've seen the following appear only at the end of the file */
#define K12_REC_UNK004	0x00020030
#define K12_REC_UNK005	0x00020031

#define K12_HDR_LEN 0x10

typedef struct {
	guint32 len;
	guint32 type;
	guint32 frame_len;
	guint32 port_id;
} k12_record_hdr_t;

typedef struct {
} k12_scrdsc_hdr_t;

typedef struct  {
	gchar* name;
	guint32 encap;
} k12_stack_encap_t;

typedef struct  {
	guint32 port_id;
	guint32 encap;
} k12_port_encap_t;

struct _k12_t {
	k12_stack_encap_t* stack_encap;
	guint stack_encap_p;
	GPtrArray *port_encaps;
	guint32 file_len;
};

static const k12_stack_encap_t virgin_stack_encap[] = {
	{NULL,WTAP_ENCAP_USER0},
	{NULL,WTAP_ENCAP_USER1},
	{NULL,WTAP_ENCAP_USER2},
	{NULL,WTAP_ENCAP_USER3},
	{NULL,WTAP_ENCAP_USER4},
	{NULL,WTAP_ENCAP_USER5},
	{NULL,WTAP_ENCAP_USER6},
	{NULL,WTAP_ENCAP_USER7},
	{NULL,WTAP_ENCAP_USER8},
	{NULL,WTAP_ENCAP_USER9},
	{NULL,WTAP_ENCAP_USER10},
	{NULL,WTAP_ENCAP_USER11},
	{NULL,WTAP_ENCAP_USER12},
	{NULL,WTAP_ENCAP_USER13},
	{NULL,WTAP_ENCAP_USER14},
/*	{NULL,WTAP_ENCAP_USER15},  used for unnknown sources */
	{NULL,0}	
};
static guint32 choose_encap(k12_t* file_data, guint32 port_id, gchar* stack_name) {
	guint32 encap = 0;
	k12_port_encap_t* pe;
	guint i;
	
	for (i =0; i < file_data->stack_encap_p; i++) {

		if (strcmp(stack_name,file_data->stack_encap[i].name) == 0) {
			encap = file_data->stack_encap[i].encap;
			g_free(stack_name);
			break;
		}
	}

	if (file_data->stack_encap_p > 14) {
		/* g_warning("k12_choose_encap: Cannot handle more than 15 stack types"); */
		return WTAP_ENCAP_USER15;
	}
	
	if ( encap == 0 ) {
		file_data->stack_encap[file_data->stack_encap_p].name = stack_name;
		encap = file_data->stack_encap[file_data->stack_encap_p].encap;
	}

	pe = g_malloc(sizeof(k12_port_encap_t));
	pe->port_id = port_id;
	pe->encap = encap;

	g_ptr_array_add(file_data->port_encaps,pe);
	return encap;
}

static guint32 get_encap(k12_t* file_data, guint32 port_id) {
	guint i;
	k12_port_encap_t* pe;

	for (i = 0; i < file_data->port_encaps->len; i++) {
		pe = g_ptr_array_index(file_data->port_encaps,i);
		
		if (pe->port_id == port_id)
			return pe->encap;
	}
	
	/*g_warning("k12_get_encap: BUG: found no encapsulation for source 0x%.8x\n"
			  "please report this to ethereal-dev@ethereal.com", port_id);*/
	
	return WTAP_ENCAP_USER15;
}



/*
 * get_k12_hdr:  hunt for the next valid header in the file.
 *   will return:
 *      -2 on I/O errors
 *		-1 at EOF
 *       the lenght of the preamble (0 if none) if OK.
 *
 *   Record headers are 4 4byte words long,
 *       - the first is the lenght of the record
 *       - the second is the type of the record
 *       - the third is the lenght of the frame in packet records
 *		 - the last is the source id to which it refers
 *
 *   Every about 0x2000 bytes up to 4 words are inserted in the file,
 *   not being able yet to understand *exactly* how and where these
 *   are inserted we need to scan the file for the next valid header.
 *
 */
gboolean get_k12_hdr(k12_record_hdr_t* hdr, wtap* wth, int* err, gchar **err_info) {
	guint8 hdr_buf[0x14]; /* five 32bit "slots" */
	guint32 magic;
	guint i;
	guint len;
	
	/*
	 * XXX: as most records are contiguous we could
	 * avoid hunting when not in the "risky zones".
	 *
	 * gboolean risky = ( (file_offset-0x210) % 0x2000) > 0x1f00 || 
	 *                    (file_offset-0x210) % 0x2000) < 0x0100   );
	 *
	 * We'll take the conservative approach and avoid trouble altogether.
	 */
	
	/* read the first three words inserting them from the second slot on */
	
	if ((len = file_read(hdr_buf + 0x4, 1, 0xC, wth->fh)) != 0xC) {
		if (len == 2) {
			if (hdr_buf[0x4] == 0xff && hdr_buf[0x5] == 0xff) {
				return -1;
			}
		}
		
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -2;
	}
	
	do {
		
		/*
		 * XXX: The stuffing should be be at most 0x10.
		 *
		 * We do not know if the record types we know are all of them.
		 *
		 * Instead of failing we could  try to skip a record whose type we do
		 * not know yet. In that case however it is possible that a "magic"
		 * number appears in the record and unpredictable things would happen.
		 * We won't try, we'll fail and ask for feedback.
		 */
		if ( len > 0x20) {
			/*
			g_warning("get_k12_hdr: found more than 4 words of stuffing, this should not happen!\n"
					  "please report this issue to ethereal-dev@ethereal.com");
			*/
			return -2;
		}
		
		/* read the next word into the last slot */
		if ( file_read( hdr_buf + K12_HDR_LEN, 1, 0x4, wth->fh) != 0x4 ) {
			*err = WTAP_ERR_SHORT_READ;
			*err_info = "record too short while reading .rf5 file";
			return -2;
		}
		
		len += 0x4;
		
		/* shift the buffer one word left */
		/* XXX: working with words this would be faster */
		for ( i = 0 ; i < 16 ; i++ )
			hdr_buf[i] = hdr_buf[i + 0x4]; 

		/* we'll be done if the second word is a magic number */
		magic = pntohl( hdr_buf + 0x4 );
		
	} while (magic != K12_REC_PACKET &&
			 magic != K12_REC_SRCDSC &&
			 magic != K12_REC_UNK001 &&
			 magic != K12_REC_UNK002 &&
			 magic != K12_REC_UNK003 &&
			 magic != K12_REC_UNK004 &&
			 magic != K12_REC_UNK005 );
	
	hdr->len = 0x0000FFFF & pntohl( hdr_buf ); 	/* the first two bytes off the record len may contain junk */
	hdr->type = magic;
	hdr->frame_len = 0x0000FFFF & pntohl( hdr_buf + 0x8 );
	hdr->port_id = pntohl( hdr_buf + 0xC );
	
	return len - K12_HDR_LEN;
}

static gboolean k12_read(wtap *wth, int *err, gchar **err_info, long *data_offset) {
	guint64 ts;
	guint8 b[8];
	guint8* junk[0x1000];
	k12_record_hdr_t hdr;
	gint stuffing = -1;
	
	*data_offset = wth->data_offset;
	
	/* ignore the record if it isn't a packet */	
	do {
		gint s;
		
		if (stuffing >= 0) {
			stuffing += hdr.len;
			
			/* skip the whole record */
			
			if ( file_read(junk,1, hdr.len - K12_HDR_LEN , wth->fh) != (gint) (hdr.len - K12_HDR_LEN) ) {
				*err = WTAP_ERR_SHORT_READ;
				*err_info = "record too short while reading .rf5 file";
				return FALSE; 		
			}
			
		} else if (stuffing < 0) {
			stuffing = 0;
		}
		
		switch ( s = get_k12_hdr(&hdr, wth, err, err_info) ) {
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
		
	} while ( hdr.type != K12_REC_PACKET
			  || hdr.len < hdr.frame_len + 0x20 );
	
	wth->data_offset += stuffing + 0x10;
	
	if ( wth->file_encap == WTAP_ENCAP_PER_PACKET) {
		wth->phdr.pkt_encap = get_encap(wth->capture.k12,hdr.port_id);
	} else {
		wth->phdr.pkt_encap = WTAP_ENCAP_USER0;
	}
	
	/* XXX: is in there something useful in these 8 bytes ? */
	if ( file_read(b,1,8,wth->fh) != 8 ) {
		*err = WTAP_ERR_SHORT_READ;
		*err_info = "record too short while reading .rf5 file";
		return FALSE; 
	}
	
	wth->data_offset += 8;

	
	/* the next 8 bytes are the timestamp */
	if ( file_read(b,1,8,wth->fh) != 8 ) {
		*err = WTAP_ERR_SHORT_READ;
		*err_info = "record too short while reading .rf5 file";
		return FALSE; 
	}
	
	wth->data_offset += 8;
	
	ts = pntohll(b);
	
	wth->phdr.ts.tv_usec = (guint32) ( (ts % 2000000) / 2);
	wth->phdr.ts.tv_sec = (guint32) ((ts / 2000000) + 631152000);
	
	wth->phdr.caplen = wth->phdr.len = hdr.frame_len;
	
	/* the frame */
	buffer_assure_space(wth->frame_buffer, hdr.frame_len);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer), hdr.frame_len, wth->fh, err);
	wth->data_offset += hdr.frame_len;

	/* XXX: should we read to a junk buffer instead of seeking? */
	/* XXX: is there useful stuff in the trailer? */
	if ( file_read(junk,1, hdr.len - ( hdr.frame_len + 0x20) , wth->fh) != (gint) ( hdr.len - ( hdr.frame_len + 0x20)) ) {
		*err = WTAP_ERR_SHORT_READ;
		*err_info = "record too short while reading .rf5 file";
		return FALSE; 		
	}
	
	wth->data_offset += hdr.len - ( hdr.frame_len + 0x20);
	
	return TRUE;
}

static gboolean k12_seek_read(wtap *wth, long seek_off, union wtap_pseudo_header *pseudo_header _U_, guchar *pd, int length, int *err _U_, gchar **err_info _U_) {

	if ( file_seek(wth->random_fh, seek_off+0x20, SEEK_SET, err) == -1)
		return FALSE;
	
	if ( file_read(pd, 1, length, wth->random_fh) != length) {
		*err = file_error(wth->random_fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	
	return TRUE;
}

static void destroy_k12_file_data(k12_t* file_data) {
	guint i;
	for (i =0; i<=file_data->stack_encap_p; i++) {
		if (file_data->stack_encap[i].name) {
			g_free(file_data->stack_encap[i].name);
			file_data->stack_encap[i].name = NULL;
		}
	}
	
	if (file_data->port_encaps) {
		g_ptr_array_free(file_data->port_encaps,TRUE);
	}
	
}

static void k12_close(wtap *wth) {
	destroy_k12_file_data(wth->capture.k12);
}

/*
 * The first few records of a file contain a description of the file:
 *   - the description of the sources (ports or circuits)
 *   - some other useless or yet unknown data.
 *
 * After that we'll find the packet records. At the end sometimes we find
 * some other (summary?) records.
 */

int k12_open(wtap *wth, int *err, gchar **err_info) {
	gchar read_buffer[0x1000];
	k12_record_hdr_t hdr;
	long offset = 0;
	gchar* stack_file;
	gchar* port_name;
	guint port_name_len;
	guint stuffing;
	k12_t* file_data;

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
	if ( file_read(read_buffer,1,4,wth->fh) != 4 ) {
		return -1;
	} 
	
	file_data = g_malloc(sizeof(k12_t));
	
	file_data->stack_encap_p = 0;
	file_data->port_encaps = g_ptr_array_new();
	file_data->stack_encap = g_memdup(virgin_stack_encap,sizeof(virgin_stack_encap));
	file_data->file_len = pntohl( read_buffer );
	
	/*
	 * we don't know yet what's in the file header
	 */
	if (file_read(read_buffer,1,0x204,wth->fh) != 0x204 ) {
		destroy_k12_file_data(file_data);
		return -1;
	}
		
	wth->data_offset = offset = 0x210;
	
	/*
	 * start reading the records until we hit the first packet record
	 */
	
	do {
		if (offset > 0x10000) {
			/* too much to be ok. */
			return 0;
		}
		
		stuffing = get_k12_hdr(&hdr, wth, err, err_info);
		
		offset += stuffing;
				
		if ( hdr.type == K12_REC_PACKET) {
			/*
			 * we are at the first packet record, rewind and leave.
			 */
			if (file_seek(wth->fh, -0x10, SEEK_CUR, err) == -1) {
				destroy_k12_file_data(file_data);
				return -1;
			}

			break;
		} else if (hdr.type == K12_REC_SRCDSC) {
			guint32 name_len;
			guint32 stack_len;
			gint read_len;
			
			if ( file_read( read_buffer, 1, 0x14, wth->fh) != 0x14 ) {
				*err = WTAP_ERR_SHORT_READ;
				return FALSE;
			}
			
			name_len = pntohs( read_buffer + 0x10 );
			stack_len = pntohs( read_buffer + 0x12 );
			

			read_len = hdr.len - (0x10 + 0x14 + name_len + stack_len);
			
			if (read_len > 0) {
				/* skip the still unknown part */
				if (file_read(read_buffer,1, read_len,wth->fh) != read_len ) {
					destroy_k12_file_data(file_data);
					*err = WTAP_ERR_SHORT_READ;
					return -1;
				}
			} else if (read_len < 0) {
				destroy_k12_file_data(file_data);
				*err = WTAP_ERR_BAD_RECORD;
				return -1;
			}
			
			/* the rest of the record contains two null terminated strings:
				the source label and the "stack" filename */
			if ( file_read(read_buffer, 1, name_len, wth->fh) != (int)name_len ) {
				destroy_k12_file_data(file_data);
				*err = WTAP_ERR_SHORT_READ;
				*err_info = "record too short while reading .rf5 file";
				return -1;
			}
			
			port_name = g_strndup(read_buffer,stack_len);

			if ( file_read(read_buffer, 1, stack_len, wth->fh) != (int)stack_len ) {
				destroy_k12_file_data(file_data);
				*err = WTAP_ERR_SHORT_READ;
				*err_info = "record too short while reading .rf5 file";
				return -1;
			}
			
			stack_file =g_strndup(read_buffer,stack_len);
						
			if (choose_encap(file_data,hdr.port_id,stack_file) == WTAP_NUM_ENCAP_TYPES ) {
				destroy_k12_file_data(file_data);
				/* more encapsulation types than we can handle */
				return 0;
			}
			
			offset += hdr.len;
			continue;
		} else {
			/* we don't need these other fellows */
			
			if (file_read(read_buffer,1, hdr.len - K12_HDR_LEN, wth->fh) != (int) hdr.len - K12_HDR_LEN ) {
				destroy_k12_file_data(file_data);
				return -1;
			}
			
			offset += hdr.len;
			
			continue;
		}
	} while(1);
	
	wth->data_offset = offset;
	wth->file_type = WTAP_FILE_K12;
	wth->snapshot_length = 0;
	wth->subtype_read = k12_read;
	wth->subtype_seek_read = k12_seek_read;
	wth->subtype_close = k12_close;
	wth->capture.k12 = file_data;
	
	/* if we use just one encapsulation for all the file
		we will use that for the whole file so we can
		use more formats to save to */
	
	if (file_data->port_encaps->len == 1) {
		wth->file_encap = ((k12_stack_encap_t*)g_ptr_array_index(file_data->port_encaps,0))->encap;
	} else {
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
	}
	
	return 1;
}

