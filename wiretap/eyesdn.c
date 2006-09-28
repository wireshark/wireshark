/* eyesdn.c
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
#include "wtap-int.h"
#include "buffer.h"
#include "eyesdn.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* This module reads the output of the EyeSDN USB S0/E1 ISDN probes
 * They store HDLC frames of D and B channels in a binary format
 * The fileformat is
 * 
 * 1-6 Byte: EyeSDN - Magic
 * 7-n Byte: Frames
 * 
 * Each Frame starts with the 0xff Flag byte
 * - Bytes 0-2: timestamp (long usec in network byte order)
 * - Bytes 3-7: timestamp (40bits sec since 1970 in network byte order)
 * - Byte 8: channel (0 for D channel, 1-30 for B1-B30, 129 for ATM)
 * - Byte 9: Sender (0 NT, 1 TE)
 * - Byte 10-11: frame size in bytes
 * - Byte 12-n: Frame Payload
 * 
 * All multibyte values are represented in network byte order
 * The frame is terminated with a flag character (0xff)
 * bytes 0xff within a frame are escaped using the 0xfe escape character
 * the byte following the escape character is decremented by two:
 * so 0xfe 0xfd is actually a 0xff
 * Characters that need to be escaped are 0xff and 0xfe
 */


static int esc_read(guint8 *buf, int len, FILE_T fh)
{
    int i;
    int value;
    
    for(i=0; i<len; i++) {
	value=file_getc(fh);
	if(value==-1)
	    return -2; /* EOF or error */
	if(value==0xff)
	    return -1; /* error !!, read into next frame */
	if(value==0xfe) {
	    /* we need to escape */
	    value=file_getc(fh);
	    if(value==-1)
		return -2;
	    value+=2;
	}
	buf[i]=value;
    }
    return i;
}

/* Magic text to check for eyesdn-ness of file */
static const unsigned char eyesdn_hdr_magic[]  =
{ 'E', 'y', 'e', 'S', 'D', 'N'};
#define EYESDN_HDR_MAGIC_SIZE  (sizeof(eyesdn_hdr_magic)  / sizeof(eyesdn_hdr_magic[0]))

/* Size of a record header */
#define EYESDN_HDR_LENGTH		12

/*
 * XXX - is this the biggest packet we can get?
 */
#define EYESDN_MAX_PACKET_LEN	16384

static gboolean eyesdn_read(wtap *wth, int *err, gchar **err_info,
	long *data_offset);
static gboolean eyesdn_seek_read(wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info);
static gboolean parse_eyesdn_packet_data(FILE_T fh, int pkt_len, guint8* buf,
	int *err, gchar **err_info);
static int parse_eyesdn_rec_hdr(wtap *wth, FILE_T fh,
	union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure, and sets "*err" to the error. */
static long eyesdn_seek_next_packet(wtap *wth, int *err)
{
  int byte;
  long cur_off;

  while ((byte = file_getc(wth->fh)) != EOF) {
    if (byte == 0xff) {
        cur_off = file_tell(wth->fh);
        if (cur_off == -1) {
          /* Error. */
          *err = file_error(wth->fh);
          return -1;
        }
        return cur_off;
      }
  }
  if (file_eof(wth->fh)) {
    /* We got an EOF. */
    *err = 0;
  } else {
    /* We (presumably) got an error (there's no equivalent to "ferror()"
       in zlib, alas, so we don't have a wrapper to check for an error). */
    *err = file_error(wth->fh);
  }
  return -1;
}

int eyesdn_open(wtap *wth, int *err, gchar **err_info _U_)
{
	int	bytes_read;
	char	magic[EYESDN_HDR_MAGIC_SIZE];

	/* Look for eyesdn header */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	if (memcmp(magic, eyesdn_hdr_magic, EYESDN_HDR_MAGIC_SIZE) != 0)
		return 0;

	wth->data_offset = 0;
	wth->file_encap = WTAP_ENCAP_ISDN;
	wth->file_type = WTAP_FILE_EYESDN;
	wth->snapshot_length = 0; /* not known */
	wth->subtype_read = eyesdn_read;
	wth->subtype_seek_read = eyesdn_seek_read;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1;
}

/* Find the next packet and parse it; called from wtap_read(). */
static gboolean eyesdn_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset)
{
	long	offset;
	guint8	*buf;
	int	pkt_len;

	/* Find the next packet */
	offset = eyesdn_seek_next_packet(wth, err);
	if (offset < 1)
		return FALSE;

	/* Parse the header */
	pkt_len = parse_eyesdn_rec_hdr(wth, wth->fh, &wth->pseudo_header, err,
	    err_info);
	if (pkt_len == -1)
		return FALSE;

	/* Make sure we have enough room for the packet */
	buffer_assure_space(wth->frame_buffer, EYESDN_MAX_PACKET_LEN);
	buf = buffer_start_ptr(wth->frame_buffer);

	/* Read the packet data */
	if (!parse_eyesdn_packet_data(wth->fh, pkt_len, buf, err, err_info))
		return FALSE;

	wth->data_offset = offset;
	*data_offset = offset;
	return TRUE;
}

/* Used to read packets in random-access fashion */
static gboolean
eyesdn_seek_read (wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info)
{
	int	pkt_len;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	pkt_len = parse_eyesdn_rec_hdr(NULL, wth->random_fh, pseudo_header,
	    err, err_info);

	if (pkt_len != len) {
		if (pkt_len != -1) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("eyesdn: requested length %d doesn't match length %d",
			    len, pkt_len);
		}
		return FALSE;
	}

	return parse_eyesdn_packet_data(wth->random_fh, pkt_len, pd, err,
	    err_info);
}

/* Parses a packet record header. */
static int
parse_eyesdn_rec_hdr(wtap *wth, FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info)
{
	guint8		hdr[EYESDN_HDR_LENGTH];
        unsigned long   secs, usecs;
	int		pkt_len;
	unsigned int    channel, direction;

	/* Our file pointer should be at the summary information header
	 * for a packet. Read in that header and extract the useful
	 * information.
	 */
	if (esc_read(hdr, EYESDN_HDR_LENGTH, fh) != EYESDN_HDR_LENGTH) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
    
        /* extract information from header */
        usecs = ((unsigned long) hdr[0]);
        usecs = (usecs << 8) | ((unsigned long) hdr[1]);
        usecs = (usecs << 8) | ((unsigned long) hdr[2]);
#ifdef TV64BITS    
        secs = ((unsigned long) hdr[3]);
#else    
        secs = 0;
#endif    
        secs = (secs << 8) | ((unsigned long) hdr[4]);
        secs = (secs << 8) | ((unsigned long) hdr[5]);
        secs = (secs << 8) | ((unsigned long) hdr[6]);
        secs = (secs << 8) | ((unsigned long) hdr[7]);

        channel = hdr[8];
        direction = hdr[9];
        pkt_len = ((unsigned long) hdr[10]);
        pkt_len = (pkt_len << 8) | ((unsigned long) hdr[11]);

        /* sanity checks */
        if((channel>30)&&(channel!=129)) {
	    *err = WTAP_ERR_BAD_RECORD;
            *err_info = g_strdup_printf("eyesdn: bad channel number %u",
		channel);
	    return -1;
	}

        if(direction>1) {
	    *err = WTAP_ERR_BAD_RECORD;
            *err_info = g_strdup_printf("eyesdn: bad direction value %u",
		direction);
	    return -1;
	}
        if(pkt_len > EYESDN_MAX_PACKET_LEN) {
	    *err = WTAP_ERR_BAD_RECORD;
	    *err_info = g_strdup_printf("eyesdn: File has %u-byte packet, bigger than maximum of %u",
		pkt_len, EYESDN_MAX_PACKET_LEN);
	    return -1;
	}

	if (wth) {
	        wth->phdr.ts.secs = secs;
		wth->phdr.ts.nsecs = usecs * 1000;
		wth->phdr.caplen = pkt_len;
		wth->phdr.len = pkt_len;
	}
        pseudo_header->isdn.uton = direction;
        pseudo_header->isdn.channel = channel;

	return pkt_len;
}

/* read a packet */
static gboolean
parse_eyesdn_packet_data(FILE_T fh, int pkt_len, guint8* buf, int *err,
    gchar **err_info)
{
        int bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = esc_read(buf, pkt_len, fh);
	if (bytes_read != pkt_len) {
	    if (bytes_read == -2) {
		*err = file_error(fh);
		if (*err == 0)
		    *err = WTAP_ERR_SHORT_READ;
	    }  else if (bytes_read == -1) {
	        *err = WTAP_ERR_BAD_RECORD;
	        *err_info = g_strdup("eyesdn: No flag character seen in frame");
	    } else
		*err = WTAP_ERR_SHORT_READ;
	    return FALSE;
	}
	return TRUE;
}
