/* iptrace.c
 *
 * $Id: iptrace.c,v 1.17 1999/11/18 08:50:34 gram Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include "wtap.h"
#include "file.h"
#include "buffer.h"
#include "iptrace.h"

static int iptrace_read(wtap *wth, int *err);
static int wtap_encap_ift(unsigned int  ift);
static void atm_guess_content(wtap *wth, guint8 *header, guint8 *pd);

/* This structure was guessed */
typedef struct {
/* 0-3 */	guint32		pkt_length;	/* packet length + 32 */
/* 4-7 */	guint32		tv_sec0;
/* 8-11 */	guint32		junk1;		/* ?? */
/* 12-15 */	char		if_name[4];	/* null-terminated */
/* 16-27 */	char		if_desc[12];	/* interface description. */
/* 28 */	guint8		if_type;	/* BSD net/if_types.h */
/* 29 */	guint8		tx_flag;	/* 0=receive, 1=transmit */
/* 30-31 */	guint16		junk3;
/* 32-35 */	guint32		tv_sec;
/* 36-39 */	guint32		tv_usec;
} iptrace_phdr;

int iptrace_open(wtap *wth, int *err)
{
	int bytes_read;
	char name[12];

	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(name, 1, 11, wth->fh);
	if (bytes_read != 11) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += 11;
	name[11] = 0;
	if (strcmp(name, "iptrace 2.0") != 0) {
		return 0;
	}

	wth->file_type = WTAP_FILE_IPTRACE;
	wth->subtype_read = iptrace_read;
	return 1;
}

/* Read the next packet */
static int iptrace_read(wtap *wth, int *err)
{
	int		bytes_read;
	int		data_offset;
	guint32		packet_size;
	guint8		header[40];
	guint8		*data_ptr;
	iptrace_phdr	pkt_hdr;
	char		if_name1, if_name2;

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(header, 1, 40, wth->fh);
	if (bytes_read != 40) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += 40;

	/* Read the packet data */
	packet_size = pntohl(&header[0]) - 32;
	buffer_assure_space( wth->frame_buffer, packet_size );
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	data_ptr = buffer_start_ptr( wth->frame_buffer );
	bytes_read = file_read( data_ptr, 1, packet_size, wth->fh );

	if (bytes_read != packet_size) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += packet_size;


	/* AIX saves time in nsec, not usec. It's easier to make iptrace
	 * files more Unix-compliant here than try to get the calling
	 * program to know when to use nsec or usec */

	wth->phdr.len = packet_size;
	wth->phdr.caplen = packet_size;
	wth->phdr.ts.tv_sec = pntohl(&header[32]);
	wth->phdr.ts.tv_usec = pntohl(&header[36]) / 1000;

	/*
	 * Byte 28 of the frame header appears to be a BSD-style IFT_xxx
	 * value giving the type of the interface.  Check out the
	 * <net/if_types.h> header file.
	 */
	pkt_hdr.if_type = header[28];
	wth->phdr.pkt_encap = wtap_encap_ift(pkt_hdr.if_type);

	/* What does a loopback trace store for its if_type? I don't know yet */
	if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
		if_name1 = header[12];
		if_name2 = header[13];

		if (if_name1 == 'l' && if_name2 == 'o') {
			wth->phdr.pkt_encap = WTAP_ENCAP_RAW_IP;
		}
		else {
			g_message("iptrace: interface type %c%c (IFT=0x%02x) unknown or unsupported",
			    if_name1, if_name2, pkt_hdr.if_type);
			*err = WTAP_ERR_BAD_RECORD;
			return -1;
		}
	}

	/* IBM couldn't make it easy on me, could they? For anyone out there
	 * who is thinking about writing a packet capture program, be sure
	 * to store all pertinent information about a packet in the trace file.
	 * Let us know what the next layer is!
	 */
	if ( wth->phdr.pkt_encap == WTAP_ENCAP_ATM_SNIFFER ) {
		atm_guess_content(wth, header, data_ptr);
	}

	/* If the per-file encapsulation isn't known, set it to this
	   packet's encapsulation.

	   If it *is* known, and it isn't this packet's encapsulation,
	   set it to WTAP_ENCAP_PER_PACKET, as this file doesn't
	   have a single encapsulation for all packets in the file. */
	if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
		wth->file_encap = wth->phdr.pkt_encap;
	else {
		if (wth->file_encap != wth->phdr.pkt_encap)
			wth->file_encap = WTAP_ENCAP_PER_PACKET;
	}

	return data_offset;
}

/* See comment above about writing good packet sniffers */
static void
atm_guess_content(wtap *wth, guint8 *header, guint8 *pd)
{
	char	if_text[9];
	char	*decimal;
	int	Vpi = 0;
	int	Vci = 0;

	wth->phdr.pseudo_header.ngsniffer_atm.AppTrafType = ATT_AAL5;

	/* Rip apart the "x.y" text into Vpi/Vci numbers */
	header[8] = '\0';
	memcpy(if_text, &header[20], 8);
	decimal = strchr(if_text, '.');
	if (decimal) {
		*decimal = '\0';
		Vpi = strtoul(if_text, NULL, 10);
		decimal++;
		Vci = strtoul(decimal, NULL, 10);
	}
	wth->phdr.pseudo_header.ngsniffer_atm.Vpi = Vpi;
	wth->phdr.pseudo_header.ngsniffer_atm.Vci = Vci;


	/* We don't have this information */
	wth->phdr.pseudo_header.ngsniffer_atm.channel = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.cells = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.aal5t_u2u = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.aal5t_len = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.aal5t_chksum = 0;

	if (pd[0] == 0xaa && pd[1] == 0xaa && pd[2] == 0x03) {
		wth->phdr.pseudo_header.ngsniffer_atm.AppHLType = ATT_HL_LLCMX;
	}
	else if ( Vpi == 0 && Vci == 16 ) {
		wth->phdr.pseudo_header.ngsniffer_atm.AppHLType = ATT_HL_ILMI;
	}
	else {
		wth->phdr.pseudo_header.ngsniffer_atm.AppHLType = ATT_HL_LANE;
	}
}

/* Given an RFC1573 (SNMP ifType) interface type,
 * return the appropriate Wiretap Encapsulation Type.
 */
static int
wtap_encap_ift(unsigned int  ift)
{

	static const int ift_encap[] = {
/* 0x0 */	WTAP_ENCAP_UNKNOWN,
/* 0x1 */	WTAP_ENCAP_UNKNOWN,
/* 0x2 */	WTAP_ENCAP_UNKNOWN,
/* 0x3 */	WTAP_ENCAP_UNKNOWN,
/* 0x4 */	WTAP_ENCAP_UNKNOWN,
/* 0x5 */	WTAP_ENCAP_RAW_IP,	/* X.25 */
/* 0x6 */	WTAP_ENCAP_ETHERNET,
/* 0x7 */	WTAP_ENCAP_UNKNOWN,
/* 0x8 */	WTAP_ENCAP_UNKNOWN,
/* 0x9 */	WTAP_ENCAP_TR,
/* 0xa */	WTAP_ENCAP_UNKNOWN,
/* 0xb */	WTAP_ENCAP_UNKNOWN,
/* 0xc */	WTAP_ENCAP_UNKNOWN,
/* 0xd */	WTAP_ENCAP_UNKNOWN,
/* 0xe */	WTAP_ENCAP_UNKNOWN,
/* 0xf */	WTAP_ENCAP_FDDI_BITSWAPPED,
/* 0x10 */	WTAP_ENCAP_LAPB,
/* 0x11 */	WTAP_ENCAP_UNKNOWN,
/* 0x12 */	WTAP_ENCAP_UNKNOWN,
/* 0x13 */	WTAP_ENCAP_UNKNOWN,
/* 0x14 */	WTAP_ENCAP_UNKNOWN,
/* 0x15 */	WTAP_ENCAP_UNKNOWN,
/* 0x16 */	WTAP_ENCAP_UNKNOWN,
/* 0x17 */	WTAP_ENCAP_UNKNOWN,
/* 0x18 */	WTAP_ENCAP_UNKNOWN,
/* 0x19 */	WTAP_ENCAP_UNKNOWN,
/* 0x1a */	WTAP_ENCAP_UNKNOWN,
/* 0x1b */	WTAP_ENCAP_UNKNOWN,
/* 0x1c */	WTAP_ENCAP_UNKNOWN,
/* 0x1d */	WTAP_ENCAP_UNKNOWN,
/* 0x1e */	WTAP_ENCAP_UNKNOWN,
/* 0x1f */	WTAP_ENCAP_UNKNOWN,
/* 0x20 */	WTAP_ENCAP_UNKNOWN,
/* 0x21 */	WTAP_ENCAP_UNKNOWN,
/* 0x22 */	WTAP_ENCAP_UNKNOWN,
/* 0x23 */	WTAP_ENCAP_UNKNOWN,
/* 0x24 */	WTAP_ENCAP_UNKNOWN,
/* 0x25 */	WTAP_ENCAP_ATM_SNIFFER,
	};
	#define NUM_IFT_ENCAPS (sizeof ift_encap / sizeof ift_encap[0])

	if (ift < NUM_IFT_ENCAPS) {
		return ift_encap[ift];
	}
	else {
		return WTAP_ENCAP_UNKNOWN;
	}
}
