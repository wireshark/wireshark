/* iptrace.c
 *
 * $Id: iptrace.c,v 1.26 2000/03/30 21:41:11 gram Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@xiexie.org>
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
#include "file_wrappers.h"
#include "buffer.h"
#include "iptrace.h"

static int iptrace_read_1_0(wtap *wth, int *err);
static int iptrace_read_2_0(wtap *wth, int *err);
static int wtap_encap_ift(unsigned int  ift);
static void get_atm_pseudo_header(wtap *wth, guint8 *header, guint8 *pd);

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

	if (strcmp(name, "iptrace 1.0") == 0) {
		wth->file_type = WTAP_FILE_IPTRACE_1_0;
		wth->subtype_read = iptrace_read_1_0;
	}
	else if (strcmp(name, "iptrace 2.0") == 0) {
		wth->file_type = WTAP_FILE_IPTRACE_2_0;
		wth->subtype_read = iptrace_read_2_0;
	}
	else {
		return 0;
	}

	return 1;
}

/***********************************************************
 * iptrace 1.0                                             *
 ***********************************************************/

/* iptrace 1.0, discovered through inspection */
typedef struct {
/* 0-3 */	guint32		pkt_length;	/* packet length + 0x16 */
/* 4-7 */	guint32		tv_sec;		/* time stamp, seconds since the Epoch */
/* 8-11 */	guint32		junk1;		/* ???, not time */
/* 12-15 */	char		if_name[4];	/* null-terminated */
/* 16-27 */	char		junk2[12];	/* ??? */
/* 28 */	guint8		if_type;	/* BSD net/if_types.h */
/* 29 */	guint8		tx_flag;	/* 0=receive, 1=transmit */
} iptrace_1_0_phdr;

/* Read the next packet */
static int iptrace_read_1_0(wtap *wth, int *err)
{
	int			bytes_read;
	int			data_offset;
	guint32			packet_size;
	guint8			header[30];
	guint8			*data_ptr;
	iptrace_1_0_phdr	pkt_hdr;

	/* Read the descriptor data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(header, 1, 30, wth->fh);
	if (bytes_read != 30) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += 30;

	/* Read the packet data */
	packet_size = pntohl(&header[0]) - 0x16;
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
	wth->phdr.ts.tv_sec = pntohl(&header[4]);
	wth->phdr.ts.tv_usec = 0;

	/*
	 * Byte 28 of the frame header appears to be a BSD-style IFT_xxx
	 * value giving the type of the interface.  Check out the
	 * <net/if_types.h> header file.
	 */
	pkt_hdr.if_type = header[28];
	wth->phdr.pkt_encap = wtap_encap_ift(pkt_hdr.if_type);

	if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
		g_message("iptrace: interface type IFT=0x%02x unknown or unsupported",
		    pkt_hdr.if_type);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	if ( wth->phdr.pkt_encap == WTAP_ENCAP_ATM_SNIFFER ) {
		get_atm_pseudo_header(wth, header, data_ptr);
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

/***********************************************************
 * iptrace 2.0                                             *
 ***********************************************************/

/* iptrace 2.0, discovered through inspection */
typedef struct {
/* 0-3 */	guint32		pkt_length;	/* packet length + 32 */
/* 4-7 */	guint32		tv_sec0;	/* time stamp, seconds since the Epoch */
/* 8-11 */	guint32		junk1;		/* ?? */
/* 12-15 */	char		if_name[4];	/* null-terminated */
/* 16-27 */	char		if_desc[12];	/* interface description. */
/* 28 */	guint8		if_type;	/* BSD net/if_types.h */
/* 29 */	guint8		tx_flag;	/* 0=receive, 1=transmit */
/* 30-31 */	guint16		junk3;
/* 32-35 */	guint32		tv_sec;		/* time stamp, seconds since the Epoch */
/* 36-39 */	guint32		tv_nsec;	/* nanoseconds since that second */
} iptrace_2_0_phdr;

/* Read the next packet */
static int iptrace_read_2_0(wtap *wth, int *err)
{
	int			bytes_read;
	int			data_offset;
	guint32			packet_size;
	guint8			header[40];
	guint8			*data_ptr;
	iptrace_2_0_phdr	pkt_hdr;

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

	if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
		g_message("iptrace: interface type IFT=0x%02x unknown or unsupported",
		    pkt_hdr.if_type);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	if ( wth->phdr.pkt_encap == WTAP_ENCAP_ATM_SNIFFER ) {
		get_atm_pseudo_header(wth, header, data_ptr);
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

/*
 * Fill in the pseudo-header information we can; alas, "iptrace" doesn't
 * tell us what type of traffic is in the packet - it was presumably
 * run on a machine that was one of the endpoints of the connection, so
 * in theory it could presumably have told us, but, for whatever reason,
 * it failed to do so - perhaps the low-level mechanism that feeds the
 * presumably-AAL5 frames to us doesn't have access to that information
 * (e.g., because it's in the ATM driver, and the ATM driver merely knows
 * that stuff on VPI/VCI X.Y should be handed up to some particular
 * client, it doesn't know what that client is).
 *
 * We let our caller try to figure out what kind of traffic it is, either
 * by guessing based on the VPI/VCI, guessing based on the header of the
 * packet, seeing earlier traffic that set up the circuit and specified
 * in some fashion what sort of traffic it is, or being told by the user.
 */
static void
get_atm_pseudo_header(wtap *wth, guint8 *header, guint8 *pd)
{
	char	if_text[9];
	char	*decimal;
	int	Vpi = 0;
	int	Vci = 0;

	/* Rip apart the "x.y" text into Vpi/Vci numbers */
	memcpy(if_text, &header[20], 8);
	if_text[8] = '\0';
	decimal = strchr(if_text, '.');
	if (decimal) {
		*decimal = '\0';
		Vpi = strtoul(if_text, NULL, 10);
		decimal++;
		Vci = strtoul(decimal, NULL, 10);
	}
	wth->phdr.pseudo_header.ngsniffer_atm.Vpi = Vpi;
	wth->phdr.pseudo_header.ngsniffer_atm.Vci = Vci;

	/*
	 * OK, which value means "DTE->DCE" and which value means
	 * "DCE->DTE"?
	 */
	wth->phdr.pseudo_header.ngsniffer_atm.channel = header[29];

	/* We don't have this information */
	wth->phdr.pseudo_header.ngsniffer_atm.cells = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.aal5t_u2u = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.aal5t_len = 0;
	wth->phdr.pseudo_header.ngsniffer_atm.aal5t_chksum = 0;

	/* Assume it's AAL5 traffic, but indicate that we don't know what
	   it is beyond that. */
	wth->phdr.pseudo_header.ngsniffer_atm.AppTrafType =
	    ATT_AAL5|ATT_HL_UNKNOWN;
	wth->phdr.pseudo_header.ngsniffer_atm.AppHLType = AHLT_UNKNOWN;
}

/* Given an RFC1573 (SNMP ifType) interface type,
 * return the appropriate Wiretap Encapsulation Type.
 */
static int
wtap_encap_ift(unsigned int  ift)
{

	static const int ift_encap[] = {
/* 0x0 */	WTAP_ENCAP_UNKNOWN,	/* nothing */
/* 0x1 */	WTAP_ENCAP_UNKNOWN,	/* IFT_OTHER */
/* 0x2 */	WTAP_ENCAP_UNKNOWN,	/* IFT_1822 */
/* 0x3 */	WTAP_ENCAP_UNKNOWN,	/* IFT_HDH1822 */
/* 0x4 */	WTAP_ENCAP_RAW_IP,	/* IFT_X25DDN */
/* 0x5 */	WTAP_ENCAP_UNKNOWN,	/* IFT_X25 */
/* 0x6 */	WTAP_ENCAP_ETHERNET,	/* IFT_ETHER */
/* 0x7 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ISO88023 */
/* 0x8 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ISO88024 */
/* 0x9 */	WTAP_ENCAP_TR,		/* IFT_ISO88025 */
/* 0xa */	WTAP_ENCAP_UNKNOWN,	/* IFT_ISO88026 */
/* 0xb */	WTAP_ENCAP_UNKNOWN,	/* IFT_STARLAN */
/* 0xc */	WTAP_ENCAP_RAW_IP,	/* IFT_P10, IBM SP switch */
/* 0xd */	WTAP_ENCAP_UNKNOWN,	/* IFT_P80 */
/* 0xe */	WTAP_ENCAP_UNKNOWN,	/* IFT_HY */
/* 0xf */	WTAP_ENCAP_FDDI_BITSWAPPED,	/* IFT_FDDI */
/* 0x10 */	WTAP_ENCAP_LAPB,	/* IFT_LAPB */	/* no data to back this up */
/* 0x11 */	WTAP_ENCAP_UNKNOWN,	/* IFT_SDLC */
/* 0x12 */	WTAP_ENCAP_UNKNOWN,	/* IFT_T1 */
/* 0x13 */	WTAP_ENCAP_UNKNOWN,	/* IFT_CEPT */
/* 0x14 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ISDNBASIC */
/* 0x15 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ISDNPRIMARY */
/* 0x16 */	WTAP_ENCAP_UNKNOWN,	/* IFT_PTPSERIAL */
/* 0x17 */	WTAP_ENCAP_UNKNOWN,	/* IFT_PPP */
/* 0x18 */	WTAP_ENCAP_RAW_IP,	/* IFT_LOOP */
/* 0x19 */	WTAP_ENCAP_UNKNOWN,	/* IFT_EON */
/* 0x1a */	WTAP_ENCAP_UNKNOWN,	/* IFT_XETHER */
/* 0x1b */	WTAP_ENCAP_UNKNOWN,	/* IFT_NSIP */
/* 0x1c */	WTAP_ENCAP_UNKNOWN,	/* IFT_SLIP */
/* 0x1d */	WTAP_ENCAP_UNKNOWN,	/* IFT_ULTRA */
/* 0x1e */	WTAP_ENCAP_UNKNOWN,	/* IFT_DS3 */
/* 0x1f */	WTAP_ENCAP_UNKNOWN,	/* IFT_SIP */
/* 0x20 */	WTAP_ENCAP_UNKNOWN,	/* IFT_FRELAY */
/* 0x21 */	WTAP_ENCAP_UNKNOWN,	/* IFT_RS232 */
/* 0x22 */	WTAP_ENCAP_UNKNOWN,	/* IFT_PARA */
/* 0x23 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ARCNET */
/* 0x24 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ARCNETPLUS */
/* 0x25 */	WTAP_ENCAP_ATM_SNIFFER,	/* IFT_ATM */
	};
	#define NUM_IFT_ENCAPS (sizeof ift_encap / sizeof ift_encap[0])

	if (ift < NUM_IFT_ENCAPS) {
		return ift_encap[ift];
	}
	else {
		return WTAP_ENCAP_UNKNOWN;
	}
}
