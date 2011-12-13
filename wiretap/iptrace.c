/* iptrace.c
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "atm.h"
#include "iptrace.h"

static gboolean iptrace_read_1_0(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean iptrace_seek_read_1_0(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int packet_size,
    int *err, gchar **err_info);

static gboolean iptrace_read_2_0(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean iptrace_seek_read_2_0(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int packet_size,
    int *err, gchar **err_info);

static int iptrace_read_rec_header(FILE_T fh, guint8 *header, int header_len,
    int *err, gchar **err_info);
static gboolean iptrace_read_rec_data(FILE_T fh, guint8 *data_ptr,
    int packet_size, int *err, gchar **err_info);
static void fill_in_pseudo_header(int encap, const guint8 *pd, guint32 len,
    union wtap_pseudo_header *pseudo_header, guint8 *header);
static int wtap_encap_ift(unsigned int  ift);

int iptrace_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char name[12];

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(name, 11, wth->fh);
	if (bytes_read != 11) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += 11;
	name[11] = 0;

	if (strcmp(name, "iptrace 1.0") == 0) {
		wth->file_type = WTAP_FILE_IPTRACE_1_0;
		wth->subtype_read = iptrace_read_1_0;
		wth->subtype_seek_read = iptrace_seek_read_1_0;
		wth->tsprecision = WTAP_FILE_TSPREC_SEC;
	}
	else if (strcmp(name, "iptrace 2.0") == 0) {
		wth->file_type = WTAP_FILE_IPTRACE_2_0;
		wth->subtype_read = iptrace_read_2_0;
		wth->subtype_seek_read = iptrace_seek_read_2_0;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
	}
	else {
		return 0;
	}

	return 1;
}

/***********************************************************
 * iptrace 1.0                                             *
 ***********************************************************/

/*
 * iptrace 1.0, discovered through inspection
 *
 * Packet record contains:
 *
 *	an initial header, with a length field and a time stamp, in
 *	seconds since the Epoch;
 *
 *	data, with the specified length.
 *
 * The data contains:
 *
 *	a bunch of information about the packet;
 *
 *	padding, at least for FDDI;
 *
 *	the raw packet data.
 */
typedef struct {
/* 0-3 */	guint32		pkt_length;	/* packet length + 0x16 */
/* 4-7 */	guint32		tv_sec;		/* time stamp, seconds since the Epoch */
/* 8-11 */	guint32		junk1;		/* ???, not time */
/* 12-15 */	char		if_name[4];	/* null-terminated */
/* 16-27 */	char		junk2[12];	/* ??? */
/* 28 */	guint8		if_type;	/* BSD net/if_types.h */
/* 29 */	guint8		tx_flag;	/* 0=receive, 1=transmit */
} iptrace_1_0_phdr;

#define IPTRACE_1_0_PHDR_SIZE	30	/* initial header plus packet data */
#define IPTRACE_1_0_PDATA_SIZE	22	/* packet data */

/* Read the next packet */
static gboolean iptrace_read_1_0(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	int			ret;
	guint32			packet_size;
	guint8			header[IPTRACE_1_0_PHDR_SIZE];
	guint8			*data_ptr;
	iptrace_1_0_phdr	pkt_hdr;
	guint8			fddi_padding[3];

	/* Read the descriptor data */
	*data_offset = wth->data_offset;
	ret = iptrace_read_rec_header(wth->fh, header, IPTRACE_1_0_PHDR_SIZE,
	    err, err_info);
	if (ret <= 0) {
		/* Read error or EOF */
		return FALSE;
	}
	wth->data_offset += IPTRACE_1_0_PHDR_SIZE;

	/*
	 * Byte 28 of the frame header appears to be a BSD-style IFT_xxx
	 * value giving the type of the interface.  Check out the
	 * <net/if_types.h> header file.
	 */
	pkt_hdr.if_type = header[28];
	wth->phdr.pkt_encap = wtap_encap_ift(pkt_hdr.if_type);

	/* Read the packet data */
	packet_size = pntohl(&header[0]);
	if (packet_size < IPTRACE_1_0_PDATA_SIZE) {
		/*
		 * Uh-oh, the record isn't big enough to even have a
		 * packet meta-data header.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("iptrace: file has a %u-byte record, too small to have even a packet meta-data header",
		    packet_size);
		return FALSE;
	}
	packet_size -= IPTRACE_1_0_PDATA_SIZE;

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (wth->phdr.pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) {
		/*
		 * The packet size is really a record size and includes
		 * the padding.
		 */
		if (packet_size < 3) {
			/*
			 * Uh-oh, the record isn't big enough to even have
			 * the padding.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("iptrace: file has a %u-byte record, too small to have even a packet meta-data header",
			    packet_size + IPTRACE_1_0_PDATA_SIZE);
			return FALSE;
		}
		packet_size -= 3;
		wth->data_offset += 3;

		/*
		 * Read the padding.
		 */
		if (!iptrace_read_rec_data(wth->fh, fddi_padding, 3, err,
		    err_info))
			return FALSE;	/* Read error */
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("iptrace: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	buffer_assure_space( wth->frame_buffer, packet_size );
	data_ptr = buffer_start_ptr( wth->frame_buffer );
	if (!iptrace_read_rec_data(wth->fh, data_ptr, packet_size, err,
	    err_info))
		return FALSE;	/* Read error */
	wth->data_offset += packet_size;

	wth->phdr.len = packet_size;
	wth->phdr.caplen = packet_size;
	wth->phdr.ts.secs = pntohl(&header[4]);
	wth->phdr.ts.nsecs = 0;

	if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("iptrace: interface type IFT=0x%02x unknown or unsupported",
		    pkt_hdr.if_type);
		return FALSE;
	}

	/* Fill in the pseudo-header. */
	fill_in_pseudo_header(wth->phdr.pkt_encap, data_ptr, wth->phdr.caplen,
	    &wth->pseudo_header, header);

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

	return TRUE;
}

static gboolean iptrace_seek_read_1_0(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int packet_size,
    int *err, gchar **err_info)
{
	int			ret;
	guint8			header[IPTRACE_1_0_PHDR_SIZE];
	int			pkt_encap;
	guint8			fddi_padding[3];

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* Read the descriptor data */
	ret = iptrace_read_rec_header(wth->random_fh, header,
	    IPTRACE_1_0_PHDR_SIZE, err, err_info);
	if (ret <= 0) {
		/* Read error or EOF */
		if (ret == 0) {
			/* EOF means "short read" in random-access mode */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	/*
	 * Get the interface type.
	 */
	pkt_encap = wtap_encap_ift(header[28]);

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) {
		/*
		 * Read the padding.
		 */
		if (!iptrace_read_rec_data(wth->random_fh, fddi_padding, 3,
		    err, err_info))
			return FALSE;	/* Read error */
	}

	/* Get the packet data */
	if (!iptrace_read_rec_data(wth->random_fh, pd, packet_size, err,
	    err_info))
		return FALSE;

	/* Fill in the pseudo_header. */
	fill_in_pseudo_header(pkt_encap, pd, packet_size, pseudo_header,
	    header);

	return TRUE;
}

/***********************************************************
 * iptrace 2.0                                             *
 ***********************************************************/

/*
 * iptrace 2.0, discovered through inspection
 *
 * Packet record contains:
 *
 *	an initial header, with a length field and a time stamp, in
 *	seconds since the Epoch;
 *
 *	data, with the specified length.
 *
 * The data contains:
 *
 *	a bunch of information about the packet;
 *
 *	padding, at least for FDDI;
 *
 *	the raw packet data.
 */
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

#define IPTRACE_2_0_PHDR_SIZE	40	/* initial header plus packet data */
#define IPTRACE_2_0_PDATA_SIZE	32	/* packet data */

/* Read the next packet */
static gboolean iptrace_read_2_0(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	int			ret;
	guint32			packet_size;
	guint8			header[IPTRACE_2_0_PHDR_SIZE];
	guint8			*data_ptr;
	iptrace_2_0_phdr	pkt_hdr;
	guint8			fddi_padding[3];

	/* Read the descriptor data */
	*data_offset = wth->data_offset;
	ret = iptrace_read_rec_header(wth->fh, header, IPTRACE_2_0_PHDR_SIZE,
	    err, err_info);
	if (ret <= 0) {
		/* Read error or EOF */
		return FALSE;
	}
	wth->data_offset += IPTRACE_2_0_PHDR_SIZE;

	/*
	 * Byte 28 of the frame header appears to be a BSD-style IFT_xxx
	 * value giving the type of the interface.  Check out the
	 * <net/if_types.h> header file.
	 */
	pkt_hdr.if_type = header[28];
	wth->phdr.pkt_encap = wtap_encap_ift(pkt_hdr.if_type);

	/* Read the packet data */
	packet_size = pntohl(&header[0]);
	if (packet_size < IPTRACE_2_0_PDATA_SIZE) {
		/*
		 * Uh-oh, the record isn't big enough to even have a
		 * packet meta-data header.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("iptrace: file has a %u-byte record, too small to have even a packet meta-data header",
		    packet_size);
		return FALSE;
	}
	packet_size -= IPTRACE_2_0_PDATA_SIZE;

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (wth->phdr.pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) {
		/*
		 * The packet size is really a record size and includes
		 * the padding.
		 */
		if (packet_size < 3) {
			/*
			 * Uh-oh, the record isn't big enough to even have
			 * the padding.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("iptrace: file has a %u-byte record, too small to have even a packet meta-data header",
			    packet_size + IPTRACE_2_0_PDATA_SIZE);
			return FALSE;
		}
		packet_size -= 3;
		wth->data_offset += 3;

		/*
		 * Read the padding.
		 */
		if (!iptrace_read_rec_data(wth->fh, fddi_padding, 3, err,
		    err_info))
			return FALSE;	/* Read error */
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("iptrace: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	buffer_assure_space( wth->frame_buffer, packet_size );
	data_ptr = buffer_start_ptr( wth->frame_buffer );
	if (!iptrace_read_rec_data(wth->fh, data_ptr, packet_size, err,
	    err_info))
		return FALSE;	/* Read error */
	wth->data_offset += packet_size;

	wth->phdr.len = packet_size;
	wth->phdr.caplen = packet_size;
	wth->phdr.ts.secs = pntohl(&header[32]);
	wth->phdr.ts.nsecs = pntohl(&header[36]);

	if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("iptrace: interface type IFT=0x%02x unknown or unsupported",
		    pkt_hdr.if_type);
		return FALSE;
	}

	/* Fill in the pseudo-header. */
	fill_in_pseudo_header(wth->phdr.pkt_encap, data_ptr, wth->phdr.caplen,
	    &wth->pseudo_header, header);

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

	return TRUE;
}

static gboolean iptrace_seek_read_2_0(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int packet_size,
    int *err, gchar **err_info)
{
	int			ret;
	guint8			header[IPTRACE_2_0_PHDR_SIZE];
	int			pkt_encap;
	guint8			fddi_padding[3];

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* Read the descriptor data */
	ret = iptrace_read_rec_header(wth->random_fh, header,
	    IPTRACE_2_0_PHDR_SIZE, err, err_info);
	if (ret <= 0) {
		/* Read error or EOF */
		if (ret == 0) {
			/* EOF means "short read" in random-access mode */
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	/*
	 * Get the interface type.
	 */
	pkt_encap = wtap_encap_ift(header[28]);

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) {
		/*
		 * Read the padding.
		 */
		if (!iptrace_read_rec_data(wth->random_fh, fddi_padding, 3,
		    err, err_info))
			return FALSE;	/* Read error */
	}

	/* Get the packet data */
	if (!iptrace_read_rec_data(wth->random_fh, pd, packet_size, err,
	    err_info))
		return FALSE;

	/* Fill in the pseudo-header. */
	fill_in_pseudo_header(pkt_encap, pd, packet_size, pseudo_header,
	    header);

	return TRUE;
}

static int
iptrace_read_rec_header(FILE_T fh, guint8 *header, int header_len, int *err,
    gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(header, header_len, fh);
	if (bytes_read != header_len) {
		*err = file_error(fh, err_info);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	return 1;
}

static gboolean
iptrace_read_rec_data(FILE_T fh, guint8 *data_ptr, int packet_size, int *err,
    gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read( data_ptr, packet_size, fh );

	if (bytes_read != packet_size) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/*
 * Fill in the pseudo-header information we can.
 *
 * For ATM traffic, "iptrace", alas, doesn't tell us what type of traffic
 * is in the packet - it was presumably run on a machine that was one of
 * the endpoints of the connection, so in theory it could presumably have
 * told us, but, for whatever reason, it failed to do so - perhaps the
 * low-level mechanism that feeds the presumably-AAL5 frames to us doesn't
 * have access to that information (e.g., because it's in the ATM driver,
 * and the ATM driver merely knows that stuff on VPI/VCI X.Y should be
 * handed up to some particular client, it doesn't know what that client is).
 *
 * We let our caller try to figure out what kind of traffic it is, either
 * by guessing based on the VPI/VCI, guessing based on the header of the
 * packet, seeing earlier traffic that set up the circuit and specified
 * in some fashion what sort of traffic it is, or being told by the user.
 */
static void
fill_in_pseudo_header(int encap, const guint8 *pd, guint32 len,
    union wtap_pseudo_header *pseudo_header, guint8 *header)
{
	char	if_text[9];
	char	*decimal;
	int	Vpi = 0;
	int	Vci = 0;

	switch (encap) {

	case WTAP_ENCAP_ATM_PDUS:
		/* Rip apart the "x.y" text into Vpi/Vci numbers */
		memcpy(if_text, &header[20], 8);
		if_text[8] = '\0';
		decimal = strchr(if_text, '.');
		if (decimal) {
			*decimal = '\0';
			Vpi = (int)strtoul(if_text, NULL, 10);
			decimal++;
			Vci = (int)strtoul(decimal, NULL, 10);
		}

		/*
		 * OK, which value means "DTE->DCE" and which value means
		 * "DCE->DTE"?
		 */
		pseudo_header->atm.channel = header[29];

		pseudo_header->atm.vpi = Vpi;
		pseudo_header->atm.vci = Vci;

		/*
		 * Attempt to guess from the packet data, the VPI,
		 * and the VCI information about the type of traffic.
		 */
		atm_guess_traffic_type(pd, len, pseudo_header);

		/* We don't have this information */
		pseudo_header->atm.flags = 0;
		pseudo_header->atm.cells = 0;
		pseudo_header->atm.aal5t_u2u = 0;
		pseudo_header->atm.aal5t_len = 0;
		pseudo_header->atm.aal5t_chksum = 0;
		break;

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		pseudo_header->eth.fcs_len = 0;
		break;
	}
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
/* 0x7 */	WTAP_ENCAP_ETHERNET,	/* IFT_ISO88023 */
/* 0x8 */	WTAP_ENCAP_UNKNOWN,	/* IFT_ISO88024 */
/* 0x9 */	WTAP_ENCAP_TOKEN_RING,	/* IFT_ISO88025 */
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
/* 0x25 */	WTAP_ENCAP_ATM_PDUS,	/* IFT_ATM */
	};
	#define NUM_IFT_ENCAPS (sizeof ift_encap / sizeof ift_encap[0])

	if (ift < NUM_IFT_ENCAPS) {
		return ift_encap[ift];
	}
	else {
		return WTAP_ENCAP_UNKNOWN;
	}
}
