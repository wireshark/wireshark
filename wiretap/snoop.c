/* snoop.c
 *
 * $Id: snoop.c,v 1.15 1999/11/26 11:18:12 guy Exp $
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
#include <errno.h>
#include "wtap.h"
#include "file.h"
#include "buffer.h"
#include "snoop.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* See RFC 1761 for a description of the "snoop" file format. */

/* Magic number in "snoop" files. */
static const char snoop_magic[] = {
	's', 'n', 'o', 'o', 'p', '\0', '\0', '\0'
};

/* "snoop" file header (minus magic number). */
struct snoop_hdr {
	guint32	version;	/* version number (should be 2) */
	guint32	network;	/* network type */
};

/* "snoop" record header. */
struct snooprec_hdr {
	guint32	orig_len;	/* actual length of packet */
	guint32	incl_len;	/* number of octets captured in file */
	guint32	rec_len;	/* length of record */
	guint32	cum_drops;	/* cumulative number of dropped packets */
	guint32	ts_sec;		/* timestamp seconds */
	guint32	ts_usec;	/* timestamp microseconds */
};

static int snoop_read(wtap *wth, int *err);

/*
 * See
 * 
 *	http://www.opengroup.org/onlinepubs/9638599/apdxf.htm
 *
 * for the "dlpi.h" header file specified by The Open Group, which lists
 * the DL_ values for various protocols.  Those are the values that
 * Solaris might also use, although the "atmdump" source seems to imply
 * that Solaris might use 15 rather than 17 for ATM (although the README.ATM
 * says of the Solaris version of "atmdump" "This version has not been
 * tested yet").  Solaris 7 uses the same values as The Open Group's
 * "dlpi.h".
 *
 * The "atmdump" source also says that an ATM packet handed up from the Sun
 * driver for the Sun SBus ATM card on Solaris 2.5.1 has 1 byte of direction,
 * 1 byte of VPI, 2 bytes of VCI, and then the ATM PDU, and suggests that
 * the direction byte is 0x80 for "transmitted" (presumably meaning
 * DTE->DCE) and presumably not 0x80 for "received" (presumably meaning
 * DCE->DTE).  (The RADCOM dissector makes the X.25 flag 0x80 for DCE->DTE
 * packets; is there some significance to 0x80?)
 *
 * I don't know what the encapsulation of any of the other types is, and
 * haven't actually seen any packets from the Sun ATM driver, so I leave
 * them all as WTAP_ENCAP_UNKNOWN.  I also don't know whether "snoop"
 * can handle any of them; even if it can't, this may be useful reference
 * information for anybody doing code to use DLPI to do raw packet
 * captures.
 */
int snoop_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof snoop_magic];
	struct snoop_hdr hdr;
	static const int snoop_encap[] = {
		WTAP_ENCAP_ETHERNET,	/* IEEE 802.3 */
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.4 Token Bus */
		WTAP_ENCAP_TR,
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.6 Metro Net */
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_UNKNOWN,	/* HDLC */
		WTAP_ENCAP_UNKNOWN,	/* Character Synchronous, e.g. bisync */
		WTAP_ENCAP_UNKNOWN,	/* IBM Channel-to-Channel */
		WTAP_ENCAP_FDDI_BITSWAPPED,
		WTAP_ENCAP_UNKNOWN,	/* Other */
		WTAP_ENCAP_UNKNOWN,	/* Frame Relay LAPF */
		WTAP_ENCAP_UNKNOWN,	/* Multi-protocol over Frame Relay */
		WTAP_ENCAP_UNKNOWN,	/* Character Async (e.g., SLIP and PPP?) */
		WTAP_ENCAP_UNKNOWN,	/* X.25 Classical IP */
		WTAP_ENCAP_UNKNOWN,	/* software loopback */
		WTAP_ENCAP_UNKNOWN,	/* not defined in "dlpi.h" */
		WTAP_ENCAP_UNKNOWN,	/* Fibre Channel */
		WTAP_ENCAP_UNKNOWN,	/* ATM */
		WTAP_ENCAP_UNKNOWN,	/* ATM Classical IP */
		WTAP_ENCAP_UNKNOWN,	/* X.25 LAPB */
		WTAP_ENCAP_UNKNOWN,	/* ISDN */
		WTAP_ENCAP_UNKNOWN,	/* HIPPI */
		WTAP_ENCAP_UNKNOWN,	/* 100VG-AnyLAN Ethernet */
		WTAP_ENCAP_UNKNOWN,	/* 100VG-AnyLAN Token Ring */
		WTAP_ENCAP_UNKNOWN,	/* "ISO 8802/3 and Ethernet" */
		WTAP_ENCAP_UNKNOWN,	/* 100BaseT (but that's just Ethernet) */
	};
	#define NUM_SNOOP_ENCAPS (sizeof snoop_encap / sizeof snoop_encap[0])

	/* Read in the string that should be at the start of a "snoop" file */
	file_seek(wth->fh, 0, SEEK_SET);
	wth->data_offset = 0;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	if (memcmp(magic, snoop_magic, sizeof snoop_magic) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof hdr;

	hdr.version = ntohl(hdr.version);
	if (hdr.version != 2) {
		/* We only support version 2. */
		g_message("snoop: version %u unsupported", hdr.version);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}
	hdr.network = ntohl(hdr.network);
	if (hdr.network >= NUM_SNOOP_ENCAPS
	    || snoop_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("snoop: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}

	/* This is a snoop file */
	wth->file_type = WTAP_FILE_SNOOP;
	wth->subtype_read = snoop_read;
	wth->file_encap = snoop_encap[hdr.network];
	wth->snapshot_length = 16384;	/* XXX - not available in header */
	return 1;
}

/* Read the next packet */
static int snoop_read(wtap *wth, int *err)
{
	guint32	packet_size;
	int	bytes_read;
	struct snooprec_hdr hdr;
	int	data_offset;
	char	padbuf[4];
	int	padbytes;
	int	bytes_to_read;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		if (bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		return 0;
	}
	wth->data_offset += sizeof hdr;

	packet_size = ntohl(hdr.incl_len);
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		g_message("snoop: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		*err = WTAP_ERR_BAD_RECORD;
		return -1;
	}
	buffer_assure_space(wth->frame_buffer, packet_size);
	data_offset = wth->data_offset;
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(wth->frame_buffer), 1,
			packet_size, wth->fh);

	if (bytes_read != packet_size) {
		*err = file_error(wth->fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	wth->data_offset += packet_size;

	wth->phdr.ts.tv_sec = ntohl(hdr.ts_sec);
	wth->phdr.ts.tv_usec = ntohl(hdr.ts_usec);
	wth->phdr.caplen = packet_size;
	wth->phdr.len = ntohl(hdr.orig_len);
	wth->phdr.pkt_encap = wth->file_encap;

	/*
	 * Skip over the padding (don't "fseek()", as the standard
	 * I/O library on some platforms discards buffered data if
	 * you do that, which means it does a lot more reads).
	 * There's probably not much padding (it's probably padded only
	 * to a 4-byte boundary), so we probably need only do one read.
	 */
	padbytes = ntohl(hdr.rec_len) - (sizeof hdr + packet_size);
	while (padbytes != 0) {
		bytes_to_read = padbytes;
		if (bytes_to_read > sizeof padbuf)
			bytes_to_read = sizeof padbuf;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(padbuf, 1, bytes_to_read, wth->fh);
		if (bytes_read != bytes_to_read) {
			*err = file_error(wth->fh);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		wth->data_offset += bytes_read;
		padbytes -= bytes_read;
	}

	return data_offset;
}
