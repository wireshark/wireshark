/* snoop.c
 *
 * $Id: snoop.c,v 1.33 2000/11/17 21:00:40 gram Exp $
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
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
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

static gboolean snoop_read(wtap *wth, int *err, int *data_offset);
static int snoop_seek_read(wtap *wth, int seek_off,
    union wtap_pseudo_header *pseudo_header, u_char *pd, int length);
static int snoop_read_atm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err);
static int snoop_read_rec_data(FILE_T fh, u_char *pd, int length, int *err);
static gboolean snoop_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err);

/*
 * See
 * 
 *	http://www.opengroup.org/onlinepubs/9638599/apdxf.htm
 *
 * for the "dlpi.h" header file specified by The Open Group, which lists
 * the DL_ values for various protocols; Solaris 7 uses the same values.
 *
 * The page at
 *
 *	http://mrpink.lerc.nasa.gov/118x/support.html
 *
 * has links to modified versions of "tcpdump" and "libpcap" for SUNatm
 * DLPI support; they suggest the 3.0 verson of SUNatm uses those
 * values.
 *
 * It also has a link to "convert.c", which is a program to convert files
 * from the format written by the "atmsnoop" program that comes with the
 * SunATM package to regular "snoop" format, claims that "SunATM 2.1 claimed
 * to be DL_FDDI (don't ask why).  SunATM 3.0 claims to be DL_IPATM, which
 * is 0x12".
 *
 * It also says that "ATM Mac header is 12 bytes long.", and seems to imply
 * that in an "atmsnoop" file, the header contains 2 bytes (direction and
 * VPI?), 2 bytes of VCI, 6 bytes of something, and 2 bytes of Ethernet
 * type; if those 6 bytes are 2 bytes of DSAP, 2 bytes of LSAP, 1 byte
 * of LLC control, and 3 bytes of SNAP OUI, that'd mean that an ATM
 * pseudo-header in an "atmsnoop" file is probably 1 byte of direction,
 * 1 byte of VPI, and 2 bytes of VCI.
 *
 * The aforementioned page also has a link to some capture files from
 * "atmsnoop"; this version of "snoop.c" appears to be able to read them.
 *
 * Source to an "atmdump" package, which includes a modified version of
 * "libpcap" to handle SunATM DLPI and an ATM driver for FreeBSD, and
 * also includes "atmdump", which is a modified "tcpdump", says that an
 * ATM packet handed up from the Sun driver for the Sun SBus ATM card on
 * Solaris 2.5.1 has 1 byte of direction, 1 byte of VPI, 2 bytes of VCI,
 * and then the ATM PDU, and suggests that the direction byte is 0x80 for
 * "transmitted" (presumably meaning DTE->DCE) and presumably not 0x80 for
 * "received" (presumably meaning DCE->DTE).
 *
 * In fact, the "direction" byte appears to have some other stuff, perhaps
 * a traffic type, in the lower 7 bits, with the 8th bit indicating the
 * direction.
 *
 * I don't know what the encapsulation of any of the other types is, so I
 * leave them all as WTAP_ENCAP_UNKNOWN.  I also don't know whether "snoop"
 * can handle any of them (it presumably can't handle ATM, otherwise Sun
 * wouldn't have supplied "atmsnoop"; even if it can't, this may be useful
 * reference information for anybody doing code to use DLPI to do raw packet
 * captures on those network types.
 */
int snoop_open(wtap *wth, int *err)
{
	int bytes_read;
	char magic[sizeof snoop_magic];
	struct snoop_hdr hdr;
	static const int snoop_encap[] = {
		WTAP_ENCAP_ETHERNET,	/* IEEE 802.3 */
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.4 Token Bus */
		WTAP_ENCAP_TOKEN_RING,
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
		WTAP_ENCAP_ATM_SNIFFER,	/* ATM Classical IP */
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
	switch (hdr.version) {

	case 2:		/* Solaris 2.x and later snoop, and Shomiti
			   Surveyor prior to 3.x */
	case 4:		/* Shomiti Surveyor 3.x */
		break;

	default:
		g_message("snoop: version %u unsupported", hdr.version);
		*err = WTAP_ERR_UNSUPPORTED;
		return -1;
	}
	hdr.network = ntohl(hdr.network);
	if (hdr.network >= NUM_SNOOP_ENCAPS
	    || snoop_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		g_message("snoop: network type %u unknown or unsupported",
		    hdr.network);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/* This is a snoop file */
	wth->file_type = WTAP_FILE_SNOOP;
	wth->subtype_read = snoop_read;
	wth->subtype_seek_read = snoop_seek_read;
	wth->file_encap = snoop_encap[hdr.network];
	wth->snapshot_length = 16384;	/* XXX - not available in header */
	return 1;
}

/* Read the next packet */
static gboolean snoop_read(wtap *wth, int *err, int *data_offset)
{
	guint32 rec_size;
	guint32	packet_size;
	guint32 orig_size;
	int	bytes_read;
	struct snooprec_hdr hdr;
	char	padbuf[4];
	int	padbytes;
	int	bytes_to_read;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}
	wth->data_offset += sizeof hdr;

	rec_size = ntohl(hdr.rec_len);
	orig_size = ntohl(hdr.orig_len);
	packet_size = ntohl(hdr.incl_len);
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		g_message("snoop: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	*data_offset = wth->data_offset;

	/*
	 * If this is an ATM packet, the first four bytes are the
	 * direction of the packet (transmit/receive), the VPI, and
	 * the VCI; read them and generate the pseudo-header from
	 * them.
	 */
	if (wth->file_encap == WTAP_ENCAP_ATM_SNIFFER) {
		if (packet_size < 4) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			g_message("snoop: atmsnoop file has a %u-byte packet, too small to have even an ATM pseudo-header\n",
			    packet_size);
			*err = WTAP_ERR_BAD_RECORD;
			return FALSE;
		}
		if (snoop_read_atm_pseudoheader(wth->fh, &wth->pseudo_header,
		    err) < 0)
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		rec_size -= 4;
		orig_size -= 4;
		packet_size -= 4;
		wth->data_offset += 4;
	}

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (snoop_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
	    packet_size, err) < 0)
		return FALSE;	/* Read error */
	wth->data_offset += packet_size;

	wth->phdr.ts.tv_sec = ntohl(hdr.ts_sec);
	wth->phdr.ts.tv_usec = ntohl(hdr.ts_usec);
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;
	wth->phdr.pkt_encap = wth->file_encap;

	/*
	 * Skip over the padding (don't "fseek()", as the standard
	 * I/O library on some platforms discards buffered data if
	 * you do that, which means it does a lot more reads).
	 * There's probably not much padding (it's probably padded only
	 * to a 4-byte boundary), so we probably need only do one read.
	 */
	padbytes = rec_size - (sizeof hdr + packet_size);
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
			return FALSE;
		}
		wth->data_offset += bytes_read;
		padbytes -= bytes_read;
	}

	return TRUE;
}

static int
snoop_seek_read(wtap *wth, int seek_off,
    union wtap_pseudo_header *pseudo_header, u_char *pd, int length)
{
	int	ret;
	int	err;		/* XXX - return this */

	file_seek(wth->random_fh, seek_off, SEEK_SET);

	if (wth->file_encap == WTAP_ENCAP_ATM_SNIFFER) {
		ret = snoop_read_atm_pseudoheader(wth->random_fh, pseudo_header,
		    &err);
		if (ret < 0) {
			/* Read error */
			return ret;
		}
	}

	/*
	 * Read the packet data.
	 */
	return snoop_read_rec_data(wth->random_fh, pd, length, &err);
}

static int
snoop_read_atm_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
    int *err)
{
	char	atm_phdr[4];
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(atm_phdr, 1, 4, fh);
	if (bytes_read != 4) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}

	pseudo_header->ngsniffer_atm.channel = (atm_phdr[0] & 0x80) ? 1 : 0;
	pseudo_header->ngsniffer_atm.Vpi = atm_phdr[1];
	pseudo_header->ngsniffer_atm.Vci = pntohs(&atm_phdr[2]);

	/* We don't have this information */
	pseudo_header->ngsniffer_atm.cells = 0;
	pseudo_header->ngsniffer_atm.aal5t_u2u = 0;
	pseudo_header->ngsniffer_atm.aal5t_len = 0;
	pseudo_header->ngsniffer_atm.aal5t_chksum = 0;

	/*
	 * Assume it's AAL5; we know nothing more about it.
	 *
	 * For what it's worth, in one "atmsnoop" capture,
	 * the lower 7 bits of the first byte of the header
	 * were 0x05 for ILMI traffic, 0x06 for Signalling
	 * AAL traffic, and 0x02 for at least some RFC 1483-style
	 * LLC multiplexed traffic.
	 */
	pseudo_header->ngsniffer_atm.AppTrafType = ATT_AAL5|ATT_HL_UNKNOWN;
	pseudo_header->ngsniffer_atm.AppHLType = AHLT_UNKNOWN;

	return 0;
}

static int
snoop_read_rec_data(FILE_T fh, u_char *pd, int length, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, 1, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	return 0;
}

static const int wtap_encap[] = {
	-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
	0x04,		/* WTAP_ENCAP_ETHERNET -> DL_ETHER */
	0x02,		/* WTAP_ENCAP_TOKEN_RING -> DL_TPR */
	-1,		/* WTAP_ENCAP_SLIP -> unsupported */
	-1,		/* WTAP_ENCAP_PPP -> unsupported */
	0x08,		/* WTAP_ENCAP_FDDI -> DL_FDDI */
	0x08,		/* WTAP_ENCAP_FDDI_BITSWAPPED -> DL_FDDI */
	-1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
	-1,		/* WTAP_ENCAP_ARCNET -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
	-1,		/* WTAP_ENCAP_LAPB -> unsupported*/
	-1,		/* WTAP_ENCAP_ATM_SNIFFER -> unsupported */
	0		/* WTAP_ENCAP_NULL -> DLT_NULL */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int snoop_dump_can_write_encap(int filetype, int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean snoop_dump_open(wtap_dumper *wdh, int *err)
{
	struct snoop_hdr file_hdr;
	int nwritten;

	/* This is a snoop file */
	wdh->subtype_write = snoop_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	nwritten = fwrite(&snoop_magic, 1, sizeof snoop_magic, wdh->fh);
	if (nwritten != sizeof snoop_magic) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	/* current "snoop" format is 2 */
	file_hdr.version = htonl(2);
	file_hdr.network = htonl(wtap_encap[wdh->encap]);
	nwritten = fwrite(&file_hdr, 1, sizeof file_hdr, wdh->fh);
	if (nwritten != sizeof file_hdr) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean snoop_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const u_char *pd, int *err)
{
	struct snooprec_hdr rec_hdr;
	int nwritten;
	int reclen;
	int padlen;
	static char zeroes[4];

	/* Record length = header length plus data length... */
	reclen = sizeof rec_hdr + phdr->caplen;

	/* ... plus enough bytes to pad it to a 4-byte boundary. */
	padlen = ((reclen + 3) & ~3) - reclen;
	reclen += padlen;

	rec_hdr.orig_len = htonl(phdr->len);
	rec_hdr.incl_len = htonl(phdr->caplen);
	rec_hdr.rec_len = htonl(reclen);
	rec_hdr.cum_drops = 0;
	rec_hdr.ts_sec = htonl(phdr->ts.tv_sec);
	rec_hdr.ts_usec = htonl(phdr->ts.tv_usec);
	nwritten = fwrite(&rec_hdr, 1, sizeof rec_hdr, wdh->fh);
	if (nwritten != sizeof rec_hdr) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	/* Now write the padding. */
	nwritten = fwrite(zeroes, 1, padlen, wdh->fh);
	if (nwritten != padlen) {
		if (nwritten < 0)
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	return TRUE;
}
