/* snoop.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "atm.h"
#include "snoop.h"
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

/*
 * The link-layer header on ATM packets.
 */
struct snoop_atm_hdr {
	guint8	flags;		/* destination and traffic type */
	guint8	vpi;		/* VPI */
	guint16	vci;		/* VCI */
};

/*
 * Extra information stuffed into the padding in Shomiti/Finisar Surveyor
 * captures.
 */
struct shomiti_trailer {
	guint16	phy_rx_length;	/* length on the wire, including FCS? */
	guint16	phy_rx_status;	/* status flags */
	guint32	ts_40_ns_lsb;	/* 40 ns time stamp, low-order bytes? */
	guint32	ts_40_ns_msb;	/* 40 ns time stamp, low-order bytes? */
	gint32	frame_id;	/* "FrameID"? */
};

/*
 * phy_rx_status flags.
 */
#define RX_STATUS_OVERFLOW		0x8000	/* overflow error */
#define RX_STATUS_BAD_CRC		0x4000	/* CRC error */
#define RX_STATUS_DRIBBLE_NIBBLE	0x2000	/* dribble/nibble bits? */
#define RX_STATUS_SHORT_FRAME		0x1000	/* frame < 64 bytes */
#define RX_STATUS_OVERSIZE_FRAME	0x0800	/* frame > 1518 bytes */
#define RX_STATUS_GOOD_FRAME		0x0400	/* frame OK */
#define RX_STATUS_N12_BYTES_RECEIVED	0x0200	/* first 12 bytes of frame received? */
#define RX_STATUS_RXABORT		0x0100	/* RXABORT during reception */
#define RX_STATUS_FIFO_ERROR		0x0080	/* receive FIFO error */
#define RX_STATUS_TRIGGERED		0x0001	/* frame did trigger */

static gboolean snoop_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean snoop_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean snoop_read_atm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean snoop_read_shomiti_wireless_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info,
    int *header_size);
static gboolean snoop_read_rec_data(FILE_T fh, guint8 *pd, int length,
    int *err, gchar **err_info);
static gboolean snoop_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err);

/*
 * See
 *
 *	http://www.opengroup.org/onlinepubs/9638599/apdxf.htm
 *
 * for the "dlpi.h" header file specified by The Open Group, which lists
 * the DL_ values for various protocols; Solaris 7 uses the same values.
 *
 * See
 *
 *	http://www.iana.org/assignments/snoop-datalink-types/snoop-datalink-types.xml
 *
 * for the IETF list of snoop datalink types.
 *
 * The page at
 *
 *	http://mrpink.lerc.nasa.gov/118x/support.html
 *
 * had links to modified versions of "tcpdump" and "libpcap" for SUNatm
 * DLPI support; they suggested that the 3.0 verson of SUNatm uses those
 * values.  The Wayback Machine archived that page, but not the stuff
 * to which it linked, unfortunately.
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
 * also includes "atmdump", which is a modified "tcpdump", was available
 * at
 *
 *	ftp://ftp.cs.ndsu.nodak.edu/pub/freebsd/atm/atm-bpf.tgz
 *
 * (the host name is no longer valid) and that code also indicated that
 * DL_IPATM is used, and that an ATM packet handed up from the Sun driver
 * for the Sun SBus ATM card on Solaris 2.5.1 has 1 byte of direction,
 * 1 byte of VPI, 2 bytes of VCI, and then the ATM PDU, and suggests that
 * the direction flag is 0x80 for "transmitted" (presumably meaning
 * DTE->DCE) and presumably not 0x80 for "received" (presumably meaning
 * DCE->DTE).  That code was used as the basis for the SunATM support in
 * later versions of libpcap and tcpdump, and it worked at the time the
 * development was done with the SunATM code on the system on which the
 * development was done.
 *
 * In fact, the "direction" byte appears to have some other stuff, perhaps
 * a traffic type, in the lower 7 bits, with the 8th bit indicating the
 * direction.  That appears to be the case.
 *
 * I don't know what the encapsulation of any of the other types is, so I
 * leave them all as WTAP_ENCAP_UNKNOWN, except for those for which Brian
 * Ginsbach has supplied information about the way UNICOS/mp uses them.
 * I also don't know whether "snoop" can handle any of them (it presumably
 * can't handle ATM, otherwise Sun wouldn't have supplied "atmsnoop"; even
 * if it can't, this may be useful reference information for anybody doing
 * code to use DLPI to do raw packet captures on those network types.
 *
 * Once upon a time
 *
 *	http://web.archive.org/web/20010906213807/http://www.shomiti.com/support/TNCapFileFormat.htm
 *
 * gave information on Shomiti's mutant flavor of snoop; Shomiti's Web site
 * is no longer available on the Wayback Machine.  For some unknown reason,
 * they decided not to just Go With The DLPI Flow, and instead used the types
 * unspecified in RFC 1461 for their own nefarious purposes, such as
 * distinguishing 10MB from 100MB from 1000MB Ethernet and distinguishing
 * 4MB from 16MB Token Ring, and distinguishing both of them from the
 * "Shomiti" versions of same.
 */
int snoop_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[sizeof snoop_magic];
	struct snoop_hdr hdr;
	struct snooprec_hdr rec_hdr;
	guint padbytes;
	gboolean is_shomiti;
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
		WTAP_ENCAP_NULL,	/* Other */
		WTAP_ENCAP_UNKNOWN,	/* Frame Relay LAPF */
		WTAP_ENCAP_UNKNOWN,	/* Multi-protocol over Frame Relay */
		WTAP_ENCAP_UNKNOWN,	/* Character Async (e.g., SLIP and PPP?) */
		WTAP_ENCAP_UNKNOWN,	/* X.25 Classical IP */
		WTAP_ENCAP_NULL,	/* software loopback */
		WTAP_ENCAP_UNKNOWN,	/* not defined in "dlpi.h" */
		WTAP_ENCAP_IP_OVER_FC,	/* Fibre Channel */
		WTAP_ENCAP_UNKNOWN,	/* ATM */
		WTAP_ENCAP_ATM_PDUS,	/* ATM Classical IP */
		WTAP_ENCAP_UNKNOWN,	/* X.25 LAPB */
		WTAP_ENCAP_UNKNOWN,	/* ISDN */
		WTAP_ENCAP_UNKNOWN,	/* HIPPI */
		WTAP_ENCAP_UNKNOWN,	/* 100VG-AnyLAN Ethernet */
		WTAP_ENCAP_UNKNOWN,	/* 100VG-AnyLAN Token Ring */
		WTAP_ENCAP_UNKNOWN,	/* "ISO 8802/3 and Ethernet" */
		WTAP_ENCAP_UNKNOWN,	/* 100BaseT (but that's just Ethernet) */
		WTAP_ENCAP_IP_OVER_IB,	/* Infiniband */
	};
	#define NUM_SNOOP_ENCAPS (sizeof snoop_encap / sizeof snoop_encap[0])
	#define SNOOP_PRIVATE_BIT 0x80000000
	static const int snoop_private_encap[] = {
		WTAP_ENCAP_UNKNOWN,	/* Not Used */
		WTAP_ENCAP_UNKNOWN,	/* IPv4 Tunnel Link */
		WTAP_ENCAP_UNKNOWN,	/* IPv6 Tunnel Link */
		WTAP_ENCAP_UNKNOWN,	/* Virtual network interface */
		WTAP_ENCAP_UNKNOWN,	/* IEEE 802.11 */
		WTAP_ENCAP_IPNET,	/* ipnet(7D) link */
		WTAP_ENCAP_UNKNOWN,	/* IPMP stub interface */
		WTAP_ENCAP_UNKNOWN,	/* 6to4 Tunnel Link */
	};
	#define NUM_SNOOP_PRIVATE_ENCAPS (sizeof snoop_private_encap / sizeof snoop_private_encap[0])
	static const int shomiti_encap[] = {
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
		WTAP_ENCAP_ETHERNET,	/* Fast Ethernet */
		WTAP_ENCAP_TOKEN_RING,	/* 4MB 802.5 token ring */
		WTAP_ENCAP_ETHERNET,	/* Gigabit Ethernet */
		WTAP_ENCAP_TOKEN_RING,	/* "IEEE 802.5 Shomiti" */
		WTAP_ENCAP_TOKEN_RING,	/* "4MB IEEE 802.5 Shomiti" */
		WTAP_ENCAP_UNKNOWN,	/* Other */
		WTAP_ENCAP_UNKNOWN,	/* Other */
		WTAP_ENCAP_UNKNOWN,	/* Other */
		WTAP_ENCAP_IEEE_802_11_WITH_RADIO, /* IEEE 802.11 with Radio Header */
		WTAP_ENCAP_ETHERNET,	/* 10 Gigabit Ethernet */
	};
	#define NUM_SHOMITI_ENCAPS (sizeof shomiti_encap / sizeof shomiti_encap[0])
	int file_encap;
	gint64 saved_offset;

	/* Read in the string that should be at the start of a "snoop" file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	if (memcmp(magic, snoop_magic, sizeof snoop_magic) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	/*
	 * Make sure it's a version we support.
	 */
	hdr.version = g_ntohl(hdr.version);
	switch (hdr.version) {

	case 2:		/* Solaris 2.x and later snoop, and Shomiti
			   Surveyor prior to 3.0, or 3.0 and later
			   with NDIS card */
	case 3:		/* Surveyor 3.0 and later, with Shomiti CMM2 hardware */
	case 4:		/* Surveyor 3.0 and later, with Shomiti GAM hardware */
	case 5:		/* Surveyor 3.0 and later, with Shomiti THG hardware */
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("snoop: version %u unsupported", hdr.version);
		return -1;
	}

	/*
	 * Oh, this is lovely.
	 *
	 * I suppose Shomiti could give a bunch of lawyerly noise about
	 * how "well, RFC 1761 said they were unassigned, and that's
	 * the standard, not the DLPI header file, so it's perfectly OK
	 * for us to use them, blah blah blah", but it's still irritating
	 * as hell that they used the unassigned-in-RFC-1761 values for
	 * their own purposes - especially given that Sun also used
	 * one of them in atmsnoop.
	 *
	 * We can't determine whether it's a Shomiti capture based on
	 * the version number, as, according to their documentation on
	 * their capture file format, Shomiti uses a version number of 2
	 * if the data "was captured using an NDIS card", which presumably
	 * means "captured with an ordinary boring network card via NDIS"
	 * as opposed to "captured with our whizzo special capture
	 * hardware".
	 *
	 * The only way I can see to determine that is to check how much
	 * padding there is in the first packet - if there's enough
	 * padding for a Shomiti trailer, it's probably a Shomiti
	 * capture, and otherwise, it's probably from Snoop.
	 */

	/*
	 * Start out assuming it's not a Shomiti capture.
	 */
	is_shomiti = FALSE;

	/* Read first record header. */
	saved_offset = file_tell(wth->fh);
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&rec_hdr, sizeof rec_hdr, wth->fh);
	if (bytes_read != sizeof rec_hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		if (*err != 0) {
			/*
			 * A real-live error.
			 */
			return -1;
		}

		/*
		 * The file ends after the record header, which means this
		 * is a capture with no packets.
		 *
		 * We assume it's a snoop file; the actual type of file is
		 * irrelevant, as there are no records in it, and thus no
		 * extra information if it's a Shomiti capture, and no
		 * link-layer headers whose type we have to know, and no
		 * Ethernet frames that might have an FCS.
		 */
	} else {
		/*
		 * Compute the number of bytes of padding in the
		 * record.  If it's at least the size of a Shomiti
		 * trailer record, we assume this is a Shomiti
		 * capture.  (Some atmsnoop captures appear
		 * to have 4 bytes of padding, and at least one
		 * snoop capture appears to have 6 bytes of padding;
		 * the Shomiti header is larger than either of those.)
		 */
		if (g_ntohl(rec_hdr.rec_len) >
		    (sizeof rec_hdr + g_ntohl(rec_hdr.incl_len))) {
			/*
			 * Well, we have padding; how much?
			 */
			padbytes = g_ntohl(rec_hdr.rec_len) -
			    ((guint)sizeof rec_hdr + g_ntohl(rec_hdr.incl_len));

			/*
			 * Is it at least the size of a Shomiti trailer?
			 */
			is_shomiti =
			    (padbytes >= sizeof (struct shomiti_trailer));
		}
	}

	/*
	 * Seek back to the beginning of the first record.
	 */
	if (file_seek(wth->fh, saved_offset, SEEK_SET, err) == -1)
		return -1;

	hdr.network = g_ntohl(hdr.network);
	if (is_shomiti) {
		if (hdr.network >= NUM_SHOMITI_ENCAPS
		    || shomiti_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("snoop: Shomiti network type %u unknown or unsupported",
			    hdr.network);
			return -1;
		}
		file_encap = shomiti_encap[hdr.network];

		/* This is a Shomiti file */
		wth->file_type = WTAP_FILE_SHOMITI;
	} else if (hdr.network & SNOOP_PRIVATE_BIT) {
		if ((hdr.network^SNOOP_PRIVATE_BIT) >= NUM_SNOOP_PRIVATE_ENCAPS
		    || snoop_private_encap[hdr.network^SNOOP_PRIVATE_BIT] == WTAP_ENCAP_UNKNOWN) {
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("snoop: private network type %u unknown or unsupported",
			    hdr.network);
			return -1;
		}
		file_encap = snoop_private_encap[hdr.network^SNOOP_PRIVATE_BIT];

		/* This is a snoop file */
		wth->file_type = WTAP_FILE_SNOOP;
	} else {
		if (hdr.network >= NUM_SNOOP_ENCAPS
		    || snoop_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("snoop: network type %u unknown or unsupported",
			    hdr.network);
			return -1;
		}
		file_encap = snoop_encap[hdr.network];

		/* This is a snoop file */
		wth->file_type = WTAP_FILE_SNOOP;
	}

	/*
	 * We don't currently use the extra information in Shomiti
	 * records, so we use the same routines to read snoop and
	 * Shomiti files.
	 */
	wth->subtype_read = snoop_read;
	wth->subtype_seek_read = snoop_seek_read;
	wth->file_encap = file_encap;
	wth->snapshot_length = 0;	/* not available in header */
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;
	return 1;
}

typedef struct {
	guint8 pad[4];
	guint8 undecrypt[2];
	guint8 rate;
	guint8 preamble;
	guint8 code;
	guint8 signal;
	guint8 qual;
	guint8 channel;
} shomiti_wireless_header;


/* Read the next packet */
static gboolean snoop_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	guint32 rec_size;
	guint32	packet_size;
	guint32 orig_size;
	int	bytes_read;
	struct snooprec_hdr hdr;
	char	padbuf[4];
	guint	padbytes;
	int	bytes_to_read;
	int header_size;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	rec_size = g_ntohl(hdr.rec_len);
	orig_size = g_ntohl(hdr.orig_len);
	packet_size = g_ntohl(hdr.incl_len);
	if (orig_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("snoop: File has %u-byte original length, bigger than maximum of %u",
		    orig_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("snoop: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}
	if (packet_size > rec_size) {
		/*
		 * Probably a corrupt capture file.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("snoop: File has %u-byte packet, bigger than record size %u",
		    packet_size, rec_size);
		return FALSE;
	}

	*data_offset = file_tell(wth->fh);

	/*
	 * If this is an ATM packet, the first four bytes are the
	 * direction of the packet (transmit/receive), the VPI, and
	 * the VCI; read them and generate the pseudo-header from
	 * them.
	 */
	switch (wth->file_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		if (packet_size < sizeof (struct snoop_atm_hdr)) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("snoop: atmsnoop file has a %u-byte packet, too small to have even an ATM pseudo-header",
			    packet_size);
			return FALSE;
		}
		if (!snoop_read_atm_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		rec_size -= (guint32)sizeof (struct snoop_atm_hdr);
		orig_size -= (guint32)sizeof (struct snoop_atm_hdr);
		packet_size -= (guint32)sizeof (struct snoop_atm_hdr);
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * If this is a snoop file, we assume there's no FCS in
		 * this frame; if this is a Shomit file, we assume there
		 * is.  (XXX - or should we treat it a "maybe"?)
		 */
		if (wth->file_type == WTAP_FILE_SHOMITI)
			wth->pseudo_header.eth.fcs_len = 4;
		else
			wth->pseudo_header.eth.fcs_len = 0;
		break;

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
		if (packet_size < sizeof (shomiti_wireless_header)) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("snoop: Shomiti wireless file has a %u-byte packet, too small to have even a wireless pseudo-header",
			    packet_size);
			return FALSE;
		}
		if (!snoop_read_shomiti_wireless_pseudoheader(wth->fh,
		    &wth->pseudo_header, err, err_info, &header_size))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		rec_size -= header_size;
		orig_size -= header_size;
		packet_size -= header_size;
		break;
	}

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!snoop_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
	    packet_size, err, err_info))
		return FALSE;	/* Read error */

	wth->phdr.presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	wth->phdr.ts.secs = g_ntohl(hdr.ts_sec);
	wth->phdr.ts.nsecs = g_ntohl(hdr.ts_usec) * 1000;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;

	/*
	 * If this is ATM LANE traffic, try to guess what type of LANE
	 * traffic it is based on the packet contents.
	 */
	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS &&
	    wth->pseudo_header.atm.type == TRAF_LANE) {
		atm_guess_lane_type(buffer_start_ptr(wth->frame_buffer),
		    wth->phdr.caplen, &wth->pseudo_header);
	}

	/*
	 * Skip over the padding (don't "fseek()", as the standard
	 * I/O library on some platforms discards buffered data if
	 * you do that, which means it does a lot more reads).
	 * There's probably not much padding (it's probably padded only
	 * to a 4-byte boundary), so we probably need only do one read.
	 */
	if (rec_size < (sizeof hdr + packet_size)) {
		/*
		 * What, *negative* padding?  Bogus.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("snoop: File has %u-byte record with packet size of %u",
		    rec_size, packet_size);
		return FALSE;
	}
	padbytes = rec_size - ((guint)sizeof hdr + packet_size);
	while (padbytes != 0) {
		bytes_to_read = padbytes;
		if ((unsigned)bytes_to_read > sizeof padbuf)
			bytes_to_read = sizeof padbuf;
		errno = WTAP_ERR_CANT_READ;
		bytes_read = file_read(padbuf, bytes_to_read, wth->fh);
		if (bytes_read != bytes_to_read) {
			*err = file_error(wth->fh, err_info);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return FALSE;
		}
		padbytes -= bytes_read;
	}

	return TRUE;
}

static gboolean
snoop_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		if (!snoop_read_atm_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * If this is a snoop file, we assume there's no FCS in
		 * this frame; if this is a Shomit file, we assume there
		 * is.  (XXX - or should we treat it a "maybe"?)
		 */
		if (wth->file_type == WTAP_FILE_SHOMITI)
			pseudo_header->eth.fcs_len = 4;
		else
			pseudo_header->eth.fcs_len = 0;
		break;

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
		if (!snoop_read_shomiti_wireless_pseudoheader(wth->random_fh,
		    pseudo_header, err, err_info, NULL)) {
			/* Read error */
			return FALSE;
		}
		break;
	}

	/*
	 * Read the packet data.
	 */
	if (!snoop_read_rec_data(wth->random_fh, pd, length, err, err_info))
		return FALSE;	/* failed */

	/*
	 * If this is ATM LANE traffic, try to guess what type of LANE
	 * traffic it is based on the packet contents.
	 */
	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS &&
	    pseudo_header->atm.type == TRAF_LANE)
		atm_guess_lane_type(pd, length, pseudo_header);
	return TRUE;
}

static gboolean
snoop_read_atm_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
    int *err, gchar **err_info)
{
	struct snoop_atm_hdr atm_phdr;
	int	bytes_read;
	guint8	vpi;
	guint16	vci;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&atm_phdr, sizeof (struct snoop_atm_hdr), fh);
	if (bytes_read != sizeof (struct snoop_atm_hdr)) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	vpi = atm_phdr.vpi;
	vci = pntohs(&atm_phdr.vci);

	/*
	 * The lower 4 bits of the first byte of the header indicate
	 * the type of traffic, as per the "atmioctl.h" header in
	 * SunATM.
	 */
	switch (atm_phdr.flags & 0x0F) {

	case 0x01:	/* LANE */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_LANE;
		break;

	case 0x02:	/* RFC 1483 LLC multiplexed traffic */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_LLCMX;
		break;

	case 0x05:	/* ILMI */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_ILMI;
		break;

	case 0x06:	/* Signalling AAL */
		pseudo_header->atm.aal = AAL_SIGNALLING;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		break;

	case 0x03:	/* MARS (RFC 2022) */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		break;

	case 0x04:	/* IFMP (Ipsilon Flow Management Protocol; see RFC 1954) */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;	/* XXX - TRAF_IPSILON? */
		break;

	default:
		/*
		 * Assume it's AAL5, unless it's VPI 0 and VCI 5, in which
		 * case assume it's AAL_SIGNALLING; we know nothing more
		 * about it.
		 *
		 * XXX - is this necessary?  Or are we guaranteed that
		 * all signalling traffic has a type of 0x06?
		 *
		 * XXX - is this guaranteed to be AAL5?  Or, if the type is
		 * 0x00 ("raw"), might it be non-AAL5 traffic?
		 */
		if (vpi == 0 && vci == 5)
			pseudo_header->atm.aal = AAL_SIGNALLING;
		else
			pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		break;
	}
	pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;

	pseudo_header->atm.vpi = vpi;
	pseudo_header->atm.vci = vci;
	pseudo_header->atm.channel = (atm_phdr.flags & 0x80) ? 0 : 1;

	/* We don't have this information */
	pseudo_header->atm.flags = 0;
	pseudo_header->atm.cells = 0;
	pseudo_header->atm.aal5t_u2u = 0;
	pseudo_header->atm.aal5t_len = 0;
	pseudo_header->atm.aal5t_chksum = 0;

	return TRUE;
}

static gboolean
snoop_read_shomiti_wireless_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info,
    int *header_size)
{
	shomiti_wireless_header whdr;
	int	bytes_read;
	int	rsize;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&whdr, sizeof (shomiti_wireless_header), fh);
	if (bytes_read != sizeof (shomiti_wireless_header)) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	/* the 4th byte of the pad is actually a header length,
	 * we've already read 8 bytes of it, and it must never
	 * be less than 8.
	 *
	 * XXX - presumably that means that the header length
	 * doesn't include the length field, as we've read
	 * 12 bytes total.
	 *
	 * XXX - what's in the other 3 bytes of the padding?  Is it a
	 * 4-byte length field?
	 * XXX - is there anything in the rest of the header of interest?
	 * XXX - are there any files where the header is shorter than
	 * 4 bytes of length plus 8 bytes of information?
	 */
	if (whdr.pad[3] < 8) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("snoop: Header length in Surveyor record is %u, less than minimum of 8",
		    whdr.pad[3]);
		return FALSE;
	}
	/* Skip the header. */
	rsize = ((int) whdr.pad[3]) - 8;
	if (file_seek(fh, rsize, SEEK_CUR, err) == -1)
		return FALSE;

	pseudo_header->ieee_802_11.fcs_len = 4;
	pseudo_header->ieee_802_11.channel = whdr.channel;
	pseudo_header->ieee_802_11.data_rate = whdr.rate;
	pseudo_header->ieee_802_11.signal_level = whdr.signal;

	/* add back the header and don't forget the pad as well */
	if(header_size != NULL)
	    *header_size = rsize + 8 + 4;

    return TRUE;
}

static gboolean
snoop_read_rec_data(FILE_T fh, guint8 *pd, int length, int *err,
    gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
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
	-1,		/* WTAP_ENCAP_ARCNET_LINUX -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
	-1,		/* WTAP_ENCAP_LAPB -> unsupported*/
	0x12,		/* WTAP_ENCAP_ATM_PDUS -> DL_IPATM */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int snoop_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || (unsigned)encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean snoop_dump_open(wtap_dumper *wdh, int *err)
{
	struct snoop_hdr file_hdr;

	/* This is a snoop file */
	wdh->subtype_write = snoop_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	if (!wtap_dump_file_write(wdh, &snoop_magic, sizeof snoop_magic, err))
		return FALSE;

	/* current "snoop" format is 2 */
	file_hdr.version = g_htonl(2);
	file_hdr.network = g_htonl(wtap_encap[wdh->encap]);
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
		return FALSE;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean snoop_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guint8 *pd, int *err)
{
	struct snooprec_hdr rec_hdr;
	int reclen;
	guint padlen;
	static char zeroes[4];
	struct snoop_atm_hdr atm_hdr;
	int atm_hdrsize;

	if (wdh->encap == WTAP_ENCAP_ATM_PDUS)
		atm_hdrsize = sizeof (struct snoop_atm_hdr);
	else
		atm_hdrsize = 0;

	/* Record length = header length plus data length... */
	reclen = (int)sizeof rec_hdr + phdr->caplen + atm_hdrsize;

	/* ... plus enough bytes to pad it to a 4-byte boundary. */
	padlen = ((reclen + 3) & ~3) - reclen;
	reclen += padlen;

	rec_hdr.orig_len = g_htonl(phdr->len + atm_hdrsize);
	rec_hdr.incl_len = g_htonl(phdr->caplen + atm_hdrsize);
	rec_hdr.rec_len = g_htonl(reclen);
	rec_hdr.cum_drops = 0;
	rec_hdr.ts_sec = g_htonl(phdr->ts.secs);
	rec_hdr.ts_usec = g_htonl(phdr->ts.nsecs / 1000);
	if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
		return FALSE;

	if (wdh->encap == WTAP_ENCAP_ATM_PDUS) {
		/*
		 * Write the ATM header.
		 */
		atm_hdr.flags =
		    (pseudo_header->atm.channel == 0) ? 0x80 : 0x00;
		switch (pseudo_header->atm.aal) {

		case AAL_SIGNALLING:
			/* Signalling AAL */
			atm_hdr.flags |= 0x06;
			break;

		case AAL_5:
			switch (pseudo_header->atm.type) {

			case TRAF_LANE:
				/* LANE */
				atm_hdr.flags |= 0x01;
				break;

			case TRAF_LLCMX:
				/* RFC 1483 LLC multiplexed traffic */
				atm_hdr.flags |= 0x02;
				break;

			case TRAF_ILMI:
				/* ILMI */
				atm_hdr.flags |= 0x05;
				break;
			}
			break;
		}
		atm_hdr.vpi = (guint8) pseudo_header->atm.vpi;
		atm_hdr.vci = g_htons(pseudo_header->atm.vci);
		if (!wtap_dump_file_write(wdh, &atm_hdr, sizeof atm_hdr, err))
			return FALSE;
	}

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;

	/* Now write the padding. */
	if (!wtap_dump_file_write(wdh, zeroes, padlen, err))
		return FALSE;
	return TRUE;
}
