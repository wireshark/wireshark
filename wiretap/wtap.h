/* wtap.h
 *
 * $Id: wtap.h,v 1.91 2001/10/19 20:18:48 guy Exp $
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

#ifndef __WTAP_H__
#define __WTAP_H__

/* Encapsulation types. Choose names that truly reflect
 * what is contained in the packet trace file.
 *
 * WTAP_ENCAP_PER_PACKET is a value passed to "wtap_dump_open()" or
 * "wtap_dump_fd_open()" to indicate that there is no single encapsulation
 * type for all packets in the file; this may cause those routines to
 * fail if the capture file format being written can't support that.
 * It's also returned by "wtap_file_encap()" for capture files that
 * don't have a single encapsulation type for all packets in the file.
 *
 * WTAP_ENCAP_UNKNOWN is returned by "wtap_pcap_encap_to_wtap_encap()"
 * if it's handed an unknown encapsulation.
 *
 * WTAP_ENCAP_FDDI_BITSWAPPED is for FDDI captures on systems where the
 * MAC addresses you get from the hardware are bit-swapped.  Ideally,
 * the driver would tell us that, but I know of none that do, so, for
 * now, we base it on the machine on which we're *reading* the
 * capture, rather than on the machine on which the capture was taken
 * (they're probably likely to be the same).  We assume that they're
 * bit-swapped on everything except for systems running Ultrix, Alpha
 * systems, and BSD/OS systems (that's what "tcpdump" does; I guess
 * Digital decided to bit-swap addresses in the hardware or in the
 * driver, and I guess BSDI bit-swapped them in the driver, given that
 * BSD/OS generally runs on Boring Old PC's).  If we create a wiretap
 * save file format, we'd use the WTAP_ENCAP values to flag the
 * encapsulation of a packet, so there we'd at least be able to base
 * it on the machine on which the capture was taken.
 *
 * WTAP_ENCAP_LINUX_ATM_CLIP is the encapsulation you get with the
 * ATM on Linux code from <http://linux-atm.sourceforge.net/>;
 * that code adds a DLT_ATM_CLIP DLT_ code of 19, and that
 * encapsulation isn't the same as the DLT_ATM_RFC1483 encapsulation
 * presumably used on some BSD systems, which we turn into
 * WTAP_ENCAP_ATM_RFC1483.
 *
 * WTAP_ENCAP_NULL corresponds to DLT_NULL from "libpcap".  This
 * corresponds to
 *
 *	1) PPP-over-HDLC encapsulation, at least with some versions
 *	   of ISDN4BSD (but not the current ones, it appears, unless
 *	   I've missed something);
 *
 *	2) a 4-byte header containing the AF_ address family, in
 *	   the byte order of the machine that saved the capture,
 *	   for the packet, as used on many BSD systems for the
 *	   loopback device and some other devices;
 *
 *	3) a 4-byte header containing 2 octets of 0 and an Ethernet
 *	   type in the byte order from an Ethernet header, that being
 *	   what "libpcap" on Linux turns the Ethernet header for
 *	   loopback interfaces into. */
#define WTAP_ENCAP_PER_PACKET			-1
#define WTAP_ENCAP_UNKNOWN			0
#define WTAP_ENCAP_ETHERNET			1
#define WTAP_ENCAP_TOKEN_RING			2
#define WTAP_ENCAP_SLIP				3
#define WTAP_ENCAP_PPP				4
#define WTAP_ENCAP_FDDI				5
#define WTAP_ENCAP_FDDI_BITSWAPPED		6
#define WTAP_ENCAP_RAW_IP			7
#define WTAP_ENCAP_ARCNET			8
#define WTAP_ENCAP_ATM_RFC1483			9
#define WTAP_ENCAP_LINUX_ATM_CLIP		10
#define WTAP_ENCAP_LAPB				11
#define WTAP_ENCAP_ATM_SNIFFER			12
#define WTAP_ENCAP_NULL				13
#define WTAP_ENCAP_ASCEND			14
#define WTAP_ENCAP_LAPD				15
#define WTAP_ENCAP_V120				16
#define WTAP_ENCAP_PPP_WITH_PHDR		17
#define WTAP_ENCAP_IEEE_802_11			18
#define WTAP_ENCAP_SLL				19
#define WTAP_ENCAP_FRELAY			20
#define WTAP_ENCAP_CHDLC			21

/* last WTAP_ENCAP_ value + 1 */
#define WTAP_NUM_ENCAP_TYPES			22

/* File types that can be read by wiretap.
   We support writing some many of these file types, too, so we
   distinguish between different versions of them. */
#define WTAP_FILE_UNKNOWN			0
#define WTAP_FILE_WTAP				1
#define WTAP_FILE_PCAP				2
#define WTAP_FILE_PCAP_SS990417			3
#define WTAP_FILE_PCAP_SS990915			4
#define WTAP_FILE_PCAP_SS991029			5
#define WTAP_FILE_PCAP_NOKIA			6
#define WTAP_FILE_LANALYZER			7
#define WTAP_FILE_NGSNIFFER_UNCOMPRESSED	8
#define WTAP_FILE_NGSNIFFER_COMPRESSED		9
#define WTAP_FILE_SNOOP				10
#define WTAP_FILE_IPTRACE_1_0			11
#define WTAP_FILE_IPTRACE_2_0			12
#define WTAP_FILE_NETMON_1_x			13
#define WTAP_FILE_NETMON_2_x			14
#define WTAP_FILE_NETXRAY_1_0			15
#define WTAP_FILE_NETXRAY_1_1			16
#define WTAP_FILE_NETXRAY_2_00x			17
#define WTAP_FILE_RADCOM			18
#define WTAP_FILE_ASCEND			19
#define WTAP_FILE_NETTL				20
#define WTAP_FILE_TOSHIBA			21
#define WTAP_FILE_I4BTRACE			22
#define WTAP_FILE_CSIDS				23
#define WTAP_FILE_PPPDUMP			24
#define WTAP_FILE_ETHERPEEK_MAC_V56		25
#define WTAP_FILE_ETHERPEEK_MAC_V7		26
#define WTAP_FILE_VMS				27
#define WTAP_FILE_DBS_ETHERWATCH		28

/* last WTAP_FILE_ value + 1 */
#define WTAP_NUM_FILE_TYPES			29

/*
 * Maximum packet size we'll support.
 */
#define	WTAP_MAX_PACKET_SIZE			65535

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <glib.h>
#include <stdio.h>

/* Packet "pseudo-header" information for X.25 capture files. */
struct x25_phdr {
	guint8	flags; /* ENCAP_LAPB : 1st bit means From DCE */
};

/* Packet "pseudo-header" for ATM Sniffer capture files. */
struct ngsniffer_atm_phdr {
	guint8	AppTrafType;	/* traffic type */
	guint8	AppHLType;	/* protocol type */
	guint16	Vpi;		/* virtual path identifier */
	guint16	Vci;		/* virtual circuit identifier */
	guint16	channel;	/* link: 0 for DCE, 1 for DTE */
	guint16	cells;		/* number of cells */
	guint16	aal5t_u2u;	/* user-to-user indicator */
	guint16	aal5t_len;	/* length of the packet */
	guint32	aal5t_chksum;	/* checksum for AAL5 packet */
};

/* Packet "pseudo-header" for the output from "wandsession", "wannext",
   "wandisplay", and similar commands on Lucent/Ascend access equipment. */

#define ASCEND_MAX_STR_LEN 64

#define ASCEND_PFX_WDS_X 1
#define ASCEND_PFX_WDS_R 2
#define ASCEND_PFX_WDD   3

struct ascend_phdr {
	guint16	type;			/* ASCEND_PFX_*, as defined above */
	char	user[ASCEND_MAX_STR_LEN];   /* Username, from wandsession header */
	guint32	sess;			/* Session number, from wandsession header */
	char	call_num[ASCEND_MAX_STR_LEN];   /* Called number, from WDD header */
	guint32	chunk;			/* Chunk number, from WDD header */
	guint32	task;			/* Task number */
};

/* Packet "pseudo_header" for etherpeek capture files. */
struct etherpeek_phdr {
	struct timeval reference_time;
};

struct p2p_phdr {
	gboolean	sent; /* TRUE=sent, FALSE=received */
};


/*
 * Bits in AppTrafType.
 *
 * For AAL types other than AAL5, the packet data is presumably for a
 * single cell, not a reassembled frame, as the ATM Sniffer manual says
 * it dosn't reassemble cells other than AAL5 cells.
 */
#define	ATT_AALTYPE		0x0F	/* AAL type: */
#define	ATT_AAL_UNKNOWN		0x00	/* Unknown AAL */
#define	ATT_AAL1		0x01	/* AAL1 */
#define	ATT_AAL3_4		0x02	/* AAL3/4 */
#define	ATT_AAL5		0x03	/* AAL5 */
#define	ATT_AAL_USER		0x04	/* User AAL */
#define	ATT_AAL_SIGNALLING	0x05	/* Signaling AAL */
#define	ATT_OAMCELL		0x06	/* OAM cell */

#define	ATT_HLTYPE		0xF0	/* Higher-layer type: */
#define	ATT_HL_UNKNOWN		0x00	/* unknown */
#define	ATT_HL_LLCMX		0x10	/* LLC multiplexed (probably RFC 1483) */
#define	ATT_HL_VCMX		0x20	/* VC multiplexed (probably RFC 1483) */
#define	ATT_HL_LANE		0x30	/* LAN Emulation */
#define	ATT_HL_ILMI		0x40	/* ILMI */
#define	ATT_HL_FRMR		0x50	/* Frame Relay */
#define	ATT_HL_SPANS		0x60	/* FORE SPANS */
#define	ATT_HL_IPSILON		0x70	/* Ipsilon */

/*
 * Values for AppHLType; the interpretation depends on the ATT_HLTYPE
 * bits in AppTrafType.
 */
#define	AHLT_UNKNOWN		0x0
#define	AHLT_VCMX_802_3_FCS	0x1	/* VCMX: 802.3 FCS */
#define	AHLT_LANE_LE_CTRL	0x1	/* LANE: LE Ctrl */
#define	AHLT_IPSILON_FT0	0x1	/* Ipsilon: Flow Type 0 */
#define	AHLT_VCMX_802_4_FCS	0x2	/* VCMX: 802.4 FCS */
#define	AHLT_LANE_802_3		0x2	/* LANE: 802.3 */
#define	AHLT_IPSILON_FT1	0x2	/* Ipsilon: Flow Type 1 */
#define	AHLT_VCMX_802_5_FCS	0x3	/* VCMX: 802.5 FCS */
#define	AHLT_LANE_802_5		0x3	/* LANE: 802.5 */
#define	AHLT_IPSILON_FT2	0x3	/* Ipsilon: Flow Type 2 */
#define	AHLT_VCMX_FDDI_FCS	0x4	/* VCMX: FDDI FCS */
#define	AHLT_LANE_802_3_MC	0x4	/* LANE: 802.3 multicast */
#define	AHLT_VCMX_802_6_FCS	0x5	/* VCMX: 802.6 FCS */
#define	AHLT_LANE_802_5_MC	0x5	/* LANE: 802.5 multicast */
#define	AHLT_VCMX_802_3		0x7	/* VCMX: 802.3 */
#define	AHLT_VCMX_802_4		0x8	/* VCMX: 802.4 */
#define	AHLT_VCMX_802_5		0x9	/* VCMX: 802.5 */
#define	AHLT_VCMX_FDDI		0xa	/* VCMX: FDDI */
#define	AHLT_VCMX_802_6		0xb	/* VCMX: 802.6 */
#define	AHLT_VCMX_FRAGMENTS	0xc	/* VCMX: Fragments */
#define	AHLT_VCMX_BPDU		0xe	/* VCMX: BPDU */

union wtap_pseudo_header {
	struct x25_phdr			x25;
	struct ngsniffer_atm_phdr	ngsniffer_atm;
	struct ascend_phdr		ascend;
	struct etherpeek_phdr           etherpeek;
	struct p2p_phdr			p2p;
};

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
	int pkt_encap;
};

typedef void (*wtap_handler)(u_char*, const struct wtap_pkthdr*,
		long, union wtap_pseudo_header *pseudo_header, const u_char *);

struct wtap;
struct Buffer;
struct wtap_dumper;

typedef struct wtap wtap;
typedef struct wtap_dumper wtap_dumper;

/*
 * On failure, "wtap_open_offline()" returns NULL, and puts into the
 * "int" pointed to by its second argument:
 *
 * a positive "errno" value if the capture file can't be opened;
 *
 * a negative number, indicating the type of error, on other failures.
 */
struct wtap* wtap_open_offline(const char *filename, int *err, gboolean do_random);

/* Returns TRUE if entire loop-reading was successful. If read failure
 * happened, FALSE is returned and err is set. */
gboolean wtap_loop(wtap *wth, int, wtap_handler, u_char*, int *err);

/* Returns TRUE if read was successful. FALSE if failure. data_offset is
 * set the the offset in the file where the data for the read packet is
 * located. */
gboolean wtap_read(wtap *wth, int *err, long *data_offset);

struct wtap_pkthdr *wtap_phdr(wtap *wth);
union wtap_pseudo_header *wtap_pseudoheader(wtap *wth);
guint8 *wtap_buf_ptr(wtap *wth);

int wtap_fd(wtap *wth);
int wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
int wtap_file_encap(wtap *wth);

const char *wtap_file_type_string(int filetype);
const char *wtap_file_type_short_string(int filetype);
int wtap_short_string_to_file_type(const char *short_name);

const char *wtap_encap_string(int encap);
const char *wtap_encap_short_string(int encap);
int wtap_short_string_to_encap(const char *short_name);

const char *wtap_strerror(int err);
void wtap_sequential_close(wtap *wth);
void wtap_close(wtap *wth);
int wtap_seek_read (wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len);
int wtap_def_seek_read (wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len);

gboolean wtap_dump_can_open(int filetype);
gboolean wtap_dump_can_write_encap(int filetype, int encap);
wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
	int snaplen, int *err);
wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
	int *err);
gboolean wtap_dump(wtap_dumper *, const struct wtap_pkthdr *,
	const union wtap_pseudo_header *pseudo_header, const u_char *, int *err);
FILE* wtap_dump_file(wtap_dumper *);
gboolean wtap_dump_close(wtap_dumper *, int *);

/* XXX - needed until "wiretap" can do live packet captures */
int wtap_pcap_encap_to_wtap_encap(int encap);

/*
 * Wiretap error codes.
 */
#define	WTAP_ERR_NOT_REGULAR_FILE		-1
	/* The file being opened for reading isn't a plain file */
#define	WTAP_ERR_FILE_UNKNOWN_FORMAT		-2
	/* The file being opened is not a capture file in a known format */
#define	WTAP_ERR_UNSUPPORTED			-3
	/* Supported file type, but there's something in the file we
	   can't support */
#define	WTAP_ERR_CANT_OPEN			-4
	/* The file couldn't be opened, reason unknown */
#define	WTAP_ERR_UNSUPPORTED_FILE_TYPE		-5
	/* Wiretap can't save files in the specified format */
#define	WTAP_ERR_UNSUPPORTED_ENCAP		-6
	/* Wiretap can't read or save files in the specified format with the
	   specified encapsulation */
#define	WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED	-7
	/* The specified format doesn't support per-packet encapsulations */
#define	WTAP_ERR_CANT_CLOSE			-8
	/* The file couldn't be closed, reason unknown */
#define	WTAP_ERR_CANT_READ			-9
	/* An attempt to read failed, reason unknown */
#define	WTAP_ERR_SHORT_READ			-10
	/* An attempt to read read less data than it should have */
#define	WTAP_ERR_BAD_RECORD			-11
	/* We read an invalid record */
#define	WTAP_ERR_SHORT_WRITE			-12
	/* An attempt to write wrote less data than it should have */
#define	WTAP_ERR_UNC_TRUNCATED			-13
	/* Sniffer compressed data was oddly truncated */
#define	WTAP_ERR_UNC_OVERFLOW			-14
	/* Uncompressing Sniffer data would overflow buffer */
#define	WTAP_ERR_UNC_BAD_OFFSET			-15
	/* LZ77 compressed data has bad offset to string */

/* Errors from zlib; zlib error Z_xxx turns into Wiretap error
   WTAP_ERR_ZLIB + Z_xxx.

   WTAP_ERR_ZLIB_MIN and WTAP_ERR_ZLIB_MAX bound the range of zlib
   errors; we leave room for 100 positive and 100 negative error
   codes. */

#define	WTAP_ERR_ZLIB				-200
#define	WTAP_ERR_ZLIB_MAX			-100
#define	WTAP_ERR_ZLIB_MIN			-300


#endif /* __WTAP_H__ */
