/* wtap.h
 *
 * $Id: wtap.h,v 1.120 2002/07/31 22:41:34 jmayer Exp $
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

#ifndef __WTAP_H__
#define __WTAP_H__

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#include <glib.h>
#include <stdio.h>

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
 *	   loopback device and some other devices, or a 4-byte header
 *	   containing the AF_ address family in network byte order,
 *	   as used on recent OpenBSD systems for the loopback device;
 *
 *	3) a 4-byte header containing 2 octets of 0 and an Ethernet
 *	   type in the byte order from an Ethernet header, that being
 *	   what older versions of "libpcap" on Linux turn the Ethernet
 *	   header for loopback interfaces into (0.6.0 and later versions
 *	   leave the Ethernet header alone and make it DLT_EN10MB). */
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
#define WTAP_ENCAP_IEEE_802_11_WITH_RADIO	19
#define WTAP_ENCAP_SLL				20
#define WTAP_ENCAP_FRELAY			21
#define WTAP_ENCAP_CHDLC			22
#define WTAP_ENCAP_CISCO_IOS			23
#define WTAP_ENCAP_LOCALTALK			24
#define WTAP_ENCAP_PRISM_HEADER			25
#define WTAP_ENCAP_PFLOG			26
#define WTAP_ENCAP_HHDLC			27
#define WTAP_ENCAP_DOCSIS			28
#define WTAP_ENCAP_COSINE			29

/* last WTAP_ENCAP_ value + 1 */
#define WTAP_NUM_ENCAP_TYPES			30

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
#define WTAP_FILE_PCAP_AIX			7
#define WTAP_FILE_LANALYZER			8
#define WTAP_FILE_NGSNIFFER_UNCOMPRESSED	9
#define WTAP_FILE_NGSNIFFER_COMPRESSED		10
#define WTAP_FILE_SNOOP				11
#define WTAP_FILE_IPTRACE_1_0			12
#define WTAP_FILE_IPTRACE_2_0			13
#define WTAP_FILE_NETMON_1_x			14
#define WTAP_FILE_NETMON_2_x			15
#define WTAP_FILE_NETXRAY_OLD			16
#define WTAP_FILE_NETXRAY_1_0			17
#define WTAP_FILE_NETXRAY_1_1			18
#define WTAP_FILE_NETXRAY_2_00x			19
#define WTAP_FILE_RADCOM			20
#define WTAP_FILE_ASCEND			21
#define WTAP_FILE_NETTL				22
#define WTAP_FILE_TOSHIBA			23
#define WTAP_FILE_I4BTRACE			24
#define WTAP_FILE_CSIDS				25
#define WTAP_FILE_PPPDUMP			26
#define WTAP_FILE_ETHERPEEK_V56			27
#define WTAP_FILE_ETHERPEEK_V7			28
#define WTAP_FILE_VMS				29
#define WTAP_FILE_DBS_ETHERWATCH		30
#define WTAP_FILE_VISUAL_NETWORKS		31
#define WTAP_FILE_COSINE			32

/* last WTAP_FILE_ value + 1 */
#define WTAP_NUM_FILE_TYPES			33

/*
 * Maximum packet size we'll support.
 */
#define	WTAP_MAX_PACKET_SIZE			65535

/*
 * "Pseudo-headers" are used to supply to the clients of wiretap
 * per-packet information that's not part of the packet payload
 * proper.
 *
 * NOTE: do not use pseudo-header structures to hold information
 * used by the code to read a particular capture file type; to
 * keep that sort of state information, add a new structure for
 * that private information to "wtap-int.h", add a pointer to that
 * type of structure to the "capture" member of the "struct wtap"
 * structure, and allocate one of those structures and set that member
 * in the "open" routine for that capture file type if the open
 * succeeds.  See various other capture file type handlers for examples
 * of that.
 */

/* Packet "pseudo-header" information for X.25 capture files. */
#define FROM_DCE			0x80
struct x25_phdr {
	guint8	flags; /* ENCAP_LAPB, ENCAP_V120 : 1st bit means From DCE */
};

/* Packet "pseudo-header" for ATM capture files.
   Not all of this information is supplied by all capture types. */

/*
 * AAL types.
 */
#define AAL_UNKNOWN	0	/* AAL unknown */
#define AAL_1		1	/* AAL1 */
#define AAL_2		2	/* AAL2 */
#define AAL_3_4		3	/* AAL3/4 */
#define AAL_5		4	/* AAL5 */
#define AAL_USER	5	/* User AAL */
#define AAL_SIGNALLING	6	/* Signaling AAL */
#define AAL_OAMCELL	7	/* OAM cell */

/*
 * Traffic types.
 */
#define TRAF_UNKNOWN	0	/* Unknown */
#define TRAF_LLCMX	1	/* LLC multiplexed (RFC 1483) */
#define TRAF_VCMX	2	/* VC multiplexed (RFC 1483) */
#define TRAF_LANE	3	/* LAN Emulation */
#define TRAF_ILMI	4	/* ILMI */
#define TRAF_FR		5	/* Frame Relay */
#define TRAF_SPANS	6	/* FORE SPANS */
#define TRAF_IPSILON	7	/* Ipsilon */

/*
 * Traffic subtypes.
 */
#define	TRAF_ST_UNKNOWN		0	/* Unknown */

/*
 * For TRAF_VCMX:
 */
#define	TRAF_ST_VCMX_802_3_FCS	1	/* 802.3 with an FCS */
#define	TRAF_ST_VCMX_802_4_FCS	2	/* 802.4 with an FCS */
#define	TRAF_ST_VCMX_802_5_FCS	3	/* 802.5 with an FCS */
#define	TRAF_ST_VCMX_FDDI_FCS	4	/* FDDI with an FCS */
#define	TRAF_ST_VCMX_802_6_FCS	5	/* 802.6 with an FCS */
#define	TRAF_ST_VCMX_802_3	7	/* 802.3 without an FCS */
#define	TRAF_ST_VCMX_802_4	8	/* 802.4 without an FCS */
#define	TRAF_ST_VCMX_802_5	9	/* 802.5 without an FCS */
#define	TRAF_ST_VCMX_FDDI	10	/* FDDI without an FCS */
#define	TRAF_ST_VCMX_802_6	11	/* 802.6 without an FCS */
#define	TRAF_ST_VCMX_FRAGMENTS	12	/* Fragments */
#define	TRAF_ST_VCMX_BPDU	13	/* BPDU */

/*
 * For TRAF_LANE:
 */
#define	TRAF_ST_LANE_LE_CTRL	1	/* LANE: LE Ctrl */
#define	TRAF_ST_LANE_802_3	2	/* LANE: 802.3 */
#define	TRAF_ST_LANE_802_5	3	/* LANE: 802.5 */
#define	TRAF_ST_LANE_802_3_MC	4	/* LANE: 802.3 multicast */
#define	TRAF_ST_LANE_802_5_MC	5	/* LANE: 802.5 multicast */

/*
 * For TRAF_IPSILON:
 */
#define	TRAF_ST_IPSILON_FT0	1	/* Ipsilon: Flow Type 0 */
#define	TRAF_ST_IPSILON_FT1	2	/* Ipsilon: Flow Type 1 */
#define	TRAF_ST_IPSILON_FT2	3	/* Ipsilon: Flow Type 2 */

struct atm_phdr {
	guint8	aal;		/* AAL of the traffic */
	guint8	type;		/* traffic type */
	guint8	subtype;	/* traffic subtype */
	guint16	vpi;		/* virtual path identifier */
	guint16	vci;		/* virtual circuit identifier */
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

/* Packet "pseudo-header" for point-to-point links with direction flags. */
struct p2p_phdr {
	gboolean	sent; /* TRUE=sent, FALSE=received */
};

/* Packet "pseudo-header" information for 802.11 with radio information. */
struct ieee_802_11_phdr {
	guint8	channel;	/* Channel number */
	guint8	data_rate;	/* in .5 Mb/s units */
	guint8	signal_level;	/* percentage */
};

/* Packet "pseudo-header" for the output from CoSine L2 debug output. */

/* XXX */
#define COSINE_MAX_IF_NAME_LEN	128

#define COSINE_ENCAP_TEST	1
#define COSINE_ENCAP_PPoATM	2
#define COSINE_ENCAP_PPoFR	3
#define COSINE_ENCAP_ATM	4
#define COSINE_ENCAP_FR		5
#define COSINE_ENCAP_HDLC	6
#define COSINE_ENCAP_PPP	7
#define COSINE_ENCAP_ETH	8
#define COSINE_ENCAP_UNKNOWN	99

#define COSINE_DIR_TX 1
#define COSINE_DIR_RX 2

/* XXX */
struct cosine_phdr {
	guint8 encap;		/* COSINE_ENCAP_* as defined above */
	guint8 direction;	/* COSINE_DIR_*, as defined above */
	char if_name[COSINE_MAX_IF_NAME_LEN];
	guint16 pro;		/*   */
	guint16 off;		/*   */
	guint16 pri;		/*   */
	guint16 rm;		/*   */
	guint16 err;		/*   */
	guint16 code1;		/*   */
	guint16 code2;		/*   */
};

union wtap_pseudo_header {
	struct x25_phdr		x25;
	struct atm_phdr		atm;
	struct ascend_phdr	ascend;
	struct p2p_phdr		p2p;
	struct ieee_802_11_phdr	ieee_802_11;
	struct cosine_phdr	cosine;
};

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
	int pkt_encap;
};

typedef void (*wtap_handler)(guchar*, const struct wtap_pkthdr*,
		long, union wtap_pseudo_header *pseudo_header, const guchar *);

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
gboolean wtap_loop(wtap *wth, int, wtap_handler, guchar*, int *err);

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
gboolean wtap_seek_read (wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len, int *err);
gboolean wtap_def_seek_read (wtap *wth, long seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len, int *err);

gboolean wtap_dump_can_open(int filetype);
gboolean wtap_dump_can_write_encap(int filetype, int encap);
wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
	int snaplen, int *err);
wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
	int *err);
gboolean wtap_dump(wtap_dumper *, const struct wtap_pkthdr *,
	const union wtap_pseudo_header *pseudo_header, const guchar *, int *err);
FILE* wtap_dump_file(wtap_dumper *);
gboolean wtap_dump_close(wtap_dumper *, int *);
long wtap_get_bytes_dumped(wtap_dumper *);
void wtap_set_bytes_dumped(wtap_dumper *wdh, long bytes_dumped);

/*
 * Wiretap error codes.
 */
#define	WTAP_ERR_NOT_REGULAR_FILE		-1
	/* The file being opened for reading isn't a plain file (or pipe) */
#define	WTAP_ERR_RANDOM_OPEN_PIPE		-2
	/* The file is being opened for random access and it's a pipe */
#define	WTAP_ERR_FILE_UNKNOWN_FORMAT		-3
	/* The file being opened is not a capture file in a known format */
#define	WTAP_ERR_UNSUPPORTED			-4
	/* Supported file type, but there's something in the file we
	   can't support */
#define	WTAP_ERR_CANT_WRITE_TO_PIPE		-5
	/* Wiretap can't save to a pipe in the specified format */
#define	WTAP_ERR_CANT_OPEN			-6
	/* The file couldn't be opened, reason unknown */
#define	WTAP_ERR_UNSUPPORTED_FILE_TYPE		-7
	/* Wiretap can't save files in the specified format */
#define	WTAP_ERR_UNSUPPORTED_ENCAP		-8
	/* Wiretap can't read or save files in the specified format with the
	   specified encapsulation */
#define	WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED	-9
	/* The specified format doesn't support per-packet encapsulations */
#define	WTAP_ERR_CANT_CLOSE			-10
	/* The file couldn't be closed, reason unknown */
#define	WTAP_ERR_CANT_READ			-11
	/* An attempt to read failed, reason unknown */
#define	WTAP_ERR_SHORT_READ			-12
	/* An attempt to read read less data than it should have */
#define	WTAP_ERR_BAD_RECORD			-13
	/* We read an invalid record */
#define	WTAP_ERR_SHORT_WRITE			-14
	/* An attempt to write wrote less data than it should have */
#define	WTAP_ERR_UNC_TRUNCATED			-15
	/* Sniffer compressed data was oddly truncated */
#define	WTAP_ERR_UNC_OVERFLOW			-16
	/* Uncompressing Sniffer data would overflow buffer */
#define	WTAP_ERR_UNC_BAD_OFFSET			-17
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
