/* wtap.h
 *
 * $Id: wtap.h,v 1.42 1999/10/05 07:06:08 guy Exp $
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

#ifndef __WTAP_H__
#define __WTAP_H__

/* Encapsulation types. Choose names that truly reflect
 * what is contained in the packet trace file.
 *
 * WTAP_ENCAP_PER_PACKET is a value passed to "wtap_dump_open()" or
 * "wtap_dump_fd_open()" to indicate that there is no single encapsulation
 * type for all packets in the file; this may cause those routines to
 * fail if the capture file format being written can't support that.
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
 * ATM on Linux code from <http://lrcwww.epfl.ch/linux-atm/>;
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
#define WTAP_ENCAP_TR				2
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
#define WTAP_ENCAP_ASCEND				14

/* last WTAP_ENCAP_ value + 1 */
#define WTAP_NUM_ENCAP_TYPES			15

/* File types that can be read by wiretap.
   We may eventually support writing some or all of these file types,
   too, so we distinguish between different versions of them. */
#define WTAP_FILE_UNKNOWN			0
#define WTAP_FILE_WTAP				1
#define WTAP_FILE_PCAP				2
#define WTAP_FILE_LANALYZER			3
#define WTAP_FILE_NGSNIFFER			4
#define WTAP_FILE_SNOOP				6
#define WTAP_FILE_IPTRACE			7
#define WTAP_FILE_NETMON_1_x			8
#define WTAP_FILE_NETMON_2_x			9
#define WTAP_FILE_NETXRAY_1_0			10
#define WTAP_FILE_NETXRAY_1_1			11
#define WTAP_FILE_NETXRAY_2_001			12
#define WTAP_FILE_RADCOM			13
#define WTAP_FILE_ASCEND			14

/*
 * Maximum packet size we'll support.
 */
#define	WTAP_MAX_PACKET_SIZE			65535

#include <sys/types.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <glib.h>
#include <stdio.h>

#ifdef HAVE_LIBZ
#include "zlib.h"
#define FILE_T	gzFile
#else /* No zLib */
#define FILE_T	FILE *
#endif /* HAVE_LIBZ */

typedef struct {
	double	timeunit;
	time_t	start;
	int	is_atm;
} ngsniffer_t;

typedef struct {
	time_t	start;
} radcom_t;

typedef struct {
	time_t	start;
} lanalyzer_t;

typedef struct {
	int	byte_swapped;
	guint16	version_major;
	guint16	version_minor;
} libpcap_t;

typedef struct {
	time_t	start_secs;
	guint32	start_usecs;
	guint8	version_major;
	int	end_offset;
} netmon_t;

typedef struct {
	time_t	start_time;
	double	timeunit;
	double	start_timestamp;
	int	wrapped;
	int	end_offset;
	int	version_major;
} netxray_t;

typedef struct {
	time_t inittime;
	int adjusted;
	int seek_add;
} ascend_t;

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

union pseudo_header {
	struct x25_phdr x25;
	struct ngsniffer_atm_phdr ngsniffer_atm;
	struct ascend_phdr ascend;
};

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
	int pkt_encap;
	union pseudo_header pseudo_header;
};

typedef void (*wtap_handler)(u_char*, const struct wtap_pkthdr*,
		int, const u_char *);

struct wtap;
struct bpf_instruction;
struct Buffer;

typedef int (*subtype_read_func)(struct wtap*, int*);
typedef struct wtap {
	FILE_T			fh;
        int                     fd;           /* File descriptor for cap file */
	int			file_type;
	int			snapshot_length;
	struct Buffer		*frame_buffer;
	struct wtap_pkthdr	phdr;

	long			data_offset;

	union {
		libpcap_t		*pcap;
		lanalyzer_t		*lanalyzer;
		ngsniffer_t		*ngsniffer;
		radcom_t		*radcom;
		netmon_t		*netmon;
		netxray_t		*netxray;
		ascend_t		*ascend;
	} capture;

	subtype_read_func	subtype_read;
	int			file_encap;	/* per-file, for those
						   file formats that have
						   per-file encapsulation
						   types */
} wtap;

struct wtap_dumper;

typedef int (*subtype_write_func)(struct wtap_dumper*,
		const struct wtap_pkthdr*, const u_char*, int*);
typedef int (*subtype_close_func)(struct wtap_dumper*, int*);
typedef struct wtap_dumper {
	FILE*			fh;
	int			file_type;
	int			snaplen;
	int			encap;

	subtype_write_func	subtype_write;
	subtype_close_func	subtype_close;
} wtap_dumper;

/*
 * On failure, "wtap_open_offline()" returns NULL, and puts into the
 * "int" pointed to by its second argument:
 *
 * a positive "errno" value if the capture file can't be opened;
 *
 * a negative number, indicating the type of error, on other failures.
 */
wtap* wtap_open_offline(const char *filename, int *err);
int wtap_loop(wtap *wth, int, wtap_handler, u_char*, int*);

FILE* wtap_file(wtap *wth);
int wtap_fd(wtap *wth);
int wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
const char *wtap_file_type_string(wtap *wth);
const char *wtap_strerror(int err);
void wtap_close(wtap *wth);
int wtap_seek_read (int encaps, FILE *fh, int seek_off, guint8 *pd, int len);
int wtap_def_seek_read (FILE *fh, int seek_off, guint8 *pd, int len);

wtap_dumper* wtap_dump_open(const char *filename, int filetype, int encap,
	int snaplen, int *err);
wtap_dumper* wtap_dump_fdopen(int fd, int filetype, int encap, int snaplen,
	int *err);
int wtap_dump(wtap_dumper *, const struct wtap_pkthdr *, const u_char *,
	int *err);
FILE* wtap_dump_file(wtap_dumper *);
int wtap_dump_close(wtap_dumper *, int *);

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
	/* Wiretap can't save files in the specified format with the
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

/* Errors from zlib; zlib error Z_xxx turns into Wiretap error
   WTAP_ERR_ZLIB + Z_xxx.

   WTAP_ERR_ZLIB_MIN and WTAP_ERR_ZLIB_MAX bound the range of zlib
   errors; we leave room for 100 positive and 100 negative error
   codes. */

#define	WTAP_ERR_ZLIB				-200
#define	WTAP_ERR_ZLIB_MAX			-100
#define	WTAP_ERR_ZLIB_MIN			-300

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 */

#ifndef pntohs
#define pntohs(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))
#endif

#ifndef pntohl
#define pntohl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)
#endif

#ifndef phtons
#define phtons(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))
#endif

#ifndef phtonl
#define phtonl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)
#endif

#ifndef pletohs
#define pletohs(p) ((guint16)                       \
                    ((guint16)*((guint8 *)p+1)<<8|  \
                     (guint16)*((guint8 *)p+0)<<0))
#endif

#ifndef plethol
#define pletohl(p) ((guint32)*((guint8 *)p+3)<<24|  \
                    (guint32)*((guint8 *)p+2)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|   \
                    (guint32)*((guint8 *)p+0)<<0)
#endif

#endif /* __WTAP_H__ */
