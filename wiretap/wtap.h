/* wtap.h
 *
 * $Id: wtap.h,v 1.28 1999/08/20 04:49:18 gram Exp $
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
 * WTAP_ENCAP_LINUX_ATM_CLIP is the encapsulation you get with the
 * ATM on Linux code from <http://lrcwww.epfl.ch/linux-atm/>;
 * that code adds a DLT_ATM_CLIP DLT_ code of 19, and that
 * encapsulation isn't the same as the DLT_ATM_RFC1483 encapsulation
 * presumably used on some BSD systems, which we turn into
 * WTAP_ENCAP_ATM_RFC1483.
 *
 * WTAP_ENCAP_PER_PACKET is a value passed to "wtap_dump_open()" or
 * "wtap_dump_fdopen()" to indicate that there is no single encapsulation
 * type for all packets in the file; this may cause those routines to
 * fail if the capture file format being written can't support that.
 *
 * WTAP_ENCAP_UNKNOWN is returned by "wtap_pcap_encap_to_wtap_encap()"
 * if it's handed an unknown encapsulation. */
#define WTAP_ENCAP_UNKNOWN			-2
#define WTAP_ENCAP_PER_PACKET			-1
#define WTAP_ENCAP_NONE				0
#define WTAP_ENCAP_ETHERNET			1
#define WTAP_ENCAP_TR				2
#define WTAP_ENCAP_SLIP				3
#define WTAP_ENCAP_PPP				4
#define WTAP_ENCAP_FDDI				5
#define WTAP_ENCAP_RAW_IP			6
#define WTAP_ENCAP_ARCNET			7
#define WTAP_ENCAP_ATM_RFC1483			8
#define WTAP_ENCAP_LINUX_ATM_CLIP		9
#define WTAP_ENCAP_LAPB				10

/* last WTAP_ENCAP_ value + 1 */
#define WTAP_NUM_ENCAP_TYPES			11

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

#include <sys/types.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <glib.h>
#include <stdio.h>

typedef struct {
	double	timeunit;
	time_t	start;
	guint16	pkt_len;
	guint16	size;
	guint16	true_size;
	double	t;
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

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
	int pkt_encap;
	guint8	flags; /* ENCAP_LAPB : 1st bit means From DCE */
};

typedef void (*wtap_handler)(u_char*, const struct wtap_pkthdr*,
		int, const u_char *);

struct wtap;
struct bpf_instruction;
struct Buffer;

typedef int (*subtype_read_func)(struct wtap*, int*);
typedef struct wtap {
	FILE*			fh;
	int			file_type;
	int			snapshot_length;
	struct Buffer		*frame_buffer;
	struct wtap_pkthdr	phdr;

	union {
		libpcap_t		*pcap;
		lanalyzer_t		*lanalyzer;
		ngsniffer_t		*ngsniffer;
		radcom_t		*radcom;
		netmon_t		*netmon;
		netxray_t		*netxray;
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
int wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
const char *wtap_file_type_string(wtap *wth);
void wtap_close(wtap *wth);

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
#define	WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED	-6
	/* The specified format doesn't support per-packet encapsulations */
#define	WTAP_ERR_CANT_CLOSE			-7
	/* The file couldn't be closed, reason unknown */
#define	WTAP_ERR_CANT_READ			-8
	/* An attempt to read failed, reason unknown */
#define	WTAP_ERR_SHORT_READ			-9
	/* An attempt to read read less data than it should have */
#define	WTAP_ERR_BAD_RECORD			-10
	/* We read an invalid record */
#define	WTAP_ERR_SHORT_WRITE			-11
	/* An attempt to write wrote less data than it should have */

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
