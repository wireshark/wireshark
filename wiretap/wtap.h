/* wtap.h
 *
 * $Id: wtap.h,v 1.15 1999/03/01 22:59:47 guy Exp $
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
 * what is contained in the packet trace file. */
#define WTAP_ENCAP_NONE				0
#define WTAP_ENCAP_ETHERNET			1
#define WTAP_ENCAP_TR				2
#define WTAP_ENCAP_SLIP				3
#define WTAP_ENCAP_PPP				4
#define WTAP_ENCAP_FDDI				5
#define WTAP_ENCAP_RAW_IP			6
#define WTAP_ENCAP_ARCNET			7
#define WTAP_ENCAP_ATM_RFC1483			8

/* last WTAP_ENCAP_ value + 1 */
#define WTAP_NUM_ENCAP_TYPES			9

/* File types that can be read by wiretap */
#define WTAP_FILE_UNKNOWN			0
#define WTAP_FILE_WTAP				1
#define WTAP_FILE_PCAP				2
#define WTAP_FILE_LANALYZER			3
#define WTAP_FILE_NGSNIFFER			4
#define WTAP_FILE_SNOOP				6
#define WTAP_FILE_IPTRACE			7
#define WTAP_FILE_NETMON			8
#define WTAP_FILE_NETXRAY			9

/* Filter types that wiretap can create. An 'offline' filter is really
 * a BPF filter, but it is treated specially because wiretap might not know
 * in advance the datalink type(s) needed.
 */
#define WTAP_FILTER_NONE			0
#define WTAP_FILTER_OFFLINE			1
#define WTAP_FILTER_BPF				2

#include <sys/types.h>
#include <sys/time.h>
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
	guint16	pkt_len;
	guint32	totpktt;
	time_t	start;
} lanalyzer_t;

typedef struct {
	int	byte_swapped;
	guint16	version_major;
	guint16	version_minor;
} libpcap_t;

typedef struct {
	time_t	start_secs;
	guint32	start_msecs;
	int	end_offset;
} netmon_t;

typedef struct {
	time_t	start_time;
	double	timeunit;
	double	start_timestamp;
	int	wrapped;
	int	end_offset;
} netxray_t;

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
	int pkt_encap;
};

typedef void (*wtap_handler)(u_char*, const struct wtap_pkthdr*,
		int, const u_char *);

struct wtap;
struct bpf_instruction;
struct Buffer;

typedef int (*subtype_func)(struct wtap*);
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
		netmon_t		*netmon;
		netxray_t		*netxray;
	} capture;

	subtype_func		subtype_read;
	int			file_encap;	/* per-file, for those
						   file formats that have
						   per-file encapsulation
						   types */
	union {
		struct bpf_instruction	*bpf;
		struct bpf_instruction	**offline;
	} filter;

	gchar			*filter_text;
	int			filter_type;
	int			filter_length; /* length in bytes or records,
						depending upon filter_type */

	int			*offline_filter_lengths;
} wtap;


wtap* wtap_open_offline(char *filename);
void wtap_loop(wtap *wth, int, wtap_handler, u_char*);
int wtap_offline_filter(wtap *wth, char *filter);

FILE* wtap_file(wtap *wth);
int wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
void wtap_close(wtap *wth);


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
