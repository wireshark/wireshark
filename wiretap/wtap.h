/* wtap.h
 *
 * $Id: wtap.h,v 1.8 1998/12/17 06:39:13 gram Exp $
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

/* File types that can be read by wiretap */
#define WTAP_FILE_UNKNOWN			0
#define WTAP_FILE_WTAP				1
#define WTAP_FILE_PCAP				2
#define WTAP_FILE_LANALYZER			3
#define WTAP_FILE_NGSNIFFER			4
#define WTAP_FILE_SNOOP				6
#define WTAP_FILE_IPTRACE			7

#include <sys/types.h>
#include <sys/time.h>
#include <glib.h>
#include <stdio.h>
#include <buffer.h>

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

struct wtap_pkthdr {
	struct timeval ts;
	guint32	caplen;
	guint32 len;
};

typedef void (*wtap_handler)(u_char*, const struct wtap_pkthdr*,
		int, const u_char *);

struct wtap;
typedef int (*subtype_func)(struct wtap*);
typedef struct wtap {
	FILE*			fh;
	int				file_type;
	int		snapshot_length;
	unsigned long	frame_number;
	unsigned long	file_byte_offset;
	Buffer			frame_buffer;
	struct wtap_pkthdr	phdr;

	union {
		libpcap_t		*pcap;
		lanalyzer_t		*lanalyzer;
		ngsniffer_t		*ngsniffer;
	} capture;

	subtype_func	subtype_read;	
	int				encapsulation;
} wtap;


wtap* wtap_open_offline(char *filename, int filetype);
void wtap_loop(wtap *wth, int, wtap_handler, u_char*);

FILE* wtap_file(wtap *wth);
int wtap_snapshot_length(wtap *wth); /* per file */
int wtap_file_type(wtap *wth);
int wtap_encapsulation(wtap *wth); /* per file */
void wtap_close(wtap *wth);


/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 */

#define pntohs(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))

#define pntohl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)

#define pletohs(p) ((guint16)                       \
                    ((guint16)*((guint8 *)p+1)<<8|  \
                     (guint16)*((guint8 *)p+0)<<0))

#define pletohl(p) ((guint32)*((guint8 *)p+3)<<24|  \
                    (guint32)*((guint8 *)p+2)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|   \
                    (guint32)*((guint8 *)p+0)<<0)


