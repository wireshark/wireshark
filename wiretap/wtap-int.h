/* wtap-int.h
 *
 * $Id: wtap-int.h,v 1.7 2000/08/25 21:25:43 gram Exp $
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

#ifndef __WTAP_INT_H__
#define __WTAP_INT_H__

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
#include <time.h>

#ifdef HAVE_LIBZ
#include "zlib.h"
#define FILE_T	gzFile
#else /* No zLib */
#define FILE_T	FILE *
#endif /* HAVE_LIBZ */

#include "wtap.h"

/* Information for a compressed Sniffer data stream. */
typedef struct {
	unsigned char *buf;	/* buffer into which we uncompress data */
	size_t	nbytes;		/* number of bytes of data in that buffer */
	int	nextout;	/* offset in that buffer of stream's current position */
	long	comp_offset;	/* current offset in compressed data stream */
	long	uncomp_offset;	/* current offset in uncompressed data stream */
} ngsniffer_comp_stream_t;

typedef struct {
	double	timeunit;
	time_t	start;
	int	is_atm;
	ngsniffer_comp_stream_t seq;	/* sequential access */
	ngsniffer_comp_stream_t rand;	/* random access */
	GList	*first_blob;		/* list element for first blob */
	GList	*last_blob;		/* list element for last blob */
	GList	*current_blob;		/* list element for current blob */
} ngsniffer_t;

typedef struct {
	gboolean byte_swapped;
	int bchannel_prot[2];	/* For the V.120 heuristic */
} i4btrace_t;

typedef struct {
	gboolean is_hpux_11;
} nettl_t;

typedef struct {
	time_t	start;
} lanalyzer_t;

typedef struct {
	gboolean byte_swapped;
	guint16	version_major;
	guint16	version_minor;
} libpcap_t;

typedef struct {
	time_t	start_secs;
	guint32	start_usecs;
	guint8	version_major;
	guint32 *frame_table;
	int	frame_table_size;
	int	current_frame;
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

typedef struct {
	gboolean byteswapped;
} csids_t;

typedef int (*subtype_read_func)(struct wtap*, int*);
typedef int (*subtype_seek_read_func)(struct wtap*, int, union wtap_pseudo_header*,
					guint8*, int);
struct wtap {
	FILE_T			fh;
        int                     fd;           /* File descriptor for cap file */
	FILE_T			random_fh;    /* Secondary FILE_T for random access */
	int			file_type;
	int			snapshot_length;
	struct Buffer		*frame_buffer;
	struct wtap_pkthdr	phdr;
	union wtap_pseudo_header pseudo_header;

	long			data_offset;

	union {
		libpcap_t		*pcap;
		lanalyzer_t		*lanalyzer;
		ngsniffer_t		*ngsniffer;
		i4btrace_t		*i4btrace;
		nettl_t			*nettl;
		netmon_t		*netmon;
		netxray_t		*netxray;
		ascend_t		*ascend;
		csids_t			*csids;
	} capture;

	subtype_read_func	subtype_read;
	subtype_seek_read_func	subtype_seek_read;
	void			(*subtype_sequential_close)(struct wtap*);
	void			(*subtype_close)(struct wtap*);
	int			file_encap;	/* per-file, for those
						   file formats that have
						   per-file encapsulation
						   types */
};

struct wtap_dumper;

typedef gboolean (*subtype_write_func)(struct wtap_dumper*,
		const struct wtap_pkthdr*, const union wtap_pseudo_header*,
		const u_char*, int*);
typedef gboolean (*subtype_close_func)(struct wtap_dumper*, int*);

typedef struct {
	gboolean first_frame;
	time_t start;
} ngsniffer_dump_t;

typedef struct {
	gboolean first_frame;
	struct timeval start;
	guint32	nframes;
} netxray_dump_t;

typedef struct {
	gboolean got_first_record_time;
	struct timeval first_record_time;
	guint32	frame_table_offset;
	guint32	*frame_table;
	int	frame_table_index;
	int	frame_table_size;
} netmon_dump_t;

struct wtap_dumper {
	FILE*			fh;
	int			file_type;
	int			snaplen;
	int			encap;

	union {
		void			*opaque;
		ngsniffer_dump_t	*ngsniffer;
		netmon_dump_t		*netmon;
		netxray_dump_t		*netxray;
	} dump;

	subtype_write_func	subtype_write;
	subtype_close_func	subtype_close;
};


/* Macros to byte-swap 32-bit and 16-bit quantities. */
#define	BSWAP32(x) \
	((((x)&0xFF000000)>>24) | \
	 (((x)&0x00FF0000)>>8) | \
	 (((x)&0x0000FF00)<<8) | \
	 (((x)&0x000000FF)<<24))
#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))

/* Turn host-byte-order values into little-endian values. */
#ifdef WORDS_BIGENDIAN
#define htoles(s) ((guint16)                       \
                    ((guint16)((s) & 0x00FF)<<8|  \
                     (guint16)((s) & 0xFF00)>>8))

#define htolel(l) ((guint32)((l) & 0x000000FF)<<24|  \
                   (guint32)((l) & 0x0000FF00)<<8|  \
                   (guint32)((l) & 0x00FF0000)>>8|   \
                   (guint32)((l) & 0xFF000000)>>24)
#else
#define htoles(s)	(s)
#define htolel(l)	(l)
#endif

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

#ifndef pletohl
#define pletohl(p) ((guint32)*((guint8 *)p+3)<<24|  \
                    (guint32)*((guint8 *)p+2)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|   \
                    (guint32)*((guint8 *)p+0)<<0)
#endif

#endif /* __WTAP_INT_H__ */
