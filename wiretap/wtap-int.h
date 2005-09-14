/* wtap-int.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __WTAP_INT_H__
#define __WTAP_INT_H__

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <glib.h>
#include <stdio.h>
#include <time.h>

#ifdef HAVE_LIBZ
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <zlib.h>
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
	guint	maj_vers;
	guint	min_vers;
	double	timeunit;
	time_t	start;
	gboolean is_atm;
	ngsniffer_comp_stream_t seq;	/* sequential access */
	ngsniffer_comp_stream_t rand;	/* random access */
	GList	*first_blob;		/* list element for first blob */
	GList	*last_blob;		/* list element for last blob */
	GList	*current_blob;		/* list element for current blob */
} ngsniffer_t;

typedef struct {
	gboolean byte_swapped;
} i4btrace_t;

typedef struct {
	gboolean is_hpux_11;
} nettl_t;

typedef struct {
	time_t	start;
} lanalyzer_t;

typedef enum {
	NOT_SWAPPED,
	SWAPPED,
	MAYBE_SWAPPED
} swapped_type_t;

typedef struct {
	gboolean byte_swapped;
	swapped_type_t lengths_swapped;
	guint16	version_major;
	guint16	version_minor;
} libpcap_t;

typedef struct {
	time_t	start_secs;
	guint32	start_usecs;
	guint8	version_major;
	guint32 *frame_table;
	guint32	frame_table_size;
	guint	current_frame;
} netmon_t;

typedef struct {
	time_t		start_time;
	double		timeunit;
	double		start_timestamp;
	gboolean	wrapped;
	guint32		nframes;
	long		start_offset;
	long		end_offset;
	int		version_major;
	gboolean	fcs_valid;	/* if packets have valid FCS at the end */
	guint		isdn_type;	/* 1 = E1 PRI, 2 = T1 PRI, 3 = BRI */
} netxray_t;

typedef struct {
	time_t inittime;
	int adjusted;
	long next_packet_seek_start;
} ascend_t;

typedef struct {
	gboolean byteswapped;
} csids_t;

typedef struct {
	struct timeval reference_time;
} etherpeek_t;

typedef struct {
	gboolean	has_fcs;
} airopeek9_t;

typedef struct {
	guint32		atm_encap;
	gboolean	is_rawatm;
	gboolean	is_ppp;
} erf_t;

typedef struct _k12_t k12_t;

typedef gboolean (*subtype_read_func)(struct wtap*, int*, char**, long*);
typedef gboolean (*subtype_seek_read_func)(struct wtap*, long, union wtap_pseudo_header*,
					guint8*, int, int *, char **);
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
		etherpeek_t		*etherpeek;
		airopeek9_t		*airopeek9;
		erf_t			*erf;
		k12_t			*k12;
		void			*generic;
	} capture;

	subtype_read_func	subtype_read;
	subtype_seek_read_func	subtype_seek_read;
	void			(*subtype_sequential_close)(struct wtap*);
	void			(*subtype_close)(struct wtap*);
	int			file_encap;	/* per-file, for those
						   file formats that have
						   per-file encapsulation
						   types */
	int			tsprecision;	/* timestamp precision of the lower 32bits
							 * e.g. WTAP_FILE_TSPREC_USEC */
};

struct wtap_dumper;

typedef gboolean (*subtype_write_func)(struct wtap_dumper*,
		const struct wtap_pkthdr*, const union wtap_pseudo_header*,
		const guchar*, int*);
typedef gboolean (*subtype_close_func)(struct wtap_dumper*, int*);

typedef struct {
	gboolean first_frame;
	time_t start;
} ngsniffer_dump_t;

typedef struct {
	gboolean first_frame;
	struct wtap_nstime start;
	guint32	nframes;
} netxray_dump_t;

typedef struct {
	gboolean got_first_record_time;
	struct wtap_nstime first_record_time;
	guint32	frame_table_offset;
	guint32	*frame_table;
	guint	frame_table_index;
	guint	frame_table_size;
} netmon_dump_t;

typedef struct {
	guint32	nframes;
} _5views_dump_t;

typedef struct {
	guint64 packet_count;
	guint8  network_type;
} niobserver_dump_t;

typedef struct {
	guint32 file_len;
	guint32 num_of_records;
	guint32 file_offset;
} k12_dump_t;


struct wtap_dumper {
	FILE*			fh;
	int			file_type;
	int			snaplen;
	int			encap;
	gboolean	compressed;
	long			bytes_dumped;

	union {
		void			*opaque;
		ngsniffer_dump_t	*ngsniffer;
		netmon_dump_t		*netmon;
		netxray_dump_t		*netxray;
		_5views_dump_t		*_5views;
		niobserver_dump_t	*niobserver;
		k12_dump_t		*k12;
	} dump;

	subtype_write_func	subtype_write;
	subtype_close_func	subtype_close;

	int			tsprecision;	/* timestamp precision of the lower 32bits
							 * e.g. WTAP_FILE_TSPREC_USEC */
};

extern size_t wtap_dump_file_write(wtap_dumper *wdh, const void *buf, unsigned bufsize);
extern int wtap_dump_file_ferror(wtap_dumper *wdh);

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
#define htoles(s) GUINT16_TO_LE(s)
#define htolel(l) GUINT32_TO_LE(l)
#define htolell(ll) GUINT64_TO_LE(ll)

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 * We also provide pntohll and phtolell, which extract 64-bit integral
 * quantities.
 */

#ifndef pntohs
#define pntohs(p)  ((guint16)                       \
                    ((guint16)*((const guint8 *)(p)+0)<<8|  \
                     (guint16)*((const guint8 *)(p)+1)<<0))
#endif

#ifndef pntoh24
#define pntoh24(p)  ((guint32)*((const guint8 *)(p)+0)<<16| \
                     (guint32)*((const guint8 *)(p)+1)<<8|  \
                     (guint32)*((const guint8 *)(p)+2)<<0)
#endif

#ifndef pntohl
#define pntohl(p)  ((guint32)*((const guint8 *)(p)+0)<<24|  \
                    (guint32)*((const guint8 *)(p)+1)<<16|  \
                    (guint32)*((const guint8 *)(p)+2)<<8|   \
                    (guint32)*((const guint8 *)(p)+3)<<0)
#endif

#ifndef pntohll
#define pntohll(p)  ((guint64)*((const guint8 *)(p)+0)<<56|  \
                     (guint64)*((const guint8 *)(p)+1)<<48|  \
                     (guint64)*((const guint8 *)(p)+2)<<40|  \
                     (guint64)*((const guint8 *)(p)+3)<<32|  \
                     (guint64)*((const guint8 *)(p)+4)<<24|  \
                     (guint64)*((const guint8 *)(p)+5)<<16|  \
                     (guint64)*((const guint8 *)(p)+6)<<8|   \
                     (guint64)*((const guint8 *)(p)+7)<<0)
#endif


#ifndef phtons
#define phtons(p)  ((guint16)                       \
                    ((guint16)*((const guint8 *)(p)+0)<<8|  \
                     (guint16)*((const guint8 *)(p)+1)<<0))
#endif

#ifndef phtonl
#define phtonl(p)  ((guint32)*((const guint8 *)(p)+0)<<24|  \
                    (guint32)*((const guint8 *)(p)+1)<<16|  \
                    (guint32)*((const guint8 *)(p)+2)<<8|   \
                    (guint32)*((const guint8 *)(p)+3)<<0)
#endif

#ifndef pletohs
#define pletohs(p) ((guint16)                       \
                    ((guint16)*((const guint8 *)(p)+1)<<8|  \
                     (guint16)*((const guint8 *)(p)+0)<<0))
#endif

#ifndef pletoh24
#define pletoh24(p) ((guint32)*((const guint8 *)(p)+2)<<16|  \
                     (guint32)*((const guint8 *)(p)+1)<<8|  \
                     (guint32)*((const guint8 *)(p)+0)<<0)
#endif


#ifndef pletohl
#define pletohl(p) ((guint32)*((const guint8 *)(p)+3)<<24|  \
                    (guint32)*((const guint8 *)(p)+2)<<16|  \
                    (guint32)*((const guint8 *)(p)+1)<<8|   \
                    (guint32)*((const guint8 *)(p)+0)<<0)
#endif


#ifndef pletohll
#define pletohll(p) ((guint64)*((const guint8 *)(p)+7)<<56|  \
                     (guint64)*((const guint8 *)(p)+6)<<48|  \
                     (guint64)*((const guint8 *)(p)+5)<<40|  \
                     (guint64)*((const guint8 *)(p)+4)<<32|  \
                     (guint64)*((const guint8 *)(p)+3)<<24|  \
                     (guint64)*((const guint8 *)(p)+2)<<16|  \
                     (guint64)*((const guint8 *)(p)+1)<<8|   \
                     (guint64)*((const guint8 *)(p)+0)<<0)
#endif

#define wtap_file_read_unknown_bytes(target, num_bytes, fh, err) \
	G_STMT_START \
	{ \
		int _bytes_read; \
		_bytes_read = file_read((target), 1, (num_bytes), (fh)); \
		if (_bytes_read != (int) (num_bytes)) { \
			*(err) = file_error((fh)); \
			return FALSE; \
		} \
	} \
	G_STMT_END

#define wtap_file_read_expected_bytes(target, num_bytes, fh, err) \
	G_STMT_START \
	{ \
		int _bytes_read; \
		_bytes_read = file_read((target), 1, (num_bytes), (fh)); \
		if (_bytes_read != (int) (num_bytes)) { \
			*(err) = file_error((fh)); \
			if (*(err) == 0 && _bytes_read > 0) { \
				*(err) = WTAP_ERR_SHORT_READ; \
			} \
			return FALSE; \
		} \
	} \
	G_STMT_END

/* glib doesn't have g_ptr_array_len of all things!*/
#ifndef g_ptr_array_len
#define g_ptr_array_len(a)      ((a)->len)
#endif

#endif /* __WTAP_INT_H__ */
