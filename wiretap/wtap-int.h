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

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <wsutil/file_util.h>

#include "wtap.h"

int wtap_fstat(wtap *wth, ws_statb64 *statb, int *err);

typedef gboolean (*subtype_read_func)(struct wtap*, int*, char**, gint64*);
typedef gboolean (*subtype_seek_read_func)(struct wtap*, gint64, union wtap_pseudo_header*,
					guint8*, int, int *, char **);
/**
 * Struct holding data of the currently read file.
 */
struct wtap {
	FILE_T						fh;
	FILE_T						random_fh;				/**< Secondary FILE_T for random access */
	int							file_type;
	guint						snapshot_length;
	struct Buffer				*frame_buffer;
	struct wtap_pkthdr			phdr;
	struct wtapng_section_s		shb_hdr;
	guint						number_of_interfaces;   /**< The number of interfaces a capture was made on, number of IDB:s in a pcapng file or equivalent(?)*/
	GArray						*interface_data;		/**< An array holding the interface data from pcapng IDB:s or equivalent(?)*/
	union wtap_pseudo_header	pseudo_header;

	gint64						data_offset;

	void						*priv;

	subtype_read_func			subtype_read;
	subtype_seek_read_func		subtype_seek_read;
	void						(*subtype_sequential_close)(struct wtap*);
	void						(*subtype_close)(struct wtap*);
	int							file_encap;	/* per-file, for those
											 * file formats that have
											 * per-file encapsulation
											 * types
											 */
	int							tsprecision;	/* timestamp precision of the lower 32bits
												 * e.g. WTAP_FILE_TSPREC_USEC
												 */
	wtap_new_ipv4_callback_t	add_new_ipv4;
	wtap_new_ipv6_callback_t	add_new_ipv6;
	GPtrArray					*fast_seek;
};

struct wtap_dumper;

/*
 * This could either be a FILE * or a gzFile.
 */
typedef void *WFILE_T;

typedef gboolean (*subtype_write_func)(struct wtap_dumper*,
		const struct wtap_pkthdr*, const union wtap_pseudo_header*,
		const guint8*, int*);
typedef gboolean (*subtype_close_func)(struct wtap_dumper*, int*);

struct wtap_dumper {
	WFILE_T			fh;
	int				file_type;
	int				snaplen;
	int				encap;
	gboolean		compressed;
	gint64			bytes_dumped;

	void			*priv;

	subtype_write_func	subtype_write;
	subtype_close_func	subtype_close;

	int							tsprecision;	/**< timestamp precision of the lower 32bits
												 * e.g. WTAP_FILE_TSPREC_USEC
												 */
	struct addrinfo				*addrinfo_list;
	struct wtapng_section_s		*shb_hdr;
	guint						number_of_interfaces;   /**< The number of interfaces a capture was made on, number of IDB:s in a pcapng file or equivalent(?)*/
	GArray						*interface_data;		/**< An array holding the interface data from pcapng IDB:s or equivalent(?) NULL if not present.*/
};

extern gboolean wtap_dump_file_write(wtap_dumper *wdh, const void *buf,
    size_t bufsize, int *err);
extern gint64 wtap_dump_file_seek(wtap_dumper *wdh, gint64 offset, int whence, int *err);
extern gint64 wtap_dump_file_tell(wtap_dumper *wdh);


extern gint wtap_num_file_types;

/* Macros to byte-swap 64-bit, 32-bit and 16-bit quantities. */
#define BSWAP64(x) \
	((((x)&G_GINT64_CONSTANT(0xFF00000000000000U))>>56) |	\
         (((x)&G_GINT64_CONSTANT(0x00FF000000000000U))>>40) |	\
	 (((x)&G_GINT64_CONSTANT(0x0000FF0000000000U))>>24) |	\
	 (((x)&G_GINT64_CONSTANT(0x000000FF00000000U))>>8) |	\
	 (((x)&G_GINT64_CONSTANT(0x00000000FF000000U))<<8) |	\
	 (((x)&G_GINT64_CONSTANT(0x0000000000FF0000U))<<24) |	\
	 (((x)&G_GINT64_CONSTANT(0x000000000000FF00U))<<40) |	\
	 (((x)&G_GINT64_CONSTANT(0x00000000000000FFU))<<56))
#define	BSWAP32(x) \
	((((x)&0xFF000000)>>24) | \
	 (((x)&0x00FF0000)>>8) | \
	 (((x)&0x0000FF00)<<8) | \
	 (((x)&0x000000FF)<<24))
#define	BSWAP16(x) \
	 ((((x)&0xFF00)>>8) | \
	  (((x)&0x00FF)<<8))

/* Macros to byte-swap possibly-unaligned 64-bit, 32-bit and 16-bit quantities;
 * they take a pointer to the quantity, and byte-swap it in place.
 */
#define PBSWAP64(p) \
	{			\
	guint8 tmp;		\
	tmp = (p)[7];		\
	(p)[7] = (p)[0];	\
	(p)[0] = tmp;		\
	tmp = (p)[6];		\
	(p)[6] = (p)[1];	\
	(p)[1] = tmp;		\
	tmp = (p)[5];		\
	(p)[5] = (p)[2];	\
	(p)[2] = tmp;		\
	tmp = (p)[4];		\
	(p)[4] = (p)[3];	\
	(p)[3] = tmp;		\
	}
#define PBSWAP32(p) \
	{			\
	guint8 tmp;		\
	tmp = (p)[3];		\
	(p)[3] = (p)[0];	\
	(p)[0] = tmp;		\
	tmp = (p)[2];		\
	(p)[2] = (p)[1];	\
	(p)[1] = tmp;		\
	}
#define PBSWAP16(p) \
	{			\
	guint8 tmp;		\
	tmp = (p)[1];		\
	(p)[1] = (p)[0];	\
	(p)[0] = tmp;		\
	}

/* Turn host-byte-order values into little-endian values. */
#define htoles(s) GUINT16_TO_LE(s)
#define htolel(l) GUINT32_TO_LE(l)
#define htolell(ll) GUINT64_TO_LE(ll)

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 * We also provide pntohll and pletohll, which extract 64-bit integral
 * quantities.
 *
 * These will work regardless of the byte alignment of the pointer.
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

/* Pointer routines to put items out in a particular byte order.
 * These will work regardless of the byte alignment of the pointer.
 */

#ifndef phtons
#define phtons(p, v) \
	{ 				\
	(p)[0] = (guint8)((v) >> 8);	\
	(p)[1] = (guint8)((v) >> 0);	\
	}
#endif

#ifndef phton24
#define phton24(p, v) \
	{ 				\
	(p)[0] = (guint8)((v) >> 16);	\
	(p)[1] = (guint8)((v) >> 8);	\
	(p)[2] = (guint8)((v) >> 0);	\
	}
#endif

#ifndef phtonl
#define phtonl(p, v) \
	{ 				\
	(p)[0] = (guint8)((v) >> 24);	\
	(p)[1] = (guint8)((v) >> 16);	\
	(p)[2] = (guint8)((v) >> 8);	\
	(p)[3] = (guint8)((v) >> 0);	\
	}
#endif

#ifndef phtonll
#define phtonll(p, v) \
	{ 				\
	(p)[0] = (guint8)((v) >> 56);	\
	(p)[1] = (guint8)((v) >> 48);	\
	(p)[2] = (guint8)((v) >> 40);	\
	(p)[3] = (guint8)((v) >> 32);	\
	(p)[4] = (guint8)((v) >> 24);	\
	(p)[5] = (guint8)((v) >> 16);	\
	(p)[6] = (guint8)((v) >> 8);	\
	(p)[7] = (guint8)((v) >> 0);	\
	}
#endif

#ifndef phtoles
#define phtoles(p, v) \
	{ 				\
	(p)[0] = (guint8)((v) >> 0);	\
	(p)[1] = (guint8)((v) >> 8);	\
	}
#endif

#ifndef phtolell
#define phtolell(p, v) \
	{ 				\
	(p)[0] = (guint8)((v) >> 0);	\
	(p)[1] = (guint8)((v) >> 8);	\
	(p)[2] = (guint8)((v) >> 16);	\
	(p)[3] = (guint8)((v) >> 24);	\
	(p)[4] = (guint8)((v) >> 32);	\
	(p)[5] = (guint8)((v) >> 40);	\
	(p)[6] = (guint8)((v) >> 48);	\
	(p)[7] = (guint8)((v) >> 56);	\
	}
#endif

#define wtap_file_read_unknown_bytes(target, num_bytes, fh, err, err_info) \
	G_STMT_START \
	{ \
		int _bytes_read; \
		_bytes_read = file_read((target), (num_bytes), (fh)); \
		if (_bytes_read != (int) (num_bytes)) { \
			*(err) = file_error((fh), (err_info)); \
			return FALSE; \
		} \
	} \
	G_STMT_END

#define wtap_file_read_expected_bytes(target, num_bytes, fh, err, err_info) \
	G_STMT_START \
	{ \
		int _bytes_read; \
		_bytes_read = file_read((target), (num_bytes), (fh)); \
		if (_bytes_read != (int) (num_bytes)) { \
			*(err) = file_error((fh), (err_info)); \
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

/*** get GSList of all compressed file extensions ***/
GSList *wtap_get_compressed_file_extensions(void);

#endif /* __WTAP_INT_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
