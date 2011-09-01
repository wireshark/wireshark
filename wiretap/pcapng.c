/* pcapng.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for pcap-ng file format
 * Copyright (c) 2007 by Ulf Lamping <ulf.lamping@web.de>
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

/* File format reference:
 *   http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
 * Related Wiki page:
 *   http://wiki.wireshark.org/Development/PcapNg
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Needed for addrinfo */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#if defined(_WIN32) && defined(INET6)
# include <ws2tcpip.h>
#endif

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "libpcap.h"
#include "pcap-common.h"
#include "pcap-encap.h"
#include "pcapng.h"

#if 0
#define pcapng_debug0(str) g_warning(str)
#define pcapng_debug1(str,p1) g_warning(str,p1)
#define pcapng_debug2(str,p1,p2) g_warning(str,p1,p2)
#define pcapng_debug3(str,p1,p2,p3) g_warning(str,p1,p2,p3)
#else
#define pcapng_debug0(str)
#define pcapng_debug1(str,p1)
#define pcapng_debug2(str,p1,p2)
#define pcapng_debug3(str,p1,p2,p3)
#endif

static gboolean
pcapng_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean
pcapng_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static void
pcapng_close(wtap *wth);


/* pcapng: common block header for every block type */
typedef struct pcapng_block_header_s {
	guint32 block_type;
	guint32 block_total_length;
	/* x bytes block_body */
	/* guint32 block_total_length */
} pcapng_block_header_t;

/* pcapng: section header block */
typedef struct pcapng_section_header_block_s {
	/* pcapng_block_header_t */
	guint32 magic;
	guint16 version_major;
	guint16 version_minor;
	guint64 section_length; /* might be -1 for unknown */
	/* ... Options ... */
} pcapng_section_header_block_t;

/* pcapng: interface description block */
typedef struct pcapng_interface_description_block_s {
	guint16 linktype;
	guint16 reserved;
	guint32 snaplen;
	/* ... Options ... */
} pcapng_interface_description_block_t;

/* pcapng: packet block (obsolete) */
typedef struct pcapng_packet_block_s {
	guint16 interface_id;
	guint16 drops_count;
	guint32 timestamp_high;
	guint32 timestamp_low;
	guint32 captured_len;
	guint32 packet_len;
	/* ... Packet Data ... */
	/* ... Padding ... */
	/* ... Options ... */
} pcapng_packet_block_t;

/* pcapng: enhanced packet block */
typedef struct pcapng_enhanced_packet_block_s {
	guint32 interface_id;
	guint32 timestamp_high;
	guint32 timestamp_low;
	guint32 captured_len;
	guint32 packet_len;
	/* ... Packet Data ... */
	/* ... Padding ... */
	/* ... Options ... */
} pcapng_enhanced_packet_block_t;

/* pcapng: simple packet block */
typedef struct pcapng_simple_packet_block_s {
	guint32 packet_len;
	/* ... Packet Data ... */
	/* ... Padding ... */
} pcapng_simple_packet_block_t;

/* pcapng: simple packet block */
typedef struct pcapng_name_resolution_block_s {
	guint16 record_type;
	guint16 record_len;
	/* ... Record ... */
} pcapng_name_resolution_block_t;

/* pcapng: interface statistics block */
typedef struct pcapng_interface_statistics_block_s {
	guint32 interface_id;
	guint32 timestamp_high;
	guint32 timestamp_low;
	/* ... Options ... */
} pcapng_interface_statistics_block_t;

/* pcapng: common option header for every option type */
typedef struct pcapng_option_header_s {
	guint16 option_code;
	guint16 option_length;
	/* ... x bytes Option Body ... */
    /* ... Padding ... */
} pcapng_option_header_t;

/* Block types */
#define BLOCK_TYPE_IDB 0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB  0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB 0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_NRB 0x00000004 /* Name Resolution Block */
#define BLOCK_TYPE_ISB 0x00000005 /* Interface Statistics Block */
#define BLOCK_TYPE_EPB 0x00000006 /* Enhanced Packet Block */
#define BLOCK_TYPE_SHB 0x0A0D0D0A /* Section Header Block */



/* Capture section */
typedef struct wtapng_section_s {
	/* mandatory */
	guint64				section_length;
	/* options */
	gchar				*opt_comment;	/* NULL if not available */
	gchar				*shb_hardware;	/* NULL if not available */
	gchar				*shb_os;	/* NULL if not available */
	gchar				*shb_user_appl;	/* NULL if not available */
} wtapng_section_t;

/* Interface Description */
typedef struct wtapng_if_descr_s {
	/* mandatory */
	guint16				link_type;
	guint32				snap_len;
	/* options */
	gchar				*opt_comment;	/* NULL if not available */
	gchar				*if_name;	/* NULL if not available */
	gchar				*if_description;/* NULL if not available */
	/* XXX: if_IPv4addr */
	/* XXX: if_IPv6addr */
	/* XXX: if_MACaddr */
	/* XXX: if_EUIaddr */
	guint64				if_speed;	/* 0xFFFFFFFF if unknown */
	guint8				if_tsresol;	/* default is 6 for microsecond resolution */
	gchar				*if_filter;	/* NULL if not available */
	gchar				*if_os;		/* NULL if not available */
	gint8				if_fcslen;	/* -1 if unknown or changes between packets */
	/* XXX: guint64	if_tsoffset; */
} wtapng_if_descr_t;

/* Packets */
typedef struct wtapng_packet_s {
	/* mandatory */
	guint32				ts_high;	/* seconds since 1.1.1970 */
	guint32				ts_low;		/* fraction of seconds, depends on if_tsresol */
	guint32				cap_len;        /* data length in the file */
	guint32				packet_len;     /* data length on the wire */
	guint32				interface_id;   /* identifier of the interface. */
	guint16				drops_count;    /* drops count, only valid for packet block */
							/* 0xffff if information no available */
	/* options */
	gchar				*opt_comment;	/* NULL if not available */
	guint64				drop_count;
	guint32				pack_flags;     /* XXX - 0 for now (any value for "we don't have it"?) */
	/* pack_hash */

	guint32 			pseudo_header_len;
	int				wtap_encap;
	/* XXX - put the packet data / pseudo_header here as well? */
} wtapng_packet_t;

/* Simple Packets */
typedef struct wtapng_simple_packet_s {
	/* mandatory */
	guint32				cap_len;        /* data length in the file */
	guint32				packet_len;     /* data length on the wire */
	guint32 			pseudo_header_len;
	int				wtap_encap;
	/* XXX - put the packet data / pseudo_header here as well? */
} wtapng_simple_packet_t;

/* Name Resolution */
typedef struct wtapng_name_res_s {
	/* options */
	gchar				*opt_comment;	/* NULL if not available */
	/* XXX */
} wtapng_name_res_t;

/* Interface Statistics */
typedef struct wtapng_if_stats_s {
	/* mandatory */
	guint64				interface_id;
	guint32				ts_high;
	guint32				ts_low;
	/* options */
	gchar				*opt_comment;	/* NULL if not available */
	/* XXX */
	/*guint32				isb_starttime_high;*/
	/*guint32				isb_starttime_low;*/
	/*guint32				isb_endtime_high;*/
	/*guint32				isb_endtime_low;*/
	guint64				isb_ifrecv;
	guint64				isb_ifdrop;
	/*guint64				isb_filteraccept;*/
	/*guint64				isb_osdrop;*/
	/*guint64				isb_usrdeliv;*/
} wtapng_if_stats_t;


typedef struct wtapng_block_s {
	guint32					type;		/* block_type as defined by pcapng */
	union {
		wtapng_section_t	section;
		wtapng_if_descr_t	if_descr;
		wtapng_packet_t		packet;
		wtapng_simple_packet_t	simple_packet;
		wtapng_name_res_t	name_res;
		wtapng_if_stats_t	if_stats;
	} data;

	/*
	 * XXX - currently don't know how to handle these!
	 *
	 * For one thing, when we're reading a block, they must be
	 * writable, i.e. not const, so that we can read into them,
	 * but, when we're writing a block, they can be const, and,
	 * in fact, they sometimes point to const values.
	 */
	const union wtap_pseudo_header *pseudo_header;
	struct wtap_pkthdr *packet_header;
	const guint8 *frame_buffer;
	int *file_encap;
} wtapng_block_t;

typedef struct interface_data_s {
	int wtap_encap;
	guint64 time_units_per_second;
} interface_data_t;


typedef struct {
	gboolean byte_swapped;
	guint16 version_major;
	guint16 version_minor;
	gint8 if_fcslen;
	GArray *interface_data;
	guint number_of_interfaces;
	wtap_new_ipv4_callback_t add_new_ipv4;
	wtap_new_ipv6_callback_t add_new_ipv6;
} pcapng_t;

static int
pcapng_get_encap(gint id, pcapng_t *pn)
{
	interface_data_t int_data;

	if ((id >= 0) && ((guint)id < pn->number_of_interfaces)) {
		int_data = g_array_index(pn->interface_data, interface_data_t, id);
		return int_data.wtap_encap;
	} else {
		return WTAP_ERR_UNSUPPORTED_ENCAP;
	}
}


static int
pcapng_read_option(FILE_T fh, pcapng_t *pn, pcapng_option_header_t *oh,
		   char *content, int len, int *err, gchar **err_info)
{
	int	bytes_read;
	int	block_read;
	guint64 file_offset64;


	/* read option header */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(oh, sizeof (*oh), fh);
	if (bytes_read != sizeof (*oh)) {
	    pcapng_debug0("pcapng_read_option: failed to read option");
	    *err = file_error(fh, err_info);
	    if (*err != 0)
		    return -1;
	    return 0;
	}
	block_read = sizeof (*oh);
	if(pn->byte_swapped) {
		oh->option_code      = BSWAP16(oh->option_code);
		oh->option_length    = BSWAP16(oh->option_length);
	}

	/* sanity check: option length */
	if (oh->option_length > len) {
		pcapng_debug2("pcapng_read_option: option_length %u larger than buffer (%u)",
			      oh->option_length, len);
		return 0;
	}

	/* read option content */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(content, oh->option_length, fh);
	if (bytes_read != oh->option_length) {
		pcapng_debug1("pcapng_read_option: failed to read content of option %u", oh->option_code);
		*err = file_error(fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	block_read += oh->option_length;

	/* jump over potential padding bytes at end of option */
	if( (oh->option_length % 4) != 0) {
		file_offset64 = file_seek(fh, 4 - (oh->option_length % 4), SEEK_CUR, err);
		if (file_offset64 <= 0) {
			if (*err != 0)
				return -1;
			return 0;
		}
		block_read += 4 - (oh->option_length % 4);
	}

	return block_read;
}


static int
pcapng_read_section_header_block(FILE_T fh, gboolean first_block,
				 pcapng_block_header_t *bh, pcapng_t *pn,
				 wtapng_block_t *wblock, int *err,
				 gchar **err_info)
{
	int	bytes_read;
	int	block_read;
	int to_read;
	pcapng_section_header_block_t shb;
	pcapng_option_header_t oh;
	char option_content[100]; /* XXX - size might need to be increased, if we see longer options */


	/* read block content */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&shb, sizeof shb, fh);
	if (bytes_read != sizeof shb) {
		*err = file_error(fh, err_info);
		if (*err == 0) {
			if (first_block) {
				/*
				 * We're reading this as part of an open,
				 * and this block is too short to be
				 * an SHB, so the file is too short
				 * to be a pcap-ng file.
				 */
				return 0;
			}

			/*
			 * Otherwise, just report this as an error.
			 */
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}
	block_read = bytes_read;

	/* is the magic number one we expect? */
	switch(shb.magic) {
	    case(0x1A2B3C4D):
		/* this seems pcapng with correct byte order */
		pn->byte_swapped		= FALSE;
		pn->version_major		= shb.version_major;
		pn->version_minor		= shb.version_minor;

		pcapng_debug3("pcapng_read_section_header_block: SHB (little endian) V%u.%u, len %u",
				pn->version_major, pn->version_minor, bh->block_total_length);
		break;
	    case(0x4D3C2B1A):
		/* this seems pcapng with swapped byte order */
		pn->byte_swapped		= TRUE;
		pn->version_major		= BSWAP16(shb.version_major);
		pn->version_minor		= BSWAP16(shb.version_minor);

		/* tweak the block length to meet current swapping that we know now */
		bh->block_total_length	= BSWAP32(bh->block_total_length);

		pcapng_debug3("pcapng_read_section_header_block: SHB (big endian) V%u.%u, len %u",
				pn->version_major, pn->version_minor, bh->block_total_length);
		break;
	    default:
		/* Not a "pcapng" magic number we know about. */
		if (first_block) {
			/* Not a pcap-ng file. */
			return 0;
		}

		/* A bad block */
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_section_header_block: unknown byte-order magic number 0x%08x", shb.magic);
		return 0;
	}

	/* OK, at this point we assume it's a pcap-ng file. */

	/* we currently only understand SHB V1.0 */
	if (pn->version_major != 1 || pn->version_minor > 0) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("pcapng_read_section_header_block: unknown SHB version %u.%u",
			      pn->version_major, pn->version_minor);
		return -1;
	}

	/* 64bit section_length (currently unused) */
	if (pn->byte_swapped) {
		wblock->data.section.section_length = BSWAP64(shb.section_length);
	} else {
		wblock->data.section.section_length = shb.section_length;
	}

	/* Option defaults */
	wblock->data.section.opt_comment	= NULL;
	wblock->data.section.shb_hardware	= NULL;
	wblock->data.section.shb_os		= NULL;
	wblock->data.section.shb_user_appl	= NULL;

	/* Options */
	errno = WTAP_ERR_CANT_READ;
	to_read = bh->block_total_length
        - (int)sizeof(pcapng_block_header_t)
        - (int)sizeof (pcapng_section_header_block_t)
        - (int)sizeof(bh->block_total_length);
	while(to_read > 0) {
		/* read option */
		bytes_read = pcapng_read_option(fh, pn, &oh, option_content, sizeof(option_content), err, err_info);
		if (bytes_read <= 0) {
			pcapng_debug0("pcapng_read_section_header_block: failed to read option");
			return bytes_read;
		}
		block_read += bytes_read;
		to_read -= bytes_read;

		/* handle option content */
		switch(oh.option_code) {
		    case(0): /* opt_endofopt */
			if(to_read != 0) {
				pcapng_debug1("pcapng_read_section_header_block: %u bytes after opt_endofopt", to_read);
			}
			/* padding should be ok here, just get out of this */
			to_read = 0;
			break;
		    case(1): /* opt_comment */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.section.opt_comment = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_section_header_block: opt_comment %s", wblock->data.section.opt_comment);
			} else {
				pcapng_debug1("pcapng_read_section_header_block: opt_comment length %u seems strange", oh.option_length);
			}
			break;
		    case(2): /* shb_hardware */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.section.shb_hardware = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_section_header_block: shb_hardware %s", wblock->data.section.shb_hardware);
			} else {
				pcapng_debug1("pcapng_read_section_header_block: shb_hardware length %u seems strange", oh.option_length);
			}
			break;
		    case(3): /* shb_os */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.section.shb_os = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_section_header_block: shb_os %s", wblock->data.section.shb_os);
			} else {
				pcapng_debug1("pcapng_read_section_header_block: shb_os length %u seems strange", oh.option_length);
			}
			break;
		    case(4): /* shb_userappl */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.section.shb_user_appl = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_section_header_block: shb_userappl %s", wblock->data.section.shb_user_appl);
			} else {
				pcapng_debug1("pcapng_read_section_header_block: shb_userappl length %u seems strange", oh.option_length);
			}
			break;
		    default:
			pcapng_debug2("pcapng_read_section_header_block: unknown option %u - ignoring %u bytes",
				      oh.option_code, oh.option_length);
		}
	}

	if (pn->interface_data != NULL) {
		g_array_free(pn->interface_data, TRUE);
		pn->interface_data = NULL;
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng: multiple section header blocks not supported.");
		return 0;
	}
	pn->interface_data = g_array_new(FALSE, FALSE, sizeof(interface_data_t));
	pn->number_of_interfaces = 0;

	return block_read;
}


/* "Interface Description Block" */
static int
pcapng_read_if_descr_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn,
			   wtapng_block_t *wblock, int *err, gchar **err_info)
{
	guint64 time_units_per_second;
	int	bytes_read;
	int	block_read;
	int to_read;
	pcapng_interface_description_block_t idb;
	pcapng_option_header_t oh;
	interface_data_t int_data;
	gint encap;
	char option_content[100]; /* XXX - size might need to be increased, if we see longer options */


	time_units_per_second = 1000000; /* default */
	/* read block content */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&idb, sizeof idb, fh);
	if (bytes_read != sizeof idb) {
		pcapng_debug0("pcapng_read_if_descr_block: failed to read IDB");
		*err = file_error(fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	block_read = bytes_read;

	/* mandatory values */
	if (pn->byte_swapped) {
		wblock->data.if_descr.link_type = BSWAP16(idb.linktype);
		wblock->data.if_descr.snap_len	= BSWAP32(idb.snaplen);
	} else {
		wblock->data.if_descr.link_type	= idb.linktype;
		wblock->data.if_descr.snap_len	= idb.snaplen;
	}

	pcapng_debug3("pcapng_read_if_descr_block: IDB link_type %u (%s), snap %u",
		      wblock->data.if_descr.link_type,
		      wtap_encap_string(wtap_pcap_encap_to_wtap_encap(wblock->data.if_descr.link_type)),
		      wblock->data.if_descr.snap_len);

	if (wblock->data.if_descr.snap_len > WTAP_MAX_PACKET_SIZE) {
		/* This is unrealisitic, but text2pcap currently uses 102400.
		 * We do not use this value, maybe we should check the
		 * snap_len of the packets against it. For now, only warn.
		 */
		pcapng_debug1("pcapng_read_if_descr_block: snapshot length %u unrealistic.",
			      wblock->data.if_descr.snap_len);
		/*wblock->data.if_descr.snap_len = WTAP_MAX_PACKET_SIZE;*/
	}

	/* Option defaults */
	wblock->data.if_descr.opt_comment	= NULL;
	wblock->data.if_descr.if_name		= NULL;
	wblock->data.if_descr.if_description	= NULL;
	/* XXX: if_IPv4addr */
	/* XXX: if_IPv6addr */
	/* XXX: if_MACaddr */
	/* XXX: if_EUIaddr */
	wblock->data.if_descr.if_speed		= 0xFFFFFFFF;	/* "unknown" */
	wblock->data.if_descr.if_tsresol	= 6;		/* default is 6 for microsecond resolution */
	wblock->data.if_descr.if_filter		= NULL;
	wblock->data.if_descr.if_os		= NULL;
	wblock->data.if_descr.if_fcslen		= -1;		/* unknown or changes between packets */
	/* XXX: guint64	if_tsoffset; */


	/* Options */
	errno = WTAP_ERR_CANT_READ;
	to_read = bh->block_total_length
        - (int)sizeof(pcapng_block_header_t)
        - (int)sizeof (pcapng_interface_description_block_t)
        - (int)sizeof(bh->block_total_length);
	while (to_read > 0) {
		/* read option */
		bytes_read = pcapng_read_option(fh, pn, &oh, option_content, sizeof(option_content), err, err_info);
		if (bytes_read <= 0) {
			pcapng_debug0("pcapng_read_if_descr_block: failed to read option");
			return bytes_read;
		}
		block_read += bytes_read;
		to_read -= bytes_read;

		/* handle option content */
		switch(oh.option_code) {
		    case(0): /* opt_endofopt */
			if(to_read != 0) {
				pcapng_debug1("pcapng_read_if_descr_block: %u bytes after opt_endofopt", to_read);
			}
			/* padding should be ok here, just get out of this */
			to_read = 0;
			break;
		    case(1): /* opt_comment */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.if_descr.opt_comment = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_if_descr_block: opt_comment %s", wblock->data.if_descr.opt_comment);
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: opt_comment length %u seems strange", oh.option_length);
			}
			break;
		    case(2): /* if_name */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.if_descr.if_name = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_if_descr_block: if_name %s", wblock->data.if_descr.if_name);
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: if_name length %u seems strange", oh.option_length);
			}
			break;
		    case(3): /* if_description */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
			    wblock->data.if_descr.if_description = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_if_descr_block: if_description %s", wblock->data.if_descr.if_description);
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: if_description length %u seems strange", oh.option_length);
			}
			break;
		    case(8): /* if_speed */
			if(oh.option_length == 8) {
				/*  Don't cast a char[] into a guint64--the
				 *  char[] may not be aligned correctly.
				 */
				memcpy(&wblock->data.if_descr.if_speed, option_content, sizeof(guint64));
				if(pn->byte_swapped)
					wblock->data.if_descr.if_speed = BSWAP64(wblock->data.if_descr.if_speed);
				pcapng_debug1("pcapng_read_if_descr_block: if_speed %" G_GINT64_MODIFIER "u (bps)", wblock->data.if_descr.if_speed);
			} else {
				    pcapng_debug1("pcapng_read_if_descr_block: if_speed length %u not 8 as expected", oh.option_length);
			}
			break;
		    case(9): /* if_tsresol */
			if (oh.option_length == 1) {
				guint64 base;
				guint64 result;
				guint8 i, exponent;

				wblock->data.if_descr.if_tsresol = option_content[0];
				if (wblock->data.if_descr.if_tsresol & 0x80) {
					base = 2;
				} else {
					base = 10;
				}
				exponent = (guint8)(wblock->data.if_descr.if_tsresol & 0x7f);
				if (((base == 2) && (exponent < 64)) || ((base == 10) && (exponent < 20))) {
					result = 1;
					for (i = 0; i < exponent; i++) {
						result *= base;
					}
					time_units_per_second = result;
				} else {
					time_units_per_second = G_MAXUINT64;
				}
				if (time_units_per_second > (((guint64)1) << 32)) {
					pcapng_debug0("pcapng_open: time conversion might be inaccurate");
				}
				pcapng_debug1("pcapng_read_if_descr_block: if_tsresol %u", wblock->data.if_descr.if_tsresol);
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: if_tsresol length %u not 1 as expected", oh.option_length);
			}
			break;
		    case(11): /* if_filter */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.if_descr.if_filter = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_if_descr_block: if_filter %s", wblock->data.if_descr.if_filter);
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: if_filter length %u seems strange", oh.option_length);
			}
			break;
		    case(13): /* if_fcslen */
			if(oh.option_length == 1) {
				wblock->data.if_descr.if_fcslen = option_content[0];
				pn->if_fcslen = wblock->data.if_descr.if_fcslen;
				pcapng_debug1("pcapng_read_if_descr_block: if_fcslen %u", wblock->data.if_descr.if_fcslen);
				/* XXX - add sanity check */
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: if_fcslen length %u not 1 as expected", oh.option_length);
			}
			break;
		    default:
			pcapng_debug2("pcapng_read_if_descr_block: unknown option %u - ignoring %u bytes",
				      oh.option_code, oh.option_length);
		}
	}

	encap = wtap_pcap_encap_to_wtap_encap(wblock->data.if_descr.link_type);
	if (*wblock->file_encap == WTAP_ENCAP_UNKNOWN) {
		*wblock->file_encap = encap;
	} else {
		if (*wblock->file_encap != encap) {
			*wblock->file_encap = WTAP_ENCAP_PER_PACKET;
		}
	}

	int_data.wtap_encap = encap;
	int_data.time_units_per_second = time_units_per_second;
	g_array_append_val(pn->interface_data, int_data);
	pn->number_of_interfaces++;
	return block_read;
}


static int
pcapng_read_packet_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info, gboolean enhanced)
{
	int bytes_read;
	int block_read;
	int to_read;
	guint64 file_offset64;
	pcapng_enhanced_packet_block_t epb;
	pcapng_packet_block_t pb;
	guint32 block_total_length;
	pcapng_option_header_t oh;
	gint wtap_encap;
	int pseudo_header_len;
	char option_content[100]; /* XXX - size might need to be increased, if we see longer options */
	int fcslen;

	/* "(Enhanced) Packet Block" read fixed part */
	errno = WTAP_ERR_CANT_READ;
	if (enhanced) {
		bytes_read = file_read(&epb, sizeof epb, fh);
		if (bytes_read != sizeof epb) {
			pcapng_debug0("pcapng_read_packet_block: failed to read packet data");
			*err = file_error(fh, err_info);
			return 0;
		}
		block_read = bytes_read;

		if (pn->byte_swapped) {
			wblock->data.packet.interface_id	= BSWAP32(epb.interface_id);
			wblock->data.packet.drops_count		= -1; /* invalid */
			wblock->data.packet.ts_high		= BSWAP32(epb.timestamp_high);
			wblock->data.packet.ts_low		= BSWAP32(epb.timestamp_low);
			wblock->data.packet.cap_len		= BSWAP32(epb.captured_len);
			wblock->data.packet.packet_len		= BSWAP32(epb.packet_len);
		} else {
			wblock->data.packet.interface_id	= epb.interface_id;
			wblock->data.packet.drops_count		= -1; /* invalid */
			wblock->data.packet.ts_high		= epb.timestamp_high;
			wblock->data.packet.ts_low		= epb.timestamp_low;
			wblock->data.packet.cap_len		= epb.captured_len;
			wblock->data.packet.packet_len		= epb.packet_len;
		}
	} else {
		bytes_read = file_read(&pb, sizeof pb, fh);
		if (bytes_read != sizeof pb) {
			pcapng_debug0("pcapng_read_packet_block: failed to read packet data");
			*err = file_error(fh, err_info);
			return 0;
		}
		block_read = bytes_read;

		if (pn->byte_swapped) {
			wblock->data.packet.interface_id	= BSWAP16(pb.interface_id);
			wblock->data.packet.drops_count		= BSWAP16(pb.drops_count);
			wblock->data.packet.ts_high		= BSWAP32(pb.timestamp_high);
			wblock->data.packet.ts_low		= BSWAP32(pb.timestamp_low);
			wblock->data.packet.cap_len		= BSWAP32(pb.captured_len);
			wblock->data.packet.packet_len		= BSWAP32(pb.packet_len);
		} else {
			wblock->data.packet.interface_id	= pb.interface_id;
			wblock->data.packet.drops_count		= pb.drops_count;
			wblock->data.packet.ts_high		= pb.timestamp_high;
			wblock->data.packet.ts_low		= pb.timestamp_low;
			wblock->data.packet.cap_len		= pb.captured_len;
			wblock->data.packet.packet_len		= pb.packet_len;
		}
	}

	if (wblock->data.packet.cap_len > wblock->data.packet.packet_len) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_packet_block: cap_len %u is larger than packet_len %u.",
		    wblock->data.packet.cap_len, wblock->data.packet.packet_len);
		return 0;
	}
	if (wblock->data.packet.cap_len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_packet_block: cap_len %u is larger than WTAP_MAX_PACKET_SIZE %u.",
		    wblock->data.packet.cap_len, WTAP_MAX_PACKET_SIZE);
		return 0;
	}
	pcapng_debug3("pcapng_read_packet_block: packet data: packet_len %u captured_len %u interface_id %u",
	              wblock->data.packet.packet_len,
	              wblock->data.packet.cap_len,
	              wblock->data.packet.interface_id);
	if (wblock->data.packet.packet_len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_packet_block: packet_len %u is larger than WTAP_MAX_PACKET_SIZE %u.",
		    wblock->data.packet.packet_len, WTAP_MAX_PACKET_SIZE);
		return 0;
	}

	wtap_encap = pcapng_get_encap(wblock->data.packet.interface_id, pn);
	pcapng_debug3("pcapng_read_packet_block: encapsulation = %d (%s), pseudo header size = %d.",
	               wtap_encap,
	               wtap_encap_string(wtap_encap),
	               pcap_get_phdr_size(wtap_encap, wblock->pseudo_header));

	memset((void *)wblock->pseudo_header, 0, sizeof(union wtap_pseudo_header));
	pseudo_header_len = pcap_process_pseudo_header(fh,
	                                               WTAP_FILE_PCAPNG,
	                                               wtap_encap,
	                                               wblock->data.packet.cap_len,
	                                               TRUE,
	                                               wblock->packet_header,
	                                               (union wtap_pseudo_header *)wblock->pseudo_header,
	                                               err,
	                                               err_info);
	if (pseudo_header_len < 0) {
		return 0;
	}
	wblock->data.packet.pseudo_header_len = (guint32)pseudo_header_len;
	block_read += pseudo_header_len;
	if (pseudo_header_len != pcap_get_phdr_size(wtap_encap, wblock->pseudo_header)) {
		pcapng_debug1("pcapng_read_packet_block: Could only read %d bytes for pseudo header.",
		              pseudo_header_len);
	}

	/* "(Enhanced) Packet Block" read capture data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read((guint8 *) (wblock->frame_buffer), wblock->data.packet.cap_len - pseudo_header_len, fh);
	if (bytes_read != (int) (wblock->data.packet.cap_len - pseudo_header_len)) {
		*err = file_error(fh, err_info);
		pcapng_debug1("pcapng_read_packet_block: couldn't read %u bytes of captured data",
			      wblock->data.packet.cap_len - pseudo_header_len);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return 0;
	}
	block_read += bytes_read;

	/* jump over potential padding bytes at end of the packet data */
	if( (wblock->data.packet.cap_len % 4) != 0) {
		file_offset64 = file_seek(fh, 4 - (wblock->data.packet.cap_len % 4), SEEK_CUR, err);
		if (file_offset64 <= 0) {
			if (*err != 0)
				return -1;
			return 0;
		}
		block_read += 4 - (wblock->data.packet.cap_len % 4);
	}

	/* add padding bytes to "block total length" */
	/* (the "block total length" of some example files don't contain the packet data padding bytes!) */
	if (bh->block_total_length % 4) {
		block_total_length = bh->block_total_length + 4 - (bh->block_total_length % 4);
	} else {
		block_total_length = bh->block_total_length;
	}

	/* Option defaults */
	wblock->data.packet.opt_comment = NULL;
	wblock->data.packet.drop_count  = -1;
	wblock->data.packet.pack_flags  = 0;    /* XXX - is 0 ok to signal "not used"? */

	/* FCS length default */
	fcslen = pn->if_fcslen;

	/* Options */
	errno = WTAP_ERR_CANT_READ;
	to_read = block_total_length
        - (int)sizeof(pcapng_block_header_t)
        - block_read    /* fixed and variable part, including padding */
        - (int)sizeof(bh->block_total_length);
	while(to_read > 0) {
		/* read option */
		bytes_read = pcapng_read_option(fh, pn, &oh, option_content, sizeof(option_content), err, err_info);
		if (bytes_read <= 0) {
			pcapng_debug0("pcapng_read_packet_block: failed to read option");
			return bytes_read;
		}
		block_read += bytes_read;
		to_read -= bytes_read;

		/* handle option content */
		switch(oh.option_code) {
		    case(0): /* opt_endofopt */
			if(to_read != 0) {
				pcapng_debug1("pcapng_read_packet_block: %u bytes after opt_endofopt", to_read);
			}
			/* padding should be ok here, just get out of this */
			to_read = 0;
			break;
		    case(1): /* opt_comment */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.packet.opt_comment = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_packet_block: opt_comment %s", wblock->data.packet.opt_comment);
			} else {
				pcapng_debug1("pcapng_read_packet_block: opt_comment length %u seems strange", oh.option_length);
			}
			break;
		    case(2): /* pack_flags / epb_flags */
			if(oh.option_length == 4) {
				/*  Don't cast a char[] into a guint32--the
				 *  char[] may not be aligned correctly.
				 */
				memcpy(&wblock->data.packet.pack_flags, option_content, sizeof(guint32));
				if(pn->byte_swapped)
					wblock->data.packet.pack_flags = BSWAP32(wblock->data.packet.pack_flags);
				if (wblock->data.packet.pack_flags & 0x000001E0) {
					/* The FCS length is present */
					fcslen = (wblock->data.packet.pack_flags & 0x000001E0) >> 5;
				}
				pcapng_debug1("pcapng_read_if_descr_block: pack_flags %u (ignored)", wblock->data.packet.pack_flags);
			} else {
				pcapng_debug1("pcapng_read_if_descr_block: pack_flags length %u not 4 as expected", oh.option_length);
			}
			break;
		    default:
			pcapng_debug2("pcapng_read_packet_block: unknown option %u - ignoring %u bytes",
				      oh.option_code, oh.option_length);
		}
	}

	pcap_fill_in_pseudo_header(WTAP_FILE_PCAPNG, wtap_encap,
	    (guint8 *) (wblock->frame_buffer),
	    (int) (wblock->data.packet.cap_len - pseudo_header_len),
	    (union wtap_pseudo_header *)wblock->pseudo_header, fcslen);

	pcap_read_post_process(wtap_encap,
	    (int) (wblock->data.packet.cap_len - pseudo_header_len),
	    pn->byte_swapped, (guint8 *) (wblock->frame_buffer));
	return block_read;
}


static int
pcapng_read_simple_packet_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info)
{
	int bytes_read;
	int block_read;
	guint64 file_offset64;
	gint encap;
	int pseudo_header_len;
	pcapng_simple_packet_block_t spb;


	/* "Simple Packet Block" read fixed part */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&spb, sizeof spb, fh);
	if (bytes_read != sizeof spb) {
		pcapng_debug0("pcapng_read_simple_packet_block: failed to read packet data");
		*err = file_error(fh, err_info);
		return 0;
	}
	block_read = bytes_read;

	if (pn->byte_swapped) {
		wblock->data.simple_packet.packet_len	= BSWAP32(spb.packet_len);
	} else {
		wblock->data.simple_packet.packet_len	= spb.packet_len;
	}

	wblock->data.simple_packet.cap_len = bh->block_total_length
					     - (guint32)sizeof(pcapng_simple_packet_block_t)
					     - (guint32)sizeof(bh->block_total_length);

	if (wblock->data.simple_packet.cap_len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_simple_packet_block: cap_len %u is larger than WTAP_MAX_PACKET_SIZE %u.",
		    wblock->data.simple_packet.cap_len, WTAP_MAX_PACKET_SIZE);
		return 0;
	}
	pcapng_debug1("pcapng_read_simple_packet_block: packet data: packet_len %u",
	               wblock->data.simple_packet.packet_len);
	if (wblock->data.simple_packet.packet_len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_simple_packet_block: packet_len %u is larger than WTAP_MAX_PACKET_SIZE %u.",
		    wblock->data.simple_packet.packet_len, WTAP_MAX_PACKET_SIZE);
		return 0;
	}

	encap = pcapng_get_encap(0, pn);
	pcapng_debug1("pcapng_read_simple_packet_block: Need to read pseudo header of size %d",
	              pcap_get_phdr_size(encap, wblock->pseudo_header));

	memset((void *)wblock->pseudo_header, 0, sizeof(union wtap_pseudo_header));
	pseudo_header_len = pcap_process_pseudo_header(fh,
	                                               WTAP_FILE_PCAPNG,
	                                               encap,
	                                               wblock->data.simple_packet.cap_len,
	                                               TRUE,
	                                               wblock->packet_header,
	                                               (union wtap_pseudo_header *)wblock->pseudo_header,
	                                               err,
	                                               err_info);
	if (pseudo_header_len < 0) {
		return 0;
	}
	wblock->data.simple_packet.pseudo_header_len = (guint32)pseudo_header_len;
	block_read += pseudo_header_len;
	if (pseudo_header_len != pcap_get_phdr_size(encap, wblock->pseudo_header)) {
		pcapng_debug1("pcapng_read_simple_packet_block: Could only read %d bytes for pseudo header.",
		              pseudo_header_len);
	}

	memset((void *)wblock->pseudo_header, 0, sizeof(union wtap_pseudo_header));

	/* "Simple Packet Block" read capture data */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read((guint8 *) (wblock->frame_buffer), wblock->data.simple_packet.cap_len, fh);
	if (bytes_read != (int) wblock->data.simple_packet.cap_len) {
		*err = file_error(fh, err_info);
		pcapng_debug1("pcapng_read_simple_packet_block: couldn't read %u bytes of captured data",
			      wblock->data.simple_packet.cap_len);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return 0;
	}
	block_read += bytes_read;

	/* jump over potential padding bytes at end of the packet data */
	if ((wblock->data.simple_packet.cap_len % 4) != 0) {
		file_offset64 = file_seek(fh, 4 - (wblock->data.simple_packet.cap_len % 4), SEEK_CUR, err);
		if (file_offset64 <= 0) {
			if (*err != 0)
				return -1;
			return 0;
		}
		block_read += 4 - (wblock->data.simple_packet.cap_len % 4);
	}

	pcap_fill_in_pseudo_header(WTAP_FILE_PCAPNG, encap,
	    (guint8 *) (wblock->frame_buffer),
	    (int) wblock->data.simple_packet.cap_len,
	    (union wtap_pseudo_header *)wblock->pseudo_header,
	    pn->if_fcslen);

	pcap_read_post_process(encap, (int) wblock->data.simple_packet.cap_len,
	    pn->byte_swapped, (guint8 *) (wblock->frame_buffer));
	return block_read;
}

#define NRES_ENDOFRECORD 0
#define NRES_IP4RECORD 1
#define NRES_IP6RECORD 2
#define PADDING4(x) ((((x + 3) >> 2) << 2) - x)
/* IPv6 + MAXNAMELEN */
#define MAX_NRB_REC_SIZE (16 + 64)
static int
pcapng_read_name_resolution_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock _U_,int *err, gchar **err_info)
{
	int bytes_read = 0;
	int block_read = 0;
	int to_read;
	guint64 file_offset64;
	pcapng_name_resolution_block_t nrb;
	guint8 nrb_rec[MAX_NRB_REC_SIZE];
	guint32 v4_addr;

	errno = WTAP_ERR_CANT_READ;
	to_read = bh->block_total_length
		- sizeof(pcapng_block_header_t)
		- sizeof(bh->block_total_length);

	while (block_read < to_read) {
		bytes_read = file_read(&nrb, sizeof nrb, fh);
		if (bytes_read != sizeof nrb) {
			pcapng_debug0("pcapng_read_name_resolution_block: failed to read record header");
			*err = file_error(fh, err_info);
			return 0;
		}
		block_read += bytes_read;

		if (pn->byte_swapped) {
			nrb.record_type = BSWAP16(nrb.record_type);
			nrb.record_len  = BSWAP16(nrb.record_len);
		}

		switch(nrb.record_type) {
			case NRES_ENDOFRECORD:
				/* There shouldn't be any more data */
				to_read = 0;
				break;
			case NRES_IP4RECORD:
				if (nrb.record_len < 6 || nrb.record_len > MAX_NRB_REC_SIZE || to_read < nrb.record_len) {
					pcapng_debug0("pcapng_read_name_resolution_block: bad length or insufficient data for IPv4 record");
					return 0;
				}
				bytes_read = file_read(nrb_rec, nrb.record_len, fh);
				if (bytes_read != nrb.record_len) {
					pcapng_debug0("pcapng_read_name_resolution_block: failed to read IPv4 record data");
					*err = file_error(fh, err_info);
					return 0;
				}
				block_read += bytes_read;

				if (pn->add_new_ipv4) {
					memcpy(&v4_addr, nrb_rec, 4);
					if (pn->byte_swapped)
						v4_addr = BSWAP32(v4_addr);
					pn->add_new_ipv4(v4_addr, nrb_rec + 4);
				}

				file_offset64 = file_seek(fh, PADDING4(nrb.record_len), SEEK_CUR, err);
				if (file_offset64 <= 0) {
					if (*err != 0)
						return -1;
					return 0;
				}
				block_read += PADDING4(nrb.record_len);
				break;
			case NRES_IP6RECORD:
				if (nrb.record_len < 18 || nrb.record_len > MAX_NRB_REC_SIZE || to_read < nrb.record_len) {
					pcapng_debug0("pcapng_read_name_resolution_block: bad length or insufficient data for IPv6 record");
					return 0;
				}
				bytes_read = file_read(nrb_rec, nrb.record_len, fh);
				if (bytes_read != nrb.record_len) {
					pcapng_debug0("pcapng_read_name_resolution_block: failed to read IPv6 record data");
					*err = file_error(fh, err_info);
					return 0;
				}
				block_read += bytes_read;

				if (pn->add_new_ipv6) {
					pn->add_new_ipv6(nrb_rec, nrb_rec + 16);
				}

				file_offset64 = file_seek(fh, PADDING4(nrb.record_len), SEEK_CUR, err);
				if (file_offset64 <= 0) {
					if (*err != 0)
						return -1;
					return 0;
				}
				block_read += PADDING4(nrb.record_len);
				break;
			default:
				pcapng_debug1("pcapng_read_name_resolution_block: unknown record type 0x%x", nrb.record_type);
				file_offset64 = file_seek(fh, nrb.record_len + PADDING4(nrb.record_len), SEEK_CUR, err);
				if (file_offset64 <= 0) {
					if (*err != 0)
						return -1;
					return 0;
				}
				block_read += nrb.record_len + PADDING4(nrb.record_len);
				break;
		}
	}

	return block_read;
}

static int
pcapng_read_interface_statistics_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock,int *err, gchar **err_info)
{
	int bytes_read;
	int block_read;
	int to_read;
	pcapng_interface_statistics_block_t isb;
	pcapng_option_header_t oh;
	char option_content[100]; /* XXX - size might need to be increased, if we see longer options */


	/* "Interface Statistics Block" read fixed part */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&isb, sizeof isb, fh);
	if (bytes_read != sizeof isb) {
		pcapng_debug0("pcapng_read_interface_statistics_block: failed to read packet data");
		*err = file_error(fh, err_info);
		return 0;
	}
	block_read = bytes_read;

	if(pn->byte_swapped) {
		wblock->data.if_stats.interface_id	= BSWAP64(isb.interface_id);
		wblock->data.if_stats.ts_high		= BSWAP32(isb.timestamp_high);
		wblock->data.if_stats.ts_low		= BSWAP32(isb.timestamp_low);
	} else {
		wblock->data.if_stats.interface_id	= isb.interface_id;
		wblock->data.if_stats.ts_high		= isb.timestamp_high;
		wblock->data.if_stats.ts_low		= isb.timestamp_low;
	}
	pcapng_debug1("pcapng_read_interface_statistics_block: interface_id %" G_GINT64_MODIFIER "u", wblock->data.if_stats.interface_id);

	/* Option defaults */
	wblock->data.if_stats.opt_comment = NULL;
	wblock->data.if_stats.isb_ifrecv  = -1;
	wblock->data.if_stats.isb_ifdrop  = -1;

	/* Options */
	errno = WTAP_ERR_CANT_READ;
	to_read = bh->block_total_length
        - sizeof(pcapng_block_header_t)
        - block_read    /* fixed and variable part, including padding */
        - sizeof(bh->block_total_length);
	while(to_read > 0) {
		/* read option */
		bytes_read = pcapng_read_option(fh, pn, &oh, option_content, sizeof(option_content), err, err_info);
		if (bytes_read <= 0) {
			pcapng_debug0("pcapng_read_interface_statistics_block: failed to read option");
			return bytes_read;
		}
		block_read += bytes_read;
		to_read -= bytes_read;

		/* handle option content */
		switch(oh.option_code) {
		    case(0): /* opt_endofopt */
			if(to_read != 0) {
				pcapng_debug1("pcapng_read_interface_statistics_block: %u bytes after opt_endofopt", to_read);
			}
			/* padding should be ok here, just get out of this */
			to_read = 0;
			break;
		    case(1): /* opt_comment */
			if(oh.option_length > 0 && oh.option_length < sizeof(option_content)) {
				wblock->data.if_stats.opt_comment = g_strndup(option_content, sizeof(option_content));
				pcapng_debug1("pcapng_read_interface_statistics_block: opt_comment %s", wblock->data.if_stats.opt_comment);
			} else {
				pcapng_debug1("pcapng_read_interface_statistics_block: opt_comment length %u seems strange", oh.option_length);
			}
			break;
		    case(4): /* isb_ifrecv */
			if(oh.option_length == 8) {
				/*  Don't cast a char[] into a guint32--the
				 *  char[] may not be aligned correctly.
				 */
				memcpy(&wblock->data.if_stats.isb_ifrecv, option_content, sizeof(guint64));
				if(pn->byte_swapped)
					wblock->data.if_stats.isb_ifrecv = BSWAP64(wblock->data.if_stats.isb_ifrecv);
				pcapng_debug1("pcapng_read_interface_statistics_block: isb_ifrecv %" G_GINT64_MODIFIER "u", wblock->data.if_stats.isb_ifrecv);
			} else {
				pcapng_debug1("pcapng_read_interface_statistics_block: isb_ifrecv length %u not 8 as expected", oh.option_length);
			}
			break;
		    case(5): /* isb_ifdrop */
			if(oh.option_length == 8) {
				/*  Don't cast a char[] into a guint32--the
				 *  char[] may not be aligned correctly.
				 */
				memcpy(&wblock->data.if_stats.isb_ifdrop, option_content, sizeof(guint64));
				if(pn->byte_swapped)
					wblock->data.if_stats.isb_ifdrop = BSWAP64(wblock->data.if_stats.isb_ifdrop);
				pcapng_debug1("pcapng_read_interface_statistics_block: isb_ifdrop %" G_GINT64_MODIFIER "u", wblock->data.if_stats.isb_ifdrop);
			} else {
				pcapng_debug1("pcapng_read_interface_statistics_block: isb_ifdrop length %u not 8 as expected", oh.option_length);
			}
			break;
		    default:
			pcapng_debug2("pcapng_read_interface_statistics_block: unknown option %u - ignoring %u bytes",
				      oh.option_code, oh.option_length);
		}
	}

    return block_read;
}


static int
pcapng_read_unknown_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn _U_, wtapng_block_t *wblock _U_,int *err, gchar **err_info _U_)
{
	int block_read;
	guint64 file_offset64;
	guint32 block_total_length;


	/* add padding bytes to "block total length" */
	/* (the "block total length" of some example files don't contain any padding bytes!) */
	if (bh->block_total_length % 4) {
		block_total_length = bh->block_total_length + 4 - (bh->block_total_length % 4);
	} else {
		block_total_length = bh->block_total_length;
	}

	block_read = block_total_length - (guint32)sizeof(pcapng_block_header_t) - (guint32)sizeof(bh->block_total_length);

	/* jump over this unknown block */
	file_offset64 = file_seek(fh, block_read, SEEK_CUR, err);
	if (file_offset64 <= 0) {
		if (*err != 0)
			return -1;
		return 0;
	}

	return block_read;
}


static int
pcapng_read_block(FILE_T fh, gboolean first_block, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info)
{
	int block_read;
	int bytes_read;
	pcapng_block_header_t bh;
	guint32 block_total_length;


	/* Try to read the (next) block header */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&bh, sizeof bh, fh);
	if (bytes_read != sizeof bh) {
		*err = file_error(fh, err_info);
		pcapng_debug3("pcapng_read_block: file_read() returned %d instead of %u, err = %d.", bytes_read, (unsigned int)sizeof bh, *err);
		if (*err != 0)
			return -1;
		return 0;
	}

	block_read = bytes_read;
	if (pn->byte_swapped) {
		bh.block_type         = BSWAP32(bh.block_type);
		bh.block_total_length = BSWAP32(bh.block_total_length);
	}

	wblock->type = bh.block_type;

	pcapng_debug1("pcapng_read_block: block_type 0x%x", bh.block_type);

	if (first_block) {
		/*
		 * This is being read in by pcapng_open(), so this block
		 * must be an SHB.  If it's not, this is not a pcap-ng
		 * file.
		 *
		 * XXX - check for various forms of Windows <-> UN*X
		 * mangling, and suggest that the file might be a
		 * pcap-ng file that was damaged in transit?
		 */
		if (bh.block_type != BLOCK_TYPE_SHB)
			return 0;	/* not a pcap-ng file */
	}

	switch(bh.block_type) {
		case(BLOCK_TYPE_SHB):
			bytes_read = pcapng_read_section_header_block(fh, first_block, &bh, pn, wblock, err, err_info);
			break;
		case(BLOCK_TYPE_IDB):
			bytes_read = pcapng_read_if_descr_block(fh, &bh, pn, wblock, err, err_info);
			break;
		case(BLOCK_TYPE_PB):
			bytes_read = pcapng_read_packet_block(fh, &bh, pn, wblock, err, err_info, FALSE);
			break;
		case(BLOCK_TYPE_SPB):
			bytes_read = pcapng_read_simple_packet_block(fh, &bh, pn, wblock, err, err_info);
			break;
		case(BLOCK_TYPE_EPB):
			bytes_read = pcapng_read_packet_block(fh, &bh, pn, wblock, err, err_info, TRUE);
			break;
		case(BLOCK_TYPE_NRB):
			bytes_read = pcapng_read_name_resolution_block(fh, &bh, pn, wblock, err, err_info);
			break;
		case(BLOCK_TYPE_ISB):
			bytes_read = pcapng_read_interface_statistics_block(fh, &bh, pn, wblock, err, err_info);
			break;
		default:
			pcapng_debug2("pcapng_read_block: Unknown block_type: 0x%x (block ignored), block total length %d", bh.block_type, bh.block_total_length);
			bytes_read = pcapng_read_unknown_block(fh, &bh, pn, wblock, err, err_info);
	}

	if (bytes_read <= 0) {
		return bytes_read;
	}
	block_read += bytes_read;

	/* sanity check: first and second block lengths must match */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&block_total_length, sizeof block_total_length, fh);
	if (bytes_read != sizeof block_total_length) {
		pcapng_debug0("pcapng_read_block: couldn't read second block length");
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}
	block_read += bytes_read;

	if (pn->byte_swapped)
		block_total_length = BSWAP32(block_total_length);

	if (!(block_total_length == bh.block_total_length)) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng_read_block: total block lengths (first %u and second %u) don't match",
			      bh.block_total_length, block_total_length);
		return -1;
	}

	return block_read;
}


/* classic wtap: open capture file */
int
pcapng_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	pcapng_t pn;
	wtapng_block_t wblock;
	pcapng_t *pcapng;

	/* we don't know the byte swapping of the file yet */
	pn.byte_swapped = FALSE;
	pn.if_fcslen = -1;
	pn.version_major = -1;
	pn.version_minor = -1;
	pn.interface_data = NULL;
	pn.number_of_interfaces = 0;

	/* we don't expect any packet blocks yet */
	wblock.frame_buffer = NULL;
	wblock.pseudo_header = NULL;
	wblock.packet_header = NULL;
	wblock.file_encap = &wth->file_encap;

	pcapng_debug0("pcapng_open: opening file");
	/* read first block */
	bytes_read = pcapng_read_block(wth->fh, TRUE, &pn, &wblock, err, err_info);
	if (bytes_read <= 0) {
		pcapng_debug0("pcapng_open: couldn't read first SHB");
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += bytes_read;

	/* first block must be a "Section Header Block" */
	if (wblock.type != BLOCK_TYPE_SHB) {
		/*
		 * XXX - check for damage from transferring a file
		 * between Windows and UN*X as text rather than
		 * binary data?
		 */
		pcapng_debug1("pcapng_open: first block type %u not SHB", wblock.type);
		return 0;
	}

	wth->file_encap = WTAP_ENCAP_UNKNOWN;
	wth->snapshot_length = 0;
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
	pcapng = (pcapng_t *)g_malloc(sizeof(pcapng_t));
	wth->priv = (void *)pcapng;
	*pcapng = pn;
	wth->subtype_read = pcapng_read;
	wth->subtype_seek_read = pcapng_seek_read;
	wth->subtype_close = pcapng_close;
	wth->file_type = WTAP_FILE_PCAPNG;

	return 1;
}


/* classic wtap: read packet */
static gboolean
pcapng_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	pcapng_t *pcapng = (pcapng_t *)wth->priv;
	int bytes_read;
	guint64 ts;
	wtapng_block_t wblock;

	pcapng_debug1("pcapng_read: wth->data_offset is initially %" G_GINT64_MODIFIER "u", wth->data_offset);
	*data_offset = wth->data_offset;
	pcapng_debug1("pcapng_read: *data_offset is initially set to %" G_GINT64_MODIFIER "u", *data_offset);

	/* XXX - This should be done in the packet block reading function and
	 * should make use of the caplen of the packet.
	 */
	if (wth->snapshot_length > 0) {
		buffer_assure_space(wth->frame_buffer, wth->snapshot_length);
	} else {
		buffer_assure_space(wth->frame_buffer, WTAP_MAX_PACKET_SIZE);
	}

	wblock.frame_buffer  = buffer_start_ptr(wth->frame_buffer);
	wblock.pseudo_header = &wth->pseudo_header;
	wblock.packet_header = &wth->phdr;
	wblock.file_encap    = &wth->file_encap;

	pcapng->add_new_ipv4 = wth->add_new_ipv4;
	pcapng->add_new_ipv6 = wth->add_new_ipv6;

	/* read next block */
	while (1) {
		bytes_read = pcapng_read_block(wth->fh, FALSE, pcapng, &wblock, err, err_info);
		if (bytes_read <= 0) {
			wth->data_offset = *data_offset;
			pcapng_debug1("pcapng_read: wth->data_offset is finally %" G_GINT64_MODIFIER "u", wth->data_offset);
			pcapng_debug0("pcapng_read: couldn't read packet block");
			return FALSE;
		}

		/* block must be a "Packet Block" or an "Enhanced Packet Block" -> otherwise continue */
		if (wblock.type == BLOCK_TYPE_PB || wblock.type == BLOCK_TYPE_EPB) {
			break;
		}

		/* XXX - improve handling of "unknown" blocks */
		pcapng_debug1("pcapng_read: block type 0x%x not PB/EPB", wblock.type);
		*data_offset += bytes_read;
		pcapng_debug1("pcapng_read: *data_offset is updated to %" G_GINT64_MODIFIER "u", *data_offset);
	}

	/* Combine the two 32-bit pieces of the timestamp into one 64-bit value */
	ts = (((guint64)wblock.data.packet.ts_high) << 32) | ((guint64)wblock.data.packet.ts_low);

	wth->phdr.caplen = wblock.data.packet.cap_len - wblock.data.packet.pseudo_header_len;
	wth->phdr.len = wblock.data.packet.packet_len - wblock.data.packet.pseudo_header_len;
	if (wblock.data.packet.interface_id < pcapng->number_of_interfaces) {
		interface_data_t int_data;
		guint64 time_units_per_second;
		gint id;

		id = (gint)wblock.data.packet.interface_id;
		int_data = g_array_index(pcapng->interface_data, interface_data_t, id);
		time_units_per_second = int_data.time_units_per_second;
		wth->phdr.pkt_encap = int_data.wtap_encap;
		wth->phdr.ts.secs = (time_t)(ts / time_units_per_second);
		wth->phdr.ts.nsecs = (int)(((ts % time_units_per_second) * 1000000000) / time_units_per_second);
	} else {
		wth->phdr.pkt_encap = WTAP_ENCAP_UNKNOWN;
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("pcapng: interface index %u is not less than interface count %u.",
		    wblock.data.packet.interface_id, pcapng->number_of_interfaces);
		wth->data_offset = *data_offset + bytes_read;
		pcapng_debug1("pcapng_read: wth->data_offset is finally %" G_GINT64_MODIFIER "u", wth->data_offset);
		return FALSE;
	}

	/*pcapng_debug2("Read length: %u Packet length: %u", bytes_read, wth->phdr.caplen);*/
	wth->data_offset = *data_offset + bytes_read;
	pcapng_debug1("pcapng_read: wth->data_offset is finally %" G_GINT64_MODIFIER "u", wth->data_offset);

	return TRUE;
}


/* classic wtap: seek to file position and read packet */
static gboolean
pcapng_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length _U_,
    int *err, gchar **err_info)
{
	pcapng_t *pcapng = (pcapng_t *)wth->priv;
	guint64 bytes_read64;
	int bytes_read;
	wtapng_block_t wblock;


	/* seek to the right file position */
	bytes_read64 = file_seek(wth->random_fh, seek_off, SEEK_SET, err);
	if (bytes_read64 <= 0) {
		return FALSE;	/* Seek error */
	}
	pcapng_debug1("pcapng_seek_read: reading at offset %" G_GINT64_MODIFIER "u", seek_off);

	wblock.frame_buffer = pd;
	wblock.pseudo_header = pseudo_header;
	wblock.packet_header = &wth->phdr;
	wblock.file_encap = &wth->file_encap;

	/* read the block */
	bytes_read = pcapng_read_block(wth->random_fh, FALSE, pcapng, &wblock, err, err_info);
	if (bytes_read <= 0) {
		*err = file_error(wth->random_fh, err_info);
		pcapng_debug3("pcapng_seek_read: couldn't read packet block (err=%d, errno=%d, bytes_read=%d).",
		              *err, errno, bytes_read);
		return FALSE;
	}

	/* block must be a "Packet Block" or an "Enhanced Packet Block" */
	if (wblock.type != BLOCK_TYPE_PB && wblock.type != BLOCK_TYPE_EPB) {
		pcapng_debug1("pcapng_seek_read: block type %u not PB/EPB", wblock.type);
		return FALSE;
	}

	return TRUE;
}


/* classic wtap: close capture file */
static void
pcapng_close(wtap *wth)
{
	pcapng_t *pcapng = (pcapng_t *)wth->priv;

	pcapng_debug0("pcapng_close: closing file");
	if (pcapng->interface_data != NULL) {
		g_array_free(pcapng->interface_data, TRUE);
	}
}



typedef struct {
	GArray *interface_data;
	guint number_of_interfaces;
	struct addrinfo *addrinfo_list_last;
} pcapng_dump_t;

static gboolean
pcapng_write_section_header_block(wtap_dumper *wdh, wtapng_block_t *wblock, int *err)
{
	pcapng_block_header_t bh;
	pcapng_section_header_block_t shb;


	/* write block header */
	bh.block_type = wblock->type;
	bh.block_total_length = sizeof(bh) + sizeof(shb) /* + options */ + 4;

	if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
		return FALSE;
	wdh->bytes_dumped += sizeof bh;

	/* write block fixed content */
	/* XXX - get these values from wblock? */
	shb.magic = 0x1A2B3C4D;
	shb.version_major = 1;
	shb.version_minor = 0;
	shb.section_length = -1;

	if (!wtap_dump_file_write(wdh, &shb, sizeof shb, err))
		return FALSE;
	wdh->bytes_dumped += sizeof shb;

	/* XXX - write (optional) block options */

	/* write block footer */
	if (!wtap_dump_file_write(wdh, &bh.block_total_length,
	    sizeof bh.block_total_length, err))
		return FALSE;
	wdh->bytes_dumped += sizeof bh.block_total_length;

	return TRUE;
}



static gboolean
pcapng_write_if_descr_block(wtap_dumper *wdh, wtapng_block_t *wblock, int *err)
{
	pcapng_block_header_t bh;
	pcapng_interface_description_block_t idb;


	pcapng_debug3("pcapng_write_if_descr_block: encap = %d (%s), snaplen = %d",
	              wblock->data.if_descr.link_type,
	              wtap_encap_string(wtap_pcap_encap_to_wtap_encap(wblock->data.if_descr.link_type)),
	              wblock->data.if_descr.snap_len);

	if (wblock->data.if_descr.link_type == (guint16)-1) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return FALSE;
	}

	/* write block header */
	bh.block_type = wblock->type;
	bh.block_total_length = sizeof(bh) + sizeof(idb) /* + options */ + 4;

	if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
		return FALSE;
	wdh->bytes_dumped += sizeof bh;

	/* write block fixed content */
	idb.linktype	= wblock->data.if_descr.link_type;
	idb.reserved	= 0;
	idb.snaplen	= wblock->data.if_descr.snap_len;

	if (!wtap_dump_file_write(wdh, &idb, sizeof idb, err))
		return FALSE;
	wdh->bytes_dumped += sizeof idb;

	/* XXX - write (optional) block options */

	/* write block footer */
	if (!wtap_dump_file_write(wdh, &bh.block_total_length,
	    sizeof bh.block_total_length, err))
		return FALSE;
	wdh->bytes_dumped += sizeof bh.block_total_length;

	return TRUE;
}


static gboolean
pcapng_write_packet_block(wtap_dumper *wdh, wtapng_block_t *wblock, int *err)
{
	pcapng_block_header_t bh;
	pcapng_enhanced_packet_block_t epb;
	const guint32 zero_pad = 0;
	guint32 pad_len;
	guint32 phdr_len;

	phdr_len = (guint32)pcap_get_phdr_size(wblock->data.packet.wtap_encap, wblock->pseudo_header);
	if ((phdr_len + wblock->data.packet.cap_len) % 4) {
		pad_len = 4 - ((phdr_len + wblock->data.packet.cap_len) % 4);
	} else {
		pad_len = 0;
	}

	/* write (enhanced) packet block header */
	bh.block_type = wblock->type;
	bh.block_total_length = (guint32)sizeof(bh) + (guint32)sizeof(epb) + phdr_len + wblock->data.packet.cap_len + pad_len /* + options */ + 4;

	if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
		return FALSE;
	wdh->bytes_dumped += sizeof bh;

	/* write block fixed content */
	epb.interface_id	= wblock->data.packet.interface_id;
	epb.timestamp_high	= wblock->data.packet.ts_high;
	epb.timestamp_low	= wblock->data.packet.ts_low;
	epb.captured_len	= wblock->data.packet.cap_len + phdr_len;
	epb.packet_len		= wblock->data.packet.packet_len + phdr_len;

	if (!wtap_dump_file_write(wdh, &epb, sizeof epb, err))
		return FALSE;
	wdh->bytes_dumped += sizeof epb;

	/* write pseudo header */
	if (!pcap_write_phdr(wdh, wblock->data.packet.wtap_encap, wblock->pseudo_header, err)) {
		return FALSE;
	}
	wdh->bytes_dumped += phdr_len;

	/* write packet data */
	if (!wtap_dump_file_write(wdh, wblock->frame_buffer,
	    wblock->data.packet.cap_len, err))
		return FALSE;
	wdh->bytes_dumped += wblock->data.packet.cap_len;

	/* write padding (if any) */
	if (pad_len != 0) {
		if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
			return FALSE;
		wdh->bytes_dumped += pad_len;
	}

	/* XXX - write (optional) block options */

	/* write block footer */
	if (!wtap_dump_file_write(wdh, &bh.block_total_length,
	    sizeof bh.block_total_length, err))
		return FALSE;
	wdh->bytes_dumped += sizeof bh.block_total_length;

	return TRUE;
}

/* Arbitrary. */
#define NRES_REC_MAX_SIZE ((WTAP_MAX_PACKET_SIZE * 4) + 16)
static gboolean
pcapng_write_name_resolution_block(wtap_dumper *wdh, pcapng_dump_t *pcapng, int *err)
{
	pcapng_block_header_t bh;
	pcapng_name_resolution_block_t nrb;
	struct addrinfo *ai;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	guint8 *rec_data;
	gint rec_off, namelen, tot_rec_len;

	if (! pcapng->addrinfo_list_last || ! pcapng->addrinfo_list_last->ai_next) {
		return TRUE;
	}

	rec_off = 8; /* block type + block total length */
	bh.block_type = BLOCK_TYPE_NRB;
	bh.block_total_length = rec_off + 8; /* end-of-record + block total length */
	rec_data = g_malloc(NRES_REC_MAX_SIZE);

	for (; pcapng->addrinfo_list_last && pcapng->addrinfo_list_last->ai_next; pcapng->addrinfo_list_last = pcapng->addrinfo_list_last->ai_next ) {
		ai = pcapng->addrinfo_list_last->ai_next; /* Skips over the first (dummy) entry */
		namelen = (gint)strlen(ai->ai_canonname) + 1;
		if (ai->ai_family == AF_INET) {
			nrb.record_type = NRES_IP4RECORD;
			nrb.record_len = 4 + namelen;
			tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);
			bh.block_total_length += tot_rec_len;

			if (rec_off + tot_rec_len > NRES_REC_MAX_SIZE)
				break;

			/*
			 * The joys of BSD sockaddrs.  In practice, this
			 * cast is alignment-safe.
			 */
			sa4 = (struct sockaddr_in *)(void *)ai->ai_addr;
			memcpy(rec_data + rec_off, &nrb, sizeof(nrb));
			rec_off += 4;

			memcpy(rec_data + rec_off, &(sa4->sin_addr.s_addr), 4);
			rec_off += 4;

			memcpy(rec_data + rec_off, ai->ai_canonname, namelen);
			rec_off += namelen;

			memset(rec_data + rec_off, 0, PADDING4(namelen));
			rec_off += PADDING4(namelen);
			pcapng_debug1("NRB: added IPv4 record for %s", ai->ai_canonname);
		} else if (ai->ai_family == AF_INET6) {
			nrb.record_type = NRES_IP6RECORD;
			nrb.record_len = 16 + namelen;
			tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);
			bh.block_total_length += tot_rec_len;

			if (rec_off + tot_rec_len > NRES_REC_MAX_SIZE)
				break;

			/*
			 * The joys of BSD sockaddrs.  In practice, this
			 * cast is alignment-safe.
			 */
			sa6 = (struct sockaddr_in6 *)(void *)ai->ai_addr;
			memcpy(rec_data + rec_off, &nrb, sizeof(nrb));
			rec_off += 4;

			memcpy(rec_data + rec_off, sa6->sin6_addr.s6_addr, 16);
			rec_off += 16;

			memcpy(rec_data + rec_off, ai->ai_canonname, namelen);
			rec_off += namelen;

			memset(rec_data + rec_off, 0, PADDING4(namelen));
			rec_off += PADDING4(namelen);
			pcapng_debug1("NRB: added IPv6 record for %s", ai->ai_canonname);
		}
	}

	/* We know the total length now; copy the block header. */
	memcpy(rec_data, &bh, sizeof(bh));

	/* End of record */
	memset(rec_data + rec_off, 0, 4);
	rec_off += 4;

	memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

	if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
		g_free(rec_data);
		return FALSE;
	}

	g_free(rec_data);
	wdh->bytes_dumped += bh.block_total_length;
	return TRUE;
}


static gboolean
pcapng_write_block(wtap_dumper *wdh, /*pcapng_t *pn, */wtapng_block_t *wblock, int *err)
{
	switch(wblock->type) {
	    case(BLOCK_TYPE_SHB):
		return pcapng_write_section_header_block(wdh, wblock, err);
	    case(BLOCK_TYPE_IDB):
		return pcapng_write_if_descr_block(wdh, wblock, err);
	    case(BLOCK_TYPE_PB):
		/* Packet Block is obsolete */
		return FALSE;
	    case(BLOCK_TYPE_EPB):
		return pcapng_write_packet_block(wdh, wblock, err);
	    default:
		pcapng_debug1("Unknown block_type: 0x%x", wblock->type);
		return FALSE;
	}
}


static guint32
pcapng_lookup_interface_id_by_encap(int wtap_encap, wtap_dumper *wdh)
{
	gint i;
	interface_data_t int_data;
	pcapng_dump_t *pcapng = (pcapng_dump_t *)wdh->priv;

	for(i = 0; i < (gint)pcapng->number_of_interfaces; i++) {
		int_data = g_array_index(pcapng->interface_data, interface_data_t, i);
		if (wtap_encap == int_data.wtap_encap) {
			return (guint32)i;
		}
	}
	return G_MAXUINT32;
}


static gboolean pcapng_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header,
	const guint8 *pd, int *err)
{
	wtapng_block_t wblock;
	interface_data_t int_data;
	guint32 interface_id;
	guint64 ts;
	pcapng_dump_t *pcapng = (pcapng_dump_t *)wdh->priv;

	pcapng_debug2("pcapng_dump: encap = %d (%s)",
	              phdr->pkt_encap,
	              wtap_encap_string(phdr->pkt_encap));

	if (!pcapng->addrinfo_list_last)
		pcapng->addrinfo_list_last = wdh->addrinfo_list;

	interface_id = pcapng_lookup_interface_id_by_encap(phdr->pkt_encap, wdh);
	if (interface_id == G_MAXUINT32) {
		/* write the interface description block */
		wblock.frame_buffer            = NULL;
		wblock.pseudo_header           = NULL;
		wblock.packet_header           = NULL;
		wblock.file_encap              = NULL;
		wblock.type                    = BLOCK_TYPE_IDB;
		wblock.data.if_descr.link_type = wtap_wtap_encap_to_pcap_encap(phdr->pkt_encap);
		wblock.data.if_descr.snap_len = (wdh->snaplen != 0) ? wdh->snaplen :
								      WTAP_MAX_PACKET_SIZE; /* XXX */

		/* XXX - options unused */
		wblock.data.if_descr.if_speed   = -1;
		wblock.data.if_descr.if_tsresol = 6;    /* default: usec */
		wblock.data.if_descr.if_os      = NULL;
		wblock.data.if_descr.if_fcslen  = -1;

		if (!pcapng_write_block(wdh, &wblock, err)) {
			return FALSE;
		}

		interface_id = pcapng->number_of_interfaces;
		int_data.wtap_encap = phdr->pkt_encap;
		int_data.time_units_per_second = 0;
		g_array_append_val(pcapng->interface_data, int_data);
		pcapng->number_of_interfaces++;

		pcapng_debug3("pcapng_dump: added interface description block with index %u for encap = %d (%s).",
		              interface_id,
		              phdr->pkt_encap,
		              wtap_encap_string(phdr->pkt_encap));
	}

	/* Flush any hostname resolution info we may have */
	while (pcapng->addrinfo_list_last && pcapng->addrinfo_list_last->ai_next) {
		pcapng_write_name_resolution_block(wdh, pcapng, err);
	}

	wblock.frame_buffer  = pd;
	wblock.pseudo_header = pseudo_header;
	wblock.packet_header = NULL;
	wblock.file_encap    = NULL;

	/* write the (enhanced) packet block */
	wblock.type = BLOCK_TYPE_EPB;

	/* default is to write out in microsecond resolution */
	ts = (((guint64)phdr->ts.secs) * 1000000) + (phdr->ts.nsecs / 1000);

	/* Split the 64-bit timestamp into two 32-bit pieces */
        wblock.data.packet.ts_high      = (guint32)(ts >> 32);
        wblock.data.packet.ts_low       = (guint32)ts;

	wblock.data.packet.cap_len      = phdr->caplen;
	wblock.data.packet.packet_len   = phdr->len;
	wblock.data.packet.interface_id = interface_id;
	wblock.data.packet.wtap_encap   = phdr->pkt_encap;

	/* currently unused */
	wblock.data.packet.drop_count   = -1;
	wblock.data.packet.opt_comment  = NULL;

	if (!pcapng_write_block(wdh, &wblock, err)) {
		return FALSE;
	}

	return TRUE;
}


/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean pcapng_dump_close(wtap_dumper *wdh, int *err _U_)
{
	pcapng_dump_t *pcapng = (pcapng_dump_t *)wdh->priv;

	pcapng_debug0("pcapng_dump_close");
	g_array_free(pcapng->interface_data, TRUE);
	pcapng->number_of_interfaces = 0;
	return TRUE;
}


/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean
pcapng_dump_open(wtap_dumper *wdh, int *err)
{
	wtapng_block_t wblock;
	pcapng_dump_t *pcapng;

	wblock.frame_buffer  = NULL;
	wblock.pseudo_header = NULL;
	wblock.packet_header = NULL;
	wblock.file_encap    = NULL;

	pcapng_debug0("pcapng_dump_open");
	/* This is a pcapng file */
	wdh->subtype_write = pcapng_dump;
	wdh->subtype_close = pcapng_dump_close;
	pcapng = (pcapng_dump_t *)g_malloc0(sizeof(pcapng_dump_t));
	wdh->priv = (void *)pcapng;
	pcapng->interface_data = g_array_new(FALSE, FALSE, sizeof(interface_data_t));

	/* write the section header block */
	wblock.type = BLOCK_TYPE_SHB;
	wblock.data.section.section_length = -1;

	/* XXX - options unused */
	wblock.data.section.opt_comment   = NULL;
	wblock.data.section.shb_hardware  = NULL;
	wblock.data.section.shb_os        = NULL;
	wblock.data.section.shb_user_appl = NULL;

	if (!pcapng_write_block(wdh, &wblock, err)) {
		return FALSE;
	}
	pcapng_debug0("pcapng_dump_open: wrote section header block.");

	return TRUE;
}


/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int pcapng_dump_can_write_encap(int wtap_encap)
{
	pcapng_debug2("pcapng_dump_can_write_encap: encap = %d (%s)",
	              wtap_encap,
	              wtap_encap_string(wtap_encap));

	/* Per-packet encapsulations is supported. */
	if (wtap_encap == WTAP_ENCAP_PER_PACKET)
		return 0;

	/* Make sure we can figure out this DLT type */
	if (wtap_wtap_encap_to_pcap_encap(wtap_encap) == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}
