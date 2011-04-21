/* netmon.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "atm.h"
#include "pcap-encap.h"
#include "netmon.h"

/* The file at
 *
 *	ftp://ftp.microsoft.com/developr/drg/cifs/cifs/Bhfile.zip
 *
 * contains "STRUCT.H", which declares the typedef CAPTUREFILE_HEADER
 * for the header of a Microsoft Network Monitor capture file.
 */

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number in Network Monitor 1.x files. */
static const char netmon_1_x_magic[] = {
	'R', 'T', 'S', 'S'
};

/* Magic number in Network Monitor 2.x files. */
static const char netmon_2_x_magic[] = {
	'G', 'M', 'B', 'U'
};

/* Network Monitor file header (minus magic number). */
struct netmon_hdr {
	guint8	ver_minor;	/* minor version number */
	guint8	ver_major;	/* major version number */
	guint16	network;	/* network type */
	guint16	ts_year;	/* year of capture start */
	guint16	ts_month;	/* month of capture start (January = 1) */
	guint16	ts_dow;		/* day of week of capture start (Sun = 0) */
	guint16	ts_day;		/* day of month of capture start */
	guint16	ts_hour;	/* hour of capture start */
	guint16	ts_min;		/* minute of capture start */
	guint16	ts_sec;		/* second of capture start */
	guint16	ts_msec;	/* millisecond of capture start */
	guint32	frametableoffset;	/* frame index table offset */
	guint32	frametablelength;	/* frame index table size */
	guint32	userdataoffset;		/* user data offset */
	guint32	userdatalength;		/* user data size */
	guint32	commentdataoffset;	/* comment data offset */
	guint32	commentdatalength;	/* comment data size */
	guint32	statisticsoffset;	/* offset to statistics structure */
	guint32	statisticslength;	/* length of statistics structure */
	guint32	networkinfooffset;	/* offset to network info structure */
	guint32	networkinfolength;	/* length of network info structure */
};

/* Network Monitor 1.x record header; not defined in STRUCT.H, but deduced by
 * looking at capture files. */
struct netmonrec_1_x_hdr {
	guint32	ts_delta;	/* time stamp - msecs since start of capture */
	guint16	orig_len;	/* actual length of packet */
	guint16	incl_len;	/* number of octets captured in file */
};

/* Network Monitor 2.x record header; not defined in STRUCT.H, but deduced by
 * looking at capture files. */
struct netmonrec_2_x_hdr {
	guint32	ts_delta_lo;	/* time stamp - usecs since start of capture */
	guint32	ts_delta_hi;	/* time stamp - usecs since start of capture */
	guint32	orig_len;	/* actual length of packet */
	guint32	incl_len;	/* number of octets captured in file */
};

/*
 * Network Monitor 2.1 and later record trailers; documented in the Network
 * Monitor 3.x help files, for 3.3 and later, although they don't clearly
 * state how the trailer format changes from version to version.
 *
 * Some fields are multi-byte integers, but they're not aligned on their
 * natural boundaries.
 */
struct netmonrec_2_1_trlr {
	guint8 network[2];		/* network type for this packet */
};

struct netmonrec_2_2_trlr {
	guint8 network[2];		/* network type for this packet */
	guint8 process_info_index[4];	/* index into the process info table */
};

struct netmonrec_2_3_trlr {
	guint8 network[2];		/* network type for this packet */
	guint8 process_info_index[4];	/* index into the process info table */
	guint8 utc_timestamp[8];	/* packet time stamp, as .1 us units since January 1, 1601, 00:00:00 UTC */
	guint8 timezone_index;		/* index of time zone information */
};

/*
 * The link-layer header on ATM packets.
 */
struct netmon_atm_hdr {
	guint8	dest[6];	/* "Destination address" - what is it? */
	guint8	src[6];		/* "Source address" - what is it? */
	guint16	vpi;		/* VPI */
	guint16	vci;		/* VCI */
};

typedef struct {
	time_t	start_secs;
	guint32	start_usecs;
	guint8	version_major;
	guint8	version_minor;
	guint32 *frame_table;
	guint32	frame_table_size;
	guint	current_frame;
} netmon_t;

/*
 * XXX - at least in some NetMon 3.4 VPN captures, the per-packet
 * link-layer type is 0, but the packets have Ethernet headers.
 * We handle this by mapping 0 to WTAP_ENCAP_ETHERNET; should we,
 * instead, use the per-file link-layer type?
 */
static const int netmon_encap[] = {
	WTAP_ENCAP_ETHERNET,
	WTAP_ENCAP_ETHERNET,
	WTAP_ENCAP_TOKEN_RING,
	WTAP_ENCAP_FDDI_BITSWAPPED,
	WTAP_ENCAP_ATM_PDUS,	/* NDIS WAN - this is what's used for ATM */
	WTAP_ENCAP_UNKNOWN,	/* NDIS LocalTalk */
	WTAP_ENCAP_IEEE802_11_NETMON_RADIO,
				/* NDIS "DIX" - used for 802.11 */
	WTAP_ENCAP_UNKNOWN,	/* NDIS ARCNET raw */
	WTAP_ENCAP_UNKNOWN,	/* NDIS ARCNET 878.2 */
	WTAP_ENCAP_UNKNOWN,	/* NDIS ATM (no, this is NOT used for ATM) */
	WTAP_ENCAP_UNKNOWN,	/* NDIS Wireless WAN */
	WTAP_ENCAP_UNKNOWN	/* NDIS IrDA */
};
#define NUM_NETMON_ENCAPS (sizeof netmon_encap / sizeof netmon_encap[0])

/*
 * Special link-layer types.
 */
#define NETMON_NET_PCAP_BASE		0xE000
#define NETMON_NET_NETEVENT		0xFFE0
#define NETMON_NET_NETWORK_INFO_EX	0xFFFB
#define NETMON_NET_PAYLOAD_HEADER	0xFFFC
#define NETMON_NET_NETWORK_INFO		0xFFFD
#define NETMON_NET_DNS_CACHE		0xFFFE
#define NETMON_NET_NETMON_FILTER	0xFFFF

static gboolean netmon_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean netmon_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);
static gboolean netmon_read_atm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean netmon_read_rec_data(FILE_T fh, guchar *pd, int length,
    int *err, gchar **err_info);
static void netmon_sequential_close(wtap *wth);
static gboolean netmon_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);
static gboolean netmon_dump_close(wtap_dumper *wdh, int *err);

int netmon_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[sizeof netmon_1_x_magic];
	struct netmon_hdr hdr;
	int file_type;
	struct tm tm;
	int frame_table_offset;
	guint32 frame_table_length;
	guint32 frame_table_size;
	guint32 *frame_table;
#ifdef WORDS_BIGENDIAN
	unsigned int i;
#endif
	netmon_t *netmon;

	/* Read in the string that should be at the start of a Network
	 * Monitor file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	if (memcmp(magic, netmon_1_x_magic, sizeof netmon_1_x_magic) != 0
	 && memcmp(magic, netmon_2_x_magic, sizeof netmon_1_x_magic) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	switch (hdr.ver_major) {

	case 1:
		file_type = WTAP_FILE_NETMON_1_x;
		break;

	case 2:
		file_type = WTAP_FILE_NETMON_2_x;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("netmon: major version %u unsupported", hdr.ver_major);
		return -1;
	}

	hdr.network = pletohs(&hdr.network);
	if (hdr.network >= NUM_NETMON_ENCAPS
	    || netmon_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
		    hdr.network);
		return -1;
	}

	/* This is a netmon file */
	wth->file_type = file_type;
	netmon = (netmon_t *)g_malloc(sizeof(netmon_t));
	wth->priv = (void *)netmon;
	wth->subtype_read = netmon_read;
	wth->subtype_seek_read = netmon_seek_read;
	wth->subtype_sequential_close = netmon_sequential_close;

	/* NetMon capture file formats v2.1+ use per-packet encapsulation types.  NetMon 3 sets the value in
	 * the header to 1 (Ethernet) for backwards compability. */
	if((hdr.ver_major == 2 && hdr.ver_minor >= 1) || hdr.ver_major > 2)
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
	else
		wth->file_encap = netmon_encap[hdr.network];

	wth->snapshot_length = 0;	/* not available in header */
	/*
	 * Convert the time stamp to a "time_t" and a number of
	 * milliseconds.
	 */
	tm.tm_year = pletohs(&hdr.ts_year) - 1900;
	tm.tm_mon = pletohs(&hdr.ts_month) - 1;
	tm.tm_mday = pletohs(&hdr.ts_day);
	tm.tm_hour = pletohs(&hdr.ts_hour);
	tm.tm_min = pletohs(&hdr.ts_min);
	tm.tm_sec = pletohs(&hdr.ts_sec);
	tm.tm_isdst = -1;
	netmon->start_secs = mktime(&tm);
	/*
	 * XXX - what if "secs" is -1?  Unlikely, but if the capture was
	 * done in a time zone that switches between standard and summer
	 * time sometime other than when we do, and thus the time was one
	 * that doesn't exist here because a switch from standard to summer
	 * time zips over it, it could happen.
	 *
	 * On the other hand, if the capture was done in a different time
	 * zone, this won't work right anyway; unfortunately, the time
	 * zone isn't stored in the capture file (why the hell didn't
	 * they stuff a FILETIME, which is the number of 100-nanosecond
	 * intervals since 1601-01-01 00:00:00 "UTC", there, instead
	 * of stuffing a SYSTEMTIME, which is time-zone-dependent, there?).
	 */
	netmon->start_usecs = pletohs(&hdr.ts_msec)*1000;

	netmon->version_major = hdr.ver_major;
	netmon->version_minor = hdr.ver_minor;

	/*
	 * Get the offset of the frame index table.
	 */
	frame_table_offset = pletohl(&hdr.frametableoffset);

	/*
	 * It appears that some NetMon 2.x files don't have the
	 * first packet starting exactly 128 bytes into the file.
	 *
	 * Furthermore, it also appears that there are "holes" in
	 * the file, i.e. frame N+1 doesn't always follow immediately
	 * after frame N.
	 *
	 * Therefore, we must read the frame table, and use the offsets
	 * in it as the offsets of the frames.
	 */
	frame_table_length = pletohl(&hdr.frametablelength);
	frame_table_size = frame_table_length / (guint32)sizeof (guint32);
	if ((frame_table_size * sizeof (guint32)) != frame_table_length) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which is not a multiple of the size of an entry",
		    frame_table_length);
		g_free(netmon);
		return -1;
	}
	if (frame_table_size == 0) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which means it's less than one entry in size",
		    frame_table_length);
		g_free(netmon);
		return -1;
	}
	if (file_seek(wth->fh, frame_table_offset, SEEK_SET, err) == -1) {
		g_free(netmon);
		return -1;
	}
	frame_table = g_malloc(frame_table_length);
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(frame_table, frame_table_length, wth->fh);
	if ((guint32)bytes_read != frame_table_length) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		g_free(frame_table);
		g_free(netmon);
		return -1;
	}
	netmon->frame_table_size = frame_table_size;
	netmon->frame_table = frame_table;

#ifdef WORDS_BIGENDIAN
	/*
	 * OK, now byte-swap the frame table.
	 */
	for (i = 0; i < frame_table_size; i++)
		frame_table[i] = pletohl(&frame_table[i]);
#endif

	/* Set up to start reading at the first frame. */
	netmon->current_frame = 0;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;

	return 1;
}

/* Read the next packet */
static gboolean netmon_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	netmon_t *netmon = (netmon_t *)wth->priv;
	guint32	packet_size = 0;
	guint32 orig_size = 0;
	int	bytes_read;
	union {
		struct netmonrec_1_x_hdr hdr_1_x;
		struct netmonrec_2_x_hdr hdr_2_x;
	}	hdr;
	union {
		struct netmonrec_2_1_trlr trlr_2_1;
		struct netmonrec_2_2_trlr trlr_2_2;
		struct netmonrec_2_3_trlr trlr_2_3;
	}	trlr;
	int	hdr_size = 0;
	int	trlr_size = 0;
	int	rec_offset;
	guint8	*data_ptr;
	gint64	delta = 0;	/* signed - frame times can be before the nominal start */
	time_t	secs;
	guint32	usecs;
	double	t;
	guint16 network;

again:
	/* Have we reached the end of the packet data? */
	if (netmon->current_frame >= netmon->frame_table_size) {
		/* Yes.  We won't need the frame table any more;
		   free it. */
		g_free(netmon->frame_table);
		netmon->frame_table = NULL;
		*err = 0;	/* it's just an EOF, not an error */
		return FALSE;
	}

	/* Seek to the beginning of the current record, if we're
	   not there already (seeking to the current position
	   may still cause a seek and a read of the underlying file,
	   so we don't want to do it unconditionally).

	   Yes, the current record could be before the previous
	   record.  At least some captures put the trailer record
	   with statistics as the first physical record in the
	   file, but set the frame table up so it's the last
	   record in sequence. */
	rec_offset = netmon->frame_table[netmon->current_frame];
	if (wth->data_offset != rec_offset) {
		wth->data_offset = rec_offset;
		if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1)
			return FALSE;
	}
	netmon->current_frame++;

	/* Read record header. */
	switch (netmon->version_major) {

	case 1:
		hdr_size = sizeof (struct netmonrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netmonrec_2_x_hdr);
		break;
	}
	errno = WTAP_ERR_CANT_READ;

	bytes_read = file_read(&hdr, hdr_size, wth->fh);
	if (bytes_read != hdr_size) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}
	wth->data_offset += hdr_size;

	switch (netmon->version_major) {

	case 1:
		orig_size = pletohs(&hdr.hdr_1_x.orig_len);
		packet_size = pletohs(&hdr.hdr_1_x.incl_len);
		break;

	case 2:
		orig_size = pletohl(&hdr.hdr_2_x.orig_len);
		packet_size = pletohl(&hdr.hdr_2_x.incl_len);
		break;
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("netmon: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	*data_offset = wth->data_offset;

	/*
	 * If this is an ATM packet, the first
	 * "sizeof (struct netmon_atm_hdr)" bytes have destination and
	 * source addresses (6 bytes - MAC addresses of some sort?)
	 * and the VPI and VCI; read them and generate the pseudo-header
	 * from them.
	 */
	switch (wth->file_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		if (packet_size < sizeof (struct netmon_atm_hdr)) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("netmon: ATM file has a %u-byte packet, too small to have even an ATM pseudo-header",
			    packet_size);
			return FALSE;
		}
		if (!netmon_read_atm_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= (guint)sizeof (struct netmon_atm_hdr);
		packet_size -= (guint)sizeof (struct netmon_atm_hdr);
		wth->data_offset += sizeof (struct netmon_atm_hdr);
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * We assume there's no FCS in this frame.
		 */
		wth->pseudo_header.eth.fcs_len = 0;
		break;
	}

	buffer_assure_space(wth->frame_buffer, packet_size);
	data_ptr = buffer_start_ptr(wth->frame_buffer);
	if (!netmon_read_rec_data(wth->fh, data_ptr, packet_size, err,
	    err_info))
		return FALSE;	/* Read error */
	wth->data_offset += packet_size;

	t = (double)netmon->start_usecs;
	switch (netmon->version_major) {

	case 1:
		/*
		 * According to Paul Long, this offset is unsigned.
		 * It's 32 bits, so the maximum value will fit in
		 * a gint64 such as delta, even after multiplying
		 * it by 1000.
		 *
		 * pletohl() returns a guint32; we cast it to gint64
		 * before multiplying, so that the product doesn't
		 * overflow a guint32.
		 */
		delta = ((gint64)pletohl(&hdr.hdr_1_x.ts_delta))*1000;
		break;

	case 2:
		delta = pletohl(&hdr.hdr_2_x.ts_delta_lo)
		    | (((guint64)pletohl(&hdr.hdr_2_x.ts_delta_hi)) << 32);
		break;
	}
	t += (double)delta;
	secs = (time_t)(t/1000000);
	usecs = (guint32)(t - (double)secs*1000000);
	wth->phdr.ts.secs = netmon->start_secs + secs;
	wth->phdr.ts.nsecs = usecs * 1000;
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;

	/*
	 * Attempt to guess from the packet data, the VPI, and the VCI
	 * information about the type of traffic.
	 */
	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS) {
		atm_guess_traffic_type(data_ptr, packet_size,
		    &wth->pseudo_header);
	}

	/*
	 * For version 2.1 and later, there's additional information
	 * after the frame data.
	 */
	if ((netmon->version_major == 2 && netmon->version_minor >= 1) ||
	    netmon->version_major > 2) {
	    	if (netmon->version_major > 2) {
	    		/*
	    		 * Asssume 2.3 format, for now.
	    		 */
			trlr_size = sizeof (struct netmonrec_2_3_trlr);
	    	} else {
			switch (netmon->version_minor) {

			case 1:
				trlr_size = sizeof (struct netmonrec_2_1_trlr);
				break;

			case 2:
				trlr_size = sizeof (struct netmonrec_2_2_trlr);
				break;

			default:
				trlr_size = sizeof (struct netmonrec_2_3_trlr);
				break;
			}
		}
		errno = WTAP_ERR_CANT_READ;

		bytes_read = file_read(&trlr, trlr_size, wth->fh);
		if (bytes_read != trlr_size) {
			*err = file_error(wth->fh, err_info);
			if (*err == 0 && bytes_read != 0) {
				*err = WTAP_ERR_SHORT_READ;
			}
			return FALSE;
		}
		wth->data_offset += trlr_size;

		network = pletohs(trlr.trlr_2_1.network);
		if ((network & 0xF000) == NETMON_NET_PCAP_BASE) {
			/*
			 * Converted pcap file - the LINKTYPE_ value
			 * is the network value with 0xF000 masked off.
			 */
			network &= 0x0FFF;
			wth->phdr.pkt_encap =
			    wtap_pcap_encap_to_wtap_encap(network);
			if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
				*err = WTAP_ERR_UNSUPPORTED_ENCAP;
				*err_info = g_strdup_printf("netmon: converted pcap network type %u unknown or unsupported",
				    network);
				return FALSE;
			}
		} else if (network < NUM_NETMON_ENCAPS) {
			/*
			 * Regular NetMon encapsulation.
			 */
			wth->phdr.pkt_encap = netmon_encap[network];
			if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
				*err = WTAP_ERR_UNSUPPORTED_ENCAP;
				*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
				    network);
				return FALSE;
			}
		} else {
			/*
			 * Special packet type for metadata.
			 */
			switch (network) {

			case NETMON_NET_NETEVENT:
			case NETMON_NET_NETWORK_INFO_EX:
			case NETMON_NET_PAYLOAD_HEADER:
			case NETMON_NET_NETWORK_INFO:
			case NETMON_NET_DNS_CACHE:
			case NETMON_NET_NETMON_FILTER:
				/*
				 * Just ignore those record types, for
				 * now.  Read the next record.
				 */
				goto again;

			default:
				*err = WTAP_ERR_UNSUPPORTED_ENCAP;
				*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
				    network);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean
netmon_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		if (!netmon_read_atm_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * We assume there's no FCS in this frame.
		 */
		pseudo_header->eth.fcs_len = 0;
		break;
	}

	/*
	 * Read the packet data.
	 */
	if (!netmon_read_rec_data(wth->random_fh, pd, length, err, err_info))
		return FALSE;

	/*
	 * Attempt to guess from the packet data, the VPI, and the VCI
	 * information about the type of traffic.
	 */
	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS)
		atm_guess_traffic_type(pd, length, pseudo_header);

	return TRUE;
}

static gboolean
netmon_read_atm_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
    int *err, gchar **err_info)
{
	struct netmon_atm_hdr atm_phdr;
	int	bytes_read;
	guint16	vpi, vci;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&atm_phdr, sizeof (struct netmon_atm_hdr), fh);
	if (bytes_read != sizeof (struct netmon_atm_hdr)) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	vpi = g_ntohs(atm_phdr.vpi);
	vci = g_ntohs(atm_phdr.vci);

	pseudo_header->atm.vpi = vpi;
	pseudo_header->atm.vci = vci;

	/* We don't have this information */
	pseudo_header->atm.flags = 0;
	pseudo_header->atm.channel = 0;
	pseudo_header->atm.cells = 0;
	pseudo_header->atm.aal5t_u2u = 0;
	pseudo_header->atm.aal5t_len = 0;
	pseudo_header->atm.aal5t_chksum = 0;

	return TRUE;
}

static gboolean
netmon_read_rec_data(FILE_T fh, guchar *pd, int length, int *err,
    gchar **err_info)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/* Throw away the frame table used by the sequential I/O stream. */
static void
netmon_sequential_close(wtap *wth)
{
	netmon_t *netmon = (netmon_t *)wth->priv;

	if (netmon->frame_table != NULL) {
		g_free(netmon->frame_table);
		netmon->frame_table = NULL;
	}
}

typedef struct {
	gboolean got_first_record_time;
	struct wtap_nstime first_record_time;
	guint32	frame_table_offset;
	guint32	*frame_table;
	guint	frame_table_index;
	guint	frame_table_size;
} netmon_dump_t;

static const int wtap_encap[] = {
	-1,		/* WTAP_ENCAP_UNKNOWN -> unsupported */
	1,		/* WTAP_ENCAP_ETHERNET -> NDIS Ethernet */
	2,		/* WTAP_ENCAP_TOKEN_RING -> NDIS Token Ring */
	-1,		/* WTAP_ENCAP_SLIP -> unsupported */
	-1,		/* WTAP_ENCAP_PPP -> unsupported */
	3,		/* WTAP_ENCAP_FDDI -> NDIS FDDI */
	3,		/* WTAP_ENCAP_FDDI_BITSWAPPED -> NDIS FDDI */
	-1,		/* WTAP_ENCAP_RAW_IP -> unsupported */
	-1,		/* WTAP_ENCAP_ARCNET -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
	-1,		/* WTAP_ENCAP_LAPB -> unsupported*/
	4,		/* WTAP_ENCAP_ATM_PDUS -> NDIS WAN (*NOT* ATM!) */
	-1		/* WTAP_ENCAP_NULL -> unsupported */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int netmon_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (encap < 0 || (unsigned) encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean netmon_dump_open(wtap_dumper *wdh, int *err)
{
	netmon_dump_t *netmon;

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	if (fseek(wdh->fh, CAPTUREFILE_HEADER_SIZE, SEEK_SET) == -1) {
		*err = errno;
		return FALSE;
	}

	wdh->subtype_write = netmon_dump;
	wdh->subtype_close = netmon_dump_close;

	netmon = (netmon_dump_t *)g_malloc(sizeof(netmon_dump_t));
	wdh->priv = (void *)netmon;
	netmon->frame_table_offset = CAPTUREFILE_HEADER_SIZE;
	netmon->got_first_record_time = FALSE;
	netmon->frame_table = NULL;
	netmon->frame_table_index = 0;
	netmon->frame_table_size = 0;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netmon_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err)
{
	netmon_dump_t *netmon = (netmon_dump_t *)wdh->priv;
	struct netmonrec_1_x_hdr rec_1_x_hdr;
	struct netmonrec_2_x_hdr rec_2_x_hdr;
	char *hdrp;
	size_t hdr_size;
	double t;
	guint32 time_low, time_high;
	struct netmon_atm_hdr atm_hdr;
	int atm_hdrsize;

	/* NetMon files have a capture start time in the file header,
	   and have times relative to that in the packet headers;
	   pick the time of the first packet as the capture start
	   time. */
	if (!netmon->got_first_record_time) {
		netmon->first_record_time = phdr->ts;
		netmon->got_first_record_time = TRUE;
	}

	if (wdh->encap == WTAP_ENCAP_ATM_PDUS)
		atm_hdrsize = sizeof (struct netmon_atm_hdr);
	else
		atm_hdrsize = 0;
	switch (wdh->file_type) {

	case WTAP_FILE_NETMON_1_x:
		rec_1_x_hdr.ts_delta = htolel(
		    (phdr->ts.secs - netmon->first_record_time.secs)*1000
		  + (phdr->ts.nsecs - netmon->first_record_time.nsecs + 500000)/1000000);
		rec_1_x_hdr.orig_len = htoles(phdr->len + atm_hdrsize);
		rec_1_x_hdr.incl_len = htoles(phdr->caplen + atm_hdrsize);
		hdrp = (char *)&rec_1_x_hdr;
		hdr_size = sizeof rec_1_x_hdr;
		break;

	case WTAP_FILE_NETMON_2_x:
		/*
		 * Unfortunately, not all the platforms on which we run
		 * support 64-bit integral types, even though most do
		 * (even on 32-bit processors), so we do it in floating
		 * point.
		 */
		t = (phdr->ts.secs - netmon->first_record_time.secs)*1000000.0
		  + (phdr->ts.nsecs - netmon->first_record_time.nsecs) / 1000;
		time_high = (guint32) (t/4294967296.0);
		time_low  = (guint32) (t - (time_high*4294967296.0));
		rec_2_x_hdr.ts_delta_lo = htolel(time_low);
		rec_2_x_hdr.ts_delta_hi = htolel(time_high);
		rec_2_x_hdr.orig_len = htolel(phdr->len + atm_hdrsize);
		rec_2_x_hdr.incl_len = htolel(phdr->caplen + atm_hdrsize);
		hdrp = (char *)&rec_2_x_hdr;
		hdr_size = sizeof rec_2_x_hdr;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	if (!wtap_dump_file_write(wdh, hdrp, hdr_size, err))
		return FALSE;

	if (wdh->encap == WTAP_ENCAP_ATM_PDUS) {
		/*
		 * Write the ATM header.
		 * We supply all-zero destination and source addresses.
		 */
		memset(&atm_hdr.dest, 0, sizeof atm_hdr.dest);
		memset(&atm_hdr.src, 0, sizeof atm_hdr.src);
		atm_hdr.vpi = g_htons(pseudo_header->atm.vpi);
		atm_hdr.vci = g_htons(pseudo_header->atm.vci);
		if (!wtap_dump_file_write(wdh, &atm_hdr, sizeof atm_hdr, err))
			return FALSE;
	}

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;

	/*
	 * Stash the file offset of this frame.
	 */
	if (netmon->frame_table_size == 0) {
		/*
		 * Haven't yet allocated the buffer for the frame table.
		 */
		netmon->frame_table = g_malloc(1024 * sizeof *netmon->frame_table);
		netmon->frame_table_size = 1024;
	} else {
		/*
		 * We've allocated it; are we at the end?
		 */
		if (netmon->frame_table_index >= netmon->frame_table_size) {
			/*
			 * Yes - double the size of the frame table.
			 */
			netmon->frame_table_size *= 2;
			netmon->frame_table = g_realloc(netmon->frame_table,
			    netmon->frame_table_size * sizeof *netmon->frame_table);
		}
	}
	netmon->frame_table[netmon->frame_table_index] =
	    htolel(netmon->frame_table_offset);
	netmon->frame_table_index++;
	netmon->frame_table_offset += (int) hdr_size + phdr->caplen + atm_hdrsize;

	return TRUE;
}

/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netmon_dump_close(wtap_dumper *wdh, int *err)
{
	netmon_dump_t *netmon = (netmon_dump_t *)wdh->priv;
	size_t n_to_write;
	struct netmon_hdr file_hdr;
	const char *magicp;
	size_t magic_size;
	struct tm *tm;

	/* Write out the frame table.  "netmon->frame_table_index" is
	   the number of entries we've put into it. */
	n_to_write = netmon->frame_table_index * sizeof *netmon->frame_table;
	if (!wtap_dump_file_write(wdh, netmon->frame_table, n_to_write, err))
		return FALSE;

	/* Now go fix up the file header. */
	fseek(wdh->fh, 0, SEEK_SET);
	memset(&file_hdr, '\0', sizeof file_hdr);
	switch (wdh->file_type) {

	case WTAP_FILE_NETMON_1_x:
		magicp = netmon_1_x_magic;
		magic_size = sizeof netmon_1_x_magic;
		/* NetMon file version, for 1.x, is 1.1 */
		file_hdr.ver_major = 1;
		file_hdr.ver_minor = 1;
		break;

	case WTAP_FILE_NETMON_2_x:
		magicp = netmon_2_x_magic;
		magic_size = sizeof netmon_2_x_magic;
		/*
		 * NetMon file version, for 2.x, is 2.0;
		 * for 3.0, it's 2.1.
		 */
		file_hdr.ver_major = 2;
		file_hdr.ver_minor = 0;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		if (err != NULL)
			*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}
	if (!wtap_dump_file_write(wdh, magicp, magic_size, err))
		return FALSE;

	file_hdr.network = htoles(wtap_encap[wdh->encap]);
	tm = localtime(&netmon->first_record_time.secs);
	if (tm != NULL) {
		file_hdr.ts_year  = htoles(1900 + tm->tm_year);
		file_hdr.ts_month = htoles(tm->tm_mon + 1);
		file_hdr.ts_dow   = htoles(tm->tm_wday);
		file_hdr.ts_day   = htoles(tm->tm_mday);
		file_hdr.ts_hour  = htoles(tm->tm_hour);
		file_hdr.ts_min   = htoles(tm->tm_min);
		file_hdr.ts_sec   = htoles(tm->tm_sec);
	} else {
		file_hdr.ts_year  = htoles(1900 + 0);
		file_hdr.ts_month = htoles(0 + 1);
		file_hdr.ts_dow   = htoles(0);
		file_hdr.ts_day   = htoles(0);
		file_hdr.ts_hour  = htoles(0);
		file_hdr.ts_min   = htoles(0);
		file_hdr.ts_sec   = htoles(0);
	}
	file_hdr.ts_msec  = htoles(netmon->first_record_time.nsecs/1000000);
		/* XXX - what about rounding? */
	file_hdr.frametableoffset = htolel(netmon->frame_table_offset);
	file_hdr.frametablelength =
	    htolel(netmon->frame_table_index * sizeof *netmon->frame_table);
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
		return FALSE;

	return TRUE;
}
