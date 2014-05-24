/* netmon.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
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
 * for the header of a Microsoft Network Monitor 1.x capture file.
 *
 * The help files for Network Monitor 3.x document the 2.x file format.
 */

/* Capture file header, *including* magic number, is padded to 128 bytes. */
#define	CAPTUREFILE_HEADER_SIZE	128

/* Magic number size, for both 1.x and 2.x. */
#define MAGIC_SIZE	4

/* Magic number in Network Monitor 1.x files. */
static const char netmon_1_x_magic[MAGIC_SIZE] = {
	'R', 'T', 'S', 'S'
};

/* Magic number in Network Monitor 2.x files. */
static const char netmon_2_x_magic[MAGIC_SIZE] = {
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

/*
 * Network Monitor 2.x record header, as documented in NetMon 3.x's
 * help files.
 */
struct netmonrec_2_x_hdr {
	guint64	ts_delta;	/* time stamp - usecs since start of capture */
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
	guint32	start_nsecs;
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
	WTAP_ENCAP_UNKNOWN,	/* NDIS LocalTalk, but format 2.x uses it for IP-over-IEEE 1394 */
	WTAP_ENCAP_IEEE_802_11_NETMON,
				/* NDIS "DIX", but format 2.x uses it for 802.11 */
	WTAP_ENCAP_RAW_IP,	/* NDIS ARCNET raw, but format 2.x uses it for "Tunneling interfaces" */
	WTAP_ENCAP_RAW_IP,	/* NDIS ARCNET 878.2, but format 2.x uses it for "Wireless WAN" */
	WTAP_ENCAP_RAW_IP,	/* NDIS ATM (no, this is NOT used for ATM); format 2.x uses it for "Raw IP Frames" */
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
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static gboolean netmon_read_atm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static int netmon_read_rec_trailer(FILE_T fh, int trlr_size, int *err,
    gchar **err_info);
static void netmon_sequential_close(wtap *wth);
static gboolean netmon_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err);
static gboolean netmon_dump_close(wtap_dumper *wdh, int *err);

int netmon_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[MAGIC_SIZE];
	struct netmon_hdr hdr;
	int file_type;
	struct tm tm;
	guint32 frame_table_offset;
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
	bytes_read = file_read(magic, MAGIC_SIZE, wth->fh);
	if (bytes_read != MAGIC_SIZE) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return -1;
		return 0;
	}

	if (memcmp(magic, netmon_1_x_magic, MAGIC_SIZE) != 0 &&
	    memcmp(magic, netmon_2_x_magic, MAGIC_SIZE) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return -1;
	}

	switch (hdr.ver_major) {

	case 1:
		file_type = WTAP_FILE_TYPE_SUBTYPE_NETMON_1_x;
		break;

	case 2:
		file_type = WTAP_FILE_TYPE_SUBTYPE_NETMON_2_x;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("netmon: major version %u unsupported", hdr.ver_major);
		return -1;
	}

	hdr.network = pletoh16(&hdr.network);
	if (hdr.network >= NUM_NETMON_ENCAPS
	    || netmon_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
		    hdr.network);
		return -1;
	}

	/* This is a netmon file */
	wth->file_type_subtype = file_type;
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
	tm.tm_year = pletoh16(&hdr.ts_year) - 1900;
	tm.tm_mon = pletoh16(&hdr.ts_month) - 1;
	tm.tm_mday = pletoh16(&hdr.ts_day);
	tm.tm_hour = pletoh16(&hdr.ts_hour);
	tm.tm_min = pletoh16(&hdr.ts_min);
	tm.tm_sec = pletoh16(&hdr.ts_sec);
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
	netmon->start_nsecs = pletoh16(&hdr.ts_msec)*1000000;

	netmon->version_major = hdr.ver_major;
	netmon->version_minor = hdr.ver_minor;

	/*
	 * No frame table allocated yet; initialize these in case we
	 * get an error before allocating it or when trying to allocate
	 * it, so that the attempt to release the private data on failure
	 * doesn't crash.
	 */
	netmon->frame_table_size = 0;
	netmon->frame_table = NULL;

	/*
	 * Get the offset of the frame index table.
	 */
	frame_table_offset = pletoh32(&hdr.frametableoffset);

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
	frame_table_length = pletoh32(&hdr.frametablelength);
	frame_table_size = frame_table_length / (guint32)sizeof (guint32);
	if ((frame_table_size * sizeof (guint32)) != frame_table_length) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which is not a multiple of the size of an entry",
		    frame_table_length);
		return -1;
	}
	if (frame_table_size == 0) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which means it's less than one entry in size",
		    frame_table_length);
		return -1;
	}
	/*
	 * XXX - clamp the size of the frame table, so that we don't
	 * attempt to allocate a huge frame table and fail.
	 *
	 * Given that file offsets in the frame table are 32-bit,
	 * a NetMon file cannot be bigger than 2^32 bytes.
	 * Given that a NetMon 1.x-format packet header is 8 bytes,
	 * that means a NetMon file cannot have more than
	 * 512*2^20 packets.  We'll pick that as the limit for
	 * now; it's 1/8th of a 32-bit address space, which is
	 * probably not going to exhaust the address space all by
	 * itself, and probably won't exhaust the backing store.
	 */
	if (frame_table_size > 512*1024*1024) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which is larger than we support",
		    frame_table_length);
		return -1;
	}
	if (file_seek(wth->fh, frame_table_offset, SEEK_SET, err) == -1) {
		return -1;
	}
	frame_table = (guint32 *)g_try_malloc(frame_table_length);
	if (frame_table_length != 0 && frame_table == NULL) {
		*err = ENOMEM;	/* we assume we're out of memory */
		return -1;
	}
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(frame_table, frame_table_length, wth->fh);
	if ((guint32)bytes_read != frame_table_length) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		g_free(frame_table);
		return -1;
	}
	netmon->frame_table_size = frame_table_size;
	netmon->frame_table = frame_table;

#ifdef WORDS_BIGENDIAN
	/*
	 * OK, now byte-swap the frame table.
	 */
	for (i = 0; i < frame_table_size; i++)
		frame_table[i] = pletoh32(&frame_table[i]);
#endif

	/* Set up to start reading at the first frame. */
	netmon->current_frame = 0;
	switch (netmon->version_major) {

	case 1:
		/*
		 * Version 1.x of the file format supports
		 * millisecond precision.
		 */
		wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
		break;

	case 2:
		/*
		 * Version 1.x of the file format supports
		 * 100-nanosecond precision; we don't
		 * currently support that, so say
		 * "nanosecond precision" for now.
		 */
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;
	}
	return 1;
}

static size_t
netmon_trailer_size(netmon_t *netmon)
{
	if ((netmon->version_major == 2 && netmon->version_minor >= 1) ||
	    netmon->version_major > 2) {
	    	if (netmon->version_major > 2) {
	    		/*
	    		 * Asssume 2.3 format, for now.
	    		 */
			return sizeof (struct netmonrec_2_3_trlr);
	    	} else {
			switch (netmon->version_minor) {

			case 1:
				return sizeof (struct netmonrec_2_1_trlr);

			case 2:
				return sizeof (struct netmonrec_2_2_trlr);

			default:
				return sizeof (struct netmonrec_2_3_trlr);
			}
		}
	}
	return 0;	/* no trailer */
}

static void
netmon_set_pseudo_header_info(int pkt_encap, struct wtap_pkthdr *phdr,
    Buffer *buf)
{
	guint8 *pd = buffer_start_ptr(buf);

	switch (pkt_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		/*
		 * Attempt to guess from the packet data, the VPI, and
		 * the VCI information about the type of traffic.
		 */
		atm_guess_traffic_type(phdr, pd);
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * We assume there's no FCS in this frame.
		 */
		phdr->pseudo_header.eth.fcs_len = 0;
		break;

	case WTAP_ENCAP_IEEE_802_11_NETMON:
		/*
		 * It appears to be the case that management
		 * frames have an FCS and data frames don't;
		 * I'm not sure about control frames.  An
		 * "FCS length" of -2 means "NetMon weirdness".
		 */
		phdr->pseudo_header.ieee_802_11.fcs_len = -2;
		phdr->pseudo_header.ieee_802_11.decrypted = FALSE;
		break;
	}
}

static gboolean netmon_process_rec_header(wtap *wth, FILE_T fh,
    struct wtap_pkthdr *phdr, int *err, gchar **err_info)
{
	netmon_t *netmon = (netmon_t *)wth->priv;
	int	hdr_size = 0;
	union {
		struct netmonrec_1_x_hdr hdr_1_x;
		struct netmonrec_2_x_hdr hdr_2_x;
	}	hdr;
	int	bytes_read;
	gint64	delta = 0;	/* signed - frame times can be before the nominal start */
	gint64	t;
	time_t	secs;
	guint32	nsecs;
	guint32	packet_size = 0;
	guint32 orig_size = 0;

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

	bytes_read = file_read(&hdr, hdr_size, fh);
	if (bytes_read != hdr_size) {
		*err = file_error(fh, err_info);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return FALSE;
	}

	switch (netmon->version_major) {

	case 1:
		orig_size = pletoh16(&hdr.hdr_1_x.orig_len);
		packet_size = pletoh16(&hdr.hdr_1_x.incl_len);
		break;

	case 2:
		orig_size = pletoh32(&hdr.hdr_2_x.orig_len);
		packet_size = pletoh32(&hdr.hdr_2_x.incl_len);
		break;
	}
	if (packet_size > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	phdr->rec_type = REC_TYPE_PACKET;

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
			*err = WTAP_ERR_BAD_FILE;
			*err_info = g_strdup_printf("netmon: ATM file has a %u-byte packet, too small to have even an ATM pseudo-header",
			    packet_size);
			return FALSE;
		}
		if (!netmon_read_atm_pseudoheader(fh, &phdr->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= (guint)sizeof (struct netmon_atm_hdr);
		packet_size -= (guint)sizeof (struct netmon_atm_hdr);
		break;

	default:
		break;
	}

	switch (netmon->version_major) {

	case 1:
		/*
		 * According to Paul Long, this offset is unsigned.
		 * It's 32 bits, so the maximum value will fit in
		 * a gint64 such as delta, even after multiplying
		 * it by 1000000.
		 *
		 * pletoh32() returns a guint32; we cast it to gint64
		 * before multiplying, so that the product doesn't
		 * overflow a guint32.
		 */
		delta = ((gint64)pletoh32(&hdr.hdr_1_x.ts_delta))*1000000;
		break;

	case 2:
		/*
		 * OK, this is weird.  Microsoft's documentation
		 * says this is in microseconds and is a 64-bit
		 * unsigned number, but it can be negative; they
		 * say what appears to amount to "treat it as an
		 * unsigned number, multiply it by 10, and then
		 * interpret the resulting 64-bit quantity as a
		 * signed number".  That operation can turn a
		 * value with the uppermost bit 0 to a value with
		 * the uppermost bit 1, hence turning a large
		 * positive number-of-microseconds into a small
		 * negative number-of-100-nanosecond-increments.
		 */
		delta = pletoh64(&hdr.hdr_2_x.ts_delta)*10;

		/*
		 * OK, it's now a signed value in 100-nanosecond
		 * units.  Now convert it to nanosecond units.
		 */
		delta *= 100;
		break;
	}
	secs = 0;
	t = netmon->start_nsecs + delta;
	while (t < 0) {
		/*
		 * Propagate a borrow into the seconds.
		 * The seconds is a time_t, and can be < 0
		 * (unlikely, as Windows didn't exist before
		 * January 1, 1970, 00:00:00 UTC), while the
		 * nanoseconds should be positive, as in
		 * "nanoseconds since the instant of time
		 * represented by the seconds".
		 *
		 * We do not want t to be negative, as, according
		 * to the C90 standard, "if either operand [of /
		 * or %] is negative, whether the result of the
		 * / operator is the largest integer less than or
		 * equal to the algebraic quotient or the smallest
		 * greater than or equal to the algebraic quotient
		 * is implementation-defined, as is the sign of
		 * the result of the % operator", and we want
		 * the result of the division and remainder
		 * operations to be the same on all platforms.
		 */
		t += 1000000000;
		secs--;
	}
	secs += (time_t)(t/1000000000);
	nsecs = (guint32)(t%1000000000);
	phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	phdr->ts.secs = netmon->start_secs + secs;
	phdr->ts.nsecs = nsecs;
	phdr->caplen = packet_size;
	phdr->len = orig_size;

	return TRUE;
}

typedef enum {
	SUCCESS,
	FAILURE,
	RETRY
} process_trailer_retval;

static process_trailer_retval netmon_process_rec_trailer(netmon_t *netmon,
    FILE_T fh, struct wtap_pkthdr *phdr, int *err, gchar **err_info)
{
	int	trlr_size;

	trlr_size = (int)netmon_trailer_size(netmon);
	if (trlr_size != 0) {
		/*
		 * I haz a trailer.
		 */
		phdr->pkt_encap = netmon_read_rec_trailer(fh,
		    trlr_size, err, err_info);
		if (phdr->pkt_encap == -1)
			return FAILURE;	/* error */
		if (phdr->pkt_encap == 0)
			return RETRY;
	}

	return SUCCESS;
}

/* Read the next packet */
static gboolean netmon_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	netmon_t *netmon = (netmon_t *)wth->priv;
	gint64	rec_offset;

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
	if (file_tell(wth->fh) != rec_offset) {
		if (file_seek(wth->fh, rec_offset, SEEK_SET, err) == -1)
			return FALSE;
	}
	netmon->current_frame++;

	*data_offset = file_tell(wth->fh);

	if (!netmon_process_rec_header(wth, wth->fh, &wth->phdr,
	    err, err_info))
		return FALSE;

	if (!wtap_read_packet_bytes(wth->fh, wth->frame_buffer,
	    wth->phdr.caplen, err, err_info))
		return FALSE;	/* Read error */

	/*
	 * For version 2.1 and later, there's additional information
	 * after the frame data.
	 */
	switch (netmon_process_rec_trailer(netmon, wth->fh, &wth->phdr,
	    err, err_info)) {

	case RETRY:
		goto again;

	case SUCCESS:
		break;

	case FAILURE:
		return FALSE;
	}

	netmon_set_pseudo_header_info(wth->phdr.pkt_encap, &wth->phdr,
	    wth->frame_buffer);
	return TRUE;
}

static gboolean
netmon_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	netmon_t *netmon = (netmon_t *)wth->priv;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!netmon_process_rec_header(wth, wth->random_fh, phdr,
	    err, err_info))
		return FALSE;

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(wth->random_fh, buf, phdr->caplen, err,
	    err_info))
		return FALSE;

	/*
	 * For version 2.1 and later, there's additional information
	 * after the frame data.
	 */
	switch (netmon_process_rec_trailer(netmon, wth->random_fh, phdr,
	    err, err_info)) {

	case RETRY:
		/*
		 * This should not happen.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("netmon: saw metadata in netmon_seek_read");
		return FALSE;

	case SUCCESS:
		break;

	case FAILURE:
		return FALSE;
	}

	netmon_set_pseudo_header_info(phdr->pkt_encap, phdr, buf);

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

/*
 * Read a record trailer.
 * On success, returns the packet encapsulation type.
 * On error, returns -1 (which is WTAP_ENCAP_PER_PACKET, but we'd
 * never return that on success).
 * For metadata packets, returns 0 (which is WTAP_ENCAP_UNKNOWN, but
 * we'd never return that on success).
 */
static int
netmon_read_rec_trailer(FILE_T fh, int trlr_size, int *err, gchar **err_info)
{
	int	bytes_read;
	union {
		struct netmonrec_2_1_trlr trlr_2_1;
		struct netmonrec_2_2_trlr trlr_2_2;
		struct netmonrec_2_3_trlr trlr_2_3;
	}	trlr;
	guint16 network;
	int	pkt_encap;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&trlr, trlr_size, fh);
	if (bytes_read != trlr_size) {
		*err = file_error(fh, err_info);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;	/* error */
	}

	network = pletoh16(trlr.trlr_2_1.network);
	if ((network & 0xF000) == NETMON_NET_PCAP_BASE) {
		/*
		 * Converted pcap file - the LINKTYPE_ value
		 * is the network value with 0xF000 masked off.
		 */
		network &= 0x0FFF;
		pkt_encap = wtap_pcap_encap_to_wtap_encap(network);
		if (pkt_encap == WTAP_ENCAP_UNKNOWN) {
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("netmon: converted pcap network type %u unknown or unsupported",
			    network);
			return -1;	/* error */
		}
	} else if (network < NUM_NETMON_ENCAPS) {
		/*
		 * Regular NetMon encapsulation.
		 */
		pkt_encap = netmon_encap[network];
		if (pkt_encap == WTAP_ENCAP_UNKNOWN) {
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
			    network);
			return -1;	/* error */
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
			 * now.  Tell our caller to read the next
			 * record.
			 */
			return 0;

		default:
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
			    network);
			return -1;	/* error */
		}
	}

	return pkt_encap;	/* success */
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
	nstime_t first_record_time;
	guint32	frame_table_offset;
	guint32	*frame_table;
	guint	frame_table_index;
	guint	frame_table_size;
	gboolean no_more_room;		/* TRUE if no more records can be written */
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
	-1,		/* WTAP_ENCAP_ARCNET_LINUX -> unsupported */
	-1,		/* WTAP_ENCAP_ATM_RFC1483 -> unsupported */
	-1,		/* WTAP_ENCAP_LINUX_ATM_CLIP -> unsupported */
	-1,		/* WTAP_ENCAP_LAPB -> unsupported*/
	4,		/* WTAP_ENCAP_ATM_PDUS -> NDIS WAN (*NOT* ATM!) */
};
#define NUM_WTAP_ENCAPS (sizeof wtap_encap / sizeof wtap_encap[0])

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int netmon_dump_can_write_encap_1_x(int encap)
{
	/*
	 * Per-packet encapsulations are *not* supported in NetMon 1.x
	 * format.
	 */
	if (encap < 0 || (unsigned) encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

int netmon_dump_can_write_encap_2_x(int encap)
{
	/*
	 * Per-packet encapsulations are supported in NetMon 2.1
	 * format.
	 */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return 0;

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
	if (wtap_dump_file_seek(wdh, CAPTUREFILE_HEADER_SIZE, SEEK_SET, err) == -1)
		return FALSE;

	wdh->subtype_write = netmon_dump;
	wdh->subtype_close = netmon_dump_close;

	netmon = (netmon_dump_t *)g_malloc(sizeof(netmon_dump_t));
	wdh->priv = (void *)netmon;
	netmon->frame_table_offset = CAPTUREFILE_HEADER_SIZE;
	netmon->got_first_record_time = FALSE;
	netmon->frame_table = NULL;
	netmon->frame_table_index = 0;
	netmon->frame_table_size = 0;
	netmon->no_more_room = FALSE;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean netmon_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
	const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	netmon_dump_t *netmon = (netmon_dump_t *)wdh->priv;
	struct netmonrec_1_x_hdr rec_1_x_hdr;
	struct netmonrec_2_x_hdr rec_2_x_hdr;
	void *hdrp;
	size_t rec_size;
	struct netmonrec_2_1_trlr rec_2_x_trlr;
	size_t hdr_size;
	struct netmon_atm_hdr atm_hdr;
	int atm_hdrsize;
	gint64	secs;
	gint32	nsecs;

	/* We can only write packet records. */
	if (phdr->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
		return FALSE;
	}

	switch (wdh->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_NETMON_1_x:
		/*
		 * The length fields are 16-bit, so there's a hard limit
		 * of 65535.
		 */
		if (phdr->caplen > 65535) {
			*err = WTAP_ERR_PACKET_TOO_LARGE;
			return FALSE;
		}
		break;

	case WTAP_FILE_TYPE_SUBTYPE_NETMON_2_x:
		/* Don't write anything we're not willing to read. */
		if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
			*err = WTAP_ERR_PACKET_TOO_LARGE;
			return FALSE;
		}
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	if (wdh->encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * Is this network type supported?
		 */
		if (phdr->pkt_encap < 0 ||
		    (unsigned) phdr->pkt_encap >= NUM_WTAP_ENCAPS ||
		    wtap_encap[phdr->pkt_encap] == -1) {
			/*
			 * No.  Fail.
			 */
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			return FALSE;
		}

		/*
		 * Fill in the trailer with the network type.
		 */
		phtoles(rec_2_x_trlr.network, wtap_encap[phdr->pkt_encap]);
	}

	/*
	 * Will the file offset of this frame fit in a 32-bit unsigned
	 * integer?
	 */
	if (netmon->no_more_room) {
		/*
		 * No, so the file is too big for NetMon format to
		 * handle.
		 */
		*err = EFBIG;
		return FALSE;
	}

	/*
	 * NetMon files have a capture start time in the file header,
	 * and have times relative to that in the packet headers;
	 * pick the time of the first packet as the capture start
	 * time.
	 *
	 * That time has millisecond resolution, so chop any
	 * sub-millisecond part of the time stamp off.
	 */
	if (!netmon->got_first_record_time) {
		netmon->first_record_time.secs = phdr->ts.secs;
		netmon->first_record_time.nsecs =
		    (phdr->ts.nsecs/1000000)*1000000;
		netmon->got_first_record_time = TRUE;
	}

	if (wdh->encap == WTAP_ENCAP_ATM_PDUS)
		atm_hdrsize = sizeof (struct netmon_atm_hdr);
	else
		atm_hdrsize = 0;
	secs = (gint64)(phdr->ts.secs - netmon->first_record_time.secs);
	nsecs = phdr->ts.nsecs - netmon->first_record_time.nsecs;
	while (nsecs < 0) {
		/*
		 * Propagate a borrow into the seconds.
		 * The seconds is a time_t, and can be < 0
		 * (unlikely, as neither UN*X nor DOS
		 * nor the original Mac System existed
		 * before January 1, 1970, 00:00:00 UTC),
		 * while the nanoseconds should be positive,
		 * as in "nanoseconds since the instant of time
		 * represented by the seconds".
		 *
		 * We do not want t to be negative, as, according
		 * to the C90 standard, "if either operand [of /
		 * or %] is negative, whether the result of the
		 * / operator is the largest integer less than or
		 * equal to the algebraic quotient or the smallest
		 * greater than or equal to the algebraic quotient
		 * is implementation-defined, as is the sign of
		 * the result of the % operator", and we want
		 * the result of the division and remainder
		 * operations to be the same on all platforms.
		 */
		nsecs += 1000000000;
		secs--;
	}
	switch (wdh->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_NETMON_1_x:
		rec_1_x_hdr.ts_delta = GUINT32_TO_LE(secs*1000 + (nsecs + 500000)/1000000);
		rec_1_x_hdr.orig_len = GUINT16_TO_LE(phdr->len + atm_hdrsize);
		rec_1_x_hdr.incl_len = GUINT16_TO_LE(phdr->caplen + atm_hdrsize);
		hdrp = &rec_1_x_hdr;
		hdr_size = sizeof rec_1_x_hdr;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_NETMON_2_x:
		rec_2_x_hdr.ts_delta = GUINT64_TO_LE(secs*1000000 + (nsecs + 500)/1000);
		rec_2_x_hdr.orig_len = GUINT32_TO_LE(phdr->len + atm_hdrsize);
		rec_2_x_hdr.incl_len = GUINT32_TO_LE(phdr->caplen + atm_hdrsize);
		hdrp = &rec_2_x_hdr;
		hdr_size = sizeof rec_2_x_hdr;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	/*
	 * Keep track of the record size, as we need to update
	 * the current file offset.
	 */
	rec_size = 0;

	if (!wtap_dump_file_write(wdh, hdrp, hdr_size, err))
		return FALSE;
	rec_size += hdr_size;

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
		rec_size += sizeof atm_hdr;
	}

	if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
		return FALSE;
	rec_size += phdr->caplen;

	if (wdh->encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * Write out the trailer.
		 */
		if (!wtap_dump_file_write(wdh, &rec_2_x_trlr,
		    sizeof rec_2_x_trlr, err))
			return FALSE;
		rec_size += sizeof rec_2_x_trlr;
	}

	/*
	 * Stash the file offset of this frame.
	 */
	if (netmon->frame_table_size == 0) {
		/*
		 * Haven't yet allocated the buffer for the frame table.
		 */
		netmon->frame_table = (guint32 *)g_malloc(1024 * sizeof *netmon->frame_table);
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
			netmon->frame_table = (guint32 *)g_realloc(netmon->frame_table,
			    netmon->frame_table_size * sizeof *netmon->frame_table);
		}
	}

	netmon->frame_table[netmon->frame_table_index] =
	    GUINT32_TO_LE(netmon->frame_table_offset);

	/*
	 * Is this the last record we can write?
	 * I.e., will the frame table offset of the next record not fit
	 * in a 32-bit frame table offset entry?
	 *
	 * (We don't bother checking whether the number of frames
	 * will fit in a 32-bit value, as, even if each record were
	 * 1 byte, if there were more than 2^32-1 packets, the frame
	 * table offset of at least one of those packets will be >
	 * 2^32 - 1.)
	 *
	 * Note: this also catches the unlikely possibility that
	 * the record itself is > 2^32 - 1 bytes long.
	 */
	if ((guint64)netmon->frame_table_offset + rec_size > G_MAXUINT32) {
		/*
		 * Yup, too big.
		 */
		netmon->no_more_room = TRUE;
	}
	netmon->frame_table_index++;
	netmon->frame_table_offset += (guint32) rec_size;

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
	if (wtap_dump_file_seek(wdh, 0, SEEK_SET, err) == -1)
		return FALSE;
	memset(&file_hdr, '\0', sizeof file_hdr);
	switch (wdh->file_type_subtype) {

	case WTAP_FILE_TYPE_SUBTYPE_NETMON_1_x:
		magicp = netmon_1_x_magic;
		magic_size = sizeof netmon_1_x_magic;
		/* NetMon file version, for 1.x, is 1.1 */
		file_hdr.ver_major = 1;
		file_hdr.ver_minor = 1;
		break;

	case WTAP_FILE_TYPE_SUBTYPE_NETMON_2_x:
		magicp = netmon_2_x_magic;
		magic_size = sizeof netmon_2_x_magic;
		/*
		 * NetMon file version, for 2.x, is 2.0;
		 * for 3.0, it's 2.1.
		 *
		 * If the file encapsulation is WTAP_ENCAP_PER_PACKET,
		 * we need version 2.1.
		 *
		 * XXX - version 2.3 supports UTC time stamps; when
		 * should we use it?  According to the file format
		 * documentation, NetMon 3.3 "cannot properly
		 * interpret" the UTC timestamp information; does
		 * that mean it ignores it and uses the local-time
		 * start time and time deltas, or mishandles them?
		 * Also, NetMon 3.1 and earlier can't read version
		 * 2.2, much less version 2.3.
		 */
		file_hdr.ver_major = 2;
		file_hdr.ver_minor =
		    (wdh->encap == WTAP_ENCAP_PER_PACKET) ? 1 : 0;
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

	if (wdh->encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * We're writing NetMon 2.1 format, so the media
		 * type in the file header is irrelevant.  Set it
		 * to 1, just as Network Monitor does.
		 */
		file_hdr.network = GUINT16_TO_LE(1);
	} else
		file_hdr.network = GUINT16_TO_LE(wtap_encap[wdh->encap]);
	tm = localtime(&netmon->first_record_time.secs);
	if (tm != NULL) {
		file_hdr.ts_year  = GUINT16_TO_LE(1900 + tm->tm_year);
		file_hdr.ts_month = GUINT16_TO_LE(tm->tm_mon + 1);
		file_hdr.ts_dow   = GUINT16_TO_LE(tm->tm_wday);
		file_hdr.ts_day   = GUINT16_TO_LE(tm->tm_mday);
		file_hdr.ts_hour  = GUINT16_TO_LE(tm->tm_hour);
		file_hdr.ts_min   = GUINT16_TO_LE(tm->tm_min);
		file_hdr.ts_sec   = GUINT16_TO_LE(tm->tm_sec);
	} else {
		file_hdr.ts_year  = GUINT16_TO_LE(1900 + 0);
		file_hdr.ts_month = GUINT16_TO_LE(0 + 1);
		file_hdr.ts_dow   = GUINT16_TO_LE(0);
		file_hdr.ts_day   = GUINT16_TO_LE(0);
		file_hdr.ts_hour  = GUINT16_TO_LE(0);
		file_hdr.ts_min   = GUINT16_TO_LE(0);
		file_hdr.ts_sec   = GUINT16_TO_LE(0);
	}
	file_hdr.ts_msec = GUINT16_TO_LE(netmon->first_record_time.nsecs/1000000);
	file_hdr.frametableoffset = GUINT32_TO_LE(netmon->frame_table_offset);
	file_hdr.frametablelength =
	    GUINT32_TO_LE(netmon->frame_table_index * sizeof *netmon->frame_table);
	if (!wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr, err))
		return FALSE;

	return TRUE;
}
