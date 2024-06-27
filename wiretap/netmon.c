/* netmon.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "netmon.h"

#include <errno.h>
#include <string.h>
#include <wsutil/unicode-utils.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "atm.h"
#include "pcap-encap.h"

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
	uint8_t	 ver_minor;	/* minor version number */
	uint8_t	 ver_major;	/* major version number */
	uint16_t network;	/* network type */
	uint16_t ts_year;	/* year of capture start */
	uint16_t ts_month;	/* month of capture start (January = 1) */
	uint16_t ts_dow;	/* day of week of capture start (Sun = 0) */
	uint16_t ts_day;	/* day of month of capture start */
	uint16_t ts_hour;	/* hour of capture start */
	uint16_t ts_min;	/* minute of capture start */
	uint16_t ts_sec;	/* second of capture start */
	uint16_t ts_msec;	/* millisecond of capture start */
	uint32_t frametableoffset;	/* frame index table offset */
	uint32_t frametablelength;	/* frame index table size */
	uint32_t userdataoffset;	/* user data offset */
	uint32_t userdatalength;	/* user data size */
	uint32_t commentdataoffset;	/* comment data offset */
	uint32_t commentdatalength;	/* comment data size */
	uint32_t processinfooffset;	/* offset to process info structure */
	uint32_t processinfocount;	/* number of process info structures */
	uint32_t networkinfooffset;	/* offset to network info structure */
	uint32_t networkinfolength;	/* length of network info structure */
};

/* Network Monitor 1.x record header; not defined in STRUCT.H, but deduced by
 * looking at capture files. */
struct netmonrec_1_x_hdr {
	uint32_t ts_delta;	/* time stamp - msecs since start of capture */
	uint16_t orig_len;	/* actual length of packet */
	uint16_t incl_len;	/* number of octets captured in file */
};

/*
 * Network Monitor 2.x record header, as documented in NetMon 3.x's
 * help files.
 */
struct netmonrec_2_x_hdr {
	uint64_t ts_delta;	/* time stamp - usecs since start of capture */
	uint32_t orig_len;	/* actual length of packet */
	uint32_t incl_len;	/* number of octets captured in file */
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
	uint8_t network[2];		/* network type for this packet */
};

struct netmonrec_2_2_trlr {
	uint8_t network[2];		/* network type for this packet */
	uint8_t process_info_index[4];	/* index into the process info table */
};

struct netmonrec_2_3_trlr {
	uint8_t network[2];		/* network type for this packet */
	uint8_t process_info_index[4];	/* index into the process info table */
	uint8_t utc_timestamp[8];	/* packet time stamp, as .1 us units since January 1, 1601, 00:00:00 UTC */
	uint8_t timezone_index;		/* index of time zone information */
};

struct netmonrec_comment {
	uint32_t numFramePerComment;	/* Currently, this is always set to 1. Each comment is attached to only one frame. */
	uint32_t frameOffset;		/* Offset in the capture file table that indicates the beginning of the frame.  Key used to match comment with frame */
	uint8_t* title;			/* Comment title */
	uint32_t descLength;		/* Number of bytes in the comment description. Must be at least zero. */
	uint8_t* description;		/* Comment description */
};

/* Just the first few fields of netmonrec_comment so it can be read sequentially from file */
struct netmonrec_comment_header {
	uint32_t numFramePerComment;
	uint32_t frameOffset;
	uint32_t titleLength;
};

union ip_address {
	uint32_t ipv4;
	ws_in6_addr ipv6;
};

struct netmonrec_process_info {
	uint8_t* path;				/* A Unicode string of length PathSize */
	uint32_t iconSize;
	uint8_t* iconData;
	uint32_t pid;
	uint16_t localPort;
	uint16_t remotePort;
	bool isIPv6;
	union ip_address localAddr;
	union ip_address remoteAddr;
};

/*
 * The link-layer header on ATM packets.
 */
struct netmon_atm_hdr {
	uint8_t	 dest[6];	/* "Destination address" - what is it? */
	uint8_t	 src[6];	/* "Source address" - what is it? */
	uint16_t vpi;		/* VPI */
	uint16_t vci;		/* VCI */
};

typedef struct {
	time_t   start_secs;
	uint32_t start_nsecs;
	uint8_t  version_major;
	uint8_t  version_minor;
	uint32_t *frame_table;
	uint32_t frame_table_size;
	GHashTable* comment_table;
	GHashTable* process_info_table;
	unsigned current_frame;
} netmon_t;

/*
 * Maximum pathname length supported in the process table; the length
 * is in a 32-bit field, so we impose a limit to prevent attempts to
 * allocate too much memory.
 *
 * See
 *
 *    https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#maximum-path-length-limitation
 *
 * The NetMon 3.4 "Capture File Format" documentation says "PathSize must be
 * greater than 0, and less than MAX_PATH (260 characters)", but, as per that
 * link above, that limit has been raised in more recent systems.
 *
 * We pick a limit of 65536, as that should handle a path length of 32767
 * UTF-16 octet pairs plus a trailing NUL octet pair.
 */
#define MATH_PROCINFO_PATH_SIZE		65536

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
#define NUM_NETMON_ENCAPS array_length(netmon_encap)

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

static bool netmon_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool netmon_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool netmon_read_atm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, char **err_info);
static void netmon_close(wtap *wth);
static bool netmon_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info);
static bool netmon_dump_finish(wtap_dumper *wdh, int *err,
    char **err_info);

static int netmon_1_x_file_type_subtype = -1;
static int netmon_2_x_file_type_subtype = -1;

void register_netmon(void);

/*
 * Convert a counted UTF-16 string, which is probably also null-terminated
 * but is not guaranteed to be null-terminated (as it came from a file),
 * to a null-terminated UTF-8 string.
 */
static uint8_t *
utf_16_to_utf_8(const uint8_t *in, uint32_t length)
{
	uint8_t *result, *out;
	gunichar2 uchar2;
	gunichar uchar;
	size_t n_bytes;
	uint32_t i;

	/*
	 * Get the length of the resulting UTF-8 string, and validate
	 * the input string in the process.
	 */
	n_bytes = 0;
	for (i = 0; i + 1 < length && (uchar2 = pletoh16(in + i)) != '\0';
	    i += 2) {
		if (IS_LEAD_SURROGATE(uchar2)) {
			/*
			 * Lead surrogate.  Must be followed by a trail
			 * surrogate.
			 */
			gunichar2 lead_surrogate;

			i += 2;
			if (i + 1 >= length) {
				/*
				 * Oops, string ends with a lead surrogate.
				 * Ignore this for now.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				break;
			}
			lead_surrogate = uchar2;
			uchar2 = pletoh16(in + i);
			if (uchar2 == '\0') {
				/*
				 * Oops, string ends with a lead surrogate.
				 * Ignore this for now.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				break;
			}
			if (IS_TRAIL_SURROGATE(uchar2)) {
				/* Trail surrogate. */
				uchar = SURROGATE_VALUE(lead_surrogate, uchar2);
				n_bytes += g_unichar_to_utf8(uchar, NULL);
			} else {
				/*
				 * Not a trail surrogate.
				 * Ignore the entire pair.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				;
			}
		} else {
			if (IS_TRAIL_SURROGATE(uchar2)) {
				/*
				 * Trail surrogate without a preceding
				 * lead surrogate.  Ignore it.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				;
			} else {
				/*
				 * Non-surrogate; just count it.
				 */
				n_bytes += g_unichar_to_utf8(uchar2, NULL);
			}
		}
	}

	/*
	 * Now allocate a buffer big enough for the UTF-8 string plus a
	 * trailing NUL, and generate the string.
	 */
	result = (uint8_t *)g_malloc(n_bytes + 1);

	out = result;
	for (i = 0; i + 1 < length && (uchar2 = pletoh16(in + i)) != '\0';
	    i += 2) {
		if (IS_LEAD_SURROGATE(uchar2)) {
			/*
			 * Lead surrogate.  Must be followed by a trail
			 * surrogate.
			 */
			gunichar2 lead_surrogate;

			i += 2;
			if (i + 1 >= length) {
				/*
				 * Oops, string ends with a lead surrogate.
				 * Ignore this for now.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				break;
			}
			lead_surrogate = uchar2;
			uchar2 = pletoh16(in + i);
			if (uchar2 == '\0') {
				/*
				 * Oops, string ends with a lead surrogate.
				 * Ignore this for now.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				break;
			}
			if (IS_TRAIL_SURROGATE(uchar2)) {
				/* Trail surrogate. */
				uchar = SURROGATE_VALUE(lead_surrogate, uchar2);
				out += g_unichar_to_utf8(uchar, out);
			} else {
				/*
				 * Not a trail surrogate.
				 * Ignore the entire pair.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				;
			}
		} else {
			if (IS_TRAIL_SURROGATE(uchar2)) {
				/*
				 * Trail surrogate without a preceding
				 * lead surrogate.  Ignore it.
				 * XXX - insert "substitute" character?
				 * Report the error in some other fashion?
				 */
				;
			} else {
				/*
				 * Non-surrogate; just count it.
				 */
				out += g_unichar_to_utf8(uchar2, out);
			}
		}
	}
	*out = '\0';

	/*
	 * XXX - if i < length, this means we were handed an odd
	 * number of bytes, so it was not a valid UTF-16 string.
	 */
	return result;
}


static void netmonrec_comment_destroy(void *key) {
	struct netmonrec_comment *comment = (struct netmonrec_comment*) key;

	g_free(comment->title);
	g_free(comment->description);
	g_free(comment);
}

static void netmonrec_process_info_destroy(void *key) {
	struct netmonrec_process_info *process_info = (struct netmonrec_process_info*) key;

	g_free(process_info->path);
	g_free(process_info->iconData);
	g_free(process_info);
}

wtap_open_return_val netmon_open(wtap *wth, int *err, char **err_info)
{
	char magic[MAGIC_SIZE];
	struct netmon_hdr hdr;
	int file_type;
	struct tm tm;
	uint32_t frame_table_offset;
	uint32_t frame_table_length;
	uint32_t frame_table_size;
	uint32_t *frame_table;
	uint32_t comment_table_offset, process_info_table_offset;
	uint32_t comment_table_size, process_info_table_count;
	GHashTable *comment_table, *process_info_table;
	struct netmonrec_comment* comment_rec;
	int64_t file_size = wtap_file_size(wth, err);
#if G_BYTE_ORDER == G_BIG_ENDIAN
	unsigned int i;
#endif
	netmon_t *netmon;

	/* Read in the string that should be at the start of a Network
	 * Monitor file */
	if (!wtap_read_bytes(wth->fh, magic, MAGIC_SIZE, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic, netmon_1_x_magic, MAGIC_SIZE) != 0 &&
	    memcmp(magic, netmon_2_x_magic, MAGIC_SIZE) != 0) {
		return WTAP_OPEN_NOT_MINE;
	}

	/* Read the rest of the header. */
	if (!wtap_read_bytes(wth->fh, &hdr, sizeof hdr, err, err_info))
		return WTAP_OPEN_ERROR;

	switch (hdr.ver_major) {

	case 1:
		file_type = netmon_1_x_file_type_subtype;
		break;

	case 2:
		file_type = netmon_2_x_file_type_subtype;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("netmon: major version %u unsupported", hdr.ver_major);
		return WTAP_OPEN_ERROR;
	}

	hdr.network = pletoh16(&hdr.network);
	if (hdr.network >= NUM_NETMON_ENCAPS
	    || netmon_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("netmon: network type %u unknown or unsupported",
		    hdr.network);
		return WTAP_OPEN_ERROR;
	}

	/* This is a netmon file */
	wth->file_type_subtype = file_type;
	netmon = g_new0(netmon_t, 1);
	wth->priv = (void *)netmon;
	wth->subtype_read = netmon_read;
	wth->subtype_seek_read = netmon_seek_read;
	wth->subtype_close = netmon_close;

	/* NetMon capture file formats v2.1+ use per-packet encapsulation types.  NetMon 3 sets the value in
	 * the header to 1 (Ethernet) for backwards compatibility. */
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
	 *
	 * Eventually they went with per-packet FILETIMEs in a later
	 * version.
	 */
	netmon->start_nsecs = pletoh16(&hdr.ts_msec)*1000000;

	netmon->version_major = hdr.ver_major;
	netmon->version_minor = hdr.ver_minor;

	/*
	 * Get the offset of the frame index table.
	 */
	frame_table_offset = pletoh32(&hdr.frametableoffset);

	/*
	 * For NetMon 2.2 format and later, get the offset and length of
	 * the comment index table and process info table.
	 *
	 * For earlier versions, set them to zero; they appear to be
	 * uninitialized, so they're not necessarily zero.
	 */
	if ((netmon->version_major == 2 && netmon->version_minor >= 2) ||
	    netmon->version_major > 2) {
		comment_table_offset = pletoh32(&hdr.commentdataoffset);
		comment_table_size = pletoh32(&hdr.commentdatalength);
		process_info_table_offset = pletoh32(&hdr.processinfooffset);
		process_info_table_count = pletoh32(&hdr.processinfocount);
	} else {
		comment_table_offset = 0;
		comment_table_size = 0;
		process_info_table_offset = 0;
		process_info_table_count = 0;
	}

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
	frame_table_size = frame_table_length / (uint32_t)sizeof (uint32_t);
	if ((frame_table_size * sizeof (uint32_t)) != frame_table_length) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("netmon: frame table length is %u, which is not a multiple of the size of an entry",
		    frame_table_length);
		return WTAP_OPEN_ERROR;
	}
	if (frame_table_size == 0) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("netmon: frame table length is %u, which means it's less than one entry in size",
		    frame_table_length);
		return WTAP_OPEN_ERROR;
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
		*err_info = ws_strdup_printf("netmon: frame table length is %u, which is larger than we support",
		    frame_table_length);
		return WTAP_OPEN_ERROR;
	}
	if (file_seek(wth->fh, frame_table_offset, SEEK_SET, err) == -1) {
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Sanity check the comment table information before we bother to allocate
	 * large chunks of memory for the frame table
	 */
	if (comment_table_size > 0) {
		/*
		 * XXX - clamp the size of the comment table, so that we don't
		 * attempt to allocate a huge comment table and fail.
		 *
		 * Just use same size requires as frame table
		 */
		if (comment_table_size > 512*1024*1024) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("netmon: comment table size is %u, which is larger than we support",
				comment_table_size);
			return WTAP_OPEN_ERROR;
		}

		if (comment_table_size < 17) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("netmon: comment table size is %u, which is too small to use",
				comment_table_size);
			return WTAP_OPEN_ERROR;
		}

		if (comment_table_offset > file_size) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("netmon: comment table offset (%u) is larger than file",
				comment_table_offset);
			return WTAP_OPEN_ERROR;
		}
	}

	/*
	 * Sanity check the process info table information before we bother to allocate
	 * large chunks of memory for the frame table
	 */
	if ((process_info_table_offset > 0) && (process_info_table_count > 0)) {
		/*
		 * XXX - clamp the size of the process info table, so that we don't
		 * attempt to allocate a huge process info table and fail.
		 */
		if (process_info_table_count > 512*1024) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("netmon: process info table size is %u, which is larger than we support",
				process_info_table_count);
			return WTAP_OPEN_ERROR;
		}

		if (process_info_table_offset > file_size) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("netmon: process info table offset (%u) is larger than file",
				process_info_table_offset);
			return WTAP_OPEN_ERROR;
		}
	}

	/*
	 * Return back to the frame table offset
	 */
	if (file_seek(wth->fh, frame_table_offset, SEEK_SET, err) == -1) {
		return WTAP_OPEN_ERROR;
	}

	/*
	 * Sanity check the process info table information before we bother to allocate
	 * large chunks of memory for the frame table
	 */

	frame_table = (uint32_t *)g_try_malloc(frame_table_length);
	if (frame_table_length != 0 && frame_table == NULL) {
		*err = ENOMEM;	/* we assume we're out of memory */
		return WTAP_OPEN_ERROR;
	}
	if (!wtap_read_bytes(wth->fh, frame_table, frame_table_length,
	    err, err_info)) {
		g_free(frame_table);
		return WTAP_OPEN_ERROR;
	}
	netmon->frame_table_size = frame_table_size;
	netmon->frame_table = frame_table;

	if (comment_table_size > 0) {
		comment_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, netmonrec_comment_destroy);
		if (comment_table == NULL) {
			*err = ENOMEM;	/* we assume we're out of memory */
			return WTAP_OPEN_ERROR;
		}

		/* Make sure the file contains the full comment section */
		if (file_seek(wth->fh, comment_table_offset+comment_table_size, SEEK_SET, err) == -1) {
			g_hash_table_destroy(comment_table);
			return WTAP_OPEN_ERROR;
		}

		if (file_seek(wth->fh, comment_table_offset, SEEK_SET, err) == -1) {
			/* Shouldn't fail... */
			g_hash_table_destroy(comment_table);
			return WTAP_OPEN_ERROR;
		}

		while (comment_table_size > 16) {
			struct netmonrec_comment_header comment_header;
			uint32_t title_length;
			uint32_t desc_length;
			uint8_t *utf16_str;

			/* Read the first 12 bytes of the structure */
			if (!wtap_read_bytes(wth->fh, &comment_header, 12, err, err_info)) {
				g_hash_table_destroy(comment_table);
				return WTAP_OPEN_ERROR;
			}
			comment_table_size -= 12;

			/* Make sure comment size is sane */
			title_length = pletoh32(&comment_header.titleLength);
			if (title_length == 0) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = g_strdup("netmon: comment title size can't be 0");
				g_hash_table_destroy(comment_table);
				return WTAP_OPEN_ERROR;
			}
			if (title_length > comment_table_size) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = ws_strdup_printf("netmon: comment title size is %u, which is larger than the amount remaining in the comment section (%u)",
						title_length, comment_table_size);
				g_hash_table_destroy(comment_table);
				return WTAP_OPEN_ERROR;
			}

			comment_rec = g_new0(struct netmonrec_comment, 1);
			comment_rec->numFramePerComment = pletoh32(&comment_header.numFramePerComment);
			comment_rec->frameOffset = pletoh32(&comment_header.frameOffset);

			g_hash_table_insert(comment_table, GUINT_TO_POINTER(comment_rec->frameOffset), comment_rec);

			/*
			 * Read in the comment title.
			 *
			 * It is in UTF-16-encoded Unicode, and the title
			 * size is a count of octets, not octet pairs or
			 * Unicode characters.
			 */
			utf16_str = (uint8_t*)g_malloc(title_length);
			if (!wtap_read_bytes(wth->fh, utf16_str, title_length,
			    err, err_info)) {
				g_hash_table_destroy(comment_table);
				return WTAP_OPEN_ERROR;
			}
			comment_table_size -= title_length;

			/*
			 * Now convert it to UTF-8 for internal use.
			 */
			comment_rec->title = utf_16_to_utf_8(utf16_str,
			    title_length);
			g_free(utf16_str);

			if (comment_table_size < 4) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = g_strdup("netmon: corrupt comment section");
				g_hash_table_destroy(comment_table);
				return WTAP_OPEN_ERROR;
			}

			if (!wtap_read_bytes(wth->fh, &desc_length, 4, err, err_info)) {
				g_hash_table_destroy(comment_table);
				return WTAP_OPEN_ERROR;
			}
			comment_table_size -= 4;

			comment_rec->descLength = pletoh32(&desc_length);
			if (comment_rec->descLength > 0) {
				/* Make sure comment size is sane */
				if (comment_rec->descLength > comment_table_size) {
					*err = WTAP_ERR_BAD_FILE;
					*err_info = ws_strdup_printf("netmon: comment description size is %u, which is larger than the amount remaining in the comment section (%u)",
								comment_rec->descLength, comment_table_size);
					g_hash_table_destroy(comment_table);
					return WTAP_OPEN_ERROR;
				}

				comment_rec->description = (uint8_t*)g_malloc(comment_rec->descLength);

				/* Read the comment description */
				if (!wtap_read_bytes(wth->fh, comment_rec->description, comment_rec->descLength, err, err_info)) {
					g_hash_table_destroy(comment_table);
					return WTAP_OPEN_ERROR;
				}

				comment_table_size -= comment_rec->descLength;
			}
		}
		netmon->comment_table = comment_table;
	}

	if ((process_info_table_offset > 0) && (process_info_table_count > 0)) {
		uint16_t version;

		/* Go to the process table offset */
		if (file_seek(wth->fh, process_info_table_offset, SEEK_SET, err) == -1) {
			return WTAP_OPEN_ERROR;
		}

		process_info_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, netmonrec_process_info_destroy);
		if (process_info_table == NULL) {
			*err = ENOMEM;	/* we assume we're out of memory */
			return WTAP_OPEN_ERROR;
		}

		/* Read the version (ignored for now) */
		if (!wtap_read_bytes(wth->fh, &version, 2, err, err_info)) {
			g_hash_table_destroy(process_info_table);
			return WTAP_OPEN_ERROR;
		}

		while (process_info_table_count > 0)
		{
			struct netmonrec_process_info* process_info;
			uint32_t tmp32;
			uint16_t tmp16;
			uint32_t path_size;
			uint8_t *utf16_str;

			process_info = g_new0(struct netmonrec_process_info, 1);

			/* Read path */
			if (!wtap_read_bytes(wth->fh, &tmp32, 4, err, err_info)) {
				g_free(process_info);
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}

			path_size = pletoh32(&tmp32);
			if (path_size > MATH_PROCINFO_PATH_SIZE) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = ws_strdup_printf("netmon: Path size for process info record is %u, which is larger than allowed max value (%u)",
				    path_size, MATH_PROCINFO_PATH_SIZE);
				g_free(process_info);
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}

			/*
			 * Read in the path string.
			 *
			 * It is in UTF-16-encoded Unicode, and the path
			 * size is a count of octets, not octet pairs or
			 * Unicode characters.
			 */
			utf16_str = (uint8_t*)g_malloc(path_size);
			if (!wtap_read_bytes(wth->fh, utf16_str, path_size,
			    err, err_info)) {
				g_free(process_info);
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}

			/*
			 * Now convert it to UTF-8 for internal use.
			 */
			process_info->path = utf_16_to_utf_8(utf16_str,
			    path_size);
			g_free(utf16_str);

			/* Read icon (currently not saved) */
			if (!wtap_read_bytes(wth->fh, &tmp32, 4, err, err_info)) {
				g_free(process_info);
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}

			process_info->iconSize = pletoh32(&tmp32);

			/* XXX - skip the icon for now */
			if (file_seek(wth->fh, process_info->iconSize, SEEK_CUR, err) == -1) {
				g_free(process_info);
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}
			process_info->iconSize = 0;

			if (!wtap_read_bytes(wth->fh, &tmp32, 4, err, err_info)) {
				g_free(process_info);
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}
			process_info->pid = pletoh32(&tmp32);

			/* XXX - Currently index process information by PID */
			g_hash_table_insert(process_info_table, GUINT_TO_POINTER(process_info->pid), process_info);

			/* Read local port */
			if (!wtap_read_bytes(wth->fh, &tmp16, 2, err, err_info)) {
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}
			process_info->localPort = pletoh16(&tmp16);

			/* Skip padding */
			if (!wtap_read_bytes(wth->fh, &tmp16, 2, err, err_info)) {
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}

			/* Read remote port */
			if (!wtap_read_bytes(wth->fh, &tmp16, 2, err, err_info)) {
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}
			process_info->remotePort = pletoh16(&tmp16);

			/* Skip padding */
			if (!wtap_read_bytes(wth->fh, &tmp16, 2, err, err_info)) {
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}

			/* Determine IP version */
			if (!wtap_read_bytes(wth->fh, &tmp32, 4, err, err_info)) {
				g_hash_table_destroy(process_info_table);
				return WTAP_OPEN_ERROR;
			}
			process_info->isIPv6 = ((pletoh32(&tmp32) == 0) ? false : true);

			if (process_info->isIPv6) {
				if (!wtap_read_bytes(wth->fh, &process_info->localAddr.ipv6, 16, err, err_info)) {
					g_hash_table_destroy(process_info_table);
					return WTAP_OPEN_ERROR;
				}
				if (!wtap_read_bytes(wth->fh, &process_info->remoteAddr.ipv6, 16, err, err_info)) {
					g_hash_table_destroy(process_info_table);
					return WTAP_OPEN_ERROR;
				}
			} else {
				uint8_t ipbuffer[16];
				if (!wtap_read_bytes(wth->fh, ipbuffer, 16, err, err_info)) {
					g_hash_table_destroy(process_info_table);
					return WTAP_OPEN_ERROR;
				}
				process_info->localAddr.ipv4 = pletoh32(ipbuffer);

				if (!wtap_read_bytes(wth->fh, ipbuffer, 16, err, err_info)) {
					g_hash_table_destroy(process_info_table);
					return WTAP_OPEN_ERROR;
				}
				process_info->remoteAddr.ipv4 = pletoh32(ipbuffer);
			}

			process_info_table_count--;
		}

		netmon->process_info_table = process_info_table;
	}

#if G_BYTE_ORDER == G_BIG_ENDIAN
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
		wth->file_tsprec = WTAP_TSPREC_MSEC;
		break;

	case 2:
		/*
		 * Versions 2.0 through 2.2 support microsecond
		 * precision; version 2.3 supports 100-nanosecond
		 * precision (2.3 was the last version).
		 */
		if (netmon->version_minor >= 3)
			wth->file_tsprec = WTAP_TSPREC_100_NSEC;
		else
			wth->file_tsprec = WTAP_TSPREC_USEC;
		break;
	}
	return WTAP_OPEN_MINE;
}

static void
netmon_set_pseudo_header_info(wtap_rec *rec, Buffer *buf)
{
	switch (rec->rec_header.packet_header.pkt_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		/*
		 * Attempt to guess from the packet data, the VPI, and
		 * the VCI information about the type of traffic.
		 */
		atm_guess_traffic_type(rec, ws_buffer_start_ptr(buf));
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * We assume there's no FCS in this frame.
		 */
		rec->rec_header.packet_header.pseudo_header.eth.fcs_len = 0;
		break;

	case WTAP_ENCAP_IEEE_802_11_NETMON:
		/*
		 * The 802.11 metadata at the beginnning of the frame data
		 * is processed by a dissector, which fills in a pseudo-
		 * header and passes it to the 802.11 radio dissector,
		 * just as is done with other 802.11 radio metadata headers
		 * that are part of the packet data, such as radiotap.
		 */
		break;
	}
}

typedef enum {
	SUCCESS,
	FAILURE,
	RETRY
} process_record_retval;

static process_record_retval
netmon_process_record(wtap *wth, FILE_T fh, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
	netmon_t *netmon = (netmon_t *)wth->priv;
	int	 hdr_size = 0;
	union {
		struct netmonrec_1_x_hdr hdr_1_x;
		struct netmonrec_2_x_hdr hdr_2_x;
	}	hdr;
	int64_t	 delta = 0;	/* signed - frame times can be before the nominal start */
	int64_t	 t;
	time_t	 secs;
	int	 nsecs;
	uint32_t packet_size = 0;
	uint32_t orig_size = 0;
	int	 trlr_size;
	union {
		struct netmonrec_2_1_trlr trlr_2_1;
		struct netmonrec_2_2_trlr trlr_2_2;
		struct netmonrec_2_3_trlr trlr_2_3;
	}	trlr;
	uint16_t network;
	int	 pkt_encap;
	struct netmonrec_comment* comment_rec = NULL;

	/* Read record header. */
	switch (netmon->version_major) {

	case 1:
		hdr_size = sizeof (struct netmonrec_1_x_hdr);
		break;

	case 2:
		hdr_size = sizeof (struct netmonrec_2_x_hdr);
		break;
	}
	if (!wtap_read_bytes_or_eof(fh, &hdr, hdr_size, err, err_info))
		return FAILURE;

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
	if (packet_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("netmon: File has %u-byte packet, bigger than maximum of %u",
		    packet_size, WTAP_MAX_PACKET_SIZE_STANDARD);
		return FAILURE;
	}

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);

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
			*err_info = ws_strdup_printf("netmon: ATM file has a %u-byte packet, too small to have even an ATM pseudo-header",
			    packet_size);
			return FAILURE;
		}
		if (!netmon_read_atm_pseudoheader(fh, &rec->rec_header.packet_header.pseudo_header,
		    err, err_info))
			return FAILURE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= (unsigned)sizeof (struct netmon_atm_hdr);
		packet_size -= (unsigned)sizeof (struct netmon_atm_hdr);
		break;

	default:
		break;
	}

	switch (netmon->version_major) {

	case 1:
		/*
		 * According to Paul Long, this offset is unsigned.
		 * It's 32 bits, so the maximum value will fit in
		 * a int64_t such as delta, even after multiplying
		 * it by 1000000.
		 *
		 * pletoh32() returns a uint32_t; we cast it to int64_t
		 * before multiplying, so that the product doesn't
		 * overflow a uint32_t.
		 */
		delta = ((int64_t)pletoh32(&hdr.hdr_1_x.ts_delta))*1000000;
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
	nsecs = (int)(t%1000000000);
	rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	rec->ts.secs = netmon->start_secs + secs;
	rec->ts.nsecs = nsecs;
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = orig_size;

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info))
		return FAILURE;

	/*
	 * For version 2.1 and later, there's additional information
	 * after the frame data.
	 */
	if (netmon->version_major == 2 && netmon->version_minor >= 1) {
		switch (netmon->version_minor) {

		case 1:
			trlr_size = (int)sizeof (struct netmonrec_2_1_trlr);
			break;

		case 2:
			trlr_size = (int)sizeof (struct netmonrec_2_2_trlr);
			break;

		default:
			trlr_size = (int)sizeof (struct netmonrec_2_3_trlr);
			break;
		}

		if (!wtap_read_bytes(fh, &trlr, trlr_size, err, err_info))
			return FAILURE;

		network = pletoh16(trlr.trlr_2_1.network);
		if ((network >= 0xE080) && (network <= 0xE08A)) {
			/* These values "violate" the LINKTYPE_ media type values
			 * in Microsoft Analyzer and are considered a MAExportedMediaType,
			 * so they need their own WTAP_ types
			 */
			switch (network)
			{
			case 0xE080:    // "WiFi Message"
				pkt_encap = WTAP_ENCAP_IEEE_802_11;
				break;
			case 0xE081:    // "Ndis Etw WiFi Channel Message"
			case 0xE082:    // "Fiddler Netmon Message"
			case 0xE089:    // "Pef Ndis Msg";
			case 0xE08A:    // "Pef Ndis Wifi Meta Msg";
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = ws_strdup_printf("netmon: network type %u unknown or unsupported", network);
				return FAILURE;
			case 0xE083:
				pkt_encap = WTAP_ENCAP_MA_WFP_CAPTURE_V4;
				break;
			case 0xE084:
				pkt_encap = WTAP_ENCAP_MA_WFP_CAPTURE_V6;
				break;
			case 0xE085:
				pkt_encap = WTAP_ENCAP_MA_WFP_CAPTURE_2V4;
				break;
			case 0xE086:
				pkt_encap = WTAP_ENCAP_MA_WFP_CAPTURE_2V6;
				break;
			case 0xE087:
				pkt_encap = WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V4;
				break;
			case 0xE088:
				pkt_encap = WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V6;
				break;
			default:
				pkt_encap = WTAP_ENCAP_UNKNOWN;
				break;
			}
		} else if ((network & 0xF000) == NETMON_NET_PCAP_BASE) {
			/*
			 * Converted pcap file - the LINKTYPE_ value
			 * is the network value with 0xF000 masked off.
			 */
			network &= 0x0FFF;
			pkt_encap = wtap_pcap_encap_to_wtap_encap(network);
			if (pkt_encap == WTAP_ENCAP_UNKNOWN) {
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = ws_strdup_printf("netmon: converted pcap network type %u unknown or unsupported",
				    network);
				return FAILURE;
			}
		} else if (network < NUM_NETMON_ENCAPS) {
			/*
			 * Regular NetMon encapsulation.
			 */
			pkt_encap = netmon_encap[network];
			if (pkt_encap == WTAP_ENCAP_UNKNOWN) {
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = ws_strdup_printf("netmon: network type %u unknown or unsupported",
				    network);
				return FAILURE;
			}
		} else {
			/*
			 * Special packet type for metadata.
			 */
			switch (network) {

			case NETMON_NET_NETEVENT:
				/*
				 * Event Tracing event.
				 *
				 * https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
				 */
				pkt_encap = WTAP_ENCAP_NETMON_NET_NETEVENT;
				break;

			case NETMON_NET_NETWORK_INFO_EX:
				/*
				 * List of adapters on which the capture
				 * was done.
				 * XXX - this could be translated into pcapng
				 * blocks but for now, just treat as a frame.
				 */
				pkt_encap = WTAP_ENCAP_NETMON_NETWORK_INFO_EX;
				break;

			case NETMON_NET_PAYLOAD_HEADER:
				/*
				 * Header for a fake frame constructed
				 * by reassembly.
				 */
				return RETRY;

			case NETMON_NET_NETWORK_INFO:
				/*
				 * List of adapters on which the capture
				 * was done.
				 */
				return RETRY;

			case NETMON_NET_DNS_CACHE:
				/*
				 * List of resolved IP addresses.
				 */
				return RETRY;

			case NETMON_NET_NETMON_FILTER:
				/*
				 * NetMon capture or display filter
				 * string.
				 */
				pkt_encap = WTAP_ENCAP_NETMON_NET_FILTER;
				break;

			default:
				*err = WTAP_ERR_UNSUPPORTED;
				*err_info = ws_strdup_printf("netmon: network type %u unknown or unsupported",
				    network);
				return FAILURE;
			}
		}

		rec->rec_header.packet_header.pkt_encap = pkt_encap;
		if (netmon->version_minor >= 3) {
			/*
			 * This is a 2.3 or later file.  That format
			 * contains a UTC per-packet time stamp; use
			 * that instead of the start time and offset.
			 */
			uint64_t d;

			d = pletoh64(trlr.trlr_2_3.utc_timestamp);

			/*
			 * Get the time as seconds and nanoseconds.
			 * and overwrite the time stamp obtained
			 * from the record header.
			 */
			if (!filetime_to_nstime(&rec->ts, d)) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = g_strdup("netmon: time stamp outside supported range");
				return FAILURE;
			}
		}
	}

	netmon_set_pseudo_header_info(rec, buf);

	/* If any header specific information is present, set it as pseudo header data
	 * and set the encapsulation type, so it can be handled to the netmon_header
	 * dissector for further processing
	 */
	if (netmon->comment_table != NULL) {
		comment_rec = (struct netmonrec_comment*)g_hash_table_lookup(netmon->comment_table, GUINT_TO_POINTER(netmon->frame_table[netmon->current_frame-1]));
	}

	if (comment_rec != NULL) {
		union wtap_pseudo_header temp_header;

		/* These are the current encapsulation types that NetMon uses.
		 * Save them off so they can be copied to the NetMon pseudoheader
		 */
		switch (rec->rec_header.packet_header.pkt_encap)
		{
		case WTAP_ENCAP_ATM_PDUS:
			memcpy(&temp_header.atm, &rec->rec_header.packet_header.pseudo_header.atm, sizeof(temp_header.atm));
			break;
		case WTAP_ENCAP_ETHERNET:
			memcpy(&temp_header.eth, &rec->rec_header.packet_header.pseudo_header.eth, sizeof(temp_header.eth));
			break;
		case WTAP_ENCAP_IEEE_802_11_NETMON:
			memcpy(&temp_header.ieee_802_11, &rec->rec_header.packet_header.pseudo_header.ieee_802_11, sizeof(temp_header.ieee_802_11));
			break;
		}
		memset(&rec->rec_header.packet_header.pseudo_header.netmon, 0, sizeof(rec->rec_header.packet_header.pseudo_header.netmon));

		/* Save the current encapsulation type to the NetMon pseudoheader */
		rec->rec_header.packet_header.pseudo_header.netmon.sub_encap = rec->rec_header.packet_header.pkt_encap;

		/* Copy the comment data */
		rec->rec_header.packet_header.pseudo_header.netmon.title = comment_rec->title;
		rec->rec_header.packet_header.pseudo_header.netmon.descLength = comment_rec->descLength;
		rec->rec_header.packet_header.pseudo_header.netmon.description = comment_rec->description;

		/* Copy the saved pseudoheaders to the netmon pseudoheader structure */
		switch (rec->rec_header.packet_header.pkt_encap)
		{
		case WTAP_ENCAP_ATM_PDUS:
			memcpy(&rec->rec_header.packet_header.pseudo_header.netmon.subheader.atm, &temp_header.atm, sizeof(temp_header.atm));
			break;
		case WTAP_ENCAP_ETHERNET:
			memcpy(&rec->rec_header.packet_header.pseudo_header.netmon.subheader.eth, &temp_header.eth, sizeof(temp_header.eth));
			break;
		case WTAP_ENCAP_IEEE_802_11_NETMON:
			memcpy(&rec->rec_header.packet_header.pseudo_header.netmon.subheader.ieee_802_11, &temp_header.ieee_802_11, sizeof(temp_header.ieee_802_11));
			break;
		}

		/* Encapsulation type is now something that can be passed to netmon_header dissector */
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_NETMON_HEADER;
	}

	return SUCCESS;
}

/* Read the next packet */
static bool netmon_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
	netmon_t *netmon = (netmon_t *)wth->priv;
	int64_t	rec_offset;

	for (;;) {
		/* Have we reached the end of the packet data? */
		if (netmon->current_frame >= netmon->frame_table_size) {
			*err = 0;	/* it's just an EOF, not an error */
			return false;
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
				return false;
		}
		netmon->current_frame++;

		*data_offset = file_tell(wth->fh);

		switch (netmon_process_record(wth, wth->fh, rec, buf, err,
		    err_info)) {

		case RETRY:
			continue;

		case SUCCESS:
			return true;

		case FAILURE:
			return false;
		}
	}
}

static bool
netmon_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	switch (netmon_process_record(wth, wth->random_fh, rec, buf, err,
	    err_info)) {

	default:
		/*
		 * This should not happen.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup("netmon: saw metadata in netmon_seek_read");
		return false;

	case SUCCESS:
		return true;

	case FAILURE:
		return false;
	}
}

static bool
netmon_read_atm_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
    int *err, char **err_info)
{
	struct netmon_atm_hdr atm_phdr;
	uint16_t	vpi, vci;

	if (!wtap_read_bytes(fh, &atm_phdr, sizeof (struct netmon_atm_hdr),
	    err, err_info))
		return false;

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

	return true;
}

/* Throw away the frame table used by the sequential I/O stream. */
static void
netmon_close(wtap *wth)
{
	netmon_t *netmon = (netmon_t *)wth->priv;

	if (netmon->frame_table != NULL) {
		g_free(netmon->frame_table);
		netmon->frame_table = NULL;
	}

	if (netmon->comment_table != NULL) {
		g_hash_table_destroy(netmon->comment_table);
		netmon->comment_table = NULL;
	}

	if (netmon->process_info_table != NULL) {
		g_hash_table_destroy(netmon->process_info_table);
		netmon->process_info_table = NULL;
	}
}

typedef struct {
	bool is_v2;
	bool got_first_record_time;
	nstime_t first_record_time;
	uint32_t frame_table_offset;
	uint32_t *frame_table;
	unsigned frame_table_index;
	unsigned frame_table_size;
	bool no_more_room;		/* true if no more records can be written */
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
#define NUM_WTAP_ENCAPS array_length(wtap_encap)

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
static int netmon_dump_can_write_encap_1_x(int encap)
{
	/*
	 * Per-packet encapsulations are *not* supported in NetMon 1.x
	 * format.
	 */
	if (encap < 0 || (unsigned) encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNWRITABLE_ENCAP;

	return 0;
}

static int netmon_dump_can_write_encap_2_x(int encap)
{
	/*
	 * Per-packet encapsulations are supported in NetMon 2.1
	 * format.
	 */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return 0;

	if (encap < 0 || (unsigned) encap >= NUM_WTAP_ENCAPS || wtap_encap[encap] == -1)
		return WTAP_ERR_UNWRITABLE_ENCAP;

	return 0;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure */
static bool netmon_dump_open(wtap_dumper *wdh, bool is_v2,
                                 int *err, char **err_info _U_)
{
	netmon_dump_t *netmon;

	/* We can't fill in all the fields in the file header, as we
	   haven't yet written any packets.  As we'll have to rewrite
	   the header when we've written out all the packets, we just
	   skip over the header for now. */
	if (wtap_dump_file_seek(wdh, CAPTUREFILE_HEADER_SIZE, SEEK_SET, err) == -1)
		return false;

	wdh->bytes_dumped = CAPTUREFILE_HEADER_SIZE;
	wdh->subtype_write = netmon_dump;
	wdh->subtype_finish = netmon_dump_finish;

	netmon = g_new(netmon_dump_t, 1);
	wdh->priv = (void *)netmon;
	netmon->is_v2 = is_v2;
	netmon->frame_table_offset = CAPTUREFILE_HEADER_SIZE;
	netmon->got_first_record_time = false;
	netmon->frame_table = NULL;
	netmon->frame_table_index = 0;
	netmon->frame_table_size = 0;
	netmon->no_more_room = false;

	return true;
}

static bool netmon_dump_open_1_x(wtap_dumper *wdh, int *err, char **err_info _U_)
{
	return netmon_dump_open(wdh, false, err, err_info);
}

static bool netmon_dump_open_2_x(wtap_dumper *wdh, int *err, char **err_info _U_)
{
	return netmon_dump_open(wdh, true, err, err_info);
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
static bool netmon_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info _U_)
{
	const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
	netmon_dump_t *netmon = (netmon_dump_t *)wdh->priv;
	struct netmonrec_1_x_hdr rec_1_x_hdr;
	struct netmonrec_2_x_hdr rec_2_x_hdr;
	void *hdrp;
	size_t rec_size;
	struct netmonrec_2_1_trlr rec_2_x_trlr;
	size_t hdr_size;
	struct netmon_atm_hdr atm_hdr;
	int atm_hdrsize;
	int64_t	secs;
	int32_t	nsecs;

	/* We can only write packet records. */
	if (rec->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		return false;
	}

	if (netmon->is_v2) {
		/* Don't write anything we're not willing to read. */
		if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
			*err = WTAP_ERR_PACKET_TOO_LARGE;
			return false;
		}
	} else {
		/*
		 * Make sure this packet doesn't have a link-layer type that
		 * differs from the one for the file.
		 */
		if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
			*err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
			return false;
		}

		/*
		 * The length fields are 16-bit, so there's a hard limit
		 * of 65535.
		 */
		if (rec->rec_header.packet_header.caplen > 65535) {
			*err = WTAP_ERR_PACKET_TOO_LARGE;
			return false;
		}
	}

	if (wdh->file_encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * Is this network type supported?
		 */
		if (rec->rec_header.packet_header.pkt_encap < 0 ||
		    (unsigned) rec->rec_header.packet_header.pkt_encap >= NUM_WTAP_ENCAPS ||
		    wtap_encap[rec->rec_header.packet_header.pkt_encap] == -1) {
			/*
			 * No.  Fail.
			 */
			*err = WTAP_ERR_UNWRITABLE_ENCAP;
			return false;
		}

		/*
		 * Fill in the trailer with the network type.
		 */
		phtoles(rec_2_x_trlr.network, wtap_encap[rec->rec_header.packet_header.pkt_encap]);
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
		return false;
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
		netmon->first_record_time.secs = rec->ts.secs;
		netmon->first_record_time.nsecs =
		    (rec->ts.nsecs/1000000)*1000000;
		netmon->got_first_record_time = true;
	}

	if (wdh->file_encap == WTAP_ENCAP_ATM_PDUS)
		atm_hdrsize = sizeof (struct netmon_atm_hdr);
	else
		atm_hdrsize = 0;
	secs = (int64_t)(rec->ts.secs - netmon->first_record_time.secs);
	nsecs = rec->ts.nsecs - netmon->first_record_time.nsecs;
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
	if (netmon->is_v2) {
		rec_2_x_hdr.ts_delta = GUINT64_TO_LE(secs*1000000 + (nsecs + 500)/1000);
		rec_2_x_hdr.orig_len = GUINT32_TO_LE(rec->rec_header.packet_header.len + atm_hdrsize);
		rec_2_x_hdr.incl_len = GUINT32_TO_LE(rec->rec_header.packet_header.caplen + atm_hdrsize);
		hdrp = &rec_2_x_hdr;
		hdr_size = sizeof rec_2_x_hdr;
	} else {
		rec_1_x_hdr.ts_delta = GUINT32_TO_LE(secs*1000 + (nsecs + 500000)/1000000);
		rec_1_x_hdr.orig_len = GUINT16_TO_LE(rec->rec_header.packet_header.len + atm_hdrsize);
		rec_1_x_hdr.incl_len = GUINT16_TO_LE(rec->rec_header.packet_header.caplen + atm_hdrsize);
		hdrp = &rec_1_x_hdr;
		hdr_size = sizeof rec_1_x_hdr;
	}

	/*
	 * Keep track of the record size, as we need to update
	 * the current file offset.
	 */
	rec_size = 0;

	if (!wtap_dump_file_write(wdh, hdrp, hdr_size, err))
		return false;
	rec_size += hdr_size;

	if (wdh->file_encap == WTAP_ENCAP_ATM_PDUS) {
		/*
		 * Write the ATM header.
		 * We supply all-zero destination and source addresses.
		 */
		memset(&atm_hdr.dest, 0, sizeof atm_hdr.dest);
		memset(&atm_hdr.src, 0, sizeof atm_hdr.src);
		atm_hdr.vpi = g_htons(pseudo_header->atm.vpi);
		atm_hdr.vci = g_htons(pseudo_header->atm.vci);
		if (!wtap_dump_file_write(wdh, &atm_hdr, sizeof atm_hdr, err))
			return false;
		rec_size += sizeof atm_hdr;
	}

	if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
		return false;
	rec_size += rec->rec_header.packet_header.caplen;

	if (wdh->file_encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * Write out the trailer.
		 */
		if (!wtap_dump_file_write(wdh, &rec_2_x_trlr,
		    sizeof rec_2_x_trlr, err))
			return false;
		rec_size += sizeof rec_2_x_trlr;
	}

	/*
	 * Stash the file offset of this frame.
	 */
	if (netmon->frame_table_size == 0) {
		/*
		 * Haven't yet allocated the buffer for the frame table.
		 */
		netmon->frame_table = (uint32_t *)g_malloc(1024 * sizeof *netmon->frame_table);
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
			netmon->frame_table = (uint32_t *)g_realloc(netmon->frame_table,
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
	if ((uint64_t)netmon->frame_table_offset + rec_size > UINT32_MAX) {
		/*
		 * Yup, too big.
		 */
		netmon->no_more_room = true;
	}
	netmon->frame_table_index++;
	netmon->frame_table_offset += (uint32_t) rec_size;

	return true;
}

/* Finish writing to a dump file.
   Returns true on success, false on failure. */
static bool netmon_dump_finish(wtap_dumper *wdh, int *err,
    char **err_info _U_)
{
	netmon_dump_t *netmon = (netmon_dump_t *)wdh->priv;
	size_t n_to_write;
	struct netmon_hdr file_hdr;
	const char *magicp;
	size_t magic_size;
	struct tm *tm;
	int64_t saved_bytes_dumped;

	/* Write out the frame table.  "netmon->frame_table_index" is
	   the number of entries we've put into it. */
	n_to_write = netmon->frame_table_index * sizeof *netmon->frame_table;
	if (!wtap_dump_file_write(wdh, netmon->frame_table, n_to_write, err))
		return false;

	/* Now go fix up the file header. */
	if (wtap_dump_file_seek(wdh, 0, SEEK_SET, err) == -1)
		return false;
	/* Save bytes_dumped since following calls to wtap_dump_file_write()
	 * will still (mistakenly) increase it.
	 */
	saved_bytes_dumped = wdh->bytes_dumped;
	memset(&file_hdr, '\0', sizeof file_hdr);
	if (netmon->is_v2) {
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
		    (wdh->file_encap == WTAP_ENCAP_PER_PACKET) ? 1 : 0;
	} else {
		magicp = netmon_1_x_magic;
		magic_size = sizeof netmon_1_x_magic;
		/* NetMon file version, for 1.x, is 1.1 */
		file_hdr.ver_major = 1;
		file_hdr.ver_minor = 1;
	}
	if (!wtap_dump_file_write(wdh, magicp, magic_size, err))
		return false;

	if (wdh->file_encap == WTAP_ENCAP_PER_PACKET) {
		/*
		 * We're writing NetMon 2.1 format, so the media
		 * type in the file header is irrelevant.  Set it
		 * to 1, just as Network Monitor does.
		 */
		file_hdr.network = GUINT16_TO_LE(1);
	} else
		file_hdr.network = GUINT16_TO_LE(wtap_encap[wdh->file_encap]);
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
		return false;

	wdh->bytes_dumped = saved_bytes_dumped;
	return true;
}

static const struct supported_block_type netmon_1_x_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info netmon_1_x_info = {
	"Microsoft NetMon 1.x", "netmon1", "cap", NULL,
	true, BLOCKS_SUPPORTED(netmon_1_x_blocks_supported),
	netmon_dump_can_write_encap_1_x, netmon_dump_open_1_x, NULL
};

static const struct supported_block_type netmon_2_x_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info netmon_2_x_info = {
	"Microsoft NetMon 2.x", "netmon2", "cap", NULL,
	true, BLOCKS_SUPPORTED(netmon_2_x_blocks_supported),
	netmon_dump_can_write_encap_2_x, netmon_dump_open_2_x, NULL
};

void register_netmon(void)
{
	netmon_1_x_file_type_subtype = wtap_register_file_type_subtype(&netmon_1_x_info);
	netmon_2_x_file_type_subtype = wtap_register_file_type_subtype(&netmon_2_x_info);

	/*
	 * Register names for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("NETMON_1_x",
	    netmon_1_x_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("NETMON_2_x",
	    netmon_2_x_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
