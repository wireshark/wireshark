/* peekclassic.c
 * Routines for opening files in what Savvius (formerly WildPackets) calls
 * the classic file format in the description of their "PeekRdr Sample
 * Application" (C++ source code to read their capture files, downloading
 * of which requires a maintenance contract, so it's not free as in beer
 * and probably not as in speech, either).
 *
 * As that description says, it's used by AiroPeek and AiroPeek NX prior
 * to 2.0, EtherPeek prior to 6.0, and EtherPeek NX prior to 3.0.  It
 * was probably also used by TokenPeek.
 *
 * This handles versions 5, 6, and 7 of that format (the format version
 * number is what appears in the file, and is distinct from the application
 * version number).
 *
 * Copyright (c) 2001, Daniel Thompson <d.thompson@gmx.net>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "peekclassic.h"

#include <string.h>

#include <wsutil/epochs.h>
#include <wsutil/802_11-utils.h>
#include <wsutil/ws_assert.h>

#include "wtap-int.h"
#include "file_wrappers.h"

/* CREDITS
 *
 * This file decoder could not have been written without examining how
 * tcptrace (http://www.tcptrace.org/) handles EtherPeek files.
 */

/* master header */
typedef struct peekclassic_master_header {
	uint8_t version;
	uint8_t status;
} peekclassic_master_header_t;
#define PEEKCLASSIC_MASTER_HDR_SIZE 2

/* secondary header (V5,V6,V7) */
typedef struct peekclassic_v567_header {
	uint32_t filelength;
	uint32_t numPackets;
	uint32_t timeDate;
	uint32_t timeStart;
	uint32_t timeStop;
	uint32_t mediaType;  /* Media Type Ethernet=0 Token Ring = 1 */
	uint32_t physMedium; /* Physical Medium native=0 802.1=1 */
	uint32_t appVers;    /* App Version Number Maj.Min.Bug.Build */
	uint32_t linkSpeed;  /* Link Speed Bits/sec */
	uint32_t reserved[3];
} peekclassic_v567_header_t;
#define PEEKCLASSIC_V567_HDR_SIZE 48

/* full header */
typedef struct peekclassic_header {
	peekclassic_master_header_t master;
	union {
		peekclassic_v567_header_t v567;
	} secondary;
} peekclassic_header_t;

/*
 * Packet header (V5, V6).
 *
 * NOTE: the time stamp, although it's a 32-bit number, is only aligned
 * on a 16-bit boundary.  (Does this date back to 68K Macs?  The 68000
 * only required 16-bit alignment of 32-bit quantities, as did the 68010,
 * and the 68020/68030/68040 required no alignment.)
 *
 * As such, we cannot declare this as a C structure, as compilers on
 * most platforms will put 2 bytes of padding before the time stamp to
 * align it on a 32-bit boundary.
 *
 * So, instead, we #define numbers as the offsets of the fields.
 */
#define PEEKCLASSIC_V56_LENGTH_OFFSET		0
#define PEEKCLASSIC_V56_SLICE_LENGTH_OFFSET	2
#define PEEKCLASSIC_V56_FLAGS_OFFSET		4
#define PEEKCLASSIC_V56_STATUS_OFFSET		5
#define PEEKCLASSIC_V56_TIMESTAMP_OFFSET	6
#define PEEKCLASSIC_V56_DESTNUM_OFFSET		10
#define PEEKCLASSIC_V56_SRCNUM_OFFSET		12
#define PEEKCLASSIC_V56_PROTONUM_OFFSET		14
#define PEEKCLASSIC_V56_PROTOSTR_OFFSET		16
#define PEEKCLASSIC_V56_FILTERNUM_OFFSET	24
#define PEEKCLASSIC_V56_PKT_SIZE		26

/* 64-bit time in micro seconds from the (Mac) epoch */
typedef struct peekclassic_utime {
	uint32_t upper;
	uint32_t lower;
} peekclassic_utime;

/*
 * Packet header (V7).
 *
 * This doesn't have the same alignment problem, but we do it with
 * #defines anyway.
 */
#define PEEKCLASSIC_V7_PROTONUM_OFFSET		0
#define PEEKCLASSIC_V7_LENGTH_OFFSET		2
#define PEEKCLASSIC_V7_SLICE_LENGTH_OFFSET	4
#define PEEKCLASSIC_V7_FLAGS_OFFSET		6
#define PEEKCLASSIC_V7_STATUS_OFFSET		7
#define PEEKCLASSIC_V7_TIMESTAMP_OFFSET		8
#define PEEKCLASSIC_V7_PKT_SIZE			16

/*
 * Flag bits.
 */
#define FLAGS_CONTROL_FRAME	0x01	/* Frame is a control frame */
#define FLAGS_HAS_CRC_ERROR	0x02	/* Frame has a CRC error */
#define FLAGS_HAS_FRAME_ERROR	0x04	/* Frame has a frame error */
#define FLAGS_ROUTE_INFO	0x08	/* Frame has token ring routing information */
#define FLAGS_FRAME_TOO_LONG	0x10	/* Frame too long */
#define FLAGS_FRAME_TOO_SHORT	0x20	/* Frame too short (runt) */
#define FLAGS_TRIGGER		0x40	/* Trigger packet (?) */
#define FLAGS_SNAP		0x80	/* SNAP packet (SNAP header?) */

/*
 * Status bits.
 */
#define STATUS_SELECTED		0x01	/* Selected (in the *Peek GUI?) */
#define STATUS_TRUNCATED	0x02	/* Truncated (?) */
#define STATUS_APPLEPEEK	0x10	/* ApplePeek packet (?) */
#define STATUS_SLICED		0x20	/* Sliced (cut short by snaplen?) */
#define STATUS_HIDDEN		0x80	/* Hidden (in the *Peek GUI?) */

typedef struct {
	time_t reference_time;
} peekclassic_t;

static bool peekclassic_read_v7(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool peekclassic_seek_read_v7(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static int peekclassic_read_packet_v7(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool peekclassic_read_v56(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool peekclassic_seek_read_v56(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool peekclassic_read_packet_v56(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);

static int peekclassic_v56_file_type_subtype = -1;
static int peekclassic_v7_file_type_subtype = -1;

void register_peekclassic(void);

wtap_open_return_val peekclassic_open(wtap *wth, int *err, char **err_info)
{
	peekclassic_header_t ep_hdr;
	time_t reference_time;
	int file_encap;
	peekclassic_t *peekclassic;

	/* Peek classic files do not start with a magic value large enough
	 * to be unique; hence we use the following algorithm to determine
	 * the type of an unknown file:
	 *  - populate the master header and reject file if there is no match
	 *  - populate the secondary header and check that the reserved space
	 *      is zero, and check some other fields; this isn't perfect,
	 *	and we may have to add more checks at some point.
	 */
	ws_assert(sizeof(ep_hdr.master) == PEEKCLASSIC_MASTER_HDR_SIZE);
	if (!wtap_read_bytes(wth->fh, &ep_hdr.master,
	    (int)sizeof(ep_hdr.master), err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/*
	 * It appears that EtherHelp (a free application from WildPackets
	 * that did blind capture, saving to a file, so that you could
	 * give the resulting file to somebody with EtherPeek) saved
	 * captures in EtherPeek format except that it ORed the 0x80
	 * bit on in the version number.
	 *
	 * We therefore strip off the 0x80 bit in the version number.
	 * Perhaps there's some reason to care whether the capture
	 * came from EtherHelp; if we discover one, we should check
	 * that bit.
	 */
	ep_hdr.master.version &= ~0x80;

	/* switch on the file version */
	switch (ep_hdr.master.version) {

	case 5:
	case 6:
	case 7:
		/* get the secondary header */
		ws_assert(sizeof(ep_hdr.secondary.v567) ==
		        PEEKCLASSIC_V567_HDR_SIZE);
		if (!wtap_read_bytes(wth->fh, &ep_hdr.secondary.v567,
		    (int)sizeof(ep_hdr.secondary.v567), err, err_info)) {
			if (*err != WTAP_ERR_SHORT_READ)
				return WTAP_OPEN_ERROR;
			return WTAP_OPEN_NOT_MINE;
		}

		if ((0 != ep_hdr.secondary.v567.reserved[0]) ||
		    (0 != ep_hdr.secondary.v567.reserved[1]) ||
		    (0 != ep_hdr.secondary.v567.reserved[2])) {
			/* still unknown */
			return WTAP_OPEN_NOT_MINE;
		}

		/*
		 * Check the mediaType and physMedium fields.
		 * We assume it's not a Peek classic file if
		 * these aren't values we know, rather than
		 * reporting them as invalid Peek classic files,
		 * as, given the lack of a magic number, we need
		 * all the checks we can get.
		 */
		ep_hdr.secondary.v567.mediaType =
		    g_ntohl(ep_hdr.secondary.v567.mediaType);
		ep_hdr.secondary.v567.physMedium =
		    g_ntohl(ep_hdr.secondary.v567.physMedium);

		switch (ep_hdr.secondary.v567.physMedium) {

		case 0:
			/*
			 * "Native" format, presumably meaning
			 * Ethernet or Token Ring.
			 */
			switch (ep_hdr.secondary.v567.mediaType) {

			case 0:
				file_encap = WTAP_ENCAP_ETHERNET;
				break;

			case 1:
				file_encap = WTAP_ENCAP_TOKEN_RING;
				break;

			default:
				/*
				 * Assume this isn't a Peek classic file.
				 */
				return WTAP_OPEN_NOT_MINE;
			}
			break;

		case 1:
			switch (ep_hdr.secondary.v567.mediaType) {

			case 0:
				/*
				 * 802.11, with a private header giving
				 * some radio information.  Presumably
				 * this is from AiroPeek.
				 */
				file_encap = WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
				break;

			default:
				/*
				 * Assume this isn't a Peek classic file.
				 */
				return WTAP_OPEN_NOT_MINE;
			}
			break;

		default:
			/*
			 * Assume this isn't a Peek classic file.
			 */
			return WTAP_OPEN_NOT_MINE;
		}


		/*
		 * Assume this is a V5, V6 or V7 Peek classic file, and
		 * byte swap the rest of the fields in the secondary header.
		 *
		 * XXX - we could check the file length if the file were
		 * uncompressed, but it might be compressed.
		 */
		ep_hdr.secondary.v567.filelength =
		    g_ntohl(ep_hdr.secondary.v567.filelength);
		ep_hdr.secondary.v567.numPackets =
		    g_ntohl(ep_hdr.secondary.v567.numPackets);
		ep_hdr.secondary.v567.timeDate =
		    g_ntohl(ep_hdr.secondary.v567.timeDate);
		ep_hdr.secondary.v567.timeStart =
		    g_ntohl(ep_hdr.secondary.v567.timeStart);
		ep_hdr.secondary.v567.timeStop =
		    g_ntohl(ep_hdr.secondary.v567.timeStop);
		ep_hdr.secondary.v567.appVers =
		    g_ntohl(ep_hdr.secondary.v567.appVers);
		ep_hdr.secondary.v567.linkSpeed =
		    g_ntohl(ep_hdr.secondary.v567.linkSpeed);

		/* Get the reference time as a time_t */
		reference_time = ep_hdr.secondary.v567.timeDate - EPOCH_DELTA_1904_01_01_00_00_00_UTC;
		break;

	default:
		/*
		 * Assume this isn't a Peek classic file.
		 */
		return WTAP_OPEN_NOT_MINE;
	}

	/*
	 * This is a Peek classic file.
	 *
	 * At this point we have recognised the file type and have populated
	 * the whole ep_hdr structure in host byte order.
	 */
	peekclassic = g_new(peekclassic_t, 1);
	wth->priv = (void *)peekclassic;
	peekclassic->reference_time = reference_time;
	wth->file_encap = file_encap;
	switch (ep_hdr.master.version) {

	case 5:
	case 6:
		wth->file_type_subtype = peekclassic_v56_file_type_subtype;
		wth->subtype_read = peekclassic_read_v56;
		wth->subtype_seek_read = peekclassic_seek_read_v56;
		break;

	case 7:
		wth->file_type_subtype = peekclassic_v7_file_type_subtype;
		wth->subtype_read = peekclassic_read_v7;
		wth->subtype_seek_read = peekclassic_seek_read_v7;
		break;

	default:
		/* this is impossible */
		ws_assert_not_reached();
	}

	wth->snapshot_length   = 0; /* not available in header */
	wth->file_tsprec = WTAP_TSPREC_USEC;

	/*
	 * Add an IDB; we don't know how many interfaces were
	 * involved, so we just say one interface, about which
	 * we only know the link-layer type, snapshot length,
	 * and time stamp resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

static bool peekclassic_read_v7(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
	int sliceLength;

	*data_offset = file_tell(wth->fh);

	/* Read the packet. */
	sliceLength = peekclassic_read_packet_v7(wth, wth->fh, rec, buf,
	    err, err_info);
	if (sliceLength < 0)
		return false;

	/* Skip extra ignored data at the end of the packet. */
	if ((uint32_t)sliceLength > rec->rec_header.packet_header.caplen) {
		if (!wtap_read_bytes(wth->fh, NULL, sliceLength - rec->rec_header.packet_header.caplen,
		    err, err_info))
			return false;
	}

	/* Records are padded to an even length, so if the slice length
	   is odd, read the padding byte. */
	if (sliceLength & 0x01) {
		if (!wtap_read_bytes(wth->fh, NULL, 1, err, err_info))
			return false;
	}

	return true;
}

static bool peekclassic_seek_read_v7(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	/* Read the packet. */
	if (peekclassic_read_packet_v7(wth, wth->random_fh, rec, buf,
	    err, err_info) == -1) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return false;
	}
	return true;
}

#define RADIO_INFO_SIZE	4

static int peekclassic_read_packet_v7(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
	uint8_t ep_pkt[PEEKCLASSIC_V7_PKT_SIZE];
#if 0
	uint16_t protoNum;
#endif
	uint16_t length;
	uint16_t sliceLength;
	uint8_t flags;
	uint8_t status;
	uint64_t timestamp;
	time_t tsecs;
	uint32_t tusecs;
	uint32_t pack_flags;
	uint8_t radio_info[RADIO_INFO_SIZE];

	if (!wtap_read_bytes_or_eof(fh, ep_pkt, sizeof(ep_pkt), err, err_info))
		return -1;

	/* Extract the fields from the packet */
#if 0
	protoNum = pntoh16(&ep_pkt[PEEKCLASSIC_V7_PROTONUM_OFFSET]);
#endif
	length = pntoh16(&ep_pkt[PEEKCLASSIC_V7_LENGTH_OFFSET]);
	sliceLength = pntoh16(&ep_pkt[PEEKCLASSIC_V7_SLICE_LENGTH_OFFSET]);
	flags = ep_pkt[PEEKCLASSIC_V7_FLAGS_OFFSET];
	status = ep_pkt[PEEKCLASSIC_V7_STATUS_OFFSET];
	timestamp = pntoh64(&ep_pkt[PEEKCLASSIC_V7_TIMESTAMP_OFFSET]);

	/* force sliceLength to be the actual length of the packet */
	if (0 == sliceLength) {
		sliceLength = length;
	}
	/*
	 * The maximum value of sliceLength and length are 65535, which
	 * are less than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't
	 * need to check them.
	 */

	/* fill in packet header values */
	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	tsecs = (time_t) (timestamp/1000000);
	tusecs = (uint32_t) (timestamp - tsecs*1000000);
	rec->ts.secs  = tsecs - EPOCH_DELTA_1904_01_01_00_00_00_UTC;
	rec->ts.nsecs = tusecs * 1000;
	rec->rec_header.packet_header.len    = length;
	rec->rec_header.packet_header.caplen = sliceLength;
	pack_flags = 0;
	if (flags & FLAGS_HAS_CRC_ERROR)
		pack_flags |= PACK_FLAGS_CRC_ERROR;
	if (flags & FLAGS_FRAME_TOO_LONG)
		pack_flags |= PACK_FLAGS_PACKET_TOO_LONG;
	if (flags & FLAGS_FRAME_TOO_SHORT)
		pack_flags |= PACK_FLAGS_PACKET_TOO_SHORT;
	wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS, pack_flags);

	switch (wth->file_encap) {

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
		memset(&rec->rec_header.packet_header.pseudo_header.ieee_802_11, 0, sizeof(rec->rec_header.packet_header.pseudo_header.ieee_802_11));
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.fcs_len = 0;		/* no FCS */
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.decrypted = false;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.datapad = false;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_UNKNOWN;

		/*
		 * Now process the radio information pseudo-header.
		 * It's a 4-byte pseudo-header, consisting of:
		 *
		 *   1 byte of data rate, in units of 500 kb/s;
		 *
		 *   1 byte of channel number;
		 *
		 *   1 byte of signal strength as a percentage of
		 *   the maximum, i.e. (RXVECTOR RSSI/RXVECTOR RSSI_Max)*100,
		 *   or, at least, that's what I infer it is, given what
		 *   the WildPackets note "Converting Signal Strength
		 *   Percentage to dBm Values" says (it also says that
		 *   the conversion the percentage to a dBm value is
		 *   an adapter-dependent process, so, as we don't know
		 *   what type of adapter was used to do the capture,
		 *   we can't do the conversion);
		 *
		 *   1 byte of unknown content (padding?).
		 */
		if (rec->rec_header.packet_header.len < RADIO_INFO_SIZE || rec->rec_header.packet_header.caplen < RADIO_INFO_SIZE) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("peekclassic: 802.11 packet has length < 4");
			return -1;
		}
		rec->rec_header.packet_header.len -= RADIO_INFO_SIZE;
		rec->rec_header.packet_header.caplen -= RADIO_INFO_SIZE;
		sliceLength -= RADIO_INFO_SIZE;

		/* read the pseudo-header */
		if (!wtap_read_bytes(fh, radio_info, RADIO_INFO_SIZE, err, err_info))
			return -1;

		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_data_rate = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate = radio_info[0];

		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_channel = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.channel = radio_info[1];

		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_percent = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_percent = radio_info[2];

		/*
		 * We don't know they PHY, but we do have the data rate;
		 * try to guess it based on the data rate and channel.
		 */
		if (RATE_IS_DSSS(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate)) {
			/* 11b */
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11B;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11b.has_short_preamble = false;
		} else if (RATE_IS_OFDM(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate)) {
			/* 11a or 11g, depending on the band. */
			if (CHAN_IS_BG(rec->rec_header.packet_header.pseudo_header.ieee_802_11.channel)) {
				/* 11g */
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11G;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.has_mode = false;
			} else {
				/* 11a */
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11A;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.has_channel_type = false;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.has_turbo_type = false;
			}
		}

		/*
		 * The last 4 bytes appear to be random data - the length
		 * might include the FCS - so we reduce the length by 4.
		 *
		 * Or maybe this is just the same kind of random 4 bytes
		 * of junk at the end you get in Wireless Sniffer
		 * captures.
		 */
		if (rec->rec_header.packet_header.len < 4 || rec->rec_header.packet_header.caplen < 4) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("peekclassic: 802.11 packet has length < 8");
			return -1;
		}
		rec->rec_header.packet_header.len -= 4;
		rec->rec_header.packet_header.caplen -= 4;
		break;

	case WTAP_ENCAP_ETHERNET:
		/* XXX - it appears that if the low-order bit of
		   "status" is 0, there's an FCS in this frame,
		   and if it's 1, there's 4 bytes of 0. */
		rec->rec_header.packet_header.pseudo_header.eth.fcs_len = (status & 0x01) ? 0 : 4;
		break;
	}

	/* read the packet data */
	if (!wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info))
		return -1;

	return sliceLength;
}

static bool peekclassic_read_v56(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
	*data_offset = file_tell(wth->fh);

	/* read the packet */
	if (!peekclassic_read_packet_v56(wth, wth->fh, rec, buf,
	    err, err_info))
		return false;

	/*
	 * XXX - is the captured packet data padded to a multiple
	 * of 2 bytes?
	 */
	return true;
}

static bool peekclassic_seek_read_v56(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	/* read the packet */
	if (!peekclassic_read_packet_v56(wth, wth->random_fh, rec, buf,
	    err, err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return false;
	}
	return true;
}

static bool peekclassic_read_packet_v56(wtap *wth, FILE_T fh,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
	peekclassic_t *peekclassic = (peekclassic_t *)wth->priv;
	uint8_t ep_pkt[PEEKCLASSIC_V56_PKT_SIZE];
	uint16_t length;
	uint16_t sliceLength;
	uint8_t flags;
#if 0
	uint8_t status;
#endif
	uint32_t timestamp;
#if 0
	uint16_t destNum;
	uint16_t srcNum;
#endif
#if 0
	uint16_t protoNum;
	char    protoStr[8];
#endif
	uint32_t pack_flags;

	if (!wtap_read_bytes_or_eof(fh, ep_pkt, sizeof(ep_pkt), err, err_info))
		return false;

	/* Extract the fields from the packet */
	length = pntoh16(&ep_pkt[PEEKCLASSIC_V56_LENGTH_OFFSET]);
	sliceLength = pntoh16(&ep_pkt[PEEKCLASSIC_V56_SLICE_LENGTH_OFFSET]);
	flags = ep_pkt[PEEKCLASSIC_V56_FLAGS_OFFSET];
#if 0
	status = ep_pkt[PEEKCLASSIC_V56_STATUS_OFFSET];
#endif
	timestamp = pntoh32(&ep_pkt[PEEKCLASSIC_V56_TIMESTAMP_OFFSET]);
#if 0
	destNum = pntoh16(&ep_pkt[PEEKCLASSIC_V56_DESTNUM_OFFSET]);
	srcNum = pntoh16(&ep_pkt[PEEKCLASSIC_V56_SRCNUM_OFFSET]);
	protoNum = pntoh16(&ep_pkt[PEEKCLASSIC_V56_PROTONUM_OFFSET]);
	memcpy(protoStr, &ep_pkt[PEEKCLASSIC_V56_PROTOSTR_OFFSET],
	    sizeof protoStr);
#endif

	/*
	 * XXX - is the captured packet data padded to a multiple
	 * of 2 bytes?
	 */

	/* force sliceLength to be the actual length of the packet */
	if (0 == sliceLength) {
		sliceLength = length;
	}
	/*
	 * The maximum value of sliceLength and length are 65535, which
	 * are less than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't
	 * need to check them.
	 */

	/* fill in packet header values */
	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
	/* timestamp is in milliseconds since reference_time */
	rec->ts.secs  = peekclassic->reference_time + (timestamp / 1000);
	rec->ts.nsecs = 1000 * (timestamp % 1000) * 1000;
	rec->rec_header.packet_header.len      = length;
	rec->rec_header.packet_header.caplen   = sliceLength;
	pack_flags = 0;
	if (flags & FLAGS_HAS_CRC_ERROR)
		pack_flags |= PACK_FLAGS_CRC_ERROR;
	if (flags & FLAGS_FRAME_TOO_LONG)
		pack_flags |= PACK_FLAGS_PACKET_TOO_LONG;
	if (flags & FLAGS_FRAME_TOO_SHORT)
		pack_flags |= PACK_FLAGS_PACKET_TOO_SHORT;
	wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS, pack_flags);

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* We assume there's no FCS in this frame. */
		rec->rec_header.packet_header.pseudo_header.eth.fcs_len = 0;
		break;
	}

	/* read the packet data */
	return wtap_read_packet_bytes(fh, buf, sliceLength, err, err_info);
}

static const struct supported_block_type peekclassic_v56_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info peekclassic_v56_info = {
	"Savvius classic (V5 and V6)", "peekclassic56", "pkt", "tpc;apc;wpz",
	false, BLOCKS_SUPPORTED(peekclassic_v56_blocks_supported),
	NULL, NULL, NULL
};

static const struct supported_block_type peekclassic_v7_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info peekclassic_v7_info = {
	"Savvius classic (V7)", "peekclassic7", "pkt", "tpc;apc;wpz",
	false, BLOCKS_SUPPORTED(peekclassic_v7_blocks_supported),
	NULL, NULL, NULL
};

void register_peekclassic(void)
{
	peekclassic_v56_file_type_subtype = wtap_register_file_type_subtype(&peekclassic_v56_info);
	peekclassic_v7_file_type_subtype = wtap_register_file_type_subtype(&peekclassic_v7_info);

	/*
	 * Register names for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("PEEKCLASSIC_V56",
	    peekclassic_v56_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("PEEKCLASSIC_V7",
	    peekclassic_v7_file_type_subtype);
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
