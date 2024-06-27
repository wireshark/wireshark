/* commview.c
 * Routines for opening CommView NCF and NCFX file format packet captures
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on csids.c and nettl.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* A brief description of these file formats is available at:
 *    https://www.tamos.com/htmlhelp/commview/logformat.htm
 *    https://www.tamos.com/htmlhelp/commwifi/logformat.htm
 *
 * Use
 *
 *    https://web.archive.org/web/20171022225753/http://www.tamos.com/htmlhelp/commview/logformat.htm
 *
 * if that doesn't display anything.
 */

#include "config.h"
#include "commview.h"

#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/802_11-utils.h>

/*
 * Capture medium types used in NCF and NCFX;
 * Token Ring isn't used in NCFX.
 */
#define MEDIUM_ETHERNET		0
#define MEDIUM_WIFI		1
#define MEDIUM_TOKEN_RING	2

typedef struct commview_ncf_header {
	uint16_t	data_len;
	uint16_t	source_data_len;
	uint8_t		version;
	uint16_t	year;
	uint8_t		month;
	uint8_t		day;
	uint8_t		hours;
	uint8_t		minutes;
	uint8_t		seconds;
	uint32_t	usecs;
	uint8_t		flags;		/* Bit-field positions defined below */
	uint8_t		signal_level_percent;
	uint8_t		rate;
	uint8_t		band;
	uint8_t		channel;
	uint8_t		direction;	/* Or for WiFi, high order byte of
					 * packet rate. */
	int8_t		signal_level_dbm;	/* WiFi-only */
	int8_t		noise_level_dbm;	/* WiFi-only */
} commview_ncf_header_t;

#define COMMVIEW_NCF_HEADER_SIZE 24

/* Bit-field positions for various fields in the flags variable of the header */
#define FLAGS_MEDIUM		0x0F
#define FLAGS_DECRYPTED		0x10
#define FLAGS_BROKEN		0x20
#define FLAGS_COMPRESSED	0x40
#define FLAGS_RESERVED		0x80

/* Values for the band variable of the header */
#define BAND_11A		0x01
#define BAND_11B		0x02
#define BAND_11G		0x04
#define BAND_11A_TURBO		0x08
#define BAND_SUPERG		0x10
#define BAND_PUBLIC_SAFETY	0x20	/* 4.99 GHz public safety */
#define BAND_11N_5GHZ		0x40
#define BAND_11N_2_4GHZ		0x80

static bool commview_ncf_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                              int *err, char **err_info, int64_t *data_offset);
static bool commview_ncf_seek_read(wtap *wth, int64_t seek_off,
				   wtap_rec *rec,
				   Buffer *buf, int *err, char **err_info);
static bool commview_ncf_read_header(commview_ncf_header_t *cv_hdr, FILE_T fh,
				     int *err, char **err_info);
static bool commview_ncf_dump(wtap_dumper *wdh,	const wtap_rec *rec,
			      const uint8_t *pd, int *err, char **err_info);

static int commview_ncf_file_type_subtype = -1;
static int commview_ncfx_file_type_subtype = -1;

void register_commview(void);

wtap_open_return_val
commview_ncf_open(wtap *wth, int *err, char **err_info)
{
	commview_ncf_header_t cv_hdr;

	if(!commview_ncf_read_header(&cv_hdr, wth->fh, err, err_info)) {
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* If any of these fields do not match what we expect, bail out. */
	if(cv_hdr.version != 0 ||
	   cv_hdr.year < 1970 || cv_hdr.year >= 2038 ||
	   cv_hdr.month < 1 || cv_hdr.month > 12 ||
	   cv_hdr.day < 1 || cv_hdr.day > 31 ||
	   cv_hdr.hours > 23 ||
	   cv_hdr.minutes > 59 ||
	   cv_hdr.seconds > 60 ||
	   cv_hdr.signal_level_percent > 100 ||
	   (cv_hdr.flags & FLAGS_RESERVED) != 0 ||
	   ((cv_hdr.flags & FLAGS_MEDIUM) != MEDIUM_ETHERNET &&
	    (cv_hdr.flags & FLAGS_MEDIUM) != MEDIUM_WIFI &&
	    (cv_hdr.flags & FLAGS_MEDIUM) != MEDIUM_TOKEN_RING))
		return WTAP_OPEN_NOT_MINE; /* Not our kind of file */

	/* No file header. Reset the fh to 0 so we can read the first packet */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Set up the pointers to the handlers for this file type */
	wth->subtype_read = commview_ncf_read;
	wth->subtype_seek_read = commview_ncf_seek_read;

	wth->file_type_subtype = commview_ncf_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_PER_PACKET;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	return WTAP_OPEN_MINE; /* Our kind of file */
}

static int
commview_ncf_read_packet(FILE_T fh, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info)
{
	commview_ncf_header_t cv_hdr;
	struct tm tm;
	unsigned frequency;

	if(!commview_ncf_read_header(&cv_hdr, fh, err, err_info))
		return false;
	/*
	 * The maximum value of cv_hdr.data_len is 65535, which is less
	 * than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to
	 * check it.
	 */

	switch(cv_hdr.flags & FLAGS_MEDIUM) {

	case MEDIUM_ETHERNET :
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;
		rec->rec_header.packet_header.pseudo_header.eth.fcs_len = -1; /* Unknown */
		break;

	case MEDIUM_WIFI :
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
		memset(&rec->rec_header.packet_header.pseudo_header.ieee_802_11, 0, sizeof(rec->rec_header.packet_header.pseudo_header.ieee_802_11));
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.fcs_len = -1; /* Unknown */
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.decrypted = false;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.datapad = false;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_UNKNOWN;
		switch (cv_hdr.band) {

		case BAND_11A:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11A;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.has_channel_type = false;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.has_turbo_type = true;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.turbo_type =
			    PHDR_802_11A_TURBO_TYPE_NORMAL;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, false);
			break;

		case BAND_11B:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11B;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11b.has_short_preamble = false;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, true);
			break;

		case BAND_11G:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11G;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.has_mode = true;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.mode =
			    PHDR_802_11G_MODE_NORMAL;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, true);
			break;

		case BAND_11A_TURBO:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11A;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.has_turbo_type = true;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.turbo_type =
			    PHDR_802_11A_TURBO_TYPE_TURBO;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, false);
			break;

		case BAND_SUPERG:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11G;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.has_mode = true;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.mode =
			    PHDR_802_11G_MODE_SUPER_G;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, true);
			break;

		case BAND_11N_5GHZ:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11N;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, false);
			break;

		case BAND_11N_2_4GHZ:
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11N;
			frequency = ieee80211_chan_to_mhz(cv_hdr.channel, true);
			break;

		case BAND_PUBLIC_SAFETY:
			/*
			 * XXX - what do we do here?  What are the channel
			 * numbers?  How do we distinguish the several
			 * different flavors of 4.9 GHz frequencies?
			 */
			frequency = 0;
			break;

		default:
			frequency = 0;
			break;
		}
		if (frequency != 0) {
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_frequency = true;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.frequency = frequency;
		}
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_channel = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.channel = cv_hdr.channel;

		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_data_rate = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate =
		    cv_hdr.rate | (cv_hdr.direction << 8);

		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_percent = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_percent = cv_hdr.signal_level_percent;

		/*
		 * XXX - these are positive in captures I've seen; does
		 * that mean that they are the negative of the actual
		 * dBm value?  (80 dBm is a bit more power than most
		 * countries' regulatory agencies are likely to allow
		 * any individual to have in their home. :-))
		 *
		 * XXX - sometimes these are 0; assume that means that no
		 * value is provided.
		 */
		if (cv_hdr.signal_level_dbm != 0) {
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_dbm = -cv_hdr.signal_level_dbm;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_dbm = true;
		}
		if (cv_hdr.noise_level_dbm != 0) {
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.noise_dbm = -cv_hdr.noise_level_dbm;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_noise_dbm = true;
		}
		if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy == PHDR_802_11_PHY_UNKNOWN) {
			/*
			 * We don't know they PHY, but we do have the
			 * data rate; try to guess it based on the
			 * data rate and center frequency.
			 */
			if (RATE_IS_DSSS(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate)) {
				/* 11b */
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11B;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11b.has_short_preamble = false;
			} else if (RATE_IS_OFDM(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate)) {
				/* 11a or 11g, depending on the band. */
				if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_frequency) {
					if (FREQ_IS_BG(rec->rec_header.packet_header.pseudo_header.ieee_802_11.frequency)) {
						/* 11g */
						rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11G;
					} else {
						/* 11a */
						rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11A;
					}
				}
			}
		} else if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy == PHDR_802_11_PHY_11G) {
			if (RATE_IS_DSSS(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate)) {
				/* DSSS, so 11b. */
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11B;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11b.has_short_preamble = false;
			}
		}
		break;

	case MEDIUM_TOKEN_RING :
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_TOKEN_RING;
		break;

	default :
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("commview: unsupported encap for NCF: %u",
					    cv_hdr.flags & FLAGS_MEDIUM);
		return false;
	}

	tm.tm_year = cv_hdr.year - 1900;
	tm.tm_mon = cv_hdr.month - 1;
	tm.tm_mday = cv_hdr.day;
	tm.tm_hour = cv_hdr.hours;
	tm.tm_min = cv_hdr.minutes;
	tm.tm_sec = cv_hdr.seconds;
	tm.tm_isdst = -1;

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS;

	rec->rec_header.packet_header.len = cv_hdr.data_len;
	rec->rec_header.packet_header.caplen = cv_hdr.data_len;

	rec->ts.secs = mktime(&tm);
	rec->ts.nsecs = cv_hdr.usecs * 1000;

	return wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info);
}

static bool
commview_ncf_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    char **err_info, int64_t *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return commview_ncf_read_packet(wth->fh, rec, buf, err, err_info);
}

static bool
commview_ncf_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	return commview_ncf_read_packet(wth->random_fh, rec, buf, err, err_info);
}

static bool
commview_ncf_read_header(commview_ncf_header_t *cv_hdr, FILE_T fh, int *err,
    char **err_info)
{
	if (!wtap_read_bytes_or_eof(fh, &cv_hdr->data_len, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->source_data_len, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->version, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->year, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->month, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->day, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->hours, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->minutes, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->seconds, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->usecs, 4, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->flags, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->signal_level_percent, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->rate, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->band, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->channel, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->direction, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->signal_level_dbm, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->noise_level_dbm, 1, err, err_info))
		return false;

	/* Convert multi-byte values from little endian to host endian format */
	cv_hdr->data_len = GUINT16_FROM_LE(cv_hdr->data_len);
	cv_hdr->source_data_len = GUINT16_FROM_LE(cv_hdr->source_data_len);
	cv_hdr->year = GUINT16_FROM_LE(cv_hdr->year);
	cv_hdr->usecs = GUINT32_FROM_LE(cv_hdr->usecs);

	return true;
}

/* Returns 0 if we can write out the specified encapsulation type
 * into a CommView format file. */
static int
commview_ncf_dump_can_write_encap(int encap)
{
	switch (encap) {

	case WTAP_ENCAP_ETHERNET :
	case WTAP_ENCAP_IEEE_802_11 :
	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO :
	case WTAP_ENCAP_TOKEN_RING :
	case WTAP_ENCAP_PER_PACKET :
		return 0;

	default:
		return WTAP_ERR_UNWRITABLE_ENCAP;
	}
}

/* Returns true on success, false on failure;
   sets "*err" to an error code on failure */
static bool
commview_ncf_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_)
{
	wdh->subtype_write = commview_ncf_dump;

	/* There is no file header to write out */
	return true;
}

/* Write a record for a packet to a dump file.
 * Returns true on success, false on failure. */
static bool
commview_ncf_dump(wtap_dumper *wdh, const wtap_rec *rec, const uint8_t *pd,
    int *err, char **err_info _U_)
{
	commview_ncf_header_t cv_hdr = {0};
	struct tm *tm;

	/* We can only write packet records. */
	if (rec->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		return false;
	}

	/* Don't write out anything bigger than we can read.
	 * (The length field in packet headers is 16 bits, which
	 * imposes a hard limit.) */
	if (rec->rec_header.packet_header.caplen > 65535) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return false;
	}

	cv_hdr.data_len = GUINT16_TO_LE((uint16_t)rec->rec_header.packet_header.caplen);
	cv_hdr.source_data_len = GUINT16_TO_LE((uint16_t)rec->rec_header.packet_header.caplen);
	cv_hdr.version = 0;

	tm = localtime(&rec->ts.secs);
	if (tm != NULL) {
		cv_hdr.year = GUINT16_TO_LE(tm->tm_year + 1900);
		cv_hdr.month = tm->tm_mon + 1;
		cv_hdr.day = tm->tm_mday;
		cv_hdr.hours = tm->tm_hour;
		cv_hdr.minutes = tm->tm_min;
		cv_hdr.seconds = tm->tm_sec;
		cv_hdr.usecs = GUINT32_TO_LE(rec->ts.nsecs / 1000);
	} else {
		/*
		 * Second before the Epoch.
		 */
		cv_hdr.year = GUINT16_TO_LE(1969);
		cv_hdr.month = 12;
		cv_hdr.day = 31;
		cv_hdr.hours = 23;
		cv_hdr.minutes = 59;
		cv_hdr.seconds = 59;
		cv_hdr.usecs = 0;
	}

	switch(rec->rec_header.packet_header.pkt_encap) {

	case WTAP_ENCAP_ETHERNET :
		cv_hdr.flags |= MEDIUM_ETHERNET;
		break;

	case WTAP_ENCAP_IEEE_802_11 :
		cv_hdr.flags |=  MEDIUM_WIFI;
		break;

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO :
		cv_hdr.flags |=  MEDIUM_WIFI;

		switch (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy) {

		case PHDR_802_11_PHY_11A:
			/*
			 * If we don't know whether it's turbo, say it's
			 * not.
			 */
			if (!rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.has_turbo_type ||
			    rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11a.turbo_type == PHDR_802_11A_TURBO_TYPE_NORMAL)
				cv_hdr.band = BAND_11A;
			else
				cv_hdr.band = BAND_11A_TURBO;
			break;

		case PHDR_802_11_PHY_11B:
			cv_hdr.band = BAND_11B;
			break;

		case PHDR_802_11_PHY_11G:
			/*
			 * If we don't know whether it's Super G, say it's
			 * not.
			 */
			if (!rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.has_mode)
				cv_hdr.band = BAND_11G;
			else {
				switch (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11g.mode) {

				case PHDR_802_11G_MODE_NORMAL:
					cv_hdr.band = BAND_11G;
					break;

				case PHDR_802_11G_MODE_SUPER_G:
					cv_hdr.band = BAND_SUPERG;
					break;

				default:
					cv_hdr.band = BAND_11G;
					break;
				}
			}
			break;

		case PHDR_802_11_PHY_11N:
			/*
			 * Pick the band based on the frequency.
			 */
			if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_frequency) {
				if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.frequency > 2484) {
					/* 5 GHz band */
					cv_hdr.band = BAND_11N_5GHZ;
				} else {
					/* 2.4 GHz band */
					cv_hdr.band = BAND_11N_2_4GHZ;
				}
			} else {
				/* Band is unknown. */
				cv_hdr.band = 0;
			}
			break;

		default:
			/*
			 * It's not documented how they handle 11ac,
			 * and they don't support the older PHYs.
			 */
			cv_hdr.band = 0;
			break;
		}
		cv_hdr.channel =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_channel ?
		      rec->rec_header.packet_header.pseudo_header.ieee_802_11.channel :
		      0;
		cv_hdr.rate =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_data_rate ?
		      (uint8_t)(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate & 0xFF) :
		      0;
		cv_hdr.direction =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_data_rate ?
		      (uint8_t)((rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate >> 8) & 0xFF) :
		      0;
		cv_hdr.signal_level_percent =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_percent ?
		      rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_percent :
		      0;
		cv_hdr.signal_level_dbm =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_dbm ?
		      -rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_dbm :
		      0;
		cv_hdr.noise_level_dbm =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_noise_dbm ?
		      -rec->rec_header.packet_header.pseudo_header.ieee_802_11.noise_dbm :
		      0;
		break;

	case WTAP_ENCAP_TOKEN_RING :
		cv_hdr.flags |= MEDIUM_TOKEN_RING;
		break;

	default :
		*err = WTAP_ERR_UNWRITABLE_ENCAP;
		return false;
	}

	if (!wtap_dump_file_write(wdh, &cv_hdr.data_len, 2, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.source_data_len, 2, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.version, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.year, 2, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.month, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.day, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.hours, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.minutes, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.seconds, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.usecs, 4, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.flags, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.signal_level_percent, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.rate, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.band, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.channel, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.direction, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.signal_level_dbm, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.noise_level_dbm, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
		return false;
	return true;
}

typedef struct commview_ncfx_header {
	uint32_t	data_len;
	uint16_t	year;
	uint8_t		month;
	uint8_t		day;
	uint8_t		hours;
	uint8_t		minutes;
	uint8_t		seconds;
	uint32_t	usecs;
	uint8_t		medium_type;
	uint8_t		decryption_flag;
	uint8_t		direction;
	uint8_t		reserved1;
	uint8_t		reserved2;
} commview_ncfx_header_t;

#define COMMVIEW_NCFX_HEADER_SIZE	20

typedef struct commview_ncfx_rf_header {
	uint16_t	header_len;		/* includes extension headers */
	uint16_t	status_modulation;
	uint16_t	frequency_band;
	uint16_t	channel;
	uint8_t		noise_level_dbm;	/* abs(noise in dBm) */
	uint8_t		signal_level_dbm;	/* abs(signal in dBm) */
	uint8_t		signal_level_percent;
	uint8_t		reserved;
	uint32_t	phy_rate;		/* in 100Kbps units */
	uint32_t	extensions_present;
} commview_ncfx_rf_header_t;

#define COMMVIEW_NCFX_RF_HEADER_SIZE	20

typedef struct commview_ncfx_mcs_header {
	uint8_t		mcs_index;
	uint8_t		n_streams;
	uint8_t		channel_width;
	uint8_t		guard_interval;
} commview_ncfx_mcs_header_t;

#define COMMVIEW_NCFX_MCS_HEADER_SIZE	4

/*
 * Bit-field positions for various fields in the status_modulation variable
 * of the header.
 */
#define STATUS_MODULATION_BAD_FCS	0x01
#define STATUS_MODULATION_HT_PHY	0x02
#define STATUS_MODULATION_VHT_PHY	0x04
#define STATUS_MODULATION_HE_PHY	0x08
#define STATUS_MODULATION_HE_OFDMA	0x10

/* Values for the frequency_band variable of the header */
#define BAND_5GHZ		0x40
#define BAND_2_4GHZ		0x80

/* Presence bits */
#define PRESENCE_MCS_HEADER	0x00000001	/* type 0, bit 0 */

static bool commview_ncfx_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool commview_ncfx_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool commview_ncfx_read_header(commview_ncfx_header_t *cv_hdr,
    FILE_T fh, int *err, char **err_info);
static bool commview_ncfx_read_rf_header(commview_ncfx_rf_header_t *cv_rf_hdr,
    FILE_T fh, int *err, char **err_info);
static bool commview_ncfx_read_mcs_header(commview_ncfx_mcs_header_t *cv_mcs_hdr,
    FILE_T fh, int *err, char **err_info);
static bool commview_ncfx_dump(wtap_dumper *wdh, const wtap_rec *rec,
     const uint8_t *pd, int *err, char **err_info);

wtap_open_return_val
commview_ncfx_open(wtap *wth, int *err, char **err_info)
{
	commview_ncfx_header_t cv_hdr;

	if(!commview_ncfx_read_header(&cv_hdr, wth->fh, err, err_info)) {
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* If any of these fields do not match what we expect, bail out. */
	if(cv_hdr.year < 2000 || /* XXX - when was this format introduced? */
	   cv_hdr.month < 1 || cv_hdr.month > 12 ||
	   cv_hdr.day < 1 || cv_hdr.day > 31 ||
	   cv_hdr.hours > 23 ||
	   cv_hdr.minutes > 59 ||
	   cv_hdr.seconds > 60)
		return WTAP_OPEN_NOT_MINE; /* Not our kind of file */
	switch (cv_hdr.medium_type) {

	case MEDIUM_ETHERNET:
		if (cv_hdr.direction != 0x00 &&
		    cv_hdr.direction != 0x01 &&
		    cv_hdr.direction != 0x02)
			return WTAP_OPEN_NOT_MINE; /* Not our kind of file */
		break;

	case MEDIUM_WIFI:
		if (cv_hdr.decryption_flag != 0x00 &&
		    cv_hdr.decryption_flag != 0x01)
			return WTAP_OPEN_NOT_MINE; /* Not our kind of file */
		if (cv_hdr.direction != 0x00)
			return WTAP_OPEN_NOT_MINE; /* Not our kind of file */
		break;

	default:
		return WTAP_OPEN_NOT_MINE; /* Not our kind of file */
	}

	/* No file header. Reset the fh to 0 so we can read the first packet */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Set up the pointers to the handlers for this file type */
	wth->subtype_read = commview_ncfx_read;
	wth->subtype_seek_read = commview_ncfx_seek_read;

	wth->file_type_subtype = commview_ncfx_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_PER_PACKET;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	return WTAP_OPEN_MINE; /* Our kind of file */
}

static int
commview_ncfx_read_packet(FILE_T fh, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info)
{
	commview_ncfx_header_t cv_hdr;
	uint32_t length_remaining;
	struct tm tm;
	commview_ncfx_rf_header_t cv_rf_hdr;
	unsigned frequency;
	commview_ncfx_mcs_header_t cv_mcs_hdr;

	if (!commview_ncfx_read_header(&cv_hdr, fh, err, err_info))
		return false;

	/* Amount of data remaining in the record, after the header */
	length_remaining = cv_hdr.data_len - COMMVIEW_NCFX_HEADER_SIZE;

	switch(cv_hdr.medium_type) {

	case MEDIUM_ETHERNET :
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;
		rec->rec_header.packet_header.pseudo_header.eth.fcs_len = -1; /* Unknown */
		break;

	case MEDIUM_WIFI :
		rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
		memset(&rec->rec_header.packet_header.pseudo_header.ieee_802_11, 0, sizeof(rec->rec_header.packet_header.pseudo_header.ieee_802_11));
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.fcs_len = 0; /* No FCS */
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.decrypted = (cv_hdr.decryption_flag == 0x01);
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.datapad = false;

		/*
		 * Make sure we have enough data left for the RF header.
		 */
		if (length_remaining < COMMVIEW_NCFX_RF_HEADER_SIZE) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("commview: RF header goes past the NCFX data length %u",
			    cv_hdr.data_len);
			return false;
		}
		length_remaining -= COMMVIEW_NCFX_RF_HEADER_SIZE;

		/*
		 * Read the RF header.
		 */
		if (!commview_ncfx_read_rf_header(&cv_rf_hdr, fh, err, err_info))
			return false;
		if (cv_rf_hdr.status_modulation & STATUS_MODULATION_HE_PHY)
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11AX;
		else if (cv_rf_hdr.status_modulation & STATUS_MODULATION_VHT_PHY)
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11AC;
		else if (cv_rf_hdr.status_modulation & STATUS_MODULATION_HT_PHY)
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11N;
		else {
			/*
			 * Unknown PHY, for now.
			 */
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_UNKNOWN;
		}
		switch (cv_rf_hdr.frequency_band) {

		case BAND_5GHZ:
			frequency = ieee80211_chan_to_mhz(cv_rf_hdr.channel, false);
			if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy == PHDR_802_11_PHY_UNKNOWN) {
				/*
				 * None of the modulation bits were set, so
				 * this is presumably the 11a OFDM PHY.
				 */
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11A;
			}
			break;

		case BAND_2_4GHZ:
			frequency = ieee80211_chan_to_mhz(cv_rf_hdr.channel, true);
			if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy == PHDR_802_11_PHY_UNKNOWN) {
				/*
				 * None of the modulation bits were set, so
				 * guess the PHY based on the data rate.
				 *
				 * cv_rf_hdr.phy_rate is in units of 100
				 * Kbits/s.
				 */
				if (cv_rf_hdr.phy_rate == 10 /* 1 Mb/s */ ||
				    cv_rf_hdr.phy_rate == 20 /* 2 Mb/s */ ||
				    cv_rf_hdr.phy_rate == 55 /* 5.5 Mb/s */ ||
				    cv_rf_hdr.phy_rate == 110 /* 11 Mb/s */ ||
				    cv_rf_hdr.phy_rate == 220 /* 22 Mb/s */ ||
				    cv_rf_hdr.phy_rate == 330 /* 33 Mb/s */)
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11B;
				else
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy = PHDR_802_11_PHY_11G;
			}
			break;

		default:
			frequency = 0;
			break;
		}
		if (frequency != 0) {
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_frequency = true;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.frequency = frequency;
		}
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_channel = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.channel = cv_rf_hdr.channel;

		/*
		 * cv_rf_hdr.phy_rate is in units of 100 Kbits/s.
		 *
		 * pseudo_header.ieee_802_11.data_rate is in units of 500
		 * Kbits/s.
		 */
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_data_rate = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate =
		    cv_rf_hdr.phy_rate/5;

		rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_percent = true;
		rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_percent = cv_rf_hdr.signal_level_percent;

		/*
		 * These is the absolute value of the signal and noise,
		 * in dBm.  The value is the negative of that.
		 *
		 * XXX - sometimes these are 0; assume that means that no
		 * value is provided.
		 */
		if (cv_rf_hdr.signal_level_dbm != 0) {
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_dbm = -cv_rf_hdr.signal_level_dbm;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_dbm = true;
		}
		if (cv_rf_hdr.noise_level_dbm != 0) {
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.noise_dbm = -cv_rf_hdr.noise_level_dbm;
			rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_noise_dbm = true;
		}

		if (cv_rf_hdr.extensions_present & PRESENCE_MCS_HEADER) {
			/*
			 * Make sure we have enough data left for the
			 * MCS header.
			 */
			if (length_remaining < COMMVIEW_NCFX_MCS_HEADER_SIZE) {
				*err = WTAP_ERR_BAD_FILE;
				*err_info = ws_strdup_printf("commview: MCS header goes past the NCFX data length %u",
				    cv_hdr.data_len);
				return false;
			}
			length_remaining -= COMMVIEW_NCFX_MCS_HEADER_SIZE;

			/*
			 * Read the MCS header.
			 */
			if (!commview_ncfx_read_mcs_header(&cv_mcs_hdr, fh,
			    err, err_info))
				return false;
			switch (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy) {

			case PHDR_802_11_PHY_11N:
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11n.has_mcs_index = true;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11n.mcs_index = cv_mcs_hdr.mcs_index;
				/* number of STBC streams? */
				switch (cv_mcs_hdr.channel_width) {

				case 0x00:
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11n.has_bandwidth = true;
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_20_MHZ;
					break;

				case 0x01:
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11n.has_bandwidth = true;
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11n.bandwidth = PHDR_802_11_BANDWIDTH_40_MHZ;
					break;

				default:
					break;
				}
				/* Guard interval? */
				break;

			case PHDR_802_11_PHY_11AC:
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.mcs[0] = cv_mcs_hdr.mcs_index;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.mcs[1] = 0;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.mcs[2] = 0;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.mcs[3] = 0;
				/* Remaining MCS indices? */
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.nss[0] = cv_mcs_hdr.n_streams;
				switch (cv_mcs_hdr.channel_width) {

				case 0x00:
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.has_bandwidth = true;
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.bandwidth = PHDR_802_11_BANDWIDTH_20_MHZ;
					break;

				case 0x01:
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.has_bandwidth = true;
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.bandwidth = PHDR_802_11_BANDWIDTH_40_MHZ;
					break;

				case 0x02:
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.has_bandwidth = true;
					rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ac.bandwidth = PHDR_802_11_BANDWIDTH_80_MHZ;
					break;

				default:
					break;
				}
				/* Guard interval? */
				break;

			case PHDR_802_11_PHY_11AX:
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ax.has_mcs_index = true;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ax.mcs = cv_mcs_hdr.mcs_index;
				rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy_info.info_11ax.nsts = cv_mcs_hdr.n_streams;
				/* Bandwidth stuff? */
				/* Guard interval? */
				break;

			default:
				break;
			}
		}
		break;

	default :
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("commview: unsupported encap for NCFX: %u",
					    cv_hdr.medium_type);
		return false;
	}

	tm.tm_year = cv_hdr.year - 1900;
	tm.tm_mon = cv_hdr.month - 1;
	tm.tm_mday = cv_hdr.day;
	tm.tm_hour = cv_hdr.hours;
	tm.tm_min = cv_hdr.minutes;
	tm.tm_sec = cv_hdr.seconds;
	tm.tm_isdst = -1;

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS;

	if (length_remaining > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("commview: File has %u-byte packet, bigger than maximum of %u",
		    length_remaining, WTAP_MAX_PACKET_SIZE_STANDARD);
		return false;
	}

	rec->rec_header.packet_header.len = length_remaining;
	rec->rec_header.packet_header.caplen = length_remaining;

	rec->ts.secs = mktime(&tm);
	rec->ts.nsecs = cv_hdr.usecs * 1000;

	return wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info);
}

static bool
commview_ncfx_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    char **err_info, int64_t *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return commview_ncfx_read_packet(wth->fh, rec, buf, err, err_info);
}

static bool
commview_ncfx_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	return commview_ncfx_read_packet(wth->random_fh, rec, buf, err, err_info);
}

static bool
commview_ncfx_read_header(commview_ncfx_header_t *cv_hdr, FILE_T fh, int *err,
    char **err_info)
{
	if (!wtap_read_bytes_or_eof(fh, &cv_hdr->data_len, 4, err, err_info))
		return false;

	/* Convert data length from little endian to host endian format */
	cv_hdr->data_len = GUINT32_FROM_LE(cv_hdr->data_len);

	/* It must be at least the length of the general header. */
	if (cv_hdr->data_len < COMMVIEW_NCFX_HEADER_SIZE) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("commview: NCFX data length %u < %u",
					    cv_hdr->data_len,
					    COMMVIEW_NCFX_HEADER_SIZE);
		return false;
	}

	if (!wtap_read_bytes(fh, &cv_hdr->year, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->month, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->day, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->hours, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->minutes, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->seconds, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->usecs, 4, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->medium_type, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->decryption_flag, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->direction, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->reserved1, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_hdr->reserved2, 1, err, err_info))
		return false;

	/* Convert multi-byte values from little endian to host endian format */
	cv_hdr->year = GUINT16_FROM_LE(cv_hdr->year);
	cv_hdr->usecs = GUINT32_FROM_LE(cv_hdr->usecs);

	return true;
}

static bool
commview_ncfx_read_rf_header(commview_ncfx_rf_header_t *cv_rf_hdr, FILE_T fh,
    int *err, char **err_info)
{
	if (!wtap_read_bytes(fh, &cv_rf_hdr->header_len, 2, err, err_info))
		return false;

	/* Convert header length from little endian to host endian format */
	cv_rf_hdr->header_len = GUINT16_FROM_LE(cv_rf_hdr->header_len);

	if (!wtap_read_bytes(fh, &cv_rf_hdr->status_modulation, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->frequency_band, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->channel, 2, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->noise_level_dbm, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->signal_level_dbm, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->signal_level_percent, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->reserved, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->phy_rate, 4, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_rf_hdr->extensions_present, 4, err, err_info))
		return false;

	/* Convert remaining multi-byte values from little endian to host endian format */
	cv_rf_hdr->status_modulation = GUINT16_FROM_LE(cv_rf_hdr->status_modulation);
	cv_rf_hdr->frequency_band = GUINT16_FROM_LE(cv_rf_hdr->frequency_band);
	cv_rf_hdr->channel = GUINT16_FROM_LE(cv_rf_hdr->channel);
	cv_rf_hdr->phy_rate = GUINT32_FROM_LE(cv_rf_hdr->phy_rate);
	cv_rf_hdr->extensions_present = GUINT32_FROM_LE(cv_rf_hdr->extensions_present);

	return true;
}

static bool
commview_ncfx_read_mcs_header(commview_ncfx_mcs_header_t *cv_mcs_hdr, FILE_T fh,
    int *err, char **err_info)
{
	if (!wtap_read_bytes(fh, &cv_mcs_hdr->mcs_index, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_mcs_hdr->n_streams, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_mcs_hdr->channel_width, 1, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &cv_mcs_hdr->guard_interval, 1, err, err_info))
		return false;

	return true;
}

/* Returns 0 if we can write out the specified encapsulation type
 * into a CommView format file. */
static int
commview_ncfx_dump_can_write_encap(int encap)
{
	switch (encap) {

	case WTAP_ENCAP_ETHERNET :
	case WTAP_ENCAP_IEEE_802_11 :
	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO :
	case WTAP_ENCAP_PER_PACKET :
		return 0;

	default:
		return WTAP_ERR_UNWRITABLE_ENCAP;
	}
}

/* Returns true on success, false on failure;
   sets "*err" to an error code on failure */
static bool
commview_ncfx_dump_open(wtap_dumper *wdh, int *err _U_, char **err_info _U_)
{
	wdh->subtype_write = commview_ncfx_dump;

	/* There is no file header to write out */
	return true;
}

/* Write a record for a packet to a dump file.
 * Returns true on success, false on failure. */
static bool
commview_ncfx_dump(wtap_dumper *wdh, const wtap_rec *rec, const uint8_t *pd,
    int *err, char **err_info _U_)
{
	commview_ncfx_header_t cv_hdr = {0};
	struct tm *tm;

	/* We can only write packet records. */
	if (rec->rec_type != REC_TYPE_PACKET) {
		*err = WTAP_ERR_UNWRITABLE_REC_TYPE;
		return false;
	}

	/* Don't write out anything bigger than we can read.
	 * (The length field in packet headers is 16 bits, which
	 * imposes a hard limit.) */
	if (rec->rec_header.packet_header.caplen > 65535) {
		*err = WTAP_ERR_PACKET_TOO_LARGE;
		return false;
	}

	cv_hdr.data_len = GUINT32_TO_LE((uint32_t)rec->rec_header.packet_header.caplen);

	tm = localtime(&rec->ts.secs);
	if (tm != NULL) {
		cv_hdr.year = GUINT16_TO_LE(tm->tm_year + 1900);
		cv_hdr.month = tm->tm_mon + 1;
		cv_hdr.day = tm->tm_mday;
		cv_hdr.hours = tm->tm_hour;
		cv_hdr.minutes = tm->tm_min;
		cv_hdr.seconds = tm->tm_sec;
		cv_hdr.usecs = GUINT32_TO_LE(rec->ts.nsecs / 1000);
	} else {
		/*
		 * Second before the Epoch.
		 */
		cv_hdr.year = GUINT16_TO_LE(1969);
		cv_hdr.month = 12;
		cv_hdr.day = 31;
		cv_hdr.hours = 23;
		cv_hdr.minutes = 59;
		cv_hdr.seconds = 59;
		cv_hdr.usecs = 0;
	}
	cv_hdr.reserved1 = 0;
	cv_hdr.reserved2 = 0;

	switch(rec->rec_header.packet_header.pkt_encap) {

	case WTAP_ENCAP_ETHERNET :
		cv_hdr.medium_type = MEDIUM_ETHERNET;
		cv_hdr.decryption_flag = 0x00;
		cv_hdr.direction = 0x00;	/* what does this mean? */
		break;

	case WTAP_ENCAP_IEEE_802_11 :
		/* XXX - the claim is that the RF header is mandatory */
		cv_hdr.medium_type = MEDIUM_WIFI;
		break;

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO :
		cv_hdr.medium_type = MEDIUM_WIFI;

#if 0
		switch (rec->rec_header.packet_header.pseudo_header.ieee_802_11.phy) {

		case PHDR_802_11_PHY_11N:
			cv_hdr.status_modulation = STATUS_MODULATION_HT_PHY;
			break;

		case PHDR_802_11_PHY_11AC:
			cv_hdr.status_modulation = STATUS_MODULATION_VHT_PHY;
			break;

		case PHDR_802_11_PHY_11AX:
			cv_hdr.status_modulation = STATUS_MODULATION_HE_PHY;
			break;

		default:
			cv_hdr.status_modulation = 0;
			break;
		}

		/*
		 * Pick the band based on the frequency.
		 */
		if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_frequency) {
			if (rec->rec_header.packet_header.pseudo_header.ieee_802_11.frequency > 2484) {
				/* 5 GHz band */
				cv_hdr.frequency_band = BAND_5GHZ;
			} else {
				/* 2.4 GHz band */
				cv_hdr.frequency_band = BAND_2_4GHZ;
			}
		} else {
			/* Band is unknown. */
			cv_hdr.band = 0;
		}

		cv_hdr.channel =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_channel ?
		      rec->rec_header.packet_header.pseudo_header.ieee_802_11.channel :
		      0;
		cv_hdr.noise_level_dbm =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_noise_dbm ?
		      -rec->rec_header.packet_header.pseudo_header.ieee_802_11.noise_dbm :
		      0;
		cv_hdr.signal_level_dbm =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_dbm ?
		      -rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_dbm :
		      0;
		cv_hdr.signal_level_percent =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_signal_percent ?
		      rec->rec_header.packet_header.pseudo_header.ieee_802_11.signal_percent :
		      0;
		cv_hdr.reserved = 0;
		cv_hdr.phy_rate =
		    rec->rec_header.packet_header.pseudo_header.ieee_802_11.has_data_rate ?
		      (uint32_t)(rec->rec_header.packet_header.pseudo_header.ieee_802_11.data_rate & 0xFF) :
		      0;
#endif
		break;

	default :
		*err = WTAP_ERR_UNWRITABLE_ENCAP;
		return false;
	}

	if (!wtap_dump_file_write(wdh, &cv_hdr.data_len, 4, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.year, 2, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.month, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.day, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.hours, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.minutes, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.seconds, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.usecs, 4, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.medium_type, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.decryption_flag, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.direction, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.reserved1, 1, err))
		return false;
	if (!wtap_dump_file_write(wdh, &cv_hdr.reserved2, 1, err))
		return false;

	/* XXX - RF and MCS headers */

	if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
		return false;

	return true;
}

static const struct supported_block_type commview_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info commview_ncf_info = {
	"TamoSoft CommView NCF", "commview-ncf", "ncf", NULL,
	false, BLOCKS_SUPPORTED(commview_blocks_supported),
	commview_ncf_dump_can_write_encap, commview_ncf_dump_open, NULL
};

static const struct file_type_subtype_info commview_ncfx_info = {
	"TamoSoft CommView NCFX", "commview-ncfx", "ncfx", NULL,
	false, BLOCKS_SUPPORTED(commview_blocks_supported),
	commview_ncfx_dump_can_write_encap, commview_ncfx_dump_open, NULL
};

void register_commview(void)
{
	commview_ncf_file_type_subtype = wtap_register_file_type_subtype(&commview_ncf_info);
	commview_ncfx_file_type_subtype = wtap_register_file_type_subtype(&commview_ncfx_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 *
	 * We don't need to register the new type, as the Wireshark
	 * version with which we're providing backwards compatibility
	 * didn't support the NCFX format.  New code should fetch
	 * the file type/subtype with wtap_name_to_file_type_subtype().
	 */
	wtap_register_backwards_compatibility_lua_name("COMMVIEW",
	    commview_ncf_file_type_subtype);
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
