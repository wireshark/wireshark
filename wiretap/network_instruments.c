/*
 * $Id: network_instruments.c,v 1.1 2003/10/31 00:43:21 guy Exp $
 */

/***************************************************************************
                          NetworkInstruments.c  -  description
                             -------------------
    begin                : Wed Oct 29 2003
    copyright            : (C) 2003 by root
    email                : scotte[AT}netinst.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "network_instruments.h"

static const char network_instruments_magic[] = {"ObserverPktBufferVersion=09.00"};
static const int true_magic_length = 17;

static const guint32 observer_packet_magic = 0x88888888;

	static const int observer_encap[] = {
		WTAP_ENCAP_ETHERNET,
		WTAP_ENCAP_TOKEN_RING
	};
#define NUM_OBSERVER_ENCAPS (sizeof observer_encap / sizeof observer_encap[0])

static gboolean fill_time_struct(guint64 ns_since2000, observer_time* time_conversion);
static gboolean observer_read(wtap *wth, int *err, long *data_offset);
static gboolean observer_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err);

int network_instruments_open(wtap *wth, int *err)
{
	int bytes_read;
	long seek_value;

	capture_file_header file_header;
	packet_entry_header packet_header;

	errno = WTAP_ERR_CANT_READ;

	/* Read in the buffer file header */
	bytes_read = file_read(&file_header, sizeof file_header, 1, wth->fh);
	if (bytes_read != sizeof file_header) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* check the magic number */
	if (memcmp(file_header.observer_version, network_instruments_magic, true_magic_length)!=0) {
		return 0;
	}

	/* check the version */
	if (strncmp(network_instruments_magic, file_header.observer_version, 30)!=0) {
		g_message("Observer: unsupported file version %s", file_header.observer_version);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/* get to the first packet */
	file_header.offset_to_first_packet =
	    GUINT16_FROM_LE(file_header.offset_to_first_packet);
	seek_value = file_seek(wth->fh, file_header.offset_to_first_packet, SEEK_SET, err);
	if (seek_value != file_header.offset_to_first_packet) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* pull off the packet header */
	bytes_read = file_read(&packet_header, sizeof packet_header, 1, wth->fh);
	if (bytes_read != sizeof packet_header) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* check the packet's magic number; the magic number is all 8's,
	   so the byte order doesn't matter */
	if (packet_header.packet_magic != observer_packet_magic) {
		g_message("Observer: unsupported packet version %ul", packet_header.packet_magic);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}

	/* Check the data link type. */
	if (packet_header.network_type >= NUM_OBSERVER_ENCAPS) {
		g_message("observer: network type %u unknown or unsupported", packet_header.network_type);
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		return -1;
	}
	wth->file_encap = observer_encap[packet_header.network_type];

	wth->file_type = WTAP_FILE_NETWORK_INSTRUMENTS_V9;

	/* set up the rest of the capture parameters */
	wth->subtype_read = observer_read;
	wth->subtype_seek_read = observer_seek_read;
	wth->subtype_close = NULL;
	wth->subtype_sequential_close = NULL;
	wth->snapshot_length = 0;

	/* reset the pointer to the first packet */
	seek_value = file_seek(wth->fh, file_header.offset_to_first_packet, SEEK_SET, err);
	if (seek_value != file_header.offset_to_first_packet) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset = file_header.offset_to_first_packet;

	return 1;
}

/* reads the next packet */
static gboolean observer_read(wtap *wth, int *err, long *data_offset)
{
	int bytes_read;
	long seek_value, seek_increment;
	long seconds, useconds;

	packet_entry_header packet_header;
	
	observer_time packet_time;

	*data_offset = wth->data_offset;

	/* pull off the packet header */
	bytes_read = file_read(&packet_header, sizeof packet_header, 1, wth->fh);
	if (bytes_read != sizeof packet_header) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += bytes_read;

	/* check the packet's magic number; the magic number is all 8's,
	   so the byte order doesn't matter */
	if (packet_header.packet_magic != observer_packet_magic) {
		g_message("Observer: bad record");
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	/* convert from observer time to wiretap time */
	packet_header.nano_seconds_since_2000 =
	    GUINT64_FROM_LE(packet_header.nano_seconds_since_2000);
	fill_time_struct(packet_header.nano_seconds_since_2000, &packet_time);
	useconds = (long)(packet_time.useconds_from_1970 - ((guint64)packet_time.seconds_from_1970)*1000000);
	seconds = (long)packet_time.seconds_from_1970 - packet_time.time_stamp.tm_gmtoff;

	/* set-up the packet header */
	packet_header.network_size =
	    GUINT16_FROM_LE(packet_header.network_size);
	packet_header.captured_size =
	    GUINT16_FROM_LE(packet_header.captured_size);
	wth->phdr.pkt_encap = observer_encap[packet_header.network_type];
	wth->phdr.len    = packet_header.network_size-4; /* neglect frame markers for wiretap */
	wth->phdr.caplen = MIN(packet_header.captured_size, wth->phdr.len);
	wth->phdr.ts.tv_sec  = seconds;
	wth->phdr.ts.tv_usec = useconds;

	/* get to the frame data */
	packet_header.offset_to_frame =
	    GUINT16_FROM_LE(packet_header.offset_to_frame);
	if (packet_header.offset_to_frame < sizeof(packet_header)) {
		g_message("Observer: bad record (offset to frame %u < %lu)",
		    packet_header.offset_to_frame,
		    (unsigned long)sizeof(packet_header));
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}
	seek_increment = packet_header.offset_to_frame - sizeof(packet_header);
	if(seek_increment>0) {
		seek_value = file_seek(wth->fh, seek_increment, SEEK_CUR, err);
		if (seek_value != seek_increment) {
			*err = file_error(wth->fh);
			g_message("Observer: bad record");
			*err = WTAP_ERR_BAD_RECORD;
			return FALSE;
		}
	}
	wth->data_offset += seek_increment;

	/* set-up the packet buffer */
	buffer_assure_space(wth->frame_buffer, packet_header.captured_size);
	wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer), packet_header.captured_size, wth->fh, err);
	wth->data_offset += packet_header.captured_size;

	/* update the pseudo header */
	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* There is no FCS in the frame */
		wth->pseudo_header.eth.fcs_len = 0;
		break;
	}

	return TRUE;
}

/* reads a packet at an offset */
static gboolean observer_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length, int *err)
{
	packet_entry_header packet_header;

	int bytes_read;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* pull off the packet header */
	bytes_read = file_read(&packet_header, sizeof packet_header, 1, wth->random_fh);
	if (bytes_read != sizeof packet_header) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}

	/* check the packets magic number */
	if (packet_header.packet_magic != observer_packet_magic) {
		g_message("Observer: bad record in observer_seek_read");
		*err = WTAP_ERR_BAD_RECORD;
		return FALSE;
	}

	/* read in the packet */
	bytes_read = file_read(pd, 1, length, wth->random_fh);
	if (bytes_read != length) {
		*err = file_error(wth->fh);
		g_message("Observer: read error in observer_seek_read");
		return FALSE;
	}

	/* update the pseudo header */
	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* There is no FCS in the frame */
		pseudo_header->eth.fcs_len = 0;
		break;
	}

	return TRUE;
}

static guint32 seconds1970to2000 = (((30*365)+7)*24*60*60); /* 7 leap years */
gboolean fill_time_struct(guint64 ns_since2000, observer_time* time_conversion)
{
	time_conversion->ns_since2000 = ns_since2000;
	time_conversion->us_since2000 = ns_since2000/1000;
	time_conversion->sec_since2000 = ns_since2000/1000000000;

	time_conversion->seconds_from_1970 = seconds1970to2000 + time_conversion->sec_since2000;
	time_conversion->useconds_from_1970 = ((guint64)seconds1970to2000*1000000)+time_conversion->us_since2000;

#if 0
	time_conversion->time_stamp = *localtime(&time_conversion->seconds_from_1970);
#endif

	return TRUE;
}

