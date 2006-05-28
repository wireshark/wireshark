/*
 * $Id$
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

static const int from_wtap_encap[] = {
	OBSERVER_UNDEFINED,
	OBSERVER_ETHERNET,
	OBSERVER_TOKENRING,
};
#define NUM_FROM_WTAP_ENCAPS (sizeof from_wtap_encap / sizeof observer_encap[0])

#define CAPTUREFILE_HEADER_SIZE sizeof(capture_file_header)

/*
 * The time in Observer files is in nanoseconds since midnight, January 1,
 * 2000, 00:00:00 local time.
 *
 * We want the seconds portion to be seconds since midnight, January 1,
 * 1970, 00:00:00 GMT.
 *
 * To do that, we add the number of seconds between midnight, January 1,
 * 2000, 00:00:00 local time and midnight, January 1, 1970, 00:00:00 GMT.
 * (That gets the wrong answer if the time zone is being read in a different
 * time zone, but there's not much we can do about that.)
 */
static gboolean have_time_offset;
static time_t seconds1970to2000;

static void init_time_offset(void)
{
	if (!have_time_offset) {
		struct tm midnight_2000_01_01;

		/*
		 * Get the number of seconds between midnight, January 1,
		 * 2000, 00:00:00 local time - that's just the UNIX
		 * time stamp for 2000-01-01 00:00:00 local time.
		 */
		midnight_2000_01_01.tm_year = 2000 - 1900;
		midnight_2000_01_01.tm_mon = 0;
		midnight_2000_01_01.tm_mday = 1;
		midnight_2000_01_01.tm_hour = 0;
		midnight_2000_01_01.tm_min = 0;
		midnight_2000_01_01.tm_sec = 0;
		midnight_2000_01_01.tm_isdst = -1;
		seconds1970to2000 = mktime(&midnight_2000_01_01);
		have_time_offset = TRUE;
	}
}

static gboolean observer_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset);
static gboolean observer_seek_read(wtap *wth, long seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);
static int read_packet_header(FILE_T fh, packet_entry_header *packet_header,
    int *err, gchar **err_info);
static gboolean read_packet_data(FILE_T fh, int offset_to_frame, int offset,
    guint8 *pd, int length, int *err, char **err_info);
static gboolean skip_to_next_packet(wtap *wth, int offset,
    int offset_to_next_packet, int *err, char **err_info);
static gboolean observer_dump_close(wtap_dumper *wdh, int *err);
static gboolean observer_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);

int network_instruments_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	int offset;
	capture_file_header file_header;
	guint i;
	tlv_header tlvh;
	int seek_increment;
	packet_entry_header packet_header;

	errno = WTAP_ERR_CANT_READ;
	offset = 0;

	/* Read in the buffer file header */
	bytes_read = file_read(&file_header, sizeof file_header, 1, wth->fh);
	if (bytes_read != sizeof file_header) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	offset += bytes_read;

	/* check the magic number */
	if (memcmp(file_header.observer_version, network_instruments_magic, true_magic_length)!=0) {
		return 0;
	}

	/* check the version */
	if (strncmp(network_instruments_magic, file_header.observer_version, 30)!=0) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("Observer: unsupported file version %s", file_header.observer_version);
		return -1;
	}

	/* process extra information */
	for (i = 0; i < file_header.number_of_information_elements; i++) {
		/* read the TLV header */
		bytes_read = file_read(&tlvh, sizeof tlvh, 1, wth->fh);
		if (bytes_read != sizeof tlvh) {
			*err = file_error(wth->fh);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		offset += bytes_read;

		tlvh.length = GUINT16_FROM_LE(tlvh.length);
		if (tlvh.length < sizeof tlvh) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("Observer: bad record (TLV length %u < %lu)",
			    tlvh.length, (unsigned long)sizeof tlvh);
			return -1;
		}

		/* skip the TLV data */
		seek_increment = tlvh.length - sizeof tlvh;
		if (seek_increment > 0) {
			if (file_seek(wth->fh, seek_increment, SEEK_CUR, err) == -1)
				return -1;
		}
		offset += seek_increment;
	}

	/* get to the first packet */
	file_header.offset_to_first_packet =
	    GUINT16_FROM_LE(file_header.offset_to_first_packet);
	if (file_header.offset_to_first_packet < offset) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("Observer: bad record (offset to first packet %d < %d)",
		    file_header.offset_to_first_packet, offset);
		return FALSE;
	}
	seek_increment = file_header.offset_to_first_packet - offset;
	if (seek_increment > 0) {
		if (file_seek(wth->fh, seek_increment, SEEK_CUR, err) == -1)
			return -1;
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
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("Observer: unsupported packet version %ul", packet_header.packet_magic);
		return -1;
	}

	/* Check the data link type. */
	if (packet_header.network_type >= NUM_OBSERVER_ENCAPS) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("Observer: network type %u unknown or unsupported", packet_header.network_type);
		return -1;
	}
	wth->file_encap = observer_encap[packet_header.network_type];

	wth->file_type = WTAP_FILE_NETWORK_INSTRUMENTS_V9;

	/* set up the rest of the capture parameters */
	wth->subtype_read = observer_read;
	wth->subtype_seek_read = observer_seek_read;
	wth->subtype_close = NULL;
	wth->subtype_sequential_close = NULL;
	wth->snapshot_length = 0;	/* not available in header */
	wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

	/* reset the pointer to the first packet */
	if (file_seek(wth->fh, file_header.offset_to_first_packet, SEEK_SET,
	    err) == -1)
		return -1;
	wth->data_offset = file_header.offset_to_first_packet;

	init_time_offset();

	return 1;
}

/* reads the next packet */
static gboolean observer_read(wtap *wth, int *err, gchar **err_info,
    long *data_offset)
{
	int offset;
	packet_entry_header packet_header;

	/*
	 * Skip records other than data records.
	 */
	for (;;) {
		*data_offset = wth->data_offset;

		/* process the packet header, including TLVs */
		offset = read_packet_header(wth->fh, &packet_header, err,
		    err_info);
		if (offset <= 0)
			return FALSE;	/* EOF or error */

		wth->data_offset += offset;

		if (packet_header.packet_type == PACKET_TYPE_DATA_PACKET)
			break;

		/* skip to next packet */
		packet_header.offset_to_next_packet =
		    GUINT16_FROM_LE(packet_header.offset_to_next_packet);
		if (!skip_to_next_packet(wth, offset,
		    packet_header.offset_to_next_packet, err, err_info))
			return FALSE;	/* EOF or error */
	}

	/* set-up the packet header */
	packet_header.network_size =
	    GUINT16_FROM_LE(packet_header.network_size);
	/* neglect frame markers for wiretap */
	if (packet_header.network_size < 4) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("Observer: bad record: Packet length %u < 4",
		    packet_header.network_size);
		return FALSE;
	}
	packet_header.network_size -= 4;
	packet_header.captured_size =
	    GUINT16_FROM_LE(packet_header.captured_size);
	wth->phdr.pkt_encap = observer_encap[packet_header.network_type];
	wth->phdr.len    = packet_header.network_size;
	wth->phdr.caplen = MIN(packet_header.captured_size, wth->phdr.len);
	packet_header.nano_seconds_since_2000 =
	    GUINT64_FROM_LE(packet_header.nano_seconds_since_2000);
	wth->phdr.ts.secs =
	    (time_t) (packet_header.nano_seconds_since_2000/1000000000 + seconds1970to2000);
	wth->phdr.ts.nsecs = packet_header.nano_seconds_since_2000%1000000000;

	/* set-up the packet buffer */
	buffer_assure_space(wth->frame_buffer, packet_header.captured_size);

	/* read data */
	if (!read_packet_data(wth->fh, packet_header.offset_to_frame, offset,
	    buffer_start_ptr(wth->frame_buffer), packet_header.captured_size,
	    err, err_info))
		return FALSE;
	wth->data_offset += packet_header.captured_size;
	offset += packet_header.captured_size;

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
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info)
{
	packet_entry_header packet_header;
	int offset;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	/* process the packet header, including TLVs */
	offset = read_packet_header(wth->random_fh, &packet_header, err,
	    err_info);
	if (offset <= 0)
		return FALSE;	/* EOF or error */

	/* read data */
	if (!read_packet_data(wth->random_fh, packet_header.offset_to_frame,
	    offset, pd, length, err, err_info))
		return FALSE;

	/* update the pseudo header */
	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* There is no FCS in the frame */
		pseudo_header->eth.fcs_len = 0;
		break;
	}

	return TRUE;
}

static int
read_packet_header(FILE_T fh, packet_entry_header *packet_header, int *err,
    gchar **err_info)
{
	int offset;
	int bytes_read;
	guint i;
	tlv_header tlvh;
	int seek_increment;

	offset = 0;

	/* pull off the packet header */
	bytes_read = file_read(packet_header, sizeof *packet_header, 1, fh);
	if (bytes_read != sizeof *packet_header) {
		*err = file_error(fh);
		if (*err != 0)
			return -1;
		return 0;	/* EOF */
	}
	offset += bytes_read;

	/* check the packet's magic number; the magic number is all 8's,
	   so the byte order doesn't matter */
	if (packet_header->packet_magic != observer_packet_magic) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("Observer: bad record: Invalid magic number 0x%08x",
		    GUINT32_FROM_LE(packet_header->packet_magic));
		return -1;
	}

	/* process extra information */
	for (i = 0; i < packet_header->number_of_information_elements; i++) {
		/* read the TLV header */
		bytes_read = file_read(&tlvh, sizeof tlvh, 1, fh);
		if (bytes_read != sizeof tlvh) {
			*err = file_error(fh);
			if (*err == 0)
				*err = WTAP_ERR_SHORT_READ;
			return -1;
		}
		offset += bytes_read;

		tlvh.length = GUINT16_FROM_LE(tlvh.length);
		if (tlvh.length < sizeof tlvh) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("Observer: bad record (TLV length %u < %lu)",
			    tlvh.length, (unsigned long)sizeof tlvh);
			return -1;
		}

		/* skip the TLV data */
		seek_increment = tlvh.length - sizeof tlvh;
		if (seek_increment > 0) {
			if (file_seek(fh, seek_increment, SEEK_CUR, err) == -1)
				return -1;
		}
		offset += seek_increment;
	}

	packet_header->offset_to_frame =
	    GUINT16_FROM_LE(packet_header->offset_to_frame);

	return offset;
}

static gboolean
read_packet_data(FILE_T fh, int offset_to_frame, int offset, guint8 *pd,
    int length, int *err, char **err_info)
{
	int seek_increment;

	/* get to the packet data */
	if (offset_to_frame < offset) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("Observer: bad record (offset to packet data %d < %d)",
		    offset_to_frame, offset);
		return FALSE;
	}
	seek_increment = offset_to_frame - offset;
	if (seek_increment > 0) {
		if (file_seek(fh, seek_increment, SEEK_CUR, err) == -1)
			return FALSE;
	}

	/* read in the packet */
	wtap_file_read_expected_bytes(pd, length, fh, err);
	return TRUE;
}

static gboolean
skip_to_next_packet(wtap *wth, int offset, int offset_to_next_packet, int *err,
    char **err_info)
{
	int seek_increment;

	if (offset_to_next_packet < offset) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("Observer: bad record (offset to next packet %d < %d)",
		    offset_to_next_packet, offset);
		return FALSE;
	}
	seek_increment = offset_to_next_packet - offset;
	if (seek_increment > 0) {
		if (file_seek(wth->fh, seek_increment, SEEK_CUR, err) == -1)
			return FALSE;
	}
	wth->data_offset += seek_increment;
	return TRUE;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int network_instruments_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
	
	if (encap < 0 || (unsigned) encap >= NUM_FROM_WTAP_ENCAPS || from_wtap_encap[encap] == OBSERVER_UNDEFINED)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean network_instruments_dump_open(wtap_dumper *wdh, gboolean cant_seek, int *err)
{
	capture_file_header file_header;
	tlv_header comment_header;
	char comment[64];
	struct tm *current_time;
	time_t system_time;

	if (cant_seek) {
		*err = WTAP_ERR_CANT_WRITE_TO_PIPE;
		return FALSE;
	}

	wdh->subtype_write = observer_dump;
	wdh->subtype_close = observer_dump_close;

	wdh->dump.niobserver = g_malloc(sizeof(niobserver_dump_t));
	wdh->dump.niobserver->packet_count = 0;
	wdh->dump.niobserver->network_type = from_wtap_encap[wdh->encap];

	/* create the file comment */
	time(&system_time);
	current_time = localtime(&system_time);
	memset(&comment, 0x00, sizeof(comment));
	sprintf(comment, "This capture was saved from Wireshark on %s", asctime(current_time));

	/* create the file header */
	if (fseek(wdh->fh, 0, SEEK_SET) == -1) {
		*err = errno;
		return FALSE;
	}
	memset(&file_header, 0x00, sizeof(capture_file_header));
	strcpy(file_header.observer_version, network_instruments_magic);
	file_header.offset_to_first_packet = sizeof(capture_file_header) + sizeof(tlv_header) + strlen(comment);
	file_header.offset_to_first_packet = GUINT16_TO_LE(file_header.offset_to_first_packet);
	file_header.number_of_information_elements = 1;
	if(!fwrite(&file_header, sizeof(capture_file_header), 1, wdh->fh)) {
		*err = errno;
		return FALSE;
	}

	/* create the comment entry */
	comment_header.type = GUINT16_TO_LE(INFORMATION_TYPE_COMMENT);
	comment_header.length = sizeof(tlv_header) + strlen(comment);
	comment_header.length = GUINT16_TO_LE(comment_header.length);
	if(!fwrite(&comment_header, sizeof(tlv_header), 1, wdh->fh)) {
		*err = errno;
		return FALSE;
	}
	if(!fwrite(&comment, sizeof(char), strlen(comment), wdh->fh)) {
		*err = errno;
		return FALSE;
	}

	init_time_offset();

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean observer_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header _U_, const guchar *pd,
    int *err)
{
	niobserver_dump_t *niobserver = wdh->dump.niobserver;
	packet_entry_header packet_header;
	size_t nwritten;
	guint64 capture_nanoseconds;

	if (phdr->ts.secs < seconds1970to2000) {
		if (phdr->ts.secs < 0)
			capture_nanoseconds = 0;
		else
			capture_nanoseconds = phdr->ts.secs;
	} else
		capture_nanoseconds = phdr->ts.secs - seconds1970to2000;
	capture_nanoseconds = capture_nanoseconds*1000000000 + phdr->ts.nsecs;

	memset(&packet_header, 0x00, sizeof(packet_entry_header));
	packet_header.packet_magic = GUINT32_TO_LE(observer_packet_magic);
	packet_header.network_speed = GUINT32_TO_LE(1000000);
	packet_header.captured_size = GUINT16_TO_LE((guint16)phdr->caplen);
	packet_header.network_size = GUINT16_TO_LE((guint16)(phdr->len+4));
	packet_header.offset_to_frame = GUINT16_TO_LE(sizeof(packet_entry_header));
	packet_header.offset_to_next_packet = GUINT16_TO_LE(sizeof(packet_entry_header) + phdr->caplen);
	packet_header.network_type = niobserver->network_type;
	packet_header.flags = 0x00;
	packet_header.number_of_information_elements = 0;
	packet_header.packet_type = PACKET_TYPE_DATA_PACKET;
	packet_header.packet_number = GUINT64_TO_LE(niobserver->packet_count);
	packet_header.original_packet_number = GUINT64_TO_LE(niobserver->packet_count);
	niobserver->packet_count++;
	packet_header.nano_seconds_since_2000 = GUINT64_TO_LE(capture_nanoseconds);

	nwritten = fwrite(&packet_header, sizeof(packet_header), 1, wdh->fh);
	if (nwritten != 1) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	nwritten = fwrite(pd, 1, phdr->caplen, wdh->fh);
	if (nwritten != phdr->caplen) {
		if (nwritten == 0 && ferror(wdh->fh))
			*err = errno;
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}

	return TRUE;
}

/* just returns TRUE, there is no clean up needed */
static gboolean observer_dump_close(wtap_dumper *wdh _U_, int *err _U_)
{
	return TRUE;
}
