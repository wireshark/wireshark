/*
 * $Id$
 */

/***************************************************************************
                          network_instruments.c  -  description
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

static const char network_instruments_magic[] = {"ObserverPktBufferVersion=15.00"};
static const int true_magic_length = 17;

static const guint32 observer_packet_magic = 0x88888888;

/*
 * This structure is used to keep state when writing files. An instance is
 * allocated for each file, and its address is stored in the wtap_dumper.priv
 * pointer field.
 */
typedef struct {
    guint64 packet_count;
    guint8  network_type;
    guint32 time_format;
} observer_dump_private_state;

/*
 * Some time offsets are calculated in advance here, when the first Observer
 * file is opened for reading or writing, and are then used to adjust frame
 * timestamps as they are read or written.
 *
 * The Wiretap API expects timestamps in nanoseconds relative to
 * January 1, 1970, 00:00:00 GMT (the Wiretap epoch).
 *
 * Observer versions before 13.10 encode frame timestamps in nanoseconds
 * relative to January 1, 2000, 00:00:00 local time (the Observer epoch).
 * Versions 13.10 and later switch over to GMT encoding. Which encoding was used
 * when saving the file is identified via the time format TLV following
 * the file header.
 *
 * Unfortunately, even though Observer versions before 13.10 saved in local
 * time, they didn't include the timezone from which the frames were captured,
 * so converting to GMT correctly from all timezones is impossible. So an
 * assumption is made that the file is being read from within the same timezone
 * that it was written.
 *
 * All code herein is normalized to versions 13.10 and later, special casing for
 * versions earlier. In other words, timestamps are worked with as if
 * they are GMT-encoded, and adjustments from local time are made only if
 * the source file warrants it.
 *
 * All destination files are saved in GMT format.
 */
static const time_t ansi_to_observer_epoch_offset = 946684800;
static time_t gmt_to_localtime_offset = (time_t) -1;

static void init_gmt_to_localtime_offset(void)
{
    if (gmt_to_localtime_offset == (time_t) -1) {
        time_t ansi_epoch_plus_one_day = 86400;
        struct tm gmt_tm;
        struct tm local_tm;

        /*
         * Compute the local time zone offset as the number of seconds west
         * of GMT. There's no obvious cross-platform API for querying this
         * directly. As a workaround, GMT and local tm structures are populated
         * relative to the ANSI time_t epoch (plus one day to ensure that
         * local time stays after 1970/1/1 00:00:00). They are then converted
         * back to time_t as if they were both local times, resulting in the
         * time zone offset being the difference between them.
         */
        gmt_tm = *gmtime(&ansi_epoch_plus_one_day);
        local_tm = *localtime(&ansi_epoch_plus_one_day);
        local_tm.tm_isdst = 0;
        gmt_to_localtime_offset = mktime(&gmt_tm) - mktime(&local_tm);
    }
}

static gboolean observer_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean observer_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info);
static int read_packet_header(FILE_T fh, union wtap_pseudo_header *pseudo_header, 
    packet_entry_header *packet_header, int *err, gchar **err_info);
static int read_packet_data(FILE_T fh, int offset_to_frame, int current_offset_from_packet_header,
    guint8 *pd, int length, int *err, char **err_info);
static gboolean skip_to_next_packet(wtap *wth, int offset_to_next_packet,
    int current_offset_from_packet_header, int *err, char **err_info);
static gboolean observer_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err);
static gint observer_to_wtap_encap(int observer_encap);
static gint wtap_to_observer_encap(int wtap_encap);

int network_instruments_open(wtap *wth, int *err, gchar **err_info)
{
    int bytes_read;
    int offset;
    capture_file_header file_header;
    guint i;
    tlv_header tlvh;
    int seek_increment;
    int header_offset;
    packet_entry_header packet_header;
    observer_dump_private_state * private_state = NULL;

    errno = WTAP_ERR_CANT_READ;
    offset = 0;

    /* read in the buffer file header */
    bytes_read = file_read(&file_header, sizeof file_header, wth->fh);
    if (bytes_read != sizeof file_header) {
        *err = file_error(wth->fh, err_info);
        if (*err != 0)
            return -1;
        return 0;
    }
    offset += bytes_read;
    CAPTURE_FILE_HEADER_FROM_LE_IN_PLACE(file_header);

    /* check if version info is present */
    if (memcmp(file_header.observer_version, network_instruments_magic, true_magic_length)!=0) {
        return 0;
    }

    /* initialize the private state */
    private_state = (observer_dump_private_state *) g_malloc(sizeof(observer_dump_private_state));
    private_state->time_format = TIME_INFO_LOCAL;
    wth->priv = (void *) private_state;

    /* get the location of the first packet */
    /* v15 and newer uses high byte offset, in previous versions it will be 0 */
    header_offset = file_header.offset_to_first_packet + ((int)(file_header.offset_to_first_packet_high_byte)<<16);

    /* process extra information */
    for (i = 0; i < file_header.number_of_information_elements; i++) {
        /* for safety break if we've reached the first packet */
        if (offset >= header_offset)
            break;

        /* read the TLV header */
        bytes_read = file_read(&tlvh, sizeof tlvh, wth->fh);
        if (bytes_read != sizeof tlvh) {
            *err = file_error(wth->fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return -1;
        }
        offset += bytes_read;
        TLV_HEADER_FROM_LE_IN_PLACE(tlvh);

        if (tlvh.length < sizeof tlvh) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("Observer: bad record (TLV length %u < %lu)",
                tlvh.length, (unsigned long)sizeof tlvh);
            return -1;
        }

        /* process (or skip over) the current TLV */
        switch (tlvh.type) {
        case INFORMATION_TYPE_TIME_INFO:
            bytes_read = file_read(&private_state->time_format, sizeof private_state->time_format, wth->fh);
            if (bytes_read != sizeof private_state->time_format) {
                *err = file_error(wth->fh, err_info);
                if(*err == 0)
                    *err = WTAP_ERR_SHORT_READ;
                return -1;
            }
            private_state->time_format = GUINT32_FROM_LE(private_state->time_format);
            offset += bytes_read;
            break;
        default:
            seek_increment = tlvh.length - (int)sizeof tlvh;
            if (seek_increment > 0) {
                if (file_seek(wth->fh, seek_increment, SEEK_CUR, err) == -1)
                    return -1;
            }
            offset += seek_increment;
        }
    }

    /* get to the first packet */
    if (header_offset < offset) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("Observer: bad record (offset to first packet %d < %d)",
            header_offset, offset);
        return FALSE;
    }
    seek_increment = header_offset - offset;
    if (seek_increment > 0) {
        if (file_seek(wth->fh, seek_increment, SEEK_CUR, err) == -1)
            return -1;
    }

    /* pull off the packet header */
    bytes_read = file_read(&packet_header, sizeof packet_header, wth->fh);
    if (bytes_read != sizeof packet_header) {
        *err = file_error(wth->fh, err_info);
        if (*err != 0)
            return -1;
        return 0;
    }
    PACKET_ENTRY_HEADER_FROM_LE_IN_PLACE(packet_header);

    /* check the packet's magic number */
    if (packet_header.packet_magic != observer_packet_magic) {
        *err = WTAP_ERR_UNSUPPORTED_ENCAP;
        *err_info = g_strdup_printf("Observer: unsupported packet version %ul", packet_header.packet_magic);
        return -1;
    }

    /* check the data link type */
    if (observer_to_wtap_encap(packet_header.network_type) == WTAP_ENCAP_UNKNOWN) {
        *err = WTAP_ERR_UNSUPPORTED_ENCAP;
        *err_info = g_strdup_printf("Observer: network type %u unknown or unsupported", packet_header.network_type);
        return -1;
    }
    wth->file_encap = observer_to_wtap_encap(packet_header.network_type);

    /* set up the rest of the capture parameters */
    private_state->packet_count = 0;
    private_state->network_type = wtap_to_observer_encap(wth->file_encap);
    wth->subtype_read = observer_read;
    wth->subtype_seek_read = observer_seek_read;
    wth->subtype_close = NULL;
    wth->subtype_sequential_close = NULL;
    wth->snapshot_length = 0;    /* not available in header */
    wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
    wth->file_type = WTAP_FILE_NETWORK_INSTRUMENTS;

    /* reset the pointer to the first packet */
    if (file_seek(wth->fh, header_offset, SEEK_SET,
        err) == -1)
        return -1;
    wth->data_offset = header_offset;

    init_gmt_to_localtime_offset();

    return 1;
}

/* Reads the next packet. */
static gboolean observer_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    int bytes_consumed;
    int offset_from_packet_header = 0;
    packet_entry_header packet_header;

    /* skip records other than data records */
    for (;;) {
        *data_offset = wth->data_offset;

        /* process the packet header, including TLVs */
        bytes_consumed = read_packet_header(wth->fh, &wth->pseudo_header, &packet_header, err,
            err_info);
        if (bytes_consumed <= 0)
            return FALSE;    /* EOF or error */

        wth->data_offset += bytes_consumed;

        if (packet_header.packet_type == PACKET_TYPE_DATA_PACKET)
            break;

        /* skip to next packet */
        offset_from_packet_header = (int) (wth->data_offset - *data_offset);
        if (!skip_to_next_packet(wth, packet_header.offset_to_next_packet,
                offset_from_packet_header, err, err_info)) {
            return FALSE;    /* EOF or error */
        }
    }

    /* neglect frame markers for wiretap */
    if (packet_header.network_size < 4) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("Observer: bad record: Packet length %u < 4",
            packet_header.network_size);
        return FALSE;
    }

    /* set the wiretap packet header fields */
    wth->phdr.pkt_encap = observer_to_wtap_encap(packet_header.network_type);
    if(wth->file_encap == WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS) {
        wth->phdr.len = packet_header.network_size;
        wth->phdr.caplen = packet_header.captured_size;
    } else {
        wth->phdr.len = packet_header.network_size - 4;
        wth->phdr.caplen = MIN(packet_header.captured_size, wth->phdr.len);
    }

    /* set the wiretap timestamp, assuming for the moment that Observer encoded it in GMT */
    wth->phdr.ts.secs = (time_t) ((packet_header.nano_seconds_since_2000 / 1000000000) + ansi_to_observer_epoch_offset);
    wth->phdr.ts.nsecs = (int) (packet_header.nano_seconds_since_2000 % 1000000000);

    /* adjust to local time, if necessary, also accounting for DST if the frame
       was captured while it was in effect */
    if (((observer_dump_private_state*)wth->priv)->time_format == TIME_INFO_LOCAL)
    {
        struct tm daylight_tm;
        struct tm standard_tm;
        time_t    dst_offset;

        /* the Observer timestamp was encoded as local time, so add a
           correction from local time to GMT */
        wth->phdr.ts.secs += gmt_to_localtime_offset;

        /* perform a DST adjustment if necessary */
        standard_tm = *localtime(&wth->phdr.ts.secs);
        if (standard_tm.tm_isdst > 0) {
            daylight_tm = standard_tm;
            standard_tm.tm_isdst = 0;
            dst_offset = mktime(&standard_tm) - mktime(&daylight_tm);
            wth->phdr.ts.secs -= dst_offset;
        }
    }

    /* update the pseudo header */
    switch (wth->file_encap) {
    case WTAP_ENCAP_ETHERNET:
        /* There is no FCS in the frame */
        wth->pseudo_header.eth.fcs_len = 0;
        break;
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        /* Updated in read_packet_header */
        break;
    }

    /* set-up the packet buffer */
    buffer_assure_space(wth->frame_buffer, packet_header.captured_size);

    /* read the frame data */
    offset_from_packet_header = (int) (wth->data_offset - *data_offset);
    bytes_consumed = read_packet_data(wth->fh, packet_header.offset_to_frame,
            offset_from_packet_header, buffer_start_ptr(wth->frame_buffer),
            packet_header.captured_size, err, err_info);
    if (bytes_consumed < 0) {
        return FALSE;
    }
    wth->data_offset += bytes_consumed;

    /* skip over any extra bytes following the frame data */
    offset_from_packet_header = (int) (wth->data_offset - *data_offset);
    if (!skip_to_next_packet(wth, packet_header.offset_to_next_packet,
            offset_from_packet_header, err, err_info)) {
        return FALSE;
    }

    return TRUE;
}

/* Reads a packet at an offset. */
static gboolean observer_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guint8 *pd, int length,
    int *err, gchar **err_info)
{
    packet_entry_header packet_header;
    int offset;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    /* process the packet header, including TLVs */
    offset = read_packet_header(wth->random_fh, pseudo_header, &packet_header, err,
        err_info);
    if (offset <= 0)
        return FALSE;    /* EOF or error */

    /* update the pseudo header */
    switch (wth->file_encap) {

    case WTAP_ENCAP_ETHERNET:
        /* There is no FCS in the frame */
        pseudo_header->eth.fcs_len = 0;
        break;
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        /* Updated in read_packet_header */
        break;
    }

    /* read the frame data */
    if (!read_packet_data(wth->random_fh, packet_header.offset_to_frame,
        offset, pd, length, err, err_info))
        return FALSE;

    return TRUE;
}

static int
read_packet_header(FILE_T fh, union wtap_pseudo_header *pseudo_header, 
    packet_entry_header *packet_header, int *err, gchar **err_info)
{
    int offset;
    int bytes_read;
    guint i;
    tlv_header tlvh;
    int seek_increment;
    tlv_wireless_info wireless_header;

    offset = 0;

    /* pull off the packet header */
    bytes_read = file_read(packet_header, sizeof *packet_header, fh);
    if (bytes_read != sizeof *packet_header) {
        *err = file_error(fh, err_info);
        if (*err != 0)
            return -1;
        return 0;    /* EOF */
    }
    offset += bytes_read;
    PACKET_ENTRY_HEADER_FROM_LE_IN_PLACE(*packet_header);

    /* check the packet's magic number */
    if (packet_header->packet_magic != observer_packet_magic) {

        /*
         * Some files are zero-padded at the end. There is no warning of this
         * in the previous packet header information, such as setting
         * offset_to_next_packet to zero. So detect this situation by treating
         * an all-zero header as a sentinel. Return EOF when it is encountered,
         * rather than treat it as a bad record.
         */
        for (i = 0; i < sizeof *packet_header; i++) {
            if (((guint8*) packet_header)[i] != 0)
                break;
        }
        if (i == sizeof *packet_header) {
            *err = 0;
            return 0;    /* EOF */
        }

        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("Observer: bad record: Invalid magic number 0x%08x",
            packet_header->packet_magic);
        return -1;
    }

    /* process extra information */
    for (i = 0; i < packet_header->number_of_information_elements; i++) {
        /* read the TLV header */
        bytes_read = file_read(&tlvh, sizeof tlvh, fh);
        if (bytes_read != sizeof tlvh) {
            *err = file_error(fh, err_info);
            if (*err == 0)
                *err = WTAP_ERR_SHORT_READ;
            return -1;
        }
        offset += bytes_read;
        TLV_HEADER_FROM_LE_IN_PLACE(tlvh);

        if (tlvh.length < sizeof tlvh) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("Observer: bad record (TLV length %u < %lu)",
                tlvh.length, (unsigned long)sizeof tlvh);
            return -1;
        }

        /* process (or skip over) the current TLV */
        switch (tlvh.type) {
        case INFORMATION_TYPE_WIRELESS:
            bytes_read = file_read(&wireless_header, sizeof wireless_header, fh);
            if (bytes_read != sizeof wireless_header) {
                *err = file_error(fh, err_info);
                if(*err == 0)
                    *err = WTAP_ERR_SHORT_READ;
                return -1;
            }
            /* update the pseudo header */
            pseudo_header->ieee_802_11.fcs_len = 0;
            pseudo_header->ieee_802_11.channel = wireless_header.frequency;
            pseudo_header->ieee_802_11.data_rate = wireless_header.rate;
            pseudo_header->ieee_802_11.signal_level = wireless_header.strengthPercent;
            offset += bytes_read;
            break;
        default:
            /* skip the TLV data */
            seek_increment = tlvh.length - (int)sizeof tlvh;
            if (seek_increment > 0) {
                if (file_seek(fh, seek_increment, SEEK_CUR, err) == -1)
                    return -1;
            }
            offset += seek_increment;
        }
    }

    return offset;
}

static int
read_packet_data(FILE_T fh, int offset_to_frame, int current_offset_from_packet_header, guint8 *pd,
    int length, int *err, char **err_info)
{
    int seek_increment;
    int bytes_consumed = 0;

    /* validate offsets */
    if (offset_to_frame < current_offset_from_packet_header) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("Observer: bad record (offset to packet data %d < %d)",
            offset_to_frame, current_offset_from_packet_header);
        return -1;
    }

    /* skip to the packet data */
    seek_increment = offset_to_frame - current_offset_from_packet_header;
    if (seek_increment > 0) {
        if (file_seek(fh, seek_increment, SEEK_CUR, err) == -1) {
            return -1;
        }
        bytes_consumed += seek_increment;
    }

    /* read in the packet data */
    wtap_file_read_expected_bytes(pd, length, fh, err, err_info);
    bytes_consumed += length;

    return bytes_consumed;
}

static gboolean
skip_to_next_packet(wtap *wth, int offset_to_next_packet, int current_offset_from_packet_header, int *err,
    char **err_info)
{
    int seek_increment;

    /* validate offsets */
    if (offset_to_next_packet < current_offset_from_packet_header) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("Observer: bad record (offset to next packet %d < %d)",
            offset_to_next_packet, current_offset_from_packet_header);
        return FALSE;
    }

    /* skip to the next packet header */
    seek_increment = offset_to_next_packet - current_offset_from_packet_header;
    if (seek_increment > 0) {
        if (file_seek(wth->fh, seek_increment, SEEK_CUR, err) == -1)
            return FALSE;
        wth->data_offset += seek_increment;
    }

    return TRUE;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int network_instruments_dump_can_write_encap(int encap)
{
    /* per-packet encapsulations aren't supported */
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap < 0 || (wtap_to_observer_encap(encap) == OBSERVER_UNDEFINED))
        return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure. */
gboolean network_instruments_dump_open(wtap_dumper *wdh, int *err)
{
    observer_dump_private_state * private_state = NULL;
    capture_file_header file_header;

    tlv_header comment_header;
    tlv_time_info time_header;
    char comment[64];
    size_t comment_length;
    struct tm * current_time;
    time_t system_time;

    /* initialize the private state */
    private_state = (observer_dump_private_state *) g_malloc(sizeof(observer_dump_private_state));
    private_state->packet_count = 0;
    private_state->network_type = wtap_to_observer_encap(wdh->encap);
    private_state->time_format = TIME_INFO_GMT;

    /* populate the fields of wdh */
    wdh->priv = (void *) private_state;
    wdh->subtype_write = observer_dump;

    /* initialize the file header */
    memset(&file_header, 0x00, sizeof(file_header));
    g_strlcpy(file_header.observer_version, network_instruments_magic, 31);
    file_header.offset_to_first_packet = (guint16)sizeof(file_header);
    file_header.offset_to_first_packet_high_byte = 0;

    /* create the file comment TLV */
    {
        time(&system_time);
        current_time = localtime(&system_time);
        memset(&comment, 0x00, sizeof(comment));
        g_snprintf(comment, 64, "This capture was saved from Wireshark on %s", asctime(current_time));
        comment_length = strlen(comment);

        comment_header.type = INFORMATION_TYPE_COMMENT;
        comment_header.length = (guint16) (sizeof(comment_header) + comment_length);

        /* update the file header to account for the comment TLV */
        file_header.number_of_information_elements++;
        file_header.offset_to_first_packet += comment_header.length;
    }

    /* create the timestamp encoding TLV */
    {
        time_header.type = INFORMATION_TYPE_TIME_INFO;
        time_header.length = (guint16) (sizeof(time_header));
        time_header.time_format = TIME_INFO_GMT;

        /* update the file header to account for the timestamp encoding TLV */
        file_header.number_of_information_elements++;
        file_header.offset_to_first_packet += time_header.length;
    }

    /* write the file header, swapping any multibyte fields first */
    CAPTURE_FILE_HEADER_TO_LE_IN_PLACE(file_header);
    if (!wtap_dump_file_write(wdh, &file_header, sizeof(file_header), err)) {
        return FALSE;
    }
    wdh->bytes_dumped += sizeof(file_header);

    /* write the comment TLV */
    {
        TLV_HEADER_TO_LE_IN_PLACE(comment_header);
        if (!wtap_dump_file_write(wdh, &comment_header, sizeof(comment_header), err)) {
            return FALSE;
        }
        wdh->bytes_dumped += sizeof(comment_header);

        if (!wtap_dump_file_write(wdh, &comment, comment_length, err)) {
            return FALSE;
        }
        wdh->bytes_dumped += comment_length;
    }

    /* write the time info TLV */
    {
        TLV_TIME_INFO_TO_LE_IN_PLACE(time_header);
        if (!wtap_dump_file_write(wdh, &time_header, sizeof(time_header), err)) {
            return FALSE;
        }
        wdh->bytes_dumped += sizeof(time_header);
    }

    init_gmt_to_localtime_offset();

    return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean observer_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header _U_, const guint8 *pd,
    int *err)
{
    observer_dump_private_state * private_state = NULL;
    packet_entry_header           packet_header;
    guint64                       seconds_since_2000;

    /* convert the number of seconds since epoch from ANSI-relative to
       Observer-relative */
    if (phdr->ts.secs < ansi_to_observer_epoch_offset) {
        if(phdr->ts.secs > (time_t) 0) {
            seconds_since_2000 = phdr->ts.secs;
        } else {
            seconds_since_2000 = (time_t) 0;
        }
    } else {
        seconds_since_2000 = phdr->ts.secs - ansi_to_observer_epoch_offset;
    }

    /* populate the fields of the packet header */
    private_state = (observer_dump_private_state *) wdh->priv;

    memset(&packet_header, 0x00, sizeof(packet_header));
    packet_header.packet_magic = observer_packet_magic;
    packet_header.network_speed = 1000000;
    packet_header.captured_size = (guint16) phdr->caplen;
    packet_header.network_size = (guint16) (phdr->len + 4);
    packet_header.offset_to_frame = sizeof(packet_header);
    /* XXX - what if this doesn't fit in 16 bits?  It's not guaranteed to... */
    packet_header.offset_to_next_packet = (guint16)sizeof(packet_header) + phdr->caplen;
    packet_header.network_type = private_state->network_type;
    packet_header.flags = 0x00;
    packet_header.number_of_information_elements = 0;
    packet_header.packet_type = PACKET_TYPE_DATA_PACKET;
    packet_header.packet_number = private_state->packet_count;
    packet_header.original_packet_number = packet_header.packet_number;
    packet_header.nano_seconds_since_2000 = seconds_since_2000 * 1000000000 + phdr->ts.nsecs;

    private_state->packet_count++;

    /* write the packet header */
    PACKET_ENTRY_HEADER_TO_LE_IN_PLACE(packet_header);
    if (!wtap_dump_file_write(wdh, &packet_header, sizeof(packet_header), err)) {
        return FALSE;
    }
    wdh->bytes_dumped += sizeof(packet_header);

    /* write the packet data */
    if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err)) {
        return FALSE;
    }
    wdh->bytes_dumped += phdr->caplen;

    return TRUE;
}

static gint observer_to_wtap_encap(int observer_encap)
{
    switch(observer_encap) {
    case OBSERVER_ETHERNET:
        return WTAP_ENCAP_ETHERNET;
    case OBSERVER_TOKENRING:
        return WTAP_ENCAP_TOKEN_RING;
    case OBSERVER_FIBRE_CHANNEL:
        return WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS;
    case OBSERVER_WIRELESS_802_11:
        return WTAP_ENCAP_IEEE_802_11_WITH_RADIO;
    case OBSERVER_UNDEFINED:
        return WTAP_ENCAP_UNKNOWN;
    }
    return WTAP_ENCAP_UNKNOWN;
}

static gint wtap_to_observer_encap(int wtap_encap)
{
    switch(wtap_encap) {
    case WTAP_ENCAP_ETHERNET:
        return OBSERVER_ETHERNET;
    case WTAP_ENCAP_TOKEN_RING:
        return OBSERVER_TOKENRING;
    case WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS:
        return OBSERVER_FIBRE_CHANNEL;
    case WTAP_ENCAP_UNKNOWN:
        return OBSERVER_UNDEFINED;
    }
    return OBSERVER_UNDEFINED;
}
