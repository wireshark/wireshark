/***************************************************************************
                          observer.c  -  description
                             -------------------
    begin                : Wed Oct 29 2003
    copyright            : (C) 2003 by root
    email                : scotte[AT}netinst.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *  SPDX-License-Identifier: GPL-2.0-or-later                              *
 *                                                                         *
 ***************************************************************************/

#include "config.h"
#include "observer.h"

#include <stdlib.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/802_11-utils.h>

static const char observer_magic[] = {"ObserverPktBufferVersion=15.00"};
static const int true_magic_length = 17;

static const uint32_t observer_packet_magic = 0x88888888;

/*
 * This structure is used to keep state when writing files. An instance is
 * allocated for each file, and its address is stored in the wtap_dumper.priv
 * pointer field.
 */
typedef struct {
    uint64_t packet_count;
    uint8_t network_type;
    uint32_t time_format;
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

static const char *init_gmt_to_localtime_offset(void)
{
    if (gmt_to_localtime_offset == (time_t) -1) {
        time_t ansi_epoch_plus_one_day = 86400;
        struct tm *tm;
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
        tm = gmtime(&ansi_epoch_plus_one_day);
        if (tm == NULL)
            return "gmtime(one day past the Epoch) fails (this \"shouldn't happen\")";
        gmt_tm = *tm;
        tm = localtime(&ansi_epoch_plus_one_day);
        if (tm == NULL)
            return "localtime(one day past the Epoch) fails (this \"shouldn't happen\")";
        local_tm = *tm;
        local_tm.tm_isdst = 0;
        gmt_to_localtime_offset = mktime(&gmt_tm) - mktime(&local_tm);
    }
    return NULL;
}

static bool observer_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset);
static bool observer_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static int read_packet_header(wtap *wth, FILE_T fh, union wtap_pseudo_header *pseudo_header,
    packet_entry_header *packet_header, int *err, char **err_info);
static bool process_packet_header(wtap *wth,
    packet_entry_header *packet_header, wtap_rec *rec, int *err,
    char **err_info);
static int read_packet_data(FILE_T fh, int offset_to_frame, int current_offset_from_packet_header,
    Buffer *buf, int length, int *err, char **err_info);
static bool skip_to_next_packet(wtap *wth, int offset_to_next_packet,
    int current_offset_from_packet_header, int *err, char **err_info);
static bool observer_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd, int *err, char **err_info);
static int observer_to_wtap_encap(int observer_encap);
static int wtap_to_observer_encap(int wtap_encap);

static int observer_file_type_subtype = -1;

void register_observer(void);

wtap_open_return_val observer_open(wtap *wth, int *err, char **err_info)
{
    unsigned offset;
    capture_file_header file_header;
    unsigned header_offset;
    unsigned i;
    tlv_header tlvh;
    unsigned seek_increment;
    packet_entry_header packet_header;
    observer_dump_private_state * private_state = NULL;
    const char *err_str;

    offset = 0;

    /* read in the buffer file header */
    if (!wtap_read_bytes(wth->fh, &file_header, sizeof file_header,
                         err, err_info)) {
        if (*err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }
    offset += (unsigned)sizeof file_header;
    CAPTURE_FILE_HEADER_FROM_LE_IN_PLACE(file_header);

    /* check if version info is present */
    if (memcmp(file_header.observer_version, observer_magic, true_magic_length)!=0) {
        return WTAP_OPEN_NOT_MINE;
    }

    /* get the location of the first packet */
    /* v15 and newer uses high byte offset, in previous versions it will be 0 */
    header_offset = file_header.offset_to_first_packet + ((unsigned)(file_header.offset_to_first_packet_high_byte)<<16);

    if (offset > header_offset) {
        /*
         * The packet data begins before the file header ends.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("Observer: The first packet begins in the middle of the file header");
        return WTAP_OPEN_ERROR;
    }

    /* initialize the private state */
    private_state = g_new(observer_dump_private_state, 1);
    private_state->time_format = TIME_INFO_LOCAL;
    wth->priv = (void *) private_state;

    /* process extra information */
    for (i = 0; i < file_header.number_of_information_elements; i++) {
        unsigned tlv_data_length;

        /*
         * Make sure reading the TLV header won't put us in the middle
         * of the packet data.
         */
        if (offset + (unsigned)sizeof tlvh > header_offset) {
            /*
             * We're at or past the point where the packet data begins,
             * but we have the IE header to read.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("Observer: TLVs run into the first packet data");
            return WTAP_OPEN_ERROR;
        }

        /* read the TLV header */
        if (!wtap_read_bytes(wth->fh, &tlvh, sizeof tlvh, err, err_info))
            return WTAP_OPEN_ERROR;
        offset += (unsigned)sizeof tlvh;
        TLV_HEADER_FROM_LE_IN_PLACE(tlvh);

        if (tlvh.length < sizeof tlvh) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("Observer: bad record (TLV length %u < %zu)",
                tlvh.length, sizeof tlvh);
            return WTAP_OPEN_ERROR;
        }

        tlv_data_length = tlvh.length - (unsigned)sizeof tlvh;
        /*
         * Make sure reading the TLV data won't put us in the middle
         * of the packet data.
         */
        if (offset + tlv_data_length > header_offset) {
            /*
             * We're at or past the point where the packet data begins,
             * but we have the IE data to read.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("Observer: TLVs run into the first packet data");
            return WTAP_OPEN_ERROR;
        }


        /* process (or skip over) the current TLV */
        switch (tlvh.type) {
        case INFORMATION_TYPE_TIME_INFO:
            if (tlv_data_length != sizeof private_state->time_format) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("Observer: bad record (time information TLV length %u != %zu)",
                    tlvh.length,
                    sizeof tlvh + sizeof private_state->time_format);
                return WTAP_OPEN_ERROR;
            }
            if (!wtap_read_bytes(wth->fh, &private_state->time_format,
                                 sizeof private_state->time_format,
                                 err, err_info))
                return WTAP_OPEN_ERROR;
            private_state->time_format = GUINT32_FROM_LE(private_state->time_format);
            offset += (unsigned)sizeof private_state->time_format;
            break;
        default:
            if (tlv_data_length != 0) {
                if (!wtap_read_bytes(wth->fh, NULL, tlv_data_length, err, err_info))
                    return WTAP_OPEN_ERROR;
            }
            offset += tlv_data_length;
        }
    }

    /* get to the first packet */
    seek_increment = header_offset - offset;
    if (seek_increment != 0) {
        if (!wtap_read_bytes(wth->fh, NULL, seek_increment, err, err_info))
            return WTAP_OPEN_ERROR;
    }

    /*
     * We assume that all packets in a file have the same network type,
     * whether they're data or expert information packets, and thus
     * we can attempt to determine the network type by reading the
     * first packet.
     *
     * If that's *not* the case, we need to use WTAP_ENCAP_PER_PACKET.
     *
     * Read the packet header.  Don't assume there *is* a packet;
     * if there isn't, report that as a bad file.  (If we use
     * WTAP_ENCAP_PER_PACKET, we don't need to handle that case, as
     * we don't need to read the first packet.
     */
    if (!wtap_read_bytes_or_eof(wth->fh, &packet_header, sizeof packet_header,
                                err, err_info)) {
        if (*err == 0) {
            /*
             * EOF, so there *are* no records.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("Observer: No records in the file, so we can't determine the link-layer type");
        }
        return WTAP_OPEN_ERROR;
    }
    PACKET_ENTRY_HEADER_FROM_LE_IN_PLACE(packet_header);

    /* check the packet's magic number */
    if (packet_header.packet_magic != observer_packet_magic) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("Observer: unsupported packet version %ul", packet_header.packet_magic);
        return WTAP_OPEN_ERROR;
    }

    /* check the data link type */
    if (observer_to_wtap_encap(packet_header.network_type) == WTAP_ENCAP_UNKNOWN) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("Observer: network type %u unknown or unsupported", packet_header.network_type);
        return WTAP_OPEN_ERROR;
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
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->file_type_subtype = observer_file_type_subtype;

    /* reset the pointer to the first packet */
    if (file_seek(wth->fh, header_offset, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    err_str = init_gmt_to_localtime_offset();
    if (err_str != NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("observer: %s", err_str);
        return WTAP_OPEN_ERROR;
    }

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/* Reads the next packet. */
static bool observer_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    int header_bytes_consumed;
    int data_bytes_consumed;
    packet_entry_header packet_header;

    /* skip records other than data records */
    for (;;) {
        *data_offset = file_tell(wth->fh);

        /* process the packet header, including TLVs */
        header_bytes_consumed = read_packet_header(wth, wth->fh, &rec->rec_header.packet_header.pseudo_header, &packet_header, err,
            err_info);
        if (header_bytes_consumed <= 0)
            return false;    /* EOF or error */

        if (packet_header.packet_type == PACKET_TYPE_DATA_PACKET)
            break;

        /* skip to next packet */
        if (!skip_to_next_packet(wth, packet_header.offset_to_next_packet,
                header_bytes_consumed, err, err_info)) {
            return false;    /* EOF or error */
        }
    }

    if (!process_packet_header(wth, &packet_header, rec, err, err_info))
        return false;

    /* read the frame data */
    data_bytes_consumed = read_packet_data(wth->fh, packet_header.offset_to_frame,
            header_bytes_consumed, buf, rec->rec_header.packet_header.caplen,
            err, err_info);
    if (data_bytes_consumed < 0) {
        return false;
    }

    /* skip over any extra bytes following the frame data */
    if (!skip_to_next_packet(wth, packet_header.offset_to_next_packet,
            header_bytes_consumed + data_bytes_consumed, err, err_info)) {
        return false;
    }

    return true;
}

/* Reads a packet at an offset. */
static bool observer_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, Buffer *buf, int *err, char **err_info)
{
    union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    packet_entry_header packet_header;
    int offset;
    int data_bytes_consumed;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /* process the packet header, including TLVs */
    offset = read_packet_header(wth, wth->random_fh, pseudo_header, &packet_header, err,
        err_info);
    if (offset <= 0)
        return false;    /* EOF or error */

    if (!process_packet_header(wth, &packet_header, rec, err, err_info))
        return false;

    /* read the frame data */
    data_bytes_consumed = read_packet_data(wth->random_fh, packet_header.offset_to_frame,
        offset, buf, rec->rec_header.packet_header.caplen, err, err_info);
    if (data_bytes_consumed < 0) {
        return false;
    }

    return true;
}

static int
read_packet_header(wtap *wth, FILE_T fh, union wtap_pseudo_header *pseudo_header,
    packet_entry_header *packet_header, int *err, char **err_info)
{
    int offset;
    unsigned i;
    tlv_header tlvh;
    tlv_wireless_info wireless_header;

    offset = 0;

    /* pull off the packet header */
    if (!wtap_read_bytes_or_eof(fh, packet_header, sizeof *packet_header,
                                err, err_info)) {
        if (*err != 0)
            return -1;
        return 0;    /* EOF */
    }
    offset += (int)sizeof *packet_header;
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
            if (((uint8_t*) packet_header)[i] != 0)
                break;
        }
        if (i == sizeof *packet_header) {
            *err = 0;
            return 0;    /* EOF */
        }

        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("Observer: bad record: Invalid magic number 0x%08x",
            packet_header->packet_magic);
        return -1;
    }

    /* initialize the pseudo header */
    switch (wth->file_encap) {
    case WTAP_ENCAP_ETHERNET:
        /* There is no FCS in the frame */
        pseudo_header->eth.fcs_len = 0;
        break;
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        memset(&pseudo_header->ieee_802_11, 0, sizeof(pseudo_header->ieee_802_11));
        pseudo_header->ieee_802_11.fcs_len = 0;
        pseudo_header->ieee_802_11.decrypted = false;
        pseudo_header->ieee_802_11.datapad = false;
        pseudo_header->ieee_802_11.phy = PHDR_802_11_PHY_UNKNOWN;
        /* Updated below */
        break;
    }

    /* process extra information */
    for (i = 0; i < packet_header->number_of_information_elements; i++) {
        unsigned tlv_data_length;

        /* read the TLV header */
        if (!wtap_read_bytes(fh, &tlvh, sizeof tlvh, err, err_info))
            return -1;
        offset += (int)sizeof tlvh;
        TLV_HEADER_FROM_LE_IN_PLACE(tlvh);

        if (tlvh.length < sizeof tlvh) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("Observer: bad record (TLV length %u < %zu)",
                tlvh.length, sizeof tlvh);
            return -1;
        }
        tlv_data_length = tlvh.length - (unsigned)sizeof tlvh;

        /* process (or skip over) the current TLV */
        switch (tlvh.type) {
        case INFORMATION_TYPE_WIRELESS:
            if (tlv_data_length != sizeof wireless_header) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("Observer: bad record (wireless TLV length %u != %zu)",
                    tlvh.length, sizeof tlvh + sizeof wireless_header);
                return -1;
            }
            if (!wtap_read_bytes(fh, &wireless_header, sizeof wireless_header,
                                 err, err_info))
                return -1;
            /* set decryption status */
            /* XXX - what other bits are there in conditions? */
            pseudo_header->ieee_802_11.decrypted = (wireless_header.conditions & WIRELESS_WEP_SUCCESS) != 0;
            pseudo_header->ieee_802_11.has_channel = true;
            pseudo_header->ieee_802_11.channel = wireless_header.frequency;
            pseudo_header->ieee_802_11.has_data_rate = true;
            pseudo_header->ieee_802_11.data_rate = wireless_header.rate;
            pseudo_header->ieee_802_11.has_signal_percent = true;
            pseudo_header->ieee_802_11.signal_percent = wireless_header.strengthPercent;

            /*
             * We don't know they PHY, but we do have the data rate;
             * try to guess the PHY based on the data rate and channel.
             */
            if (RATE_IS_DSSS(pseudo_header->ieee_802_11.data_rate)) {
                /* 11b */
                pseudo_header->ieee_802_11.phy = PHDR_802_11_PHY_11B;
                pseudo_header->ieee_802_11.phy_info.info_11b.has_short_preamble = false;
            } else if (RATE_IS_OFDM(pseudo_header->ieee_802_11.data_rate)) {
                /* 11a or 11g, depending on the band. */
                if (CHAN_IS_BG(pseudo_header->ieee_802_11.channel)) {
                    /* 11g */
                    pseudo_header->ieee_802_11.phy = PHDR_802_11_PHY_11G;
                    pseudo_header->ieee_802_11.phy_info.info_11g.has_mode = false;
                } else {
                    /* 11a */
                    pseudo_header->ieee_802_11.phy = PHDR_802_11_PHY_11A;
                    pseudo_header->ieee_802_11.phy_info.info_11a.has_channel_type = false;
                    pseudo_header->ieee_802_11.phy_info.info_11a.has_turbo_type = false;
                }
            }

            offset += (int)sizeof wireless_header;
            break;
        default:
            /* skip the TLV data */
            if (tlv_data_length != 0) {
                if (!wtap_read_bytes(fh, NULL, tlv_data_length, err, err_info))
                    return -1;
            }
            offset += tlv_data_length;
        }
    }

    return offset;
}

static bool
process_packet_header(wtap *wth, packet_entry_header *packet_header,
    wtap_rec *rec, int *err, char **err_info)
{
    /* set the wiretap record metadata fields */
    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->rec_header.packet_header.pkt_encap = observer_to_wtap_encap(packet_header->network_type);
    if(wth->file_encap == WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS) {
        rec->rec_header.packet_header.len = packet_header->network_size;
        rec->rec_header.packet_header.caplen = packet_header->captured_size;
    } else {
        /*
         * XXX - what are those 4 bytes?
         *
         * The comment in the code said "neglect frame markers for wiretap",
         * but in the captures I've seen, there's no actual data corresponding
         * to them that might be a "frame marker".
         *
         * Instead, the packets had a network_size 4 bytes larger than the
         * captured_size; does the network_size include the CRC, even
         * though it's not included in a capture?  If so, most other
         * network analyzers that have a "network size" and a "captured
         * size" don't include the CRC in the "network size" if they
         * don't include the CRC in a full-length captured packet; the
         * "captured size" is less than the "network size" only if a
         * user-specified "snapshot length" caused the packet to be
         * sliced at a particular point.
         *
         * That's the model that wiretap and Wireshark/TShark use, so
         * we implement that model here.
         */
        if (packet_header->network_size < 4) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("Observer: bad record: Packet length %u < 4",
                                        packet_header->network_size);
            return false;
        }

        rec->rec_header.packet_header.len = packet_header->network_size - 4;
        rec->rec_header.packet_header.caplen = MIN(packet_header->captured_size, rec->rec_header.packet_header.len);
    }
    /*
     * The maximum value of packet_header->captured_size is 65535, which
     * is less than WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need
     * to check it.
     */

    /* set the wiretap timestamp, assuming for the moment that Observer encoded it in GMT */
    rec->ts.secs = (time_t) ((packet_header->nano_seconds_since_2000 / 1000000000) + ansi_to_observer_epoch_offset);
    rec->ts.nsecs = (int) (packet_header->nano_seconds_since_2000 % 1000000000);

    /* adjust to local time, if necessary, also accounting for DST if the frame
       was captured while it was in effect */
    if (((observer_dump_private_state*)wth->priv)->time_format == TIME_INFO_LOCAL)
    {
        struct tm *tm;
        struct tm daylight_tm;
        struct tm standard_tm;
        time_t    dst_offset;

        /* the Observer timestamp was encoded as local time, so add a
           correction from local time to GMT */
        rec->ts.secs += gmt_to_localtime_offset;

        /* perform a DST adjustment if necessary */
        tm = localtime(&rec->ts.secs);
        if (tm != NULL) {
            standard_tm = *tm;
            if (standard_tm.tm_isdst > 0) {
                daylight_tm = standard_tm;
                standard_tm.tm_isdst = 0;
                dst_offset = mktime(&standard_tm) - mktime(&daylight_tm);
                 rec->ts.secs -= dst_offset;
            }
        }
    }

    return true;
}

static int
read_packet_data(FILE_T fh, int offset_to_frame, int current_offset_from_packet_header, Buffer *buf,
    int length, int *err, char **err_info)
{
    int seek_increment;
    int bytes_consumed = 0;

    /* validate offsets */
    if (offset_to_frame < current_offset_from_packet_header) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("Observer: bad record (offset to packet data %d < %d)",
            offset_to_frame, current_offset_from_packet_header);
        return -1;
    }

    /* skip to the packet data */
    seek_increment = offset_to_frame - current_offset_from_packet_header;
    if (seek_increment > 0) {
        if (!wtap_read_bytes(fh, NULL, seek_increment, err, err_info)) {
            return -1;
        }
        bytes_consumed += seek_increment;
    }

    /* read in the packet data */
    if (!wtap_read_packet_bytes(fh, buf, length, err, err_info))
        return false;
    bytes_consumed += length;

    return bytes_consumed;
}

static bool
skip_to_next_packet(wtap *wth, int offset_to_next_packet, int current_offset_from_packet_header, int *err,
    char **err_info)
{
    int seek_increment;

    /* validate offsets */
    if (offset_to_next_packet < current_offset_from_packet_header) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("Observer: bad record (offset to next packet %d < %d)",
            offset_to_next_packet, current_offset_from_packet_header);
        return false;
    }

    /* skip to the next packet header */
    seek_increment = offset_to_next_packet - current_offset_from_packet_header;
    if (seek_increment > 0) {
        if (!wtap_read_bytes(wth->fh, NULL, seek_increment, err, err_info))
            return false;
    }

    return true;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
static int observer_dump_can_write_encap(int encap)
{
    /* per-packet encapsulations aren't supported */
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap < 0 || (wtap_to_observer_encap(encap) == OBSERVER_UNDEFINED))
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure. */
static bool observer_dump_open(wtap_dumper *wdh, int *err,
    char **err_info)
{
    observer_dump_private_state * private_state = NULL;
    capture_file_header file_header;
    unsigned header_offset;
    const char *err_str;
    tlv_header comment_header;
    char comment[64];
    size_t comment_length;
    tlv_header time_info_header;
    tlv_time_info time_info;
    struct tm * current_time;
    time_t system_time;

    /* initialize the private state */
    private_state = g_new(observer_dump_private_state, 1);
    private_state->packet_count = 0;
    private_state->network_type = wtap_to_observer_encap(wdh->file_encap);
    private_state->time_format = TIME_INFO_GMT;

    /* populate the fields of wdh */
    wdh->priv = (void *) private_state;
    wdh->subtype_write = observer_dump;

    /* initialize the file header */
    memset(&file_header, 0x00, sizeof(file_header));
    (void) g_strlcpy(file_header.observer_version, observer_magic, 31);
    header_offset = (uint16_t)sizeof(file_header);

    /* create the file comment TLV */
    {
        time(&system_time);
        current_time = localtime(&system_time);
        memset(&comment, 0x00, sizeof(comment));
        if (current_time != NULL)
            snprintf(comment, 64, "This capture was saved from Wireshark on %s", asctime(current_time));
        else
            snprintf(comment, 64, "This capture was saved from Wireshark");
        comment_length = strlen(comment);

        comment_header.type = INFORMATION_TYPE_COMMENT;
        comment_header.length = (uint16_t) (sizeof(comment_header) + comment_length);

        /* update the file header to account for the comment TLV */
        file_header.number_of_information_elements++;
        header_offset += comment_header.length;
    }

    /* create the timestamp encoding TLV */
    {
        time_info_header.type = INFORMATION_TYPE_TIME_INFO;
        time_info_header.length = (uint16_t) (sizeof(time_info_header) + sizeof(time_info));
        time_info.time_format = TIME_INFO_GMT;

        /* update the file header to account for the timestamp encoding TLV */
        file_header.number_of_information_elements++;
        header_offset += time_info_header.length;
    }

    /* Store the offset to the first packet */
    file_header.offset_to_first_packet_high_byte = (header_offset >> 16);
    file_header.offset_to_first_packet = (header_offset & 0xFFFF);

    /* write the file header, swapping any multibyte fields first */
    CAPTURE_FILE_HEADER_TO_LE_IN_PLACE(file_header);
    if (!wtap_dump_file_write(wdh, &file_header, sizeof(file_header), err)) {
        return false;
    }

    /* write the comment TLV */
    {
        TLV_HEADER_TO_LE_IN_PLACE(comment_header);
        if (!wtap_dump_file_write(wdh, &comment_header, sizeof(comment_header), err)) {
            return false;
        }

        if (!wtap_dump_file_write(wdh, &comment, comment_length, err)) {
            return false;
        }
    }

    /* write the time info TLV */
    {
        TLV_HEADER_TO_LE_IN_PLACE(time_info_header);
        if (!wtap_dump_file_write(wdh, &time_info_header, sizeof(time_info_header), err)) {
            return false;
        }

        TLV_TIME_INFO_TO_LE_IN_PLACE(time_info);
        if (!wtap_dump_file_write(wdh, &time_info, sizeof(time_info), err)) {
            return false;
        }
    }

    err_str = init_gmt_to_localtime_offset();
    if (err_str != NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("observer: %s", err_str);
        return false;
    }

    return true;
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
static bool observer_dump(wtap_dumper *wdh, const wtap_rec *rec,
    const uint8_t *pd,
    int *err, char **err_info _U_)
{
    observer_dump_private_state * private_state = NULL;
    packet_entry_header           packet_header;
    uint64_t                      seconds_since_2000;

    /* We can only write packet records. */
    if (rec->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
        return false;
    }

    /*
     * Make sure this packet doesn't have a link-layer type that
     * differs from the one for the file.
     */
    if (wdh->file_encap != rec->rec_header.packet_header.pkt_encap) {
        *err = WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;
        return false;
    }

    /* The captured size field is 16 bits, so there's a hard limit of
       65535. */
    if (rec->rec_header.packet_header.caplen > 65535) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    /* convert the number of seconds since epoch from ANSI-relative to
       Observer-relative */
    if (rec->ts.secs < ansi_to_observer_epoch_offset) {
        if(rec->ts.secs > (time_t) 0) {
            seconds_since_2000 = rec->ts.secs;
        } else {
            seconds_since_2000 = (time_t) 0;
        }
    } else {
        seconds_since_2000 = rec->ts.secs - ansi_to_observer_epoch_offset;
    }

    /* populate the fields of the packet header */
    private_state = (observer_dump_private_state *) wdh->priv;

    memset(&packet_header, 0x00, sizeof(packet_header));
    packet_header.packet_magic = observer_packet_magic;
    packet_header.network_speed = 1000000;
    packet_header.captured_size = (uint16_t) rec->rec_header.packet_header.caplen;
    packet_header.network_size = (uint16_t) (rec->rec_header.packet_header.len + 4);
    packet_header.offset_to_frame = sizeof(packet_header);
    /* XXX - what if this doesn't fit in 16 bits?  It's not guaranteed to... */
    packet_header.offset_to_next_packet = (uint16_t)sizeof(packet_header) + rec->rec_header.packet_header.caplen;
    packet_header.network_type = private_state->network_type;
    packet_header.flags = 0x00;
    packet_header.number_of_information_elements = 0;
    packet_header.packet_type = PACKET_TYPE_DATA_PACKET;
    packet_header.packet_number = private_state->packet_count;
    packet_header.original_packet_number = packet_header.packet_number;
    packet_header.nano_seconds_since_2000 = seconds_since_2000 * 1000000000 + rec->ts.nsecs;

    private_state->packet_count++;

    /* write the packet header */
    PACKET_ENTRY_HEADER_TO_LE_IN_PLACE(packet_header);
    if (!wtap_dump_file_write(wdh, &packet_header, sizeof(packet_header), err)) {
        return false;
    }

    /* write the packet data */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err)) {
        return false;
    }

    return true;
}

static int observer_to_wtap_encap(int observer_encap)
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

static int wtap_to_observer_encap(int wtap_encap)
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

static const struct supported_block_type observer_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info observer_info = {
    "Viavi Observer", "observer", "bfr", NULL,
    false, BLOCKS_SUPPORTED(observer_blocks_supported),
    observer_dump_can_write_encap, observer_dump_open, NULL
};

void register_observer(void)
{
    observer_file_type_subtype = wtap_register_file_type_subtype(&observer_info);

    /*
     * We now call this file format just "observer", but we allow
     * it to be referred to as "niobserver" for backwards
     * compatibility.
     *
     * Register "niobserver" for that purpose.
     */
    wtap_register_compatibility_file_subtype_name("niobserver", "observer");

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("NETWORK_INSTRUMENTS",
                                                   observer_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
