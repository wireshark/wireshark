/** @file
                          observer.h  -  description
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

#ifndef __NETWORK_INSTRUMENTS_H__
#define __NETWORK_INSTRUMENTS_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val observer_open(wtap *wth, int *err, char **err_info);

/*
 * In v15 the high_byte was added to allow a larger offset This was done by
 * reducing the size of observer_version by 1 byte.  Since version strings are
 * only 30 characters the high_byte will always be 0 in previous versions.
 */
typedef struct capture_file_header
{
    char    observer_version[31];
    uint8_t offset_to_first_packet_high_byte; /* allows to extend the offset to the first packet to 256*0x10000 = 16 MB */
    uint16_t offset_to_first_packet;
    char    probe_instance;
    uint8_t number_of_information_elements;   /* number of TLVs in the header */
} capture_file_header;

#define CAPTURE_FILE_HEADER_FROM_LE_IN_PLACE(_capture_file_header) \
    _capture_file_header.offset_to_first_packet = GUINT16_FROM_LE((_capture_file_header).offset_to_first_packet)

#define CAPTURE_FILE_HEADER_TO_LE_IN_PLACE(_capture_file_header) \
    _capture_file_header.offset_to_first_packet = GUINT16_TO_LE((_capture_file_header).offset_to_first_packet)

typedef struct tlv_header
{
    uint16_t type;
    uint16_t length;        /* includes the length of the TLV header */
} tlv_header;

#define TLV_HEADER_FROM_LE_IN_PLACE(_tlv_header) \
    (_tlv_header).type   = GUINT16_FROM_LE((_tlv_header).type); \
    (_tlv_header).length = GUINT16_FROM_LE((_tlv_header).length)

#define TLV_HEADER_TO_LE_IN_PLACE(_tlv_header) \
    (_tlv_header).type   = GUINT16_TO_LE((_tlv_header).type); \
    (_tlv_header).length = GUINT16_TO_LE((_tlv_header).length)

/*
 * TLV type values.
 *
 * Do TLVs without the 0x0100 bit set show up in packets, and
 * do TLVs with that set show up in the file header, or are
 * there two separate types of TLV?
 *
 * ALIAS_LIST contains an ASCII string (null-terminated, but
 * we can't trust that, of course) that is the pathname of
 * a file containing the alias list.  Not much use to us.
 *
 * COMMENT contains an ASCII string (null-terminated, but
 * we can't trust that, of course); in all the captures
 * I've seen, it appears to be a note about the file added
 * by Observer, not by a user.  It appears to end with 0x0a
 * 0x2e, i.e. '\n' '.'.
 *
 * REMOTE_PROBE contains, in all the captures I've seen, an
 * ASCII string (null-terminated, but we cna't trust that,
 * of course) of the form "Remote Probe [hex string]".  THe
 * hex string has 8 characters, i.e. 4 octets.
 *
 * The Observer document indicates that the types of expert information
 * packets are:
 *
 *    Network Load (markers used by Expert Time Interval and What If
 *    analysis modes)
 *
 *    Start/Stop Packet Capture marker frames (with time stamps when
 *    captures start and stop)
 *
 *    Wireless Channel Change (markers showing what channel was being
 *    currently listened to)
 *
 * That information appears to be contained in TLVs.
 */
#define INFORMATION_TYPE_ALIAS_LIST         0x0001
#define INFORMATION_TYPE_COMMENT            0x0002 /* ASCII text */
#define INFORMATION_TYPE_TIME_INFO          0x0004
#define INFORMATION_TYPE_REMOTE_PROBE       0x0005
#define INFORMATION_TYPE_NETWORK_LOAD       0x0100
#define INFORMATION_TYPE_WIRELESS           0x0101
#define INFORMATION_TYPE_CAPTURE_START_STOP 0x0104

/*
 * See in Fibre Channel captures; not seen elsewhere.
 *
 * It has 4 bytes of data in all captures I've seen.
 */
/*                                          0x0106 */

typedef struct tlv_time_info {
    uint16_t type;
    uint16_t length;
    uint32_t time_format;
} tlv_time_info;

/*
 * TIME_INFO time_format values.
 */
#define TIME_INFO_LOCAL 0
#define TIME_INFO_GMT   1

#define TLV_TIME_INFO_FROM_LE_IN_PLACE(_tlv_time_info) \
    (_tlv_time_info).time_format = GUINT32_FROM_LE((_tlv_time_info).time_format)

#define TLV_TIME_INFO_TO_LE_IN_PLACE(_tlv_time_info) \
    (_tlv_time_info).time_format = GUINT32_TO_LE((_tlv_time_info).time_format)

/*
 * Might some of these be broadecast and multicast packet counts, or
 * error counts, or both?
 */
typedef struct tlv_network_load
{
    uint32_t utilization;        /* network utilization, in .1% units */
    uint32_t unknown1;           /* zero in all captures I've seen */
    uint32_t unknown2;           /* zero in all captures I've seen */
    uint32_t packets_per_second;
    uint32_t unknown3;           /* zero in all captures I've seen */
    uint32_t bytes_per_second;
    uint32_t unknown4;           /* zero in all captures I've seen */
} tlv_network_load;

#define TLV_NETWORK_LOAD_FROM_LE_IN_PLACE(_tlv_network_load) \
    (_tlv_network_load).utilization = GUINT32_FROM_LE((_tlv_network_load).utilization); \
    (_tlv_network_load).unknown1 = GUINT32_FROM_LE((_tlv_network_load).unknown1); \
    (_tlv_network_load).unknown2 = GUINT32_FROM_LE((_tlv_network_load).unknown2); \
    (_tlv_network_load).packets_per_second = GUINT32_FROM_LE((_tlv_network_load).packets_per_second); \
    (_tlv_network_load).unknown3 = GUINT32_FROM_LE((_tlv_network_load).unknown3); \
    (_tlv_network_load).bytes_per_second = GUINT32_FROM_LE((_tlv_network_load).bytes_per_second); \
    (_tlv_network_load).unknown4 = GUINT32_FROM_LE((_tlv_network_load).unknown4) \

#define TLV_NETWORK_LOAD_TO_LE_IN_PLACE(_tlv_network_load) \
    (_tlv_network_load).utilization = GUINT32_TO_LE((_tlv_network_load).utilization); \
    (_tlv_network_load).unknown1 = GUINT32_TO_LE((_tlv_network_load).unknown1); \
    (_tlv_network_load).unknown2 = GUINT32_TO_LE((_tlv_network_load).unknown2); \
    (_tlv_network_load).packets_per_second = GUINT32_TO_LE((_tlv_network_load).packets_per_second); \
    (_tlv_network_load).unknown3 = GUINT32_TO_LE((_tlv_network_load).unknown3); \
    (_tlv_network_load).bytes_per_second = GUINT32_TO_LE((_tlv_network_load).bytes_per_second); \
    (_tlv_network_load).unknown4 = GUINT32_TO_LE((_tlv_network_load).unknown4) \

/*
 * quality is presumably some measure of signal quality; in
 * the captures I've seen, it has values of 15, 20-27, 50-54,
 * 208, and 213.
 *
 * conditions has values of 0x00, 0x02, and 0x90.
 *
 * reserved is either 0x00 or 0x80; the 0x80 values
 * are for TLVs where conditions is 0x90.
 */
typedef struct tlv_wireless_info {
    uint8_t quality;
    uint8_t signalStrength;
    uint8_t rate;
    uint8_t frequency;
    uint8_t qualityPercent;
    uint8_t strengthPercent;
    uint8_t conditions;
    uint8_t reserved;
} tlv_wireless_info;

/*
 * Wireless conditions
 */
#define WIRELESS_WEP_SUCCESS		0x80
/*                                      0x10 */
/*                                      0x02 */

typedef struct tlv_capture_start_stop
{
    uint32_t start_stop;
} tlv_capture_start_stop;

#define START_STOP_TYPE_STOP   0
#define START_STOP_TYPE_START  1

typedef struct packet_entry_header
{
    uint32_t packet_magic;
    uint32_t network_speed;
    uint16_t captured_size;
    uint16_t network_size;
    uint16_t offset_to_frame;
    uint16_t offset_to_next_packet;
    uint8_t network_type;
    uint8_t flags;
    uint8_t number_of_information_elements;    /* number of TLVs in the header */
    uint8_t packet_type;
    uint16_t errors;
    uint16_t reserved;
    uint64_t packet_number;
    uint64_t original_packet_number;
    uint64_t nano_seconds_since_2000;
} packet_entry_header;

#define PACKET_ENTRY_HEADER_FROM_LE_IN_PLACE(_packet_entry_header) \
    (_packet_entry_header).packet_magic            = GUINT32_FROM_LE((_packet_entry_header).packet_magic); \
    (_packet_entry_header).network_speed           = GUINT32_FROM_LE((_packet_entry_header).network_speed); \
    (_packet_entry_header).captured_size           = GUINT16_FROM_LE((_packet_entry_header).captured_size); \
    (_packet_entry_header).network_size            = GUINT16_FROM_LE((_packet_entry_header).network_size); \
    (_packet_entry_header).offset_to_frame         = GUINT16_FROM_LE((_packet_entry_header).offset_to_frame); \
    (_packet_entry_header).offset_to_next_packet   = GUINT16_FROM_LE((_packet_entry_header).offset_to_next_packet); \
    (_packet_entry_header).errors                  = GUINT16_FROM_LE((_packet_entry_header).errors); \
    (_packet_entry_header).reserved                = GUINT16_FROM_LE((_packet_entry_header).reserved); \
    (_packet_entry_header).packet_number           = GUINT64_FROM_LE((_packet_entry_header).packet_number); \
    (_packet_entry_header).original_packet_number  = GUINT64_FROM_LE((_packet_entry_header).original_packet_number); \
    (_packet_entry_header).nano_seconds_since_2000 = GUINT64_FROM_LE((_packet_entry_header).nano_seconds_since_2000)

#define PACKET_ENTRY_HEADER_TO_LE_IN_PLACE(_packet_entry_header) \
    (_packet_entry_header).packet_magic            = GUINT32_TO_LE((_packet_entry_header).packet_magic); \
    (_packet_entry_header).network_speed           = GUINT32_TO_LE((_packet_entry_header).network_speed); \
    (_packet_entry_header).captured_size           = GUINT16_TO_LE((_packet_entry_header).captured_size); \
    (_packet_entry_header).network_size            = GUINT16_TO_LE((_packet_entry_header).network_size); \
    (_packet_entry_header).offset_to_frame         = GUINT16_TO_LE((_packet_entry_header).offset_to_frame); \
    (_packet_entry_header).offset_to_next_packet   = GUINT16_TO_LE((_packet_entry_header).offset_to_next_packet); \
    (_packet_entry_header).errors                  = GUINT16_TO_LE((_packet_entry_header).errors); \
    (_packet_entry_header).reserved                = GUINT16_TO_LE((_packet_entry_header).reserved); \
    (_packet_entry_header).packet_number           = GUINT64_TO_LE((_packet_entry_header).packet_number); \
    (_packet_entry_header).original_packet_number  = GUINT64_TO_LE((_packet_entry_header).original_packet_number); \
    (_packet_entry_header).nano_seconds_since_2000 = GUINT64_TO_LE((_packet_entry_header).nano_seconds_since_2000)

/*
 * Network type values.
 */
#define OBSERVER_UNDEFINED       0xFF
#define OBSERVER_ETHERNET        0x00
#define OBSERVER_TOKENRING       0x01
#define OBSERVER_FIBRE_CHANNEL   0x08
#define OBSERVER_WIRELESS_802_11 0x09

/*
 * Packet type values.
 */
#define PACKET_TYPE_DATA_PACKET               0
#define PACKET_TYPE_EXPERT_INFORMATION_PACKET 1

#endif
