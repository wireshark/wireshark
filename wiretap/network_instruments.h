/***************************************************************************
                          network_instruments.h  -  description
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

#ifndef __NETWORK_INSTRUMENTS_H__
#define __NETWORK_INSTRUMENTS_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val network_instruments_open(wtap *wth, int *err, gchar **err_info);
int network_instruments_dump_can_write_encap(int encap);
gboolean network_instruments_dump_open(wtap_dumper *wdh, int *err);

/*
 * In v15 the high_byte was added to allow a larger offset This was done by
 * reducing the size of observer_version by 1 byte.  Since version strings are
 * only 30 characters the high_byte will always be 0 in previous versions.
 */
typedef struct capture_file_header
{
    char    observer_version[31];
    guint8  offset_to_first_packet_high_byte; /* allows to extend the offset to the first packet to 256*0x10000 = 16 MB */
    guint16 offset_to_first_packet;
    char    probe_instance;
    guint8  number_of_information_elements;   /* number of TLVs in the header */
} capture_file_header;

#define CAPTURE_FILE_HEADER_FROM_LE_IN_PLACE(_capture_file_header) \
    _capture_file_header.offset_to_first_packet = GUINT16_FROM_LE((_capture_file_header).offset_to_first_packet)

#define CAPTURE_FILE_HEADER_TO_LE_IN_PLACE(_capture_file_header) \
    _capture_file_header.offset_to_first_packet = GUINT16_TO_LE((_capture_file_header).offset_to_first_packet)

typedef struct tlv_header
{
    guint16 type;
    guint16 length;        /* includes the length of the TLV header */
} tlv_header;

#define TLV_HEADER_FROM_LE_IN_PLACE(_tlv_header) \
    (_tlv_header).type   = GUINT16_FROM_LE((_tlv_header).type); \
    (_tlv_header).length = GUINT16_FROM_LE((_tlv_header).length)

#define TLV_HEADER_TO_LE_IN_PLACE(_tlv_header) \
    (_tlv_header).type   = GUINT16_TO_LE((_tlv_header).type); \
    (_tlv_header).length = GUINT16_TO_LE((_tlv_header).length)

typedef struct tlv_time_info {
    guint16 type;
    guint16 length;
    guint32 time_format;
} tlv_time_info;

#define TLV_TIME_INFO_FROM_LE_IN_PLACE(_tlv_time_info) \
    (_tlv_time_info).type   = GUINT16_FROM_LE((_tlv_time_info).type); \
    (_tlv_time_info).length = GUINT16_FROM_LE((_tlv_time_info).length); \
    (_tlv_time_info).time_format = GUINT32_FROM_LE((_tlv_time_info).time_format)

#define TLV_TIME_INFO_TO_LE_IN_PLACE(_tlv_time_info) \
    (_tlv_time_info).type   = GUINT16_TO_LE((_tlv_time_info).type); \
    (_tlv_time_info).length = GUINT16_TO_LE((_tlv_time_info).length); \
    (_tlv_time_info).time_format = GUINT32_FROM_LE((_tlv_time_info).time_format)

typedef struct tlv_wireless_info {
    guint8 quality;
    guint8 signalStrength;
    guint8 rate;
    guint8 frequency;
    guint8 qualityPercent;
    guint8 strengthPercent;
    guint8 conditions;
    guint8 reserved;
} tlv_wireless_info;

/*
 * Wireless conditions
 */
#define WIRELESS_WEP_SUCCESS		0x80

/*
 * TLV type values.
 */
#define INFORMATION_TYPE_ALIAS_LIST 0x01
#define INFORMATION_TYPE_COMMENT    0x02 /* ASCII text */
#define INFORMATION_TYPE_TIME_INFO  0x04
#define INFORMATION_TYPE_WIRELESS   0x101

/*
 * TVL TIME_INFO values.
 */
#define TIME_INFO_LOCAL 0
#define TIME_INFO_GMT   1

typedef struct packet_entry_header
{
    guint32 packet_magic;
    guint32 network_speed;
    guint16 captured_size;
    guint16 network_size;
    guint16 offset_to_frame;
    guint16 offset_to_next_packet;
    guint8 network_type;
    guint8 flags;
    guint8 number_of_information_elements;    /* number of TLVs in the header */
    guint8 packet_type;
    guint16 errors;
    guint16 reserved;
    guint64 packet_number;
    guint64 original_packet_number;
    guint64 nano_seconds_since_2000;
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

/*
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

/*
 * TLV type values.
 */
#define INFORMATION_TYPE_NETWORK_LOAD       0x0100
#define INFORMATION_TYPE_CAPTURE_START_STOP 0x0104

/*
 * Might some of these be broadcast and multicast packet counts?
 */
typedef struct tlv_network_load
{
    guint32 utilization;        /* network utilization, in .1% units */
    guint32 unknown1;
    guint32 unknown2;
    guint32 packets_per_second;
    guint32 unknown3;
    guint32 bytes_per_second;
    guint32 unknown4;
} tlv_network_load;

typedef struct tlv_capture_start_stop
{
    guint32 start_stop;
} tlv_capture_start_stop;

#define START_STOP_TYPE_STOP   0
#define START_STOP_TYPE_START  1

#endif

