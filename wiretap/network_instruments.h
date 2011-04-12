/*
 * $Id$
 */

/***************************************************************************
                          NetworkInstruments.h  -  description
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

int network_instruments_open(wtap *wth, int *err, gchar **err_info);
int network_instruments_dump_can_write_encap(int encap);
gboolean network_instruments_dump_open(wtap_dumper *wdh, int *err);

typedef struct capture_file_header
{
	char	observer_version[32];
	guint16	offset_to_first_packet;
	char	probe_instance;
	guint8	number_of_information_elements;	/* number of TLVs in the header */
} capture_file_header;

typedef struct tlv_header
{
	guint16	type;
	guint16	length;		/* includes the length of the TLV header */
} tlv_header;

/*
 * TLV type values.
 */
#define INFORMATION_TYPE_ALIAS_LIST 0x01
#define INFORMATION_TYPE_COMMENT    0x02	/* ASCII text */

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
	guint8 number_of_information_elements;	/* number of TLVs in the header */
	guint8 packet_type;
	guint16 errors;
	guint16 reserved;
	guint64 packet_number;
	guint64 original_packet_number;
	guint64 nano_seconds_since_2000;
} packet_entry_header;

/*
 * Network type values.
 */
#define OBSERVER_UNDEFINED 0xFF
#define OBSERVER_ETHERNET  0x00
#define OBSERVER_TOKENRING 0x01
#define OBSERVER_FDDI      0x02

/*
 * Packet type values.
 */
#define PACKET_TYPE_DATA_PACKET			0
#define PACKET_TYPE_EXPERT_INFORMATION_PACKET	1

/*
 * The Observer document indicates that the types of expert information
 * packets are:
 *
 *	Network Load (markers used by Expert Time Interval and What If
 *	analysis modes)
 *
 *	Start/Stop Packet Capture marker frames (with time stamps when
 *	captures start and stop)
 *
 *	Wireless Channel Change (markers showing what channel was being
 *	currently listened to)
 *
 * That information appears to be contained in TLVs.
 */

/*
 * TLV type values.
 */
#define INFORMATION_TYPE_NETWORK_LOAD		0x0100
#define INFORMATION_TYPE_CAPTURE_START_STOP	0x0104

/*
 * Might some of these be broadcast and multicast packet counts?
 */
typedef struct tlv_network_load
{
	guint32 utilization;	/* network utilization, in .1% units */
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

#define START_STOP_TYPE_STOP	0
#define START_STOP_TYPE_START	1

#endif

