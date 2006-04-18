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
gboolean network_instruments_dump_open(wtap_dumper *wdh, gboolean cant_seek, int *err);

typedef struct capture_file_header
{
	char	observer_version[32];
	guint16	offset_to_first_packet;
	char	probe_instance;
	char	extra_information_present;
} capture_file_header;

#define TYPE_DATA_PACKET		0
#define TYPE_EXPERT_INFORMATION_PACKET	1

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
 */

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
	guint8 extra_information;
	guint8 packet_type;
	guint16 errors;
	guint16 reserved;
	guint64 packet_number;
	guint64 original_packet_number;
	guint64 nano_seconds_since_2000;
} packet_entry_header;

typedef struct tlv_header
{
	guint16	type;
	guint16	length;
} tlv_header;

typedef struct tlv_alias_list
{
	tlv_header header;
	char alias_list[1];
} tlv_alias_list;

typedef struct tlv_user_commnent
{
	tlv_header header;
	char user_comment[1];
} tlv_user_comment;

typedef struct observer_time
{
	guint64 ns_since2000;		/* given in packet_entry_header */

	guint64 us_since2000;		/* Micro-Seconds since 1-1-2000 */
	guint64 sec_since2000;		/* Seconds since 1-1-2000 */

	time_t seconds_from_1970;
	guint64 useconds_from_1970;

} observer_time;


#endif

