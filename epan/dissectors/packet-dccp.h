/* packet-dccp.h
 * Definitions for Datagram Congestion Control Protocol, "DCCP" dissection:
 * it should conform to RFC 4340
 *
 * Copyright 2005 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * Copyright 2020-2021 by Thomas Dreibholz <dreibh [AT] simula.no>
 *
 * template taken from packet-udp.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCCP_H__
#define __PACKET_DCCP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* DCCP structs and definitions */
typedef struct _e_dccphdr {
    guint16 sport;
    guint16 dport;
    guint8 data_offset;
    guint8 cscov;         /* 4 bits */
    guint8 ccval;         /* 4 bits */
    guint16 checksum;
    guint8 reserved1;     /* 3 bits */
    guint8 type;          /* 4 bits */
    gboolean x;           /* 1 bits */
    guint8 reserved2;     /* if x == 1 */
    guint64 seq;          /* 48 or 24 bits sequence number */

    guint16 ack_reserved; /*
                           * for all defined packet types except DCCP-Request
                           * and DCCP-Data
                           */
    guint64 ack;           /* 48 or 24 bits acknowledgement sequence number */

    guint32 service_code;
    guint8 reset_code;
    guint8 data1;
    guint8 data2;
    guint8 data3;

    guint32 stream; /* this stream index field is included to help differentiate when address/port pairs are reused */

    address ip_src;
    address ip_dst;
} e_dccphdr;

/* Conversation and process structures originally copied from packet-tcp.c */
typedef struct _dccp_flow_t {
	/* Process info, currently discovered via IPFIX */
	guint32 process_uid;    /* UID of local process */
	guint32 process_pid;    /* PID of local process */
	gchar *username;	/* Username of the local process */
	gchar *command;         /* Local process name + path + args */
} dccp_flow_t;

struct dccp_analysis {
	/* These two structs are managed based on comparing the source
	 * and destination addresses and, if they're equal, comparing
	 * the source and destination ports.
	 *
	 * If the source is greater than the destination, then stuff
	 * sent from src is in ual1.
	 *
	 * If the source is less than the destination, then stuff
	 * sent from src is in ual2.
	 *
	 * XXX - if the addresses and ports are equal, we don't guarantee
	 * the behavior.
	 */
	dccp_flow_t	flow1;
	dccp_flow_t	flow2;

	/* These pointers are set by get_dccp_conversation_data()
	 * fwd point in the same direction as the current packet
	 * and rev in the reverse direction
	 */
	dccp_flow_t	*fwd;
	dccp_flow_t	*rev;

	/* Keep track of dccp stream numbers instead of using the conversation
	 * index (as how it was done before). This prevents gaps in the
	 * stream index numbering
	 */
	guint32		stream;

	/* Remember the timestamp of the first frame seen in this dccp
	 * conversation to be able to calculate a relative time compared
	 * to the start of this conversation
	 */
	nstime_t	ts_first;

	/* Remember the timestamp of the frame that was last seen in this
	 * dccp conversation to be able to calculate a delta time compared
	 * to previous frame in this conversation
	 */
	nstime_t	ts_prev;
};

/** Get the current number of DCCP streams
 *
 * @return The number of DCCP streams
 */
WS_DLL_PUBLIC guint32 get_dccp_stream_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_DCCP_H__ */

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
