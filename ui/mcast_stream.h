/** @file
 *
 * Copyright 2006, Iskratel , Slovenia
 * By Jakob Bratkovic <j.bratkovic@iskratel.si> and
 * Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream.h
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MCAST_STREAM_H__
#define __MCAST_STREAM_H__

#include <epan/tap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAX_SPEED 200000

/* typedefs for sliding window and buffer size */
typedef struct buffer{
    nstime_t *buff;            /* packet times */
    int32_t first;             /* pointer to the first element */
    int32_t last;              /* pointer to the last element */
    int32_t burstsize;         /* current burst */
    int32_t topburstsize;      /* maximum burst in the refresh interval*/
    int32_t count;             /* packet counter */
    int32_t burststatus;       /* burst status */
    int32_t numbursts;         /* number of bursts */
    int32_t buffusage;         /* buffer usage */
    int32_t buffstatus;        /* buffer status */
    int32_t numbuffalarms;     /* number of alarms triggered by buffer underruns */
    int32_t topbuffusage;      /* top buffer usage in refresh interval */
    double maxbw;              /* Maximum bandwidth usage. Bits/s */
} t_buffer;


/* defines an mcast stream */
typedef struct _mcast_stream_info {
    address src_addr;
    uint16_t src_port;
    address dest_addr;
    uint16_t dest_port;
    uint32_t npackets;
    double  apackets;
    uint32_t total_bytes;
    double  average_bw;         /* Bits/s */

    uint32_t first_frame_num; /* frame number of first frame */
    /* start of recording (GMT) of this stream */
    nstime_t start_abs;        /* absolute stream start time */
    nstime_t start_rel;        /* stream start time relative to first packet in capture */
    nstime_t stop_rel;         /* stream stop time relative to first packet in capture */
    uint16_t vlan_id;

    /*for the sliding window */
    t_buffer element;

} mcast_stream_info_t;

typedef struct _mcaststream_tapinfo mcaststream_tapinfo_t;

typedef void (*mcaststream_tap_reset_cb)(mcaststream_tapinfo_t *tapinfo);
typedef void (*mcaststream_tap_draw_cb)(mcaststream_tapinfo_t *tapinfo);

/* structure that holds the information about all detected streams */
/* struct holding all information of the tap */
struct _mcaststream_tapinfo {
    void *user_data;     /* User data pointer */
    mcaststream_tap_reset_cb tap_reset; /**< tap reset callback */
    mcaststream_tap_draw_cb tap_draw;   /**< tap draw callback */
    GList*  strinfo_list;   /* list of mcast_stream_info_t */
    uint32_t npackets;       /* total number of mcast packets of all streams */
    mcast_stream_info_t* allstreams; /* structure holding information common for all streams */

    bool is_registered; /* if the tap listener is currently registered or not */
};


extern int32_t mcast_stream_trigger;
extern int32_t mcast_stream_bufferalarm;
extern uint16_t mcast_stream_burstint;
extern int32_t mcast_stream_emptyspeed;
extern int32_t mcast_stream_cumulemptyspeed;

/****************************************************************************/
/* INTERFACE */

/*
* Registers the mcast_streams tap listener (if not already done).
* From that point on, the Mcast streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever mcast_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the mcast_streams and mcast_analysis functions that need it.
*/
GString * register_tap_listener_mcast_stream(mcaststream_tapinfo_t *tapinfo);

/*
* Removes the mcast_streams tap listener (if not already done)
* From that point on, the Mcast streams list won't be updated any more.
*/
void remove_tap_listener_mcast_stream(mcaststream_tapinfo_t *tapinfo);

/*
* Cleans up memory of mcast streams tap.
*/
void mcaststream_reset(mcaststream_tapinfo_t *tapinfo);

/*
* Tap callback (tap_packet_cb) for Mcast stream tap updates. Useful if for
* some reason you can't register the default listener, but want to make use
* of the existing Mcast calculations.
*/
tap_packet_status mcaststream_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MCAST_STREAM_H__ */
