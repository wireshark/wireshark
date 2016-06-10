/* voip_calls.c
 * VoIP calls summary addition for Wireshark
 *
 * Copyright 2004, Ericsson, Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_calls.c
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP, RTP Event, MGCP, AudioCodes (ISDN PRI and CAS), T38 and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "epan/epan_dissect.h"
#include "epan/packet.h"
#include "epan/proto_data.h"
#include "epan/to_str.h"
#include "epan/dissectors/packet-sip.h"
#include "epan/dissectors/packet-h225.h"
#include "epan/dissectors/packet-h245.h"
#include "epan/dissectors/packet-isup.h"
#include "epan/dissectors/packet-sdp.h"
#include "epan/dissectors/packet-mgcp.h"
#include "epan/dissectors/packet-mtp3.h"
#include "epan/dissectors/packet-actrace.h"
#include "epan/dissectors/packet-q931.h"
#include "epan/dissectors/packet-rtp.h"
#include "epan/dissectors/packet-rtp-events.h"
#include "epan/dissectors/packet-t38.h"
#include "epan/dissectors/packet-t30.h"
#include "epan/dissectors/packet-h248.h"
#include "epan/dissectors/packet-sccp.h"
#include "plugins/unistim/packet-unistim.h"
#include "epan/dissectors/packet-skinny.h"
#include "epan/dissectors/packet-iax2.h"
#include "epan/rtp_pt.h"

#include "ui/rtp_stream.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"
#include "ui/voip_calls.h"

#define DUMP_PTR1(p) printf("#=> %p\n",(void *)p)
#define DUMP_PTR2(p) printf("==> %p\n",(void *)p)

const char *voip_call_state_name[8]={
    "",
    "CALL SETUP",
    "RINGING",
    "IN CALL",
    "CANCELLED",
    "COMPLETED",
    "REJECTED",
    "UNKNOWN"
};

/* defines whether we can consider the call active */
const char *voip_protocol_name[]={
    "SIP",
    "ISUP",
    "H.323",
    "MGCP",
    "AC_ISDN",
    "AC_CAS",
    "T.38",
    "H.248",
    "SCCP",
    "BSSMAP",
    "RANAP",
    "UNISTIM",
    "SKINNY",
    "IAX2",
    "VoIP"
};

/*
 * Tap IDs must be unique. Since different taps need to share the
 * same voip_calls_tapinfo_t *, make it unique by offsetting its
 * value.
 */
enum {
    tap_id_offset_actrace_,
    tap_id_offset_h225_,
    tap_id_offset_h245dg_,
    tap_id_offset_h248_,
    tap_id_offset_iax2_,
    tap_id_offset_isup_,
    tap_id_offset_m3ua_,
    tap_id_offset_megaco_,
    tap_id_offset_mgcp_,
    tap_id_offset_mtp3_,
    tap_id_offset_q931_,
    tap_id_offset_rtp_,
    tap_id_offset_rtp_event_,
    tap_id_offset_sccp_,
    tap_id_offset_sdp_,
    tap_id_offset_sip_,
    tap_id_offset_skinny_,
    tap_id_offset_sua_,
    tap_id_offset_t38_,
    tap_id_offset_unistim_,
    tap_id_offset_voip_
};

#define REDRAW_ACTRACE   (1 << tap_id_offset_actrace_)
#define REDRAW_H225      (1 << tap_id_offset_h225_)
#define REDRAW_H245DG    (1 << tap_id_offset_h245dg_)
#define REDRAW_H248      (1 << tap_id_offset_h248_)
#define REDRAW_IAX2      (1 << tap_id_offset_iax2_)
#define REDRAW_ISUP      (1 << tap_id_offset_isup_)
#define REDRAW_M3UA      (1 << tap_id_offset_m3ua_)
#define REDRAW_MEGACO    (1 << tap_id_offset_megaco_)
#define REDRAW_MGCP      (1 << tap_id_offset_mgcp_)
#define REDRAW_MTP3      (1 << tap_id_offset_mtp3_)
#define REDRAW_Q931      (1 << tap_id_offset_q931_)
#define REDRAW_RTP       (1 << tap_id_offset_rtp_)
#define REDRAW_RTP_EVENT (1 << tap_id_offset_rtp_event_)
#define REDRAW_SCCP      (1 << tap_id_offset_sccp_)
#define REDRAW_SDP       (1 << tap_id_offset_sdp_)
#define REDRAW_SIP       (1 << tap_id_offset_sip_)
#define REDRAW_SKINNY    (1 << tap_id_offset_skinny_)
#define REDRAW_SUA       (1 << tap_id_offset_sua_)
#define REDRAW_T38       (1 << tap_id_offset_t38_)
#define REDRAW_UNISTIM   (1 << tap_id_offset_unistim_)
#define REDRAW_VOIP      (1 << tap_id_offset_voip_)

static inline void *
tap_base_to_id(voip_calls_tapinfo_t* tap_base, int offset) {
    return GSIZE_TO_POINTER(GPOINTER_TO_SIZE(tap_base) + offset);
}

static inline voip_calls_tapinfo_t *
tap_id_to_base(void* tap_id, int offset) {
    return (voip_calls_tapinfo_t *) GSIZE_TO_POINTER(GPOINTER_TO_SIZE(tap_id) - offset);
}

typedef struct {
    gchar *frame_label;
    gchar *comment;
} graph_str;

#define H245_MAX 6

typedef struct _h245_labels {
    guint32   frame_num;
    gint8     labels_count;
    graph_str labels[H245_MAX];
} h245_labels_t;

static void actrace_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void h225_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void h245dg_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void h248_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void iax2_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void isup_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void mgcp_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void mtp3_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void q931_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void rtp_event_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void rtp_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void sccp_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void sdp_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void sip_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void skinny_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void t38_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void unistim_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);
static void voip_calls_init_tap(voip_calls_tapinfo_t *tap_id_base);

void
voip_calls_init_all_taps(voip_calls_tapinfo_t *tap_id_base)
{
    actrace_calls_init_tap(tap_id_base);
    h225_calls_init_tap(tap_id_base);
    h245dg_calls_init_tap(tap_id_base);
    h248_calls_init_tap(tap_id_base);
    iax2_calls_init_tap(tap_id_base);
    isup_calls_init_tap(tap_id_base);
    mgcp_calls_init_tap(tap_id_base);
    mtp3_calls_init_tap(tap_id_base);
    q931_calls_init_tap(tap_id_base);
    rtp_event_init_tap(tap_id_base);
    rtp_init_tap(tap_id_base); /* This calls tap_reset_cb, tap_packet_cb, and tap_draw_cb */
    sccp_calls_init_tap(tap_id_base);
    sdp_calls_init_tap(tap_id_base);
    sip_calls_init_tap(tap_id_base);
    skinny_calls_init_tap(tap_id_base);
    t38_init_tap(tap_id_base);
    /* We don't register this tap if we don't have the unistim plugin loaded.*/
    if (find_tap_id("unistim")) {
        unistim_calls_init_tap(tap_id_base);
    }
    if (find_tap_id("voip")) {
        voip_calls_init_tap(tap_id_base);
    }
}

static void remove_tap_listener_actrace_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_h225_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_h245dg_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_h248_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_iax2_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_isup_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_mgcp_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_mtp3_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_q931_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_rtp(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_rtp_event(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_sccp_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_sdp_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_sip_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_skinny_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_t38(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_unistim_calls(voip_calls_tapinfo_t *tap_id_base);
static void remove_tap_listener_voip_calls(voip_calls_tapinfo_t *tap_id_base);

void voip_calls_remove_all_tap_listeners(voip_calls_tapinfo_t *tap_id_base)
{
    /* Remove the calls tap listener */
    remove_tap_listener_actrace_calls(tap_id_base);
    remove_tap_listener_h225_calls(tap_id_base);
    remove_tap_listener_h245dg_calls(tap_id_base);
    remove_tap_listener_h248_calls(tap_id_base);
    remove_tap_listener_iax2_calls(tap_id_base);
    remove_tap_listener_isup_calls(tap_id_base);
    remove_tap_listener_mgcp_calls(tap_id_base);
    remove_tap_listener_mtp3_calls(tap_id_base);
    remove_tap_listener_q931_calls(tap_id_base);
    remove_tap_listener_rtp(tap_id_base);
    remove_tap_listener_rtp_event(tap_id_base);
    remove_tap_listener_sccp_calls(tap_id_base);
    remove_tap_listener_sdp_calls(tap_id_base);
    remove_tap_listener_sip_calls(tap_id_base);
    remove_tap_listener_skinny_calls(tap_id_base);
    remove_tap_listener_t38(tap_id_base);
    if (find_tap_id("unistim")) { /* The plugin may be missing */
        remove_tap_listener_unistim_calls(tap_id_base);
    }
    if (find_tap_id("voip")) {
        remove_tap_listener_voip_calls(tap_id_base);
    }
}

/****************************************************************************/
/* when there is a [re]reading of packet's */
void
voip_calls_reset_all_taps(voip_calls_tapinfo_t *tapinfo)
{
    voip_calls_info_t *callsinfo;
    rtp_stream_info_t *strinfo;
    GList *list = NULL;

    /* VOIP_CALLS_DEBUG("reset packets: %d streams: %d", tapinfo->npackets, tapinfo->nrtp_streams); */

    /* free the data items first */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list)
    {
        callsinfo = (voip_calls_info_t *)list->data;
        g_free(callsinfo->call_id);
        g_free(callsinfo->from_identity);
        g_free(callsinfo->to_identity);
        free_address(&callsinfo->initial_speaker);
        g_free(callsinfo->protocol_name);
        g_free(callsinfo->call_comment);

        if (callsinfo->free_prot_info && callsinfo->prot_info)
            callsinfo->free_prot_info(callsinfo->prot_info);

        g_free(list->data);
        list = g_list_next(list);
    }
    g_queue_clear(tapinfo->callsinfos);
    /* free the SIP_HASH */
    if(NULL!=tapinfo->callsinfo_hashtable[SIP_HASH])
        g_hash_table_remove_all (tapinfo->callsinfo_hashtable[SIP_HASH]);

    /* free the strinfo data items first */
    list = g_list_first(tapinfo->rtp_stream_list);
    while(list)
    {
        strinfo = (rtp_stream_info_t *)list->data;
        wmem_free(NULL, strinfo->payload_type_name);
        list = g_list_next(list);
    }
    g_list_free(tapinfo->rtp_stream_list);
    tapinfo->rtp_stream_list = NULL;

    if (tapinfo->h245_labels) {
        memset(tapinfo->h245_labels, 0, sizeof(h245_labels_t));
    }

    tapinfo->ncalls = 0;
    tapinfo->start_packets = 0;
    tapinfo->completed_calls = 0;
    tapinfo->rejected_calls = 0;

    return;
}

/****************************************************************************/
/* Add a new item into the graph */
static void
add_to_graph(voip_calls_tapinfo_t *tapinfo, packet_info *pinfo, epan_dissect_t *edt, const gchar *frame_label, const gchar *comment, guint16 call_num, address *src_addr, address *dst_addr, guint16 line_style)
{
    seq_analysis_item_t *gai;
    gchar time_str[COL_MAX_LEN];

    if (!tapinfo->graph_analysis) {
        return;
    }

    gai = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
    gai->frame_number = pinfo->num;
    copy_address(&(gai->src_addr),src_addr);
    copy_address(&(gai->dst_addr),dst_addr);

    gai->port_src=pinfo->srcport;
    gai->port_dst=pinfo->destport;
    gai->protocol = g_strdup(port_type_to_str(pinfo->ptype));

    if (frame_label != NULL)
        gai->frame_label = g_strdup(frame_label);
    else
        gai->frame_label = g_strdup("");

    if (comment != NULL)
        gai->comment = g_strdup(comment);
    else
        gai->comment = g_strdup("");

    gai->conv_num=call_num;
    gai->line_style=line_style;
    set_fd_time(edt->session, pinfo->fd, time_str);
    gai->time_str = g_strdup(time_str);
    gai->display=FALSE;

    g_queue_push_tail(tapinfo->graph_analysis->items, gai);
    g_hash_table_insert(tapinfo->graph_analysis->ht, &gai->frame_number, gai);
}

/****************************************************************************/
/* Append str to frame_label and comment in a graph item */
/* return 0 if the frame_num is not in the graph list */
static int append_to_frame_graph(voip_calls_tapinfo_t *tapinfo, guint32 frame_num, const gchar *new_frame_label, const gchar *new_comment)
{
    seq_analysis_item_t *gai=NULL;
    gchar *frame_label = NULL;
    gchar *comment = NULL;

    if(tapinfo->graph_analysis && NULL!=tapinfo->graph_analysis->ht)
        gai=(seq_analysis_item_t *)g_hash_table_lookup(tapinfo->graph_analysis->ht, &frame_num);
    if(gai) {
        frame_label = gai->frame_label;
        comment = gai->comment;

        if (new_frame_label != NULL) {
            gai->frame_label = g_strdup_printf("%s %s", frame_label, new_frame_label);
            g_free(frame_label);
        }

        if (new_comment != NULL) {
            gai->comment = g_strdup_printf("%s %s", comment, new_comment);
            g_free(comment);
        }
    }

    return gai? 1 : 0;
}

/****************************************************************************/
/* Change the frame_label and comment in a graph item if not NULL*/
/* return 0 if the frame_num is not in the graph list */
static int change_frame_graph(voip_calls_tapinfo_t *tapinfo, guint32 frame_num, const gchar *new_frame_label, const gchar *new_comment)
{
    seq_analysis_item_t *gai=NULL;
    gchar *frame_label = NULL;
    gchar *comment = NULL;

    if(tapinfo->graph_analysis && NULL!=tapinfo->graph_analysis->ht)
        gai=(seq_analysis_item_t *)g_hash_table_lookup(tapinfo->graph_analysis->ht, &frame_num);
    if(gai) {
        frame_label = gai->frame_label;
        comment = gai->comment;

        if (new_frame_label != NULL) {
            gai->frame_label = g_strdup(new_frame_label);
            g_free(frame_label);
        }

        if (new_comment != NULL) {
            gai->comment = g_strdup(new_comment);
            g_free(comment);
        }
    }

    return gai? 1 : 0;
}

/****************************************************************************/
/* Change all the graph items with call_num to new_call_num */
static guint change_call_num_graph(voip_calls_tapinfo_t *tapinfo, guint16 call_num, guint16 new_call_num)
{
    seq_analysis_item_t *gai;
    GList *list;
    guint  items_changed;

    items_changed = 0;
    if(tapinfo->graph_analysis){
        list = g_queue_peek_nth_link(tapinfo->graph_analysis->items, 0);
        while (list)
        {
            gai = (seq_analysis_item_t *)list->data;
            if (gai->conv_num == call_num) {
                gai->conv_num = new_call_num;
                items_changed++;
            }
            list = g_list_next(list);
        }
    }
    return items_changed;
}

/****************************************************************************/
/* Insert the item in the graph list */
static void insert_to_graph_t38(voip_calls_tapinfo_t *tapinfo, packet_info *pinfo, epan_dissect_t *edt, const gchar *frame_label, const gchar *comment, guint16 call_num, address *src_addr, address *dst_addr, guint16 line_style, guint32 frame_num)
{
    seq_analysis_item_t *gai, *new_gai;
    GList    *list;
    guint     item_num;
    gboolean  inserted;
    gchar     time_str[COL_MAX_LEN];

    new_gai = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
    new_gai->frame_number = frame_num;
    copy_address(&(new_gai->src_addr),src_addr);
    copy_address(&(new_gai->dst_addr),dst_addr);

    new_gai->port_src=pinfo->srcport;
    new_gai->port_dst=pinfo->destport;
    new_gai->protocol = g_strdup(port_type_to_str(pinfo->ptype));
    if (frame_label != NULL)
        new_gai->frame_label = g_strdup(frame_label);
    else
        new_gai->frame_label = g_strdup("");

    if (comment != NULL)
        new_gai->comment = g_strdup(comment);
    else
        new_gai->comment = g_strdup("");
    new_gai->conv_num=call_num;
    new_gai->line_style=line_style;
    set_fd_time(edt->session, pinfo->fd, time_str);
    new_gai->time_str = g_strdup(time_str);
    new_gai->display=FALSE;

    item_num = 0;
    inserted = FALSE;
    if(tapinfo->graph_analysis){
        list = g_queue_peek_nth_link(tapinfo->graph_analysis->items, 0);
        while (list)
        {
            gai = (seq_analysis_item_t *)list->data;
            if (gai->frame_number > frame_num) {
                g_queue_insert_before(tapinfo->graph_analysis->items, list, new_gai);
                g_hash_table_insert(tapinfo->graph_analysis->ht, &new_gai->frame_number, new_gai);
                inserted = TRUE;
                break;
            }
            list = g_list_next(list);
            item_num++;
        }

        if (!inserted) {
            g_queue_push_tail(tapinfo->graph_analysis->items, new_gai);
            g_hash_table_insert(tapinfo->graph_analysis->ht, &new_gai->frame_number, new_gai);
        }
    }
}

/****************************************************************************/
/* ***************************TAP for RTP Events*****************************/
/****************************************************************************/

/*static guint32 rtp_evt_setup_frame_num = 0;*/

/****************************************************************************/
/* whenever a rtp event packet is seen by the tap listener */
static int
rtp_event_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *rtp_event_info)
{
    voip_calls_tapinfo_t         *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_rtp_event_);
    const struct _rtp_event_info *pi      = (const struct _rtp_event_info *)rtp_event_info;

    /* do not consider RTP events packets without a setup frame */
    if (pi->info_setup_frame_num == 0) {
        return FALSE;
    }

    tapinfo->rtp_evt_frame_num = pinfo->num;
    tapinfo->rtp_evt = pi->info_rtp_evt;
    tapinfo->rtp_evt_end = pi->info_end;

    return FALSE;
}

/****************************************************************************/
void
rtp_event_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("rtpevent", tap_base_to_id(tap_id_base, tap_id_offset_rtp_event_),
            NULL,
            0,
            NULL,
            rtp_event_packet,
            NULL
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/

void
remove_tap_listener_rtp_event(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_rtp_event_));
}

/****************************************************************************/
/* ***************************TAP for RTP **********************************/
/****************************************************************************/

/****************************************************************************/
/* when there is a [re]reading of RTP packets */
static void
rtp_reset(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_rtp_);
    GList *list;

    /* free the data items first */
    list = g_list_first(tapinfo->rtp_stream_list);
    while (list)
    {
        g_free(list->data);
        list = g_list_next(list);
    }
    g_list_free(tapinfo->rtp_stream_list);
    tapinfo->rtp_stream_list = NULL;
    tapinfo->nrtp_streams = 0;

    if (tapinfo->tap_reset) {
        tapinfo->tap_reset(tapinfo);
    }

    return;
}

/****************************************************************************/
/* whenever a RTP packet is seen by the tap listener */
static gboolean
rtp_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, void const *rtp_info_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_rtp_);
    rtp_stream_info_t    *tmp_listinfo;
    rtp_stream_info_t    *strinfo = NULL;
    GList                *list;
    struct _rtp_conversation_info *p_conv_data = NULL;

    const struct _rtp_info *rtp_info = (const struct _rtp_info *)rtp_info_ptr;

    /* do not consider RTP packets without a setup frame */
    if (rtp_info->info_setup_frame_num == 0) {
        return FALSE;
    }

    if (tapinfo->tap_packet) {
        tapinfo->tap_packet(tapinfo, pinfo, edt, rtp_info_ptr);
    }

    /* check whether we already have a RTP stream with this setup frame and ssrc in the list */
    list = g_list_first(tapinfo->rtp_stream_list);
    while (list)
    {
        tmp_listinfo=(rtp_stream_info_t *)list->data;
        if ( (tmp_listinfo->setup_frame_number == rtp_info->info_setup_frame_num)
                && (tmp_listinfo->ssrc == rtp_info->info_sync_src) && (tmp_listinfo->end_stream == FALSE)) {
            /* if the payload type has changed, we mark the stream as finished to create a new one
               this is to show multiple payload changes in the Graph for example for DTMF RFC2833 */
            if ( tmp_listinfo->payload_type != rtp_info->info_payload_type ) {
                tmp_listinfo->end_stream = TRUE;
            } else {
                strinfo = (rtp_stream_info_t*)(list->data);
                break;
            }
        }
        list = g_list_next(list);
    }

    /* if this is a duplicated RTP Event End, just return */
    if ((tapinfo->rtp_evt_frame_num == pinfo->num) && !strinfo && (tapinfo->rtp_evt_end == TRUE)) {
        return FALSE;
    }

    /* not in the list? then create a new entry */
    if (strinfo==NULL) {
        strinfo = (rtp_stream_info_t *)g_malloc0(sizeof(rtp_stream_info_t));
        copy_address(&(strinfo->src_addr), &(pinfo->src));
        strinfo->src_port = pinfo->srcport;
        copy_address(&(strinfo->dest_addr), &(pinfo->dst));
        strinfo->dest_port = pinfo->destport;
        strinfo->ssrc = rtp_info->info_sync_src;
        strinfo->payload_type = rtp_info->info_payload_type;
        strinfo->is_srtp = rtp_info->info_is_srtp;
        /* if it is dynamic payload, let use the conv data to see if it is defined */
        if ( (strinfo->payload_type >= PT_UNDF_96) && (strinfo->payload_type <= PT_UNDF_127) ) {
            /* Use existing packet info if available */
            p_conv_data = (struct _rtp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_get_id_by_filter_name("rtp"), 0);
            if (p_conv_data && p_conv_data->rtp_dyn_payload) {
                const gchar *encoding_name = rtp_dyn_payload_get_name(p_conv_data->rtp_dyn_payload, strinfo->payload_type);
                if (encoding_name) {
                    strinfo->payload_type_name = wmem_strdup(NULL, encoding_name);
                }
            }
        }
        if (!strinfo->payload_type_name) strinfo->payload_type_name = (gchar*)val_to_str_ext_wmem(NULL, strinfo->payload_type, &rtp_payload_type_short_vals_ext, "%u");
        strinfo->start_fd = pinfo->fd;
        strinfo->start_rel_time = pinfo->rel_ts;
        strinfo->setup_frame_number = rtp_info->info_setup_frame_num;
        strinfo->call_num = -1;
        strinfo->rtp_event = -1;
        tapinfo->rtp_stream_list = g_list_prepend(tapinfo->rtp_stream_list, strinfo);
    }

    /* Add the info to the existing RTP stream */
    strinfo->packet_count++;
    strinfo->stop_fd = pinfo->fd;

    /* process RTP Event */
    if (tapinfo->rtp_evt_frame_num == pinfo->num) {
        strinfo->rtp_event = tapinfo->rtp_evt;
        if (tapinfo->rtp_evt_end == TRUE) {
            strinfo->end_stream = TRUE;
        }
    }

    tapinfo->redraw |= REDRAW_RTP;

    return FALSE;
}

/****************************************************************************/
/* whenever a redraw in the RTP tap listener */
static void
rtp_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_rtp_);
    GList                *rtp_streams_list;
    rtp_stream_info_t    *rtp_listinfo;
    /* GList *voip_calls_graph_list; */
    seq_analysis_item_t  *gai     = NULL;
    seq_analysis_item_t  *new_gai;
    guint16               conv_num;
    guint32               duration;
    gchar                 time_str[COL_MAX_LEN];

    /* add each rtp stream to the graph */
    rtp_streams_list = g_list_first(tapinfo->rtp_stream_list);
    while (rtp_streams_list)
    {
        rtp_listinfo = (rtp_stream_info_t *)rtp_streams_list->data;

        /* using the setup frame number of the RTP stream, we get the call number that it belongs to*/
        /* voip_calls_graph_list = g_list_first(tapinfo->graph_analysis->list); */
        if(tapinfo->graph_analysis){
            gai = (seq_analysis_item_t *)g_hash_table_lookup(tapinfo->graph_analysis->ht, &rtp_listinfo->setup_frame_number);
        }
        if(gai != NULL) {
            const char *comment_fmt = "%s, %u packets. Duration: %u.%03us SSRC: 0x%X";
            /* Found the setup frame*/
            conv_num = gai->conv_num;
            /* if RTP was already in the Graph, just update the comment information */
            gai = (seq_analysis_item_t *)g_hash_table_lookup(tapinfo->graph_analysis->ht, &rtp_listinfo->start_fd->num);
            if (gai != NULL) {
                duration = (guint32)(nstime_to_msec(&rtp_listinfo->stop_rel_time) - nstime_to_msec(&rtp_listinfo->start_rel_time));
                g_free(gai->comment);
                gai->comment = g_strdup_printf(comment_fmt,
                        (rtp_listinfo->is_srtp)?"SRTP":"RTP", rtp_listinfo->packet_count,
                        duration/1000,(duration%1000), rtp_listinfo->ssrc);
            } else {
                new_gai = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
                new_gai->frame_number = rtp_listinfo->start_fd->num;
                copy_address(&(new_gai->src_addr),&(rtp_listinfo->src_addr));
                copy_address(&(new_gai->dst_addr),&(rtp_listinfo->dest_addr));
                new_gai->port_src = rtp_listinfo->src_port;
                new_gai->port_dst = rtp_listinfo->dest_port;
                duration = (guint32)(nstime_to_msec(&rtp_listinfo->stop_rel_time) - nstime_to_msec(&rtp_listinfo->start_rel_time));
                new_gai->frame_label = g_strdup_printf("%s (%s) %s",
                        (rtp_listinfo->is_srtp)?"SRTP":"RTP",
                        rtp_listinfo->payload_type_name,
                        (rtp_listinfo->rtp_event == -1)?
                        "":val_to_str_ext_const(rtp_listinfo->rtp_event, &rtp_event_type_values_ext, "Unknown RTP Event"));
                new_gai->comment = g_strdup_printf(comment_fmt,
                        (rtp_listinfo->is_srtp)?"SRTP":"RTP", rtp_listinfo->packet_count,
                        duration/1000,(duration%1000), rtp_listinfo->ssrc);
                new_gai->conv_num = conv_num;
                set_fd_time(tapinfo->session, rtp_listinfo->start_fd, time_str);
                new_gai->time_str = g_strdup(time_str);
                new_gai->display=FALSE;
                new_gai->line_style = 2;  /* the arrow line will be 2 pixels width */
                g_queue_push_tail(tapinfo->graph_analysis->items, new_gai);
                g_hash_table_insert(tapinfo->graph_analysis->ht, &rtp_listinfo->start_fd, new_gai);
            }
        }
        rtp_streams_list = g_list_next(rtp_streams_list);
    } /* while (rtp_streams_list) */

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_RTP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_RTP;
    }
}
#if 0
static void
rtp_packet_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_rtp_);
    GList                *rtp_streams_list;
    rtp_stream_info_t    *rtp_listinfo;
    GList                *voip_calls_graph_list;
    guint                 item;
    seq_analysis_item_t  *gai;
    seq_analysis_item_t  *new_gai;
    guint16               conv_num;
    guint32               duration;
    gchar                 time_str[COL_MAX_LEN];

    /* add each rtp stream to the graph */
    rtp_streams_list = g_list_first(tapinfo->stream_list);
    while (rtp_streams_list)
    {
        rtp_listinfo = rtp_streams_list->data;

        /* using the setup frame number of the RTP stream, we get the call number that it belongs to*/
        voip_calls_graph_list = g_list_first(tapinfo->graph_analysis->list);
        while (voip_calls_graph_list)
        {
            gai = voip_calls_graph_list->data;
            conv_num = gai->conv_num;
            /* if we get the setup frame number, then get the time position to graph the RTP arrow */
            if (rtp_listinfo->setup_frame_number == gai->frame_number) {
                /* look again from the beginning because there are cases where the Setup frame is after the RTP */
                voip_calls_graph_list = g_list_first(tapinfo->graph_analysis->list);
                item = 0;
                while(voip_calls_graph_list) {
                    gai = voip_calls_graph_list->data;
                    /* if RTP was already in the Graph, just update the comment information */
                    if (rtp_listinfo->start_fd->num == gai->frame_number) {
                        duration = (guint32)(nstime_to_msec(&rtp_listinfo->stop_fd->rel_ts) - nstime_to_msec(&rtp_listinfo->start_fd->rel_ts));
                        g_free(gai->comment);
                        gai->comment = g_strdup_printf("%s Num packets:%u  Duration:%u.%03us SSRC:0x%X",
                                                       (rtp_listinfo->is_srtp)?"SRTP":"RTP", rtp_listinfo->npackets,
                                                       duration/1000,(duration%1000), rtp_listinfo->ssrc);
                        break;
                    }

                    /* we increment the list here to be able to check if it is the last item in this calls, which means the RTP is after so we have to draw it */
                    voip_calls_graph_list = g_list_next(voip_calls_graph_list);
                    if (!voip_calls_graph_list) item++;

                    /* add the RTP item to the graph if was not there*/
                    if (rtp_listinfo->start_fd->num<gai->frame_number || !voip_calls_graph_list) {
                        new_gai = g_malloc0(sizeof(seq_analysis_item_t));
                        new_gai->frame_number = rtp_listinfo->start_fd->num;
                        copy_address(&(new_gai->src_addr),&(rtp_listinfo->src_addr));
                        copy_address(&(new_gai->dst_addr),&(rtp_listinfo->dest_addr));
                        new_gai->port_src = rtp_listinfo->src_port;
                        new_gai->port_dst = rtp_listinfo->dest_port;
                        new_gai->protocol = g_strdup(port_type_to_str(pinfo->ptype));
                        duration = (guint32)(nstime_to_msec(&rtp_listinfo->stop_fd->rel_ts) - nstime_to_msec(&rtp_listinfo->start_fd->rel_ts));
                        new_gai->frame_label = g_strdup_printf("%s (%s) %s",
                                                               (rtp_listinfo->is_srtp)?"SRTP":"RTP",
                                                               rtp_listinfo->payload_type_str,
                                                               (rtp_listinfo->rtp_event == -1)?
                                                               "":val_to_str_ext_const(rtp_listinfo->rtp_event, &rtp_event_type_values_ext, "Unknown RTP Event"));
                        new_gai->comment = g_strdup_printf("%s Num packets:%u  Duration:%u.%03us SSRC:0x%X",
                                                           (rtp_listinfo->is_srtp)?"SRTP":"RTP", rtp_listinfo->npackets,
                                                           duration/1000,(duration%1000), rtp_listinfo->ssrc);
                        new_gai->conv_num = conv_num;
                        set_fd_time(cfile.epan, rtp_listinfo->start_fd, time_str);
                        new_gai->time_str = g_strdup(time_str);
                        new_gai->display=FALSE;
                        new_gai->line_style = 2;  /* the arrow line will be 2 pixels width */
                        tapinfo->graph_analysis->list = g_list_insert(tapinfo->graph_analysis->list, new_gai, item);
                        break;
                    }
                    if (voip_calls_graph_list) item++;
                }
                break;
            }
            voip_calls_graph_list = g_list_next(voip_calls_graph_list);
        }
        rtp_streams_list = g_list_next(rtp_streams_list);
    }
}
#endif

/****************************************************************************/
void
rtp_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("rtp", tap_base_to_id(tap_id_base, tap_id_offset_rtp_), NULL,
            0,
            rtp_reset,
            rtp_packet,
            rtp_draw
            );
    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_rtp(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_rtp_));
}

/****************************************************************************/
/******************************TAP for T38 **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a T38 packet is seen by the tap listener */
static gboolean
t38_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *t38_info_ptr)
{
    voip_calls_tapinfo_t *tapinfo               = tap_id_to_base(tap_offset_ptr, tap_id_offset_t38_);

    voip_calls_info_t    *callsinfo             = NULL;
    voip_calls_info_t    *tmp_listinfo;
    GList                *voip_calls_graph_list = NULL;
    GList                *list;
    gchar                *frame_label           = NULL;
    gchar                *comment               = NULL;
    seq_analysis_item_t  *tmp_gai, *gai         = NULL;
    gchar                *tmp_str1, *tmp_str2;
    guint16               line_style            = 2;
    double                duration;
    int                   conv_num              = -1;

    const t38_packet_info *t38_info = (const t38_packet_info *)t38_info_ptr;

    if  (t38_info->setup_frame_number != 0) {
        /* using the setup frame number of the T38 packet, we get the call number that it belongs */
        if(tapinfo->graph_analysis){
            voip_calls_graph_list = g_queue_peek_nth_link(tapinfo->graph_analysis->items, 0);
        }
        while (voip_calls_graph_list)
        {
            tmp_gai = (seq_analysis_item_t *)voip_calls_graph_list->data;
            if (t38_info->setup_frame_number == tmp_gai->frame_number) {
                gai = tmp_gai;
                break;
            }
            voip_calls_graph_list = g_list_next(voip_calls_graph_list);
        }
        if (gai) conv_num = (int) gai->conv_num;
    }

    /* if setup_frame_number in the t38 packet is 0, it means it was not set using an SDP or H245 sesion, which means we don't
     * have the associated Voip calls. It probably means the the packet was decoded using the default t38 port, or using "Decode as.."
     * in this case we create a "voip" call that only have t38 media (no signaling)
     * OR if we have not found the Setup message in the graph.
     */
    if ( (t38_info->setup_frame_number == 0) || (gai == NULL) ) {
        /* check whether we already have a call with these parameters in the list */
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if (tmp_listinfo->protocol == MEDIA_T38) {
                callsinfo = (voip_calls_info_t*)(list->data);
                break;
            }
            list = g_list_next (list);
        }

        /* not in the list? then create a new entry */
        if (callsinfo==NULL) {
            callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_UNKNOWN;
            callsinfo->from_identity=g_strdup("T38 Media only");
            callsinfo->to_identity=g_strdup("T38 Media only");
            copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
            callsinfo->selected=FALSE;
            callsinfo->start_fd = pinfo->fd;
            callsinfo->start_rel_ts = pinfo->rel_ts;
            callsinfo->protocol=MEDIA_T38;
            callsinfo->prot_info=NULL;
            callsinfo->free_prot_info = NULL;
            callsinfo->npackets = 0;
            callsinfo->call_num = tapinfo->ncalls++;
            g_queue_push_tail(tapinfo->callsinfos, callsinfo);
        }
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
        /* increment the packets counter of all calls */
        ++(tapinfo->npackets);

        conv_num = (int) callsinfo->call_num;
    }

    /* at this point we should have found the call num for this t38 packets belong */
    if (conv_num == -1) {
        return FALSE;
    }

    /* add the item to the graph list */
    if (t38_info->type_msg == 0) { /* 0=t30-indicator */
        tmp_str1 = val_to_str_wmem(NULL, t38_info->t30ind_value, t38_T30_indicator_vals, "Ukn (0x%02X)");
        frame_label = g_strdup(tmp_str1);
        comment = g_strdup_printf("t38:t30 Ind:%s", tmp_str1);
        wmem_free(NULL, tmp_str1);
        line_style = 1;
    } else if (t38_info->type_msg == 1) {  /* 1=data */
        switch(t38_info->Data_Field_field_type_value) {
            case 0: /* hdlc-data */
                break;
            case 2: /* hdlc-fcs-OK */
            case 4: /* hdlc-fcs-OK-sig-end */
                tmp_str1 = val_to_str_ext_wmem(NULL, t38_info->t30_Facsimile_Control & 0x7F,
                            &t30_facsimile_control_field_vals_short_ext,
                            "Ukn (0x%02X)");
                frame_label = g_strdup_printf("%s %s",
                        tmp_str1,
                        t38_info->desc);
                wmem_free(NULL, tmp_str1);

                tmp_str1 = val_to_str_ext_wmem(NULL, t38_info->t30_Facsimile_Control & 0x7F,
                            &t30_facsimile_control_field_vals_ext,
                            "Ukn (0x%02X)");
                tmp_str2 = val_to_str_wmem(NULL, t38_info->data_value,
                            t38_T30_data_vals,
                            "Ukn (0x%02X)");
                comment      = g_strdup_printf("t38:%s:HDLC:%s", tmp_str2, tmp_str1);
                wmem_free(NULL, tmp_str1);
                wmem_free(NULL, tmp_str2);
                break;
            case 3: /* hdlc-fcs-BAD */
            case 5: /* hdlc-fcs-BAD-sig-end */
                frame_label = g_strdup(t38_info->Data_Field_field_type_value == 3 ? "fcs-BAD" : "fcs-BAD-sig-end");
                tmp_str1    = val_to_str_wmem(NULL, t38_info->data_value, t38_T30_data_vals, "Ukn (0x%02X)");
                comment    = g_strdup_printf("WARNING: received t38:%s:HDLC:%s",
                        tmp_str1,
                        t38_info->Data_Field_field_type_value == 3 ? "fcs-BAD" : "fcs-BAD-sig-end");
                wmem_free(NULL, tmp_str1);
                break;
            case 7: /* t4-non-ecm-sig-end */
                duration = nstime_to_sec(&pinfo->rel_ts) - t38_info->time_first_t4_data;
                tmp_str1    = val_to_str_wmem(NULL, t38_info->data_value, t38_T30_data_vals, "Ukn (0x%02X)");
                frame_label = g_strdup_printf("t4-non-ecm-data:%s", tmp_str1);
                comment     = g_strdup_printf("t38:t4-non-ecm-data:%s Duration: %.2fs %s",
                        tmp_str1, duration, t38_info->desc_comment );
                insert_to_graph_t38(tapinfo, pinfo, edt, frame_label, comment,
                        (guint16)conv_num, &(pinfo->src), &(pinfo->dst),
                        line_style, t38_info->frame_num_first_t4_data);
                wmem_free(NULL, tmp_str1);
                break;
        }
    }

    if (frame_label && !(t38_info->Data_Field_field_type_value == 7 && t38_info->type_msg == 1)) {
        add_to_graph(tapinfo, pinfo, edt, frame_label, comment, (guint16)conv_num, &(pinfo->src), &(pinfo->dst), line_style);
    }

    g_free(comment);
    g_free(frame_label);

    tapinfo->redraw |= REDRAW_T38;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
t38_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_t38_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_T38)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_T38;
    }
}

/****************************************************************************/
void
t38_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("t38", tap_base_to_id(tap_id_base, tap_id_offset_t38_), NULL,
            0,
            NULL,
            t38_packet,
            t38_draw
            );
    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_t38(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_t38_));
}


/****************************************************************************/
/* ***************************TAP for SIP **********************************/
/****************************************************************************/

static void
free_sip_info(gpointer p) {
    sip_calls_info_t *si = (sip_calls_info_t *)p;

    g_free(si->call_identifier);
    g_free(si);
}

/****************************************************************************/
/* whenever a SIP packet is seen by the tap listener */
static gboolean
sip_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt , const void *SIPinfo)
{
    voip_calls_tapinfo_t *tapinfo     = tap_id_to_base(tap_offset_ptr, tap_id_offset_sip_);
    /* we just take note of the ISUP data here; when we receive the MTP3 part everything will
       be compared with existing calls */

    voip_calls_info_t    *callsinfo   = NULL;
    sip_calls_info_t     *tmp_sipinfo = NULL;
    address               tmp_src, tmp_dst;
    gchar                *frame_label = NULL;
    gchar                *comment     = NULL;
    gchar                *old_comment = NULL;
    gchar                *key         = NULL;

    const sip_info_value_t *pi = (const sip_info_value_t *)SIPinfo;

    tapinfo->sip_frame_num = pinfo->num;

    /* do not consider packets without call_id */
    if (pi->tap_call_id ==NULL) {
        return FALSE;
    }
    key=pi->tap_call_id;
    /* init the hash table */
    if(NULL==tapinfo->callsinfo_hashtable[SIP_HASH]) {
        /* TODO: check how efficient g_str_hash is for sip call ids */
        tapinfo->callsinfo_hashtable[SIP_HASH]=g_hash_table_new_full(g_str_hash,
                g_str_equal,
                NULL, /* key_destroy_func */
                NULL);/* value_destroy_func */
    }
    /* search the call information in the SIP_HASH */
    callsinfo = (voip_calls_info_t *)g_hash_table_lookup(tapinfo->callsinfo_hashtable[SIP_HASH], key);

    /* Create a new flow entry if the message is INVITE in case of FLOW_ONLY_INVITES,
       Create a new flow entry for all messages which have a method in case of FLOW_ALL.
       Flows for REGISTER, OPTIONS, MESSAGE and other SIP methods can be seen. */

    if ((callsinfo==NULL) && (pi->request_method!=NULL)) {

        /* check VoIPcalls_get_flow_show_option() == FLOW_ALL or FLOW_ONLY_INVITES */

        if (tapinfo->fs_option == FLOW_ALL ||
                (tapinfo->fs_option == FLOW_ONLY_INVITES &&
                 strcmp(pi->request_method,"INVITE")==0)) {
            callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_CALL_SETUP;
            callsinfo->from_identity=g_strdup(pi->tap_from_addr);
            callsinfo->to_identity=g_strdup(pi->tap_to_addr);
            copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
            callsinfo->selected=FALSE;
            callsinfo->start_fd=pinfo->fd;
            callsinfo->start_rel_ts=pinfo->rel_ts;
            callsinfo->protocol=VOIP_SIP;
            callsinfo->prot_info=g_malloc(sizeof(sip_calls_info_t));
            callsinfo->free_prot_info = free_sip_info;
            callsinfo->call_id = g_strdup(pi->tap_call_id);
            tmp_sipinfo = (sip_calls_info_t *)callsinfo->prot_info;
            tmp_sipinfo->call_identifier = g_strdup(pi->tap_call_id);
            tmp_sipinfo->sip_state = SIP_INVITE_SENT;
            tmp_sipinfo->invite_cseq = pi->tap_cseq_number;
            callsinfo->npackets = 0;
            callsinfo->call_num = tapinfo->ncalls++;

            /* show method in comment in conversation list dialog, user can discern different conversation types */
            callsinfo->call_comment=g_strdup(pi->request_method);

            g_queue_push_tail(tapinfo->callsinfos, callsinfo);
            /* insert the call information in the SIP_HASH */
            g_hash_table_insert(tapinfo->callsinfo_hashtable[SIP_HASH],
                    tmp_sipinfo->call_identifier, callsinfo);
        }
    }

    if (callsinfo != NULL) {
        tmp_sipinfo = (sip_calls_info_t *)callsinfo->prot_info;

        /* let's analyze the call state */

        copy_address(&(tmp_src), &(pinfo->src));
        copy_address(&(tmp_dst), &(pinfo->dst));

        if (pi->request_method == NULL) {
            frame_label = g_strdup_printf("%u %s", pi->response_code, pi->reason_phrase );
            comment = g_strdup_printf("SIP Status %u %s", pi->response_code, pi->reason_phrase );

            if ((tmp_sipinfo && pi->tap_cseq_number == tmp_sipinfo->invite_cseq)&&(addresses_equal(&tmp_dst,&(callsinfo->initial_speaker)))) {
                if ((pi->response_code > 199) && (pi->response_code<300) && (tmp_sipinfo->sip_state == SIP_INVITE_SENT)) {
                    tmp_sipinfo->sip_state = SIP_200_REC;
                }
                else if ((pi->response_code>299)&&(tmp_sipinfo->sip_state == SIP_INVITE_SENT)) {
                    callsinfo->call_state = VOIP_REJECTED;
                    tapinfo->rejected_calls++;
                }

                /* UPDATE comment in conversation list dialog with response code and reason.
                   Multiple code(+reason) may be appended, so skip over intermediate codes (100 trying, 183 ringing, e.t.c.)
TODO: is useful but not perfect, what is appended is truncated when displayed in dialog window */
                if (pi->response_code >= 200) {
                    old_comment = callsinfo->call_comment;
                    callsinfo->call_comment=g_strdup_printf("%s %u",
                            callsinfo->call_comment,
                            pi->response_code/*, pi->reason_phrase*/);

                    g_free(old_comment);
                }

            }

        }
        else {
            frame_label = g_strdup(pi->request_method);

            if ((strcmp(pi->request_method,"INVITE")==0)&&(addresses_equal(&tmp_src,&(callsinfo->initial_speaker)))) {
                tmp_sipinfo->invite_cseq = pi->tap_cseq_number;
                callsinfo->call_state = VOIP_CALL_SETUP;
                /* TODO: sometimes truncated when displayed in dialog window */
                comment = g_strdup_printf("SIP INVITE From: %s To:%s Call-ID:%s CSeq:%d",
                        callsinfo->from_identity, callsinfo->to_identity,
                        callsinfo->call_id, pi->tap_cseq_number);
            }
            else if ((strcmp(pi->request_method,"ACK")==0)&&(pi->tap_cseq_number == tmp_sipinfo->invite_cseq)
                    &&(addresses_equal(&tmp_src,&(callsinfo->initial_speaker)))&&(tmp_sipinfo->sip_state==SIP_200_REC)
                    &&(callsinfo->call_state == VOIP_CALL_SETUP)) {
                callsinfo->call_state = VOIP_IN_CALL;
                comment = g_strdup_printf("SIP Request INVITE ACK 200 CSeq:%d", pi->tap_cseq_number);
            }
            else if (strcmp(pi->request_method,"BYE")==0) {
                callsinfo->call_state = VOIP_COMPLETED;
                tapinfo->completed_calls++;
                comment = g_strdup_printf("SIP Request BYE CSeq:%d", pi->tap_cseq_number);
            }
            else if ((strcmp(pi->request_method,"CANCEL")==0)&&(pi->tap_cseq_number == tmp_sipinfo->invite_cseq)
                    &&(addresses_equal(&tmp_src,&(callsinfo->initial_speaker)))&&(callsinfo->call_state==VOIP_CALL_SETUP)) {
                callsinfo->call_state = VOIP_CANCELLED;
                tmp_sipinfo->sip_state = SIP_CANCEL_SENT;
                comment = g_strdup_printf("SIP Request CANCEL CSeq:%d", pi->tap_cseq_number);
            } else {
                /* comment = g_strdup_printf("SIP %s", pi->request_method); */
                comment = g_strdup_printf("SIP %s From: %s To:%s CSeq:%d",
                        pi->request_method,
                        callsinfo->from_identity,
                        callsinfo->to_identity, pi->tap_cseq_number);
            }
        }

        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
        /* increment the packets counter of all calls */
        ++(tapinfo->npackets);

        /* add to the graph */
        add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
        g_free(comment);
        g_free(frame_label);
        free_address(&tmp_src);
        free_address(&tmp_dst);

        /* add SDP info if apply */
        if ( (tapinfo->sdp_summary != NULL) && (tapinfo->sdp_frame_num == pinfo->num) ) {
            append_to_frame_graph(tapinfo, pinfo->num, tapinfo->sdp_summary, NULL);
            g_free(tapinfo->sdp_summary);
            tapinfo->sdp_summary = NULL;
        }

    }

    tapinfo->redraw |= REDRAW_SIP;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
sip_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sip_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_SIP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_SIP;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/

void
sip_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("sip", tap_base_to_id(tap_id_base, tap_id_offset_sip_), NULL,
            0,
            NULL,
            sip_calls_packet,
            sip_calls_draw
            );
    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_sip_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_sip_));
}

/****************************************************************************/
/* ***************************TAP for ISUP **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a isup_ packet is seen by the tap listener */
static gboolean
isup_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *isup_info)
{
    voip_calls_tapinfo_t *tapinfo     = tap_id_to_base(tap_offset_ptr, tap_id_offset_isup_);
    voip_calls_info_t    *tmp_listinfo;
    voip_calls_info_t    *callsinfo   = NULL;
    isup_calls_info_t    *tmp_isupinfo;
    gboolean              found       = FALSE;
    gboolean              forward     = FALSE;
    gboolean              right_pair;
    GList                *list;
    gchar                *frame_label = NULL;
    gchar                *comment     = NULL;

    const isup_tap_rec_t *pi = (const isup_tap_rec_t *)isup_info;

    /* check if the lower layer is MTP matching the frame number */
    if (tapinfo->mtp3_frame_num != pinfo->num)
        return FALSE;

    /* check whether we already have a call with these parameters in the list */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list)
    {
        right_pair = TRUE;
        tmp_listinfo=(voip_calls_info_t *)list->data;
        if ((tmp_listinfo->protocol == VOIP_ISUP)&&(tmp_listinfo->call_active_state==VOIP_ACTIVE)) {
            tmp_isupinfo = (isup_calls_info_t *)tmp_listinfo->prot_info;
            if ((tmp_isupinfo->cic == pi->circuit_id)&&(tmp_isupinfo->ni == tapinfo->mtp3_ni)) {
                if ((tmp_isupinfo->opc == tapinfo->mtp3_opc)&&(tmp_isupinfo->dpc == tapinfo->mtp3_dpc)) {
                    forward = TRUE;
                } else if ((tmp_isupinfo->dpc == tapinfo->mtp3_opc)&&(tmp_isupinfo->opc == tapinfo->mtp3_dpc)) {
                    forward = FALSE;
                } else {
                    right_pair = FALSE;
                }

                if (right_pair) {
                    /* if there is an IAM for a call that is not in setup state, that means the previous call in the same
                       cic is no longer active */
                    if (tmp_listinfo->call_state == VOIP_CALL_SETUP) {
                        found = TRUE;
                    } else if (pi->message_type != 1) {
                        found = TRUE;
                    } else {
                        tmp_listinfo->call_active_state=VOIP_INACTIVE;
                    }
                }

                if (found) {
                    callsinfo = (voip_calls_info_t*)(list->data);
                    break;
                }
            }
        }
        list = g_list_next (list);
    }

    /* not in the list? then create a new entry if the message is IAM
       -i.e. if this session is a call*/

    if ((callsinfo==NULL) &&(pi->message_type==1)) {
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_active_state = VOIP_ACTIVE;
        callsinfo->call_state = VOIP_UNKNOWN;
        copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
        callsinfo->selected=FALSE;
        callsinfo->start_fd=pinfo->fd;
        callsinfo->start_rel_ts=pinfo->rel_ts;
        callsinfo->protocol=VOIP_ISUP;
        if (pi->calling_number!=NULL) {
            callsinfo->from_identity=g_strdup(pi->calling_number);
        }
        if (pi->called_number!=NULL) {
            callsinfo->to_identity=g_strdup(pi->called_number);
        }
        callsinfo->prot_info=g_malloc(sizeof(isup_calls_info_t));
        callsinfo->free_prot_info = g_free;
        tmp_isupinfo=(isup_calls_info_t *)callsinfo->prot_info;
        tmp_isupinfo->opc = tapinfo->mtp3_opc;
        tmp_isupinfo->dpc = tapinfo->mtp3_dpc;
        tmp_isupinfo->ni = tapinfo->mtp3_ni;
        tmp_isupinfo->cic = pi->circuit_id;
        callsinfo->npackets = 0;
        callsinfo->call_num = tapinfo->ncalls++;
        g_queue_push_tail(tapinfo->callsinfos, callsinfo);
    }


    if (callsinfo!=NULL) {
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);

        /* Let's analyze the call state */

        frame_label = g_strdup(val_to_str_ext_const(pi->message_type, &isup_message_type_value_acro_ext, "Unknown"));

        if (callsinfo->npackets == 1) { /* this is the first packet, that must be an IAM */

            if ((pi->calling_number!=NULL)&&(pi->called_number !=NULL)) {
                comment = g_strdup_printf("Call from %s to %s",
                        pi->calling_number, pi->called_number);
            }
        } else if (callsinfo->npackets == 2) { /* in the second packet we show the SPs */
            if (forward) {
                comment = g_strdup_printf("%i-%i -> %i-%i. Cic:%i",
                        tapinfo->mtp3_ni, tapinfo->mtp3_opc,
                        tapinfo->mtp3_ni, tapinfo->mtp3_dpc, pi->circuit_id);
            } else {
                comment = g_strdup_printf("%i-%i -> %i-%i. Cic:%i",
                        tapinfo->mtp3_ni, tapinfo->mtp3_dpc,
                        tapinfo->mtp3_ni, tapinfo->mtp3_opc, pi->circuit_id);
            }
        }

        switch(pi->message_type) {
            case 1: /* IAM */
                callsinfo->call_state=VOIP_CALL_SETUP;
                break;
            case 7: /* CONNECT */
            case 9: /* ANSWER */
                callsinfo->call_state=VOIP_IN_CALL;
                break;
            case 12: /* RELEASE */
                if (callsinfo->call_state==VOIP_CALL_SETUP) {
                    if (forward) {
                        callsinfo->call_state=VOIP_CANCELLED;
                    }
                    else {
                        callsinfo->call_state=VOIP_REJECTED;
                        tapinfo->rejected_calls++;
                    }
                }
                else if (callsinfo->call_state == VOIP_IN_CALL) {
                    callsinfo->call_state = VOIP_COMPLETED;
                    tapinfo->completed_calls++;
                }
                comment = g_strdup_printf("Cause %i - %s",
                        pi->cause_value,
                        val_to_str_ext_const(pi->cause_value, &q931_cause_code_vals_ext, "(Unknown)"));
                break;
        }

        /* increment the packets counter of all calls */
        ++(tapinfo->npackets);

        /* add to the graph */
        add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
        g_free(comment);
        g_free(frame_label);
    }

    tapinfo->redraw |= REDRAW_ISUP;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
isup_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_isup_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_ISUP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_ISUP;
    }
}

/****************************************************************************/

void
isup_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("isup", tap_base_to_id(tap_id_base, tap_id_offset_isup_),
            NULL,
            0,
            NULL,
            isup_calls_packet,
            isup_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/

void
remove_tap_listener_isup_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_isup_));
}

/****************************************************************************/
/* ***************************TAP for MTP3 **********************************/
/****************************************************************************/


/****************************************************************************/
/* whenever a mtp3_ packet is seen by the tap listener */
static gboolean
mtp3_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *mtp3_info)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_mtp3_);
    const mtp3_tap_rec_t *pi      = (const mtp3_tap_rec_t *)mtp3_info;

    /* keep the data in memory to use when the ISUP information arrives */

    tapinfo->mtp3_opc = pi->addr_opc.pc;
    tapinfo->mtp3_dpc = pi->addr_dpc.pc;
    tapinfo->mtp3_ni = pi->addr_opc.ni;
    tapinfo->mtp3_frame_num = pinfo->num;

    return FALSE;
}

/****************************************************************************/

void
mtp3_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("mtp3", tap_base_to_id(tap_id_base, tap_id_offset_mtp3_),
            NULL,
            0,
            NULL,
            mtp3_calls_packet,
            NULL
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }

    error_string = register_tap_listener("m3ua", tap_base_to_id(tap_id_base, tap_id_offset_m3ua_),
            NULL,
            0,
            NULL,
            mtp3_calls_packet,
            NULL
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }

}

/****************************************************************************/

void
remove_tap_listener_mtp3_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_mtp3_));
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_m3ua_));
}

/****************************************************************************/
/* ***************************TAP for Q931 **********************************/
/****************************************************************************/
static void h245_add_to_graph(voip_calls_tapinfo_t *tapinfo, guint32 new_frame_num);
static const e_guid_t guid_allzero = {0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
/* defines specific H323 data */

/****************************************************************************/
/* whenever a q931_ packet is seen by the tap listener */
static gboolean
q931_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *q931_info)
{
    GList                     *list,*list2;
    voip_calls_tapinfo_t      *tapinfo   = tap_id_to_base(tap_offset_ptr, tap_id_offset_q931_);
    h323_calls_info_t         *tmp_h323info,*tmp2_h323info;
    actrace_isdn_calls_info_t *tmp_actrace_isdn_info;
    voip_calls_info_t         *tmp_listinfo;
    voip_calls_info_t         *callsinfo = NULL;
    h245_address_t            *h245_add  = NULL;
    gchar                     *comment, *tmp_str;

    const q931_packet_info *pi = (const q931_packet_info *)q931_info;

    /* free previously allocated q931_calling/ed_number */
    g_free(tapinfo->q931_calling_number);
    g_free(tapinfo->q931_called_number);

    if (pi->calling_number!=NULL)
        tapinfo->q931_calling_number = g_strdup(pi->calling_number);
    else
        tapinfo->q931_calling_number = g_strdup("");

    if (pi->called_number!=NULL)
        tapinfo->q931_called_number = g_strdup(pi->called_number);
    else
        tapinfo->q931_called_number = g_strdup("");
    tapinfo->q931_cause_value = pi->cause_value;
    tapinfo->q931_frame_num = pinfo->num;
    tapinfo->q931_crv = pi->crv;


    /* add staff to H323 calls */
    if (tapinfo->h225_frame_num == tapinfo->q931_frame_num) {
        tmp_h323info = NULL;
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if ( (tmp_listinfo->protocol == VOIP_H323) && (tmp_listinfo->call_num == tapinfo->h225_call_num) ) {
                tmp_h323info = (h323_calls_info_t *)tmp_listinfo->prot_info;
                callsinfo = (voip_calls_info_t*)(list->data);

                /* Add the CRV to the h323 call */
                if (tmp_h323info->q931_crv == -1) {
                    tmp_h323info->q931_crv = tapinfo->q931_crv;
                } else if (tmp_h323info->q931_crv != tapinfo->q931_crv) {
                    tmp_h323info->q931_crv2 = tapinfo->q931_crv;
                }
                break;
            }
            list = g_list_next (list);
        }

        if (callsinfo != NULL) {
            comment = NULL;
            if (tapinfo->h225_cstype == H225_SETUP) {
                /* set te calling and called number from the Q931 packet */
                if (tapinfo->q931_calling_number != NULL) {
                    g_free(callsinfo->from_identity);
                    callsinfo->from_identity=g_strdup(tapinfo->q931_calling_number);
                }
                if (tapinfo->q931_called_number != NULL) {
                    g_free(callsinfo->to_identity);
                    callsinfo->to_identity=g_strdup(tapinfo->q931_called_number);
                }

                /* check if there is an LRQ/LCF that match this Setup */
                /* TODO: we are just checking the DialedNumer in LRQ/LCF against the Setup
                   we should also check if the h225 signaling IP and port match the destination
                   Setup ip and port */
                list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
                while (list)
                {
                    tmp_listinfo=(voip_calls_info_t *)list->data;
                    if (tmp_listinfo->protocol == VOIP_H323) {
                        tmp2_h323info = (h323_calls_info_t *)tmp_listinfo->prot_info;

                        /* check if the called number match a LRQ/LCF */
                        if ( (strcmp(callsinfo->to_identity, tmp_listinfo->to_identity)==0)
                                && (memcmp(tmp2_h323info->guid, &guid_allzero, GUID_LEN) == 0) ) {
                            /* change the call graph to the LRQ/LCF to belong to this call */
                            callsinfo->npackets += change_call_num_graph(tapinfo, tmp_listinfo->call_num, callsinfo->call_num);

                            /* remove this LRQ/LCF call entry because we have found the Setup that match them */
                            g_free(tmp_listinfo->from_identity);
                            g_free(tmp_listinfo->to_identity);
                            DUMP_PTR2(tmp2_h323info->guid);
                            g_free(tmp2_h323info->guid);

                            list2 = g_list_first(tmp2_h323info->h245_list);
                            while (list2)
                            {
                                h245_add=(h245_address_t *)list2->data;
                                free_address(&h245_add->h245_address);
                                g_free(list2->data);
                                list2 = g_list_next(list2);
                            }
                            g_list_free(tmp_h323info->h245_list);
                            tmp_h323info->h245_list = NULL;
                            g_free(tmp_listinfo->prot_info);
                            g_queue_unlink(tapinfo->callsinfos, list);
                            break;
                        }
                    }
                    list = g_list_next (list);
                }

                comment = g_strdup_printf("H225 From: %s To:%s  TunnH245:%s FS:%s", callsinfo->from_identity, callsinfo->to_identity, (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
                        (tapinfo->h225_is_faststart==TRUE?"on":"off"));
            } else if (tapinfo->h225_cstype == H225_RELEASE_COMPLET) {
                /* get the Q931 Release cause code */
                if (tapinfo->q931_cause_value != 0xFF) {
                    comment = g_strdup_printf("H225 Q931 Rel Cause (%i):%s", tapinfo->q931_cause_value,
                            val_to_str_ext_const(tapinfo->q931_cause_value, &q931_cause_code_vals_ext, "<unknown>"));
                } else { /* Cause not set */
                    comment = g_strdup("H225 No Q931 Rel Cause");
                }
            }
            /* change the graph comment for this new one */
            if (comment != NULL) {
                change_frame_graph(tapinfo, tapinfo->h225_frame_num, NULL, comment);
                g_free(comment);
            }
        }
        /* we reset the h225_frame_num to 0 because there could be empty h225 in the same frame
           as non empty h225 (e.g connect), so we don't have to be here twice */
        tapinfo->h225_frame_num = 0;

        /* add staff to H245 */
    } else if (tapinfo->h245_labels->frame_num == tapinfo->q931_frame_num) {
        /* there are empty H225 frames that don't have guid (guaid=0) but they have h245 info,
           so the only way to match those frames is with the Q931 CRV number */
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if (tmp_listinfo->protocol == VOIP_H323) {
                tmp_h323info = (h323_calls_info_t *)tmp_listinfo->prot_info;
                if ( ((tmp_h323info->q931_crv == tapinfo->q931_crv) || (tmp_h323info->q931_crv2 == tapinfo->q931_crv)) && (tapinfo->q931_crv!=-1)) {
                    /* if the frame number exists in graph, append to it*/
                    if (!append_to_frame_graph(tapinfo, tapinfo->q931_frame_num, NULL, NULL)) {
                        /* if not exist, add to the graph */
                        add_to_graph(tapinfo, pinfo, edt, NULL, NULL, tmp_listinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
                        ++(tmp_listinfo->npackets);
                        /* increment the packets counter of all calls */
                        ++(tapinfo->npackets);
                    }

                    /* Add the H245 info if exists to the Graph */
                    h245_add_to_graph(tapinfo, pinfo->num);
                    break;
                }
            }
            list = g_list_next (list);
        }
    /* SIP-Q */
    } else if (tapinfo->sip_frame_num == tapinfo->q931_frame_num) {
         /* Do nothing for now */
    /* add stuff to ACTRACE */
    } else {
        address pstn_add;

        comment = NULL;
        callsinfo = NULL;
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if ( tmp_listinfo->protocol == VOIP_AC_ISDN ) {
                tmp_actrace_isdn_info = (actrace_isdn_calls_info_t *)tmp_listinfo->prot_info;
                /* TODO: Also check the IP of the Blade, and if the call is complete (no active) */
                if ( (tmp_actrace_isdn_info->crv == tapinfo->q931_crv) && (tmp_actrace_isdn_info->trunk == tapinfo->actrace_trunk) ) {
                    callsinfo = (voip_calls_info_t*)(list->data);
                    break;
                }
            }
            list = g_list_next (list);
        }

        set_address(&pstn_add, AT_STRINGZ, 5, g_strdup("PSTN"));

        /* if it is a new call, add it to the list */
        if (!callsinfo) {
            callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_CALL_SETUP;
            callsinfo->from_identity=g_strdup(tapinfo->q931_calling_number);
            callsinfo->to_identity=g_strdup(tapinfo->q931_called_number);
            copy_address(&(callsinfo->initial_speaker),tapinfo->actrace_direction?&pstn_add:&(pinfo->src));
            callsinfo->selected=FALSE;
            callsinfo->start_fd=pinfo->fd;
            callsinfo->start_rel_ts=pinfo->rel_ts;
            callsinfo->protocol=VOIP_AC_ISDN;
            callsinfo->prot_info=g_malloc(sizeof(actrace_isdn_calls_info_t));
            callsinfo->free_prot_info = g_free;
            tmp_actrace_isdn_info=(actrace_isdn_calls_info_t *)callsinfo->prot_info;
            tmp_actrace_isdn_info->crv=tapinfo->q931_crv;
            tmp_actrace_isdn_info->trunk=tapinfo->actrace_trunk;
            callsinfo->npackets = 0;
            callsinfo->call_num = tapinfo->ncalls++;
            g_queue_push_tail(tapinfo->callsinfos, callsinfo);
        }

        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
        /* increment the packets counter of all calls */
        ++(tapinfo->npackets);

        switch(pi->message_type) {
            case Q931_SETUP:
                comment = g_strdup_printf("AC_ISDN trunk:%u Calling: %s  Called:%s", tapinfo->actrace_trunk, tapinfo->q931_calling_number, tapinfo->q931_called_number);
                callsinfo->call_state=VOIP_CALL_SETUP;
                break;
            case Q931_CONNECT:
                callsinfo->call_state=VOIP_IN_CALL;
                break;
            case Q931_RELEASE_COMPLETE:
            case Q931_RELEASE:
            case Q931_DISCONNECT:
                if (callsinfo->call_state==VOIP_CALL_SETUP) {
                    if (addresses_equal(&(callsinfo->initial_speaker), tapinfo->actrace_direction?&pstn_add:&(pinfo->src) )) {  /* forward direction */
                        callsinfo->call_state=VOIP_CANCELLED;
                    }
                    else { /* reverse */
                        callsinfo->call_state=VOIP_REJECTED;
                        tapinfo->rejected_calls++;
                    }
                } else if ( (callsinfo->call_state!=VOIP_CANCELLED) && (callsinfo->call_state!=VOIP_REJECTED) ) {
                    callsinfo->call_state=VOIP_COMPLETED;
                    tapinfo->completed_calls++;
                }
                if (tapinfo->q931_cause_value != 0xFF) {
                    comment = g_strdup_printf("AC_ISDN trunk:%u Q931 Rel Cause (%i):%s", tapinfo->actrace_trunk, tapinfo->q931_cause_value,
                            val_to_str_ext_const(tapinfo->q931_cause_value, &q931_cause_code_vals_ext, "<unknown>"));
                } else { /* Cause not set */
                    comment = g_strdup("AC_ISDN No Q931 Rel Cause");
                }
                break;
        }

        if (!comment)
            comment = g_strdup_printf("AC_ISDN  trunk:%u", tapinfo->actrace_trunk );

        tmp_str = val_to_str_wmem(NULL, pi->message_type, q931_message_type_vals, "<unknown (%d)>");
        add_to_graph(tapinfo, pinfo, edt, tmp_str, comment, callsinfo->call_num,
                tapinfo->actrace_direction?&pstn_add:&(pinfo->src),
                tapinfo->actrace_direction?&(pinfo->src):&pstn_add,
                1 );
        wmem_free(NULL, tmp_str);

        g_free(comment);
        free_address(&pstn_add);
    }

    tapinfo->redraw |= REDRAW_Q931;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
q931_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_q931_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_Q931)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_Q931;
    }
}

/****************************************************************************/

void
q931_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("q931", tap_base_to_id(tap_id_base, tap_id_offset_q931_),
            NULL,
            0,
            NULL,
            q931_calls_packet,
            q931_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/

void
remove_tap_listener_q931_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_q931_));
}

/****************************************************************************/
/****************************TAP for H323 ***********************************/
/****************************************************************************/

static void
add_h245_Address(h323_calls_info_t *h323info,  h245_address_t *h245_address)
{
    h323info->h245_list = g_list_prepend(h323info->h245_list, h245_address);
}


static void
free_h225_info(gpointer p) {
    h323_calls_info_t *tmp_h323info = (h323_calls_info_t *)p;

    DUMP_PTR2(tmp_h323info->guid);
    g_free(tmp_h323info->guid);

    if (tmp_h323info->h245_list) {
        GList *list2 = g_list_first(tmp_h323info->h245_list);
        while (list2)
        {
            h245_address_t *h245_add=(h245_address_t *)list2->data;
            free_address(&h245_add->h245_address);
            g_free(list2->data);
            list2 = g_list_next(list2);
        }

        g_list_free(tmp_h323info->h245_list);

    }

    g_free(p);
}
/****************************************************************************/
/* whenever a H225 packet is seen by the tap listener */
static gboolean
h225_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *H225info)
{
    voip_calls_tapinfo_t *tapinfo      = tap_id_to_base(tap_offset_ptr, tap_id_offset_h225_);
    voip_calls_info_t    *tmp_listinfo;
    voip_calls_info_t    *callsinfo    = NULL;
    h323_calls_info_t    *tmp_h323info = NULL;
    gchar                *frame_label;
    gchar                *comment;
    GList                *list;
    h245_address_t       *h245_add     = NULL;

    const h225_packet_info *pi = (const h225_packet_info *)H225info;

    /* if not guid and RAS and not LRQ, LCF or LRJ return because did not belong to a call */
    /* OR, if not guid and is H225 return because doesn't belong to a call */
    if ((memcmp(&pi->guid, &guid_allzero, GUID_LEN) == 0))
        if ( ((pi->msg_type == H225_RAS) && ((pi->msg_tag < 18) || (pi->msg_tag > 20))) || (pi->msg_type != H225_RAS) )
            return FALSE;

    /* if it is RAS LCF or LRJ*/
    if ( (pi->msg_type == H225_RAS) && ((pi->msg_tag == 19) || (pi->msg_tag == 20))) {
        /* if the LCF/LRJ doesn't match to a LRQ, just return */
        if (!pi->request_available) return FALSE;

        /* check whether we already have a call with this request SeqNum */
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            g_assert(tmp_listinfo != NULL);
            if (tmp_listinfo->protocol == VOIP_H323) {
                tmp_h323info = (h323_calls_info_t *)tmp_listinfo->prot_info;
                if (tmp_h323info->requestSeqNum == pi->requestSeqNum) {
                    callsinfo = (voip_calls_info_t*)(list->data);
                    break;
                }
            }
            list = g_list_next (list);
        }
    } else {
        /* check whether we already have a call with this guid in the list */
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if (tmp_listinfo->protocol == VOIP_H323) {
                tmp_h323info = (h323_calls_info_t *)tmp_listinfo->prot_info;
                g_assert(tmp_h323info != NULL);
                if ( (memcmp(tmp_h323info->guid, &guid_allzero, GUID_LEN) != 0) && (memcmp(tmp_h323info->guid, &pi->guid,GUID_LEN)==0) ) {
                    callsinfo = (voip_calls_info_t*)(list->data);
                    break;
                }
            }
            list = g_list_next (list);
        }
    }

    tapinfo->h225_cstype = pi->cs_type;
    tapinfo->h225_is_faststart = pi->is_faststart;

    /* not in the list? then create a new entry */
    if (callsinfo==NULL) {
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_active_state = VOIP_ACTIVE;
        callsinfo->call_state = VOIP_UNKNOWN;
        callsinfo->from_identity=g_strdup("");
        callsinfo->to_identity=g_strdup("");
        copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
        callsinfo->selected=FALSE;
        callsinfo->start_fd=pinfo->fd;
        callsinfo->start_rel_ts=pinfo->rel_ts;
        callsinfo->protocol=VOIP_H323;
        callsinfo->prot_info=g_malloc(sizeof(h323_calls_info_t));
        callsinfo->free_prot_info = free_h225_info;

        tmp_h323info = (h323_calls_info_t *)callsinfo->prot_info;
        g_assert(tmp_h323info != NULL);
        tmp_h323info->guid = (e_guid_t *)g_memdup(&pi->guid, sizeof pi->guid);
        DUMP_PTR1(tmp_h323info->guid);

        clear_address(&tmp_h323info->h225SetupAddr);
        tmp_h323info->h245_list = NULL;
        tmp_h323info->is_faststart_Setup = FALSE;
        tmp_h323info->is_faststart_Proc = FALSE;
        tmp_h323info->is_h245Tunneling = FALSE;
        tmp_h323info->is_h245 = FALSE;
        tmp_h323info->q931_crv = -1;
        tmp_h323info->q931_crv2 = -1;
        tmp_h323info->requestSeqNum = 0;
        callsinfo->call_num = tapinfo->ncalls++;
        callsinfo->npackets = 0;

        g_queue_push_tail(tapinfo->callsinfos, callsinfo);
    }

    tapinfo->h225_frame_num = pinfo->num;
    tapinfo->h225_call_num = callsinfo->call_num;

    /* let's analyze the call state */

    callsinfo->stop_fd = pinfo->fd;
    callsinfo->stop_rel_ts = pinfo->rel_ts;
    ++(callsinfo->npackets);
    /* increment the packets counter of all calls */
    ++(tapinfo->npackets);


    /* XXX: it is supposed to be initialized isn't it? */
    g_assert(tmp_h323info != NULL);

    /* change the status */
    if (pi->msg_type == H225_CS) {

        /* this is still IPv4 only, because the dissector is */
        if (pi->is_h245 == TRUE) {
            h245_add = (h245_address_t *)g_malloc(sizeof (h245_address_t));
            alloc_address_wmem(NULL, &h245_add->h245_address, AT_IPv4, 4, &pi->h245_address);
            h245_add->h245_port = pi->h245_port;
            add_h245_Address(tmp_h323info, h245_add);
        }

        if (pi->cs_type != H225_RELEASE_COMPLET) tmp_h323info->is_h245Tunneling = pi->is_h245Tunneling;

        frame_label = g_strdup(pi->frame_label);

        switch(pi->cs_type) {
            case H225_SETUP:
                tmp_h323info->is_faststart_Setup = pi->is_faststart;

                /* Set the Setup address if it was not set */
                if (tmp_h323info->h225SetupAddr.type == AT_NONE)
                    copy_address(&(tmp_h323info->h225SetupAddr), &(pinfo->src));
                callsinfo->call_state=VOIP_CALL_SETUP;
                comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
                        (pi->is_faststart==TRUE?"on":"off"));
                break;
            case H225_CONNECT:
                callsinfo->call_state=VOIP_IN_CALL;
                if (pi->is_faststart == TRUE) tmp_h323info->is_faststart_Proc = TRUE;
                comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
                        (pi->is_faststart==TRUE?"on":"off"));
                break;
            case H225_RELEASE_COMPLET:
                if (callsinfo->call_state==VOIP_CALL_SETUP) {
                    if (addresses_equal(&(tmp_h323info->h225SetupAddr),&(pinfo->src))) {  /* forward direction */
                        callsinfo->call_state=VOIP_CANCELLED;
                    }
                    else { /* reverse */
                        callsinfo->call_state=VOIP_REJECTED;
                        tapinfo->rejected_calls++;
                    }
                } else {
                    callsinfo->call_state=VOIP_COMPLETED;
                    tapinfo->completed_calls++;
                }
                comment = g_strdup("H225 No Q931 Rel Cause");
                break;
            case H225_PROGRESS:
            case H225_ALERTING:
            case H225_CALL_PROCEDING:
                if (pi->is_faststart == TRUE) tmp_h323info->is_faststart_Proc = TRUE;
                comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
                        (pi->is_faststart==TRUE?"on":"off"));
                break;
            default:
                comment = g_strdup_printf("H225 TunnH245:%s FS:%s", (tmp_h323info->is_h245Tunneling==TRUE?"on":"off"),
                        (pi->is_faststart==TRUE?"on":"off"));

        }
    }
    else if (pi->msg_type == H225_RAS) {
        switch(pi->msg_tag) {
            case 18:  /* LRQ */
                if (!pi->is_duplicate) {
                    g_free(callsinfo->to_identity);
                    callsinfo->to_identity=g_strdup(pi->dialedDigits);
                    tmp_h323info->requestSeqNum = pi->requestSeqNum;
                }
                /* Fall Through */
            case 19: /* LCF */
                if (strlen(pi->dialedDigits))
                    comment = g_strdup_printf("H225 RAS dialedDigits: %s", pi->dialedDigits);
                else
                    comment = g_strdup("H225 RAS");
                break;
            default:
                comment = g_strdup("H225 RAS");
        }
        frame_label = g_strdup(val_to_str_const(pi->msg_tag, h225_RasMessage_vals, "<unknown>"));
    } else {
        frame_label = g_strdup("H225: Unknown");
        comment = NULL;
    }

    /* add to graph analysis */

    /* if the frame number exists in graph, append to it*/
    if (!append_to_frame_graph(tapinfo, pinfo->num, pi->frame_label, comment)) {
        /* if not exist, add to the graph */
        add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
    }

    /* Add the H245 info if exists to the Graph */
    h245_add_to_graph(tapinfo, pinfo->num);

    g_free(frame_label);
    g_free(comment);

    tapinfo->redraw |= REDRAW_H225;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
h225_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_h225_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_H225)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_H225;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
h225_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("h225", tap_base_to_id(tap_id_base, tap_id_offset_h225_), NULL,
            0,
            NULL,
            h225_calls_packet,
            h225_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_h225_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_h225_));
}

/* Add the h245 label info to the graph */
void
h245_add_to_graph(voip_calls_tapinfo_t *tapinfo, guint32 new_frame_num)
{
    gint8 n;

    if (new_frame_num != tapinfo->h245_labels->frame_num) return;

    for (n=0; n<tapinfo->h245_labels->labels_count; n++) {
        append_to_frame_graph(tapinfo, new_frame_num, tapinfo->h245_labels->labels[n].frame_label, tapinfo->h245_labels->labels[n].comment);
        g_free(tapinfo->h245_labels->labels[n].frame_label);
        tapinfo->h245_labels->labels[n].frame_label = NULL;
        g_free(tapinfo->h245_labels->labels[n].comment);
        tapinfo->h245_labels->labels[n].comment = NULL;
    }
    tapinfo->h245_labels->frame_num = 0;
    tapinfo->h245_labels->labels_count = 0;
}

/* free the h245_labels if the frame number is different */
static void
h245_free_labels(voip_calls_tapinfo_t *tapinfo, guint32 new_frame_num)
{
    gint8 n;

    if (new_frame_num == tapinfo->h245_labels->frame_num) return;

    for (n=0; n<tapinfo->h245_labels->labels_count; n++) {
        g_free(tapinfo->h245_labels->labels[n].frame_label);
        tapinfo->h245_labels->labels[n].frame_label = NULL;
        g_free(tapinfo->h245_labels->labels[n].comment);
        tapinfo->h245_labels->labels[n].comment = NULL;
    }
    tapinfo->h245_labels->frame_num = 0;
    tapinfo->h245_labels->labels_count = 0;
}

/* add the frame_label and comment to h245_labels and free the actual one if it is different frame num */
static void
h245_add_label(voip_calls_tapinfo_t *tapinfo, guint32 new_frame_num, const gchar *frame_label, const gchar *comment)
{
    h245_free_labels(tapinfo, new_frame_num);

    tapinfo->h245_labels->frame_num = new_frame_num;
    tapinfo->h245_labels->labels[tapinfo->h245_labels->labels_count].frame_label = g_strdup(frame_label);
    tapinfo->h245_labels->labels[tapinfo->h245_labels->labels_count].comment = g_strdup(comment);

    if (tapinfo->h245_labels->labels_count < (H245_MAX-1))
        tapinfo->h245_labels->labels_count++;

}

/****************************************************************************/
/* whenever a H245dg packet is seen by the tap listener (when H245 tunneling is ON) */
static gboolean
h245dg_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *H245info)
{
    voip_calls_tapinfo_t *tapinfo   = tap_id_to_base(tap_offset_ptr, tap_id_offset_h245dg_);
    voip_calls_info_t    *tmp_listinfo;
    voip_calls_info_t    *callsinfo = NULL;
    h323_calls_info_t    *tmp_h323info;
    GList                *list;
    GList                *list2;
    h245_address_t       *h245_add  = NULL;

    const h245_packet_info *pi = (const h245_packet_info *)H245info;

    /* check if Tunneling is OFF and we have a call with this H245 add */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list)
    {
        tmp_listinfo=(voip_calls_info_t *)list->data;
        if (tmp_listinfo->protocol == VOIP_H323) {
            tmp_h323info = (h323_calls_info_t *)tmp_listinfo->prot_info;

            list2 = g_list_first(tmp_h323info->h245_list);
            while (list2)
            {
                h245_add=(h245_address_t *)list2->data;
                if ( (addresses_equal(&(h245_add->h245_address),&(pinfo->src)) && (h245_add->h245_port == pinfo->srcport))
                        || (addresses_equal(&(h245_add->h245_address),&(pinfo->dst)) && (h245_add->h245_port == pinfo->destport)) ) {
                    callsinfo = (voip_calls_info_t*)(list->data);

                    ++(callsinfo->npackets);
                    /* increment the packets counter of all calls */
                    ++(tapinfo->npackets);

                    break;
                }
                list2 = g_list_next(list2);
            }
            if (callsinfo!=NULL) break;
        }
        list = g_list_next(list);
    }

    /* Tunnel is OFF, and we matched the h245 add so we add it to graph */
    if (callsinfo!=NULL) {
        ++(callsinfo->npackets);
        /* increment the packets counter of all calls */
        ++(tapinfo->npackets);
        /* if the frame number exists in graph, append to it*/
        if (!append_to_frame_graph(tapinfo, pinfo->num, pi->frame_label, pi->comment)) {
            /* if not exist, add to the graph */
            add_to_graph(tapinfo, pinfo, edt, pi->frame_label, pi->comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
        }
    } else {
        /* Tunnel is ON, so we save the label info to use it into h225 or q931 tap. OR may be
           tunnel OFF but we did not matched the h245 add, in this case nobady will set this label
           since the frame_num will not match */

        h245_add_label(tapinfo, pinfo->num, (gchar *) pi->frame_label, (gchar *) pi->comment);
    }

    tapinfo->redraw |= REDRAW_H245DG;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
h245dg_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_h245dg_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_H245DG)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_H245DG;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
h245dg_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    if (!tap_id_base->h245_labels) {
        tap_id_base->h245_labels = g_new0(h245_labels_t, 1);
    }

    error_string = register_tap_listener("h245dg", tap_base_to_id(tap_id_base, tap_id_offset_h245dg_), NULL,
            0,
            NULL,
            h245dg_calls_packet,
            h245dg_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_h245dg_calls(voip_calls_tapinfo_t *tap_id_base)
{
    if (tap_id_base->h245_labels) {
        g_free(tap_id_base->h245_labels);
        tap_id_base->h245_labels = NULL;
    }
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_h245dg_));
}

/****************************************************************************/
/****************************TAP for SDP PROTOCOL ***************************/
/****************************************************************************/
/* whenever a SDP packet is seen by the tap listener */
static gboolean
sdp_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *SDPinfo)
{
    voip_calls_tapinfo_t  *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sdp_);
    const sdp_packet_info *pi      = (const sdp_packet_info *)SDPinfo;

    /* There are protocols like MGCP/SIP where the SDP is called before the tap for the
       MGCP/SIP packet, in those cases we assign the SPD summary to global lastSDPsummary
       to use it later
     */
    g_free(tapinfo->sdp_summary);
    tapinfo->sdp_frame_num = pinfo->num;
    /* Append to graph the SDP summary if the packet exists */
    tapinfo->sdp_summary = g_strdup_printf("SDP (%s)", pi->summary_str);
    append_to_frame_graph(tapinfo, pinfo->num, tapinfo->sdp_summary, NULL);

    tapinfo->redraw |= REDRAW_SDP;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
sdp_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sdp_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_SDP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_SDP;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
sdp_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("sdp", tap_base_to_id(tap_id_base, tap_id_offset_sdp_), NULL,
            0,
            NULL,
            sdp_calls_packet,
            sdp_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_sdp_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_sdp_));
}

/****************************************************************************/
/* ***************************TAP for MGCP **********************************/
/****************************************************************************/

/*
   This function will look for a signal/event in the SignalReq/ObsEvent string
   and return true if it is found
*/
static gboolean
is_mgcp_signal(const gchar *signal_str_p, const gchar *signalStr)
{
    gint    i;
    gchar **resultArray;

    /* if there is no signalStr, just return false */
    if (signalStr == NULL) return FALSE;

    /* if are both "blank" return true */
    if ( (*signal_str_p == '\0') &&  (*signalStr == '\0') ) return TRUE;

    /* look for signal in signalStr */
    resultArray = g_strsplit(signalStr, ",", 10);

    for (i = 0; resultArray[i]; i++) {
        g_strstrip(resultArray[i]);
        if (strcmp(resultArray[i], signal_str_p) == 0) return TRUE;
    }

    g_strfreev(resultArray);

    return FALSE;
}

/*
   This function will get the Caller ID info and replace the current string
   This is how it looks the caller Id: rg, ci(02/16/08/29, "3035550002","Ale Sipura 2")
*/
static void
mgcp_caller_id(gchar *signalStr, gchar **callerId)
{
    gchar **arrayStr;

    /* if there is no signalStr, just return false */
    if (signalStr == NULL) return;

    arrayStr = g_strsplit(signalStr, "\"", 3);

    /* look for the ci signal */
    if (g_strv_length(arrayStr) == 3 && strstr(arrayStr[0], "ci(")) {
        /* free the previous "From" field of the call, and assign the new */
        g_free(*callerId);
        *callerId = g_strdup(arrayStr[1]);
    }
    g_strfreev(arrayStr);
}

/*
   This function will get the Dialed Digits and replace the current string
   This is how it looks the dialed digits 5,5,5,0,0,0,2,#,*
*/
static void
mgcp_dialed_digits(gchar *signalStr, gchar **dialedDigits)
{
    gchar *tmpStr;
    gchar *resultStr;
    gint   i,j;

    /* start with 1 for the null-terminator */
    guint resultStrLen = 1;

    /* if there is no signalStr, just return false */
    if (signalStr == NULL) return;

    tmpStr = g_strdup(signalStr);

    for ( i = 0 ; tmpStr[i] ; i++) {
        switch (tmpStr[i]) {
            case '0' : case '1' : case '2' : case '3' : case '4' :
            case '5' : case '6' : case '7' : case '8' : case '9' :
            case '#' : case '*' :
                resultStrLen++;
                break;
            default:
                tmpStr[i] = '?';
                break;
        }
    }

    if (resultStrLen == 1) {
        g_free(tmpStr);
        return;
    }

    resultStr = (gchar *)g_malloc(resultStrLen);

    for (i = 0, j = 0; tmpStr[i]; i++) {
        if (tmpStr[i] != '?')
            resultStr[j++] = tmpStr[i];
    }
    resultStr[j] = '\0';

    g_free(*dialedDigits);
    g_free(tmpStr);

    *dialedDigits = resultStr;

    return;
}



/****************************************************************************/
/* whenever a MGCP packet is seen by the tap listener */
static gboolean
mgcp_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *MGCPinfo)
{
    voip_calls_tapinfo_t *tapinfo      = tap_id_to_base(tap_offset_ptr, tap_id_offset_mgcp_);
    voip_calls_info_t    *tmp_listinfo;
    voip_calls_info_t    *callsinfo    = NULL;
    mgcp_calls_info_t    *tmp_mgcpinfo = NULL;
    GList                *list;
    GList                *listGraph    = NULL;
    gchar                *frame_label  = NULL;
    gchar                *comment      = NULL;
    seq_analysis_item_t  *gai          = NULL;
    gboolean              newcall      = FALSE;
    gboolean              fromEndpoint = FALSE; /* true for calls originated in Endpoints, false for calls from MGC */
    gdouble               diff_time;

    const mgcp_info_t *pi = (const mgcp_info_t *)MGCPinfo;


    if ((pi->mgcp_type == MGCP_REQUEST) && !pi->is_duplicate ) {
        /* check whether we already have a call with this Endpoint and it is active*/
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if ((tmp_listinfo->protocol == VOIP_MGCP) && (tmp_listinfo->call_active_state == VOIP_ACTIVE)) {
                tmp_mgcpinfo = (mgcp_calls_info_t *)tmp_listinfo->prot_info;
                if (pi->endpointId != NULL) {
                    if (g_ascii_strcasecmp(tmp_mgcpinfo->endpointId,pi->endpointId) == 0) {
                        /*
                           check first if it is an ended call. We can still match packets to this Endpoint 2 seconds
                           after the call has been released
                         */
                        diff_time = nstime_to_sec(&pinfo->rel_ts) - nstime_to_sec(&tmp_listinfo->stop_rel_ts);
                        if ( ((tmp_listinfo->call_state == VOIP_CANCELLED) ||
                                    (tmp_listinfo->call_state == VOIP_COMPLETED)  ||
                                    (tmp_listinfo->call_state == VOIP_REJECTED)) &&
                                (diff_time > 2) )
                        {
                            tmp_listinfo->call_active_state = VOIP_INACTIVE;
                        } else {
                            callsinfo = (voip_calls_info_t*)(list->data);
                            break;
                        }
                    }
                }
            }
            list = g_list_next (list);
        }

        /* there is no call with this Endpoint, lets see if this a new call or not */
        if (callsinfo == NULL) {
            if ( (strcmp(pi->code, "NTFY") == 0) && is_mgcp_signal("hd", pi->observedEvents) ) { /* off hook transition */
                /* this is a new call from the Endpoint */
                fromEndpoint = TRUE;
                newcall = TRUE;
            } else if (strcmp(pi->code, "CRCX") == 0) {
                /* this is a new call from the MGC */
                fromEndpoint = FALSE;
                newcall = TRUE;
            }
            if (!newcall) return FALSE;
        }
    } else if ( ((pi->mgcp_type == MGCP_RESPONSE) && pi->request_available) ||
            ((pi->mgcp_type == MGCP_REQUEST) && pi->is_duplicate) ) {
        /* if it is a response OR if it is a duplicated Request, lets look in the Graph to see
           if there is a request that matches */
        if(tapinfo->graph_analysis){
            listGraph = g_queue_peek_nth_link(tapinfo->graph_analysis->items, 0);
        }
        while (listGraph)
        {
            gai = (seq_analysis_item_t *)listGraph->data;
            if (gai->frame_number == pi->req_num) {
                /* there is a request that match, so look the associated call with this call_num */
                list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
                while (list)
                {
                    tmp_listinfo=(voip_calls_info_t *)list->data;
                    if (tmp_listinfo->protocol == VOIP_MGCP) {
                        if (tmp_listinfo->call_num == gai->conv_num) {
                            tmp_mgcpinfo = (mgcp_calls_info_t *)tmp_listinfo->prot_info;
                            callsinfo = (voip_calls_info_t*)(list->data);
                            break;
                        }
                    }
                    list = g_list_next (list);
                }
                if (callsinfo != NULL) break;
            }
            listGraph = g_list_next(listGraph);
        }
        /* if there is not a matching request, just return */
        if (callsinfo == NULL) return FALSE;
    } else return FALSE;

    /* not in the list? then create a new entry */
    if (callsinfo==NULL) {
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_active_state = VOIP_ACTIVE;
        callsinfo->call_state = VOIP_CALL_SETUP;
        if (fromEndpoint) {
            callsinfo->from_identity=g_strdup(pi->endpointId);
            callsinfo->to_identity=g_strdup("");
        } else {
            callsinfo->from_identity=g_strdup("");
            callsinfo->to_identity=g_strdup(pi->endpointId);
        }
        copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
        callsinfo->selected=FALSE;
        callsinfo->start_fd=pinfo->fd;
        callsinfo->start_rel_ts=pinfo->rel_ts;
        callsinfo->protocol=VOIP_MGCP;
        callsinfo->prot_info=g_malloc(sizeof(mgcp_calls_info_t));
        callsinfo->free_prot_info = g_free;
        tmp_mgcpinfo=(mgcp_calls_info_t *)callsinfo->prot_info;
        tmp_mgcpinfo->endpointId = g_strdup(pi->endpointId);
        tmp_mgcpinfo->fromEndpoint = fromEndpoint;
        callsinfo->npackets = 0;
        callsinfo->call_num = tapinfo->ncalls++;
        g_queue_push_tail(tapinfo->callsinfos, callsinfo);
    }

    g_assert(tmp_mgcpinfo != NULL);

    /* change call state and add to graph */
    switch (pi->mgcp_type)
    {
        case MGCP_REQUEST:
            if ( (strcmp(pi->code, "NTFY") == 0) && (pi->observedEvents != NULL) ) {
                frame_label = g_strdup_printf("%s ObsEvt:%s",pi->code, pi->observedEvents);

                if (tmp_mgcpinfo->fromEndpoint) {
                    /* use the Dialed digits to fill the "To" for the call, but use the first NTFY */
                    if (callsinfo->to_identity[0] == '\0') mgcp_dialed_digits(pi->observedEvents, &(callsinfo->to_identity));

                    /* from MGC and the user picked up, the call is connected */
                } else if (is_mgcp_signal("hd", pi->observedEvents))
                    callsinfo->call_state=VOIP_IN_CALL;

                /* hung up signal */
                if (is_mgcp_signal("hu", pi->observedEvents)) {
                    if ((callsinfo->call_state == VOIP_CALL_SETUP) || (callsinfo->call_state == VOIP_RINGING)) {
                        callsinfo->call_state = VOIP_CANCELLED;
                    } else {
                        callsinfo->call_state = VOIP_COMPLETED;
                    }
                }

            } else if (strcmp(pi->code, "RQNT") == 0) {
                /* for calls from Endpoint: if there is a "no signal" RQNT and the call was RINGING, we assume this is the CONNECT */
                if ( tmp_mgcpinfo->fromEndpoint && is_mgcp_signal("", pi->signalReq) && (callsinfo->call_state == VOIP_RINGING) ) {
                    callsinfo->call_state = VOIP_IN_CALL;
                }

                /* if there is ringback or ring tone, change state to ringing */
                if ( is_mgcp_signal("rg", pi->signalReq) || is_mgcp_signal("rt", pi->signalReq) ) {
                    callsinfo->call_state = VOIP_RINGING;
                }

                /* if there is a Busy or ReorderTone, and the call was Ringing or Setup the call is Rejected */
                if ( (is_mgcp_signal("ro", pi->signalReq) || is_mgcp_signal("bz", pi->signalReq)) && ((callsinfo->call_state == VOIP_CALL_SETUP) || (callsinfo->call_state == VOIP_RINGING)) ) {
                    callsinfo->call_state = VOIP_REJECTED;
                }

                if (pi->signalReq != NULL)
                    frame_label = g_strdup_printf("%s%sSigReq:%s",pi->code, (pi->hasDigitMap == TRUE)?" DigitMap ":"", pi->signalReq);
                else
                    frame_label = g_strdup_printf("%s%s",pi->code, (pi->hasDigitMap == TRUE)?" DigitMap ":"");

                /* use the CallerID info to fill the "From" for the call */
                if (!tmp_mgcpinfo->fromEndpoint) mgcp_caller_id(pi->signalReq, &(callsinfo->from_identity));

            } else if (strcmp(pi->code, "DLCX") == 0) {
                /*
                   if there is a DLCX in a call To an Endpoint and the call was not connected, we use
                   the DLCX as the end of the call
                 */
                if (!tmp_mgcpinfo->fromEndpoint) {
                    if ((callsinfo->call_state == VOIP_CALL_SETUP) || (callsinfo->call_state == VOIP_RINGING)) {
                        callsinfo->call_state = VOIP_CANCELLED;
                    }
                }
            }

            if (frame_label == NULL) frame_label = g_strdup(pi->code);
            break;
        case MGCP_RESPONSE:
            frame_label = g_strdup_printf("%u (%s)",pi->rspcode, pi->code);
            break;
        case MGCP_OTHERS:
            /* XXX what to do? */
            break;
    }

    comment = g_strdup_printf("MGCP %s %s%s", tmp_mgcpinfo->endpointId, (pi->mgcp_type == MGCP_REQUEST)?"Request":"Response", pi->is_duplicate?" Duplicate":"");

    callsinfo->stop_fd = pinfo->fd;
    callsinfo->stop_rel_ts = pinfo->rel_ts;
    ++(callsinfo->npackets);
    /* increment the packets counter of all calls */
    ++(tapinfo->npackets);

    /* add to the graph */
    add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
    g_free(comment);
    g_free(frame_label);

    /* add SDP info if apply */
    if ( (tapinfo->sdp_summary != NULL) && (tapinfo->sdp_frame_num == pinfo->num) ) {
        append_to_frame_graph(tapinfo, pinfo->num, tapinfo->sdp_summary, NULL);
        g_free(tapinfo->sdp_summary);
        tapinfo->sdp_summary = NULL;
    }

    tapinfo->redraw |= REDRAW_MGCP;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
mgcp_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_mgcp_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_MGCP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_MGCP;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
mgcp_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    /*
     * We set TL_REQUIRES_PROTO_TREE to force a non-null "tree"
     * in the MGCP dissector; otherwise, the dissector
     * doesn't fill in the info passed to the tap's packet
     * routine.
     */
    error_string = register_tap_listener("mgcp",
            tap_base_to_id(tap_id_base, tap_id_offset_mgcp_),
            NULL,
            TL_REQUIRES_PROTO_TREE,
            NULL,
            mgcp_calls_packet,
            mgcp_calls_draw
            );
    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_mgcp_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_mgcp_));
}

/****************************************************************************/
/****************************TAP for ACTRACE (AudioCodes trace)**************/
/****************************************************************************/

/* whenever a ACTRACE packet is seen by the tap listener */
static gboolean
actrace_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *ACTRACEinfo)
{
    voip_calls_tapinfo_t     *tapinfo   = tap_id_to_base(tap_offset_ptr, tap_id_offset_actrace_);
    const actrace_info_t     *pi        = (const actrace_info_t *)ACTRACEinfo;
    GList                    *list;
    actrace_cas_calls_info_t *tmp_actrace_cas_info;
    voip_calls_info_t        *tmp_listinfo;
    voip_calls_info_t        *callsinfo = NULL;

    tapinfo->actrace_frame_num = pinfo->num;
    tapinfo->actrace_trunk = pi->trunk;
    tapinfo->actrace_direction = pi->direction;

    if (pi->type == 1) { /* is CAS protocol */
        address pstn_add;
        gchar *comment = NULL;

        callsinfo = NULL;
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
        while (list)
        {
            tmp_listinfo=(voip_calls_info_t *)list->data;
            if ( tmp_listinfo->protocol == VOIP_AC_CAS ) {
                tmp_actrace_cas_info = (actrace_cas_calls_info_t *)tmp_listinfo->prot_info;
                /* TODO: Also check the IP of the Blade, and if the call is complete (no active) */
                if ( (tmp_actrace_cas_info->bchannel == pi->cas_bchannel) && (tmp_actrace_cas_info->trunk == tapinfo->actrace_trunk) ) {
                    callsinfo = (voip_calls_info_t*)(list->data);
                    break;
                }
            }
            list = g_list_next (list);
        }

        set_address(&pstn_add, AT_STRINGZ, 5, "PSTN");

        /* if it is a new call, add it to the list */
        if (!callsinfo) {
            callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_CALL_SETUP;
            callsinfo->from_identity=g_strdup("N/A");
            callsinfo->to_identity=g_strdup("N/A");
            copy_address(&(callsinfo->initial_speaker),tapinfo->actrace_direction?&pstn_add:&(pinfo->src));
            callsinfo->selected=FALSE;
            callsinfo->start_fd=pinfo->fd;
            callsinfo->start_rel_ts=pinfo->rel_ts;
            callsinfo->protocol=VOIP_AC_CAS;
            callsinfo->prot_info=g_malloc(sizeof(actrace_cas_calls_info_t));
            callsinfo->free_prot_info = g_free;

            tmp_actrace_cas_info=(actrace_cas_calls_info_t *)callsinfo->prot_info;
            tmp_actrace_cas_info->bchannel=pi->cas_bchannel;
            tmp_actrace_cas_info->trunk=tapinfo->actrace_trunk;
            callsinfo->npackets = 0;
            callsinfo->call_num = tapinfo->ncalls++;
            g_queue_push_tail(tapinfo->callsinfos, callsinfo);
        }

        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
        /* increment the packets counter of all calls */
        ++(tapinfo->npackets);

        comment = g_strdup_printf("AC_CAS  trunk:%u", tapinfo->actrace_trunk);

        add_to_graph(tapinfo, pinfo, edt, pi->cas_frame_label, comment, callsinfo->call_num,
                tapinfo->actrace_direction?&pstn_add:&(pinfo->src),
                tapinfo->actrace_direction?&(pinfo->src):&pstn_add,
                1 );

        g_free(comment);
    }

    tapinfo->redraw |= REDRAW_ACTRACE;

    return TRUE;  /* refresh output */
}

/****************************************************************************/
static void
actrace_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_actrace_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_ACTRACE)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_ACTRACE;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
actrace_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("actrace", tap_base_to_id(tap_id_base, tap_id_offset_actrace_), NULL,
            0,
            NULL,
            actrace_calls_packet,
            actrace_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_actrace_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_actrace_));
}


/****************************************************************************/
/**************************** TAP for H248/MEGACO **********************************/
/****************************************************************************/

#define gcp_is_req(type) ( type == GCP_CMD_ADD_REQ || type == GCP_CMD_MOVE_REQ || type == GCP_CMD_MOD_REQ || \
                           type == GCP_CMD_SUB_REQ || type == GCP_CMD_AUDITCAP_REQ || type == GCP_CMD_AUDITVAL_REQ || \
                           type == GCP_CMD_NOTIFY_REQ || type == GCP_CMD_SVCCHG_REQ || type == GCP_CMD_TOPOLOGY_REQ || \
                           type == GCP_CMD_CTX_ATTR_AUDIT_REQ )


static gboolean
h248_calls_packet_common(voip_calls_tapinfo_t *tapinfo, packet_info *pinfo, epan_dissect_t *edt, const void *prot_info, guint32 redraw_bit) {
    const gcp_cmd_t      *cmd       = (const gcp_cmd_t *)prot_info;
    GList                *list;
    voip_calls_info_t    *callsinfo = NULL;
    address              *mgw;
    address              *mgc;
    gchar                 mgw_addr[128];

    if (cmd->ctx->id == NULL_CONTEXT || cmd->ctx->id == ALL_CONTEXTS ) {
        return FALSE;
    }

    if ( gcp_is_req(cmd->type) ) {
        mgw = &(pinfo->dst);
        mgc = &(pinfo->src);
    } else {
        mgc = &(pinfo->dst);
        mgw = &(pinfo->src);
    }

    address_to_str_buf(mgw, mgw_addr, 128);

    /* check whether we already have this context in the list */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list)
    {
        voip_calls_info_t* tmp_listinfo = (voip_calls_info_t *)list->data;

        if (tmp_listinfo->protocol == TEL_H248) {
            if (tmp_listinfo->prot_info == cmd->ctx) {
                callsinfo = (voip_calls_info_t*)(list->data);
                break;
            }
        }
        list = g_list_next (list);
    }

    if (callsinfo==NULL) {

        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_state = VOIP_NO_STATE;
        callsinfo->call_active_state = VOIP_ACTIVE;
        callsinfo->from_identity = g_strdup_printf("%s : %.8x", mgw_addr, cmd->ctx->id);
        callsinfo->to_identity = g_strdup("");
        callsinfo->prot_info = cmd->ctx;
        callsinfo->free_prot_info = NULL;

        callsinfo->npackets = 1;

        copy_address(&(callsinfo->initial_speaker), mgc);

        callsinfo->protocol = TEL_H248;
        callsinfo->call_num = tapinfo->ncalls++;
        callsinfo->start_fd = pinfo->fd;
        callsinfo->start_rel_ts = pinfo->rel_ts;
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;

        callsinfo->selected = FALSE;

        g_queue_push_tail(tapinfo->callsinfos, callsinfo);

    } else {
        GString *s = g_string_new("");
        gcp_terms_t *ctx_term;

        g_free(callsinfo->from_identity);
        callsinfo->from_identity = g_strdup_printf("%s : %.8x", mgw_addr, ((gcp_ctx_t*)callsinfo->prot_info)->id);

        g_free(callsinfo->to_identity);

        for (ctx_term = ((gcp_ctx_t*)callsinfo->prot_info)->terms.next;
                ctx_term;
                ctx_term = ctx_term->next ) {
            if ( ctx_term->term && ctx_term->term->str) {
                g_string_append_printf(s," %s",ctx_term->term->str);
            }
        }

        callsinfo->to_identity = g_string_free(s,FALSE);

        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
    }

    add_to_graph(tapinfo, pinfo, edt, cmd->str ? cmd->str : "unknown Msg",
            wmem_strdup_printf(wmem_packet_scope(), "TrxId = %u, CtxId = %.8x",cmd->trx->id,cmd->ctx->id),
            callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

    ++(tapinfo->npackets);

    tapinfo->redraw |= redraw_bit;

    return TRUE;
}

static gboolean
h248_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *prot_info) {
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_h248_);

    return h248_calls_packet_common(tapinfo, pinfo, edt, prot_info, REDRAW_H248);
}

static void
h248_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_h248_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_H248)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_H248;
    }
}

static gboolean
megaco_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *prot_info) {
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_megaco_);

    return h248_calls_packet_common(tapinfo, pinfo, edt, prot_info, REDRAW_MEGACO);
}

static void
megaco_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_megaco_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_MEGACO)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_MEGACO;
    }
}

void
h248_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("megaco", tap_base_to_id(tap_id_base, tap_id_offset_megaco_),
            NULL,
            0,
            NULL,
            megaco_calls_packet,
            megaco_calls_draw);

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }

    error_string = register_tap_listener("h248", tap_base_to_id(tap_id_base, tap_id_offset_h248_),
            NULL,
            0,
            NULL,
            h248_calls_packet,
            h248_calls_draw);

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

void
remove_tap_listener_h248_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_h248_));
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_megaco_));
}

/****************************************************************************/
/**************************** TAP for SCCP and SUA **********************************/
/**************************** ( RANAP and BSSAP ) **********************************/
/****************************************************************************/

static const voip_protocol sccp_proto_map[] = {
    TEL_SCCP,
    TEL_BSSMAP,
    TEL_RANAP
};
#define SP2VP(ap) ((ap) < SCCP_PLOAD_NUM_PLOADS ? sccp_proto_map[(ap)] : TEL_SCCP)
const value_string* sccp_payload_values;

static gboolean
sccp_calls(voip_calls_tapinfo_t *tapinfo, packet_info *pinfo, epan_dissect_t *edt, const void *prot_info, guint32 redraw_bit) {
    const sccp_msg_info_t*  msg       = (const sccp_msg_info_t *)prot_info;
    sccp_assoc_info_t*      assoc     = msg->data.co.assoc;
    GList                  *list;
    voip_calls_info_t      *callsinfo = NULL;
    gchar                  *label     = NULL;
    const gchar            *comment   = NULL;
    /* check whether we already have this assoc in the list */

    for(list = g_queue_peek_nth_link(tapinfo->callsinfos, 0) ; list ; list = g_list_next (list) ) {
        if ( ((voip_calls_info_t*)(list->data))->prot_info == assoc ) {
            callsinfo = (voip_calls_info_t*)(list->data);
            break;
        }
    }

    if (callsinfo==NULL) {
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_state = VOIP_CALL_SETUP;
        callsinfo->call_active_state = VOIP_ACTIVE;
        if ( assoc->calling_party ) {
            callsinfo->from_identity =  g_strdup(assoc->calling_party);
        } else {
            callsinfo->from_identity =  g_strdup("Unknown");
        }

        if ( assoc->called_party ) {
            callsinfo->to_identity =  g_strdup(assoc->called_party);
        } else {
            callsinfo->to_identity =  g_strdup("Unknown");
        }

        callsinfo->prot_info = (void*)assoc;
        callsinfo->free_prot_info = NULL;

        callsinfo->npackets = 1;

        copy_address(&(callsinfo->initial_speaker), &(pinfo->src));

        callsinfo->protocol =   SP2VP(assoc->payload);
        /* Store frame data which holds time and frame number */
        callsinfo->start_fd = pinfo->fd;
        callsinfo->start_rel_ts = pinfo->rel_ts;
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;

        callsinfo->selected = FALSE;
        callsinfo->call_num = tapinfo->ncalls++;

        g_queue_push_tail(tapinfo->callsinfos, callsinfo);
    } else {

        if ( assoc->calling_party ) {
            g_free(callsinfo->from_identity);
            callsinfo->from_identity =  g_strdup(assoc->calling_party);
        }

        if ( assoc->called_party ) {
            g_free(callsinfo->to_identity);
            callsinfo->to_identity =  g_strdup(assoc->called_party);
        }

        callsinfo->protocol =  SP2VP(assoc->payload);
        /* Store frame data which holds stop time and frame number */
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);

        switch (msg->type) {
            case SCCP_MSG_TYPE_CC:
                callsinfo->call_state = VOIP_IN_CALL;
                break;
            case SCCP_MSG_TYPE_RLC:
                callsinfo->call_state = VOIP_COMPLETED;
                callsinfo->call_active_state = VOIP_INACTIVE;
                break;
            default:
                break;
        }
    }

    if (msg->data.co.label) {
        label = wmem_strdup(NULL, msg->data.co.label);
    } else {
        label = val_to_str_wmem(NULL, msg->type, sccp_payload_values, "Unknown(%d)");
    }

    if (msg->data.co.comment) {
        comment = msg->data.co.comment;
    } else {
        comment = NULL;
    }

    add_to_graph(tapinfo, pinfo, edt, label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
    wmem_free(NULL, label);

    ++(tapinfo->npackets);

    tapinfo->redraw |= redraw_bit;

    return TRUE;
}

static gboolean
sccp_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *prot_info) {
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sccp_);

    sccp_payload_values = sccp_message_type_acro_values;
    return sccp_calls(tapinfo, pinfo, edt, prot_info, REDRAW_SCCP);
}

static void
sccp_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sccp_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_SCCP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_SCCP;
    }
}

static gboolean
sua_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *prot_info) {
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sua_);

    sccp_payload_values = sua_co_class_type_acro_values;
    return sccp_calls(tapinfo, pinfo, edt, prot_info, REDRAW_SUA);
}

static void
sua_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_sua_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_SUA)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_SUA;
    }
}

void sccp_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("sccp", tap_base_to_id(tap_id_base, tap_id_offset_sccp_),
            NULL,
            0,
            NULL,
            sccp_calls_packet,
            sccp_calls_draw);

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }

    error_string = register_tap_listener("sua", tap_base_to_id(tap_id_base, tap_id_offset_sua_),
            NULL,
            0,
            NULL,
            sua_calls_packet,
            sua_calls_draw);

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

void
remove_tap_listener_sccp_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_sccp_));
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_sua_));
}


/****************************************************************************/
/****************************TAP for UNISTIM ********************************/
/****************************************************************************/

static gboolean
unistim_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *unistim_info)
{
    voip_calls_tapinfo_t *tapinfo          = tap_id_to_base(tap_offset_ptr, tap_id_offset_unistim_);
    voip_calls_info_t    *tmp_listinfo;
    voip_calls_info_t    *callsinfo        = NULL;
    unistim_info_t       *tmp_unistim_info = NULL;
    GList                *list             = NULL;
    GString              *g_tmp            = NULL;
    const gchar          *frame_label      = NULL;
    gchar                *comment          = NULL;

    /* Fetch specific packet infos */
    const unistim_info_t *pi = (const unistim_info_t *)unistim_info;

    /* Init gstring */
    g_tmp = g_string_new(NULL);

    /* Check to see if this is a dup */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);

    while(list)
    {
        tmp_listinfo = (voip_calls_info_t *)list->data;

        if(tmp_listinfo->protocol == VOIP_UNISTIM) {

            tmp_unistim_info = (unistim_info_t *)tmp_listinfo->prot_info;

            /* Search by termid if possible, otherwise use ni/it ip + port.. */
            if(pi->termid != 0) {
                if(tmp_unistim_info->termid == pi->termid) {
                    /* If the call has ended, then we can reuse it.. */
                    if(tmp_listinfo->call_state == VOIP_COMPLETED || tmp_listinfo->call_state == VOIP_UNKNOWN) {
                        /* Do nothing */
                    } else {
                        callsinfo = (voip_calls_info_t*)(list->data);
                        break;
                    }
                }
            } else {
                /* If no term id use ips / port to find entry */
                if(addresses_equal(&tmp_unistim_info->it_ip, &pinfo->dst) && addresses_equal(&tmp_unistim_info->ni_ip,&pinfo->src) && (tmp_unistim_info->it_port == pinfo->destport)) {
                    if(tmp_listinfo->call_state == VOIP_COMPLETED || tmp_listinfo->call_state == VOIP_UNKNOWN) {
                        /* Do nothing previous call */
                    } else {
                        callsinfo = (voip_calls_info_t*)(list->data);
                        break;
                    }
                }
                else if(addresses_equal(&tmp_unistim_info->it_ip, &pinfo->src) && addresses_equal(&tmp_unistim_info->ni_ip,&pinfo->dst) && (tmp_unistim_info->it_port == pinfo->srcport)) {
                    if(tmp_listinfo->call_state == VOIP_COMPLETED || tmp_listinfo->call_state == VOIP_UNKNOWN) {
                        /* Do nothing, it ain't our call.. */
                    } else {
                        callsinfo = (voip_calls_info_t*)(list->data);
                        break;
                    }
                }
            }
        }

        /* Otherwise, go to the next one.. */
        list = g_list_next(list);
    }

    if(pi->payload_type == 2 || pi->payload_type == 1) {

        if(pi->key_state == 1 || pi->hook_state == 1) {

            /* If the user hits a button,
               Session will be SETUP */

            /* If new add to list */
            if (callsinfo==NULL) {

                callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
                callsinfo->call_active_state = VOIP_ACTIVE;
                callsinfo->call_state = VOIP_CALL_SETUP;
                callsinfo->from_identity=g_strdup_printf("%x",pi->termid);
                callsinfo->to_identity=g_strdup("UNKNOWN");
                copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
                callsinfo->selected=FALSE;

                /* Set this on init of struct so in case the call doesn't complete, we'll have a ref. */
                /* Otherwise if the call is completed we'll have the open/close streams to ref actual call duration */
                /* Store frame data which holds time and frame number */
                callsinfo->start_fd=pinfo->fd;
                callsinfo->start_rel_ts=pinfo->rel_ts;

                callsinfo->protocol=VOIP_UNISTIM;
                callsinfo->prot_info=g_malloc(sizeof(unistim_info_t));

                tmp_unistim_info = (unistim_info_t *)callsinfo->prot_info;

                /* Clear tap struct */
                tmp_unistim_info->rudp_type = 0;
                tmp_unistim_info->payload_type = 0;
                tmp_unistim_info->sequence = pi->sequence;
                tmp_unistim_info->termid = pi->termid;
                tmp_unistim_info->key_val = -1;
                tmp_unistim_info->key_state = -1;
                tmp_unistim_info->hook_state = -1;
                tmp_unistim_info->stream_connect = -1;
                tmp_unistim_info->trans_connect = -1;
                tmp_unistim_info->set_termid = -1;
                tmp_unistim_info->string_data = NULL;
                tmp_unistim_info->key_buffer = NULL;

                copy_address(&(tmp_unistim_info->it_ip),&(pi->it_ip));
                copy_address(&(tmp_unistim_info->ni_ip),&(pi->ni_ip));
                tmp_unistim_info->it_port = pi->it_port;

                callsinfo->free_prot_info = g_free;
                callsinfo->npackets = 0;
                callsinfo->call_num = tapinfo->ncalls++;
                g_queue_push_tail(tapinfo->callsinfos, callsinfo);

            } else {

                /* Set up call wide info struct */
                tmp_unistim_info = (unistim_info_t *)callsinfo->prot_info;
                tmp_unistim_info->sequence = pi->sequence;
            }

            /* Each packet COULD BE OUR LAST!!!! */
            /* Store frame data which holds time and frame number */
            callsinfo->stop_fd = pinfo->fd;
            callsinfo->stop_rel_ts = pinfo->rel_ts;

            /* This is a valid packet so increment counter */
            ++(callsinfo->npackets);

            /* increment the packets counter of all calls */
            ++(tapinfo->npackets);

            /* Key was depressed.. update key buffer.. */
            if(pi->key_val >= 0 && pi->key_val <= 11) {

                if(tmp_unistim_info->key_buffer != NULL) {

                    /* assign to temp variable */
                    g_string_assign(g_tmp,tmp_unistim_info->key_buffer);

                    /* Manipulate the data */
                    if(pi->key_val == 10) {
                        tmp_unistim_info->key_buffer = g_strdup_printf("%s*",g_tmp->str);
                    } else if(pi->key_val == 11) {
                        tmp_unistim_info->key_buffer = g_strdup_printf("%s#",g_tmp->str);
                    } else {
                        tmp_unistim_info->key_buffer = g_strdup_printf("%s%d",g_tmp->str,pi->key_val);
                    }

                } else {

                    /* Create new string */
                    if(pi->key_val == 10) {
                        tmp_unistim_info->key_buffer = g_strdup("*");
                    } else if(pi->key_val == 11) {
                        tmp_unistim_info->key_buffer = g_strdup("#");
                    } else {
                        tmp_unistim_info->key_buffer = g_strdup_printf("%d",pi->key_val);
                    }

                }

                /* Select for non-digit characters */
                if(pi->key_val == 10) {
                    comment = g_strdup_printf("Key Input Sent: * (%d)", pi->sequence);
                } else if(pi->key_val == 11) {
                    comment = g_strdup_printf("Key Input Sent: # (%d)", pi->sequence);
                } else {
                    comment = g_strdup_printf("Key Input Sent: %d (%d)",pi->key_val, pi->sequence);
                }
            } else if(pi->key_val == 12) {
                /* Set label and comment for graph */
                comment = g_strdup_printf("Key Input Sent: UP (%d)", pi->sequence);
            } else if(pi->key_val == 13) {
                /* Set label and comment for graph */
                comment = g_strdup_printf("Key Input Sent: DOWN (%d)", pi->sequence);
            } else if(pi->key_val == 14) {
                /* Set label and comment for graph */
                comment = g_strdup_printf("Key Input Sent: RIGHT (%d)", pi->sequence);
            } else if(pi->key_val == 15) {
                if(pi->key_buffer != NULL) {
                    /* Get data */
                    g_string_assign(g_tmp,pi->key_buffer);

                    /* Manipulate the data */
                    g_string_truncate(g_tmp,g_tmp->len-1);

                    /* Insert new data */
                    tmp_unistim_info->key_buffer = g_strdup(g_tmp->str);
                }

                /* Set label and comment for graph */
                comment = g_strdup_printf("Key Input Sent: LEFT (%d)", pi->sequence);
            } else if(pi->key_val == 20) {
                /* User pressed the soft key 0 probably dial */
                comment = g_strdup_printf("Key Input Sent: S0 (%d)", pi->sequence);
            } else if(pi->key_val == 21) {
                /* User pressed the soft key 1 */
                comment = g_strdup_printf("Key Input Sent: S1 (%d)", pi->sequence);
            } else if(pi->key_val == 22) {
                /* User pressed the soft key 2 */
                /* On cs2k phones, soft key 2 is backspace. */
                if(pi->key_buffer != NULL) {

                    /* Get data */
                    g_string_assign(g_tmp,pi->key_buffer);

                    /* Manipulate the data */
                    g_string_truncate(g_tmp,g_tmp->len-1);

                    /* Insert new data */
                    tmp_unistim_info->key_buffer = g_strdup(g_tmp->str);
                }

                /* add label and comment */
                comment = g_strdup_printf("Key Input Sent: S2 (%d)", pi->sequence);
            } else if(pi->key_val == 28) {
                /* User pressed something */
                comment = g_strdup_printf("Key Input Sent: Release (%d)", pi->sequence);
            } else if(pi->key_val == 23) {
                /* User pressed the soft key 3 */
                /* Cancel on cs2k so clear buffer */
                /* On mcs it's config which will clear the buffer too */
                tmp_unistim_info->key_buffer = g_strdup("\n");

                /* User pressed something, set labels*/
                comment = g_strdup_printf("Key Input Sent: S3 (%d)", pi->sequence);
            } else if(pi->key_val == 27) {
                /* User pressed something */
                comment = g_strdup_printf("Key Input Sent: Hold (%d)", pi->sequence);
            } else if(pi->key_val == 29) {
                /* User pressed something */
                comment = g_strdup_printf("Key Input Sent: Mute (%d)", pi->sequence);
            } else if(pi->key_val == 30) {
                /* User pressed something */
                comment = g_strdup_printf("Key Input Sent: Headset (%d)", pi->sequence);
            } else if(pi->key_val == 31) {
                /* Handsfree button */
                comment = g_strdup_printf("Key Input Sent: Handsfree (%d)", pi->sequence);
            } else if(pi->key_val >= 32 && pi->key_val <= 56) {
                /* Prog. Key X */
                comment = g_strdup_printf("Key Input Sent: Prog%d (%d)", (pi->key_val & 31), pi->sequence);
            }

            if(pi->key_val != -1) {

                frame_label = "KEY INPUT";

                if (comment == NULL)
                    /* Ouch! What do you do!? */
                    /* User pressed something */
                    comment = g_strdup_printf("Key Input Sent: UNKNOWN - %d (%d)", pi->key_val, pi->sequence);

                /* add to the graph */
                add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

                g_free(comment);
            }

            if(pi->hook_state == 1) {

                /* Phone is off hook */
                frame_label = "OFF HOOK";
                comment = g_strdup_printf("Off Hook (%d)", pi->sequence);

                /* add to the graph */
                add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

                g_free(comment);
            } else if(pi->hook_state == 0) {

                /* Phone is on hook */
                frame_label = "ON HOOK";
                comment = g_strdup_printf("On Hook (%d)", pi->sequence);

                /* add to the graph */
                add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

                g_free(comment);
            }
        }

        /* Open stream was sent from server */
        if(pi->stream_connect == 1 && callsinfo != NULL) {

            /* Open stream */
            /* Signifies the start of the call so set start_sec & start_usec */
            /* Frame data holds the time info */
            callsinfo->start_fd=pinfo->fd;
            callsinfo->start_rel_ts=pinfo->rel_ts;
            /* Each packet COULD BE OUR LAST!!!! */
            /* Store frame data which holds time and frame number */
            callsinfo->stop_fd = pinfo->fd;
            callsinfo->stop_rel_ts = pinfo->rel_ts;

            /* Local packets too */
            ++(callsinfo->npackets);

            /* increment the packets counter of all calls */
            ++(tapinfo->npackets);

            /* ?? means we're not quite sure if this is accurate. Since Unistim isn't a true
               Call control protocol, we can only guess at the destination by messing with
               key buffers. */
            if(tmp_unistim_info->key_buffer != NULL) {
                callsinfo->to_identity = g_strdup_printf("?? %s",tmp_unistim_info->key_buffer);
            }

            /* change sequence number for ACK detection */
            tmp_unistim_info->sequence = pi->sequence;

            /* State changes too */
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_IN_CALL;

            /* Add graph data */
            frame_label = "STREAM OPENED";
            comment = g_strdup_printf("Stream Opened (%d)",pi->sequence);

            /* add to the graph */
            add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

        } else if(pi->stream_connect == 1 && callsinfo == NULL) {

            /* Research indicates some nortel products initiate stream first
             * without keypresses. therefore creating this solely on a keypress is
             * ineffective.
             * Sometimes calls start immediately with open stream.
             */
            callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_CALL_SETUP;
            callsinfo->from_identity=g_strdup("UNKNOWN");
            callsinfo->to_identity=g_strdup("UNKNOWN");
            copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
            callsinfo->selected=FALSE;

            /* Set this on init of struct so in case the call doesn't complete, we'll have a ref. */
            /* Otherwise if the call is completed we'll have the open/close streams to ref actual call duration */
            callsinfo->start_fd=pinfo->fd;
            callsinfo->start_rel_ts=pinfo->rel_ts;

            callsinfo->protocol=VOIP_UNISTIM;
            callsinfo->prot_info=g_malloc(sizeof(unistim_info_t));

            tmp_unistim_info = (unistim_info_t *)callsinfo->prot_info;

            /* Clear tap struct */
            tmp_unistim_info->rudp_type = 0;
            tmp_unistim_info->payload_type = 0;
            tmp_unistim_info->sequence = pi->sequence;
            tmp_unistim_info->termid = 0;
            tmp_unistim_info->key_val = -1;
            tmp_unistim_info->key_state = -1;
            tmp_unistim_info->hook_state = -1;
            tmp_unistim_info->stream_connect = -1;
            tmp_unistim_info->trans_connect = -1;
            tmp_unistim_info->set_termid = -1;
            tmp_unistim_info->string_data = NULL;
            tmp_unistim_info->key_buffer = NULL;

            copy_address(&(tmp_unistim_info->it_ip),&(pi->it_ip));
            copy_address(&(tmp_unistim_info->ni_ip),&(pi->ni_ip));
            tmp_unistim_info->it_port = pi->it_port;

            callsinfo->free_prot_info = g_free;
            callsinfo->npackets = 0;
            callsinfo->call_num = tapinfo->ncalls++;
            g_queue_push_tail(tapinfo->callsinfos, callsinfo);

            /* Open stream */
            /* Each packet COULD BE OUR LAST!!!! */
            /* Store frame data which holds time and frame number */
            callsinfo->stop_fd = pinfo->fd;
            callsinfo->stop_rel_ts = pinfo->rel_ts;
            /* Local packets too */
            ++(callsinfo->npackets);

            /* increment the packets counter of all calls */
            ++(tapinfo->npackets);

            /* ?? means we're not quite sure if this is accurate. Since Unistim isn't a true
               Call control protocol, we can only guess at the destination by messing with
               key buffers. */
            if(tmp_unistim_info->key_buffer != NULL) {
                callsinfo->to_identity = g_strdup_printf("?? %s",tmp_unistim_info->key_buffer);
            }

            /* change sequence number for ACK detection */
            tmp_unistim_info->sequence = pi->sequence;

            /* State changes too */
            callsinfo->call_active_state = VOIP_ACTIVE;
            callsinfo->call_state = VOIP_IN_CALL;

            /* Add graph data */
            frame_label = "STREAM OPENED";
            comment = g_strdup_printf("Stream Opened (%d)",pi->sequence);

            /* add to the graph */
            add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

        } else if(pi->stream_connect == 0 && callsinfo != NULL) {
            /* Close Stream */

            /* Set stop seconds + usec */
            /* frame_data holds the time info */
            callsinfo->stop_fd = pinfo->fd;
            callsinfo->stop_rel_ts = pinfo->rel_ts;

            tmp_unistim_info->sequence = pi->sequence;

            if(callsinfo->call_state == VOIP_IN_CALL) {
                callsinfo->call_active_state = VOIP_INACTIVE;
                callsinfo->call_state = VOIP_COMPLETED;
            } else {
                callsinfo->call_state = VOIP_UNKNOWN;
                callsinfo->call_active_state = VOIP_INACTIVE;
            }

            frame_label = "STREAM CLOSED";
            comment = g_strdup_printf("Stream Closed (%d)",pi->sequence);

            /* add to the graph */
            add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

        } else
            comment = NULL;

    } else if(pi->rudp_type == 1 && callsinfo != NULL) {
        /* ACK */
        /* Only show acks for processed seq #s */
        if(tmp_unistim_info->sequence == pi->sequence) {

            frame_label = "ACK";
            comment = g_strdup_printf("ACK for sequence %d",pi->sequence);

            /* add to the graph */
            add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

        }

    } else if(pi->rudp_type == 0 && callsinfo != NULL) {

        /* NAK */
        frame_label = "NAK";
        comment = g_strdup_printf("NAK for sequence %d",pi->sequence);

        /* add to the graph */
        add_to_graph(tapinfo, pinfo, edt, frame_label, comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

    }

    /* free data */
    g_free(comment);

    tapinfo->redraw |= REDRAW_UNISTIM;

    return TRUE;
}

/****************************************************************************/
static void
unistim_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_unistim_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_UNISTIM)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_UNISTIM;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
unistim_calls_init_tap(voip_calls_tapinfo_t *tap_id_base) {

    GString *error_string;

    error_string = register_tap_listener("unistim", tap_base_to_id(tap_id_base, tap_id_offset_unistim_),
            NULL,
            0,
            NULL,
            unistim_calls_packet,
            unistim_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_unistim_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_unistim_));
}

/****************************************************************************/
/* ***************************TAP for SKINNY **********************************/
/****************************************************************************/

/* Telecaster to tap-voip call state mapping */
static const voip_call_state skinny_tap_voip_state[] = {
    VOIP_NO_STATE,
    VOIP_CALL_SETUP,
    VOIP_COMPLETED,
    VOIP_RINGING,
    VOIP_RINGING,
    VOIP_IN_CALL,
    VOIP_REJECTED,
    VOIP_REJECTED,
    VOIP_IN_CALL,
    VOIP_IN_CALL,
    VOIP_COMPLETED,
    VOIP_COMPLETED,
    VOIP_CALL_SETUP,
    VOIP_UNKNOWN,
    VOIP_REJECTED
};

static gboolean
skinny_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *skinny_info)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_skinny_);
    GList* list;
    voip_calls_info_t *callsinfo = NULL;
    address* phone;
    const skinny_info_t *si = (const skinny_info_t *)skinny_info;
    skinny_calls_info_t *tmp_skinnyinfo;
    gchar *comment;

    if (si == NULL || (si->callId == 0 && si->passThruId == 0))
        return FALSE;
    /* check whether we already have this context in the list */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list)
    {
        voip_calls_info_t* tmp_listinfo = (voip_calls_info_t *)list->data;
        if (tmp_listinfo->protocol == VOIP_SKINNY) {
            tmp_skinnyinfo = (skinny_calls_info_t *)tmp_listinfo->prot_info;
            if (tmp_skinnyinfo->callId == si->callId ||
                    tmp_skinnyinfo->callId == si->passThruId) {
                callsinfo = (voip_calls_info_t*)(list->data);
                break;
            }
        }
        list = g_list_next (list);
    }

    if (si->messId >= 256)
        phone = &(pinfo->dst);
    else
        phone = &(pinfo->src);

    if (callsinfo==NULL) {
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_state = VOIP_NO_STATE;
        callsinfo->call_active_state = VOIP_ACTIVE;
        /* callsinfo->from_identity = g_strdup_printf("%s : %.8x", "Skinny", 1); */
        callsinfo->from_identity = g_strdup("");
        callsinfo->to_identity = g_strdup("");
        callsinfo->prot_info = g_malloc(sizeof(skinny_calls_info_t));
        callsinfo->free_prot_info = g_free;
        tmp_skinnyinfo = (skinny_calls_info_t *)callsinfo->prot_info;
        tmp_skinnyinfo->callId = si->callId ? si->callId : si->passThruId;
        callsinfo->npackets = 1;

        copy_address(&(callsinfo->initial_speaker), phone);

        callsinfo->protocol = VOIP_SKINNY;
        callsinfo->call_num = tapinfo->ncalls++;
        callsinfo->start_fd = pinfo->fd;
        callsinfo->start_rel_ts = pinfo->rel_ts;
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;

        callsinfo->selected = FALSE;
        g_queue_push_tail(tapinfo->callsinfos, callsinfo);
    } else {
        if (si->callingParty) {
            g_free(callsinfo->from_identity);
            callsinfo->from_identity = g_strdup(si->callingParty);
        }
        if (si->calledParty) {
            g_free(callsinfo->to_identity);
            callsinfo->to_identity =  g_strdup(si->calledParty);
        }
        if ((si->callState > 0) && (si->callState < (sizeof(skinny_tap_voip_state)/sizeof(skinny_tap_voip_state[0]))))
            callsinfo->call_state = skinny_tap_voip_state[si->callState];

        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
    }

    if (si->callId) {
        if (si->passThruId)
            comment = g_strdup_printf("CallId = %u, PTId = %u", si->callId, si->passThruId);
        else
            comment = g_strdup_printf("CallId = %u, LineId = %u", si->callId, si->lineId);
    } else {
        if (si->passThruId)
            comment = g_strdup_printf("PTId = %u", si->passThruId);
        else
            comment = NULL;
    }

    add_to_graph(tapinfo, pinfo, edt, si->messageName, comment,
            callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);
    g_free(comment);

    tapinfo->redraw |= REDRAW_SKINNY;

    return TRUE;
}

/****************************************************************************/
static void
skinny_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_skinny_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_SKINNY)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_SKINNY;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
skinny_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    /*
     * We set TL_REQUIRES_PROTO_TREE to force a non-null "tree"
     * in the SKINNY dissector; otherwise, the dissector
     * doesn't fill in the info passed to the tap's packet
     * routine.
     */
    error_string = register_tap_listener("skinny",
            tap_base_to_id(tap_id_base, tap_id_offset_skinny_),
            NULL,
            TL_REQUIRES_PROTO_TREE,
            NULL,
            skinny_calls_packet,
            skinny_calls_draw
            );
    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_skinny_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_skinny_));
}

/****************************************************************************/
/* ***************************TAP for IAX2 **********************************/
/****************************************************************************/

static void free_iax2_info(gpointer p) {
    iax2_info_t *ii = (iax2_info_t *)p;

    g_free(ii);
}


/****************************************************************************/
/* whenever a IAX2 packet is seen by the tap listener */
static gboolean
iax2_calls_packet( void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *iax2_info)
{
    voip_calls_tapinfo_t *tapinfo   = tap_id_to_base(tap_offset_ptr, tap_id_offset_iax2_);
    GList*                list;
    voip_calls_info_t    *callsinfo = NULL;
    address              *phone;
    const iax2_info_t    *ii        = (const iax2_info_t *)iax2_info;
    iax2_info_t          *tmp_iax2info;

    if (ii == NULL || ii->ptype != IAX2_FULL_PACKET || (ii->scallno == 0 && ii->dcallno == 0))
        return FALSE;
    /* check whether we already have this context in the list */
    list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list)
    {
        voip_calls_info_t* tmp_listinfo = (voip_calls_info_t *)list->data;
        if (tmp_listinfo->protocol == VOIP_IAX2) {
            tmp_iax2info = (iax2_info_t *)tmp_listinfo->prot_info;
            if (tmp_iax2info->scallno == ii->scallno ||
                    tmp_iax2info->scallno == ii->dcallno) {
                callsinfo = (voip_calls_info_t*)(list->data);
                break;
            }
        }
        list = g_list_next (list);
    }
    phone = &(pinfo->src);


    if (callsinfo==NULL) {
        /* We only care about real calls, i.e., no registration stuff */
        if (ii->ftype != AST_FRAME_IAX ||  ii->csub != IAX_COMMAND_NEW)
            return FALSE;
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_state = VOIP_NO_STATE;
        callsinfo->call_active_state = VOIP_ACTIVE;
        callsinfo->prot_info=g_malloc(sizeof(iax2_info_t));
        callsinfo->free_prot_info = free_iax2_info;
        tmp_iax2info = (iax2_info_t *)callsinfo->prot_info;

        tmp_iax2info->scallno = ii->scallno;
        if (tmp_iax2info->scallno == 0) tmp_iax2info->scallno = ii->dcallno;
        tmp_iax2info->callState = ii->callState;

        callsinfo->npackets = 1;

        copy_address(&(callsinfo->initial_speaker), phone);
        callsinfo->from_identity = g_strdup(ii->callingParty);
        callsinfo->to_identity =  g_strdup(ii->calledParty);

        callsinfo->protocol = VOIP_IAX2;
        callsinfo->call_num = tapinfo->ncalls++;
        callsinfo->start_fd=pinfo->fd;
        callsinfo->start_rel_ts=pinfo->rel_ts;
        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;

        callsinfo->selected = FALSE;
        g_queue_push_tail(tapinfo->callsinfos, callsinfo);

    } else {
        callsinfo->call_state = ii->callState;

        callsinfo->stop_fd = pinfo->fd;
        callsinfo->stop_rel_ts = pinfo->rel_ts;
        ++(callsinfo->npackets);
    }

    add_to_graph(tapinfo, pinfo, edt, ii->messageName, "",
            callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

    tapinfo->redraw |= REDRAW_IAX2;

    return TRUE;

}

/****************************************************************************/
static void
iax2_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_iax2_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_IAX2)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_IAX2;
    }
}

/****************************************************************************/
/* TAP INTERFACE */
/****************************************************************************/
void
iax2_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    /*
     * We set TL_REQUIRES_PROTO_TREE to force a non-null "tree"
     * in the IAX2 dissector; otherwise, the dissector
     * doesn't fill in the info passed to the tap's packet
     * routine.
     * XXX - that appears to be true of the MGCP and SKINNY
     * dissectors, but, unless I've missed something, it doesn't
     * appear to be true of the IAX2 dissector.
     */
    error_string = register_tap_listener("IAX2",
            tap_base_to_id(tap_id_base, tap_id_offset_iax2_),
            NULL,
            TL_REQUIRES_PROTO_TREE,
            NULL,
            iax2_calls_packet,
            iax2_calls_draw
            );
    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s",
                error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_iax2_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_iax2_));
}

/****************************************************************************/
/* ***************************TAP for OTHER PROTOCOL **********************************/
/****************************************************************************/

/* voip_calls_packet and voip_calls_init_tap appear to be dead code. We don't have a "voip" tap. */
static gboolean
voip_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *VoIPinfo)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_voip_);
    voip_calls_info_t    *callsinfo = NULL;
    voip_calls_info_t    *tmp_listinfo;
    GList *list = NULL;
    const voip_packet_info_t *pi = (const voip_packet_info_t *)VoIPinfo;

    /* VOIP_CALLS_DEBUG("num %u", pinfo->num); */
    if (pi->call_id)
        list = g_queue_peek_nth_link(tapinfo->callsinfos, 0);
    while (list) {
        tmp_listinfo = (voip_calls_info_t *)list->data;
        if ( tmp_listinfo->protocol == VOIP_COMMON ) {
            if (!strcmp(pi->call_id, tmp_listinfo->call_id)) {
                callsinfo = (voip_calls_info_t*)(list->data);
                break;
            }
        }
        list = g_list_next(list);
    }

    if (callsinfo == NULL) {
        callsinfo = (voip_calls_info_t *)g_malloc0(sizeof(voip_calls_info_t));
        callsinfo->call_active_state = pi->call_active_state;
        callsinfo->call_state = pi->call_state;
        callsinfo->call_id=g_strdup((pi->call_id)?pi->call_id:"");
        callsinfo->from_identity = g_strdup((pi->from_identity)?pi->from_identity:"");
        callsinfo->to_identity = g_strdup((pi->to_identity)?pi->to_identity:"");
        copy_address(&(callsinfo->initial_speaker),&(pinfo->src));
        callsinfo->selected=FALSE;
        callsinfo->start_fd=pinfo->fd;
        callsinfo->start_rel_ts=pinfo->rel_ts;
        callsinfo->protocol=VOIP_COMMON;
        callsinfo->protocol_name=g_strdup((pi->protocol_name)?pi->protocol_name:"");
        callsinfo->call_comment=g_strdup((pi->call_comment)?pi->call_comment:"");
        callsinfo->prot_info=NULL;
        callsinfo->free_prot_info = NULL;

        callsinfo->call_num = tapinfo->ncalls++;
        callsinfo->npackets = 0;

        g_queue_push_tail(tapinfo->callsinfos, callsinfo);
    }

    callsinfo->call_active_state = pi->call_active_state;
    if ((callsinfo->call_state != VOIP_COMPLETED) && (pi->call_state == VOIP_COMPLETED))
        tapinfo->completed_calls++;
    if (pi->call_state != VOIP_NO_STATE)
        callsinfo->call_state = pi->call_state;
    if (pi->call_comment) {
        g_free(callsinfo->call_comment);
        callsinfo->call_comment=g_strdup(pi->call_comment);
    }
    callsinfo->stop_fd = pinfo->fd;
    callsinfo->stop_rel_ts = pinfo->rel_ts;
    ++(callsinfo->npackets);
    ++(tapinfo->npackets);

    /* add to the graph */
    add_to_graph(tapinfo, pinfo, edt, (pi->frame_label)?pi->frame_label:"VoIP msg", pi->frame_comment, callsinfo->call_num, &(pinfo->src), &(pinfo->dst), 1);

    tapinfo->redraw |= REDRAW_VOIP;

    return TRUE;
}

/****************************************************************************/
static void
voip_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_voip_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_VOIP)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_VOIP;
    }
}

/****************************************************************************/

void
voip_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("voip", tap_base_to_id(tap_id_base, tap_id_offset_voip_),
            NULL,
            0,
            NULL,
            voip_calls_packet,
            voip_calls_draw
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_voip_calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_voip_));
}

/****************************************************************************/
/* ***************************TAP for OTHER PROTOCOL **********************************/
/****************************************************************************/

/****************************************************************************/
/* whenever a prot_ packet is seen by the tap listener */
#if 0
static gboolean
prot_calls_packet(void *tap_offset_ptr, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prot_info _U_)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_prot_);
    if (callsinfo!=NULL) {
        callsinfo->stop_abs = pinfo->abs_ts;
        callsinfo->stop_rel = pinfo->rel_ts;
        callsinfo->last_frame_num=pinfo->num;
        ++(callsinfo->npackets);
        ++(tapinfo->npackets);
    }

    tapinfo->redraw = REDRAW_PROT;

    return TRUE;
}

/****************************************************************************/
static void
prot_calls_draw(void *tap_offset_ptr)
{
    voip_calls_tapinfo_t *tapinfo = tap_id_to_base(tap_offset_ptr, tap_id_offset_prot_);

    if (tapinfo->tap_draw && (tapinfo->redraw & REDRAW_PROT)) {
        tapinfo->tap_draw(tapinfo);
        tapinfo->redraw &= ~REDRAW_PROT;
    }
}

/****************************************************************************/
void
prot_calls_init_tap(voip_calls_tapinfo_t *tap_id_base)
{
    GString *error_string;

    error_string = register_tap_listener("prot_", tap_base_to_id(tap_id_base, tap_id_offset_prot_),
                                         NULL,
                                         0,
                                         NULL,
                                         prot_calls_packet,
                                         prot_calls_draw
        );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}

/****************************************************************************/
void
remove_tap_listener_prot__calls(voip_calls_tapinfo_t *tap_id_base)
{
    remove_tap_listener(tap_base_to_id(tap_id_base, tap_id_offset_prot_));
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
