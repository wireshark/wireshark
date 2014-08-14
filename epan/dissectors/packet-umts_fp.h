/* packet-fp.h
 *
 * Martin Mathieson
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <glib.h>

/* Channel types */
#define CHANNEL_RACH_FDD          1
#define CHANNEL_RACH_TDD          2
#define CHANNEL_FACH_FDD          3
#define CHANNEL_FACH_TDD          4
#define CHANNEL_DSCH_FDD          5         /* DSCH Downlink Shared Channel */
#define CHANNEL_DSCH_TDD          6
#define CHANNEL_USCH_TDD_384      8
#define CHANNEL_USCH_TDD_128     24
#define CHANNEL_PCH               9
#define CHANNEL_CPCH             10
#define CHANNEL_BCH              11
#define CHANNEL_DCH              12        /* DCH Dedicated Transport Channel */
#define CHANNEL_HSDSCH           13        /* HS-DSCH - High Speed Downlink Shared Channel */
#define CHANNEL_IUR_CPCHF        14
#define CHANNEL_IUR_FACH         15
#define CHANNEL_IUR_DSCH         16
#define CHANNEL_EDCH             17        /* E-DCH Enhanced DCH */
#define CHANNEL_RACH_TDD_128     18
#define CHANNEL_HSDSCH_COMMON    19        /* HS-DSCH - High Speed Downlink Shared Channel */
#define CHANNEL_HSDSCH_COMMON_T3 20
#define CHANNEL_EDCH_COMMON      21

enum fp_interface_type
{
    IuB_Interface,
    IuR_Interface
};

enum division_type
{
    Division_FDD     = 1,
    Division_TDD_384 = 2,
    Division_TDD_128 = 3,
    Division_TDD_768 = 4
};

enum fp_hsdsch_entity
{
    entity_not_specified = 0,
    hs                   = 1,
    ehs                  = 2
};

enum fp_link_type
{
    FP_Link_Unknown,
    FP_Link_ATM,
    FP_Link_Ethernet
};

enum fp_rlc_mode {
    FP_RLC_MODE_UNKNOWN,
    FP_RLC_TM,
    FP_RLC_UM,
    FP_RLC_AM
};

/* Info attached to each FP packet */
typedef struct fp_info
{
    enum fp_interface_type iface_type;
    enum division_type     division;
    guint8  release;                     /* e.g. 99, 4, 5, 6, 7 */
    guint16 release_year;                /* e.g. 2001 */
    guint8  release_month;               /* e.g. 12 for December */
    gboolean is_uplink;
    gint channel;                       /* see Channel types definitions above */
    guint8  dch_crc_present;            /* 0=No, 1=Yes, 2=Unknown */
    gint paging_indications;
    gint num_chans;
#define MAX_FP_CHANS  64
    gint chan_tf_size[MAX_FP_CHANS];
    gint chan_num_tbs[MAX_FP_CHANS];

#define MAX_EDCH_DDIS 16
    gint   no_ddi_entries;
    guint8 edch_ddi[MAX_EDCH_DDIS];
    guint  edch_macd_pdu_size[MAX_EDCH_DDIS];

    guint  edch_lchId[MAX_EDCH_DDIS];   /* Logical Channel Id for E-DCH*/

    guint8 edch_type;       /* 1 means T2 */

    gint cur_tb;            /* current transport block (required for dissecting of single TBs */
    gint cur_chan;          /* current channel, required to retrieve the correct channel configuration for UMTS MAC */
    gint com_context_id;    /* Identifies a single UE in the network */
    guint16 srcport, destport;

    /* HSDSCH Related data */
    enum   fp_hsdsch_entity hsdsch_entity;
    gint        hsdsch_macflowd_id;
#define MAX_NUM_HSDHSCH_MACDFLOW        8
    gboolean hsdhsch_macfdlow_is_mux[MAX_NUM_HSDHSCH_MACDFLOW];
    enum   fp_link_type link_type;
    guint urnti;         /*Used for tracking a "sequence" over diffrent transport channels*/

    gboolean reset_frag; /*Used to indicate that a stream has been reconfigured, hence we need to reset the fragtable*/
} fp_info;

/* From NBAC-Constants.asn */
#define FP_maxNrOfTFs           32

typedef struct
{
    gint num_ul_chans;
    gint ul_chan_tf_size[MAX_FP_CHANS];
    gint ul_chan_num_tbs[MAX_FP_CHANS];
    gint num_dl_chans;
    gint dl_chan_tf_size[MAX_FP_CHANS];
    gint dl_chan_num_tbs[MAX_FP_CHANS];

} fp_dch_channel_info_t;


typedef struct
{
    enum fp_interface_type iface_type;
    enum division_type     division;
    gint channel;               /* see Channel types definitions above */
    guint32 dl_frame_number;    /* the frame where this conversation is started from CRNC */
    guint32 ul_frame_number;    /* the frame where this conversation is started from Node B */
    address crnc_address;
    guint16 crnc_port;
        gint com_context_id;    /*Identifies a single UE in the network*/

    /* For PCH channel */
    gint paging_indications;

    /* DCH's in this flow */
    gint num_dch_in_flow;
    gint dchs_in_flow_list[FP_maxNrOfTFs];

    guint8  dch_crc_present;    /* 0=No, 1=Yes, 2=Unknown */
    enum fp_rlc_mode rlc_mode;

    /* DCH type channel data */
    fp_dch_channel_info_t fp_dch_channel_info[FP_maxNrOfTFs];

    /* E-DCH related data */
    gint   no_ddi_entries;
    guint8 edch_ddi[MAX_EDCH_DDIS];
    guint  edch_macd_pdu_size[MAX_EDCH_DDIS];
    guint8 edch_lchId[MAX_EDCH_DDIS];
    guint8 edch_type;  /* 1 means T2 */

    /* HSDSCH Related data */
    enum   fp_hsdsch_entity hsdsch_entity;
    guint8 hsdsch_macdflow_id;

    guint8 hsdsch_num_chans_per_flow[MAX_NUM_HSDHSCH_MACDFLOW];

    /*HSDSCH Common related data*/
    guint8 common_macdflow_id;

    guint urnti;          /*Used for tracking a "sequence" over diffrent transport channels*/
    guint hrnti;          /*Used for tracking a HS-DSCH flow*/
    gboolean reset_frag;  /*Used to indicate that a stream has been reconfigured, hence we need to reset the fragtable*/
    guint32 cfn;
    guint32 cfn_index;
} umts_fp_conversation_info_t;

void set_umts_fp_conv_data(conversation_t *conversation, umts_fp_conversation_info_t *umts_fp_conversation_info);

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
