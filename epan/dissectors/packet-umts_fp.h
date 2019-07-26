/* packet-umts_fp.h
 *
 * Martin Mathieson
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include <glib.h>

/* Channel types */
#define CHANNEL_UNKNOWN           0
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


/* Constants */
#define MAX_FP_CHANS  64
#define MAX_EDCH_DDIS 16
#define MAX_NUM_HSDHSCH_MACDFLOW 8
#define FP_maxNrOfDCHs 128 /* From NBAP-Constants.asn */

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


typedef struct
{
    gint num_ul_chans;
    gint ul_chan_tf_size[MAX_FP_CHANS];
    gint ul_chan_num_tbs[MAX_FP_CHANS];
    gint num_dl_chans;
    gint dl_chan_tf_size[MAX_FP_CHANS];
    gint dl_chan_num_tbs[MAX_FP_CHANS];

} fp_dch_channel_info_t;


/****************************************/
/* Channel Specific Information Structs */

/****************/
/* FACH Structs */

typedef struct fp_crnti_allocation_info_t
{
    guint32 alloc_frame_number; /* Frame where C-RNTI was allocated */
    guint32 urnti; /* The U-RNTI to which the C-RNTI was allocated*/
    guint32 global_retrieval_count; /* How many times this alloc info was retrieved for FACH channels*/
} fp_crnti_allocation_info_t;

/* Used in the 'channel_specific_info' field for FACH channels */
typedef struct fp_fach_channel_info_t
{
    /* Key: (guint32) C-RNTI */
    /* Value: (fp_crnti_allocation_info_t) U-RNTI allocation info */
    wmem_tree_t* crnti_to_urnti_map; /* Mapping between C-RNTIs and U-RNTIs using them in this FACH */
} fp_fach_channel_info_t;


/****************/
/* RACH Structs */

/* Used in the 'channel_specific_info' field for RACH channels */
typedef struct fp_rach_channel_info_t
{
    /* Key: (guint32) C-RNTI */
    /* Value: (fp_crnti_allocation_info_t) U-RNTI allocation info */
    wmem_tree_t* crnti_to_urnti_map; /* Mapping between C-RNTIs and U-RNTIs using them in this RACH */
} fp_rach_channel_info_t;


/****************/
/* PCH Structs  */

/* Information about the Paging Indication Bitmap seen in a specific PCH frame*/
typedef struct paging_indications_info_t
{
    guint32 frame_number;
    guint8* paging_indications_bitmap;
} paging_indications_info_t;

/* Used in the 'channel_specific_info' field for PCH channels */
typedef struct fp_pch_channel_info_t
{
    /*Size of the Paging Indication field in this PCH*/
    gint paging_indications;
    /* Information from the previous frame in this field which contained the paging indication field*/
    paging_indications_info_t* last_paging_indication_info;
} fp_pch_channel_info_t;


/*****************/
/* E-DCH Structs */

/* Used in the 'channel_specific_info' field for E-DCH channels */
typedef struct fp_edch_channel_info_t
{
    gint   no_ddi_entries;
    guint8 edch_ddi[MAX_EDCH_DDIS];
    guint  edch_macd_pdu_size[MAX_EDCH_DDIS];
    guint8 edch_lchId[MAX_EDCH_DDIS];
    guint8 edch_type;  /* 1 means T2 */
} fp_edch_channel_info_t;


/*******************/
/* HS-DSCH Structs */

/* Used in the 'channel_specific_info' field for HS-DSCH channels */
typedef struct fp_hsdsch_channel_info_t
{
    enum fp_hsdsch_entity hsdsch_entity;
    guint8 common_macdflow_id;
    guint8 hsdsch_macdflow_id;
    guint hrnti;          /*Used for tracking a HS-DSCH flow*/
} fp_hsdsch_channel_info_t;


/************************/
/* FP Conversation Data */

typedef struct
{
    enum fp_interface_type iface_type;
    enum division_type     division;
    gint channel;               /* see Channel types definitions above */
    enum fp_rlc_mode rlc_mode;
    guint32 dl_frame_number;    /* the frame where this conversation is started from CRNC */
    guint32 ul_frame_number;    /* the frame where this conversation is started from Node B */
    address crnc_address;
    guint16 crnc_port;

    guint urnti;                /* Identifies a single UE in the UTRAN. Used for tracking it's RLC session across different transport channels */
    gint com_context_id;        /* Identifies a single UE in all NBAP messages */
    guint32 scrambling_code;    /* Identifies a single UE's radio transmissions in the UTRAN */

    void* channel_specific_info; /* Extended channel info based on the channel type */

    /* DCH's in this flow */
    gint num_dch_in_flow;
    gint dch_ids_in_flow_list[FP_maxNrOfDCHs];
    /* DCH type channel data */
    fp_dch_channel_info_t fp_dch_channel_info[FP_maxNrOfDCHs];
    guint8 dch_crc_present;    /* 0=No, 1=Yes, 2=Unknown */

    gboolean reset_frag;  /*Used to indicate that a stream has been reconfigured, hence we need to reset the fragtable*/
    guint32 cfn;
    guint32 cfn_index;

} umts_fp_conversation_info_t;


/********************************/
/* FP Packet Data               */
/* (attached to each FP packet) */
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
    gint num_chans;
    gint chan_tf_size[MAX_FP_CHANS];
    gint chan_num_tbs[MAX_FP_CHANS];

    gint   no_ddi_entries;
    guint8 edch_ddi[MAX_EDCH_DDIS];
    guint  edch_macd_pdu_size[MAX_EDCH_DDIS];

    guint  edch_lchId[MAX_EDCH_DDIS];   /* Logical Channel Id for E-DCH*/

    guint8 edch_type;       /* 1 means T2 */

    gint cur_tb;            /* current transport block (required for dissecting of single TBs */
    gint cur_chan;          /* current channel, required to retrieve the correct channel configuration for UMTS MAC */
    gint com_context_id;    /* Identifies a single UE in the network */
    guint16 srcport, destport;

    /* PCH Related data*/
    gint paging_indications;
    paging_indications_info_t* relevant_paging_indications; /* Info from previous frame */
    /* Info from the current frame. Used to carry information from this frame to the converstaion info */
    paging_indications_info_t* current_paging_indications;

    /* HSDSCH Related data */
    enum   fp_hsdsch_entity hsdsch_entity;
    gint        hsdsch_macflowd_id;
    gboolean hsdhsch_macfdlow_is_mux[MAX_NUM_HSDHSCH_MACDFLOW];
    enum   fp_rlc_mode hsdsch_rlc_mode;
    enum   fp_link_type link_type;
    guint urnti;         /*Used for tracking a "sequence" over diffrent transport channels*/

    gboolean reset_frag; /*Used to indicate that a stream has been reconfigured, hence we need to reset the fragtable*/
} fp_info;

void set_umts_fp_conv_data(conversation_t *conversation, umts_fp_conversation_info_t *umts_fp_conversation_info);

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
