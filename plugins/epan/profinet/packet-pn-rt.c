/* packet-pn-rt.c
 * Routines for pn-rt (PROFINET Real-Time) packet dissection.
 * This is the base for other PROFINET protocols like IO, CBA, DCP, ...
 * (the "content subdissectors" will register themselves using a heuristic)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>
#include <epan/dissectors/packet-dcerpc.h>

#include <wsutil/crc16-plain.h>
#include "packet-pn.h"


void proto_register_pn_rt(void);
void proto_reg_handoff_pn_rt(void);

#define PROFINET_UDP_PORT 0x8892

/* Define the pn-rt proto */
static int proto_pn_rt     = -1;
static gboolean pnio_desegment = TRUE;

static dissector_handle_t pn_rt_handle;

/* Define many header fields for pn-rt */
static int hf_pn_rt_frame_id = -1;
static int hf_pn_rt_cycle_counter = -1;
static int hf_pn_rt_transfer_status = -1;
static int hf_pn_rt_data_status = -1;
static int hf_pn_rt_data_status_ignore = -1;
static int hf_pn_rt_frame_info_type = -1;
static int hf_pn_rt_frame_info_function_meaning_input_conv = -1;
static int hf_pn_rt_frame_info_function_meaning_output_conv = -1;
static int hf_pn_rt_data_status_Reserved_2 = -1;
static int hf_pn_rt_data_status_ok = -1;
static int hf_pn_rt_data_status_operate = -1;
static int hf_pn_rt_data_status_res3 = -1;
static int hf_pn_rt_data_status_valid = -1;
static int hf_pn_rt_data_status_redundancy = -1;
static int hf_pn_rt_data_status_redundancy_output_cr = -1;
static int hf_pn_rt_data_status_redundancy_input_cr_state_is_backup = -1;
static int hf_pn_rt_data_status_redundancy_input_cr_state_is_primary = -1;
static int hf_pn_rt_data_status_primary = -1;

static int hf_pn_rt_sf_crc16 = -1;
static int hf_pn_rt_sf_crc16_status = -1;
static int hf_pn_rt_sf = -1;
static int hf_pn_rt_sf_position = -1;
/* static int hf_pn_rt_sf_position_control = -1; */
static int hf_pn_rt_sf_data_length = -1;
static int hf_pn_rt_sf_cycle_counter = -1;

static int hf_pn_rt_frag = -1;
static int hf_pn_rt_frag_data_length = -1;
static int hf_pn_rt_frag_status = -1;
static int hf_pn_rt_frag_status_more_follows = -1;
static int hf_pn_rt_frag_status_error = -1;
static int hf_pn_rt_frag_status_fragment_number = -1;
static int hf_pn_rt_frag_data = -1;


/*
 * Define the trees for pn-rt
 * We need one tree for pn-rt itself and one for the pn-rt data status subtree
 */
static int ett_pn_rt = -1;
static int ett_pn_rt_data_status = -1;
static int ett_pn_rt_sf = -1;
static int ett_pn_rt_frag = -1;
static int ett_pn_rt_frag_status = -1;

static expert_field ei_pn_rt_sf_crc16 = EI_INIT;

/*
 * Here are the global variables associated with
 * the various user definable characteristics of the dissection
 */
/* Place summary in proto tree */
static gboolean pn_rt_summary_in_tree = TRUE;

/* heuristic to find the right pn-rt payload dissector */
static heur_dissector_list_t heur_subdissector_list;


#if 0
static const value_string pn_rt_position_control[] = {
    { 0x00, "CRC16 and CycleCounter shall not be checked" },
    { 0x80, "CRC16 and CycleCounter valid" },
    { 0, NULL }
};
#endif

static const true_false_string tfs_pn_rt_ds_redundancy_output_cr =
    { "Unknown", "Redundancy has no meaning for OutputCRs, it is set to the fixed value of zero" };

static const true_false_string tfs_pn_rt_ds_redundancy_input_cr_state_is_backup =
    { "None primary AR of a given AR-set is present", "Default - One primary AR of a given AR-set is present" };

static const true_false_string tfs_pn_rt_ds_redundancy_input_cr_state_is_primary =
    { "The ARState from the IO device point of view is Backup", "Default - The ARState from the IO device point of view is Primary" };

static const value_string pn_rt_frame_info_function_meaning_input_conv[] = {
    {0x00, "Backup Acknowledge without actual data" },
    {0x02, "Primary Missing without actual data" },
    {0x04, "Backup Acknowledge with actual data independent from the Arstate" },
    {0x05, "Primary Acknowledge"},
    {0x06, "Primary Missing with actual data independent from the Arstate" },
    {0x07, "Primary Fault" },
    {0, NULL}
};

static const value_string pn_rt_frame_info_function_meaning_output_conv[] = {
    { 0x04, "Backup Request" },
    { 0x05, "Primary Request" },
    { 0, NULL }
};

static const true_false_string tfs_pn_rt_ds_redundancy =
    { "None primary AR of a given AR-set is present",  "Redundancy has no meaning for OutputCRs / One primary AR of a given AR-set is present" };

static const value_string pn_rt_frag_status_error[] = {
    { 0x00, "reserved" },
    { 0x01, "reserved: invalid should be zero" },
    { 0, NULL }
};

static const value_string pn_rt_frag_status_more_follows[] = {
    { 0x00, "Last fragment" },
    { 0x01, "More fragments follow" },
    { 0, NULL }
};

/* Copied and renamed from proto.c because global value_strings don't work for plugins */
static const value_string plugin_proto_checksum_vals[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad"  },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },

	{ 0,        NULL }
};

static void
dissect_DataStatus(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, guint8 u8DataStatus)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint8 u8DataValid;
    guint8 u8Redundancy;
    guint8 u8State;
    conversation_t    *conversation;
    gboolean    inputFlag = FALSE;
    gboolean    outputFlag = FALSE;
    apduStatusSwitch *apdu_status_switch;

    u8State = (u8DataStatus & 0x01);
    u8Redundancy = (u8DataStatus >> 1) & 0x01;
    u8DataValid = (u8DataStatus >> 2) & 0x01;

    /* if PN Connect Request has been read, IOC mac is dl_src and IOD mac is dl_dst */
    conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_UDP, 0, 0, 0);

    if (conversation != NULL) {
        apdu_status_switch = (apduStatusSwitch*)conversation_get_proto_data(conversation, proto_pn_io_apdu_status);
        if (apdu_status_switch != NULL && apdu_status_switch->isRedundancyActive) {
            /* IOC -> IOD: OutputCR */
            if (addresses_equal(&(pinfo->src), conversation_key_addr1(conversation->key_ptr)) && addresses_equal(&(pinfo->dst), conversation_key_addr2(conversation->key_ptr))) {
                outputFlag = TRUE;
                inputFlag = FALSE;
            }
            /* IOD -> IOC: InputCR */
            if (addresses_equal(&(pinfo->dst), conversation_key_addr1(conversation->key_ptr)) && addresses_equal(&(pinfo->src), conversation_key_addr2(conversation->key_ptr))) {
                inputFlag = TRUE;
                outputFlag = FALSE;
            }
        }
    }

    /* input conversation is found */
    if (inputFlag)
    {
        proto_tree_add_string_format_value(tree, hf_pn_rt_frame_info_type, tvb,
            offset, 0, "Input", "Input Frame (IO_Device -> IO_Controller)");
    }
    /* output conversation is found. */
    else if (outputFlag)
    {
        proto_tree_add_string_format_value(tree, hf_pn_rt_frame_info_type, tvb,
            offset, 0, "Output", "Output Frame (IO_Controller -> IO_Device)");
    }

    sub_item = proto_tree_add_uint_format(tree, hf_pn_rt_data_status,
        tvb, offset, 1, u8DataStatus,
        "DataStatus: 0x%02x (Frame: %s and %s, Provider: %s and %s)",
        u8DataStatus,
        (u8DataStatus & 0x04) ? "Valid"   : "Invalid",
        (u8DataStatus & 0x01) ? "Primary" : "Backup",
        (u8DataStatus & 0x20) ? "Ok"      : "Problem",
        (u8DataStatus & 0x10) ? "Run"     : "Stop");
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_rt_data_status);
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_ignore,     tvb, offset, 1, u8DataStatus);
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_Reserved_2, tvb, offset, 1, u8DataStatus);
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_ok,         tvb, offset, 1, u8DataStatus);
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_operate,    tvb, offset, 1, u8DataStatus);
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_res3,       tvb, offset, 1, u8DataStatus);
    /* input conversation is found */
    if (inputFlag)
    {
        proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_valid, tvb, offset, 1, u8DataStatus);
        proto_tree_add_uint(tree, hf_pn_rt_frame_info_function_meaning_input_conv, tvb, offset, 1, u8DataStatus);
        if (u8State == 0 && u8Redundancy == 0 && u8DataValid == 1)
        {
            proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_input_cr_state_is_backup, tvb, offset, 1, u8DataStatus);
        }
        else if (u8State == 0 && u8Redundancy == 0 && u8DataValid == 0)
        {
            proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_input_cr_state_is_backup, tvb, offset, 1, u8DataStatus);
        }
        else if (u8State == 0 && u8Redundancy == 1 && u8DataValid == 1)
        {
            proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_input_cr_state_is_backup, tvb, offset, 1, u8DataStatus);
        }
        else if (u8State == 0 && u8Redundancy == 1 && u8DataValid == 0)
        {
            proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_input_cr_state_is_backup, tvb, offset, 1, u8DataStatus);
        }
        else if (u8State == 1 && u8Redundancy == 0 && u8DataValid == 1)
        {
            proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_input_cr_state_is_primary, tvb, offset, 1, u8DataStatus);
        }
        else if (u8State == 1 && u8Redundancy == 1 && u8DataValid == 1)
        {
            proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_input_cr_state_is_primary, tvb, offset, 1, u8DataStatus);
        }

        proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_primary, tvb, offset, 1, u8DataStatus);
        return;
    }
    // output conversation is found.
    else if (outputFlag)
    {
        proto_tree_add_uint(tree, hf_pn_rt_frame_info_function_meaning_output_conv, tvb, offset, 1, u8DataStatus);

        proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_valid, tvb, offset, 1, u8DataStatus);
        proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy_output_cr, tvb, offset, 1, u8DataStatus);
        proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_primary, tvb, offset, 1, u8DataStatus);

        return;
    }

    // If no conversation is found
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_valid,      tvb, offset, 1, u8DataStatus);
    proto_tree_add_boolean(sub_tree, hf_pn_rt_data_status_redundancy, tvb, offset, 1, u8DataStatus);
    proto_tree_add_uint(sub_tree, hf_pn_rt_data_status_primary,    tvb, offset, 1, u8DataStatus);
}


static gboolean
IsDFP_Frame(tvbuff_t *tvb, packet_info *pinfo, guint16 u16FrameID)
{
    guint16       u16SFCRC16;
    guint8        u8SFPosition;
    guint8        u8SFDataLength   = 255;
    int           offset           = 0;
    guint32       u32SubStart;
    guint16       crc;
    gint          tvb_len          = 0;
    unsigned char virtualFramebuffer[16];

    /* try to build a temporaray buffer for generating this CRC */
    if (!pinfo->src.data || !pinfo->dst.data ||
            pinfo->dst.type != AT_ETHER || pinfo->src.type != AT_ETHER) {
        /* if we don't have src/dst mac addresses then we assume it's not
         * to avoid various crashes */
        return FALSE;
    }
    memcpy(&virtualFramebuffer[0], pinfo->dst.data, 6);
    memcpy(&virtualFramebuffer[6], pinfo->src.data, 6);
    virtualFramebuffer[12] = 0x88;
    virtualFramebuffer[13] = 0x92;
    virtualFramebuffer[15] = (unsigned char) (u16FrameID &0xff);
    virtualFramebuffer[14] = (unsigned char) (u16FrameID>>8);
    crc = crc16_plain_init();
    crc = crc16_plain_update(crc, &virtualFramebuffer[0], 16);
    crc = crc16_plain_finalize(crc);
    /* can check this CRC only by having built a temporary data buffer out of the pinfo data */
    u16SFCRC16 = tvb_get_letohs(tvb, offset);
    if (u16SFCRC16 != 0) /* no crc! */
    {
        if (u16SFCRC16 != crc)
        {
            return(FALSE);
        }
    }
    /* end of first CRC check */

    offset += 2;    /*Skip first crc */
    tvb_len = tvb_captured_length(tvb);
    if (offset + 4 > tvb_len)
        return FALSE;
    if (tvb_get_letohs(tvb, offset) == 0)
        return FALSE;   /* no valid DFP frame */
    while (1) {
        u32SubStart = offset;

        u8SFPosition = tvb_get_guint8(tvb, offset);
        offset += 1;

        u8SFDataLength = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (u8SFDataLength == 0) {
            break;
        }

        offset += 2;

        offset += u8SFDataLength;
       if (offset > tvb_len)
           return /*TRUE; */FALSE;

        u16SFCRC16 = tvb_get_letohs(tvb, offset);
        if (u16SFCRC16 != 0) {
            if (u8SFPosition & 0x80) {
                crc = crc16_plain_tvb_offset_seed(tvb, u32SubStart, offset-u32SubStart, 0);
                if (crc != u16SFCRC16) {
                    return FALSE;
                } else {
                }
            } else {
            }
        }
        offset += 2;
    }
    return TRUE;
}

/* possibly dissect a CSF_SDU related PN-RT packet */
gboolean
dissect_CSF_SDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* the sub tvb will NOT contain the frame_id here! */
    guint16     u16FrameID = GPOINTER_TO_UINT(data);
    guint16     u16SFCRC16;
    guint8      u8SFPosition;
    guint8      u8SFDataLength = 255;
    guint8      u8SFCycleCounter;
    guint8      u8SFDataStatus;
    gint        offset         = 0;
    guint32     u32SubStart;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16     crc;


    /* possible FrameID ranges for DFP */
    if ((u16FrameID < 0x0100) || (u16FrameID > 0x3FFF))
        return (FALSE);
    if (IsDFP_Frame(tvb, pinfo, u16FrameID)) {
        /* can't check this CRC, as the checked data bytes are not available */
        u16SFCRC16 = tvb_get_letohs(tvb, offset);
        if (u16SFCRC16 != 0) {
            /* Checksum verify will always succeed */
            /* XXX - should we combine the two calls to always show "unverified"? */
            proto_tree_add_checksum(tree, tvb, offset, hf_pn_rt_sf_crc16, hf_pn_rt_sf_crc16_status, &ei_pn_rt_sf_crc16, pinfo, u16SFCRC16,
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        }
        else {
            proto_tree_add_checksum(tree, tvb, offset, hf_pn_rt_sf_crc16, hf_pn_rt_sf_crc16_status, &ei_pn_rt_sf_crc16, pinfo, 0,
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
        offset += 2;

        while (1) {
            sub_item = proto_tree_add_item(tree, hf_pn_rt_sf, tvb, offset, 0, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn_rt_sf);
            u32SubStart = offset;

            u8SFPosition = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(sub_tree, hf_pn_rt_sf_position, tvb, offset, 1, u8SFPosition);
            offset += 1;

            u8SFDataLength = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(sub_tree, hf_pn_rt_sf_data_length, tvb, offset, 1, u8SFDataLength);
            offset += 1;

            if (u8SFDataLength == 0) {
                proto_item_append_text(sub_item, ": Pos:%u, Length:%u", u8SFPosition, u8SFDataLength);
                proto_item_set_len(sub_item, offset - u32SubStart);
                break;
            }

            u8SFCycleCounter = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(sub_tree, hf_pn_rt_sf_cycle_counter, tvb, offset, 1, u8SFCycleCounter);
            offset += 1;

            u8SFDataStatus = tvb_get_guint8(tvb, offset);
            dissect_DataStatus(tvb, offset, sub_tree, pinfo, u8SFDataStatus);
            offset += 1;

            offset = dissect_pn_user_data(tvb, offset, pinfo, sub_tree, u8SFDataLength, "DataItem");

            u16SFCRC16 = tvb_get_letohs(tvb, offset);

            if (u16SFCRC16 != 0 /* "old check": u8SFPosition & 0x80 */) {
                crc = crc16_plain_tvb_offset_seed(tvb, u32SubStart, offset-u32SubStart, 0);
                proto_tree_add_checksum(tree, tvb, offset, hf_pn_rt_sf_crc16, hf_pn_rt_sf_crc16_status, &ei_pn_rt_sf_crc16, pinfo, crc,
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
            } else {
                proto_tree_add_checksum(tree, tvb, offset, hf_pn_rt_sf_crc16, hf_pn_rt_sf_crc16_status, &ei_pn_rt_sf_crc16, pinfo, 0,
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
            }
            offset += 2;

            proto_item_append_text(sub_item, ": Pos:%u, Length:%u, Cycle:%u, Status: 0x%02x (%s,%s,%s,%s)",
                u8SFPosition, u8SFDataLength, u8SFCycleCounter, u8SFDataStatus,
                (u8SFDataStatus & 0x04) ? "Valid" : "Invalid",
                (u8SFDataStatus & 0x01) ? "Primary" : "Backup",
                (u8SFDataStatus & 0x20) ? "Ok" : "Problem",
                (u8SFDataStatus & 0x10) ? "Run" : "Stop");

            proto_item_set_len(sub_item, offset - u32SubStart);
        }

        return TRUE;
    }

    else {
        dissect_pn_user_data(tvb, offset, pinfo, tree, tvb_captured_length_remaining(tvb, offset),
                 "PROFINET IO Cyclic Service Data Unit");
    }

    return FALSE;

}

/* for reasemble processing we need some inits.. */
/* Register PNIO defrag table init routine.      */

static reassembly_table pdu_reassembly_table;
static GHashTable *reasembled_frag_table = NULL;

static dissector_table_t ethertype_subdissector_table;

static guint32 start_frag_OR_ID[16];


static void
pnio_defragment_init(void)
{
    guint32 i;
    for (i=0; i < 16; i++)    /* init  the reasemble help array */
        start_frag_OR_ID[i] = 0;
    reasembled_frag_table = g_hash_table_new(NULL, NULL);
}

static void
pnio_defragment_cleanup(void)
{
    g_hash_table_destroy(reasembled_frag_table);
}

/* possibly dissect a FRAG_PDU related PN-RT packet */
static gboolean
dissect_FRAG_PDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* the sub tvb will NOT contain the frame_id here! */
    guint16 u16FrameID = GPOINTER_TO_UINT(data);
    int     offset = 0;


    /* possible FrameID ranges for FRAG_PDU */
    if (u16FrameID >= 0xFF80 && u16FrameID <= 0xFF8F) {
        proto_item *sub_item;
        proto_tree *sub_tree;
        proto_item *status_item;
        proto_tree *status_tree;
        guint8      u8FragDataLength;
        guint8      u8FragStatus;
        gboolean    bMoreFollows;
        guint8      uFragNumber;

        sub_item = proto_tree_add_item(tree, hf_pn_rt_frag, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_rt_frag);

        u8FragDataLength = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(sub_tree, hf_pn_rt_frag_data_length, tvb, offset, 1, u8FragDataLength);
        offset += 1;

        status_item = proto_tree_add_item(sub_tree, hf_pn_rt_frag_status, tvb, offset, 1, ENC_NA);
        status_tree = proto_item_add_subtree(status_item, ett_pn_rt_frag_status);

        u8FragStatus = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(status_tree, hf_pn_rt_frag_status_more_follows, tvb, offset, 1, u8FragStatus);
        proto_tree_add_uint(status_tree, hf_pn_rt_frag_status_error, tvb, offset, 1, u8FragStatus);
        proto_tree_add_uint(status_tree, hf_pn_rt_frag_status_fragment_number, tvb, offset, 1, u8FragStatus);
        offset += 1;
        uFragNumber = u8FragStatus & 0x3F; /* bits 0 to 5 */
        bMoreFollows = (u8FragStatus & 0x80) != 0;
        proto_item_append_text(status_item, ": Number: %u, %s",
            uFragNumber,
            val_to_str( (u8FragStatus & 0x80) >> 7, pn_rt_frag_status_more_follows, "Unknown"));

        /* Is this a string or a bunch of bytes? Should it be FT_BYTES? */
        proto_tree_add_string_format(sub_tree, hf_pn_rt_frag_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), "data",
            "Fragment Length: %d bytes", tvb_captured_length_remaining(tvb, offset));
        col_append_fstr(pinfo->cinfo, COL_INFO, " Fragment Length: %d bytes", tvb_captured_length_remaining(tvb, offset));

        dissect_pn_user_data_bytes(tvb, offset, pinfo, sub_tree, tvb_captured_length_remaining(tvb, offset), FRAG_DATA);
        if ((guint)tvb_captured_length_remaining(tvb, offset) < (guint)(u8FragDataLength *8)) {
            proto_item_append_text(status_item, ": FragDataLength out of Framerange -> discarding!");
            return (TRUE);
        }
        /* defragmentation starts here */
        if (pnio_desegment)
        {
            guint32 u32FragID;
            guint32 u32ReasembleID /*= 0xfedc ??*/;
            fragment_head *pdu_frag;

            u32FragID = (u16FrameID & 0xf);
            if (uFragNumber == 0)
            { /* this is the first "new" fragment, so set up a new key Id */
                guint32 u32FrameKey;
                u32FrameKey = (pinfo->num << 2) | u32FragID;
                /* store it in the array */
                start_frag_OR_ID[u32FragID] = u32FrameKey;
            }
            u32ReasembleID = start_frag_OR_ID[u32FragID];
            /* use frame data instead of "pnio fraglen" which sets 8 octet steps */
            pdu_frag = fragment_add_seq(&pdu_reassembly_table, tvb, offset,
                                        pinfo, u32ReasembleID, NULL, uFragNumber,
                                        (tvb_captured_length_remaining(tvb, offset))/*u8FragDataLength*8*/, bMoreFollows, 0);

            if (pdu_frag && !bMoreFollows) /* PDU is complete! and last fragment */
            {   /* store this fragment as the completed fragment in hash table */
                g_hash_table_insert(reasembled_frag_table, GUINT_TO_POINTER(pinfo->num), pdu_frag);
                start_frag_OR_ID[u32FragID] = 0; /* reset the starting frame counter */
            }
            if (!bMoreFollows) /* last fragment */
            {
                pdu_frag = (fragment_head *)g_hash_table_lookup(reasembled_frag_table, GUINT_TO_POINTER(pinfo->num));
                if (pdu_frag)    /* found a matching fragment; dissect it */
                {
                    guint16   type;
                    tvbuff_t *pdu_tvb;

                    /* create the new tvb for defragmented frame */
                    pdu_tvb = tvb_new_chain(tvb, pdu_frag->tvb_data);
                    /* add the defragmented data to the data source list */
                    add_new_data_source(pinfo, pdu_tvb, "Reassembled Profinet Frame");
                    /* PDU is complete: look for the Ethertype and give it to the appropriate dissection routine */
                    type = tvb_get_ntohs(pdu_tvb, 0);
                    pdu_tvb = tvb_new_subset_remaining(pdu_tvb, 2);
                    if (!dissector_try_uint(ethertype_subdissector_table, type, pdu_tvb, pinfo, tree))
                        call_data_dissector(pdu_tvb, pinfo, tree);
                }
            }
            return TRUE;
        }
        else
            return TRUE;
    }
    return FALSE;
}


/*
 * dissect_pn_rt - The dissector for the Soft-Real-Time protocol
 */
static int
dissect_pn_rt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gint         pdu_len;
    gint         data_len;
    guint16      u16FrameID;
    guint8       u8DataStatus;
    guint8       u8TransferStatus;
    guint16      u16CycleCounter;
    const gchar *pszProtAddInfo;
    const gchar *pszProtShort;
    const gchar *pszProtSummary;
    const gchar *pszProtComment;
    proto_tree  *pn_rt_tree, *ti;
    gchar        szFieldSummary[100];
    tvbuff_t    *next_tvb;
    gboolean     bCyclic;
    heur_dtbl_entry_t *hdtbl_entry;
    conversation_t* conversation;
    guint8 isTimeAware = FALSE;

    /* If the link-layer dissector for the protocol above us knows whether
     * the packet, as handed to it, includes a link-layer FCS, what it
     * hands to us should not include the FCS; if that's not the case,
     * that's a bug in that dissector, and should be fixed there.
     *
     * If the link-layer dissector for the protocol above us doesn't know
     * whether the packet, as handed to us, includes a link-layer FCS,
     * there are limits as to what can be done there; the dissector
     * ultimately needs a "yes, it has an FCS" preference setting, which
     * both the Ethernet and 802.11 dissectors do.  If that's not the case
     * for a dissector, that's a deficiency in that dissector, and should
     * be fixed there.
     *
     * Therefore, we assume we are not handed a packet that includes an
     * FCS.  If we are ever handed such a packet, either the link-layer
     * dissector needs to be fixed or the link-layer dissector's preference
     * needs to be set for your capture (even if that means adding such
     * a preference).  This dissector (and other dissectors for protcols
     * running atop the link layer) should not attempt to process the
     * FCS themselves, as that will just break things. */

    /* Initialize variables */
    pn_rt_tree = NULL;
    ti         = NULL;

    /*
     * Set the columns now, so that they'll be set correctly if we throw
     * an exception.  We can set them (or append things) later again ....
     */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN-RT");
    col_set_str(pinfo->cinfo, COL_INFO, "PROFINET Real-Time");

    pdu_len = tvb_reported_length(tvb);
    if (pdu_len < 6) {
        dissect_pn_malformed(tvb, 0, pinfo, tree, pdu_len);
        return 0;
    }

    /* TimeAwareness Information needed for differentiating RTC3 - RTSteam frames  */
    conversation = find_conversation(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, CONVERSATION_NONE, 0, 0, 0);

    if (conversation != NULL) {
        isTimeAware = GPOINTER_TO_UINT(conversation_get_proto_data(conversation, proto_pn_io_time_aware_status));
    }

    /* build some "raw" data */
    u16FrameID = tvb_get_ntohs(tvb, 0);
    if (u16FrameID <= 0x001F) {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0x0000-0x001F: Reserved ID";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0x0021) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "Synchronization, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0x0020-0x0021: Real-Time: Sync (with follow up)";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0x007F) {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0x0022-0x007F: Reserved ID";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0x0081) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "Synchronization, ";
        pszProtSummary  = "Isochronous-Real-Time";
        pszProtComment  = "0x0080-0x0081: Real-Time: Sync (without follow up)";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0x00FF) {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0x0082-0x00FF: Reserved ID";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0x6FF && !isTimeAware) {
        pszProtShort    = "PN-RTC3";
        pszProtAddInfo  = "RTC3, ";
        pszProtSummary  = "Isochronous-Real-Time";
        pszProtComment  = "0x0100-0x06FF: RED: Real-Time(class=3): non redundant, normal or DFP";
        bCyclic         = TRUE;
    } else if (u16FrameID <= 0x0FFF && !isTimeAware) {
        pszProtShort    = "PN-RTC3";
        pszProtAddInfo  = "RTC3, ";
        pszProtSummary  = "Isochronous-Real-Time";
        pszProtComment  = "0x0700-0x0FFF: RED: Real-Time(class=3): redundant, normal or DFP";
        bCyclic         = TRUE;
    } else if (u16FrameID <= 0x7FFF && !isTimeAware) {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0x1000-0x7FFF: Reserved ID";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0x0FFF && isTimeAware) {
        pszProtShort = "PN-RT";
        pszProtAddInfo = "reserved, ";
        pszProtSummary = "Real-Time";
        pszProtComment = "0x0100-0x0FFF: Reserved ID";
        bCyclic = FALSE;
    } else if (u16FrameID <= 0x2FFF && isTimeAware) {
        pszProtShort = "PN-RTCS";
        pszProtAddInfo = "RT_STREAM, ";
        pszProtSummary = "Real-Time";
        pszProtComment = "0x1000-0x2FFF: RT_CLASS_STREAM";
        bCyclic = TRUE;
    } else if (u16FrameID <= 0x37FF && isTimeAware) {
        pszProtShort = "PN-RT";
        pszProtAddInfo = "reserved, ";
        pszProtSummary = "Real-Time";
        pszProtComment = "0x3000-0x37FF: Reserved ID";
        bCyclic = FALSE;
    } else if (u16FrameID <= 0x3FFF && isTimeAware) {
        pszProtShort = "PN-RTCS";
        pszProtAddInfo = "RT_STREAM, ";
        pszProtSummary = "Real-Time";
        pszProtComment = "0x3800-0x3FFF: RT_CLASS_STREAM";
        bCyclic = TRUE;
    } else if (u16FrameID <= 0xBBFF) {
        pszProtShort    = "PN-RTC1";
        pszProtAddInfo  = "RTC1, ";
        pszProtSummary  = "cyclic Real-Time";
        pszProtComment  = "0x8000-0xBBFF: Real-Time(class=1 unicast): non redundant, normal";
        bCyclic         = TRUE;
    } else if (u16FrameID <= 0xBFFF) {
        pszProtShort    = "PN-RTC1";
        pszProtAddInfo  = "RTC1, ";
        pszProtSummary  = "cyclic Real-Time";
        pszProtComment  = "0xBC00-0xBFFF: Real-Time(class=1 multicast): non redundant, normal";
        bCyclic         = TRUE;
    } else if (u16FrameID <= 0xF7FF) {
        /* check if udp frame on PNIO port */
        if (pinfo->destport == 0x8892)
        { /* UDP frame */
            pszProtShort = "PN-RTCUDP,";
            pszProtAddInfo = "RT_CLASS_UDP, ";
            pszProtComment = "0xC000-0xF7FF: Real-Time(UDP unicast): Cyclic";
        }
        else
        { /* layer 2 frame */
            pszProtShort = "PN-RT";
            pszProtAddInfo = "RTC1(legacy), ";
            pszProtComment = "0xC000-0xF7FF: Real-Time(class=1 unicast): Cyclic";
        }
        pszProtSummary  = "cyclic Real-Time";
        bCyclic         = TRUE;
    } else if (u16FrameID <= 0xFBFF) {
        if (pinfo->destport == 0x8892)
        { /* UDP frame */
            pszProtShort = "PN-RTCUDP,";
            pszProtAddInfo = "RT_CLASS_UDP, ";
            pszProtComment = "0xF800-0xFBFF:: Real-Time(UDP multicast): Cyclic";
        }
        else
        { /* layer 2 frame */
            pszProtShort = "PN-RT";
            pszProtAddInfo = "RTC1(legacy), ";
            pszProtComment = "0xF800-0xFBFF: Real-Time(class=1 multicast): Cyclic";
         }
        pszProtSummary  = "cyclic Real-Time";
        bCyclic         = TRUE;
    } else if (u16FrameID <= 0xFDFF) {
        pszProtShort    = "PN-RTA";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFC00-0xFDFF: Reserved";
        bCyclic         = FALSE;
        if (u16FrameID == 0xfc01) {
            pszProtShort    = "PN-RTA";
            pszProtAddInfo  = "Alarm High, ";
            pszProtSummary  = "acyclic Real-Time";
            pszProtComment  = "Real-Time: Acyclic PN-IO Alarm high priority";
        }

    } else if (u16FrameID <= 0xFEFF) {
        pszProtShort    = "PN-RTA";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFE00-0xFEFF: Real-Time: Reserved";
        bCyclic         = FALSE;
        if (u16FrameID == 0xFE01) {
            pszProtShort    = "PN-RTA";
            pszProtAddInfo  = "Alarm Low, ";
            pszProtSummary  = "acyclic Real-Time";
            pszProtComment  = "Real-Time: Acyclic PN-IO Alarm low priority";
        }
        if (u16FrameID == 0xFE02) {
            pszProtShort = "PN-RSI";
            pszProtAddInfo = "";
            pszProtSummary = "acyclic Real-Time";
            pszProtComment = "Real-Time: Acyclic PN-IO RSI";
        }
        if (u16FrameID == FRAME_ID_DCP_HELLO) {
            pszProtShort    = "PN-RTA";
            pszProtAddInfo  = "";
            pszProtSummary  = "acyclic Real-Time";
            pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) hello";
        }
        if (u16FrameID == FRAME_ID_DCP_GETORSET) {
            pszProtShort    = "PN-RTA";
            pszProtAddInfo  = "";
            pszProtSummary  = "acyclic Real-Time";
            pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) get/set";
        }
        if (u16FrameID == FRAME_ID_DCP_IDENT_REQ) {
            pszProtShort    = "PN-RTA";
            pszProtAddInfo  = "";
            pszProtSummary  = "acyclic Real-Time";
            pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) identify multicast request";
        }
        if (u16FrameID == FRAME_ID_DCP_IDENT_RES) {
            pszProtShort    = "PN-RTA";
            pszProtAddInfo  = "";
            pszProtSummary  = "acyclic Real-Time";
            pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) identify response";
        }
    } else if (u16FrameID <= 0xFF01) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "RTA Sync, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFF00-0xFF01: PTCP Announce";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0xFF1F) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "RTA Sync, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFF02-0xFF1F: Reserved";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0xFF21) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "Follow Up, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFF20-0xFF21: PTCP Follow Up";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0xFF22) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "Follow Up, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFF22-0xFF3F: Reserved";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0xFF43) {
        pszProtShort    = "PN-PTCP";
        pszProtAddInfo  = "Delay, ";
        pszProtSummary  = "acyclic Real-Time";
        pszProtComment  = "0xFF40-0xFF43: Acyclic Real-Time: Delay";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0xFF7F) {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0xFF44-0xFF7F: reserved ID";
        bCyclic         = FALSE;
    } else if (u16FrameID <= 0xFF8F) {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "";
        pszProtSummary  = "Fragmentation";
        pszProtComment  = "0xFF80-0xFF8F: Fragmentation";
        bCyclic         = FALSE;
    } else {
        pszProtShort    = "PN-RT";
        pszProtAddInfo  = "Reserved, ";
        pszProtSummary  = "Real-Time";
        pszProtComment  = "0xFF90-0xFFFF: reserved ID";
        bCyclic         = FALSE;
    }

    /* decode optional cyclic fields at the packet end and build the summary line */
    if (bCyclic) {
        /* cyclic transfer has cycle counter, data status and transfer status fields at the end */
        u16CycleCounter  = tvb_get_ntohs(tvb, pdu_len - 4);
        u8DataStatus     = tvb_get_guint8(tvb, pdu_len - 2);
        u8TransferStatus = tvb_get_guint8(tvb, pdu_len - 1);

        snprintf (szFieldSummary, sizeof(szFieldSummary),
                "%sID:0x%04x, Len:%4u, Cycle:%5u (%s,%s,%s,%s)",
                pszProtAddInfo, u16FrameID, pdu_len - 2 - 4, u16CycleCounter,
                (u8DataStatus & 0x04) ? "Valid"   : "Invalid",
                (u8DataStatus & 0x01) ? "Primary" : "Backup",
                (u8DataStatus & 0x20) ? "Ok"      : "Problem",
                (u8DataStatus & 0x10) ? "Run"     : "Stop");

        /* user data length is packet len - frame id - optional cyclic status fields */
        data_len = pdu_len - 2 - 4;
    } else {
        /* satisfy the gcc compiler, so it won't throw an "uninitialized" warning */
        u16CycleCounter     = 0;
        u8DataStatus        = 0;
        u8TransferStatus    = 0;

        /* acyclic transfer has no fields at the end */
        snprintf (szFieldSummary, sizeof(szFieldSummary),
                  "%sID:0x%04x, Len:%4u",
                pszProtAddInfo, u16FrameID, pdu_len - 2);

        /* user data length is packet len - frame id field */
        data_len = pdu_len - 2;
    }

    /* build protocol tree only, if tree is really used */
    if (tree) {
        /* build pn_rt protocol tree with summary line */
        if (pn_rt_summary_in_tree) {
          ti = proto_tree_add_protocol_format(tree, proto_pn_rt, tvb, 0, pdu_len,
                "PROFINET %s, %s", pszProtSummary, szFieldSummary);
        } else {
            ti = proto_tree_add_item(tree, proto_pn_rt, tvb, 0, pdu_len, ENC_NA);
        }
        pn_rt_tree = proto_item_add_subtree(ti, ett_pn_rt);

        /* add frame ID */
        proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_frame_id, tvb,
          0, 2, u16FrameID, "FrameID: 0x%04x (%s)", u16FrameID, pszProtComment);

        if (bCyclic) {
            /* add cycle counter */
            proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_cycle_counter, tvb,
              pdu_len - 4, 2, u16CycleCounter, "CycleCounter: %u", u16CycleCounter);

            /* add data status subtree */
            dissect_DataStatus(tvb, pdu_len - 2, pn_rt_tree, pinfo, u8DataStatus);

            /* add transfer status */
            if (u8TransferStatus) {
                proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_transfer_status, tvb,
                    pdu_len - 1, 1, u8TransferStatus,
                    "TransferStatus: 0x%02x (ignore this frame)", u8TransferStatus);
            } else {
                proto_tree_add_uint_format(pn_rt_tree, hf_pn_rt_transfer_status, tvb,
                    pdu_len - 1, 1, u8TransferStatus,
                    "TransferStatus: 0x%02x (OK)", u8TransferStatus);
            }
        }
    }

    /* update column info now */
    if (u16FrameID == 0xFE02)
    {
        snprintf(szFieldSummary, sizeof(szFieldSummary), "%s", "");
    }
    col_add_str(pinfo->cinfo, COL_INFO, szFieldSummary);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, pszProtShort);

    /* get frame user data tvb (without header and footer) */
    next_tvb = tvb_new_subset_length(tvb, 2, data_len);

    /* ask heuristics, if some sub-dissector is interested in this packet payload */
    if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, GUINT_TO_POINTER( (guint32) u16FrameID))) {
        /*col_set_str(pinfo->cinfo, COL_INFO, "Unknown");*/

        /* Oh, well, we don't know this; dissect it as data. */
        dissect_pn_undecoded(next_tvb, 0, pinfo, tree, tvb_captured_length(next_tvb));
    }
    return tvb_captured_length(tvb);
}


/* Register all the bits needed by the filtering engine */
void
proto_register_pn_rt(void)
{
    static hf_register_info hf[] = {
        { &hf_pn_rt_frame_id,
          { "FrameID", "pn_rt.frame_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_cycle_counter,
          { "CycleCounter", "pn_rt.cycle_counter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_data_status,
          { "DataStatus", "pn_rt.ds",
            FT_UINT8, BASE_HEX, 0, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_ignore,
          { "Ignore (1:Ignore/0:Evaluate)", "pn_rt.ds_ignore", FT_UINT8, BASE_HEX, 0, 0x80,
            NULL, HFILL }},

        { &hf_pn_rt_frame_info_type,
          { "PN Frame Type", "pn_rt.ds_frame_info_type", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_frame_info_function_meaning_input_conv,
          { "Function/Meaning", "pn_rt.ds_frame_info_meaning",
            FT_UINT8, BASE_HEX, VALS(pn_rt_frame_info_function_meaning_input_conv), 0x7,
            NULL, HFILL } },

        { &hf_pn_rt_frame_info_function_meaning_output_conv,
          { "Function/Meaning", "pn_rt.ds_frame_info_meaning",
            FT_UINT8, BASE_HEX, VALS(pn_rt_frame_info_function_meaning_output_conv), 0x7,
            NULL, HFILL } },

        { &hf_pn_rt_data_status_Reserved_2,
          { "Reserved_2 (should be zero)", "pn_rt.ds_Reserved_2",
            FT_UINT8, BASE_HEX, 0, 0x40,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_ok,
          { "StationProblemIndicator (1:Ok/0:Problem)", "pn_rt.ds_ok",
            FT_UINT8, BASE_HEX, 0, 0x20,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_operate,
          { "ProviderState (1:Run/0:Stop)", "pn_rt.ds_operate",
            FT_UINT8, BASE_HEX, 0, 0x10,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_res3,
          { "Reserved_1 (should be zero)", "pn_rt.ds_res3",
            FT_UINT8, BASE_HEX, 0, 0x08,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_valid,
          { "DataValid (1:Valid/0:Invalid)", "pn_rt.ds_valid",
            FT_UINT8, BASE_HEX, 0, 0x04,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_redundancy,
          { "Redundancy", "pn_rt.ds_redundancy",
            FT_BOOLEAN, 8, TFS(&tfs_pn_rt_ds_redundancy), 0x02,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_redundancy_output_cr,
          { "Redundancy", "pn_rt.ds_redundancy",
            FT_BOOLEAN, 8, TFS(&tfs_pn_rt_ds_redundancy_output_cr), 0x02,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_redundancy_input_cr_state_is_backup,
          { "Redundancy", "pn_rt.ds_redundancy",
            FT_BOOLEAN, 8, TFS(&tfs_pn_rt_ds_redundancy_input_cr_state_is_backup), 0x02,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_redundancy_input_cr_state_is_primary,
          { "Redundancy", "pn_rt.ds_redundancy",
            FT_BOOLEAN, 8, TFS(&tfs_pn_rt_ds_redundancy_input_cr_state_is_primary), 0x02,
            NULL, HFILL }},

        { &hf_pn_rt_data_status_primary,
          { "State (1:Primary/0:Backup)", "pn_rt.ds_primary",
            FT_UINT8, BASE_HEX, 0, 0x01,
            NULL, HFILL }},

        { &hf_pn_rt_transfer_status,
          { "TransferStatus", "pn_rt.transfer_status",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_sf,
          { "SubFrame", "pn_rt.sf",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_sf_crc16,
          { "SFCRC16", "pn_rt.sf.crc16",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_sf_crc16_status,
          { "SFCRC16 status", "pn_rt.sf.crc16.status",
            FT_UINT8, BASE_NONE, VALS(plugin_proto_checksum_vals), 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_sf_position,
          { "Position", "pn_rt.sf.position",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }},

#if 0
        { &hf_pn_rt_sf_position_control,
          { "Control", "pn_rt.sf.position_control",
            FT_UINT8, BASE_DEC, VALS(pn_rt_position_control), 0x80,
            NULL, HFILL }},
#endif

        { &hf_pn_rt_sf_data_length,
          { "DataLength", "pn_rt.sf.data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_sf_cycle_counter,
          { "CycleCounter", "pn_rt.sf.cycle_counter",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_frag,
          { "PROFINET Fragment", "pn_rt.frag",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_frag_data_length,
          { "FragDataLength", "pn_rt.frag_data_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_frag_status,
          { "FragStatus", "pn_rt.frag_status",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_pn_rt_frag_status_more_follows,
          { "MoreFollows", "pn_rt.frag_status.more_follows",
            FT_UINT8, BASE_HEX, VALS(pn_rt_frag_status_more_follows), 0x80,
            NULL, HFILL }},

        { &hf_pn_rt_frag_status_error,
          { "Reserved", "pn_rt.frag_status.error",
            FT_UINT8, BASE_HEX, VALS(pn_rt_frag_status_error), 0x40,
            NULL, HFILL }},

        { &hf_pn_rt_frag_status_fragment_number,
          { "FragmentNumber (zero based)", "pn_rt.frag_status.fragment_number",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }},

        /* Is this a string or a bunch of bytes? Should it be FT_BYTES? */
        { &hf_pn_rt_frag_data,
          { "FragData", "pn_rt.frag_data",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},

    };
    static gint *ett[] = {
        &ett_pn_rt,
        &ett_pn_rt_data_status,
        &ett_pn_rt_sf,
        &ett_pn_rt_frag,
        &ett_pn_rt_frag_status
    };

    static ei_register_info ei[] = {
        { &ei_pn_rt_sf_crc16, { "pn_rt.sf.crc16_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    module_t *pn_rt_module;
    expert_module_t* expert_pn_rt;

    proto_pn_rt = proto_register_protocol("PROFINET Real-Time Protocol",
                                          "PN-RT", "pn_rt");
    pn_rt_handle = register_dissector("pn_rt", dissect_pn_rt, proto_pn_rt);

    proto_register_field_array(proto_pn_rt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pn_rt = expert_register_protocol(proto_pn_rt);
    expert_register_field_array(expert_pn_rt, ei, array_length(ei));

    /* Register our configuration options */

    pn_rt_module = prefs_register_protocol(proto_pn_rt, NULL);

    prefs_register_bool_preference(pn_rt_module, "summary_in_tree",
                                   "Show PN-RT summary in protocol tree",
                                   "Whether the PN-RT summary line should be shown in the protocol tree",
                                   &pn_rt_summary_in_tree);

    prefs_register_bool_preference(pn_rt_module, "desegment",
                                   "reassemble PNIO Fragments",
                                   "Reassemble PNIO Fragments and get them decoded",
                                   &pnio_desegment);

    /* register heuristics anchor for payload dissectors */
    heur_subdissector_list = register_heur_dissector_list("pn_rt", proto_pn_rt);

    init_pn (proto_pn_rt);
    register_init_routine(pnio_defragment_init);
    register_cleanup_routine(pnio_defragment_cleanup);
    reassembly_table_register(&pdu_reassembly_table,
                          &addresses_reassembly_table_functions);
}


/* The registration hand-off routine is called at startup */
void
proto_reg_handoff_pn_rt(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_PROFINET, pn_rt_handle);
    dissector_add_uint_with_preference("udp.port", PROFINET_UDP_PORT, pn_rt_handle);

    heur_dissector_add("pn_rt", dissect_CSF_SDU_heur, "PROFINET CSF_SDU IO", "pn_csf_sdu_pn_rt", proto_pn_rt, HEURISTIC_ENABLE);
    heur_dissector_add("pn_rt", dissect_FRAG_PDU_heur, "PROFINET Frag PDU IO", "pn_frag_pn_rt", proto_pn_rt, HEURISTIC_ENABLE);

    ethertype_subdissector_table = find_dissector_table("ethertype");
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
