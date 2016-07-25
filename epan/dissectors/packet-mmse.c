/* packet-mmse.c
 * Routines for MMS Message Encapsulation dissection
 * Copyright 2001, Tom Uijldert <tom.uijldert@cmg.nl>
 * Copyright 2004, Olivier Biot
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * ----------
 *
 * Dissector of an encoded Multimedia message PDU, as defined by the WAPForum
 * (http://www.wapforum.org) in "WAP-209-MMSEncapsulation-20020105-a".
 * Subsequent releases of MMS are in control of the Open Mobile Alliance (OMA):
 * Dissection of MMS 1.1 as in OMA-MMS-ENC-v1.1.
 * Dissection of MMS 1.2 as in OMA-MMS-ENC-v1.2 (not finished yet).
 */

/* This file has been edited with 8-space tabs and 4-space indentation */

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include "packet-wap.h"
#include "packet-wsp.h"

void proto_register_mmse(void);
void proto_reg_handoff_mmse(void);

#define MM_QUOTE                0x7F    /* Quoted string        */

#define MMS_CONTENT_TYPE        0x3E    /* WINA-value for mms-message   */

/* General-purpose debug logger.
 * Requires double parentheses because of variable arguments of printf().
 *
 * Enable debug logging for MMSE by defining AM_CFLAGS
 * so that it contains "-DDEBUG_mmse"
 */
#ifdef DEBUG_mmse
#define DebugLog(x) \
        g_print("%s:%u: ", __FILE__, __LINE__); \
        g_print x
#else
#define DebugLog(x) ;
#endif

/*
 * Forward declarations
 */
static int dissect_mmse_standalone(tvbuff_t *, packet_info *, proto_tree *, void*);
static void dissect_mmse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint8 pdut, const char *message_type);

/*
 * Header field values
 */
/* MMS 1.0 */
#define MM_BCC_HDR              0x81    /* Bcc                          */
#define MM_CC_HDR               0x82    /* Cc                           */
#define MM_CLOCATION_HDR        0x83    /* X-Mms-Content-Location       */
#define MM_CTYPE_HDR            0x84    /* Content-Type                 */
#define MM_DATE_HDR             0x85    /* Date                         */
#define MM_DREPORT_HDR          0x86    /* X-Mms-Delivery-Report        */
#define MM_DTIME_HDR            0x87    /* X-Mms-Delivery-Time          */
#define MM_EXPIRY_HDR           0x88    /* X-Mms-Expiry                 */
#define MM_FROM_HDR             0x89    /* From                         */
#define MM_MCLASS_HDR           0x8A    /* X-Mms-Message-Class          */
#define MM_MID_HDR              0x8B    /* Message-ID                   */
#define MM_MTYPE_HDR            0x8C    /* X-Mms-Message-Type           */
#define MM_VERSION_HDR          0x8D    /* X-Mms-MMS-Version            */
#define MM_MSIZE_HDR            0x8E    /* X-Mms-Message-Size           */
#define MM_PRIORITY_HDR         0x8F    /* X-Mms-Priority               */
#define MM_RREPLY_HDR           0x90    /* X-Mms-Read-Reply             */
#define MM_RALLOWED_HDR         0x91    /* X-Mms-Report-Allowed         */
#define MM_RSTATUS_HDR          0x92    /* X-Mms-Response-Status        */
#define MM_RTEXT_HDR            0x93    /* X-Mms-Response-Text          */
#define MM_SVISIBILITY_HDR      0x94    /* X-Mms-Sender-Visibility      */
#define MM_STATUS_HDR           0x95    /* X-Mms-Status                 */
#define MM_SUBJECT_HDR          0x96    /* Subject                      */
#define MM_TO_HDR               0x97    /* To                           */
#define MM_TID_HDR              0x98    /* X-Mms-Transaction-Id         */
/* MMS 1.1 */
#define MM_RETRIEVE_STATUS_HDR  0x99    /* X-Mms-Retrieve-Status        */
#define MM_RETRIEVE_TEXT_HDR    0x9A    /* X-Mms-Retrieve-Text          */
#define MM_READ_STATUS_HDR      0x9B    /* X-Mms-Read-Status            */
#define MM_REPLY_CHARGING_HDR   0x9C    /* X-Mms-Reply-Charging         */
#define MM_REPLY_CHARGING_DEADLINE_HDR  \
                                0x9D    /* X-Mms-Reply-Charging-Deadline*/
#define MM_REPLY_CHARGING_ID_HDR        \
                                0x9E    /* X-Mms-Reply-Charging-ID      */
#define MM_REPLY_CHARGING_SIZE_HDR      \
                                0x9F    /* X-Mms-Reply-Charging-Size    */
#define MM_PREV_SENT_BY_HDR     0xA0    /* X-Mms-Previously-Sent-By     */
#define MM_PREV_SENT_DATE_HDR   0xA1    /* X-Mms-Previously-Sent-Date   */
/* MMS 1.2 */
#define MM_STORE_HDR            0xA2    /* X-Mms-Store                  */
#define MM_MM_STATE_HDR         0xA3    /* X-Mms-MM-State               */
#define MM_MM_FLAGS_HDR         0xA4    /* X-Mms-MM-Flags               */
#define MM_STORE_STATUS_HDR     0xA5    /* X-Mms-Store-Status           */
#define MM_STORE_STATUS_TEXT_HDR        \
                                0xA6    /* X-Mms-Store-Status-Text      */
#define MM_STORED_HDR           0xA7    /* X-Mms-Stored                 */
#define MM_ATTRIBUTES_HDR       0xA8    /* X-Mms-Attributes             */
#define MM_TOTALS_HDR           0xA9    /* X-Mms-Totals                 */
#define MM_MBOX_TOTALS_HDR      0xAA    /* X-Mms-Mbox-Totals            */
#define MM_QUOTAS_HDR           0xAB    /* X-Mms-Quotas                 */
#define MM_MBOX_QUOTAS_HDR      0xAC    /* X-Mms-Mbox-Quotas            */
#define MM_MBOX_MSG_COUNT_HDR   0xAD    /* X-Mms-Message-Count          */
#define MM_CONTENT_HDR          0xAE    /* Content                      */
#define MM_START_HDR            0xAF    /* X-Mms-Start                  */
#define MM_ADDITIONAL_HDR       0xB0    /* Additional-headers           */
#define MM_DISTRIBUION_IND_HDR  0xB1    /* X-Mms-Distribution-Indicator */
#define MM_ELEMENT_DESCR_HDR    0xB2    /* X-Mms-Element-Descriptor     */
#define MM_LIMIT_HDR            0xB3    /* X-Mms-Limit                  */

static const value_string vals_mm_header_names[] = {
        /* MMS 1.0 */
        { MM_BCC_HDR,                   "Bcc" },
        { MM_CC_HDR,                    "Cc" },
        { MM_CLOCATION_HDR,             "X-Mms-Content-Location" },
        { MM_CTYPE_HDR,                 "X-Mms-Content-Type" },
        { MM_DATE_HDR,                  "Date" },
        { MM_DREPORT_HDR,               "X-Mms-Delivery-Report" },
        { MM_DTIME_HDR,                 "X-Mms-Delivery-Time" },
        { MM_EXPIRY_HDR,                "X-Mms-Expiry" },
        { MM_FROM_HDR,                  "From" },
        { MM_MCLASS_HDR,                "X-Mms-Message-Class" },
        { MM_MID_HDR,                   "Message-ID" },
        { MM_MTYPE_HDR,                 "X-Mms-Message-Type" },
        { MM_VERSION_HDR,               "X-Mms-MMS-Version" },
        { MM_MSIZE_HDR,                 "X-Mms-Message-Size" },
        { MM_PRIORITY_HDR,              "X-Mms-Priority" },
        { MM_RREPLY_HDR,                "X-Mms-Read-Reply" },
        { MM_RALLOWED_HDR,              "X-Mms-Report-Allowed" },
        { MM_RSTATUS_HDR,               "X-Mms-Response-Status" },
        { MM_RTEXT_HDR,                 "X-Mms-Response-Text" },
        { MM_SVISIBILITY_HDR,           "X-Mms-Sender-Visibility" },
        { MM_STATUS_HDR,                "X-Mms-Status" },
        { MM_SUBJECT_HDR,               "Subject" },
        { MM_TO_HDR,                    "To" },
        { MM_TID_HDR,                   "X-Mms-Transaction-Id" },
        /* MMS 1.1 */
        { MM_RETRIEVE_STATUS_HDR,       "X-Mms-Retrieve-Status" },
        { MM_RETRIEVE_TEXT_HDR,         "X-Mms-Retrieve-Text" },
        { MM_READ_STATUS_HDR,           "X-Mms-Read-Status" },
        { MM_REPLY_CHARGING_HDR,        "X-Mms-Reply-Charging" },
        { MM_REPLY_CHARGING_DEADLINE_HDR,
                                        "X-Mms-Reply-Charging-Deadline" },
        { MM_REPLY_CHARGING_ID_HDR,     "X-Mms-Reply-Charging-ID" },
        { MM_REPLY_CHARGING_SIZE_HDR,   "X-Mms-Reply-Charging-Size" },
        { MM_PREV_SENT_BY_HDR,          "X-Mms-Previously-Sent-By" },
        { MM_PREV_SENT_DATE_HDR,        "X-Mms-Previously-Sent-Date" },
        /* MMS 1.2 */
        { MM_STORE_HDR,                 "X-Mms-Store" },
        { MM_MM_STATE_HDR,              "X-Mms-MM-State" },
        { MM_MM_FLAGS_HDR,              "X-Mms-MM-Flags" },
        { MM_STORE_STATUS_HDR,          "X-Mms-Store-Status" },
        { MM_STORE_STATUS_TEXT_HDR,     "X-Mms-Store-Status-Text" },
        { MM_STORED_HDR,                "X-Mms-Stored" },
        { MM_ATTRIBUTES_HDR,            "X-Mms-Attributes" },
        { MM_TOTALS_HDR,                "X-Mms-Totals" },
        { MM_MBOX_TOTALS_HDR,           "X-Mms-Mbox-Totals" },
        { MM_QUOTAS_HDR,                "X-Mms-Quotas" },
        { MM_MBOX_QUOTAS_HDR,           "X-Mms-Mbox-Quotas" },
        { MM_MBOX_MSG_COUNT_HDR,        "X-Mms-Message-Count" },
        { MM_CONTENT_HDR,               "Content" },
        { MM_START_HDR,                 "X-Mms-Start" },
        { MM_ADDITIONAL_HDR,            "Additional-headers" },
        { MM_DISTRIBUION_IND_HDR,       "X-Mms-Distribution-Indcator" },
        { MM_ELEMENT_DESCR_HDR,         "X-Mms-Element-Descriptor" },
        { MM_LIMIT_HDR,                 "X-Mms-Limit" },

        { 0x00, NULL },
};
/*
 * Initialize the protocol and registered fields
 */
static int proto_mmse = -1;

static int hf_mmse_message_type         = -1;
static int hf_mmse_transaction_id       = -1;
static int hf_mmse_mms_version          = -1;
static int hf_mmse_bcc                  = -1;
static int hf_mmse_cc                   = -1;
static int hf_mmse_content_location     = -1;
static int hf_mmse_date                 = -1;
static int hf_mmse_delivery_report      = -1;
static int hf_mmse_delivery_time_abs    = -1;
static int hf_mmse_delivery_time_rel    = -1;
static int hf_mmse_expiry_abs           = -1;
static int hf_mmse_expiry_rel           = -1;
static int hf_mmse_from                 = -1;
static int hf_mmse_message_class_id     = -1;
static int hf_mmse_message_class_str    = -1;
static int hf_mmse_message_id           = -1;
static int hf_mmse_message_size         = -1;
static int hf_mmse_priority             = -1;
static int hf_mmse_read_reply           = -1;
static int hf_mmse_report_allowed       = -1;
static int hf_mmse_response_status      = -1;
static int hf_mmse_response_text        = -1;
static int hf_mmse_sender_visibility    = -1;
static int hf_mmse_status               = -1;
static int hf_mmse_subject              = -1;
static int hf_mmse_to                   = -1;
/* static int hf_mmse_content_type              = -1; */
static int hf_mmse_ffheader             = -1;
/* MMSE 1.1 */
static int hf_mmse_read_report          = -1;
static int hf_mmse_retrieve_status      = -1;
static int hf_mmse_retrieve_text        = -1;
static int hf_mmse_read_status          = -1;
static int hf_mmse_reply_charging       = -1;
static int hf_mmse_reply_charging_deadline_abs  = -1;
static int hf_mmse_reply_charging_deadline_rel  = -1;
static int hf_mmse_reply_charging_id    = -1;
static int hf_mmse_reply_charging_size  = -1;
static int hf_mmse_prev_sent_by = -1;
static int hf_mmse_prev_sent_by_fwd_count       = -1;
static int hf_mmse_prev_sent_by_address = -1;
static int hf_mmse_prev_sent_date       = -1;
static int hf_mmse_prev_sent_date_fwd_count     = -1;
static int hf_mmse_prev_sent_date_date  = -1;
static int hf_mmse_header_uint = -1;
static int hf_mmse_header_string = -1;
static int hf_mmse_header_bytes = -1;

/*
 * Initialize the subtree pointers
 */
static gint ett_mmse                    = -1;
static gint ett_mmse_hdr_details        = -1;

static expert_field ei_mmse_oversized_uintvar = EI_INIT;

/*
 * Valuestrings for PDU types
 */
/* MMS 1.0 */
#define PDU_M_SEND_REQ          0x80
#define PDU_M_SEND_CONF         0x81
#define PDU_M_NOTIFICATION_IND  0x82
#define PDU_M_NOTIFYRESP_IND    0x83
#define PDU_M_RETRIEVE_CONF     0x84
#define PDU_M_ACKNOWLEDGE_IND   0x85
#define PDU_M_DELIVERY_IND      0x86
/* MMS 1.1 */
#define PDU_M_READ_REC_IND      0x87
#define PDU_M_READ_ORIG_IND     0x88
#define PDU_M_FORWARD_REQ       0x89
#define PDU_M_FORWARD_CONF      0x8A
/* MMS 1.2 */
#define PDU_M_MBOX_STORE_REQ    0x8B
#define PDU_M_MBOX_STORE_CONF   0x8C
#define PDU_M_MBOX_VIEW_REQ     0x8D
#define PDU_M_MBOX_VIEW_CONF    0x8E
#define PDU_M_MBOX_UPLOAD_REQ   0x8F
#define PDU_M_MBOX_UPLOAD_CONF  0x90
#define PDU_M_MBOX_DELETE_REQ   0x91
#define PDU_M_MBOX_DELETE_CONF  0x92
#define PDU_M_MBOX_DESCR        0x93

#define pdu_has_content(pdut) \
        (  ((pdut) == PDU_M_SEND_REQ) \
        || ((pdut) == PDU_M_DELIVERY_IND) \
        || ((pdut) == PDU_M_RETRIEVE_CONF) \
        || ((pdut) == PDU_M_MBOX_VIEW_CONF) \
        || ((pdut) == PDU_M_MBOX_DESCR) \
        || ((pdut) == PDU_M_MBOX_UPLOAD_REQ) \
        )

static const value_string vals_message_type[] = {
    /* MMS 1.0 */
    { PDU_M_SEND_REQ,           "m-send-req" },
    { PDU_M_SEND_CONF,          "m-send-conf" },
    { PDU_M_NOTIFICATION_IND,   "m-notification-ind" },
    { PDU_M_NOTIFYRESP_IND,     "m-notifyresp-ind" },
    { PDU_M_RETRIEVE_CONF,      "m-retrieve-conf" },
    { PDU_M_ACKNOWLEDGE_IND,    "m-acknowledge-ind" },
    { PDU_M_DELIVERY_IND,       "m-delivery-ind" },
    /* MMS 1.1 */
    { PDU_M_READ_REC_IND,       "m-read-rec-ind" },
    { PDU_M_READ_ORIG_IND,      "m-read-orig-ind" },
    { PDU_M_FORWARD_REQ,        "m-forward-req" },
    { PDU_M_FORWARD_CONF,       "m-forward-conf" },
    /* MMS 1.2 */
    { PDU_M_MBOX_STORE_REQ,     "m-mbox-store-req" },
    { PDU_M_MBOX_STORE_CONF,    "m-mbox-store-conf" },
    { PDU_M_MBOX_VIEW_REQ,      "m-mbox-view-req" },
    { PDU_M_MBOX_VIEW_CONF,     "m-mbox-view-conf" },
    { PDU_M_MBOX_UPLOAD_REQ,    "m-mbox-upload-req" },
    { PDU_M_MBOX_UPLOAD_CONF,   "m-mbox-upload-conf" },
    { PDU_M_MBOX_DELETE_REQ,    "m-mbox-delete-req" },
    { PDU_M_MBOX_DELETE_CONF,   "m-mbox-delete-conf" },
    { PDU_M_MBOX_DESCR,         "m-mbox-descr" },
    { 0x00, NULL },
};

static const value_string vals_yes_no[] = {
    { 0x80, "Yes" },
    { 0x81, "No" },
    { 0x00, NULL },
};

static const value_string vals_message_class[] = {
    { 0x80, "Personal" },
    { 0x81, "Advertisement" },
    { 0x82, "Informational" },
    { 0x83, "Auto" },
    { 0x00, NULL },
};

static const value_string vals_priority[] = {
    { 0x80, "Low" },
    { 0x81, "Normal" },
    { 0x82, "High" },
    { 0x00, NULL },
};

static const value_string vals_response_status[] = {
    /* MMS 1.0 - obsolete as from MMS 1.1 */
    { 0x80, "Ok" },
    { 0x81, "Unspecified" },
    { 0x82, "Service denied" },
    { 0x83, "Message format corrupt" },
    { 0x84, "Sending address unresolved" },
    { 0x85, "Message not found" },
    { 0x86, "Network problem" },
    { 0x87, "Content not accepted" },
    { 0x88, "Unsupported message" },

    /*
     * Transient errors
     */
    /* MMS 1.1 */
    { 0xC0, "Transient failure" },
    { 0xC1, "Transient: Sending address unresolved" },
    { 0xC2, "Transient: Message not found" },
    { 0xC3, "Transient: Network problem" },
    /* MMS 1.2 */
    { 0xC4, "Transient: Partial success" },

    /*
     * Permanent errors
     */
    /* MMS 1.1 */
    { 0xE0, "Permanent failure" },
    { 0xE1, "Permanent: Service denied" },
    { 0xE2, "Permanent: Message format corrupt" },
    { 0xE3, "Permanent: Sending address unresolved" },
    { 0xE4, "Permanent: Message not found" },
    { 0xE5, "Permanent: Content not accepted" },
    { 0xE6, "Permanent: Reply charging limitations not met" },
    { 0xE7, "Permanent: Reply charging request not accepted" },
    { 0xE8, "Permanent: Reply charging forwarding denied" },
    { 0xE9, "Permanent: Reply charging not supported" },
    /* MMS 1.2 */
    { 0xEA, "Permanent: Address hiding not supported" },

    { 0x00, NULL },
};

static const value_string vals_sender_visibility[] = {
    { 0x80, "Hide" },
    { 0x81, "Show" },
    { 0x00, NULL },
};

static const value_string vals_message_status[] = {
    /* MMS 1.0 */
    { 0x80, "Expired" },
    { 0x81, "Retrieved" },
    { 0x82, "Rejected" },
    { 0x83, "Deferred" },
    { 0x84, "Unrecognized" },
    /* MMS 1.1 */
    { 0x85, "Indeterminate" },
    { 0x86, "Forwarded" },
    /* MMS 1.2 */
    { 0x87, "Unreachable" },

    { 0x00, NULL },
};

static const value_string vals_retrieve_status[] = {
    /*
     * Transient errors
     */
    /* MMS 1.1 */
    { 0xC0, "Transient failure" },
    { 0xC1, "Transient: Message not found" },
    { 0xC2, "Transient: Network problem" },

    /*
     * Permanent errors
     */
    /* MMS 1.1 */
    { 0xE0, "Permanent failure" },
    { 0xE1, "Permanent: Service denied" },
    { 0xE2, "Permanent: Message not found" },
    { 0xE3, "Permanent: Content unsupported" },

    { 0x00, NULL },
};

static const value_string vals_read_status[] = {
    { 0x80, "Read" },
    { 0x81, "Deleted without being read" },

    { 0x00, NULL },
};

static const value_string vals_reply_charging[] = {
    { 0x80, "Requested" },
    { 0x81, "Requested text only" },
    { 0x82, "Accepted" },
    { 0x83, "Accepted text only" },

    { 0x00, NULL },
};

/*!
 * Decodes a Text-string from the protocol data
 *      Text-string = [Quote] *TEXT End-of-string
 *      Quote       = <Octet 127>
 *      End-of-string = <Octet 0>
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param       tvb     The buffer with PDU-data
 * \param       offset  Offset within that buffer
 * \param       strval  Pointer to variable into which to put pointer to
 *                      buffer allocated to hold the text; must be freed
 *                      when no longer used
 *
 * \return              The length in bytes of the entire field
 */
static guint
get_text_string(tvbuff_t *tvb, guint offset, const char **strval)
{
    guint        len;

    DebugLog(("get_text_string(tvb = %p, offset = %u, **strval) - start\n",
                tvb, offset));
    len = tvb_strsize(tvb, offset);
    DebugLog((" [1] tvb_strsize(tvb, offset) == %u\n", len));
    if (tvb_get_guint8(tvb, offset) == MM_QUOTE)
        *strval = (const char *)tvb_memdup(wmem_packet_scope(), tvb, offset+1, len-1);
    else
        *strval = (const char *)tvb_memdup(wmem_packet_scope(), tvb, offset, len);
    DebugLog((" [3] Return(len) == %u\n", len));
    return len;
}

/*!
 * Decodes a Value-length from the protocol data.
 *      Value-length = Short-length | (Length-quote Length)
 *      Short-length = <Any octet 0-30>
 *      Length-quote = <Octet 31>
 *      Length       = Uintvar-integer
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param       tvb             The buffer with PDU-data
 * \param       offset          Offset within that buffer
 * \param       byte_count      Returns the length in bytes of
 *                              the "Value-length" field.
 * \param       pinfo           packet_info structure
 *
 * \return                      The actual value of "Value-length"
 */
static guint
get_value_length(tvbuff_t *tvb, guint offset, guint *byte_count, packet_info *pinfo)
{
    guint        field;

    field = tvb_get_guint8(tvb, offset++);
    if (field < 31)
        *byte_count = 1;
    else {                      /* Must be 31 so, Uintvar follows       */
        field = tvb_get_guintvar(tvb, offset, byte_count, pinfo, &ei_mmse_oversized_uintvar);
        (*byte_count)++;
    }
    return field;
}

/*!
 * Decodes an Encoded-string-value from the protocol data
 *      Encoded-string-value = Text-string | Value-length Char-set Text-string
 *
 * \param       tvb     The buffer with PDU-data
 * \param       offset  Offset within that buffer
 * \param       strval  Pointer to variable into which to put pointer to
 *                      buffer allocated to hold the text; must be freed
 *                      when no longer used
 *
 * \return              The length in bytes of the entire field
 */
static guint
get_encoded_strval(tvbuff_t *tvb, guint offset, const char **strval, packet_info *pinfo)
{
    guint        field;
    guint        length;
    guint        count;

    field = tvb_get_guint8(tvb, offset);

    if (field < 32) {
        length = get_value_length(tvb, offset, &count, pinfo);
        if (length < 2) {
            *strval = "";
        } else {
            /* \todo    Something with "Char-set", skip for now */
            *strval = (char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + count + 1, length - 1, ENC_ASCII);
        }
        return count + length;
    } else
        return get_text_string(tvb, offset, strval);
}

/*!
 * Decodes a Long-integer from the protocol data
 *      Long-integer = Short-length Multi-octet-integer
 *      Short-length = <Any octet 0-30>
 *      Multi-octet-integer = 1*30OCTET
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param       tvb             The buffer with PDU-data
 * \param       offset          Offset within that buffer
 * \param       byte_count      Returns the length in bytes of the field
 *
 * \return                      The value of the Long-integer
 *
 * \note        A maximum of 4-byte integers will be handled.
 */
static guint
get_long_integer(tvbuff_t *tvb, guint offset, guint *byte_count)
{
    guint        val;

    *byte_count = tvb_get_guint8(tvb, offset++);
    switch (*byte_count) {
        case 1:
            val = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            val = tvb_get_ntohs(tvb, offset);
            break;
        case 3:
            val = tvb_get_ntoh24(tvb, offset);
            break;
        case 4:
            val = tvb_get_ntohl(tvb, offset);
            break;
        default:
            val = 0;
            break;
    }
    (*byte_count)++;
    return val;
}

/*!
 * Decodes an Integer-value from the protocol data
 *      Integer-value = Short-integer | Long-integer
 *      Short-integer = OCTET
 *      Long-integer = Short-length Multi-octet-integer
 *      Short-length = <Any octet 0-30>
 *      Multi-octet-integer = 1*30OCTET
 *
 * \todo Shouldn't we be sharing this with WSP (packet-wap.c)?
 *
 * \param       tvb             The buffer with PDU-data
 * \param       offset          Offset within that buffer
 * \param       byte_count      Returns the length in bytes of the field
 *
 * \return                      The value of the Long-integer
 *
 * \note        A maximum of 4-byte integers will be handled.
 */
static guint
get_integer_value(tvbuff_t *tvb, guint offset, guint *byte_count)
{
    guint        val;
    guint8 peek;

    peek = tvb_get_guint8(tvb, offset++);
    if (peek & 0x80) {
        val = peek & 0x7F;
        *byte_count = 1;
        return val;
    } else {
        *byte_count = peek;
        switch (peek) {
        case 1:
            val = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            val = tvb_get_ntohs(tvb, offset);
            break;
        case 3:
            val = tvb_get_ntoh24(tvb, offset);
            break;
        case 4:
            val = tvb_get_ntohl(tvb, offset);
            break;
        default:
            val = 0;
            break;
        }
    }
    (*byte_count)++;
    return val;
}

/* Code to actually dissect the packets */
static gboolean
dissect_mmse_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8       pdut;

        DebugLog(("dissect_mmse_heur()\n"));
    /*
     * Check if data makes sense for it to be dissected as MMSE:  Message-type
     * field must make sense and followed by either Transaction-Id
     * or MMS-Version header
     */
    if (tvb_get_guint8(tvb, 0) != MM_MTYPE_HDR)
        return FALSE;
    pdut = tvb_get_guint8(tvb, 1);
    if (try_val_to_str(pdut, vals_message_type) == NULL)
        return FALSE;
    if ((tvb_get_guint8(tvb, 2) != MM_TID_HDR) &&
        (tvb_get_guint8(tvb, 2) != MM_VERSION_HDR))
        return FALSE;
    dissect_mmse_standalone(tvb, pinfo, tree, data);
    return TRUE;
}

static int
dissect_mmse_standalone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8       pdut;
    const char   *message_type;

    DebugLog(("dissect_mmse_standalone() - START (Packet %u)\n",
                pinfo->num));

    pdut = tvb_get_guint8(tvb, 1);
    message_type = val_to_str(pdut, vals_message_type, "Unknown type %u");

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMSE");

        col_add_fstr(pinfo->cinfo, COL_INFO, "MMS %s", message_type);

    dissect_mmse(tvb, pinfo, tree, pdut, message_type);
    return tvb_captured_length(tvb);
}

static int
dissect_mmse_encapsulated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8       pdut;
    const char   *message_type;

    DebugLog(("dissect_mmse_encapsulated() - START (Packet %u)\n",
                pinfo->num));

    pdut = tvb_get_guint8(tvb, 1);
    message_type = val_to_str(pdut, vals_message_type, "Unknown type %u");

    /* Make entries in Info column on summary display */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(MMS %s)",
                message_type);

    dissect_mmse(tvb, pinfo, tree, pdut, message_type);
    return tvb_captured_length(tvb);
}

static void
dissect_mmse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 pdut,
        const char *message_type)
{
    guint        offset;
    guint8       field = 0;
    const char   *strval;
    guint        length;
    guint        count;
    guint8       version = 0x80; /* Default to MMSE 1.0 */

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item  *ti = NULL;
    proto_tree  *mmse_tree = NULL;

    DebugLog(("dissect_mmse() - START (Packet %u)\n", pinfo->num));

    /* If tree == NULL then we are only interested in protocol dissection
     * up to reassembly and handoff to subdissectors if applicable; the
     * columns must be set appropriately too.
     * If tree != NULL then we also want to display the protocol tree
     * with its fields.
     *
     * In the interest of speed, skip protocol tree item generation
     * if tree is NULL.
     */
    if (tree) {
        DebugLog(("tree != NULL\n"));

        ti = proto_tree_add_item(tree, proto_mmse, tvb, 0, -1, ENC_NA);
        proto_item_append_text(ti, ", Type: %s", message_type);
        /* create display subtree for the protocol */
        mmse_tree = proto_item_add_subtree(ti, ett_mmse);

        /* Report PDU-type      */
        proto_tree_add_uint(mmse_tree, hf_mmse_message_type, tvb, 0, 2, pdut);
    }

    offset = 2;                 /* Skip Message-Type    */

    /*
     * Cycle through MMS-headers
     *
     * NOTE - some PDUs may convey content which can be handed off
     *        to subdissectors.
     */
    if (tree || pdu_has_content(pdut)) {
        while ((offset < tvb_reported_length(tvb)) &&
               (field = tvb_get_guint8(tvb, offset++)) != MM_CTYPE_HDR)
        {
            DebugLog(("\tField =  0x%02X (offset = %u): %s\n",
                        field, offset,
                        val_to_str(field, vals_mm_header_names,
                            "Unknown MMS header 0x%02X")));
            switch (field)
            {
                case MM_TID_HDR:                /* Text-string  */
                    length = get_text_string(tvb, offset, &strval);
                    if (tree) {
                        proto_tree_add_string(mmse_tree, hf_mmse_transaction_id,
                                tvb, offset - 1, length + 1,strval);
                    }
                    offset += length;
                    break;
                case MM_VERSION_HDR:            /* nibble-Major/nibble-minor*/
                    version = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        guint8   major, minor;
                        char    *vers_string;

                        major = (version & 0x70) >> 4;
                        minor = version & 0x0F;
                        if (minor == 0x0F)
                            vers_string = wmem_strdup_printf(wmem_packet_scope(), "%u", major);
                        else
                            vers_string = wmem_strdup_printf(wmem_packet_scope(), "%u.%u", major, minor);
                        proto_tree_add_string(mmse_tree, hf_mmse_mms_version,
                                tvb, offset - 2, 2, vers_string);
                    }
                    break;
                case MM_BCC_HDR:                /* Encoded-string-value */
                    length = get_encoded_strval(tvb, offset, &strval, pinfo);
                    if (tree) {
                        proto_tree_add_string(mmse_tree, hf_mmse_bcc, tvb,
                                offset - 1, length + 1, strval);
                    }
                    offset += length;
                    break;
                case MM_CC_HDR:                 /* Encoded-string-value */
                    length = get_encoded_strval(tvb, offset, &strval, pinfo);
                    if (tree) {
                        proto_tree_add_string(mmse_tree, hf_mmse_cc, tvb,
                                offset - 1, length + 1, strval);
                    }
                    offset += length;
                    break;
                case MM_CLOCATION_HDR:          /* Uri-value            */
                    if (pdut == PDU_M_MBOX_DELETE_CONF) {
                        /* General form with length */
                        length = tvb_get_guint8(tvb, offset);
                        if (length == 0x1F) {
                            guint length_len = 0;
                            length = tvb_get_guintvar(tvb, offset + 1,
                                    &length_len, pinfo, &ei_mmse_oversized_uintvar);
                            length += 1 + length_len;
                        } else {
                            length += 1;
                        }
                        proto_tree_add_string(mmse_tree,
                                    hf_mmse_content_location,
                                    tvb, offset - 1, length + 1,
                                    "<Undecoded value for m-mbox-delete-conf>");
                    } else {
                        length = get_text_string(tvb, offset, &strval);
                        if (tree) {
                            proto_tree_add_string(mmse_tree,
                                    hf_mmse_content_location,
                                    tvb, offset - 1, length + 1, strval);
                        }
                    }
                    offset += length;
                    break;
                case MM_DATE_HDR:               /* Long-integer         */
                    {
                        guint            tval;
                        nstime_t         tmptime;

                        tval = get_long_integer(tvb, offset, &count);
                        tmptime.secs = tval;
                        tmptime.nsecs = 0;
                        proto_tree_add_time(mmse_tree, hf_mmse_date, tvb,
                                    offset - 1, count + 1, &tmptime);
                    }
                    offset += count;
                    break;
                case MM_DREPORT_HDR:            /* Yes|No               */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree,
                                hf_mmse_delivery_report,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_DTIME_HDR:
                    /*
                     * Value-length(Absolute-token Date-value|
                     *              Relative-token Delta-seconds-value)
                     */
                    length = get_value_length(tvb, offset, &count, pinfo);
                    field = tvb_get_guint8(tvb, offset + count);
                    if (tree) {
                        guint            tval;
                        nstime_t         tmptime;
                        guint            cnt;

                        tval =  get_long_integer(tvb, offset + count + 1, &cnt);
                        tmptime.secs = tval;
                        tmptime.nsecs = 0;

                        if (field == 0x80)
                            proto_tree_add_time(mmse_tree,
                                    hf_mmse_delivery_time_abs,
                                    tvb, offset - 1,
                                    length + count + 1, &tmptime);
                        else
                            proto_tree_add_time(mmse_tree,
                                    hf_mmse_delivery_time_rel,
                                    tvb, offset - 1,
                                    length + count + 1, &tmptime);
                    }
                    offset += length + count;
                    break;
                case MM_EXPIRY_HDR:
                    /*
                     * Value-length(Absolute-token Date-value|
                     *              Relative-token Delta-seconds-value)
                     */
                    length = get_value_length(tvb, offset, &count, pinfo);
                    field = tvb_get_guint8(tvb, offset + count);
                    if (tree) {
                        guint            tval;
                        nstime_t         tmptime;
                        guint            cnt;

                        tval = get_long_integer(tvb, offset + count + 1, &cnt);
                        tmptime.secs = tval;
                        tmptime.nsecs = 0;

                        if (field == 0x80)
                            proto_tree_add_time(mmse_tree, hf_mmse_expiry_abs,
                                    tvb, offset - 1,
                                    length + count + 1, &tmptime);
                        else
                            proto_tree_add_time(mmse_tree, hf_mmse_expiry_rel,
                                    tvb, offset - 1,
                                    length + count + 1, &tmptime);
                    }
                    offset += length + count;
                    break;
                case MM_FROM_HDR:
                    /*
                     * Value-length(Address-present-token Encoded-string-value
                     *              |Insert-address-token)
                     */
                    length = get_value_length(tvb, offset, &count, pinfo);
                    if (tree) {
                        field = tvb_get_guint8(tvb, offset + count);
                        if (field == 0x81) {
                            proto_tree_add_string(mmse_tree, hf_mmse_from, tvb,
                                    offset-1, length + count + 1,
                                    "<insert address>");
                        } else {
                            (void) get_encoded_strval(tvb, offset + count + 1,
                                                      &strval, pinfo);
                            proto_tree_add_string(mmse_tree, hf_mmse_from, tvb,
                                    offset-1, length + count + 1, strval);
                        }
                    }
                    offset += length + count;
                    break;
                case MM_MCLASS_HDR:
                    /*
                     * Class-identifier|Text-string
                     */
                    field = tvb_get_guint8(tvb, offset);
                    if (field & 0x80) {
                        offset++;
                        if (tree) {
                            proto_tree_add_uint(mmse_tree,
                                    hf_mmse_message_class_id,
                                    tvb, offset - 2, 2, field);
                        }
                    } else {
                        length = get_text_string(tvb, offset, &strval);
                        if (tree) {
                            proto_tree_add_string(mmse_tree,
                                    hf_mmse_message_class_str,
                                    tvb, offset - 1, length + 1,
                                    strval);
                        }
                        offset += length;
                    }
                    break;
                case MM_MID_HDR:                /* Text-string          */
                    length = get_text_string(tvb, offset, &strval);
                    if (tree) {
                        proto_tree_add_string(mmse_tree, hf_mmse_message_id,
                                tvb, offset - 1, length + 1, strval);
                    }
                    offset += length;
                    break;
                case MM_MSIZE_HDR:              /* Long-integer         */
                    length = get_long_integer(tvb, offset, &count);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_message_size,
                                tvb, offset - 1, count + 1, length);
                    }
                    offset += count;
                    break;
                case MM_PRIORITY_HDR:           /* Low|Normal|High      */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_priority, tvb,
                                offset - 2, 2, field);
                    }
                    break;
                case MM_RREPLY_HDR:             /* Yes|No               */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        if (version == 0x80) { /* MMSE 1.0 */
                            proto_tree_add_uint(mmse_tree, hf_mmse_read_reply,
                                    tvb, offset - 2, 2, field);
                        } else {
                            proto_tree_add_uint(mmse_tree, hf_mmse_read_report,
                                    tvb, offset - 2, 2, field);
                        }
                    }
                    break;
                case MM_RALLOWED_HDR:           /* Yes|No               */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_report_allowed,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_RSTATUS_HDR:
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_response_status,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_RTEXT_HDR:              /* Encoded-string-value */
                    if (pdut == PDU_M_MBOX_DELETE_CONF) {
                        /* General form with length */
                        length = tvb_get_guint8(tvb, offset);
                        if (length == 0x1F) {
                            guint length_len = 0;
                            length = tvb_get_guintvar(tvb, offset + 1,
                                    &length_len, pinfo, &ei_mmse_oversized_uintvar);
                            length += 1 + length_len;
                        } else {
                            length += 1;
                        }
                        if (tree) {
                            proto_tree_add_string(mmse_tree,
                                    hf_mmse_content_location,
                                    tvb, offset - 1, length + 1,
                                    "<Undecoded value for m-mbox-delete-conf>");
                        }
                    } else {
                        length = get_encoded_strval(tvb, offset, &strval, pinfo);
                        if (tree) {
                            proto_tree_add_string(mmse_tree,
                                    hf_mmse_response_text, tvb, offset - 1,
                                    length + 1, strval);
                        }
                    }
                    offset += length;
                    break;
                case MM_SVISIBILITY_HDR:        /* Hide|Show            */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree,hf_mmse_sender_visibility,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_STATUS_HDR:
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_status, tvb,
                                offset - 2, 2, field);
                    }
                    break;
                case MM_SUBJECT_HDR:            /* Encoded-string-value */
                    length = get_encoded_strval(tvb, offset, &strval, pinfo);
                    if (tree) {
                        proto_tree_add_string(mmse_tree, hf_mmse_subject, tvb,
                                offset - 1, length + 1, strval);
                    }
                    offset += length;
                    break;
                case MM_TO_HDR:                 /* Encoded-string-value */
                    length = get_encoded_strval(tvb, offset, &strval, pinfo);
                    if (tree) {
                        proto_tree_add_string(mmse_tree, hf_mmse_to, tvb,
                                offset - 1, length + 1, strval);
                    }
                    offset += length;
                    break;

                /*
                 * MMS Encapsulation 1.1
                 */
                case MM_RETRIEVE_STATUS_HDR:    /* Well-known-value */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_retrieve_status,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_RETRIEVE_TEXT_HDR:
                    if (pdut == PDU_M_MBOX_DELETE_CONF) {
                        /* General form with length */
                        length = tvb_get_guint8(tvb, offset);
                        if (length == 0x1F) {
                            guint length_len = 0;
                            length = tvb_get_guintvar(tvb, offset + 1,
                                    &length_len, pinfo, &ei_mmse_oversized_uintvar);
                            length += 1 + length_len;
                        } else {
                            length += 1;
                        }
                        if (tree) {
                            proto_tree_add_string(mmse_tree,
                                    hf_mmse_content_location,
                                    tvb, offset - 1, length + 1,
                                    "<Undecoded value for m-mbox-delete-conf>");
                        }
                    } else {
                        /* Encoded-string-value */
                        length = get_encoded_strval(tvb, offset, &strval, pinfo);
                        if (tree) {
                            proto_tree_add_string(mmse_tree,
                                    hf_mmse_retrieve_text, tvb, offset - 1,
                                    length + 1, strval);
                        }
                    }
                    offset += length;
                    break;
                case MM_READ_STATUS_HDR:        /* Well-known-value */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_read_status,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_REPLY_CHARGING_HDR:     /* Well-known-value */
                    field = tvb_get_guint8(tvb, offset++);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree, hf_mmse_reply_charging,
                                tvb, offset - 2, 2, field);
                    }
                    break;
                case MM_REPLY_CHARGING_DEADLINE_HDR:    /* Well-known-value */
                    /*
                     * Value-length(Absolute-token Date-value|
                     *              Relative-token Delta-seconds-value)
                     */
                    length = get_value_length(tvb, offset, &count, pinfo);
                    field = tvb_get_guint8(tvb, offset + count);
                    if (tree) {
                        guint            tval;
                        nstime_t         tmptime;
                        guint            cnt;

                        tval = get_long_integer(tvb, offset + count + 1, &cnt);
                        tmptime.secs = tval;
                        tmptime.nsecs = 0;

                        if (field == 0x80)
                            proto_tree_add_time(mmse_tree, hf_mmse_reply_charging_deadline_abs,
                                    tvb, offset - 1,
                                    length + count + 1, &tmptime);
                        else
                            proto_tree_add_time(mmse_tree, hf_mmse_reply_charging_deadline_rel,
                                    tvb, offset - 1,
                                    length + count + 1, &tmptime);
                    }
                    offset += length + count;
                    break;
                case MM_REPLY_CHARGING_ID_HDR:  /* Text-string */
                    length = get_text_string(tvb, offset, &strval);
                    if (tree) {
                        proto_tree_add_string(mmse_tree,
                                hf_mmse_reply_charging_id,
                                tvb, offset - 1, length + 1, strval);
                    }
                    offset += length;
                    break;
                case MM_REPLY_CHARGING_SIZE_HDR:        /* Long-integer */
                    length = get_long_integer(tvb, offset, &count);
                    if (tree) {
                        proto_tree_add_uint(mmse_tree,
                                hf_mmse_reply_charging_size,
                                tvb, offset - 1, count + 1, length);
                    }
                    offset += count;
                    break;
                case MM_PREV_SENT_BY_HDR:
                    /* Value-length Integer-value Encoded-string-value */
                    length = get_value_length(tvb, offset, &count, pinfo);
                    if (tree) {
                        guint32 fwd_count, count1, count2;
                        proto_tree *subtree = NULL;
                        proto_item *tii = NULL;
                        /* 1. Forwarded-count-value := Integer-value */
                        fwd_count = get_integer_value(tvb, offset + count,
                            &count1);
                        /* 2. Encoded-string-value */
                        count2 = get_encoded_strval(tvb,
                                offset + count + count1, &strval, pinfo);
                        /* Now render the fields */
                        tii = proto_tree_add_string_format(mmse_tree,
                                hf_mmse_prev_sent_by,
                                tvb, offset - 1, 1 + count + length,
                                strval, "%s (Forwarded-count=%u)",
                                format_text(strval, strlen(strval)),
                                fwd_count);
                        subtree = proto_item_add_subtree(tii,
                                ett_mmse_hdr_details);
                        proto_tree_add_uint(subtree,
                                hf_mmse_prev_sent_by_fwd_count,
                                tvb, offset + count, count1, fwd_count);
                        proto_tree_add_string(subtree,
                                hf_mmse_prev_sent_by_address,
                                tvb, offset + count + count1, count2, strval);
                    }
                    offset += length + count;
                    break;
                case MM_PREV_SENT_DATE_HDR:
                    /* Value-Length Forwarded-count-value Date-value */
                    length = get_value_length(tvb, offset, &count, pinfo);
                    if (tree) {
                        guint32 fwd_count, count1, count2;
                        guint            tval;
                        nstime_t         tmptime;
                        proto_tree *subtree = NULL;
                        proto_item *tii = NULL;
                        /* 1. Forwarded-count-value := Integer-value */
                        fwd_count = get_integer_value(tvb, offset + count,
                            &count1);
                        /* 2. Date-value := Long-integer */
                        tval = get_long_integer(tvb, offset + count + count1,
                                &count2);
                        tmptime.secs = tval;
                        tmptime.nsecs = 0;
                        strval = abs_time_to_str(wmem_packet_scope(), &tmptime, ABSOLUTE_TIME_LOCAL,
                            TRUE);
                        /* Now render the fields */
                        tii = proto_tree_add_string_format(mmse_tree,
                                hf_mmse_prev_sent_date,
                                tvb, offset - 1, 1 + count + length,
                                strval, "%s (Forwarded-count=%u)",
                                format_text(strval, strlen(strval)),
                                fwd_count);
                        subtree = proto_item_add_subtree(tii,
                                ett_mmse_hdr_details);
                        proto_tree_add_uint(subtree,
                                hf_mmse_prev_sent_date_fwd_count,
                                tvb, offset + count, count1, fwd_count);
                        proto_tree_add_string(subtree,
                                hf_mmse_prev_sent_date_date,
                                tvb, offset + count + count1, count2, strval);
                    }
                    offset += length + count;
                    break;

                /* MMS Encapsulation 1.2 */

                default:
                    if (field & 0x80) { /* Well-known WSP header encoding */
                        guint8 peek = tvb_get_guint8(tvb, offset);
                        const char *hdr_name = val_to_str(field, vals_mm_header_names,
                                "Unknown field (0x%02x)");
            const char *str;
                        DebugLog(("\t\tUndecoded well-known header: %s\n",
                                    hdr_name));

                        if (peek & 0x80) { /* Well-known value */
                            length = 1;
                            if (tree) {
                                proto_tree_add_uint_format(mmse_tree, hf_mmse_header_uint, tvb, offset - 1,
                                        length + 1, peek,
                                        "%s: <Well-known value 0x%02x>"
                                        " (not decoded)",
                                        hdr_name, peek);
                            }
                        } else if ((peek == 0) || (peek >= 0x20)) { /* Text */
                            length = get_text_string(tvb, offset, &strval);
                            if (tree) {
                                str = format_text(strval, strlen(strval));
                                proto_tree_add_string_format(mmse_tree, hf_mmse_header_string, tvb, offset - 1,
                                        length + 1, str, "%s: %s (Not decoded)", hdr_name, str);
                            }
                        } else { /* General form with length */
                            if (peek == 0x1F) { /* Value length in guintvar */
                                guint length_len = 0;
                                length = 1 + tvb_get_guintvar(tvb, offset + 1,
                                        &length_len, pinfo, &ei_mmse_oversized_uintvar);
                                length += length_len;
                            } else { /* Value length in octet */
                                length = 1 + tvb_get_guint8(tvb, offset);
                            }
                            if (tree) {
                                proto_tree_add_bytes_format(mmse_tree, hf_mmse_header_bytes, tvb, offset - 1,
                                        length + 1, NULL, "%s: "
                                        "<Value in general form> (not decoded)",
                                        hdr_name);
                            }
                        }
                        offset += length;
                    } else { /* Literal WSP header encoding */
                        guint            length2;
                        const char       *strval2;

                        --offset;
                        length = get_text_string(tvb, offset, &strval);
                        DebugLog(("\t\tUndecoded literal header: %s\n",
                                    strval));
                        length2= get_text_string(tvb, offset+length, &strval2);

                        if (tree) {
                            proto_tree_add_string_format(mmse_tree,
                                    hf_mmse_ffheader, tvb, offset,
                                    length + length2,
                                    tvb_get_string_enc(wmem_packet_scope(), tvb, offset,
                                            length + length2, ENC_ASCII),
                                    "%s: %s",
                                    format_text(strval, strlen(strval)),
                                    format_text(strval2, strlen(strval2)));
                        }
                        offset += length + length2;
                    }
                    break;
            }
            DebugLog(("\tEnd(case)\n"));
        }
        DebugLog(("\tEnd(switch)\n"));
        if (field == MM_CTYPE_HDR) {
            /*
             * Eeehh, we're now actually back to good old WSP content-type
             * encoding. Let's steal that from the WSP-dissector.
             */
            tvbuff_t    *tmp_tvb;
            guint        type;
            const char  *type_str;

            DebugLog(("Content-Type: [from WSP dissector]\n"));
            DebugLog(("Calling add_content_type() in WSP dissector\n"));
            offset = add_content_type(mmse_tree, pinfo, tvb, offset, &type, &type_str);
            DebugLog(("Generating new TVB subset (offset = %u)\n", offset));
            tmp_tvb = tvb_new_subset_remaining(tvb, offset);
            DebugLog(("Add POST data\n"));
            add_post_data(mmse_tree, tmp_tvb, type, type_str, pinfo);
            DebugLog(("Done!\n"));
        }
    } else {
        DebugLog(("tree == NULL and PDU has no potential content\n"));
    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 */
    DebugLog(("dissect_mmse() - END\n"));
}


/* Register the protocol with Wireshark */

/* this format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */
void
proto_register_mmse(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details       */
    static hf_register_info hf[] = {
        {   &hf_mmse_message_type,
            {   "X-Mms-Message-Type", "mmse.message_type",
                FT_UINT8, BASE_HEX, VALS(vals_message_type), 0x00,
                "Specifies the transaction type. Effectively defines PDU.",
                HFILL
            }
        },
        {   &hf_mmse_transaction_id,
            {   "X-Mms-Transaction-ID", "mmse.transaction_id",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "A unique identifier for this transaction. Identifies request and corresponding response only.",
                HFILL
            }
        },
        {   &hf_mmse_mms_version,
            {   "X-Mms-MMS-Version", "mmse.mms_version",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Version of the protocol used.",
                HFILL
            }
        },
        {   &hf_mmse_bcc,
            {   "Bcc", "mmse.bcc",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Blind carbon copy.",
                HFILL
            }
        },
        {   &hf_mmse_cc,
            {   "Cc", "mmse.cc",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Carbon copy.",
                HFILL
            }
        },
        {   &hf_mmse_content_location,
            {   "X-Mms-Content-Location", "mmse.content_location",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Defines the location of the message.",
                HFILL
            }
        },
        {   &hf_mmse_date,
            {   "Date", "mmse.date",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
                "Arrival timestamp of the message or sending timestamp.",
                HFILL
            }
        },
        {   &hf_mmse_delivery_report,
            {   "X-Mms-Delivery-Report", "mmse.delivery_report",
                FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
                "Whether a report of message delivery is wanted or not.",
                HFILL
            }
        },
        {   &hf_mmse_delivery_time_abs,
            {   "X-Mms-Delivery-Time", "mmse.delivery_time.abs",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
                "The time at which message delivery is desired.",
                HFILL
            }
        },
        {   &hf_mmse_delivery_time_rel,
            {   "X-Mms-Delivery-Time", "mmse.delivery_time.rel",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                "The desired message delivery delay.",
                HFILL
            }
        },
        {   &hf_mmse_expiry_abs,
            {   "X-Mms-Expiry", "mmse.expiry.abs",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
                "Time when message expires and need not be delivered anymore.",
                HFILL
            }
        },
        {   &hf_mmse_expiry_rel,
            {   "X-Mms-Expiry", "mmse.expiry.rel",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                "Delay before message expires and need not be delivered anymore.",
                HFILL
            }
        },
        {   &hf_mmse_from,
            {   "From", "mmse.from",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Address of the message sender.",
                HFILL
            }
        },
        {   &hf_mmse_message_class_id,
            {   "X-Mms-Message-Class", "mmse.message_class.id",
                FT_UINT8, BASE_HEX, VALS(vals_message_class), 0x00,
                "Of what category is the message.",
                HFILL
            }
        },
        {   &hf_mmse_message_class_str,
            {   "X-Mms-Message-Class", "mmse.message_class.str",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Of what category is the message.",
                HFILL
            }
        },
        {   &hf_mmse_message_id,
            {   "Message-Id", "mmse.message_id",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Unique identification of the message.",
                HFILL
            }
        },
        {   &hf_mmse_message_size,
            {   "X-Mms-Message-Size", "mmse.message_size",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "The size of the message in octets.",
                HFILL
            }
        },
        {   &hf_mmse_priority,
            {   "X-Mms-Priority", "mmse.priority",
                FT_UINT8, BASE_HEX, VALS(vals_priority), 0x00,
                "Priority of the message.",
                HFILL
            }
        },
        {   &hf_mmse_read_reply,
            {   "X-Mms-Read-Reply", "mmse.read_reply",
                FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
                "Whether a read report from every recipient is wanted.",
                HFILL
            }
        },
        {   &hf_mmse_read_report,
            {   "X-Mms-Read-Report", "mmse.read_report",
                FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
                "Whether a read report from every recipient is wanted.",
                HFILL
            }
        },
        {   &hf_mmse_report_allowed,
            {   "X-Mms-Report-Allowed", "mmse.report_allowed",
                FT_UINT8, BASE_HEX, VALS(vals_yes_no), 0x00,
                "Sending of delivery report allowed or not.",
                HFILL
            }
        },
        {   &hf_mmse_response_status,
            {   "Response-Status", "mmse.response_status",
                FT_UINT8, BASE_HEX, VALS(vals_response_status), 0x00,
                "MMS-specific result of a message submission or retrieval.",
                HFILL
            }
        },
        {   &hf_mmse_response_text,
            {   "Response-Text", "mmse.response_text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Additional information on MMS-specific result.",
                HFILL
            }
        },
        {   &hf_mmse_sender_visibility,
            {   "Sender-Visibility", "mmse.sender_visibility",
                FT_UINT8, BASE_HEX, VALS(vals_sender_visibility), 0x00,
                "Disclose sender identity to receiver or not.",
                HFILL
            }
        },
        {   &hf_mmse_status,
            {   "Status", "mmse.status",
                FT_UINT8, BASE_HEX, VALS(vals_message_status), 0x00,
                "Current status of the message.",
                HFILL
            }
        },
        {   &hf_mmse_subject,
            {   "Subject", "mmse.subject",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Subject of the message.",
                HFILL
            }
        },
        {   &hf_mmse_to,
            {   "To", "mmse.to",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Recipient(s) of the message.",
                HFILL
            }
        },
#if 0
        {   &hf_mmse_content_type,
            {   "Data", "mmse.content_type",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Media content of the message.",
                HFILL
            }
        },
#endif
        {   &hf_mmse_ffheader,
            {   "Free format (not encoded) header", "mmse.ffheader",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Application header without corresponding encoding.",
                HFILL
            }
        },
        /* MMSE 1.1 */
        {   &hf_mmse_retrieve_status,
            {   "X-Mms-Retrieve-Status", "mmse.retrieve_status",
                FT_UINT8, BASE_HEX, VALS(vals_retrieve_status), 0x00,
                "MMS-specific result of a message retrieval.",
                HFILL
            }
        },
        {   &hf_mmse_retrieve_text,
            {   "X-Mms-Retrieve-Text", "mmse.retrieve_text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Status text of a MMS message retrieval.",
                HFILL
            }
        },
        {   &hf_mmse_read_status,
            {   "X-Mms-Read-Status", "mmse.read_status",
                FT_UINT8, BASE_HEX, VALS(vals_read_status), 0x00,
                "MMS-specific message read status.",
                HFILL
            }
        },
        {   &hf_mmse_reply_charging,
            {   "X-Mms-Reply-Charging", "mmse.reply_charging",
                FT_UINT8, BASE_HEX, VALS(vals_reply_charging), 0x00,
                "MMS-specific message reply charging method.",
                HFILL
            }
        },
        {   &hf_mmse_reply_charging_deadline_abs,
            {   "X-Mms-Reply-Charging-Deadline", "mmse.reply_charging_deadline.abs",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
                "The latest time of the recipient(s) to submit the Reply MM.",
                HFILL
            }
        },
        {   &hf_mmse_reply_charging_deadline_rel,
            {   "X-Mms-Reply-Charging-Deadline", "mmse.reply_charging_deadline.rel",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                "The latest time of the recipient(s) to submit the Reply MM.",
                HFILL
            }
        },
        {   &hf_mmse_reply_charging_id,
            {   "X-Mms-Reply-Charging-Id", "mmse.reply_charging_id",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Unique reply charging identification of the message.",
                HFILL
            }
        },
        {   &hf_mmse_reply_charging_size,
            {   "X-Mms-Reply-Charging-Size", "mmse.reply_charging_size",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "The size of the reply charging in octets.",
                HFILL
            }
        },
        {   &hf_mmse_prev_sent_by,
            {   "X-Mms-Previously-Sent-By", "mmse.previously_sent_by",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Indicates that the MM has been previously sent by this user.",
                HFILL
            }
        },
        {   &hf_mmse_prev_sent_by_fwd_count,
            {   "Forward Count", "mmse.previously_sent_by.forward_count",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Forward count of the previously sent MM.",
                HFILL
            }
        },
        {   &hf_mmse_prev_sent_by_address,
            {   "Address", "mmse.previously_sent_by.address",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Indicates from whom the MM has been previously sent.",
                HFILL
            }
        },
        {   &hf_mmse_prev_sent_date,
            {   "X-Mms-Previously-Sent-Date", "mmse.previously_sent_date",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Indicates the date that the MM has been previously sent.",
                HFILL
            }
        },
        {   &hf_mmse_prev_sent_date_fwd_count,
            {   "Forward Count", "mmse.previously_sent_date.forward_count",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Forward count of the previously sent MM.",
                HFILL
            }
        },
        {   &hf_mmse_prev_sent_date_date,
            {   "Date", "mmse.previously_sent_date.date",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Time when the MM has been previously sent.",
                HFILL
            }
        },
        {   &hf_mmse_header_uint,
            {   "Header Uint Value", "mmse.header.uint",
                FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
            }
        },
        {   &hf_mmse_header_string,
            {   "Header String Value", "mmse.header.string",
                FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },
        {   &hf_mmse_header_bytes,
            {   "Header Byte array", "mmse.header.bytes",
                FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },


    };
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mmse,
        &ett_mmse_hdr_details,
    };

    static ei_register_info ei[] = {
        { &ei_mmse_oversized_uintvar, { "mmse.oversized_uintvar", PI_MALFORMED, PI_ERROR, "Uintvar is oversized", EXPFILL }}
    };

    expert_module_t* expert_mmse;

        /* Register the protocol name and description */
    proto_mmse = proto_register_protocol("MMS Message Encapsulation",
                                         "MMSE", "mmse");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_mmse, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_mmse = expert_register_protocol(proto_mmse);
    expert_register_field_array(expert_mmse, ei, array_length(ei));
}

/* If this dissector uses sub-dissector registration add registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_mmse(void)
{
    dissector_handle_t mmse_standalone_handle;
    dissector_handle_t mmse_encapsulated_handle;

    heur_dissector_add("wsp", dissect_mmse_heur, "MMS Message Encapsulation over WSP", "mmse_wsp", proto_mmse, HEURISTIC_ENABLE);
    mmse_standalone_handle = create_dissector_handle(
            dissect_mmse_standalone, proto_mmse);
    mmse_encapsulated_handle = create_dissector_handle(
            dissect_mmse_encapsulated, proto_mmse);
        /* As the media types for WSP and HTTP are the same, the WSP dissector
         * uses the same string dissector table as the HTTP protocol. */
    dissector_add_string("media_type",
            "application/vnd.wap.mms-message", mmse_standalone_handle);
    dissector_add_string("multipart_media_type",
            "application/vnd.wap.mms-message", mmse_encapsulated_handle);
}

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
