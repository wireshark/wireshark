/* packet-dcm.c
 * Routines for DICOM dissection
 * Copyright 2003, Rich Coe <richcoe2@gmail.com>
 * Copyright 2008-2019, David Aggeler <david_aggeler@hispeed.ch>
 *
 * DICOM communication protocol: https://www.dicomstandard.org/current/
 *
 * Part  5: Data Structures and Encoding
 * Part  6: Data Dictionary
 * Part  7: Message Exchange
 * Part  8: Network Communication Support for Message Exchange
 * Part 10: Media Storage and File Format
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/*
 *
 * ToDo
 *
 * - Implement value multiplicity (VM) consistently in dissect_dcm_tag_value()
 * - Syntax detection, in case an association request is missing in capture
 * - Read private tags from configuration and parse in capture
 *
 * History
 *
 * Feb 2019 - David Aggeler
 *
 * - Fixed re-assembly and export (consolidated duplicate code)
 * - Fixed random COL_INFO issues
 * - Improved COL_INFO for C-FIND
 * - Improved COL_INFO for multiple PDUs in one frame
 *
 * Feb 2019 - Rickard Holmberg
 *
 * - Updated DICOM definitions to 2019a
 *
 * Oct 2018 - Rickard Holmberg
 *
 * - Moved DICOM definitions to packet-dcm.h
 * - Generate definitions from docbook with Phyton script
 * - Updated DICOM definitions to 2018e
 *
 * June 2018 - David Aggeler
 *
 * - Fixed initial COL_INFO for associations. It used to 'append' instead of 'set'.
 * - Changed initial length check from tvb_reported_length() to tvb_captured_length()
 * - Heuristic Dissection:
 *   o Modified registration, so it can be clearly identified in the Enable/Disable Protocols dialog
 *   o Enabled by default
 *   o Return proper data type
 *
 * February 2018 - David Aggeler
 *
 * - Fixed Bug 14415. Some tag descriptions which are added to the parent item (32 tags).
 *   If one of those was empty a crash occurred. Mainly the RTPlan modality was affected.
 * - Fixed length decoding for OD, OL, UC, UR
 * - Fixed hf_dcm_assoc_item_type to be interpreted as 1 byte
 * - Fixed pdu_type to be interpreted as 1 byte
 * - Fixed decoding of AT type, where value length was wrongly reported in capture as 2 (instead of n*4)
 *
 * Misc. authors & dates
 *
 * - Fixed 'AT' value representation. The 'element' was equal to the 'group'.
 * - Changed 'FL' value representations
 *
 * September 2013 - Pascal Quantin
 *
 * - Replace all ep_ and se_ allocation with wmem_ allocations
 *
 * February 2013 - Stefan Allers
 *
 * - Support for dissection of Extended Negotiation (Query/Retrieve)
 * - Support for dissection of SCP/SCU Role Selection
 * - Support for dissection of Async Operations Window Negotiation
 * - Fixed: Improper calculation of length for Association Header
 * - Missing UIDs (Transfer Syntax, SOP Class...) added acc. PS 3.x-2011
 *
 * Jul 11, 2010 - David Aggeler
 *
 * - Finally, better reassembly using fragment_add_seq_next().
 *   The previous mode is still supported.
 * - Fixed sporadic decoding and export issues. Always decode
 *   association negotiation, since performance check (tree==NULL)
 *   is now only in dissect_dcm_pdv_fragmented().
 * - Added one more PDV length check
 * - Show Association Headers as individual items
 * - Code cleanup. i.e. moved a few lookup functions to be closer to the dissection
 *
 * May 13, 2010 - David Aggeler (SVN 32815)
 *
 * - Fixed HF to separate signed & unsigned values and to have BASE_DEC all signed ones
 * - Fixed private sequences with undefined length in ILE
 * - Fixed some spellings in comments
 *
 * May 27, 2009 - David Aggeler (SVN 29060)
 *
 * - Fixed corrupt files on DICOM Export
 * - Fixed memory limitation on DICOM Export
 * - Removed minimum packet length for static port mode
 * - Simplified checks for heuristic mode
 * - Removed unused functions
 *
 * May 17, 2009 - David Aggeler (SVN 28392)
 *
 * - Spelling
 * - Added expert_add_info() for status responses with warning & error level
 * - Added command details in info column (optionally)
 *
 * Dec 19, 2008 to Mar 29, 2009 - Misc (SVN 27880)
 *
 * - Spellings, see SVN
 *
 * Oct 26, 2008 - David Aggeler (SVN 26662)
 *
 * - Support remaining DICOM/ARCNEMA tags
 *
 * Oct 3, 2008 - David Aggeler (SVN 26417)
 *
 * - DICOM Tags: Support all tags, except for group 1000, 7Fxx
 *               and tags (0020,3100 to 0020, 31FF).
 *               Luckily these ones are retired anyhow
 * - DICOM Tags: Optionally show sequences, items and tags as subtree
 * - DICOM Tags: Certain items do have a summary of a few contained tags
 * - DICOM Tags: Support all defined VR representations
 * - DICOM Tags: For Explicit Syntax, use VR in the capture
 * - DICOM Tags: Lookup UIDs
 * - DICOM Tags: Handle split at PDV start and end. RT Structures were affected by this.
 * - DICOM Tags: Handle split in tag header
 *
 * - Added all status messages from PS 3.4 & PS 3.7
 * - Fixed two more type warnings on solaris, i.e. (gchar *)tvb_get_ephemeral_string
 * - Replaced all ep_alloc() with ep_alloc0() and se_alloc() with se_alloc0()
 * - Replaced g_strdup with ep_strdup() or se_strdup()
 * - Show multiple PDU description in COL_INFO, not just last one. Still not all, but more
 *   sophisticated logic for this column is probably overkill
 * - Since DICOM is a 32 bit protocol with all length items specified unsigned
 *   all offset & position variables are now declared as guint32 for dissect_dcm_pdu and
 *   its nested functions. dissect_dcm_main() remained by purpose on int,
 *   since we request data consolidation, requiring a TRUE as return value
 * - Decode DVTk streams when using defined ports (not in heuristic mode)
 * - Changed to warning level 4 (for MSVC) and fixed the warnings
 * - Code cleanup & removed last DISSECTOR_ASSERT()
 *
 * Jul 25, 2008 - David Aggeler (SVN 25834)
 *
 * - Replaced guchar with gchar, since it caused a lot of warnings on solaris.
 * - Moved a little more form the include to this one to be consistent
 *
 * Jul 17, 2008 - David Aggeler
 *
 * - Export objects as part 10 compliant DICOM file. Finally, this major milestone has been reached.
 * - PDVs are now a child of the PCTX rather than the ASSOC object.
 * - Fixed PDV continuation for unknown tags (e.g. RT Structure Set)
 * - Replaced proprietary trim() with g_strstrip()
 * - Fixed strings that are displayed with /000 (padding of odd length)
 * - Added expert_add_info() for invalid flags and presentation context IDs
 *
 * Jun 17, 2008 - David Aggeler
 *
 * - Support multiple PDVs per PDU
 * - Better summary, in PDV, PDU header and in INFO Column, e.g. show commands like C-STORE
 * - Fixed Association Reject (was working before my changes)
 * - Fixed PDV Continuation with very small packets. Reduced minimum packet length
 *   from 10 to 2 Bytes for PDU Type 4
 * - Fixed PDV Continuation. Last packet was not found correctly.
 * - Fixed compilation warning (build 56 on solaris)
 * - Fixed tree expansion (hf_dcm_xxx)
 * - Added expert_add_info() for Association Reject
 * - Added expert_add_info() for Association Abort
 * - Added expert_add_info() for short PDVs (i.e. last fragment, but PDV is not completed yet)
 * - Clarified and grouped data structures and its related code (dcmItem, dcmState) to have
 *   consistent _new() & _get() functions and to be according to coding conventions
 * - Added more function declaration to be more consistent
 * - All dissect_dcm_xx now have (almost) the same parameter order
 * - Removed DISSECTOR_ASSERT() for packet data errors. Not designed to handle this.
 * - Handle multiple DICOM Associations in a capture correctly, i.e. if presentation contexts are different.
 *
 * May 23, 2008 - David Aggeler
 *
 * - Added Class UID lookup, both in the association and in the transfer
 * - Better hierarchy for items in Association request/response and therefore better overview
 *   This was a major rework. Abstract Syntax & Transfer Syntax are now children
 *   of a presentation context and therefore grouped. User Info is now grouped.
 * - Re-assemble PDVs that span multiple PDUs, i.e fix continuation packets
 *   This caused significant changes to the data structures
 * - Added preference with DICOM TCP ports, to prevent 'stealing' the conversation
 *   i.e. don't just rely on heuristic
 * - Use pinfo->desegment_len instead of tcp_dissect_pdus()
 * - Returns number of bytes parsed
 * - For non DICOM packets, do not allocate any memory anymore,
 * - Added one DISSECTOR_ASSERT() to prevent loop with len==0. More to come
 * - Heuristic search is optional to save resources for non DICOM users
 *
 * - Output naming closer to DICOM Standard
 * - Variable names closer to Standard
 * - Protocol in now called DICOM not dcm anymore.
 * - Fixed type of a few variables to guchar instead of guint8
 * - Changed some of the length displays to decimal, because the hex value can
 *   already be seen in the packet and decimal is easier for length calculation
 *   in respect to TCP
 *
 * Apr 28, 2005 - Rich Coe
 *
 * - fix memory leak when Assoc packet is processed repeatedly in wireshark
 * - removed unused partial packet flag
 * - added better support for DICOM VR
 *      - sequences
 *      - report actual VR in packet display, if supplied by xfer syntax
 *      - show that we are not displaying entire tag string with '[...]',
 *        some tags can hold up to 2^32-1 chars
 *
 * - remove my goofy attempt at trying to get access to the fragmented packets
 * - process all the data in the Assoc packet even if display is off
 * - limit display of data in Assoc packet to defined size of the data even
 *   if reported size is larger
 * - show the last tag in a packet as [incomplete] if we don't have all the data
 * - added framework for reporting DICOM async negotiation (not finished)
 *   (I'm not aware of an implementation which currently supports this)
 *
 * Nov 9, 2004 - Rich Coe
 *
 * - Fixed the heuristic code -- sometimes a conversation already exists
 * - Fixed the dissect code to display all the tags in the PDU
 *
 * Initial - Rich Coe
 *
 * - It currently displays most of the DICOM packets.
 * - I've used it to debug Query/Retrieve, Storage, and Echo protocols.
 * - Not all DICOM tags are currently displayed symbolically.
 *   Unknown tags are displayed as '(unknown)'
 *   More known tags might be added in the future.
 *   If the tag data contains a string, it will be displayed.
 *   Even if the tag contains Explicit VR, it is not currently used to
 *   symbolically display the data.
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/reassemble.h>
#include <epan/export_object.h>

#include "packet-tcp.h"

#include "packet-dcm.h"

void proto_register_dcm(void);
void proto_reg_handoff_dcm(void);

#define DICOM_DEFAULT_RANGE "104"

/* Many thanks to http://medicalconnections.co.uk/ for the GUID */
#define WIRESHARK_IMPLEMENTATION_UID                    "1.2.826.0.1.3680043.8.427.10"
#define WIRESHARK_MEDIA_STORAGE_SOP_CLASS_UID           "1.2.826.0.1.3680043.8.427.11.1"
#define WIRESHARK_MEDIA_STORAGE_SOP_INSTANCE_UID_PREFIX "1.2.826.0.1.3680043.8.427.11.2"
#define WIRESHARK_IMPLEMENTATION_VERSION                "WIRESHARK"

static gboolean global_dcm_export_header = TRUE;
static guint    global_dcm_export_minsize = 4096;           /* Filter small objects in export */

static gboolean global_dcm_seq_subtree = TRUE;
static gboolean global_dcm_tag_subtree = FALSE;             /* Only useful for debugging */
static gboolean global_dcm_cmd_details = TRUE;              /* Show details in header and info column */
static gboolean global_dcm_reassemble = TRUE;               /* Merge fragmented PDVs */

static wmem_map_t *dcm_tag_table = NULL;
static wmem_map_t *dcm_uid_table = NULL;
static wmem_map_t *dcm_status_table = NULL;

/* Initialize the protocol and registered fields */
static int proto_dcm = -1;

static int dicom_eo_tap = -1;

static int hf_dcm_pdu_type = -1;
static int hf_dcm_pdu_len = -1;
static int hf_dcm_assoc_version = -1;
static int hf_dcm_assoc_called = -1;
static int hf_dcm_assoc_calling = -1;
static int hf_dcm_assoc_reject_result = -1;
static int hf_dcm_assoc_reject_source = -1;
static int hf_dcm_assoc_reject_reason = -1;
static int hf_dcm_assoc_abort_source = -1;
static int hf_dcm_assoc_abort_reason = -1;
static int hf_dcm_assoc_item_type = -1;
static int hf_dcm_assoc_item_len = -1;
static int hf_dcm_actx = -1;
static int hf_dcm_pctx_id = -1;
static int hf_dcm_pctx_result = -1;
static int hf_dcm_pctx_abss_syntax = -1;
static int hf_dcm_pctx_xfer_syntax = -1;
static int hf_dcm_info = -1;
static int hf_dcm_info_uid = -1;
static int hf_dcm_info_version = -1;
static int hf_dcm_info_extneg = -1;
static int hf_dcm_info_extneg_sopclassuid_len = -1;
static int hf_dcm_info_extneg_sopclassuid = -1;
static int hf_dcm_info_extneg_relational_query = -1;
static int hf_dcm_info_extneg_date_time_matching = -1;
static int hf_dcm_info_extneg_fuzzy_semantic_matching = -1;
static int hf_dcm_info_extneg_timezone_query_adjustment = -1;
static int hf_dcm_info_rolesel = -1;
static int hf_dcm_info_rolesel_sopclassuid_len = -1;
static int hf_dcm_info_rolesel_sopclassuid = -1;
static int hf_dcm_info_rolesel_scurole = -1;
static int hf_dcm_info_rolesel_scprole = -1;
static int hf_dcm_info_async_neg = -1;
static int hf_dcm_info_async_neg_max_num_ops_inv = -1;
static int hf_dcm_info_async_neg_max_num_ops_per = -1;
static int hf_dcm_info_user_identify = -1;
static int hf_dcm_info_user_identify_type = -1;
static int hf_dcm_info_user_identify_response_requested = -1;
static int hf_dcm_info_user_identify_primary_field_length = -1;
static int hf_dcm_info_user_identify_primary_field = -1;
static int hf_dcm_info_user_identify_secondary_field_length = -1;
static int hf_dcm_info_user_identify_secondary_field = -1;
static int hf_dcm_info_unknown = -1;
static int hf_dcm_assoc_item_data = -1;
static int hf_dcm_pdu_maxlen = -1;
static int hf_dcm_pdv_len = -1;
static int hf_dcm_pdv_ctx = -1;
static int hf_dcm_pdv_flags = -1;
static int hf_dcm_data_tag = -1;
static int hf_dcm_tag = -1;
static int hf_dcm_tag_vr = -1;
static int hf_dcm_tag_vl = -1;
static int hf_dcm_tag_value_str = -1;
static int hf_dcm_tag_value_16u = -1;
static int hf_dcm_tag_value_16s = -1;
static int hf_dcm_tag_value_32s = -1;
static int hf_dcm_tag_value_32u = -1;
static int hf_dcm_tag_value_byte = -1;

/* Initialize the subtree pointers */
static gint ett_dcm = -1;
static gint ett_assoc = -1;
static gint ett_assoc_header = -1;
static gint ett_assoc_actx = -1;
static gint ett_assoc_pctx = -1;
static gint ett_assoc_pctx_abss = -1;
static gint ett_assoc_pctx_xfer = -1;
static gint ett_assoc_info = -1;
static gint ett_assoc_info_uid = -1;
static gint ett_assoc_info_version = -1;
static gint ett_assoc_info_extneg = -1;
static gint ett_assoc_info_rolesel = -1;
static gint ett_assoc_info_async_neg = -1;
static gint ett_assoc_info_user_identify = -1;
static gint ett_assoc_info_unknown = -1;
static gint ett_dcm_data = -1;
static gint ett_dcm_data_pdv = -1;
static gint ett_dcm_data_tag = -1;
static gint ett_dcm_data_seq = -1;
static gint ett_dcm_data_item = -1;

static expert_field ei_dcm_data_tag = EI_INIT;
static expert_field ei_dcm_multiple_transfer_syntax = EI_INIT;
static expert_field ei_dcm_pdv_len = EI_INIT;
static expert_field ei_dcm_pdv_flags = EI_INIT;
static expert_field ei_dcm_pdv_ctx = EI_INIT;
static expert_field ei_dcm_no_abstract_syntax = EI_INIT;
static expert_field ei_dcm_no_abstract_syntax_uid = EI_INIT;
static expert_field ei_dcm_status_msg = EI_INIT;
static expert_field ei_dcm_no_transfer_syntax = EI_INIT;
static expert_field ei_dcm_multiple_abstract_syntax = EI_INIT;
static expert_field ei_dcm_invalid_pdu_length = EI_INIT;
static expert_field ei_dcm_assoc_item_len = EI_INIT;
static expert_field ei_dcm_assoc_rejected = EI_INIT;
static expert_field ei_dcm_assoc_aborted = EI_INIT;

static dissector_handle_t dcm_handle;

static const value_string dcm_pdu_ids[] = {
    { 1, "ASSOC Request" },
    { 2, "ASSOC Accept" },
    { 3, "ASSOC Reject" },
    { 4, "Data" },
    { 5, "RELEASE Request" },
    { 6, "RELEASE Response" },
    { 7, "ABORT" },
    { 0, NULL }
};

static const value_string dcm_assoc_item_type[] = {
    { 0x10, "Application Context" },
    { 0x20, "Presentation Context" },
    { 0x21, "Presentation Context Reply" },
    { 0x30, "Abstract Syntax" },
    { 0x40, "Transfer Syntax" },
    { 0x50, "User Info" },
    { 0x51, "Max Length" },
    { 0x52, "Implementation Class UID" },
    { 0x53, "Asynchronous Operations Window Negotiation" },
    { 0x54, "SCP/SCU Role Selection" },
    { 0x55, "Implementation Version" },
    { 0x56, "SOP Class Extended Negotiation" },
    { 0x58, "User Identity" },
    { 0, NULL }
};

static const value_string user_identify_type_vals[] = {
    { 1, "Username as a string in UTF-8" },
    { 2, "Username as a string in UTF-8 and passcode" },
    { 3, "Kerberos Service ticket" },
    { 4, "SAML Assertion" },
    { 0, NULL }
};

/* Used for DICOM Export Object feature */
typedef struct _dicom_eo_t {
    guint32  pkt_num;
    gchar   *hostname;
    gchar   *filename;
    gchar   *content_type;
    guint32  payload_len;
    guint8  *payload_data;
} dicom_eo_t;

static tap_packet_status
dcm_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
                const void *data, tap_flags_t flags _U_)
{
    export_object_list_t *object_list = (export_object_list_t *)tapdata;
    const dicom_eo_t *eo_info = (const dicom_eo_t *)data;
    export_object_entry_t *entry;

    if (eo_info) { /* We have data waiting for us */
        /*
           Don't copy any data. dcm_export_create_object() is already g_malloc() the items
           Still, the values will be freed when the export Object window is closed.
           Therefore, strings and buffers must be copied
        */
        entry = g_new(export_object_entry_t, 1);

        entry->pkt_num = pinfo->num;
        entry->hostname = eo_info->hostname;
        entry->content_type = eo_info->content_type;
        entry->filename = g_path_get_basename(eo_info->filename);
        entry->payload_len  = eo_info->payload_len;
        entry->payload_data = eo_info->payload_data;

        object_list->add_entry(object_list->gui_data, entry);

        return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
    } else {
        return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
    }
}


/* ************************************************************************* */
/*                  Fragment items                                           */
/* ************************************************************************* */

/* Initialize the subtree pointers */
static gint ett_dcm_pdv = -1;

static gint ett_dcm_pdv_fragment = -1;
static gint ett_dcm_pdv_fragments = -1;

static int hf_dcm_pdv_fragments = -1;
static int hf_dcm_pdv_fragment = -1;
static int hf_dcm_pdv_fragment_overlap = -1;
static int hf_dcm_pdv_fragment_overlap_conflicts = -1;
static int hf_dcm_pdv_fragment_multiple_tails = -1;
static int hf_dcm_pdv_fragment_too_long_fragment = -1;
static int hf_dcm_pdv_fragment_error = -1;
static int hf_dcm_pdv_fragment_count = -1;
static int hf_dcm_pdv_reassembled_in = -1;
static int hf_dcm_pdv_reassembled_length = -1;

static const fragment_items dcm_pdv_fragment_items = {
    /* Fragment subtrees */
    &ett_dcm_pdv_fragment,
    &ett_dcm_pdv_fragments,
    /* Fragment fields */
    &hf_dcm_pdv_fragments,
    &hf_dcm_pdv_fragment,
    &hf_dcm_pdv_fragment_overlap,
    &hf_dcm_pdv_fragment_overlap_conflicts,
    &hf_dcm_pdv_fragment_multiple_tails,
    &hf_dcm_pdv_fragment_too_long_fragment,
    &hf_dcm_pdv_fragment_error,
    &hf_dcm_pdv_fragment_count,
    &hf_dcm_pdv_reassembled_in,
    &hf_dcm_pdv_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

/* Structure to handle fragmented DICOM PDU packets */
static reassembly_table dcm_pdv_reassembly_table;

typedef struct dcm_open_tag {

    /* Contains information about an open tag in a PDV, in case it was not complete.

       This implementation differentiates between open headers (grm, elm, vr, vl) and
       open values. This data structure will handle both cases.

       Open headers are not shown in the packet where the tag starts, but only in the next PDV.
       Open values are shown in the packet where the tag starts, with <Byte 1-n> as the value

       The same PDV can close an open tag from a previous PDV at the beginning
       and at the same have time open a new tag at the end. The closing part at the beginning
       does not have its own persistent data.

       Do not overwrite the values, once defined, to save some memory.

       Since PDVs are always n*2 bytes, store each of the 2 Bytes in a variable.
       This way, we don't need to call tvb_get_xxx on a self created buffer

    */

    gboolean    is_header_fragmented;
    gboolean    is_value_fragmented;

    guint32     len_decoded;    /* Should only be < 16 bytes                */

    guint16     grp;            /* Already decoded group                    */
    guint16     elm;            /* Already decoded element                  */
    gchar      *vr;             /* Already decoded VR                       */

    gboolean    is_vl_long;     /* If TRUE, Value Length is 4 Bytes, otherwise 2 */
    guint16     vl_1;           /* Partially decoded 1st two bytes of length  */
    guint16     vl_2;           /* Partially decoded 2nd two bytes of length  */

    /* These ones are, where the value was truncated */
    guint32 len_total;          /* Tag length of 'over-sized' tags. Used for display */
    guint32 len_remaining;      /* Remaining tag bytes to 'decoded' as binary data after this PDV */

    gchar  *desc;               /* Last decoded description */

} dcm_open_tag_t;

/*
    Per Data PDV store data needed, to allow decoding of tags longer than a PDV
*/
typedef struct dcm_state_pdv {

    struct dcm_state_pdv *next, *prev;

    guint32  packet_no;         /* Wireshark packet number, where pdv starts */
    guint32  offset;            /* Offset in packet, where PDV header starts */

    gchar   *desc;              /* PDV description. wmem_file_scope() */

    guint8  pctx_id;            /* Reference to used Presentation Context */

    /* Following is derived from the transfer syntax in the parent PCTX, except for Command PDVs */
    guint8  syntax;

    /* Used and filled for Export Object only */
    gpointer data;              /* Copy of PDV data without any PDU/PDV header */
    guint32  data_len;          /* Length of this PDV buffer. If >0, memory has been allocated */

    gchar   *sop_class_uid;     /* SOP Class UID.    Set in 1st PDV of a DICOM object. wmem_file_scope() */
    gchar   *sop_instance_uid;  /* SOP Instance UID. Set in 1st PDV of a DICOM object. wmem_file_scope() */
    /* End Export use */

    gboolean is_storage;        /* True, if the Data PDV is on the context of a storage SOP Class */
    gboolean is_flagvalid;      /* The following two flags are initialized correctly */
    gboolean is_command;        /* This PDV is a command rather than a data package */
    gboolean is_last_fragment;  /* Last Fragment bit was set, i.e. termination of an object
                                   This flag delimits different DICOM object in the same association */
    gboolean is_corrupt;        /* Early termination of long PDVs */

                                /* The following five attributes are only used for command PDVs */

    gchar   *command;           /* Decoded command as text */
    gchar   *status;            /* Decoded status as text */
    gchar   *comment;           /* Error comment, if any */

    gboolean is_warning;        /* Command response is a cancel, warning, error */
    gboolean is_pending;        /* Command response is 'Current Match is supplied. Sub-operations are continuing' */

    guint16  message_id;        /* (0000,0110) Message ID */
    guint16  message_id_resp;   /* (0000,0120) Message ID being responded to */

    guint16  no_remaining;      /* (0000,1020) Number of remaining sub-operations */
    guint16  no_completed;      /* (0000,1021) Number of completed sub-operations */
    guint16  no_failed;         /* (0000,1022) Number of failed sub-operations  */
    guint16  no_warning;        /* (0000,1023) Number of warning sub-operations */

    dcm_open_tag_t  open_tag;   /* Container to store information about a fragmented tag */

    guint8 reassembly_id;

} dcm_state_pdv_t;

/*
Per Presentation Context in an association store data needed, for subsequent decoding
*/
typedef struct dcm_state_pctx {

    struct dcm_state_pctx *next, *prev;

    guint8 id;                  /* 0x20 Presentation Context ID */
    gchar *abss_uid;            /* 0x30 Abstract syntax */
    gchar *abss_desc;           /* 0x30 Abstract syntax decoded*/
    gchar *xfer_uid;            /* 0x40 Accepted Transfer syntax */
    gchar *xfer_desc;           /* 0x40 Accepted Transfer syntax decoded*/
    guint8 syntax;              /* Decoded transfer syntax */
#define DCM_ILE  0x01           /* implicit, little endian */
#define DCM_EBE  0x02           /* explicit, big endian */
#define DCM_ELE  0x03           /* explicit, little endian */
#define DCM_UNK  0xf0

    guint8 reassembly_count;
    dcm_state_pdv_t     *first_pdv,  *last_pdv;         /* List of PDV objects */

} dcm_state_pctx_t;


typedef struct dcm_state_assoc {

    struct dcm_state_assoc *next, *prev;

    dcm_state_pctx_t    *first_pctx, *last_pctx;        /* List of Presentation context objects */

    guint32 packet_no;                  /* Wireshark packet number, where association starts */

    char *ae_called;                    /* Called  AE title in A-ASSOCIATE RQ */
    char *ae_calling;                   /* Calling AE title in A-ASSOCIATE RQ */
    char *ae_called_resp;               /* Called  AE title in A-ASSOCIATE RP */
    char *ae_calling_resp;              /* Calling AE title in A-ASSOCIATE RP */

} dcm_state_assoc_t;

typedef struct dcm_state {

    struct dcm_state_assoc *first_assoc, *last_assoc;

    gboolean valid;                     /* this conversation is a DICOM conversation */

} dcm_state_t;


/* ---------------------------------------------------------------------
 * DICOM Status Value Definitions
 *
 * Collected from PS 3.7 & 3.4
 *
*/

typedef struct dcm_status {
    const guint16 value;
    const gchar *description;
} dcm_status_t;

static dcm_status_t dcm_status_data[] = {

    /* From PS 3.7 */

    { 0x0000,   "Success"},
    { 0x0105,   "No such attribute"},
    { 0x0106,   "Invalid attribute value"},
    { 0x0107,   "Attribute list error"},
    { 0x0110,   "Processing failure"},
    { 0x0111,   "Duplicate SOP instance"},
    { 0x0112,   "No Such object instance"},
    { 0x0113,   "No such event type"},
    { 0x0114,   "No such argument"},
    { 0x0115,   "Invalid argument value"},
    { 0x0116,   "Attribute Value Out of Range"},
    { 0x0117,   "Invalid object instance"},
    { 0x0118,   "No Such SOP class"},
    { 0x0119,   "Class-instance conflict"},
    { 0x0120,   "Missing attribute"},
    { 0x0121,   "Missing attribute value"},
    { 0x0122,   "Refused: SOP class not supported"},
    { 0x0123,   "No such action type"},
    { 0x0210,   "Duplicate invocation"},
    { 0x0211,   "Unrecognized operation"},
    { 0x0212,   "Mistyped argument"},
    { 0x0213,   "Resource limitation"},
    { 0xFE00,   "Cancel"},

    /* from PS 3.4 */

    { 0x0001,   "Requested optional Attributes are not supported"},
    { 0xA501,   "Refused because General Purpose Scheduled Procedure Step Object may no longer be updated"},
    { 0xA502,   "Refused because the wrong Transaction UID is used"},
    { 0xA503,   "Refused because the General Purpose Scheduled Procedure Step SOP Instance is already in the 'IN PROGRESS' state"},
    { 0xA504,   "Refused because the related General Purpose Scheduled Procedure Step SOP Instance is not in the 'IN PROGRESS' state"},
    { 0xA505,   "Refused because Referenced General Purpose Scheduled Procedure Step Transaction UID does not match the Transaction UID of the N-ACTION request"},
    { 0xA510,   "Refused because an Initiate Media Creation action has already been received for this SOP Instance"},
    { 0xA700,   "Refused: Out of Resources"},
    { 0xA701,   "Refused: Out of Resources - Unable to calculate number of matches"},
    { 0xA702,   "Refused: Out of Resources - Unable to perform sub-operations"},
    /*
    { 0xA7xx,   "Refused: Out of Resources"},
    */
    { 0xA801,   "Refused: Move Destination unknown"},
    /*
    { 0xA9xx,   "Error: Data Set does not match SOP Class"},
    */
    { 0xB000,   "Sub-operations Complete - One or more Failures"},
    { 0xB006,   "Elements Discarded"},
    { 0xB007,   "Data Set does not match SOP Class"},
    { 0xB101,   "Specified Synchronization Frame of Reference UID does not match SCP Synchronization Frame of Reference"},
    { 0xB102,   "Study Instance UID coercion; Event logged under a different Study Instance UID"},
    { 0xB104,   "IDs inconsistent in matching a current study; Event logged"},
    { 0xB605,   "Requested Min Density or Max Density outside of printer's operating range. The printer will use its respective minimum or maximum density value instead"},
    { 0xC000,   "Error: Cannot understand/Unable to process"},
    { 0xC100,   "More than one match found"},
    { 0xC101,   "Procedural Logging not available for specified Study Instance UID"},
    { 0xC102,   "Event Information does not match Template"},
    { 0xC103,   "Cannot match event to a current study"},
    { 0xC104,   "IDs inconsistent in matching a current study; Event not logged"},
    { 0xC200,   "Unable to support requested template"},
    { 0xC201,   "Media creation request already completed"},
    { 0xC202,   "Media creation request already in progress and cannot be interrupted"},
    { 0xC203,   "Cancellation denied for unspecified reason"},
    /*
    { 0xCxxx,   "Error: Cannot understand/Unable to Process"},
    { 0xFE00,   "Matching/Sub-operations terminated due to Cancel request"},
    */
    { 0xFF00,   "Current Match is supplied. Sub-operations are continuing"},
    { 0xFF01,   "Matches are continuing - Warning that one or more Optional Keys were not supported for existence for this Identifier"}

};


/* following definitions are used to call dissect_dcm_assoc_item() */
#define DCM_ITEM_VALUE_TYPE_UID     1
#define DCM_ITEM_VALUE_TYPE_STRING  2
#define DCM_ITEM_VALUE_TYPE_UINT32  3

/* And from here on, only use unsigned 32 bit values. Offset is always positive number in respect to the tvb buffer start */
static guint32  dissect_dcm_pdu     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset);

static guint32  dissect_dcm_assoc_detail(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,   dcm_state_assoc_t *assoc, guint32 offset, guint32 len);

static guint32 dissect_dcm_tag_value(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, dcm_state_pdv_t * pdv, guint32 offset, guint16 grp, guint16 elm, guint32 vl, guint32 vl_max, const gchar * vr, gchar ** tag_value);

static void
dcm_init(void)
{
    guint   i;

    /* Create three hash tables for quick lookups */
    /* Add UID objects to hash table */
    dcm_uid_table = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
    for (i = 0; i < array_length(dcm_uid_data); i++) {
        wmem_map_insert(dcm_uid_table, (gpointer) dcm_uid_data[i].value,
        (gpointer) &dcm_uid_data[i]);
    }

    /* Add Tag objects to hash table */
    dcm_tag_table = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    for (i = 0; i < array_length(dcm_tag_data); i++) {
        wmem_map_insert(dcm_tag_table, GUINT_TO_POINTER(dcm_tag_data[i].tag),
        (gpointer) &dcm_tag_data[i]);
    }

   /* Add Status Values to hash table */
    dcm_status_table = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    for (i = 0; i < array_length(dcm_status_data); i++) {
        wmem_map_insert(dcm_status_table, GUINT_TO_POINTER((guint32)dcm_status_data[i].value),
        (gpointer)&dcm_status_data[i]);
    }
}

/*
Get or create conversation and DICOM data structure if desired.
Return new or existing DICOM structure, which is used to store context IDs and transfer syntax.
Return NULL in case of the structure couldn't be created.
*/
static dcm_state_t *
dcm_state_get(packet_info *pinfo, gboolean create)
{

    conversation_t  *conv;
    dcm_state_t     *dcm_data;

    conv = find_or_create_conversation(pinfo);
    dcm_data = (dcm_state_t *)conversation_get_proto_data(conv, proto_dcm);

    if (dcm_data == NULL && create) {

        dcm_data =  wmem_new0(wmem_file_scope(), dcm_state_t);
        conversation_add_proto_data(conv, proto_dcm, dcm_data);

        /*  Mark it as DICOM conversation. Needed for the heuristic mode,
            to prevent stealing subsequent packets by other dissectors
        */
        conversation_set_dissector(conv, dcm_handle);
    }

    return dcm_data;
}


static dcm_state_assoc_t *
dcm_state_assoc_new(dcm_state_t *dcm_data, guint32 packet_no)
{
    /* Create new association object and initialize the members */

    dcm_state_assoc_t *assoc;

    assoc = wmem_new0(wmem_file_scope(), dcm_state_assoc_t);
    assoc->packet_no = packet_no;           /* Identifier */

    /* add to the end of the list */
    if (dcm_data->last_assoc) {
        dcm_data->last_assoc->next = assoc;
        assoc->prev = dcm_data->last_assoc;
    }
    else {
        dcm_data->first_assoc = assoc;
    }
    dcm_data->last_assoc = assoc;
    return assoc;
}

/*
Find or create association object based on packet number. Return NULL, if association was not found.
*/
static dcm_state_assoc_t *
dcm_state_assoc_get(dcm_state_t *dcm_data, guint32 packet_no, gboolean create)
{

    dcm_state_assoc_t *assoc = dcm_data->first_assoc;

    while (assoc) {

        if (assoc->next) {
            /* we have more associations in the same stream */
            if ((assoc->packet_no <= packet_no) && (packet_no < assoc->next->packet_no))
                break;
        }
        else {
            /* last or only associations in the same stream */
            if (assoc->packet_no <= packet_no)
                break;
        }
        assoc = assoc->next;
    }

    if (assoc == NULL && create) {
        assoc = dcm_state_assoc_new(dcm_data, packet_no);
    }
    return assoc;
}

static dcm_state_pctx_t *
dcm_state_pctx_new(dcm_state_assoc_t *assoc, guint8 pctx_id)
{
    /* Create new presentation context object and initialize the members */

    dcm_state_pctx_t *pctx;

    pctx = wmem_new0(wmem_file_scope(), dcm_state_pctx_t);
    pctx->id = pctx_id;
    pctx->syntax = DCM_UNK;

    /* add to the end of the list list */
    if (assoc->last_pctx) {
        assoc->last_pctx->next = pctx;
        pctx->prev = assoc->last_pctx;
    }
    else {
        assoc->first_pctx = pctx;
    }
    assoc->last_pctx = pctx;

    return pctx;
}

static dcm_state_pctx_t *
dcm_state_pctx_get(dcm_state_assoc_t *assoc, guint8 pctx_id, gboolean create)
{
    /*  Find or create presentation context object. Return NULL, if Context ID was not found */

    dcm_state_pctx_t *pctx = assoc->first_pctx;
    /*
    static char notfound[] = "not found - click on ASSOC Request";
    static dcm_state_pctx_t dunk = { NULL, NULL, FALSE, 0, notfound, notfound, notfound, notfound, DCM_UNK };
    */
    while (pctx) {
        if (pctx->id == pctx_id)
            break;
        pctx = pctx->next;
    }

    if (pctx == NULL && create) {
        pctx = dcm_state_pctx_new(assoc, pctx_id);
    }

    return pctx;
}


/*
Create new PDV object and initialize all members
*/
static dcm_state_pdv_t*
dcm_state_pdv_new(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset)
{
    dcm_state_pdv_t *pdv;

    pdv = wmem_new0(wmem_file_scope(), dcm_state_pdv_t);
    pdv->syntax = DCM_UNK;
    pdv->is_last_fragment = TRUE;       /* Continuation PDVs are more tricky */
    pdv->packet_no = packet_no;
    pdv->offset = offset;

    /* add to the end of the list */
    if (pctx->last_pdv) {
        pctx->last_pdv->next = pdv;
        pdv->prev = pctx->last_pdv;
    }
    else {
        pctx->first_pdv = pdv;
    }
    pctx->last_pdv = pdv;
    return pdv;
}


static dcm_state_pdv_t*
dcm_state_pdv_get(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset, gboolean create)
{
    /*  Find or create PDV object. Return NULL, if PDV was not found, based on packet number and offset */

    dcm_state_pdv_t *pdv = pctx->first_pdv;

    while (pdv) {
        if ((pdv->packet_no == packet_no) && (pdv->offset == offset))
            break;
        pdv = pdv->next;
    }

    if (pdv == NULL && create) {
        pdv = dcm_state_pdv_new(pctx, packet_no, offset);
    }
    return pdv;
}

static dcm_state_pdv_t*
dcm_state_pdv_get_obj_start(dcm_state_pdv_t *pdv_curr)
{

    dcm_state_pdv_t *pdv_first=pdv_curr;

    /* Get First PDV of the DICOM Object */
    while (pdv_first->prev && !pdv_first->prev->is_last_fragment) {
        pdv_first = pdv_first->prev;
    }

    return pdv_first;
}

static const value_string dcm_cmd_vals[] = {
    { 0x0001, "C-STORE-RQ" },
    { 0x0010, "C-GET-RQ" },
    { 0x0020, "C-FIND-RQ" },
    { 0x0021, "C-MOVE-RQ" },
    { 0x0030, "C-ECHO-RQ" },
    { 0x0100, "N-EVENT-REPORT-RQ" },
    { 0x0110, "N-GET-RQ" },
    { 0x0120, "N-SET-RQ" },
    { 0x0130, "N-ACTION-RQ" },
    { 0x0140, "N-CREATE-RQ" },
    { 0x0150, "N-DELETE-RQ" },
    { 0x8001, "C-STORE-RSP" },
    { 0x8010, "C-GET-RSP" },
    { 0x8020, "C-FIND-RSP" },
    { 0x8021, "C-MOVE-RSP" },
    { 0x8030, "C-ECHO-RSP" },
    { 0x8100, "N-EVENT-REPORT-RSP" },
    { 0x8110, "N-GET-RSP" },
    { 0x8120, "N-SET-RSP" },
    { 0x8130, "N-ACTION-RSP" },
    { 0x8140, "N-CREATE-RSP" },
    { 0x8150, "N-DELETE-RSP" },
    { 0x0FFF, "C-CANCEL-RQ" },
    { 0, NULL }
};


/*
Convert the two status bytes into a text based on lookup.

Classification
0x0000          : SUCCESS
0x0001 & Bxxx   : WARNING
0xFE00          : CANCEL
0XFFxx          : PENDING
All other       : FAILURE
*/
static const gchar *
dcm_rsp2str(guint16 status_value)
{

    dcm_status_t    *status = NULL;
    const gchar *s = "";

    /* Use specific text first */
    status = (dcm_status_t*) wmem_map_lookup(dcm_status_table, GUINT_TO_POINTER((guint32)status_value));

    if (status) {
         s = status->description;
    }
    else {

        if ((status_value & 0xFF00) == 0xA700) {
            /* 0xA7xx */
            s = "Refused: Out of Resources";
        }
        else if ((status_value & 0xFF00) == 0xA900) {
            /* 0xA9xx */
            s = "Error: Data Set does not match SOP Class";
        }
        else if ((status_value & 0xF000) == 0xC000) {
            /* 0xCxxx */
            s = "Error: Cannot understand/Unable to Process";
        }
        else {
            /* Encountered at least one case, with status_value == 0xD001 */
            s = "Unknown";
        }
    }

    return s;
}

static const gchar*
dcm_uid_or_desc(gchar *dcm_uid, gchar *dcm_desc)
{
    /* Return Description, UID or error */

    return (dcm_desc == NULL ? (dcm_uid == NULL ? "Malformed Packet" : dcm_uid) : dcm_desc);
}

static void
dcm_set_syntax(dcm_state_pctx_t *pctx, gchar *xfer_uid, const gchar *xfer_desc)
{
    if ((pctx == NULL) || (xfer_uid == NULL) || (xfer_desc == NULL))
        return;

    g_free(pctx->xfer_uid);     /* free prev allocated xfer */
    g_free(pctx->xfer_desc);    /* free prev allocated xfer */

    pctx->syntax = 0;
    pctx->xfer_uid = g_strdup(xfer_uid);
    pctx->xfer_desc = g_strdup(xfer_desc);

    /* this would be faster to skip the common parts, and have a FSA to
     * find the syntax.
     * Absent of coding that, this is in descending order of probability */
    if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2"))
        pctx->syntax = DCM_ILE;  /* implicit little endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.1"))
        pctx->syntax = DCM_ELE;  /* explicit little endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.2"))
        pctx->syntax = DCM_EBE;  /* explicit big endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.113619.5.2"))
        pctx->syntax = DCM_ILE;  /* implicit little endian, big endian pixels, GE private */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.4.70"))
        pctx->syntax = DCM_ELE;  /* explicit little endian, jpeg */
    else if (0 == strncmp(xfer_uid, "1.2.840.10008.1.2.4", 18))
        pctx->syntax = DCM_ELE;  /* explicit little endian, jpeg */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.1.99"))
        pctx->syntax = DCM_ELE;  /* explicit little endian, deflated */
}

static void
dcm_guint16_to_le(guint8 *buffer, guint16 value)
{

    buffer[0]=(guint8) (value & 0x00FF);
    buffer[1]=(guint8)((value & 0xFF00) >> 8);
}

static void
dcm_guint32_to_le(guint8 *buffer, guint32 value)
{

    buffer[0]=(guint8) (value & 0x000000FF);
    buffer[1]=(guint8)((value & 0x0000FF00) >>  8);
    buffer[2]=(guint8)((value & 0x00FF0000) >> 16);
    buffer[3]=(guint8)((value & 0xFF000000) >> 24);

}

static guint32
dcm_export_create_tag_base(guint8 *buffer, guint32 bufflen, guint32 offset,
                           guint16 grp, guint16 elm, guint16 vr,
                           const guint8 *value_buffer, guint32 value_len)
{
    /*  Only Explicit Little Endian is needed to create Metafile Header
        Generic function to write a TAG, VR, LEN & VALUE to a combined buffer
        The value (buffer, len) must be preprocessed by a VR specific function
    */

    if (offset + 6 > bufflen) return bufflen;

    dcm_guint16_to_le(buffer + offset, grp);
    offset += 2;
    dcm_guint16_to_le(buffer + offset, elm);
    offset += 2;
    memmove(buffer + offset, dcm_tag_vr_lookup[vr], 2);
    offset += 2;

    switch (vr) {
    case DCM_VR_OB:
    case DCM_VR_OD:
    case DCM_VR_OF:
    case DCM_VR_OL:
    case DCM_VR_OW:
    case DCM_VR_SQ:
    case DCM_VR_UC:
    case DCM_VR_UR:
    case DCM_VR_UT:
    case DCM_VR_UN:
        /* DICOM likes it complicated. Special handling for these types */

        if (offset + 6 > bufflen) return bufflen;

        /* Add two reserved 0x00 bytes */
        dcm_guint16_to_le(buffer + offset, 0);
        offset += 2;

        /* Length is a 4 byte field */
        dcm_guint32_to_le(buffer + offset, value_len);
        offset += 4;

        break;

    default:
        /* Length is a 2 byte field */
        if (offset + 2 > bufflen) return bufflen;

        dcm_guint16_to_le(buffer + offset, (guint16)value_len);
        offset += 2;
    }

    if (offset + value_len > bufflen) return bufflen;

    memmove(buffer + offset, value_buffer, value_len);
    offset += value_len;

    return offset;
}

static guint32
dcm_export_create_tag_guint16(guint8 *buffer, guint32 bufflen, guint32 offset,
                              guint16 grp, guint16 elm, guint16 vr, guint16 value)
{

    return dcm_export_create_tag_base(buffer, bufflen, offset, grp, elm, vr, (guint8*)&value, 2);
}

static guint32
dcm_export_create_tag_guint32(guint8 *buffer, guint32 bufflen, guint32 offset,
                              guint16 grp, guint16 elm, guint16 vr, guint32 value)
{

    return dcm_export_create_tag_base(buffer, bufflen, offset, grp, elm, vr, (guint8*)&value, 4);
}

static guint32
dcm_export_create_tag_str(guint8 *buffer, guint32 bufflen, guint32 offset,
                          guint16 grp, guint16 elm, guint16 vr,
                          const gchar *value)
{
    guint32 len;

    if (!value) {
        /* NULL object. E.g. happens if UID was not found/set. Don't create element*/
        return offset;
    }

    len=(int)strlen(value);

    if ((len & 0x01) == 1) {
        /*  Odd length: since buffer is 0 initialized, pad with a 0x00 */
        len += 1;
    }

    return dcm_export_create_tag_base(buffer, bufflen, offset, grp, elm, vr, (const guint8 *)value, len);
}


static guint8*
dcm_export_create_header(packet_info *pinfo, guint32 *dcm_header_len, const gchar *sop_class_uid, gchar *sop_instance_uid, gchar *xfer_uid)
{
    guint8      *dcm_header=NULL;
    guint32     offset=0;
    guint32     offset_header_len=0;

#define DCM_HEADER_MAX 512

    dcm_header=(guint8 *)wmem_alloc0(pinfo->pool, DCM_HEADER_MAX);   /* Slightly longer than needed */
                                                      /* The subsequent functions rely on a 0 initialized buffer */
    offset=128;

    memmove(dcm_header+offset, "DICM", 4);
    offset+=4;

    offset_header_len=offset;   /* remember for later */

    offset+=12;

    /*
        (0002,0000)     File Meta Information Group Length  UL
        (0002,0001)     File Meta Information Version       OB
        (0002,0002)     Media Storage SOP Class UID         UI
        (0002,0003)     Media Storage SOP Instance UID      UI
        (0002,0010)     Transfer Syntax UID                 UI
        (0002,0012)     Implementation Class UID            UI
        (0002,0013)     Implementation Version Name         SH
    */

    offset=dcm_export_create_tag_guint16(dcm_header, DCM_HEADER_MAX, offset,
        0x0002, 0x0001, DCM_VR_OB, 0x0100);  /* will result on 00 01 since it is little endian */

    offset=dcm_export_create_tag_str(dcm_header, DCM_HEADER_MAX, offset,
        0x0002, 0x0002, DCM_VR_UI, sop_class_uid);

    offset=dcm_export_create_tag_str(dcm_header, DCM_HEADER_MAX, offset,
        0x0002, 0x0003, DCM_VR_UI, sop_instance_uid);

    offset=dcm_export_create_tag_str(dcm_header, DCM_HEADER_MAX, offset,
        0x0002, 0x0010, DCM_VR_UI, xfer_uid);

    offset=dcm_export_create_tag_str(dcm_header, DCM_HEADER_MAX, offset,
        0x0002, 0x0012, DCM_VR_UI, WIRESHARK_IMPLEMENTATION_UID);

    offset=dcm_export_create_tag_str(dcm_header, DCM_HEADER_MAX, offset,
        0x0002, 0x0013, DCM_VR_SH, WIRESHARK_IMPLEMENTATION_VERSION);

    /* Finally write the meta header length */
    dcm_export_create_tag_guint32(dcm_header, DCM_HEADER_MAX, offset_header_len,
        0x0002, 0x0000, DCM_VR_UL, offset-offset_header_len-12);

    *dcm_header_len=offset;

    return dcm_header;

}


/*
Concatenate related PDVs into one buffer and add it to the export object list.

Supports both modes:

- Multiple DICOM PDVs are reassembled with fragment_add_seq_next()
  and process_reassembled_data(). In this case all data will be in the last
  PDV, and all its predecessors will have zero data.

- DICOM PDVs are keep separate. Every PDV contains data.
*/
static void
dcm_export_create_object(packet_info *pinfo, dcm_state_assoc_t *assoc, dcm_state_pdv_t *pdv)
{

    dicom_eo_t          *eo_info = NULL;

    dcm_state_pdv_t     *pdv_curr = NULL;
    dcm_state_pdv_t     *pdv_same_pkt = NULL;
    dcm_state_pctx_t    *pctx = NULL;

    guint8     *pdv_combined = NULL;
    guint8     *pdv_combined_curr = NULL;
    guint8     *dcm_header = NULL;
    guint32     pdv_combined_len = 0;
    guint32     dcm_header_len = 0;
    guint16     cnt_same_pkt = 1;
    gchar      *filename;
    const gchar *hostname;

    const gchar *sop_class_uid;
    gchar       *sop_instance_uid;

    /* Calculate total PDV length, i.e. all packets until last PDV without continuation  */
    pdv_curr = pdv;
    pdv_same_pkt = pdv;
    pdv_combined_len=pdv_curr->data_len;

    while (pdv_curr->prev && !pdv_curr->prev->is_last_fragment) {
        pdv_curr = pdv_curr->prev;
        pdv_combined_len += pdv_curr->data_len;
    }

    /* Count number of PDVs with the same Packet Number */
    while (pdv_same_pkt->prev && (pdv_same_pkt->prev->packet_no == pdv_same_pkt->packet_no)) {
        pdv_same_pkt = pdv_same_pkt->prev;
        cnt_same_pkt += 1;
    }

    pctx=dcm_state_pctx_get(assoc, pdv_curr->pctx_id, FALSE);

    if (assoc->ae_calling != NULL && strlen(assoc->ae_calling)>0 &&
        assoc->ae_called != NULL &&  strlen(assoc->ae_called)>0) {
        hostname = wmem_strdup_printf(pinfo->pool, "%s <-> %s", assoc->ae_calling, assoc->ae_called);
    }
    else {
        hostname = "AE title(s) unknown";
    }

    if (pdv->is_storage &&
        pdv_curr->sop_class_uid    && strlen(pdv_curr->sop_class_uid)>0 &&
        pdv_curr->sop_instance_uid && strlen(pdv_curr->sop_instance_uid)>0) {

        sop_class_uid = wmem_strdup(pinfo->pool, pdv_curr->sop_class_uid);
        sop_instance_uid = wmem_strdup(pinfo->pool, pdv_curr->sop_instance_uid);

        /* Make sure filename does not contain invalid character. Rather conservative.
           Even though this should be a valid DICOM UID, apply the same filter rules
           in case of bogus data.
        */
        filename = wmem_strdup_printf(pinfo->pool, "%06d-%d-%s.dcm", pinfo->num, cnt_same_pkt,
            g_strcanon(pdv_curr->sop_instance_uid, G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS "-.", '-'));
    }
    else {
        /* No SOP Instance or SOP Class UID found in PDV. Use wireshark ones */

        sop_class_uid = wmem_strdup(pinfo->pool, WIRESHARK_MEDIA_STORAGE_SOP_CLASS_UID);
        sop_instance_uid = wmem_strdup_printf(pinfo->pool, "%s.%d.%d",
            WIRESHARK_MEDIA_STORAGE_SOP_INSTANCE_UID_PREFIX, pinfo->num, cnt_same_pkt);

        /* Make sure filename does not contain invalid character. Rather conservative.*/
        filename = wmem_strdup_printf(pinfo->pool, "%06d-%d-%s.dcm", pinfo->num, cnt_same_pkt,
            g_strcanon(pdv->desc, G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS "-.", '-'));

    }

    if (global_dcm_export_header) {
        if (pctx && pctx->xfer_uid && strlen(pctx->xfer_uid)>0) {
            dcm_header=dcm_export_create_header(pinfo, &dcm_header_len, sop_class_uid, sop_instance_uid, pctx->xfer_uid);
        }
        else {
            /* We are running blind, i.e. no presentation context/syntax found.
               Don't invent one, so the meta header will miss
               the transfer syntax UID tag (even though it is mandatory)
            */
            dcm_header=dcm_export_create_header(pinfo, &dcm_header_len, sop_class_uid, sop_instance_uid, NULL);
        }
    }


    if (dcm_header_len + pdv_combined_len >= global_dcm_export_minsize) {
        /* Allocate the final size */

        pdv_combined = (guint8 *)wmem_alloc0(wmem_file_scope(), dcm_header_len + pdv_combined_len);

        pdv_combined_curr = pdv_combined;

        if (dcm_header_len != 0) {  /* Will be 0 when global_dcm_export_header is FALSE */
            memmove(pdv_combined, dcm_header, dcm_header_len);
            pdv_combined_curr += dcm_header_len;
        }

        /* Copy PDV per PDV to target buffer */
        while (!pdv_curr->is_last_fragment) {
            memmove(pdv_combined_curr, pdv_curr->data, pdv_curr->data_len);         /* this is a copy not move */
            pdv_combined_curr += pdv_curr->data_len;
            pdv_curr = pdv_curr->next;
        }

        /* Last packet */
        memmove(pdv_combined_curr, pdv->data, pdv->data_len);       /* this is a copy not a move */

        /* Add to list */
        eo_info = wmem_new0(wmem_file_scope(), dicom_eo_t);
        eo_info->hostname = g_strdup(hostname);
        eo_info->filename = g_strdup(filename);
        eo_info->content_type = g_strdup(pdv->desc);

        eo_info->payload_data = pdv_combined;
        eo_info->payload_len  = dcm_header_len + pdv_combined_len;

        tap_queue_packet(dicom_eo_tap, pinfo, eo_info);
    }
}

/*
For tags with fixed length items, calculate the value multiplicity (VM). String tags use a separator, which is not supported by this function.
Support item count from 0 to n. and handles bad encoding (e.g. an 'AT' tag was reported to be 2 bytes instead of 4 bytes)
*/
static guint32
dcm_vm_item_count(guint32 value_length, guint32 item_length)
{

    /* This could all be formulated in a single line but it does not make it easier to read */

    if (value_length == 0) {
        return 0;
    }
    else if (value_length <= item_length) {
        return 1;                           /* This is the special case of bad encoding */
    }
    else {
        return (value_length / item_length);
    }

}

/*
Decode the association header
 */
static guint32
dissect_dcm_assoc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, dcm_state_assoc_t *assoc,
                         guint8 pdu_type, guint32 pdu_len)
{

    proto_item *assoc_header_pitem;
    proto_tree *assoc_header_ptree;     /* Tree for item details */

    const gchar  *buf_desc = NULL;
    const char   *reject_result_desc = "";
    const char   *reject_source_desc = "";
    const char   *reject_reason_desc = "";
    const char   *abort_source_desc = "";
    const char   *abort_reason_desc = "";

    char  *ae_called;
    char  *ae_calling;
    char  *ae_called_resp;
    char  *ae_calling_resp;

    guint8  reject_result;
    guint8  reject_source;
    guint8  reject_reason;
    guint8  abort_source;
    guint8  abort_reason;

    assoc_header_ptree = proto_tree_add_subtree(tree, tvb, offset, pdu_len, ett_assoc_header, &assoc_header_pitem, "Association Header");

    switch (pdu_type) {
    case 1:                                     /* Association Request */

        proto_tree_add_item(assoc_header_ptree, hf_dcm_assoc_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        offset += 2;                            /* Two reserved bytes*/

        /*
         * XXX - this is in "the ISO 646:1990-Basic G0 Set"; ISO/IEC 646:1991
         * claims to be the third edition of the standard, with the second
         * version being ISO 646:1983, so I'm not sure what happened to
         * ISO 646:1990.  ISO/IEC 646:1991 speaks of "the basic 7-bit code
         * table", which leaves positions 2/3 (0x23) and 2/4 (0x24) as
         * being either NUMBER SIGN or POUND SIGN and either DOLLAR SIGN or
         * CURRENCY SIGN, respectively, and positions 4/0 (0x40), 5/11 (0x5b),
         * 5/12 (0x5c), 5/13 (0x5d), 5/14 (0x5e), 6/0 (0x60), 7/11 (0x7b),
         * 7/12 (0x7c), 7/13 (0x7d), and 7/14 (0x7e) as being "available for
         * national or application-oriented use", so I'm *guessing* that
         * "the ISO 646:1990-Basic G0 Set" means "those positions aren't
         * specified" and thus should probably be treated as not valid
         * in that "Basic" set.
         */
        proto_tree_add_item_ret_display_string(assoc_header_ptree, hf_dcm_assoc_called, tvb, offset, 16, ENC_ISO_646_BASIC|ENC_NA, pinfo->pool, &ae_called);
        assoc->ae_called = wmem_strdup(wmem_file_scope(), g_strstrip(ae_called));
        offset += 16;

        proto_tree_add_item_ret_display_string(assoc_header_ptree, hf_dcm_assoc_calling, tvb, offset, 16, ENC_ISO_646_BASIC|ENC_NA, pinfo->pool, &ae_calling);
        assoc->ae_calling = wmem_strdup(wmem_file_scope(), g_strstrip(ae_calling));
        offset += 16;

        offset += 32;                           /* 32 reserved bytes */

        buf_desc = wmem_strdup_printf(pinfo->pool, "A-ASSOCIATE request %s --> %s",
            assoc->ae_calling, assoc->ae_called);

        offset = dissect_dcm_assoc_detail(tvb, pinfo, assoc_header_ptree, assoc, offset, pdu_len-offset);

        break;
    case 2:                                     /* Association Accept */

        proto_tree_add_item(assoc_header_ptree, hf_dcm_assoc_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        offset += 2;                            /* Two reserved bytes*/

        proto_tree_add_item_ret_display_string(assoc_header_ptree, hf_dcm_assoc_called, tvb, offset, 16, ENC_ISO_646_BASIC|ENC_NA, pinfo->pool, &ae_called_resp);
        assoc->ae_called_resp = wmem_strdup(wmem_file_scope(), g_strstrip(ae_called_resp));
        offset += 16;

        proto_tree_add_item_ret_display_string(assoc_header_ptree, hf_dcm_assoc_calling, tvb, offset, 16, ENC_ISO_646_BASIC|ENC_NA, pinfo->pool, &ae_calling_resp);
        assoc->ae_calling_resp = wmem_strdup(wmem_file_scope(), g_strstrip(ae_calling_resp));
        offset += 16;

        offset += 32;                           /* 32 reserved bytes */

        buf_desc = wmem_strdup_printf(pinfo->pool, "A-ASSOCIATE accept  %s <-- %s",
            assoc->ae_calling_resp, assoc->ae_called_resp);

        offset = dissect_dcm_assoc_detail(tvb, pinfo, assoc_header_ptree, assoc, offset, pdu_len-offset);

        break;
    case 3:                                     /* Association Reject */

        offset += 1;                            /* One reserved byte */

        reject_result = tvb_get_guint8(tvb, offset);
        reject_source = tvb_get_guint8(tvb, offset+1);
        reject_reason = tvb_get_guint8(tvb, offset+2);

        switch (reject_result) {
        case 1:  reject_result_desc = "Reject Permanent"; break;
        case 2:  reject_result_desc = "Reject Transient"; break;
        default: break;
        }

        switch (reject_source) {
        case 1:
            reject_source_desc = "User";
            switch (reject_reason) {
            case 1:  reject_reason_desc = "No reason given"; break;
            case 2:  reject_reason_desc = "Application context name not supported"; break;
            case 3:  reject_reason_desc = "Calling AE title not recognized"; break;
            case 7:  reject_reason_desc = "Called AE title not recognized"; break;
            }
            break;
        case 2:
            reject_source_desc = "Provider (ACSE)";
            switch (reject_reason) {
            case 1:  reject_reason_desc = "No reason given"; break;
            case 2:  reject_reason_desc = "Protocol version not supported"; break;
            }
            break;
        case 3:
            reject_source_desc = "Provider (Presentation)";
            switch (reject_reason) {
            case 1:  reject_reason_desc = "Temporary congestion"; break;
            case 2:  reject_reason_desc = "Local limit exceeded"; break;
            }
            break;
        }

        proto_tree_add_uint_format_value(assoc_header_ptree, hf_dcm_assoc_reject_result, tvb,
            offset  , 1, reject_result, "%s", reject_result_desc);

        proto_tree_add_uint_format_value(assoc_header_ptree, hf_dcm_assoc_reject_source, tvb,
            offset+1, 1, reject_source, "%s", reject_source_desc);

        proto_tree_add_uint_format_value(assoc_header_ptree, hf_dcm_assoc_reject_reason, tvb,
            offset+2, 1, reject_reason, "%s", reject_reason_desc);

        offset += 3;

        /* Provider aborted */
        buf_desc = wmem_strdup_printf(pinfo->pool, "A-ASSOCIATE reject  %s <-- %s (%s)",
            assoc->ae_calling, assoc->ae_called, reject_reason_desc);

        expert_add_info(pinfo, assoc_header_pitem, &ei_dcm_assoc_rejected);

        break;
    case 5:                                     /* RELEASE Request */

        offset += 2;                            /* Two reserved bytes */
        buf_desc="A-RELEASE request";

        break;
    case 6:                                     /* RELEASE Response */

        offset += 2;                            /* Two reserved bytes */
        buf_desc="A-RELEASE response";

        break;
    case 7:                                     /* ABORT */

        offset += 2;                            /* Two reserved bytes */

        abort_source = tvb_get_guint8(tvb, offset);
        abort_reason = tvb_get_guint8(tvb, offset+1);

        switch (abort_source) {
        case 0:
            abort_source_desc = "User";
            abort_reason_desc = "N/A";          /* No details can be provided*/
            break;
        case 1:
            /* reserved */
            break;
        case 2:
            abort_source_desc = "Provider";

            switch (abort_reason) {
            case 0:  abort_reason_desc = "Not specified"; break;
            case 1:  abort_reason_desc = "Unrecognized PDU"; break;
            case 2:  abort_reason_desc = "Unexpected PDU"; break;
            case 4:  abort_reason_desc = "Unrecognized PDU parameter"; break;
            case 5:  abort_reason_desc = "Unexpected PDU parameter"; break;
            case 6:  abort_reason_desc = "Invalid PDU parameter value"; break;
            }

            break;
        }

        proto_tree_add_uint_format_value(assoc_header_ptree, hf_dcm_assoc_abort_source,
            tvb, offset  , 1, abort_source, "%s", abort_source_desc);

        proto_tree_add_uint_format_value(assoc_header_ptree, hf_dcm_assoc_abort_reason,
            tvb, offset+1, 1, abort_reason, "%s", abort_reason_desc);
        offset += 2;

        if (abort_source == 0) {
            /* User aborted */
            buf_desc = wmem_strdup_printf(pinfo->pool, "ABORT %s --> %s",
                assoc->ae_calling, assoc->ae_called);
        }
        else {
            /* Provider aborted, slightly more information */
            buf_desc = wmem_strdup_printf(pinfo->pool, "ABORT %s <-- %s (%s)",
                assoc->ae_calling, assoc->ae_called, abort_reason_desc);
        }

        expert_add_info(pinfo, assoc_header_pitem, &ei_dcm_assoc_aborted);

        break;
    }

    if (buf_desc) {
        proto_item_set_text(assoc_header_pitem, "%s", buf_desc);
        col_set_str(pinfo->cinfo, COL_INFO, buf_desc);

        /* proto_item and proto_tree are one and the same */
        proto_item_append_text(tree, ", %s", buf_desc);
    }
    return offset;
}

/*
Decode one item in a association request or response. Lookup UIDs if requested.
Create a subtree node with summary and three elements (item_type, item_len, value)
*/
static void
dissect_dcm_assoc_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset,
                       const gchar *pitem_prefix, int item_value_type,
                       gchar **item_value, const gchar **item_description,
                       int *hf_type, int *hf_len, int *hf_value, int ett_subtree)
{

    proto_tree *assoc_item_ptree;       /* Tree for item details */
    proto_item *assoc_item_pitem;
    dcm_uid_t  *uid = NULL;

    guint32 item_number = 0;

    guint8  item_type;
    guint16 item_len;

    gchar *buf_desc = "";             /* Used for item text */

    *item_value = NULL;
    *item_description = NULL;

    item_type = tvb_get_guint8(tvb, offset);
    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_ptree = proto_tree_add_subtree(tree, tvb, offset, item_len+4, ett_subtree, &assoc_item_pitem, pitem_prefix);

    proto_tree_add_uint(assoc_item_ptree, *hf_type, tvb, offset,   1, item_type);
    proto_tree_add_uint(assoc_item_ptree, *hf_len,  tvb, offset+2, 2, item_len);

    switch (item_value_type) {
    case DCM_ITEM_VALUE_TYPE_UID:
        *item_value = (gchar *)tvb_get_string_enc(pinfo->pool, tvb, offset+4, item_len, ENC_ASCII);

        uid = (dcm_uid_t *)wmem_map_lookup(dcm_uid_table, (gpointer) *item_value);
        if (uid) {
            *item_description = uid->name;
            buf_desc = wmem_strdup_printf(pinfo->pool, "%s (%s)", *item_description, *item_value);
        }
        else {
            /* Unknown UID, or no UID at all */
            buf_desc = *item_value;
        }

        proto_item_append_text(assoc_item_pitem, "%s", buf_desc);
        proto_tree_add_string(assoc_item_ptree, *hf_value, tvb, offset+4, item_len, buf_desc);

        break;

    case DCM_ITEM_VALUE_TYPE_STRING:
        *item_value = (gchar *)tvb_get_string_enc(pinfo->pool, tvb, offset+4, item_len, ENC_ASCII);
        proto_item_append_text(assoc_item_pitem, "%s", *item_value);
        proto_tree_add_string(assoc_item_ptree, *hf_value, tvb, offset+4, item_len, *item_value);

        break;

    case DCM_ITEM_VALUE_TYPE_UINT32:
        item_number = tvb_get_ntohl(tvb, offset+4);
        *item_value = (gchar *)wmem_strdup_printf(wmem_file_scope(), "%d", item_number);

        proto_item_append_text(assoc_item_pitem, "%s", *item_value);
        proto_tree_add_item(assoc_item_ptree, *hf_value, tvb, offset+4, 4, ENC_BIG_ENDIAN);

        break;

    default:
        break;
    }
}

/*
Decode the SOP Class Extended Negotiation Sub-Item Fields in a association request or response.
Lookup UIDs if requested
*/
static void
dissect_dcm_assoc_sopclass_extneg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{

    proto_tree *assoc_item_extneg_tree = NULL;  /* Tree for item details */
    proto_item *assoc_item_extneg_item = NULL;

    guint16 item_len  = 0;
    guint16 sop_class_uid_len  = 0;
    gint32 cnt = 0;

    gchar *buf_desc = NULL;             /* Used for item text */
    dcm_uid_t *sopclassuid=NULL;
    gchar *sopclassuid_str = NULL;

    item_len  = tvb_get_ntohs(tvb, offset+2);
    sop_class_uid_len  = tvb_get_ntohs(tvb, offset+4);

    assoc_item_extneg_item = proto_tree_add_item(tree, hf_dcm_info_extneg, tvb, offset, item_len+4, ENC_NA);
    proto_item_set_text(assoc_item_extneg_item, "Ext. Neg.: ");
    assoc_item_extneg_tree = proto_item_add_subtree(assoc_item_extneg_item, ett_assoc_info_extneg);

    proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_assoc_item_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_assoc_item_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_info_extneg_sopclassuid_len, tvb, offset+4, 2, ENC_BIG_ENDIAN);

    sopclassuid_str = (gchar *)tvb_get_string_enc(pinfo->pool, tvb, offset+6, sop_class_uid_len, ENC_ASCII);
    sopclassuid = (dcm_uid_t *)wmem_map_lookup(dcm_uid_table, (gpointer) sopclassuid_str);

    if (sopclassuid) {
        buf_desc = wmem_strdup_printf(pinfo->pool, "%s (%s)", sopclassuid->name, sopclassuid->value);
    }
    else {
        buf_desc = sopclassuid_str;
    }

    proto_item_append_text(assoc_item_extneg_item, "%s", buf_desc);
    proto_tree_add_string(assoc_item_extneg_tree, hf_dcm_info_extneg_sopclassuid, tvb, offset+6, sop_class_uid_len, buf_desc);

    /* Count how many fields are following. */
    cnt = item_len - 2 - sop_class_uid_len;

    /*
     * The next field contains Service Class specific information identified by the SOP Class UID.
     */
    if (0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENT_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_FIND) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_STUDY_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_FIND) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENTSTUDY_ONLY_QUERYRETRIEVE_INFORMATION_MODEL_FIND_RETIRED) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENT_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_MOVE) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_STUDY_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_MOVE) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENTSTUDY_ONLY_QUERYRETRIEVE_INFORMATION_MODEL_MOVE_RETIRED) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENT_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_GET) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_STUDY_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_GET) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENTSTUDY_ONLY_QUERYRETRIEVE_INFORMATION_MODEL_GET_RETIRED))
    {
        if (cnt<=0)
        {
            return;
        }

        /* Support for Relational queries. */
        proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_info_extneg_relational_query, tvb, offset+6+sop_class_uid_len, 1, ENC_BIG_ENDIAN);
        --cnt;
    }

    /* More sub-items are only allowed for the C-FIND SOP Classes. */
    if (0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENT_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_FIND) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_STUDY_ROOT_QUERYRETRIEVE_INFORMATION_MODEL_FIND) ||
        0 == strcmp(sopclassuid_str, DCM_UID_SOP_CLASS_PATIENTSTUDY_ONLY_QUERYRETRIEVE_INFORMATION_MODEL_FIND_RETIRED))
    {
        if (cnt<=0)
        {
            return;
        }

        /* Combined Date-Time matching. */
        proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_info_extneg_date_time_matching, tvb, offset+7+sop_class_uid_len, 1, ENC_BIG_ENDIAN);
        --cnt;

        if (cnt<=0)
        {
            return;
        }

        /* Fuzzy semantic matching of person names. */
        proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_info_extneg_fuzzy_semantic_matching, tvb, offset+8+sop_class_uid_len, 1, ENC_BIG_ENDIAN);
        --cnt;

        if (cnt<=0)
        {
            return;
        }

        /* Timezone query adjustment. */
        proto_tree_add_item(assoc_item_extneg_tree, hf_dcm_info_extneg_timezone_query_adjustment, tvb, offset+9+sop_class_uid_len, 1, ENC_BIG_ENDIAN);
        --cnt;
    }
}

/*
Decode user identities in the association
*/
static void
dissect_dcm_assoc_user_identify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{

    proto_tree *assoc_item_user_identify_tree = NULL;  /* Tree for item details */
    proto_item *assoc_item_user_identify_item = NULL;

    guint16 primary_field_length, secondary_field_length, item_len  = 0;
    guint8 type;

    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_user_identify_item = proto_tree_add_item(tree, hf_dcm_info_user_identify, tvb, offset, item_len+4, ENC_NA);
    assoc_item_user_identify_tree = proto_item_add_subtree(assoc_item_user_identify_item, ett_assoc_info_user_identify);

    proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_assoc_item_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_assoc_item_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_info_user_identify_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_info_user_identify_response_requested, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    primary_field_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_info_user_identify_primary_field_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_info_user_identify_primary_field, tvb, offset, primary_field_length, ENC_UTF_8);
    proto_item_append_text(assoc_item_user_identify_item, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, primary_field_length, ENC_UTF_8|ENC_NA));
    offset += primary_field_length;

    if (type == 2) {
        secondary_field_length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_info_user_identify_secondary_field_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(assoc_item_user_identify_tree, hf_dcm_info_user_identify_secondary_field, tvb, offset, secondary_field_length, ENC_UTF_8);
        proto_item_append_text(assoc_item_user_identify_item, ", %s", tvb_get_string_enc(pinfo->pool, tvb, offset, secondary_field_length, ENC_UTF_8|ENC_NA));
    }
}

/*
Decode unknown item types in the association
*/
static void
dissect_dcm_assoc_unknown(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{

    proto_tree *assoc_item_unknown_tree = NULL;  /* Tree for item details */
    proto_item *assoc_item_unknown_item = NULL;

    guint16 item_len  = 0;

    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_unknown_item = proto_tree_add_item(tree, hf_dcm_info_unknown, tvb, offset, item_len+4, ENC_NA);
    assoc_item_unknown_tree = proto_item_add_subtree(assoc_item_unknown_item, ett_assoc_info_unknown);

    proto_tree_add_item(assoc_item_unknown_tree, hf_dcm_assoc_item_type, tvb, offset,   1, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_unknown_tree, hf_dcm_assoc_item_len,  tvb, offset+2, 2, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(assoc_item_unknown_tree, hf_dcm_assoc_item_data, tvb, offset, item_len, ENC_NA);
}

/*
Decode the SCP/SCU Role Selection Sub-Item Fields in a association request or response.
Lookup UIDs if requested
*/
static void
dissect_dcm_assoc_role_selection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{

    proto_tree *assoc_item_rolesel_tree; /* Tree for item details */
    proto_item *assoc_item_rolesel_item;

    guint16 item_len, sop_class_uid_len;
    guint8 scp_role, scu_role;

    gchar *buf_desc;     /* Used for item text */
    dcm_uid_t *sopclassuid;
    gchar *sopclassuid_str;

    item_len  = tvb_get_ntohs(tvb, offset+2);
    sop_class_uid_len  = tvb_get_ntohs(tvb, offset+4);

    assoc_item_rolesel_item = proto_tree_add_item(tree, hf_dcm_info_rolesel, tvb, offset, item_len+4, ENC_NA);
    proto_item_set_text(assoc_item_rolesel_item, "Role Selection: ");
    assoc_item_rolesel_tree = proto_item_add_subtree(assoc_item_rolesel_item, ett_assoc_info_rolesel);

    proto_tree_add_item(assoc_item_rolesel_tree, hf_dcm_assoc_item_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_rolesel_tree, hf_dcm_assoc_item_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_rolesel_tree, hf_dcm_info_rolesel_sopclassuid_len, tvb, offset+4, 2, ENC_BIG_ENDIAN);

    sopclassuid_str = (gchar *)tvb_get_string_enc(pinfo->pool, tvb, offset+6, sop_class_uid_len, ENC_ASCII);
    sopclassuid = (dcm_uid_t *)wmem_map_lookup(dcm_uid_table, (gpointer) sopclassuid_str);

    scu_role = tvb_get_guint8(tvb, offset+6+sop_class_uid_len);
    scp_role = tvb_get_guint8(tvb, offset+7+sop_class_uid_len);

    if (scu_role) {
        proto_item_append_text(assoc_item_rolesel_item, "%s", "SCU-role: yes");
    }
    else {
        proto_item_append_text(assoc_item_rolesel_item, "%s", "SCU-role: no");
    }

    if (scp_role) {
        proto_item_append_text(assoc_item_rolesel_item, ", %s", "SCP-role: yes");
    }
    else {
        proto_item_append_text(assoc_item_rolesel_item, ", %s", "SCP-role: no");
    }

    if (sopclassuid) {
        buf_desc = wmem_strdup_printf(pinfo->pool, "%s (%s)", sopclassuid->name, sopclassuid->value);
    }
    else {
        buf_desc = sopclassuid_str;
    }

    proto_tree_add_string(assoc_item_rolesel_tree, hf_dcm_info_rolesel_sopclassuid, tvb, offset+6, sop_class_uid_len, buf_desc);

    proto_tree_add_item(assoc_item_rolesel_tree, hf_dcm_info_rolesel_scurole, tvb, offset+6+sop_class_uid_len, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_rolesel_tree, hf_dcm_info_rolesel_scprole, tvb, offset+7+sop_class_uid_len, 1, ENC_BIG_ENDIAN);
}

/*
Decode the Asynchronous operations (and sub-operations) Window Negotiation Sub-Item Fields in a association request or response.
*/
static void
dissect_dcm_assoc_async_negotiation(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{

    proto_tree *assoc_item_asyncneg_tree; /* Tree for item details */
    proto_item *assoc_item_asyncneg_item;

    guint16 item_len, max_num_ops_inv, max_num_ops_per = 0;

    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_asyncneg_item = proto_tree_add_item(tree, hf_dcm_info_async_neg, tvb, offset, item_len+4, ENC_NA);
    proto_item_set_text(assoc_item_asyncneg_item, "Async Negotiation: ");
    assoc_item_asyncneg_tree = proto_item_add_subtree(assoc_item_asyncneg_item, ett_assoc_info_async_neg);

    proto_tree_add_item(assoc_item_asyncneg_tree, hf_dcm_assoc_item_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_asyncneg_tree, hf_dcm_assoc_item_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_asyncneg_tree, hf_dcm_info_async_neg_max_num_ops_inv, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(assoc_item_asyncneg_tree, hf_dcm_info_async_neg_max_num_ops_per, tvb, offset+6, 2, ENC_BIG_ENDIAN);

    max_num_ops_inv = tvb_get_ntohs(tvb, offset+4);
    max_num_ops_per = tvb_get_ntohs(tvb, offset+6);

    proto_item_append_text(assoc_item_asyncneg_item, "%s%d", "Maximum Number Operations Invoked: ", max_num_ops_inv);
    if (max_num_ops_inv==0) proto_item_append_text(assoc_item_asyncneg_item, "%s", " (unlimited)");
    proto_item_append_text(assoc_item_asyncneg_item, ", %s%d", "Maximum Number Operations Performed: ", max_num_ops_per);
    if (max_num_ops_per==0) proto_item_append_text(assoc_item_asyncneg_item, "%s", " (unlimited)");
}

/*
Decode a presentation context item in a Association Request or Response. In the response, set the accepted transfer syntax, if any.
*/
static void
dissect_dcm_pctx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 dcm_state_assoc_t *assoc, guint32 offset, guint32 len,
                 const gchar *pitem_prefix, gboolean is_assoc_request)
{

    proto_tree *pctx_ptree;                 /* Tree for presentation context details */
    proto_item *pctx_pitem;

    dcm_state_pctx_t *pctx = NULL;

    guint8  item_type = 0;
    guint16 item_len = 0;

    guint8  pctx_id = 0;                    /* Presentation Context ID */
    guint8  pctx_result = 0;

    const char  *pctx_result_desc = "";

    gchar *pctx_abss_uid  = NULL;           /* Abstract Syntax UID alias SOP Class UID */
    const gchar *pctx_abss_desc = NULL;     /* Description of UID */

    gchar *pctx_xfer_uid = NULL;            /* Transfer Syntax UID */
    const gchar *pctx_xfer_desc = NULL;     /* Description of UID */

    gchar *buf_desc = "";                   /* Used in info mode for item text */

    guint32 endpos = 0;
    int     cnt_abbs = 0;                   /* Number of Abstract Syntax Items */
    int     cnt_xfer = 0;                   /* Number of Transfer Syntax Items */

    endpos = offset + len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    pctx_ptree = proto_tree_add_subtree(tree, tvb, offset-4, item_len+4, ett_assoc_pctx, &pctx_pitem, pitem_prefix);

    pctx_id     = tvb_get_guint8(tvb, offset);
    pctx_result = tvb_get_guint8(tvb, 2 + offset);      /* only set in responses, otherwise reserved and 0x00 */

    /* Find or create DICOM context object */
    pctx = dcm_state_pctx_get(assoc, pctx_id, TRUE);
    if (pctx == NULL) { /* Internal error. Failed to create data structure */
        return;
    }

    proto_tree_add_uint(pctx_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 1, item_type);           /* The type is only one byte long */
    proto_tree_add_uint(pctx_ptree, hf_dcm_assoc_item_len,  tvb, offset-2, 2, item_len);

    proto_tree_add_uint_format(pctx_ptree, hf_dcm_pctx_id, tvb, offset, 1, pctx_id, "Context ID: 0x%02x", pctx_id);

    if (!is_assoc_request) {
        /* Association response. */

        switch (pctx_result) {
        case 0:  pctx_result_desc = "Accept"; break;
        case 1:  pctx_result_desc = "User Reject"; break;
        case 2:  pctx_result_desc = "No Reason"; break;
        case 3:  pctx_result_desc = "Abstract Syntax Unsupported"; break;
        case 4:  pctx_result_desc = "Transfer Syntax Unsupported"; break;
        }

        proto_tree_add_uint_format(pctx_ptree, hf_dcm_pctx_result, tvb, offset+2, 1,
            pctx_result, "Result: %s (0x%x)", pctx_result_desc, pctx_result);
    }

    offset += 4;
    while (offset < endpos) {

        item_type = tvb_get_guint8(tvb, offset);
        item_len = tvb_get_ntohs(tvb, 2 + offset);

        offset += 4;
        switch (item_type) {
        case 0x30:              /* Abstract syntax */

            /* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
            dissect_dcm_assoc_item(tvb, pinfo, pctx_ptree, offset-4,
                "Abstract Syntax: ", DCM_ITEM_VALUE_TYPE_UID, &pctx_abss_uid, &pctx_abss_desc,
                &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pctx_abss_syntax, ett_assoc_pctx_abss);

            cnt_abbs += 1;
            offset += item_len;
            break;

        case 0x40:              /* Transfer syntax */

            dissect_dcm_assoc_item(tvb, pinfo, pctx_ptree, offset-4,
                "Transfer Syntax: ", DCM_ITEM_VALUE_TYPE_UID, &pctx_xfer_uid, &pctx_xfer_desc,
                &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pctx_xfer_syntax, ett_assoc_pctx_xfer);

            /*
               In a correct Association Response, only one Transfer syntax shall be present.
               Therefore, pctx_xfer_uid, pctx_xfer_desc are used for the accept scenario in the info mode
            */

            if (!is_assoc_request && pctx_result == 0) {
                /* Association Response, Context Accepted */
                dcm_set_syntax(pctx, pctx_xfer_uid, pctx_xfer_desc);
            }
            cnt_xfer += 1;
            offset += item_len;
            break;

        default:
            offset += item_len;
            break;
        }
    }

    if (is_assoc_request) {

        if (cnt_abbs<1) {
            expert_add_info(pinfo, pctx_pitem, &ei_dcm_no_abstract_syntax);
            return;
        }
        else if (cnt_abbs>1) {
            expert_add_info(pinfo, pctx_pitem, &ei_dcm_multiple_abstract_syntax);
            return;
        }

        if (cnt_xfer==0) {
            expert_add_info(pinfo, pctx_pitem, &ei_dcm_no_transfer_syntax);
            return;
        }

        if (pctx_abss_uid==NULL) {
            expert_add_info(pinfo, pctx_pitem, &ei_dcm_no_abstract_syntax_uid);
            return;
        }

    }
    else {

        if (cnt_xfer>1) {
            expert_add_info(pinfo, pctx_pitem, &ei_dcm_multiple_transfer_syntax);
            return;
        }
    }

    if (pctx->abss_uid==NULL) {
        /* Permanent copy information into structure */
        pctx->abss_uid  = wmem_strdup(wmem_file_scope(), pctx_abss_uid);
        pctx->abss_desc = wmem_strdup(wmem_file_scope(), pctx_abss_desc);
    }

    /*
      Copy to buffer first, because proto_item_append_text()
      crashed for an unknown reason using 'ID 0x%02x, %s, %s'
      and in my opinion correctly set parameters.
    */

    if (is_assoc_request) {
        if (pctx_abss_desc == NULL) {
            buf_desc = pctx_abss_uid;
        }
        else {
            buf_desc = wmem_strdup_printf(pinfo->pool, "%s (%s)", pctx_abss_desc, pctx_abss_uid);
        }
    }
    else
    {
        if (pctx_result==0) {
            /* Accepted */
            buf_desc = wmem_strdup_printf(pinfo->pool, "ID 0x%02x, %s, %s, %s",
                pctx_id, pctx_result_desc,
                dcm_uid_or_desc(pctx->xfer_uid, pctx->xfer_desc),
                dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
        }
        else {
            /* Rejected */
            buf_desc = wmem_strdup_printf(pinfo->pool, "ID 0x%02x, %s, %s",
                pctx_id, pctx_result_desc,
                dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
        }
    }
    proto_item_append_text(pctx_pitem, "%s", buf_desc);

}

/*
Decode the user info item in a Association Request or Response
*/
static void
dissect_dcm_userinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 len, const gchar *pitem_prefix)
{

    proto_item *userinfo_pitem = NULL;
    proto_tree *userinfo_ptree = NULL;  /* Tree for presentation context details */

    guint8  item_type;
    guint16 item_len;

    gboolean first_item=TRUE;

    gchar *info_max_pdu=NULL;
    gchar *info_impl_uid=NULL;
    gchar *info_impl_version=NULL;
    const gchar *dummy=NULL;

    guint32 endpos;

    endpos = offset + len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    userinfo_pitem = proto_tree_add_item(tree, hf_dcm_info, tvb, offset-4, item_len+4, ENC_NA);
    proto_item_set_text(userinfo_pitem, "%s", pitem_prefix);
    userinfo_ptree = proto_item_add_subtree(userinfo_pitem, ett_assoc_info);

    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 1, item_type);       /* The type is only one byte long */
    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_len,  tvb, offset-2, 2, item_len);

    while (offset < endpos) {

        item_type = tvb_get_guint8(tvb, offset);
        item_len = tvb_get_ntohs(tvb, 2 + offset);

        offset += 4;
        switch (item_type) {
        case 0x51:              /* Max length */

            dissect_dcm_assoc_item(tvb, pinfo, userinfo_ptree, offset-4,
                "Max PDU Length: ", DCM_ITEM_VALUE_TYPE_UINT32, &info_max_pdu, &dummy,
                &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pdu_maxlen, ett_assoc_info_uid);

            if (!first_item) {
                proto_item_append_text(userinfo_pitem, ", ");
            }
            proto_item_append_text(userinfo_pitem, "Max PDU Length %s", info_max_pdu);
            first_item=FALSE;

            offset += item_len;
            break;

        case 0x52:              /* UID */

            /* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
            dissect_dcm_assoc_item(tvb, pinfo, userinfo_ptree, offset-4,
                "Implementation UID: ", DCM_ITEM_VALUE_TYPE_STRING, &info_impl_uid, &dummy,
                &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_info_uid, ett_assoc_info_uid);

            if (!first_item) {
                proto_item_append_text(userinfo_pitem, ", ");
            }
            proto_item_append_text(userinfo_pitem, "Implementation UID %s", info_impl_uid);
            first_item=FALSE;

            offset += item_len;
            break;

        case 0x55:              /* version */

            dissect_dcm_assoc_item(tvb, pinfo, userinfo_ptree, offset-4,
                "Implementation Version: ", DCM_ITEM_VALUE_TYPE_STRING, &info_impl_version, &dummy,
                &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_info_version, ett_assoc_info_version);

            if (!first_item) {
                proto_item_append_text(userinfo_pitem, ", ");
            }
            proto_item_append_text(userinfo_pitem, "Version %s", info_impl_version);
            first_item=FALSE;

            offset += item_len;
            break;

        case 0x53:              /* async negotiation */

            dissect_dcm_assoc_async_negotiation(tvb, userinfo_ptree, offset-4);

            offset += item_len;
            break;

        case 0x54:              /* scp/scu role selection */

           dissect_dcm_assoc_role_selection(tvb, pinfo, userinfo_ptree, offset-4);

           offset += item_len;
           break;

        case 0x56:              /* extended negotiation */

            dissect_dcm_assoc_sopclass_extneg(tvb, pinfo, userinfo_ptree, offset-4);

            offset += item_len;
            break;

        case 0x58:              /* User Identify */

            dissect_dcm_assoc_user_identify(tvb, pinfo, userinfo_ptree, offset-4);

            offset += item_len;
            break;

        default:

            dissect_dcm_assoc_unknown(tvb, userinfo_ptree, offset-4);

            offset += item_len;
            break;
        }
    }
}


/*
Create a subtree for association requests or responses
*/
static guint32
dissect_dcm_assoc_detail(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,
                         dcm_state_assoc_t *assoc, guint32 offset, guint32 len)
{
    proto_tree *assoc_tree  = NULL;     /* Tree for PDU details */

    guint8  item_type;
    guint16 item_len;

    guint32 endpos;

    gchar *item_value = NULL;
    const gchar *item_description = NULL;

    endpos = offset + len;

    assoc_tree = proto_item_add_subtree(ti, ett_assoc);
    while (offset < endpos) {

        item_type = tvb_get_guint8(tvb, offset);
        item_len  = tvb_get_ntohs(tvb, 2 + offset);

        if (item_len == 0) {
            expert_add_info(pinfo, ti, &ei_dcm_assoc_item_len);
            return endpos;
        }

        offset += 4;

        switch (item_type) {
        case 0x10:              /* Application context */
            dissect_dcm_assoc_item(tvb, pinfo, assoc_tree, offset-4,
                "Application Context: ", DCM_ITEM_VALUE_TYPE_UID, &item_value, &item_description,
                &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_actx, ett_assoc_actx);

            offset += item_len;
            break;

        case 0x20:              /* Presentation context request */
            dissect_dcm_pctx(tvb, pinfo, assoc_tree, assoc, offset, item_len, "Presentation Context: ", TRUE);
            offset += item_len;
            break;

        case 0x21:              /* Presentation context reply */
            dissect_dcm_pctx(tvb, pinfo, assoc_tree, assoc, offset, item_len, "Presentation Context: ", FALSE);
            offset += item_len;
            break;

        case 0x50:              /* User Info */
            dissect_dcm_userinfo(tvb, pinfo, assoc_tree, offset, item_len, "User Info: ");
            offset += item_len;
            break;

        default:
            offset += item_len;
            break;
        }
    }

    return offset;

}

static guint32
dissect_dcm_pdv_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       dcm_state_assoc_t *assoc, guint32 offset, dcm_state_pdv_t **pdv)
{
    /* Dissect Context and Flags of a PDV and create new PDV structure */

    proto_item *pdv_ctx_pitem = NULL;
    proto_item *pdv_flags_pitem = NULL;

    dcm_state_pctx_t    *pctx = NULL;
    dcm_state_pdv_t     *pdv_first_data = NULL;

    const gchar *desc_flag = NULL;      /* Flag Description in tree */
    gchar *desc_header = NULL;          /* Used for PDV description */

    guint8  flags = 0, o_flags = 0;
    guint8  pctx_id = 0;

    /* 1 Byte Context */
    pctx_id = tvb_get_guint8(tvb, offset);
    pctx = dcm_state_pctx_get(assoc, pctx_id, FALSE);

    if (pctx && pctx->xfer_uid) {
        proto_tree_add_uint_format(tree, hf_dcm_pdv_ctx, tvb, offset, 1,
            pctx_id, "Context: 0x%02x (%s, %s)", pctx_id,
        dcm_uid_or_desc(pctx->xfer_uid, pctx->xfer_desc),
        dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
    }
    else {
        pdv_ctx_pitem=proto_tree_add_uint_format(tree, hf_dcm_pdv_ctx, tvb,  offset, 1,
            pctx_id, "Context: 0x%02x not found. A-ASSOCIATE request not found in capture.", pctx_id);

        expert_add_info(pinfo, pdv_ctx_pitem, &ei_dcm_pdv_ctx);

        if (pctx == NULL) {
            /* only create presentation context, if it does not yet exist */

            /* Create fake PCTX and guess Syntax ILE, ELE, EBE */
            pctx = dcm_state_pctx_new(assoc, pctx_id);

            /* To be done: Guess Syntax */
            pctx->syntax = DCM_UNK;
        }
    }
    offset +=1;

    /* Create PDV structure:

       Since we can have multiple PDV per packet (offset) and
       multiple merged packets per PDV (the tvb raw_offset)
       we need both values to uniquely identify a PDV
    */

    *pdv = dcm_state_pdv_get(pctx, pinfo->num, tvb_raw_offset(tvb)+offset, TRUE);
    if (*pdv == NULL) {
        return 0;                   /* Failed to allocate memory */
    }

    /* 1 Byte Flag */
    /* PS3.8 E.2  Bits 2 through 7 are always set to 0 by the sender and never checked by the receiver. */
    o_flags = tvb_get_guint8(tvb, offset);
    flags = 0x3 & o_flags;

    (*pdv)->pctx_id = pctx_id;

    switch (flags) {
    case 0:     /* 00 */
        if (0 != (0xfc & o_flags))
            desc_flag = "Data, More Fragments (Warning: Invalid)";
        else
            desc_flag = "Data, More Fragments";

        (*pdv)->is_flagvalid = TRUE;
        (*pdv)->is_command = FALSE;
        (*pdv)->is_last_fragment = FALSE;
        (*pdv)->syntax = pctx->syntax;      /* Inherit syntax for data PDVs*/
        break;

    case 2:     /* 10 */
        if (0 != (0xfc & o_flags))
            desc_flag = "Data, Last Fragment (Warning: Invalid)";
        else
            desc_flag = "Data, Last Fragment";

        (*pdv)->is_flagvalid = TRUE;
        (*pdv)->is_command = FALSE;
        (*pdv)->is_last_fragment = TRUE;
        (*pdv)->syntax = pctx->syntax;      /* Inherit syntax for data PDVs*/
        break;

    case 1:     /* 01 */
        if (0 != (0xfc & o_flags))
            desc_flag = "Command, More Fragments (Warning: Invalid)";
        else
            desc_flag = "Command, More Fragments";
        desc_header = wmem_strdup(wmem_file_scope(), "Command");        /* Will be overwritten with real command tag */

        (*pdv)->is_flagvalid = TRUE;
        (*pdv)->is_command = TRUE;
        (*pdv)->is_last_fragment = FALSE;
        (*pdv)->syntax = DCM_ILE;           /* Command tags are always little endian*/
        break;

    case 3:     /* 11 */
        if (0 != (0xfc & o_flags))
            desc_flag = "Command, Last Fragment (Warning: Invalid)";
        else
            desc_flag = "Command, Last Fragment";
        desc_header = wmem_strdup(wmem_file_scope(), "Command");

        (*pdv)->is_flagvalid = TRUE;
        (*pdv)->is_command = TRUE;
        (*pdv)->is_last_fragment = TRUE;
        (*pdv)->syntax = DCM_ILE;           /* Command tags are always little endian*/
        break;

    default:
        desc_flag = "Invalid Flags";
        desc_header = wmem_strdup(wmem_file_scope(), desc_flag);

        (*pdv)->is_flagvalid = FALSE;
        (*pdv)->is_command = FALSE;
        (*pdv)->is_last_fragment = FALSE;
        (*pdv)->syntax = DCM_UNK;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        (*pdv)->reassembly_id = pctx->reassembly_count;
        if ((*pdv)->is_last_fragment) {
            pctx->reassembly_count++;
        }
    }

    if (flags == 0 || flags == 2) {
        /* Data PDV */
        pdv_first_data = dcm_state_pdv_get_obj_start(*pdv);

        if (pdv_first_data->prev && pdv_first_data->prev->is_command) {
            /* Every Data PDV sequence should be preceded by a Command PDV,
               so we should always hit this for a correct capture
            */

            if (pctx->abss_desc && g_str_has_suffix(pctx->abss_desc, "Storage")) {
                /* Should be done far more intelligent, e.g. does not catch the (Retired) ones */
                if (flags == 0) {
                    desc_header = wmem_strdup_printf(wmem_file_scope(), "%s Fragment", pctx->abss_desc);
                }
                else {
                    desc_header = wmem_strdup(wmem_file_scope(), pctx->abss_desc);
                }
                (*pdv)->is_storage = TRUE;
            }
            else {
                /* Use previous command and append DATA*/
                desc_header = wmem_strdup_printf(wmem_file_scope(), "%s-DATA", pdv_first_data->prev->desc);
            }
        }
        else {
            desc_header = wmem_strdup(wmem_file_scope(), "DATA");
        }
    }

    (*pdv)->desc = desc_header;

    pdv_flags_pitem = proto_tree_add_uint_format(tree, hf_dcm_pdv_flags, tvb, offset, 1,
        flags, "Flags: 0x%02x (%s)", o_flags, desc_flag);

    if (o_flags>3) {
        expert_add_info(pinfo, pdv_flags_pitem, &ei_dcm_pdv_flags);
    }
    offset +=1;

    return offset;
}

/*
Based on the value representation, decode the value of one tag.
Support VM>1 for most types, but not all. Returns new offset
*/
static guint32
dissect_dcm_tag_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_pdv_t *pdv,
                      guint32 offset, guint16 grp, guint16 elm,
                      guint32 vl, guint32 vl_max, const gchar* vr, gchar **tag_value)
{

    proto_item *pitem = NULL;
    guint encoding = (pdv->syntax == DCM_EBE) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;


    /* Make sure we have all the bytes of the item; this should throw
       and exception if vl_max is so large that it causes the offset
       to overflow. */
    tvb_ensure_bytes_exist(tvb, offset, vl_max);

    /* ---------------------------------------------------------------------------
       Potentially long types. Obey vl_max
       ---------------------------------------------------------------------------
    */

    if ((strncmp(vr, "AE", 2) == 0) || (strncmp(vr, "AS", 2) == 0) || (strncmp(vr, "CS", 2) == 0) ||
        (strncmp(vr, "DA", 2) == 0) || (strncmp(vr, "DS", 2) == 0) || (strncmp(vr, "DT", 2) == 0) ||
        (strncmp(vr, "IS", 2) == 0) || (strncmp(vr, "LO", 2) == 0) || (strncmp(vr, "LT", 2) == 0) ||
        (strncmp(vr, "PN", 2) == 0) || (strncmp(vr, "SH", 2) == 0) || (strncmp(vr, "ST", 2) == 0) ||
        (strncmp(vr, "TM", 2) == 0) || (strncmp(vr, "UI", 2) == 0) || (strncmp(vr, "UT", 2) == 0) ) {
        /*
            15 ways to represent a string.

            For LT, ST, UT the DICOM standard does not allow multi-value
            For the others, VM is built into 'automatically, because it uses '\' as separator
        */

        gchar   *vals;
        dcm_uid_t *uid = NULL;
        guint8 val8;

        val8 = tvb_get_guint8(tvb, offset + vl_max - 1);
        if (val8 == 0x00) {
            /* Last byte of string is 0x00, i.e. padded */
            vals = tvb_format_text(pinfo->pool, tvb, offset, vl_max - 1);
        }
        else {
            vals = tvb_format_text(pinfo->pool, tvb, offset, vl_max);
        }

        if ((strncmp(vr, "UI", 2) == 0)) {
            /* This is a UID. Attempt a lookup. Will only return something for classes of course */

            uid = (dcm_uid_t *)wmem_map_lookup(dcm_uid_table, (gpointer) vals);
            if (uid) {
                *tag_value = wmem_strdup_printf(pinfo->pool, "%s (%s)", vals, uid->name);
            }
            else {
                *tag_value = vals;
            }
        }
        else {
            if (strlen(vals) > 50) {
                *tag_value = wmem_strdup_printf(pinfo->pool, "%-50.50s...", vals);
            }
            else {
                *tag_value = vals;
            }
        }
        proto_tree_add_string(tree, hf_dcm_tag_value_str, tvb, offset, vl_max, *tag_value);

        if (grp == 0x0000 && elm == 0x0902) {
            /* The error comment */
            pdv->comment = wmem_strdup(wmem_file_scope(), g_strstrip(vals));
        }
    }
    else if ((strncmp(vr, "OB", 2) == 0) || (strncmp(vr, "OW", 2) == 0) ||
             (strncmp(vr, "OF", 2) == 0) || (strncmp(vr, "OD", 2) == 0)) {

        /* Array of Bytes, Words, Float, or Doubles. Don't perform any decoding. VM=1. Multiple arrays are not possible */

        proto_tree_add_bytes_format_value(tree, hf_dcm_tag_value_byte, tvb, offset, vl_max, NULL, "%s", "(binary)");

        *tag_value = wmem_strdup(pinfo->pool, "(binary)");
    }
    else if (strncmp(vr, "UN", 2) == 0) {

        /*  Usually the case for private tags in implicit syntax, since tag was not found and VR not specified.
            Not been able to create UN yet. No need to support VM > 1.
        */

        guint8    val8;
        gchar    *vals;
        guint32  i;

        /* String detector, i.e. check if we only have alpha-numeric character */
        gboolean        is_string = TRUE;
        gboolean        is_padded = FALSE;

        for (i = 0; i < vl_max ; i++) {
            val8 = tvb_get_guint8(tvb, offset + i);

            if ((val8 == 0x09) || (val8 == 0x0A) || (val8 == 0x0D)) {
                /* TAB, LF, CR */
            }
            else if ((val8 >= 0x20) && (val8 <= 0x7E)) {
                /* No extended ASCII, 0-9, A-Z, a-z */
            }
            else if ((i == vl_max -1) && (val8 == 0x00)) {
                /* Last Byte can be null*/
                is_padded = TRUE;
            }
            else {
                /* Here's the code */
                is_string = FALSE;
            }
        }

        if (is_string) {
            vals = tvb_format_text(pinfo->pool, tvb, offset, (is_padded ? vl_max - 1 : vl_max));
            proto_tree_add_string(tree, hf_dcm_tag_value_str, tvb, offset, vl_max, vals);

            *tag_value = vals;
        }
        else {
            proto_tree_add_bytes_format_value(tree, hf_dcm_tag_value_byte, tvb, offset, vl_max, NULL, "%s", "(binary)");

            *tag_value = wmem_strdup(pinfo->pool, "(binary)");
        }
    }
    /* ---------------------------------------------------------------------------
       Smaller types. vl/vl_max are not used. Fixed item length from 2 to 8 bytes
       ---------------------------------------------------------------------------
    */
    else if (strncmp(vr, "AT", 2) == 0)  {

        /* Attribute Tag e.g. (0022,8866). 2*2 Bytes, Can have VM > 1 */

        guint16 at_grp;
        guint16 at_elm;
        gchar *at_value = "";

        /* In on capture the reported length for this tag was 2 bytes. And since vl_max is unsigned long, -3 caused it to be 2^32-1
           So make it at least one loop so set it to at least 4.
        */

        guint32 vm_item_len = 4;
        guint32 vm_item_count = dcm_vm_item_count(vl_max, vm_item_len);

        guint32 i = 0;
        while (i < vm_item_count) {
            at_grp = tvb_get_guint16(tvb, offset+ i*vm_item_len,   encoding);
            at_elm = tvb_get_guint16(tvb, offset+ i*vm_item_len+2, encoding);

            proto_tree_add_uint_format_value(tree, hf_dcm_tag_value_32u, tvb, offset + i*vm_item_len, vm_item_len,
                (at_grp << 16) | at_elm, "%04x,%04x", at_grp, at_elm);

            at_value = wmem_strdup_printf(pinfo->pool,"%s(%04x,%04x)", at_value, at_grp, at_elm);

            i++;
        }
        *tag_value = at_value;
    }
    else if (strncmp(vr, "FL", 2) == 0)  {      /* Single Float. Can be VM > 1, but not yet supported */

        gfloat valf = tvb_get_ieee_float(tvb, offset, encoding);

        proto_tree_add_bytes_format_value(tree, hf_dcm_tag_value_byte, tvb, offset, 4, NULL, "%f", valf);

        *tag_value = wmem_strdup_printf(pinfo->pool, "%f", valf);
    }
    else if (strncmp(vr, "FD", 2) == 0)  {      /* Double Float. Can be VM > 1, but not yet supported */

        gdouble vald = tvb_get_ieee_double(tvb, offset, encoding);

        proto_tree_add_bytes_format_value(tree, hf_dcm_tag_value_byte, tvb, offset, 8, NULL, "%f", vald);

        *tag_value = wmem_strdup_printf(pinfo->pool, "%f", vald);
    }
    else if (strncmp(vr, "SL", 2) == 0)  {      /* Signed Long. Can be VM > 1, but not yet supported */
        gint32  val32;

        proto_tree_add_item_ret_int(tree, hf_dcm_tag_value_32s, tvb, offset, 4, encoding, &val32);

        *tag_value = wmem_strdup_printf(pinfo->pool, "%d", val32);
    }
    else if (strncmp(vr, "SS", 2) == 0)  {          /* Signed Short. Can be VM > 1, but not yet supported */
        gint32  val32;

        proto_tree_add_item_ret_int(tree, hf_dcm_tag_value_16s, tvb, offset, 2, encoding, &val32);

        *tag_value = wmem_strdup_printf(pinfo->pool, "%d", val32);
    }
    else if (strncmp(vr, "UL", 2) == 0)  {          /* Unsigned Long. Can be VM > 1, but not yet supported */
        guint32  val32;

        proto_tree_add_item_ret_uint(tree, hf_dcm_tag_value_32u, tvb, offset, 4, encoding, &val32);

        *tag_value = wmem_strdup_printf(pinfo->pool, "%u", val32);
    }
    else if (strncmp(vr, "US", 2) == 0)  {          /* Unsigned Short. Can be VM > 1, but not yet supported */
        const gchar *status_message = NULL;
        guint16     val16 = tvb_get_guint16(tvb, offset, encoding);

        if (grp == 0x0000 && elm == 0x0100) {
            /* This is a command */
            pdv->command = wmem_strdup(wmem_file_scope(), val_to_str(val16, dcm_cmd_vals, " "));
            *tag_value = pdv->command;
        }
        else if (grp == 0x0000 && elm == 0x0900) {
            /* This is a status message. If value is not 0x0000, add an expert info */

            status_message = dcm_rsp2str(val16);
            *tag_value = wmem_strdup_printf(pinfo->pool, "%s (0x%02x)", status_message, val16);

            if ((val16 & 0xFF00) == 0xFF00) {
                /* C-FIND also has a 0xFF01 as a valid response */
                pdv->is_pending = TRUE;
            }
            else if (val16 != 0x0000) {
                /* Neither success nor pending */
                pdv->is_warning = TRUE;
            }

            pdv->status = wmem_strdup(wmem_file_scope(), status_message);

        }
        else {
            *tag_value = wmem_strdup_printf(pinfo->pool, "%u", val16);
        }

        if (grp == 0x0000) {
            if (elm == 0x0110) {                /* (0000,0110) Message ID */
                pdv->message_id = val16;
            }
            else if (elm == 0x0120) {           /* (0000,0120) Message ID Being Responded To */
                pdv->message_id_resp = val16;
            }
            else if (elm == 0x1020) {           /* (0000,1020) Number of Remaining Sub-operations */
                pdv->no_remaining = val16;
            }
            else if (elm == 0x1021) {           /* (0000,1021) Number of Completed Sub-operations */
                pdv->no_completed = val16;
            }
            else if (elm == 0x1022) {           /* (0000,1022) Number of Failed Sub-operations  */
                pdv->no_failed = val16;
            }
            else if (elm == 0x1023) {           /* (0000,1023) Number of Warning Sub-operations */
                pdv->no_warning = val16;
            }
        }

        pitem = proto_tree_add_uint_format_value(tree, hf_dcm_tag_value_16u, tvb, offset, 2,
                    val16, "%s", *tag_value);

        if (pdv->is_warning && status_message) {
            expert_add_info(pinfo, pitem, &ei_dcm_status_msg);
        }
    }
    /* Invalid VR, can only occur with Explicit syntax */
    else {
        proto_tree_add_bytes_format_value(tree, hf_dcm_tag_value_byte, tvb, offset, vl_max,
            NULL, "%s", (vl > vl_max ? "" : "(unknown VR)"));

        *tag_value = wmem_strdup(pinfo->pool, "(unknown VR)");
    }
    offset += vl_max;

    return offset;

}

/*
Return true, if the required size does not fit at position 'offset'.
*/
static gboolean
dcm_tag_is_open(dcm_state_pdv_t *pdv, guint32 startpos, guint32 offset, guint32 endpos, guint32 size_required)
{

    if (offset + size_required > endpos) {

        pdv->open_tag.is_header_fragmented = TRUE;
        pdv->open_tag.len_decoded = endpos - startpos;

        return TRUE;
    }
    else {
        return FALSE;
    }
}

static dcm_tag_t*
dcm_tag_lookup(guint16 grp, guint16 elm)
{

    static dcm_tag_t *tag_def = NULL;

    static dcm_tag_t tag_unknown         = { 0x00000000, "(unknown)", "UN", "1", 0, 0};
    static dcm_tag_t tag_private         = { 0x00000000, "Private Tag", "UN", "1", 0, 0 };
    static dcm_tag_t tag_private_grp_len = { 0x00000000, "Private Tag Group Length", "UL", "1", 0, 0 };
    static dcm_tag_t tag_grp_length      = { 0x00000000, "Group Length", "UL", "1", 0, 0 };

    /* Try a direct hit first before doing a masked search */
    tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER(((guint32)grp << 16) | elm));

    if (tag_def == NULL) {

        /* No match found */
        if ((grp & 0x0001) && (elm == 0x0000)) {
            tag_def = &tag_private_grp_len;
        }
        else if (grp & 0x0001) {
            tag_def = &tag_private;
        }
        else if (elm == 0x0000) {
            tag_def = &tag_grp_length;
        }

        /* There are a few tags that require a mask to be found */
        else if (((grp & 0xFF00) == 0x5000) || ((grp & 0xFF00) == 0x6000) || ((grp & 0xFF00) == 0x7F00)) {
            /* Do a special for groups 0x50xx, 0x60xx and 0x7Fxx */
            tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER((((guint32)grp & 0xFF00) << 16) | elm));
        }
        else if ((grp == 0x0020) && ((elm & 0xFF00) == 0x3100)) {
            tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER(((guint32)grp << 16) | (elm & 0xFF00)));
        }
        else if ((grp == 0x0028) && ((elm & 0xFF00) == 0x0400)) {
            /* This map was done to 0x041x */
            tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER(((guint32)grp << 16) | (elm & 0xFF0F) | 0x0010));
        }
        else if ((grp == 0x0028) && ((elm & 0xFF00) == 0x0800)) {
            tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER(((guint32)grp << 16) | (elm & 0xFF0F)));
        }
        else if (grp == 0x1000) {
            tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER(((guint32)grp << 16) | (elm & 0x000F)));
        }
        else if (grp == 0x1010) {
            tag_def = (dcm_tag_t *)wmem_map_lookup(dcm_tag_table, GUINT_TO_POINTER(((guint32)grp << 16) | (elm & 0x0000)));
        }

        if (tag_def == NULL) {
            /* Still no match found */
            tag_def = &tag_unknown;
        }
    }

    return tag_def;
}

static gchar*
dcm_tag_summary(packet_info *pinfo, guint16 grp, guint16 elm, guint32 vl, const gchar *tag_desc, const gchar *vr,
                gboolean is_retired, gboolean is_implicit)
{

    gchar *desc_mod;
    gchar *tag_vl;
    gchar *tag_sum;

    if (is_retired) {
        desc_mod = wmem_strdup_printf(pinfo->pool, "(Retired) %-35.35s", tag_desc);
    }
    else {
        desc_mod = wmem_strdup_printf(pinfo->pool, "%-45.45s", tag_desc);
    }

    if (vl == 0xFFFFFFFF) {
        tag_vl = wmem_strdup_printf(pinfo->pool, "%10.10s", "<udef>");
    }
    else {
        tag_vl = wmem_strdup_printf(pinfo->pool, "%10u", vl);           /* Show as dec */
    }

    if (is_implicit)    tag_sum = wmem_strdup_printf(pinfo->pool, "(%04x,%04x) %s %s", grp, elm, tag_vl, desc_mod);
    else                tag_sum = wmem_strdup_printf(pinfo->pool, "(%04x,%04x) %s %s [%s]", grp, elm, tag_vl, desc_mod, vr);

    return tag_sum;
}

/*
Decode one tag. If it is a sequence or item start create a subtree. Returns new offset.
http://dicom.nema.org/medical/dicom/current/output/chtml/part05/chapter_7.html
*/
static guint32
dissect_dcm_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                dcm_state_pdv_t *pdv, guint32 offset, guint32 endpos,
                gboolean is_first_tag, const gchar **tag_description,
                gboolean *end_of_seq_or_item)
{


    proto_tree  *tag_ptree = NULL;      /* Tree for decoded tag details */
    proto_tree  *seq_ptree = NULL;      /* Possible subtree for sequences and items */

    proto_item  *tag_pitem = NULL;
    dcm_tag_t   *tag_def   = NULL;

    gint ett;

    const gchar *vr = NULL;
    gchar       *tag_value = "";      /* Tag Value converted to a string      */
    gchar       *tag_summary;

    guint32 vl = 0;
    guint16 vl_1 = 0;
    guint16 vl_2 = 0;

    guint32 offset_tag   = 0;           /* Remember offsets for tree, since the tree    */
    guint32 offset_vr    = 0;           /* header is created pretty late                */
    guint32 offset_vl    = 0;

    guint32 vl_max = 0;                 /* Max Value Length to Parse */

    guint16 grp = 0;
    guint16 elm = 0;

    guint32 len_decoded_remaing = 0;

    /* Decode the syntax a little more */
    guint32 encoding = (pdv->syntax == DCM_EBE) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN;
    gboolean is_implicit = (pdv->syntax == DCM_ILE);
    gboolean is_vl_long = FALSE;            /* True for 4 Bytes length fields */

    gboolean is_sequence = FALSE;           /* True for Sequence Tags */
    gboolean is_item = FALSE;               /* True for Sequence Item Tags */

    *tag_description = NULL;                /* Reset description. It's wmem packet scope memory, so not really bad*/

    offset_tag = offset;


    if (pdv->prev && is_first_tag) {
        len_decoded_remaing = pdv->prev->open_tag.len_decoded;
    }


    /* Since we may have a fragmented header, check for every attribute,
       whether we have already decoded left-overs from the previous PDV.
       Since we have implicit & explicit syntax, copying the open tag to
       a buffer without decoding, would have caused tvb_get_xxtohs()
       implementations on the copy.

       An alternative approach would have been to resemble the PDVs first.

       The attempts to reassemble without named sources (to be implemented)
       were very sensitive to missing packets. In such a case, no packet
       of a PDV chain was decoded, not even the start.

       So for the time being, use this rather cumbersome approach.

       For every two bytes (PDV length are always a factor of 2)
       check whether we have enough data in the buffer and store the value
       accordingly. In the next frame check, whether we have decoded this yet.
    */

    /* Group */
    if (len_decoded_remaing >= 2) {
        grp = pdv->prev->open_tag.grp;
        len_decoded_remaing -= 2;
    }
    else {

        if (dcm_tag_is_open(pdv, offset_tag, offset, endpos, 2))
             return endpos; /* Exit if needed */

        grp = tvb_get_guint16(tvb, offset, encoding);
        offset += 2;
        pdv->open_tag.grp = grp;
    }

    /* Element */
    if (len_decoded_remaing >= 2) {
        elm = pdv->prev->open_tag.elm;
        len_decoded_remaing -= 2;
    }
    else {

        if (dcm_tag_is_open(pdv, offset_tag, offset, endpos, 2))
             return endpos;    /* Exit if needed */

        elm = tvb_get_guint16(tvb, offset, encoding);
        offset += 2;
        pdv->open_tag.elm = elm;
    }

    /* Find the best matching tag */
    tag_def = dcm_tag_lookup(grp, elm);

    /* Value Representation */
    offset_vr = offset;
    if ((grp == 0xFFFE) && (elm == 0xE000 || elm == 0xE00D || elm == 0xE0DD))  {
        /* Item start, Item Delimitation or Sequence Delimitation */
        vr = "UL";
        is_vl_long = TRUE;                          /* These tags always have a 4 byte length field */
    }
    else if (is_implicit) {
        /* Get VR from tag definition */
        vr = wmem_strdup(pinfo->pool, tag_def->vr);
        is_vl_long = TRUE;                          /* Implicit always has 4 byte length field */
    }
    else {

        if (len_decoded_remaing >= 2) {
            vr = wmem_strdup(pinfo->pool, pdv->prev->open_tag.vr);
            len_decoded_remaing -= 2;
        }
        else {

            /* Controlled exit, if VR does not fit. */
            if (dcm_tag_is_open(pdv, offset_tag, offset_vr, endpos, 2))
                return endpos;

            vr = (gchar *)tvb_get_string_enc(pinfo->pool, tvb, offset, 2, ENC_ASCII);
            offset += 2;

            g_free(pdv->open_tag.vr);
            pdv->open_tag.vr = g_strdup(vr);        /* needs to survive within a session */
        }

        if ((strcmp(vr, "OB") == 0) || (strcmp(vr, "OW") == 0) || (strcmp(vr, "OF") == 0) || (strcmp(vr, "OD") == 0) || (strcmp(vr, "OL") == 0) ||
            (strcmp(vr, "SQ") == 0) || (strcmp(vr, "UC") == 0) || (strcmp(vr, "UR") == 0) || (strcmp(vr, "UT") == 0) || (strcmp(vr, "UN") == 0)) {
            /* Part 5, Table 7.1-1 in the standard */
            /* Length is always 4 bytes: OB, OD, OF, OL, OW, SQ, UC, UR, UT or UN */

            is_vl_long = TRUE;

            /* Skip 2 Bytes */
            if (len_decoded_remaing >= 2) {
                len_decoded_remaing -= 2;
            }
            else {
                if (dcm_tag_is_open(pdv, offset_tag, offset_vr, endpos, 2))
                    return endpos;
                offset += 2;
            }
        }
        else {
            is_vl_long = FALSE;
        }
    }


    /* Value Length. This is rather cumbersome code to get a 4 byte length, but in the
       fragmented case, we have 2*2 bytes. So always use that pattern
    */

    offset_vl = offset;
    if (len_decoded_remaing >= 2) {
        vl_1 = pdv->prev->open_tag.vl_1;
        len_decoded_remaing -= 2;
    }
    else {

        if (dcm_tag_is_open(pdv, offset_tag, offset_vl, endpos, 2))
            return endpos;
        vl_1 = tvb_get_guint16(tvb, offset, encoding);
        offset += 2;
        pdv->open_tag.vl_1 = vl_1;
    }

    if (is_vl_long) {

        if (len_decoded_remaing >= 2) {
            vl_2 = pdv->prev->open_tag.vl_2;
        }
        else {

            if (dcm_tag_is_open(pdv, offset_tag, offset_vl+2, endpos, 2))
                return endpos;
            vl_2 = tvb_get_guint16(tvb, offset, encoding);
            offset += 2;
            pdv->open_tag.vl_2 = vl_2;
        }

        if (encoding == ENC_LITTLE_ENDIAN)   vl = (vl_2 << 16) + vl_1;
        else                    vl = (vl_1 << 16) + vl_2;
    }
    else {
        vl = vl_1;
    }

    /* Now we have most of the information, except for sequences and items with undefined
       length :-/. But, whether we know the length or not, we now need to create the tree
       item and subtree, before we can loop into sequences and items

       Display the information we collected so far. Don't wait until the value is parsed,
       because that parsing might cause an exception. If that happens within a sequence,
       the sequence tag would not show up with the value

       Use different ett_ for Sequences & Items, so that fold/unfold state makes sense
    */

    tag_summary = dcm_tag_summary(pinfo, grp, elm, vl, tag_def->description, vr, tag_def->is_retired, is_implicit);
    is_sequence = (strcmp(vr, "SQ") == 0) || (vl == 0xFFFFFFFF);
    is_item = ((grp == 0xFFFE) && (elm == 0xE000));

    if ((is_sequence | is_item) &&  global_dcm_seq_subtree) {
        ett = is_sequence ? ett_dcm_data_seq : ett_dcm_data_item;
    }
    else {
        ett = ett_dcm_data_tag;
    }

    if (vl == 0xFFFFFFFF) {
        /* 'Just' mark header as the length of the item */
        tag_ptree = proto_tree_add_subtree(tree, tvb, offset_tag, offset - offset_tag, ett, &tag_pitem, tag_summary);
        vl_max = 0;         /* We don't know who long this sequence/item is */
    }
    else if (offset + vl <= endpos) {
        /* Show real length of item */
        tag_ptree = proto_tree_add_subtree(tree, tvb, offset_tag, offset + vl - offset_tag, ett, &tag_pitem, tag_summary);
        vl_max = vl;
    }
    else {
        /* Value is longer than what we have in the PDV, -> we do have a OPEN tag */
        tag_ptree = proto_tree_add_subtree(tree, tvb, offset_tag, endpos - offset_tag, ett, &tag_pitem, tag_summary);
        vl_max = endpos - offset;
    }

    /* If you are going to touch the following 25 lines, make sure you reserve a few hours to go
        through both display options and check for proper tree display :-)
    */
    if (is_sequence | is_item) {

        if (global_dcm_seq_subtree) {
            /* Use different ett_ for Sequences & Items, so that fold/unfold state makes sense */
            seq_ptree = tag_ptree;
            if (!global_dcm_tag_subtree) {
                tag_ptree = NULL;
            }
        }
        else {
            seq_ptree = tree;
            if (!global_dcm_tag_subtree) {
                tag_ptree = NULL;
            }
        }
    }
    else {
        /* For tags */
        if (!global_dcm_tag_subtree) {
            tag_ptree = NULL;
        }
    }

    /*  ---------------------------------------------------------------
        Tag details as separate items
        ---------------------------------------------------------------
    */

    proto_tree_add_uint_format_value(tag_ptree, hf_dcm_tag, tvb, offset_tag, 4,
        (grp << 16) | elm, "%04x,%04x (%s)", grp, elm, tag_def->description);

    /* Add VR to tag detail, except for sequence items */
    if (!is_item)  {
        if (is_implicit) {
            /* Select header, since no VR is present in implicit syntax */
            proto_tree_add_string(tag_ptree, hf_dcm_tag_vr, tvb, offset_tag, 4, vr);
        }
        else {
            proto_tree_add_string(tag_ptree, hf_dcm_tag_vr, tvb, offset_vr,  2, vr);
        }
    }

    /* Add length to tag detail */
    proto_tree_add_uint(tag_ptree, hf_dcm_tag_vl, tvb, offset_vl, (is_vl_long ? 4 : 2), vl);


    /*  ---------------------------------------------------------------
        Finally the Tag Value
        ---------------------------------------------------------------
    */
    if ((is_sequence || is_item) && (vl > 0)) {
        /* Sequence or Item Start */

        guint32 endpos_item = 0;
        gboolean local_end_of_seq_or_item = FALSE;
        gboolean is_first_desc = TRUE;

        const gchar *item_description = NULL;       /* Will be allocated as wmem packet scope memory in dissect_dcm_tag() */

        if (vl == 0xFFFFFFFF) {
            /* Undefined length */

            while ((!local_end_of_seq_or_item) && (!pdv->open_tag.is_header_fragmented) && (offset < endpos)) {

                offset = dissect_dcm_tag(tvb, pinfo, seq_ptree, pdv, offset, endpos, FALSE, &item_description, &local_end_of_seq_or_item);

                if (item_description && global_dcm_seq_subtree) {
                    proto_item_append_text(tag_pitem, (is_first_desc ? " %s" : ", %s"), item_description);
                    is_first_desc = FALSE;
                }
            }
        }
        else {
            /* Defined length */
            endpos_item = offset + vl_max;

            while (offset < endpos_item) {

                offset = dissect_dcm_tag(tvb, pinfo, seq_ptree, pdv, offset, endpos_item, FALSE, &item_description, &local_end_of_seq_or_item);

                if (item_description && global_dcm_seq_subtree) {
                    proto_item_append_text(tag_pitem, (is_first_desc ? " %s" : ", %s"), item_description);
                    is_first_desc = FALSE;
                }
            }
        }
    } /*  if ((is_sequence || is_item) && (vl > 0)) */
    else if ((grp == 0xFFFE) && (elm == 0xE00D)) {
        /* Item delimitation for items with undefined length */
        *end_of_seq_or_item = TRUE;
    }
    else if ((grp == 0xFFFE) && (elm == 0xE0DD)) {
        /* Sequence delimitation for sequences with undefined length */
        *end_of_seq_or_item = TRUE;
    }
    else if (vl == 0) {
        /* No value for this tag */

        /*  The following copy is needed. tag_value is post processed with g_strstrip()
            and that one will crash the whole application, when a constant is used.
        */

        tag_value = wmem_strdup(pinfo->pool, "<Empty>");
    }
    else if (vl > vl_max) {
        /* Tag is longer than the PDV/PDU. Don't perform any decoding */

        gchar *tag_desc;

        proto_tree_add_bytes_format(tag_ptree, hf_dcm_tag_value_byte, tvb, offset, vl_max,
            NULL, "%-8.8sBytes %d - %d [start]", "Value:", 1, vl_max);

        tag_value = wmem_strdup_printf(pinfo->pool, "<Bytes %d - %d, start>", 1, vl_max);
        offset += vl_max;

        /*  Save the needed data for reuse, and subsequent packets
            This will leak a little within the session.

            But since we may have tags being closed and reopen in the same PDV
            we will always need to store this
        */

        tag_desc = dcm_tag_summary(pinfo, grp, elm, vl, tag_def->description, vr, tag_def->is_retired, is_implicit);

        if (pdv->open_tag.desc == NULL) {
            pdv->open_tag.is_value_fragmented = TRUE;
            pdv->open_tag.desc = wmem_strdup(wmem_file_scope(), tag_desc);
            pdv->open_tag.len_total = vl;
            pdv->open_tag.len_remaining = vl - vl_max;
        }
    }
    else {
        /* Regular value. Identify the type, decode and display */

        offset = dissect_dcm_tag_value(tvb, pinfo, tag_ptree, pdv, offset, grp, elm, vl, vl_max, vr, &tag_value);

        /* -------------------------------------------------------------
           We have decoded the value. Now store those tags of interest
           -------------------------------------------------------------
        */

        /* Store SOP Class and Instance UID in first PDV of this object */
        if (grp == 0x0008 && elm == 0x0016) {
            dcm_state_pdv_get_obj_start(pdv)->sop_class_uid = wmem_strdup(wmem_file_scope(), tag_value);
        }
        else if (grp == 0x0008 && elm == 0x0018) {
            dcm_state_pdv_get_obj_start(pdv)->sop_instance_uid = wmem_strdup(wmem_file_scope(), tag_value);
        }
        else if (grp == 0x0000 && elm == 0x0100) {
            /* This is the command tag -> overwrite existing PDV description */
            pdv->desc = wmem_strdup(wmem_file_scope(), tag_value);
        }
    }


    /* -------------------------------------------------------------------
       Add the value to the already constructed item
       -------------------------------------------------------------------
    */

    proto_item_append_text(tag_pitem, " %s", tag_value);

    if (tag_def->add_to_summary) {
        *tag_description = wmem_strdup(pinfo->pool, g_strstrip(tag_value));
    }

    return offset;
}

/*
'Decode' open tags from previous PDV. It mostly ends in 'continuation' or 'end' in the description.
*/
static guint32
dissect_dcm_tag_open(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                dcm_state_pdv_t *pdv, guint32 offset, guint32 endpos, gboolean *is_first_tag)
{

    proto_item *pitem = NULL;

    guint32 tag_value_fragment_len = 0;

    if ((pdv->prev) && (pdv->prev->open_tag.len_remaining > 0))  {
        /* Not first PDV in the given presentation context (Those don't have remaining data to parse :-) */
        /* And previous PDV has left overs, i.e. this is a continuation PDV */

        if (endpos - offset >= pdv->prev->open_tag.len_remaining) {
            /*
               Remaining bytes are equal or more than we expect for the open tag
               Finally reach the end of this tag. Don't touch the open_tag structure
               of this PDV, as we may see a new open tag at the end
            */
            tag_value_fragment_len = pdv->prev->open_tag.len_remaining;
            pdv->is_corrupt = FALSE;
        }
        else if (pdv->is_flagvalid && pdv->is_last_fragment) {
            /*
              The tag is not yet complete, however, the flag indicates that it should be
              Therefore end this tag and issue an expert_add_info. Don't touch the
              open_tag structure of this PDV, as we may see a new open tag at the end
            */
            tag_value_fragment_len = endpos - offset;
            pdv->is_corrupt = TRUE;
        }
        else {
            /*
             * More to do for this tag
             */
            tag_value_fragment_len = endpos - offset;

            /* Set data in current PDV structure */
            if (!pdv->open_tag.is_value_fragmented)  {
                /* No need to do it twice or more */

                pdv->open_tag.is_value_fragmented = TRUE;
                pdv->open_tag.len_total = pdv->prev->open_tag.len_total;
                pdv->open_tag.len_remaining = pdv->prev->open_tag.len_remaining - tag_value_fragment_len;
                pdv->open_tag.desc = wmem_strdup(wmem_file_scope(), pdv->prev->open_tag.desc);

            }
            pdv->is_corrupt = FALSE;
        }

        if (pdv->is_corrupt) {
            pitem = proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
                offset, tag_value_fragment_len, NULL,
                "%s <incomplete>", pdv->prev->open_tag.desc);

            expert_add_info(pinfo, pitem, &ei_dcm_data_tag);

        }
        else {
            proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
                offset, tag_value_fragment_len, NULL,
                "%s <Bytes %d - %d, %s>", pdv->prev->open_tag.desc,
                pdv->prev->open_tag.len_total - pdv->prev->open_tag.len_remaining + 1,
                pdv->prev->open_tag.len_total - pdv->prev->open_tag.len_remaining + tag_value_fragment_len,
                (pdv->prev->open_tag.len_remaining > tag_value_fragment_len ? "continuation" : "end") );
        }

        offset += tag_value_fragment_len;
        *is_first_tag = FALSE;
    }

    return offset;
}

/*
Decode the tag section inside a PDV. This can be a single combined dataset
or DICOM natively split PDVs. Therefore it needs to resume previously opened tags.
For data PDVs, only process tags when tree is set or listening to export objects tap.
For command PDVs, process all tags.
On export copy the content to the export buffer.
*/
static guint32
dissect_dcm_pdv_body(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        dcm_state_assoc_t *assoc,
        dcm_state_pdv_t *pdv,
        guint32 offset,
        guint32 pdv_body_len,
        gchar **pdv_description)
{
    const gchar *tag_value = NULL;
    gboolean dummy = FALSE;
    guint32 startpos = offset;
    guint32 endpos = 0;

    endpos = offset + pdv_body_len;

    if (pdv->is_command || tree || have_tap_listener(dicom_eo_tap)) {
        /* Performance optimization starts here. Don't put any COL_INFO related stuff in here */

        if (pdv->syntax == DCM_UNK) {
            /* Eventually, we will have a syntax detector. Until then, don't decode */

            proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
                offset, pdv_body_len, NULL,
                "(%04x,%04x) %-8x Unparsed data", 0, 0, pdv_body_len);
        }
        else {

            gboolean is_first_tag = TRUE;

            /* Treat the left overs */
            offset = dissect_dcm_tag_open(tvb, pinfo, tree, pdv, offset, endpos, &is_first_tag);

            /* Decode all tags, sequences and items in this PDV recursively */
            while (offset < endpos) {
                offset = dissect_dcm_tag(tvb, pinfo, tree, pdv, offset, endpos, is_first_tag, &tag_value, &dummy);
                is_first_tag = FALSE;
            }
        }
    }

    *pdv_description = pdv->desc;

    if (pdv->is_command) {

        if (pdv->is_warning) {
            if (pdv->comment) {
                *pdv_description = wmem_strdup_printf(pinfo->pool, "%s (%s, %s)", pdv->desc, pdv->status, pdv->comment);
            }
            else {
                *pdv_description = wmem_strdup_printf(pinfo->pool, "%s (%s)", pdv->desc, pdv->status);
            }

        }
        else if (global_dcm_cmd_details) {
            /* Show command details in header */

            if (pdv->message_id > 0) {
                *pdv_description = wmem_strdup_printf(pinfo->pool, "%s ID=%d", pdv->desc, pdv->message_id);
            }
            else if (pdv->message_id_resp > 0) {

                *pdv_description = wmem_strdup_printf(pinfo->pool, "%s ID=%d", pdv->desc, pdv->message_id_resp);

                if (pdv->no_completed > 0) {
                    *pdv_description = wmem_strdup_printf(pinfo->pool, "%s C=%d", *pdv_description, pdv->no_completed);
                }
                if (pdv->no_remaining > 0) {
                    *pdv_description = wmem_strdup_printf(pinfo->pool, "%s R=%d", *pdv_description, pdv->no_remaining);
                }
                if (pdv->no_warning > 0) {
                    *pdv_description = wmem_strdup_printf(pinfo->pool, "%s W=%d", *pdv_description, pdv->no_warning);
                }
                if (pdv->no_failed > 0) {
                    *pdv_description = wmem_strdup_printf(pinfo->pool, "%s F=%d", *pdv_description, pdv->no_failed);
                }
                if (!pdv->is_pending && pdv->status)
                {
                    *pdv_description = wmem_strdup_printf(pinfo->pool, "%s (%s)", *pdv_description, pdv->status);
                }
            }
        }
    }

    if (have_tap_listener(dicom_eo_tap)) {

        if (pdv->data_len == 0) {
            /* Copy pure DICOM data to buffer, without PDV flags
               Packet scope for the memory allocation is too small, since we may have PDV in different tvb.
               Therefore check if this was already done.
            */
            pdv->data = wmem_alloc0(wmem_file_scope(), pdv_body_len);
            pdv->data_len = pdv_body_len;
            tvb_memcpy(tvb, pdv->data, startpos, pdv_body_len);
        }
        if ((pdv_body_len > 0) && (pdv->is_last_fragment)) {
            /* At the last segment, merge all related previous PDVs and copy to export buffer */
            dcm_export_create_object(pinfo, assoc, pdv);
        }
    }

    return endpos;
}

/*
Handle one PDV inside a data PDU. When needed, perform the reassembly of PDV fragments.
PDV fragments are different from TCP fragmentation.
Create PDV object when needed.
Return pdv_description to be used e.g. in COL_INFO.
*/
static guint32
dissect_dcm_pdv_fragmented(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                dcm_state_assoc_t *assoc, guint32 offset, guint32 pdv_len, gchar **pdv_description)
{

    conversation_t  *conv = NULL;

    dcm_state_pdv_t *pdv = NULL;

    tvbuff_t *combined_tvb = NULL;
    fragment_head *head = NULL;

    guint32 reassembly_id;
    guint32 pdv_body_len;

    pdv_body_len = pdv_len-2;

    /* Dissect Context ID, Find PDV object, Decode Command/Data flag and More Fragments flag */
    offset = dissect_dcm_pdv_header(tvb, pinfo, tree, assoc, offset, &pdv);

    if (global_dcm_reassemble)
    {
        /* Combine the different PDVs. This is the default preference and useful in most scenarios.
           This will create one 'huge' PDV. E.g. a CT image will fits in one buffer.
        */
        conv = find_conversation_pinfo(pinfo, 0);

        /* Try to create somewhat unique ID.
           Include the conversation index, to separate TCP session
           Include bits from the reassembly number in the current Presentation
           Context (that we track ourselves) in order to distinguish between
           PDV fragments from the same frame but different reassemblies.
        */
        DISSECTOR_ASSERT(conv);

        /* The following expression seems to executed late in VS2017 in 'RelWithDebInf'.
           Therefore it may appear as 0 at first
        */
        reassembly_id = (((conv->conv_index) & 0x000FFFFF) << 12) +
                        ((guint32)(pdv->pctx_id) << 4) + ((guint32)(pdv->reassembly_id & 0xF));

        /* This one will chain the packets until 'is_last_fragment' */
        head = fragment_add_seq_next(
            &dcm_pdv_reassembly_table,
            tvb,
            offset,
            pinfo,
            reassembly_id,
            NULL,
            pdv_body_len,
            !(pdv->is_last_fragment));

        if (head && (head->next == NULL)) {
            /* Was not really fragmented, therefore use 'conventional' decoding.
               process_reassembled_data() does not cope with two PDVs in the same frame, therefore catch it here
            */

            offset = dissect_dcm_pdv_body(tvb, pinfo, tree, assoc, pdv, offset, pdv_body_len, pdv_description);
        }
        else
        {
            /* Will return a complete buffer, once last fragment is hit.
               The description is not used in packet-dcm. COL_INFO is set specifically in dissect_dcm_pdu()
            */
            combined_tvb = process_reassembled_data(
                tvb,
                offset,
                pinfo,
                "Reassembled PDV",
                head,
                &dcm_pdv_fragment_items,
                NULL,
                tree);

            if (combined_tvb == NULL) {
                /* Just show this as a fragment */

                if (head && head->reassembled_in != pinfo->num) {

                    if (pdv->desc) {
                        /* We know the presentation context already */
                        *pdv_description = wmem_strdup_printf(pinfo->pool, "%s (reassembled in #%u)", pdv->desc, head->reassembled_in);
                    }
                    else {
                        /* Decoding of the presentation context did not occur yet or did not succeed */
                        *pdv_description = wmem_strdup_printf(pinfo->pool, "PDV Fragment (reassembled in #%u)", head->reassembled_in);
                    }
                }
                else {
                    /* We don't know the last fragment yet (and/or we'll never see it).
                       This can happen, e.g. when TCP packet arrive our of order.
                    */
                    *pdv_description = wmem_strdup(pinfo->pool, "PDV Fragment");
                }

                offset += pdv_body_len;
            }
            else {
                /* Decode reassembled data. This needs to be += */
                offset += dissect_dcm_pdv_body(combined_tvb, pinfo, tree, assoc, pdv, 0, tvb_captured_length(combined_tvb), pdv_description);
            }
        }
    }
    else {
        /* Do not reassemble DICOM PDVs, i.e. decode PDVs one by one.
           This may be useful when troubleshooting PDU length issues,
           or to better understand the PDV split.
           The tag level decoding is more challenging, as leftovers need
           to be displayed adequately. Not a big deal for binary values.
        */
        offset = dissect_dcm_pdv_body(tvb, pinfo, tree, assoc, pdv, offset, pdv_body_len, pdv_description);
    }

    return offset;
}

static guint32
dissect_dcm_pdu_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     dcm_state_assoc_t *assoc, guint32 offset, guint32 pdu_len, gchar **pdu_data_description)
{

    /*  04 P-DATA-TF
         1  1 reserved
         2  4 length
              - (1+) presentation data value (PDV) items
         6  4 length
        10  1 Presentation Context ID (odd ints 1 - 255)
              - PDV
        11  1 header
              0x01 if set, contains Message Command info, else Message Data
              0x02 if set, contains last fragment
    */

    proto_tree *pdv_ptree;      /* Tree for item details */
    proto_item *pdv_pitem, *pdvlen_item;

    gchar  *buf_desc = NULL;            /* PDU description */
    gchar  *pdv_description = NULL;

    gboolean first_pdv = TRUE;

    guint32 endpos = 0;
    guint32 pdv_len = 0;

    endpos = offset + pdu_len;

    /* Loop through multiple PDVs */
    while (offset < endpos) {

        pdv_len = tvb_get_ntohl(tvb, offset);

        pdv_ptree = proto_tree_add_subtree(tree, tvb, offset, pdv_len+4, ett_dcm_data_pdv, &pdv_pitem, "PDV");

        pdvlen_item = proto_tree_add_item(pdv_ptree, hf_dcm_pdv_len, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if ((pdv_len + 4 > pdu_len)  || (pdv_len + 4 < pdv_len)) {
            expert_add_info_format(pinfo, pdvlen_item, &ei_dcm_pdv_len, "Invalid PDV length (too large)");
            return endpos;
        }
        else if (pdv_len <= 2) {
            expert_add_info_format(pinfo, pdvlen_item, &ei_dcm_pdv_len, "Invalid PDV length (too small)");
            return endpos;
        }
        else if (((pdv_len >> 1) << 1) != pdv_len) {
            expert_add_info_format(pinfo, pdvlen_item, &ei_dcm_pdv_len, "Invalid PDV length (not even)");
            return endpos;
        }

        offset = dissect_dcm_pdv_fragmented(tvb, pinfo, pdv_ptree, assoc, offset, pdv_len, &pdv_description);

        /* The following doesn't seem to work anymore */
        if (pdv_description) {
            if (first_pdv) {
                buf_desc = wmem_strdup(pinfo->pool, pdv_description);
            }
            else {
                buf_desc = wmem_strdup_printf(pinfo->pool, "%s, %s", buf_desc, pdv_description);
            }
        }

        proto_item_append_text(pdv_pitem, ", %s", pdv_description);
        first_pdv=FALSE;

    }

    *pdu_data_description = buf_desc;

    return offset;
}


/*
Test for DICOM traffic.

- Minimum 10 Bytes
- Look for the association request
- Check PDU size vs TCP payload size

Since used in heuristic mode, be picky for performance reasons.
We are called in static mode, once we decoded the association request and called conversation_set_dissector()
They we can be more liberal on the packet selection
*/
static gboolean
test_dcm(tvbuff_t *tvb)
{

    guint8  pdu_type;
    guint32 pdu_len;
    guint16 vers;

    /*
    Ensure that the tvb_captured_length is big enough before fetching the values.
    Otherwise it can trigger an exception during the heuristic check,
    preventing next heuristic dissectors from being called

    tvb_reported_length() is the real size of the packet as transmitted on the wire
    tvb_captured_length() is the number of bytes captured (so you always have captured <= reported).

    The 10 bytes represent an association request header including the 2 reserved bytes not used below
    In the captures at hand, the parsing result was equal.
    */

    if (tvb_captured_length(tvb) < 8) {
        return FALSE;
    }
    if (tvb_reported_length(tvb) < 10) {
        return FALSE;
    }

    pdu_type = tvb_get_guint8(tvb, 0);
    pdu_len = tvb_get_ntohl(tvb, 2);
    vers = tvb_get_ntohs(tvb, 6);

    /* Exit, if not an association request at version 1 */
    if (!(pdu_type == 1 && vers == 1)) {
        return FALSE;
    }

    /* Exit if TCP payload is bigger than PDU length (plus header)
    OK for PRESENTATION_DATA, questionable for ASSOCIATION requests
    */
    if (tvb_reported_length(tvb) > pdu_len + 6) {
        return FALSE;
    }

    return TRUE;
}

/*
Main function to decode DICOM traffic. Supports reassembly of TCP packets.
*/
static int
dissect_dcm_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_port_static)
{

    guint8  pdu_type = 0;
    guint32 pdu_start = 0;
    guint32 pdu_len = 0;
    guint32 tlen = 0;

    int offset = 0;

    /*
        TCP packets are assembled well by wireshark in conjunction with the dissectors.

        Therefore, we will only see properly aligned PDUs, at the beginning of the buffer.
        So if the buffer does not start with the PDU header, it's not DICOM traffic.

        Do the byte checking as early as possible.
        The heuristic hook requires an association request

        DICOM PDU are nice, but need to be managed

        We can have any combination:
        - One or more DICOM PDU per TCP packet
        - PDU split over different TCP packets
        - And both together, i.e. some complete PDUs and then a fraction of a new PDU in a TCP packet

        This function will handle multiple PDUs per TCP packet and will ask for more data,
        if the last PDU does not fit

        It does not reassemble fragmented PDVs by purpose, since the Tag Value parsing needs to be done
        per Tag, and PDU recombination here would
        a) need to eliminate PDU/PDV/Ctx header (12 bytes)
        b) not show the true DICOM logic in transfer

        The length check is tricky. If not a PDV continuation, 10 Bytes are required. For PDV continuation
        anything seems to be possible, depending on the buffer alignment of the sending process.

    */

    tlen = tvb_reported_length(tvb);

    pdu_type = tvb_get_guint8(tvb, 0);
    if (pdu_type == 0 || pdu_type > 7)          /* Wrong PDU type. 'Or' is slightly more efficient than 'and' */
        return 0;                               /* No bytes taken from the stack */

    if (is_port_static) {
        /* Port is defined explicitly, or association request was previously found successfully.
           Be more tolerant on minimum packet size. Also accept < 6
        */

        if (tlen < 6) {
            /* we need 6 bytes at least to get PDU length */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return tvb_captured_length(tvb);
        }
    }


    /* Passing this point, we should always have tlen >= 6 */

    pdu_len = tvb_get_ntohl(tvb, 2);
    if (pdu_len < 4)                /* The smallest PDUs are ASSOC Rejects & Release messages */
        return 0;

    /* Mark it. This is a DICOM packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DICOM");

     /* Process all PDUs in the buffer */
    while (pdu_start < tlen) {
        guint32 old_pdu_start;

        if ((pdu_len+6) > (tlen-offset)) {

            /*  PDU is larger than the remaining packet (buffer), therefore request whole PDU
                The next time this function is called, tlen will be equal to pdu_len
            */

            pinfo->desegment_offset = offset;
            pinfo->desegment_len = (pdu_len+6) - (tlen-offset);
            return tvb_captured_length(tvb);
        }

        /* Process a whole PDU */
        offset=dissect_dcm_pdu(tvb, pinfo, tree, pdu_start);

        /* Next PDU */
        old_pdu_start = pdu_start;
        pdu_start =  pdu_start + pdu_len + 6;
        if (pdu_start <= old_pdu_start) {
            expert_add_info_format(pinfo, NULL, &ei_dcm_invalid_pdu_length, "Invalid PDU length (%u)", pdu_len);
            break;
        }

        if (pdu_start < tlen - 6) {
            /* we got at least 6 bytes of the next PDU still in the buffer */
             pdu_len = tvb_get_ntohl(tvb, pdu_start+2);
        }
        else {
            pdu_len = 0;
        }
    }
    return offset;
}

/*
Callback function used to register
*/
static int
dissect_dcm_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Less checking on ports that match */
    return dissect_dcm_main(tvb, pinfo, tree, TRUE);
}

/*
Test for an Association Request. Decode, when successful.
*/
static gboolean
dissect_dcm_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    /* This will be potentially called for every packet */

    if (!test_dcm(tvb))
        return FALSE;

    /*
    Conversation_set_dissector() is called inside dcm_state_get() once
    we have enough details. From there on, we will be 'static'
    */

    if (dissect_dcm_main(tvb, pinfo, tree, FALSE) == 0) {
        /* there may have been another reason why it is not DICOM */
        return FALSE;
    }

    return TRUE;

}

/*
Only set a valued with col_set_str() if it does not yet exist.
(In a multiple PDV scenario, col_set_str() actually appends for the subsequent calls)
*/
static void col_set_str_conditional(column_info *cinfo, const gint el, const gchar* str)
{
    const char *col_string = col_get_text(cinfo, el);

    if (col_string == NULL || !g_str_has_prefix(col_string, str))
    {
        col_add_str(cinfo, el, str);
    }
}

/*
CSV add a value to a column, if it does not exist yet
*/
static void col_append_str_conditional(column_info *cinfo, const gint el, const gchar* str)
{
    const char *col_string = col_get_text(cinfo, el);

    if (col_string == NULL || !g_strrstr(col_string, str))
    {
        col_append_fstr(cinfo, el, ", %s", str);
    }
}

/*
Dissect a single DICOM PDU. Can be an association or a data package. Creates a tree item.
*/
static guint32
dissect_dcm_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
    proto_tree *dcm_ptree=NULL;     /* Root DICOM tree and its item */
    proto_item *dcm_pitem=NULL;

    dcm_state_t *dcm_data=NULL;
    dcm_state_assoc_t *assoc=NULL;

    guint8  pdu_type=0;
    guint32 pdu_len=0;

    gchar *pdu_data_description=NULL;

    /* Get or create conversation. Used to store context IDs and xfer Syntax */

    dcm_data = dcm_state_get(pinfo, TRUE);
    if (dcm_data == NULL) {     /* Internal error. Failed to create main DICOM data structure */
        return offset;
    }

    dcm_pitem = proto_tree_add_item(tree, proto_dcm, tvb, offset, -1, ENC_NA);
    dcm_ptree = proto_item_add_subtree(dcm_pitem, ett_dcm);

    /* PDU type is only one byte, then one byte reserved */
    pdu_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(dcm_ptree, hf_dcm_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    pdu_len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(dcm_ptree, hf_dcm_pdu_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Find previously detected association, else create a new one object*/
    assoc = dcm_state_assoc_get(dcm_data, pinfo->num, TRUE);

    if (assoc == NULL) {        /* Internal error. Failed to create association structure */
        return offset;
    }

    if (pdu_type == 4) {

        col_set_str_conditional(pinfo->cinfo, COL_INFO, "P-DATA");

        /* Everything that needs to be shown in any UI column (like COL_INFO)
           needs to be calculated also with tree == null
        */
        offset = dissect_dcm_pdu_data(tvb, pinfo, dcm_ptree, assoc, offset, pdu_len, &pdu_data_description);

        if (pdu_data_description) {
            proto_item_append_text(dcm_pitem, ", %s", pdu_data_description);
            col_append_str_conditional(pinfo->cinfo, COL_INFO, pdu_data_description);
        }
    }
    else {

        /* Decode Association request, response, reject, abort details */
        offset = dissect_dcm_assoc_header(tvb, pinfo, dcm_ptree, offset, assoc, pdu_type, pdu_len);
    }

    return offset;          /* return the number of processed bytes */
}


/*
Register the protocol with Wireshark
*/
void
proto_register_dcm(void)
{
    static hf_register_info hf[] = {
    { &hf_dcm_pdu_type, { "PDU Type", "dicom.pdu.type",
        FT_UINT8, BASE_HEX, VALS(dcm_pdu_ids), 0, NULL, HFILL } },
    { &hf_dcm_pdu_len, { "PDU Length", "dicom.pdu.len",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

    { &hf_dcm_assoc_version, { "Protocol Version", "dicom.assoc.version",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_called, { "Called  AE Title", "dicom.assoc.ae.called",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_calling, { "Calling AE Title", "dicom.assoc.ae.calling",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_reject_result, { "Result", "dicom.assoc.reject.result",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_reject_source, { "Source", "dicom.assoc.reject.source",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_reject_reason, { "Reason", "dicom.assoc.reject.reason",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_abort_source, { "Source", "dicom.assoc.abort.source",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_abort_reason, { "Reason", "dicom.assoc.abort.reason",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_item_type, { "Item Type", "dicom.assoc.item.type",
        FT_UINT8, BASE_HEX, VALS(dcm_assoc_item_type), 0, NULL, HFILL } },
    { &hf_dcm_assoc_item_len, { "Item Length", "dicom.assoc.item.len",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

    { &hf_dcm_actx, { "Application Context", "dicom.actx",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pctx_id, { "Presentation Context ID", "dicom.pctx.id",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pctx_result, { "Presentation Context Result", "dicom.pctx.result",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pctx_abss_syntax, { "Abstract Syntax", "dicom.pctx.abss.syntax",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pctx_xfer_syntax, { "Transfer Syntax", "dicom.pctx.xfer.syntax",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info, { "User Info", "dicom.userinfo",
        FT_NONE, BASE_NONE, NULL, 0, "This field contains the ACSE User Information Item of the A-ASSOCIATErequest.", HFILL } },
    { &hf_dcm_info_uid, { "Implementation Class UID", "dicom.userinfo.uid",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_version, { "Implementation Version", "dicom.userinfo.version",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_extneg, { "Extended Negotiation", "dicom.userinfo.extneg",
        FT_NONE, BASE_NONE, NULL, 0, "This field contains the optional SOP Class Extended Negotiation Sub-Item of the ACSE User Information Item of the A-ASSOCIATE-RQ/RSP.", HFILL } },
    { &hf_dcm_info_extneg_sopclassuid_len, { "SOP Class UID Length", "dicom.userinfo.extneg.sopclassuid.len",
        FT_UINT16, BASE_DEC, NULL, 0, "This field contains the length of the SOP Class UID in the Extended Negotiation Sub-Item.", HFILL } },
    { &hf_dcm_info_extneg_sopclassuid, { "SOP Class UID", "dicom.userinfo.extneg.sopclassuid",
        FT_STRING, BASE_NONE, NULL, 0, "This field contains the SOP Class UID in the Extended Negotiation Sub-Item.", HFILL } },
    { &hf_dcm_info_extneg_relational_query, { "Relational-queries", "dicom.userinfo.extneg.relational",
        FT_UINT8, BASE_HEX, NULL, 0, "This field indicates, if relational queries are supported.", HFILL } },
    { &hf_dcm_info_extneg_date_time_matching, { "Combined Date-Time matching", "dicom.userinfo.extneg.datetimematching",
        FT_UINT8, BASE_HEX, NULL, 0, "This field indicates, if combined date-time matching is supported.", HFILL } },
    { &hf_dcm_info_extneg_fuzzy_semantic_matching, { "Fuzzy semantic matching", "dicom.userinfo.extneg.fuzzymatching",
        FT_UINT8, BASE_HEX, NULL, 0, "This field indicates, if fuzzy semantic matching of person names is supported.", HFILL } },
    { &hf_dcm_info_extneg_timezone_query_adjustment, { "Timezone query adjustment", "dicom.userinfo.extneg.timezone",
        FT_UINT8, BASE_HEX, NULL, 0, "This field indicates, if timezone query adjustment is supported.", HFILL } },
    { &hf_dcm_info_rolesel, { "SCP/SCU Role Selection", "dicom.userinfo.rolesel",
        FT_NONE, BASE_NONE, NULL, 0, "This field contains the optional SCP/SCU Role Selection Sub-Item of the ACSE User Information Item of the A-ASSOCIATE-RQ/RSP.", HFILL } },
    { &hf_dcm_info_rolesel_sopclassuid_len, { "SOP Class UID Length", "dicom.userinfo.rolesel.sopclassuid.len",
        FT_UINT16, BASE_DEC, NULL, 0, "This field contains the length of the SOP Class UID in the SCP/SCU Role Selection Sub-Item.", HFILL } },
    { &hf_dcm_info_rolesel_sopclassuid, { "SOP Class UID", "dicom.userinfo.rolesel.sopclassuid",
        FT_STRING, BASE_NONE, NULL, 0, "This field contains the SOP Class UID in the SCP/SCU Role Selection Sub-Item.", HFILL } },
    { &hf_dcm_info_rolesel_scurole, { "SCU-role", "dicom.userinfo.rolesel.scurole",
        FT_UINT8, BASE_HEX, NULL, 0, "This field contains the SCU-role as defined for the Association-requester.", HFILL } },
    { &hf_dcm_info_rolesel_scprole, { "SCP-role", "dicom.userinfo.rolesel.scprole",
        FT_UINT8, BASE_HEX, NULL, 0, "This field contains the SCP-role as defined for the Association-requester.", HFILL } },
    { &hf_dcm_info_async_neg, { "Asynchronous Operations (and sub-operations) Window Negotiation", "dicom.userinfo.asyncneg",
        FT_NONE, BASE_NONE, NULL, 0, "This field contains the optional Asynchronous Operations (and sub-operations) Window Negotiation Sub-Item of the ACSE User Information Item of the A-ASSOCIATE-RQ/RSP.", HFILL } },
    { &hf_dcm_info_async_neg_max_num_ops_inv, { "Maximum-number-operations-invoked", "dicom.userinfo.asyncneg.maxnumopsinv",
        FT_UINT16, BASE_DEC, NULL, 0, "This field contains the maximum-number-operations-invoked in the Asynchronous Operations (and sub-operations) Window Negotiation Sub-Item.", HFILL } },
    { &hf_dcm_info_async_neg_max_num_ops_per, { "Maximum-number-operations-performed", "dicom.userinfo.asyncneg.maxnumopsper",
        FT_UINT16, BASE_DEC, NULL, 0, "This field contains the maximum-number-operations-performed in the Asynchronous Operations (and sub-operations) Window Negotiation Sub-Item.", HFILL } },
    { &hf_dcm_info_unknown, { "Unknown", "dicom.userinfo.unknown",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_assoc_item_data, { "Unknown Data", "dicom.userinfo.data",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify, { "User Identify", "dicom.userinfo.user_identify",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify_type, { "Type", "dicom.userinfo.user_identify.type",
        FT_UINT8, BASE_DEC, VALS(user_identify_type_vals), 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify_response_requested, { "Response Requested", "dicom.userinfo.user_identify.response_requested",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify_primary_field_length, { "Primary Field Length", "dicom.userinfo.user_identify.primary_field_length",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify_primary_field, { "Primary Field", "dicom.userinfo.user_identify.primary_field",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify_secondary_field_length, { "Secondary Field Length", "dicom.userinfo.user_identify.secondary_field_length",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_user_identify_secondary_field, { "Secondary Field", "dicom.userinfo.user_identify.secondary_field",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pdu_maxlen, { "Max PDU Length", "dicom.max_pdu_len",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pdv_len, { "PDV Length", "dicom.pdv.len",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pdv_ctx, { "PDV Context", "dicom.pdv.ctx",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pdv_flags, { "PDV Flags", "dicom.pdv.flags",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_dcm_data_tag, { "Tag", "dicom.data.tag",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

    { &hf_dcm_tag, { "Tag", "dicom.tag",
        FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_vr, { "VR", "dicom.tag.vr",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_vl, { "Length", "dicom.tag.vl",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },

    { &hf_dcm_tag_value_str, { "Value", "dicom.tag.value.str",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_value_16s, { "Value", "dicom.tag.value.16s",
        FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_value_16u, { "Value", "dicom.tag.value.16u",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_value_32s, { "Value", "dicom.tag.value.32s",
        FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_value_32u, { "Value", "dicom.tag.value.32u",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_tag_value_byte, { "Value", "dicom.tag.value.byte",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

    /* Fragment entries */
    { &hf_dcm_pdv_fragments,
            { "Message fragments", "dicom.pdv.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment,
            { "Message fragment", "dicom.pdv.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment_overlap,
            { "Message fragment overlap", "dicom.pdv.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data",
            "dicom.pdv.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment_multiple_tails,
            { "Message has multiple tail fragments",
            "dicom.pdv.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment_too_long_fragment,
            { "Message fragment too long", "dicom.pdv.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment_error,
            { "Message defragmentation error", "dicom.pdv.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_fragment_count,
            { "Message fragment count", "dicom.pdv.fragment_count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_reassembled_in,
            { "Reassembled in", "dicom.pdv.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dcm_pdv_reassembled_length,
            { "Reassembled PDV length", "dicom.pdv.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } }
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
            &ett_dcm,
            &ett_assoc,
            &ett_assoc_header,
            &ett_assoc_actx,
            &ett_assoc_pctx,
            &ett_assoc_pctx_abss,
            &ett_assoc_pctx_xfer,
            &ett_assoc_info,
            &ett_assoc_info_uid,
            &ett_assoc_info_version,
            &ett_assoc_info_extneg,
            &ett_assoc_info_rolesel,
            &ett_assoc_info_async_neg,
            &ett_assoc_info_user_identify,
            &ett_assoc_info_unknown,
            &ett_dcm_data,
            &ett_dcm_data_pdv,
            &ett_dcm_data_tag,
            &ett_dcm_data_seq,
            &ett_dcm_data_item,
            &ett_dcm_pdv,               /* used for fragments */
            &ett_dcm_pdv_fragment,
            &ett_dcm_pdv_fragments
    };

    static ei_register_info ei[] = {
        { &ei_dcm_assoc_rejected, { "dicom.assoc.reject", PI_RESPONSE_CODE, PI_WARN, "Association rejected", EXPFILL }},
        { &ei_dcm_assoc_aborted, { "dicom.assoc.abort", PI_RESPONSE_CODE, PI_WARN, "Association aborted", EXPFILL }},
        { &ei_dcm_no_abstract_syntax, { "dicom.no_abstract_syntax", PI_MALFORMED, PI_ERROR, "No Abstract Syntax provided for this Presentation Context", EXPFILL }},
        { &ei_dcm_multiple_abstract_syntax, { "dicom.multiple_abstract_syntax", PI_MALFORMED, PI_ERROR, "More than one Abstract Syntax provided for this Presentation Context", EXPFILL }},
        { &ei_dcm_no_transfer_syntax, { "dicom.no_transfer_syntax", PI_MALFORMED, PI_ERROR, "No Transfer Syntax provided for this Presentation Context", EXPFILL }},
        { &ei_dcm_no_abstract_syntax_uid, { "dicom.no_abstract_syntax_uid", PI_MALFORMED, PI_ERROR, "No Abstract Syntax UID found for this Presentation Context", EXPFILL }},
        { &ei_dcm_multiple_transfer_syntax, { "dicom.multiple_transfer_syntax", PI_MALFORMED, PI_ERROR, "Only one Transfer Syntax allowed in a Association Response", EXPFILL }},
        { &ei_dcm_assoc_item_len, { "dicom.assoc.item.len.invalid", PI_MALFORMED, PI_ERROR, "Invalid Association Item Length", EXPFILL }},
        { &ei_dcm_pdv_ctx, { "dicom.pdv.ctx.invalid", PI_MALFORMED, PI_ERROR, "Invalid Presentation Context ID", EXPFILL }},
        { &ei_dcm_pdv_flags, { "dicom.pdv.flags.invalid", PI_MALFORMED, PI_ERROR, "Invalid Flags", EXPFILL }},
        { &ei_dcm_status_msg, { "dicom.status_msg", PI_RESPONSE_CODE, PI_WARN, "%s", EXPFILL }},
        { &ei_dcm_data_tag, { "dicom.data.tag.missing", PI_MALFORMED, PI_ERROR, "Early termination of tag. Data is missing", EXPFILL }},
        { &ei_dcm_pdv_len, { "dicom.pdv.len.invalid", PI_MALFORMED, PI_ERROR, "Invalid PDV length", EXPFILL }},
        { &ei_dcm_invalid_pdu_length, { "dicom.pdu_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid PDU length", EXPFILL }},
    };

    module_t *dcm_module;
    expert_module_t* expert_dcm;

    /* Register the protocol name and description */
    proto_dcm = proto_register_protocol("DICOM", "DICOM", "dicom");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_dcm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dcm = expert_register_protocol(proto_dcm);
    expert_register_field_array(expert_dcm, ei, array_length(ei));

    /* Allow other dissectors to find this one by name. */
    dcm_handle = register_dissector("dicom", dissect_dcm_static, proto_dcm);

    dcm_module = prefs_register_protocol(proto_dcm, NULL);

    /*  Used to migrate an older configuration file to a newer one  */
    prefs_register_obsolete_preference(dcm_module, "heuristic");

    prefs_register_bool_preference(dcm_module, "export_header",
            "Create Meta Header on Export",
            "Create DICOM File Meta Header according to PS 3.10 on export for PDUs. "
            "If the captured PDV does not contain a SOP Class UID and SOP Instance UID "
            "(e.g. for command PDVs), wireshark specific ones will be created.",
            &global_dcm_export_header);

    prefs_register_uint_preference(dcm_module, "export_minsize",
            "Min. item size in bytes to export",
            "Do not show items below this size in the export list. "
            "Set it to 0, to see DICOM commands and responses in the list. "
            "Set it higher, to just export DICOM IODs (i.e. CT Images, RT Structures).", 10,
            &global_dcm_export_minsize);

    prefs_register_bool_preference(dcm_module, "seq_tree",
            "Create subtrees for Sequences and Items",
            "Create a node for sequences and items, and show children in a hierarchy. "
            "De-select this option, if you prefer a flat display or e.g. "
            "when using TShark to create a text output.",
            &global_dcm_seq_subtree);

    prefs_register_bool_preference(dcm_module, "tag_tree",
            "Create subtrees for DICOM Tags",
            "Create a node for a tag and show tag details as single elements. "
            "This can be useful to debug a tag and to allow display filters on these attributes. "
            "When using TShark to create a text output, it's better to have it disabled. ",
            &global_dcm_tag_subtree);

    prefs_register_bool_preference(dcm_module, "cmd_details",
            "Show command details in header",
            "Show message ID and number of completed, remaining, warned or failed operations in header and info column.",
            &global_dcm_cmd_details);

    prefs_register_bool_preference(dcm_module, "pdv_reassemble",
            "Merge fragmented PDVs",
            "Decode all DICOM tags in the last PDV. This will ensure the proper reassembly. "
            "De-select, to troubleshoot PDU length issues, or to understand PDV fragmentation. "
            "When not set, the decoding may fail and the exports may become corrupt.",
            &global_dcm_reassemble);

    dicom_eo_tap = register_export_object(proto_dcm, dcm_eo_packet, NULL);

    register_init_routine(&dcm_init);

    /* Register processing of fragmented DICOM PDVs */
    reassembly_table_register(&dcm_pdv_reassembly_table, &addresses_reassembly_table_functions);

}

/*
Register static TCP port range specified in preferences.
Register heuristic search as well.

Statically defined ports take precedence over a heuristic one. I.e., if a foreign protocol claims a port,
where DICOM is running on, we would never be called, by just having the heuristic registration.

This function is also called, when preferences change.
*/
void
proto_reg_handoff_dcm(void)
{
    /* Adds a UI element to the preferences dialog. This is the static part. */
    dissector_add_uint_range_with_preference("tcp.port", DICOM_DEFAULT_RANGE, dcm_handle);

    /*
    The following shows up as child protocol of 'DICOM' in 'Enable/Disable Protocols ...'

    The registration procedure for dissectors is a two-stage procedure.

    In stage 1, dissectors create tables in which other dissectors can register them. That's the stage in which proto_register_ routines are called.
    In stage 2, dissectors register themselves in tables created in stage 1. That's the stage in which proto_reg_handoff_ routines are called.

    heur_dissector_add() needs to be called in proto_reg_handoff_dcm() function.
    */

    heur_dissector_add("tcp", dissect_dcm_heuristic, "DICOM on any TCP port (heuristic)", "dicom_tcp", proto_dcm, HEURISTIC_ENABLE);
}


/*

PDU's
01 ASSOC-RQ
 1    1 reserved
 2    4 length
 6    2 protocol version (0x0 0x1)
 8    2 reserved
10   16 dest aetitle
26   16 src  aetitle
42   32 reserved
74    - presentation data value items

02 A-ASSOC-AC
    1 reserved
    4 length
    2 protocol version (0x0 0x1)
    2 reserved
   16 dest aetitle (not checked)
   16 src  aetitle (not checked)
   32 reserved
    - presentation data value items

03 ASSOC-RJ
    1 reserved
    4 length (4)
    1 reserved
    1 result  (1 reject perm, 2 reject transient)
    1 source  (1 service user, 2 service provider, 3 service provider)
    1 reason
        1 == source
            1 no reason given
            2 application context name not supported
            3 calling aetitle not recognized
            7 called aetitle not recognized
        2 == source
            1 no reason given
            2 protocol version not supported
        3 == source
            1 temporary congestion
            2 local limit exceeded

04 P-DATA
 1  1 reserved
 2  4 length
    - (1+) presentation data value (PDV) items
 6      4 length
10      1 Presentation Context ID (odd ints 1 - 255)
        - PDV
11      1 header
            0x01 if set, contains Message Command info, else Message Data
            0x02 if set, contains last fragment

05 A-RELEASE-RQ
    1 reserved
    4 length (4)
    4 reserved

06 A-RELEASE-RP
    1 reserved
    4 length (4)
    4 reserved

07 A-ABORT
    1  reserved
    4  length (4)
    2  reserved
    1  source  (0 = user, 1 = provider)
    1  reason  if 1 == source (0 not spec, 1 unrecognized, 2 unexpected 4 unrecognized param, 5 unexpected param, 6 invalid param)



ITEM's
10 Application Context
    1 reserved
    2 length
    - name

20 Presentation Context
    1 reserved
    2 length
    1 Presentation context id
    3 reserved
    - (1) abstract and (1+) transfer syntax sub-items

21 Presentation Context (Reply)
    1 reserved
    2 length
    1 ID (odd int's 1-255)
    1 reserved
    1 result (0 accept, 1 user-reject, 2 no-reason, 3 abstract not supported, 4- transfer syntax not supported)
    1 reserved
    - (1) type 40

30 Abstract syntax
    1 reserved
    2 length
    - name (<= 64)

40 Transfer syntax
    1 reserved
    2 length
    - name (<= 64)

50 user information
    1 reserved
    2 length
    - user data

51 max length
    1 reserved
    2 length (4)
    4 max PDU lengths

From 3.7 Annex D Association Negotiation
========================================

52 IMPLEMENTATION CLASS UID
    1 Item-type 52H
    1 Reserved
    2 Item-length
    n Implementation-class-uid

55 IMPLEMENTATION VERSION NAME
    1 Item-type 55H
    1 Reserved
    2 Item-length
    n Implementation-version-name

53 ASYNCHRONOUS OPERATIONS WINDOW
    1 Item-type 53H
    1 Reserved
    2 Item-length
    2 Maximum-number-operations-invoked
    2 Maximum-number-operations-performed

54 SCP/SCU ROLE SELECTION
    1 Item-type 54H
    1 Reserved
    2 Item-length (n)
    2 UID-length (m)
    m SOP-class-uid
    1 SCU-role
      0 - non support of the SCU role
      1 - support of the SCU role
    1 SCP-role
      0 - non support of the SCP role
      1 - support of the SCP role.

56 SOP CLASS EXTENDED NEGOTIATION
    1 Item-type 56H
    1 Reserved
    2 Item-Length (n)
    2 SOP-class-uid-length (m)
    m SOP-class-uid
    n-m Service-class-application-information

57 SOP CLASS COMMON EXTENDED NEGOTIATION
    1 Item-type 57H
    1 Sub-item-version
    2 Item-Length
    2 SOP-class-uid-length (m)
    7-x   SOP-class-uid The SOP Class identifier encoded as a UID as defined in PS 3.5.
    (x+1)-(x+2) Service-class-uid-length  The Service-class-uid-length shall be the number of bytes in the Service-class-uid field. It shall be encoded as an unsigned binary number.
    (x+3)-y Service-class-uid The Service Class identifier encoded as a UID as defined in PS 3.5.
    (y+1)-(y+2) Related-general-sop-class-identification-length The Related-general-sop-class-identification-length shall be the number of bytes in the Related-general-sop-class-identification field. Shall be zero if no Related General SOP Classes are identified.
    (y+3)-z Related-general-sop-class-identification  The Related-general-sop-class-identification is a sequence of pairs of length and UID sub-fields.  Each pair of sub-fields shall be formatted in accordance with Table D.3-13.
    (z+1)-k Reserved  Reserved for additional fields of the sub-item. Shall be zero-length for Version 0 of Sub-item definition.

    Table D.3-13
    RELATED-GENERAL-SOP-CLASS-IDENTIFICATION SUB-FIELDS
    Bytes Sub-Field Name    Description of Sub-Field
    1-2 Related-general-sop-class-uid-length      The Related-general-sop-class-uid-length shall be the number of bytes in the Related-general-sop-class-uid sub-field. It shall be encoded as an unsigned binary number.
    3-n Related-general-sop-class-uid The Related General SOP Class identifier encoded as a UID as defined in PS 3.5.

58 User Identity Negotiation
    1 Item-type 58H
    1 Reserved
    2 Item-length
    1 User-Identity-Type  Field value shall be in the range 1 to 4 with the following meanings:
        1 - Username as a string in UTF-8
        2 - Username as a string in UTF-8 and passcode
        3 - Kerberos Service ticket
        4 - SAML Assertion
        Other values are reserved for future standardization.
    1 Positive-response-requested Field value:
        0 - no response requested
        1 - positive response requested
    2 Primary-field-length  The User-Identity-Length shall contain the length of the User-Identity value.
    9-n Primary-field   This field shall convey the user identity, either the username as a series of characters, or the Kerberos Service ticket encoded in accordance with RFC-1510.
    n+1-n+2 Secondary-field-length  This field shall be non-zero only if User-Identity-Type has the value 2.  It shall contain the length of the secondary-field.
    n+3-m Secondary-field   This field shall be present only if User-Identity-Type has the value 2.  It shall contain the Passcode value.

59 User Identity Negotiation Reply
    1 Item-type 59H
    1 Reserved
    2 Item-length
    5-6 Server-response-length  This field shall contain the number of bytes in the Server-response.  May be zero.
    7-n Server-response This field shall contain the Kerberos Server ticket, encoded in accordance with RFC-1510, if the User-Identity-Type value in the A-ASSOCIATE-RQ was 3. This field shall contain the SAML response if the User-Identity-Type value in the A-ASSOCIATE-RQ was 4. This field shall be zero length if the value of the User-Identity-Type in the A-ASSOCIATE-RQ was 1 or 2.

 */

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
