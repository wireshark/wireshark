/* packet-dcm.c
 * Routines for DICOM dissection
 * Copyright 2003, Rich Coe <Richard.Coe@med.ge.com>
 * Copyright 2008-2010, David Aggeler <david_aggeler@hispeed.ch>
 *
 * DICOM communication protocol
 * http://medical.nema.org/dicom/2008
 *   DICOM Part 8: Network Communication Support for Message Exchange
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/* History:
 * This dissector was originally coded by Rich Coe and then modified by David Aggeler
 * **********************************************************************************
 * ToDo
 *
 * - Syntax detection, in case an association request is missing in capture
 * - Read private tags from configuration and parse in capture
 * - dissect_dcm_heuristic() to return proper data type
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
 * Oct 12, 2008 - David Aggeler (SVN 26424)
 *
 * - Follow-up checkin 26417
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
 *   consistent _new() & _get() functions and to be be according to coding conventions
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
 * - Added preference with dicom tcp ports, to prevent 'stealing' the conversation
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
 *	- sequences
 *	- report actual VR in packet display, if supplied by xfer syntax
 *	- show that we are not displaying entire tag string with '[...]',
 *	  some tags can hold up to 2^32-1 chars
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
 * - Fixed the dissect code to display all the tags in the pdu
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
 *   symbolically display the data.  Consider this a future enhancement.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/reassemble.h>

#include "packet-tcp.h"

#include "packet-dcm.h"

#define DICOM_DEFAULT_RANGE "104"

/* Many thanks to http://medicalconnections.co.uk/ for the GUID */
#define WIRESHARK_IMPLEMENTATION_UID			"1.2.826.0.1.3680043.8.427.10"
#define WIRESHARK_MEDIA_STORAGE_SOP_CLASS_UID		"1.2.826.0.1.3680043.8.427.11.1"
#define WIRESHARK_MEDIA_STORAGE_SOP_INSTANCE_UID_PREFIX	"1.2.826.0.1.3680043.8.427.11.2"
#define WIRESHARK_IMPLEMENTATION_VERSION		"WIRESHARK"

#define MAX_BUF_LEN 1024				    /* Used for string allocations */

static range_t *global_dcm_tcp_range = NULL;
static range_t *global_dcm_tcp_range_backup = NULL;	    /* needed to deregister */

static gboolean global_dcm_heuristic = FALSE;
static gboolean global_dcm_export_header = TRUE;
static guint    global_dcm_export_minsize = 4096;	    /* Filter small objects in export */

static gboolean global_dcm_seq_subtree = TRUE;
static gboolean global_dcm_tag_subtree = FALSE;		    /* Only useful for debugging */
static gboolean global_dcm_cmd_details = TRUE;		    /* Show details in header and info column */
static gboolean global_dcm_reassemble = TRUE;		    /* Merge fragmented PDVs */

static GHashTable *dcm_tag_table = NULL;
static GHashTable *dcm_uid_table = NULL;
static GHashTable *dcm_status_table = NULL;

/* Initialize the protocol and registered fields */
static int proto_dcm = -1;

static int dicom_eo_tap = -1;

static int hf_dcm_pdu = -1,
    hf_dcm_pdu_len = -1,
    hf_dcm_pdu_type = -1,
    hf_dcm_assoc_version = -1,
    hf_dcm_assoc_called = -1,
    hf_dcm_assoc_calling = -1,
    hf_dcm_assoc_reject_result = -1,
    hf_dcm_assoc_reject_source = -1,
    hf_dcm_assoc_reject_reason = -1,
    hf_dcm_assoc_abort_source = -1,
    hf_dcm_assoc_abort_reason = -1,
    hf_dcm_assoc_item_type = -1,
    hf_dcm_assoc_item_len = -1,
    hf_dcm_actx = -1,
    hf_dcm_pctx_id = -1,
    hf_dcm_pctx_result = -1,
    hf_dcm_pctx_abss_syntax = -1,
    hf_dcm_pctx_xfer_syntax = -1,
    hf_dcm_info_uid = -1,
    hf_dcm_info_version = -1,
    hf_dcm_pdu_maxlen = -1,
    hf_dcm_pdv_len = -1,
    hf_dcm_pdv_ctx = -1,
    hf_dcm_pdv_flags = -1,
    hf_dcm_data_tag = -1,
    hf_dcm_tag = -1,
    hf_dcm_tag_vr = -1,
    hf_dcm_tag_vl = -1,
    hf_dcm_tag_value_str = -1,
    hf_dcm_tag_value_16u = -1,
    hf_dcm_tag_value_16s = -1,
    hf_dcm_tag_value_32s = -1,
    hf_dcm_tag_value_32u = -1,
    hf_dcm_tag_value_byte = -1;


/* Initialize the subtree pointers */
static gint
    ett_dcm = -1,
    ett_assoc = -1,
    ett_assoc_header = -1,
    ett_assoc_actx = -1,
    ett_assoc_pctx = -1,
    ett_assoc_pctx_abss = -1,
    ett_assoc_pctx_xfer = -1,
    ett_assoc_info = -1,
    ett_assoc_info_uid = -1,
    ett_assoc_info_version = -1,
    ett_dcm_data = -1,
    ett_dcm_data_pdv = -1,
    ett_dcm_data_tag = -1,
    ett_dcm_data_seq = -1,
    ett_dcm_data_item = -1;

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
    { 0x55, "Implementation Version" },
    { 0, NULL }
};

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
    /* Tag */
    "Message fragments"
};

/* Structures to handle fragmented DICOM PDU packets */
static GHashTable *dcm_pdv_fragment_table = NULL;
static GHashTable *dcm_pdv_reassembled_table = NULL;

typedef struct dcm_open_tag {

    /* Contains information about an open tag in a PDV, in case it was not complete.

       This implementation differentiates between open headers (grm, elm, vr, vl) and
       open values. This data structure will handl both cases.

       Open headers are not shown in the packet where the tag starts, but only in the next PDV.
       Open values are shown in the packet where the tag starts, with <Byte 1-n> as the value

       The same PDV can close an open tag from a previous PDV at the beginning
       and at the same have time open a new tag at the end. The closing part at the beginning
       does not have it's own persitent data.

       Do not overwrite the values, once defined, to save some memory.

       Since PDVs are always n*2 bytes, store each of the 2 Bytes in a variable.
       This way, we don't need to call tvb_get_xxx on a self created buffer

    */

    gboolean	is_header_fragmented;
    gboolean	is_value_fragmented;

    guint32	len_decoded;	/* Should only by < 16 bytes		    */

    guint16	grp;		/* Already decoded group		    */
    guint16	elm;		/* Already decoded element		    */
    gchar      *vr;		/* Already decoded VR			    */

    gboolean	is_vl_long;	/* If TRUE, Value Length is 4 Bytes, otherwise 2 */
    guint16	vl_1;		/* Partially decoded 1st two bytes of length  */
    guint16	vl_2;		/* Partially decoded 2nd two bytes of length  */

    /* These ones are, where the value was truncated */
    guint32 len_total;		/* Tag length of 'oversized' tags. Used for display */
    guint32 len_remaining;	/* Remining tag bytes to 'decoded' as binary data after this PDV */

    gchar  *desc;		/* Last decoded description */

} dcm_open_tag_t;

/*
    Per Data PDV store data needed, to allow decoding of tags longer than a PDV
*/
typedef struct dcm_state_pdv {

    struct dcm_state_pdv *next, *prev;

    guint32  packet_no;		/* Wireshark packet number, where pdv starts */
    guint32  offset;		/* Offset in packet, where PDV header starts */

    gchar   *desc;		/* PDV description.	    se_alloc()	*/

    guint8  pctx_id;		/* Reference to used Presentation Context */

    /* Following is drived from the transfer syntax in the parent PCTX, execpt for Command PDVs */
    guint8  syntax;

    /* Used and filled for Export Object only */
    gpointer data;		/* Copy of PDV data without any PDU/PDV header */
    guint32  data_len;		/* Length of this PDV buffer. If >0, memory has been allocated */

    gchar   *sop_class_uid;	/* SOP Class UID.    Set in 1st PDV of a DICOM object. se_alloc() */
    gchar   *sop_instance_uid;	/* SOP Instance UID. Set in 1st PDV of a DICOM object. se_alloc() */
    /* End Export use */

    gboolean is_storage;	/* Ture, if the Data PDV is on the context of a storage SOP Class */
    gboolean is_flagvalid;	/* The following two flags are initalized correctly */
    gboolean is_command;	/* This PDV is a command rather than a data package */
    gboolean is_last_fragment;	/* Last Fragment bit was set, i.e. termination of an object
				   This flag delimits different dicom object in the same
				   association */
    gboolean is_corrupt;	/* Early termination of long PDVs */

				/* The following five attributes are only used from command PDVs */

    gchar   *command;		/* Decoded command as text */
    gchar   *status;
    gchar   *comment;		/* Error comment, if any */

    gboolean is_warning;	/* Command response is a cancel, warning, error */

    guint16  message_id;	/* (0000,0110) Message ID */
    guint16  message_id_resp;	/* (0000,0120) Message ID Being Responded To */

    guint16  no_remaining;	/* (0000,1020) Number of Remaining Sub-operations */
    guint16  no_completed;	/* (0000,1021) Number of Completed Sub-operations */
    guint16  no_failed;		/* (0000,1022) Number of Failed Sub-operations	*/
    guint16  no_warning;	/* (0000,1023) Number of Warning Sub-operations */

    dcm_open_tag_t  open_tag;	/* Container to store information about a fragmented tag */

} dcm_state_pdv_t;

/*
    Per Presentation Context in an association store data needed, for subsequent decoding
*/
typedef struct dcm_state_pctx {

    struct dcm_state_pctx *next, *prev;

    guint8 id;			/* 0x20 Presentation Context ID */
    gchar *abss_uid;		/* 0x30 Abstract syntax */
    gchar *abss_desc;		/* 0x30 Abstract syntax decoded*/
    gchar *xfer_uid;		/* 0x40 Accepted Transfer syntax */
    gchar *xfer_desc;		/* 0x40 Accepted Transfer syntax decoded*/
    guint8 syntax;		/* Decoded transfer syntax */
#define DCM_ILE  0x01		/* implicit, little endian */
#define DCM_EBE  0x02           /* explicit, big endian */
#define DCM_ELE  0x03           /* explicit, little endian */
#define DCM_UNK  0xf0

    dcm_state_pdv_t	*first_pdv,  *last_pdv;		/* List of PDV objects */

} dcm_state_pctx_t;


typedef struct dcm_state_assoc {

    struct dcm_state_assoc *next, *prev;

    dcm_state_pctx_t	*first_pctx, *last_pctx;	/* List of Presentation context objects */

    guint32 packet_no;			/* Wireshark packet number, where association starts */

#define AEEND 16
    gchar ae_called[1+AEEND];		/* Called  AE tilte in A-ASSOCIATE RQ */
    gchar ae_calling[1+AEEND];		/* Calling AE tilte in A-ASSOCIATE RQ */
    gchar ae_called_resp[1+AEEND];	/* Called  AE tilte in A-ASSOCIATE RP */
    gchar ae_calling_resp[1+AEEND];	/* Calling AE tilte in A-ASSOCIATE RP */

} dcm_state_assoc_t;

typedef struct dcm_state {

    struct dcm_state_assoc *first_assoc, *last_assoc;

    gboolean valid;			/* this conversation is a DICOM conversation */

} dcm_state_t;


#define DCM_VR_AE  1  /* Application Entity        */
#define DCM_VR_AS  2  /* Age String                */
#define DCM_VR_AT  3  /* Attribute Tag             */
#define DCM_VR_CS  4  /* Code String               */
#define DCM_VR_DA  5  /* Date                      */
#define DCM_VR_DS  6  /* Decimal String            */
#define DCM_VR_DT  7  /* Date Time                 */
#define DCM_VR_FL  8  /* Floating Point Single     */
#define DCM_VR_FD  9  /* Floating Point Double     */
#define DCM_VR_IS 10  /* Integer String            */
#define DCM_VR_LO 11  /* Long String               */
#define DCM_VR_LT 12  /* Long Text                 */
#define DCM_VR_OB 13  /* Other Byte String         */
#define DCM_VR_OF 14  /* Other Float String        */
#define DCM_VR_OW 15  /* Other Word String         */
#define DCM_VR_PN 16  /* Person Name               */
#define DCM_VR_SH 17  /* Short String              */
#define DCM_VR_SL 18  /* Signed Long               */
#define DCM_VR_SQ 19  /* Sequence of Items         */
#define DCM_VR_SS 20  /* Signed Short              */
#define DCM_VR_ST 21  /* Short Text                */
#define DCM_VR_TM 22  /* Time                      */
#define DCM_VR_UI 23  /* Unique Identifier (UID)   */
#define DCM_VR_UL 24  /* Unsigned Long             */
#define DCM_VR_UN 25  /* Unknown                   */
#define DCM_VR_US 26  /* Unsigned Short            */
#define DCM_VR_UT 27  /* Unlimited Text            */

/* Following must be in the same order as the defintions above */
static const gchar* dcm_tag_vr_lookup[] = {
    "  ",
    "AE","AS","AT","CS","DA","DS","DT","FL",
    "FD","IS","LO","LT","OB","OF","OW","PN",
    "SH","SL","SQ","SS","ST","TM","UI","UL",
    "UN","US","UT"
};

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

    { 0x0000,	"Success"},
    { 0x0105,	"No such attribute"},
    { 0x0106,	"Invalid attribute value"},
    { 0x0107,	"Attribute list error"},
    { 0x0110,	"Processing failure"},
    { 0x0111,	"Duplicate SOP instance"},
    { 0x0112,	"No Such object instance"},
    { 0x0113,	"No such event type"},
    { 0x0114,	"No such argument"},
    { 0x0115,	"Invalid argument value"},
    { 0x0116,	"Attribute Value Out of Range"},
    { 0x0117,	"Invalid object instance"},
    { 0x0118,	"No Such SOP class"},
    { 0x0119,	"Class-instance conflict"},
    { 0x0120,	"Missing attribute"},
    { 0x0121,	"Missing attribute value"},
    { 0x0122,	"Refused: SOP class not supported"},
    { 0x0123,	"No such action type"},
    { 0x0210,	"Duplicate invocation"},
    { 0x0211,	"Unrecognized operation"},
    { 0x0212,	"Mistyped argument"},
    { 0x0213,	"Resource limitation"},
    { 0xFE00,	"Cancel"},

    /* from PS 3.4 */

    { 0x0001,	"Requested optional Attributes are not supported"},
    { 0xA501,	"Refused because General Purpose Scheduled Procedure Step Object may no longer be updated"},
    { 0xA502,	"Refused because the wrong Transaction UID is used"},
    { 0xA503,	"Refused because the General Purpose Scheduled Procedure Step SOP Instance is already in the 'IN PROGRESS' state"},
    { 0xA504,	"Refused because the related General Purpose Scheduled Procedure Step SOP Instance is not in the 'IN PROGRESS' state"},
    { 0xA505,	"Refused because Referenced General Purpose Scheduled Procedure Step Transaction UID does not match the Transaction UID of the N-ACTION request"},
    { 0xA510,	"Refused because an Initiate Media Creation action has already been received for this SOP Instance"},
    { 0xA700,	"Refused: Out of Resources"},
    { 0xA701,	"Refused: Out of Resources - Unable to calculate number of matches"},
    { 0xA702,	"Refused: Out of Resources - Unable to perform sub-operations"},
    /*
    { 0xA7xx,	"Refused: Out of Resources"},
    */
    { 0xA801,	"Refused: Move Destination unknown"},
    /*
    { 0xA9xx,	"Error: Data Set does not match SOP Class"},
    */
    { 0xB000,	"Sub-operations Complete - One or more Failures"},
    { 0xB006,	"Elements Discarded"},
    { 0xB007,	"Data Set does not match SOP Class"},
    { 0xB101,	"Specified Synchronization Frame of Reference UID does not match SCP Synchronization Frame of Reference"},
    { 0xB102,	"Study Instance UID coercion; Event logged under a different Study Instance UID"},
    { 0xB104,	"IDs inconsistent in matching a current study; Event logged"},
    { 0xB605,	"Requested Min Density or Max Density outside of printer's operating range. The printer will use its respective minimum or maximum density value instead"},
    { 0xC000,	"Error: Cannot understand/Unable to process"},
    { 0xC100,	"More than one match found"},
    { 0xC101,	"Procedural Logging not available for specified Study Instance UID"},
    { 0xC102,	"Event Information does not match Template"},
    { 0xC103,	"Cannot match event to a current study"},
    { 0xC104,	"IDs inconsistent in matching a current study; Event not logged"},
    { 0xC200,	"Unable to support requested template"},
    { 0xC201,	"Media creation request already completed"},
    { 0xC202,	"Media creation request already in progress and cannot be interrupted"},
    { 0xC203,	"Cancellation denied for unspecified reason"},
    /*
    { 0xCxxx,	"Error: Cannot understand/Unable to Process"},
    { 0xFE00,	"Matching/Sub-operations terminated due to Cancel request"},
    */
    { 0xFF00,	"Current Match is supplied. Sub-operations are continuing"},
    { 0xFF01,	"Matches are continuing - Warning that one or more Optional Keys were not supported for existence for this Identifier"}

};


/* ---------------------------------------------------------------------
 * DICOM Tag Definitions
 *
 * Part 6 lists following different Value Representations (2006-2008)
 * AE,AS,AT,CS,DA,DS,DT,FD,FL,IS,LO,LT,OB,OB or OW,OF,OW,OW or OB,
 * PN,SH,SL,SQ,SS,ST,TM,UI,UL,US,US or SS,US or SS or OW,UT
 *
 * Some Tags can have different VRs
 *
 * Group 1000 is not supported, multiple tags with same description  (retired anyhow)
 * Group 7Fxx is not supported, multiple tags with same description  (retired anyhow)
 *
 * Tags (0020,3100 to 0020, 31FF) not supported, multiple tags with same description  (retired anyhow)
 *
 * Repeating groups (50xx & 60xx) are manually added. Declared as 5000 & 6000
 */

typedef struct dcm_tag {
    const guint32 tag;
    const gchar *description;
    const gchar *vr;
    const gchar *vm;
    const gboolean is_retired;
    const gboolean add_to_summary;	    /* Add to parent's item description */
} dcm_tag_t;

static dcm_tag_t dcm_tag_data[] = {

    /* Command Tags */
    { 0x00000000, "Command Group Length", "UL", "1", 0, 0},
    { 0x00000002, "Affected SOP Class UID", "UI", "1", 0, 0},
    { 0x00000003, "Requested SOP Class UID", "UI", "1", 0, 0},
    { 0x00000100, "Command Field", "US", "1", 0, 0},
    { 0x00000110, "Message ID", "US", "1", 0, 0},
    { 0x00000120, "Message ID Being Responded To", "US", "1", 0, 0},
    { 0x00000600, "Move Destination", "AE", "1", 0, 0},
    { 0x00000700, "Priority", "US", "1", 0, 0},
    { 0x00000800, "Data Set Type", "US", "1", 0, 0},
    { 0x00000900, "Status", "US", "1", 0, 0},
    { 0x00000901, "Offending Element", "AT", "1-n", 0, 0},
    { 0x00000902, "Error Comment", "LO", "1", 0, 0},
    { 0x00000903, "Error ID", "US", "1", 0, 0},
    { 0x00001000, "Affected SOP Instance UID", "UI", "1", 0, 0},
    { 0x00001001, "Requested SOP Instance UID", "UI", "1", 0, 0},
    { 0x00001002, "Event Type ID", "US", "1", 0, 0},
    { 0x00001005, "Attribute Identifier List", "AT", "1-n", 0, 0},
    { 0x00001008, "Action Type ID", "US", "1", 0, 0},
    { 0x00001020, "Number of Remaining Sub-operations", "US", "1", 0, 0},
    { 0x00001021, "Number of Completed Sub-operations", "US", "1", 0, 0},
    { 0x00001022, "Number of Failed Sub-operations", "US", "1", 0, 0},
    { 0x00001023, "Number of Warning Sub-operations", "US", "1", 0, 0},
    { 0x00001030, "Move Originator Application Entity Title", "AE", "1", 0, 0},
    { 0x00001031, "Move Originator Message ID", "US", "1", 0, 0},
    { 0x00000001, "Length to End", "UL", "1", -1, 0},
    { 0x00000010, "Recognition Code", "CS", "1", -1, 0},
    { 0x00000200, "Initiator", "AE", "1", -1, 0},
    { 0x00000300, "Receiver", "AE", "1", -1, 0},
    { 0x00000400, "Find Location", "AE", "1", -1, 0},
    { 0x00000850, "Number of Matches", "US", "1", -1, 0},
    { 0x00000860, "Response Sequence Number", "US", "1", -1, 0},
    { 0x00004000, "DIALOG Receiver", "AT", "1", -1, 0},
    { 0x00004010, "Terminal Type", "AT", "1", -1, 0},
    { 0x00005010, "Message Set ID", "SH", "1", -1, 0},
    { 0x00005020, "End Message ID", "SH", "1", -1, 0},
    { 0x00005110, "Display Format", "AT", "1", -1, 0},
    { 0x00005120, "Page Position ID", "AT", "1", -1, 0},
    { 0x00005130, "Text Format ID", "CS", "1", -1, 0},
    { 0x00005140, "Nor/Rev", "CS", "1", -1, 0},
    { 0x00005150, "Add Gray Scale", "CS", "1", -1, 0},
    { 0x00005160, "Borders", "CS", "1", -1, 0},
    { 0x00005170, "Copies", "IS", "1", -1, 0},
    { 0x00005180, "Magnification Type", "CS", "1", -1, 0},
    { 0x00005190, "Erase", "CS", "1", -1, 0},
    { 0x000051A0, "Print", "CS", "1", -1, 0},
    { 0x000051B0, "Overlays", "US", "1-n", -1, 0},


    /* Data Tags */
    { 0x00080001, "Length to End", "UL", "1", -1, 0},
    { 0x00080005, "Specific Character Set", "CS", "1-n", 0, 0},
    { 0x00080008, "Image Type", "CS", "2-n", 0, 0},
    { 0x00080010, "Recognition Code", "CS", "1", -1, 0},
    { 0x00080012, "Instance Creation Date", "DA", "1", 0, 0},
    { 0x00080013, "Instance Creation Time", "TM", "1", 0, 0},
    { 0x00080014, "Instance Creator UID", "UI", "1", 0, 0},
    { 0x00080016, "SOP Class UID", "UI", "1", 0, 0},
    { 0x00080018, "SOP Instance UID", "UI", "1", 0, 0},
    { 0x0008001A, "Related General SOP Class UID", "UI", "1-n", 0, 0},
    { 0x0008001B, "Original Specialized SOP Class UID", "UI", "1", 0, 0},
    { 0x00080020, "Study Date", "DA", "1", 0, 0},
    { 0x00080021, "Series Date", "DA", "1", 0, 0},
    { 0x00080022, "Acquisition Date", "DA", "1", 0, 0},
    { 0x00080023, "Content Date", "DA", "1", 0, 0},
    { 0x00080024, "Overlay Date", "DA", "1", -1, 0},
    { 0x00080025, "Curve Date", "DA", "1", -1, 0},
    { 0x0008002A, "Acquisition DateTime", "DT", "1", 0, 0},
    { 0x00080030, "Study Time", "TM", "1", 0, 0},
    { 0x00080031, "Series Time", "TM", "1", 0, 0},
    { 0x00080032, "Acquisition Time", "TM", "1", 0, 0},
    { 0x00080033, "Content Time", "TM", "1", 0, 0},
    { 0x00080034, "Overlay Time", "TM", "1", -1, 0},
    { 0x00080035, "Curve Time", "TM", "1", -1, 0},
    { 0x00080040, "Data Set Type", "US", "1", -1, 0},
    { 0x00080041, "Data Set Subtype", "LO", "1", -1, 0},
    { 0x00080042, "Nuclear Medicine Series Type", "CS", "1", -1, 0},
    { 0x00080050, "Accession Number", "SH", "1", 0, 0},
    { 0x00080052, "Query/Retrieve Level", "CS", "1", 0, 0},
    { 0x00080054, "Retrieve AE Title", "AE", "1-n", 0, 0},
    { 0x00080056, "Instance Availability", "CS", "1", 0, 0},
    { 0x00080058, "Failed SOP Instance UID List", "UI", "1-n", 0, 0},
    { 0x00080060, "Modality", "CS", "1", 0, 0},
    { 0x00080061, "Modalities in Study", "CS", "1-n", 0, 0},
    { 0x00080062, "SOP Classes in Study", "UI", "1-n", 0, 0},
    { 0x00080064, "Conversion Type", "CS", "1", 0, 0},
    { 0x00080068, "Presentation Intent Type", "CS", "1", 0, 0},
    { 0x00080070, "Manufacturer", "LO", "1", 0, 0},
    { 0x00080080, "Institution Name", "LO", "1", 0, 0},
    { 0x00080081, "Institution Address", "ST", "1", 0, 0},
    { 0x00080082, "Institution Code Sequence", "SQ", "1", 0, 0},
    { 0x00080090, "Referring Physician's Name", "PN", "1", 0, 0},
    { 0x00080092, "Referring Physician's Address", "ST", "1", 0, 0},
    { 0x00080094, "Referring Physician's Telephone Numbers", "SH", "1-n", 0, 0},
    { 0x00080096, "Referring Physician Identification Sequence", "SQ", "1", 0, 0},
    { 0x00080100, "Code Value", "SH", "1", 0, 0},
    { 0x00080102, "Coding Scheme Designator", "SH", "1", 0, 0},
    { 0x00080103, "Coding Scheme Version", "SH", "1", 0, 0},
    { 0x00080104, "Code Meaning", "LO", "1", 0, 0},
    { 0x00080105, "Mapping Resource", "CS", "1", 0, 0},
    { 0x00080106, "Context Group Version", "DT", "1", 0, 0},
    { 0x00080107, "Context Group Local Version", "DT", "1", 0, 0},
    { 0x0008010B, "Context Group Extension Flag", "CS", "1", 0, 0},
    { 0x0008010C, "Coding Scheme UID", "UI", "1", 0, 0},
    { 0x0008010D, "Context Group Extension Creator UID", "UI", "1", 0, 0},
    { 0x0008010F, "Context Identifier", "CS", "1", 0, 0},
    { 0x00080110, "Coding Scheme Identification Sequence", "SQ", "1", 0, 0},
    { 0x00080112, "Coding Scheme Registry", "LO", "1", 0, 0},
    { 0x00080114, "Coding Scheme External ID", "ST", "1", 0, 0},
    { 0x00080115, "Coding Scheme Name", "ST", "1", 0, 0},
    { 0x00080116, "Coding Scheme Responsible Organization", "ST", "1", 0, 0},
    { 0x00080201, "Timezone Offset From UTC", "SH", "1", 0, 0},
    { 0x00081000, "Network ID", "AE", "1", -1, 0},
    { 0x00081010, "Station Name", "SH", "1", 0, 0},
    { 0x00081030, "Study Description", "LO", "1", 0, 0},
    { 0x00081032, "Procedure Code Sequence", "SQ", "1", 0, 0},
    { 0x0008103E, "Series Description", "LO", "1", 0, 0},
    { 0x00081040, "Institutional Department Name", "LO", "1", 0, 0},
    { 0x00081048, "Physician(s) of Record", "PN", "1-n", 0, 0},
    { 0x00081049, "Physician(s) of Record Identification Sequence", "SQ", "1", 0, 0},
    { 0x00081050, "Performing Physician's Name", "PN", "1-n", 0, 0},
    { 0x00081052, "Performing Physician Identification Sequence", "SQ", "1", 0, 0},
    { 0x00081060, "Name of Physician(s) Reading Study", "PN", "1-n", 0, 0},
    { 0x00081062, "Physician(s) Reading Study Identification Sequence", "SQ", "1", 0, 0},
    { 0x00081070, "Operators' Name", "PN", "1-n", 0, 0},
    { 0x00081072, "Operator Identification Sequence", "SQ", "1", 0, 0},
    { 0x00081080, "Admitting Diagnoses Description", "LO", "1-n", 0, 0},
    { 0x00081084, "Admitting Diagnoses Code Sequence", "SQ", "1", 0, 0},
    { 0x00081090, "Manufacturer's Model Name", "LO", "1", 0, 0},
    { 0x00081100, "Referenced Results Sequence", "SQ", "1", -1, 0},
    { 0x00081110, "Referenced Study Sequence", "SQ", "1", 0, 0},
    { 0x00081111, "Referenced Performed Procedure Step Sequence", "SQ", "1", 0, 0},
    { 0x00081115, "Referenced Series Sequence", "SQ", "1", 0, 0},
    { 0x00081120, "Referenced Patient Sequence", "SQ", "1", 0, 0},
    { 0x00081125, "Referenced Visit Sequence", "SQ", "1", 0, 0},
    { 0x00081130, "Referenced Overlay Sequence", "SQ", "1", -1, 0},
    { 0x0008113A, "Referenced Waveform Sequence", "SQ", "1", 0, 0},
    { 0x00081140, "Referenced Image Sequence", "SQ", "1", 0, 0},
    { 0x00081145, "Referenced Curve Sequence", "SQ", "1", -1, 0},
    { 0x0008114A, "Referenced Instance Sequence", "SQ", "1", 0, 0},
    { 0x0008114B, "Referenced Real World Value Mapping Instance Sequence", "SQ", "1", 0, 0},
    { 0x00081150, "Referenced SOP Class UID", "UI", "1", 0, 0},
    { 0x00081155, "Referenced SOP Instance UID", "UI", "1", 0, 0},
    { 0x0008115A, "SOP Classes Supported", "UI", "1-n", 0, 0},
    { 0x00081160, "Referenced Frame Number", "IS", "1-n", 0, 0},
    { 0x00081195, "Transaction UID", "UI", "1", 0, 0},
    { 0x00081197, "Failure Reason", "US", "1", 0, 0},
    { 0x00081198, "Failed SOP Sequence", "SQ", "1", 0, 0},
    { 0x00081199, "Referenced SOP Sequence", "SQ", "1", 0, 0},
    { 0x00081200, "Studies Containing Other Referenced Instances Sequence", "SQ", "1", 0, 0},
    { 0x00081250, "Related Series Sequence", "SQ", "1", 0, 0},
    { 0x00082110, "Lossy Image Compression (Retired)", "CS", "1", -1, 0},
    { 0x00082111, "Derivation Description", "ST", "1", 0, 0},
    { 0x00082112, "Source Image Sequence", "SQ", "1", 0, 0},
    { 0x00082120, "Stage Name", "SH", "1", 0, 0},
    { 0x00082122, "Stage Number", "IS", "1", 0, 0},
    { 0x00082124, "Number of Stages", "IS", "1", 0, 0},
    { 0x00082127, "View Name", "SH", "1", 0, 0},
    { 0x00082128, "View Number", "IS", "1", 0, 0},
    { 0x00082129, "Number of Event Timers", "IS", "1", 0, 0},
    { 0x0008212A, "Number of Views in Stage", "IS", "1", 0, 0},
    { 0x00082130, "Event Elapsed Time(s)", "DS", "1-n", 0, 0},
    { 0x00082132, "Event Timer Name(s)", "LO", "1-n", 0, 0},
    { 0x00082142, "Start Trim", "IS", "1", 0, 0},
    { 0x00082143, "Stop Trim", "IS", "1", 0, 0},
    { 0x00082144, "Recommended Display Frame Rate", "IS", "1", 0, 0},
    { 0x00082200, "Transducer Position", "CS", "1", -1, 0},
    { 0x00082204, "Transducer Orientation", "CS", "1", -1, 0},
    { 0x00082208, "Anatomic Structure", "CS", "1", -1, 0},
    { 0x00082218, "Anatomic Region Sequence", "SQ", "1", 0, 0},
    { 0x00082220, "Anatomic Region Modifier Sequence", "SQ", "1", 0, 0},
    { 0x00082228, "Primary Anatomic Structure Sequence", "SQ", "1", 0, 0},
    { 0x00082229, "Anatomic Structure, Space or Region Sequence", "SQ", "1", 0, 0},
    { 0x00082230, "Primary Anatomic Structure Modifier Sequence", "SQ", "1", 0, 0},
    { 0x00082240, "Transducer Position Sequence", "SQ", "1", -1, 0},
    { 0x00082242, "Transducer Position Modifier Sequence", "SQ", "1", -1, 0},
    { 0x00082244, "Transducer Orientation Sequence", "SQ", "1", -1, 0},
    { 0x00082246, "Transducer Orientation Modifier Sequence", "SQ", "1", -1, 0},
    { 0x00082251, "Anatomic Structure Space Or Region Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x00082253, "Anatomic Portal Of Entrance Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x00082255, "Anatomic Approach Direction Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x00082256, "Anatomic Perspective Description (Trial)", "ST", "1", -1, 0},
    { 0x00082257, "Anatomic Perspective Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x00082258, "Anatomic Location Of Examining Instrument Description (Trial)", "ST", "1", -1, 0},
    { 0x00082259, "Anatomic Location Of Examining Instrument Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x0008225A, "Anatomic Structure Space Or Region Modifier Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x0008225C, "OnAxis Background Anatomic Structure Code Sequence (Trial)", "SQ", "1", -1, 0},
    { 0x00083001, "Alternate Representation Sequence", "SQ", "1", 0, 0},
    { 0x00083010, "Irradiation Event UID", "UI", "1", 0, 0},
    { 0x00084000, "Identifying Comments", "LT", "1", -1, 0},
    { 0x00089007, "Frame Type", "CS", "4", 0, 0},
    { 0x00089092, "Referenced Image Evidence Sequence", "SQ", "1", 0, 0},
    { 0x00089121, "Referenced Raw Data Sequence", "SQ", "1", 0, 0},
    { 0x00089123, "Creator-Version UID", "UI", "1", 0, 0},
    { 0x00089124, "Derivation Image Sequence", "SQ", "1", 0, 0},
    { 0x00089154, "Source Image Evidence Sequence", "SQ", "1", 0, 0},
    { 0x00089205, "Pixel Presentation", "CS", "1", 0, 0},
    { 0x00089206, "Volumetric Properties", "CS", "1", 0, 0},
    { 0x00089207, "Volume Based Calculation Technique", "CS", "1", 0, 0},
    { 0x00089208, "Complex Image Component", "CS", "1", 0, 0},
    { 0x00089209, "Acquisition Contrast", "CS", "1", 0, 0},
    { 0x00089215, "Derivation Code Sequence", "SQ", "1", 0, 0},
    { 0x00089237, "Referenced Grayscale Presentation State Sequence", "SQ", "1", 0, 0},
    { 0x00089410, "Referenced Other Plane Sequence", "SQ", "1", 0, 0},
    { 0x00089458, "Frame Display Sequence", "SQ", "1", 0, 0},
    { 0x00089459, "Recommended Display Frame Rate in Float", "FL", "1", 0, 0},
    { 0x00089460, "Skip Frame Range Flag", "CS", "1", 0, 0},
    { 0x00100010, "Patient's Name", "PN", "1", 0, 0},
    { 0x00100020, "Patient ID", "LO", "1", 0, 0},
    { 0x00100021, "Issuer of Patient ID", "LO", "1", 0, 0},
    { 0x00100022, "Type of Patient ID", "CS", "1", 0, 0},
    { 0x00100030, "Patient's Birth Date", "DA", "1", 0, 0},
    { 0x00100032, "Patient's Birth Time", "TM", "1", 0, 0},
    { 0x00100040, "Patient's Sex", "CS", "1", 0, 0},
    { 0x00100050, "Patient's Insurance Plan Code Sequence", "SQ", "1", 0, 0},
    { 0x00100101, "Patient's Primary Language Code Sequence", "SQ", "1", 0, 0},
    { 0x00100102, "Patient's Primary Language Code Modifier Sequence", "SQ", "1", 0, 0},
    { 0x00101000, "Other Patient IDs", "LO", "1-n", 0, 0},
    { 0x00101001, "Other Patient Names", "PN", "1-n", 0, 0},
    { 0x00101002, "Other Patient IDs Sequence", "SQ", "1", 0, 0},
    { 0x00101005, "Patient's Birth Name", "PN", "1", 0, 0},
    { 0x00101010, "Patient's Age", "AS", "1", 0, 0},
    { 0x00101020, "Patient's Size", "DS", "1", 0, 0},
    { 0x00101030, "Patient's Weight", "DS", "1", 0, 0},
    { 0x00101040, "Patient's Address", "LO", "1", 0, 0},
    { 0x00101050, "Insurance Plan Identification", "LO", "1-n", -1, 0},
    { 0x00101060, "Patient's Mother's Birth Name", "PN", "1", 0, 0},
    { 0x00101080, "Military Rank", "LO", "1", 0, 0},
    { 0x00101081, "Branch of Service", "LO", "1", 0, 0},
    { 0x00101090, "Medical Record Locator", "LO", "1", 0, 0},
    { 0x00102000, "Medical Alerts", "LO", "1-n", 0, 0},
    { 0x00102110, "Allergies", "LO", "1-n", 0, 0},
    { 0x00102150, "Country of Residence", "LO", "1", 0, 0},
    { 0x00102152, "Region of Residence", "LO", "1", 0, 0},
    { 0x00102154, "Patient's Telephone Numbers", "SH", "1-n", 0, 0},
    { 0x00102160, "Ethnic Group", "SH", "1", 0, 0},
    { 0x00102180, "Occupation", "SH", "1", 0, 0},
    { 0x001021A0, "Smoking Status", "CS", "1", 0, 0},
    { 0x001021B0, "Additional Patient History", "LT", "1", 0, 0},
    { 0x001021C0, "Pregnancy Status", "US", "1", 0, 0},
    { 0x001021D0, "Last Menstrual Date", "DA", "1", 0, 0},
    { 0x001021F0, "Patient's Religious Preference", "LO", "1", 0, 0},
    { 0x00102201, "Patient Species Description", "LO", "1", 0, 0},
    { 0x00102202, "Patient Species Code Sequence", "SQ", "1", 0, 0},
    { 0x00102203, "Patient's Sex Neutered", "CS", "1", 0, 0},
    { 0x00102292, "Patient Breed Description", "LO", "1", 0, 0},
    { 0x00102293, "Patient Breed Code Sequence", "SQ", "1", 0, 0},
    { 0x00102294, "Breed Registration Sequence", "SQ", "1", 0, 0},
    { 0x00102295, "Breed Registration Number", "LO", "1", 0, 0},
    { 0x00102296, "Breed Registry Code Sequence", "SQ", "1", 0, 0},
    { 0x00102297, "Responsible Person", "PN", "1", 0, 0},
    { 0x00102298, "Responsible Person Role", "CS", "1", 0, 0},
    { 0x00102299, "Responsible Organization", "LO", "1", 0, 0},
    { 0x00104000, "Patient Comments", "LT", "1", 0, 0},
    { 0x00109431, "Examined Body Thickness", "FL", "1", 0, 0},
    { 0x00120010, "Clinical Trial Sponsor Name", "LO", "1", 0, 0},
    { 0x00120020, "Clinical Trial Protocol ID", "LO", "1", 0, 0},
    { 0x00120021, "Clinical Trial Protocol Name", "LO", "1", 0, 0},
    { 0x00120030, "Clinical Trial Site ID", "LO", "1", 0, 0},
    { 0x00120031, "Clinical Trial Site Name", "LO", "1", 0, 0},
    { 0x00120040, "Clinical Trial Subject ID", "LO", "1", 0, 0},
    { 0x00120042, "Clinical Trial Subject Reading ID", "LO", "1", 0, 0},
    { 0x00120050, "Clinical Trial Time Point ID", "LO", "1", 0, 0},
    { 0x00120051, "Clinical Trial Time Point Description", "ST", "1", 0, 0},
    { 0x00120060, "Clinical Trial Coordinating Center Name", "LO", "1", 0, 0},
    { 0x00120062, "Patient Identity Removed", "CS", "1", 0, 0},
    { 0x00120063, "De-identification Method", "LO", "1-n", 0, 0},
    { 0x00120064, "De-identification Method Code Sequence", "SQ", "1", 0, 0},
    { 0x00120071, "Clinical Trial Series ID", "LO", "1", 0, 0},
    { 0x00120072, "Clinical Trial Series Description", "LO", "1", 0, 0},
    { 0x00180010, "Contrast/Bolus Agent", "LO", "1", 0, 0},
    { 0x00180012, "Contrast/Bolus Agent Sequence", "SQ", "1", 0, 0},
    { 0x00180014, "Contrast/Bolus Administration Route Sequence", "SQ", "1", 0, 0},
    { 0x00180015, "Body Part Examined", "CS", "1", 0, 0},
    { 0x00180020, "Scanning Sequence", "CS", "1-n", 0, 0},
    { 0x00180021, "Sequence Variant", "CS", "1-n", 0, 0},
    { 0x00180022, "Scan Options", "CS", "1-n", 0, 0},
    { 0x00180023, "MR Acquisition Type", "CS", "1", 0, 0},
    { 0x00180024, "Sequence Name", "SH", "1", 0, 0},
    { 0x00180025, "Angio Flag", "CS", "1", 0, 0},
    { 0x00180026, "Intervention Drug Information Sequence", "SQ", "1", 0, 0},
    { 0x00180027, "Intervention Drug Stop Time", "TM", "1", 0, 0},
    { 0x00180028, "Intervention Drug Dose", "DS", "1", 0, 0},
    { 0x00180029, "Intervention Drug Sequence", "SQ", "1", 0, 0},
    { 0x0018002A, "Additional Drug Sequence", "SQ", "1", 0, 0},
    { 0x00180030, "Radionuclide", "LO", "1-n", -1, 0},
    { 0x00180031, "Radiopharmaceutical", "LO", "1", 0, 0},
    { 0x00180032, "Energy Window Centerline", "DS", "1", -1, 0},
    { 0x00180033, "Energy Window Total Width", "DS", "1-n", -1, 0},
    { 0x00180034, "Intervention Drug Name", "LO", "1", 0, 0},
    { 0x00180035, "Intervention Drug Start Time", "TM", "1", 0, 0},
    { 0x00180036, "Intervention Sequence", "SQ", "1", 0, 0},
    { 0x00180037, "Therapy Type", "CS", "1", -1, 0},
    { 0x00180038, "Intervention Status", "CS", "1", 0, 0},
    { 0x00180039, "Therapy Description", "CS", "1", -1, 0},
    { 0x0018003A, "Intervention Description", "ST", "1", 0, 0},
    { 0x00180040, "Cine Rate", "IS", "1", 0, 0},
    { 0x00180050, "Slice Thickness", "DS", "1", 0, 0},
    { 0x00180060, "KVP", "DS", "1", 0, 0},
    { 0x00180070, "Counts Accumulated", "IS", "1", 0, 0},
    { 0x00180071, "Acquisition Termination Condition", "CS", "1", 0, 0},
    { 0x00180072, "Effective Duration", "DS", "1", 0, 0},
    { 0x00180073, "Acquisition Start Condition", "CS", "1", 0, 0},
    { 0x00180074, "Acquisition Start Condition Data", "IS", "1", 0, 0},
    { 0x00180075, "Acquisition Termination Condition Data", "IS", "1", 0, 0},
    { 0x00180080, "Repetition Time", "DS", "1", 0, 0},
    { 0x00180081, "Echo Time", "DS", "1", 0, 0},
    { 0x00180082, "Inversion Time", "DS", "1", 0, 0},
    { 0x00180083, "Number of Averages", "DS", "1", 0, 0},
    { 0x00180084, "Imaging Frequency", "DS", "1", 0, 0},
    { 0x00180085, "Imaged Nucleus", "SH", "1", 0, 0},
    { 0x00180086, "Echo Number(s)", "IS", "1-n", 0, 0},
    { 0x00180087, "Magnetic Field Strength", "DS", "1", 0, 0},
    { 0x00180088, "Spacing Between Slices", "DS", "1", 0, 0},
    { 0x00180089, "Number of Phase Encoding Steps", "IS", "1", 0, 0},
    { 0x00180090, "Data Collection Diameter", "DS", "1", 0, 0},
    { 0x00180091, "Echo Train Length", "IS", "1", 0, 0},
    { 0x00180093, "Percent Sampling", "DS", "1", 0, 0},
    { 0x00180094, "Percent Phase Field of View", "DS", "1", 0, 0},
    { 0x00180095, "Pixel Bandwidth", "DS", "1", 0, 0},
    { 0x00181000, "Device Serial Number", "LO", "1", 0, 0},
    { 0x00181002, "Device UID", "UI", "1", 0, 0},
    { 0x00181003, "Device ID", "LO", "1", 0, 0},
    { 0x00181004, "Plate ID", "LO", "1", 0, 0},
    { 0x00181005, "Generator ID", "LO", "1", 0, 0},
    { 0x00181006, "Grid ID", "LO", "1", 0, 0},
    { 0x00181007, "Cassette ID", "LO", "1", 0, 0},
    { 0x00181008, "Gantry ID", "LO", "1", 0, 0},
    { 0x00181010, "Secondary Capture Device ID", "LO", "1", 0, 0},
    { 0x00181011, "Hardcopy Creation Device ID", "LO", "1", -1, 0},
    { 0x00181012, "Date of Secondary Capture", "DA", "1", 0, 0},
    { 0x00181014, "Time of Secondary Capture", "TM", "1", 0, 0},
    { 0x00181016, "Secondary Capture Device Manufacturers", "LO", "1", 0, 0},
    { 0x00181017, "Hardcopy Device Manufacturer", "LO", "1", -1, 0},
    { 0x00181018, "Secondary Capture Device Manufacturer's Model Name", "LO", "1", 0, 0},
    { 0x00181019, "Secondary Capture Device Software Version(s)", "LO", "1-n", 0, 0},
    { 0x0018101A, "Hardcopy Device Software Version", "LO", "1-n", -1, 0},
    { 0x0018101B, "Hardcopy Device Manufacturer's Model Name", "LO", "1", -1, 0},
    { 0x00181020, "Software Version(s)", "LO", "1-n", 0, 0},
    { 0x00181022, "Video Image Format Acquired", "SH", "1", 0, 0},
    { 0x00181023, "Digital Image Format Acquired", "LO", "1", 0, 0},
    { 0x00181030, "Protocol Name", "LO", "1", 0, 0},
    { 0x00181040, "Contrast/Bolus Route", "LO", "1", 0, 0},
    { 0x00181041, "Contrast/Bolus Volume", "DS", "1", 0, 0},
    { 0x00181042, "Contrast/Bolus Start Time", "TM", "1", 0, 0},
    { 0x00181043, "Contrast/Bolus Stop Time", "TM", "1", 0, 0},
    { 0x00181044, "Contrast/Bolus Total Dose", "DS", "1", 0, 0},
    { 0x00181045, "Syringe Counts", "IS", "1", 0, 0},
    { 0x00181046, "Contrast Flow Rate", "DS", "1-n", 0, 0},
    { 0x00181047, "Contrast Flow Duration", "DS", "1-n", 0, 0},
    { 0x00181048, "Contrast/Bolus Ingredient", "CS", "1", 0, 0},
    { 0x00181049, "Contrast/Bolus Ingredient Concentration", "DS", "1", 0, 0},
    { 0x00181050, "Spatial Resolution", "DS", "1", 0, 0},
    { 0x00181060, "Trigger Time", "DS", "1", 0, 0},
    { 0x00181061, "Trigger Source or Type", "LO", "1", 0, 0},
    { 0x00181062, "Nominal Interval", "IS", "1", 0, 0},
    { 0x00181063, "Frame Time", "DS", "1", 0, 0},
    { 0x00181064, "Cardiac Framing Type", "LO", "1", 0, 0},
    { 0x00181065, "Frame Time Vector", "DS", "1-n", 0, 0},
    { 0x00181066, "Frame Delay", "DS", "1", 0, 0},
    { 0x00181067, "Image Trigger Delay", "DS", "1", 0, 0},
    { 0x00181068, "Multiplex Group Time Offset", "DS", "1", 0, 0},
    { 0x00181069, "Trigger Time Offset", "DS", "1", 0, 0},
    { 0x0018106A, "Synchronization Trigger", "CS", "1", 0, 0},
    { 0x0018106C, "Synchronization Channel", "US", "2", 0, 0},
    { 0x0018106E, "Trigger Sample Position", "UL", "1", 0, 0},
    { 0x00181070, "Radiopharmaceutical Route", "LO", "1", 0, 0},
    { 0x00181071, "Radiopharmaceutical Volume", "DS", "1", 0, 0},
    { 0x00181072, "Radiopharmaceutical Start Time", "TM", "1", 0, 0},
    { 0x00181073, "Radiopharmaceutical Stop Time", "TM", "1", 0, 0},
    { 0x00181074, "Radionuclide Total Dose", "DS", "1", 0, 0},
    { 0x00181075, "Radionuclide Half Life", "DS", "1", 0, 0},
    { 0x00181076, "Radionuclide Positron Fraction", "DS", "1", 0, 0},
    { 0x00181077, "Radiopharmaceutical Specific Activity", "DS", "1", 0, 0},
    { 0x00181078, "Radiopharmaceutical Start DateTime", "DT", "1", 0, 0},
    { 0x00181079, "Radiopharmaceutical Stop DateTime", "DT", "1", 0, 0},
    { 0x00181080, "Beat Rejection Flag", "CS", "1", 0, 0},
    { 0x00181081, "Low R-R Value", "IS", "1", 0, 0},
    { 0x00181082, "High R-R Value", "IS", "1", 0, 0},
    { 0x00181083, "Intervals Acquired", "IS", "1", 0, 0},
    { 0x00181084, "Intervals Rejected", "IS", "1", 0, 0},
    { 0x00181085, "PVC Rejection", "LO", "1", 0, 0},
    { 0x00181086, "Skip Beats", "IS", "1", 0, 0},
    { 0x00181088, "Heart Rate", "IS", "1", 0, 0},
    { 0x00181090, "Cardiac Number of Images", "IS", "1", 0, 0},
    { 0x00181094, "Trigger Window", "IS", "1", 0, 0},
    { 0x00181100, "Reconstruction Diameter", "DS", "1", 0, 0},
    { 0x00181110, "Distance Source to Detector", "DS", "1", 0, 0},
    { 0x00181111, "Distance Source to Patient", "DS", "1", 0, 0},
    { 0x00181114, "Estimated Radiographic Magnification Factor", "DS", "1", 0, 0},
    { 0x00181120, "Gantry/Detector Tilt", "DS", "1", 0, 0},
    { 0x00181121, "Gantry/Detector Slew", "DS", "1", 0, 0},
    { 0x00181130, "Table Height", "DS", "1", 0, 0},
    { 0x00181131, "Table Traverse", "DS", "1", 0, 0},
    { 0x00181134, "Table Motion", "CS", "1", 0, 0},
    { 0x00181135, "Table Vertical Increment", "DS", "1-n", 0, 0},
    { 0x00181136, "Table Lateral Increment", "DS", "1-n", 0, 0},
    { 0x00181137, "Table Longitudinal Increment", "DS", "1-n", 0, 0},
    { 0x00181138, "Table Angle", "DS", "1", 0, 0},
    { 0x0018113A, "Table Type", "CS", "1", 0, 0},
    { 0x00181140, "Rotation Direction", "CS", "1", 0, 0},
    { 0x00181141, "Angular Position", "DS", "1", -1, 0},
    { 0x00181142, "Radial Position", "DS", "1-n", 0, 0},
    { 0x00181143, "Scan Arc", "DS", "1", 0, 0},
    { 0x00181144, "Angular Step", "DS", "1", 0, 0},
    { 0x00181145, "Center of Rotation Offset", "DS", "1", 0, 0},
    { 0x00181146, "Rotation Offset", "DS", "1-n", -1, 0},
    { 0x00181147, "Field of View Shape", "CS", "1", 0, 0},
    { 0x00181149, "Field of View Dimension(s)", "IS", "1-2", 0, 0},
    { 0x00181150, "Exposure Time", "IS", "1", 0, 0},
    { 0x00181151, "X-Ray Tube Current", "IS", "1", 0, 0},
    { 0x00181152, "Exposure", "IS", "1", 0, 0},
    { 0x00181153, "Exposure in uAs", "IS", "1", 0, 0},
    { 0x00181154, "Average Pulse Width", "DS", "1", 0, 0},
    { 0x00181155, "Radiation Setting", "CS", "1", 0, 0},
    { 0x00181156, "Rectification Type", "CS", "1", 0, 0},
    { 0x0018115A, "Radiation Mode", "CS", "1", 0, 0},
    { 0x0018115E, "Image and Fluoroscopy Area Dose Product", "DS", "1", 0, 0},
    { 0x00181160, "Filter Type", "SH", "1", 0, 0},
    { 0x00181161, "Type of Filters", "LO", "1-n", 0, 0},
    { 0x00181162, "Intensifier Size", "DS", "1", 0, 0},
    { 0x00181164, "Imager Pixel Spacing", "DS", "2", 0, 0},
    { 0x00181166, "Grid", "CS", "1-n", 0, 0},
    { 0x00181170, "Generator Power", "IS", "1", 0, 0},
    { 0x00181180, "Collimator/grid Name", "SH", "1", 0, 0},
    { 0x00181181, "Collimator Type", "CS", "1", 0, 0},
    { 0x00181182, "Focal Distance", "IS", "1-2", 0, 0},
    { 0x00181183, "X Focus Center", "DS", "1-2", 0, 0},
    { 0x00181184, "Y Focus Center", "DS", "1-2", 0, 0},
    { 0x00181190, "Focal Spot(s)", "DS", "1-n", 0, 0},
    { 0x00181191, "Anode Target Material", "CS", "1", 0, 0},
    { 0x001811A0, "Body Part Thickness", "DS", "1", 0, 0},
    { 0x001811A2, "Compression Force", "DS", "1", 0, 0},
    { 0x00181200, "Date of Last Calibration", "DA", "1-n", 0, 0},
    { 0x00181201, "Time of Last Calibration", "TM", "1-n", 0, 0},
    { 0x00181210, "Convolution Kernel", "SH", "1-n", 0, 0},
    { 0x00181240, "Upper/Lower Pixel Values", "IS", "1-n", -1, 0},
    { 0x00181242, "Actual Frame Duration", "IS", "1", 0, 0},
    { 0x00181243, "Count Rate", "IS", "1", 0, 0},
    { 0x00181244, "Preferred Playback Sequencing", "US", "1", 0, 0},
    { 0x00181250, "Receive Coil Name", "SH", "1", 0, 0},
    { 0x00181251, "Transmit Coil Name", "SH", "1", 0, 0},
    { 0x00181260, "Plate Type", "SH", "1", 0, 0},
    { 0x00181261, "Phosphor Type", "LO", "1", 0, 0},
    { 0x00181300, "Scan Velocity", "DS", "1", 0, 0},
    { 0x00181301, "Whole Body Technique", "CS", "1-n", 0, 0},
    { 0x00181302, "Scan Length", "IS", "1", 0, 0},
    { 0x00181310, "Acquisition Matrix", "US", "4", 0, 0},
    { 0x00181312, "In-plane Phase Encoding Direction", "CS", "1", 0, 0},
    { 0x00181314, "Flip Angle", "DS", "1", 0, 0},
    { 0x00181315, "Variable Flip Angle Flag", "CS", "1", 0, 0},
    { 0x00181316, "SAR", "DS", "1", 0, 0},
    { 0x00181318, "dB/dt", "DS", "1", 0, 0},
    { 0x00181400, "Acquisition Device Processing Description", "LO", "1", 0, 0},
    { 0x00181401, "Acquisition Device Processing Code", "LO", "1", 0, 0},
    { 0x00181402, "Cassette Orientation", "CS", "1", 0, 0},
    { 0x00181403, "Cassette Size", "CS", "1", 0, 0},
    { 0x00181404, "Exposures on Plate", "US", "1", 0, 0},
    { 0x00181405, "Relative X-Ray Exposure", "IS", "1", 0, 0},
    { 0x00181450, "Column Angulation", "DS", "1", 0, 0},
    { 0x00181460, "Tomo Layer Height", "DS", "1", 0, 0},
    { 0x00181470, "Tomo Angle", "DS", "1", 0, 0},
    { 0x00181480, "Tomo Time", "DS", "1", 0, 0},
    { 0x00181490, "Tomo Type", "CS", "1", 0, 0},
    { 0x00181491, "Tomo Class", "CS", "1", 0, 0},
    { 0x00181495, "Number of Tomosynthesis Source Images", "IS", "1", 0, 0},
    { 0x00181500, "Positioner Motion", "CS", "1", 0, 0},
    { 0x00181508, "Positioner Type", "CS", "1", 0, 0},
    { 0x00181510, "Positioner Primary Angle", "DS", "1", 0, 0},
    { 0x00181511, "Positioner Secondary Angle", "DS", "1", 0, 0},
    { 0x00181520, "Positioner Primary Angle Increment", "DS", "1-n", 0, 0},
    { 0x00181521, "Positioner Secondary Angle Increment", "DS", "1-n", 0, 0},
    { 0x00181530, "Detector Primary Angle", "DS", "1", 0, 0},
    { 0x00181531, "Detector Secondary Angle", "DS", "1", 0, 0},
    { 0x00181600, "Shutter Shape", "CS", "1-3", 0, 0},
    { 0x00181602, "Shutter Left Vertical Edge", "IS", "1", 0, 0},
    { 0x00181604, "Shutter Right Vertical Edge", "IS", "1", 0, 0},
    { 0x00181606, "Shutter Upper Horizontal Edge", "IS", "1", 0, 0},
    { 0x00181608, "Shutter Lower Horizontal Edge", "IS", "1", 0, 0},
    { 0x00181610, "Center of Circular Shutter", "IS", "2", 0, 0},
    { 0x00181612, "Radius of Circular Shutter", "IS", "1", 0, 0},
    { 0x00181620, "Vertices of the Polygonal Shutter", "IS", "2-2n", 0, 0},
    { 0x00181622, "Shutter Presentation Value", "US", "1", 0, 0},
    { 0x00181623, "Shutter Overlay Group", "US", "1", 0, 0},
    { 0x00181624, "Shutter Presentation Color CIELab Value", "US", "3", 0, 0},
    { 0x00181700, "Collimator Shape", "CS", "1-3", 0, 0},
    { 0x00181702, "Collimator Left Vertical Edge", "IS", "1", 0, 0},
    { 0x00181704, "Collimator Right Vertical Edge", "IS", "1", 0, 0},
    { 0x00181706, "Collimator Upper Horizontal Edge", "IS", "1", 0, 0},
    { 0x00181708, "Collimator Lower Horizontal Edge", "IS", "1", 0, 0},
    { 0x00181710, "Center of Circular Collimator", "IS", "2", 0, 0},
    { 0x00181712, "Radius of Circular Collimator", "IS", "1", 0, 0},
    { 0x00181720, "Vertices of the Polygonal Collimator", "IS", "2-2n", 0, 0},
    { 0x00181800, "Acquisition Time Synchronized", "CS", "1", 0, 0},
    { 0x00181801, "Time Source", "SH", "1", 0, 0},
    { 0x00181802, "Time Distribution Protocol", "CS", "1", 0, 0},
    { 0x00181803, "NTP Source Address", "LO", "1", 0, 0},
    { 0x00182001, "Page Number Vector", "IS", "1-n", 0, 0},
    { 0x00182002, "Frame Label Vector", "SH", "1-n", 0, 0},
    { 0x00182003, "Frame Primary Angle Vector", "DS", "1-n", 0, 0},
    { 0x00182004, "Frame Secondary Angle Vector", "DS", "1-n", 0, 0},
    { 0x00182005, "Slice Location Vector", "DS", "1-n", 0, 0},
    { 0x00182006, "Display Window Label Vector", "SH", "1-n", 0, 0},
    { 0x00182010, "Nominal Scanned Pixel Spacing", "DS", "2", 0, 0},
    { 0x00182020, "Digitizing Device Transport Direction", "CS", "1", 0, 0},
    { 0x00182030, "Rotation of Scanned Film", "DS", "1", 0, 0},
    { 0x00183100, "IVUS Acquisition", "CS", "1", 0, 0},
    { 0x00183101, "IVUS Pullback Rate", "DS", "1", 0, 0},
    { 0x00183102, "IVUS Gated Rate", "DS", "1", 0, 0},
    { 0x00183103, "IVUS Pullback Start Frame Number", "IS", "1", 0, 0},
    { 0x00183104, "IVUS Pullback Stop Frame Number", "IS", "1", 0, 0},
    { 0x00183105, "Lesion Number", "IS", "1-n", 0, 0},
    { 0x00184000, "Acquisition Comments", "LT", "1", -1, 0},
    { 0x00185000, "Output Power", "SH", "1-n", 0, 0},
    { 0x00185010, "Transducer Data", "LO", "3", 0, 0},
    { 0x00185012, "Focus Depth", "DS", "1", 0, 0},
    { 0x00185020, "Processing Function", "LO", "1", 0, 0},
    { 0x00185021, "Postprocessing Function", "LO", "1", -1, 0},
    { 0x00185022, "Mechanical Index", "DS", "1", 0, 0},
    { 0x00185024, "Bone Thermal Index", "DS", "1", 0, 0},
    { 0x00185026, "Cranial Thermal Index", "DS", "1", 0, 0},
    { 0x00185027, "Soft Tissue Thermal Index", "DS", "1", 0, 0},
    { 0x00185028, "Soft Tissue-focus Thermal Index", "DS", "1", 0, 0},
    { 0x00185029, "Soft Tissue-surface Thermal Index", "DS", "1", 0, 0},
    { 0x00185030, "Dynamic Range", "DS", "1", -1, 0},
    { 0x00185040, "Total Gain", "DS", "1", -1, 0},
    { 0x00185050, "Depth of Scan Field", "IS", "1", 0, 0},
    { 0x00185100, "Patient Position", "CS", "1", 0, -1},
    { 0x00185101, "View Position", "CS", "1", 0, 0},
    { 0x00185104, "Projection Eponymous Name Code Sequence", "SQ", "1", 0, 0},
    { 0x00185210, "Image Transformation Matrix", "DS", "6", -1, 0},
    { 0x00185212, "Image Translation Vector", "DS", "3", -1, 0},
    { 0x00186000, "Sensitivity", "DS", "1", 0, 0},
    { 0x00186011, "Sequence of Ultrasound Regions", "SQ", "1", 0, 0},
    { 0x00186012, "Region Spatial Format", "US", "1", 0, 0},
    { 0x00186014, "Region Data Type", "US", "1", 0, 0},
    { 0x00186016, "Region Flags", "UL", "1", 0, 0},
    { 0x00186018, "Region Location Min X0", "UL", "1", 0, 0},
    { 0x0018601A, "Region Location Min Y0", "UL", "1", 0, 0},
    { 0x0018601C, "Region Location Max X1", "UL", "1", 0, 0},
    { 0x0018601E, "Region Location Max Y1", "UL", "1", 0, 0},
    { 0x00186020, "Reference Pixel X0", "SL", "1", 0, 0},
    { 0x00186022, "Reference Pixel Y0", "SL", "1", 0, 0},
    { 0x00186024, "Physical Units X Direction", "US", "1", 0, 0},
    { 0x00186026, "Physical Units Y Direction", "US", "1", 0, 0},
    { 0x00186028, "Reference Pixel Physical Value X", "FD", "1", 0, 0},
    { 0x0018602A, "Reference Pixel Physical Value Y", "FD", "1", 0, 0},
    { 0x0018602C, "Physical Delta X", "FD", "1", 0, 0},
    { 0x0018602E, "Physical Delta Y", "FD", "1", 0, 0},
    { 0x00186030, "Transducer Frequency", "UL", "1", 0, 0},
    { 0x00186031, "Transducer Type", "CS", "1", 0, 0},
    { 0x00186032, "Pulse Repetition Frequency", "UL", "1", 0, 0},
    { 0x00186034, "Doppler Correction Angle", "FD", "1", 0, 0},
    { 0x00186036, "Steering Angle", "FD", "1", 0, 0},
    { 0x00186038, "Doppler Sample Volume X Position (Retired)", "UL", "1", -1, 0},
    { 0x00186039, "Doppler Sample Volume X Position", "SL", "1", 0, 0},
    { 0x0018603A, "Doppler Sample Volume Y Position (Retired)", "UL", "1", -1, 0},
    { 0x0018603B, "Doppler Sample Volume Y Position", "SL", "1", 0, 0},
    { 0x0018603C, "TM-Line Position X0 (Retired)", "UL", "1", -1, 0},
    { 0x0018603D, "TM-Line Position X0", "SL", "1", 0, 0},
    { 0x0018603E, "TM-Line Position Y0 (Retired)", "UL", "1", -1, 0},
    { 0x0018603F, "TM-Line Position Y0", "SL", "1", 0, 0},
    { 0x00186040, "TM-Line Position X1 (Retired)", "UL", "1", -1, 0},
    { 0x00186041, "TM-Line Position X1", "SL", "1", 0, 0},
    { 0x00186042, "TM-Line Position Y1 (Retired)", "UL", "1", -1, 0},
    { 0x00186043, "TM-Line Position Y1", "SL", "1", 0, 0},
    { 0x00186044, "Pixel Component Organization", "US", "1", 0, 0},
    { 0x00186046, "Pixel Component Mask", "UL", "1", 0, 0},
    { 0x00186048, "Pixel Component Range Start", "UL", "1", 0, 0},
    { 0x0018604A, "Pixel Component Range Stop", "UL", "1", 0, 0},
    { 0x0018604C, "Pixel Component Physical Units", "US", "1", 0, 0},
    { 0x0018604E, "Pixel Component Data Type", "US", "1", 0, 0},
    { 0x00186050, "Number of Table Break Points", "UL", "1", 0, 0},
    { 0x00186052, "Table of X Break Points", "UL", "1-n", 0, 0},
    { 0x00186054, "Table of Y Break Points", "FD", "1-n", 0, 0},
    { 0x00186056, "Number of Table Entries", "UL", "1", 0, 0},
    { 0x00186058, "Table of Pixel Values", "UL", "1-n", 0, 0},
    { 0x0018605A, "Table of Parameter Values", "FL", "1-n", 0, 0},
    { 0x00186060, "R Wave Time Vector", "FL", "1-n", 0, 0},
    { 0x00187000, "Detector Conditions Nominal Flag", "CS", "1", 0, 0},
    { 0x00187001, "Detector Temperature", "DS", "1", 0, 0},
    { 0x00187004, "Detector Type", "CS", "1", 0, 0},
    { 0x00187005, "Detector Configuration", "CS", "1", 0, 0},
    { 0x00187006, "Detector Description", "LT", "1", 0, 0},
    { 0x00187008, "Detector Mode", "LT", "1", 0, 0},
    { 0x0018700A, "Detector ID", "SH", "1", 0, 0},
    { 0x0018700C, "Date of Last Detector Calibration", "DA", "1", 0, 0},
    { 0x0018700E, "Time of Last Detector Calibration", "TM", "1", 0, 0},
    { 0x00187010, "Exposures on Detector Since Last Calibration", "IS", "1", 0, 0},
    { 0x00187011, "Exposures on Detector Since Manufactured", "IS", "1", 0, 0},
    { 0x00187012, "Detector Time Since Last Exposure", "DS", "1", 0, 0},
    { 0x00187014, "Detector Active Time", "DS", "1", 0, 0},
    { 0x00187016, "Detector Activation Offset From Exposure", "DS", "1", 0, 0},
    { 0x0018701A, "Detector Binning", "DS", "2", 0, 0},
    { 0x00187020, "Detector Element Physical Size", "DS", "2", 0, 0},
    { 0x00187022, "Detector Element Spacing", "DS", "2", 0, 0},
    { 0x00187024, "Detector Active Shape", "CS", "1", 0, 0},
    { 0x00187026, "Detector Active Dimension(s)", "DS", "1-2", 0, 0},
    { 0x00187028, "Detector Active Origin", "DS", "2", 0, 0},
    { 0x0018702A, "Detector Manufacturer Name", "LO", "1", 0, 0},
    { 0x0018702B, "Detector Manufacturer's Model Name", "LO", "1", 0, 0},
    { 0x00187030, "Field of View Origin", "DS", "2", 0, 0},
    { 0x00187032, "Field of View Rotation", "DS", "1", 0, 0},
    { 0x00187034, "Field of View Horizontal Flip", "CS", "1", 0, 0},
    { 0x00187040, "Grid Absorbing Material", "LT", "1", 0, 0},
    { 0x00187041, "Grid Spacing Material", "LT", "1", 0, 0},
    { 0x00187042, "Grid Thickness", "DS", "1", 0, 0},
    { 0x00187044, "Grid Pitch", "DS", "1", 0, 0},
    { 0x00187046, "Grid Aspect Ratio", "IS", "2", 0, 0},
    { 0x00187048, "Grid Period", "DS", "1", 0, 0},
    { 0x0018704C, "Grid Focal Distance", "DS", "1", 0, 0},
    { 0x00187050, "Filter Material", "CS", "1-n", 0, 0},
    { 0x00187052, "Filter Thickness Minimum", "DS", "1-n", 0, 0},
    { 0x00187054, "Filter Thickness Maximum", "DS", "1-n", 0, 0},
    { 0x00187060, "Exposure Control Mode", "CS", "1", 0, 0},
    { 0x00187062, "Exposure Control Mode Description", "LT", "1", 0, 0},
    { 0x00187064, "Exposure Status", "CS", "1", 0, 0},
    { 0x00187065, "Phototimer Setting", "DS", "1", 0, 0},
    { 0x00188150, "Exposure Time in uS", "DS", "1", 0, 0},
    { 0x00188151, "X-Ray Tube Current in uA", "DS", "1", 0, 0},
    { 0x00189004, "Content Qualification", "CS", "1", 0, 0},
    { 0x00189005, "Pulse Sequence Name", "SH", "1", 0, 0},
    { 0x00189006, "MR Imaging Modifier Sequence", "SQ", "1", 0, 0},
    { 0x00189008, "Echo Pulse Sequence", "CS", "1", 0, 0},
    { 0x00189009, "Inversion Recovery", "CS", "1", 0, 0},
    { 0x00189010, "Flow Compensation", "CS", "1", 0, 0},
    { 0x00189011, "Multiple Spin Echo", "CS", "1", 0, 0},
    { 0x00189012, "Multi-planar Excitation", "CS", "1", 0, 0},
    { 0x00189014, "Phase Contrast", "CS", "1", 0, 0},
    { 0x00189015, "Time of Flight Contrast", "CS", "1", 0, 0},
    { 0x00189016, "Spoiling", "CS", "1", 0, 0},
    { 0x00189017, "Steady State Pulse Sequence", "CS", "1", 0, 0},
    { 0x00189018, "Echo Planar Pulse Sequence", "CS", "1", 0, 0},
    { 0x00189019, "Tag Angle First Axis", "FD", "1", 0, 0},
    { 0x00189020, "Magnetization Transfer", "CS", "1", 0, 0},
    { 0x00189021, "T2 Preparation", "CS", "1", 0, 0},
    { 0x00189022, "Blood Signal Nulling", "CS", "1", 0, 0},
    { 0x00189024, "Saturation Recovery", "CS", "1", 0, 0},
    { 0x00189025, "Spectrally Selected Suppression", "CS", "1", 0, 0},
    { 0x00189026, "Spectrally Selected Excitation", "CS", "1", 0, 0},
    { 0x00189027, "Spatial Pre-saturation", "CS", "1", 0, 0},
    { 0x00189028, "Tagging", "CS", "1", 0, 0},
    { 0x00189029, "Oversampling Phase", "CS", "1", 0, 0},
    { 0x00189030, "Tag Spacing First Dimension", "FD", "1", 0, 0},
    { 0x00189032, "Geometry of k-Space Traversal", "CS", "1", 0, 0},
    { 0x00189033, "Segmented k-Space Traversal", "CS", "1", 0, 0},
    { 0x00189034, "Rectilinear Phase Encode Reordering", "CS", "1", 0, 0},
    { 0x00189035, "Tag Thickness", "FD", "1", 0, 0},
    { 0x00189036, "Partial Fourier Direction", "CS", "1", 0, 0},
    { 0x00189037, "Cardiac Synchronization Technique", "CS", "1", 0, 0},
    { 0x00189041, "Receive Coil Manufacturer Name", "LO", "1", 0, 0},
    { 0x00189042, "MR Receive Coil Sequence", "SQ", "1", 0, 0},
    { 0x00189043, "Receive Coil Type", "CS", "1", 0, 0},
    { 0x00189044, "Quadrature Receive Coil", "CS", "1", 0, 0},
    { 0x00189045, "Multi-Coil Definition Sequence", "SQ", "1", 0, 0},
    { 0x00189046, "Multi-Coil Configuration", "LO", "1", 0, 0},
    { 0x00189047, "Multi-Coil Element Name", "SH", "1", 0, 0},
    { 0x00189048, "Multi-Coil Element Used", "CS", "1", 0, 0},
    { 0x00189049, "MR Transmit Coil Sequence", "SQ", "1", 0, 0},
    { 0x00189050, "Transmit Coil Manufacturer Name", "LO", "1", 0, 0},
    { 0x00189051, "Transmit Coil Type", "CS", "1", 0, 0},
    { 0x00189052, "Spectral Width", "FD", "1-2", 0, 0},
    { 0x00189053, "Chemical Shift Reference", "FD", "1-2", 0, 0},
    { 0x00189054, "Volume Localization Technique", "CS", "1", 0, 0},
    { 0x00189058, "MR Acquisition Frequency Encoding Steps", "US", "1", 0, 0},
    { 0x00189059, "De-coupling", "CS", "1", 0, 0},
    { 0x00189060, "De-coupled Nucleus", "CS", "1-2", 0, 0},
    { 0x00189061, "De-coupling Frequency", "FD", "1-2", 0, 0},
    { 0x00189062, "De-coupling Method", "CS", "1", 0, 0},
    { 0x00189063, "De-coupling Chemical Shift Reference", "FD", "1-2", 0, 0},
    { 0x00189064, "k-space Filtering", "CS", "1", 0, 0},
    { 0x00189065, "Time Domain Filtering", "CS", "1-2", 0, 0},
    { 0x00189066, "Number of Zero fills", "US", "1-2", 0, 0},
    { 0x00189067, "Baseline Correction", "CS", "1", 0, 0},
    { 0x00189069, "Parallel Reduction Factor In-plane", "FD", "1", 0, 0},
    { 0x00189070, "Cardiac R-R Interval Specified", "FD", "1", 0, 0},
    { 0x00189073, "Acquisition Duration", "FD", "1", 0, 0},
    { 0x00189074, "Frame Acquisition DateTime", "DT", "1", 0, 0},
    { 0x00189075, "Diffusion Directionality", "CS", "1", 0, 0},
    { 0x00189076, "Diffusion Gradient Direction Sequence", "SQ", "1", 0, 0},
    { 0x00189077, "Parallel Acquisition", "CS", "1", 0, 0},
    { 0x00189078, "Parallel Acquisition Technique", "CS", "1", 0, 0},
    { 0x00189079, "Inversion Times", "FD", "1-n", 0, 0},
    { 0x00189080, "Metabolite Map Description", "ST", "1", 0, 0},
    { 0x00189081, "Partial Fourier", "CS", "1", 0, 0},
    { 0x00189082, "Effective Echo Time", "FD", "1", 0, 0},
    { 0x00189083, "Metabolite Map Code Sequence", "SQ", "1", 0, 0},
    { 0x00189084, "Chemical Shift Sequence", "SQ", "1", 0, 0},
    { 0x00189085, "Cardiac Signal Source", "CS", "1", 0, 0},
    { 0x00189087, "Diffusion b-value", "FD", "1", 0, 0},
    { 0x00189089, "Diffusion Gradient Orientation", "FD", "3", 0, 0},
    { 0x00189090, "Velocity Encoding Direction", "FD", "3", 0, 0},
    { 0x00189091, "Velocity Encoding Minimum Value", "FD", "1", 0, 0},
    { 0x00189093, "Number of k-Space Trajectories", "US", "1", 0, 0},
    { 0x00189094, "Coverage of k-Space", "CS", "1", 0, 0},
    { 0x00189095, "Spectroscopy Acquisition Phase Rows", "UL", "1", 0, 0},
    { 0x00189096, "Parallel Reduction Factor In-plane (Retired)", "FD", "1", -1, 0},
    { 0x00189098, "Transmitter Frequency", "FD", "1-2", 0, 0},
    { 0x00189100, "Resonant Nucleus", "CS", "1-2", 0, 0},
    { 0x00189101, "Frequency Correction", "CS", "1", 0, 0},
    { 0x00189103, "MR Spectroscopy FOV/Geometry Sequence", "SQ", "1", 0, 0},
    { 0x00189104, "Slab Thickness", "FD", "1", 0, 0},
    { 0x00189105, "Slab Orientation", "FD", "3", 0, 0},
    { 0x00189106, "Mid Slab Position", "FD", "3", 0, 0},
    { 0x00189107, "MR Spatial Saturation Sequence", "SQ", "1", 0, 0},
    { 0x00189112, "MR Timing and Related Parameters Sequence", "SQ", "1", 0, 0},
    { 0x00189114, "MR Echo Sequence", "SQ", "1", 0, 0},
    { 0x00189115, "MR Modifier Sequence", "SQ", "1", 0, 0},
    { 0x00189117, "MR Diffusion Sequence", "SQ", "1", 0, 0},
    { 0x00189118, "Cardiac Synchronization Sequence", "SQ", "1", 0, 0},
    { 0x00189119, "MR Averages Sequence", "SQ", "1", 0, 0},
    { 0x00189125, "MR FOV/Geometry Sequence", "SQ", "1", 0, 0},
    { 0x00189126, "Volume Localization Sequence", "SQ", "1", 0, 0},
    { 0x00189127, "Spectroscopy Acquisition Data Columns", "UL", "1", 0, 0},
    { 0x00189147, "Diffusion Anisotropy Type", "CS", "1", 0, 0},
    { 0x00189151, "Frame Reference DateTime", "DT", "1", 0, 0},
    { 0x00189152, "MR Metabolite Map Sequence", "SQ", "1", 0, 0},
    { 0x00189155, "Parallel Reduction Factor out-of-plane", "FD", "1", 0, 0},
    { 0x00189159, "Spectroscopy Acquisition Out-of-plane Phase Steps", "UL", "1", 0, 0},
    { 0x00189166, "Bulk Motion Status", "CS", "1", -1, 0},
    { 0x00189168, "Parallel Reduction Factor Second In-plane", "FD", "1", 0, 0},
    { 0x00189169, "Cardiac Beat Rejection Technique", "CS", "1", 0, 0},
    { 0x00189170, "Respiratory Motion Compensation Technique", "CS", "1", 0, 0},
    { 0x00189171, "Respiratory Signal Source", "CS", "1", 0, 0},
    { 0x00189172, "Bulk Motion Compensation Technique", "CS", "1", 0, 0},
    { 0x00189173, "Bulk Motion Signal Source", "CS", "1", 0, 0},
    { 0x00189174, "Applicable Safety Standard Agency", "CS", "1", 0, 0},
    { 0x00189175, "Applicable Safety Standard Description", "LO", "1", 0, 0},
    { 0x00189176, "Operating Mode Sequence", "SQ", "1", 0, 0},
    { 0x00189177, "Operating Mode Type", "CS", "1", 0, 0},
    { 0x00189178, "Operating Mode", "CS", "1", 0, 0},
    { 0x00189179, "Specific Absorption Rate Definition", "CS", "1", 0, 0},
    { 0x00189180, "Gradient Output Type", "CS", "1", 0, 0},
    { 0x00189181, "Specific Absorption Rate Value", "FD", "1", 0, 0},
    { 0x00189182, "Gradient Output", "FD", "1", 0, 0},
    { 0x00189183, "Flow Compensation Direction", "CS", "1", 0, 0},
    { 0x00189184, "Tagging Delay", "FD", "1", 0, 0},
    { 0x00189185, "Respiratory Motion Compensation Technique Description", "ST", "1", 0, 0},
    { 0x00189186, "Respiratory Signal Source ID", "SH", "1", 0, 0},
    { 0x00189195, "Chemical Shifts Minimum Integration Limit in Hz", "FD", "1", -1, 0},
    { 0x00189196, "Chemical Shifts Maximum Integration Limit in Hz", "FD", "1", -1, 0},
    { 0x00189197, "MR Velocity Encoding Sequence", "SQ", "1", 0, 0},
    { 0x00189198, "First Order Phase Correction", "CS", "1", 0, 0},
    { 0x00189199, "Water Referenced Phase Correction", "CS", "1", 0, 0},
    { 0x00189200, "MR Spectroscopy Acquisition Type", "CS", "1", 0, 0},
    { 0x00189214, "Respiratory Cycle Position", "CS", "1", 0, 0},
    { 0x00189217, "Velocity Encoding Maximum Value", "FD", "1", 0, 0},
    { 0x00189218, "Tag Spacing Second Dimension", "FD", "1", 0, 0},
    { 0x00189219, "Tag Angle Second Axis", "SS", "1", 0, 0},
    { 0x00189220, "Frame Acquisition Duration", "FD", "1", 0, 0},
    { 0x00189226, "MR Image Frame Type Sequence", "SQ", "1", 0, 0},
    { 0x00189227, "MR Spectroscopy Frame Type Sequence", "SQ", "1", 0, 0},
    { 0x00189231, "MR Acquisition Phase Encoding Steps in-plane", "US", "1", 0, 0},
    { 0x00189232, "MR Acquisition Phase Encoding Steps out-of-plane", "US", "1", 0, 0},
    { 0x00189234, "Spectroscopy Acquisition Phase Columns", "UL", "1", 0, 0},
    { 0x00189236, "Cardiac Cycle Position", "CS", "1", 0, 0},
    { 0x00189239, "Specific Absorption Rate Sequence", "SQ", "1", 0, 0},
    { 0x00189240, "RF Echo Train Length", "US", "1", 0, 0},
    { 0x00189241, "Gradient Echo Train Length", "US", "1", 0, 0},
    { 0x00189295, "Chemical Shifts Minimum Integration Limit in ppm", "FD", "1", 0, 0},
    { 0x00189296, "Chemical Shifts Maximum Integration Limit in ppm", "FD", "1", 0, 0},
    { 0x00189301, "CT Acquisition Type Sequence", "SQ", "1", 0, 0},
    { 0x00189302, "Acquisition Type", "CS", "1", 0, 0},
    { 0x00189303, "Tube Angle", "FD", "1", 0, 0},
    { 0x00189304, "CT Acquisition Details Sequence", "SQ", "1", 0, 0},
    { 0x00189305, "Revolution Time", "FD", "1", 0, 0},
    { 0x00189306, "Single Collimation Width", "FD", "1", 0, 0},
    { 0x00189307, "Total Collimation Width", "FD", "1", 0, 0},
    { 0x00189308, "CT Table Dynamics Sequence", "SQ", "1", 0, 0},
    { 0x00189309, "Table Speed", "FD", "1", 0, 0},
    { 0x00189310, "Table Feed per Rotation", "FD", "1", 0, 0},
    { 0x00189311, "Spiral Pitch Factor", "FD", "1", 0, 0},
    { 0x00189312, "CT Geometry Sequence", "SQ", "1", 0, 0},
    { 0x00189313, "Data Collection Center (Patient)", "FD", "3", 0, 0},
    { 0x00189314, "CT Reconstruction Sequence", "SQ", "1", 0, 0},
    { 0x00189315, "Reconstruction Algorithm", "CS", "1", 0, 0},
    { 0x00189316, "Convolution Kernel Group", "CS", "1", 0, 0},
    { 0x00189317, "Reconstruction Field of View", "FD", "2", 0, 0},
    { 0x00189318, "Reconstruction Target Center (Patient)", "FD", "3", 0, 0},
    { 0x00189319, "Reconstruction Angle", "FD", "1", 0, 0},
    { 0x00189320, "Image Filter", "SH", "1", 0, 0},
    { 0x00189321, "CT Exposure Sequence", "SQ", "1", 0, 0},
    { 0x00189322, "Reconstruction Pixel Spacing", "FD", "2", 0, 0},
    { 0x00189323, "Exposure Modulation Type", "CS", "1", 0, 0},
    { 0x00189324, "Estimated Dose Saving", "FD", "1", 0, 0},
    { 0x00189325, "CT X-Ray Details Sequence", "SQ", "1", 0, 0},
    { 0x00189326, "CT Position Sequence", "SQ", "1", 0, 0},
    { 0x00189327, "Table Position", "FD", "1", 0, 0},
    { 0x00189328, "Exposure Time in ms", "FD", "1", 0, 0},
    { 0x00189329, "CT Image Frame Type Sequence", "SQ", "1", 0, 0},
    { 0x00189330, "X-Ray Tube Current in mA", "FD", "1", 0, 0},
    { 0x00189332, "Exposure in mAs", "FD", "1", 0, 0},
    { 0x00189333, "Constant Volume Flag", "CS", "1", 0, 0},
    { 0x00189334, "Fluoroscopy Flag", "CS", "1", 0, 0},
    { 0x00189335, "Distance Source to Data Collection Center", "FD", "1", 0, 0},
    { 0x00189337, "Contrast/Bolus Agent Number", "US", "1", 0, 0},
    { 0x00189338, "Contrast/Bolus Ingredient Code Sequence", "SQ", "1", 0, 0},
    { 0x00189340, "Contrast Administration Profile Sequence", "SQ", "1", 0, 0},
    { 0x00189341, "Contrast/Bolus Usage Sequence", "SQ", "1", 0, 0},
    { 0x00189342, "Contrast/Bolus Agent Administered", "CS", "1", 0, 0},
    { 0x00189343, "Contrast/Bolus Agent Detected", "CS", "1", 0, 0},
    { 0x00189344, "Contrast/Bolus Agent Phase", "CS", "1", 0, 0},
    { 0x00189345, "CTDIvol", "FD", "1", 0, 0},
    { 0x00189346, "CTDI Phantom Type Code Sequence", "SQ", "1", 0, 0},
    { 0x00189351, "Calcium Scoring Mass Factor Patient", "FL", "1", 0, 0},
    { 0x00189352, "Calcium Scoring Mass Factor Device", "FL", "3", 0, 0},
    { 0x00189360, "CT Additional X-Ray Source Sequence", "SQ", "1", 0, 0},
    { 0x00189401, "Projection Pixel Calibration Sequence", "SQ", "1", 0, 0},
    { 0x00189402, "Distance Source to Isocenter", "FL", "1", 0, 0},
    { 0x00189403, "Distance Object to Table Top", "FL", "1", 0, 0},
    { 0x00189404, "Object Pixel Spacing in Center of Beam", "FL", "2", 0, 0},
    { 0x00189405, "Positioner Position Sequence", "SQ", "1", 0, 0},
    { 0x00189406, "Table Position Sequence", "SQ", "1", 0, 0},
    { 0x00189407, "Collimator Shape Sequence", "SQ", "1", 0, 0},
    { 0x00189412, "XA/XRF Frame Characteristics Sequence", "SQ", "1", 0, 0},
    { 0x00189417, "Frame Acquisition Sequence", "SQ", "1", 0, 0},
    { 0x00189420, "X-Ray Receptor Type", "CS", "1", 0, 0},
    { 0x00189423, "Acquisition Protocol Name", "LO", "1", 0, 0},
    { 0x00189424, "Acquisition Protocol Description", "LT", "1", 0, 0},
    { 0x00189425, "Contrast/Bolus Ingredient Opaque", "CS", "1", 0, 0},
    { 0x00189426, "Distance Receptor Plane to Detector Housing", "FL", "1", 0, 0},
    { 0x00189427, "Intensifier Active Shape", "CS", "1", 0, 0},
    { 0x00189428, "Intensifier Active Dimension(s)", "FL", "1-2", 0, 0},
    { 0x00189429, "Physical Detector Size", "FL", "2", 0, 0},
    { 0x00189430, "Position of Isocenter Projection", "US", "2", 0, 0},
    { 0x00189432, "Field of View Sequence", "SQ", "1", 0, 0},
    { 0x00189433, "Field of View Description", "LO", "1", 0, 0},
    { 0x00189434, "Exposure Control Sensing Regions Sequence", "SQ", "1", 0, 0},
    { 0x00189435, "Exposure Control Sensing Region Shape", "CS", "1", 0, 0},
    { 0x00189436, "Exposure Control Sensing Region Left Vertical Edge", "SS", "1", 0, 0},
    { 0x00189437, "Exposure Control Sensing Region Right Vertical Edge", "SS", "1", 0, 0},
    { 0x00189438, "Exposure Control Sensing Region Upper Horizontal Edge", "SS", "1", 0, 0},
    { 0x00189439, "Exposure Control Sensing Region Lower Horizontal Edge", "SS", "1", 0, 0},
    { 0x00189440, "Center of Circular Exposure Control Sensing Region", "SS", "2", 0, 0},
    { 0x00189441, "Radius of Circular Exposure Control Sensing Region", "US", "1", 0, 0},
    { 0x00189442, "Vertices of the Polygonal Exposure Control Sensing Region", "SS", "2-n", 0, 0},
    { 0x00189445, "", "", "", -1, 0},
    { 0x00189447, "Column Angulation (Patient)", "FL", "1", 0, 0},
    { 0x00189449, "Beam Angle", "FL", "1", 0, 0},
    { 0x00189451, "Frame Detector Parameters Sequence", "SQ", "1", 0, 0},
    { 0x00189452, "Calculated Anatomy Thickness", "FL", "1", 0, 0},
    { 0x00189455, "Calibration Sequence", "SQ", "1", 0, 0},
    { 0x00189456, "Object Thickness Sequence", "SQ", "1", 0, 0},
    { 0x00189457, "Plane Identification", "CS", "1", 0, 0},
    { 0x00189461, "Field of View Dimension(s) in Float", "FL", "1-2", 0, 0},
    { 0x00189462, "Isocenter Reference System Sequence", "SQ", "1", 0, 0},
    { 0x00189463, "Positioner Isocenter Primary Angle", "FL", "1", 0, 0},
    { 0x00189464, "Positioner Isocenter Secondary Angle", "FL", "1", 0, 0},
    { 0x00189465, "Positioner Isocenter Detector Rotation Angle", "FL", "1", 0, 0},
    { 0x00189466, "Table X Position to Isocenter", "FL", "1", 0, 0},
    { 0x00189467, "Table Y Position to Isocenter", "FL", "1", 0, 0},
    { 0x00189468, "Table Z Position to Isocenter", "FL", "1", 0, 0},
    { 0x00189469, "Table Horizontal Rotation Angle", "FL", "1", 0, 0},
    { 0x00189470, "Table Head Tilt Angle", "FL", "1", 0, 0},
    { 0x00189471, "Table Cradle Tilt Angle", "FL", "1", 0, 0},
    { 0x00189472, "Frame Display Shutter Sequence", "SQ", "1", 0, 0},
    { 0x00189473, "Acquired Image Area Dose Product", "FL", "1", 0, 0},
    { 0x00189474, "C-arm Positioner Tabletop Relationship", "CS", "1", 0, 0},
    { 0x00189476, "X-Ray Geometry Sequence", "SQ", "1", 0, 0},
    { 0x00189477, "Irradiation Event Identification Sequence", "SQ", "1", 0, 0},
    { 0x00189504, "X-Ray 3D Frame Type Sequence", "SQ", "1", 0, 0},
    { 0x00189506, "Contributing Sources Sequence", "SQ", "1", 0, 0},
    { 0x00189507, "X-Ray 3D Acquisition Sequence", "SQ", "1", 0, 0},
    { 0x00189508, "Primary Positioner Scan Arc", "FL", "1", 0, 0},
    { 0x00189509, "Secondary Positioner Scan Arc", "FL", "1", 0, 0},
    { 0x00189510, "Primary Positioner Scan Start Angle", "FL", "1", 0, 0},
    { 0x00189511, "Secondary Positioner Scan Start Angle", "FL", "1", 0, 0},
    { 0x00189514, "Primary Positioner Increment", "FL", "1", 0, 0},
    { 0x00189515, "Secondary Positioner Increment", "FL", "1", 0, 0},
    { 0x00189516, "Start Acquisition DateTime", "DT", "1", 0, 0},
    { 0x00189517, "End Acquisition DateTime", "DT", "1", 0, 0},
    { 0x00189524, "Application Name", "LO", "1", 0, 0},
    { 0x00189525, "Application Version", "LO", "1", 0, 0},
    { 0x00189526, "Application Manufacturer", "LO", "1", 0, 0},
    { 0x00189527, "Algorithm Type", "CS", "1", 0, 0},
    { 0x00189528, "Algorithm Description", "LO", "1", 0, 0},
    { 0x00189530, "X-Ray 3D Reconstruction Sequence", "SQ", "1", 0, 0},
    { 0x00189531, "Reconstruction Description", "LO", "1", 0, 0},
    { 0x00189538, "Per Projection Acquisition Sequence", "SQ", "1", 0, 0},
    { 0x00189601, "Diffusion b-matrix Sequence", "SQ", "1", 0, 0},
    { 0x00189602, "Diffusion b-value XX", "FD", "1", 0, 0},
    { 0x00189603, "Diffusion b-value XY", "FD", "1", 0, 0},
    { 0x00189604, "Diffusion b-value XZ", "FD", "1", 0, 0},
    { 0x00189605, "Diffusion b-value YY", "FD", "1", 0, 0},
    { 0x00189606, "Diffusion b-value YZ", "FD", "1", 0, 0},
    { 0x00189607, "Diffusion b-value ZZ", "FD", "1", 0, 0},
    { 0x0018A001, "Contributing Equipment Sequence", "SQ", "1", 0, 0},
    { 0x0018A002, "Contribution Date Time", "DT", "1", 0, 0},
    { 0x0018A003, "Contribution Description", "ST", "1", 0, 0},
    { 0x0020000D, "Study Instance UID", "UI", "1", 0, 0},
    { 0x0020000E, "Series Instance UID", "UI", "1", 0, 0},
    { 0x00200010, "Study ID", "SH", "1", 0, 0},
    { 0x00200011, "Series Number", "IS", "1", 0, 0},
    { 0x00200012, "Acquisition Number", "IS", "1", 0, 0},
    { 0x00200013, "Instance Number", "IS", "1", 0, 0},
    { 0x00200014, "Isotope Number", "IS", "1", -1, 0},
    { 0x00200015, "Phase Number", "IS", "1", -1, 0},
    { 0x00200016, "Interval Number", "IS", "1", -1, 0},
    { 0x00200017, "Time Slot Number", "IS", "1", -1, 0},
    { 0x00200018, "Angle Number", "IS", "1", -1, 0},
    { 0x00200019, "Item Number", "IS", "1", 0, 0},
    { 0x00200020, "Patient Orientation", "CS", "2", 0, 0},
    { 0x00200022, "Overlay Number", "IS", "1", -1, 0},
    { 0x00200024, "Curve Number", "IS", "1", -1, 0},
    { 0x00200026, "Lookup Table Number", "IS", "1", -1, 0},
    { 0x00200030, "Image Position", "DS", "3", -1, 0},
    { 0x00200032, "Image Position (Patient)", "DS", "3", 0, 0},
    { 0x00200035, "Image Orientation", "DS", "6", -1, 0},
    { 0x00200037, "Image Orientation (Patient)", "DS", "6", 0, 0},
    { 0x00200050, "Location", "DS", "1", -1, 0},
    { 0x00200052, "Frame of Reference UID", "UI", "1", 0, 0},
    { 0x00200060, "Laterality", "CS", "1", 0, 0},
    { 0x00200062, "Image Laterality", "CS", "1", 0, 0},
    { 0x00200070, "Image Geometry Type", "LO", "1", -1, 0},
    { 0x00200080, "Masking Image", "CS", "1-n", -1, 0},
    { 0x00200100, "Temporal Position Identifier", "IS", "1", 0, 0},
    { 0x00200105, "Number of Temporal Positions", "IS", "1", 0, 0},
    { 0x00200110, "Temporal Resolution", "DS", "1", 0, 0},
    { 0x00200200, "Synchronization Frame of Reference UID", "UI", "1", 0, 0},
    { 0x00201000, "Series in Study", "IS", "1", -1, 0},
    { 0x00201001, "Acquisitions in Series", "IS", "1", -1, 0},
    { 0x00201002, "Images in Acquisition", "IS", "1", 0, 0},
    { 0x00201003, "Images in Series", "IS", "1", -1, 0},
    { 0x00201004, "Acquisitions in Study", "IS", "1", -1, 0},
    { 0x00201005, "Images in Study", "IS", "1", -1, 0},
    { 0x00201020, "Reference", "CS", "1-n", -1, 0},
    { 0x00201040, "Position Reference Indicator", "LO", "1", 0, 0},
    { 0x00201041, "Slice Location", "DS", "1", 0, 0},
    { 0x00201070, "Other Study Numbers", "IS", "1-n", -1, 0},
    { 0x00201200, "Number of Patient Related Studies", "IS", "1", 0, 0},
    { 0x00201202, "Number of Patient Related Series", "IS", "1", 0, 0},
    { 0x00201204, "Number of Patient Related Instances", "IS", "1", 0, 0},
    { 0x00201206, "Number of Study Related Series", "IS", "1", 0, 0},
    { 0x00201208, "Number of Study Related Instances", "IS", "1", 0, 0},
    { 0x00201209, "Number of Series Related Instances", "IS", "1", 0, 0},
    { 0x00203100, "Source Image IDs", "CS", "1-n", -1, 0},
    { 0x00203401, "Modifying Device ID", "CS", "1", -1, 0},
    { 0x00203402, "Modified Image ID", "CS", "1", -1, 0},
    { 0x00203403, "Modified Image Date", "DA", "1", -1, 0},
    { 0x00203404, "Modifying Device Manufacturer", "LO", "1", -1, 0},
    { 0x00203405, "Modified Image Time", "TM", "1", -1, 0},
    { 0x00203406, "Modified Image Description", "LO", "1", -1, 0},
    { 0x00204000, "Image Comments", "LT", "1", 0, 0},
    { 0x00205000, "Original Image Identification", "AT", "1-n", -1, 0},
    { 0x00205002, "Original Image Identification Nomenclature", "CS", "1-n", -1, 0},
    { 0x00209056, "Stack ID", "SH", "1", 0, 0},
    { 0x00209057, "In-Stack Position Number", "UL", "1", 0, 0},
    { 0x00209071, "Frame Anatomy Sequence", "SQ", "1", 0, 0},
    { 0x00209072, "Frame Laterality", "CS", "1", 0, 0},
    { 0x00209111, "Frame Content Sequence", "SQ", "1", 0, 0},
    { 0x00209113, "Plane Position Sequence", "SQ", "1", 0, 0},
    { 0x00209116, "Plane Orientation Sequence", "SQ", "1", 0, 0},
    { 0x00209128, "Temporal Position Index", "UL", "1", 0, 0},
    { 0x00209153, "Nominal Cardiac Trigger Delay Time", "FD", "1", 0, 0},
    { 0x00209156, "Frame Acquisition Number", "US", "1", 0, 0},
    { 0x00209157, "Dimension Index Values", "UL", "1-n", 0, 0},
    { 0x00209158, "Frame Comments", "LT", "1", 0, 0},
    { 0x00209161, "Concatenation UID", "UI", "1", 0, 0},
    { 0x00209162, "In-concatenation Number", "US", "1", 0, 0},
    { 0x00209163, "In-concatenation Total Number", "US", "1", 0, 0},
    { 0x00209164, "Dimension Organization UID", "UI", "1", 0, 0},
    { 0x00209165, "Dimension Index Pointer", "AT", "1", 0, 0},
    { 0x00209167, "Functional Group Pointer", "AT", "1", 0, 0},
    { 0x00209213, "Dimension Index Private Creator", "LO", "1", 0, 0},
    { 0x00209221, "Dimension Organization Sequence", "SQ", "1", 0, 0},
    { 0x00209222, "Dimension Index Sequence", "SQ", "1", 0, 0},
    { 0x00209228, "Concatenation Frame Offset Number", "UL", "1", 0, 0},
    { 0x00209238, "Functional Group Private Creator", "LO", "1", 0, 0},
    { 0x00209241, "Nominal Percentage of Cardiac Phase", "FL", "1", 0, 0},
    { 0x00209245, "Nominal Percentage of Respiratory Phase", "FL", "1", 0, 0},
    { 0x00209246, "Starting Respiratory Amplitude", "FL", "1", 0, 0},
    { 0x00209247, "Starting Respiratory Phase", "CS", "1", 0, 0},
    { 0x00209248, "Ending Respiratory Amplitude", "FL", "1", 0, 0},
    { 0x00209249, "Ending Respiratory Phase", "CS", "1", 0, 0},
    { 0x00209250, "Respiratory Trigger Type", "CS", "1", 0, 0},
    { 0x00209251, "R - R Interval Time Nominal", "FD", "1", 0, 0},
    { 0x00209252, "Actual Cardiac Trigger Delay Time", "FD", "1", 0, 0},
    { 0x00209253, "Respiratory Synchronization Sequence", "SQ", "1", 0, 0},
    { 0x00209254, "Respiratory Interval Time", "FD", "1", 0, 0},
    { 0x00209255, "Nominal Respiratory Trigger Delay Time", "FD", "1", 0, 0},
    { 0x00209256, "Respiratory Trigger Delay Threshold", "FD", "1", 0, 0},
    { 0x00209257, "Actual Respiratory Trigger Delay Time", "FD", "1", 0, 0},
    { 0x00209421, "Dimension Description Label", "LO", "1", 0, 0},
    { 0x00209450, "Patient Orientation in Frame Sequence", "SQ", "1", 0, 0},
    { 0x00209453, "Frame Label", "LO", "1", 0, 0},
    { 0x00209518, "Acquisition Index", "US", "1-n", 0, 0},
    { 0x00209529, "Contributing SOP Instances Reference Sequence", "SQ", "1", 0, 0},
    { 0x00209536, "Reconstruction Index", "US", "1", 0, 0},
    { 0x00220001, "Light Path Filter Pass-Through Wavelength", "US", "1", 0, 0},
    { 0x00220002, "Light Path Filter Pass Band", "US", "2", 0, 0},
    { 0x00220003, "Image Path Filter Pass-Through Wavelength", "US", "1", 0, 0},
    { 0x00220004, "Image Path Filter Pass Band", "US", "2", 0, 0},
    { 0x00220005, "Patient Eye Movement Commanded", "CS", "1", 0, 0},
    { 0x00220006, "Patient Eye Movement Command Code Sequence", "SQ", "1", 0, 0},
    { 0x00220007, "Spherical Lens Power", "FL", "1", 0, 0},
    { 0x00220008, "Cylinder Lens Power", "FL", "1", 0, 0},
    { 0x00220009, "Cylinder Axis", "FL", "1", 0, 0},
    { 0x0022000A, "Emmetropic Magnification", "FL", "1", 0, 0},
    { 0x0022000B, "Intra Ocular Pressure", "FL", "1", 0, 0},
    { 0x0022000C, "Horizontal Field of View", "FL", "1", 0, 0},
    { 0x0022000D, "Pupil Dilated", "CS", "1", 0, 0},
    { 0x0022000E, "Degree of Dilation", "FL", "1", 0, 0},
    { 0x00220010, "Stereo Baseline Angle", "FL", "1", 0, 0},
    { 0x00220011, "Stereo Baseline Displacement", "FL", "1", 0, 0},
    { 0x00220012, "Stereo Horizontal Pixel Offset", "FL", "1", 0, 0},
    { 0x00220013, "Stereo Vertical Pixel Offset", "FL", "1", 0, 0},
    { 0x00220014, "Stereo Rotation", "FL", "1", 0, 0},
    { 0x00220015, "Acquisition Device Type Code Sequence", "SQ", "1", 0, 0},
    { 0x00220016, "Illumination Type Code Sequence", "SQ", "1", 0, 0},
    { 0x00220017, "Light Path Filter Type Stack Code Sequence", "SQ", "1", 0, 0},
    { 0x00220018, "Image Path Filter Type Stack Code Sequence", "SQ", "1", 0, 0},
    { 0x00220019, "Lenses Code Sequence", "SQ", "1", 0, 0},
    { 0x0022001A, "Channel Description Code Sequence", "SQ", "1", 0, 0},
    { 0x0022001B, "Refractive State Sequence", "SQ", "1", 0, 0},
    { 0x0022001C, "Mydriatic Agent Code Sequence", "SQ", "1", 0, 0},
    { 0x0022001D, "Relative Image Position Code Sequence", "SQ", "1", 0, 0},
    { 0x00220020, "Stereo Pairs Sequence", "SQ", "1", 0, 0},
    { 0x00220021, "Left Image Sequence", "SQ", "1", 0, 0},
    { 0x00220022, "Right Image Sequence", "SQ", "1", 0, 0},
    { 0x00220030, "Axial Length of the Eye", "FL", "1", 0, 0},
    { 0x00220031, "Ophthalmic Frame Location Sequence", "SQ", "1", 0, 0},
    { 0x00220032, "Reference Coordinates", "FL", "2-2n", 0, 0},
    { 0x00220035, "Depth Spatial Resolution", "FL", "1", 0, 0},
    { 0x00220036, "Maximum Depth Distortion", "FL", "1", 0, 0},
    { 0x00220037, "Along-scan Spatial Resolution", "FL", "1", 0, 0},
    { 0x00220038, "Maximum Along-scan Distortion", "FL", "1", 0, 0},
    { 0x00220039, "Ophthalmic Image Orientation", "CS", "1", 0, 0},
    { 0x00220041, "Depth of Transverse Image", "FL", "1", 0, 0},
    { 0x00220042, "Mydriatic Agent Concentration Units Sequence", "SQ", "1", 0, 0},
    { 0x00220048, "Across-scan Spatial Resolution", "FL", "1", 0, 0},
    { 0x00220049, "Maximum Across-scan Distortion", "FL", "1", 0, 0},
    { 0x0022004E, "Mydriatic Agent Concentration", "DS", "1", 0, 0},
    { 0x00220055, "Illumination Wave Length", "FL", "1", 0, 0},
    { 0x00220056, "Illumination Power", "FL", "1", 0, 0},
    { 0x00220057, "Illumination Bandwidth", "FL", "1", 0, 0},
    { 0x00220058, "Mydriatic Agent Sequence", "SQ", "1", 0, 0},
    { 0x00280002, "Samples per Pixel", "US", "1", 0, 0},
    { 0x00280003, "Samples per Pixel Used", "US", "1", 0, 0},
    { 0x00280004, "Photometric Interpretation", "CS", "1", 0, 0},
    { 0x00280005, "Image Dimensions", "US", "1", -1, 0},
    { 0x00280006, "Planar Configuration", "US", "1", 0, 0},
    { 0x00280008, "Number of Frames", "IS", "1", 0, 0},
    { 0x00280009, "Frame Increment Pointer", "AT", "1-n", 0, 0},
    { 0x0028000A, "Frame Dimension Pointer", "AT", "1-n", 0, 0},
    { 0x00280010, "Rows", "US", "1", 0, 0},
    { 0x00280011, "Columns", "US", "1", 0, 0},
    { 0x00280012, "Planes", "US", "1", -1, 0},
    { 0x00280014, "Ultrasound Color Data Present", "US", "1", 0, 0},
    { 0x00280020, "", "", "", -1, 0},
    { 0x00280030, "Pixel Spacing", "DS", "2", 0, 0},
    { 0x00280031, "Zoom Factor", "DS", "2", 0, 0},
    { 0x00280032, "Zoom Center", "DS", "2", 0, 0},
    { 0x00280034, "Pixel Aspect Ratio", "IS", "2", 0, 0},
    { 0x00280040, "Image Format", "CS", "1", -1, 0},
    { 0x00280050, "Manipulated Image", "LO", "1-n", -1, 0},
    { 0x00280051, "Corrected Image", "CS", "1-n", 0, 0},
    { 0x0028005F, "Compression Recognition Code", "LO", "1", -1, 0},
    { 0x00280060, "Compression Code", "CS", "1", -1, 0},
    { 0x00280061, "Compression Originator", "SH", "1", -1, 0},
    { 0x00280062, "Compression Label", "LO", "1", -1, 0},
    { 0x00280063, "Compression Description", "SH", "1", -1, 0},
    { 0x00280065, "Compression Sequence", "CS", "1-n", -1, 0},
    { 0x00280066, "Compression Step Pointers", "AT", "1-n", -1, 0},
    { 0x00280068, "Repeat Interval", "US", "1", -1, 0},
    { 0x00280069, "Bits Grouped", "US", "1", -1, 0},
    { 0x00280070, "Perimeter Table", "US", "1-n", -1, 0},
    { 0x00280071, "Perimeter Value", "US or SS", "1", -1, 0},
    { 0x00280080, "Predictor Rows", "US", "1", -1, 0},
    { 0x00280081, "Predictor Columns", "US", "1", -1, 0},
    { 0x00280082, "Predictor Constants", "US", "1-n", -1, 0},
    { 0x00280090, "Blocked Pixels", "CS", "1", -1, 0},
    { 0x00280091, "Block Rows", "US", "1", -1, 0},
    { 0x00280092, "Block Columns", "US", "1", -1, 0},
    { 0x00280093, "Row Overlap", "US", "1", -1, 0},
    { 0x00280094, "Column Overlap", "US", "1", -1, 0},
    { 0x00280100, "Bits Allocated", "US", "1", 0, 0},
    { 0x00280101, "Bits Stored", "US", "1", 0, 0},
    { 0x00280102, "High Bit", "US", "1", 0, 0},
    { 0x00280103, "Pixel Representation", "US", "1", 0, 0},
    { 0x00280104, "Smallest Valid Pixel Value", "US or SS", "1", -1, 0},
    { 0x00280105, "Largest Valid Pixel Value", "US or SS", "1", -1, 0},
    { 0x00280106, "Smallest Image Pixel Value", "US or SS", "1", 0, 0},
    { 0x00280107, "Largest Image Pixel Value", "US or SS", "1", 0, 0},
    { 0x00280108, "Smallest Pixel Value in Series", "US or SS", "1", 0, 0},
    { 0x00280109, "Largest Pixel Value in Series", "US or SS", "1", 0, 0},
    { 0x00280110, "Smallest Image Pixel Value in Plane", "US or SS", "1", -1, 0},
    { 0x00280111, "Largest Image Pixel Value in Plane", "US or SS", "1", -1, 0},
    { 0x00280120, "Pixel Padding Value", "US or SS", "1", 0, 0},
    { 0x00280121, "Pixel Padding Range Limit", "US or SS", "1", 0, 0},
    { 0x00280200, "Image Location", "US", "1", -1, 0},
    { 0x00280300, "Quality Control Image", "CS", "1", 0, 0},
    { 0x00280301, "Burned In Annotation", "CS", "1", 0, 0},
    { 0x00280400, "Transform Label", "LO", "1", -1, 0},
    { 0x00280401, "Transform Version Number", "LO", "1", -1, 0},
    { 0x00280402, "Number of Transform Steps", "US", "1", -1, 0},
    { 0x00280403, "Sequence of Compressed Data", "LO", "1-n", -1, 0},
    { 0x00280404, "Details of Coefficients", "AT", "1-n", -1, 0},
    { 0x00280410, "Rows For Nth Order Coefficients", "US", "1", -1, 0},
    { 0x00280411, "Columns For Nth Order Coefficients", "US", "1", -1, 0},
    { 0x00280412, "Coefficient Coding", "LO", "1-n", -1, 0},
    { 0x00280413, "Coefficient Coding Pointers", "AT", "1-n", -1, 0},
    { 0x00280700, "DCT Label", "LO", "1", -1, 0},
    { 0x00280701, "Data Block Description", "CS", "1-n", -1, 0},
    { 0x00280702, "Data Block", "AT", "1-n", -1, 0},
    { 0x00280710, "Normalization Factor Format", "US", "1", -1, 0},
    { 0x00280720, "Zonal Map Number Format", "US", "1", -1, 0},
    { 0x00280721, "Zonal Map Location", "AT", "1-n", -1, 0},
    { 0x00280722, "Zonal Map Format", "US", "1", -1, 0},
    { 0x00280730, "Adaptive Map Format", "US", "1", -1, 0},
    { 0x00280740, "Code Number Format", "US", "1", -1, 0},
    { 0x00280800, "Code Label", "CS", "1-n", -1, 0},
    { 0x00280802, "Number of Table", "US", "1", -1, 0},
    { 0x00280803, "Code Table Location", "AT", "1-n", -1, 0},
    { 0x00280804, "Bits For Code Word", "US", "1", -1, 0},
    { 0x00280808, "Image Data Location", "AT", "1-n", -1, 0},
    { 0x00280A02, "Pixel Spacing Calibration Type", "CS", "1", 0, 0},
    { 0x00280A04, "Pixel Spacing Calibration Description", "LO", "1", 0, 0},
    { 0x00281040, "Pixel Intensity Relationship", "CS", "1", 0, 0},
    { 0x00281041, "Pixel Intensity Relationship Sign", "SS", "1", 0, 0},
    { 0x00281050, "Window Center", "DS", "1-n", 0, 0},
    { 0x00281051, "Window Width", "DS", "1-n", 0, 0},
    { 0x00281052, "Rescale Intercept", "DS", "1", 0, 0},
    { 0x00281053, "Rescale Slope", "DS", "1", 0, 0},
    { 0x00281054, "Rescale Type", "LO", "1", 0, 0},
    { 0x00281055, "Window Center & Width Explanation", "LO", "1-n", 0, 0},
    { 0x00281056, "VOI LUT Function", "CS", "1", 0, 0},
    { 0x00281080, "Gray Scale", "CS", "1", -1, 0},
    { 0x00281090, "Recommended Viewing Mode", "CS", "1", 0, 0},
    { 0x00281100, "Gray Lookup Table Descriptor", "US or SS", "3", -1, 0},
    { 0x00281101, "Red Palette Color Lookup Table Descriptor", "US or SS", "3", 0, 0},
    { 0x00281102, "Green Palette Color Lookup Table Descriptor", "US or SS", "3", 0, 0},
    { 0x00281103, "Blue Palette Color Lookup Table Descriptor", "US or SS", "3", 0, 0},
    { 0x00281111, "Large Red Palette Color Lookup Table Descriptor", "US or SS", "4", -1, 0},
    { 0x00281112, "Large Green Palette Color Lookup Table Descriptor", "US or SS", "4", -1, 0},
    { 0x00281113, "Large Blue Palette Color Lookup Table Descriptor", "US or SS", "4", -1, 0},
    { 0x00281199, "Palette Color Lookup Table UID", "UI", "1", 0, 0},
    { 0x00281200, "Gray Lookup Table Data", "US or SS or OW", "1-n 1", -1, 0},
    { 0x00281201, "Red Palette Color Lookup Table Data", "OW", "1", 0, 0},
    { 0x00281202, "Green Palette Color Lookup Table Data", "OW", "1", 0, 0},
    { 0x00281203, "Blue Palette Color Lookup Table Data", "OW", "1", 0, 0},
    { 0x00281211, "Large Red Palette Color Lookup Table Data", "OW", "1", -1, 0},
    { 0x00281212, "Large Green Palette Color Lookup Table Data", "OW", "1", -1, 0},
    { 0x00281213, "Large Blue Palette Color Lookup Table Data", "OW", "1", -1, 0},
    { 0x00281214, "Large Palette Color Lookup Table UID", "UI", "1", -1, 0},
    { 0x00281221, "Segmented Red Palette Color Lookup Table Data", "OW", "1", 0, 0},
    { 0x00281222, "Segmented Green Palette Color Lookup Table Data", "OW", "1", 0, 0},
    { 0x00281223, "Segmented Blue Palette Color Lookup Table Data", "OW", "1", 0, 0},
    { 0x00281300, "Implant Present", "CS", "1", 0, 0},
    { 0x00281350, "Partial View", "CS", "1", 0, 0},
    { 0x00281351, "Partial View Description", "ST", "1", 0, 0},
    { 0x00281352, "Partial View Code Sequence", "SQ", "1", 0, 0},
    { 0x0028135A, "Spatial Locations Preserved", "CS", "1", 0, 0},
    { 0x00282000, "ICC Profile", "OB", "1", 0, 0},
    { 0x00282110, "Lossy Image Compression", "CS", "1", 0, 0},
    { 0x00282112, "Lossy Image Compression Ratio", "DS", "1-n", 0, 0},
    { 0x00282114, "Lossy Image Compression Method", "CS", "1-n", 0, 0},
    { 0x00283000, "Modality LUT Sequence", "SQ", "1", 0, 0},
    { 0x00283002, "LUT Descriptor", "US or SS", "3", 0, 0},
    { 0x00283003, "LUT Explanation", "LO", "1", 0, 0},
    { 0x00283004, "Modality LUT Type", "LO", "1", 0, 0},
    { 0x00283006, "LUT Data", "US or SS or OW", "1-n 1", 0, 0},
    { 0x00283010, "VOI LUT Sequence", "SQ", "1", 0, 0},
    { 0x00283110, "Softcopy VOI LUT Sequence", "SQ", "1", 0, 0},
    { 0x00284000, "Image Presentation Comments", "LT", "1", -1, 0},
    { 0x00285000, "Bi-Plane Acquisition Sequence", "SQ", "1", -1, 0},
    { 0x00286010, "Representative Frame Number", "US", "1", 0, 0},
    { 0x00286020, "Frame Numbers of Interest (FOI)", "US", "1-n", 0, 0},
    { 0x00286022, "Frame(s) of Interest Description", "LO", "1-n", 0, 0},
    { 0x00286023, "Frame of Interest Type", "CS", "1-n", 0, 0},
    { 0x00286030, "Mask Pointer(s)", "US", "1-n", -1, 0},
    { 0x00286040, "R Wave Pointer", "US", "1-n", 0, 0},
    { 0x00286100, "Mask Subtraction Sequence", "SQ", "1", 0, 0},
    { 0x00286101, "Mask Operation", "CS", "1", 0, 0},
    { 0x00286102, "Applicable Frame Range", "US", "2-2n", 0, 0},
    { 0x00286110, "Mask Frame Numbers", "US", "1-n", 0, 0},
    { 0x00286112, "Contrast Frame Averaging", "US", "1", 0, 0},
    { 0x00286114, "Mask Sub-pixel Shift", "FL", "2", 0, 0},
    { 0x00286120, "TID Offset", "SS", "1", 0, 0},
    { 0x00286190, "Mask Operation Explanation", "ST", "1", 0, 0},
    { 0x00287FE0, "Pixel Data Provider URL", "UT", "1", 0, 0},
    { 0x00289001, "Data Point Rows", "UL", "1", 0, 0},
    { 0x00289002, "Data Point Columns", "UL", "1", 0, 0},
    { 0x00289003, "Signal Domain Columns", "CS", "1", 0, 0},
    { 0x00289099, "Largest Monochrome Pixel Value", "US", "1", -1, 0},
    { 0x00289108, "Data Representation", "CS", "1", 0, 0},
    { 0x00289110, "Pixel Measures Sequence", "SQ", "1", 0, 0},
    { 0x00289132, "Frame VOI LUT Sequence", "SQ", "1", 0, 0},
    { 0x00289145, "Pixel Value Transformation Sequence", "SQ", "1", 0, 0},
    { 0x00289235, "Signal Domain Rows", "CS", "1", 0, 0},
    { 0x00289411, "Display Filter Percentage", "FL", "1", 0, 0},
    { 0x00289415, "Frame Pixel Shift Sequence", "SQ", "1", 0, 0},
    { 0x00289416, "Subtraction Item ID", "US", "1", 0, 0},
    { 0x00289422, "Pixel Intensity Relationship LUT Sequence", "SQ", "1", 0, 0},
    { 0x00289443, "Frame Pixel Data Properties Sequence", "SQ", "1", 0, 0},
    { 0x00289444, "Geometrical Properties", "CS", "1", 0, 0},
    { 0x00289445, "Geometric Maximum Distortion", "FL", "1", 0, 0},
    { 0x00289446, "Image Processing Applied", "CS", "1-n", 0, 0},
    { 0x00289454, "Mask Selection Mode", "CS", "1", 0, 0},
    { 0x00289474, "LUT Function", "CS", "1", 0, 0},
    { 0x00289520, "Image to Equipment Mapping Matrix", "DS", "16", 0, 0},
    { 0x00289537, "Equipment Coordinate System Identification", "CS", "1", 0, 0},
    { 0x0032000A, "Study Status ID", "CS", "1", -1, 0},
    { 0x0032000C, "Study Priority ID", "CS", "1", -1, 0},
    { 0x00320012, "Study ID Issuer", "LO", "1", -1, 0},
    { 0x00320032, "Study Verified Date", "DA", "1", -1, 0},
    { 0x00320033, "Study Verified Time", "TM", "1", -1, 0},
    { 0x00320034, "Study Read Date", "DA", "1", -1, 0},
    { 0x00320035, "Study Read Time", "TM", "1", -1, 0},
    { 0x00321000, "Scheduled Study Start Date", "DA", "1", -1, 0},
    { 0x00321001, "Scheduled Study Start Time", "TM", "1", -1, 0},
    { 0x00321010, "Scheduled Study Stop Date", "DA", "1", -1, 0},
    { 0x00321011, "Scheduled Study Stop Time", "TM", "1", -1, 0},
    { 0x00321020, "Scheduled Study Location", "LO", "1", -1, 0},
    { 0x00321021, "Scheduled Study Location AE Title", "AE", "1-n", -1, 0},
    { 0x00321030, "Reason for Study", "LO", "1", -1, 0},
    { 0x00321031, "Requesting Physician Identification Sequence", "SQ", "1", 0, 0},
    { 0x00321032, "Requesting Physician", "PN", "1", 0, 0},
    { 0x00321033, "Requesting Service", "LO", "1", 0, 0},
    { 0x00321040, "Study Arrival Date", "DA", "1", -1, 0},
    { 0x00321041, "Study Arrival Time", "TM", "1", -1, 0},
    { 0x00321050, "Study Completion Date", "DA", "1", -1, 0},
    { 0x00321051, "Study Completion Time", "TM", "1", -1, 0},
    { 0x00321055, "Study Component Status ID", "CS", "1", -1, 0},
    { 0x00321060, "Requested Procedure Description", "LO", "1", 0, 0},
    { 0x00321064, "Requested Procedure Code Sequence", "SQ", "1", 0, 0},
    { 0x00321070, "Requested Contrast Agent", "LO", "1", 0, 0},
    { 0x00324000, "Study Comments", "LT", "1", -1, 0},
    { 0x00380004, "Referenced Patient Alias Sequence", "SQ", "1", 0, 0},
    { 0x00380008, "Visit Status ID", "CS", "1", 0, 0},
    { 0x00380010, "Admission ID", "LO", "1", 0, 0},
    { 0x00380011, "Issuer of Admission ID", "LO", "1", 0, 0},
    { 0x00380016, "Route of Admissions", "LO", "1", 0, 0},
    { 0x0038001A, "Scheduled Admission Date", "DA", "1", -1, 0},
    { 0x0038001B, "Scheduled Admission Time", "TM", "1", -1, 0},
    { 0x0038001C, "Scheduled Discharge Date", "DA", "1", -1, 0},
    { 0x0038001D, "Scheduled Discharge Time", "TM", "1", -1, 0},
    { 0x0038001E, "Scheduled Patient Institution Residence", "LO", "1", -1, 0},
    { 0x00380020, "Admitting Date", "DA", "1", 0, 0},
    { 0x00380021, "Admitting Time", "TM", "1", 0, 0},
    { 0x00380030, "Discharge Date", "DA", "1", -1, 0},
    { 0x00380032, "Discharge Time", "TM", "1", -1, 0},
    { 0x00380040, "Discharge Diagnosis Description", "LO", "1", -1, 0},
    { 0x00380044, "Discharge Diagnosis Code Sequence", "SQ", "1", -1, 0},
    { 0x00380050, "Special Needs", "LO", "1", 0, 0},
    { 0x00380060, "Service Episode ID", "LO", "1", 0, 0},
    { 0x00380061, "Issuer of Service Episode ID", "LO", "1", 0, 0},
    { 0x00380062, "Service Episode Description", "LO", "1", 0, 0},
    { 0x00380100, "Pertinent Documents Sequence", "SQ", "1", 0, 0},
    { 0x00380300, "Current Patient Location", "LO", "1", 0, 0},
    { 0x00380400, "Patient's Institution Residence", "LO", "1", 0, 0},
    { 0x00380500, "Patient State", "LO", "1", 0, 0},
    { 0x00380502, "Patient Clinical Trial Participation Sequence", "SQ", "1", 0, 0},
    { 0x00384000, "Visit Comments", "LT", "1", 0, 0},
    { 0x003A0004, "Waveform Originality", "CS", "1", 0, 0},
    { 0x003A0005, "Number of Waveform Channels", "US", "1", 0, 0},
    { 0x003A0010, "Number of Waveform Samples", "UL", "1", 0, 0},
    { 0x003A001A, "Sampling Frequency", "DS", "1", 0, 0},
    { 0x003A0020, "Multiplex Group Label", "SH", "1", 0, 0},
    { 0x003A0200, "Channel Definition Sequence", "SQ", "1", 0, 0},
    { 0x003A0202, "Waveform Channel Number", "IS", "1", 0, 0},
    { 0x003A0203, "Channel Label", "SH", "1", 0, 0},
    { 0x003A0205, "Channel Status", "CS", "1-n", 0, 0},
    { 0x003A0208, "Channel Source Sequence", "SQ", "1", 0, 0},
    { 0x003A0209, "Channel Source Modifiers Sequence", "SQ", "1", 0, 0},
    { 0x003A020A, "Source Waveform Sequence", "SQ", "1", 0, 0},
    { 0x003A020C, "Channel Derivation Description", "LO", "1", 0, 0},
    { 0x003A0210, "Channel Sensitivity", "DS", "1", 0, 0},
    { 0x003A0211, "Channel Sensitivity Units Sequence", "SQ", "1", 0, 0},
    { 0x003A0212, "Channel Sensitivity Correction Factor", "DS", "1", 0, 0},
    { 0x003A0213, "Channel Baseline", "DS", "1", 0, 0},
    { 0x003A0214, "Channel Time Skew", "DS", "1", 0, 0},
    { 0x003A0215, "Channel Sample Skew", "DS", "1", 0, 0},
    { 0x003A0218, "Channel Offset", "DS", "1", 0, 0},
    { 0x003A021A, "Waveform Bits Stored", "US", "1", 0, 0},
    { 0x003A0220, "Filter Low Frequency", "DS", "1", 0, 0},
    { 0x003A0221, "Filter High Frequency", "DS", "1", 0, 0},
    { 0x003A0222, "Notch Filter Frequency", "DS", "1", 0, 0},
    { 0x003A0223, "Notch Filter Bandwidth", "DS", "1", 0, 0},
    { 0x003A0230, "Waveform Data Display Scale", "FL", "1", 0, 0},
    { 0x003A0231, "Waveform Display Background CIELab Value", "US", "3", 0, 0},
    { 0x003A0240, "Waveform Presentation Group Sequence", "SQ", "1", 0, 0},
    { 0x003A0241, "Presentation Group Number", "US", "1", 0, 0},
    { 0x003A0242, "Channel Display Sequence", "SQ", "1", 0, 0},
    { 0x003A0244, "Channel Recommended Display CIELab Value", "US", "3", 0, 0},
    { 0x003A0245, "Channel Position", "FL", "1", 0, 0},
    { 0x003A0246, "Display Shading Flag", "CS", "1", 0, 0},
    { 0x003A0247, "Fractional Channel Display Scale", "FL", "1", 0, 0},
    { 0x003A0248, "Absolute Channel Display Scale", "FL", "1", 0, 0},
    { 0x003A0300, "Multiplexed Audio Channels Description Code Sequence", "SQ", "1", 0, 0},
    { 0x003A0301, "Channel Identification Code", "IS", "1", 0, 0},
    { 0x003A0302, "Channel Mode", "CS", "1", 0, 0},
    { 0x00400001, "Scheduled Station AE Title", "AE", "1-n", 0, 0},
    { 0x00400002, "Scheduled Procedure Step Start Date", "DA", "1", 0, 0},
    { 0x00400003, "Scheduled Procedure Step Start Time", "TM", "1", 0, 0},
    { 0x00400004, "Scheduled Procedure Step End Date", "DA", "1", 0, 0},
    { 0x00400005, "Scheduled Procedure Step End Time", "TM", "1", 0, 0},
    { 0x00400006, "Scheduled Performing Physician's Name", "PN", "1", 0, 0},
    { 0x00400007, "Scheduled Procedure Step Description", "LO", "1", 0, 0},
    { 0x00400008, "Scheduled Protocol Code Sequence", "SQ", "1", 0, 0},
    { 0x00400009, "Scheduled Procedure Step ID", "SH", "1", 0, 0},
    { 0x0040000A, "Stage Code Sequence", "SQ", "1", 0, 0},
    { 0x0040000B, "Scheduled Performing Physician Identification Sequence", "SQ", "1", 0, 0},
    { 0x00400010, "Scheduled Station Name", "SH", "1-n", 0, 0},
    { 0x00400011, "Scheduled Procedure Step Location", "SH", "1", 0, 0},
    { 0x00400012, "Pre-Medication", "LO", "1", 0, 0},
    { 0x00400020, "Scheduled Procedure Step Status", "CS", "1", 0, 0},
    { 0x00400100, "Scheduled Procedure Step Sequence", "SQ", "1", 0, 0},
    { 0x00400220, "Referenced Non-Image Composite SOP Instance Sequence", "SQ", "1", 0, 0},
    { 0x00400241, "Performed Station AE Title", "AE", "1", 0, 0},
    { 0x00400242, "Performed Station Name", "SH", "1", 0, 0},
    { 0x00400243, "Performed Location", "SH", "1", 0, 0},
    { 0x00400244, "Performed Procedure Step Start Date", "DA", "1", 0, 0},
    { 0x00400245, "Performed Procedure Step Start Time", "TM", "1", 0, 0},
    { 0x00400250, "Performed Procedure Step End Date", "DA", "1", 0, 0},
    { 0x00400251, "Performed Procedure Step End Time", "TM", "1", 0, 0},
    { 0x00400252, "Performed Procedure Step Status", "CS", "1", 0, 0},
    { 0x00400253, "Performed Procedure Step ID", "SH", "1", 0, 0},
    { 0x00400254, "Performed Procedure Step Description", "LO", "1", 0, 0},
    { 0x00400255, "Performed Procedure Type Description", "LO", "1", 0, 0},
    { 0x00400260, "Performed Protocol Code Sequence", "SQ", "1", 0, 0},
    { 0x00400270, "Scheduled Step Attributes Sequence", "SQ", "1", 0, 0},
    { 0x00400275, "Request Attributes Sequence", "SQ", "1", 0, 0},
    { 0x00400280, "Comments on the Performed Procedure Step", "ST", "1", 0, 0},
    { 0x00400281, "Performed Procedure Step Discontinuation Reason Code Sequence", "SQ", "1", 0, 0},
    { 0x00400293, "Quantity Sequence", "SQ", "1", 0, 0},
    { 0x00400294, "Quantity", "DS", "1", 0, 0},
    { 0x00400295, "Measuring Units Sequence", "SQ", "1", 0, 0},
    { 0x00400296, "Billing Item Sequence", "SQ", "1", 0, 0},
    { 0x00400300, "Total Time of Fluoroscopy", "US", "1", 0, 0},
    { 0x00400301, "Total Number of Exposures", "US", "1", 0, 0},
    { 0x00400302, "Entrance Dose", "US", "1", 0, 0},
    { 0x00400303, "Exposed Area", "US", "1-2", 0, 0},
    { 0x00400306, "Distance Source to Entrance", "DS", "1", 0, 0},
    { 0x00400307, "Distance Source to Support", "DS", "1", -1, 0},
    { 0x0040030E, "Exposure Dose Sequence", "SQ", "1", 0, 0},
    { 0x00400310, "Comments on Radiation Dose", "ST", "1", 0, 0},
    { 0x00400312, "X-Ray Output", "DS", "1", 0, 0},
    { 0x00400314, "Half Value Layer", "DS", "1", 0, 0},
    { 0x00400316, "Organ Dose", "DS", "1", 0, 0},
    { 0x00400318, "Organ Exposed", "CS", "1", 0, 0},
    { 0x00400320, "Billing Procedure Step Sequence", "SQ", "1", 0, 0},
    { 0x00400321, "Film Consumption Sequence", "SQ", "1", 0, 0},
    { 0x00400324, "Billing Supplies and Devices Sequence", "SQ", "1", 0, 0},
    { 0x00400330, "Referenced Procedure Step Sequence", "SQ", "1", -1, 0},
    { 0x00400340, "Performed Series Sequence", "SQ", "1", 0, 0},
    { 0x00400400, "Comments on the Scheduled Procedure Step", "LT", "1", 0, 0},
    { 0x00400440, "Protocol Context Sequence", "SQ", "1", 0, 0},
    { 0x00400441, "Content Item Modifier Sequence", "SQ", "1", 0, 0},
    { 0x0040050A, "Specimen Accession Number", "LO", "1", 0, 0},
    { 0x00400550, "Specimen Sequence", "SQ", "1", 0, 0},
    { 0x00400551, "Specimen Identifier", "LO", "1", 0, 0},
    { 0x00400552, "Specimen Description Sequence - Trial", "SQ", "1", -1, 0},
    { 0x00400553, "Specimen Description - Trial", "ST", "1", -1, 0},
    { 0x00400555, "Acquisition Context Sequence", "SQ", "1", 0, 0},
    { 0x00400556, "Acquisition Context Description", "ST", "1", 0, 0},
    { 0x0040059A, "Specimen Type Code Sequence", "SQ", "1", 0, 0},
    { 0x004006FA, "Slide Identifier", "LO", "1", 0, 0},
    { 0x0040071A, "Image Center Point Coordinates Sequence", "SQ", "1", 0, 0},
    { 0x0040072A, "X offset in Slide Coordinate System", "DS", "1", 0, 0},
    { 0x0040073A, "Y offset in Slide Coordinate System", "DS", "1", 0, 0},
    { 0x0040074A, "Z offset in Slide Coordinate System", "DS", "1", 0, 0},
    { 0x004008D8, "Pixel Spacing Sequence", "SQ", "1", 0, 0},
    { 0x004008DA, "Coordinate System Axis Code Sequence", "SQ", "1", 0, 0},
    { 0x004008EA, "Measurement Units Code Sequence", "SQ", "1", 0, 0},
    { 0x004009F8, "Vital Stain Code Sequence - Trial", "SQ", "1", -1, 0},
    { 0x00401001, "Requested Procedure ID", "SH", "1", 0, 0},
    { 0x00401002, "Reason for the Requested Procedure", "LO", "1", 0, 0},
    { 0x00401003, "Requested Procedure Priority", "SH", "1", 0, 0},
    { 0x00401004, "Patient Transport Arrangements", "LO", "1", 0, 0},
    { 0x00401005, "Requested Procedure Location", "LO", "1", 0, 0},
    { 0x00401006, "Placer Order Number / Procedure", "SH", "1", -1, 0},
    { 0x00401007, "Filler Order Number / Procedure", "SH", "1", -1, 0},
    { 0x00401008, "Confidentiality Code", "LO", "1", 0, 0},
    { 0x00401009, "Reporting Priority", "SH", "1", 0, 0},
    { 0x0040100A, "Reason for Requested Procedure Code Sequence", "SQ", "1", 0, 0},
    { 0x00401010, "Names of Intended Recipients of Results", "PN", "1-n", 0, 0},
    { 0x00401011, "Intended Recipients of Results Identification Sequence", "SQ", "1", 0, 0},
    { 0x00401101, "Person Identification Code Sequence", "SQ", "1", 0, 0},
    { 0x00401102, "Person's Address", "ST", "1", 0, 0},
    { 0x00401103, "Person's Telephone Numbers", "LO", "1-n", 0, 0},
    { 0x00401400, "Requested Procedure Comments", "LT", "1", 0, 0},
    { 0x00402001, "Reason for the Imaging Service Request", "LO", "1", -1, 0},
    { 0x00402004, "Issue Date of Imaging Service Request", "DA", "1", 0, 0},
    { 0x00402005, "Issue Time of Imaging Service Request", "TM", "1", 0, 0},
    { 0x00402006, "Placer Order Number / Imaging Service Request (Retired)", "SH", "1", -1, 0},
    { 0x00402007, "Filler Order Number / Imaging Service Request (Retired)", "SH", "1", -1, 0},
    { 0x00402008, "Order Entered By", "PN", "1", 0, 0},
    { 0x00402009, "Order Enterer's Location", "SH", "1", 0, 0},
    { 0x00402010, "Order Callback Phone Number", "SH", "1", 0, 0},
    { 0x00402016, "Placer Order Number / Imaging Service Request", "LO", "1", 0, 0},
    { 0x00402017, "Filler Order Number / Imaging Service Request", "LO", "1", 0, 0},
    { 0x00402400, "Imaging Service Request Comments", "LT", "1", 0, 0},
    { 0x00403001, "Confidentiality Constraint on Patient Data Description", "LO", "1", 0, 0},
    { 0x00404001, "General Purpose Scheduled Procedure Step Status", "CS", "1", 0, 0},
    { 0x00404002, "General Purpose Performed Procedure Step Status", "CS", "1", 0, 0},
    { 0x00404003, "General Purpose Scheduled Procedure Step Priority", "CS", "1", 0, 0},
    { 0x00404004, "Scheduled Processing Applications Code Sequence", "SQ", "1", 0, 0},
    { 0x00404005, "Scheduled Procedure Step Start Date and Time", "DT", "1", 0, 0},
    { 0x00404006, "Multiple Copies Flag", "CS", "1", 0, 0},
    { 0x00404007, "Performed Processing Applications Code Sequence", "SQ", "1", 0, 0},
    { 0x00404009, "Human Performer Code Sequence", "SQ", "1", 0, 0},
    { 0x00404010, "Scheduled Procedure Step Modification Date and Time", "DT", "1", 0, 0},
    { 0x00404011, "Expected Completion Date and Time", "DT", "1", 0, 0},
    { 0x00404015, "Resulting General Purpose Performed Procedure Steps Sequence", "SQ", "1", 0, 0},
    { 0x00404016, "Referenced General Purpose Scheduled Procedure Step Sequence", "SQ", "1", 0, 0},
    { 0x00404018, "Scheduled Workitem Code Sequence", "SQ", "1", 0, 0},
    { 0x00404019, "Performed Workitem Code Sequence", "SQ", "1", 0, 0},
    { 0x00404020, "Input Availability Flag", "CS", "1", 0, 0},
    { 0x00404021, "Input Information Sequence", "SQ", "1", 0, 0},
    { 0x00404022, "Relevant Information Sequence", "SQ", "1", 0, 0},
    { 0x00404023, "Referenced General Purpose Scheduled Procedure Step Transaction UID", "UI", "1", 0, 0},
    { 0x00404025, "Scheduled Station Name Code Sequence", "SQ", "1", 0, 0},
    { 0x00404026, "Scheduled Station Class Code Sequence", "SQ", "1", 0, 0},
    { 0x00404027, "Scheduled Station Geographic Location Code Sequence", "SQ", "1", 0, 0},
    { 0x00404028, "Performed Station Name Code Sequence", "SQ", "1", 0, 0},
    { 0x00404029, "Performed Station Class Code Sequence", "SQ", "1", 0, 0},
    { 0x00404030, "Performed Station Geographic Location Code Sequence", "SQ", "1", 0, 0},
    { 0x00404031, "Requested Subsequent Workitem Code Sequence", "SQ", "1", 0, 0},
    { 0x00404032, "Non-DICOM Output Code Sequence", "SQ", "1", 0, 0},
    { 0x00404033, "Output Information Sequence", "SQ", "1", 0, 0},
    { 0x00404034, "Scheduled Human Performers Sequence", "SQ", "1", 0, 0},
    { 0x00404035, "Actual Human Performers Sequence", "SQ", "1", 0, 0},
    { 0x00404036, "Human Performer's Organization", "LO", "1", 0, 0},
    { 0x00404037, "Human Performer's Name", "PN", "1", 0, 0},
    { 0x00408302, "Entrance Dose in mGy", "DS", "1", 0, 0},
    { 0x00409094, "Referenced Image Real World Value Mapping Sequence", "SQ", "1", 0, 0},
    { 0x00409096, "Real World Value Mapping Sequence", "SQ", "1", 0, 0},
    { 0x00409098, "Pixel Value Mapping Code Sequence", "SQ", "1", 0, 0},
    { 0x00409210, "LUT Label", "SH", "1", 0, 0},
    { 0x00409211, "Real World Value Last Value Mapped", "US or SS", "1", 0, 0},
    { 0x00409212, "Real World Value LUT Data", "FD", "1-n", 0, 0},
    { 0x00409216, "Real World Value First Value Mapped", "US or SS", "1", 0, 0},
    { 0x00409224, "Real World Value Intercept", "FD", "1", 0, 0},
    { 0x00409225, "Real World Value Slope", "FD", "1", 0, 0},
    { 0x0040A010, "Relationship Type", "CS", "1", 0, 0},
    { 0x0040A027, "Verifying Organization", "LO", "1", 0, 0},
    { 0x0040A030, "Verification Date Time", "DT", "1", 0, 0},
    { 0x0040A032, "Observation Date Time", "DT", "1", 0, 0},
    { 0x0040A040, "Value Type", "CS", "1", 0, 0},
    { 0x0040A043, "Concept Name Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A050, "Continuity Of Content", "CS", "1", 0, 0},
    { 0x0040A073, "Verifying Observer Sequence", "SQ", "1", 0, 0},
    { 0x0040A075, "Verifying Observer Name", "PN", "1", 0, 0},
    { 0x0040A078, "Author Observer Sequence", "SQ", "1", 0, 0},
    { 0x0040A07A, "Participant Sequence", "SQ", "1", 0, 0},
    { 0x0040A07C, "Custodial Organization Sequence", "SQ", "1", 0, 0},
    { 0x0040A080, "Participation Type", "CS", "1", 0, 0},
    { 0x0040A082, "Participation DateTime", "DT", "1", 0, 0},
    { 0x0040A084, "Observer Type", "CS", "1", 0, 0},
    { 0x0040A088, "Verifying Observer Identification Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A090, "Equivalent CDA Document Sequence", "SQ", "1", -1, 0},
    { 0x0040A0B0, "Referenced Waveform Channels", "US", "2-2n", 0, 0},
    { 0x0040A120, "DateTime", "DT", "1", 0, 0},
    { 0x0040A121, "Date", "DA", "1", 0, 0},
    { 0x0040A122, "Time", "TM", "1", 0, 0},
    { 0x0040A123, "Person Name", "PN", "1", 0, 0},
    { 0x0040A124, "UID", "UI", "1", 0, 0},
    { 0x0040A130, "Temporal Range Type", "CS", "1", 0, 0},
    { 0x0040A132, "Referenced Sample Positions", "UL", "1-n", 0, 0},
    { 0x0040A136, "Referenced Frame Numbers", "US", "1-n", 0, 0},
    { 0x0040A138, "Referenced Time Offsets", "DS", "1-n", 0, 0},
    { 0x0040A13A, "Referenced DateTime", "DT", "1-n", 0, 0},
    { 0x0040A160, "Text Value", "UT", "1", 0, 0},
    { 0x0040A168, "Concept Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A170, "Purpose of Reference Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A180, "Annotation Group Number", "US", "1", 0, 0},
    { 0x0040A195, "Modifier Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A300, "Measured Value Sequence", "SQ", "1", 0, 0},
    { 0x0040A301, "Numeric Value Qualifier Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A30A, "Numeric Value", "DS", "1-n", 0, 0},
    { 0x0040A353, "Address - Trial", "ST", "1", -1, 0},
    { 0x0040A354, "Telephone Number - Trial", "LO", "1", -1, 0},
    { 0x0040A360, "Predecessor Documents Sequence", "SQ", "1", 0, 0},
    { 0x0040A370, "Referenced Request Sequence", "SQ", "1", 0, 0},
    { 0x0040A372, "Performed Procedure Code Sequence", "SQ", "1", 0, 0},
    { 0x0040A375, "Current Requested Procedure Evidence Sequence", "SQ", "1", 0, 0},
    { 0x0040A385, "Pertinent Other Evidence Sequence", "SQ", "1", 0, 0},
    { 0x0040A390, "HL7 Structured Document Reference Sequence", "SQ", "1", 0, 0},
    { 0x0040A491, "Completion Flag", "CS", "1", 0, 0},
    { 0x0040A492, "Completion Flag Description", "LO", "1", 0, 0},
    { 0x0040A493, "Verification Flag", "CS", "1", 0, 0},
    { 0x0040A494, "Archive Requested", "CS", "1", 0, 0},
    { 0x0040A504, "Content Template Sequence", "SQ", "1", 0, 0},
    { 0x0040A525, "Identical Documents Sequence", "SQ", "1", 0, 0},
    { 0x0040A730, "Content Sequence", "SQ", "1", 0, 0},
    { 0x0040B020, "Annotation Sequence", "SQ", "1", 0, 0},
    { 0x0040DB00, "Template Identifier", "CS", "1", 0, 0},
    { 0x0040DB06, "Template Version", "DT", "1", -1, 0},
    { 0x0040DB07, "Template Local Version", "DT", "1", -1, 0},
    { 0x0040DB0B, "Template Extension Flag", "CS", "1", -1, 0},
    { 0x0040DB0C, "Template Extension Organization UID", "UI", "1", -1, 0},
    { 0x0040DB0D, "Template Extension Creator UID", "UI", "1", -1, 0},
    { 0x0040DB73, "Referenced Content Item Identifier", "UL", "1-n", 0, 0},
    { 0x0040E001, "HL7 Instance Identifier", "ST", "1", 0, 0},
    { 0x0040E004, "HL7 Document Effective Time", "DT", "1", 0, 0},
    { 0x0040E006, "HL7 Document Type Code Sequence", "SQ", "1", 0, 0},
    { 0x0040E010, "Retrieve URI", "UT", "1", 0, 0},
    { 0x00420010, "Document Title", "ST", "1", 0, 0},
    { 0x00420011, "Encapsulated Document", "OB", "1", 0, 0},
    { 0x00420012, "MIME Type of Encapsulated Document", "LO", "1", 0, 0},
    { 0x00420013, "Source Instance Sequence", "SQ", "1", 0, 0},
    { 0x00420014, "List of MIME Types", "LO", "1-n", 0, 0},
    { 0x00440001, "Product Package Identifier", "ST", "1", 0, 0},
    { 0x00440002, "Substance Administration Approval", "CS", "1", 0, 0},
    { 0x00440003, "Approval Status Further Description", "LT", "1", 0, 0},
    { 0x00440004, "Approval Status DateTime", "DT", "1", 0, 0},
    { 0x00440007, "Product Type Code Sequence", "SQ", "1", 0, 0},
    { 0x00440008, "Product Name", "LO", "1-n", 0, 0},
    { 0x00440009, "Product Description", "LT", "1", 0, 0},
    { 0x0044000A, "Product Lot Identifier", "LO", "1", 0, 0},
    { 0x0044000B, "Product Expiration DateTime", "DT", "1", 0, 0},
    { 0x00440010, "Substance Administration DateTime", "DT", "1", 0, 0},
    { 0x00440011, "Substance Administration Notes", "LO", "1", 0, 0},
    { 0x00440012, "Substance Administration Device ID", "LO", "1", 0, 0},
    { 0x00440013, "Product Parameter Sequence", "SQ", "1", 0, 0},
    { 0x00440019, "Substance Administration Parameter Sequence", "SQ", "1", 0, 0},
    { 0x00500004, "Calibration Image", "CS", "1", 0, 0},
    { 0x00500010, "Device Sequence", "SQ", "1", 0, 0},
    { 0x00500014, "Device Length", "DS", "1", 0, 0},
    { 0x00500016, "Device Diameter", "DS", "1", 0, 0},
    { 0x00500017, "Device Diameter Units", "CS", "1", 0, 0},
    { 0x00500018, "Device Volume", "DS", "1", 0, 0},
    { 0x00500019, "Intermarker Distance", "DS", "1", 0, 0},
    { 0x00500020, "Device Description", "LO", "1", 0, 0},
    { 0x00540010, "Energy Window Vector", "US", "1-n", 0, 0},
    { 0x00540011, "Number of Energy Windows", "US", "1", 0, 0},
    { 0x00540012, "Energy Window Information Sequence", "SQ", "1", 0, 0},
    { 0x00540013, "Energy Window Range Sequence", "SQ", "1", 0, 0},
    { 0x00540014, "Energy Window Lower Limit", "DS", "1", 0, 0},
    { 0x00540015, "Energy Window Upper Limit", "DS", "1", 0, 0},
    { 0x00540016, "Radiopharmaceutical Information Sequence", "SQ", "1", 0, 0},
    { 0x00540017, "Residual Syringe Counts", "IS", "1", 0, 0},
    { 0x00540018, "Energy Window Name", "SH", "1", 0, 0},
    { 0x00540020, "Detector Vector", "US", "1-n", 0, 0},
    { 0x00540021, "Number of Detectors", "US", "1", 0, 0},
    { 0x00540022, "Detector Information Sequence", "SQ", "1", 0, 0},
    { 0x00540030, "Phase Vector", "US", "1-n", 0, 0},
    { 0x00540031, "Number of Phases", "US", "1", 0, 0},
    { 0x00540032, "Phase Information Sequence", "SQ", "1", 0, 0},
    { 0x00540033, "Number of Frames in Phase", "US", "1", 0, 0},
    { 0x00540036, "Phase Delay", "IS", "1", 0, 0},
    { 0x00540038, "Pause Between Frames", "IS", "1", 0, 0},
    { 0x00540039, "Phase Description", "CS", "1", 0, 0},
    { 0x00540050, "Rotation Vector", "US", "1-n", 0, 0},
    { 0x00540051, "Number of Rotations", "US", "1", 0, 0},
    { 0x00540052, "Rotation Information Sequence", "SQ", "1", 0, 0},
    { 0x00540053, "Number of Frames in Rotation", "US", "1", 0, 0},
    { 0x00540060, "R-R Interval Vector", "US", "1-n", 0, 0},
    { 0x00540061, "Number of R-R Intervals", "US", "1", 0, 0},
    { 0x00540062, "Gated Information Sequence", "SQ", "1", 0, 0},
    { 0x00540063, "Data Information Sequence", "SQ", "1", 0, 0},
    { 0x00540070, "Time Slot Vector", "US", "1-n", 0, 0},
    { 0x00540071, "Number of Time Slots", "US", "1", 0, 0},
    { 0x00540072, "Time Slot Information Sequence", "SQ", "1", 0, 0},
    { 0x00540073, "Time Slot Time", "DS", "1", 0, 0},
    { 0x00540080, "Slice Vector", "US", "1-n", 0, 0},
    { 0x00540081, "Number of Slices", "US", "1", 0, 0},
    { 0x00540090, "Angular View Vector", "US", "1-n", 0, 0},
    { 0x00540100, "Time Slice Vector", "US", "1-n", 0, 0},
    { 0x00540101, "Number of Time Slices", "US", "1", 0, 0},
    { 0x00540200, "Start Angle", "DS", "1", 0, 0},
    { 0x00540202, "Type of Detector Motion", "CS", "1", 0, 0},
    { 0x00540210, "Trigger Vector", "IS", "1-n", 0, 0},
    { 0x00540211, "Number of Triggers in Phase", "US", "1", 0, 0},
    { 0x00540220, "View Code Sequence", "SQ", "1", 0, 0},
    { 0x00540222, "View Modifier Code Sequence", "SQ", "1", 0, 0},
    { 0x00540300, "Radionuclide Code Sequence", "SQ", "1", 0, 0},
    { 0x00540302, "Administration Route Code Sequence", "SQ", "1", 0, 0},
    { 0x00540304, "Radiopharmaceutical Code Sequence", "SQ", "1", 0, 0},
    { 0x00540306, "Calibration Data Sequence", "SQ", "1", 0, 0},
    { 0x00540308, "Energy Window Number", "US", "1", 0, 0},
    { 0x00540400, "Image ID", "SH", "1", 0, 0},
    { 0x00540410, "Patient Orientation Code Sequence", "SQ", "1", 0, 0},
    { 0x00540412, "Patient Orientation Modifier Code Sequence", "SQ", "1", 0, 0},
    { 0x00540414, "Patient Gantry Relationship Code Sequence", "SQ", "1", 0, 0},
    { 0x00540500, "Slice Progression Direction", "CS", "1", 0, 0},
    { 0x00541000, "Series Type", "CS", "2", 0, 0},
    { 0x00541001, "Units", "CS", "1", 0, 0},
    { 0x00541002, "Counts Source", "CS", "1", 0, 0},
    { 0x00541004, "Reprojection Method", "CS", "1", 0, 0},
    { 0x00541100, "Randoms Correction Method", "CS", "1", 0, 0},
    { 0x00541101, "Attenuation Correction Method", "LO", "1", 0, 0},
    { 0x00541102, "Decay Correction", "CS", "1", 0, 0},
    { 0x00541103, "Reconstruction Method", "LO", "1", 0, 0},
    { 0x00541104, "Detector Lines of Response Used", "LO", "1", 0, 0},
    { 0x00541105, "Scatter Correction Method", "LO", "1", 0, 0},
    { 0x00541200, "Axial Acceptance", "DS", "1", 0, 0},
    { 0x00541201, "Axial Mash", "IS", "2", 0, 0},
    { 0x00541202, "Transverse Mash", "IS", "1", 0, 0},
    { 0x00541203, "Detector Element Size", "DS", "2", 0, 0},
    { 0x00541210, "Coincidence Window Width", "DS", "1", 0, 0},
    { 0x00541220, "Secondary Counts Type", "CS", "1-n", 0, 0},
    { 0x00541300, "Frame Reference Time", "DS", "1", 0, 0},
    { 0x00541310, "Primary (Prompts) Counts Accumulated", "IS", "1", 0, 0},
    { 0x00541311, "Secondary Counts Accumulated", "IS", "1-n", 0, 0},
    { 0x00541320, "Slice Sensitivity Factor", "DS", "1", 0, 0},
    { 0x00541321, "Decay Factor", "DS", "1", 0, 0},
    { 0x00541322, "Dose Calibration Factor", "DS", "1", 0, 0},
    { 0x00541323, "Scatter Fraction Factor", "DS", "1", 0, 0},
    { 0x00541324, "Dead Time Factor", "DS", "1", 0, 0},
    { 0x00541330, "Image Index", "US", "1", 0, 0},
    { 0x00541400, "Counts Included", "CS", "1-n", -1, 0},
    { 0x00541401, "Dead Time Correction Flag", "CS", "1", -1, 0},
    { 0x00603000, "Histogram Sequence", "SQ", "1", 0, 0},
    { 0x00603002, "Histogram Number of Bins", "US", "1", 0, 0},
    { 0x00603004, "Histogram First Bin Value", "US or SS", "1", 0, 0},
    { 0x00603006, "Histogram Last Bin Value", "US or SS", "1", 0, 0},
    { 0x00603008, "Histogram Bin Width", "US", "1", 0, 0},
    { 0x00603010, "Histogram Explanation", "LO", "1", 0, 0},
    { 0x00603020, "Histogram Data", "UL", "1-n", 0, 0},
    { 0x00620001, "Segmentation Type", "CS", "1", 0, 0},
    { 0x00620002, "Segment Sequence", "SQ", "1", 0, 0},
    { 0x00620003, "Segmented Property Category Code Sequence", "SQ", "1", 0, 0},
    { 0x00620004, "Segment Number", "US", "1", 0, 0},
    { 0x00620005, "Segment Label", "LO", "1", 0, 0},
    { 0x00620006, "Segment Description", "ST", "1", 0, 0},
    { 0x00620008, "Segment Algorithm Type", "CS", "1", 0, 0},
    { 0x00620009, "Segment Algorithm Name", "LO", "1", 0, 0},
    { 0x0062000A, "Segment Identification Sequence", "SQ", "1", 0, 0},
    { 0x0062000B, "Referenced Segment Number", "US", "1-n", 0, 0},
    { 0x0062000C, "Recommended Display Grayscale Value", "US", "1", 0, 0},
    { 0x0062000D, "Recommended Display CIELab Value", "US", "3", 0, 0},
    { 0x0062000E, "Maximum Fractional Value", "US", "1", 0, 0},
    { 0x0062000F, "Segmented Property Type Code Sequence", "SQ", "1", 0, 0},
    { 0x00620010, "Segmentation Fractional Type", "CS", "1", 0, 0},
    { 0x00640002, "Deformable Registration Sequence", "SQ", "1", 0, 0},
    { 0x00640003, "Source Frame of Reference UID", "UI", "1", 0, 0},
    { 0x00640005, "Deformable Registration Grid Sequence", "SQ", "1", 0, 0},
    { 0x00640007, "Grid Dimensions", "UL", "3", 0, 0},
    { 0x00640008, "Grid Resolution", "FD", "3", 0, 0},
    { 0x00640009, "Vector Grid Data", "OF", "1", 0, 0},
    { 0x0064000F, "Pre Deformation Matrix Registration Sequence", "SQ", "1", 0, 0},
    { 0x00640010, "Post Deformation Matrix Registration Sequence", "SQ", "1", 0, 0},
    { 0x00700001, "Graphic Annotation Sequence", "SQ", "1", 0, 0},
    { 0x00700002, "Graphic Layer", "CS", "1", 0, 0},
    { 0x00700003, "Bounding Box Annotation Units", "CS", "1", 0, 0},
    { 0x00700004, "Anchor Point Annotation Units", "CS", "1", 0, 0},
    { 0x00700005, "Graphic Annotation Units", "CS", "1", 0, 0},
    { 0x00700006, "Unformatted Text Value", "ST", "1", 0, 0},
    { 0x00700008, "Text Object Sequence", "SQ", "1", 0, 0},
    { 0x00700009, "Graphic Object Sequence", "SQ", "1", 0, 0},
    { 0x00700010, "Bounding Box Top Left Hand Corner", "FL", "2", 0, 0},
    { 0x00700011, "Bounding Box Bottom Right Hand Corner", "FL", "2", 0, 0},
    { 0x00700012, "Bounding Box Text Horizontal Justification", "CS", "1", 0, 0},
    { 0x00700014, "Anchor Point", "FL", "2", 0, 0},
    { 0x00700015, "Anchor Point Visibility", "CS", "1", 0, 0},
    { 0x00700020, "Graphic Dimensions", "US", "1", 0, 0},
    { 0x00700021, "Number of Graphic Points", "US", "1", 0, 0},
    { 0x00700022, "Graphic Data", "FL", "2-n", 0, 0},
    { 0x00700023, "Graphic Type", "CS", "1", 0, 0},
    { 0x00700024, "Graphic Filled", "CS", "1", 0, 0},
    { 0x00700040, "Image Rotation (Retired)", "IS", "1", -1, 0},
    { 0x00700041, "Image Horizontal Flip", "CS", "1", 0, 0},
    { 0x00700042, "Image Rotation", "US", "1", 0, 0},
    { 0x00700050, "Displayed Area Top Left Hand Corner (Trial)", "US", "2", -1, 0},
    { 0x00700051, "Displayed Area Bottom Right Hand Corner (Trial)", "US", "2", -1, 0},
    { 0x00700052, "Displayed Area Top Left Hand Corner", "SL", "2", 0, 0},
    { 0x00700053, "Displayed Area Bottom Right Hand Corner", "SL", "2", 0, 0},
    { 0x0070005A, "Displayed Area Selection Sequence", "SQ", "1", 0, 0},
    { 0x00700060, "Graphic Layer Sequence", "SQ", "1", 0, 0},
    { 0x00700062, "Graphic Layer Order", "IS", "1", 0, 0},
    { 0x00700066, "Graphic Layer Recommended Display Grayscale Value", "US", "1", 0, 0},
    { 0x00700067, "Graphic Layer Recommended Display RGB Value", "US", "3", -1, 0},
    { 0x00700068, "Graphic Layer Description", "LO", "1", 0, 0},
    { 0x00700080, "Content Label", "CS", "1", 0, 0},
    { 0x00700081, "Content Description", "LO", "1", 0, 0},
    { 0x00700082, "Presentation Creation Date", "DA", "1", 0, 0},
    { 0x00700083, "Presentation Creation Time", "TM", "1", 0, 0},
    { 0x00700084, "Content Creator's Name", "PN", "1", 0, 0},
    { 0x00700086, "Content Creator's Identification Code Sequence", "SQ", "1", 0, 0},
    { 0x00700100, "Presentation Size Mode", "CS", "1", 0, 0},
    { 0x00700101, "Presentation Pixel Spacing", "DS", "2", 0, 0},
    { 0x00700102, "Presentation Pixel Aspect Ratio", "IS", "2", 0, 0},
    { 0x00700103, "Presentation Pixel Magnification Ratio", "FL", "1", 0, 0},
    { 0x00700306, "Shape Type", "CS", "1", 0, 0},
    { 0x00700308, "Registration Sequence", "SQ", "1", 0, 0},
    { 0x00700309, "Matrix Registration Sequence", "SQ", "1", 0, 0},
    { 0x0070030A, "Matrix Sequence", "SQ", "1", 0, 0},
    { 0x0070030C, "Frame of Reference Transformation Matrix Type", "CS", "1", 0, 0},
    { 0x0070030D, "Registration Type Code Sequence", "SQ", "1", 0, 0},
    { 0x0070030F, "Fiducial Description", "ST", "1", 0, 0},
    { 0x00700310, "Fiducial Identifier", "SH", "1", 0, 0},
    { 0x00700311, "Fiducial Identifier Code Sequence", "SQ", "1", 0, 0},
    { 0x00700312, "Contour Uncertainty Radius", "FD", "1", 0, 0},
    { 0x00700314, "Used Fiducials Sequence", "SQ", "1", 0, 0},
    { 0x00700318, "Graphic Coordinates Data Sequence", "SQ", "1", 0, 0},
    { 0x0070031A, "Fiducial UID", "UI", "1", 0, 0},
    { 0x0070031C, "Fiducial Set Sequence", "SQ", "1", 0, 0},
    { 0x0070031E, "Fiducial Sequence", "SQ", "1", 0, 0},
    { 0x00700401, "Graphic Layer Recommended Display CIELab Value", "US", "3", 0, 0},
    { 0x00700402, "Blending Sequence", "SQ", "1", 0, 0},
    { 0x00700403, "Relative Opacity", "FL", "1", 0, 0},
    { 0x00700404, "Referenced Spatial Registration Sequence", "SQ", "1", 0, 0},
    { 0x00700405, "Blending Position", "CS", "1", 0, 0},
    { 0x00720002, "Hanging Protocol Name", "SH", "1", 0, 0},
    { 0x00720004, "Hanging Protocol Description", "LO", "1", 0, 0},
    { 0x00720006, "Hanging Protocol Level", "CS", "1", 0, 0},
    { 0x00720008, "Hanging Protocol Creator", "LO", "1", 0, 0},
    { 0x0072000A, "Hanging Protocol Creation DateTime", "DT", "1", 0, 0},
    { 0x0072000C, "Hanging Protocol Definition Sequence", "SQ", "1", 0, 0},
    { 0x0072000E, "Hanging Protocol User Identification Code Sequence", "SQ", "1", 0, 0},
    { 0x00720010, "Hanging Protocol User Group Name", "LO", "1", 0, 0},
    { 0x00720012, "Source Hanging Protocol Sequence", "SQ", "1", 0, 0},
    { 0x00720014, "Number of Priors Referenced", "US", "1", 0, 0},
    { 0x00720020, "Image Sets Sequence", "SQ", "1", 0, 0},
    { 0x00720022, "Image Set Selector Sequence", "SQ", "1", 0, 0},
    { 0x00720024, "Image Set Selector Usage Flag", "CS", "1", 0, 0},
    { 0x00720026, "Selector Attribute", "AT", "1", 0, 0},
    { 0x00720028, "Selector Value Number", "US", "1", 0, 0},
    { 0x00720030, "Time Based Image Sets Sequence", "SQ", "1", 0, 0},
    { 0x00720032, "Image Set Number", "US", "1", 0, 0},
    { 0x00720034, "Image Set Selector Category", "CS", "1", 0, 0},
    { 0x00720038, "Relative Time", "US", "2", 0, 0},
    { 0x0072003A, "Relative Time Units", "CS", "1", 0, 0},
    { 0x0072003C, "Abstract Prior Value", "SS", "2", 0, 0},
    { 0x0072003E, "Abstract Prior Code Sequence", "SQ", "1", 0, 0},
    { 0x00720040, "Image Set Label", "LO", "1", 0, 0},
    { 0x00720050, "Selector Attribute VR", "CS", "1", 0, 0},
    { 0x00720052, "Selector Sequence Pointer", "AT", "1", 0, 0},
    { 0x00720054, "Selector Sequence Pointer Private Creator", "LO", "1", 0, 0},
    { 0x00720056, "Selector Attribute Private Creator", "LO", "1", 0, 0},
    { 0x00720060, "Selector AT Value", "AT", "1-n", 0, 0},
    { 0x00720062, "Selector CS Value", "CS", "1-n", 0, 0},
    { 0x00720064, "Selector IS Value", "IS", "1-n", 0, 0},
    { 0x00720066, "Selector LO Value", "LO", "1-n", 0, 0},
    { 0x00720068, "Selector LT Value", "LT", "1", 0, 0},
    { 0x0072006A, "Selector PN Value", "PN", "1-n", 0, 0},
    { 0x0072006C, "Selector SH Value", "SH", "1-n", 0, 0},
    { 0x0072006E, "Selector ST Value", "ST", "1", 0, 0},
    { 0x00720070, "Selector UT Value", "UT", "1", 0, 0},
    { 0x00720072, "Selector DS Value", "DS", "1-n", 0, 0},
    { 0x00720074, "Selector FD Value", "FD", "1-n", 0, 0},
    { 0x00720076, "Selector FL Value", "FL", "1-n", 0, 0},
    { 0x00720078, "Selector UL Value", "UL", "1-n", 0, 0},
    { 0x0072007A, "Selector US Value", "US", "1-n", 0, 0},
    { 0x0072007C, "Selector SL Value", "SL", "1-n", 0, 0},
    { 0x0072007E, "Selector SS Value", "SS", "1-n", 0, 0},
    { 0x00720080, "Selector Code Sequence Value", "SQ", "1", 0, 0},
    { 0x00720100, "Number of Screens", "US", "1", 0, 0},
    { 0x00720102, "Nominal Screen Definition Sequence", "SQ", "1", 0, 0},
    { 0x00720104, "Number of Vertical Pixels", "US", "1", 0, 0},
    { 0x00720106, "Number of Horizontal Pixels", "US", "1", 0, 0},
    { 0x00720108, "Display Environment Spatial Position", "FD", "4", 0, 0},
    { 0x0072010A, "Screen Minimum Grayscale Bit Depth", "US", "1", 0, 0},
    { 0x0072010C, "Screen Minimum Color Bit Depth", "US", "1", 0, 0},
    { 0x0072010E, "Application Maximum Repaint Time", "US", "1", 0, 0},
    { 0x00720200, "Display Sets Sequence", "SQ", "1", 0, 0},
    { 0x00720202, "Display Set Number", "US", "1", 0, 0},
    { 0x00720203, "Display Set Label", "LO", "1", 0, 0},
    { 0x00720204, "Display Set Presentation Group", "US", "1", 0, 0},
    { 0x00720206, "Display Set Presentation Group Description", "LO", "1", 0, 0},
    { 0x00720208, "Partial Data Display Handling", "CS", "1", 0, 0},
    { 0x00720210, "Synchronized Scrolling Sequence", "SQ", "1", 0, 0},
    { 0x00720212, "Display Set Scrolling Group", "US", "2-n", 0, 0},
    { 0x00720214, "Navigation Indicator Sequence", "SQ", "1", 0, 0},
    { 0x00720216, "Navigation Display Set", "US", "1", 0, 0},
    { 0x00720218, "Reference Display Sets", "US", "1-n", 0, 0},
    { 0x00720300, "Image Boxes Sequence", "SQ", "1", 0, 0},
    { 0x00720302, "Image Box Number", "US", "1", 0, 0},
    { 0x00720304, "Image Box Layout Type", "CS", "1", 0, 0},
    { 0x00720306, "Image Box Tile Horizontal Dimension", "US", "1", 0, 0},
    { 0x00720308, "Image Box Tile Vertical Dimension", "US", "1", 0, 0},
    { 0x00720310, "Image Box Scroll Direction", "CS", "1", 0, 0},
    { 0x00720312, "Image Box Small Scroll Type", "CS", "1", 0, 0},
    { 0x00720314, "Image Box Small Scroll Amount", "US", "1", 0, 0},
    { 0x00720316, "Image Box Large Scroll Type", "CS", "1", 0, 0},
    { 0x00720318, "Image Box Large Scroll Amount", "US", "1", 0, 0},
    { 0x00720320, "Image Box Overlap Priority", "US", "1", 0, 0},
    { 0x00720330, "Cine Relative to Real-Time", "FD", "1", 0, 0},
    { 0x00720400, "Filter Operations Sequence", "SQ", "1", 0, 0},
    { 0x00720402, "Filter-by Category", "CS", "1", 0, 0},
    { 0x00720404, "Filter-by Attribute Presence", "CS", "1", 0, 0},
    { 0x00720406, "Filter-by Operator", "CS", "1", 0, 0},
    { 0x00720500, "Blending Operation Type", "CS", "1", 0, 0},
    { 0x00720510, "Reformatting Operation Type", "CS", "1", 0, 0},
    { 0x00720512, "Reformatting Thickness", "FD", "1", 0, 0},
    { 0x00720514, "Reformatting Interval", "FD", "1", 0, 0},
    { 0x00720516, "Reformatting Operation Initial View Direction", "CS", "1", 0, 0},
    { 0x00720520, "3D Rendering Type", "CS", "1-n", 0, 0},
    { 0x00720600, "Sorting Operations Sequence", "SQ", "1", 0, 0},
    { 0x00720602, "Sort-by Category", "CS", "1", 0, 0},
    { 0x00720604, "Sorting Direction", "CS", "1", 0, 0},
    { 0x00720700, "Display Set Patient Orientation", "CS", "2", 0, 0},
    { 0x00720702, "VOI Type", "CS", "1", 0, 0},
    { 0x00720704, "Pseudo-color Type", "CS", "1", 0, 0},
    { 0x00720706, "Show Grayscale Inverted", "CS", "1", 0, 0},
    { 0x00720710, "Show Image True Size Flag", "CS", "1", 0, 0},
    { 0x00720712, "Show Graphic Annotation Flag", "CS", "1", 0, 0},
    { 0x00720714, "Show Patient Demographics Flag", "CS", "1", 0, 0},
    { 0x00720716, "Show Acquisition Techniques Flag", "CS", "1", 0, 0},
    { 0x00720717, "Display Set Horizontal Justification", "CS", "1", 0, 0},
    { 0x00720718, "Display Set Vertical Justification", "CS", "1", 0, 0},
    { 0x00741000, "Unified Procedure Step State", "CS", "1", 0, 0},
    { 0x00741002, "UPS Progress Information Sequence", "SQ", "1", 0, 0},
    { 0x00741004, "Unified Procedure Step Progress", "DS", "1", 0, 0},
    { 0x00741006, "Unified Procedure Step Progress Description", "ST", "1", 0, 0},
    { 0x00741008, "Unified Procedure Step Communications URI Sequence", "SQ", "1", 0, 0},
    { 0x0074100a, "Contact URI", "ST", "1", 0, 0},
    { 0x0074100c, "Contact Display Name", "LO", "1", 0, 0},
    { 0x0074100e, "Unified Procedure Step Discontinuation Reason Code Sequence", "SQ", "1", 0, 0},
    { 0x00741020, "Beam Task Sequence", "SQ", "1", 0, 0},
    { 0x00741022, "Beam Task Type", "CS", "1", 0, 0},
    { 0x00741024, "Beam Order Index", "IS", "1", 0, 0},
    { 0x00741030, "Delivery Verification Image Sequence", "SQ", "1", 0, 0},
    { 0x00741032, "Verification Image Timing", "CS", "1", 0, 0},
    { 0x00741034, "Double Exposure Flag", "CS", "1", 0, 0},
    { 0x00741036, "Double Exposure Ordering", "CS", "1", 0, 0},
    { 0x00741038, "Double Exposure Meterset", "DS", "1", 0, 0},
    { 0x0074103A, "Double Exposure Field Delta", "DS", "4", 0, 0},
    { 0x00741040, "Related Reference RT Image Sequence", "SQ", "1", 0, 0},
    { 0x00741042, "General Machine Verification Sequence", "SQ", "1", 0, 0},
    { 0x00741044, "Conventional Machine Verification Sequence", "SQ", "1", 0, 0},
    { 0x00741046, "Ion Machine Verification Sequence", "SQ", "1", 0, 0},
    { 0x00741048, "Failed Attributes Sequence", "SQ", "1-n", 0, 0},
    { 0x0074104A, "Overridden Attributes Sequence", "SQ", "1-n", 0, 0},
    { 0x0074104C, "Conventional Control Point Verification Sequence", "SQ", "1", 0, 0},
    { 0x0074104E, "Ion Control Point Verification Sequence", "SQ", "1", 0, 0},
    { 0x00741050, "Attribute Occurrence Sequence", "SQ", "1-n", 0, 0},
    { 0x00741052, "Attribute Occurrence Pointer", "AT", "1", 0, 0},
    { 0x00741054, "Attribute Item Selector", "UL", "1", 0, 0},
    { 0x00741056, "Attribute Occurrence Private Creator", "LO", "1", 0, 0},
    { 0x00741200, "Scheduled Procedure Step Priority", "CS", "1", 0, 0},
    { 0x00741202, "Worklist Label", "LO", "1", 0, 0},
    { 0x00741204, "Procedure Step Label", "LO", "1", 0, 0},
    { 0x00741210, "Scheduled Processing Parameters Sequence", "SQ", "1", 0, 0},
    { 0x00741212, "Performed Processing Parameters Sequence", "SQ", "1", 0, 0},
    { 0x00741216, "UPS Performed Procedure Sequence", "SQ", "1", 0, 0},
    { 0x00741220, "Related Procedure Step Sequence", "SQ", "1", 0, 0},
    { 0x00741222, "Procedure Step Relationship Type", "LO", "1", 0, 0},
    { 0x00741230, "Deletion Lock", "LO", "1", 0, 0},
    { 0x00741234, "Receiving AE", "AE", "1", 0, 0},
    { 0x00741236, "Requesting AE", "AE", "1", 0, 0},
    { 0x00741238, "Reason for Cancellation", "LT", "1", 0, 0},
    { 0x00741242, "SCP Status", "CS", "1", 0, 0},
    { 0x00741244, "Subscription List Status", "CS", "1", 0, 0},
    { 0x00741246, "UPS List Status", "CS", "1", 0, 0},
    { 0x00880130, "Storage Media File-set ID", "SH", "1", 0, 0},
    { 0x00880140, "Storage Media File-set UID", "UI", "1", 0, 0},
    { 0x00880200, "Icon Image Sequence", "SQ", "1", 0, 0},
    { 0x00880904, "Topic Title", "LO", "1", -1, 0},
    { 0x00880906, "Topic Subject", "ST", "1", -1, 0},
    { 0x00880910, "Topic Author", "LO", "1", -1, 0},
    { 0x00880912, "Topic Keywords", "LO", "1-32", -1, 0},
    { 0x01000410, "SOP Instance Status", "CS", "1", 0, 0},
    { 0x01000420, "SOP Authorization Date and Time", "DT", "1", 0, 0},
    { 0x01000424, "SOP Authorization Comment", "LT", "1", 0, 0},
    { 0x01000426, "Authorization Equipment Certification Number", "LO", "1", 0, 0},
    { 0x04000005, "MAC ID Number", "US", "1", 0, 0},
    { 0x04000010, "MAC Calculation Transfer Syntax UID", "UI", "1", 0, 0},
    { 0x04000015, "MAC Algorithm", "CS", "1", 0, 0},
    { 0x04000020, "Data Elements Signed", "AT", "1-n", 0, 0},
    { 0x04000100, "Digital Signature UID", "UI", "1", 0, 0},
    { 0x04000105, "Digital Signature DateTime", "DT", "1", 0, 0},
    { 0x04000110, "Certificate Type", "CS", "1", 0, 0},
    { 0x04000115, "Certificate of Signer", "OB", "1", 0, 0},
    { 0x04000120, "Signature", "OB", "1", 0, 0},
    { 0x04000305, "Certified Timestamp Type", "CS", "1", 0, 0},
    { 0x04000310, "Certified Timestamp", "OB", "1", 0, 0},
    { 0x04000401, "Digital Signature Purpose Code Sequence", "SQ", "1", 0, 0},
    { 0x04000402, "Referenced Digital Signature Sequence", "SQ", "1", 0, 0},
    { 0x04000403, "Referenced SOP Instance MAC Sequence", "SQ", "1", 0, 0},
    { 0x04000404, "MAC", "OB", "1", 0, 0},
    { 0x04000500, "Encrypted Attributes Sequence", "SQ", "1", 0, 0},
    { 0x04000510, "Encrypted Content Transfer Syntax UID", "UI", "1", 0, 0},
    { 0x04000520, "Encrypted Content", "OB", "1", 0, 0},
    { 0x04000550, "Modified Attributes Sequence", "SQ", "1", 0, 0},
    { 0x04000561, "Original Attributes Sequence", "SQ", "1", 0, 0},
    { 0x04000562, "Attribute Modification DateTime", "DT", "1", 0, 0},
    { 0x04000563, "Modifying System", "LO", "1", 0, 0},
    { 0x04000564, "Source of Previous Values", "LO", "1", 0, 0},
    { 0x04000565, "Reason for the Attribute Modification", "CS", "1", 0, 0},
    { 0x10000000, "Escape Triplet", "US", "3", -1, 0},
    { 0x10000001, "Run Length Triplet", "US", "3", -1, 0},
    { 0x10000002, "Huffman Table Size", "US", "1", -1, 0},
    { 0x10000003, "Huffman Table Triplet", "US", "3", -1, 0},
    { 0x10000004, "Shift Table Size", "US", "1", -1, 0},
    { 0x10000005, "Shift Table Triplet", "US", "3", -1, 0},
    { 0x10100000, "Zonal Map", "US", "1-n", -1, 0},
    { 0x20000010, "Number of Copies", "IS", "1", 0, 0},
    { 0x2000001E, "Printer Configuration Sequence", "SQ", "1", 0, 0},
    { 0x20000020, "Print Priority", "CS", "1", 0, 0},
    { 0x20000030, "Medium Type", "CS", "1", 0, 0},
    { 0x20000040, "Film Destination", "CS", "1", 0, 0},
    { 0x20000050, "Film Session Label", "LO", "1", 0, 0},
    { 0x20000060, "Memory Allocation", "IS", "1", 0, 0},
    { 0x20000061, "Maximum Memory Allocation", "IS", "1", 0, 0},
    { 0x20000062, "Color Image Printing Flag", "CS", "1", -1, 0},
    { 0x20000063, "Collation Flag", "CS", "1", -1, 0},
    { 0x20000065, "Annotation Flag", "CS", "1", -1, 0},
    { 0x20000067, "Image Overlay Flag", "CS", "1", -1, 0},
    { 0x20000069, "Presentation LUT Flag", "CS", "1", -1, 0},
    { 0x2000006A, "Image Box Presentation LUT Flag", "CS", "1", -1, 0},
    { 0x200000A0, "Memory Bit Depth", "US", "1", 0, 0},
    { 0x200000A1, "Printing Bit Depth", "US", "1", 0, 0},
    { 0x200000A2, "Media Installed Sequence", "SQ", "1", 0, 0},
    { 0x200000A4, "Other Media Available Sequence", "SQ", "1", 0, 0},
    { 0x200000A8, "Supported Image Display Formats Sequence", "SQ", "1", 0, 0},
    { 0x20000500, "Referenced Film Box Sequence", "SQ", "1", 0, 0},
    { 0x20000510, "Referenced Stored Print Sequence", "SQ", "1", -1, 0},
    { 0x20100010, "Image Display Format", "ST", "1", 0, 0},
    { 0x20100030, "Annotation Display Format ID", "CS", "1", 0, 0},
    { 0x20100040, "Film Orientation", "CS", "1", 0, 0},
    { 0x20100050, "Film Size ID", "CS", "1", 0, 0},
    { 0x20100052, "Printer Resolution ID", "CS", "1", 0, 0},
    { 0x20100054, "Default Printer Resolution ID", "CS", "1", 0, 0},
    { 0x20100060, "Magnification Type", "CS", "1", 0, 0},
    { 0x20100080, "Smoothing Type", "CS", "1", 0, 0},
    { 0x201000A6, "Default Magnification Type", "CS", "1", 0, 0},
    { 0x201000A7, "Other Magnification Types Available", "CS", "1-n", 0, 0},
    { 0x201000A8, "Default Smoothing Type", "CS", "1", 0, 0},
    { 0x201000A9, "Other Smoothing Types Available", "CS", "1-n", 0, 0},
    { 0x20100100, "Border Density", "CS", "1", 0, 0},
    { 0x20100110, "Empty Image Density", "CS", "1", 0, 0},
    { 0x20100120, "Min Density", "US", "1", 0, 0},
    { 0x20100130, "Max Density", "US", "1", 0, 0},
    { 0x20100140, "Trim", "CS", "1", 0, 0},
    { 0x20100150, "Configuration Information", "ST", "1", 0, 0},
    { 0x20100152, "Configuration Information Description", "LT", "1", 0, 0},
    { 0x20100154, "Maximum Collated Films", "IS", "1", 0, 0},
    { 0x2010015E, "Illumination", "US", "1", 0, 0},
    { 0x20100160, "Reflected Ambient Light", "US", "1", 0, 0},
    { 0x20100376, "Printer Pixel Spacing", "DS", "2", 0, 0},
    { 0x20100500, "Referenced Film Session Sequence", "SQ", "1", 0, 0},
    { 0x20100510, "Referenced Image Box Sequence", "SQ", "1", 0, 0},
    { 0x20100520, "Referenced Basic Annotation Box Sequence", "SQ", "1", 0, 0},
    { 0x20200010, "Image Box Position", "US", "1", 0, 0},
    { 0x20200020, "Polarity", "CS", "1", 0, 0},
    { 0x20200030, "Requested Image Size", "DS", "1", 0, 0},
    { 0x20200040, "Requested Decimate/Crop Behavior", "CS", "1", 0, 0},
    { 0x20200050, "Requested Resolution ID", "CS", "1", 0, 0},
    { 0x202000A0, "Requested Image Size Flag", "CS", "1", 0, 0},
    { 0x202000A2, "Decimate/Crop Result", "CS", "1", 0, 0},
    { 0x20200110, "Basic Grayscale Image Sequence", "SQ", "1", 0, 0},
    { 0x20200111, "Basic Color Image Sequence", "SQ", "1", 0, 0},
    { 0x20200130, "Referenced Image Overlay Box Sequence", "SQ", "1", -1, 0},
    { 0x20200140, "Referenced VOI LUT Box Sequence", "SQ", "1", -1, 0},
    { 0x20300010, "Annotation Position", "US", "1", 0, 0},
    { 0x20300020, "Text String", "LO", "1", 0, 0},
    { 0x20400010, "Referenced Overlay Plane Sequence", "SQ", "1", -1, 0},
    { 0x20400011, "Referenced Overlay Plane Groups", "US", "1-99", -1, 0},
    { 0x20400020, "Overlay Pixel Data Sequence", "SQ", "1", -1, 0},
    { 0x20400060, "Overlay Magnification Type", "CS", "1", -1, 0},
    { 0x20400070, "Overlay Smoothing Type", "CS", "1", -1, 0},
    { 0x20400072, "Overlay or Image Magnification", "CS", "1", -1, 0},
    { 0x20400074, "Magnify to Number of Columns", "US", "1", -1, 0},
    { 0x20400080, "Overlay Foreground Density", "CS", "1", -1, 0},
    { 0x20400082, "Overlay Background Density", "CS", "1", -1, 0},
    { 0x20400090, "Overlay Mode", "CS", "1", -1, 0},
    { 0x20400100, "Threshold Density", "CS", "1", -1, 0},
    { 0x20400500, "Referenced Image Box Sequence (Retired)", "SQ", "1", -1, 0},
    { 0x20500010, "Presentation LUT Sequence", "SQ", "1", 0, 0},
    { 0x20500020, "Presentation LUT Shape", "CS", "1", 0, 0},
    { 0x20500500, "Referenced Presentation LUT Sequence", "SQ", "1", 0, 0},
    { 0x21000010, "Print Job ID", "SH", "1", -1, 0},
    { 0x21000020, "Execution Status", "CS", "1", 0, 0},
    { 0x21000030, "Execution Status Info", "CS", "1", 0, 0},
    { 0x21000040, "Creation Date", "DA", "1", 0, 0},
    { 0x21000050, "Creation Time", "TM", "1", 0, 0},
    { 0x21000070, "Originator", "AE", "1", 0, 0},
    { 0x21000140, "Destination AE", "AE", "1", -1, 0},
    { 0x21000160, "Owner ID", "SH", "1", 0, 0},
    { 0x21000170, "Number of Films", "IS", "1", 0, 0},
    { 0x21000500, "Referenced Print Job Sequence (Pull Stored Print)", "SQ", "1", -1, 0},
    { 0x21100010, "Printer Status", "CS", "1", 0, 0},
    { 0x21100020, "Printer Status Info", "CS", "1", 0, 0},
    { 0x21100030, "Printer Name", "LO", "1", 0, 0},
    { 0x21100099, "Print Queue ID", "SH", "1", -1, 0},
    { 0x21200010, "Queue Status", "CS", "1", -1, 0},
    { 0x21200050, "Print Job Description Sequence", "SQ", "1", -1, 0},
    { 0x21200070, "Referenced Print Job Sequence", "SQ", "1", -1, 0},
    { 0x21300010, "Print Management Capabilities Sequence", "SQ", "1", -1, 0},
    { 0x21300015, "Printer Characteristics Sequence", "SQ", "1", -1, 0},
    { 0x21300030, "Film Box Content Sequence", "SQ", "1", -1, 0},
    { 0x21300040, "Image Box Content Sequence", "SQ", "1", -1, 0},
    { 0x21300050, "Annotation Content Sequence", "SQ", "1", -1, 0},
    { 0x21300060, "Image Overlay Box Content Sequence", "SQ", "1", -1, 0},
    { 0x21300080, "Presentation LUT Content Sequence", "SQ", "1", -1, 0},
    { 0x213000A0, "Proposed Study Sequence", "SQ", "1", -1, 0},
    { 0x213000C0, "Original Image Sequence", "SQ", "1", -1, 0},
    { 0x22000001, "Label Using Information Extracted From Instances", "CS", "1", 0, 0},
    { 0x22000002, "Label Text", "UT", "1", 0, 0},
    { 0x22000003, "Label Style Selection", "CS", "1", 0, 0},
    { 0x22000004, "Media Disposition", "LT", "1", 0, 0},
    { 0x22000005, "Barcode Value", "LT", "1", 0, 0},
    { 0x22000006, "Barcode Symbology", "CS", "1", 0, 0},
    { 0x22000007, "Allow Media Splitting", "CS", "1", 0, 0},
    { 0x22000008, "Include Non-DICOM Objects", "CS", "1", 0, 0},
    { 0x22000009, "Include Display Application", "CS", "1", 0, 0},
    { 0x2200000A, "Preserve Composite Instances After Media Creation", "CS", "1", 0, 0},
    { 0x2200000B, "Total Number of Pieces of Media Created", "US", "1", 0, 0},
    { 0x2200000C, "Requested Media Application Profile", "LO", "1", 0, 0},
    { 0x2200000D, "Referenced Storage Media Sequence", "SQ", "1", 0, 0},
    { 0x2200000E, "Failure Attributes", "AT", "1-n", 0, 0},
    { 0x2200000F, "Allow Lossy Compression", "CS", "1", 0, 0},
    { 0x22000020, "Request Priority", "CS", "1", 0, 0},
    { 0x30020002, "RT Image Label", "SH", "1", 0, 0},
    { 0x30020003, "RT Image Name", "LO", "1", 0, 0},
    { 0x30020004, "RT Image Description", "ST", "1", 0, 0},
    { 0x3002000A, "Reported Values Origin", "CS", "1", 0, 0},
    { 0x3002000C, "RT Image Plane", "CS", "1", 0, 0},
    { 0x3002000D, "X-Ray Image Receptor Translation", "DS", "3", 0, 0},
    { 0x3002000E, "X-Ray Image Receptor Angle", "DS", "1", 0, 0},
    { 0x30020010, "RT Image Orientation", "DS", "6", 0, 0},
    { 0x30020011, "Image Plane Pixel Spacing", "DS", "2", 0, 0},
    { 0x30020012, "RT Image Position", "DS", "2", 0, 0},
    { 0x30020020, "Radiation Machine Name", "SH", "1", 0, 0},
    { 0x30020022, "Radiation Machine SAD", "DS", "1", 0, 0},
    { 0x30020024, "Radiation Machine SSD", "DS", "1", 0, 0},
    { 0x30020026, "RT Image SID", "DS", "1", 0, 0},
    { 0x30020028, "Source to Reference Object Distance", "DS", "1", 0, 0},
    { 0x30020029, "Fraction Number", "IS", "1", 0, 0},
    { 0x30020030, "Exposure Sequence", "SQ", "1", 0, 0},
    { 0x30020032, "Meterset Exposure", "DS", "1", 0, 0},
    { 0x30020034, "Diaphragm Position", "DS", "4", 0, 0},
    { 0x30020040, "Fluence Map Sequence", "SQ", "1", 0, 0},
    { 0x30020041, "Fluence Data Source", "CS", "1", 0, 0},
    { 0x30020042, "Fluence Data Scale", "DS", "1", 0, 0},
    { 0x30040001, "DVH Type", "CS", "1", 0, 0},
    { 0x30040002, "Dose Units", "CS", "1", 0, 0},
    { 0x30040004, "Dose Type", "CS", "1", 0, 0},
    { 0x30040006, "Dose Comment", "LO", "1", 0, 0},
    { 0x30040008, "Normalization Point", "DS", "3", 0, 0},
    { 0x3004000A, "Dose Summation Type", "CS", "1", 0, 0},
    { 0x3004000C, "Grid Frame Offset Vector", "DS", "2-n", 0, 0},
    { 0x3004000E, "Dose Grid Scaling", "DS", "1", 0, 0},
    { 0x30040010, "RT Dose ROI Sequence", "SQ", "1", 0, 0},
    { 0x30040012, "Dose Value", "DS", "1", 0, 0},
    { 0x30040014, "Tissue Heterogeneity Correction", "CS", "1-3", 0, 0},
    { 0x30040040, "DVH Normalization Point", "DS", "3", 0, 0},
    { 0x30040042, "DVH Normalization Dose Value", "DS", "1", 0, 0},
    { 0x30040050, "DVH Sequence", "SQ", "1", 0, 0},
    { 0x30040052, "DVH Dose Scaling", "DS", "1", 0, 0},
    { 0x30040054, "DVH Volume Units", "CS", "1", 0, 0},
    { 0x30040056, "DVH Number of Bins", "IS", "1", 0, 0},
    { 0x30040058, "DVH Data", "DS", "2-2n", 0, 0},
    { 0x30040060, "DVH Referenced ROI Sequence", "SQ", "1", 0, 0},
    { 0x30040062, "DVH ROI Contribution Type", "CS", "1", 0, 0},
    { 0x30040070, "DVH Minimum Dose", "DS", "1", 0, 0},
    { 0x30040072, "DVH Maximum Dose", "DS", "1", 0, 0},
    { 0x30040074, "DVH Mean Dose", "DS", "1", 0, 0},
    { 0x30060002, "Structure Set Label", "SH", "1", 0, 0},
    { 0x30060004, "Structure Set Name", "LO", "1", 0, 0},
    { 0x30060006, "Structure Set Description", "ST", "1", 0, 0},
    { 0x30060008, "Structure Set Date", "DA", "1", 0, 0},
    { 0x30060009, "Structure Set Time", "TM", "1", 0, 0},
    { 0x30060010, "Referenced Frame of Reference Sequence", "SQ", "1", 0, 0},
    { 0x30060012, "RT Referenced Study Sequence", "SQ", "1", 0, 0},
    { 0x30060014, "RT Referenced Series Sequence", "SQ", "1", 0, 0},
    { 0x30060016, "Contour Image Sequence", "SQ", "1", 0, 0},
    { 0x30060020, "Structure Set ROI Sequence", "SQ", "1", 0, 0},
    { 0x30060022, "ROI Number", "IS", "1", 0, -1},
    { 0x30060024, "Referenced Frame of Reference UID", "UI", "1", 0, 0},
    { 0x30060026, "ROI Name", "LO", "1", 0, -1},
    { 0x30060028, "ROI Description", "ST", "1", 0, 0},
    { 0x3006002A, "ROI Display Color", "IS", "3", 0, 0},
    { 0x3006002C, "ROI Volume", "DS", "1", 0, 0},
    { 0x30060030, "RT Related ROI Sequence", "SQ", "1", 0, 0},
    { 0x30060033, "RT ROI Relationship", "CS", "1", 0, 0},
    { 0x30060036, "ROI Generation Algorithm", "CS", "1", 0, 0},
    { 0x30060038, "ROI Generation Description", "LO", "1", 0, 0},
    { 0x30060039, "ROI Contour Sequence", "SQ", "1", 0, 0},
    { 0x30060040, "Contour Sequence", "SQ", "1", 0, 0},
    { 0x30060042, "Contour Geometric Type", "CS", "1", 0, -1},
    { 0x30060044, "Contour Slab Thickness", "DS", "1", 0, 0},
    { 0x30060045, "Contour Offset Vector", "DS", "3", 0, 0},
    { 0x30060046, "Number of Contour Points", "IS", "1", 0, 0},
    { 0x30060048, "Contour Number", "IS", "1", 0, 0},
    { 0x30060049, "Attached Contours", "IS", "1-n", 0, 0},
    { 0x30060050, "Contour Data", "DS", "3-3n", 0, 0},
    { 0x30060080, "RT ROI Observations Sequence", "SQ", "1", 0, 0},
    { 0x30060082, "Observation Number", "IS", "1", 0, -1},
    { 0x30060084, "Referenced ROI Number", "IS", "1", 0, 0},
    { 0x30060085, "ROI Observation Label", "SH", "1", 0, -1},
    { 0x30060086, "RT ROI Identification Code Sequence", "SQ", "1", 0, 0},
    { 0x30060088, "ROI Observation Description", "ST", "1", 0, 0},
    { 0x300600A0, "Related RT ROI Observations Sequence", "SQ", "1", 0, 0},
    { 0x300600A4, "RT ROI Interpreted Type", "CS", "1", 0, -1},
    { 0x300600A6, "ROI Interpreter", "PN", "1", 0, 0},
    { 0x300600B0, "ROI Physical Properties Sequence", "SQ", "1", 0, 0},
    { 0x300600B2, "ROI Physical Property", "CS", "1", 0, 0},
    { 0x300600B4, "ROI Physical Property Value", "DS", "1", 0, 0},
    { 0x300600B6, "ROI Elemental Composition Sequence", "SQ", "1", 0, 0},
    { 0x300600B7, "ROI Elemental Composition Atomic Number", "US", "1", 0, 0},
    { 0x300600B8, "ROI Elemental Composition Atomic Mass Fraction", "FL", "1", 0, 0},
    { 0x300600C0, "Frame of Reference Relationship Sequence", "SQ", "1", 0, 0},
    { 0x300600C2, "Related Frame of Reference UID", "UI", "1", 0, 0},
    { 0x300600C4, "Frame of Reference Transformation Type", "CS", "1", 0, 0},
    { 0x300600C6, "Frame of Reference Transformation Matrix", "DS", "16", 0, 0},
    { 0x300600C8, "Frame of Reference Transformation Comment", "LO", "1", 0, 0},
    { 0x30080010, "Measured Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x30080012, "Measured Dose Description", "ST", "1", 0, 0},
    { 0x30080014, "Measured Dose Type", "CS", "1", 0, 0},
    { 0x30080016, "Measured Dose Value", "DS", "1", 0, 0},
    { 0x30080020, "Treatment Session Beam Sequence", "SQ", "1", 0, 0},
    { 0x30080021, "Treatment Session Ion Beam Sequence", "SQ", "1", 0, 0},
    { 0x30080022, "Current Fraction Number", "IS", "1", 0, 0},
    { 0x30080024, "Treatment Control Point Date", "DA", "1", 0, 0},
    { 0x30080025, "Treatment Control Point Time", "TM", "1", 0, 0},
    { 0x3008002A, "Treatment Termination Status", "CS", "1", 0, 0},
    { 0x3008002B, "Treatment Termination Code", "SH", "1", 0, 0},
    { 0x3008002C, "Treatment Verification Status", "CS", "1", 0, 0},
    { 0x30080030, "Referenced Treatment Record Sequence", "SQ", "1", 0, 0},
    { 0x30080032, "Specified Primary Meterset", "DS", "1", 0, 0},
    { 0x30080033, "Specified Secondary Meterset", "DS", "1", 0, 0},
    { 0x30080036, "Delivered Primary Meterset", "DS", "1", 0, 0},
    { 0x30080037, "Delivered Secondary Meterset", "DS", "1", 0, 0},
    { 0x3008003A, "Specified Treatment Time", "DS", "1", 0, 0},
    { 0x3008003B, "Delivered Treatment Time", "DS", "1", 0, 0},
    { 0x30080040, "Control Point Delivery Sequence", "SQ", "1", 0, 0},
    { 0x30080041, "Ion Control Point Delivery Sequence", "SQ", "1", 0, 0},
    { 0x30080042, "Specified Meterset", "DS", "1", 0, 0},
    { 0x30080044, "Delivered Meterset", "DS", "1", 0, 0},
    { 0x30080045, "Meterset Rate Set", "FL", "1", 0, 0},
    { 0x30080046, "Meterset Rate Delivered", "FL", "1", 0, 0},
    { 0x30080047, "Scan Spot Metersets Delivered", "FL", "1-n", 0, 0},
    { 0x30080048, "Dose Rate Delivered", "DS", "1", 0, 0},
    { 0x30080050, "Treatment Summary Calculated Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x30080052, "Cumulative Dose to Dose Reference", "DS", "1", 0, 0},
    { 0x30080054, "First Treatment Date", "DA", "1", 0, 0},
    { 0x30080056, "Most Recent Treatment Date", "DA", "1", 0, 0},
    { 0x3008005A, "Number of Fractions Delivered", "IS", "1", 0, 0},
    { 0x30080060, "Override Sequence", "SQ", "1", 0, 0},
    { 0x30080061, "Parameter Sequence Pointer", "AT", "1", 0, 0},
    { 0x30080062, "Override Parameter Pointer", "AT", "1", 0, 0},
    { 0x30080063, "Parameter Item Index", "IS", "1", 0, 0},
    { 0x30080064, "Measured Dose Reference Number", "IS", "1", 0, 0},
    { 0x30080065, "Parameter Pointer", "AT", "1", 0, 0},
    { 0x30080066, "Override Reason", "ST", "1", 0, 0},
    { 0x30080068, "Corrected Parameter Sequence", "SQ", "1", 0, 0},
    { 0x3008006A, "Correction Value", "FL", "1", 0, 0},
    { 0x30080070, "Calculated Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x30080072, "Calculated Dose Reference Number", "IS", "1", 0, 0},
    { 0x30080074, "Calculated Dose Reference Description", "ST", "1", 0, 0},
    { 0x30080076, "Calculated Dose Reference Dose Value", "DS", "1", 0, 0},
    { 0x30080078, "Start Meterset", "DS", "1", 0, 0},
    { 0x3008007A, "End Meterset", "DS", "1", 0, 0},
    { 0x30080080, "Referenced Measured Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x30080082, "Referenced Measured Dose Reference Number", "IS", "1", 0, 0},
    { 0x30080090, "Referenced Calculated Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x30080092, "Referenced Calculated Dose Reference Number", "IS", "1", 0, 0},
    { 0x300800A0, "Beam Limiting Device Leaf Pairs Sequence", "SQ", "1", 0, 0},
    { 0x300800B0, "Recorded Wedge Sequence", "SQ", "1", 0, 0},
    { 0x300800C0, "Recorded Compensator Sequence", "SQ", "1", 0, 0},
    { 0x300800D0, "Recorded Block Sequence", "SQ", "1", 0, 0},
    { 0x300800E0, "Treatment Summary Measured Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x300800F0, "Recorded Snout Sequence", "SQ", "1", 0, 0},
    { 0x300800F2, "Recorded Range Shifter Sequence", "SQ", "1", 0, 0},
    { 0x300800F4, "Recorded Lateral Spreading Device Sequence", "SQ", "1", 0, 0},
    { 0x300800F6, "Recorded Range Modulator Sequence", "SQ", "1", 0, 0},
    { 0x30080100, "Recorded Source Sequence", "SQ", "1", 0, 0},
    { 0x30080105, "Source Serial Number", "LO", "1", 0, 0},
    { 0x30080110, "Treatment Session Application Setup Sequence", "SQ", "1", 0, 0},
    { 0x30080116, "Application Setup Check", "CS", "1", 0, 0},
    { 0x30080120, "Recorded Brachy Accessory Device Sequence", "SQ", "1", 0, 0},
    { 0x30080122, "Referenced Brachy Accessory Device Number", "IS", "1", 0, 0},
    { 0x30080130, "Recorded Channel Sequence", "SQ", "1", 0, 0},
    { 0x30080132, "Specified Channel Total Time", "DS", "1", 0, 0},
    { 0x30080134, "Delivered Channel Total Time", "DS", "1", 0, 0},
    { 0x30080136, "Specified Number of Pulses", "IS", "1", 0, 0},
    { 0x30080138, "Delivered Number of Pulses", "IS", "1", 0, 0},
    { 0x3008013A, "Specified Pulse Repetition Interval", "DS", "1", 0, 0},
    { 0x3008013C, "Delivered Pulse Repetition Interval", "DS", "1", 0, 0},
    { 0x30080140, "Recorded Source Applicator Sequence", "SQ", "1", 0, 0},
    { 0x30080142, "Referenced Source Applicator Number", "IS", "1", 0, 0},
    { 0x30080150, "Recorded Channel Shield Sequence", "SQ", "1", 0, 0},
    { 0x30080152, "Referenced Channel Shield Number", "IS", "1", 0, 0},
    { 0x30080160, "Brachy Control Point Delivered Sequence", "SQ", "1", 0, 0},
    { 0x30080162, "Safe Position Exit Date", "DA", "1", 0, 0},
    { 0x30080164, "Safe Position Exit Time", "TM", "1", 0, 0},
    { 0x30080166, "Safe Position Return Date", "DA", "1", 0, 0},
    { 0x30080168, "Safe Position Return Time", "TM", "1", 0, 0},
    { 0x30080200, "Current Treatment Status", "CS", "1", 0, 0},
    { 0x30080202, "Treatment Status Comment", "ST", "1", 0, 0},
    { 0x30080220, "Fraction Group Summary Sequence", "SQ", "1", 0, 0},
    { 0x30080223, "Referenced Fraction Number", "IS", "1", 0, 0},
    { 0x30080224, "Fraction Group Type", "CS", "1", 0, 0},
    { 0x30080230, "Beam Stopper Position", "CS", "1", 0, 0},
    { 0x30080240, "Fraction Status Summary Sequence", "SQ", "1", 0, 0},
    { 0x30080250, "Treatment Date", "DA", "1", 0, 0},
    { 0x30080251, "Treatment Time", "TM", "1", 0, 0},
    { 0x300A0002, "RT Plan Label", "SH", "1", 0, 0},
    { 0x300A0003, "RT Plan Name", "LO", "1", 0, 0},
    { 0x300A0004, "RT Plan Description", "ST", "1", 0, 0},
    { 0x300A0006, "RT Plan Date", "DA", "1", 0, 0},
    { 0x300A0007, "RT Plan Time", "TM", "1", 0, 0},
    { 0x300A0009, "Treatment Protocols", "LO", "1-n", 0, 0},
    { 0x300A000A, "Plan Intent", "CS", "1", 0, 0},
    { 0x300A000B, "Treatment Sites", "LO", "1-n", 0, 0},
    { 0x300A000C, "RT Plan Geometry", "CS", "1", 0, 0},
    { 0x300A000E, "Prescription Description", "ST", "1", 0, 0},
    { 0x300A0010, "Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x300A0012, "Dose Reference Number", "IS", "1", 0, 0},
    { 0x300A0013, "Dose Reference UID", "UI", "1", 0, 0},
    { 0x300A0014, "Dose Reference Structure Type", "CS", "1", 0, -1},
    { 0x300A0015, "Nominal Beam Energy Unit", "CS", "1", 0, 0},
    { 0x300A0016, "Dose Reference Description", "LO", "1", 0, -1},
    { 0x300A0018, "Dose Reference Point Coordinates", "DS", "3", 0, 0},
    { 0x300A001A, "Nominal Prior Dose", "DS", "1", 0, 0},
    { 0x300A0020, "Dose Reference Type", "CS", "1", 0, -1},
    { 0x300A0021, "Constraint Weight", "DS", "1", 0, 0},
    { 0x300A0022, "Delivery Warning Dose", "DS", "1", 0, 0},
    { 0x300A0023, "Delivery Maximum Dose", "DS", "1", 0, 0},
    { 0x300A0025, "Target Minimum Dose", "DS", "1", 0, 0},
    { 0x300A0026, "Target Prescription Dose", "DS", "1", 0, -1},
    { 0x300A0027, "Target Maximum Dose", "DS", "1", 0, 0},
    { 0x300A0028, "Target Underdose Volume Fraction", "DS", "1", 0, 0},
    { 0x300A002A, "Organ at Risk Full-volume Dose", "DS", "1", 0, 0},
    { 0x300A002B, "Organ at Risk Limit Dose", "DS", "1", 0, 0},
    { 0x300A002C, "Organ at Risk Maximum Dose", "DS", "1", 0, 0},
    { 0x300A002D, "Organ at Risk Overdose Volume Fraction", "DS", "1", 0, 0},
    { 0x300A0040, "Tolerance Table Sequence", "SQ", "1", 0, 0},
    { 0x300A0042, "Tolerance Table Number", "IS", "1", 0, 0},
    { 0x300A0043, "Tolerance Table Label", "SH", "1", 0, -1},
    { 0x300A0044, "Gantry Angle Tolerance", "DS", "1", 0, 0},
    { 0x300A0046, "Beam Limiting Device Angle Tolerance", "DS", "1", 0, 0},
    { 0x300A0048, "Beam Limiting Device Tolerance Sequence", "SQ", "1", 0, 0},
    { 0x300A004A, "Beam Limiting Device Position Tolerance", "DS", "1", 0, -1},
    { 0x300A004B, "Snout Position Tolerance", "FL", "1", 0, 0},
    { 0x300A004C, "Patient Support Angle Tolerance", "DS", "1", 0, 0},
    { 0x300A004E, "Table Top Eccentric Angle Tolerance", "DS", "1", 0, 0},
    { 0x300A004F, "Table Top Pitch Angle Tolerance", "FL", "1", 0, 0},
    { 0x300A0050, "Table Top Roll Angle Tolerance", "FL", "1", 0, 0},
    { 0x300A0051, "Table Top Vertical Position Tolerance", "DS", "1", 0, 0},
    { 0x300A0052, "Table Top Longitudinal Position Tolerance", "DS", "1", 0, 0},
    { 0x300A0053, "Table Top Lateral Position Tolerance", "DS", "1", 0, 0},
    { 0x300A0055, "RT Plan Relationship", "CS", "1", 0, 0},
    { 0x300A0070, "Fraction Group Sequence", "SQ", "1", 0, 0},
    { 0x300A0071, "Fraction Group Number", "IS", "1", 0, 0},
    { 0x300A0072, "Fraction Group Description", "LO", "1", 0, 0},
    { 0x300A0078, "Number of Fractions Planned", "IS", "1", 0, -1},
    { 0x300A0079, "Number of Fraction Pattern Digits Per Day", "IS", "1", 0, 0},
    { 0x300A007A, "Repeat Fraction Cycle Length", "IS", "1", 0, 0},
    { 0x300A007B, "Fraction Pattern", "LT", "1", 0, 0},
    { 0x300A0080, "Number of Beams", "IS", "1", 0, 0},
    { 0x300A0082, "Beam Dose Specification Point", "DS", "3", 0, 0},
    { 0x300A0084, "Beam Dose", "DS", "1", 0, 0},
    { 0x300A0086, "Beam Meterset", "DS", "1", 0, 0},
    { 0x300A0088, "Beam Dose Point Depth", "FL", "1", 0, 0},
    { 0x300A0089, "Beam Dose Point Equivalent Depth", "FL", "1", 0, 0},
    { 0x300A008A, "Beam Dose Point SSD", "FL", "1", 0, 0},
    { 0x300A00A0, "Number of Brachy Application Setups", "IS", "1", 0, 0},
    { 0x300A00A2, "Brachy Application Setup Dose Specification Point", "DS", "3", 0, 0},
    { 0x300A00A4, "Brachy Application Setup Dose", "DS", "1", 0, 0},
    { 0x300A00B0, "Beam Sequence", "SQ", "1", 0, 0},
    { 0x300A00B2, "Treatment Machine Name", "SH", "1", 0, -1},
    { 0x300A00B3, "Primary Dosimeter Unit", "CS", "1", 0, 0},
    { 0x300A00B4, "Source-Axis Distance", "DS", "1", 0, 0},
    { 0x300A00B6, "Beam Limiting Device Sequence", "SQ", "1", 0, 0},
    { 0x300A00B8, "RT Beam Limiting Device Type", "CS", "1", 0, -1},
    { 0x300A00BA, "Source to Beam Limiting Device Distance", "DS", "1", 0, 0},
    { 0x300A00BB, "Isocenter to Beam Limiting Device Distance", "FL", "1", 0, 0},
    { 0x300A00BC, "Number of Leaf/Jaw Pairs", "IS", "1", 0, 0},
    { 0x300A00BE, "Leaf Position Boundaries", "DS", "3-n", 0, 0},
    { 0x300A00C0, "Beam Number", "IS", "1", 0, -1},
    { 0x300A00C2, "Beam Name", "LO", "1", 0, -1},
    { 0x300A00C3, "Beam Description", "ST", "1", 0, 0},
    { 0x300A00C4, "Beam Type", "CS", "1", 0, -1},
    { 0x300A00C6, "Radiation Type", "CS", "1", 0, -1},
    { 0x300A00C7, "High-Dose Technique Type", "CS", "1", 0, 0},
    { 0x300A00C8, "Reference Image Number", "IS", "1", 0, 0},
    { 0x300A00CA, "Planned Verification Image Sequence", "SQ", "1", 0, 0},
    { 0x300A00CC, "Imaging Device-Specific Acquisition Parameters", "LO", "1-n", 0, 0},
    { 0x300A00CE, "Treatment Delivery Type", "CS", "1", 0, 0},
    { 0x300A00D0, "Number of Wedges", "IS", "1", 0, 0},
    { 0x300A00D1, "Wedge Sequence", "SQ", "1", 0, 0},
    { 0x300A00D2, "Wedge Number", "IS", "1", 0, 0},
    { 0x300A00D3, "Wedge Type", "CS", "1", 0, -1},
    { 0x300A00D4, "Wedge ID", "SH", "1", 0, -1},
    { 0x300A00D5, "Wedge Angle", "IS", "1", 0, -1},
    { 0x300A00D6, "Wedge Factor", "DS", "1", 0, 0},
    { 0x300A00D7, "Total Wedge Tray Water-Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A00D8, "Wedge Orientation", "DS", "1", 0, 0},
    { 0x300A00D9, "Isocenter to Wedge Tray Distance", "FL", "1", 0, 0},
    { 0x300A00DA, "Source to Wedge Tray Distance", "DS", "1", 0, 0},
    { 0x300A00DB, "Wedge Thin Edge Position", "FL", "1", 0, 0},
    { 0x300A00DC, "Bolus ID", "SH", "1", 0, 0},
    { 0x300A00DD, "Bolus Description", "ST", "1", 0, 0},
    { 0x300A00E0, "Number of Compensators", "IS", "1", 0, 0},
    { 0x300A00E1, "Material ID", "SH", "1", 0, -1},
    { 0x300A00E2, "Total Compensator Tray Factor", "DS", "1", 0, 0},
    { 0x300A00E3, "Compensator Sequence", "SQ", "1", 0, 0},
    { 0x300A00E4, "Compensator Number", "IS", "1", 0, 0},
    { 0x300A00E5, "Compensator ID", "SH", "1", 0, 0},
    { 0x300A00E6, "Source to Compensator Tray Distance", "DS", "1", 0, 0},
    { 0x300A00E7, "Compensator Rows", "IS", "1", 0, 0},
    { 0x300A00E8, "Compensator Columns", "IS", "1", 0, 0},
    { 0x300A00E9, "Compensator Pixel Spacing", "DS", "2", 0, 0},
    { 0x300A00EA, "Compensator Position", "DS", "2", 0, 0},
    { 0x300A00EB, "Compensator Transmission Data", "DS", "1-n", 0, 0},
    { 0x300A00EC, "Compensator Thickness Data", "DS", "1-n", 0, 0},
    { 0x300A00ED, "Number of Boli", "IS", "1", 0, 0},
    { 0x300A00EE, "Compensator Type", "CS", "1", 0, 0},
    { 0x300A00F0, "Number of Blocks", "IS", "1", 0, 0},
    { 0x300A00F2, "Total Block Tray Factor", "DS", "1", 0, 0},
    { 0x300A00F3, "Total Block Tray Water-Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A00F4, "Block Sequence", "SQ", "1", 0, 0},
    { 0x300A00F5, "Block Tray ID", "SH", "1", 0, -1},
    { 0x300A00F6, "Source to Block Tray Distance", "DS", "1", 0, 0},
    { 0x300A00F7, "Isocenter to Block Tray Distance", "FL", "1", 0, 0},
    { 0x300A00F8, "Block Type", "CS", "1", 0, 0},
    { 0x300A00F9, "Accessory Code", "LO", "1", 0, 0},
    { 0x300A00FA, "Block Divergence", "CS", "1", 0, 0},
    { 0x300A00FB, "Block Mounting Position", "CS", "1", 0, 0},
    { 0x300A00FC, "Block Number", "IS", "1", 0, 0},
    { 0x300A00FE, "Block Name", "LO", "1", 0, -1},
    { 0x300A0100, "Block Thickness", "DS", "1", 0, 0},
    { 0x300A0102, "Block Transmission", "DS", "1", 0, 0},
    { 0x300A0104, "Block Number of Points", "IS", "1", 0, 0},
    { 0x300A0106, "Block Data", "DS", "2-2n", 0, 0},
    { 0x300A0107, "Applicator Sequence", "SQ", "1", 0, 0},
    { 0x300A0108, "Applicator ID", "SH", "1", 0, -1},
    { 0x300A0109, "Applicator Type", "CS", "1", 0, -1},
    { 0x300A010A, "Applicator Description", "LO", "1", 0, 0},
    { 0x300A010C, "Cumulative Dose Reference Coefficient", "DS", "1", 0, 0},
    { 0x300A010E, "Final Cumulative Meterset Weight", "DS", "1", 0, 0},
    { 0x300A0110, "Number of Control Points", "IS", "1", 0, 0},
    { 0x300A0111, "Control Point Sequence", "SQ", "1", 0, 0},
    { 0x300A0112, "Control Point Index", "IS", "1", 0, -1},
    { 0x300A0114, "Nominal Beam Energy", "DS", "1", 0, -1},
    { 0x300A0115, "Dose Rate Set", "DS", "1", 0, 0},
    { 0x300A0116, "Wedge Position Sequence", "SQ", "1", 0, 0},
    { 0x300A0118, "Wedge Position", "CS", "1", 0, 0},
    { 0x300A011A, "Beam Limiting Device Position Sequence", "SQ", "1", 0, 0},
    { 0x300A011C, "Leaf/Jaw Positions", "DS", "2-2n", 0, 0},
    { 0x300A011E, "Gantry Angle", "DS", "1", 0, 0},
    { 0x300A011F, "Gantry Rotation Direction", "CS", "1", 0, 0},
    { 0x300A0120, "Beam Limiting Device Angle", "DS", "1", 0, 0},
    { 0x300A0121, "Beam Limiting Device Rotation Direction", "CS", "1", 0, 0},
    { 0x300A0122, "Patient Support Angle", "DS", "1", 0, 0},
    { 0x300A0123, "Patient Support Rotation Direction", "CS", "1", 0, 0},
    { 0x300A0124, "Table Top Eccentric Axis Distance", "DS", "1", 0, 0},
    { 0x300A0125, "Table Top Eccentric Angle", "DS", "1", 0, 0},
    { 0x300A0126, "Table Top Eccentric Rotation Direction", "CS", "1", 0, 0},
    { 0x300A0128, "Table Top Vertical Position", "DS", "1", 0, 0},
    { 0x300A0129, "Table Top Longitudinal Position", "DS", "1", 0, 0},
    { 0x300A012A, "Table Top Lateral Position", "DS", "1", 0, 0},
    { 0x300A012C, "Isocenter Position", "DS", "3", 0, 0},
    { 0x300A012E, "Surface Entry Point", "DS", "3", 0, 0},
    { 0x300A0130, "Source to Surface Distance", "DS", "1", 0, 0},
    { 0x300A0134, "Cumulative Meterset Weight", "DS", "1", 0, -1},
    { 0x300A0140, "Table Top Pitch Angle", "FL", "1", 0, 0},
    { 0x300A0142, "Table Top Pitch Rotation Direction", "CS", "1", 0, 0},
    { 0x300A0144, "Table Top Roll Angle", "FL", "1", 0, 0},
    { 0x300A0146, "Table Top Roll Rotation Direction", "CS", "1", 0, 0},
    { 0x300A0148, "Head Fixation Angle", "FL", "1", 0, 0},
    { 0x300A014A, "Gantry Pitch Angle", "FL", "1", 0, 0},
    { 0x300A014C, "Gantry Pitch Rotation Direction", "CS", "1", 0, 0},
    { 0x300A014E, "Gantry Pitch Angle Tolerance", "FL", "1", 0, 0},
    { 0x300A0180, "Patient Setup Sequence", "SQ", "1", 0, 0},
    { 0x300A0182, "Patient Setup Number", "IS", "1", 0, -1},
    { 0x300A0183, "Patient Setup Label", "LO", "1", 0, 0},
    { 0x300A0184, "Patient Additional Position", "LO", "1", 0, 0},
    { 0x300A0190, "Fixation Device Sequence", "SQ", "1", 0, 0},
    { 0x300A0192, "Fixation Device Type", "CS", "1", 0, 0},
    { 0x300A0194, "Fixation Device Label", "SH", "1", 0, 0},
    { 0x300A0196, "Fixation Device Description", "ST", "1", 0, 0},
    { 0x300A0198, "Fixation Device Position", "SH", "1", 0, 0},
    { 0x300A0199, "Fixation Device Pitch Angle", "FL", "1", 0, 0},
    { 0x300A019A, "Fixation Device Roll Angle", "FL", "1", 0, 0},
    { 0x300A01A0, "Shielding Device Sequence", "SQ", "1", 0, 0},
    { 0x300A01A2, "Shielding Device Type", "CS", "1", 0, 0},
    { 0x300A01A4, "Shielding Device Label", "SH", "1", 0, 0},
    { 0x300A01A6, "Shielding Device Description", "ST", "1", 0, 0},
    { 0x300A01A8, "Shielding Device Position", "SH", "1", 0, 0},
    { 0x300A01B0, "Setup Technique", "CS", "1", 0, 0},
    { 0x300A01B2, "Setup Technique Description", "ST", "1", 0, 0},
    { 0x300A01B4, "Setup Device Sequence", "SQ", "1", 0, 0},
    { 0x300A01B6, "Setup Device Type", "CS", "1", 0, 0},
    { 0x300A01B8, "Setup Device Label", "SH", "1", 0, 0},
    { 0x300A01BA, "Setup Device Description", "ST", "1", 0, 0},
    { 0x300A01BC, "Setup Device Parameter", "DS", "1", 0, 0},
    { 0x300A01D0, "Setup Reference Description", "ST", "1", 0, 0},
    { 0x300A01D2, "Table Top Vertical Setup Displacement", "DS", "1", 0, 0},
    { 0x300A01D4, "Table Top Longitudinal Setup Displacement", "DS", "1", 0, 0},
    { 0x300A01D6, "Table Top Lateral Setup Displacement", "DS", "1", 0, 0},
    { 0x300A0200, "Brachy Treatment Technique", "CS", "1", 0, 0},
    { 0x300A0202, "Brachy Treatment Type", "CS", "1", 0, 0},
    { 0x300A0206, "Treatment Machine Sequence", "SQ", "1", 0, 0},
    { 0x300A0210, "Source Sequence", "SQ", "1", 0, 0},
    { 0x300A0212, "Source Number", "IS", "1", 0, 0},
    { 0x300A0214, "Source Type", "CS", "1", 0, 0},
    { 0x300A0216, "Source Manufacturer", "LO", "1", 0, 0},
    { 0x300A0218, "Active Source Diameter", "DS", "1", 0, 0},
    { 0x300A021A, "Active Source Length", "DS", "1", 0, 0},
    { 0x300A0222, "Source Encapsulation Nominal Thickness", "DS", "1", 0, 0},
    { 0x300A0224, "Source Encapsulation Nominal Transmission", "DS", "1", 0, 0},
    { 0x300A0226, "Source Isotope Name", "LO", "1", 0, 0},
    { 0x300A0228, "Source Isotope Half Life", "DS", "1", 0, 0},
    { 0x300A0229, "Source Strength Units", "CS", "1", 0, 0},
    { 0x300A022A, "Reference Air Kerma Rate", "DS", "1", 0, 0},
    { 0x300A022B, "Source Strength", "DS", "1", 0, 0},
    { 0x300A022C, "Source Strength Reference Date", "DA", "1", 0, 0},
    { 0x300A022E, "Source Strength Reference Time", "TM", "1", 0, 0},
    { 0x300A0230, "Application Setup Sequence", "SQ", "1", 0, 0},
    { 0x300A0232, "Application Setup Type", "CS", "1", 0, 0},
    { 0x300A0234, "Application Setup Number", "IS", "1", 0, 0},
    { 0x300A0236, "Application Setup Name", "LO", "1", 0, 0},
    { 0x300A0238, "Application Setup Manufacturer", "LO", "1", 0, 0},
    { 0x300A0240, "Template Number", "IS", "1", 0, 0},
    { 0x300A0242, "Template Type", "SH", "1", 0, 0},
    { 0x300A0244, "Template Name", "LO", "1", 0, 0},
    { 0x300A0250, "Total Reference Air Kerma", "DS", "1", 0, 0},
    { 0x300A0260, "Brachy Accessory Device Sequence", "SQ", "1", 0, 0},
    { 0x300A0262, "Brachy Accessory Device Number", "IS", "1", 0, 0},
    { 0x300A0263, "Brachy Accessory Device ID", "SH", "1", 0, 0},
    { 0x300A0264, "Brachy Accessory Device Type", "CS", "1", 0, 0},
    { 0x300A0266, "Brachy Accessory Device Name", "LO", "1", 0, 0},
    { 0x300A026A, "Brachy Accessory Device Nominal Thickness", "DS", "1", 0, 0},
    { 0x300A026C, "Brachy Accessory Device Nominal Transmission", "DS", "1", 0, 0},
    { 0x300A0280, "Channel Sequence", "SQ", "1", 0, 0},
    { 0x300A0282, "Channel Number", "IS", "1", 0, 0},
    { 0x300A0284, "Channel Length", "DS", "1", 0, 0},
    { 0x300A0286, "Channel Total Time", "DS", "1", 0, 0},
    { 0x300A0288, "Source Movement Type", "CS", "1", 0, 0},
    { 0x300A028A, "Number of Pulses", "IS", "1", 0, 0},
    { 0x300A028C, "Pulse Repetition Interval", "DS", "1", 0, 0},
    { 0x300A0290, "Source Applicator Number", "IS", "1", 0, 0},
    { 0x300A0291, "Source Applicator ID", "SH", "1", 0, 0},
    { 0x300A0292, "Source Applicator Type", "CS", "1", 0, 0},
    { 0x300A0294, "Source Applicator Name", "LO", "1", 0, 0},
    { 0x300A0296, "Source Applicator Length", "DS", "1", 0, 0},
    { 0x300A0298, "Source Applicator Manufacturer", "LO", "1", 0, 0},
    { 0x300A029C, "Source Applicator Wall Nominal Thickness", "DS", "1", 0, 0},
    { 0x300A029E, "Source Applicator Wall Nominal Transmission", "DS", "1", 0, 0},
    { 0x300A02A0, "Source Applicator Step Size", "DS", "1", 0, 0},
    { 0x300A02A2, "Transfer Tube Number", "IS", "1", 0, 0},
    { 0x300A02A4, "Transfer Tube Length", "DS", "1", 0, 0},
    { 0x300A02B0, "Channel Shield Sequence", "SQ", "1", 0, 0},
    { 0x300A02B2, "Channel Shield Number", "IS", "1", 0, 0},
    { 0x300A02B3, "Channel Shield ID", "SH", "1", 0, 0},
    { 0x300A02B4, "Channel Shield Name", "LO", "1", 0, 0},
    { 0x300A02B8, "Channel Shield Nominal Thickness", "DS", "1", 0, 0},
    { 0x300A02BA, "Channel Shield Nominal Transmission", "DS", "1", 0, 0},
    { 0x300A02C8, "Final Cumulative Time Weight", "DS", "1", 0, 0},
    { 0x300A02D0, "Brachy Control Point Sequence", "SQ", "1", 0, 0},
    { 0x300A02D2, "Control Point Relative Position", "DS", "1", 0, 0},
    { 0x300A02D4, "Control Point 3D Position", "DS", "3", 0, 0},
    { 0x300A02D6, "Cumulative Time Weight", "DS", "1", 0, 0},
    { 0x300A02E0, "Compensator Divergence", "CS", "1", 0, 0},
    { 0x300A02E1, "Compensator Mounting Position", "CS", "1", 0, 0},
    { 0x300A02E2, "Source to Compensator Distance", "DS", "1-n", 0, 0},
    { 0x300A02E3, "Total Compensator Tray Water-Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A02E4, "Isocenter to Compensator Tray Distance", "FL", "1", 0, 0},
    { 0x300A02E5, "Compensator Column Offset", "FL", "1", 0, 0},
    { 0x300A02E6, "Isocenter to Compensator Distances", "FL", "1-n", 0, 0},
    { 0x300A02E7, "Compensator Relative Stopping Power Ratio", "FL", "1", 0, 0},
    { 0x300A02E8, "Compensator Milling Tool Diameter", "FL", "1", 0, 0},
    { 0x300A02EA, "Ion Range Compensator Sequence", "SQ", "1", 0, 0},
    { 0x300A02EB, "Compensator Description", "LT", "1", 0, 0},
    { 0x300A0302, "Radiation Mass Number", "IS", "1", 0, 0},
    { 0x300A0304, "Radiation Atomic Number", "IS", "1", 0, 0},
    { 0x300A0306, "Radiation Charge State", "SS", "1", 0, 0},
    { 0x300A0308, "Scan Mode", "CS", "1", 0, 0},
    { 0x300A030A, "Virtual Source-Axis Distances", "FL", "2", 0, 0},
    { 0x300A030C, "Snout Sequence", "SQ", "1", 0, 0},
    { 0x300A030D, "Snout Position", "FL", "1", 0, 0},
    { 0x300A030F, "Snout ID", "SH", "1", 0, 0},
    { 0x300A0312, "Number of Range Shifters", "IS", "1", 0, 0},
    { 0x300A0314, "Range Shifter Sequence", "SQ", "1", 0, 0},
    { 0x300A0316, "Range Shifter Number", "IS", "1", 0, 0},
    { 0x300A0318, "Range Shifter ID", "SH", "1", 0, 0},
    { 0x300A0320, "Range Shifter Type", "CS", "1", 0, 0},
    { 0x300A0322, "Range Shifter Description", "LO", "1", 0, 0},
    { 0x300A0330, "Number of Lateral Spreading Devices", "IS", "1", 0, 0},
    { 0x300A0332, "Lateral Spreading Device Sequence", "SQ", "1", 0, 0},
    { 0x300A0334, "Lateral Spreading Device Number", "IS", "1", 0, 0},
    { 0x300A0336, "Lateral Spreading Device ID", "SH", "1", 0, 0},
    { 0x300A0338, "Lateral Spreading Device Type", "CS", "1", 0, 0},
    { 0x300A033A, "Lateral Spreading Device Description", "LO", "1", 0, 0},
    { 0x300A033C, "Lateral Spreading Device Water Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A0340, "Number of Range Modulators", "IS", "1", 0, 0},
    { 0x300A0342, "Range Modulator Sequence", "SQ", "1", 0, 0},
    { 0x300A0344, "Range Modulator Number", "IS", "1", 0, 0},
    { 0x300A0346, "Range Modulator ID", "SH", "1", 0, 0},
    { 0x300A0348, "Range Modulator Type", "CS", "1", 0, 0},
    { 0x300A034A, "Range Modulator Description", "LO", "1", 0, 0},
    { 0x300A034C, "Beam Current Modulation ID", "SH", "1", 0, 0},
    { 0x300A0350, "Patient Support Type", "CS", "1", 0, 0},
    { 0x300A0352, "Patient Support ID", "SH", "1", 0, 0},
    { 0x300A0354, "Patient Support Accessory Code", "LO", "1", 0, 0},
    { 0x300A0356, "Fixation Light Azimuthal Angle", "FL", "1", 0, 0},
    { 0x300A0358, "Fixation Light Polar Angle", "FL", "1", 0, 0},
    { 0x300A035A, "Meterset Rate", "FL", "1", 0, 0},
    { 0x300A0360, "Range Shifter Settings Sequence", "SQ", "1", 0, 0},
    { 0x300A0362, "Range Shifter Setting", "LO", "1", 0, 0},
    { 0x300A0364, "Isocenter to Range Shifter Distance", "FL", "1", 0, 0},
    { 0x300A0366, "Range Shifter Water Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A0370, "Lateral Spreading Device Settings Sequence", "SQ", "1", 0, 0},
    { 0x300A0372, "Lateral Spreading Device Setting", "LO", "1", 0, 0},
    { 0x300A0374, "Isocenter to Lateral Spreading Device Distance", "FL", "1", 0, 0},
    { 0x300A0380, "Range Modulator Settings Sequence", "SQ", "1", 0, 0},
    { 0x300A0382, "Range Modulator Gating Start Value", "FL", "1", 0, 0},
    { 0x300A0384, "Range Modulator Gating Stop Value", "FL", "1", 0, 0},
    { 0x300A0386, "Range Modulator Gating Start Water Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A0388, "Range Modulator Gating Stop Water Equivalent Thickness", "FL", "1", 0, 0},
    { 0x300A038A, "Isocenter to Range Modulator Distance", "FL", "1", 0, 0},
    { 0x300A0390, "Scan Spot Tune ID", "SH", "1", 0, 0},
    { 0x300A0392, "Number of Scan Spot Positions", "IS", "1", 0, 0},
    { 0x300A0394, "Scan Spot Position Map", "FL", "1-n", 0, 0},
    { 0x300A0396, "Scan Spot Meterset Weights", "FL", "1-n", 0, 0},
    { 0x300A0398, "Scanning Spot Size", "FL", "2", 0, 0},
    { 0x300A039A, "Number of Paintings", "IS", "1", 0, 0},
    { 0x300A03A0, "Ion Tolerance Table Sequence", "SQ", "1", 0, 0},
    { 0x300A03A2, "Ion Beam Sequence", "SQ", "1", 0, 0},
    { 0x300A03A4, "Ion Beam Limiting Device Sequence", "SQ", "1", 0, 0},
    { 0x300A03A6, "Ion Block Sequence", "SQ", "1", 0, 0},
    { 0x300A03A8, "Ion Control Point Sequence", "SQ", "1", 0, 0},
    { 0x300A03AA, "Ion Wedge Sequence", "SQ", "1", 0, 0},
    { 0x300A03AC, "Ion Wedge Position Sequence", "SQ", "1", 0, 0},
    { 0x300A0401, "Referenced Setup Image Sequence", "SQ", "1", 0, 0},
    { 0x300A0402, "Setup Image Comment", "ST", "1", 0, 0},
    { 0x300A0410, "Motion Synchronization Sequence", "SQ", "1", 0, 0},
    { 0x300A0412, "Control Point Orientation", "FL", "3", 0, 0},
    { 0x300A0420, "General Accessory Sequence", "SQ", "1", 0, 0},
    { 0x300A0421, "General Accessory ID", "CS", "1", 0, 0},
    { 0x300A0422, "General Accessory Description", "ST", "1", 0, 0},
    { 0x300A0423, "General Accessory Type", "SH", "1", 0, 0},
    { 0x300A0424, "General Accessory Number", "IS", "1", 0, 0},
    { 0x300C0002, "Referenced RT Plan Sequence", "SQ", "1", 0, 0},
    { 0x300C0004, "Referenced Beam Sequence", "SQ", "1", 0, 0},
    { 0x300C0006, "Referenced Beam Number", "IS", "1", 0, 0},
    { 0x300C0007, "Referenced Reference Image Number", "IS", "1", 0, 0},
    { 0x300C0008, "Start Cumulative Meterset Weight", "DS", "1", 0, 0},
    { 0x300C0009, "End Cumulative Meterset Weight", "DS", "1", 0, 0},
    { 0x300C000A, "Referenced Brachy Application Setup Sequence", "SQ", "1", 0, 0},
    { 0x300C000C, "Referenced Brachy Application Setup Number", "IS", "1", 0, 0},
    { 0x300C000E, "Referenced Source Number", "IS", "1", 0, 0},
    { 0x300C0020, "Referenced Fraction Group Sequence", "SQ", "1", 0, 0},
    { 0x300C0022, "Referenced Fraction Group Number", "IS", "1", 0, 0},
    { 0x300C0040, "Referenced Verification Image Sequence", "SQ", "1", 0, 0},
    { 0x300C0042, "Referenced Reference Image Sequence", "SQ", "1", 0, 0},
    { 0x300C0050, "Referenced Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x300C0051, "Referenced Dose Reference Number", "IS", "1", 0, 0},
    { 0x300C0055, "Brachy Referenced Dose Reference Sequence", "SQ", "1", 0, 0},
    { 0x300C0060, "Referenced Structure Set Sequence", "SQ", "1", 0, 0},
    { 0x300C006A, "Referenced Patient Setup Number", "IS", "1", 0, 0},
    { 0x300C0080, "Referenced Dose Sequence", "SQ", "1", 0, 0},
    { 0x300C00A0, "Referenced Tolerance Table Number", "IS", "1", 0, 0},
    { 0x300C00B0, "Referenced Bolus Sequence", "SQ", "1", 0, 0},
    { 0x300C00C0, "Referenced Wedge Number", "IS", "1", 0, 0},
    { 0x300C00D0, "Referenced Compensator Number", "IS", "1", 0, 0},
    { 0x300C00E0, "Referenced Block Number", "IS", "1", 0, 0},
    { 0x300C00F0, "Referenced Control Point Index", "IS", "1", 0, 0},
    { 0x300C00F2, "Referenced Control Point Sequence", "SQ", "1", 0, 0},
    { 0x300C00F4, "Referenced Start Control Point Index", "IS", "1", 0, 0},
    { 0x300C00F6, "Referenced Stop Control Point Index", "IS", "1", 0, 0},
    { 0x300C0100, "Referenced Range Shifter Number", "IS", "1", 0, 0},
    { 0x300C0102, "Referenced Lateral Spreading Device Number", "IS", "1", 0, 0},
    { 0x300C0104, "Referenced Range Modulator Number", "IS", "1", 0, 0},
    { 0x300E0002, "Approval Status", "CS", "1", 0, 0},
    { 0x300E0004, "Review Date", "DA", "1", 0, 0},
    { 0x300E0005, "Review Time", "TM", "1", 0, 0},
    { 0x300E0008, "Reviewer Name", "PN", "1", 0, 0},
    { 0x40000010, "Arbitrary", "LT", "1", -1, 0},
    { 0x40004000, "Text Comments", "LT", "1", -1, 0},
    { 0x40080040, "Results ID", "SH", "1", -1, 0},
    { 0x40080042, "Results ID Issuer", "LO", "1", -1, 0},
    { 0x40080050, "Referenced Interpretation Sequence", "SQ", "1", -1, 0},
    { 0x40080100, "Interpretation Recorded Date", "DA", "1", -1, 0},
    { 0x40080101, "Interpretation Recorded Time", "TM", "1", -1, 0},
    { 0x40080102, "Interpretation Recorder", "PN", "1", -1, 0},
    { 0x40080103, "Reference to Recorded Sound", "LO", "1", -1, 0},
    { 0x40080108, "Interpretation Transcription Date", "DA", "1", -1, 0},
    { 0x40080109, "Interpretation Transcription Time", "TM", "1", -1, 0},
    { 0x4008010A, "Interpretation Transcriber", "PN", "1", -1, 0},
    { 0x4008010B, "Interpretation Text", "ST", "1", -1, 0},
    { 0x4008010C, "Interpretation Author", "PN", "1", -1, 0},
    { 0x40080111, "Interpretation Approver Sequence", "SQ", "1", -1, 0},
    { 0x40080112, "Interpretation Approval Date", "DA", "1", -1, 0},
    { 0x40080113, "Interpretation Approval Time", "TM", "1", -1, 0},
    { 0x40080114, "Physician Approving Interpretation", "PN", "1", -1, 0},
    { 0x40080115, "Interpretation Diagnosis Description", "LT", "1", -1, 0},
    { 0x40080117, "Interpretation Diagnosis Code Sequence", "SQ", "1", -1, 0},
    { 0x40080118, "Results Distribution List Sequence", "SQ", "1", -1, 0},
    { 0x40080119, "Distribution Name", "PN", "1", -1, 0},
    { 0x4008011A, "Distribution Address", "LO", "1", -1, 0},
    { 0x40080200, "Interpretation ID", "SH", "1", -1, 0},
    { 0x40080202, "Interpretation ID Issuer", "LO", "1", -1, 0},
    { 0x40080210, "Interpretation Type ID", "CS", "1", -1, 0},
    { 0x40080212, "Interpretation Status ID", "CS", "1", -1, 0},
    { 0x40080300, "Impressions", "ST", "1", -1, 0},
    { 0x40084000, "Results Comments", "ST", "1", -1, 0},
    { 0x4FFE0001, "MAC Parameters Sequence", "SQ", "1", 0, 0},
    { 0x50000005, "Curve Dimensions", "US", "1", -1, 0},
    { 0x50000010, "Number of Points", "US", "1", -1, 0},
    { 0x50000020, "Type of Data", "CS", "1", -1, 0},
    { 0x50000022, "Curve Description", "LO", "1", -1, 0},
    { 0x50000030, "Axis Units", "SH", "1-n", -1, 0},
    { 0x50000040, "Axis Labels", "SH", "1-n", -1, 0},
    { 0x50000103, "Data Value Representation", "US", "1", -1, 0},
    { 0x50000104, "Minimum Coordinate Value", "US", "1-n", -1, 0},
    { 0x50000105, "Maximum Coordinate Value", "US", "1-n", -1, 0},
    { 0x50000106, "Curve Range", "SH", "1-n", -1, 0},
    { 0x50000110, "Curve Data Descriptor", "US", "1-n", -1, 0},
    { 0x50000112, "Coordinate Start Value", "US", "1-n", -1, 0},
    { 0x50000114, "Coordinate Step Value", "US", "1-n", -1, 0},
    { 0x50001001, "Curve Activation Layer", "CS", "1", -1, 0},
    { 0x50002000, "Audio Type", "US", "1", -1, 0},
    { 0x50002002, "Audio Sample Format", "US", "1", -1, 0},
    { 0x50002004, "Number of Channels", "US", "1", -1, 0},
    { 0x50002006, "Number of Samples", "UL", "1", -1, 0},
    { 0x50002008, "Sample Rate", "UL", "1", -1, 0},
    { 0x5000200A, "Total Time", "UL", "1", -1, 0},
    { 0x5000200C, "Audio Sample Data", "OW or OB", "1", -1, 0},
    { 0x5000200E, "Audio Comments", "LT", "1", -1, 0},
    { 0x50002500, "Curve Label", "LO", "1", -1, 0},
    { 0x50002600, "Curve Referenced Overlay Sequence", "SQ", "1", -1, 0},
    { 0x50002610, "Curve Referenced Overlay Group", "US", "1", -1, 0},
    { 0x50003000, "Curve Data", "OW or OB", "1", -1, 0},
    { 0x52009229, "Shared Functional Groups Sequence", "SQ", "1", 0, 0},
    { 0x52009230, "Per-frame Functional Groups Sequence", "SQ", "1", 0, 0},
    { 0x54000100, "Waveform Sequence", "SQ", "1", 0, 0},
    { 0x54000110, "Channel Minimum Value", "OB or OW", "1", 0, 0},
    { 0x54000112, "Channel Maximum Value", "OB or OW", "1", 0, 0},
    { 0x54001004, "Waveform Bits Allocated", "US", "1", 0, 0},
    { 0x54001006, "Waveform Sample Interpretation", "CS", "1", 0, 0},
    { 0x5400100A, "Waveform Padding Value", "OB or OW", "1", 0, 0},
    { 0x54001010, "Waveform Data", "OB or OW", "1", 0, 0},
    { 0x56000010, "First Order Phase Correction Angle", "OF", "1", 0, 0},
    { 0x56000020, "Spectroscopy Data", "OF", "1", 0, 0},
    { 0x60000010, "Overlay Rows", "US", "1", 0, 0},
    { 0x60000011, "Overlay Columns", "US", "1", 0, 0},
    { 0x60000012, "Overlay Planes", "US", "1", -1, 0},
    { 0x60000015, "Number of Frames in Overlay", "IS", "1", 0, 0},
    { 0x60000022, "Overlay Description", "LO", "1", 0, 0},
    { 0x60000040, "Overlay Type", "CS", "1", 0, 0},
    { 0x60000045, "Overlay Subtype", "LO", "1", 0, 0},
    { 0x60000050, "Overlay Origin", "SS", "2", 0, 0},
    { 0x60000051, "Image Frame Origin", "US", "1", 0, 0},
    { 0x60000052, "Overlay Plane Origin", "US", "1", -1, 0},
    { 0x60000060, "Overlay Compression Code", "CS", "1", -1, 0},
    { 0x60000061, "Overlay Compression Originator", "SH", "1", -1, 0},
    { 0x60000062, "Overlay Compression Label", "SH", "1", -1, 0},
    { 0x60000063, "Overlay Compression Description", "CS", "1", -1, 0},
    { 0x60000066, "Overlay Compression Step Pointers", "AT", "1-n", -1, 0},
    { 0x60000068, "Overlay Repeat Interval", "US", "1", -1, 0},
    { 0x60000069, "Overlay Bits Grouped", "US", "1", -1, 0},
    { 0x60000100, "Overlay Bits Allocated", "US", "1", 0, 0},
    { 0x60000102, "Overlay Bit Position", "US", "1", 0, 0},
    { 0x60000110, "Overlay Format", "CS", "1", -1, 0},
    { 0x60000200, "Overlay Location", "US", "1", -1, 0},
    { 0x60000800, "Overlay Code Label", "CS", "1-n", -1, 0},
    { 0x60000802, "Overlay Number of Tables", "US", "1", -1, 0},
    { 0x60000803, "Overlay Code Table Location", "AT", "1-n", -1, 0},
    { 0x60000804, "Overlay Bits For Code Word", "US", "1", -1, 0},
    { 0x60001001, "Overlay Activation Layer", "CS", "1", 0, 0},
    { 0x60001100, "Overlay Descriptor - Gray", "US", "1", -1, 0},
    { 0x60001101, "Overlay Descriptor - Red", "US", "1", -1, 0},
    { 0x60001102, "Overlay Descriptor - Green", "US", "1", -1, 0},
    { 0x60001103, "Overlay Descriptor - Blue", "US", "1", -1, 0},
    { 0x60001200, "Overlays- Gray", "US", "1-n", -1, 0},
    { 0x60001201, "Overlays - Red", "US", "1-n", -1, 0},
    { 0x60001202, "Overlays - Green", "US", "1-n", -1, 0},
    { 0x60001203, "Overlays- Blue", "US", "1-n", -1, 0},
    { 0x60001301, "ROI Area", "IS", "1", 0, 0},
    { 0x60001302, "ROI Mean", "DS", "1", 0, 0},
    { 0x60001303, "ROI Standard Deviation", "DS", "1", 0, 0},
    { 0x60001500, "Overlay Label", "LO", "1", 0, 0},
    { 0x60003000, "Overlay Data", "OB or OW", "1", 0, 0},
    { 0x60004000, "Overlay Comments", "LT", "1", -1, 0},
    { 0x7FE00010, "Pixel Data", "OW or OB", "1", 0, 0},
    { 0x7FE00020, "Coefficients SDVN", "OW", "1", -1, 0},
    { 0x7FE00030, "Coefficients SDHN", "OW", "1", -1, 0},
    { 0x7FE00040, "Coefficients SDDN", "OW", "1", -1, 0},
    { 0x7F000010, "Variable Pixel Data", "OW or OB", "1", -1, 0},
    { 0x7F000011, "Variable Next Data Group", "US", "1", -1, 0},
    { 0x7F000020, "Variable Coefficients SDVN", "OW", "1", -1, 0},
    { 0x7F000030, "Variable Coefficients SDHN", "OW", "1", -1, 0},
    { 0x7F000040, "Variable Coefficients SDDN", "OW", "1", -1, 0},
    { 0xFFFAFFFA, "Digital Signatures Sequence", "SQ", "1", 0, 0},
    { 0xFFFCFFFC, "Data Set Trailing Padding", "OB", "1", 0, 0},
    { 0xFFFEE000, "Item", "see note", "1", 0, 0},
    { 0xFFFEE00D, "Item Delimitation Item", "see note", "1", 0, 0},
    { 0xFFFEE0DD, "Sequence Delimitation Item", "see note", "1", 0, 0},
    { 0x00020000, "File Meta Information Group Length", "UL", "1", 0, 0},
    { 0x00020001, "File Meta Information Version", "OB", "1", 0, 0},
    { 0x00020002, "Media Storage SOP Class UID", "UI", "1", 0, 0},
    { 0x00020003, "Media Storage SOP Instance UID", "UI", "1", 0, 0},
    { 0x00020010, "Transfer Syntax UID", "UI", "1", 0, 0},
    { 0x00020012, "Implementation Class UID", "UI", "1", 0, 0},
    { 0x00020013, "Implementation Version Name", "SH", "1", 0, 0},
    { 0x00020016, "Source Application Entity Title", "AE", "1", 0, 0},
    { 0x00020100, "Private Information Creator UID", "UI", "1", 0, 0},
    { 0x00020102, "Private Information", "OB", "1", 0, 0},
    { 0x00041130, "File-set ID", "CS", "1", 0, 0},
    { 0x00041141, "File-set Descriptor File ID", "CS", "1-8", 0, 0},
    { 0x00041142, "Specific Character Set of File-set Descriptor File", "CS", "1", 0, 0},
    { 0x00041200, "Offset of the First Directory Record of the Root Directory Entity", "UL", "1", 0, 0},
    { 0x00041202, "Offset of the Last Directory Record of the Root Directory Entity", "UL", "1", 0, 0},
    { 0x00041212, "File-set Consistency Flag", "US", "1", 0, 0},
    { 0x00041220, "Directory Record Sequence", "SQ", "1", 0, 0},
    { 0x00041400, "Offset of the Next Directory Record", "UL", "1", 0, 0},
    { 0x00041410, "Record In-use Flag", "US", "1", 0, 0},
    { 0x00041420, "Offset of Referenced Lower-Level Directory Entity", "UL", "1", 0, 0},
    { 0x00041430, "Directory Record Type", "CS", "1", 0, 0},
    { 0x00041432, "Private Record UID", "UI", "1", 0, 0},
    { 0x00041500, "Referenced File ID", "CS", "1-8", 0, 0},
    { 0x00041504, "MRDR Directory Record Offset", "UL", "1", -1, 0},
    { 0x00041510, "Referenced SOP Class UID in File", "UI", "1", 0, 0},
    { 0x00041511, "Referenced SOP Instance UID in File", "UI", "1", 0, 0},
    { 0x00041512, "Referenced Transfer Syntax UID in File", "UI", "1", 0, 0},
    { 0x0004151A, "Referenced Related General SOP Class UID in File", "UI", "1-n", 0, 0},
    { 0x00041600, "Number of References", "UL", "1", -1, 0},
};

/* ---------------------------------------------------------------------
 * DICOM UID Definitions

 * Part 6 lists following different UID Types (2006-2008)

 * Application Context Name
 * Coding Scheme
 * DICOM UIDs as a Coding Scheme
 * LDAP OID
 * Meta SOP Class
 * SOP Class
 * Service Class
 * Transfer Syntax
 * Well-known Print Queue SOP Instance
 * Well-known Printer SOP Instance
 * Well-known SOP Instance
 * Well-known frame of reference
 */

typedef struct dcm_uid {
    const gchar *value;
    const gchar *name;
    const gchar *type;
} dcm_uid_t;

static dcm_uid_t dcm_uid_data[] = {
    { "1.2.840.10008.1.1", "Verification SOP Class", "SOP Class"},
    { "1.2.840.10008.1.2", "Implicit VR Little Endian", "Transfer Syntax"},
    { "1.2.840.10008.1.2.1", "Explicit VR Little Endian", "Transfer Syntax"},
    { "1.2.840.10008.1.2.1.99", "Deflated Explicit VR Little Endian", "Transfer Syntax"},
    { "1.2.840.10008.1.2.2", "Explicit VR Big Endian", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.50", "JPEG Baseline (Process 1): Default Transfer Syntax for Lossy JPEG 8 Bit Image Compression", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.51", "JPEG Extended (Process 2 & 4): Default Transfer Syntax for Lossy JPEG 12 Bit Image Compression (Process 4 only)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.52", "JPEG Extended (Process 3 & 5) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.53", "JPEG Spectral Selection, Non-Hierarchical (Process 6 & 8) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.54", "JPEG Spectral Selection, Non-Hierarchical (Process 7 & 9) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.55", "JPEG Full Progression, Non-Hierarchical (Process 10 & 12) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.56", "JPEG Full Progression, Non-Hierarchical (Process 11 & 13) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.57", "JPEG Lossless, Non-Hierarchical (Process 14)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.58", "JPEG Lossless, Non-Hierarchical (Process 15) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.59", "JPEG Extended, Hierarchical (Process 16 & 18) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.60", "JPEG Extended, Hierarchical (Process 17 & 19) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.61", "JPEG Spectral Selection, Hierarchical (Process 20 & 22) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.62", "JPEG Spectral Selection, Hierarchical (Process 21 & 23) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.63", "JPEG Full Progression, Hierarchical (Process 24 & 26) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.64", "JPEG Full Progression, Hierarchical (Process 25 & 27) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.65", "JPEG Lossless, Hierarchical (Process 28) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.66", "JPEG Lossless, Hierarchical (Process 29) (Retired)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.70", "JPEG Lossless, Non-Hierarchical, First-Order Prediction (Process 14 [Selection Value 1]): Default Transfer Syntax for Lossless JPEG Image Compression", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.80", "JPEG-LS Lossless Image Compression", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.81", "JPEG-LS Lossy (Near-Lossless) Image Compression", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.90", "JPEG 2000 Image Compression (Lossless Only)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.91", "JPEG 2000 Image Compression", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.92", "JPEG 2000 Part 2 Multi-component Image Compression (Lossless Only)", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.93", "JPEG 2000 Part 2 Multi-component Image Compression", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.94", "JPIP Referenced", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.95", "JPIP Referenced Deflate", "Transfer Syntax"},
    { "1.2.840.10008.1.2.4.100", "MPEG2 Main Profile @ Main Level", "Transfer Syntax"},
    { "1.2.840.10008.1.2.5", "RLE Lossless", "Transfer Syntax"},
    { "1.2.840.10008.1.2.6.1", "RFC 2557 MIME encapsulation", "Transfer Syntax"},
    { "1.2.840.10008.1.2.6.2", "XML Encoding", "Transfer Syntax"},
    { "1.2.840.10008.1.3.10", "Media Storage Directory Storage", "SOP Class"},
    { "1.2.840.10008.1.4.1.1", "Talairach Brain Atlas Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.2", "SPM2 T1 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.3", "SPM2 T2 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.4", "SPM2 PD Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.5", "SPM2 EPI Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.6", "SPM2 FIL T1 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.7", "SPM2 PET Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.8", "SPM2 TRANSM Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.9", "SPM2 SPECT Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.10", "SPM2 GRAY Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.11", "SPM2 WHITE Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.12", "SPM2 CSF Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.13", "SPM2 BRAINMASK Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.14", "SPM2 AVG305T1 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.15", "SPM2 AVG152T1 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.16", "SPM2 AVG152T2 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.17", "SPM2 AVG152PD Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.1.18", "SPM2 SINGLESUBJT1 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.2.1", "ICBM 452 T1 Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.4.2.2", "ICBM Single Subject MRI Frame of Reference", "Well-known frame of reference"},
    { "1.2.840.10008.1.9", "Basic Study Content Notification SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.1.20.1", "Storage Commitment Push Model SOP Class", "SOP Class"},
    { "1.2.840.10008.1.20.1.1", "Storage Commitment Push Model SOP Instance", "Well-known SOP Instance"},
    { "1.2.840.10008.1.20.2", "Storage Commitment Pull Model SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.1.20.2.1", "Storage Commitment Pull Model SOP Instance (Retired)", "Well-known SOP Instance"},
    { "1.2.840.10008.1.40", "Procedural Event Logging SOP Class", "SOP Class"},
    { "1.2.840.10008.1.40.1", "Procedural Event Logging SOP Instance", "Well-known SOP Instance"},
    { "1.2.840.10008.1.42", "Substance Administration Logging SOP Class", "SOP Class"},
    { "1.2.840.10008.1.42.1", "Substance Administration Logging SOP Instance", "Well-known SOP Instance"},
    { "1.2.840.10008.2.6.1", "DICOM UID Registry", "DICOM UIDs as a Coding Scheme"},
    { "1.2.840.10008.2.16.4", "DICOM Controlled Terminology", "Coding Scheme"},
    { "1.2.840.10008.3.1.1.1", "DICOM Application Context Name", "Application Context Name"},
    { "1.2.840.10008.3.1.2.1.1", "Detached Patient Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.3.1.2.1.4", "Detached Patient Management Meta SOP Class (Retired)", "Meta SOP Class"},
    { "1.2.840.10008.3.1.2.2.1", "Detached Visit Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.3.1.2.3.1", "Detached Study Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.3.1.2.3.2", "Study Component Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.3.1.2.3.3", "Modality Performed Procedure Step SOP Class", "SOP Class"},
    { "1.2.840.10008.3.1.2.3.4", "Modality Performed Procedure Step Retrieve SOP Class", "SOP Class"},
    { "1.2.840.10008.3.1.2.3.5", "Modality Performed Procedure Step Notification SOP Class", "SOP Class"},
    { "1.2.840.10008.3.1.2.5.1", "Detached Results Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.3.1.2.5.4", "Detached Results Management Meta SOP Class (Retired)", "Meta SOP Class"},
    { "1.2.840.10008.3.1.2.5.5", "Detached Study Management Meta SOP Class (Retired)", "Meta SOP Class"},
    { "1.2.840.10008.3.1.2.6.1", "Detached Interpretation Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.4.2", "Storage Service Class", "Service Class"},
    { "1.2.840.10008.5.1.1.1", "Basic Film Session SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.2", "Basic Film Box SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.4", "Basic Grayscale Image Box SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.4.1", "Basic Color Image Box SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.4.2", "Referenced Image Box SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.9", "Basic Grayscale Print Management Meta SOP Class", "Meta SOP Class"},
    { "1.2.840.10008.5.1.1.9.1", "Referenced Grayscale Print Management Meta SOP Class (Retired)", "Meta SOP Class"},
    { "1.2.840.10008.5.1.1.14", "Print Job SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.15", "Basic Annotation Box SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.16", "Printer SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.16.376", "Printer Configuration Retrieval SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.17", "Printer SOP Instance", "Well-known Printer SOP Instance"},
    { "1.2.840.10008.5.1.1.17.376", "Printer Configuration Retrieval SOP Instance", "Well-known Printer SOP Instance"},
    { "1.2.840.10008.5.1.1.18", "Basic Color Print Management Meta SOP Class", "Meta SOP Class"},
    { "1.2.840.10008.5.1.1.18.1", "Referenced Color Print Management Meta SOP Class (Retired)", "Meta SOP Class"},
    { "1.2.840.10008.5.1.1.22", "VOI LUT Box SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.23", "Presentation LUT SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.1.24", "Image Overlay Box SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.24.1", "Basic Print Image Overlay Box SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.25", "Print Queue SOP Instance (Retired)", "Well-known Print Queue SOP Instance"},
    { "1.2.840.10008.5.1.1.26", "Print Queue Management SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.27", "Stored Print Storage SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.29", "Hardcopy Grayscale Image Storage SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.30", "Hardcopy Color Image Storage SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.31", "Pull Print Request SOP Class (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.1.32", "Pull Stored Print Management Meta SOP Class (Retired)", "Meta SOP Class"},
    { "1.2.840.10008.5.1.1.33", "Media Creation Management SOP Class UID", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1", "Computed Radiography Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1.1", "Digital X-Ray Image Storage - For Presentation", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1.1.1", "Digital X-Ray Image Storage - For Processing", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1.2", "Digital Mammography X-Ray Image Storage - For Presentation", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1.2.1", "Digital Mammography X-Ray Image Storage - For Processing", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1.3", "Digital Intra-oral X-Ray Image Storage - For Presentation", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.1.3.1", "Digital Intra-oral X-Ray Image Storage - For Processing", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.2", "CT Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.2.1", "Enhanced CT Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.3", "Ultrasound Multi-frame Image Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.3.1", "Ultrasound Multi-frame Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.4", "MR Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.4.1", "Enhanced MR Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.4.2", "MR Spectroscopy Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.5", "Nuclear Medicine Image Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.6", "Ultrasound Image Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.6.1", "Ultrasound Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.7", "Secondary Capture Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.7.1", "Multi-frame Single Bit Secondary Capture Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.7.2", "Multi-frame Grayscale Byte Secondary Capture Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.7.3", "Multi-frame Grayscale Word Secondary Capture Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.7.4", "Multi-frame True Color Secondary Capture Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.8", "Standalone Overlay Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9", "Standalone Curve Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.1", "Waveform Storage - Trial (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.1.1", "12-lead ECG Waveform Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.1.2", "General ECG Waveform Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.1.3", "Ambulatory ECG Waveform Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.2.1", "Hemodynamic Waveform Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.3.1", "Cardiac Electrophysiology Waveform Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.9.4.1", "Basic Voice Audio Waveform Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.10", "Standalone Modality LUT Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.11", "Standalone VOI LUT Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.11.1", "Grayscale Softcopy Presentation State Storage SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.11.2", "Color Softcopy Presentation State Storage SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.11.3", "Pseudo-Color Softcopy Presentation State Storage SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.11.4", "Blending Softcopy Presentation State Storage SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.12.1", "X-Ray Angiographic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.12.1.1", "Enhanced XA Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.12.2", "X-Ray Radiofluoroscopic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.12.2.1", "Enhanced XRF Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.13.1.1", "X-Ray 3D Angiographic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.13.1.2", "X-Ray 3D Craniofacial Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.12.3", "X-Ray Angiographic Bi-Plane Image Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.20", "Nuclear Medicine Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.66", "Raw Data Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.66.1", "Spatial Registration Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.66.2", "Spatial Fiducials Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.66.3", "Deformable Spatial Registration Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.66.4", "Segmentation Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.67", "Real World Value Mapping Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1", "VL Image Storage - Trial (Retired)", ""},
    { "1.2.840.10008.5.1.4.1.1.77.2", "VL Multi-frame Image Storage - Trial (Retired)", ""},
    { "1.2.840.10008.5.1.4.1.1.77.1.1", "VL Endoscopic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.1.1", "Video Endoscopic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.2", "VL Microscopic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.2.1", "Video Microscopic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.3", "VL Slide-Coordinates Microscopic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.4", "VL Photographic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.4.1", "Video Photographic Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.5.1", "Ophthalmic Photography 8 Bit Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.5.2", "Ophthalmic Photography 16 Bit Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.5.3", "Stereometric Relationship Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.77.1.5.4", "Ophthalmic Tomography Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.1", "Text SR Storage - Trial (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.2", "Audio SR Storage - Trial (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.3", "Detail SR Storage - Trial (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.4", "Comprehensive SR Storage - Trial (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.11", "Basic Text SR Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.22", "Enhanced SR Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.33", "Comprehensive SR Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.40", "Procedure Log Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.50", "Mammography CAD SR Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.59", "Key Object Selection Document Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.65", "Chest CAD SR Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.88.67", "X-Ray Radiation Dose SR Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.104.1", "Encapsulated PDF Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.104.2", "Encapsulated CDA Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.128", "Positron Emission Tomography Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.129", "Standalone PET Curve Storage (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.1", "RT Image Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.2", "RT Dose Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.3", "RT Structure Set Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.4", "RT Beams Treatment Record Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.5", "RT Plan Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.6", "RT Brachy Treatment Record Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.7", "RT Treatment Summary Record Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.8", "RT Ion Plan Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.1.481.9", "RT Ion Beams Treatment Record Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.1.1", "Patient Root Query/Retrieve Information Model - FIND", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.1.2", "Patient Root Query/Retrieve Information Model - MOVE", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.1.3", "Patient Root Query/Retrieve Information Model - GET", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.2.1", "Study Root Query/Retrieve Information Model - FIND", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.2.2", "Study Root Query/Retrieve Information Model - MOVE", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.2.3", "Study Root Query/Retrieve Information Model - GET", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.3.1", "Patient/Study Only Query/Retrieve Information Model - FIND (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.3.2", "Patient/Study Only Query/Retrieve Information Model - MOVE (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.1.2.3.3", "Patient/Study Only Query/Retrieve Information Model - GET (Retired)", "SOP Class"},
    { "1.2.840.10008.5.1.4.31", "Modality Worklist Information Model - FIND", "SOP Class"},
    { "1.2.840.10008.5.1.4.32.1", "General Purpose Worklist Information Model - FIND", "SOP Class"},
    { "1.2.840.10008.5.1.4.32.2", "General Purpose Scheduled Procedure Step SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.32.3", "General Purpose Performed Procedure Step SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.32", "General Purpose Worklist Management Meta SOP Class", "Meta SOP Class"},
    { "1.2.840.10008.5.1.4.33", "Instance Availability Notification SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.1", "RT Beams Delivery Instruction Storage (Supplement 74 Frozen Draft)", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.2", "RT Conventional Machine Verification (Supplement 74 Frozen Draft)", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.3", "RT Ion Machine Verification (Supplement 74 Frozen Draft)", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.4", "Unified Worklist and Procedure Step Service Class", "Service Class"},
    { "1.2.840.10008.5.1.4.34.4.1", "Unified Procedure Step - Push SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.4.2", "Unified Procedure Step - Watch SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.4.3", "Unified Procedure Step - Pull SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.4.4", "Unified Procedure Step - Event SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.34.5", "Unified Worklist and Procedure Step SOP Instance", "Well-known SOP Instance"},
    { "1.2.840.10008.5.1.4.37.1", "General Relevant Patient Information Query", "SOP Class"},
    { "1.2.840.10008.5.1.4.37.2", "Breast Imaging Relevant Patient Information Query", "SOP Class"},
    { "1.2.840.10008.5.1.4.37.3", "Cardiac Relevant Patient Information Query", "SOP Class"},
    { "1.2.840.10008.5.1.4.38.1", "Hanging Protocol Storage", "SOP Class"},
    { "1.2.840.10008.5.1.4.38.2", "Hanging Protocol Information Model - FIND", "SOP Class"},
    { "1.2.840.10008.5.1.4.38.3", "Hanging Protocol Information Model - MOVE", "SOP Class"},
    { "1.2.840.10008.5.1.4.41", "Product Characteristics Query SOP Class", "SOP Class"},
    { "1.2.840.10008.5.1.4.42", "Substance Approval Query SOP Class", "SOP Class"},
    { "1.2.840.10008.15.0.3.1", "dicomDeviceName", "LDAP OID"},
    { "1.2.840.10008.15.0.3.2", "dicomDescription", "LDAP OID"},
    { "1.2.840.10008.15.0.3.3", "dicomManufacturer", "LDAP OID"},
    { "1.2.840.10008.15.0.3.4", "dicomManufacturerModelName", "LDAP OID"},
    { "1.2.840.10008.15.0.3.5", "dicomSoftwareVersion", "LDAP OID"},
    { "1.2.840.10008.15.0.3.6", "dicomVendorData", "LDAP OID"},
    { "1.2.840.10008.15.0.3.7", "dicomAETitle", "LDAP OID"},
    { "1.2.840.10008.15.0.3.8", "dicomNetworkConnectionReference", "LDAP OID"},
    { "1.2.840.10008.15.0.3.9", "dicomApplicationCluster", "LDAP OID"},
    { "1.2.840.10008.15.0.3.10", "dicomAssociationInitiator", "LDAP OID"},
    { "1.2.840.10008.15.0.3.11", "dicomAssociationAcceptor", "LDAP OID"},
    { "1.2.840.10008.15.0.3.12", "dicomHostname", "LDAP OID"},
    { "1.2.840.10008.15.0.3.13", "dicomPort", "LDAP OID"},
    { "1.2.840.10008.15.0.3.14", "dicomSOPClass", "LDAP OID"},
    { "1.2.840.10008.15.0.3.15", "dicomTransferRole", "LDAP OID"},
    { "1.2.840.10008.15.0.3.16", "dicomTransferSyntax", "LDAP OID"},
    { "1.2.840.10008.15.0.3.17", "dicomPrimaryDeviceType", "LDAP OID"},
    { "1.2.840.10008.15.0.3.18", "dicomRelatedDeviceReference", "LDAP OID"},
    { "1.2.840.10008.15.0.3.19", "dicomPreferredCalledAETitle", "LDAP OID"},
    { "1.2.840.10008.15.0.3.20", "dicomTLSCyphersuite", "LDAP OID"},
    { "1.2.840.10008.15.0.3.21", "dicomAuthorizedNodeCertificateReference", "LDAP OID"},
    { "1.2.840.10008.15.0.3.22", "dicomThisNodeCertificateReference", "LDAP OID"},
    { "1.2.840.10008.15.0.3.23", "dicomInstalled", "LDAP OID"},
    { "1.2.840.10008.15.0.3.24", "dicomStationName", "LDAP OID"},
    { "1.2.840.10008.15.0.3.25", "dicomDeviceSerialNumber", "LDAP OID"},
    { "1.2.840.10008.15.0.3.26", "dicomInstitutionName", "LDAP OID"},
    { "1.2.840.10008.15.0.3.27", "dicomInstitutionAddress", "LDAP OID"},
    { "1.2.840.10008.15.0.3.28", "dicomInstitutionDepartmentName", "LDAP OID"},
    { "1.2.840.10008.15.0.3.29", "dicomIssuerOfPatientID", "LDAP OID"},
    { "1.2.840.10008.15.0.3.30", "dicomPreferredCallingAETitle", "LDAP OID"},
    { "1.2.840.10008.15.0.3.31", "dicomSupportedCharacterSet", "LDAP OID"},
    { "1.2.840.10008.15.0.4.1", "dicomConfigurationRoot", "LDAP OID"},
    { "1.2.840.10008.15.0.4.2", "dicomDevicesRoot", "LDAP OID"},
    { "1.2.840.10008.15.0.4.3", "dicomUniqueAETitlesRegistryRoot", "LDAP OID"},
    { "1.2.840.10008.15.0.4.4", "dicomDevice", "LDAP OID"},
    { "1.2.840.10008.15.0.4.5", "dicomNetworkAE", "LDAP OID"},
    { "1.2.840.10008.15.0.4.6", "dicomNetworkConnection", "LDAP OID"},
    { "1.2.840.10008.15.0.4.7", "dicomUniqueAETitle", "LDAP OID"},
    { "1.2.840.10008.15.0.4.8", "dicomTransferCapability", "LDAP OID"},

    { "1.2.840.113619.5.2", "Implicit VR Little Endian, Big Endian Pixels, GE Private", "Transfer Syntax"},

};

/* following definitions are used to call dissect_dcm_assoc_item() */
#define DCM_ITEM_VALUE_TYPE_UID	    1
#define DCM_ITEM_VALUE_TYPE_STRING  2
#define DCM_ITEM_VALUE_TYPE_UINT32  3

/* A few function declarations to ensure consitency*/

/* Per object, a xxx_new() and a xxx_get() function. The _get() will create one if specified. */

static dcm_state_t*	 dcm_state_new(void);
static dcm_state_t*	 dcm_state_get(packet_info *pinfo, gboolean create);

static dcm_state_assoc_t*   dcm_state_assoc_new (dcm_state_t *dcm_data, guint32 packet_no);
static dcm_state_assoc_t*   dcm_state_assoc_get (dcm_state_t *dcm_data, guint32 packet_no, gboolean create);
static dcm_state_pctx_t*    dcm_state_pctx_new	(dcm_state_assoc_t *assoc, guint8 pctx_id);
static dcm_state_pctx_t*    dcm_state_pctx_get	(dcm_state_assoc_t *assoc, guint8 pctx_id, gboolean create);
static dcm_state_pdv_t*	    dcm_state_pdv_new	(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset);
static dcm_state_pdv_t*	    dcm_state_pdv_get	(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset, gboolean create);

/* Following three functions by purpose only return int, since we request data consolidation */
static int  dissect_dcm_static	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* ToDo: The heuristic one should actually return true/false only */
static int  dissect_dcm_heuristic   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int  dissect_dcm_main	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_port_static);

/* And from here on, only use unsigned 32 bit values. Offset is always positive number in respect to the tvb buffer start */
static guint32  dissect_dcm_pdu	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset);

static guint32  dissect_dcm_assoc_detail(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,   dcm_state_assoc_t *assoc, guint32 offset, guint32 len);
static void	dissect_dcm_pctx	(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, guint32 offset, guint32 len, const gchar *pitem_prefix, gboolean request);
static void	dissect_dcm_assoc_item  (tvbuff_t *tvb, proto_tree *tree, guint32 offset, const gchar *pitem_prefix, int item_value_type, gchar **item_value, const gchar **item_description, int *hf_type, int *hf_len, int *hf_value, int ett_subtree);
static void	dissect_dcm_userinfo    (tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 len, const gchar *pitem_prefix);

static guint32  dissect_dcm_pdu_data	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, guint32 offset, guint32 pdu_len, gchar **pdu_data_description);
static guint32  dissect_dcm_pdv_header	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, guint32 offset, dcm_state_pdv_t **pdv);
static guint32	dissect_dcm_pdv_fragmented  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, guint32 offset, guint32 pdv_len, gchar **pdv_description);
static guint32	dissect_dcm_pdv_body	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_pdv_t *pdv, guint32 offset, guint32 pdv_body_len, gchar **pdv_description);

static guint32  dissect_dcm_tag		    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_pdv_t *pdv, guint32 offset, guint32 endpos, gboolean is_first_tag, gchar **tag_description, gboolean *end_of_seq_or_item);
static guint32  dissect_dcm_tag_open	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_pdv_t *pdv, guint32 offset, guint32 endpos, gboolean *is_first_tag);
static guint32  dissect_dcm_tag_value	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_pdv_t *pdv, guint32 offset, guint16 grp, guint16 elm, guint32 vl, guint32 vl_max, const gchar* vr, gchar **tag_value);

static void dcm_set_syntax		(dcm_state_pctx_t *pctx, gchar *xfer_uid, const gchar *xfer_desc);
static void dcm_export_create_object	(packet_info *pinfo, dcm_state_assoc_t *assoc, dcm_state_pdv_t *pdv);

static void

dcm_init(void)
{
    guint   i;

    /* Add UID objects to hash table */
    if (dcm_uid_table == NULL) {
	dcm_uid_table = g_hash_table_new(g_str_hash, g_str_equal);
	for (i = 0; i < array_length(dcm_uid_data); i++) {
	    g_hash_table_insert(dcm_uid_table, (gpointer) dcm_uid_data[i].value,
	    (gpointer) &dcm_uid_data[i]);
	}
    }

    /* Add Tag objects to hash table */
    if (dcm_tag_table == NULL) {
	dcm_tag_table = g_hash_table_new(NULL, NULL);
	for (i = 0; i < array_length(dcm_tag_data); i++) {
	    g_hash_table_insert(dcm_tag_table, GUINT_TO_POINTER(dcm_tag_data[i].tag),
	    (gpointer) &dcm_tag_data[i]);
	}
    }

   /* Add Status Values to hash table */
    if (dcm_status_table == NULL) {
	dcm_status_table = g_hash_table_new(NULL, NULL);
	for (i = 0; i < array_length(dcm_status_data); i++) {
	    g_hash_table_insert(dcm_status_table, GUINT_TO_POINTER((guint32)dcm_status_data[i].value),
	    (gpointer)&dcm_status_data[i]);
	}
    }

    /* Register processing of fragmented DICOM PDVs */
    fragment_table_init(&dcm_pdv_fragment_table);
    reassembled_table_init(&dcm_pdv_reassembled_table);
}

static dcm_state_t *
dcm_state_new(void)
{
    /* Not much fun. Just create very simple root structure */

    dcm_state_t *ds;

    ds = (dcm_state_t *) se_alloc0(sizeof(dcm_state_t));
    return ds;
}

static dcm_state_t *
dcm_state_get(packet_info *pinfo, gboolean create)
{

    /*	Get or create converstation and DICOM data structure if desired
	Return new or existing dicom struture, which is used to store context IDs and xfer Syntax
	Return NULL in case of the structure couldn't be created
    */

    conversation_t  *conv=NULL;
    dcm_state_t	    *dcm_data=NULL;

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
	pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

    if (conv == NULL) {
	/* Conversation does not exist, create one.
	   Usually set for the first packet already. Probably by dissect-tcp
	*/
	conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
	    pinfo->srcport, pinfo->destport, 0);
    }
    else {			/* conversation exists, try to get data already filled */
	dcm_data = (dcm_state_t *)conversation_get_proto_data(conv, proto_dcm);
    }


    if (dcm_data == NULL && create) {

	dcm_data = dcm_state_new();
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
    /* Create new accociation object and initalize the members */

    dcm_state_assoc_t *assoc;

    assoc = (dcm_state_assoc_t *) se_alloc0(sizeof(dcm_state_assoc_t));
    assoc->packet_no = packet_no;	    /* Identifier */

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

static dcm_state_assoc_t *
dcm_state_assoc_get(dcm_state_t *dcm_data, guint32 packet_no, gboolean create)
{
  /*  Find or create Association object.
      Return NULL, if Association was not found, based on packet number
  */

    dcm_state_assoc_t *assoc = NULL;

    assoc=dcm_data->first_assoc;

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
    /* Create new presentation context object and initalize the members */

    dcm_state_pctx_t *pctx=NULL;

    pctx = (dcm_state_pctx_t *)se_alloc0(sizeof(dcm_state_pctx_t));
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

    dcm_state_pctx_t *pctx =NULL;

    pctx = assoc->first_pctx;
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


static dcm_state_pdv_t*
dcm_state_pdv_new(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset)
{
    /* Create new PDV object and initalize the members */

    dcm_state_pdv_t *pdv = NULL;

    pdv = (dcm_state_pdv_t *) se_alloc0(sizeof(dcm_state_pdv_t));
    pdv->syntax = DCM_UNK;
    pdv->is_last_fragment = TRUE;	/* Continuation PDVs are more tricky */
    pdv->packet_no = packet_no;
    pdv->offset = offset;

    /* add to the end of the list list */
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

    dcm_state_pdv_t *pdv = NULL;

    pdv=pctx->first_pdv;

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

static const char *
dcm_pdu2str(guint8 item)
{
    const char *s = "";
    switch (item) {
    case 1: s = "ASSOC Request"; break;
    case 2: s = "ASSOC Accept"; break;
    case 3: s = "ASSOC Reject"; break;
    case 4: s = "Data"; break;
    case 5: s = "RELEASE Request"; break;
    case 6: s = "RELEASE Response"; break;
    case 7: s = "ABORT"; break;
    default: break;
    }
    return s;
}


static const char *
dcm_cmd2str(guint16 us)
{
    const char *s = "";
    /* there should be a better way to do this */
    switch (us) {
    case 0x0001:  s = "C-STORE-RQ"; break;
    case 0x8001:  s = "C-STORE-RSP"; break;
    case 0x0010:  s = "C-GET-RQ"; break;
    case 0x8010:  s = "C-GET-RSP"; break;
    case 0x0020:  s = "C-FIND-RQ"; break;
    case 0x8020:  s = "C-FIND-RSP"; break;
    case 0x0021:  s = "C-MOVE-RQ"; break;
    case 0x8021:  s = "C-MOVE-RSP"; break;
    case 0x0030:  s = "C-ECHO-RQ"; break;
    case 0x8030:  s = "C-ECHO-RSP"; break;
    case 0x0100:  s = "N-EVENT-REPORT-RQ"; break;
    case 0x8100:  s = "N-EVENT-REPORT-RSP"; break;
    case 0x0110:  s = "N-GET-RQ"; break;
    case 0x8110:  s = "N-GET-RSP"; break;
    case 0x0120:  s = "N-SET-RQ"; break;
    case 0x8120:  s = "N-SET-RSP"; break;
    case 0x0130:  s = "N-ACTION-RQ"; break;
    case 0x8130:  s = "N-ACTION-RSP"; break;
    case 0x0140:  s = "N-CREATE-RQ"; break;
    case 0x8140:  s = "N-CREATE-RSP"; break;
    case 0x0150:  s = "N-DELETE-RQ"; break;
    case 0x8150:  s = "N-DELETE-RSP"; break;
    case 0x0fff:  s = "C-CANCEL-RQ"; break;
    default: break;
    }
    return s;
}

static const gchar *
dcm_rsp2str(guint16 status_value)
{

    dcm_status_t    *status = NULL;

    const gchar *s = "";

    /*
	Clasification
	0x0000		: SUCCESS
	0x0001 & Bxxx	: WARNING
	0xFE00		: CANCEL
	0XFFxx		: PENDING

	All other	: FAILURE
    */

    /* Use specific text first */
    status = (dcm_status_t*) g_hash_table_lookup(dcm_status_table, GUINT_TO_POINTER((guint32)status_value));

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
	    /* At least came across 0xD001 in one capture */
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

    g_free(pctx->xfer_uid);	/* free prev allocated xfer */
    g_free(pctx->xfer_desc);	/* free prev allocated xfer */

    pctx->syntax = 0;
    pctx->xfer_uid = g_strdup(xfer_uid);
    pctx->xfer_desc = g_strdup(xfer_desc);

    /* this would be faster to skip the common parts, and have a FSA to
     * find the syntax.
     * Absent of coding that, this is in descending order of probability */
    if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2"))
	pctx->syntax = DCM_ILE;	 /* implicit little endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.1"))
	pctx->syntax = DCM_ELE;	 /* explicit little endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.2"))
	pctx->syntax = DCM_EBE;	 /* explicit big endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.113619.5.2"))
	pctx->syntax = DCM_ILE;	 /* implicit little endian, big endian pixels, GE private */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.4.70"))
	pctx->syntax = DCM_ELE;	 /* explicit little endian, jpeg */
    else if (0 == strncmp(xfer_uid, "1.2.840.10008.1.2.4", 18))
	pctx->syntax = DCM_ELE;	 /* explicit little endian, jpeg */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.1.99"))
	pctx->syntax = DCM_ELE;	 /* explicit little endian, deflated */
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
    /*  Only Explict Littele Endian is needed to create Metafile Header
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
    case DCM_VR_OW:
    case DCM_VR_OF:
    case DCM_VR_SQ:
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
	/*  Odd length: since buffer is 0 initalized, pad with a 0x00 */
	len += 1;
    }

    return dcm_export_create_tag_base(buffer, bufflen, offset, grp, elm, vr, (const guint8 *)value, len);
}


static guint8*
dcm_export_create_header(guint32 *dcm_header_len, gchar *sop_class_uid, gchar *sop_instance_uid, gchar *xfer_uid)
{
    guint8	*dcm_header=NULL;
    guint32	offset=0;
    guint32	offset_header_len=0;

#define DCM_HEADER_MAX 512

    dcm_header=(guint8 *)ep_alloc0(DCM_HEADER_MAX);   /* Slightly longer than needed */
						      /* The subsequent functions rely on a 0 intitalized buffer */
    offset=128;

    memmove(dcm_header+offset, "DICM", 4);
    offset+=4;

    offset_header_len=offset;	/* remember for later */

    offset+=12;

    /*
	(0002,0000)	File Meta Information Group Length  UL
	(0002,0001)	File Meta Information Version	    OB
	(0002,0002)	Media Storage SOP Class UID	    UI
	(0002,0003)	Media Storage SOP Instance UID	    UI
	(0002,0010)	Transfer Syntax UID		    UI
	(0002,0012)	Implementation Class UID	    UI
	(0002,0013)	Implementation Version Name	    SH
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

static void
dcm_export_create_object(packet_info *pinfo, dcm_state_assoc_t *assoc, dcm_state_pdv_t *pdv)
{

    /* Concat different PDVs into one buffer and add it to export object list
       This function caused quite a few crashes, with all the string pointers

       Every since the adding fragment_add_seq_next() and process_reassembled_data(),
       this function would not need to perform any reassembly anymore, but it's
       left unchagned, to still support export, even when global_dcm_reassemble
       is not set.

       Using process_reassembled_data(), all data will be in the last PDV, and all
       it's predecessor will zero data.
    */

    dicom_eo_t		*eo_info = NULL;

    dcm_state_pdv_t	*pdv_curr = NULL;
    dcm_state_pdv_t	*pdv_same_pkt = NULL;
    dcm_state_pctx_t	*pctx = NULL;

    guint8     *pdv_combined = NULL;
    guint8     *pdv_combined_curr = NULL;
    guint8     *dcm_header = NULL;
    guint32	pdv_combined_len = 0;
    guint32	dcm_header_len = 0;
    guint16	cnt_same_pkt = 1;
    gchar      *filename;
    const gchar *hostname;

    gchar	*sop_class_uid;
    gchar	*sop_instance_uid;

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

    if (strlen(assoc->ae_calling)>0 && strlen(assoc->ae_called)>0 ) {
	hostname = ep_strdup_printf("%s <-> %s", assoc->ae_calling, assoc->ae_called);
    }
    else {
	hostname = "AE title(s) unknown";
    }

    if (pdv->is_storage &&
	pdv_curr->sop_class_uid    && strlen(pdv_curr->sop_class_uid)>0 &&
	pdv_curr->sop_instance_uid && strlen(pdv_curr->sop_instance_uid)>0) {

	sop_class_uid = ep_strndup(pdv_curr->sop_class_uid, MAX_BUF_LEN);
	sop_instance_uid = ep_strndup(pdv_curr->sop_instance_uid, MAX_BUF_LEN);

	/* Make sure filename does not contain invalid character. Rather conservative.
	   Eventhough this should be a valid DICOM UID, apply the same filter rules
	   in case of bogus data.
	*/
	filename = ep_strdup_printf("%06d-%d-%s.dcm", pinfo->fd->num, cnt_same_pkt,
	    g_strcanon(pdv_curr->sop_instance_uid, G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS "-.", '-'));
    }
    else {
	/* No SOP Instance or SOP Class UID found in PDV. Use wireshark ones */

    	sop_class_uid = ep_strdup(WIRESHARK_MEDIA_STORAGE_SOP_CLASS_UID);
	sop_instance_uid = ep_strdup_printf("%s.%d.%d",
	    WIRESHARK_MEDIA_STORAGE_SOP_INSTANCE_UID_PREFIX, pinfo->fd->num, cnt_same_pkt);

	/* Make sure filename does not contain invalid character. Rather conservative.*/
	filename = ep_strdup_printf("%06d-%d-%s.dcm", pinfo->fd->num, cnt_same_pkt,
	    g_strcanon(pdv->desc, G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS "-.", '-'));

    }

    if (global_dcm_export_header) {
	if (pctx && pctx->xfer_uid && strlen(pctx->xfer_uid)>0) {
    	    dcm_header=dcm_export_create_header(&dcm_header_len, sop_class_uid, sop_instance_uid, pctx->xfer_uid);
	}
	else {
	    /* We are running blind, i.e. no presentation context/syntax found.
	       Don't invent one, so the meta header will miss
	       the transfer syntax UID tag (even though it is mandatory)
	    */
	    dcm_header=dcm_export_create_header(&dcm_header_len, sop_class_uid, sop_instance_uid, NULL);
	}
    }


    if (dcm_header_len + pdv_combined_len >= global_dcm_export_minsize) {
	/* Allocate the final size */

	/* The complete eo_info structure and its elements will be freed in
	   export_object.c -> eo_win_destroy_cb() using g_free()
	*/

	pdv_combined = (guint8 *)g_malloc0(dcm_header_len + pdv_combined_len);

	pdv_combined_curr = pdv_combined;

	if (dcm_header_len != 0) {  /* Will be 0 when global_dcm_export_header is FALSE */
	    memmove(pdv_combined, dcm_header, dcm_header_len);
	    pdv_combined_curr += dcm_header_len;
	}

	/* Copy PDV per PDV to target buffer */
	while (!pdv_curr->is_last_fragment) {
	    memmove(pdv_combined_curr, pdv_curr->data, pdv_curr->data_len);	    /* this is a copy not move */
	    g_free(pdv_curr->data);
	    pdv_combined_curr += pdv_curr->data_len;
	    pdv_curr = pdv_curr->next;
	}

	/* Last packet */
	memmove(pdv_combined_curr, pdv->data, pdv->data_len);	    /* this is a copy not a move */
	g_free(pdv_curr->data);

	/* Add to list */
	eo_info = (dicom_eo_t *)g_malloc0(sizeof(dicom_eo_t));
	eo_info->hostname = g_strdup(hostname);
	eo_info->filename = g_strdup(filename);
	eo_info->content_type = g_strdup(pdv->desc);

	eo_info->payload_data = pdv_combined;
	eo_info->payload_len  = dcm_header_len + pdv_combined_len;

	tap_queue_packet(dicom_eo_tap, pinfo, eo_info);
    }
}

static guint32
dissect_dcm_assoc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, dcm_state_assoc_t *assoc,
			 guint8 pdu_type, guint32 pdu_len)
{
    /*
     *	Decode association header
     */

    proto_item *assoc_header_pitem = NULL;
    proto_tree *assoc_header_ptree = NULL;	/* Tree for item details */

    guint16  assoc_ver;

    gchar	 *buf_desc = NULL;
    const char   *reject_result_desc = "";
    const char   *reject_source_desc = "";
    const char   *reject_reason_desc = "";
    const char   *abort_source_desc = "";
    const char   *abort_reason_desc = "";

    guint8  reject_result;
    guint8  reject_source;
    guint8  reject_reason;
    guint8  abort_source;
    guint8  abort_reason;

    buf_desc = (gchar *)ep_alloc0(MAX_BUF_LEN);	    /* Valid for this packet */

    assoc_header_pitem = proto_tree_add_text(tree, tvb, offset, pdu_len-6, "Association Header");
    assoc_header_ptree = proto_item_add_subtree(assoc_header_pitem, ett_assoc_header);

    switch (pdu_type) {
    case 1:					/* Association Request */

	assoc_ver = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(assoc_header_ptree, hf_dcm_assoc_version, tvb, offset, 2, assoc_ver);
	offset += 2;

	offset += 2;				/* Two reserved bytes*/

	tvb_memcpy(tvb, assoc->ae_called, offset, 16);
	assoc->ae_called[AEEND] = 0;
	proto_tree_add_string(assoc_header_ptree, hf_dcm_assoc_called, tvb, offset, 16, assoc->ae_called);
	offset += 16;

	tvb_memcpy(tvb, assoc->ae_calling, offset, 16);
	assoc->ae_calling[AEEND] = 0;
	proto_tree_add_string(assoc_header_ptree, hf_dcm_assoc_calling, tvb, offset, 16, assoc->ae_calling);
	offset += 16;

	offset += 32;				/* 32 reserved bytes */

	g_snprintf(buf_desc, MAX_BUF_LEN, "A-ASSOCIATE request %s --> %s",
	    g_strstrip(assoc->ae_calling), g_strstrip(assoc->ae_called));

	offset = dissect_dcm_assoc_detail(tvb, pinfo, assoc_header_ptree, assoc,
	    offset, pdu_len-offset);

	break;
    case 2: 					/* Association Accept */

	assoc_ver = tvb_get_ntohs(tvb, offset+2);
	proto_tree_add_uint(assoc_header_ptree, hf_dcm_assoc_version, tvb, offset, 2, assoc_ver);
	offset += 2;

	offset += 2;				/* Two reserved bytes*/

	tvb_memcpy(tvb, assoc->ae_called_resp, offset, 16);
	assoc->ae_called_resp[AEEND] = 0;
	proto_tree_add_string(assoc_header_ptree, hf_dcm_assoc_called, tvb, offset, 16, assoc->ae_called_resp);
	offset += 16;

	tvb_memcpy(tvb, assoc->ae_calling_resp, offset, 16);
	assoc->ae_calling_resp[AEEND] = 0;
	proto_tree_add_string(assoc_header_ptree, hf_dcm_assoc_calling, tvb, offset, 16, assoc->ae_calling_resp);
	offset += 16;

	offset += 32;				/* 32 reserved bytes */

	g_snprintf(buf_desc, MAX_BUF_LEN, "A-ASSOCIATE accept  %s <-- %s",
	    g_strstrip(assoc->ae_calling_resp), g_strstrip(assoc->ae_called_resp));

	offset = dissect_dcm_assoc_detail(tvb, pinfo, assoc_header_ptree, assoc,
	    offset, pdu_len-offset);

	break;
    case 3:					/* Association Reject */

	offset += 1;				/* One reserved byte */

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

	proto_tree_add_uint_format(assoc_header_ptree, hf_dcm_assoc_reject_result, tvb,
	    offset  , 1, reject_result, "Result: %s", reject_result_desc);

	proto_tree_add_uint_format(assoc_header_ptree, hf_dcm_assoc_reject_source, tvb,
	    offset+1, 1, reject_source, "Source: %s", reject_source_desc);

	proto_tree_add_uint_format(assoc_header_ptree, hf_dcm_assoc_reject_reason, tvb,
	    offset+2, 1, reject_reason, "Reason: %s", reject_reason_desc);

	offset += 3;

	/* Provider aborted */
	g_snprintf(buf_desc, MAX_BUF_LEN,"A-ASSOCIATE reject  %s <-- %s (%s)",
	    g_strstrip(assoc->ae_calling), g_strstrip(assoc->ae_called), reject_reason_desc);

	expert_add_info_format(pinfo, assoc_header_pitem,
	    PI_RESPONSE_CODE, PI_WARN, "Association rejected");

	break;
    case 5:					/* RELEASE Request */

	offset += 2;				/* Two reserved bytes */
	buf_desc="A-RELEASE request";

	break;
    case 6:					/* RELEASE Response */

	offset += 2;				/* Two reserved bytes */
	buf_desc="A-RELEASE response";

	break;
    case 7:					/* ABORT */

	offset += 2;				/* Two reserved bytes */

	abort_source = tvb_get_guint8(tvb, offset);
	abort_reason = tvb_get_guint8(tvb, offset+1);

	switch (abort_source) {
	case 0:
	    abort_source_desc = "User";
	    abort_reason_desc = "N/A";		/* No details can be provided*/
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

	proto_tree_add_uint_format(assoc_header_ptree, hf_dcm_assoc_abort_source,
	    tvb, offset  , 1, abort_source, "Source: %s", abort_source_desc);

	proto_tree_add_uint_format(assoc_header_ptree, hf_dcm_assoc_abort_reason,
	    tvb, offset+1, 1, abort_reason, "Reason: %s", abort_reason_desc);
	offset += 2;

	if (abort_source == 0) {
	    /* User aborted */
	    g_snprintf(buf_desc, MAX_BUF_LEN,"ABORT %s --> %s",
		g_strstrip(assoc->ae_calling), g_strstrip(assoc->ae_called));
	}
	else {
	    /* Provider aborted, slightly more information */
	    g_snprintf(buf_desc, MAX_BUF_LEN,"ABORT %s <-- %s (%s)",
		g_strstrip(assoc->ae_calling), g_strstrip(assoc->ae_called), abort_reason_desc);
	}

	expert_add_info_format(pinfo, assoc_header_pitem,
	    PI_RESPONSE_CODE, PI_WARN, "Association aborted");

	break;
    }

    proto_item_set_text(assoc_header_pitem, "%s", buf_desc);
    col_append_str(pinfo->cinfo, COL_INFO, buf_desc);

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, se_strdup(buf_desc));	/* requires SE not EP memory */

    /* proto_item and proto_tree are one and the same */
    proto_item_append_text(tree, ", %s", buf_desc);

    return offset;
}

static void
dissect_dcm_assoc_item(tvbuff_t *tvb, proto_tree *tree, guint32 offset,
		       const gchar *pitem_prefix, int item_value_type,
		       gchar **item_value, const gchar **item_description,
		       int *hf_type, int *hf_len, int *hf_value, int ett_subtree)
{
    /*
     *	Decode one item in a association request or response. Lookup UIDs if requested
     *
     *  If dcm_tree is set, create a Subtree Node with summary and three elements
     *  - item_type
     *  - item_len
     *  - value
     *
     */

    proto_tree *assoc_item_ptree = NULL;	/* Tree for item details */
    proto_item *assoc_item_pitem = NULL;
    dcm_uid_t  *uid = NULL;

    guint32 item_number = 0;

    guint8  item_type = 0;
    guint16 item_len  = 0;

    gchar *buf_desc = NULL;		/* Used for item text */

    *item_value = NULL;
    *item_description = NULL;

    buf_desc = (gchar *)ep_alloc0(MAX_BUF_LEN);	/* Valid for this packet */

    item_type = tvb_get_guint8(tvb, offset);
    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_pitem = proto_tree_add_text(tree, tvb, offset, item_len+4, "%s", pitem_prefix);
    assoc_item_ptree = proto_item_add_subtree(assoc_item_pitem, ett_subtree);

    proto_tree_add_uint(assoc_item_ptree, *hf_type, tvb, offset, 1, item_type);
    proto_tree_add_uint(assoc_item_ptree, *hf_len, tvb, offset+2, 2, item_len);

    switch (item_value_type) {
    case DCM_ITEM_VALUE_TYPE_UID:
	*item_value = (gchar *)tvb_get_ephemeral_string(tvb, offset+4, item_len);

	uid = (dcm_uid_t *)g_hash_table_lookup(dcm_uid_table, (gpointer) *item_value);
	if (uid) {
	    *item_description = uid->name;
   	    g_snprintf(buf_desc, MAX_BUF_LEN, "%s (%s)", *item_description, *item_value);
	}
	else {
	    /* Unknown UID, or no UID at all */
	    g_snprintf(buf_desc, MAX_BUF_LEN, "%s", *item_value);
	}

	proto_item_append_text(assoc_item_pitem, "%s", buf_desc);
	proto_tree_add_string(assoc_item_ptree, *hf_value, tvb, offset+4, item_len, buf_desc);

	break;

    case DCM_ITEM_VALUE_TYPE_STRING:
	*item_value = (gchar *)tvb_get_ephemeral_string(tvb, offset+4, item_len);
        proto_item_append_text(assoc_item_pitem, "%s", *item_value);
	proto_tree_add_string(assoc_item_ptree, *hf_value, tvb, offset+4, item_len, *item_value);

	break;

    case DCM_ITEM_VALUE_TYPE_UINT32:
	item_number = tvb_get_ntohl(tvb, offset+4);
	*item_value = (gchar *)se_alloc0(MAX_BUF_LEN);
	g_snprintf(*item_value, MAX_BUF_LEN, "%d", item_number);

	proto_item_append_text(assoc_item_pitem, "%s", *item_value);
	proto_tree_add_item(assoc_item_ptree, *hf_value, tvb, offset+4, 4, FALSE);

	break;

    default:
	break;
    }
}


static void
dissect_dcm_pctx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 dcm_state_assoc_t *assoc, guint32 offset, guint32 len,
		 const gchar *pitem_prefix, gboolean is_assoc_request)
{
    /*
	Decode a presentation context item in a Association Request or Response
	In the response, set the accepted transfer syntax, if any
    */

    proto_tree *pctx_ptree = NULL;	/* Tree for presentation context details */
    proto_item *pctx_pitem = NULL;

    dcm_state_pctx_t *pctx = NULL;

    guint8  item_type = 0;
    guint16 item_len = 0;

    guint8  pctx_id = 0;		    /* Presentation Context ID */
    guint8  pctx_result = 0;

    const char	*pctx_result_desc = "";

    gchar *pctx_abss_uid  = NULL;	    /* Abstract Syntax UID alias SOP Class UID */
    const gchar *pctx_abss_desc = NULL;	    /* Description of UID */

    gchar *pctx_xfer_uid = NULL;	    /* Transfer Syntax UID */
    const gchar *pctx_xfer_desc = NULL;	    /* Description of UID */

    gchar *buf_desc = NULL;	    /* Used in infor mode for item text */

    guint32 endpos = 0;
    int	    cnt_abbs = 0;	    /* Number of Abstract Syntax Items */
    int	    cnt_xfer = 0;	    /* Number of Trasfer Syntax Items */

    buf_desc = (gchar *)ep_alloc0(MAX_BUF_LEN);	/* Valid for this packet */

    endpos = offset + len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    pctx_pitem = proto_tree_add_text(tree, tvb, offset-4, item_len+4, "%s", pitem_prefix);
    pctx_ptree = proto_item_add_subtree(pctx_pitem, ett_assoc_pctx);

    pctx_id     = tvb_get_guint8(tvb, offset);
    pctx_result = tvb_get_guint8(tvb, 2 + offset);	/* only set in responses, otherwise reserved and 0x00 */

    /* Find or create dicom context object */
    pctx = dcm_state_pctx_get(assoc, pctx_id, TRUE);
    if (pctx == NULL) {	/* Internal error. Failed to create data structre */
	return;
    }

    proto_tree_add_uint(pctx_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 2, item_type);
    proto_tree_add_uint(pctx_ptree, hf_dcm_assoc_item_len,  tvb, offset-2, 2, item_len);

    proto_tree_add_uint_format(pctx_ptree, hf_dcm_pctx_id, tvb, offset, 1, pctx_id, "Context ID: 0x%02x", pctx_id);

    if (!is_assoc_request) {
	/* Accociation response. */

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
	case 0x30:		/* Abstract syntax */

	    /* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
	    dissect_dcm_assoc_item(tvb, pctx_ptree, offset-4,
		"Abstract Syntax: ", DCM_ITEM_VALUE_TYPE_UID, &pctx_abss_uid, &pctx_abss_desc,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pctx_abss_syntax, ett_assoc_pctx_abss);

	    cnt_abbs += 1;
	    offset += item_len;
	    break;

	case 0x40:		/* Transfer syntax */

	    dissect_dcm_assoc_item(tvb, pctx_ptree, offset-4,
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
	    expert_add_info_format(pinfo, pctx_pitem, PI_MALFORMED, PI_ERROR,
		"No Abstract Syntax provided for this Presentation Context");
	    return;
	}
	else if (cnt_abbs>1) {
	    expert_add_info_format(pinfo, pctx_pitem, PI_MALFORMED, PI_ERROR,
		"More than one Abstract Syntax provided for this Presentation Context");
	    return;
	}

	if (cnt_xfer==0) {
	    expert_add_info_format(pinfo, pctx_pitem, PI_MALFORMED, PI_ERROR,
		"No Transfer Syntax provided for this Presentation Context");
	    return;
	}

	if (pctx_abss_uid==NULL) {
	    expert_add_info_format(pinfo, pctx_pitem, PI_MALFORMED, PI_ERROR,
		"No Abstract Syntax UID found for this Presentation Context");
	    return;
	}

    }
    else {

	if (cnt_xfer>1) {
	    expert_add_info_format(pinfo, pctx_pitem, PI_MALFORMED, PI_ERROR,
		"Only one Transfer Syntax allowed in a Association Response");
    	    return;
	}
    }

    if (pctx->abss_uid==NULL) {
	/* Permanent copy information into structure */
	pctx->abss_uid  = se_strdup(pctx_abss_uid);
	pctx->abss_desc = se_strdup(pctx_abss_desc);
    }

    /*
      Copy to buffer first, because proto_item_append_text()
      crashed for an unknown reason using 'ID 0x%02x, %s, %s'
      and in my opinion correctly set parameters.
    */

    if (is_assoc_request) {
	if (pctx_abss_desc == NULL) {
	    g_snprintf(buf_desc, MAX_BUF_LEN, "%s", pctx_abss_uid);
	}
	else {
	    g_snprintf(buf_desc, MAX_BUF_LEN, "%s (%s)", pctx_abss_desc, pctx_abss_uid);
	}
    }
    else
    {
	/* g_snprintf() does not like NULL pointers */

	if (pctx_result==0) {
	    /* Accepted */
	    g_snprintf(buf_desc, MAX_BUF_LEN, "ID 0x%02x, %s, %s, %s",
		pctx_id, pctx_result_desc,
		dcm_uid_or_desc(pctx->xfer_uid, pctx->xfer_desc),
		dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
	}
	else {
	    /* Rejected */
	    g_snprintf(buf_desc, MAX_BUF_LEN, "ID 0x%02x, %s, %s",
		pctx_id, pctx_result_desc,
		dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
	}
    }
    proto_item_append_text(pctx_pitem, "%s", buf_desc);

}

static void
dissect_dcm_userinfo(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 len, const gchar *pitem_prefix)
{
    /*
	Decode the user info item in a Association Request or Response
    */

    proto_item *userinfo_pitem = NULL;
    proto_tree *userinfo_ptree = NULL;	/* Tree for presentation context details */

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

    userinfo_pitem = proto_tree_add_text(tree, tvb, offset-4, item_len+4, "%s", pitem_prefix);
    userinfo_ptree = proto_item_add_subtree(userinfo_pitem, ett_assoc_info);

    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 2, item_type);
    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_len, tvb, offset-2, 2, item_len);

    while (offset < endpos) {

	item_type = tvb_get_guint8(tvb, offset);
	item_len = tvb_get_ntohs(tvb, 2 + offset);

	offset += 4;
	switch (item_type) {
	case 0x51:		/* Max length */

	    dissect_dcm_assoc_item(tvb, userinfo_ptree, offset-4,
		"Max PDU Length: ", DCM_ITEM_VALUE_TYPE_UINT32, &info_max_pdu, &dummy,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pdu_maxlen, ett_assoc_info_uid);

	    if (!first_item) {
		proto_item_append_text(userinfo_pitem, ", ");
	    }
	    proto_item_append_text(userinfo_pitem, "Max PDU Length %s", info_max_pdu);
	    first_item=FALSE;

	    offset += item_len;
	    break;

	case 0x52:		/* UID */

	    /* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
	    dissect_dcm_assoc_item(tvb, userinfo_ptree, offset-4,
		"Implementation UID: ", DCM_ITEM_VALUE_TYPE_STRING, &info_impl_uid, &dummy,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_info_uid, ett_assoc_info_uid);

	    if (!first_item) {
		proto_item_append_text(userinfo_pitem, ", ");
	    }
	    proto_item_append_text(userinfo_pitem, "Implementation UID %s", info_impl_uid);
	    first_item=FALSE;

	    offset += item_len;
	    break;

	case 0x55:		/* version */

    	    dissect_dcm_assoc_item(tvb, userinfo_ptree, offset-4,
		"Implementation Version: ", DCM_ITEM_VALUE_TYPE_STRING, &info_impl_version, &dummy,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_info_version, ett_assoc_info_version);

	    if (!first_item) {
		proto_item_append_text(userinfo_pitem, ", ");
	    }
	    proto_item_append_text(userinfo_pitem, "Version %s", info_impl_version);
	    first_item=FALSE;

	    offset += item_len;
	    break;

	case 0x53:		/* async negotion */
	    /* hf_dcm_async */
	    offset += item_len;
	    break;

	default:
	    offset += item_len;
	    break;
	}
    }
}


static guint32
dissect_dcm_assoc_detail(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,
			 dcm_state_assoc_t *assoc, guint32 offset, guint32 len)
{
    proto_tree *assoc_tree  = NULL;	/* Tree for PDU details */

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
	    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Invalid Association Item Length");
	    return endpos;
	}

	offset += 4;

	switch (item_type) {
	case 0x10:		/* Application context */
	    dissect_dcm_assoc_item(tvb, assoc_tree, offset-4,
		"Application Context: ", DCM_ITEM_VALUE_TYPE_UID, &item_value, &item_description,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_actx, ett_assoc_actx);

	    offset += item_len;
	    break;

	case 0x20:		/* Presentation context request */
	    dissect_dcm_pctx(tvb, pinfo, assoc_tree, assoc, offset, item_len,
		"Presentation Context: ", TRUE);
	    offset += item_len;
	    break;

	case 0x21:		/* Presentation context reply */
	    dissect_dcm_pctx(tvb, pinfo, assoc_tree, assoc, offset, item_len,
		"Presentation Context: ", FALSE);
	    offset += item_len;
	    break;

	case 0x50:		/* User Info */
	    dissect_dcm_userinfo(tvb, assoc_tree, offset, item_len, "User Info: ");
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
    /* Dissect Context and Flags of a PDV and create new PDV stucture */

    proto_item *pdv_ctx_pitem = NULL;
    proto_item *pdv_flags_pitem = NULL;

    dcm_state_pctx_t	*pctx = NULL;
    dcm_state_pdv_t	*pdv_first_data = NULL;

    const gchar *desc_flag = NULL;	/* Flag Description in tree */
    gchar *desc_header = NULL;		/* Used for PDV description */

    guint8  flags = 0;
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

	expert_add_info_format(pinfo, pdv_ctx_pitem, PI_MALFORMED, PI_ERROR, "Invalid Presentation Context ID");

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
       multiple merged packets per PDV (tvb->raw_offset)
       we need both values to uniquely identify a PDV
    */

    *pdv = dcm_state_pdv_get(pctx, pinfo->fd->num, tvb->raw_offset+offset, TRUE);
    if (*pdv == NULL) {
	return 0;		    /* Failed to allocate memory */
    }

    /* 1 Byte Flag */
    flags = tvb_get_guint8(tvb, offset);

    (*pdv)->pctx_id = pctx_id;

    desc_header=(gchar *)se_alloc0(MAX_BUF_LEN);	/* Valid for this capture, since we return this buffer */

    switch (flags) {
    case 0:	/* 00 */
	desc_flag = "Data, More Fragments";

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = FALSE;
	(*pdv)->is_last_fragment = FALSE;
	(*pdv)->syntax = pctx->syntax;	    /* Inherit syntax for data PDVs*/
	break;

    case 2:	/* 10 */
	desc_flag = "Data, Last Fragment";

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = FALSE;
	(*pdv)->is_last_fragment = TRUE;
	(*pdv)->syntax = pctx->syntax;	    /* Inherit syntax for data PDVs*/
	break;

    case 1:	/* 01 */
	desc_flag = "Command, More Fragments";
	g_snprintf(desc_header, MAX_BUF_LEN, "Command");		/* Will be overwritten with real command tag */

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = TRUE;
	(*pdv)->is_last_fragment = FALSE;
	(*pdv)->syntax = DCM_ILE;	    /* Command tags are always little endian*/
	break;

    case 3:	/* 11 */
	desc_flag = "Command, Last Fragment";
        g_snprintf(desc_header, MAX_BUF_LEN, "Command");

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = TRUE;
	(*pdv)->is_last_fragment = TRUE;
	(*pdv)->syntax = DCM_ILE;	    /* Command tags are always little endian*/
	break;

    default:
	desc_flag = "Invalid Flags";
        g_snprintf(desc_header, MAX_BUF_LEN, "Invalid Flags");

	(*pdv)->is_flagvalid = FALSE;
	(*pdv)->is_command = FALSE;
	(*pdv)->is_last_fragment = FALSE;
	(*pdv)->syntax = DCM_UNK;
    }

    if (flags == 0 || flags == 2) {
	/* Data PDV */
	pdv_first_data = dcm_state_pdv_get_obj_start(*pdv);

	if (pdv_first_data->prev && pdv_first_data->prev->is_command) {
	    /* Every Data PDV sequence should be preceeded by a Command PDV,
	       so we should always hit this for a correct capture
	    */

	    if (pctx->abss_desc && g_str_has_suffix(pctx->abss_desc, "Storage")) {
		/* Should be done far more intelligent, e.g. does not catch the (Retired) ones */
		if (flags == 0) {
		    g_snprintf(desc_header, MAX_BUF_LEN, "%s Fragment", pctx->abss_desc);
		}
		else {
		    g_snprintf(desc_header, MAX_BUF_LEN, "%s", pctx->abss_desc);
		}
		(*pdv)->is_storage = TRUE;
	    }
	    else {
		/* Use previous command and append DATA*/
		g_snprintf(desc_header, MAX_BUF_LEN, "%s-DATA", pdv_first_data->prev->desc);
	    }
	}
	else {
	    g_snprintf(desc_header, MAX_BUF_LEN, "DATA");
	}
    }

    (*pdv)->desc = desc_header;

    pdv_flags_pitem = proto_tree_add_uint_format(tree, hf_dcm_pdv_flags, tvb, offset, 1,
	flags, "Flags: 0x%02x (%s)", flags, desc_flag);

    if (flags>3) {
	expert_add_info_format(pinfo, pdv_flags_pitem, PI_MALFORMED, PI_ERROR, "Invalid Flags");
    }
    offset +=1;

    return offset;
}

static guint32
dissect_dcm_tag_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_pdv_t *pdv,
		      guint32 offset, guint16 grp, guint16 elm,
		      guint32 vl, guint32 vl_max, const gchar* vr, gchar **tag_value)
{
    /* Based on the value representation, decode the value of one tag. Returns new offset */

    proto_item *pitem = NULL;

    gboolean is_little_endian;

    if (pdv->syntax == DCM_EBE)	is_little_endian = FALSE;
    else			is_little_endian = TRUE;


    /* ---------------------------------------------------------------------------
       Potentially long types. Obey vl_max
       ---------------------------------------------------------------------------
    */

    if ((strncmp(vr, "AE", 2) == 0) || (strncmp(vr, "AS", 2) == 0) || (strncmp(vr, "CS", 2) == 0) ||
	(strncmp(vr, "DA", 2) == 0) || (strncmp(vr, "DS", 2) == 0) || (strncmp(vr, "DT", 2) == 0) ||
	(strncmp(vr, "IS", 2) == 0) || (strncmp(vr, "LO", 2) == 0) || (strncmp(vr, "LT", 2) == 0) ||
	(strncmp(vr, "PN", 2) == 0) || (strncmp(vr, "SH", 2) == 0) || (strncmp(vr, "ST", 2) == 0) ||
	(strncmp(vr, "TM", 2) == 0) || (strncmp(vr, "UI", 2) == 0) || (strncmp(vr, "UT", 2) == 0) ) {
	/* 15 ways to represent a string ... */

	gchar	*vals;
	dcm_uid_t *uid = NULL;
	guint8 val8;

	val8 = tvb_get_guint8(tvb, offset + vl_max - 1);
	if (val8 == 0x00) {
	    /* Last byte of string is 0x00, i.e. padded */
	    vals = tvb_format_text(tvb, offset, vl_max - 1);
	}
	else {
	    vals = tvb_format_text(tvb, offset, vl_max);
	}

	if ((strncmp(vr, "UI", 2) == 0)) {
	    /* This is a UID. Attempt a lookup. Will only return something for classes of course */

	    uid = (dcm_uid_t *)g_hash_table_lookup(dcm_uid_table, (gpointer) vals);
	    if (uid) {
		g_snprintf(*tag_value, MAX_BUF_LEN, "%s (%s)", vals, uid->name);
	    }
	    else {
		g_snprintf(*tag_value, MAX_BUF_LEN, "%s", vals);
	    }
	}
	else {
	    if (strlen(vals) > 50) {
		g_snprintf(*tag_value, MAX_BUF_LEN, "%-50.50s...", vals);
	    }
	    else {
		g_snprintf(*tag_value, MAX_BUF_LEN, "%s", vals);
	    }
	}
	proto_tree_add_string_format(tree, hf_dcm_tag_value_str, tvb, offset, vl_max, *tag_value, "%-8.8s%s", "Value:", *tag_value);

	if (grp == 0x0000 && elm == 0x0902) {
	    /* The error comment */
	    pdv->comment = se_strdup(g_strstrip(vals));
	}
    }
    else if ((strncmp(vr, "OB", 2) == 0) || (strncmp(vr, "OF", 2) == 0) ||
	     (strncmp(vr, "OW", 2) == 0)) {
	/* Array of Bytes, Float or Words. Don't perform any decoding */

	proto_tree_add_bytes_format(tree, hf_dcm_tag_value_byte, tvb, offset, vl_max,
	    NULL, "%-8.8s%s", "Value:", "(binary)");

	g_snprintf(*tag_value, MAX_BUF_LEN, "(binary)");
    }
    else if (strncmp(vr, "UN", 2) == 0) {
	/* Usually the case for private tags in implicit syntax, since tag was not found and vr not specified */
	guint8	  val8;
	gchar	 *vals;
	guint32	 i;

	/* String detector, i.e. check if we only have alpha-numeric character */
	gboolean	is_string = TRUE;
	gboolean	is_padded = FALSE;

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
	    vals = tvb_format_text(tvb, offset, (is_padded ? vl_max - 1 : vl_max));
	    proto_tree_add_string_format(tree, hf_dcm_tag_value_str, tvb, offset, vl_max,
		vals, "%-8.8s%s", "Value:", vals);

	    g_snprintf(*tag_value, MAX_BUF_LEN, "%s", vals);
	}
	else {
	    proto_tree_add_bytes_format(tree, hf_dcm_tag_value_byte, tvb, offset, vl_max,
		NULL, "%-8.8s%s", "Value:", "(binary)");

	    g_snprintf(*tag_value, MAX_BUF_LEN, "(binary)");
	}
    }
    /* ---------------------------------------------------------------------------
       Smaller types. vl/vl_max are not used. Fixed item length from 2 to 8 bytes
       ---------------------------------------------------------------------------
    */
    else if (strncmp(vr, "AT", 2) == 0)  {	/* Attribute Tag */
	/* 2*2 Bytes */

	guint16 at_grp;
	guint16 at_elm;

	if (is_little_endian)	at_grp = tvb_get_letohs(tvb, offset);
	else			at_grp = tvb_get_ntohs(tvb, offset);

	if (is_little_endian)	at_elm = tvb_get_letohs(tvb, offset);
	else			at_elm = tvb_get_ntohs(tvb, offset);

	proto_tree_add_uint_format(tree, hf_dcm_tag_value_32u, tvb, offset, 4,
	    (at_grp << 16) | at_elm, "%-8.8s%04x,%04x", "Value:", at_grp, at_elm);

	g_snprintf(*tag_value, MAX_BUF_LEN, "(%04x,%04x)", at_grp, at_elm);
    }
    else if (strncmp(vr, "FL", 2) == 0)  {	/* Single Float */

	gfloat valf;

	if (is_little_endian) valf = tvb_get_letohieee_float(tvb, offset);
	else		      valf = tvb_get_ntohieee_float(tvb, offset);

	proto_tree_add_bytes_format(tree, hf_dcm_tag_value_byte, tvb, offset, 4,
	    NULL, "%-8.8s%f", "Value:", valf);

	g_snprintf(*tag_value, MAX_BUF_LEN, "%f", valf);
    }
    else if (strncmp(vr, "FD", 2) == 0)  {	/* Double Float */

	gdouble vald;

	if (is_little_endian) vald = tvb_get_letohieee_double(tvb, offset);
	else		      vald = tvb_get_ntohieee_double(tvb, offset);

        proto_tree_add_bytes_format(tree, hf_dcm_tag_value_byte, tvb, offset, 8,
	    NULL, "%-8.8s%f", "Value:", vald);

	g_snprintf(*tag_value, MAX_BUF_LEN, "%f", vald);
    }
    else if (strncmp(vr, "SL", 2) == 0)  {	    /* Signed Long */
	gint32  val32;

	if (is_little_endian)	val32 = tvb_get_letohl(tvb, offset);
	else			val32 = tvb_get_ntohl(tvb, offset);

	proto_tree_add_int_format(tree, hf_dcm_tag_value_32s, tvb, offset, 4,
	    val32, "%-8.8s%d", "Value:", val32);

	g_snprintf(*tag_value, MAX_BUF_LEN, "%d", val32);
    }
    else if (strncmp(vr, "SS", 2) == 0)  {	    /* Signed Short */
	gint16  val16;

	if (is_little_endian)	val16 = tvb_get_letohs(tvb, offset);
	else			val16 = tvb_get_ntohs(tvb, offset);

	proto_tree_add_int_format(tree, hf_dcm_tag_value_16s, tvb, offset, 2,
	    val16, "%-8.8s%d", "Value:", val16);

	g_snprintf(*tag_value, MAX_BUF_LEN, "%d", val16);
    }
    else if (strncmp(vr, "UL", 2) == 0)  {	    /* Unsigned Long */
	guint32  val32;

	if (is_little_endian)	val32 = tvb_get_letohl(tvb, offset);
	else			val32 = tvb_get_ntohl(tvb, offset);

	proto_tree_add_uint_format(tree, hf_dcm_tag_value_32u, tvb, offset, 4,
	    val32, "%-8.8s%u", "Value:", val32);

	g_snprintf(*tag_value, MAX_BUF_LEN, "%u", val32);
    }
    else if (strncmp(vr, "US", 2) == 0)  {	    /* Unsigned Short */
	const gchar *status_message = NULL;
	guint16	    val16;

	if (is_little_endian)	val16 = tvb_get_letohs(tvb, offset);
	else			val16 = tvb_get_ntohs(tvb, offset);

	if (grp == 0x0000 && elm == 0x0100) {
	    /* This is a command */
	    g_snprintf(*tag_value, MAX_BUF_LEN, "%s", dcm_cmd2str(val16));

	    pdv->command = se_strdup(*tag_value);
	}
	else if (grp == 0x0000 && elm == 0x0900) {
	    /* This is a status message. If value is not 0x0000, add an expert info */

	    status_message = dcm_rsp2str(val16);
	    g_snprintf(*tag_value, MAX_BUF_LEN, "%s (0x%02x)", status_message, val16);

	    if (val16 != 0x0000 && ((val16 & 0xFF00) != 0xFF00)) {
		/* Not 0x0000 0xFFxx */
		pdv->is_warning = TRUE;
	    }

	    pdv->status = se_strdup(status_message);

	}
	else {
	    g_snprintf(*tag_value, MAX_BUF_LEN, "%u", val16);
	}

	if (grp == 0x0000) {
	    if (elm == 0x0110) {		/* (0000,0110) Message ID */
		pdv->message_id = val16;
	    }
	    else if (elm == 0x0120) {		/* (0000,0120) Message ID Being Responded To */
		pdv->message_id_resp = val16;
	    }
	    else if (elm == 0x1020) {		/* (0000,1020) Number of Remaining Sub-operations */
		pdv->no_remaining = val16;
	    }
	    else if (elm == 0x1021) {		/* (0000,1021) Number of Completed Sub-operations */
		pdv->no_completed = val16;
	    }
	    else if (elm == 0x1022) {		/* (0000,1022) Number of Failed Sub-operations	*/
		pdv->no_failed = val16;
	    }
	    else if (elm == 0x1023) {		/* (0000,1023) Number of Warning Sub-operations */
		pdv->no_warning = val16;
	    }
	}

	pitem = proto_tree_add_uint_format(tree, hf_dcm_tag_value_16u, tvb, offset, 2,
		    val16, "%-8.8s%s", "Value:", *tag_value);

	if (pdv->is_warning && status_message) {
	    expert_add_info_format(pinfo, pitem, PI_RESPONSE_CODE, PI_WARN, "%s", status_message);
	}
    }
    /* Invalid VR, can only occur with Explicit syntax */
    else {
	proto_tree_add_bytes_format(tree, hf_dcm_tag_value_byte, tvb, offset, vl_max,
	    NULL, "%-8.8s%s", "Value:", (vl > vl_max ? "" : "(unknown VR)"));

	g_snprintf(*tag_value, MAX_BUF_LEN, "(unknown VR)");
    }
    offset += vl_max;

    return offset;

}

static gboolean
dcm_tag_is_open(dcm_state_pdv_t *pdv, guint32 startpos, guint32 offset, guint32 endpos, guint32 size_required)
{
    /* Return true, if the required size does not fit at position 'offset'.
       Copy memory from startpos to endpos into pdv structure
    */

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

    static dcm_tag_t tag_unknown	 = { 0x00000000, "(unknown)", "UN", "1", 0, 0};
    static dcm_tag_t tag_private	 = { 0x00000000, "Private Tag", "UN", "1", 0, 0 };
    static dcm_tag_t tag_private_grp_len = { 0x00000000, "Private Tag Group Length", "UL", "1", 0, 0 };
    static dcm_tag_t tag_grp_length	 = { 0x00000000, "Group Length", "UL", "1", 0, 0 };

    /* Try a direct hit first before doing a masked search */
    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER((grp << 16) | elm));

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
	    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER(((grp & 0xFF00) << 16) | elm));
	}
	else if ((grp == 0x0020) && ((elm & 0xFF00) == 0x3100)) {
	    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER((grp << 16) | (elm & 0xFF00)));
	}
	else if ((grp == 0x0028) && ((elm & 0xFF00) == 0x0400)) {
	    /* This map was done to 0x041x */
	    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER((grp << 16) | (elm & 0xFF0F) | 0x0010));
	}
	else if ((grp == 0x0028) && ((elm & 0xFF00) == 0x0800)) {
	    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER((grp << 16) | (elm & 0xFF0F)));
	}
	else if (grp == 0x1000) {
	    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER((grp << 16) | (elm & 0x000F)));
	}
	else if (grp == 0x1010) {
	    tag_def = (dcm_tag_t *)g_hash_table_lookup(dcm_tag_table, GUINT_TO_POINTER((grp << 16) | (elm & 0x0000)));
	}

        if (tag_def == NULL) {
    	    /* Still no match found */
	    tag_def = &tag_unknown;
	}
    }

    return tag_def;
}

static gchar*
dcm_tag_summary(guint16 grp, guint16 elm, guint32 vl, const gchar *tag_desc, const gchar *vr,
		gboolean is_retired, gboolean is_implicit)
{

    gchar *desc_mod;
    gchar *tag_vl;
    gchar *tag_sum;

    if (is_retired) {
	desc_mod = ep_strdup_printf("(Retired) %-35.35s", tag_desc);
    }
    else {
	desc_mod = ep_strdup_printf("%-45.45s", tag_desc);
    }

    if (vl == 0xFFFFFFFF) {
	tag_vl = ep_strdup_printf("%10.10s", "<udef>");
    }
    else {
	tag_vl = ep_strdup_printf("%10u", vl);		/* Show as dec */
    }

    if (is_implicit)	tag_sum = ep_strdup_printf("(%04x,%04x) %s %s",      grp, elm, tag_vl, desc_mod);
    else		tag_sum = ep_strdup_printf("(%04x,%04x) %s %s [%s]", grp, elm, tag_vl, desc_mod, vr);

    return tag_sum;
}

static guint32
dissect_dcm_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		dcm_state_pdv_t *pdv, guint32 offset, guint32 endpos,
		gboolean is_first_tag, gchar **tag_description,
		gboolean *end_of_seq_or_item)
{
    /* Decode one tag. If it is a sequence or item start create a subtree.
       Returns new offset.
    */

    proto_tree  *tag_ptree = NULL;	/* Tree for decoded tag details */
    proto_tree  *seq_ptree = NULL;	/* Possible subtree for sequences and items */

    proto_item  *tag_pitem = NULL;
    dcm_tag_t   *tag_def   = NULL;

    const gchar *vr = NULL;
    gchar       *tag_value = NULL;	/* Tag Value converted to a string	*/
    gchar       *tag_summary;

    guint32 vl = 0;
    guint16 vl_1 = 0;
    guint16 vl_2 = 0;

    guint32 offset_tag   = 0;		/* Remember offsets for tree, since the tree	*/
    guint32 offset_vr    = 0;		/* header is created pretty late		*/
    guint32 offset_vl    = 0;

    guint32 vl_max = 0;			/* Max Value Length to Parse */

    guint16 grp = 0;
    guint16 elm = 0;

    guint32 len_decoded_remaing = 0;

    gboolean is_little_endian = FALSE;
    gboolean is_implicit = FALSE;
    gboolean is_vl_long = FALSE;	    /* True for 4 Bytes length fields */

    gboolean is_sequence = FALSE;	    /* True for Sequence Tags */
    gboolean is_item = FALSE;		    /* True for Sequence Item Tags */

    *tag_description = NULL;		    /* Reset description. It's ep_ memory, so not really bad*/

    tag_value = (gchar *)ep_alloc0(MAX_BUF_LEN);

    /* Decode the syntax a little more */
    if (pdv->syntax == DCM_EBE)	is_little_endian = FALSE;
    else			is_little_endian = TRUE;

    if (pdv->syntax == DCM_ILE) is_implicit = TRUE;
    else			is_implicit = FALSE;

    offset_tag = offset;


    if (pdv->prev && is_first_tag) {
	len_decoded_remaing = pdv->prev->open_tag.len_decoded;
    }


    /* Since we may have a fragmented header, check for every attribute,
       whether we have already decoded left-overs from the previous PDV.
       Since we have implicit & explicit syntax, copying the open tag to
       a buffer without decoding, would have caused tvb_get_xxtohs()
       implemnetations on the copy.

       An alternative approach would have been to resemble the PDVs first.

       The attemtps to reassemblye without named sources (to be implemented)
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

	if (dcm_tag_is_open(pdv, offset_tag, offset, endpos, 2)) return endpos;	/* Exit if needed */

	if (is_little_endian)   grp = tvb_get_letohs(tvb, offset);
	else			grp = tvb_get_ntohs (tvb, offset);
	offset += 2;
	pdv->open_tag.grp = grp;
    }

    /* Element */
    if (len_decoded_remaing >= 2) {
	elm = pdv->prev->open_tag.elm;
	len_decoded_remaing -= 2;
    }
    else {

	if (dcm_tag_is_open(pdv, offset_tag, offset, endpos, 2)) return endpos;    /* Exit if needed */

	if (is_little_endian)   elm = tvb_get_letohs(tvb, offset);
	else			elm = tvb_get_ntohs (tvb, offset);
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
	is_vl_long = TRUE;			    /* These tags always have a 4 byte lentgh field */
    }
    else if (is_implicit) {
	/* Get VR from tag definition */
	vr = ep_strdup(tag_def->vr);
	is_vl_long = TRUE;			    /* Implict always has 4 byte lentgh field */
    }
    else {

	if (len_decoded_remaing >= 2) {
	    vr = ep_strdup(pdv->prev->open_tag.vr);
	    len_decoded_remaing -= 2;
	}
	else {

	    /* Controlled exit, if VR does not fit. */
	    if (dcm_tag_is_open(pdv, offset_tag, offset_vr, endpos, 2)) return endpos;

	    vr = (gchar *)tvb_get_ephemeral_string(tvb, offset, 2);
	    offset += 2;

	    g_free(pdv->open_tag.vr);
	    pdv->open_tag.vr = g_strdup(vr);	    /* needs to survive withing a session */
	}


	if ((strcmp(vr, "OB") == 0) || (strcmp(vr, "OW") == 0) || (strcmp(vr, "OF") == 0) ||
	    (strcmp(vr, "SQ") == 0) || (strcmp(vr, "UT") == 0) || (strcmp(vr, "UN") == 0)) {
	    /* 4 bytes specials: OB, OW, OF, SQ, UT or UN */
	    is_vl_long = TRUE;

	    /* Skip 2 Bytes */
	    if (len_decoded_remaing >= 2) {
		len_decoded_remaing -= 2;
	    }
	    else {
		if (dcm_tag_is_open(pdv, offset_tag, offset_vr, endpos, 2)) return endpos;
		offset += 2;
	    }
	}
	else {
	    is_vl_long = FALSE;
	}
    }


    /* Value Length. This is rather cumbersume code to get a 4 byte length, but in the
       fragmented case, we have 2*2 bytes. So always use that pattern
    */

    offset_vl = offset;
    if (len_decoded_remaing >= 2) {
	vl_1 = pdv->prev->open_tag.vl_1;
	len_decoded_remaing -= 2;
    }
    else {

	if (dcm_tag_is_open(pdv, offset_tag, offset_vl, endpos, 2)) return endpos;
	if (is_little_endian)	vl_1 = tvb_get_letohs(tvb, offset);
	else			vl_1 = tvb_get_ntohs(tvb, offset);
	offset += 2;
	pdv->open_tag.vl_1 = vl_1;
    }

    if (is_vl_long) {

	if (len_decoded_remaing >= 2) {
	    vl_2 = pdv->prev->open_tag.vl_2;
	    len_decoded_remaing -= 2;
	}
	else {

	    if (dcm_tag_is_open(pdv, offset_tag, offset_vl+2, endpos, 2)) return endpos;
	    if (is_little_endian)	vl_2 = tvb_get_letohs(tvb, offset);
	    else			vl_2 = tvb_get_ntohs(tvb, offset);
	    offset += 2;
	    pdv->open_tag.vl_2 = vl_2;
	}

	if (is_little_endian)	vl = (vl_2 << 16) + vl_1;
	else			vl = (vl_1 << 16) + vl_2;
    }
    else {
	vl = vl_1;
    }

    /* Now we have most of the information, excpet for sequences and items with undefined
       length :-/. But, whether we know the length or not, we now need to create the tree
       item and subtree, before we can loop into sequences and items

       Display the information we collected so far. Don't wait until the value is parsed,
       because that parsing might cause an exception. If that happens within a sequence,
       the sequence tag would not show up with the value
    */

    tag_summary = dcm_tag_summary(grp, elm, vl, tag_def->description, vr, tag_def->is_retired, is_implicit);

    if (vl == 0xFFFFFFFF) {
	/* 'Just' mark header as the length of the item */
	tag_pitem = proto_tree_add_text(tree, tvb, offset_tag, offset - offset_tag, "%s", tag_summary);
	vl_max = 0;	    /* We don't know who long this sequence/item is */
    }
    else if (offset + vl <= endpos) {
	/* Show real length of item */
	tag_pitem = proto_tree_add_text(tree, tvb, offset_tag, offset + vl - offset_tag, "%s", tag_summary);
	vl_max = vl;
    }
    else {
	/* Value is longer than what we have in the PDV, -> we do have a OPEN tag */
	tag_pitem = proto_tree_add_text(tree, tvb, offset_tag, endpos - offset_tag, "%s", tag_summary);
	vl_max = endpos - offset;
    }

    is_sequence = (strcmp(vr, "SQ") == 0) || (vl == 0xFFFFFFFF);
    is_item = ((grp == 0xFFFE) && (elm == 0xE000));


    /* If you are going to touch the following 25 lines, make sure you reserve a few hours to go
       through both display options and check for proper tree display :-)
    */
    if (is_sequence | is_item) {

	if (global_dcm_seq_subtree) {
	    /* Use different ett_ for Sequences & Items, so that fold/unfold state makes sense */
    	    seq_ptree = proto_item_add_subtree(tag_pitem, (is_sequence ? ett_dcm_data_seq : ett_dcm_data_item));
	    if (global_dcm_tag_subtree)	    tag_ptree = seq_ptree;
	    else			    tag_ptree = NULL;
	}
	else {
	    seq_ptree = tree;
	    if (global_dcm_tag_subtree) {
		tag_ptree = proto_item_add_subtree(tag_pitem, ett_dcm_data_tag);
	    }
	    else {
		tag_ptree = NULL;
	    }
	}
    }
    else {
	/* For tags */
	if (global_dcm_tag_subtree) {
	    tag_ptree = proto_item_add_subtree(tag_pitem, ett_dcm_data_tag);
	}
	else {
	    tag_ptree = NULL;
	}
    }

    /*  ---------------------------------------------------------------
	Tag details as separate items
	---------------------------------------------------------------
    */

    proto_tree_add_uint_format(tag_ptree, hf_dcm_tag, tvb, offset_tag, 4,
        (grp << 16) | elm, "Tag:    %04x,%04x (%s)", grp, elm, tag_def->description);

    /* Add VR to tag detail, excpet for dicom items */
    if (!is_item)  {
	if (is_implicit) {
	    /* Select header, since no VR is present in implicit syntax */
	    proto_tree_add_string_format(tag_ptree, hf_dcm_tag_vr, tvb, offset_tag, 4, vr, "%-8.8s%s", "VR:", vr);
	}
	else {
	    proto_tree_add_string_format(tag_ptree, hf_dcm_tag_vr, tvb, offset_vr,  2, vr, "%-8.8s%s", "VR:", vr);
	}
    }

    /* Add length to tag detail */
    proto_tree_add_uint_format(tag_ptree, hf_dcm_tag_vl, tvb, offset_vl, (is_vl_long ? 4 : 2), vl, "%-8.8s%u", "Length:", vl);


    /*  ---------------------------------------------------------------
	Finally the Tag Value
	---------------------------------------------------------------
    */
    if ((is_sequence || is_item) && (vl > 0)) {
	/* Sequence or Item Start */

	guint32	endpos_item = 0;
	gboolean local_end_of_seq_or_item = FALSE;
	gboolean is_first_desc = TRUE;

	gchar *item_description = NULL;	    /* Will be allocated as ep_ memory in dissect_dcm_tag() */

	if (vl == 0xFFFFFFFF) {
	    /* Undefined length */

	    while ((!local_end_of_seq_or_item) && (!pdv->open_tag.is_header_fragmented) && (offset < endpos)) {

		offset = dissect_dcm_tag(tvb, pinfo, seq_ptree, pdv, offset, endpos, FALSE,
		    &item_description, &local_end_of_seq_or_item);

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

		offset = dissect_dcm_tag(tvb, pinfo, seq_ptree, pdv, offset, endpos_item, FALSE,
		    &item_description, &local_end_of_seq_or_item);

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
	/* No value */
	g_strlcpy(tag_value, "<Empty>", MAX_BUF_LEN);
    }
    else if (vl > vl_max) {
	/* Tag is longer than the PDV/PDU. Don't perform any decoding */

	gchar *tag_desc;

        proto_tree_add_bytes_format(tag_ptree, hf_dcm_tag_value_byte, tvb, offset, vl_max,
	    NULL, "%-8.8sBytes %d - %d [start]", "Value:", 1, vl_max);

	g_snprintf(tag_value, MAX_BUF_LEN, "<Bytes %d - %d, start>", 1, vl_max);
	offset += vl_max;

	/*  Save the needed data for reuse, and subsequent packets
	    This will leak a little within the session.

	    But since we may have tags being closed and reopen in the same PDV
	    we will always need to store this
	*/

	tag_desc = dcm_tag_summary(grp, elm, vl, tag_def->description, vr, tag_def->is_retired, is_implicit);

	if (pdv->open_tag.desc == NULL) {
	    pdv->open_tag.is_value_fragmented = TRUE;
	    pdv->open_tag.desc = se_strdup(tag_desc);
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
	    dcm_state_pdv_get_obj_start(pdv)->sop_class_uid = se_strdup(tag_value);
	}
	else if (grp == 0x0008 && elm == 0x0018) {
	    dcm_state_pdv_get_obj_start(pdv)->sop_instance_uid = se_strdup(tag_value);
	}
	else if (grp == 0x0000 && elm == 0x0100) {
	    /* This is the command tag -> overwrite existing PDV description */
	    pdv->desc = se_strdup(tag_value);
	}
    }


    /* -------------------------------------------------------------------
       Adde the value to the already constructued item
       -------------------------------------------------------------------
    */

    proto_item_append_text(tag_pitem, " %s", tag_value);

    if (tag_def->add_to_summary) {
	*tag_description = ep_strdup(g_strstrip(tag_value));
    }

    return offset;
}

static guint32
dissect_dcm_tag_open(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		dcm_state_pdv_t *pdv, guint32 offset, guint32 endpos, gboolean *is_first_tag)
{
    /* 'Decode' open tags from previous PDV */

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
		pdv->open_tag.desc = se_strdup(pdv->prev->open_tag.desc);

	    }
	    pdv->is_corrupt = FALSE;
	}

	if (pdv->is_corrupt) {
	    pitem = proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
		offset, tag_value_fragment_len, NULL,
		"%s <incomplete>", pdv->prev->open_tag.desc);

	    expert_add_info_format(pinfo, pitem, PI_MALFORMED, PI_ERROR,
		"Early termination of tag. Data is missing");

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

static guint32
dissect_dcm_pdv_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		dcm_state_pdv_t *pdv, guint32 offset, guint32 pdv_body_len,
		gchar **pdv_description)
{
    /* Handle one PDV inside a data PDU */

    gchar *tag_value = NULL;
    gboolean dummy = FALSE;
    guint32 startpos = 0;
    guint32 endpos = 0;

    startpos = offset;
    endpos = offset + pdv_body_len;

    if (pdv->syntax == DCM_UNK) {
	/* Eventually, we will have a syntax detector. Until then, don't decode */

	proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
	    offset, pdv_body_len, NULL,
	    "(%04x,%04x) %-8x Unparsed data", 0, 0, pdv_body_len);
	offset = endpos;
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

    if (pdv->is_command) {

	*pdv_description = (gchar *)se_alloc0(MAX_BUF_LEN);

	if (pdv->is_warning) {
	    if (pdv->comment) {
		g_snprintf(*pdv_description, MAX_BUF_LEN, "%s (%s, %s)", pdv->desc, pdv->status, pdv->comment);
	    }
	    else {
		g_snprintf(*pdv_description, MAX_BUF_LEN, "%s (%s)", pdv->desc, pdv->status);
	    }

	}
	else if (global_dcm_cmd_details) {
	    /* Show command details in header */

	    if (pdv->message_id > 0) {
		g_snprintf(*pdv_description, MAX_BUF_LEN, "%s ID=%d", pdv->desc, pdv->message_id);
	    }
	    else if (pdv->message_id_resp > 0) {

		g_snprintf(*pdv_description, MAX_BUF_LEN, "%s ID=%d", pdv->desc, pdv->message_id_resp);

		if (pdv->no_completed > 0) {
		    g_snprintf(*pdv_description, MAX_BUF_LEN, "%s C=%d", *pdv_description, pdv->no_completed);
		}
		if (pdv->no_remaining > 0) {
		    g_snprintf(*pdv_description, MAX_BUF_LEN, "%s R=%d", *pdv_description, pdv->no_remaining);
		}
		if (pdv->no_warning > 0) {
		    g_snprintf(*pdv_description, MAX_BUF_LEN, "%s W=%d", *pdv_description, pdv->no_warning);
		}
		if (pdv->no_failed > 0) {
		    g_snprintf(*pdv_description, MAX_BUF_LEN, "%s F=%d", *pdv_description, pdv->no_failed);
		}
	    }
	    else {
		*pdv_description = pdv->desc;
	    }
	}
	else {
	    *pdv_description = pdv->desc;
	}
    }
    else {
	*pdv_description = pdv->desc;
    }

    return endpos;	/* we could try offset as return value */
}


static guint32
dissect_dcm_pdv_fragmented(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		dcm_state_assoc_t *assoc, guint32 offset, guint32 pdv_len, gchar **pdv_description)
{
    /* Handle one PDV inside a data PDU. Perform the necessary reassembly
       Create PDV object when needed
    */

    conversation_t  *conv=NULL;

    dcm_state_pdv_t *pdv = NULL;

    tvbuff_t *next_tvb = NULL;
    fragment_data *head = NULL;

    guint32 reassembly_id;
    guint32 pdv_body_len;
    guint32 startpos;

    startpos = offset;
    pdv_body_len = pdv_len-2;

    /* Dissect Context ID, Find PDV object, Decode Command/Data flag and More Fragments flag */
    offset = dissect_dcm_pdv_header(tvb, pinfo, tree, assoc, offset, &pdv);

    /* When fragmented, do reassambly and subsequently decode merged PDV */
    if (global_dcm_reassemble)
    {

	conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			    pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	/* Try to create somewhat unique ID.
	   Include the conversation index, to separate TCP session
	*/
	reassembly_id = (((conv->index) & 0x00FFFFFF) << 8) + pdv->pctx_id;

	head = fragment_add_seq_next(tvb, offset, pinfo, reassembly_id,
				dcm_pdv_fragment_table,
				dcm_pdv_reassembled_table,
				pdv_body_len,
				!(pdv->is_last_fragment));

	if (head && (head->next == NULL)) {
	    /* Was not really fragmented, therefore use 'conventional' decoding
	       fragment_add_seq_next() won't add any items to the list, when last fragment only
	    */

	    offset = dissect_dcm_pdv_body(tvb, pinfo, tree, pdv, offset, pdv_body_len, pdv_description);
	}
	else {
	    next_tvb = process_reassembled_data(tvb, offset, pinfo,
					"Reassembled PDV", head,
					&dcm_pdv_fragment_items, NULL, tree);

	    if (next_tvb == NULL) {
		/* Just show this as a fragment */

		*pdv_description = (gchar *)se_alloc0(MAX_BUF_LEN);

		if (head && head->reassembled_in != pinfo->fd->num) {

		    if (pdv->desc) {
			/* We know the presentation context already */
			g_snprintf(*pdv_description, MAX_BUF_LEN, "%s (reassembled in #%u)", pdv->desc, head->reassembled_in);
		    }
		    else {
			/* Decoding of the presentation context did not occure yet or did not succeed */
			g_snprintf(*pdv_description, MAX_BUF_LEN, "PDV Fragment (reassembled in #%u)", head->reassembled_in);
		    }
		}
		else {
		    /* We have done done any tag decoding yet */
		    g_snprintf(*pdv_description, MAX_BUF_LEN, "PDV Fragment");
		}

		offset += pdv_body_len;
	    }
	    else {
		/* Decode reassembled data */

		if (tree || have_tap_listener(dicom_eo_tap)) {
		    /* The performance optimization now starts at tag level.

		       During, tree can be NULL, but we need a few tags to be decoded,
		       i.e Class & Instance UID, so the export dialog has all information and
		       that the dicome header is complete
		    */
		    offset += dissect_dcm_pdv_body(next_tvb, pinfo, tree, pdv, 0, next_tvb->length, pdv_description);
		}

		if (have_tap_listener(dicom_eo_tap)) {
		    /* Copy pure DICOM data to buffer, no PDV flags */

		    pdv->data = g_malloc(next_tvb->length);      /* will be freed in dcm_export_create_object() */
                    tvb_memcpy(next_tvb, pdv->data, 0, next_tvb->length);
                    pdv->data_len = next_tvb->length;

		    /* Copy to export buffer */
		    dcm_export_create_object(pinfo, assoc, pdv);
		}
	    }
	}
    }
    else if (tree) {
	/* Do not reassemble PDVs, i.e. decode PDV one by one. Only execute when in detail mode */
	offset = dissect_dcm_pdv_body(tvb, pinfo, tree, pdv, offset, pdv_body_len, pdv_description);

	/* During DICOM Export, perform a few extra steps */
	if (have_tap_listener(dicom_eo_tap)) {
	    /* Copy pure DICOM data to buffer, no PDV flags */

	    pdv->data = g_malloc(pdv_body_len);      /* will be freed in dcm_export_create_object() */
            tvb_memcpy(tvb, pdv->data, startpos, pdv_body_len);
            pdv->data_len = pdv_body_len;

	    if ((pdv_body_len > 0) && (pdv->is_last_fragment)) {
		/* At the last segment, merge all related previous PDVs and copy to export buffer */
		dcm_export_create_object(pinfo, assoc, pdv);
	    }
	}
    }

    return offset;

}
static guint32
dissect_dcm_pdu_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		     dcm_state_assoc_t *assoc, guint32 offset, guint32 pdu_len, gchar **pdu_data_description)
{

    /*	04 P-DATA-TF
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

    proto_tree *pdv_ptree = NULL;	/* Tree for item details */
    proto_item *pdv_pitem = NULL;

    gchar  *buf_desc = NULL;		/* PDU description */
    gchar  *pdv_description = NULL;

    gboolean first_pdv = TRUE;

    guint32 endpos = 0;
    guint32 pdv_len = 0;

    endpos = offset + pdu_len;

    buf_desc=(gchar *)se_alloc0(MAX_BUF_LEN);	/* Valid for this capture, since we return this buffer */

    /* Loop through multiple PDVs */
    while (offset < endpos) {

	pdv_len = tvb_get_ntohl(tvb, offset);

	pdv_pitem = proto_tree_add_text(tree, tvb, offset, pdv_len+4, "PDV");
	pdv_ptree = proto_item_add_subtree(pdv_pitem, ett_dcm_data_pdv);

	if (pdv_len + 4 > pdu_len) {
	    expert_add_info_format(pinfo, pdv_pitem, PI_MALFORMED, PI_ERROR,
		"Invalid PDV length (too large)");
	    return endpos;
	}
	else if (pdv_len <= 2) {
	    expert_add_info_format(pinfo, pdv_pitem, PI_MALFORMED, PI_ERROR,
		"Invalid PDV length (too small)");
	    return endpos;
	}
	else if (((pdv_len >> 1) << 1) != pdv_len) {
	    expert_add_info_format(pinfo, pdv_pitem, PI_MALFORMED, PI_ERROR,
		"Invalid PDV length (not even)");
	    return endpos;
	}

	proto_tree_add_item(pdv_ptree, hf_dcm_pdv_len, tvb, offset, 4, FALSE);
	offset += 4;

	offset = dissect_dcm_pdv_fragmented(tvb, pinfo, pdv_ptree, assoc, offset, pdv_len, &pdv_description);

	/* The following doesn't seem to work anymore */
	if (pdv_description) {
	    if (first_pdv) {
		g_snprintf(buf_desc, MAX_BUF_LEN, "%s", pdv_description);
	    }
	    else {
		g_snprintf(buf_desc, MAX_BUF_LEN, "%s, %s", buf_desc, pdv_description);
	    }
	}

	proto_item_append_text(pdv_pitem, ", %s", pdv_description);
	first_pdv=FALSE;

    }

    *pdu_data_description = buf_desc;

    return offset;
}

static int
dissect_dcm_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_port_static)
{
    /* Code to actually dissect the packets */

    guint8  pdu_type = 0;
    guint32 pdu_start = 0;
    guint32 pdu_len = 0;
    guint16 vers = 0;
    guint32 tlen = 0;

    int offset = 0;

    /*
	Modified orignal code, which was optimized for a heuristic detection, and therefore
	caused some load and memory consumption, for every non DICOM packet not processed
	by someone else.

	Since tcp packets are now assembled well by wireshark (in conjunction with the dissectors)
	we will only see properly alligned PDUs, at the beginnig of the buffer, else its not DICOM
	traffic.

	Therfore do the byte checking as early as possible
	The heurisitc hook requires an association request

	DICOM PDU are nice, but need to be managed

	We can have any combination:
	- One or more DICOM PDU per TCP packet
	- PDU split over different TCP packets
	- And both together, i.e. some complete PDUs and then a fraction of a new PDU in a TCP packet

	This function will handle multiple PDUs per TCP packet and will ask for more data,
	if the last PDU does not fit

	It does not reassamble fragmented PDVs by purpose, since the Tag Value parsing needs to be done
	per Tag, and PDU recombinaion here would
	a) need to eliminate PDU/PDV/Ctx header (12 bytes)
	b) not show the true DICOM logic in transfer

	The length check is tricky. If not a PDV continuation, 10 Bytes are required. For PDV continuation
	anything seems to be possible, depending on the buffer alignment of the sending process.

    */

    tlen = tvb_reported_length(tvb);

    pdu_type = tvb_get_guint8(tvb, 0);
    if (pdu_type == 0 || pdu_type > 7) 		/* Wrong PDU type. 'Or' is slightly more efficient than 'and' */
	return 0;				/* No bytes taken from the stack */

    if (is_port_static) {
	/* Port is defined explicitly, or association request was previously found succesfully.
	   Be more tolerant on minimum packet size. Also accept < 6
	*/

	if (tlen < 6) {
	    /* we need 6 bytes at least to get PDU length */
	    pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return TRUE;
	}
    }
    else {
	/* We operate in heuristic mode, be picky out of performance reasons:

	   - Minimum 10 Bytes
	   - Look for the association request
	   - Reasonable PDU size

	   Tried find_conversation() and dcm_state_get() with no benefit

	   But since we are called in static mode, once we decoded the associtaion reqest and
	   called conversation_set_dissector(), we really only need to filter for an associtaion reqest

	*/

        if (tlen < 10) {
	    /* For all association handling ones, 10 bytes would be needed. Be happy with 6 */
	    return 0;
	}

	pdu_len = tvb_get_ntohl(tvb, 2);
	vers = tvb_get_ntohs(tvb, 6);

	/* Exit, if not a association request at version 1*/
	if (!(pdu_type == 1 && vers == 1)) {
	    return 0;
	}

	/* Exit if TCP payload is bigger than PDU length (plus header)
	   ok. for PRESENTATION_DATA, questionable for ASSOCIATION requests
	*/
	if (pdu_len+6 < tlen) {
	    return 0;
	}
    }


    /* Passing this point, we should always have tlen >= 6 */

    pdu_len = tvb_get_ntohl(tvb, 2);
    if (pdu_len < 4)                /* The smallest PDUs are ASSOC Rejects & Release Msgs */
	return 0;

    /* Mark it. This is a DICOM packet */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DICOM");

     /* Process all PDUs in the buffer */
    while (pdu_start < tlen) {
	guint32 old_pdu_start;

	if ((pdu_len+6) > (tlen-offset)) {

	    /*	PDU is larger than the remaing packet (buffer), therefore request whole PDU
		The next time this function is called, tlen will be equal to pdu_len
	    */

	    pinfo->desegment_offset = offset;
	    pinfo->desegment_len = (pdu_len+6) - (tlen-offset);

	    /*	Why return a boolean for a deliberate int function? No clue, but
		no better working example found.
	    */
	    return TRUE;
	}

	/* Process a whole PDU */
	offset=dissect_dcm_pdu(tvb, pinfo, tree, pdu_start);

	/* Next PDU */
	old_pdu_start = pdu_start;
	pdu_start =  pdu_start + pdu_len + 6;
	if (pdu_start <= old_pdu_start) {
	    expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR,
		"Invalid PDU length (%u)", pdu_len);
	    THROW(ReportedBoundsError);
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

/* Call back functions used to register */
static int
dissect_dcm_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Less checking on ports that match */
    return dissect_dcm_main(tvb, pinfo, tree, TRUE);
}

static int
dissect_dcm_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Only decode conerstations, which include an Association Request */
    /* This will be potentially called for every packet */
    return dissect_dcm_main(tvb, pinfo, tree, FALSE);
}

static guint32
dissect_dcm_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
    proto_tree *dcm_ptree=NULL;	    /* Root DICOM tree and its item */
    proto_item *dcm_pitem=NULL;

    dcm_state_t	*dcm_data=NULL;
    dcm_state_assoc_t *assoc=NULL;

    guint8  pdu_type=0;
    guint32 pdu_len=0;

    gchar *pdu_data_description=NULL;

    /* Get or create converstation. Used to store context IDs and xfer Syntax */

    dcm_data = dcm_state_get(pinfo, TRUE);
    if (dcm_data == NULL) {	/* Internal error. Failed to create main dicom data structre */
	return offset;
    }

    dcm_pitem = proto_tree_add_item(tree, proto_dcm, tvb, offset, -1, FALSE);
    dcm_ptree = proto_item_add_subtree(dcm_pitem, ett_dcm);

    pdu_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format(dcm_ptree, hf_dcm_pdu, tvb, offset, 2,
	pdu_type, "PDU Type 0x%x (%s)", pdu_type, dcm_pdu2str(pdu_type));
    offset += 2;

    pdu_len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(dcm_ptree, hf_dcm_pdu_len, tvb, offset, 4, FALSE);
    offset += 4;

    /* Find previously detected association, else create a new one object*/
    assoc = dcm_state_assoc_get(dcm_data, pinfo->fd->num, TRUE);

    if (assoc == NULL) {	/* Internal error. Failed to create association structre */
	return offset;
    }

    if (pdu_type == 4) {
	col_add_str(pinfo->cinfo, COL_INFO, "P-DATA");

	offset = dissect_dcm_pdu_data(tvb, pinfo, dcm_ptree, assoc, offset, pdu_len, &pdu_data_description);

	if (pdu_data_description) {
	    proto_item_append_text(dcm_pitem, ", %s", pdu_data_description);
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", pdu_data_description);
	}
    }
    else {

	/* Decode Association request, response, reject, abort details */
        offset = dissect_dcm_assoc_header(tvb, pinfo, dcm_ptree, offset, assoc, pdu_type, pdu_len);
    }

    return offset;	    /* return the number of processed bytes */
}

static void range_delete_dcm_tcp_callback(guint32 port) {
    dissector_delete_uint("tcp.port", port, dcm_handle);
}

static void range_add_dcm_tcp_callback(guint32 port) {
    dissector_add_uint("tcp.port", port, dcm_handle);
}

static void dcm_apply_settings(void) {

    /* deregister first */
    range_foreach(global_dcm_tcp_range_backup, range_delete_dcm_tcp_callback);
    g_free(global_dcm_tcp_range_backup);

    heur_dissector_delete("tcp", dissect_dcm_heuristic, proto_dcm);

    /*	Register 'static' tcp port range specified in properties
	Statically defined ports take precedence over a heuristic one,
	I.e., if an foreign protocol claims a port, where dicom is running on
	We would never be called, by just having the heuristic registration
    */

    range_foreach(global_dcm_tcp_range, range_add_dcm_tcp_callback);

    /* remember settings for next time */
    global_dcm_tcp_range_backup = range_copy(global_dcm_tcp_range);

    /*	Add heuristic search, if user selected it */

    if (global_dcm_heuristic)
	heur_dissector_add("tcp", dissect_dcm_heuristic, proto_dcm);

}

/* Register the protocol with Wireshark */

void
proto_register_dcm(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
    { &hf_dcm_pdu, { "PDU Type", "dicom.pdu.type",
	FT_UINT8, BASE_HEX, VALS(dcm_pdu_ids), 0, NULL, HFILL } },
    { &hf_dcm_pdu_len, { "PDU Length", "dicom.pdu.len",
	FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pdu_type, { "PDU Detail", "dicom.pdu.detail",
	FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

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
    { &hf_dcm_pctx_result, { "Presentation Context Result", "dicom.pctx.id",
	FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pctx_abss_syntax, { "Abstract Syntax", "dicom.pctx.abss.syntax",
	FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_pctx_xfer_syntax, { "Transfer Syntax", "dicom.pctx.xfer.syntax",
	FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_uid, { "Implementation Class UID", "dicom.userinfo.uid",
	FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_dcm_info_version, { "Implementation Version", "dicom.userinfo.version",
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

/*
    { &hf_dcm_FIELDABBREV, { "FIELDNAME", "dicom.FIELDABBREV",
	FIELDTYPE, FIELDBASE, FIELDCONVERT, BITMASK, "FIELDDESCR", HFILL } },
 */
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
	    &ett_dcm_data,
	    &ett_dcm_data_pdv,
	    &ett_dcm_data_tag,
	    &ett_dcm_data_seq,
	    &ett_dcm_data_item,
	    &ett_dcm_pdv,		/* used for fragments */
	    &ett_dcm_pdv_fragment,
	    &ett_dcm_pdv_fragments
    };

    module_t *dcm_module;

    /* Register the protocol name and description */
    proto_dcm = proto_register_protocol("DICOM", "DICOM", "dicom");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_dcm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dcm_module = prefs_register_protocol(proto_dcm, dcm_apply_settings);

    range_convert_str(&global_dcm_tcp_range, DICOM_DEFAULT_RANGE, 65535);
    global_dcm_tcp_range_backup = range_empty();
    prefs_register_range_preference(dcm_module, "tcp.port",
	"DICOM Ports", "DICOM Ports range", &global_dcm_tcp_range, 65535);

    prefs_register_bool_preference(dcm_module, "heuristic",
	    "Search on any TCP Port (heuristic mode)",
	    "When enabled, the DICOM dissector will parse all TCP packets "
	    "not handled by any other dissector and look for an association request. "
	    "Disabled by default, to preserve resources for the non DICOM community.",
	    &global_dcm_heuristic);

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
	    "Deselect this option, if you prefer a flat display or e.g. "
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
	    "When not set, the decoding may fail and the exports may become corrupt.",
	    &global_dcm_reassemble);

    dicom_eo_tap = register_tap("dicom_eo"); /* DICOM Export Object tap */

    register_init_routine(&dcm_init);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_dcm(void)
{

    dcm_handle = new_create_dissector_handle(dissect_dcm_static, proto_dcm);

    dcm_apply_settings();	/* Register static and heuristic ports */

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
    1 source  (1 service user, 2 service provider, 3 service profider)
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
