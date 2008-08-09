/* packet-dcm.c
 * Routines for DICOM dissection
 * Copyright 2003, Rich Coe <Richard.Coe@med.ge.com>
 * Copyright 2008, David Aggeler <david_aggeler@hispeed.ch>
 *
 * DICOM communication protocol
 * http://medical.nema.org/dicom/2008
 *   DICOM Part 8: Network Communication Support for Message Exchange
 *
 * (NOTE: you need to turn on 'Allow subdissector to desegment TCP streams'
 *        in Preferences/Protocols/TCP Option menu, in order to view
 *        DICOM packets correctly.
 *        Also, you might have to turn off tcp.check_checksum if tcp
 *        detects that the checksum is bad - for example, if you're
 *        capturing on a network interface that does TCP checksum
 *        offloading and you're capturing outgoing packets.
 *        This should probably be documented somewhere besides here.)
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Notes:
 * This is my first pass at a Wireshark dissector to display
 * DICOM (Digital Imaging and Communications in Medicine) packets.
 *
 * - It currently displays most of the DICOM packets.
 *
 * - I've used it to debug Query/Retrieve, Storage, and Echo protocols.
 *
 * - Not all DICOM tags are currently displayed symbolically.
 *   Unknown tags are displayed as '(unknown)'
 *   More known tags might be added in the future.
 *   If the tag data contains a string, it will be displayed.
 *   Even if the tag contains Explicit VR, it is not currently used to
 *   symbolically display the data.  Consider this a future enhancement.
 *
 * - The 'value to string' routines should probably be hash lookups.
 *
 * 9 Nov 2004, Rich Coe
 * - Fixed the heuristic code -- sometimes a conversation already exists
 * - Fixed the dissect code to display all the tags in the pdu
 *
 * 28 Apr 2005, Rich Coe
 * - fix memory leak when Assoc packet is processed repeatedly in wireshark
 *
 * - removed unused partial packet flag
 *
 * - added better support for DICOM VR
 *	- sequences
 *	- report actual VR in packet display, if supplied by xfer syntax
 *	- show that we are not displaying entire tag string with '[...]',
 *	  some tags can hold up to 2^32-1 chars
 *
 * - remove my goofy attempt at trying to get access to the fragmented packets
 *   (anyone have an idea on how to fix this ???)
 *
 * - process all the data in the Assoc packet even if display is off
 *
 * - limit display of data in Assoc packet to defined size of the data even
 *   if reported size is larger
 *
 * - show the last tag in a packet as [incomplete] if we don't have all the data
 *
 * - added framework for reporting DICOM async negotiation (not finished)
 *   (I'm not aware of an implementation which currently supports this)
 *
 *
 * May 23 2008, David Aggeler
 *
 * - Added Class UID lookup, both in the association and in the transfer
 * - Better hierarchy for items in Association request/response and therefore better overview
 *   This was a major rework. Abstract Syntax & Transfer Syntax are now children
 *   of a presentation context and therefore grouped. User Info is now grouped.
 * - Re-assemble PDVs that span multiple PDUs, i.e fix continuation packets
 *   This caused significant changes to the data structures
 * - Added preference with dicom tcp ports, to prevent 'stealing' the converstation
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
 * Jun 17 2008, David Aggeler
 *
 * - Support multiple PDVs per PDU
 * - Better summary, in PDV, PDU header and in INFO Column, e.g. show commands like C-STORE
 * - Fixed Association Reject (was working before my changes)
 * - Fixed PDV Continuation with very small packets. Reduced minimum packet length
 *   from 10 to 2 Bytes for PDU Type 4
 * - Fixed PDV Continuation. Last packet was not found correctly.
 * - Fixed complilation warning (build 56 on solaris)
 * - Fixed tree expansion (hf_dcm_xxx)
 * - Added expert_add_info() for Assoctiation Reject
 * - Added expert_add_info() for Assoctiation Abort
 * - Added expert_add_info() for short PDVs (i.e. last fragment, but PDV is not completed yet)
 * - Clarified and grouped data structures and its related code (dcmItem, dcmState) to have
 *   consistent _new() & _get() functions and to be be according to coding conventions
 * - Added more function declaration to be more consistent
 * - All dissect_dcm_xx now have (almost) the same parameter order
 * - Removed DISSECTOR_ASSERT() for packet data errors. Not designed to handle this.
 * - Handle multiple DICOM Associations in a capture correctly, i.e. if presentation contexts are different.
 *
 * Jul 17 2008, David Aggeler
 *
 * - Export objects as part 10 compliant DICOM file. Finally, this major milestone has beed reached.
 * - PDVs are now a child of the PCTX rather than the ASSOC object.
 * - Fixed PDV continuation for unknown tags (e.g. RT Structure Set)
 * - Replaced proprietary trim() with g_strstrip()
 * - Fixed strings that are displayed with /000 (padding of odd length)
 * - Added expert_add_info() for invalid flags and presentation context IDs
 *
 * Jul 25 2008, David Aggeler
 * 
 * - Replaced guchar with gchar, since it caused a lot of warnings on solaris. 
 * - Moved a little more form the include to this one to be consistent
 *
 * ****************************************************************************************
 * - Still ToDo
 *   Decent error handlung for expert_add_info(), i.e. return value handling and info column text
 *   Support almost all tags
 *   Show tags as subtree
 *   Show Association Headers as individual items
 *   Cleanup types of offset & position
 *   Create subtrees for sequences
 *   Support item 56-59 in Accociation Request
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "isprint.h"

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/tap.h>

#include "packet-tcp.h"

#include "packet-dcm.h"

#define DICOM_DEFAULT_RANGE "104"

/* Many thanks to http://medicalconnections.co.uk/ for the GUID */
#define WIRESHARK_IMPLEMENTATION_UID			"1.2.826.0.1.3680043.8.427.10"
#define WIRESHARK_MEDIA_STORAGE_SOP_CLASS_UID		"1.2.826.0.1.3680043.8.427.11.1"
#define WIRESHARK_MEDIA_STORAGE_SOP_INSTANCE_UID_PREFIX	"1.2.826.0.1.3680043.8.427.11.2"
#define WIRESHARK_IMPLEMENTATION_VERSION		"WIRESHARK"

static range_t *global_dcm_tcp_range = NULL;
static range_t *global_dcm_tcp_range_backup = NULL;	    /* needed to deregister */

static gboolean global_dcm_heuristic = FALSE;
static gboolean global_dcm_header = TRUE;

/* Initialize the protocol and registered fields */
static int proto_dcm = -1;

static int dicom_eo_tap = -1;

static int hf_dcm_pdu = -1,
    hf_dcm_pdu_len = -1,
    hf_dcm_pdu_type = -1,
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
    hf_dcm_data_tag = -1;

/* Initialize the subtree pointers */
static gint
    ett_dcm = -1,
    ett_assoc = -1,
    ett_assoc_actx = -1,
    ett_assoc_pctx = -1,
    ett_assoc_pctx_abss = -1,
    ett_assoc_pctx_xfer = -1,
    ett_assoc_info = -1,
    ett_assoc_info_uid = -1,
    ett_assoc_info_version = -1,
    ett_dcm_data = -1,
    ett_dcm_data_pdv = -1,
    ett_dcm_data_tag = -1;

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

/*
    Per Data PDV store data needed, to allow decoding of tags longer than a PDV
*/
typedef struct dcm_state_pdv {

    struct dcm_state_pdv *next, *prev;

    gboolean initalized;	/* define, wheter open_tag_len, open_tag_rlen and open_tag_desc have been set */
    guint32  packet_no;		/* Wireshark packet number, where pdv starts */
    guint32  offset;		/* Offset in packet, where PDV header starts */

    gchar   *desc;		/* PDV description.	    se_alloc()	*/

    guint8  pctx_id;		/* Reference to used Presentation Context */

    /* Used and filled for Export Object only */
    gpointer data;		/* Copy of PDV data without any PDU/PDV header */
    guint32  data_len;		/* Length of this PDV buffer. If >0, memory has been alocated */

    gchar   *sop_class_uid;	/* SOP Class UID.    Set in 1st PDV of a DICOM object. se_alloc() */
    gchar   *sop_instance_uid;	/* SOP Instance UID. Set in 1st PDV of a DICOM object. se_alloc() */
    /* End Export use */

    gboolean is_storage;	/* Ture, if the Data PDV is on the context of a storage SOP Class */
    gboolean is_flagvalid;	/* The following two flags are initalized correctly (TBD if needed) */
    gboolean is_command;	/* This PDV is a command rather than a data package */
    gboolean is_last_fragment;	/* Last Fragment bit was set, i.e. termination of an object
				   This flag delimits different dicom object in the same
				   association */
    gboolean is_corrupt;	/* Early termination of long PDVs */

    /* Used to reassemble PDVs */
    guint32 open_tag_len;	/* Tag lenght of 'oversized' tags. Used for display */
    guint32 open_tag_rlen;	/* Remining tag bytes to 'decoded' as binary data after this PDV */
    gchar  *open_tag_desc;	/* last decoded description */

} dcm_state_pdv_t;

/*
    Per Presentation Context in an association store data needed, for subsequent decoding
*/
typedef struct dcm_state_pctx {

    struct dcm_state_pctx *next, *prev;

    guint8 id;			/* 0x20 Presentation Context ID */
    gchar *abss_uid;		/* 0x30 Abstract syntax */
    gchar *abss_desc;		/* 0x30 Abstract syntax decoded*/
    gchar *xfer_uid;		/* 0x40 Acepted Transfer syntax */
    gchar *xfer_desc;		/* 0x40 Acepted Transfer syntax decoded*/
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
    guint8 source, result, reason;
} dcm_state_assoc_t;

typedef struct dcm_state {

    struct dcm_state_assoc *first_assoc, *last_assoc;

    gboolean valid;			/* this conversation is a DICOM conversation */

} dcm_state_t;


/* Following defines around tags have a potential to be merged */
typedef struct dcmTag {
    guint32 tag;
    int dtype;
    const char *desc;
#define DCM_TSTR  1
#define DCM_TINT2 2
#define DCM_TINT4 3
#define DCM_TFLT  4
#define DCM_TDBL  5
#define DCM_TSTAT 6	/* call dcm_rsp2str() on TINT2 */
#define DCM_TRET  7
#define DCM_TCMD  8
#define DCM_SQ    9 	/* sequence */
#define DCM_OTH   10    /* other */
} dcmTag_t;


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
static const gchar* dcm_tag_lookup[] = {
    "  ",
    "AE","AS","AT","CS","DA","DS","DT","FL",
    "FD","IS","LO","LT","OB","OF","OW","PN",
    "SH","SL","SQ","SS","ST","TM","UI","UL",
    "UN","US","UT"
};


static GHashTable *dcm_tagTable = NULL;

static dcmTag_t tagData[] = {
    {  0x1,    DCM_TRET,  "(Ret) Length to End" },
    {  0x2,    DCM_TSTR,  "Affected Class" },
    {  0x3,    DCM_TSTR,  "Requested Class" },
    {  0x0010, DCM_TRET,  "(Ret) Recognition Code" },
    {  0x0100, DCM_TCMD,  "Command Field" },
    {  0x0110, DCM_TINT2, "Message ID" },
    {  0x0120, DCM_TINT2, "Resp Message ID" },
    {  0x0200, DCM_TRET,  "(Ret) Initiator" },
    {  0x0300, DCM_TRET,  "(Ret) Reciever" },
    {  0x0400, DCM_TRET,  "(Ret) Find Location" },
    {  0x0600, DCM_TSTR,  "Dest AE" },
    {  0x0700, DCM_TINT2, "Priority" },
    {  0x0800, DCM_TINT2, "Data Set (0x0101 means no data set present)" },
    {  0x0850, DCM_TRET,  "(Ret) Num Matches" },
    {  0x0860, DCM_TRET,  "(Ret) Resp Seq Num" },
    {  0x0900, DCM_TSTAT, "Status" },
    {  0x0901, DCM_TSTR,  "Offending elm(s)" },
    {  0x0902, DCM_TSTR,  "Error Comment" },
    {  0x0903, DCM_TINT2, "Error Id" },
    {  0x1000, DCM_TSTR,  "Affected Instance UID" },
    {  0x1001, DCM_TSTR,  "Requested Instance UID" },
    {  0x1002, DCM_TINT2, "Event Type Id" },
    {  0x1005, DCM_TSTR,  "Attr Id List" },
    {  0x1008, DCM_TINT2, "Action Type Id" },
    {  0x1020, DCM_TINT2, "Num Remaining Ops" },
    {  0x1021, DCM_TINT2, "Num Completed Ops" },
    {  0x1022, DCM_TINT2, "Num Failed Ops" },
    {  0x1023, DCM_TINT2, "Num Warning Ops" },
    {  0x1030, DCM_TSTR,  "Move ae_called AE" },
    {  0x1031, DCM_TINT2, "Move ae_called Id" },
    {  0x4000, DCM_TRET,  "(Ret) DIALOG Recv'r" },
    {  0x4010, DCM_TRET,  "(Ret) Terminal Type" },
    {  0x5010, DCM_TRET,  "(Ret) Msg Set ID" },
    {  0x5020, DCM_TRET,  "(Ret) End Msg ID" },
    {  0x5110, DCM_TRET,  "(Ret) Display Fmt" },
    {  0x5120, DCM_TRET,  "(Ret) Page Position ID" },
    {  0x5130, DCM_TRET,  "(Ret) Text Fmt ID" },
    {  0x5140, DCM_TRET,  "(Ret) Nor/Rev" },
    {  0x5150, DCM_TRET,  "(Ret) Add Gray Scale" },
    {  0x5160, DCM_TRET,  "(Ret) Borders" },
    {  0x5170, DCM_TRET,  "(Ret) Copies" },
    {  0x5180, DCM_TRET,  "(Ret) Mag Type" },
    {  0x5190, DCM_TRET,  "(Ret) Erase" },
    {  0x51a0, DCM_TRET,  "(Ret) Print" },
    {  0x080018, DCM_TSTR, "Image UID" },
    {  0x080020, DCM_TSTR, "Study Date" },
    {  0x080030, DCM_TSTR, "Study Time" },
    {  0x080050, DCM_TSTR, "Acc Num" },
    {  0x080052, DCM_TSTR, "Q/R Level" },
    {  0x080054, DCM_TSTR, "Retrieve AE" },
    {  0x080060, DCM_TSTR, "Modality" },
    {  0x080070, DCM_TSTR, "Manuf" },
    {  0x081030, DCM_TSTR, "Study Desc" },
    {  0x08103e, DCM_TSTR, "Series Desc" },
    {  0x100010, DCM_TSTR, "Patient Name" },
    {  0x100020, DCM_TSTR, "Patient Id" },
    {  0x20000d, DCM_TSTR, "Study UID" },
    {  0x20000e, DCM_TSTR, "Series UID" },
    {  0x200010, DCM_TSTR, "Study Num" },
    {  0x200011, DCM_TSTR, "Series Num" },
    {  0x200012, DCM_TSTR, "Acq Num" },
    {  0x200013, DCM_TSTR, "Image Num" },
    {  0x7fe00010, DCM_OTH, "Pixels" },
    {  0xfffee000, DCM_TRET, "Item Begin" },
    {  0xfffee00d, DCM_TRET, "Item End" },
    {  0xfffee0dd, DCM_TRET, "Sequence End" },
};

static GHashTable *dcm_uid_table = NULL;


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
    const char *value;
    const char *name;
    const char *type;
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
};

/* following definitions are used to call dissect_dcm_assoc_item() */
#define DCM_ITEM_VALUE_TYPE_UID	    1
#define DCM_ITEM_VALUE_TYPE_STRING  2
#define DCM_ITEM_VALUE_TYPE_UINT32  3

/* A few function declataions */

/* Per object, a xxx_new() and a xxx_get() function. The _get() will create one if specified. */

static dcm_state_t*	 dcm_state_new(void);
static dcm_state_t*	 dcm_state_get(packet_info *pinfo, gboolean create);

static dcm_state_assoc_t*   dcm_state_assoc_new (dcm_state_t *dcm_data, guint32 packet_no);
static dcm_state_assoc_t*   dcm_state_assoc_get (dcm_state_t *dcm_data, guint32 packet_no, gboolean create);
static dcm_state_pctx_t*    dcm_state_pctx_new	(dcm_state_assoc_t *assoc, guint8 pctx_id);
static dcm_state_pctx_t*    dcm_state_pctx_get	(dcm_state_assoc_t *assoc, guint8 pctx_id, gboolean create);
static dcm_state_pdv_t*	    dcm_state_pdv_new	(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset);
static dcm_state_pdv_t*	    dcm_state_pdv_get	(dcm_state_pctx_t *pctx, guint32 packet_no, guint32 offset, gboolean create);

static int  dissect_dcm_static	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int  dissect_dcm_heuristic   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int  dissect_dcm_main	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean require_assoc_req);
static int  dissect_dcm_pdu	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

static int  dissect_dcm_assoc       (tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,   dcm_state_assoc_t *assoc, int offset, int len);
static void dissect_dcm_pctx	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, int offset, int len, gchar *pitem_prefix, gboolean request);
static void dissect_dcm_assoc_item  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, int offset, gchar *pitem_prefix, int item_value_type, gchar **item_value, gchar **item_description, int *hf_type, int *hf_len, int *hf_value, int ett_subtree);
static void dissect_dcm_userinfo    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, int offset, int len, gchar *pitem_prefix);

static int  dissect_dcm_data	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, int offset, guint32 pdu_len, gchar **pdu_description);
static int  dissect_dcm_pdv	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, int offset, guint32 pdv_len, gchar **pdv_description);
static int  dissect_dcm_pdv_header  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dcm_state_assoc_t *assoc, int offset, guint8 *syntax, dcm_state_pdv_t **pdv);

static void dcm_set_syntax		(dcm_state_pctx_t *pctx, gchar *xfer_uid, gchar *xfer_desc);
static void dcm_export_create_object	(packet_info *pinfo, dcm_state_assoc_t *assoc, dcm_state_pdv_t *pdv);

static void
dcm_init(void)
{

    if (NULL == dcm_tagTable) {
	unsigned int i;
	dcm_tagTable = g_hash_table_new(NULL, NULL);
	for (i = 0; i < sizeof(tagData) / sizeof(dcmTag_t); i++)
	    g_hash_table_insert(dcm_tagTable, GINT_TO_POINTER(tagData[i].tag),
		(gpointer) (tagData+i));
    }

    if (NULL == dcm_uid_table) {
	unsigned int i;
	dcm_uid_table = g_hash_table_new(g_str_hash, g_str_equal);
	for (i = 0; i < sizeof(dcm_uid_data) / sizeof(dcm_uid_t); i++)
	    g_hash_table_insert(dcm_uid_table, (gpointer) dcm_uid_data[i].value, (gpointer) dcm_uid_data[i].name);

    }

}

static dcm_state_t *
dcm_state_new(void)
{
    /* Not much fun. Just create very simple root structure */

    dcm_state_t *ds=NULL;

    ds = (dcm_state_t *) se_alloc(sizeof(dcm_state_t));
    if (ds) {
	ds->first_assoc=NULL;
	ds->last_assoc=NULL;
    }
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
	dcm_data = conversation_get_proto_data(conv, proto_dcm);
    }

    if (dcm_data == NULL && create) {

	dcm_data = dcm_state_new();
	if (dcm_data != NULL) {
	    conversation_add_proto_data(conv, proto_dcm, dcm_data);
	}

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

    assoc = (dcm_state_assoc_t *) g_malloc(sizeof(dcm_state_assoc_t));
    if (assoc) {

	assoc->next = NULL;
	assoc->prev = NULL;
	assoc->packet_no = packet_no;	    /* Identifier */

	assoc->first_pctx = NULL;	    /* List of Presentation context objects */
	assoc->last_pctx  = NULL;

	memset(assoc->ae_called, 0, sizeof(assoc->ae_called));
	memset(assoc->ae_calling, 0, sizeof(assoc->ae_calling));
	memset(assoc->ae_called_resp, 0, sizeof(assoc->ae_called_resp));
	memset(assoc->ae_calling_resp, 0, sizeof(assoc->ae_calling_resp));

	/* add to the end of the list */
	if (dcm_data->last_assoc) {
	    dcm_data->last_assoc->next = assoc;
	    assoc->prev = dcm_data->last_assoc;
	}
	else {
	    dcm_data->first_assoc = assoc;
	}
	dcm_data->last_assoc = assoc;
    }
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

    pctx = se_alloc(sizeof(dcm_state_pctx_t));
    if (pctx) {

	pctx->next = NULL;
	pctx->prev = NULL;

	pctx->id = pctx_id;

	pctx->abss_uid = NULL;
	pctx->abss_desc = NULL;
	pctx->xfer_uid = NULL;
	pctx->xfer_desc = NULL;
	pctx->syntax = DCM_UNK;

	pctx->first_pdv = NULL;	    /* List of PDV objects */
	pctx->last_pdv  = NULL;

	/* add to the end of the list list */
	if (assoc->last_pctx) {
	    assoc->last_pctx->next = pctx;
	    pctx->prev = assoc->last_pctx;
	}
	else {
	    assoc->first_pctx = pctx;
	}
	assoc->last_pctx = pctx;
    }

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

    dcm_state_pdv_t *pdv=NULL;

    pdv = (dcm_state_pdv_t *) se_alloc(sizeof(dcm_state_pdv_t));
    if (pdv != NULL) {

	pdv->prev = NULL;
	pdv->next = NULL;

	pdv->data = NULL;
	pdv->data_len = 0;
	pdv->pctx_id = 0;

	pdv->desc = NULL;

	pdv->sop_class_uid = NULL;
	pdv->sop_instance_uid = NULL;

	pdv->is_storage = FALSE;
	pdv->is_flagvalid = FALSE;
	pdv->is_command = FALSE;
	pdv->is_last_fragment = TRUE;	/* Continuation PDVs are more tricky */
	pdv->is_corrupt = FALSE;

	pdv->packet_no = packet_no;
	pdv->offset = offset;
	pdv->initalized = FALSE;
	pdv->open_tag_desc = NULL;
	pdv->open_tag_len = 0;
	pdv->open_tag_rlen = 0;

	/* add to the end of the list list */
	if (pctx->last_pdv) {
	    pctx->last_pdv->next = pdv;
	    pdv->prev = pctx->last_pdv;
	}
	else {
	    pctx->first_pdv = pdv;
	}
	pctx->last_pdv = pdv;
    }
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
    case 0x10: s = "Application Context"; break;
    case 0x20: s = "Presentation Context"; break;
    case 0x21: s = "Presentation Context Reply"; break;
    case 0x30: s = "Abstract syntax"; break;
    case 0x40: s = "Transfer syntax"; break;
    case 0x50: s = "User Info"; break;
    case 0x51: s = "Max Length"; break;
    default: break;
    }
    return s;
}

static const char *
dcm_result2str(guint8 result)
{
    const char *s = "";
    switch (result) {
    case 1:  s = "Reject Permanent"; break;
    case 2:  s = "Reject Transient"; break;
    default: break;
    }
    return s;
}

static const char *
dcm_source2str(guint8 source)
{
    const char *s = "";
    switch (source) {
    case 1:  s = "User"; break;
    case 2:  s = "Provider (ACSE)"; break;
    case 3:  s = "Provider (Presentation)"; break;
    default: break;
    }
    return s;
}

static const char *
dcm_reason2str(guint8 source, guint8 reason)
{
    const char *s = "";
    if (1 == source) switch (reason) {
	case 1:  s = "No reason"; break;
	case 2:  s = "App Name not supported"; break;
	case 3:  s = "calling AET not recognized"; break;
	case 7:  s = "called AET not recognized"; break;
	default: break;
    } else if (2 == source) switch (reason) {
	case 1:  s = "No reason"; break;
	case 2:  s = "protocol unsupported"; break;
	default: break;
    } else if (3 == source) switch (reason) {
	case 1:  s = "temporary congestion"; break;
	case 2:  s = "local limit exceeded"; break;
	default: break;
    }
    return s;
}

static const char *
dcm_abort2str(guint8 reason)
{
    const char *s = "";
    switch (reason) {
    case 0:  s = "not specified"; break;
    case 1:  s = "unrecognized"; break;
    case 2:  s = "unexpected"; break;
    case 4:  s = "unrecognized parameter"; break;
    case 5:  s = "unexpected parameter"; break;
    case 6:  s = "invalid parameter"; break;
    default: break;
    }
    return s;
}

static const char *
dcm_PCresult2str(guint8 result)
{
    const char *s = "";
    switch (result) {
    case 0:  s = "Accept"; break;
    case 1:  s = "User Reject"; break;
    case 2:  s = "No Reason"; break;
    case 3:  s = "Abstract Syntax Unsupported"; break;
    case 4:  s = "Transfer Syntax Unsupported"; break;
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

static const char *
dcm_rsp2str(guint16 us)
{
    const char *s = "";
    switch (us) {
    case 0x0000:  s = "Success"; break;
    case 0xa701:
    case 0xa702:  s = "Refused: Out of Resources"; break;
    case 0xa801:  s = "Refused: Move Destination unknown"; break;
    case 0xa900:  s = "Failed:  Id does not match Class"; break;
    case 0xb000:  s = "Warning: operations complete -- One or more Failures"; break;
    case 0xfe00:  s = "Cancel:  operations terminated by Cancel"; break;
    case 0xff00:  s = "Pending: operations are continuing"; break;
    default: break;
    }
    if (0xC000 == (0xF000 & us))  s = "Failed:  Unable to Process";
    return s;
}

static gchar*
dcm_uid_or_desc(gchar *dcm_uid, gchar *dcm_desc)
{
    /* Return Description, UID or error */

    return (dcm_desc == NULL ? (dcm_uid == NULL ? (gchar *)"Malformed Packet" : dcm_uid) : dcm_desc);
}

static void
dcm_set_syntax(dcm_state_pctx_t *pctx, gchar *xfer_uid, gchar *xfer_desc)
{
    if (pctx == NULL)
	return;

    if (pctx->xfer_uid != NULL)
	g_free(pctx->xfer_uid);	/* free prev allocated xfer */
    if (pctx->xfer_desc != NULL)
	g_free(pctx->xfer_desc);	/* free prev allocated xfer */

    pctx->syntax = 0;
    pctx->xfer_uid = g_strdup(xfer_uid);
    pctx->xfer_desc = g_strdup(xfer_desc);

    if (xfer_uid == NULL) return;
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

static gchar*
dcm_tag2str(guint16 grp, guint16 elm, guint8 syntax, tvbuff_t *tvb, int offset, guint32 len, int vr, int tr, gchar **tag_value)
{
    gchar *buf;
    const gchar *vval;
    gchar *p;

    guint32 tag, val32=0;
    guint16 val16=0;
    guint8  val8=0;
    dcmTag_t *dtag;
    static dcmTag_t utag = { 0, 0, "(unknown)" };

#define MAX_BUF_LEN 1024

    buf=ep_alloc(MAX_BUF_LEN);
    *tag_value = se_alloc(MAX_BUF_LEN);

    *buf = 0;
    if (0 == elm) {
	if (DCM_ILE & syntax)
	     val32 = tvb_get_letohl(tvb, offset);
	else val32 = tvb_get_ntohl(tvb, offset);
	g_snprintf(buf, MAX_BUF_LEN, "Group Length 0x%x (%d)", val32, val32);
	return buf;
    }
    tag = (grp << 16) | elm;
    if (NULL == (dtag = g_hash_table_lookup(dcm_tagTable, GUINT_TO_POINTER(tag))))
	dtag = &utag;

    DISSECTOR_ASSERT(MAX_BUF_LEN > strlen(dtag->desc));
    p=buf;
    p+=MIN(MAX_BUF_LEN-(p-buf),
	   g_snprintf(p, MAX_BUF_LEN-(p-buf), "%s", dtag->desc));
    if (vr > 0) {
	vval = tvb_format_text(tvb, vr, 2);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " [%s]", vval));
    }

    switch (tr > 0 ? tr : dtag->dtype) {
    case DCM_TSTR:
    default:		/* try ascii */

	val8 = tvb_get_guint8(tvb, offset+len-1);
	if (val8 == 0x00) {
	    /* Last byte of string is 0x00, i.e. padded */
	    vval = tvb_format_text(tvb, offset, len-1);
	}
	else {
	    vval = tvb_format_text(tvb, offset, len);
	}
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " %s", vval));

        g_snprintf(*tag_value, MAX_BUF_LEN, "%s", vval);

	break;
    case DCM_TINT2:
	if (DCM_ILE & syntax)
	     val16 = tvb_get_letohs(tvb, offset);
	else val16 = tvb_get_ntohs(tvb, offset);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " 0x%x (%d)", val16, val16));
	break;
    case DCM_TINT4:
	if (DCM_ILE & syntax)
	     val32 = tvb_get_letohl(tvb, offset);
	else val32 = tvb_get_ntohl(tvb, offset);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " 0x%x (%d)", val32, val32));
	break;
    case DCM_TFLT: {
	gfloat valf;
	if (DCM_ILE & syntax)
	     valf = tvb_get_letohieee_float(tvb, offset);
	else valf = tvb_get_ntohieee_float(tvb, offset);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " (%f)", valf));
	} break;
    case DCM_TDBL: {
	gdouble vald;
	if (DCM_ILE & syntax)
	     vald = tvb_get_letohieee_double(tvb, offset);
	else vald = tvb_get_ntohieee_double(tvb, offset);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " (%f)", vald));
	} break;
    case DCM_TSTAT: /* call dcm_rsp2str() on TINT2 */
	if (DCM_ILE & syntax)
	     val16 = tvb_get_letohs(tvb, offset);
	else val16 = tvb_get_ntohs(tvb, offset);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " 0x%x '%s'", val16, dcm_rsp2str(val16)));
	break;
    case DCM_TCMD:   /* call dcm_cmd2str() on TINT2 */
	if (DCM_ILE & syntax)
	     val16 = tvb_get_letohs(tvb, offset);
	else val16 = tvb_get_ntohs(tvb, offset);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " 0x%x '%s'", val16, dcm_cmd2str(val16)));

	g_snprintf(*tag_value, MAX_BUF_LEN, "%s", dcm_cmd2str(val16));
	break;
    case DCM_SQ:	/* Sequence */
    case DCM_OTH:	/* Other BYTE, WORD, ... */
    case DCM_TRET:	/* Retired */
	break;
    }
    return buf;
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
dcm_export_create_tag_base(guint8 *buffer, guint32 bufflen _U_, guint32 offset,
 			   guint16 grp, guint16 elm, guint16 vr,
			   guint8 *value_buffer, guint32 value_len)

    /*  Only Explict Littele Endian is needed to create Metafile Header
	Generic function to write a TAG, VR, LEN & VALUE to a combined buffer
	The value (buffer, len) must be preprocessed by a VR specific function
    */
{
    guint8 *pos=NULL;

    pos=buffer+offset;

    dcm_guint16_to_le(pos, grp);
    pos+=2;
    dcm_guint16_to_le(pos, elm);
    pos+=2;

    memmove(pos, dcm_tag_lookup[vr], 2);
    pos+=2;

    switch (vr) {
    case DCM_VR_OB:
    case DCM_VR_OW:
    case DCM_VR_OF:
    case DCM_VR_SQ:
    case DCM_VR_UT:
    case DCM_VR_UN:
	/* DICOM likes it complicated. Special handling for these types */

	/* Add two reserved 0x00 bytes */
	dcm_guint16_to_le(pos, 0);
	pos+=2;

	/* Length is a 4 byte field */
        dcm_guint32_to_le(pos, (guint32)value_len);
	pos+=4;
	break;

    default:
	/* Length is a 2 byte field */
        dcm_guint16_to_le(pos, (guint16)value_len);
	pos+=2;
    }

    memmove(pos, value_buffer, value_len);
    pos+=value_len;

    return pos-buffer;
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
			  guint16 grp, guint16 elm, guint16 vr, gchar *value)
{
    guint16 len;

    if (!value) {
	/* NULL object. E.g. happens if UID was not found/set. Don't create element*/
	return offset;
    }

    len=strlen(value);

    if ((len & 0x01) == 1) {
	/*  Odd length: since buffer is 0 initalized, pad with a 0x00 */
	len += 1;
    }

    return dcm_export_create_tag_base(buffer, bufflen, offset, grp, elm, vr,
	(guint8*)value, len);
}


static guint8*
dcm_export_create_header(guint32 *dcm_header_len, gchar *sop_class_uid, gchar *sop_instance_uid, gchar *xfer_uid)
{
    guint8	*dcm_header=NULL;
    guint32	offset=0;
    guint32	offset_header_len=0;

#define DCM_HEADER_MAX 512

    dcm_header=ep_alloc(DCM_HEADER_MAX);	/* Slightly longer than needed */

    memset(dcm_header, 0, DCM_HEADER_MAX);	/* The subsequent functions rely on a 0 intitalized buffer */
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

    /* Finally write the meta header lenght */
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
    gchar      *filename = NULL;
    gchar      *hostname = NULL;

    gchar	*sop_class_uid = NULL;
    gchar	*sop_instance_uid = NULL;

    /* Calculate total PDV lenghth, i.e. all packets until last PDV without continuation  */
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

    sop_class_uid = ep_alloc(MAX_BUF_LEN);
    sop_instance_uid = ep_alloc(MAX_BUF_LEN);

    hostname = ep_alloc(MAX_BUF_LEN);
    filename = ep_alloc(MAX_BUF_LEN);

    if (assoc->ae_calling && strlen(assoc->ae_calling)>0 &&
	assoc->ae_called  && strlen(assoc->ae_called)>0 ) {
	g_snprintf(hostname, MAX_BUF_LEN, "%s <-> %s", assoc->ae_calling, assoc->ae_called);
    }
    else {
	g_snprintf(hostname, MAX_BUF_LEN, "AE title(s) unknown");
    }

    if (pdv->is_storage &&
	pdv_curr->sop_class_uid    && strlen(pdv_curr->sop_class_uid)>0 &&
	pdv_curr->sop_instance_uid && strlen(pdv_curr->sop_instance_uid)>0) {

	g_snprintf(sop_class_uid, MAX_BUF_LEN, "%s", pdv_curr->sop_class_uid);
	g_snprintf(sop_instance_uid, MAX_BUF_LEN, "%s", pdv_curr->sop_instance_uid);

	/* Make sure filename does not contain invalid character. Rather conservative.
	   Eventhough this should be a valid DICOM UID, apply the same filter rules
	   in case of bogus data.
	*/
	g_snprintf(filename, MAX_BUF_LEN, "%06d-%d-%s.dcm", pinfo->fd->num, cnt_same_pkt,
	    g_strcanon(pdv_curr->sop_instance_uid, G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS "-.", '-'));
    }
    else {
	/* No SOP Instance or SOP Class UID found in PDV. Use wireshark ones */

    	g_snprintf(sop_class_uid, MAX_BUF_LEN, "%s", WIRESHARK_MEDIA_STORAGE_SOP_CLASS_UID);

	g_snprintf(sop_instance_uid, MAX_BUF_LEN, "%s.%d.%d",
	    WIRESHARK_MEDIA_STORAGE_SOP_INSTANCE_UID_PREFIX, pinfo->fd->num, cnt_same_pkt);

	/* Make sure filename does not contain invalid character. Rather conservative.*/
	g_snprintf(filename, MAX_BUF_LEN, "%06d-%d-%s.dcm", pinfo->fd->num, cnt_same_pkt,
	    g_strcanon(pdv->desc, G_CSET_A_2_Z G_CSET_a_2_z G_CSET_DIGITS "-.", '-'));

    }

    if (global_dcm_header) {
	if (pctx && pctx->xfer_uid && strlen(pctx->xfer_uid)>0) {
    	    dcm_header=dcm_export_create_header(&dcm_header_len, sop_class_uid, sop_instance_uid, pctx->xfer_uid);
	}
	else {
	    /* We are running blind, i.e. no presentation context found. Don't invent one
	       The meta header will miss this tag (even tough it is mandatory)
	    */
	    dcm_header=dcm_export_create_header(&dcm_header_len, sop_class_uid, sop_instance_uid, NULL);
	}
    }


    /* Allocate the final size */
    pdv_combined = ep_alloc(dcm_header_len+pdv_combined_len);
    pdv_combined_curr = pdv_combined;

    memmove(pdv_combined, dcm_header, dcm_header_len);
    pdv_combined_curr += dcm_header_len;

    /* Copy PDV per PDV to target buffer */
    while (!pdv_curr->is_last_fragment) {
	memmove(pdv_combined_curr, pdv_curr->data, pdv_curr->data_len);	    /* this is a copy not move */
	pdv_combined_curr += pdv_curr->data_len;
	pdv_curr = pdv_curr->next;
    }

    /* Last packet */
    g_memmove(pdv_combined_curr, pdv->data, pdv->data_len);	    /* this is a copy not move */

    /* Add to list */
    eo_info = ep_alloc(sizeof(dicom_eo_t));
    eo_info->hostname = hostname;
    eo_info->filename = filename;
    eo_info->content_type = pdv->desc;

    eo_info->payload_data = pdv_combined;
    eo_info->payload_len  = dcm_header_len+pdv_combined_len;

    tap_queue_packet(dicom_eo_tap, pinfo, eo_info);
}


static void
dissect_dcm_assoc_item(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
		       dcm_state_assoc_t *assoc _U_, int offset,
		       gchar *pitem_prefix, int item_value_type,
		       gchar **item_value, gchar **item_description,
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
     * 	The Summary is also returned as
     */

    proto_tree *assoc_item_ptree = NULL;	/* Tree for item details */
    proto_item *assoc_item_pitem = NULL;

    guint32 item_number;

    guint8  item_type;
    guint16 item_len;

    gchar *buf_desc=NULL;		/* Used for item text */

    #define MAX_BUFFER 1024

    *item_value=NULL;
    *item_description=NULL;

    buf_desc=ep_alloc(MAX_BUFFER);	/* Valid for this packet */
    buf_desc[0]=0;

    item_type = tvb_get_guint8(tvb, offset);
    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_pitem = proto_tree_add_text(tree, tvb, offset, item_len+4, pitem_prefix);
    assoc_item_ptree = proto_item_add_subtree(assoc_item_pitem, ett_subtree);

    proto_tree_add_uint(assoc_item_ptree, *hf_type, tvb, offset, 1, item_type);
    proto_tree_add_uint(assoc_item_ptree, *hf_len, tvb, offset+2, 2, item_len);

    switch (item_value_type) {
    case DCM_ITEM_VALUE_TYPE_UID:
	*item_value = tvb_get_ephemeral_string(tvb, offset+4, item_len);
	*item_description = g_hash_table_lookup(dcm_uid_table, (gpointer) *item_value);

	if (NULL == *item_description) {	    /* Unknown UID, or no UID at all */
	    g_snprintf(buf_desc, MAX_BUFFER, "%s", *item_value);
	}
	else {
	    g_snprintf(buf_desc, MAX_BUFFER, "%s (%s)", *item_description, *item_value);
	}

	proto_item_append_text(assoc_item_pitem, "%s", buf_desc);
	proto_tree_add_string(assoc_item_ptree, *hf_value, tvb, offset+4, item_len, buf_desc);

	break;

    case DCM_ITEM_VALUE_TYPE_STRING:
	*item_value = tvb_get_ephemeral_string(tvb, offset+4, item_len);
        proto_item_append_text(assoc_item_pitem, "%s", *item_value);
	proto_tree_add_string(assoc_item_ptree, *hf_value, tvb, offset+4, item_len, *item_value);

	break;

    case DCM_ITEM_VALUE_TYPE_UINT32:
	item_number = tvb_get_ntohl(tvb, offset+4);
	*item_value = se_alloc(MAX_BUFFER);
	g_snprintf(*item_value, MAX_BUFFER, "%d", item_number);

	proto_item_append_text(assoc_item_pitem, "%s", *item_value);
	proto_tree_add_item(assoc_item_ptree, *hf_value, tvb, offset+4, 4, FALSE);

	break;

    default:
	break;
    }
}


static void
dissect_dcm_pctx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 dcm_state_assoc_t *assoc, int offset, int len, gchar *pitem_prefix, gboolean is_assoc_request)
{
    /*
	Decode a presentation context item in a Association Request or Response
	In the response, set the accepted transfer syntax, if any
    */

    proto_tree *pctx_ptree = NULL;	/* Tree for presentation context details */
    proto_item *pctx_pitem = NULL;

    dcm_state_pctx_t *pctx = NULL;

    guint8  item_type=0;
    guint16 item_len=0;

    guint8  pctx_id=0;		    /* Presentation Context ID */
    guint8  pctx_result=0;

    gchar *pctx_abss_uid=NULL;	    /* Abstract Syntax UID alias SOP Class UID */
    gchar *pctx_abss_desc=NULL;    /* Description of UID */

    gchar *pctx_xfer_uid=NULL;	    /* Transfer Syntax UID */
    gchar *pctx_xfer_desc=NULL;    /* Description of UID */

    gchar *buf_desc=NULL;	    /* Used in infor mode for item text */
    int	    endpos=0;

    int	    cnt_abbs=0;		    /* Number of Abstract Syntax Items */
    int	    cnt_xfer=0;		    /* Number of Trasfer Syntax Items */

    #define MAX_BUFFER 1024

    buf_desc=ep_alloc(MAX_BUFFER);	/* Valid for this packet */
    buf_desc[0]=0;

    endpos=offset+len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    pctx_pitem = proto_tree_add_text(tree, tvb, offset-4, item_len+4, pitem_prefix);
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
	proto_tree_add_uint_format(pctx_ptree, hf_dcm_pctx_result, tvb, offset+2, 1, pctx_result, "Result: %s (0x%x)", dcm_PCresult2str(pctx_result), pctx_result);
    }

    offset += 4;
    while (-1 < offset && offset < endpos) {

	item_type = tvb_get_guint8(tvb, offset);
	item_len = tvb_get_ntohs(tvb, 2 + offset);

	offset += 4;
	switch (item_type) {
	case 0x30:		/* Abstract syntax */

	    /* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
	    dissect_dcm_assoc_item(tvb, pinfo, pctx_ptree, assoc, offset-4,
		"Abstract Syntax: ", DCM_ITEM_VALUE_TYPE_UID, &pctx_abss_uid, &pctx_abss_desc,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pctx_abss_syntax, ett_assoc_pctx_abss);

	    cnt_abbs += 1;
	    offset += item_len;
	    break;

	case 0x40:		/* Transfer syntax */

	    dissect_dcm_assoc_item(tvb, pinfo, pctx_ptree, assoc, offset-4,
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
	pctx->abss_uid =g_strdup(pctx_abss_uid);
	pctx->abss_desc=g_strdup(pctx_abss_desc);
    }

    /*
      Copy to buffer first, because proto_item_append_text()
      crashed for an unknown reason using 'ID 0x%02x, %s, %s'
      and in my opinion correctly set parameters.
    */

    if (is_assoc_request) {
	if (pctx_abss_desc == NULL) {
	    g_snprintf(buf_desc, MAX_BUFFER, "%s", pctx_abss_uid);
	}
	else {
	    g_snprintf(buf_desc, MAX_BUFFER, "%s (%s)", pctx_abss_desc, pctx_abss_uid);
	}
    }
    else
    {
	/* g_snprintf() does not like NULL pointers */

	if (pctx_result==0) {
	    /* Accepted */
	    g_snprintf(buf_desc, MAX_BUFFER, "ID 0x%02x, %s, %s, %s",
		pctx_id, dcm_PCresult2str(pctx_result),
		dcm_uid_or_desc(pctx->xfer_uid, pctx->xfer_desc),
		dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
	}
	else {
	    /* Rejected */
	    g_snprintf(buf_desc, MAX_BUFFER, "ID 0x%02x, %s, %s",
		pctx_id, dcm_PCresult2str(pctx_result),
		dcm_uid_or_desc(pctx->abss_uid, pctx->abss_desc));
	}
    }
    proto_item_append_text(pctx_pitem, "%s", buf_desc);

}

static void
dissect_dcm_userinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		     dcm_state_assoc_t *assoc, int offset, int len, gchar *pitem_prefix)
{
    /*
	Decode the user info item in a Association Request or Response
    */

    proto_item *userinfo_pitem = NULL;
    proto_tree *userinfo_ptree = NULL;	    /* Tree for presentation context details */

    guint8  item_type;
    guint16 item_len;

    gboolean first_item=TRUE;

    gchar *info_max_pdu=NULL;
    gchar *info_impl_uid=NULL;
    gchar *info_impl_version=NULL;
    gchar *dummy=NULL;

    int	    endpos;

    endpos=offset+len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    userinfo_pitem = proto_tree_add_text(tree, tvb, offset-4, item_len+4, pitem_prefix);
    userinfo_ptree = proto_item_add_subtree(userinfo_pitem, ett_assoc_info);

    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 2, item_type);
    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_len, tvb, offset-2, 2, item_len);

    while (-1 < offset && offset < endpos) {

	item_type = tvb_get_guint8(tvb, offset);
	item_len = tvb_get_ntohs(tvb, 2 + offset);

	offset += 4;
	switch (item_type) {
	case 0x51:		/* Max length */

	    dissect_dcm_assoc_item(tvb, pinfo, userinfo_ptree, assoc, offset-4,
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
	    dissect_dcm_assoc_item(tvb, pinfo, userinfo_ptree, assoc, offset-4,
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

    	    dissect_dcm_assoc_item(tvb, pinfo, userinfo_ptree, assoc, offset-4,
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


static int
dissect_dcm_assoc(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti,
		  dcm_state_assoc_t *assoc, int offset, int len)
{
    proto_tree *assoc_tree  = NULL;	/* Tree for PDU details */

    guint8  item_type;
    guint16 item_len;

    int	    endpos;

    gchar *item_value=NULL;
    gchar *item_description=NULL;

    endpos = offset+len;

    if (ti) {
	assoc_tree = proto_item_add_subtree(ti, ett_assoc);
	while (-1 < offset && offset < endpos) {

	    item_type = tvb_get_guint8(tvb, offset);
	    item_len  = tvb_get_ntohs(tvb, 2 + offset);

	    DISSECTOR_ASSERT(item_len > 0);

	    offset += 4;

	    switch (item_type) {
	    case 0x10:		/* Application context */
		dissect_dcm_assoc_item(tvb, pinfo, assoc_tree, assoc, offset-4,
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
		dissect_dcm_userinfo(tvb, pinfo, assoc_tree, assoc, offset, item_len, "User Info: ");
		offset += item_len;
		break;

	    default:
		offset += item_len;
		break;
	    }
	}
    }
    return offset;

}

static int
dissect_dcm_pdv_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       dcm_state_assoc_t *assoc, int offset, guint8 *syntax,
		       dcm_state_pdv_t **pdv)
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

    *syntax = DCM_UNK;

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

	/* Create fake PCTX and guess Syntax ILE, ELE, EBE */
        pctx = dcm_state_pctx_new(assoc, pctx_id);

	/* To be done: Guess Syntax */
	pctx->syntax = DCM_UNK;
    }
    offset +=1;

    *syntax = pctx->syntax;

    /* Create PDV structure:

       Since we can have multiple PDV per packet (offset) and
       multiple merged packets per PDV (tvb->raw_offset)
       we need both values to uniquely identify a PDV
    */

    *pdv=dcm_state_pdv_get(pctx, pinfo->fd->num, tvb->raw_offset+offset, TRUE);
    if (*pdv==NULL) {
	return 0;		    /* Failed to allocate memory */
    }

    /* 1 Byte Flag */
    flags = tvb_get_guint8(tvb, offset);

    (*pdv)->pctx_id = pctx_id;		/* TBD: Required for export */

    desc_header=se_alloc(MAX_BUFFER);	/* Valid for this capture, since we return this buffer */
    memset(desc_header, 0, MAX_BUFFER);

    switch (flags) {
    case 0:	/* 00 */
	desc_flag = "Data, More Fragments";

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = FALSE;
	(*pdv)->is_last_fragment = FALSE;
	break;

    case 2:	/* 10 */
	desc_flag = "Data, Last Fragment";

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = FALSE;
	(*pdv)->is_last_fragment = TRUE;
	break;

    case 1:	/* 01 */
	desc_flag = "Command, More Fragments";
	g_snprintf(desc_header, MAX_BUFFER, "Command");		/* Will be overwritten with real command tag */

	*syntax = DCM_ILE;		/* Command tags are always little endian*/

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = TRUE;
	(*pdv)->is_last_fragment = FALSE;
	break;

    case 3:	/* 11 */
	desc_flag = "Command, Last Fragment";
        g_snprintf(desc_header, MAX_BUFFER, "Command");

	*syntax = DCM_ILE;		/* Command tags are always little endian*/

	(*pdv)->is_flagvalid = TRUE;
	(*pdv)->is_command = TRUE;
	(*pdv)->is_last_fragment = TRUE;
	break;

    default:
	desc_flag = "Invalid Flags";
        g_snprintf(desc_header, MAX_BUFFER, "Invalid Flags");

	*syntax = DCM_UNK;

	(*pdv)->is_flagvalid = FALSE;
	(*pdv)->is_command = FALSE;
	(*pdv)->is_last_fragment = FALSE;
    }

    if (flags == 0 || flags == 2) {
	/* Data PDV */
	pdv_first_data = dcm_state_pdv_get_obj_start(*pdv);

	if (pdv_first_data->prev && pdv_first_data->prev->is_command) {
	    /* Every Data PDV sequence should be preceeded by a Command PDV,
	       so we should always hit this for a correct capture
	    */

	    if (pctx && pctx->abss_desc && g_str_has_suffix(pctx->abss_desc, "Storage")) {
		/* Should be done far more intelligent, e.g. does not catch the (Retired) ones */
		if (flags == 0) {
		    g_snprintf(desc_header, MAX_BUFFER, "%s (more fragments)", pctx->abss_desc);
		}
		else {
		    g_snprintf(desc_header, MAX_BUFFER, "%s", pctx->abss_desc);
		}
		(*pdv)->is_storage = TRUE;
	    }
	    else {
		/* Use previous command and append DATA*/
		g_snprintf(desc_header, MAX_BUFFER, "%s-DATA", pdv_first_data->prev->desc);
	    }
	}
	else {
	    g_snprintf(desc_header, MAX_BUFFER, "DATA");
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


static int
dissect_dcm_pdv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		dcm_state_assoc_t *assoc, int offset, guint32 pdv_len, gchar **pdv_description)
{
    /* Handle one PDV inside a data PDU */

#define D_HEADER 1
#define D_TAG    2
#define D_VR     3
#define D_LEN2   4
#define D_LEN4   5
#define D_VALUE  6

    dcm_state_pdv_t *pdv = NULL;

    proto_item *pitem = NULL;

    int toffset, state, vr = 0, tr = 0;

    guint32 tag_value_fragment_len;	/* used for values that span multiple PDVs */

    guint16 grp = 0, elm = 0;
    guint32 tlen = 0;
    guint32 nlen = 0;			/* Length of next sub item */

    gchar *tag_value=NULL;		/* used for commands only so far */

    guint8  syntax;

    const guint8 *val=NULL;

    int endpos = offset + pdv_len;

    /* Dissect Context ID, Command/Data flag and More Fragments flag */
    offset = dissect_dcm_pdv_header(tvb, pinfo, tree, assoc, offset, &syntax, &pdv);

    if (have_tap_listener(dicom_eo_tap) && pdv->data_len==0) {
	/* If not yet done, copy pure dicom data to buffer when running in export object mode */
	pdv->data_len = endpos-offset;
	pdv->data = se_alloc(pdv->data_len);
	if (pdv->data) {
	    g_memmove(pdv->data, tvb_get_ptr(tvb, offset, pdv->data_len), pdv->data_len);
	}
	else {
	    pdv->data_len = 0;		/* Failed to allocate memory. Don't copy anything */
	}
    }

    if (pdv->prev) {
	/* Not frist PDV in the give presentation context (Those don't have remaining data to parse :-) */

	if (pdv->prev->open_tag_rlen > 0) {
	    /* previous PDV has left overs, i.e. this is a continuation PDV */

	    if (endpos - offset >= (int)pdv->prev->open_tag_rlen) {
		/*
		 * Remaining bytes are equal or more than we expect for the open tag
		 * Finally reach the end of this tag
		 */
		tag_value_fragment_len = pdv->prev->open_tag_rlen;

		pdv->open_tag_len  = 0;
		pdv->open_tag_rlen = 0;
		pdv->open_tag_desc = NULL;
		pdv->initalized = TRUE;

		pdv->is_corrupt = FALSE;
	    }
	    else if (pdv->is_flagvalid && pdv->is_last_fragment) {
		/*
		 * The tag is not yet complete, however, the flag indicates that it should be
		 * Therefore end this tag and issue an expert_add_info
		 */

		tag_value_fragment_len = endpos - offset;

		pdv->open_tag_len  = 0;
		pdv->open_tag_rlen = 0;
		pdv->open_tag_desc = NULL;
		pdv->initalized = TRUE;
		pdv->is_corrupt = TRUE;
	    }
	    else {
		/*
		 * More to do for this tag
		 */
		tag_value_fragment_len = endpos - offset;

		/* Set data in current PDV structure */
		pdv->open_tag_len  = pdv->prev->open_tag_len;
	        pdv->open_tag_rlen = pdv->prev->open_tag_rlen - tag_value_fragment_len;
		pdv->open_tag_desc = pdv->prev->open_tag_desc;
		pdv->initalized = TRUE;
		pdv->is_corrupt = FALSE;
	    }

	    val = tvb_get_ptr(tvb, offset, tag_value_fragment_len);

	    if (pdv->is_corrupt) {
		pitem = proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
		    offset, tag_value_fragment_len, val, "%s [incomplete]",
		    pdv->prev->open_tag_desc);

		expert_add_info_format(pinfo, pitem, PI_MALFORMED, PI_ERROR,
		    "Early termination of tag. Data is missing");

	    }
	    else {
		proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
		    offset, tag_value_fragment_len, val, "%s Bytes %d - %d [%s]",
		    pdv->prev->open_tag_desc,
		    pdv->prev->open_tag_len - pdv->prev->open_tag_rlen + 1,
		    pdv->prev->open_tag_len - pdv->open_tag_rlen,
		    (pdv->open_tag_rlen > 0 ? "continuation" : "end") );
	    }

	    offset += tag_value_fragment_len;
	}
    }

    if (syntax == DCM_UNK) {
	const guint8 *val;
	tlen = endpos - offset;
	val = tvb_get_ptr(tvb, offset, tlen);	    /* Verify */
	proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
	    offset, tlen, val, "(%04x,%04x) %-8x Unparsed data", 0, 0, tlen);
	offset = pdv_len;
    }

    /*	Command Tags
	2   Group
	2   Element
	4   unsigned Length n
	n   Value, always in Implicit Little VR
    */
    toffset = offset;
    state = D_TAG;
    nlen = 4;
    while (offset + nlen <= (guint32) endpos) {
	switch (state) {
	case D_TAG: {
	    vr = tr = 0;
	    if (DCM_ILE & syntax) {
		grp = tvb_get_letohs(tvb, offset);
		elm = tvb_get_letohs(tvb, offset+2);
		state = (DCM_EBE & syntax) ? D_VR : D_LEN4;  /* is Explicit */
		nlen  = (DCM_EBE & syntax) ? 2 : 4;	    /* is Explicit */
	    } else {
		grp = tvb_get_ntohs(tvb, offset);
		elm = tvb_get_ntohs(tvb, offset+2);
		state = D_VR;
		nlen = 2;
	    }
	    toffset = offset;
	    if (0xfffe == grp) state = D_LEN4;
	    offset += 4;
	    } break;		/* don't fall through -- check length */
	case D_VR:  {
	    guint8 V, R;
	    vr = offset;
	    V = tvb_get_guint8(tvb, offset);
	    R = tvb_get_guint8(tvb, offset+1);
	    offset +=2;
	    /* 4byte lengths OB, OW, OF, SQ, UN, UT */
	    state = D_LEN2;
	    nlen = 2;
	    if ((('O' == V) && ('B' == R || 'W' == R || 'F' == R) && (tr = DCM_OTH))
		|| (('U' == V) && ('N' == R || (('T' == R) && (tr = DCM_TSTR))))
		|| ('S' == V && 'Q' == R && (tr = DCM_SQ))) {
		state = D_LEN4;
		offset += 2;	/* skip 00 (2 bytes) */
		nlen = 4;
	    } else if ('F' == V && 'L' == R) {
		tr = DCM_TFLT;
	    } else if ('F' == V && 'D' == R) {
		tr = DCM_TDBL;
	    } else if (('S' == V && 'L' == R) || ('U' == V && 'L' == R)) {
		tr = DCM_TINT4;
	    } else if (('S' == V && 'S' == R) || ('U' == V && 'S' == R)) {
		tr = DCM_TINT2;
	    } else if ('A' == V && 'T' == R) {
		tr = DCM_OTH;
	    } else
		tr = DCM_TSTR;
    /*
	    else if (('A' == V && ('E' == R || 'S' == R))
		|| ('C' == V && 'S' == R)
		|| ('D' == V && ('A' == R || 'S' == R || 'T' == R))
		|| ('I' == V && 'S' == R)
		|| ('L' == V && ('O' == R || 'T' == R))
		|| ('P' == V && 'N' == R)
		|| ('S' == V && ('H' == R ||| 'T' == R))
		|| ('T' == V && 'M' == R)
		|| ('U' == V && ('I' == R || 'T' == R)))
		tr = DCM_TSTR;
     */
	    } break;		/* don't fall through -- check length */
	case D_LEN2: {
	    if (DCM_ILE & syntax)	/* is it LE */
		tlen = tvb_get_letohs(tvb, offset);
	    else
		tlen = tvb_get_ntohs(tvb, offset);
	    offset += 2;
	    state = D_VALUE;
	    nlen = tlen;
	    /*
	    DISSECTOR_ASSERT(tlen > 0);
	    */
	    } break;
	case D_LEN4: {
	    if (DCM_ILE & syntax)	/* is it LE */
		tlen = tvb_get_letohl(tvb, offset);
	    else
		tlen = tvb_get_ntohl(tvb, offset);
	    offset += 4;
	    state = D_VALUE;
	    nlen = tlen;
	    /*
	    DISSECTOR_ASSERT(tlen > 0);
	    */
	    } break;		/* don't fall through -- check length */
	case D_VALUE: {
	    const guint8 *val;
	    int totlen = (offset - toffset);
	    if (0xffffffff == tlen || 0xfffe == grp) {
		val = tvb_get_ptr(tvb, toffset, totlen);
		proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
		    toffset, totlen, val,
		    "(%04x,%04x) %-8x %s", grp, elm, tlen,
			dcm_tag2str(grp, elm, syntax, tvb, offset, 0, vr, tr, &tag_value));

		tlen = 0;
	    /* } else if (0xfffe == grp) { */ /* need to make a sub-tree here */
	    } else {
		totlen += tlen;
		val = tvb_get_ptr(tvb, toffset, totlen);
		proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
		    toffset, totlen, val,
		    "(%04x,%04x) %-8x %s", grp, elm, tlen,
			dcm_tag2str(grp, elm, syntax, tvb, offset, tlen, vr, tr, &tag_value));
	    }


	    /* Store SOP Class and Instance UID in first PDV of this object */
	    if (grp == 0x0008 && elm == 0x0016) {
		dcm_state_pdv_get_obj_start(pdv)->sop_class_uid = g_strdup(tag_value);
	    }
	    else if (grp == 0x0008 && elm == 0x0018) {
		dcm_state_pdv_get_obj_start(pdv)->sop_instance_uid = g_strdup(tag_value);
	    }
	    else if (grp == 0x0000 && elm == 0x0100) {
		/* This is the command tag -> overwrite existing PDV description */
		pdv->desc = g_strdup(tag_value);
	    }

	    offset += tlen;
	    state = D_TAG;
	    nlen = 4;
	    } break;
	}
    }
    /*  After a properly formed Tag, where Tag, VR, Len and Value are present
	The next state should be a D_TAG

	If the value is too large (start of a long value) we remain in state D_VALUE
	But if we are in a not detected continutation we may also get 'stuck' in state D_VALUE
    */

    if (D_VALUE == state) {

	const guint8 *val;
	gchar	*buf;

	tag_value_fragment_len = pdv_len - offset + 10;	    /*  The 10 is a result of debugging :-((
								Fix once the Tag parisng has been structured
							    */
	val = tvb_get_ptr(tvb, offset, tag_value_fragment_len);

	buf=ep_alloc(2048);	    /* Longer than what dcm_tag2str() returns */
	*buf = 0;

	g_snprintf(buf, 2048, "(%04x,%04x) %-8x %s",
	    grp, elm, tlen,
	    dcm_tag2str(grp, elm, syntax, tvb, offset, tlen, vr, DCM_OTH, &tag_value));

	proto_tree_add_bytes_format(tree, hf_dcm_data_tag, tvb,
	    offset, tag_value_fragment_len, val, "%s Bytes %10d - %10d [start]", buf, 1, tag_value_fragment_len);

	if (!pdv->initalized) {
	    /*  First time parsing of this PDV.
		Save the needed data for reuse, i.e. when being called just to open a particular packet
	    */

	    pdv->open_tag_len  = tlen;
	    pdv->open_tag_rlen = tlen-tag_value_fragment_len;
	    pdv->open_tag_desc = g_strdup(buf);		    /* EP memory will be freeded. Therefore copy */
	    pdv->initalized = TRUE;
	}
    }
    else {
	if (!pdv->initalized) {
	    /*  First time parsing of this PDV.
		Save the needed data for reuse, i.e. when called just to open a particular packet
	    */
	    pdv->open_tag_len = 0;
	    pdv->open_tag_rlen = 0;
	    pdv->open_tag_desc = NULL;
	    pdv->initalized = TRUE;
	}
    }

    if (have_tap_listener(dicom_eo_tap) && pdv->data_len>0) {
	if (pdv->is_last_fragment) {
	    dcm_export_create_object(pinfo, assoc, pdv);
	}
    }

    *pdv_description = pdv->desc;

    return endpos;
}

static int
dissect_dcm_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 dcm_state_assoc_t *assoc, int offset, guint32 pdu_len, gchar **pdu_description)
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

    gchar  *buf_desc=NULL;		/* PDU description */
    gchar  *pdv_description=NULL;

    gboolean first_pdv=TRUE;

    int endpos = offset + pdu_len;
    int pdv_len=0;

    buf_desc=se_alloc(MAX_BUFFER);	/* Valid for this capture, since we return this buffer */
    buf_desc[0]=0;

    /* Loop thorugh multiple PDVs */
    while (offset < endpos) {
	pdv_len = tvb_get_ntohl(tvb, offset);
	DISSECTOR_ASSERT(pdv_len > 0);

	pdv_pitem = proto_tree_add_text(tree, tvb, offset, pdv_len+4, "PDV");
	pdv_ptree = proto_item_add_subtree(pdv_pitem, ett_dcm_data_pdv);

	proto_tree_add_item(pdv_ptree, hf_dcm_pdv_len, tvb, offset, 4, FALSE);
	offset +=4;

	offset = dissect_dcm_pdv(tvb, pinfo, pdv_ptree, assoc, offset, pdv_len, &pdv_description);

	if (first_pdv) {
	    g_snprintf(buf_desc, MAX_BUFFER, "%s", pdv_description);
	}
	else {
	    g_snprintf(buf_desc, MAX_BUFFER, "%s, %s", buf_desc, pdv_description);
	}

	proto_item_append_text(pdv_pitem, ", %s", pdv_description);
	first_pdv=FALSE;


	/* offset should be advanced by pdv_len */
    }

    *pdu_description=buf_desc;
    return offset;
}


static int
dissect_dcm_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean require_assoc_req)
{
    /* Code to actually dissect the packets */

    guint8  pdu_type=0;
    guint32 pdu_start=0;
    guint32 pdu_len=0;
    guint16 vers=0;
    guint32 tlen=0;

    int offset=0;

    /*
	Modified orignal code, which was optimized for a heuristic detection, and therefore
	caused some load and memory consumption, for every non DICOM packet not processed
	by someone else.

	Since tcp packets are now assembled well by wireshark (in conjunction with the dissectors)
	we will only see properly alligned PDUs, at the beginnig of the buffer, else its not DICOM
	traffic.

	Therfore do the byte checking as early as possible
	The heurisitc hook, checks for an association request

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

	The Lenght check is tricky. If not a PDV continuation, 10 Bytes are required. For PDV continuation
	anything seems to be possible, depending on the buffer alignment of the sending process

	I have seen a 4 Byte PDU 'Header' just at the end of a TCP packet, which will come in here
	as tlen with 4 bytes.
    */

    tlen = tvb_reported_length(tvb);

    pdu_type = tvb_get_guint8(tvb, 0);
    if (pdu_type==0 || pdu_type>7) 		/* Wrong PDU type. 'Or' is slightly more efficient than 'and' */
	return 0;				/* No bytes taken from the stack */

    if (pdu_type==4) {
	if (tlen<2) {
	    /* Hopefully we don't have 1 Byte PDUs in PDV continuations, otherwise reduce to 1 */
	    return 0;
	}
	else if (tlen<6) {
	    /* we need 6 bytes at least to get PDU length */
	    pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return TRUE;
	}
    }
    else if (tlen<10) {
	return 0;
    }

    pdu_len = tvb_get_ntohl(tvb, 2);
    if (pdu_len<4) 				/* The smallest PDUs are ASSOC Rejects & Release Msgs */
	return 0;

    if (require_assoc_req) {

	/* find_conversation() seems to return a converstation, even if we never saw
	   any packet yet. Not really my interpretation of this function.

	   Therefore also check, if we already stored configuration data for converstation
	*/

	if (dcm_state_get(pinfo, FALSE)==NULL) {

	    /* config data does not exist, check for association request */

	    vers = tvb_get_ntohs(tvb, 6);

	    if (!(pdu_type == 1 && vers == 1)) {    /* Not PDU type 0x01 or not Version 1 */
		return 0;
	    }

	    /* Exit if TCP payload is bigger than PDU length (plues header)
	       ok. for PRESENTATION_DATA, questionable for ASSOCIATION requests
	    */
	    if (pdu_len+6 < tlen)
		return 0;

	}
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	col_clear(pinfo->cinfo, COL_PROTOCOL);
    }

     /* Process all PDUs in the buffer */
    while (pdu_start < tlen) {

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
	pdu_start =  pdu_start + pdu_len + 6;

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
    return dissect_dcm_main(tvb, pinfo, tree, 0);
}

static int
dissect_dcm_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Only decode conerstations, which include an Association Request */
    /* This will be potentially called for every packet */
    return dissect_dcm_main(tvb, pinfo, tree, TRUE);
}

static int
dissect_dcm_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *ti=NULL;
    proto_item *ti_pdu_type=NULL;

    dcm_state_t	*dcm_data=NULL;
    dcm_state_assoc_t *assoc=NULL;

    proto_tree *dcm_tree=NULL;

    guint8  pdu_type=0;
    guint32 pdu_len=0;

    gchar *pdu_description=NULL;

    int assoc_header=0;

    gboolean	valid_pdutype=TRUE;

    gchar *info_str = NULL;

    /* Get or create converstation. Used to store context IDs and xfer Syntax */

    dcm_data = dcm_state_get(pinfo, TRUE);
    if (dcm_data == NULL) {	/* internal error. Failed to create main dicom data structre */
	return  0;
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DICOM");

    /* This field shows up as the "Info" column in the display; you should make
       it, if possible, summarize what's in the packet, so that a user looking
       at the list of packets can tell what type of packet it is. See section 1.5
       for more information.
    */

    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    if (pdu_type==1) {
	/* 'Force' new association object */
	assoc=dcm_state_assoc_new(dcm_data, pinfo->fd->num);
    }
    else {
	/* Create new association object, if needed, i.e. if we association request is not in capture */
	assoc=dcm_state_assoc_get(dcm_data, pinfo->fd->num, TRUE);
    }

    if (assoc == NULL) {	/* internal error. Failed to association structre */
	return  0;
    }

    info_str=ep_alloc(MAX_BUFFER);
    info_str[0]=0;

    pdu_type = tvb_get_guint8(tvb, offset);
    pdu_len = tvb_get_ntohl(tvb, offset + 2);

    switch (pdu_type) {
    case 1:					/* ASSOC Request */
	tvb_memcpy(tvb, assoc->ae_called, 10, 16);
	tvb_memcpy(tvb, assoc->ae_calling, 26, 16);
	assoc->ae_called[AEEND] = 0;
	assoc->ae_calling[AEEND] = 0;
	g_snprintf(info_str, 128, "A-ASSOCIATE request %s --> %s",
	    g_strstrip(assoc->ae_calling), g_strstrip(assoc->ae_called));
	assoc_header = 74;
	break;
    case 2: 					/* ASSOC Accept */
	tvb_memcpy(tvb, assoc->ae_called_resp, 10, 16);
	tvb_memcpy(tvb, assoc->ae_calling_resp, 26, 16);
	assoc->ae_called_resp[AEEND] = 0;
	assoc->ae_calling_resp[AEEND] = 0;
	g_snprintf(info_str, MAX_BUFFER, "A-ASSOCIATE accept  %s <-- %s",
	    g_strstrip(assoc->ae_calling_resp), g_strstrip(assoc->ae_called_resp));
	assoc_header = 74;
	break;
    case 3:					/* ASSOC Reject */
	assoc->result = tvb_get_guint8(tvb, 7);
	assoc->source = tvb_get_guint8(tvb, 8);
	assoc->reason = tvb_get_guint8(tvb, 9);
	g_snprintf(info_str, 128, "A-ASSOCIATE reject  %s <-- %s %s %s %s",
	    g_strstrip(assoc->ae_calling), g_strstrip(assoc->ae_called),
	    dcm_result2str(assoc->result),
	    dcm_source2str(assoc->source),
	    dcm_reason2str(assoc->source, assoc->reason));
	break;
    case 4:					/* DATA */
	info_str="P-DATA";
	break;
    case 5:					/* RELEASE Request */
	info_str="A-RELEASE request";
	break;
    case 6:					/* RELEASE Response */
	info_str="A-RELEASE response";
	break;
    case 7:					/* ABORT */
	assoc->source = tvb_get_guint8(tvb, 8);
	assoc->reason = tvb_get_guint8(tvb, 9);
	g_snprintf(info_str, 128, "ABORT %s <-- %s %s %s",
	    assoc->ae_called, assoc->ae_calling,
	    (assoc->source == 1) ? "USER" :
		(assoc->source == 2) ? "PROVIDER" : "",
	    assoc->source == 1 ? dcm_abort2str(assoc->reason) : "");
	break;
    default:
	info_str="Continuation or non-DICOM traffic";
	valid_pdutype = FALSE;				/* No packets taken from stack */
	break;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO, info_str);

    if (valid_pdutype) {

	if (tree || have_tap_listener(dicom_eo_tap)) {
	    /*  In the interest of speed, if "tree" is NULL, don't do any work not
		necessary to generate protocol tree items.
	    */

	    proto_item *tf;
	    ti = proto_tree_add_item(tree, proto_dcm, tvb, offset, -1, FALSE);
	    dcm_tree = proto_item_add_subtree(ti, ett_dcm);
	    ti_pdu_type = proto_tree_add_uint_format(dcm_tree, hf_dcm_pdu, tvb, offset, pdu_len+6,
		pdu_type, "PDU Type 0x%x (%s)", pdu_type, dcm_pdu2str(pdu_type));
	    proto_tree_add_item(dcm_tree, hf_dcm_pdu_len, tvb, offset+2, 4, FALSE);

	    if (pdu_type==3) {
		expert_add_info_format(pinfo, ti_pdu_type, PI_RESPONSE_CODE, PI_WARN, "Asscociation rejected");
	    }
	    else if (pdu_type==7) {
		expert_add_info_format(pinfo, ti_pdu_type, PI_RESPONSE_CODE, PI_WARN, "Asscociation aborted");
	    }

	    switch (pdu_type) {
	    case 1:					/* ASSOC Request */
	    case 2: 					/* ASSOC Accept */
		tf = proto_tree_add_string(dcm_tree, hf_dcm_pdu_type, tvb, offset, pdu_len+6, info_str);
		offset = dissect_dcm_assoc(tvb, pinfo, tf, assoc, offset+assoc_header, pdu_len+6-assoc_header);
		break;

	    case 4:					/* DATA */
		offset = dissect_dcm_data(tvb, pinfo, dcm_tree, assoc, offset+6, pdu_len, &pdu_description);
		proto_item_append_text(ti, ", %s", pdu_description);

		if (check_col(pinfo->cinfo, COL_INFO))
		    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", pdu_description);

		break;

	    case 3:					/* ASSOC Reject */
	    case 5:					/* RELEASE Request */
	    case 6:					/* RELEASE Response */
	    case 7:					/* ABORT */
		/* Info string decoding only at this point */
		offset += pdu_len+6;
		break;

	    default:
		offset=0;
		break;
	    }
	}
	else if (pdu_type == 1 || pdu_type == 2) {
	    /*  Always dissect Association request and response in order
		to set the data strucures needed for the PDU Data packets
	    */
 	    offset = dissect_dcm_assoc(tvb, pinfo, NULL, assoc, offset+assoc_header, pdu_len+6-assoc_header);
	}
    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 */

    return offset;	    /* return the number of processed bytes */

}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

static void range_delete_dcm_tcp_callback(guint32 port) {
    dissector_delete("tcp.port", port, dcm_handle);
}

static void range_add_dcm_tcp_callback(guint32 port) {
    dissector_add("tcp.port", port, dcm_handle);
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
void
proto_register_dcm(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
    { &hf_dcm_pdu, { "PDU Type", "dicom.pdu.type",
	FT_UINT8, BASE_HEX, VALS(dcm_pdu_ids), 0, "", HFILL } },
    { &hf_dcm_pdu_len, { "PDU Length", "dicom.pdu.len",
	FT_UINT32, BASE_DEC, NULL, 0, "", HFILL } },
    { &hf_dcm_pdu_type, { "PDU Detail", "dicom.pdu.detail",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_assoc_item_type, { "Item Type", "dicom.assoc.item.type",
	FT_UINT8, BASE_HEX, VALS(dcm_assoc_item_type), 0, "", HFILL } },
    { &hf_dcm_assoc_item_len, { "Item Length", "dicom.assoc.item.len",
	FT_UINT16, BASE_DEC, NULL, 0, "", HFILL } },
    { &hf_dcm_actx, { "Application Context", "dicom.actx",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_pctx_id, { "Presentation Context ID", "dicom.pctx.id",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_pctx_result, { "Presentation Context Result", "dicom.pctx.id",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_pctx_abss_syntax, { "Abstract Syntax", "dicom.pctx.abss.syntax",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_pctx_xfer_syntax, { "Transfer Syntax", "dicom.pctx.xfer.syntax",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_info_uid, { "Implementation Class UID", "dicom.userinfo.uid",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_info_version, { "Implementation Version", "dicom.userinfo.version",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_pdu_maxlen, { "Max PDU Length", "dicom.max_pdu_len",
	FT_UINT32, BASE_DEC, NULL, 0, "", HFILL } },
    { &hf_dcm_pdv_len, { "PDV Length", "dicom.pdv.len",
	FT_UINT32, BASE_DEC, NULL, 0, "", HFILL } },
    { &hf_dcm_pdv_ctx, { "PDV Context", "dicom.pdv.ctx",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_pdv_flags, { "PDV Flags", "dicom.pdv.flags",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_data_tag, { "Tag", "dicom.data.tag",
	FT_BYTES, BASE_HEX, NULL, 0, "", HFILL } },
/*
    { &hf_dcm_FIELDABBREV, { "FIELDNAME", "dicom.FIELDABBREV",
	FIELDTYPE, FIELDBASE, FIELDCONVERT, BITMASK, "FIELDDESCR", HFILL } },
 */
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	    &ett_dcm,
	    &ett_assoc,
	    &ett_assoc_actx,
	    &ett_assoc_pctx,
	    &ett_assoc_pctx_abss,
	    &ett_assoc_pctx_xfer,
	    &ett_assoc_info,
	    &ett_assoc_info_uid,
	    &ett_assoc_info_version,
	    &ett_dcm_data,
	    &ett_dcm_data_pdv,
	    &ett_dcm_data_tag
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

    prefs_register_bool_preference(dcm_module, "header",
	    "Create Meta Header on Export",
	    "Create DICOM File Meta Header according to PS 3.10 on export for PDUs. "
	    "If the cpatured PDV does not contain a SOP Class UID and SOP Instance UID "
	    "(e.g. for command PDVs), wireshark spefic ones will be created.",
	    &global_dcm_header);

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

04 P-DATA-TF
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

