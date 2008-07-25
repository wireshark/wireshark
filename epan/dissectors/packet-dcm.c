/* packet-dcm.c
 * Routines for DICOM dissection
 * Copyright 2003, Rich Coe <Richard.Coe@med.ge.com>
 * Copyright 2008, David Aggeler <david_aggeler@hispeed.ch>
 *
 * DICOM communication protocol
 * http://medical.nema.org/dicom/2003.html
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
 * 9 Nov 2004
 * - Fixed the heuristic code -- sometimes a conversation already exists
 * - Fixed the dissect code to display all the tags in the pdu
 *
 * 28 Apr 2005
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
 * - still need to fix display of continuation packets
 *
 *
 * 23 May 2008 David Aggeler
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
 * - Still to do
 *   Support multiple PDV per PDU
 *   Support almost all tags (prepared)
 *   Cleanup types of offset & position
 *   Cleanup hf_dcm_xx to make tree expansion more logical
 *   Cleanup data structures
 *   Create subtrees for sequences
 *   Support item 56-59 in Accociation Request
 *   More length checks
 *   Handle multiple dicom associations in a capture correctly, if presentation contexts are different. 
 *   Save content as dicom file
 *   Fix string that are displayed with /000
 *   Add Command (C-STRORE) ... to Info Column
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

#include "packet-tcp.h"

#include "packet-dcm.h"

#define DICOM_DEFAULT_RANGE "104"

static range_t *global_dcm_tcp_range = NULL;
static range_t *global_dcm_tcp_range_backup = NULL;	    /* needed to deregister */

static gboolean global_dcm_heuristic = FALSE;

/* Initialize the protocol and registered fields */
static int proto_dcm = -1;
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
static gint ett_dcm = -1,
    ett_assoc = -1,
    ett_assoc_item = -1,
    ett_assoc_pctx = -1,
    ett_assoc_userinfo = -1,
    ett_dcm_data = -1;

static dissector_handle_t dcm_handle;

static gboolean dcm_desegment_headers = TRUE;

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
    { 0, NULL }
};

static const value_string dcm_pctx_result[] = {
    { 0, "Accept" },
    { 1, "User Reject" },
    { 2, "No Reason" },
    { 3, "Abstract Syntax Unsupported" },
    { 4, "Transfer Syntax Unsupported" }
    { 0, NULL }
};


/*
    Per Presentation Context in an association store data needed, for subsequent decoding
*/
struct dcmItem {
    struct dcmItem *next, *prev;
    int valid;
    guint8 id;			/* 0x20 Presentation Context ID */
    guchar *abss_uid;		/* 0x30 Abstract syntax */
    guchar *abss_desc;		/* 0x30 Abstract syntax decoded*/
    guchar *xfer_uid;		/* 0x40 Acepted Transfer syntax */
    guchar *xfer_desc;		/* 0x40 Acepted Transfer syntax decoded*/
    guint8 syntax;		/* Decoded transfer syntax */
#define DCM_ILE  0x01		/* implicit, little endian */
#define DCM_EBE  0x02           /* explicit, big endian */
#define DCM_ELE  0x03           /* explicit, little endian */
#define DCM_UNK  0xf0
};
typedef struct dcmItem dcmItem_t;

/*
    Per Presentation Data PDU store data needed, to allow decoding of tags longer than a PDU
*/
struct dcm_pdu_state {
    struct dcm_pdu_state *next, *prev;
    gboolean valid;
    guint32 packet_no;		/* Wireshark packet number */
    guint32 offset;		/* Offset in packet, where PDU header starts */
    guint32 tag_rlen;		/* remining tag bytes to 'decoded' as binary data after this PDU */
    guchar  *tag_desc;		/* last decoded description */
};
typedef struct dcm_pdu_state dcm_pdu_state_t;


struct dcmState {
    dcmItem_t		*first_pctx, *last_pctx;	/* List of Presentation context objects */
    dcm_pdu_state_t	*first_pdu,  *last_pdu;		/* List of PDU objects */

    gboolean valid;			/* this conversation is a DICOM conversation */

#define AEEND 16
    guchar ae_called[1+AEEND];		/* Called  AE tilte in A-ASSOCIATE RQ */
    guchar ae_calling[1+AEEND];		/* Calling AE tilte in A-ASSOCIATE RQ */
    guchar ae_called_resp[1+AEEND];	/* Called  AE tilte in A-ASSOCIATE RP */
    guchar ae_calling_resp[1+AEEND];	/* Calling AE tilte in A-ASSOCIATE RP */
    guint8 source, result, reason;
};
typedef struct dcmState dcmState_t;

struct dcmTag {
    int tag;
    int dtype;
    const char *desc;
#define DCM_TSTR  1
#define DCM_TINT2 2
#define DCM_TINT4 3
#define DCM_TFLT  4
#define DCM_TDBL  5
#define DCM_TSTAT 6  /* call dcm_rsp2str() on TINT2 */
#define DCM_TRET  7
#define DCM_TCMD  8
#define DCM_SQ    9 	/* sequence */
#define DCM_OTH   10    /* other */
};
typedef struct dcmTag dcmTag_t;

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

/* following definitions are used to call */
#define DCM_ITEM_VALUE_TYPE_UID	    1
#define DCM_ITEM_VALUE_TYPE_STRING  2
#define DCM_ITEM_VALUE_TYPE_UINT32  3

/* A few function declataions */


static dcmItem_t * lookupCtx(dcmState_t *dd, guint8 ctx);

static dcm_pdu_state_t* dcm_pdu_state_get_or_create(dcmState_t *dcm_data, guint32 packet_no, guint32 offset);

static int  dissect_dcm_static	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int  dissect_dcm_heuristic   (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int  dissect_dcm_main	    (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean require_assoc_req);

static int  dissect_dcm_pdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

static int  dissect_dcm_assoc               (dcmState_t *dcm_data, proto_item *ti,       tvbuff_t *tvb, int offset, int len);
static void dissect_dcm_presentation_context(dcmState_t *dcm_data, proto_tree *dcm_tree, tvbuff_t *tvb, int offset, int len, guchar *pitem_prefix, gboolean request);
static void dissect_dcm_assoc_item          (proto_tree *dcm_tree, tvbuff_t *tvb, int offset, guchar *pitem_prefix, int item_value_type, guchar **item_value, guchar **item_description, int *hf_type, int *hf_len, int *hf_value);
static void dissect_dcm_userinfo	    (dcmState_t *dcm_data, proto_tree *dcm_tree, tvbuff_t *tvb, int offset, int len, guchar *pitem_prefix);

static int  dissect_dcm_data		    (dcmState_t *dcm_data, proto_item *ti, tvbuff_t *tvb, packet_info *pinfo, int offset, int len);

static void
dcm_init(void)
{
    guchar *test=NULL;

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

static dcmState_t *
mkds(void)
{
    dcmState_t *ds;

    if (NULL == (ds = (dcmState_t *) g_malloc(sizeof(dcmState_t)))) {
	return NULL;
    }

    ds->first_pctx = NULL;	    /* List of Presentation context objects */
    ds->last_pctx  = NULL;

    ds->first_pdu = NULL;	    /* List of PDU objects */
    ds->last_pdu  = NULL;

    ds->valid = TRUE;

    memset(ds->ae_called, 0, sizeof(ds->ae_called));
    memset(ds->ae_calling, 0, sizeof(ds->ae_calling));
    memset(ds->ae_called_resp, 0, sizeof(ds->ae_called_resp));
    memset(ds->ae_calling_resp, 0, sizeof(ds->ae_calling_resp));

    return ds;
}

static dcm_pdu_state_t*
dcm_pdu_state_new(dcmState_t *dcm_data, guint32 packet_no, guint32 offset)
{
    dcm_pdu_state_t *pdu=NULL;

    pdu = (dcm_pdu_state_t *) se_alloc(sizeof(dcm_pdu_state_t));
    if (pdu != NULL) {

	pdu->prev=NULL;
	pdu->next=NULL;

	pdu->packet_no=packet_no;
	pdu->offset=offset;
	pdu->valid=FALSE;
	pdu->tag_desc=NULL;
	pdu->tag_rlen=0;

	/* add to the end of the list list */
	if (dcm_data->last_pdu) {
	    dcm_data->last_pdu->next = pdu;
	    pdu->prev = dcm_data->last_pdu;
	}
	else {
	    dcm_data->first_pdu = pdu;

	}
	dcm_data->last_pdu = pdu;

    }

    return pdu;

}

static dcm_pdu_state_t*
dcm_pdu_state_get_or_create(dcmState_t *dcm_data, guint32 packet_no, guint32 offset)
{

    dcm_pdu_state_t *pdu = NULL;

    pdu=dcm_data->first_pdu;

    while (pdu) {
	if ((pdu->packet_no == packet_no) && (pdu->offset == offset))
	    break;
	pdu = pdu->next;
    }

    if (pdu == NULL) {
	pdu = dcm_pdu_state_new(dcm_data, packet_no, offset);
    }
    return pdu;
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
dcm_flags2str(guint8 flags)
{
    const char *s = "";
    switch (flags) {
    case 0:  s = "Data,    more Fragments"; break;	/* 00 */
    case 1:  s = "Command, more Fragments"; break;      /* 01 */
    case 2:  s = "Data,    last Fragment";  break;      /* 10 */
    case 3:  s = "Command, last Fragment";  break;      /* 11 */
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

static guchar*
dcm_uid_or_desc(guchar *dcm_uid, guchar *dcm_desc)
{
    /* Return Description, UID or error */

    return (dcm_desc == NULL ? (dcm_uid == NULL ? "Malformed Packet" : dcm_uid) : dcm_desc);
}

static void
dcm_setSyntax(dcmItem_t *di, guchar *xfer_uid, guchar *xfer_desc)
{
    if (NULL == di) return;
    if (di->xfer_uid != NULL)
	g_free(di->xfer_uid);	/* free prev allocated xfer */
    if (di->xfer_desc != NULL)
	g_free(di->xfer_desc);	/* free prev allocated xfer */

    di->syntax = 0;
    di->xfer_uid = g_strdup(xfer_uid);
    di->xfer_desc = g_strdup(xfer_desc);

    if (*xfer_uid == NULL) return;
    /* this would be faster to skip the common parts, and have a FSA to
     * find the syntax.
     * Absent of coding that, this is in descending order of probability */
    if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2"))
	di->syntax = DCM_ILE;	 /* implicit little endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.1"))
	di->syntax = DCM_ELE;	 /* explicit little endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.2"))
	di->syntax = DCM_EBE;	 /* explicit big endian */
    else if (0 == strcmp(xfer_uid, "1.2.840.113619.5.2"))
	di->syntax = DCM_ILE;	 /* implicit little endian, big endian pixels, GE private */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.4.70"))
	di->syntax = DCM_ELE;	 /* explicit little endian, jpeg */
    else if (0 == strncmp(xfer_uid, "1.2.840.10008.1.2.4", 18))
	di->syntax = DCM_ELE;	 /* explicit little endian, jpeg */
    else if (0 == strcmp(xfer_uid, "1.2.840.10008.1.2.1.99"))
	di->syntax = DCM_ELE;	 /* explicit little endian, deflated */
}

static char *
dcm_tag2str(guint16 grp, guint16 elm, guint8 syntax, tvbuff_t *tvb, int offset, guint32 len, int vr, int tr)
{
    char *buf;
    const guint8 *vval;
    char *p;
    guint32 tag, val32;
    guint16 val16;
    dcmTag_t *dtag;
    static dcmTag_t utag = { 0, 0, "(unknown)" };

#define MAX_BUF_LEN 1024
    buf=ep_alloc(MAX_BUF_LEN);
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
	vval = tvb_format_text(tvb, offset, len);
	p+=MIN(MAX_BUF_LEN-(p-buf),
	       g_snprintf(p, MAX_BUF_LEN-(p-buf), " %s", vval));
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
	break;
    case DCM_SQ:	/* Sequence */
    case DCM_OTH:	/* Other BYTE, WORD, ... */
    case DCM_TRET:	/* Retired */
	break;
    }
    return buf;
}

static void
dissect_dcm_assoc_item(proto_tree *dcm_tree, tvbuff_t *tvb, int offset,
		       guchar *pitem_prefix, int item_value_type,
		       guchar **item_value, guchar **item_description,
		       int *hf_type, int *hf_len, int *hf_value)
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

    guint8  item_type;
    guint16 item_len;

    guchar *buf_desc=NULL;		/* Used for item text */

    #define MAX_BUFFER 1024

    *item_value=NULL;
    *item_description=NULL;

    buf_desc=ep_alloc(MAX_BUFFER);	/* Valid for this packet */
    buf_desc[0]=0;

    item_type = tvb_get_guint8(tvb, offset);
    item_len  = tvb_get_ntohs(tvb, offset+2);

    assoc_item_pitem = proto_tree_add_text(dcm_tree, tvb, offset, item_len+4, pitem_prefix);
    assoc_item_ptree = proto_item_add_subtree(assoc_item_pitem, ett_assoc_item);

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
    /*
    case DCM_ITEM_VALUE_TYPE_UINT32:
	*item_value = tvb_get_ntohl(tvb, offset+4);
	break;*/

    default:
	break;
    }
}


static void
dissect_dcm_presentation_context(dcmState_t *dcm_data, proto_tree *dcm_tree, tvbuff_t *tvb,
				 int offset, int len, guchar *pitem_prefix, gboolean request)
{
    /*
	Decode a presentation context item in a Association Request or Response
	In the response, set the accepted transfer syntax, if any
    */

    proto_tree *pctx_ptree = NULL;	/* Tree for presentation context details */
    proto_item *pctx_pitem = NULL;

    dcmItem_t *di = NULL;

    guint8  item_type;
    guint16 item_len;

    guint8  pctx_id;		    /* Presentation Context ID */
    guint8  pctx_result;

    guchar *pctx_abss_uid=NULL;	    /* Abstract Syntax UID alias SOP Class UID */
    guchar *pctx_abss_desc=NULL;    /* Description of UID */

    guchar *pctx_xfer_uid=NULL;	    /* Transfer Syntax UID */
    guchar *pctx_xfer_desc=NULL;    /* Description of UID */

    guchar *buf_desc=NULL;	    /* Used in infor mode for item text */
    int	    endpos;

    #define MAX_BUFFER 1024

    buf_desc=ep_alloc(MAX_BUFFER);	/* Valid for this packet */
    buf_desc[0]=0;

    endpos=offset+len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    pctx_pitem = proto_tree_add_text(dcm_tree, tvb, offset-4, item_len+4, pitem_prefix);
    pctx_ptree = proto_item_add_subtree(pctx_pitem, ett_assoc_pctx);

    pctx_id     = tvb_get_guint8(tvb, offset);
    pctx_result = tvb_get_guint8(tvb, 2 + offset);	/* only set in responses, otherwise reserved and 0x00 */

    /* Find or create dicom context object */
    di = lookupCtx(dcm_data, pctx_id);
    if (!di->valid) {
	di = se_alloc(sizeof(struct dcmItem));
	di->id = pctx_id;
	di->valid = 1;

	if (request) {
	    di->abss_uid = NULL;
	}
	else {
	    di->abss_uid = "Missing A-ASSOCIATE request";
	}
	di->abss_desc = NULL;

	di->xfer_uid = NULL;
	di->xfer_desc = NULL;
	di->syntax = DCM_UNK;
	di->next = di->prev = NULL;
	if (dcm_data->last_pctx) {
	    dcm_data->last_pctx->next = di;
	    di->prev = dcm_data->last_pctx;
	    dcm_data->last_pctx = di;
	} else
	    dcm_data->first_pctx = dcm_data->last_pctx = di;
    }

    proto_tree_add_uint(pctx_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 2, item_type);
    proto_tree_add_uint(pctx_ptree, hf_dcm_assoc_item_len, tvb, offset-2, 2, item_len);

    proto_tree_add_uint_format(pctx_ptree, hf_dcm_pctx_id, tvb, offset, 1, pctx_id, "Context ID: 0x%02x", pctx_id);

    if (!request) {
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

	    if (request) {

		/* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
	        dissect_dcm_assoc_item(pctx_ptree, tvb, offset-4,
		    "Abstract Syntax: ", DCM_ITEM_VALUE_TYPE_UID, &pctx_abss_uid, &pctx_abss_desc,
		    &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pctx_abss_syntax);
	    }

	    offset += item_len;
	    break;

	case 0x40:		/* Transfer syntax */

	    dissect_dcm_assoc_item(pctx_ptree, tvb, offset-4,
		"Transfer Syntax: ", DCM_ITEM_VALUE_TYPE_UID, &pctx_xfer_uid, &pctx_xfer_desc,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_pctx_xfer_syntax);

	    /*
	       In a correct Association Response, only one Transfer syntax shall be present.
	       Therefore, pctx_xfer_uid, pctx_xfer_desc are used for the accept scenario in the info mode
	    */

	    if (!request && pctx_result == 0) {
		/* Association Response, Context Accepted*/

		if (di && di->valid) {
			dcm_setSyntax(di, pctx_xfer_uid, pctx_xfer_desc);
		}
	    }
	    offset += item_len;
	    break;

	default:
	    offset += item_len;
	    break;
	}
    }

    if (di->abss_uid==NULL) {
	/* Permanent copy information into structure */
	di->abss_uid =g_strdup(pctx_abss_uid);
	di->abss_desc=g_strdup(pctx_abss_desc);
    }


    /*
      Copy to buffer first, because proto_item_append_text()
      crashed for an unknown reason using 'ID 0x%02x, %s, %s'
      and in my opinion correctly set parameters.
    */

    if (request) {
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
		dcm_uid_or_desc(di->xfer_uid, di->xfer_desc),
		dcm_uid_or_desc(di->abss_uid, di->abss_desc));
	}
	else {
	    /* Rejected */
	    g_snprintf(buf_desc, MAX_BUFFER, "ID 0x%02x, %s, %s",
		pctx_id, dcm_PCresult2str(pctx_result),
		dcm_uid_or_desc(di->abss_uid, di->abss_desc));
	}
    }
    proto_item_append_text(pctx_pitem, "%s", buf_desc);

}

static void
dissect_dcm_userinfo(dcmState_t *dcm_data, proto_tree *dcm_tree, tvbuff_t *tvb, int offset, int len,
		     guchar *pitem_prefix)
{
    /*
	Decode the user info item in a Association Request or Response
    */

    proto_item *userinfo_pitem = NULL;
    proto_tree *userinfo_ptree = NULL;	/* Tree for presentation context details */

    guint8  item_type;
    guint16 item_len;

    guint32 mlen=0;

    gboolean first_item=-1;

    guchar *buf_desc=NULL;		    /* Used in infor mode for item text */
    guchar *info_impl_uid=NULL;
    guchar *info_impl_version=NULL;
    guchar *dummy=NULL;

    int	    endpos;

    endpos=offset+len;

    item_type = tvb_get_guint8(tvb, offset-4);
    item_len  = tvb_get_ntohs(tvb, offset-2);

    userinfo_pitem = proto_tree_add_text(dcm_tree, tvb, offset-4, item_len+4, pitem_prefix);
    userinfo_ptree = proto_item_add_subtree(userinfo_pitem, ett_assoc_userinfo);

    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_type, tvb, offset-4, 2, item_type);
    proto_tree_add_uint(userinfo_ptree, hf_dcm_assoc_item_len, tvb, offset-2, 2, item_len);

    while (-1 < offset && offset < endpos) {

	item_type = tvb_get_guint8(tvb, offset);
	item_len = tvb_get_ntohs(tvb, 2 + offset);

	offset += 4;
	switch (item_type) {
	case 0x51:		/* Max length */
    	    mlen = tvb_get_ntohl(tvb, offset);
	    proto_tree_add_item(userinfo_ptree, hf_dcm_pdu_maxlen, tvb, offset, 4, FALSE);

	    if (!first_item) {
		proto_item_append_text(userinfo_pitem, ", ");
	    }
	    proto_item_append_text(userinfo_pitem, "Max PDU LENGHT 0x%x", mlen);
	    first_item=0;

	    offset += item_len;
	    break;

	case 0x52:		/* UID */

	    /* Parse Item. Works also in info mode where dcm_pctx_tree is NULL */
	    dissect_dcm_assoc_item(userinfo_ptree, tvb, offset-4,
		"Implementation UID: ", DCM_ITEM_VALUE_TYPE_STRING, &info_impl_uid, &dummy,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_info_uid);

	    if (!first_item) {
		proto_item_append_text(userinfo_pitem, ", ");
	    }
	    proto_item_append_text(userinfo_pitem, "Implementation UID %s", info_impl_uid);

	    first_item=0;

	    offset += item_len;
	    break;
	case 0x55:		/* version */

    	    dissect_dcm_assoc_item(userinfo_ptree, tvb, offset-4,
		"Implementation Version: ", DCM_ITEM_VALUE_TYPE_STRING, &info_impl_version, &dummy,
		&hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_info_version);

	    if (!first_item) {
		proto_item_append_text(userinfo_pitem, ", ");
	    }
	    proto_item_append_text(userinfo_pitem, "Version %s", info_impl_version);
	    first_item=0;

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
dissect_dcm_assoc(dcmState_t *dcm_data, proto_item *ti, tvbuff_t *tvb, int offset, int len)
{
    proto_tree *dcm_tree  = NULL;	/* Tree for PDU details */
    proto_item *item_pctx = NULL;

    guint8  item_type;
    guint16 item_len;

    int	    endpos;

    guchar *item_value=NULL;
    guchar *item_description=NULL;

    guchar *info_pctx=NULL;		/* Description of Presentation Context */

    endpos = offset+len;

    if (ti) {
	dcm_tree = proto_item_add_subtree(ti, ett_assoc);
	while (-1 < offset && offset < endpos) {

	    item_type = tvb_get_guint8(tvb, offset);
	    item_len  = tvb_get_ntohs(tvb, 2 + offset);

	    DISSECTOR_ASSERT(item_len > 0);

	    offset += 4;

	    switch (item_type) {
	    case 0x10:		/* Application context */
		dissect_dcm_assoc_item(dcm_tree, tvb, offset-4,
		    "Application Context: ", DCM_ITEM_VALUE_TYPE_UID, &item_value, &item_description,
		    &hf_dcm_assoc_item_type, &hf_dcm_assoc_item_len, &hf_dcm_actx);

		offset += item_len;
		break;

	    case 0x20:		/* Presentation context request */
		dissect_dcm_presentation_context(dcm_data, dcm_tree, tvb, offset, item_len,
		    "Presentation Context: ", -1);
		offset += item_len;
		break;

	    case 0x21:		/* Presentation context reply */
		dissect_dcm_presentation_context(dcm_data, dcm_tree, tvb, offset, item_len,
		    "Presentation Context: ", 0);
		offset += item_len;
		break;

	    case 0x50:		/* User Info */
		dissect_dcm_userinfo(dcm_data, dcm_tree, tvb, offset, item_len, "User Info: ");
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

static dcmItem_t *
lookupCtx(dcmState_t *dd, guint8 ctx)
{
    dcmItem_t *di = dd->first_pctx;
    static char notfound[] = "not found - click on ASSOC Request";
    static dcmItem_t dunk = { NULL, NULL, 0, -1, notfound, notfound, notfound, notfound, DCM_UNK };
    while (di) {
	if (ctx == di->id)
	    break;
	di = di->next;
    }
    return di ? di : &dunk;
}

/*
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
 */
#define D_HEADER 1
#define D_TAG    2
#define D_VR     3
#define D_LEN2   4
#define D_LEN4   5
#define D_VALUE  6

char *trim(char *str)
{
    char *ibuf = str, *obuf = str;
    int i = 0, cnt = 0;

    if (str)
    {
	/*  Remove leading spaces */

	for (ibuf = str; *ibuf && isspace(*ibuf); ++ibuf)
	    ;

	if (str != ibuf)
	    memmove(str, ibuf, ibuf - str);

	while (*ibuf)
	{
	    obuf[i++] = *ibuf++;
	}
	obuf[i] = 0x0;

	/* Remove trailing spaces */

	while (--i >= 0)
	{
	    if (!isspace(obuf[i]))
		break;
	}
	obuf[++i] = 0x0;
    }
    return str;
}

static int
dissect_dcm_data(dcmState_t *dcm_data, proto_item *ti, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{

    int toffset, state, vr = 0, tr = 0;
    proto_tree *dcm_tree;
    dcmItem_t	    *di;
    dcm_pdu_state_t *pdu=NULL;

    guint32 tag_value_fragment_len;	/* used for values that span multiple PDUs */

    guint8 ctx = DCM_UNK;
    guint8 syntax = DCM_UNK;
    guint8 flags;

    guint16 grp = 0, elm = 0;
    guint32 tlen = 0;
    guint32 nlen = 0;			/* Length of next sub item */

    guint32 tag_rlen = 0;

    int endpos = offset + datalen;

    offset += 6;	/* Skip PDU Header */

    /* There should be a loop per PDV. Currently only one is supported */

    dcm_tree = proto_item_add_subtree(ti, ett_dcm_data);
    proto_tree_add_item(dcm_tree, hf_dcm_pdv_len, tvb, offset, 4, FALSE);
    offset +=4;

    ctx = tvb_get_guint8(tvb, offset);
    di = lookupCtx(dcm_data, ctx);

    if (di->xfer_uid) {
	proto_tree_add_uint_format(dcm_tree, hf_dcm_pdv_ctx, tvb, offset, 1,
	    ctx, "Context: 0x%x (%s, %s)", ctx,
	dcm_uid_or_desc(di->xfer_uid, di->xfer_desc),
	dcm_uid_or_desc(di->abss_uid, di->abss_desc));
    }
    else {
	proto_tree_add_uint_format(dcm_tree, hf_dcm_pdv_ctx, tvb,  offset, 1,
	    ctx, "Context: 0x%x not found. A-ASSOCIATE request not found in capture.", ctx);
    }
    offset +=1;

    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format(dcm_tree, hf_dcm_pdv_flags, tvb, offset, 1,
	flags, "Flags: 0x%x (%s)", flags, dcm_flags2str(flags));

    offset +=1;

    if (0x1 & flags)
	syntax = DCM_ILE;
    else if (di->syntax == DCM_UNK) {
	const guint8 *val;
	tlen = datalen - offset;
	val = tvb_get_ptr(tvb, offset, tlen+8);
	proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
	    offset, tlen, val, "(%04x,%04x) %-8x Unparsed data", 0, 0, tlen);
	offset = datalen;
    } else
	syntax = di->syntax;

    /* Since we can have multiple PDU per packet (offset) and
       multiple merged packets per PDU (tvb->raw_offset)
       we need both to uniquely identify a PDU
    */

    pdu=dcm_pdu_state_get_or_create(dcm_data, pinfo->fd->num, tvb->raw_offset+offset);

    if (pdu==NULL) {
	return 0;	    /* Failed to allocate memory */
    }
    else if (pdu != dcm_data->first_pdu) {
	/* Not frist PDU in association (Those don't have remaining data to parse :-) */

	if (pdu->prev->tag_rlen>0) {
	    /* previous PDU has left overs, i.e. this is a continuation PDU */

	    const guint8 *val;

	    if (datalen - offset>=(int)pdu->prev->tag_rlen) {
		/*
		 * Remaining bytes are equal or more than we expect for the open tag
		 * Finally reach the end of this tag
		 */

		val = tvb_get_ptr(tvb, offset, pdu->prev->tag_rlen);

		proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
		    offset, pdu->prev->tag_rlen, val, "%s [end]", pdu->prev->tag_desc);

		offset+=pdu->prev->tag_rlen;

	    }
	    else {
		/*
		 * More to do for this tag
		 */
		tag_value_fragment_len = datalen - offset;

		val = tvb_get_ptr(tvb, offset, tag_value_fragment_len);

		proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
		    offset, tag_value_fragment_len, val, "%s [contiuation]", pdu->prev->tag_desc);

		offset+=tag_value_fragment_len;

		/* Update data in PDU structure */
	        pdu->tag_rlen=pdu->prev->tag_rlen-tag_value_fragment_len;
		pdu->tag_desc=pdu->prev->tag_desc;
		pdu->valid = TRUE;

	    }
	}
    }

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
		proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
		    toffset, totlen, val,
		    "(%04x,%04x) %-8x %s", grp, elm, tlen,
			dcm_tag2str(grp, elm, syntax, tvb, offset, 0, vr, tr));
		tlen = 0;
	    /* } else if (0xfffe == grp) { */ /* need to make a sub-tree here */
	    } else {
		totlen += tlen;
		val = tvb_get_ptr(tvb, toffset, totlen);
		proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
		    toffset, totlen, val,
		    "(%04x,%04x) %-8x %s", grp, elm, tlen,
			dcm_tag2str(grp, elm, syntax, tvb, offset, tlen, vr, tr));
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
	guchar	*buf;

	tag_value_fragment_len = datalen - offset;
	val = tvb_get_ptr(tvb, offset, tag_value_fragment_len);

	buf=ep_alloc(2048);	    /* Longer than what dcm_tag2str() returns */
	*buf = 0;

	g_snprintf(buf, 2048, "(%04x,%04x) %-8x %s",
	    grp, elm, tlen,
	    dcm_tag2str(grp, elm, syntax, tvb, offset, tlen, vr, tr));

	proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
	    offset, tag_value_fragment_len, val, "%s [start]", buf);

	if (!pdu->valid) {
	    /*  First time parsing of this PDU.
		Save the needed data for reuse, i.e. when called just to open a particular packet
	    */

	    pdu->tag_rlen=tlen-tag_value_fragment_len;
	    pdu->tag_desc=buf;
	    pdu->valid = TRUE;
	}
    }
    else {
	if (!pdu->valid) {
	    /*  First time parsing of this PDU.
		Save the needed data for reuse, i.e. when called just to open a particular packet
	    */
	    pdu->tag_rlen=0;
	    pdu->tag_desc=NULL;
	    pdu->valid = TRUE;
	}
    }

    return endpos;
}

static dcmState_t *
dcm_state_get_or_create(packet_info *pinfo, gboolean create_dcm_data)
{

    /*	Get or create converstation and DICOM data structure if desired
	Return new or existing dicom struture, which is used to store context IDs and xfer Syntax
	Return NULL in case of the structure couldn't be created
    */

    conversation_t  *conv=NULL;
    dcmState_t	    *dcm_data=NULL;

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
	pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

    if (conv == NULL) {		/* conversation does not exist, create one */
	conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
	    pinfo->srcport, pinfo->destport, 0);
    }
    else {			/* conversation exists, try to get data already filled */
	dcm_data = conversation_get_proto_data(conv, proto_dcm);
    }

    if (dcm_data == NULL && create_dcm_data) {

	dcm_data = mkds();
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

/* Code to actually dissect the packets */
static int
dissect_dcm_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean require_assoc_req)
{
    guint8  pdu_type;
    guint32 pdu_start;
    guint32 pdu_len;
    guint16 vers;
    guint32 tlen;

    int offset=0;

    /*
	Modified orignal code, which was optimized for a heuristic detection, and therefore
	caused some load and memory consumption, for every non DICOM packet not processed
	by someone else.

	Since tcp packets are now assembled well by wireshark (in conjunction with the dissectors)
	we will only see properly alligned PDUs, at the beginnig of the buffer, else its not DICOM
	traffic.

	Therfore do the byte checking as early as possible

	TBD: for the heurisitc hook, check for a converstation


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
    */

    tlen = tvb_reported_length(tvb);
    if (tlen<10) 				/* Not long enough	*/
	return 0;				/* No bytes taken from the stack */

    pdu_type = tvb_get_guint8(tvb, 0);
    if (pdu_type==0 || pdu_type>7) 		/* Wrong PDU type. Or is slightly more efficient than and here */
	return 0;

    pdu_len = tvb_get_ntohl(tvb, 2);
    if (pdu_len<6) 				/* Not long enough	*/
	return 0;

    vers = tvb_get_ntohs(tvb, 6);

    if (require_assoc_req) {

	/* find_conversation() seems to return a converstation, even if we never saw
	   any packet yet. Not really my interpretation of this function.

	   Therefore also check, if we already stored configuration data for converstation
	*/

	if (dcm_state_get_or_create(pinfo, FALSE)==NULL) {
	    	    
	    /* config data does not exist, check for association request */

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


    pdu_start = 0;
    pdu_len = tvb_get_ntohl(tvb, pdu_start+2);

     /* Process all PDUs in the buffer */
    while (pdu_start < tlen) {

	if ((pdu_len+6) > (tlen-offset)) {

	    /*	PDU is larger than the remaing packet (buffer), therefore request whole PDU
		The next time this function is called, tlen will be equal to pdu_len
	    */

	    pinfo->desegment_offset = offset;
	    pinfo->desegment_len = (pdu_len+6) - (tlen-offset);

	    /*	Why return a boolean for a deliberate int function?
		No better working example found.  
	    */
	    return TRUE;		
	}

	/* Process a whole PDU */
	offset=dissect_dcm_pdu(tvb, pinfo, tree, pdu_start);

	/* Next PDU */
	pdu_start =  pdu_start + pdu_len + 6;
	if (pdu_start < tlen) {
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
    proto_item *ti;
    dcmState_t *dcm_data;
    proto_tree *dcm_tree;

    guint8  pdu_type;
    guint32 pdu_len;

    int assoc_header=0;

    gboolean	valid_pdutype=TRUE;

    char *buf;
    const char *info_str = NULL;

    /* Get or create converstation. Used to store context IDs and xfer Syntax */

    dcm_data = dcm_state_get_or_create(pinfo, TRUE);
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

    pdu_type = tvb_get_guint8(tvb, offset);
    pdu_len = tvb_get_ntohl(tvb, offset + 2);

    switch (pdu_type) {
    case 1:					/* ASSOC Request */
	tvb_memcpy(tvb, dcm_data->ae_called, 10, 16);
	tvb_memcpy(tvb, dcm_data->ae_calling, 26, 16);
	dcm_data->ae_called[AEEND] = 0;
	dcm_data->ae_calling[AEEND] = 0;
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "A-ASSOCIATE request %s --> %s",
	    trim(dcm_data->ae_calling), trim(dcm_data->ae_called));
	info_str = buf;
	assoc_header = 74;
	break;
    case 2: 					/* ASSOC Accept */
	tvb_memcpy(tvb, dcm_data->ae_called_resp, 10, 16);
	tvb_memcpy(tvb, dcm_data->ae_calling_resp, 26, 16);
	dcm_data->ae_called_resp[AEEND] = 0;
	dcm_data->ae_calling_resp[AEEND] = 0;
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "A-ASSOCIATE accept  %s <-- %s",
	    trim(dcm_data->ae_calling_resp), trim(dcm_data->ae_called_resp));
	info_str = buf;
	assoc_header = 74;
	break;
    case 3:					/* ASSOC Reject */
	dcm_data->result = tvb_get_guint8(tvb, 7);
	dcm_data->source = tvb_get_guint8(tvb, 8);
	dcm_data->reason = tvb_get_guint8(tvb, 9);
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "A-ASSOCIATE reject  %s <-- %s %s %s %s",
	    trim(dcm_data->ae_calling_resp), trim(dcm_data->ae_called_resp),
	    dcm_result2str(dcm_data->result),
	    dcm_source2str(dcm_data->source),
	    dcm_reason2str(dcm_data->source, dcm_data->reason));
	info_str = buf;
	offset += pdu_len+6;
	break;
    case 4:					/* DATA */
	info_str="PRESENTATION-DATA";
	break;
    case 5:					/* RELEASE Request */
	info_str="A-RELEASE request";
	break;
    case 6:					/* RELEASE Response */
	info_str="A-RELEASE response";
	break;
    case 7:					/* ABORT */
	dcm_data->source = tvb_get_guint8(tvb, 8);
	dcm_data->reason = tvb_get_guint8(tvb, 9);
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "ABORT %s <-- %s %s %s",
	    dcm_data->ae_called, dcm_data->ae_calling,
	    (dcm_data->source == 1) ? "USER" :
		(dcm_data->source == 2) ? "PROVIDER" : "",
	    dcm_data->source == 1 ? dcm_abort2str(dcm_data->reason) : "");
	info_str = buf;
	break;
    default:
	info_str="Continuation or non-DICOM traffic";
	valid_pdutype = FALSE;				/* No packets taken from stack */
	break;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO, info_str);

    if (valid_pdutype) {

	if (tree) {
	    /*  In the interest of speed, if "tree" is NULL, don't do any work not
		necessary to generate protocol tree items.
	    */

	    proto_item *tf;
	    ti = proto_tree_add_item(tree, proto_dcm, tvb, offset, -1, FALSE);
	    dcm_tree = proto_item_add_subtree(ti, ett_dcm);
	    proto_tree_add_uint_format(dcm_tree, hf_dcm_pdu, tvb, offset, pdu_len+6,
		pdu_type, "PDU Type 0x%x (%s)", pdu_type, dcm_pdu2str(pdu_type));
	    proto_tree_add_item(dcm_tree, hf_dcm_pdu_len, tvb, offset+2, 4, FALSE);

	    switch (pdu_type) {
	    case 1:					/* ASSOC Request */
	    case 2: 					/* ASSOC Accept */
		tf = proto_tree_add_string(dcm_tree, hf_dcm_pdu_type, tvb, offset, pdu_len+6, info_str);
		offset = dissect_dcm_assoc(dcm_data, tf, tvb, offset+assoc_header, pdu_len+6-assoc_header);
		break;
	    case 4:					/* DATA */
		tf = proto_tree_add_string(dcm_tree, hf_dcm_pdu_type, tvb, offset, pdu_len+6, info_str);
		offset = dissect_dcm_data(dcm_data, tf, tvb, pinfo, offset, pdu_len+6);
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
	    offset = dissect_dcm_assoc(dcm_data, NULL, tvb, offset+assoc_header, pdu_len+6-assoc_header);
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
    { &hf_dcm_assoc_item_len, { "Item Len", "dicom.assoc.item.len",
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
    { &hf_dcm_pdu_maxlen, { "MAX PDU LENGTH", "dicom.max_pdu_len",
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
	    &ett_assoc_item,
	    &ett_assoc_pctx,
	    &ett_assoc_userinfo,
	    &ett_dcm_data
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
        1 – Username as a string in UTF-8
        2 – Username as a string in UTF-8 and passcode
        3 – Kerberos Service ticket
        4 – SAML Assertion
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
