/* packet-dcm.c
 * Routines for DICOM dissection
 * Copyright 2003, Rich Coe <Richard.Coe@med.ge.com>
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
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * This is my first pass at a Ethereal dissector to display
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
 * - If the DATA PDU has the 'more' bit set, subsequent packets will
 *   not currently display.  Finding out how much 'more' data is coming
 *   currently requires parsing the entire packet.
 * 
 * - The 'value to string' routines should probably be hash lookups.
 *
 * 9 Nov 2004
 * - Fixed the heuristic code -- sometimes a conversation already exists
 * - Fixed the dissect code to display all the tags in the pdu
 *
 * 28 Apr 2005
 * - fix memory leak when Assoc packet is processed repeatedly in ethereal
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "isprint.h"

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#include "packet-tcp.h"

/* Initialize the protocol and registered fields */
static int proto_dcm = -1;
static int hf_dcm_pdu = -1,
    hf_dcm_pdu_len = -1,
    hf_dcm_pdu_type = -1,
    hf_dcm_pdi = -1,
    hf_dcm_pdi_name = -1,
    hf_dcm_pdi_syntax = -1, 
    hf_dcm_pctxt = -1,
    hf_dcm_pcres = -1,
    hf_dcm_pdu_maxlen = -1,
    hf_dcm_impl = -1,
    hf_dcm_vers = -1,
    hf_dcm_async = -1,
    hf_dcm_data_len = -1,
    hf_dcm_data_ctx = -1,
    hf_dcm_data_flags = -1,
    hf_dcm_data_tag = -1;

/* Initialize the subtree pointers */
static gint ett_dcm = -1, ett_assoc = -1, ett_dcm_data = -1;

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

static const value_string dcm_pdi_ids[] = {
    { 0x10, "Application Context" },
    { 0x20, "Presentation Context" },
    { 0x21, "Presentation Context Reply" },
    { 0x30, "Abstract syntax" },
    { 0x40, "Transfer syntax" },
    { 0x50, "User Info" },
    { 0x51, "Max Length" },
    { 0, NULL }
};

struct dcmContext {
    guint8 id;
    guint8 result;
};
struct dcmItem {
    struct dcmItem *next, *prev;
    int valid;
    guint8 id;		/* 0x20 Presentation Context */
    const guint8 *abs;	/* 0x30 Abstract syntax */
    char *xfer;		/* 0x40 Transfer syntax */
    guint8 syntax;
#define DCM_ILE  0x01		/* implicit, little endian */
#define DCM_EBE  0x02           /* explicit, big endian */
#define DCM_ELE  0x03           /* explicit, little endian */
#define DCM_UNK  0xf0
};
typedef struct dcmItem dcmItem_t;

struct dcmState {
    dcmItem_t *first, *last;
    guint8 pdu;		/* protocol data unit */
    guint32 tlen, clen, rlen;    /* length: total, current, remaining */
    int coff;		/* current offset */
    int valid;		/* this conversation is a dicom conversation */
    /* enum { DCM_NONE, DCM_ASSOC, DCM_ }; */
#define AEEND 16
    guint8 orig[1+AEEND], targ[1+AEEND], resp[1+AEEND], source, result, reason;
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

dcmItem_t * lookupCtx(dcmState_t *dd, guint8 ctx);

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
    {  0x1030, DCM_TSTR,  "Move Orig AE" },
    {  0x1031, DCM_TINT2, "Move Orig Id" },
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
}

static dcmState_t *
mkds(void)
{
    dcmState_t *ds;

    if (NULL == (ds = (dcmState_t *) g_malloc(sizeof(dcmState_t)))) {
	return NULL;
    }
    ds->pdu = 0;
    ds->tlen = ds->rlen = 0;
    ds->valid = TRUE;
    memset(ds->orig, 0, sizeof(ds->orig));
    memset(ds->targ, 0, sizeof(ds->targ));
    memset(ds->resp, 0, sizeof(ds->resp));
    ds->first = ds->last = NULL;
    return ds;
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
    case 0:  s = "accept"; break;
    case 1:  s = "user-reject"; break;
    case 2:  s = "no-reason"; break;
    case 3:  s = "abstract syntax unsupported"; break;
    case 4:  s = "transfer syntax unsupported"; break;
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

static void
dcm_setSyntax(dcmItem_t *di, char *name)
{
    if (NULL == di) return;
    if (di->xfer != NULL)
	g_free(di->xfer);	/* free prev allocated xfer */
    di->syntax = 0;
    di->xfer = g_strdup(name);
    if (0 == *name) return;
    /* this would be faster to skip the common parts, and have a FSA to 
     * find the syntax.
     * Absent of coding that, this is in descending order of probability */
    if (0 == strcmp(name, "1.2.840.10008.1.2"))
	di->syntax = DCM_ILE;	 /* implicit little endian */
    else if (0 == strcmp(name, "1.2.840.10008.1.2.1"))
	di->syntax = DCM_ELE;	 /* explicit little endian */
    else if (0 == strcmp(name, "1.2.840.10008.1.2.2"))
	di->syntax = DCM_EBE;	 /* explicit big endian */
    else if (0 == strcmp(name, "1.2.840.113619.5.2"))
	di->syntax = DCM_ILE;	 /* implicit little endian, big endian pixels */
    else if (0 == strcmp(name, "1.2.840.10008.1.2.4.70"))
	di->syntax = DCM_ELE;	 /* explicit little endian, jpeg */
    else if (0 == strncmp(name, "1.2.840.10008.1.2.4", 18))
	di->syntax = DCM_ELE;	 /* explicit little endian, jpeg */
    else if (0 == strcmp(name, "1.2.840.10008.1.2.1.99"))
	di->syntax = DCM_ELE;	 /* explicit little endian, deflated */
}

static char *
dcm_tag2str(guint16 grp, guint16 elm, guint8 syntax, tvbuff_t *tvb, int offset, guint32 len, int vr, int tr)
{
    static char buf[512+1];	/* bad form ??? */
    const guint8 *vval;
    size_t vval_len;
    char *p;
    guint32 tag, val32;
    guint16 val16;
    dcmTag_t *dtag;
    size_t pl;
    static dcmTag_t utag = { 0, 0, "(unknown)" };

    *buf = 0;
    if (0 == elm) {
	if (DCM_ILE & syntax) 
	     val32 = tvb_get_letohl(tvb, offset); 
	else val32 = tvb_get_ntohl(tvb, offset); 
	g_snprintf(buf, sizeof(buf), "Group Length 0x%x (%d)", val32, val32);
	return buf;
    }
    tag = (grp << 16) | elm;
    if (NULL == (dtag = g_hash_table_lookup(dcm_tagTable, GUINT_TO_POINTER(tag))))
	dtag = &utag;

    DISSECTOR_ASSERT(sizeof(buf) > strlen(dtag->desc));
    strcpy(buf, dtag->desc);
    pl = sizeof(buf) - strlen(buf);
    p = buf + strlen(buf);
    if (vr > 0) {
	vval = tvb_format_text(tvb, vr, 2);
	*p++ = ' ';
	*p++ = '[';
	strcpy(p, vval);
	p += strlen(vval);
	*p++ = ']';
	*p = 0;
	pl -= 5;
    }

    switch (tr > 0 ? tr : dtag->dtype) {
    case DCM_TSTR:
    default:		/* try ascii */
	*p++ = ' ';
	vval = tvb_format_text(tvb, offset, len);
	vval_len = strlen(vval);
	if (vval_len > pl) {
	    strncpy(p, vval, pl - 6);
	    p += pl - 6;
	    strcpy(p, "[...]");
	} else {
	    strncpy(p, vval, vval_len);
	    p += vval_len;
	    *p = 0;
	}
	break;
    case DCM_TINT2:
	if (DCM_ILE & syntax) 
	     val16 = tvb_get_letohs(tvb, offset);
	else val16 = tvb_get_ntohs(tvb, offset);
	sprintf(p, " 0x%x (%d)", val16, val16);
	break;
    case DCM_TINT4:
	if (DCM_ILE & syntax) 
	     val32 = tvb_get_letohl(tvb, offset); 
	else val32 = tvb_get_ntohl(tvb, offset); 
	sprintf(p, " 0x%x (%d)", val32, val32);
	break;
    case DCM_TFLT: {
	gfloat valf;
	if (DCM_ILE & syntax) 
	     valf = tvb_get_letohieee_float(tvb, offset); 
	else valf = tvb_get_ntohieee_float(tvb, offset); 
	sprintf(p, " (%f)", valf);
	} break;
    case DCM_TDBL: {
	gdouble vald;
	if (DCM_ILE & syntax) 
	     vald = tvb_get_letohieee_double(tvb, offset); 
	else vald = tvb_get_ntohieee_double(tvb, offset); 
	sprintf(p, " (%f)", vald);
	} break;
    case DCM_TSTAT: /* call dcm_rsp2str() on TINT2 */
	if (DCM_ILE & syntax) 
	     val16 = tvb_get_letohs(tvb, offset);
	else val16 = tvb_get_ntohs(tvb, offset);
	sprintf(p, " 0x%x '%s'", val16, dcm_rsp2str(val16));
	break;
    case DCM_TCMD:   /* call dcm_cmd2str() on TINT2 */
	if (DCM_ILE & syntax) 
	     val16 = tvb_get_letohs(tvb, offset);
	else val16 = tvb_get_ntohs(tvb, offset);
	sprintf(p, " 0x%x '%s'", val16, dcm_cmd2str(val16));
	break;
    case DCM_SQ:	/* Sequence */
    case DCM_OTH:	/* Other BYTE, WORD, ... */
    case DCM_TRET:	/* Retired */
	break;
    }
    return buf;
}

static guint
dcm_get_pdu_len(tvbuff_t *tvb, int offset)
{
    guint32 len;

    len = tvb_get_ntohl(tvb, 2 + offset);
    return len + 6;		/* add in fixed header part */
}

static void 
dissect_dcm_assoc(dcmState_t *dcm_data, proto_item *ti, tvbuff_t *tvb, int offset)
{ 
    proto_tree *dcm_tree = NULL;
    dcmItem_t *di = NULL;
    guint8 id, *name, result;
    int reply = 0;

    if (!ti)
	return;

    dcm_tree = proto_item_add_subtree(ti, ett_assoc);
    while (-1 < offset && offset < (int) dcm_data->clen) {
	guint16 len;
	guint32 mlen;
	id = tvb_get_guint8(tvb, offset);
	len = tvb_get_ntohs(tvb, 2 + offset);
	if (ti)
	    proto_tree_add_uint_format(dcm_tree, hf_dcm_pdi, tvb,
	        offset, 4+len, id, "Item 0x%x (%s)", id, dcm_pdu2str(id));
	offset += 4;
	switch (id) {
	case 0x10:		/* App context */
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_pdi_name, tvb, offset, len > 65 ? 65 : len, FALSE);
	    offset += len;
	    break;
	case 0x30:		/* Abstract syntax */
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_pdi_syntax, tvb, offset, len > 65 ? 65 : len, FALSE);
	    offset += len;
	    break;
	case 0x40:		/* Transfer syntax */
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_pdi_syntax, tvb, offset, len > 65 ? 65 : len, FALSE);
	    if (reply && di && di->valid) {
		name = tvb_get_ephemeral_string(tvb, offset, len);
		dcm_setSyntax(di, name);
	    }
	    reply = 0;
	    offset += len;
	    break;
	case 0x20:		/* Presentation context */
	    id = tvb_get_guint8(tvb, offset);
	    di = lookupCtx(dcm_data, id);
	    if (!di->valid) {
		di = se_alloc(sizeof(struct dcmItem));
		di->id = id;
		di->valid = 1;
		di->xfer = NULL;
		di->syntax = DCM_UNK;
		di->next = di->prev = NULL;
		if (dcm_data->last) {
		    dcm_data->last->next = di;
		    di->prev = dcm_data->last;
		    dcm_data->last = di;
		} else 
		    dcm_data->first = dcm_data->last = di;
	    }
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_pctxt, tvb, offset, 1, FALSE);
	    offset += 4;
	    break;
	case 0x21:		/* Presentation context reply */
	    id = tvb_get_guint8(tvb, offset);
	    result = tvb_get_guint8(tvb, 2 + offset);
	    if (ti) {
		proto_tree_add_item(dcm_tree, hf_dcm_pctxt, tvb, offset, 1, FALSE);
		proto_tree_add_uint_format(dcm_tree, hf_dcm_pcres, tvb, 
		    2 + offset, 1, result, 
		    "Result 0x%x (%s)", result, dcm_PCresult2str(result));
	    }
	    if (0 == result) {
		reply = 1;
		di = lookupCtx(dcm_data, id);
		offset += 4;
	    } else
		offset += len;
	    break;
	case 0x50:		/* User Info */
	    break;
	case 0x51:		/* Max length */
	    mlen = tvb_get_ntohl(tvb, offset);
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_pdu_maxlen, tvb, offset, 4, FALSE);
	    offset += len;
	    break;
	case 0x52:		/* UID */
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_impl, tvb, offset, len > 65 ? 65 : len, FALSE);
	    offset += len;
	    break;
	case 0x55:		/* version */
	    if (ti)
		proto_tree_add_item(dcm_tree, hf_dcm_vers, tvb, offset, len > 17 ? 17 : len, FALSE);
	    offset += len;
	    break;
	case 0x53:		/* async negotion */
	    /* hf_dcm_async */
	    offset += len;
	    break;
	default:
	    offset += len;
	    break;
	}
    }
}

dcmItem_t *
lookupCtx(dcmState_t *dd, guint8 ctx)
{
    dcmItem_t *di = dd->first;
    static dcmItem_t dunk = { NULL, NULL, 0, -1, 
	"not found - click on ASSOC Request", 
	"not found - click on ASSOC Request", DCM_UNK };
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

static void 
dissect_dcm_data(dcmState_t *dcm_data, proto_item *ti, tvbuff_t *tvb)
{
    int len, offset, toffset, state, vr, tr;
    proto_tree *dcm_tree;
    dcmItem_t *di;
    guint8 ctx, syntax = DCM_UNK;
    guint16 grp = 0, elm = 0;
    guint32 tlen = 0, nlen;

    dcm_tree = proto_item_add_subtree(ti, ett_dcm_data);
    proto_tree_add_item(dcm_tree, hf_dcm_data_len, tvb, 6, 4, FALSE);
    ctx = tvb_get_guint8(tvb, 10);
    di = lookupCtx(dcm_data, ctx);
    /*
     * XXX - telling the user to "click on ASSOC request" is bogus if we
     * have already identified the ASSOC request and can connect it to
     * this mnessage; if clicking on a request prior to this one causes
     * additional state information to be set up that would affect the
     * dissection of this request, we should set up that state *at the
     * time we dissect that request*, if possible, and if clicking on it
     * doesn't change any state, clicking on the request doesn't convey
     * any additional information.
     */
    proto_tree_add_uint_format(dcm_tree, hf_dcm_data_ctx, tvb, 10, 1, 
	ctx, "Context 0x%x (%s)", ctx,
	di->xfer == NULL ? "not found - click on ASSOC Request" :
			   di->xfer);
    if (DCM_UNK == di->syntax)
	return;
    len = offset = toffset = 11;
    state = D_HEADER;
    nlen = 1;
    while (len + nlen <= dcm_data->tlen && len + nlen <= dcm_data->clen) {
    switch (state) {
    case D_HEADER: {
	guint8 flags;
	flags = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(dcm_tree, hf_dcm_data_flags, tvb, offset, 1, 
	    flags, "Flags 0x%x (%s)", flags, dcm_flags2str(flags));
	/* proto_tree_add_item(dcm_tree, hf_dcm_data_flags, tvb, offset, 1, FALSE); */
	len++;
	offset++;
	if (0x1 & flags) 
	    syntax = DCM_ILE;
	else if (DCM_UNK == di->syntax) {
	    const guint8 *val;
	    tlen = dcm_data->clen - len;
	    val = tvb_get_ptr(tvb, offset, tlen+8);
	    proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
		offset, tlen, val, "(%04x,%04x) %-8x Unparsed data", 0, 0, tlen);
	    len = dcm_data->clen;      /* ends parsing */
	} else
	    syntax = di->syntax;
	state = D_TAG;
	nlen = 4;
	} break;		/* don't fall through -- check length */
    case D_TAG: {
	vr = tr = 0;
	if (DCM_ILE & syntax) {
	    grp = tvb_get_letohs(tvb, offset);
	    elm = tvb_get_letohs(tvb, offset+2);
	    state = (DCM_EBE & syntax) ? D_VR : D_LEN4;  /* is Explicit */
	    nlen  = (DCM_EBE & syntax) ? 2 : 4;  /* is Explicit */
	} else {
	    grp = tvb_get_ntohs(tvb, offset);
	    elm = tvb_get_ntohs(tvb, offset+2);
	    state = D_VR;
	    nlen = 2;
	}
	toffset = offset;
	if (0xfffe == grp) state = D_LEN4;
	offset += 4;
	len += 4;
	} break;		/* don't fall through -- check length */
    case D_VR:  {
	guint8 V, R;
	vr = offset;
	V = tvb_get_guint8(tvb, offset); offset++;
	R = tvb_get_guint8(tvb, offset); offset++;
	len += 2;
	/* 4byte lengths OB, OW, OF, SQ, UN, UT */
	state = D_LEN2;
	nlen = 2;
	if ((('O' == V) && ('B' == R || 'W' == R || 'F' == R) && (tr = DCM_OTH))
	    || (('U' == V) && ('N' == R || (('T' == R) && (tr = DCM_TSTR))))
	    || ('S' == V && 'Q' == R && (tr = DCM_SQ))) {
	    state = D_LEN4;
	    offset += 2;	/* skip 00 (2 bytes) */
	    len += 2;
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
	len += 2;
	state = D_VALUE;
	nlen = tlen;
	} break;
    case D_LEN4: {
	if (DCM_ILE & syntax)	/* is it LE */
	    tlen = tvb_get_letohl(tvb, offset); 
	else
	    tlen = tvb_get_ntohl(tvb, offset); 
	offset += 4;
	len += 4;
	state = D_VALUE;
	nlen = tlen;
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
	len += tlen;
	offset += tlen;
	state = D_TAG;
	nlen = 4;
	} break;
    }
    }
    if (D_VALUE == state) {
	const guint8 *val;
	int totlen = (offset - toffset);
	val = tvb_get_ptr(tvb, toffset, totlen);
	proto_tree_add_bytes_format(dcm_tree, hf_dcm_data_tag, tvb,
	    toffset, totlen, val,
	    "(%04x,%04x) %-8x %s [incomplete]", grp, elm, tlen, 
		dcm_tag2str(grp, elm, syntax, tvb, offset, tlen, vr, tr));
    }
}

/* 
     Originator src:srcport dest:destport
     Acceptor   src:srcport dest:destport

     conn = lookup(src:srcport, dest:destport) 
     if (!conn)
	 look at data payload of packet
	 if no-data return false;
	 if 01 == *p && *p+10 ... *p+42 <= [ 0x20 .. printable ]
	    create conn
 */

static void dissect_dcm_pdu(tvbuff_t *tvb,packet_info *pinfo,proto_tree *tree);

/* Code to actually dissect the packets */
static gboolean
dissect_dcm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    conversation_t *conv;
    guint8 pdu;
    guint16 vers;
    guint32 len, tlen;
    dcmState_t *dcm_data = NULL;

    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
	pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

    if (NULL != conv) 	/* conversation exists */
			/* do we have any data for this conversation ? */
	dcm_data = conversation_get_proto_data(conv, proto_dcm);
    else
	conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
	    pinfo->srcport, pinfo->destport, 0);

    if (NULL == dcm_data) {
	/* No conversation found.
	 * only look for the first packet of a DICOM conversation.
	 * if we don't get the first packet, we cannot decode the rest
	 * of the session.
	 */
	if (NULL == (dcm_data = mkds()))
	    return FALSE;	/* internal error */
	if (10 > (tlen = tvb_reported_length(tvb))     /* not long enough */
	    || 1 != (pdu = tvb_get_guint8(tvb, 0))     /* look for the start */
	    || 1 != (vers = tvb_get_ntohs(tvb, 6)))    /* not version 1 */
	    dcm_data->valid = FALSE;		
	else {
	    len = 6 + tvb_get_ntohl(tvb, 2);
	    if (len < tlen)
		dcm_data->valid = FALSE;	/* packet is > decl len */
	}

	conversation_add_proto_data(conv, proto_dcm, dcm_data);
    }

    if (FALSE == dcm_data->valid)
	return FALSE;

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	col_clear(pinfo->cinfo, COL_PROTOCOL);

    tcp_dissect_pdus(tvb, pinfo, tree, 1, 6, dcm_get_pdu_len, dissect_dcm_pdu);

    return TRUE;
}

static void
dissect_dcm_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    dcmState_t *dcm_data;
    proto_tree *dcm_tree;
    conversation_t *conv;
    char *buf=NULL;
    int offset = 0;

    if (NULL == (conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
	pinfo->ptype, pinfo->srcport, pinfo->destport, 0)))
	return;  /* OOPS */

    dcm_data = conversation_get_proto_data(conv, proto_dcm);

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCM");
    
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. See section 1.5
   for more information.
   */

    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_clear(pinfo->cinfo, COL_INFO);

    dcm_data->pdu = tvb_get_guint8(tvb, 0);
    dcm_data->tlen = tvb_get_ntohl(tvb, 2) + 6;
    dcm_data->clen = tvb_reported_length(tvb);

    switch (dcm_data->pdu) {
    case 1:					/* ASSOC Request */
	tvb_memcpy(tvb, dcm_data->orig, 10, 16);
	tvb_memcpy(tvb, dcm_data->targ, 26, 16);
	dcm_data->orig[AEEND] = dcm_data->targ[AEEND] = 0;
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "DCM ASSOC Request %s <-- %s",
	    dcm_data->orig, dcm_data->targ);
	offset = 74;
	break;
    case 2: 				/* ASSOC Accept */
	tvb_memcpy(tvb, dcm_data->resp, 26, 16);
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "DCM ASSOC Accept %s <-- %s (%s)",
	    dcm_data->orig, dcm_data->targ, dcm_data->resp);
	offset = 74; 
	break;
    case 3:					/* ASSOC Reject */
	dcm_data->result = tvb_get_guint8(tvb, 7);
	dcm_data->source = tvb_get_guint8(tvb, 8);
	dcm_data->reason = tvb_get_guint8(tvb, 9);
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "DCM ASSOC Reject %s <-- %s %s %s %s",
	    dcm_data->orig, dcm_data->targ,
	    dcm_result2str(dcm_data->result),
	    dcm_source2str(dcm_data->source),
	    dcm_reason2str(dcm_data->source, dcm_data->reason));
	offset = 10;
	break;
    case 4:					/* DATA */
	offset = 6; 
	buf = ep_alloc(128);
	strcpy(buf, "DCM Data");
	break;
    case 5:					/* RELEASE Request */
	buf = ep_alloc(128);
	strcpy(buf, "DCM RELEASE Request");
	offset = 6; 
	break;
    case 6:					/* RELEASE Response */
	buf = ep_alloc(128);
	strcpy(buf, "DCM RELEASE Response");
	offset = 6; 
	break;
    case 7:					/* ABORT */
	dcm_data->source = tvb_get_guint8(tvb, 8);
	dcm_data->reason = tvb_get_guint8(tvb, 9);
	buf = ep_alloc(128);
	g_snprintf(buf, 128, "DCM ABORT %s <-- %s %s %s", 
	    dcm_data->orig, dcm_data->targ,
	    (dcm_data->source == 1) ? "USER" :
		(dcm_data->source == 2) ? "PROVIDER" : "",
	    dcm_data->source == 1 ? dcm_abort2str(dcm_data->reason) : "");
	break;
    default:
	buf = ep_alloc(128);
	strcpy(buf, "DCM Continuation");
	offset = -1;				/* cannot continue parsing */
	break;
    }
    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_set_str(pinfo->cinfo, COL_INFO, buf);

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
    if (tree) {
    proto_item *tf;
    ti = proto_tree_add_item(tree, proto_dcm, tvb, 0, -1, FALSE);
    dcm_tree = proto_item_add_subtree(ti, ett_dcm);
    proto_tree_add_uint_format(dcm_tree, hf_dcm_pdu, tvb, 0, dcm_data->tlen, 
	dcm_data->pdu, "PDU 0x%x (%s)", dcm_data->pdu, 
	dcm_pdu2str(dcm_data->pdu));
    proto_tree_add_item(dcm_tree, hf_dcm_pdu_len, tvb, 2, 4, FALSE);

    switch (dcm_data->pdu) {
    case 1:					/* ASSOC Request */
    case 2: 					/* ASSOC Accept */
    case 3:					/* ASSOC Reject */
    case 5:					/* RELEASE Request */
    case 6:					/* RELEASE Response */
    case 7:					/* ABORT */
	tf = proto_tree_add_string(dcm_tree, hf_dcm_pdu_type, tvb, 0, dcm_data->tlen, buf);
	dissect_dcm_assoc(dcm_data, tf, tvb, offset);
	break;
    case 4:					/* DATA */
	tf = proto_tree_add_string(dcm_tree, hf_dcm_pdu_type, tvb, 0, dcm_data->tlen, buf);
	dissect_dcm_data(dcm_data, tf, tvb);
	break;
    default:
	break;
    }

/* Continue adding tree items to process the packet here */
    } else if (1 == dcm_data->pdu || 2 == dcm_data->pdu) {
	dissect_dcm_assoc(dcm_data, NULL, tvb, offset);
    }

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_dcm(void)
{                 
/* Setup list of header fields  See Section 1.6.1 for details*/
static hf_register_info hf[] = {
    { &hf_dcm_pdu, { "PDU", "dcm.pdu",
	FT_UINT8, BASE_HEX, VALS(dcm_pdu_ids), 0, "", HFILL } },
    { &hf_dcm_pdu_len, { "PDU LENGTH", "dcm.pdu_len",
	FT_UINT32, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_pdu_type, { "PDU Detail", "dcm.pdu_detail",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_pdi, { "Item", "dcm.pdu.pdi",
	FT_UINT8, BASE_HEX, VALS(dcm_pdi_ids), 0, "", HFILL } },
    { &hf_dcm_pdi_name, { "Application Context", "dcm.pdi.name",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_pdi_syntax, { "Abstract Syntax", "dcm.pdi.syntax",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_pctxt, { "Presentation Context", "dcm.pdi.ctxt",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_pcres, { "Presentation Context result", "dcm.pdi.result",
	FT_UINT8, BASE_HEX, VALS(dcm_pdi_ids), 0, "", HFILL } },
    { &hf_dcm_pdu_maxlen, { "MAX PDU LENGTH", "dcm.max_pdu_len",
	FT_UINT32, BASE_DEC, NULL, 0, "", HFILL } },
    { &hf_dcm_impl, { "Implementation", "dcm.pdi.impl",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_vers, { "Version", "dcm.pdi.version",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_async, { "Asynch", "dcm.pdi.async",
	FT_STRING, BASE_NONE, NULL, 0, "", HFILL } },
    { &hf_dcm_data_len, { "DATA LENGTH", "dcm.data.len",
	FT_UINT32, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_data_ctx, { "Data Context", "dcm.data.ctx",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_data_flags, { "Flags", "dcm.data.flags",
	FT_UINT8, BASE_HEX, NULL, 0, "", HFILL } },
    { &hf_dcm_data_tag, { "Tag", "dcm.data.tag",
	FT_BYTES, BASE_HEX, NULL, 0, "", HFILL } },
/*
    { &hf_dcm_FIELDABBREV, { "FIELDNAME", "dcm.FIELDABBREV",
	FIELDTYPE, FIELDBASE, FIELDCONVERT, BITMASK, "FIELDDESCR", HFILL } },
 */
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	    &ett_dcm,
	    &ett_assoc,
	    &ett_dcm_data
    };
/* Register the protocol name and description */
    proto_dcm = proto_register_protocol("DICOM", "dicom", "dcm");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_dcm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(&dcm_init);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_dcm(void)
{
    dissector_handle_t dcm_handle;

    heur_dissector_add("tcp", dissect_dcm, proto_dcm);
    dcm_handle = new_create_dissector_handle(dissect_dcm, proto_dcm);
    dissector_add("tcp.port", 104, dcm_handle);
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
 */
