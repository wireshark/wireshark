/* packet-x25.c
 * Routines for x25 packet disassembly
 * Olivier Abad <abad@daba.dhis.net>
 *
 * $Id: packet-x25.c,v 1.22 2000/03/12 04:47:51 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "packet-ip.h"
#include "packet-osi.h"
#include "nlpid.h"

#define FROM_DCE			0x80

#define	X25_CALL_REQUEST		0x0B
#define	X25_CALL_ACCEPTED		0x0F
#define	X25_CLEAR_REQUEST		0x13
#define	X25_CLEAR_CONFIRMATION		0x17
#define	X25_INTERRUPT			0x23
#define	X25_INTERRUPT_CONFIRMATION	0x27
#define	X25_RESET_REQUEST		0x1B
#define	X25_RESET_CONFIRMATION		0x1F
#define	X25_RESTART_REQUEST		0xFB
#define	X25_RESTART_CONFIRMATION	0xFF
#define	X25_REGISTRATION_REQUEST	0xF3
#define	X25_REGISTRATION_CONFIRMATION	0xF7
#define	X25_DIAGNOSTIC			0xF1
#define	X25_RR				0x01
#define	X25_RNR				0x05
#define	X25_REJ				0x09
#define	X25_DATA			0x00

#define X25_FAC_CLASS_MASK		0xC0

#define X25_FAC_CLASS_A			0x00
#define X25_FAC_CLASS_B			0x40
#define X25_FAC_CLASS_C			0x80
#define X25_FAC_CLASS_D			0xC0

#define X25_FAC_COMP_MARK		0x00
#define X25_FAC_REVERSE			0x01
#define X25_FAC_THROUGHPUT		0x02
#define X25_FAC_CUG			0x03
#define X25_FAC_CALLED_MODIF		0x08
#define X25_FAC_CUG_OUTGOING_ACC	0x09
#define X25_FAC_THROUGHPUT_MIN		0x0A
#define X25_FAC_EXPRESS_DATA		0x0B
#define X25_FAC_BILATERAL_CUG		0x41
#define X25_FAC_PACKET_SIZE		0x42
#define X25_FAC_WINDOW_SIZE		0x43
#define X25_FAC_RPOA_SELECTION		0x44
#define X25_FAC_TRANSIT_DELAY		0x49
#define X25_FAC_CALL_TRANSFER		0xC3
#define X25_FAC_CALLED_ADDR_EXT		0xC9
#define X25_FAC_ETE_TRANSIT_DELAY	0xCA
#define X25_FAC_CALLING_ADDR_EXT	0xCB
#define X25_FAC_CALL_DEFLECT		0xD1
#define X25_FAC_PRIORITY		0xD2

static int proto_x25 = -1;
static int hf_x25_qbit = -1;
static int hf_x25_dbit = -1;
static int hf_x25_mod = -1;
static int hf_x25_lcn = -1;
static int hf_x25_type = -1;
static int hf_x25_p_r = -1;
static int hf_x25_mbit = -1;
static int hf_x25_p_s = -1;
static int proto_ex25 = -1;
static int hf_ex25_qbit = -1;
static int hf_ex25_dbit = -1;
static int hf_ex25_mod = -1;
static int hf_ex25_lcn = -1;
static int hf_ex25_type = -1;
static int hf_ex25_p_r = -1;
static int hf_ex25_mbit = -1;
static int hf_ex25_p_s = -1;

static gint ett_x25 = -1;
static gint ett_x25_fac = -1;
static gint ett_x25_fac_unknown = -1;
static gint ett_x25_fac_mark = -1;
static gint ett_x25_fac_reverse = -1;
static gint ett_x25_fac_throughput = -1;
static gint ett_x25_fac_cug = -1;
static gint ett_x25_fac_called_modif = -1;
static gint ett_x25_fac_cug_outgoing_acc = -1;
static gint ett_x25_fac_throughput_min = -1;
static gint ett_x25_fac_express_data = -1;
static gint ett_x25_fac_bilateral_cug = -1;
static gint ett_x25_fac_packet_size = -1;
static gint ett_x25_fac_window_size = -1;
static gint ett_x25_fac_rpoa_selection = -1;
static gint ett_x25_fac_transit_delay = -1;
static gint ett_x25_fac_call_transfer = -1;
static gint ett_x25_fac_called_addr_ext = -1;
static gint ett_x25_fac_ete_transit_delay = -1;
static gint ett_x25_fac_calling_addr_ext = -1;
static gint ett_x25_fac_call_deflect = -1;
static gint ett_x25_fac_priority = -1;

static const value_string vals_modulo[] = {
	{ 1, "8" },
	{ 2, "128" },
	{ 0, NULL}
};

static const value_string vals_x25_type[] = {
	{ X25_CALL_REQUEST, "Call" },
	{ X25_CALL_ACCEPTED, "Call Accepted" },
	{ X25_CLEAR_REQUEST, "Clear" },
	{ X25_CLEAR_CONFIRMATION, "Clear Confirmation" },
	{ X25_INTERRUPT, "Interrupt" },
	{ X25_INTERRUPT_CONFIRMATION, "Interrupt Confirmation" },
	{ X25_RESET_REQUEST, "Reset" },
	{ X25_RESET_CONFIRMATION, "Reset Confirmation" },
	{ X25_RESTART_REQUEST, "Restart" },
	{ X25_RESTART_CONFIRMATION, "Restart Confirmation" },
	{ X25_REGISTRATION_REQUEST, "Registration" },
	{ X25_REGISTRATION_CONFIRMATION, "Registration Confirmation" },
	{ X25_DIAGNOSTIC, "Diagnostic" },
	{ X25_RR, "RR" },
	{ X25_RNR, "RNR" },
	{ X25_REJ, "REJ" },
	{ X25_DATA, "DATA" },
	{ 0,   NULL}
};

/*
 * each vc_info node contains :
 *   the time of the first frame using this dissector (secs and usecs)
 *   the time of the last frame using this dissector (0 if it is unknown)
 *   a pointer to the dissector
 *
 * the "time of first frame" is initialized when a Call Req. is received
 * the "time of last frame" is initialized when a Clear, Reset, or Restart
 * is received
 */
typedef struct _vc_info {
	guint32 first_frame_secs, first_frame_usecs;
	guint32 last_frame_secs, last_frame_usecs;
	void (*dissect)(const u_char *, int, frame_data *, proto_tree *);
	struct _vc_info *next;
} vc_info;

/*
 * the hash table will contain linked lists of global_vc_info
 * each global_vc_info struct contains :
 *   the VC number (the hash table is indexed with VC % 64)
 *   a linked list of vc_info
 */
typedef struct _global_vc_info {
	int vc_num;
	vc_info *info;
	struct _global_vc_info *next;
} global_vc_info;

static global_vc_info *hash_table[64];

void
free_vc_info(vc_info *pt)
{
  vc_info *vci = pt;

  while (pt) {
    vci = pt;
    pt = pt->next;
    g_free(vci);
  }
}

static void
reinit_x25_hashtable(void)
{
  int i;

  for (i=0; i<64; i++) {
    if (hash_table[i]) /* not NULL ==> free */
    {
      global_vc_info *hash_ent, *hash_ent2;
      hash_ent2 = hash_ent = hash_table[i];
      while (hash_ent)
      {
        hash_ent2 = hash_ent;
	hash_ent = hash_ent->next;
	free_vc_info(hash_ent2->info);
	g_free(hash_ent2);
      }
      hash_table[i]=0;
    }
  }
}

void
x25_hash_add_proto_start(guint16 vc, guint32 frame_secs, guint32 frame_usecs,
		         void (*dissect)(const u_char *, int, frame_data *,
				       proto_tree *))
{
  int idx = vc % 64;
  global_vc_info *hash_ent;
  global_vc_info *hash_ent2;

  if (hash_table[idx] == 0)
  {
    hash_ent = (global_vc_info *)g_malloc(sizeof(global_vc_info));
    if (!hash_ent) {
      fprintf(stderr, "Could not allocate space for hash structure in dissect_x25\n");
      exit(1);
    }
    hash_ent->vc_num = vc;
    hash_ent->next=0;
    hash_ent->info = (vc_info *)g_malloc(sizeof(vc_info));
    if (!hash_ent->info) {
      fprintf(stderr, "Could not allocate space for hash structure in dissect_x25\n");
      exit(1);
    }
    hash_ent->info->first_frame_secs = frame_secs;
    hash_ent->info->first_frame_usecs = frame_usecs;
    hash_ent->info->last_frame_secs = 0;
    hash_ent->info->last_frame_usecs = 0;
    hash_ent->info->dissect = dissect;
    hash_ent->info->next = 0;
    hash_table[idx] = hash_ent;
  }
  else
  {
    hash_ent2 = hash_ent = hash_table[idx];
    /* search an entry with the same VC number */
    while (hash_ent != NULL && hash_ent->vc_num != vc) {
      hash_ent2 = hash_ent;
      hash_ent = hash_ent->next;
    }
    if (hash_ent != NULL) /* hash_ent->vc_num == vc */
    {
      vc_info *vci = hash_ent->info;
      while (vci->next) vci = vci->next; /* last element */
      if (vci->dissect == dissect) {
	vci->last_frame_secs = 0;
	vci->last_frame_usecs = 0;
      }
      else {
        vci->next = (vc_info *)g_malloc(sizeof(vc_info));
	if (vci->next == 0) {
	  fprintf(stderr, "Could not allocate space for hash structure in dissect_x25\n");
	  exit(1);
	}
	vci->next->first_frame_secs = frame_secs;
	vci->next->first_frame_usecs = frame_usecs;
	vci->next->last_frame_secs = 0;
	vci->next->last_frame_usecs = 0;
	vci->next->dissect = dissect;
	vci->next->next = 0;
      }
    }
    else /* new vc number */
    {
      hash_ent2->next = (global_vc_info *)g_malloc(sizeof(global_vc_info));
      if (!hash_ent2->next) {
        fprintf(stderr, "Could not allocate space for hash structure in dissect_x25\n");
        exit(1);
      }
      hash_ent2->next->info = (vc_info *)g_malloc(sizeof(vc_info));
      if (!hash_ent2->next->info) {
        fprintf(stderr, "Could not allocate space for hash structure in dissect_x25\n");
        exit(1);
      }
      hash_ent2->next->info->first_frame_secs = frame_secs;
      hash_ent2->next->info->first_frame_usecs = frame_usecs;
      hash_ent2->next->info->last_frame_secs = 0;
      hash_ent2->next->info->last_frame_usecs = 0;
      hash_ent2->next->info->dissect = dissect;
      hash_ent2->next->info->next = 0;
    }
  }
}

void
x25_hash_add_proto_end(guint16 vc, guint32 frame_secs, guint32 frame_usecs)
{
  global_vc_info *hash_ent = hash_table[vc%64];
  vc_info *vci;

  if (!hash_ent) return;
  while(hash_ent->vc_num != vc) hash_ent = hash_ent->next;
  if (!hash_ent) return;

  vci = hash_ent->info;
  while (vci->next) vci = vci->next;
  vci->last_frame_secs = frame_secs;
  vci->last_frame_usecs = frame_usecs;
}

void (*x25_hash_get_dissect(guint32 frame_secs, guint32 frame_usecs, guint16 vc))(const u_char *, int, frame_data *, proto_tree *)
{
  global_vc_info *hash_ent = hash_table[vc%64];
  vc_info *vci;
  vc_info *vci2;

  if (!hash_ent) return 0;

  while(hash_ent && hash_ent->vc_num != vc) hash_ent = hash_ent->next;
  if (!hash_ent) return 0;

  /* a hash_ent was found for this VC number */
  vci2 = vci = hash_ent->info;

  /* looking for an entry matching our frame time */
  while (vci && (vci->last_frame_secs < frame_secs ||
		 (vci->last_frame_secs == frame_secs &&
		  vci->last_frame_usecs < frame_usecs))) {
    vci2 = vci;
    vci = vci->next;
  }
  /* we reached last record, and previous record has a non zero
   * last frame time ==> no dissector */
  if (!vci && (vci2->last_frame_secs || vci2->last_frame_usecs)) return 0;

  /* we reached last record, and previous record has a zero last frame time
   * ==> dissector for previous frame has not been "stopped" by a Clear, etc */
  if (!vci) {
    /* if the start time for vci2 is greater than our frame time
     * ==> no dissector */
    if (frame_secs < vci2->first_frame_secs ||
        (frame_secs == vci2->first_frame_secs &&
         frame_usecs < vci2->first_frame_usecs))
      return 0;
    else
      return vci2->dissect;
  }

  /* our frame time is before vci's end. Check if it is adter vci's start */
  if (frame_secs < vci->first_frame_secs ||
      (frame_secs == vci->first_frame_secs &&
       frame_usecs < vci->first_frame_usecs))
    return 0;
  else
    return vci->dissect;
}

static char *clear_code(unsigned char code)
{
    static char buffer[25];

    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x01)
	return "Number Busy";
    if (code == 0x09)
	return "Out Of Order";
    if (code == 0x11)
	return "Remote Procedure Error";
    if (code == 0x19)
	return "Reverse Charging Acceptance Not Subscribed";
    if (code == 0x21)
	return "Incompatible Destination";
    if (code == 0x29)
	return "Fast Select Acceptance Not Subscribed";
    if (code == 0x39)
	return "Destination Absent";
    if (code == 0x03)
	return "Invalid Facility Requested";
    if (code == 0x0B)
	return "Access Barred";
    if (code == 0x13)
	return "Local Procedure Error";
    if (code == 0x05)
	return "Network Congestion";
    if (code == 0x0D)
	return "Not Obtainable";
    if (code == 0x15)
	return "RPOA Out Of Order";

    sprintf(buffer, "Unknown %02X", code);

    return buffer;
}

static char *clear_diag(unsigned char code)
{
    static char buffer[25];

    if (code == 0)
	return "No additional information";
    if (code == 1)
	return "Invalid P(S)";
    if (code == 2)
	return "Invalid P(R)";
    if (code == 16)
	return "Packet type invalid";
    if (code == 17)
	return "Packet type invalid for state r1";
    if (code == 18)
	return "Packet type invalid for state r2";
    if (code == 19)
	return "Packet type invalid for state r3";
    if (code == 20)
	return "Packet type invalid for state p1";
    if (code == 21)
	return "Packet type invalid for state p2";
    if (code == 22)
	return "Packet type invalid for state p3";
    if (code == 23)
	return "Packet type invalid for state p4";
    if (code == 24)
	return "Packet type invalid for state p5";
    if (code == 25)
	return "Packet type invalid for state p6";
    if (code == 26)
	return "Packet type invalid for state p7";
    if (code == 27)
	return "Packet type invalid for state d1";
    if (code == 28)
	return "Packet type invalid for state d2";
    if (code == 29)
	return "Packet type invalid for state d3";
    if (code == 32)
	return "Packet not allowed";
    if (code == 33)
	return "Unidentifiable packet";
    if (code == 34)
	return "Call on one-way logical channel";
    if (code == 35)
	return "Invalid packet type on a PVC";
    if (code == 36)
	return "Packet on unassigned LC";
    if (code == 37)
	return "Reject not subscribed to";
    if (code == 38)
	return "Packet too short";
    if (code == 39)
	return "Packet too long";
    if (code == 40)
	return "Invalid general format identifier";
    if (code == 41)
	return "Restart/registration packet with nonzero bits";
    if (code == 42)
	return "Packet type not compatible with facility";
    if (code == 43)
	return "Unauthorised interrupt confirmation";
    if (code == 44)
	return "Unauthorised interrupt";
    if (code == 45)
	return "Unauthorised reject";
    if (code == 48)
	return "Time expired";
    if (code == 49)
	return "Time expired for incoming call";
    if (code == 50)
	return "Time expired for clear indication";
    if (code == 51)
	return "Time expired for reset indication";
    if (code == 52)
	return "Time expired for restart indication";
    if (code == 53)
	return "Time expired for call deflection";
    if (code == 64)
	return "Call set-up/clearing or registration pb.";
    if (code == 65)
	return "Facility/registration code not allowed";
    if (code == 66)
	return "Facility parameter not allowed";
    if (code == 67)
	return "Invalid called DTE address";
    if (code == 68)
	return "Invalid calling DTE address";
    if (code == 69)
	return "Invalid facility/registration length";
    if (code == 70)
	return "Incoming call barred";
    if (code == 71)
	return "No logical channel available";
    if (code == 72)
	return "Call collision";
    if (code == 73)
	return "Duplicate facility requested";
    if (code == 74)
	return "Non zero address length";
    if (code == 75)
	return "Non zero facility length";
    if (code == 76)
	return "Facility not provided when expected";
    if (code == 77)
	return "Invalid CCITT-specified DTE facility";
    if (code == 78)
	return "Max. nb of call redir/defl. exceeded";
    if (code == 80)
	return "Miscellaneous";
    if (code == 81)
	return "Improper cause code from DTE";
    if (code == 82)
	return "Not aligned octet";
    if (code == 83)
	return "Inconsistent Q bit setting";
    if (code == 84)
	return "NUI problem";
    if (code == 112)
	return "International problem";
    if (code == 113)
	return "Remote network problem";
    if (code == 114)
	return "International protocol problem";
    if (code == 115)
	return "International link out of order";
    if (code == 116)
	return "International link busy";
    if (code == 117)
	return "Transit network facility problem";
    if (code == 118)
	return "Remote network facility problem";
    if (code == 119)
	return "International routing problem";
    if (code == 120)
	return "Temporary routing problem";
    if (code == 121)
	return "Unknown called DNIC";
    if (code == 122)
	return "Maintenance action";

    sprintf(buffer, "Unknown %d", code);

    return buffer;
}

static char *reset_code(unsigned char code)
{
    static char buffer[25];

    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x01)
	return "Out of order";
    if (code == 0x03)
	return "Remote Procedure Error";
    if (code == 0x05)
	return "Local Procedure Error";
    if (code == 0x07)
	return "Network Congestion";
    if (code == 0x09)
	return "Remote DTE operational";
    if (code == 0x0F)
	return "Network operational";
    if (code == 0x11)
	return "Incompatible Destination";
    if (code == 0x1D)
	return "Network out of order";

    sprintf(buffer, "Unknown %02X", code);

    return buffer;
}

static char *restart_code(unsigned char code)
{
    static char buffer[25];

    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x01)
	return "Local Procedure Error";
    if (code == 0x03)
	return "Network Congestion";
    if (code == 0x07)
	return "Network Operational";
    if (code == 0x7F)
	return "Registration/cancellation confirmed";

    sprintf(buffer, "Unknown %02X", code);

    return buffer;
}

static char *registration_code(unsigned char code)
{
    static char buffer[25];

    if (code == 0x03)
	return "Invalid facility request";
    if (code == 0x05)
	return "Network congestion";
    if (code == 0x13)
	return "Local procedure error";
    if (code == 0x7F)
	return "Registration/cancellation confirmed";

    sprintf(buffer, "Unknown %02X", code);

    return buffer;
}

void
dump_facilities(proto_tree *tree, int *offset, const guint8 *p)
{
    const guint8 *ptr = p;
    guint32 len;      /* facilities length */
    proto_item *ti=0;
    proto_tree *fac_tree = 0;
    proto_tree *fac_subtree;

    len = *ptr++;
    if (len && tree) {
	ti = proto_tree_add_text(tree, *offset, len + 1,
		                 "Facilities");
	fac_tree = proto_item_add_subtree(ti, ett_x25_fac);
	proto_tree_add_text(fac_tree, *offset, 1,
			    "Facilities length: %d", len);
    }
    (*offset)++;

    while (len > 0) {
	switch(*ptr & X25_FAC_CLASS_MASK) {
	case X25_FAC_CLASS_A:
	    switch (*ptr) {
	    case X25_FAC_COMP_MARK:
		if (fac_tree)
		    ti = proto_tree_add_text(fac_tree, *offset, 1,
			    "Code : 00 (Marker)");
		switch (ptr[1]) {
		case 0x00:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, *offset+1, 1,
					    "Parameter : 00 (Network complementary "
					    "services - calling DTE)");
		    }
		    break;
		case 0xFF:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, *offset+1, 1,
					    "Parameter : FF (Network complementary "
					    "services - called DTE)");
		    }
		    break;
		case 0x0F:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, *offset+1, 1,
					    "Parameter : 0F (DTE complementary "
					    "services)");
		    }
		    break;
		default:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, *offset+1, 1,
					    "Parameter : %02X (Unknown marker)",
					    ptr[1]);
		    }
		    break;
		}
		break;
	    case X25_FAC_REVERSE:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Reverse charging / Fast select)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_reverse);
		    proto_tree_add_text(fac_subtree, *offset+1, 1, "Parameter : %02X",
			    ptr[1]);
		    if (ptr[1] & 0xC0)
			proto_tree_add_text(fac_subtree, *offset+1, 1,
				"11.. .... = Fast select with restriction");
		    else if (ptr[1] & 0x80)
			proto_tree_add_text(fac_subtree, *offset+1, 1,
				"10.. .... = Fast select - no restriction");
		    else
			proto_tree_add_text(fac_subtree, *offset+1, 1,
				"00.. .... = Fast select not requested");
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    decode_boolean_bitfield(ptr[1], 0x01, 1*8,
				"Reverse charging requested",
				"Reverse charging not requested"));
		}
		break;
	    case X25_FAC_THROUGHPUT:
		if (fac_tree) {
		    char tmpbuf[80];

		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Throughput class negociation)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_throughput);
		    switch (ptr[1] >> 4)
		    {
		    case 3:
		    case 4:
		    case 5:
		    case 6:
		    case 7:
		    case 8:
		    case 9:
		    case 10:
		    case 11:
			sprintf(tmpbuf, "From the called DTE : %%u (%d bps)",
				75*(1<<((ptr[1] >> 4)-3)));
			break;
		    case 12:
			sprintf(tmpbuf, "From the called DTE : %%u (48000 bps)");
			break;
		    case 13:
			sprintf(tmpbuf, "From the called DTE : %%u (64000 bps)");
			break;
		    default:
			sprintf(tmpbuf, "From the called DTE : %%u (Reserved)");
		    }
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    decode_numeric_bitfield(ptr[1], 0xF0, 1*8, tmpbuf));
		    switch (ptr[1] & 0x0F)
		    {
		    case 3:
		    case 4:
		    case 5:
		    case 6:
		    case 7:
		    case 8:
		    case 9:
		    case 10:
		    case 11:
			sprintf(tmpbuf, "From the calling DTE : %%u (%d bps)",
				75*(1<<((ptr[1] & 0x0F)-3)));
			break;
		    case 12:
			sprintf(tmpbuf, "From the calling DTE : %%u (48000 bps)");
			break;
		    case 13:
			sprintf(tmpbuf, "From the calling DTE : %%u (64000 bps)");
			break;
		    default:
			sprintf(tmpbuf, "From the calling DTE : %%u (Reserved)");
		    }
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    decode_numeric_bitfield(ptr[1], 0x0F, 1*8, tmpbuf));
		}
		break;
	    case X25_FAC_CUG:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Closed user group selection)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_cug);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Closed user group: %02X", ptr[1]);
		}
		break;
	    case X25_FAC_CALLED_MODIF:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Called address modified)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_called_modif);
		    proto_tree_add_text(fac_tree, *offset, 2,
			    "Parameter %02X", ptr[1]);
		}
		break;
	    case X25_FAC_CUG_OUTGOING_ACC:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Closed user group with outgoing access selection)",
			    *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_cug_outgoing_acc);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Closed user group: %02X", ptr[1]);
		}
		break;
	    case X25_FAC_THROUGHPUT_MIN:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Minimum throughput class)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_throughput_min);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Parameter %02X", ptr[1]);
		}
		break;
	    case X25_FAC_EXPRESS_DATA:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Negociation of express data)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_express_data);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Parameter %02X", ptr[1]);
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1,
			    "Code : %02X (Unknown class A)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Parameter %02X", ptr[1]);
		}
		break;
	    }
	    (*offset) += 2;
	    len -= 2;
	    ptr += 2;
	    break;
	case X25_FAC_CLASS_B:
	    switch (*ptr) {
	    case X25_FAC_BILATERAL_CUG:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Bilateral closed user group selection)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_bilateral_cug);
		    proto_tree_add_text(fac_subtree, *offset+1, 2,
					"Bilateral CUG: %02X%02X",
					ptr[1], ptr[2]);
		}
		break;
	    case X25_FAC_PACKET_SIZE:
		if (fac_tree)
		{
		    char tmpbuf[80];

		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Packet size)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_packet_size);
		    switch (ptr[1])
		    {
		    case 0x04:
			sprintf(tmpbuf, "From the called DTE : %%u (16)");
			break;
		    case 0x05:
			sprintf(tmpbuf, "From the called DTE : %%u (32)");
			break;
		    case 0x06:
			sprintf(tmpbuf, "From the called DTE : %%u (64)");
			break;
		    case 0x07:
			sprintf(tmpbuf, "From the called DTE : %%u (128)");
			break;
		    case 0x08:
			sprintf(tmpbuf, "From the called DTE : %%u (256)");
			break;
		    case 0x0D:
			sprintf(tmpbuf, "From the called DTE : %%u (512)");
			break;
		    case 0x0C:
			sprintf(tmpbuf, "From the called DTE : %%u (1024)");
			break;
		    case 0x0E:
			sprintf(tmpbuf, "From the called DTE : %%u (2048)");
			break;
		    case 0x0F:
			sprintf(tmpbuf, "From the called DTE : %%u (4096)");
			break;
		    default:
			sprintf(tmpbuf, "From the called DTE : %%u (Unknown)");
			break;
		    }
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    decode_numeric_bitfield(ptr[1], 0x0F, 1*8, tmpbuf));

		    switch (ptr[2])
		    {
		    case 0x04:
			sprintf(tmpbuf, "From the calling DTE : %%u (16)");
			break;
		    case 0x05:
			sprintf(tmpbuf, "From the calling DTE : %%u (32)");
			break;
		    case 0x06:
			sprintf(tmpbuf, "From the calling DTE : %%u (64)");
			break;
		    case 0x07:
			sprintf(tmpbuf, "From the calling DTE : %%u (128)");
			break;
		    case 0x08:
			sprintf(tmpbuf, "From the calling DTE : %%u (256)");
			break;
		    case 0x0D:
			sprintf(tmpbuf, "From the calling DTE : %%u (512)");
			break;
		    case 0x0C:
			sprintf(tmpbuf, "From the calling DTE : %%u (1024)");
			break;
		    case 0x0E:
			sprintf(tmpbuf, "From the calling DTE : %%u (2048)");
			break;
		    case 0x0F:
			sprintf(tmpbuf, "From the calling DTE : %%u (4096)");
			break;
		    default:
			sprintf(tmpbuf, "From the calling DTE : %%u (Unknown)");
			break;
		    }
		    proto_tree_add_text(fac_subtree, *offset+2, 1,
			    decode_numeric_bitfield(ptr[2], 0x0F, 1*8, tmpbuf));
		}
		break;
	    case X25_FAC_WINDOW_SIZE:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Window size)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_window_size);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    decode_numeric_bitfield(ptr[1], 0x7F, 1*8,
			    "From the called DTE: %u"));
		    proto_tree_add_text(fac_subtree, *offset+2, 1,
			    decode_numeric_bitfield(ptr[2], 0x7F, 1*8,
			    "From the calling DTE: %u"));
		}
		break;
	    case X25_FAC_RPOA_SELECTION:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(RPOA selection)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_rpoa_selection);
		    proto_tree_add_text(fac_subtree, *offset+1, 2,
					"Data network identification code : %02X%02X",
					ptr[1], ptr[2]);
		}
		break;
	    case X25_FAC_TRANSIT_DELAY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Transit delay selection and indication)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_transit_delay);
		    proto_tree_add_text(fac_subtree, *offset+1, 2,
					"Transit delay: %d ms",
					(ptr[1]<<8) + ptr[2]);
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1,
			    "Code : %02X (Unknown class B)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, *offset+1, 2,
			    "Parameter %02X%02X", ptr[1], ptr[2]);
		}
		break;
	    }
	    (*offset) += 3;
	    len -= 3;
	    ptr += 3;
	    break;
	case X25_FAC_CLASS_C:
	    if (fac_tree) {
		ti = proto_tree_add_text(fac_tree, *offset, 1,
			"Code : %02X (Unknown class C)", *ptr);
		fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		proto_tree_add_text(fac_subtree, *offset+1, 3,
			"Parameter %02X%02X%02X",
			ptr[1], ptr[2], ptr[3]);
	    }
	    (*offset) += 4;
	    len -= 4;
	    ptr += 4;
	    break;
	case X25_FAC_CLASS_D:
	    switch (*ptr) {
	    case X25_FAC_CALL_TRANSFER:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Call redirection or deflection notification)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_call_transfer);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    if ((ptr[2] & 0xC0) == 0xC0) {
			proto_tree_add_text(fac_subtree, *offset+2, 1,
				"Reason : call deflection by the originally "
				"called DTE address");
		    }
		    else {
			switch (ptr[2]) {
			case 0x01:
			    proto_tree_add_text(fac_subtree, *offset+2, 1,
				    "Reason : originally called DTE busy");
			    break;
			case 0x07:
			    proto_tree_add_text(fac_subtree, *offset+2, 1,
				    "Reason : call dist. within a hunt group");
			    break;
			case 0x09:
			    proto_tree_add_text(fac_subtree, *offset+2, 1,
				    "Reason : originally called DTE out of order");
			    break;
			case 0x0F:
			    proto_tree_add_text(fac_subtree, *offset+2, 1,
				    "Reason : systematic call redirection");
			    break;
			default:
			    proto_tree_add_text(fac_subtree, *offset+2, 1,
				    "Reason : unknown");
			    break;
			}
		    }
		    proto_tree_add_text(fac_subtree, *offset+3, 1,
			    "Number of semi-octets in DTE address : %u", ptr[3]);
		    for (i = 0; i < ptr[3]; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((ptr[4+i/2] >> 4) & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (ptr[4+i/2] & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, *offset+4, ptr[1] - 2,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_CALLING_ADDR_EXT:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Calling address extension)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_calling_addr_ext);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    proto_tree_add_text(fac_subtree, *offset+2, 1,
			    "Number of semi-octets in DTE address : %u", ptr[2]);
		    for (i = 0; i < ptr[2]; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((ptr[3+i/2] >> 4) & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (ptr[3+i/2] & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, *offset+3, ptr[1] - 1,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_CALLED_ADDR_EXT:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Called address extension)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_called_addr_ext);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    proto_tree_add_text(fac_subtree, *offset+2, 1,
			    "Number of semi-octets in DTE address : %u", ptr[2]);
		    for (i = 0; i < ptr[2]; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((ptr[3+i/2] >> 4) & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (ptr[3+i/2] & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, *offset+3, ptr[1] - 1,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_ETE_TRANSIT_DELAY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(End to end transit delay)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_ete_transit_delay);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    proto_tree_add_text(fac_subtree, *offset+2, ptr[1], "Value");
		}
		break;
	    case X25_FAC_CALL_DEFLECT:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, *offset, 1, "Code : %02X "
			    "(Call deflection selection)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_call_deflect);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    if ((ptr[2] & 0xC0) == 0xC0)
			proto_tree_add_text(fac_subtree, *offset+2, 1,
				"Reason : call DTE originated");
		    else
			proto_tree_add_text(fac_subtree, *offset+2, 1,
				"Reason : unknown");
		    proto_tree_add_text(fac_subtree, *offset+3, 1,
			    "Number of semi-octets in the alternative DTE address : %u",
			    ptr[3]);
		    for (i = 0; i < ptr[3]; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((ptr[4+i/2] >> 4) & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (ptr[4+i/2] & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, *offset+4, ptr[1] - 2,
			    "Alternative DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_PRIORITY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1,
			    "Code : %02X (Priority)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_priority);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    proto_tree_add_text(fac_subtree, *offset+2, ptr[1], "Value");
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, *offset, 1,
			    "Code : %02X (Unknown class D)", *ptr);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, *offset+1, 1,
			    "Length : %u", ptr[1]);
		    proto_tree_add_text(fac_subtree, *offset+2, ptr[1], "Value");
		}
	    }
	    (*offset) += ptr[1]+2;
	    len -= ptr[1]+2;
	    ptr += ptr[1]+2;
	    break;
	}
    }
}

void
x25_ntoa(proto_tree *tree, int *offset, const guint8 *p,
	 frame_data *fd, gboolean toa)
{
    int len1, len2;
    int i;
    char addr1[16], addr2[16];
    char *first, *second;

    len1  = (*p >> 4) & 0x0F;
    len2 = (*p >> 0) & 0x0F;
    if (tree) {
	proto_tree_add_text(tree, *offset, 1,
		decode_numeric_bitfield(*p, 0xF0, 1*8,
		    toa ? "Called address length : %u" :
		          "Calling address length : %u"));
	proto_tree_add_text(tree, *offset, 1,
		decode_numeric_bitfield(*p, 0x0F, 1*8,
		    toa ? "Calling address length : %u" :
		          "Called address length : %u"));
    }
    (*offset)++;

    p++;

    first=addr1;
    second=addr2;
    for (i = 0; i < (len1 + len2); i++) {
	if (i < len1) {
	    if (i % 2 != 0) {
		*first++ = ((*p >> 0) & 0x0F) + '0';
		p++;
	    } else {
		*first++ = ((*p >> 4) & 0x0F) + '0';
	    }
	} else {
	    if (i % 2 != 0) {
		*second++ = ((*p >> 0) & 0x0F) + '0';
		p++;
	    } else {
		*second++ = ((*p >> 4) & 0x0F) + '0';
	    }
	}
    }

    *first  = '\0';
    *second = '\0';

    if (len1) {
	if (toa) {
	    if (check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, addr1);
	}
	else {
	    if(check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, addr1);
	}
	if (tree)
	    proto_tree_add_text(tree, *offset,
				(len1 + 1) / 2,
				"%s address : %s",
				toa ? "Called" : "Calling",
				addr1);
    }
    if (len2) {
	if (toa) {
	    if (check_col(fd, COL_RES_DL_SRC))
		col_add_str(fd, COL_RES_DL_SRC, addr2);
	}
	else {
	    if(check_col(fd, COL_RES_DL_DST))
		col_add_str(fd, COL_RES_DL_DST, addr2);
	}
	if (tree)
	    proto_tree_add_text(tree, *offset + len1/2,
				(len2+1)/2+(len1%2+(len2+1)%2)/2,
				"%s address : %s",
				toa ? "Calling" : "Called",
				addr2);
    }
    (*offset) += ((len1 + len2 + 1) / 2);
}

int
get_x25_pkt_len(const char *data, frame_data *fd, int offset)
{
    int length, called_len, calling_len, dte_len, dce_len;

    /* packet size should always be > 3 */
    if (!BYTES_ARE_IN_FRAME(offset, 3)) return END_OF_FRAME;

    switch ((guint8)data[2])
    {
    case X25_CALL_REQUEST:
	if (BYTES_ARE_IN_FRAME(offset, 4)) /* pkt size >= 4 */
	{
	    called_len  = (data[3] >> 0) & 0x0F;
	    calling_len = (data[3] >> 4) & 0x0F;
	    length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	    if (length+offset < pi.captured_len)
		length += (1 + data[length]); /* facilities */
	}
	else length = END_OF_FRAME;
	return MIN(END_OF_FRAME,length);

    case X25_CALL_ACCEPTED:
	if (BYTES_ARE_IN_FRAME(offset, 4)) /* pkt size >= 4 */
	{
	    called_len  = (data[3] >> 0) & 0x0F;
	    calling_len = (data[3] >> 4) & 0x0F;
	    length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	    if (length+offset < pi.captured_len)
		length += (1 + data[length]); /* facilities */
	}
	else length = END_OF_FRAME;
	return MIN(END_OF_FRAME,length);

    case X25_CLEAR_REQUEST:
    case X25_RESET_REQUEST:
    case X25_RESTART_REQUEST:
	return MIN(END_OF_FRAME,5);

    case X25_DIAGNOSTIC:
	return MIN(END_OF_FRAME,4);

    case X25_CLEAR_CONFIRMATION:
    case X25_INTERRUPT:
    case X25_INTERRUPT_CONFIRMATION:
    case X25_RESET_CONFIRMATION:
    case X25_RESTART_CONFIRMATION:
	return MIN(END_OF_FRAME,3);

    case X25_REGISTRATION_REQUEST:
	if (BYTES_ARE_IN_FRAME(offset, 4)) /* pkt size >= 4 */
	{
	    dce_len  = (data[3] >> 0) & 0x0F;
	    dte_len = (data[3] >> 4) & 0x0F;
	    length = 4 + (dte_len + dce_len + 1) / 2; /* addr */
	    if (length+offset < pi.captured_len)
		length += (1 + data[length]); /* registration */
	}
	else length = END_OF_FRAME;
	return MIN(END_OF_FRAME,length);

    case X25_REGISTRATION_CONFIRMATION:
	if (BYTES_ARE_IN_FRAME(offset, 6)) /* pkt size >= 6 */
	{
	    dce_len  = (data[5] >> 0) & 0x0F;
	    dte_len = (data[5] >> 4) & 0x0F;
	    length = 6 + (dte_len + dce_len + 1) / 2; /* addr */
	    if (length+offset < pi.captured_len)
		length += (1 + data[length]); /* registration */
	}
	else length = END_OF_FRAME;
	return MIN(END_OF_FRAME,length);
    }
	    
    if ((data[2] & 0x01) == X25_DATA) return MIN(END_OF_FRAME,3);

    switch (data[2] & 0x1F)
    {
    case X25_RR:
	return MIN(END_OF_FRAME,3);

    case X25_RNR:
	return MIN(END_OF_FRAME,3);

    case X25_REJ:
	return MIN(END_OF_FRAME,3);
    }

    return 0;
}

#define	PRT_ID_ISO_8073	0x01

static const value_string prt_id_vals[] = {
        {PRT_ID_ISO_8073, "ISO 8073 COTP"},
        {0x02,            "ISO 8602"},
        {0x03,            "ISO 10732 in conjunction with ISO 8073"},
        {0x04,            "ISO 10736 in conjunction with ISO 8602"},
        {0x00,            NULL}
};

static const value_string sharing_strategy_vals[] = {
        {0x00,            "No sharing"},
        {0x00,            NULL}
};

void
dissect_x25(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *x25_tree=0, *ti;
    int localoffset=offset;
    int x25_pkt_len;
    int modulo;
    guint16 vc;
    void (*dissect)(const u_char *, int, frame_data *, proto_tree *);
    gboolean toa;         /* TOA/NPI address format */

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "X.25");

    modulo = ((pd[localoffset] & 0x20) ? 128 : 8);

    if (pd[localoffset] & 0x80) toa = TRUE;
    else toa = FALSE;

    x25_pkt_len = get_x25_pkt_len(&pd[localoffset], fd, offset);
    if (x25_pkt_len < 3) /* packet too short */
    {
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Invalid/short X.25 packet");
	if (tree)
	    proto_tree_add_protocol_format(tree, (modulo == 8 ? proto_x25 : proto_ex25),
			    localoffset, END_OF_FRAME,
			    "Invalid/short X.25 packet");
	return;
    }
    vc = (int)(pd[localoffset] & 0x0F)*256 + (int)pd[localoffset+1];
    if (tree) {
	ti = proto_tree_add_item(tree, (modulo == 8) ? proto_x25 : proto_ex25,
		localoffset, x25_pkt_len, NULL);
	x25_tree = proto_item_add_subtree(ti, ett_x25);
	if (pd[localoffset] & 0x80)
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_qbit : hf_ex25_qbit,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	if (pd[localoffset] & 0x40)
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_dbit : hf_ex25_dbit,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_mod : hf_ex25_mod,
		localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
    }
    switch (pd[localoffset+2]) {
    case X25_CALL_REQUEST:
	if (check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "%s VC:%d",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Inc. call"
		                                             : "Call req." ,
                    vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_uint_format(x25_tree,
		    (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_CALL_REQUEST,
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Incoming call"
			                                     : "Call request");
	}
	localoffset += 3;
	if (localoffset < x25_pkt_len+offset) /* calling/called addresses */
	    x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd, toa);

	if (localoffset < x25_pkt_len+offset) /* facilities */
	    dump_facilities(x25_tree, &localoffset, &pd[localoffset]);

	if (IS_DATA_IN_FRAME(localoffset)) /* user data */
	{
	    guint8 spi;
	    guint8 prt_id;

	    /* Compare the first octet of the CALL REQUEST packet with
	       various ISO 9577 NLPIDs, as per Annex A of ISO 9577. */
	    spi = pd[localoffset];
	    switch (spi) {

	    /* XXX - handle other NLPIDs, e.g. PPP? */

	    case NLPID_IP:
		x25_hash_add_proto_start(vc, fd->abs_secs,
					 fd->abs_usecs, dissect_ip);
		if (x25_tree)
		    proto_tree_add_text(x25_tree, localoffset, 1,
					"X.224 secondary protocol ID: IP");
		localoffset++;
		break;

	    default:
		if ((pd[localoffset] >= 0x03 && pd[localoffset] <= 0x82)
		    && pd[localoffset+1] == 0x01) {
		    /* ISO 9577 claims that a SPI in that range is a
		       length field for X.224/ISO 8073 or X.264/ISO 11570;
		       however, some of them collide with NLPIDs such
		       as 0x81 for ISO 8473 CLNP or ISO 8542 ESIS, so
		       I don't know how you run those over X.25, assuming
		       you do.

		       I'm also not sure what the "or" means there; it
		       looks as if X.264 specifies the layout of a
		       "UN TPDU" ("Use of network connection TPDU"),
		       which specifies the transport protocol to use
		       over this network connection, and 0x03 0x01 0x01
		       0x00 is such a TPDU, with a length of 3, a UN
		       field of 1 (as is required), a PRT-ID ("protocol
		       identifier") field of 1 (X.224/ISO 8073, a/k/a
		       COTP service), and a SHARE ("sharing strategy")
		       field of 0 ("no sharing", which is the only one
		       allowed).

		       So we'll assume that's what it is, as the SPI
		       is in the right range for a length, and the UN
		       field is 0x01. */
		    prt_id = pd[localoffset+2];
		    if (x25_tree) {
		        proto_tree_add_text(x25_tree, localoffset, 1,
					"X.264 length indicator: %u",
					pd[localoffset]);
		        proto_tree_add_text(x25_tree, localoffset+1, 1,
		        		"X.264 UN TPDU identifier: 0x%02X",
		        		pd[localoffset+1]);
		        proto_tree_add_text(x25_tree, localoffset+2, 1,
		        		"X.264 protocol identifier: %s",
					val_to_str(prt_id, prt_id_vals, "Unknown (0x%02X)"));
		        proto_tree_add_text(x25_tree, localoffset+3, 1,
		        		"X.264 sharing strategy: %s",
					val_to_str(pd[localoffset+3], sharing_strategy_vals, "Unknown (0x%02X)"));
		    }

		    /* XXX - dissect the variable part? */

		    /* The length doesn't include the length octet itself. */
		    localoffset += pd[localoffset] + 1;

		    switch (prt_id) {

		    case PRT_ID_ISO_8073:
			/* ISO 8073 COTP */
			x25_hash_add_proto_start(vc, fd->abs_secs,
					 fd->abs_usecs, dissect_cotp);
			break;

		    default:
			goto unknown;
		    }
		} else {
		unknown:
		    if (x25_tree) {
			if (IS_DATA_IN_FRAME(localoffset))
			   proto_tree_add_text(x25_tree, localoffset,
					pi.captured_len-localoffset, "Data");
		    }
		    localoffset = pi.captured_len;
		}
	    }
	}
	break;
    case X25_CALL_ACCEPTED:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "%s VC:%d",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Call conn."
			                                     : "Call acc." ,
		    vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_uint_format(x25_tree,
		    (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_CALL_ACCEPTED,
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Call connected"
		                                             : "Call accepted");
	}
	localoffset += 3;
        if (localoffset < x25_pkt_len+offset) /* calling/called addresses */
	    x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd, toa);

	if (localoffset < x25_pkt_len+offset) /* facilities */
	    dump_facilities(x25_tree, &localoffset, &pd[localoffset]);

	if (IS_DATA_IN_FRAME(localoffset)) { /* user data */
	    if (x25_tree)
	        proto_tree_add_text(x25_tree, localoffset,
				    pi.captured_len-localoffset, "Data");
	    localoffset=pi.captured_len;
	}
	break;
    case X25_CLEAR_REQUEST:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "%s VC:%d %s - %s",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Clear ind."
			                                     : "Clear req." ,
		    vc, clear_code(pd[localoffset+3]),
		    clear_diag(pd[localoffset+4]));
	}
	x25_hash_add_proto_end(vc, fd->abs_secs, fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_uint_format(x25_tree,
		    (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_CLEAR_REQUEST,
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Clear indication"
		                                             : "Clear request");
	    if (localoffset+3 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+3, 1,
			"Cause : %s", clear_code(pd[localoffset+3]));
	    if (localoffset+4 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+4, 1,
			"Diagnostic : %s",
			clear_diag(pd[localoffset+4]));
	}
	localoffset += x25_pkt_len;
	break;
    case X25_CLEAR_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Clear Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_CLEAR_CONFIRMATION);
	}
	localoffset += x25_pkt_len;

	if (IS_DATA_IN_FRAME(localoffset)) /* extended clear conf format */
	    x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd, toa);

	if (IS_DATA_IN_FRAME(localoffset)) /* facilities */
	    dump_facilities(x25_tree, &localoffset, &pd[localoffset]);
	break;
    case X25_DIAGNOSTIC:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "Diag. %d", (int)pd[localoffset+3]);
	}
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_DIAGNOSTIC);
	    if (localoffset+3 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+3, 1,
			"Diagnostic : %d", (int)pd[localoffset+3]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_INTERRUPT:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Interrupt VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_INTERRUPT);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_INTERRUPT_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Interrupt Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_INTERRUPT_CONFIRMATION);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_RESET_REQUEST:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "%s VC:%d %s - Diag.:%d",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Reset ind."
		                                             : "Reset req.",
		    vc, reset_code(pd[localoffset+3]),
		    (int)pd[localoffset+4]);
	}
	x25_hash_add_proto_end(vc, fd->abs_secs, fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_uint_format(x25_tree,
		    (modulo == 8) ? hf_x25_type : hf_ex25_type, localoffset+2, 1,
		    X25_RESET_REQUEST,
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Reset indication"
                                                             : "Reset request");
	    if (localoffset+3 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+3, 1,
			"Cause : %s", reset_code(pd[localoffset+3]));
	    if (localoffset+4 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+4, 1,
			"Diagnostic : %d", (int)pd[localoffset+4]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_RESET_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Reset conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_RESET_CONFIRMATION);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_RESTART_REQUEST:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "%s %s - Diag.:%d",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Restart ind."
		                                             : "Restart req.",
		    restart_code(pd[localoffset+3]),
		    (int)pd[localoffset+4]);
	}
	if (x25_tree) {
	    proto_tree_add_uint_format(x25_tree,
		    (modulo == 8) ? hf_x25_type : hf_ex25_type, localoffset+2, 1,
		    X25_RESTART_REQUEST,
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Restart indication"
		                                             : "Restart request");
	    if (localoffset+3 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+3, 1,
			"Cause : %s", restart_code(pd[localoffset+3]));
	    if (localoffset+4 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+4, 1,
			"Diagnostic : %d", (int)pd[localoffset+4]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_RESTART_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Restart conf.");
	if (x25_tree)
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_RESTART_CONFIRMATION);
	localoffset += x25_pkt_len;
	break;
    case X25_REGISTRATION_REQUEST:
	if(check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Registration req.");
	if (x25_tree)
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_REGISTRATION_REQUEST);
	localoffset += 3;
	if (localoffset < x25_pkt_len+offset)
	    x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd, FALSE);

	if (x25_tree) {
	    if (localoffset < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset, 1,
			"Registration length: %d", pd[localoffset] & 0x7F);
	    if (localoffset+1 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+1,
			pd[localoffset] & 0x7F, "Registration");
	}
	localoffset = pi.captured_len;
	break;
    case X25_REGISTRATION_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Registration conf.");
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_REGISTRATION_CONFIRMATION);
	    if (localoffset+3 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+3, 1,
			"Cause: %s", registration_code(pd[localoffset+3]));
	    if (localoffset+4 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+4, 1,
			"Diagnostic: %s", registration_code(pd[localoffset+4]));
	}
	localoffset += 5;
	if (localoffset < x25_pkt_len+offset)
	    x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd, TRUE);

	if (x25_tree) {
	    if (localoffset < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset, 1,
			"Registration length: %d", pd[localoffset] & 0x7F);
	    if (localoffset+1 < x25_pkt_len+offset)
		proto_tree_add_text(x25_tree, localoffset+1,
			pd[localoffset] & 0x7F, "Registration");
	}
	localoffset = pi.captured_len;
	break;
    default :
	localoffset += 2;
	if ((pd[localoffset] & 0x01) == X25_DATA)
	{
	    if(check_col(fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(fd, COL_INFO,
			    "Data VC:%d P(S):%d P(R):%d %s", vc,
			    (pd[localoffset] >> 1) & 0x07,
			    (pd[localoffset] >> 5) & 0x07,
			    ((pd[localoffset]>>4) & 0x01) ? " M" : "");
		else
		    col_add_fstr(fd, COL_INFO,
			    "Data VC:%d P(S):%d P(R):%d %s", vc,
			    pd[localoffset+1] >> 1,
			    pd[localoffset] >> 1,
			    (pd[localoffset+1] & 0x01) ? " M" : "");
	    }
	    if (x25_tree) {
		proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
			localoffset-2, 2, pd[localoffset-2]*256+pd[localoffset-1]);
		if (modulo == 8) {
		    proto_tree_add_item_hidden(x25_tree, hf_x25_type, localoffset, 1,
			    X25_DATA);
		    proto_tree_add_item(x25_tree, hf_x25_p_r, localoffset, 1,
			    pd[localoffset]);
		    if (pd[localoffset] & 0x10)
			proto_tree_add_item(x25_tree, hf_x25_mbit, localoffset, 1,
			    pd[localoffset]);
		    proto_tree_add_item(x25_tree, hf_x25_p_s, localoffset, 1,
			    pd[localoffset]);
		    proto_tree_add_text(x25_tree, localoffset, 1,
			    decode_boolean_bitfield(pd[localoffset], 0x01, 1*8,
				NULL, "DATA"));
		}
		else {
		    proto_tree_add_item_hidden(x25_tree, hf_ex25_type, localoffset, 1,
			    X25_DATA);
		    proto_tree_add_item(x25_tree, hf_x25_p_r, localoffset, 1,
			    pd[localoffset]);
		    proto_tree_add_item(x25_tree, hf_x25_p_s, localoffset+1, 1,
			    pd[localoffset+1]);
		    if (pd[localoffset+1] & 0x01)
			proto_tree_add_item(x25_tree, hf_ex25_mbit, localoffset+1, 1,
			    pd[localoffset+1]);
		}
	    }
	    localoffset += (modulo == 8) ? 1 : 2;
	    break;
	}
	switch (pd[localoffset] & 0x1F)
	{
	case X25_RR:
	    if(check_col(fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(fd, COL_INFO, "RR VC:%d P(R):%d",
			    vc, (pd[localoffset] >> 5) & 0x07);
		else
		    col_add_fstr(fd, COL_INFO, "RR VC:%d P(R):%d",
			    vc, pd[localoffset+1] >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
			localoffset-2, 2, pd[localoffset-2]*256+pd[localoffset-1]);
		if (modulo == 8) {
		    proto_tree_add_item(x25_tree, hf_x25_p_r,
			    localoffset, 1, pd[localoffset]);
		    proto_tree_add_item(x25_tree, hf_x25_type, localoffset, 1, X25_RR);
		}
		else {
		    proto_tree_add_item(x25_tree, hf_ex25_type, localoffset, 1, X25_RR);
		    proto_tree_add_item(x25_tree, hf_ex25_p_r,
			    localoffset+1, 1, pd[localoffset+1]);
		}
	    }
	    break;

	case X25_RNR:
	    if(check_col(fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(fd, COL_INFO, "RNR VC:%d P(R):%d",
			    vc, (pd[localoffset] >> 5) & 0x07);
		else
		    col_add_fstr(fd, COL_INFO, "RNR VC:%d P(R):%d",
			    vc, pd[localoffset+1] >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
			localoffset-2, 2, pd[localoffset-2]*256+pd[localoffset-1]);
		if (modulo == 8) {
		    proto_tree_add_item(x25_tree, hf_x25_p_r,
			    localoffset, 1, pd[localoffset]);
		    proto_tree_add_item(x25_tree, hf_x25_type, localoffset, 1, X25_RNR);
		}
		else {
		    proto_tree_add_item(x25_tree, hf_ex25_type, localoffset, 1, X25_RNR);
		    proto_tree_add_item(x25_tree, hf_ex25_p_r,
			    localoffset+1, 1, pd[localoffset+1]);
		}
	    }
	    break;

	case X25_REJ:
	    if(check_col(fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(fd, COL_INFO, "REJ VC:%d P(R):%d",
			    vc, (pd[localoffset] >> 5) & 0x07);
		else
		    col_add_fstr(fd, COL_INFO, "REJ VC:%d P(R):%d",
			    vc, pd[localoffset+1] >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
			localoffset-2, 2, pd[localoffset-2]*256+pd[localoffset-1]);
		if (modulo == 8) {
		    proto_tree_add_item(x25_tree, hf_x25_p_r,
			    localoffset, 1, pd[localoffset]);
		    proto_tree_add_item(x25_tree, hf_x25_type, localoffset, 1, X25_REJ);
		}
		else {
		    proto_tree_add_item(x25_tree, hf_ex25_type, localoffset, 1, X25_REJ);
		    proto_tree_add_item(x25_tree, hf_ex25_p_r,
			    localoffset+1, 1, pd[localoffset+1]);
		}
	    }
	}
	localoffset += (modulo == 8) ? 1 : 2;
    }

    if (!IS_DATA_IN_FRAME(localoffset)) return;

    /* search the dissector in the hash table */
    if ((dissect = x25_hash_get_dissect(fd->abs_secs, fd->abs_usecs, vc)))
      (*dissect)(pd, localoffset, fd, tree);
    else {
      if (pd[localoffset] == 0x45) /* If the Call Req. has not been captured,
				    * assume these packets carry IP */
      {
	  x25_hash_add_proto_start(vc, fd->abs_secs,
				   fd->abs_usecs, dissect_ip);
 	  dissect_ip(pd, localoffset, fd, tree);
      }
      else {
	  dissect_data(pd, localoffset, fd, tree);
      }
    }
}

void
proto_register_x25(void)
{
    static hf_register_info hf8[] = {
	{ &hf_x25_qbit,
	  { "Q Bit", "x25.q", FT_BOOLEAN, 2, NULL, 0x8000,
	  	"Qualifier Bit" } },
	{ &hf_x25_qbit,
	  { "D Bit", "x25.d", FT_BOOLEAN, 2, NULL, 0x4000,
	  	"Delivery Confirmation Bit" } },
	{ &hf_x25_mod,
	  { "Modulo", "x25.mod", FT_UINT16, BASE_DEC, VALS(vals_modulo), 0x3000,
	  	"Specifies whether the frame is modulo 8 or 128" } },
	{ &hf_x25_lcn,
	  { "Logical Channel", "x25.lcn", FT_UINT16, BASE_HEX, NULL, 0x0FFF,
	  	"Logical Channel Number" } },
	{ &hf_x25_type,
	  { "Packet Type", "x25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x0,
	  	"Packet Type" } },
	{ &hf_x25_p_r,
	  { "P(R)", "x25.p_r", FT_UINT8, BASE_HEX, NULL, 0xE0,
	  	"Packet Receive Sequence Number" } },
	{ &hf_x25_mbit,
	  { "M Bit", "x25.m", FT_BOOLEAN, 1, NULL, 0x10,
	  	"More Bit" } },
	{ &hf_x25_p_s,
	  { "P(S)", "x25.p_s", FT_UINT8, BASE_HEX, NULL, 0x0E,
	  	"Packet Send Sequence Number" } },
    };

    static hf_register_info hf128[] = {
	{ &hf_ex25_qbit,
	  { "Q Bit", "ex25.q", FT_BOOLEAN, 2, NULL, 0x8000,
	  	"Qualifier Bit" } },
	{ &hf_ex25_qbit,
	  { "D Bit", "ex25.d", FT_BOOLEAN, 2, NULL, 0x4000,
	  	"Delivery Confirmation Bit" } },
	{ &hf_ex25_mod,
	  { "Modulo", "ex25.mod", FT_UINT16, BASE_DEC, VALS(vals_modulo), 0x3000,
	  	"Specifies whether the frame is modulo 8 or 128" } },
	{ &hf_ex25_lcn,
	  { "Logical Channel", "ex25.lcn", FT_UINT16, BASE_HEX, NULL, 0x0FFF,
	  	"Logical Channel Number" } },
	{ &hf_ex25_type,
	  { "Packet Type", "ex25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x0,
	  	"Packet Type" } },
	{ &hf_ex25_p_r,
	  { "P(R)", "ex25.p_r", FT_UINT8, BASE_HEX, NULL, 0xFE,
	  	"Packet Receive Sequence Number" } },
	{ &hf_ex25_mbit,
	  { "M Bit", "ex25.m", FT_BOOLEAN, 1, NULL, 0x01,
	  	"More Bit" } },
	{ &hf_ex25_p_s,
	  { "P(S)", "ex25.p_s", FT_UINT8, BASE_HEX, NULL, 0xFE,
	  	"Packet Send Sequence Number" } },
    };
    static gint *ett[] = {
        &ett_x25,
	&ett_x25_fac,
	&ett_x25_fac_unknown,
	&ett_x25_fac_mark,
	&ett_x25_fac_reverse,
	&ett_x25_fac_throughput,
	&ett_x25_fac_cug,
	&ett_x25_fac_called_modif,
	&ett_x25_fac_cug_outgoing_acc,
	&ett_x25_fac_throughput_min,
	&ett_x25_fac_express_data,
	&ett_x25_fac_bilateral_cug,
	&ett_x25_fac_packet_size,
	&ett_x25_fac_window_size,
	&ett_x25_fac_rpoa_selection,
	&ett_x25_fac_transit_delay,
	&ett_x25_fac_call_transfer,
	&ett_x25_fac_called_addr_ext,
	&ett_x25_fac_ete_transit_delay,
	&ett_x25_fac_calling_addr_ext,
	&ett_x25_fac_call_deflect,
	&ett_x25_fac_priority
    };

    proto_x25 = proto_register_protocol ("X.25", "x25");
    proto_ex25 = proto_register_protocol ("Extended X.25 (modulo 128)", "ex25");
    proto_register_field_array (proto_x25, hf8, array_length(hf8));
    proto_register_field_array (proto_ex25, hf128, array_length(hf128));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine(&reinit_x25_hashtable);
}
