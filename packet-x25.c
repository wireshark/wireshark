/* packet-x25.c
 * Routines for x25 packet disassembly
 * Olivier Abad <abad@daba.dhis.net>
 *
 * $Id: packet-x25.c,v 1.10 1999/11/29 22:44:48 gram Exp $
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
#define X25_FAC_ADDR_EXT		0xCB
#define X25_FAC_CALL_DEFLECT		0xD1

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

void
init_dissect_x25()
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

    len = *ptr++;
    if (len && tree)
	proto_tree_add_text(tree, *offset, 1,
			    "Facilities length: %d", len);
    (*offset)++;

    while (len > 0) {
	switch(*ptr & X25_FAC_CLASS_MASK) {
	case X25_FAC_CLASS_A:
	    switch (*ptr) {
	    case X25_FAC_COMP_MARK:
		switch (ptr[1]) {
		case 0x00:
		    if (tree)
			proto_tree_add_text(tree, *offset, 2,
					    "Network complementary services - calling DTE");
		    break;
		case 0xFF:
		    if (tree)
			proto_tree_add_text(tree, *offset, 2,
					    "Network complementary services - called DTE");
		    break;
		case 0x0F:
		    if (tree)
			proto_tree_add_text(tree, *offset, 2,
					    "DTE complementary services");
		    break;
		default:
		    if (tree)
			proto_tree_add_text(tree, *offset, 2,
					    "Unknown marker");
		    break;
		}
		break;
	    case X25_FAC_REVERSE:
		if (tree) {
		    if (ptr[1] & 0x01)
			proto_tree_add_text(tree, *offset, 2,
					    "Reverse Charging");
		    else
			proto_tree_add_text(tree, *offset, 2,
					    "No Reverse Charging");
		    if (ptr[1] & 0xC0)
			proto_tree_add_text(tree, *offset, 2,
					    "Fast select with restriction");
		    else if (ptr[1] & 0x80)
			proto_tree_add_text(tree, *offset, 2,
					    "Fast select - no restriction");
		    else
			proto_tree_add_text(tree, *offset, 2,
					    "No Fast select");
		}
		break;
	    case X25_FAC_THROUGHPUT:
		if (tree) {
		    int called_dte_throughput=0;
		    int calling_dte_throughput=0;

		    if ( (ptr[1] >> 4) >= 3 && (ptr[1] >> 4) <= 13 )
			called_dte_throughput = 75*2^((ptr[1] >> 4)-3);
		    if ( (ptr[1] & 0x0F) >= 3 && (ptr[1] & 0x0F) <= 13 )
			calling_dte_throughput = 75*2^((ptr[1] & 0x0F)-3);
		    proto_tree_add_text(tree, *offset, 2,
			    "Throughput: called DTE: %d - calling DTE: %d",
			    called_dte_throughput, calling_dte_throughput);
		}
		break;
	    case X25_FAC_CUG:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Closed user group: %d%d",
					ptr[1] >> 4, ptr[1] & 0x0F);
		break;
	    case X25_FAC_CALLED_MODIF:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Called address modified: %02X",
					ptr[1]);
		break;
	    case X25_FAC_CUG_OUTGOING_ACC:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"CUG with outgoing access: %d%d",
					ptr[1]>>4, ptr[1] & 0x0F);
		break;
	    case X25_FAC_THROUGHPUT_MIN:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Minimum throughput class");
		break;
	    case X25_FAC_EXPRESS_DATA:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Negociation of express data");
		break;
	    default:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Unknown facility %02X, value %02X",
					ptr[0], ptr[1]);
		break;
	    }
	    (*offset) += 2;
	    len -= 2;
	    ptr += 2;
	    break;
	case X25_FAC_CLASS_B:
	    switch (*ptr) {
	    case X25_FAC_BILATERAL_CUG:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
					"Bilateral CUG: %d%d%d%d",
					ptr[1] >> 4,
					ptr[1] & 0x0F,
					ptr[2] >> 4,
					ptr[2] & 0x0F);
		break;
	    case X25_FAC_PACKET_SIZE:
		if (tree)
		{
		    int called_dte_size, calling_dte_size;

		    switch (ptr[1])
		    {
		    case 0x04:
			called_dte_size = 16;
			break;
		    case 0x05:
			called_dte_size = 32;
			break;
		    case 0x06:
			called_dte_size = 64;
			break;
		    case 0x07:
			called_dte_size = 128;
			break;
		    case 0x08:
			called_dte_size = 256;
			break;
		    case 0x0D:
			called_dte_size = 512;
			break;
		    case 0x0C:
			called_dte_size = 1024;
			break;
		    case 0x0E:
			called_dte_size = 2048;
			break;
		    case 0x0F:
			called_dte_size = 4096;
			break;
		    default:
			called_dte_size = 0;
			break;
		    }

		    switch (ptr[2])
		    {
		    case 0x04:
			calling_dte_size = 16;
			break;
		    case 0x05:
			calling_dte_size = 32;
			break;
		    case 0x06:
			calling_dte_size = 64;
			break;
		    case 0x07:
			calling_dte_size = 128;
			break;
		    case 0x08:
			calling_dte_size = 256;
			break;
		    case 0x0D:
			calling_dte_size = 512;
			break;
		    case 0x0C:
			calling_dte_size = 1024;
			break;
		    case 0x0E:
			calling_dte_size = 2048;
			break;
		    case 0x0F:
			calling_dte_size = 4096;
			break;
		    default:
			calling_dte_size = 0;
			break;
		    }
		    proto_tree_add_text(tree, *offset, 3,
			    "Packet Size: called DTE: %d - calling DTE: %d",
			    called_dte_size,
			    calling_dte_size);
		}
		break;
	    case X25_FAC_WINDOW_SIZE:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
			    "Window Size: called DTE: %d - calling DTE: %d",
			    ptr[1], ptr[2]);
		break;
	    case X25_FAC_RPOA_SELECTION:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
					"RPOA: %d%d%d%d",
					ptr[1] >> 4,
					ptr[1] & 0x0F,
					ptr[2] >> 4,
					ptr[2] & 0x0F);
		break;
	    case X25_FAC_TRANSIT_DELAY:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
					"Transit delay: %d",
					(ptr[1]<<8) + ptr[2]);
		break;
	    default:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
					"Unknown facility %02X, values %02X%02X",
					ptr[0], ptr[1], ptr[2]);
		break;
	    }
	    (*offset) += 3;
	    len -= 3;
	    ptr += 3;
	    break;
	case X25_FAC_CLASS_C:
	    if (tree)
		proto_tree_add_text(tree, *offset, 4,
				    "Unknown facility %02X, values %02X%02X%02X",
				    ptr[0], ptr[1], ptr[2], ptr[3]);
	    (*offset) += 4;
	    len -= 4;
	    ptr += 4;
	    break;
	case X25_FAC_CLASS_D:
	    switch (*ptr) {
	    case X25_FAC_CALL_TRANSFER:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2+ptr[1],
					"Call Transfer: reason = %02X",
					ptr[2]);
		break;
	    case X25_FAC_ADDR_EXT:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2+ptr[1],
					"Address extension");
		break;
	    case X25_FAC_CALLED_ADDR_EXT:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2+ptr[1],
					"Called address extension");
		break;
	    case X25_FAC_ETE_TRANSIT_DELAY:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2+ptr[1],
					"End to end transit delay");
		break;
	    case X25_FAC_CALL_DEFLECT:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2+ptr[1],
					"Call deflection: reason = %02X",
					ptr[2]);
		break;
	    default:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2+ptr[1],
					"Unknown facility %02X, length %02X",
					ptr[0], ptr[1]);
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

    len1  = (*p >> 0) & 0x0F;
    len2 = (*p >> 4) & 0x0F;
    if (tree) {
	proto_tree_add_text(tree, *offset, 1,
		"%s address length : %d",
		toa ? "Called" : "Calling",
		len1);
	proto_tree_add_text(tree, *offset, 1,
		"%s address length : %d",
		toa ? "Calling" : "Called",
		len2);
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
	if(check_col(fd, COL_RES_DL_DST))
	    col_add_str(fd, COL_RES_DL_DST, addr1);
	if (tree)
	    proto_tree_add_text(tree, *offset,
				(len1 + 1) / 2,
				"%s address : %s",
				toa ? "Called" : "Calling",
				addr1);
    }
    if (len2) {
	if(check_col(fd, COL_RES_DL_SRC))
	    col_add_str(fd, COL_RES_DL_SRC, addr2);
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
    if (fd->cap_len - offset < 3) return fd->cap_len;

    switch ((guint8)data[2])
    {
    case X25_CALL_REQUEST:
	if (fd->cap_len > offset+3) /* pkt size > 3 */
	{
	    called_len  = (data[3] >> 0) & 0x0F;
	    calling_len = (data[3] >> 4) & 0x0F;
	    length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	    if (length+offset < fd->cap_len)
		length += (1 + data[length]); /* facilities */
	}
	else length = fd->cap_len - offset;
	return MIN(fd->cap_len-offset,length);

    case X25_CALL_ACCEPTED:
	if (fd->cap_len > offset+3) /* pkt size > 3 */
	{
	    called_len  = (data[3] >> 0) & 0x0F;
	    calling_len = (data[3] >> 4) & 0x0F;
	    length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	    if (length+offset < fd->cap_len)
		length += (1 + data[length]); /* facilities */
	}
	else length = fd->cap_len - offset;
	return MIN(fd->cap_len-offset,length);

    case X25_CLEAR_REQUEST:
    case X25_RESET_REQUEST:
    case X25_RESTART_REQUEST:
	return MIN(fd->cap_len-offset,5);

    case X25_DIAGNOSTIC:
	return MIN(fd->cap_len-offset,4);

    case X25_CLEAR_CONFIRMATION:
    case X25_INTERRUPT:
    case X25_INTERRUPT_CONFIRMATION:
    case X25_RESET_CONFIRMATION:
    case X25_RESTART_CONFIRMATION:
	return MIN(fd->cap_len-offset,3);

    case X25_REGISTRATION_REQUEST:
	if (fd->cap_len > offset+3) /* pkt size > 3 */
	{
	    dce_len  = (data[3] >> 0) & 0x0F;
	    dte_len = (data[3] >> 4) & 0x0F;
	    length = 4 + (dte_len + dce_len + 1) / 2; /* addr */
	    if (length+offset < fd->cap_len)
		length += (1 + data[length]); /* registration */
	}
	else length = fd->cap_len-offset;
	return MIN(fd->cap_len-offset,length);

    case X25_REGISTRATION_CONFIRMATION:
	if (fd->cap_len > offset+5) /* pkt size > 5 */
	{
	    dce_len  = (data[5] >> 0) & 0x0F;
	    dte_len = (data[5] >> 4) & 0x0F;
	    length = 6 + (dte_len + dce_len + 1) / 2; /* addr */
	    if (length+offset < fd->cap_len)
		length += (1 + data[length]); /* registration */
	}
	else length = fd->cap_len-offset;
	return MIN(fd->cap_len-offset,length);
    }
	    
    if ((data[2] & 0x01) == X25_DATA) return MIN(fd->cap_len-offset,3);

    switch (data[2] & 0x1F)
    {
    case X25_RR:
	return MIN(fd->cap_len-offset,3);

    case X25_RNR:
	return MIN(fd->cap_len-offset,3);

    case X25_REJ:
	return MIN(fd->cap_len-offset,3);
    }

    return 0;
}

void
dissect_x25(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *x25_tree=0, *ti;
    int localoffset=offset;
    int x25_pkt_len;
    int modulo;
    guint16 vc;
    void (*dissect)(const u_char *, int, frame_data *, proto_tree *);
    gboolean toa=FALSE;

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "X.25");

    modulo = ((pd[localoffset] & 0x20) ? 128 : 8);
    x25_pkt_len = get_x25_pkt_len(&pd[localoffset], fd, offset);
    if (x25_pkt_len < 3) /* packet too short */
    {
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, "Invalid/short X.25 packet");
	if (tree)
	    proto_tree_add_item_format(tree, (modulo == 8 ? proto_x25 : proto_ex25),
			    localoffset, fd->cap_len - offset, NULL,
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
	if (pd[localoffset+2] & 0x80) /* TOA/NPI address format */
	    toa = TRUE;

	if (check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "%s VC:%d",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Inc. call"
		                                             : "Call req." ,
                    vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item_format(x25_tree,
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

	if (localoffset < fd->cap_len) /* user data */
	{
	    if (pd[localoffset] == 0xCC)
	    {
		x25_hash_add_proto_start(vc, fd->abs_secs,
					 fd->abs_usecs, dissect_ip);
		if (x25_tree)
		    proto_tree_add_text(x25_tree, localoffset, 1,
					"pid = IP");
		localoffset++;
	    }
	    else if (pd[localoffset] == 0x03 &&
		     pd[localoffset+1] == 0x01 &&
		     pd[localoffset+2] == 0x01 &&
		     pd[localoffset+3] == 0x00)
	    {
		x25_hash_add_proto_start(vc, fd->abs_secs,
					 fd->abs_usecs, dissect_cotp);
		if (x25_tree)
		    proto_tree_add_text(x25_tree, localoffset, 4,
					"pid = COTP");
		localoffset += 4;
	    }
	    else {
		if (x25_tree)
		    proto_tree_add_text(x25_tree, localoffset,
					fd->cap_len-localoffset, "Data");
		localoffset = fd->cap_len;
	    }
	}
	break;
    case X25_CALL_ACCEPTED:
	if (pd[localoffset+2] & 0x80) /* TOA/NPI address format */
	    toa = TRUE;

	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "%s VC:%d",
		    (fd->pseudo_header.x25.flags & FROM_DCE) ? "Call conn."
			                                     : "Call acc." ,
		    vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item_format(x25_tree,
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

	if (localoffset < fd->cap_len) { /* user data */
	    if (x25_tree)
	        proto_tree_add_text(x25_tree, localoffset,
				    fd->cap_len-localoffset, "Data");
	    localoffset=fd->cap_len;
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
	    proto_tree_add_item_format(x25_tree,
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
	if (pd[localoffset+2] & 0x80) /* TOA/NPI address format */
	    toa = TRUE;

	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Clear Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_lcn : hf_ex25_lcn,
		    localoffset, 2, pd[localoffset]*256+pd[localoffset+1]);
	    proto_tree_add_item(x25_tree, (modulo == 8) ? hf_x25_type : hf_ex25_type,
		    localoffset+2, 1, X25_CLEAR_CONFIRMATION);
	}
	localoffset += x25_pkt_len;

	if (localoffset < fd->cap_len) /* extended clear conf format */
	    x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd, toa);

	if (localoffset < fd->cap_len) /* facilities */
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
	    proto_tree_add_item_format(x25_tree,
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
	    proto_tree_add_item_format(x25_tree,
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
	localoffset = fd->cap_len;
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
	localoffset = fd->cap_len;
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

    if (localoffset >= fd->cap_len) return;

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
    };

    proto_x25 = proto_register_protocol ("X.25", "x25");
    proto_ex25 = proto_register_protocol ("Extended X.25 (modulo 128)", "ex25");
    proto_register_field_array (proto_x25, hf8, array_length(hf8));
    proto_register_field_array (proto_ex25, hf128, array_length(hf128));
    proto_register_subtree_array(ett, array_length(ett));
}
