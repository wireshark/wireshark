/* packet-x25.c
 * Routines for x25 packet disassembly
 * Olivier Abad <oabad@cybercable.fr>
 *
 * $Id: packet-x25.c,v 1.61 2001/12/08 06:41:42 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998
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
#include "llcsaps.h"
#include "packet.h"
#include "prefs.h"
#include "nlpid.h"
#include "x264_prt_id.h"

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
static int hf_x25_gfi = -1;
static int hf_x25_abit = -1;
static int hf_x25_qbit = -1;
static int hf_x25_dbit = -1;
static int hf_x25_mod = -1;
static int hf_x25_lcn = -1;
static int hf_x25_type = -1;
static int hf_x25_p_r_mod8 = -1;
static int hf_x25_p_r_mod128 = -1;
static int hf_x25_mbit_mod8 = -1;
static int hf_x25_mbit_mod128 = -1;
static int hf_x25_p_s_mod8 = -1;
static int hf_x25_p_s_mod128 = -1;

static gint ett_x25 = -1;
static gint ett_x25_gfi = -1;
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
static gint ett_x25_user_data = -1;

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

static dissector_handle_t ip_handle;
static dissector_handle_t ositp_handle;
static dissector_handle_t sna_handle;
static dissector_handle_t qllc_handle;
static dissector_handle_t data_handle;

/* Preferences */
static gboolean non_q_bit_is_sna = FALSE;

static dissector_table_t x25_subdissector_table;
static heur_dissector_list_t x25_heur_subdissector_list;

/*
 * each vc_info node contains :
 *   the time of the first frame using this dissector (secs and usecs)
 *   the time of the last frame using this dissector (0 if it is unknown)
 *   a handle for the dissector
 *
 * the "time of first frame" is initialized when a Call Req. is received
 * the "time of last frame" is initialized when a Clear, Reset, or Restart
 * is received
 */
typedef struct _vc_info {
	guint32 first_frame_secs, first_frame_usecs;
	guint32 last_frame_secs, last_frame_usecs;
	dissector_handle_t dissect;
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

static void
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

static void
x25_hash_add_proto_start(guint16 vc, guint32 frame_secs, guint32 frame_usecs,
		         dissector_handle_t dissect)
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

static void
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

static dissector_handle_t
x25_hash_get_dissect(guint32 frame_secs, guint32 frame_usecs, guint16 vc)
{
  global_vc_info *hash_ent = hash_table[vc%64];
  vc_info *vci;
  vc_info *vci2;

  if (!hash_ent)
    return NULL;

  while (hash_ent && hash_ent->vc_num != vc)
    hash_ent = hash_ent->next;
  if (!hash_ent)
    return NULL;

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
  if (!vci && (vci2->last_frame_secs || vci2->last_frame_usecs))
    return NULL;

  /* we reached last record, and previous record has a zero last frame time
   * ==> dissector for previous frame has not been "stopped" by a Clear, etc */
  if (!vci) {
    /* if the start time for vci2 is greater than our frame time
     * ==> no dissector */
    if (frame_secs < vci2->first_frame_secs ||
        (frame_secs == vci2->first_frame_secs &&
         frame_usecs < vci2->first_frame_usecs))
      return NULL;
    else
      return vci2->dissect;
  }

  /* our frame time is before vci's end. Check if it is after vci's start */
  if (frame_secs < vci->first_frame_secs ||
      (frame_secs == vci->first_frame_secs &&
       frame_usecs < vci->first_frame_usecs))
    return NULL;
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
    if (code == 0x03)
	return "Invalid Facility Requested";
    if (code == 0x05)
	return "Network Congestion";
    if (code == 0x09)
	return "Out Of Order";
    if (code == 0x0B)
	return "Access Barred";
    if (code == 0x0D)
	return "Not Obtainable";
    if (code == 0x11)
	return "Remote Procedure Error";
    if (code == 0x13)
	return "Local Procedure Error";
    if (code == 0x15)
	return "RPOA Out Of Order";
    if (code == 0x19)
	return "Reverse Charging Acceptance Not Subscribed";
    if (code == 0x21)
	return "Incompatible Destination";
    if (code == 0x29)
	return "Fast Select Acceptance Not Subscribed";
    if (code == 0x39)
	return "Destination Absent";

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
    if (code == 144)
	return "Timer expired or retransmission count surpassed";
    if (code == 145)
	return "Timer expired or retransmission count surpassed for INTERRUPT";
    if (code == 146)
	return "Timer expired or retransmission count surpassed for DATA "
	       "packet transmission";
    if (code == 147)
	return "Timer expired or retransmission count surpassed for REJECT";
    if (code == 160)
	return "DTE-specific signals";
    if (code == 161)
	return "DTE operational";
    if (code == 162)
	return "DTE not operational";
    if (code == 163)
	return "DTE resource constraint";
    if (code == 164)
	return "Fast select not subscribed";
    if (code == 165)
	return "Invalid partially full DATA packet";
    if (code == 166)
	return "D-bit procedure not supported";
    if (code == 167)
	return "Registration/Cancellation confirmed";
    if (code == 224)
	return "OSI network service problem";
    if (code == 225)
	return "Disconnection (transient condition)";
    if (code == 226)
	return "Disconnection (permanent condition)";
    if (code == 227)
	return "Connection rejection - reason unspecified (transient "
	       "condition)";
    if (code == 228)
	return "Connection rejection - reason unspecified (permanent "
	       "condition)";
    if (code == 229)
	return "Connection rejection - quality of service not available "
               "transient condition)";
    if (code == 230)
	return "Connection rejection - quality of service not available "
               "permanent condition)";
    if (code == 231)
	return "Connection rejection - NSAP unreachable (transient condition)";
    if (code == 232)
	return "Connection rejection - NSAP unreachable (permanent condition)";
    if (code == 233)
	return "reset - reason unspecified";
    if (code == 234)
	return "reset - congestion";
    if (code == 235)
	return "Connection rejection - NSAP address unknown (permanent "
               "condition)";
    if (code == 240)
	return "Higher layer initiated";
    if (code == 241)
	return "Disconnection - normal";
    if (code == 242)
	return "Disconnection - abnormal";
    if (code == 243)
	return "Disconnection - incompatible information in user data";
    if (code == 244)
	return "Connection rejection - reason unspecified (transient "
               "condition)";
    if (code == 245)
	return "Connection rejection - reason unspecified (permanent "
               "condition)";
    if (code == 246)
	return "Connection rejection - quality of service not available "
               "(transient condition)";
    if (code == 247)
	return "Connection rejection - quality of service not available "
               "(permanent condition)";
    if (code == 248)
	return "Connection rejection - incompatible information in user data";
    if (code == 249)
	return "Connection rejection - unrecognizable protocol indentifier "
               "in user data";
    if (code == 250)
	return "Reset - user resynchronization";

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

static void
dump_facilities(proto_tree *tree, int *offset, tvbuff_t *tvb)
{
    guint8 fac, byte1, byte2, byte3;
    guint32 len;      /* facilities length */
    proto_item *ti=0;
    proto_tree *fac_tree = 0;
    proto_tree *fac_subtree;

    len = tvb_get_guint8(tvb, *offset);
    if (len && tree) {
	ti = proto_tree_add_text(tree, tvb, *offset, len + 1,
		                 "Facilities");
	fac_tree = proto_item_add_subtree(ti, ett_x25_fac);
	proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Facilities length: %d", len);
    }
    (*offset)++;

    while (len > 0) {
	fac = tvb_get_guint8(tvb, *offset);
	switch(fac & X25_FAC_CLASS_MASK) {
	case X25_FAC_CLASS_A:
	    switch (fac) {
	    case X25_FAC_COMP_MARK:
		if (fac_tree)
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : 00 (Marker)");
		switch (tvb_get_guint8(tvb, *offset + 1)) {
		case 0x00:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : 00 (Network complementary "
					    "services - calling DTE)");
		    }
		    break;
		case 0xFF:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : FF (Network complementary "
					    "services - called DTE)");
		    }
		    break;
		case 0x0F:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : 0F (DTE complementary "
					    "services)");
		    }
		    break;
		default:
		    if (fac_tree) {
			fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_mark);
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
					    "Parameter : %02X (Unknown marker)",
					    tvb_get_guint8(tvb, *offset+1));
		    }
		    break;
		}
		break;
	    case X25_FAC_REVERSE:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Reverse charging / Fast select)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_reverse);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter : %02X", byte1);
		    if (byte1 & 0xC0)
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"11.. .... = Fast select with restriction");
		    else if (byte1 & 0x80)
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"10.. .... = Fast select - no restriction");
		    else
			proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
				"00.. .... = Fast select not requested");
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    decode_boolean_bitfield(byte1, 0x01, 1*8,
				"Reverse charging requested",
				"Reverse charging not requested"));
		}
		break;
	    case X25_FAC_THROUGHPUT:
		if (fac_tree) {
		    char tmpbuf[80];

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Throughput class negociation)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_throughput);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    switch (byte1 >> 4)
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
				75*(1<<((byte1 >> 4)-3)));
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
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    decode_numeric_bitfield(byte1, 0xF0, 1*8, tmpbuf));
		    switch (byte1 & 0x0F)
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
				75*(1<<((byte1 & 0x0F)-3)));
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
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    decode_numeric_bitfield(byte1, 0x0F, 1*8, tmpbuf));
		}
		break;
	    case X25_FAC_CUG:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Closed user group selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_cug);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Closed user group: %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_CALLED_MODIF:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Called address modified)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_called_modif);
		    proto_tree_add_text(fac_tree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_CUG_OUTGOING_ACC:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Closed user group with outgoing access selection)",
			    fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_cug_outgoing_acc);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Closed user group: %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_THROUGHPUT_MIN:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Minimum throughput class)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_throughput_min);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    case X25_FAC_EXPRESS_DATA:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Negociation of express data)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_express_data);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Unknown class A)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Parameter %02X", tvb_get_guint8(tvb, *offset+1));
		}
		break;
	    }
	    (*offset) += 2;
	    len -= 2;
	    break;
	case X25_FAC_CLASS_B:
	    switch (fac) {
	    case X25_FAC_BILATERAL_CUG:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Bilateral closed user group selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_bilateral_cug);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
					"Bilateral CUG: %04X",
					tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    case X25_FAC_PACKET_SIZE:
		if (fac_tree)
		{
		    char tmpbuf[80];

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Packet size)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_packet_size);
		    byte1 = tvb_get_guint8(tvb, *offset + 1);
		    switch (byte1)
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
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    decode_numeric_bitfield(byte1, 0x0F, 1*8, tmpbuf));

		    byte2 = tvb_get_guint8(tvb, *offset + 1);
		    switch (byte2)
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
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
			    decode_numeric_bitfield(byte2, 0x0F, 1*8, tmpbuf));
		}
		break;
	    case X25_FAC_WINDOW_SIZE:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Window size)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_window_size);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    decode_numeric_bitfield(tvb_get_guint8(tvb, *offset+1),
				0x7F, 1*8, "From the called DTE: %u"));
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
			    decode_numeric_bitfield(tvb_get_guint8(tvb, *offset+2),
				0x7F, 1*8, "From the calling DTE: %u"));
		}
		break;
	    case X25_FAC_RPOA_SELECTION:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(RPOA selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_rpoa_selection);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
					"Data network identification code : %04X",
					tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    case X25_FAC_TRANSIT_DELAY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Transit delay selection and indication)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_transit_delay);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
					"Transit delay: %d ms",
					tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Unknown class B)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 2,
			    "Parameter %04X", tvb_get_ntohs(tvb, *offset+1));
		}
		break;
	    }
	    (*offset) += 3;
	    len -= 3;
	    break;
	case X25_FAC_CLASS_C:
	    if (fac_tree) {
		ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			"Code : %02X (Unknown class C)", fac);
		fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		proto_tree_add_text(fac_subtree, tvb, *offset+1, 3,
			"Parameter %06X",
			tvb_get_ntoh24(tvb, *offset+1));
	    }
	    (*offset) += 4;
	    len -= 4;
	    break;
	case X25_FAC_CLASS_D:
	    switch (fac) {
	    case X25_FAC_CALL_TRANSFER:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Call redirection or deflection notification)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_call_transfer);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    byte2 = tvb_get_guint8(tvb, *offset+2);
		    if ((byte2 & 0xC0) == 0xC0) {
			proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				"Reason : call deflection by the originally "
				"called DTE address");
		    }
		    else {
			switch (byte2) {
			case 0x01:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : originally called DTE busy");
			    break;
			case 0x07:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : call dist. within a hunt group");
			    break;
			case 0x09:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : originally called DTE out of order");
			    break;
			case 0x0F:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : systematic call redirection");
			    break;
			default:
			    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				    "Reason : unknown");
			    break;
			}
		    }
		    byte3 = tvb_get_guint8(tvb, *offset+3);
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, 1,
			    "Number of semi-octets in DTE address : %u",
			    byte3);
		    for (i = 0; i < byte3; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+4+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+4+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+4, byte1 - 2,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_CALLING_ADDR_EXT:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Calling address extension)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_calling_addr_ext);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    byte2 = tvb_get_guint8(tvb, *offset+2);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
			    "Number of semi-octets in DTE address : %u", byte2);
		    for (i = 0; i < byte2; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+3+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+3+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, byte1 - 1,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_CALLED_ADDR_EXT:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Called address extension)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_called_addr_ext);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    byte2 = tvb_get_guint8(tvb, *offset+2);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
			    "Number of semi-octets in DTE address : %u", byte2);
		    for (i = 0; i < byte2; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+3+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+3+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, byte1 - 1,
			    "DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_ETE_TRANSIT_DELAY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(End to end transit delay)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_ete_transit_delay);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
		break;
	    case X25_FAC_CALL_DEFLECT:
		if (fac_tree) {
		    int i;
		    char tmpbuf[256];

		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1, "Code : %02X "
			    "(Call deflection selection)", fac);
		    fac_subtree = proto_item_add_subtree(ti,
			    ett_x25_fac_call_deflect);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    byte2 = tvb_get_guint8(tvb, *offset+2);
		    if ((byte2 & 0xC0) == 0xC0)
			proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				"Reason : call DTE originated");
		    else
			proto_tree_add_text(fac_subtree, tvb, *offset+2, 1,
				"Reason : unknown");
		    byte3 = tvb_get_guint8(tvb, *offset+3);
		    proto_tree_add_text(fac_subtree, tvb, *offset+3, 1,
			    "Number of semi-octets in the alternative DTE address : %u",
			    byte3);
		    for (i = 0; i < byte3; i++) {
			if (i % 2 == 0) {
			    tmpbuf[i] = ((tvb_get_guint8(tvb, *offset+4+i/2) >> 4)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			} else {
			    tmpbuf[i] = (tvb_get_guint8(tvb, *offset+4+i/2)
				    & 0x0F) + '0';
			    /* if > 9, convert to the right hexadecimal letter */
			    if (tmpbuf[i] > '9') tmpbuf[i] += ('A' - '0' - 10);
			}
		    }
		    tmpbuf[i] = 0;
		    proto_tree_add_text(fac_subtree, tvb, *offset+4, byte1 - 2,
			    "Alternative DTE address : %s", tmpbuf);
		}
		break;
	    case X25_FAC_PRIORITY:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Priority)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_priority);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
		break;
	    default:
		if (fac_tree) {
		    ti = proto_tree_add_text(fac_tree, tvb, *offset, 1,
			    "Code : %02X (Unknown class D)", fac);
		    fac_subtree = proto_item_add_subtree(ti, ett_x25_fac_unknown);
		    byte1 = tvb_get_guint8(tvb, *offset+1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+1, 1,
			    "Length : %u", byte1);
		    proto_tree_add_text(fac_subtree, tvb, *offset+2, byte1, "Value");
		}
	    }
	    byte1 = tvb_get_guint8(tvb, *offset+1);
	    (*offset) += byte1+2;
	    len -= byte1+2;
	    break;
	}
    }
}

static void
x25_ntoa(proto_tree *tree, int *offset, tvbuff_t *tvb,
	 frame_data *fd, gboolean toa)
{
    int len1, len2;
    int i;
    char addr1[16], addr2[16];
    char *first, *second;
    guint8 byte;
    int localoffset;

    byte = tvb_get_guint8(tvb, *offset);
    len1 = (byte >> 4) & 0x0F;
    len2 = (byte >> 0) & 0x0F;
    if (tree) {
	proto_tree_add_text(tree, tvb, *offset, 1,
		decode_numeric_bitfield(byte, 0xF0, 1*8,
		    toa ? "Called address length : %u" :
		          "Calling address length : %u"));
	proto_tree_add_text(tree, tvb, *offset, 1,
		decode_numeric_bitfield(byte, 0x0F, 1*8,
		    toa ? "Calling address length : %u" :
		          "Called address length : %u"));
    }
    (*offset)++;

    localoffset = *offset;
    byte = tvb_get_guint8(tvb, localoffset);

    first=addr1;
    second=addr2;
    for (i = 0; i < (len1 + len2); i++) {
	if (i < len1) {
	    if (i % 2 != 0) {
		*first++ = ((byte >> 0) & 0x0F) + '0';
		localoffset++;
		byte = tvb_get_guint8(tvb, localoffset);
	    } else {
		*first++ = ((byte >> 4) & 0x0F) + '0';
	    }
	} else {
	    if (i % 2 != 0) {
		*second++ = ((byte >> 0) & 0x0F) + '0';
		localoffset++;
		byte = tvb_get_guint8(tvb, localoffset);
	    } else {
		*second++ = ((byte >> 4) & 0x0F) + '0';
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
	    proto_tree_add_text(tree, tvb, *offset,
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
	    proto_tree_add_text(tree, tvb, *offset + len1/2,
				(len2+1)/2+(len1%2+(len2+1)%2)/2,
				"%s address : %s",
				toa ? "Calling" : "Called",
				addr2);
    }
    (*offset) += ((len1 + len2 + 1) / 2);
}

static int
get_x25_pkt_len(tvbuff_t *tvb)
{
    guint length, called_len, calling_len, dte_len, dce_len;
    guint8 byte2, bytex;

    byte2 = tvb_get_guint8(tvb, 2);
    switch (byte2)
    {
    case X25_CALL_REQUEST:
	bytex = tvb_get_guint8(tvb, 3);
	called_len  = (bytex >> 0) & 0x0F;
	calling_len = (bytex >> 4) & 0x0F;
	length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* facilities */

	return MIN(tvb_reported_length(tvb),length);

    case X25_CALL_ACCEPTED:
	/* The calling/called address length byte (following the packet type)
	 * is not mandatory, so we must check the packet length before trying
	 * to read it */
	if (tvb_reported_length(tvb) == 3)
	    return(3);
	bytex = tvb_get_guint8(tvb, 3);
	called_len  = (bytex >> 0) & 0x0F;
	calling_len = (bytex >> 4) & 0x0F;
	length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* facilities */

	return MIN(tvb_reported_length(tvb),length);

    case X25_CLEAR_REQUEST:
    case X25_RESET_REQUEST:
    case X25_RESTART_REQUEST:
	return MIN(tvb_reported_length(tvb),5);

    case X25_DIAGNOSTIC:
	return MIN(tvb_reported_length(tvb),4);

    case X25_CLEAR_CONFIRMATION:
    case X25_INTERRUPT:
    case X25_INTERRUPT_CONFIRMATION:
    case X25_RESET_CONFIRMATION:
    case X25_RESTART_CONFIRMATION:
	return MIN(tvb_reported_length(tvb),3);

    case X25_REGISTRATION_REQUEST:
	bytex = tvb_get_guint8(tvb, 3);
	dce_len = (bytex >> 0) & 0x0F;
	dte_len = (bytex >> 4) & 0x0F;
	length = 4 + (dte_len + dce_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* registration */

	return MIN(tvb_reported_length(tvb),length);

    case X25_REGISTRATION_CONFIRMATION:
	bytex = tvb_get_guint8(tvb, 5);
	dce_len = (bytex >> 0) & 0x0F;
	dte_len = (bytex >> 4) & 0x0F;
	length = 6 + (dte_len + dce_len + 1) / 2; /* addr */
	if (length < tvb_reported_length(tvb))
	    length += (1 + tvb_get_guint8(tvb, length)); /* registration */

	return MIN(tvb_reported_length(tvb),length);
    }

    if ((byte2 & 0x01) == X25_DATA) return MIN(tvb_reported_length(tvb),3);

    switch (byte2 & 0x1F)
    {
    case X25_RR:
	return MIN(tvb_reported_length(tvb),3);

    case X25_RNR:
	return MIN(tvb_reported_length(tvb),3);

    case X25_REJ:
	return MIN(tvb_reported_length(tvb),3);
    }

    return 0;
}

static const value_string prt_id_vals[] = {
        {PRT_ID_ISO_8073,           "ISO 8073 COTP"},
        {PRT_ID_ISO_8602,           "ISO 8602 CLTP"},
        {PRT_ID_ISO_10736_ISO_8073, "ISO 10736 in conjunction with ISO 8073 COTP"},
        {PRT_ID_ISO_10736_ISO_8602, "ISO 10736 in conjunction with ISO 8602 CLTP"},
        {0x00,                      NULL}
};

static const value_string sharing_strategy_vals[] = {
        {0x00,            "No sharing"},
        {0x00,            NULL}
};

static void
dissect_x25(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *x25_tree=0, *gfi_tree=0, *userdata_tree=0;
    proto_item *ti;
    guint localoffset=0;
    guint x25_pkt_len;
    int modulo;
    guint16 vc;
    dissector_handle_t dissect;
    gboolean toa;         /* TOA/NPI address format */
    guint16 bytes0_1;
    guint8 pkt_type;
    tvbuff_t *next_tvb;
    gboolean q_bit_set = FALSE;

    if (check_col(pinfo->fd, COL_PROTOCOL))
	col_set_str(pinfo->fd, COL_PROTOCOL, "X.25");

    bytes0_1 = tvb_get_ntohs(tvb, 0);

    modulo = ((bytes0_1 & 0x2000) ? 128 : 8);
    vc     = (int)(bytes0_1 & 0x0FFF);

    if (bytes0_1 & 0x8000) toa = TRUE;
    else toa = FALSE;

    x25_pkt_len = get_x25_pkt_len(tvb);
    if (x25_pkt_len < 3) /* packet too short */
    {
	if (check_col(pinfo->fd, COL_INFO))
	    col_set_str(pinfo->fd, COL_INFO, "Invalid/short X.25 packet");
	if (tree)
	    proto_tree_add_protocol_format(tree, proto_x25, tvb, 0,
		    tvb_length(tvb), "Invalid/short X.25 packet");
	return;
    }

    pkt_type = tvb_get_guint8(tvb, 2);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_x25, tvb, 0, x25_pkt_len, FALSE);
        x25_tree = proto_item_add_subtree(ti, ett_x25);
        ti = proto_tree_add_item(x25_tree, hf_x25_gfi, tvb, 0, 2, FALSE);
        gfi_tree = proto_item_add_subtree(ti, ett_x25_gfi);

        if ((pkt_type & 0x01) == X25_DATA) {
            proto_tree_add_boolean(gfi_tree, hf_x25_qbit, tvb, 0, 2,
                bytes0_1);
            if (bytes0_1 & 0x8000) {
                q_bit_set = TRUE;
            }
        }
        else if (pkt_type == X25_CALL_REQUEST ||
            pkt_type == X25_CALL_ACCEPTED ||
            pkt_type == X25_CLEAR_REQUEST ||
            pkt_type == X25_CLEAR_CONFIRMATION) {
            proto_tree_add_boolean(gfi_tree, hf_x25_abit, tvb, 0, 2,
                bytes0_1);
        }

        if (pkt_type == X25_CALL_REQUEST || pkt_type == X25_CALL_ACCEPTED ||
            (pkt_type & 0x01) == X25_DATA) {
            proto_tree_add_boolean(gfi_tree, hf_x25_dbit, tvb, 0, 2,
                bytes0_1);
        }
        proto_tree_add_uint(gfi_tree, hf_x25_mod, tvb, 0, 2, bytes0_1);
    }

    switch (pkt_type) {
    case X25_CALL_REQUEST:
	if (check_col(pinfo->fd, COL_INFO))
	    col_add_fstr(pinfo->fd, COL_INFO, "%s VC:%d",
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Inc. call"
		                                                 : "Call req." ,
                    vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb,
		    0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_CALL_REQUEST,
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Incoming call"
			                                         : "Call request");
	}
	localoffset = 3;
	if (localoffset < x25_pkt_len) /* calling/called addresses */
	    x25_ntoa(x25_tree, &localoffset, tvb, pinfo->fd, toa);

	if (localoffset < x25_pkt_len) /* facilities */
	    dump_facilities(x25_tree, &localoffset, tvb);

	if (localoffset < tvb_reported_length(tvb)) /* user data */
	{
	    guint8 spi;
	    int is_x_264;
	    guint8 prt_id;

	    if (x25_tree) {
		ti = proto_tree_add_text(x25_tree, tvb, localoffset,
			tvb_length_remaining(tvb, localoffset),
			"User data");
		userdata_tree = proto_item_add_subtree(ti, ett_x25_user_data);
	    }

	    /* X.263/ISO 9577 says that:

		    When CLNP or ESIS are run over X.25, the SPI
		    is 0x81 or 0x82, respectively; those are the
		    NLPIDs for those protocol.

		    When X.224/ISO 8073 COTP is run over X.25, and
		    when ISO 11570 explicit identification is being
		    used, the first octet of the user data field is
		    a TPDU length field, and the rest is "as defined
		    in ITU-T Rec. X.225 | ISO/IEC 8073, Annex B,
		    or ITU-T Rec. X.264 and ISO/IEC 11570".

		    When X.264/ISO 11570 default identification is
		    being used, there is no user data field in the
		    CALL REQUEST packet.  This is for X.225/ISO 8073
		    COTP.

	       It also says that SPI values from 0x03 through 0x3f are
	       reserved and are in use by X.224/ISO 8073 Annex B and
	       X.264/ISO 11570.  The note says that those values are
	       not NLPIDs, they're "used by the respective higher layer
	       protocol" and "not used for higher layer protocol
	       identification".  I infer from this and from what
	       X.264/ISO 11570 says that this means that values in those
	       range are valid values for the first octet of an
	       X.224/ISO 8073 packet or for X.264/ISO 11570.

	       Annex B of X.225/ISO 8073 mentions some additional TPDU
	       types that can be put in what I presume is the user
	       data of connect requests.  It says that:

		    The sending transport entity shall:

			a) either not transmit any TPDU in the NS-user data
			   parameter of the N-CONNECT request primitive; or

			b) transmit the UN-TPDU (see ITU-T Rec. X.264 and
			   ISO/IEC 11570) followed by the NCM-TPDU in the
			   NS-user data parameter of the N-CONNECT request
			   primitive.

	       I don't know if this means that the user data field
	       will contain a UN TPDU followed by an NCM TPDU or not.

	       X.264/ISO 11570 says that:

		    When default identification is being used,
		    X.225/ISO 8073 COTP is identified.  No user data
		    is sent in the network-layer connection request.

		    When explicit identification is being used,
		    the user data is a UN TPDU ("Use of network
		    connection TPDU"), which specifies the transport
		    protocol to use over this network connection.
		    It also says that the length of a UN TPDU shall
		    not exceed 32 octets, i.e. shall not exceed 0x20;
		    it says this is "due to the desire not to conflict
		    with the protocol identifier field carried by X.25
		    CALL REQUEST/INCOMING CALL packets", and says that
		    field has values specified in X.244.  X.244 has been
		    superseded by X.263/ISO 9577, so that presumably
		    means the goal is to allow a UN TPDU's length
		    field to be distinguished from an NLPID, allowing
		    you to tell whether X.264/ISO 11570 explicit
		    identification is being used or an NLPID is
		    being used as the SPI.

	       I read this as meaning that, if the ISO mechanisms are
	       used to identify the protocol being carried over X.25:

		    if there's no user data in the CALL REQUEST/
		    INCOMING CALL packet, it's COTP;

		    if there is user data, then:

			if the first octet is less than or equal to
			32, it might be a UN TPDU, and that identifies
			the transport protocol being used, and
			it may be followed by more data, such
			as a COTP NCM TPDU if it's COTP;

			if the first octet is greater than 32, it's
			an NLPID, *not* a TPDU length, and the
			stuff following it is *not* a TPDU.

	       Figure A.2 of X.263/ISO 9577 seems to say that the
	       first octet of the user data is a TPDU length field,
	       in the range 0x03 through 0x82, and says they are
	       for X.225/ISO 8073 Annex B or X.264/ISO 11570.

	       However, X.264/ISO 11570 seems to imply that the length
	       field would be that of a UN TPDU, which must be less
	       than or equal to 0x20, and X.225/ISO 8073 Annex B seems
	       to indicate that the user data must begin with
	       an X.264/ISO 11570 UN TPDU, so I'd say that A.2 should
	       have said "in the range 0x03 through 0x20", instead
	       (the length value doesn't include the length field,
	       and the minimum UN TPDU has length, type, PRT-ID,
	       and SHARE, so that's 3 bytes without the length). */
	    spi = tvb_get_guint8(tvb, localoffset);
	    if (spi > 32 || spi < 3) {
		/* First octet is > 32, or < 3, so the user data isn't an
		   X.264/ISO 11570 UN TPDU */
		is_x_264 = FALSE;
	    } else {
		/* First octet is >= 3 and <= 32, so the user data *might*
		   be an X.264/ISO 11570 UN TPDU.  Check whether we have
		   enough data to see if it is. */
		if (tvb_bytes_exist(tvb, localoffset+1, 1)) {
		    /* We do; check whether the second octet is 1. */
		    if (tvb_get_guint8(tvb, localoffset+1) == 0x01) {
			/* Yes, the second byte is 1, so it looks like
			   a UN TPDU. */
			is_x_264 = TRUE;
		    } else {
			/* No, the second byte is not 1, so it's not a
			   UN TPDU. */
			is_x_264 = FALSE;
		    }
		} else {
		    /* We can't see the second byte of the putative UN
		       TPDU, so we don't know if that's what it is. */
		    is_x_264 = -1;
		}
	    }
	    if (is_x_264 == -1) {
		/*
		 * We don't know what it is; just skip it.
		 */
		localoffset = tvb_length(tvb);
	    } else if (is_x_264) {
		/* It looks like an X.264 UN TPDU, so show it as such. */
		if (userdata_tree) {
		    proto_tree_add_text(userdata_tree, tvb, localoffset, 1,
					"X.264 length indicator: %u",
					spi);
		    proto_tree_add_text(userdata_tree, tvb, localoffset+1, 1,
					"X.264 UN TPDU identifier: 0x%02X",
					tvb_get_guint8(tvb, localoffset+1));
		}
		prt_id = tvb_get_guint8(tvb, localoffset+2);
		if (userdata_tree) {
		    proto_tree_add_text(x25_tree, tvb, localoffset+2, 1,
					"X.264 protocol identifier: %s",
					val_to_str(prt_id, prt_id_vals,
					       "Unknown (0x%02X)"));
		    proto_tree_add_text(x25_tree, tvb, localoffset+3, 1,
					"X.264 sharing strategy: %s",
					val_to_str(tvb_get_guint8(tvb, localoffset+3),
					sharing_strategy_vals, "Unknown (0x%02X)"));
		}

		/* XXX - dissect the variable part? */

		/* The length doesn't include the length octet itself. */
		localoffset += spi + 1;

		switch (prt_id) {

		case PRT_ID_ISO_8073:
		    /* ISO 8073 COTP */
		    x25_hash_add_proto_start(vc, pinfo->fd->abs_secs,
					     pinfo->fd->abs_usecs,
					     ositp_handle);
		    /* XXX - disssect the rest of the user data as COTP?
		       That needs support for NCM TPDUs, etc. */
		    break;

		case PRT_ID_ISO_8602:
		    /* ISO 8602 CLTP */
		    x25_hash_add_proto_start(vc, pinfo->fd->abs_secs,
					     pinfo->fd->abs_usecs,
					     ositp_handle);
		    break;
		}
	    } else if (is_x_264 == 0) {
		/* It doesn't look like a UN TPDU, so compare the first
		   octet of the CALL REQUEST packet with various X.263/
		   ISO 9577 NLPIDs, as per Annex A of X.263/ISO 9577. */ 

		if (userdata_tree) {
		    proto_tree_add_text(userdata_tree, tvb, localoffset, 1,
					"X.263 secondary protocol ID: %s",
					val_to_str(spi, nlpid_vals, "Unknown (0x%02x)"));
		}
		localoffset++;
		
		/*
		 * What's the dissector handle for this SPI?
		 */
		dissect = dissector_get_port_handle(x25_subdissector_table, spi);
		x25_hash_add_proto_start(vc, pinfo->fd->abs_secs,
					 pinfo->fd->abs_usecs, dissect);
	    }
	    if (localoffset < tvb_length(tvb)) {
		if (userdata_tree) {
		    proto_tree_add_text(userdata_tree, tvb, localoffset,
				tvb_length(tvb)-localoffset, "Data");
		}
		localoffset = tvb_length(tvb);
	    }
	}
	break;
    case X25_CALL_ACCEPTED:
	if(check_col(pinfo->fd, COL_INFO))
	    col_add_fstr(pinfo->fd, COL_INFO, "%s VC:%d",
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Call conn."
			                                         : "Call acc." ,
		    vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
	    	    X25_CALL_ACCEPTED,
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Call connected"
		                                                 : "Call accepted");
	}
	localoffset = 3;
        if (localoffset < x25_pkt_len) /* calling/called addresses */
	    x25_ntoa(x25_tree, &localoffset, tvb, pinfo->fd, toa);

	if (localoffset < x25_pkt_len) /* facilities */
	    dump_facilities(x25_tree, &localoffset, tvb);

	if (localoffset < tvb_reported_length(tvb)) { /* user data */
	    if (x25_tree)
	        proto_tree_add_text(x25_tree, tvb, localoffset,
				    tvb_reported_length(tvb)-localoffset, "Data");
	    localoffset=tvb_reported_length(tvb);
	}
	break;
    case X25_CLEAR_REQUEST:
	if(check_col(pinfo->fd, COL_INFO)) {
	    col_add_fstr(pinfo->fd, COL_INFO, "%s VC:%d %s - %s",
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Clear ind."
			                                         : "Clear req." ,
		    vc, clear_code(tvb_get_guint8(tvb, 3)),
		    clear_diag(tvb_get_guint8(tvb, 4)));
	}
	x25_hash_add_proto_end(vc, pinfo->fd->abs_secs, pinfo->fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb,
	    	    localoffset+2, 1, X25_CLEAR_REQUEST,
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Clear indication"
		                                                 : "Clear request");
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause : %s", clear_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic : %s", clear_diag(tvb_get_guint8(tvb, 4)));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_CLEAR_CONFIRMATION:
	if(check_col(pinfo->fd, COL_INFO))
	    col_add_fstr(pinfo->fd, COL_INFO, "Clear Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_CLEAR_CONFIRMATION);
	}
	localoffset = x25_pkt_len;

	if (localoffset < tvb_reported_length(tvb)) /* extended clear conf format */
	    x25_ntoa(x25_tree, &localoffset, tvb, pinfo->fd, toa);

	if (localoffset < tvb_reported_length(tvb)) /* facilities */
	    dump_facilities(x25_tree, &localoffset, tvb);
	break;
    case X25_DIAGNOSTIC:
	if(check_col(pinfo->fd, COL_INFO)) {
	    col_add_fstr(pinfo->fd, COL_INFO, "Diag. %d",
		    (int)tvb_get_guint8(tvb, 3));
	}
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_DIAGNOSTIC);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Diagnostic : %d", (int)tvb_get_guint8(tvb, 3));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_INTERRUPT:
	if(check_col(pinfo->fd, COL_INFO))
	    col_add_fstr(pinfo->fd, COL_INFO, "Interrupt VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_INTERRUPT);
	}
	localoffset = x25_pkt_len;
	break;
    case X25_INTERRUPT_CONFIRMATION:
	if(check_col(pinfo->fd, COL_INFO))
	    col_add_fstr(pinfo->fd, COL_INFO, "Interrupt Conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_INTERRUPT_CONFIRMATION);
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESET_REQUEST:
	if(check_col(pinfo->fd, COL_INFO)) {
	    col_add_fstr(pinfo->fd, COL_INFO, "%s VC:%d %s - Diag.:%d",
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Reset ind."
		                                                 : "Reset req.",
		    vc, reset_code(tvb_get_guint8(tvb, 3)),
		    (int)tvb_get_guint8(tvb, 4));
	}
	x25_hash_add_proto_end(vc, pinfo->fd->abs_secs, pinfo->fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESET_REQUEST,
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Reset indication"
                                                                 : "Reset request");
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause : %s", reset_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic : %d", (int)tvb_get_guint8(tvb, 4));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESET_CONFIRMATION:
	if(check_col(pinfo->fd, COL_INFO))
	    col_add_fstr(pinfo->fd, COL_INFO, "Reset conf. VC:%d", vc);
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, 0, 2, bytes0_1);
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESET_CONFIRMATION);
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESTART_REQUEST:
	if(check_col(pinfo->fd, COL_INFO)) {
	    col_add_fstr(pinfo->fd, COL_INFO, "%s %s - Diag.:%d",
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Restart ind."
		                                                 : "Restart req.",
		    restart_code(tvb_get_guint8(tvb, 3)),
		    (int)tvb_get_guint8(tvb, 3));
	}
	if (x25_tree) {
	    proto_tree_add_uint_format(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESTART_REQUEST,
		    (pinfo->pseudo_header->x25.flags & FROM_DCE) ? "Restart indication"
		                                                 : "Restart request");
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause : %s", restart_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic : %d", (int)tvb_get_guint8(tvb, 4));
	}
	localoffset = x25_pkt_len;
	break;
    case X25_RESTART_CONFIRMATION:
	if(check_col(pinfo->fd, COL_INFO))
	    col_set_str(pinfo->fd, COL_INFO, "Restart conf.");
	if (x25_tree)
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_RESTART_CONFIRMATION);
	localoffset = x25_pkt_len;
	break;
    case X25_REGISTRATION_REQUEST:
	if(check_col(pinfo->fd, COL_INFO))
	    col_set_str(pinfo->fd, COL_INFO, "Registration req.");
	if (x25_tree)
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_REGISTRATION_REQUEST);
	localoffset = 3;
	if (localoffset < x25_pkt_len)
	    x25_ntoa(x25_tree, &localoffset, tvb, pinfo->fd, FALSE);

	if (x25_tree) {
	    if (localoffset < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset, 1,
			"Registration length: %d",
			tvb_get_guint8(tvb, localoffset) & 0x7F);
	    if (localoffset+1 < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset+1,
			tvb_get_guint8(tvb, localoffset) & 0x7F,
			"Registration");
	}
	localoffset = tvb_reported_length(tvb);
	break;
    case X25_REGISTRATION_CONFIRMATION:
	if(check_col(pinfo->fd, COL_INFO))
	    col_set_str(pinfo->fd, COL_INFO, "Registration conf.");
	if (x25_tree) {
	    proto_tree_add_uint(x25_tree, hf_x25_type, tvb, 2, 1,
		    X25_REGISTRATION_CONFIRMATION);
	    proto_tree_add_text(x25_tree, tvb, 3, 1,
		    "Cause: %s", registration_code(tvb_get_guint8(tvb, 3)));
	    proto_tree_add_text(x25_tree, tvb, 4, 1,
		    "Diagnostic: %s", registration_code(tvb_get_guint8(tvb, 4)));
	}
	localoffset = 5;
	if (localoffset < x25_pkt_len)
	    x25_ntoa(x25_tree, &localoffset, tvb, pinfo->fd, TRUE);

	if (x25_tree) {
	    if (localoffset < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset, 1,
			"Registration length: %d",
			tvb_get_guint8(tvb, localoffset) & 0x7F);
	    if (localoffset+1 < x25_pkt_len)
		proto_tree_add_text(x25_tree, tvb, localoffset+1,
			tvb_get_guint8(tvb, localoffset) & 0x7F,
			"Registration");
	}
	localoffset = tvb_reported_length(tvb);
	break;
    default :
	localoffset = 2;
	if ((pkt_type & 0x01) == X25_DATA)
	{
	    if(check_col(pinfo->fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->fd, COL_INFO,
			    "Data VC:%d P(S):%d P(R):%d %s", vc,
			    (pkt_type >> 1) & 0x07,
			    (pkt_type >> 5) & 0x07,
			    ((pkt_type >> 4) & 0x01) ? " M" : "");
		else
		    col_add_fstr(pinfo->fd, COL_INFO,
			    "Data VC:%d P(S):%d P(R):%d %s", vc,
			    tvb_get_guint8(tvb, localoffset+1) >> 1,
			    pkt_type >> 1,
			    (tvb_get_guint8(tvb, localoffset+1) & 0x01) ? " M" : "");
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		proto_tree_add_uint_hidden(x25_tree, hf_x25_type, tvb,
			localoffset, 1, X25_DATA);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    if (pkt_type & 0x10)
			proto_tree_add_boolean(x25_tree, hf_x25_mbit_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_p_s_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_text(x25_tree, tvb, localoffset, 1,
			    decode_boolean_bitfield(pkt_type, 0x01, 1*8,
				NULL, "DATA"));
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_p_s_mod128, tvb,
			    localoffset+1, 1,
			    tvb_get_guint8(tvb, localoffset+1));
		    if (tvb_get_guint8(tvb, localoffset+1) & 0x01)
			proto_tree_add_boolean(x25_tree, hf_x25_mbit_mod128, tvb,
				localoffset+1, 1,
				tvb_get_guint8(tvb, localoffset+1));
		}
	    }
	    localoffset += (modulo == 8) ? 1 : 2;
	    break;
	}
	switch (pkt_type & 0x1F)
	{
	case X25_RR:
	    if(check_col(pinfo->fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->fd, COL_INFO, "RR VC:%d P(R):%d",
			    vc, (pkt_type >> 5) & 0x07);
		else
		    col_add_fstr(pinfo->fd, COL_INFO, "RR VC:%d P(R):%d",
			    vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_RR);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_RR);
		    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset+1, 1, FALSE);
		}
	    }
	    break;

	case X25_RNR:
	    if(check_col(pinfo->fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->fd, COL_INFO, "RNR VC:%d P(R):%d",
			    vc, (pkt_type >> 5) & 0x07);
		else
		    col_add_fstr(pinfo->fd, COL_INFO, "RNR VC:%d P(R):%d",
			    vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_RNR);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_RNR);
		    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset+1, 1, FALSE);
		}
	    }
	    break;

	case X25_REJ:
	    if(check_col(pinfo->fd, COL_INFO)) {
		if (modulo == 8)
		    col_add_fstr(pinfo->fd, COL_INFO, "REJ VC:%d P(R):%d",
			    vc, (pkt_type >> 5) & 0x07);
		else
		    col_add_fstr(pinfo->fd, COL_INFO, "REJ VC:%d P(R):%d",
			    vc, tvb_get_guint8(tvb, localoffset+1) >> 1);
	    }
	    if (x25_tree) {
		proto_tree_add_uint(x25_tree, hf_x25_lcn, tvb, localoffset-2,
			2, bytes0_1);
		if (modulo == 8) {
		    proto_tree_add_uint(x25_tree, hf_x25_p_r_mod8, tvb,
			    localoffset, 1, pkt_type);
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_REJ);
		}
		else {
		    proto_tree_add_uint(x25_tree, hf_x25_type, tvb,
			    localoffset, 1, X25_REJ);
		    proto_tree_add_item(x25_tree, hf_x25_p_r_mod128, tvb,
			    localoffset+1, 1, FALSE);
		}
	    }
	}
	localoffset += (modulo == 8) ? 1 : 2;
    }

    if (localoffset >= tvb_reported_length(tvb)) return;

    next_tvb = tvb_new_subset(tvb, localoffset, -1, -1);

    /* QLLC ? */
    if (q_bit_set) {
        call_dissector(qllc_handle, next_tvb, pinfo, tree);
        return;
    }

    /* search the dissector in the hash table */
    if ((dissect = x25_hash_get_dissect(pinfo->fd->abs_secs, pinfo->fd->abs_usecs, vc))) {
        /* Found it in the hash table; use it. */
        call_dissector(dissect, next_tvb, pinfo, tree);
        return;
    }

    /* Did the user suggest SNA-over-X.25? */
    if (non_q_bit_is_sna) {
        /* Yes - dissect it as SNA. */
	x25_hash_add_proto_start(vc, pinfo->fd->abs_secs,
				 pinfo->fd->abs_usecs, sna_handle);
	call_dissector(sna_handle, next_tvb, pinfo, tree);
	return;
    }

    /* If the Call Req. has not been captured, and the payload begins
       with what appears to be an IP header, assume these packets carry
       IP */
    if (tvb_get_guint8(tvb, localoffset) == 0x45) {
	x25_hash_add_proto_start(vc, pinfo->fd->abs_secs,
				 pinfo->fd->abs_usecs, ip_handle);
	call_dissector(ip_handle, next_tvb, pinfo, tree);
	return;
    }

    /* Try the heuristic dissectors. */
    if (dissector_try_heuristic(x25_heur_subdissector_list, next_tvb, pinfo,
				tree))
	return;

    /* All else failed; dissect it as raw data */
    call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_x25(void)
{
    static hf_register_info hf[] = {
	{ &hf_x25_gfi,
	  { "GFI", "x.25.gfi", FT_UINT16, BASE_BIN, NULL, 0xF000,
	  	"General format identifier", HFILL }},
	{ &hf_x25_abit,
	  { "A Bit", "x.25.a", FT_BOOLEAN, 16, NULL, 0x8000,
	  	"Address Bit", HFILL }},
	{ &hf_x25_qbit,
	  { "Q Bit", "x.25.q", FT_BOOLEAN, 16, NULL, 0x8000,
	  	"Qualifier Bit", HFILL }},
	{ &hf_x25_dbit,
	  { "D Bit", "x.25.d", FT_BOOLEAN, 16, NULL, 0x4000,
	  	"Delivery Confirmation Bit", HFILL }},
	{ &hf_x25_mod,
	  { "Modulo", "x.25.mod", FT_UINT16, BASE_DEC, VALS(vals_modulo), 0x3000,
	  	"Specifies whether the frame is modulo 8 or 128", HFILL }},
	{ &hf_x25_lcn,
	  { "Logical Channel", "x.25.lcn", FT_UINT16, BASE_DEC, NULL, 0x0FFF,
	  	"Logical Channel Number", HFILL }},
	{ &hf_x25_type,
	  { "Packet Type", "x.25.type", FT_UINT8, BASE_HEX, VALS(vals_x25_type), 0x0,
	  	"Packet Type", HFILL }},
	{ &hf_x25_p_r_mod8,
	  { "P(R)", "x.25.p_r", FT_UINT8, BASE_HEX, NULL, 0xE0,
	  	"Packet Receive Sequence Number", HFILL }},
	{ &hf_x25_p_r_mod128,
	  { "P(R)", "x.25.p_r", FT_UINT8, BASE_HEX, NULL, 0xFE,
	  	"Packet Receive Sequence Number", HFILL }},
	{ &hf_x25_mbit_mod8,
	  { "M Bit", "x.25.m", FT_BOOLEAN, 8, NULL, 0x10,
	  	"More Bit", HFILL }},
	{ &hf_x25_mbit_mod128,
	  { "M Bit", "x.25.m", FT_BOOLEAN, 8, NULL, 0x01,
	  	"More Bit", HFILL }},
	{ &hf_x25_p_s_mod8,
	  { "P(S)", "x.25.p_s", FT_UINT8, BASE_HEX, NULL, 0x0E,
	  	"Packet Send Sequence Number", HFILL }},
	{ &hf_x25_p_s_mod128,
	  { "P(S)", "x.25.p_s", FT_UINT8, BASE_HEX, NULL, 0xFE,
	  	"Packet Send Sequence Number", HFILL }},
    };
    static gint *ett[] = {
        &ett_x25,
	&ett_x25_gfi,
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
	&ett_x25_fac_priority,
	&ett_x25_user_data
    };
    module_t *x25_module;

    proto_x25 = proto_register_protocol ("X.25", "X.25", "x.25");
    proto_register_field_array (proto_x25, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine(&reinit_x25_hashtable);

    x25_subdissector_table = register_dissector_table("x.25.spi",
	"X.25 secondary protocol identifier", FT_UINT8, BASE_HEX);
    register_heur_dissector_list("x.25", &x25_heur_subdissector_list);

    register_dissector("x.25", dissect_x25, proto_x25);

    /* Preferences */
    x25_module = prefs_register_protocol(proto_x25, NULL);
    prefs_register_bool_preference(x25_module, "non_q_bit_is_sna",
            "When Q-bit is 0, payload is SNA", "When Q-bit is 0, payload is SNA",
            &non_q_bit_is_sna);
}

void
proto_reg_handoff_x25(void)
{
    dissector_handle_t x25_handle;

    /*
     * Get handles for various dissectors.
     */
    ip_handle = find_dissector("ip");
    ositp_handle = find_dissector("ositp");
    sna_handle = find_dissector("sna");
    qllc_handle = find_dissector("qllc");
    data_handle = find_dissector("data");

    x25_handle = find_dissector("x.25");
    dissector_add("llc.dsap", SAP_X25, x25_handle);
}
