/* packet-x25.c
 * Routines for x25 packet disassembly
 * Olivier Abad <abad@daba.dhis.org>
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
#define X25_FAC_THROUGHPUT_MIN		0x0A
#define X25_FAC_EXPRESS_DATA		0x0B
#define X25_FAC_PACKET_SIZE		0x42
#define X25_FAC_WINDOW_SIZE		0x43
#define X25_FAC_TRANSIT_DELAY		0x49
#define X25_FAC_CALL_TRANSFER		0xC3
#define X25_FAC_CALLED_ADDR_EXT		0xC9
#define X25_FAC_ETE_TRANSIT_DELAY	0xCA
#define X25_FAC_ADDR_EXT		0xCB

int proto_x25 = -1;
int hf_x25_lcn = -1;
int hf_x25_type = -1;

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

global_vc_info *hash_table[64];

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

static char *reset_code(unsigned char code)
{
    static char buffer[25];

    if (code == 0x00 || (code & 0x80) == 0x80)
	return "DTE Originated";
    if (code == 0x03)
	return "Remote Procedure Error";
    if (code == 0x11)
	return "Incompatible Destination";
    if (code == 0x05)
	return "Local Procedure Error";
    if (code == 0x07)
	return "Network Congestion";

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
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Throughput: %02X", ptr[1]);
		break;
	    case X25_FAC_CUG:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"CUG: %02X",
					ptr[1]);
		break;
	    case X25_FAC_CALLED_MODIF:
		if (tree)
		    proto_tree_add_text(tree, *offset, 2,
					"Called address modified: %02X",
					ptr[1]);
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
	    case X25_FAC_PACKET_SIZE:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
					"Packet Size: %02X %02X", ptr[1], ptr[2]);
		break;
	    case X25_FAC_WINDOW_SIZE:
		if (tree)
		    proto_tree_add_text(tree, *offset, 3,
					"Window Size: %2d %2d", ptr[1],
					ptr[2]);
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
x25_ntoa(proto_tree *tree, int *offset, const guint8 *p, frame_data *fd)
{
    int called_len, calling_len;
    int i;
    char called_addr[16], calling_addr[16];
    char *called, *calling;

    called_len  = (*p >> 0) & 0x0F;
    calling_len = (*p >> 4) & 0x0F;
    if (tree) {
	proto_tree_add_text(tree, *offset, 1,
			    "Calling address length : %d", calling_len);
	proto_tree_add_text(tree, *offset, 1,
			    "Called address length : %d", called_len);
    }
    (*offset)++;

    p++;

    called=called_addr;
    calling=calling_addr;
    for (i = 0; i < (called_len + calling_len); i++) {
	if (i < called_len) {
	    if (i % 2 != 0) {
		*called++ = ((*p >> 0) & 0x0F) + '0';
		p++;
	    } else {
		*called++ = ((*p >> 4) & 0x0F) + '0';
	    }
	} else {
	    if (i % 2 != 0) {
		*calling++ = ((*p >> 0) & 0x0F) + '0';
		p++;
	    } else {
		*calling++ = ((*p >> 4) & 0x0F) + '0';
	    }
	}
    }

    *called  = '\0';
    *calling = '\0';

    if (called_len) {
	if(check_col(fd, COL_RES_DL_DST))
	    col_add_str(fd, COL_RES_DL_DST, called_addr);
	if (tree)
	    proto_tree_add_text(tree, *offset,
				(called_len + 1) / 2,
				"Called address : %s", called_addr);
    }
    if (calling_len) {
	if(check_col(fd, COL_RES_DL_SRC))
	    col_add_str(fd, COL_RES_DL_SRC, calling_addr);
	if (tree)
	    proto_tree_add_text(tree, *offset + called_len/2,
				(calling_len+1)/2+(called_len%2+(calling_len+1)%2)/2,
				"Calling address : %s", calling_addr);
    }
    (*offset) += ((called_len + calling_len + 1) / 2);
}

int
get_x25_pkt_len(const char *data)
{
    int length, called_len, calling_len;

    switch ((guint8)data[2])
    {
    case X25_CALL_REQUEST:
	called_len  = (data[3] >> 0) & 0x0F;
	calling_len = (data[3] >> 4) & 0x0F;
	length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	length += (1 + data[length]); /* facilities */
	return length;

    case X25_CALL_ACCEPTED:
	called_len  = (data[3] >> 0) & 0x0F;
	calling_len = (data[3] >> 4) & 0x0F;
	length = 4 + (called_len + calling_len + 1) / 2; /* addr */
	length += (1 + data[length]); /* facilities */
	return length;

    case X25_CLEAR_REQUEST:
	return 5;

    case X25_CLEAR_CONFIRMATION:
	return 3;

    case X25_DIAGNOSTIC:
	return 4;

    case X25_INTERRUPT:
	return 3;

    case X25_INTERRUPT_CONFIRMATION:
	return 3;

    case X25_RESET_REQUEST:
	return 5;

    case X25_RESET_CONFIRMATION:
	return 3;
		
    case X25_RESTART_REQUEST:
	return 5;
		
    case X25_RESTART_CONFIRMATION:
	return 3;

    case X25_REGISTRATION_REQUEST:
	return 3;
		
    case X25_REGISTRATION_CONFIRMATION:
	return 3;
    }
	    
    if ((data[2] & 0x01) == X25_DATA) return 3;

    switch (data[2])
    {
    case X25_RR:
	return 3;

    case X25_RNR:
	return 3;

    case X25_REJ:
	return 3;
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

    if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "X.25");

    modulo = ((pd[localoffset] & 0x20) ? 128 : 8);
    vc = (int)(pd[localoffset] & 0x0F) + (int)pd[localoffset+1];
    x25_pkt_len = get_x25_pkt_len(&pd[localoffset]);
    if (tree) {
	ti = proto_tree_add_item(tree, proto_x25, localoffset, x25_pkt_len,
				 NULL);
	x25_tree = proto_item_add_subtree(ti, ETT_X25);
	proto_tree_add_text(x25_tree, localoffset, 1,
			    "GFI : Q: %d, D: %d, Mod: %d",
			    (pd[localoffset] & 0x80) ? 1 : 0,
			    (pd[localoffset] & 0x40) ? 1 : 0,
			    modulo);
	proto_tree_add_item_format(x25_tree, hf_x25_lcn, localoffset, 2,
				   (int)(pd[localoffset] & 0x0F) +
				   (int)pd[localoffset+1],
				   "Logical channel : %3.3X",
				   vc);
    }
    switch (pd[localoffset+2]) {
    case X25_CALL_REQUEST:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Call Req. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "CALL REQ", "CALL REQUEST");
	localoffset += 3;
	x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd);

	if (localoffset < x25_pkt_len+2) /* facilities */
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
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Call Acc. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "CALL ACC", "CALL ACCEPTED");
	localoffset += 3;
	x25_ntoa(x25_tree, &localoffset, &pd[localoffset], fd);

	if (localoffset < x25_pkt_len+2) /* facilities */
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
	    col_add_fstr(fd, COL_INFO, "Clear Req. VC:%d %s - Diag.:%d",
		    vc, clear_code(pd[localoffset+3]),
		    (int)pd[localoffset+4]);
	}
	x25_hash_add_proto_end(vc, fd->abs_secs, fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "CLEAR REQ", "CLEAR REQUEST");
	    proto_tree_add_text(x25_tree, localoffset+3, 1,
				"Cause : %s", clear_code(pd[localoffset+3]));
	    proto_tree_add_text(x25_tree, localoffset+4, 1,
				"Diagnostic : %d", (int)pd[localoffset+4]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_CLEAR_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Clear Conf. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "CLEAR CONF", "CLEAR CONFIRMATION");
	localoffset += x25_pkt_len;
	break;
    case X25_DIAGNOSTIC:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "Diag. VC:%d %d",
		    vc, (int)pd[localoffset+3]);
	}
	if (x25_tree) {
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "DIAG", "DIAGNOSTIC");
	    proto_tree_add_text(x25_tree, localoffset+3, 1,
				"Diagnostic : %d", (int)pd[localoffset+3]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_INTERRUPT:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Interrupt VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "INTR", "INTERRUPT");
	localoffset += x25_pkt_len;
	break;
    case X25_INTERRUPT_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Interrupt Conf. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "INTR CONF", "INTERRUPT CONFIRMATION");
	localoffset += x25_pkt_len;
	break;
    case X25_RESET_REQUEST:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "Reset Req. VC:%d %s - Diag.:%d",
		    vc, reset_code(pd[localoffset+3]),
		    (int)pd[localoffset+4]);
	}
	x25_hash_add_proto_end(vc, fd->abs_secs, fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "RESET REQ", "RESET REQUEST");
	    proto_tree_add_text(x25_tree, localoffset+3, 1,
				"Cause : %s", reset_code(pd[localoffset+3]));
	    proto_tree_add_text(x25_tree, localoffset+4, 1,
				"Diagnostic : %d", (int)pd[localoffset+4]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_RESET_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Reset Conf. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "RESET CONF", "RESET CONFIRMATION");
	localoffset += x25_pkt_len;
	break;
    case X25_RESTART_REQUEST:
	if(check_col(fd, COL_INFO)) {
	    col_add_fstr(fd, COL_INFO, "Restart Req. VC:%d %s - Diag.:%d",
		    vc, restart_code(pd[localoffset+3]),
		    (int)pd[localoffset+4]);
	}
	x25_hash_add_proto_end(vc, fd->abs_secs, fd->abs_usecs);
	if (x25_tree) {
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "RESTART REQ", "RESTART REQUEST");
	    proto_tree_add_text(x25_tree, localoffset+3, 1,
				"Cause : %s", restart_code(pd[localoffset+3]));
	    proto_tree_add_text(x25_tree, localoffset+4, 1,
				"Diagnostic : %d", (int)pd[localoffset+4]);
	}
	localoffset += x25_pkt_len;
	break;
    case X25_RESTART_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Restart Conf. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "RESTART CONF", "RESTART CONFIRMATION");
	localoffset += x25_pkt_len;
	break;
    case X25_REGISTRATION_REQUEST:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Registration Req. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "REG REQ", "REGISTRATION REQUEST");
	localoffset += x25_pkt_len;
	break;
    case X25_REGISTRATION_CONFIRMATION:
	if(check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "Registration Conf. VC:%d", vc);
	if (x25_tree)
	    proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset+2, 1,
				       "REG CONF", "REGISTRATION CONFIRMATION");
	localoffset += x25_pkt_len;
	break;
    default :
	localoffset += 2;
	if ((pd[localoffset] & 0x01) == X25_DATA)
	{
	    if(check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "Data VC:%d P(S):%d P(R):%d %s", vc,
			     (pd[localoffset] >> 1) & 0x07,
			     (pd[localoffset] >> 5) & 0x07,
			     ((pd[localoffset]>>4) & 0x01) ? " M" : "");
	    }
	    if (x25_tree) {
		proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset,
					   1, "DATA",
					   "Packet type identifier : 0x%02X",
					   pd[localoffset]);
		proto_tree_add_text(x25_tree, localoffset, 1,
				    "              %d%d%d..... : P(R) = %d",
				    (pd[localoffset] >> 7) & 0x01,
				    (pd[localoffset] >> 6) & 0x01,
				    (pd[localoffset] >> 5) & 0x01,
				    (pd[localoffset] >> 5) & 0x07);
		proto_tree_add_text(x25_tree, localoffset, 1,
				    "              ...%d.... : More bit",
				    (pd[localoffset] >> 4) & 0x01);
		proto_tree_add_text(x25_tree, localoffset, 1,
				    "              ....%d%d%d. : P(S) = %d",
				    (pd[localoffset] >> 3) & 0x01,
				    (pd[localoffset] >> 2) & 0x01,
				    (pd[localoffset] >> 1) & 0x01,
				    (pd[localoffset] >> 1) & 0x07);
		proto_tree_add_text(x25_tree, localoffset, 1,
				    "              .......0 : Packet type id = DATA");
	    }
	    localoffset++;
	    break;
	}
	switch (pd[localoffset] & 0x1F)
	{
	case X25_RR:
	    if(check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "RR VC:%d P(R):%d",
			     vc, (pd[localoffset] >> 5) & 0x07);
	    }
	    if (x25_tree)
		proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset,
					   1, "RR", "RR P(R):%d",
					   (pd[localoffset] >> 5) & 0x07);
	    break;

	case X25_RNR:
	    if(check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "RNR VC:%d P(R):%d",
			     vc, (pd[localoffset] >> 5) & 0x07);
	    }
	    if (x25_tree)
		proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset,
					   1, "RNR", "RNR P(R):%d",
					   (pd[localoffset] >> 5) & 0x07);
	    break;

	case X25_REJ:
	    if(check_col(fd, COL_INFO)) {
		col_add_fstr(fd, COL_INFO, "REJ VC:%d P(R):%d",
			     vc, (pd[localoffset] >> 5) & 0x07);
	    }
	    if (x25_tree)
		proto_tree_add_item_format(x25_tree, hf_x25_type, localoffset,
					   1, "REJ", "REJ P(R):%d",
					   (pd[localoffset] >> 5) & 0x07);
	}
	localoffset++;
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
    static hf_register_info hf[] = {
	{ &hf_x25_lcn,
	  { "Logical Channel", "x25.lcn", FT_UINT16, NULL} },
	{ &hf_x25_type,
	  { "Packet Type", "x25.type", FT_STRING, NULL} },
    };

    proto_x25 = proto_register_protocol ("X.25", "x25");
    proto_register_field_array (proto_x25, hf, array_length(hf));
}
