/* packet-smb-pipe.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb-pipe.c,v 1.4 2000/03/06 20:03:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include "packet.h"
#include "conversation.h"
#include "smb.h"
#include "alignment.h"

static int proto_smb_lanman = -1;

static gint ett_lanman = -1;
static gint ett_lanman_servers = -1;
static gint ett_lanman_server = -1;
static gint ett_lanman_shares = -1;
static gint ett_lanman_share = -1;
static gint ett_lanman_flags = -1;



/* 
 * The following data structure describes the LANMAN requests we understand
 *
 * Simply fill in the number, name, and parameter names if you know them
 * Try to keep them in order 
 *
 * We will extend this data structure as we try to decode more ...
 */

struct lanman_desc {
  int   lanman_num;
  char  *lanman_name;
  char  **req;
  char  **req_data;     /* Hmmm, not flexible enough */
  char  **resp;
  char  **resp_data;
};

static char *lm_params_req_0[]   = {"Detail Level", "Return Buffer Size", NULL};
static char *lm_params_req_1[]   = {"Share Name", "Detail Level", "Receive Buffer Size", NULL};
static char *lm_params_resp_1[]  = {"Returned Data Len", NULL};
static char *lm_params_req_13[]  = {"Detail Level", "Receive Buffer Size", NULL};
static char *lm_params_req_56[]  = {"User Name", "Detail Level", "Receive Buffer Size", NULL};
static char *lm_params_req_104[] = {"Detail Level", "Return Buffer Size", "Server Type", "Domain", NULL};
static char *lm_params_req_132[] = {"Reserved1", "Reserved2", "Detail Level", "UserInfoStruct?", "Length of UStruct", "Receive Buffer Size", NULL};
static char *lm_params_req_133[] = {"Reserved1", "Reserved2", "Detail Level", "UserInfoStruct?", "Length of UStruct", "Receive Buffer Size", NULL};

static char *lm_null_params[] = {NULL};

struct lanman_desc lmd[] = {
  {0, "NetShareEnum", lm_params_req_0, lm_null_params, lm_null_params, lm_null_params},
  {1, "NetShareGetInfo", lm_params_req_1, lm_null_params, lm_params_resp_1, lm_null_params},
  {13, "NetServerGetInfo", lm_params_req_13, lm_null_params, lm_null_params, lm_null_params},
  {52, "NetGroupGetUsers", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {56, "NetUserGetInfo", lm_params_req_56, lm_null_params, lm_null_params, lm_null_params},
  {59, "NetUserGetGroups", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {63, "NetWkstaGetInfo", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {69, "DOSPrintQEnum", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {70, "DOSPrintQGetInfo", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {74, "WPrintQueuePause", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {75, "WPrintQueueResume", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {76, "WPrintJobEnumerate", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {77, "WPrintJobGetInfo", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {81, "RDOSPrintJobDel", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {82, "RDOSPrintJobPause", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {83, "RDOSPrintJobResume", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {84, "WPrintDestEnum", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {85, "WPrintDestGetInfo", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {91, "NetRemoteTOD", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {103, "WPrintQueuePurge", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {104, "NetServerEnum2", lm_params_req_104, lm_null_params, lm_null_params, lm_null_params},
  {105, "WAccessGetUserPerms", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {115, "SetUserPassword", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {132, "NetWkstaUserLogon", lm_params_req_132, lm_null_params, lm_null_params, lm_null_params},
  {133, "NetWkstaUserLogoff", lm_params_req_133, lm_null_params, lm_null_params, lm_null_params},
  {147, "PrintJobInfo", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {205, "WPrintDriverEnum", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {206, "WPrintQProcEnum", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {207, "WPrintPortEnum", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {214, "SamOEMChangePassword", lm_null_params, lm_null_params, lm_null_params, lm_null_params},
  {-1, NULL, NULL,NULL, NULL, NULL}
};

struct lanman_desc *
find_lanman(int lanman_num)
{
  int i = 0;

  /* FIXME, This could be more efficient */

  while (lmd[i].lanman_num != -1) {

    if (lmd[i].lanman_num == lanman_num) {

      return &lmd[i];

    }

    i++;

  }

  return NULL;

}


#define NETSHAREENUM   0x00  /* 00  */
#define NETSERVERENUM2 0x68  /* 104 */

void dissect_server_flags(proto_tree *tree, int offset, int length, int flags)
{
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0001, length*8, "Workstation", "Not Workstation"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0002, length*8, "Server", "Not Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0004, length*8, "SQL Server", "Not SQL Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0008, length*8, "Domain Controller", "Not Domain Controller"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0010, length*8, "Backup Controller", "Not Backup Controller"));
  proto_tree_add_text(tree, offset, 4, "%s",
		      decode_boolean_bitfield(flags, 0x0020, length*8, "Time Source", "Not Time Source"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0040, length*8, "Apple Server", "Not Apple Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0080, length*8, "Novell Server", "Not Novell Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0100, length*8, "Domain Member Server", "Not Domain Member Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0200, length*8, "Print Queue Server", "Not Print Queue Server"));      
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0400, length*8, "Dialin Server", "Not Dialin Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x0800, length*8, "Xenix Server", "Not Xenix Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x1000, length*8, "NT Workstation", "Not NT Workstation"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x2000, length*8, "Windows for Workgroups", "Not Windows for Workgroups"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x8000, length*8, "NT Server", "Not NT Server"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x10000, length*8, "Potential Browser", "Not Potential Browser"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x20000, length*8, "Backup Browser", "Not Backup Browser"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x40000, length*8, "Master Browser", "Not Master Browser"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x80000, length*8, "Domain Master Browser", "Not Domain Master Browser"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x100000, length*8, "OSF", "Not OSF"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x200000, length*8, "VMS", "Not VMS"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x400000, length*8, "Windows 95 or above", "Not Windows 95 or above"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x40000000, length*8, "Local List Only", "Not Local List Only"));
  proto_tree_add_text(tree, offset, length, "%s",
		      decode_boolean_bitfield(flags, 0x80000000, length*8, "Domain Enum", "Not Domain Enum"));

}



static char *p_desc = NULL, *d_desc = NULL, *data = NULL, *params = NULL;
static int p_count, d_count, p_offset, d_offset, d_current = 0, p_current = 0;
static int pd_p_current = 0, pd_d_current = 0, in_params = 0, need_data = 0;
static int lm_ent_count = 0, lm_act_count = 0; 

/* Initialize the various data structure */
void 
dissect_transact_engine_init(const u_char *pd, const char *param_desc, const char *data_desc, int SMB_offset, int ParameterOffset, int ParameterCount, int DataOffset, int DataCount)
{

  d_count = DataCount;
  p_count = ParameterCount;
  d_offset = 0;
  p_offset = 0;
  d_current = 0;
  p_current = 0;
  lm_ent_count = lm_act_count = 0;
  pd_d_current = DataOffset;
  pd_p_current = ParameterOffset;
  in_params = need_data = 0;

  if (p_desc) g_free(p_desc);
  p_desc = g_malloc(strlen(param_desc) + 1);
  strcpy(p_desc, param_desc);

  if (d_desc) g_free(d_desc);
  d_desc= g_malloc(strlen(data_desc) + 1);
  strcpy(d_desc, data_desc);

  if (params) g_free(params);
  params = g_malloc(p_count);
  memcpy(params, pd + ParameterOffset, ParameterCount);

  if (data) g_free(data);
  data = g_malloc(d_count);
  memcpy(data, pd + DataOffset, DataCount);

}

int get_ent_count()
{

  return lm_ent_count;

}

int get_act_count()
{

  return lm_act_count;

}

int get_byte_count(const u_char *p_data)

{
  int count = 0, off = 0;

  while (p_data[off] && isdigit(p_data[off])) {

    count = (count * 10) + (int)p_data[off++] - (int)'0';

  }

  return count;
}


/* Dissect the next item, if Name is null, call it by its data type  */
/* We pull out the next item in the appropriate place and display it */
/* We display the parameters first, then the data, then any auxilliary data */

int dissect_transact_next(const u_char *pd, char *Name, int dirn, proto_tree *tree)
{
  /*  guint8        BParam; */
  guint16       WParam = 0;
  guint32       LParam = 0;
  const char    /**Bytes,*/ *AsciiZ = NULL;
  int           bc;

  while (1) {

    if (p_desc[p_offset] == 0) return 0;  /* No more ... */

    switch (in_params) {

    case 0:   /* We are in the params area ... */

      switch (p_desc[p_offset++]) {

      case 'r':

	if (dirn == 0) { /* We need to process the data ... */
	  
	  need_data = 1;

	}

	break;

      case 'h':  /* A WORD parameter received */

	if (dirn == 0) {

	  WParam = GSHORT(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 2, "%s: %u (%04X)", (Name) ? Name : "Returned Word", WParam, WParam);

	  pd_p_current += 2;

	  lm_act_count = WParam;

	  return 1;

	}

	break;

      case 'e':  /* An ent count ..  */

	if (dirn == 0) { /* Only relevant in a response */

	  WParam = GSHORT(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 2, "%s: (%04X)", (Name) ? Name : "Entry Count", WParam);

	  pd_p_current += 2;

	  lm_ent_count = WParam;  /* Save this for later retrieval */

	  return 1;

	}

	break;

      case 'W':  /* Word Parameter */

	if (dirn == 1) {  /* A request ... */
	
	  /* Insert a word param */

	  WParam = GSHORT(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 2, "%s: %u (%04X)", (Name) ? Name : "Word Param", WParam, WParam);

	  pd_p_current += 2;

	  return 1;  /* That's it here ... we have dissected a param */

	}

	break;

      case 'i':  /* A long word is returned */

	if (dirn == 0) {

	  LParam = GWORD(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 4, "%s: %u (0x%08X)", (Name) ? Name : "Returned Long Word", LParam, LParam);

	  pd_p_current += 2;

	  return 1;

	}

	break;

      case 'D':  /* Double Word parameter */

	if (dirn == 1) {

	  LParam = GWORD(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 4, "%s: %u (0x%08X)", (Name) ? Name : "DWord Param", LParam, LParam);

	  pd_p_current += 4;
	  
	  return 1;  /* That's it here */

	}

	break;

      case 'g':  /* A byte or series of bytes is returned */

	if (dirn == 0) {
 
	  bc = get_byte_count(p_desc + p_offset);

	  proto_tree_add_text(tree, pd_p_current, bc, "%s%u: %s", (Name) ? Name : "B", (bc) ? bc : 1, format_text( pd + pd_p_current, (bc) ? bc : 1));

	  pd_p_current += (bc) ? bc : 1;

	  return 1;

	}

	break;

      case 'b':  /* A byte or series of bytes */

	if (dirn == 1) {

	  bc = get_byte_count(p_desc + p_offset);  /* This is not clean */

	  /*Bytes = g_malloc(bc + 1); / * Is this needed ? */

	  proto_tree_add_text(tree, pd_p_current, bc, "%s%u: %s", (Name) ? Name : "B", (bc) ? bc : 1, format_text(pd + pd_p_current, (bc) ? bc : 1));

	  pd_p_current += (bc) ? bc : 1;

	  return 1;  /* That's it here ... */

	}

	break;

      case 'O': /* A null pointer */

	if (dirn == 1) {

	  proto_tree_add_text(tree, pd_p_current, 0, "%s: Null Pointer", (Name) ? Name : "Unknown");

	  return 1;  /* That's it here */

	}

	break;

      case 'z': /* An AsciiZ string */

	if (dirn == 1) {

	  AsciiZ = pd + pd_p_current;

	  proto_tree_add_text(tree, pd_p_current, strlen(AsciiZ) + 1, "%s: %s", (Name) ? Name : "AsciiZ", AsciiZ);

	  pd_p_current += strlen(AsciiZ) + 1;

	  return 1;  /* That's it here ... */

	}

	break;

      case 'F': /* One or more pad bytes */

	if (dirn == 1) {

	  bc = get_byte_count(pd);

	  proto_tree_add_text(tree, pd_p_current, bc, "%s%u: %s", (Name) ? Name : "Pad", bc, format_text(pd + pd_p_current, bc));

	  pd_p_current += bc;

	  return 1;  /* That's it here */

	}

	break;

      case 'L': /* Receive buffer len: Short */

	if (dirn == 1) {

	  WParam = GSHORT(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 2, "%s: %u (0x%04X)", (Name) ? Name : "Receive Buffer Len", WParam, WParam);

	  pd_p_current += 2;

	  return 1;  /* That's it here ... */

	}

	break;

      case 's': /* Send buf ... */

	if (dirn == 1) {

	  need_data = 1;

	  LParam = GWORD(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 4, "%s: %u", (Name) ? Name : "Send Buffer Ptr", LParam);

	  pd_p_current += 4;

	  return 1;  /* That's it here ... */

	}

	break;

      case 'T':

	if (dirn == 1) {

	  WParam = GSHORT(pd, pd_p_current);

	  proto_tree_add_text(tree, pd_p_current, 2, "%s: %u", (Name) ? Name : "Send Buffer Len", WParam);

	  pd_p_current += 2;

	  return 1;

	}

	break;
	
      default:

	break;

      }

      break;

    case 1:   /* We are in the data area ... */

      
      break;
	
    }
  }

  return 0;

}



guint32 
dissect_pipe_lanman(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si,
	int max_data, int SMB_offset, int errcode, int dirn,
	const u_char *command, int DataOffset, int DataCount,
	int ParameterOffset, int ParameterCount) {
	

  guint32             loc_offset = SMB_offset + ParameterOffset;
  guint16             FunctionCode;
  guint16             Level;
  guint16             RecvBufLen;
  guint16             Flags;
  const char          *ParameterDescriptor;
  const char          *ReturnDescriptor;
  proto_tree          *lanman_tree = NULL, *flags_tree = NULL;
  proto_item          *ti;
  struct lanman_desc  *lanman;

  if (check_col(fd, COL_PROTOCOL))
    col_add_fstr(fd, COL_PROTOCOL, "LANMAN");

  if (dirn == 1) { /* The request side */

    FunctionCode = GSHORT(pd, loc_offset);

    si.request_val -> last_lanman_cmd = FunctionCode;

    switch (FunctionCode) {

    case NETSHAREENUM:   /* Never decode this at the moment ... */

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "NetShareEnum Request");

      }

      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + ParameterOffset, ParameterCount, NULL);
	lanman_tree = proto_item_add_subtree(ti, ett_lanman);

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Function Code: NetShareEnum");

      }

      loc_offset += 2;

      ParameterDescriptor = pd + loc_offset;

      si.request_val -> trans_response_seen = 0; 

      if (si.request_val -> last_param_descrip) g_free(si.request_val -> last_param_descrip);
      si.request_val -> last_param_descrip = g_malloc(strlen(ParameterDescriptor) + 1);
      if (si.request_val -> last_param_descrip)
	strcpy(si.request_val -> last_param_descrip, ParameterDescriptor);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, strlen(ParameterDescriptor) + 1, "Parameter Descriptor: %s", ParameterDescriptor);

      }

      loc_offset += strlen(ParameterDescriptor) + 1;

      ReturnDescriptor = pd + loc_offset;

      if (si.request_val -> last_data_descrip) g_free(si.request_val -> last_data_descrip);
      si.request_val -> last_data_descrip = g_malloc(strlen(ReturnDescriptor) + 1);
      if (si.request_val -> last_data_descrip)
	strcpy(si.request_val -> last_data_descrip, ReturnDescriptor);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, strlen(ReturnDescriptor) + 1, "Return Descriptor: %s", ReturnDescriptor);

      }

      loc_offset += strlen(ReturnDescriptor) + 1;

      Level = GSHORT(pd, loc_offset);
      
      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Detail Level: %u", Level);

      }

      loc_offset += 2;

      RecvBufLen = GSHORT(pd, loc_offset);
      
      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Receive Buffer Length: %u", RecvBufLen);

      }

      loc_offset += 2;
      
      break;

    case NETSERVERENUM2:  /* Process a NetServerEnum2 */

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "NetServerEnum2 %s", dirn ? "Request" : "Response");

      }

      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + ParameterOffset, ParameterCount, NULL);
	lanman_tree = proto_item_add_subtree(ti, ett_lanman);
      
	proto_tree_add_text(lanman_tree, loc_offset, 2, "Function Code: NetServerEnum2");

      }

      loc_offset += 2;

      ParameterDescriptor = pd + loc_offset;

      /* Now, save these for later */

      si.request_val -> trans_response_seen = 0; 

      if (si.request_val -> last_param_descrip) g_free(si.request_val -> last_param_descrip);
      si.request_val -> last_param_descrip = g_malloc(strlen(ParameterDescriptor) + 1);
      if (si.request_val -> last_param_descrip)
	strcpy(si.request_val -> last_param_descrip, ParameterDescriptor);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, strlen(ParameterDescriptor) + 1, "Parameter Descriptor: %s", ParameterDescriptor);

      }

      loc_offset += strlen(ParameterDescriptor) + 1;

      ReturnDescriptor = pd + loc_offset;

      if (si.request_val -> last_data_descrip) g_free(si.request_val -> last_data_descrip);

      si.request_val -> last_data_descrip = g_malloc(strlen(ReturnDescriptor) + 1);
      if (si.request_val -> last_data_descrip)
	strcpy(si.request_val -> last_data_descrip, ReturnDescriptor);
      
      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, strlen(ReturnDescriptor) + 1, "Return Descriptor: %s", ReturnDescriptor);

      }

      loc_offset += strlen(ReturnDescriptor) + 1;

      Level = GSHORT(pd, loc_offset);
      si.request_val -> last_level = Level;

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Info Detail Level: %u", Level);

      }

      loc_offset += 2;
      
      RecvBufLen = GSHORT(pd, loc_offset);
      
      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Receive Buffer Length: %u", RecvBufLen);

      }

      loc_offset += 2;

      Flags = GWORD(pd, loc_offset);

      if (tree) {

	ti = proto_tree_add_text(lanman_tree, loc_offset, 4, "Server Types Required: 0x%08X", Flags);
	flags_tree = proto_item_add_subtree(ti, ett_lanman_flags);
	dissect_server_flags(flags_tree, loc_offset, 4, Flags);

      }

      loc_offset += 4;

      return 1;
      break;

      default:   /* Just try to handle what is there ... */

      lanman = find_lanman(FunctionCode);

      if (check_col(fd, COL_INFO)) {

	if (lanman) { 
	  col_add_fstr(fd, COL_INFO, "%s Request", lanman -> lanman_name);
	}
	else {
	  col_add_fstr(fd, COL_INFO, "Unknown LANMAN Request: %u", FunctionCode);
	}
      }

      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + ParameterOffset, ParameterCount, NULL);
	lanman_tree = proto_item_add_subtree(ti, ett_lanman);

	if (lanman) {
	  proto_tree_add_text(lanman_tree, loc_offset, 2, "%s Request", lanman -> lanman_name);
	}
	else {
	  proto_tree_add_text(lanman_tree, loc_offset, 2, "Function Code: Unknown LANMAN Request: %u", FunctionCode);
	}

      }

      loc_offset += 2;

      ParameterDescriptor = pd + loc_offset;

      si.request_val -> trans_response_seen = 0; 

      if (si.request_val -> last_param_descrip) g_free(si.request_val -> last_param_descrip);
      si.request_val -> last_param_descrip = g_malloc(strlen(ParameterDescriptor) + 1);
      if (si.request_val -> last_param_descrip)
	strcpy(si.request_val -> last_param_descrip, ParameterDescriptor);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, strlen(ParameterDescriptor) + 1, "Parameter Descriptor: %s", ParameterDescriptor);

      }

      loc_offset += strlen(ParameterDescriptor) + 1;

      ReturnDescriptor = pd + loc_offset;

      if (si.request_val -> last_data_descrip) g_free(si.request_val -> last_data_descrip);
      si.request_val -> last_data_descrip = g_malloc(strlen(ReturnDescriptor) + 1);
      if (si.request_val -> last_data_descrip)
	strcpy(si.request_val -> last_data_descrip, ReturnDescriptor);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, strlen(ReturnDescriptor) + 1, "Return Descriptor: %s", ReturnDescriptor);

      }

      loc_offset += strlen(ReturnDescriptor) + 1;

      if (tree) {

	int i = 0;  /* Counter for names below */
	char *name = NULL;

	dissect_transact_engine_init(pd, ParameterDescriptor, ReturnDescriptor,SMB_offset, loc_offset, ParameterCount, DataOffset, DataCount);

	if (lanman) name = lanman -> req[i];  /* Must be OK ... */

	while (dissect_transact_next(pd, name, dirn, lanman_tree))
	  if (name) name = lanman -> req[++i];
      }

      break;
    
    }
  }
  else {  /* Dirn == 0, response */
    guint16          Status;
    guint16          Convert;
    guint16          EntCount;
    guint16          AvailCount;
    guint32          loc_offset = 0;
    int              i;
    proto_tree       *server_tree = NULL, *flags_tree = NULL, *share_tree = NULL;

    FunctionCode = si.request_val -> last_lanman_cmd;

    /*
     * If we have already seen the response to this transact, simply
     * record it as a continuation ...
     */

/*$$    printf("TransResponseSeen = %u\n", si.request_val -> trans_response_seen);
*/
    if (si.request_val -> trans_response_seen == 1) {

      if (check_col(fd, COL_INFO)) {
	  col_add_fstr(fd, COL_INFO, "Transact Continuation");
      }
      
      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + DataOffset, END_OF_FRAME, NULL);

	lanman_tree = proto_item_add_subtree(ti, ett_lanman);

	proto_tree_add_text(lanman_tree, loc_offset, END_OF_FRAME, "Payload: %s", format_text(pd + SMB_offset + DataOffset, END_OF_FRAME));

      }

      return 1;


    } 

    si.request_val -> trans_response_seen = 1; 

    switch (FunctionCode) {

    case NETSHAREENUM:

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "NetShareEnum Response");

      }

      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + ParameterOffset, END_OF_FRAME, NULL);
	lanman_tree = proto_item_add_subtree(ti, ett_lanman);
      
	proto_tree_add_text(lanman_tree, loc_offset, 0, "Function Code: NetShareEnum");

      }

      si.request_val -> trans_response_seen = 1; 

      loc_offset = SMB_offset + ParameterOffset;

      Status = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Status: %u", Status);

      }

      loc_offset += 2;

      Convert = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Convert: %u", Convert);

      }

      loc_offset += 2;

      EntCount = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Entry Count: %u", EntCount);

      }

      loc_offset += 2;

      AvailCount = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Available Entries: %u", AvailCount);

      }

      loc_offset += 2;

      if (tree) {

	ti = proto_tree_add_text(lanman_tree, loc_offset, AvailCount * 20, "Available Shares");

	share_tree = proto_item_add_subtree(ti, ett_lanman_shares);

      }

      for (i = 1; i <= EntCount; i++) {
	const gchar *Share = pd + loc_offset;
	guint32     Flags;
	const gchar *Comment;
	proto_tree  *share = NULL;
	proto_item  *ti = NULL;

	if (tree) {

	  ti = proto_tree_add_text(share_tree, loc_offset, 20, "Share %s", Share);
	  share = proto_item_add_subtree(ti, ett_lanman_share);


	}

	if (tree) {
	  
	  proto_tree_add_text(share, loc_offset, 13, "Share Name: %s", Share);

	}

	loc_offset += 13;

	while (loc_offset % 4)
	  loc_offset += 1;  /* Align to a word boundary ... */

	Flags = GSHORT(pd, loc_offset);

	if (tree) {

	  proto_tree_add_text(share, loc_offset, 2, "Share Type: %u", Flags);

	}

	loc_offset += 2;

	Comment = pd + SMB_offset + DataOffset + (GWORD(pd, loc_offset) & 0xFFFF) - Convert;

	if (tree) {

	  proto_tree_add_text(share, loc_offset, 4, "Share Comment: %s", Comment);

	}

	loc_offset += 4;

      }

      break;

    case NETSERVERENUM2:

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "NetServerEnum2 %s", dirn ? "Request" : "Response");

      }

      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + ParameterOffset, END_OF_FRAME, NULL);
	lanman_tree = proto_item_add_subtree(ti, ett_lanman);
      
	proto_tree_add_text(lanman_tree, loc_offset, 2, "Function Code: NetServerEnum2");

      }

      loc_offset = SMB_offset + ParameterOffset;
      Status = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Status: %u", Status);

      }

      loc_offset += 2;

      Convert = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Convert: %u", Convert);

      }

      loc_offset += 2;

      EntCount = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Entry Count: %u", EntCount);

      }

      loc_offset += 2;

      AvailCount = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Available Entries: %u", AvailCount);

      }

      loc_offset += 2;

      if (tree) {

	ti = proto_tree_add_text(lanman_tree, loc_offset, 26 * AvailCount, "Servers");
	if (ti == NULL) { 

	  printf("Null value returned from proto_tree_add_text\n");
	  exit(1);

	}

	server_tree = proto_item_add_subtree(ti, ett_lanman_servers);

      }

      /* Make sure we don't go past the end of the capture buffer */

      for (i = 1; (i <= EntCount) && ((pi.captured_len - loc_offset) > 16); i++) {
	const gchar *Server = pd + loc_offset;
	gint8       ServerMajor;
	guint       ServerMinor;
	guint32     ServerFlags;
	const gchar *Comment;
	proto_tree  *server = NULL;
	proto_item  *ti;

	if (tree) {

	  ti = proto_tree_add_text(server_tree, loc_offset, 
				   (si.request_val -> last_level) ? 26 : 16,
				   "Server %s", Server);
	  server = proto_item_add_subtree(ti, ett_lanman_server);


	}

	if (tree) {
	  
	  proto_tree_add_text(server, loc_offset, 16, "Server Name: %s", Server);

	}

	loc_offset += 16;

	if (si.request_val -> last_level) { /* Print out the rest of the info */

	  ServerMajor = GBYTE(pd, loc_offset);

	  if (tree) {

	    proto_tree_add_text(server, loc_offset, 1, "Major Version: %u", ServerMajor);

	  }

	  loc_offset += 1;

	  ServerMinor = GBYTE(pd, loc_offset);

	  if (tree) {

	    proto_tree_add_text(server, loc_offset, 1, "Minor Version: %u", ServerMinor);

	  }

	  loc_offset += 1;

	  ServerFlags = GWORD(pd, loc_offset);

	  if (tree) {

	    ti = proto_tree_add_text(server, loc_offset, 4, "Server Type: 0x%08X", ServerFlags);
	    flags_tree = proto_item_add_subtree(ti, ett_lanman_flags);
	    dissect_server_flags(flags_tree, loc_offset, 4, ServerFlags);

	  }

	  loc_offset += 4;

	  Comment = pd + SMB_offset + DataOffset + (GWORD(pd, loc_offset) & 0xFFFF) - Convert;

	  if (tree) {

	    proto_tree_add_text(server, loc_offset, 4, "Server Comment: %s", Comment);

	  }

	  loc_offset += 4;

	}

      }

      break;

    default:

      lanman = find_lanman(si.request_val -> last_lanman_cmd);

      if (check_col(fd, COL_INFO)) {

	if (lanman) {
	  col_add_fstr(fd, COL_INFO, "%s Response", lanman -> lanman_name);
	}
	else {
	  col_add_fstr(fd, COL_INFO, "Unknown LANMAN Response: %u", FunctionCode);
	}
      }

      if (tree) {

	ti = proto_tree_add_item(parent, proto_smb_lanman, SMB_offset + ParameterOffset, END_OF_FRAME, NULL);
	lanman_tree = proto_item_add_subtree(ti, ett_lanman);
	if (lanman) {
	  proto_tree_add_text(lanman_tree, 0, 0, "%s Response", lanman -> lanman_name);
	}
	else {
	  proto_tree_add_text(lanman_tree, loc_offset, 0, "Function Code: Unknown LANMAN Response: %u", FunctionCode);
	}
      }

      loc_offset = SMB_offset + ParameterOffset;

      Status = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Status: %u", Status);

      }

      loc_offset += 2;

      Convert = GSHORT(pd, loc_offset);

      if (tree) {

	proto_tree_add_text(lanman_tree, loc_offset, 2, "Convert: %u", Convert);

      }

      loc_offset += 2;

      if (tree) {

	int i = 0;
	char *name = NULL;

	dissect_transact_engine_init(pd, si.request_val -> last_param_descrip, si.request_val -> last_data_descrip, SMB_offset, loc_offset, ParameterCount, DataOffset, DataCount);

	if (lanman) name = lanman -> resp[i];
	  
	while (dissect_transact_next(pd, name, dirn, lanman_tree))
	  if (name) name = lanman -> resp[++i];
	  
      }

      return 1;
      break;

    }

  }

  return 0;

}

guint32
dissect_pipe_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn, const u_char *command, int DataOffset, int DataCount, int ParameterOffset, int ParameterCount)
{

  if (strcmp(command, "LANMAN") == 0) { /* Try to decode a LANMAN */

    return dissect_pipe_lanman(pd, offset, fd, parent, tree, si, max_data, SMB_offset, errcode, dirn, command, DataOffset, DataCount, ParameterOffset, ParameterCount);

  }

  return 0;

}




void
register_proto_smb_pipe( void){


	static gint *ett[] = {

		&ett_lanman,
		&ett_lanman_servers,
		&ett_lanman_server,
		&ett_lanman_shares,
		&ett_lanman_share,
		&ett_lanman_flags
	};


    	proto_smb_lanman = proto_register_protocol(
    		"Microsoft Windows Lanman Protocol", "lanman");

	proto_register_subtree_array(ett, array_length(ett));
}
