/* packet-smb-browse.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb-browse.c,v 1.6 2000/11/19 08:54:06 guy Exp $
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

static int proto_smb_browse = -1;

static gint ett_browse = -1;
static gint ett_browse_flags = -1;
static gint ett_browse_election_criteria = -1;
static gint ett_browse_election_os = -1;
static gint ett_browse_election_desire = -1;



char *browse_commands[] = 
{ "Error, No such command!",       /* Value 0 */
  "Host Announcement",             /* Value 1 */
  "Request Announcement",          /* Value 2 */
  "Error, No such command!",       /* Value 3 */
  "Error, No such command!",       /* Value 4 */
  "Error, No such command!",       /* Value 5 */
  "Error, No such command!",       /* Value 6 */
  "Error, No such command!",       /* Value 7 */
  "Browser Election Request",      /* Value 8 */
  "Get Backup List Request",       /* Value 9 */
  "Get Backup List Response",      /* Value 10 */
  "Become Backup Browser",         /* Value 11 */
  "Domain/Workgroup Announcement", /* Value 12 */
  "Master Announcement",           /* Value 13 */
  "Error! No such command",        /* Value 14 */
  "Local Master Announcement"      /* Value 15 */
};

#define HOST_ANNOUNCE        1
#define REQUEST_ANNOUNCE     2
#define BROWSER_ELECTION     8
#define GETBACKUPLISTREQ     9
#define GETBACKUPLISTRESP   10
#define BECOMEBACKUPBROWSER 11
#define DOMAINANNOUNCEMENT  12
#define MASTERANNOUNCEMENT  13
#define LOCALMASTERANNOUNC  15

char *svr_types[32] = {
  "Workstation",
  "Server",
  "SQL Server",
  "Domain Controller",
  "Backup Controller",
  "Time Source",
  "Apple Server",
  "Novell Server",
  "Domain Member Server",
  "Print Queue Server",
  "Dialin Server",
  "Xenix Server",
  "NT Workstation",
  "Windows for Workgroups",
  "Unknown Server - FIXME",
  "NT Server",
  "Potential Browser",
  "Backup Browser",
  "Master Browser",
  "Domain Master Browser",
  "OSF",
  "VMS",
  "Windows 95 or above",
  "Unused",
  "Unused",
  "Unused",
  "Unused",
  "Unused",
  "Unused",
  "Unused",
  "Local List Only",
  "Domain Enum"
};

guint32 
dissect_mailslot_browse(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset, int errcode, int dirn, const u_char *command, int DataOffset, int DataCount)
{
  guint8               OpCode;
  guint8               UpdateCount;
  guint8               VersionMajor;
  guint8               VersionMinor;
  guint32              Periodicity;
  guint32              ServerType;
  guint16              SigConstant;
  guint32              Token;
  guint8               BackupServerCount;
  guint8               Flags;
  guint32              MBZ;
  guint8               ElectionVersion;
  guint32              ElectionCriteria;
  guint8               ElectionOS;
  guint8               ElectionDesire;
  guint16              ElectionRevision;
  guint32              ServerUpTime;
  const char           *ServerName;
  const char           *ServerComment;
  proto_tree           *browse_tree = NULL, *flags_tree = NULL, 
                       *OSflags = NULL, *DesireFlags = NULL;
  proto_item           *ti, *ec;
  guint32              loc_offset = DataOffset, count = 0;
  int                  i;

  if (!proto_is_protocol_enabled(proto_smb_browse))
    return 0;

  if (check_col(fd, COL_PROTOCOL))
    col_set_str(fd, COL_PROTOCOL, "BROWSER");

  if (check_col(fd, COL_INFO)) /* Put in something, and replace it later */
    col_set_str(fd, COL_INFO, "Browse Announcement");

  /*
   * Now, decode the browse request 
   */

  OpCode = GBYTE(pd, loc_offset);

  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, (OpCode > (sizeof(browse_commands)/sizeof(char *))) ? "Error, No Such Command:%u" : browse_commands[OpCode], OpCode);
    
  if (tree) {  /* Add the browse tree */

    ti = proto_tree_add_item(parent, proto_smb_browse, NullTVB, DataOffset, DataCount, FALSE);
    browse_tree = proto_item_add_subtree(ti, ett_browse);

    proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "OpCode: %s", (OpCode > (sizeof(browse_commands)/sizeof(char *))) ? "Error, No Such Command" : browse_commands[OpCode]);

  }

  loc_offset += 1;    /* Skip the OpCode */

  switch (OpCode) {

  case DOMAINANNOUNCEMENT:
  case LOCALMASTERANNOUNC:
  case HOST_ANNOUNCE:

    UpdateCount = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Update Count: %u", UpdateCount);

    }

    loc_offset += 1;  /* Skip the Update Count */

    Periodicity = GWORD(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 4, "Update Periodicity: %u Sec", Periodicity/1000 );

    }

    loc_offset += 4;

    ServerName = pd + loc_offset;

    if (check_col(fd, COL_INFO)) {

      col_append_fstr(fd, COL_INFO, " %s", ServerName);

    }

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 16, (OpCode == DOMAINANNOUNCEMENT) ? "Domain/WorkGroup: %s": "Host Name: %s", ServerName);

    }

    loc_offset += 16;

    VersionMajor = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Major Version: %u", VersionMajor);

    }

    loc_offset += 1;

    VersionMinor = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Minor Version: %u", VersionMinor);

    }

    loc_offset += 1;

    ServerType = GWORD(pd, loc_offset);

    if (check_col(fd, COL_INFO)) {

      /* Append the type(s) of the system to the COL_INFO line ... */

      for (i = 0; i < 32; i++) {

	if (ServerType & (1 << i) && (strcmp("Unused", svr_types[i]) != 0))
	    col_append_fstr(fd, COL_INFO, ", %s", svr_types[i]);
	
      }
      
    }

    if (tree) {

      ti = proto_tree_add_text(browse_tree, NullTVB, loc_offset, 4, "Server Type: 0x%04x", ServerType);
      flags_tree = proto_item_add_subtree(ti, ett_browse_flags);
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0001, 32, "Workstation", "Not Workstation"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0002, 32, "Server", "Not Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0004, 32, "SQL Server", "Not SQL Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0008, 32, "Domain Controller", "Not Domain Controller"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0010, 32, "Backup Controller", "Not Backup Controller"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0020, 32, "Time Source", "Not Time Source"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0040, 32, "Apple Server", "Not Apple Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0080, 32, "Novell Server", "Not Novell Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0100, 32, "Domain Member Server", "Not Domain Member Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0200, 32, "Print Queue Server", "Not Print Queue Server"));      
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0400, 32, "Dialin Server", "Not Dialin Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x0800, 32, "Xenix Server", "Not Xenix Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x1000, 32, "NT Workstation", "Not NT Workstation"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x2000, 32, "Windows for Workgroups", "Not Windows for Workgroups"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x8000, 32, "NT Server", "Not NT Server"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x10000, 32, "Potential Browser", "Not Potential Browser"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x20000, 32, "Backup Browser", "Not Backup Browser"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x40000, 32, "Master Browser", "Not Master Browser"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x80000, 32, "Domain Master Browser", "Not Domain Master Browser"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x100000, 32, "OSF", "Not OSF"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x200000, 32, "VMS", "Not VMS"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x400000, 32, "Windows 95 or above", "Not Windows 95 or above"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x40000000, 32, "Local List Only", "Not Local List Only"));
      proto_tree_add_text(flags_tree, NullTVB, loc_offset, 4, "%s",
			  decode_boolean_bitfield(ServerType, 0x80000000, 32, "Domain Enum", "Not Domain Enum"));
    }
    loc_offset += 4;
    
    ElectionVersion = GSHORT(pd, loc_offset);
    
    if (tree) {
      
      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 2, "Election Version: %u", ElectionVersion);

    }

    loc_offset += 2;

    SigConstant = GSHORT(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 2, "Signature: %u (0x%04X)", SigConstant, SigConstant);

    }

    loc_offset += 2;

    ServerComment = pd + loc_offset;

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, strlen(ServerComment) + 1, "Host Comment: %s", ServerComment);

    }

    break;

  case REQUEST_ANNOUNCE:

    Flags = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Unused Flags: %u", Flags);

    }

    loc_offset += 1;

    ServerName = pd + loc_offset;

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, strlen(ServerName) + 1, "Send List To: %s", ServerName);

    }

    break;

  case BROWSER_ELECTION:

    ElectionVersion = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Election Version = %u", ElectionVersion);

    }

    loc_offset += 1;

    ElectionCriteria = GWORD(pd, loc_offset);
    ElectionOS       = GBYTE(pd, loc_offset + 3);
    ElectionRevision = GSHORT(pd, loc_offset + 1);
    ElectionDesire   = GBYTE(pd, loc_offset);

    if (tree) {

      ti = proto_tree_add_text(browse_tree, NullTVB, loc_offset, 4, "Election Criteria = %u (0x%08X)", ElectionCriteria, ElectionCriteria);

      ec = proto_item_add_subtree(ti, ett_browse_election_criteria);

      ti = proto_tree_add_text(ec, NullTVB, loc_offset + 3, 1, "Election OS Summary: %u (0x%02X)", ElectionOS, ElectionOS);

      OSflags = proto_item_add_subtree(ti, ett_browse_election_os);

      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			    decode_boolean_bitfield(ElectionOS, 0x01, 8, "Windows for Workgroups", "Not Windows for Workgroups"));
      
      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x02, 8, "Unknown", "Not used"));

      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x04, 8, "Unknown", "Not used"));

      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x08, 8, "Unknown", "Not used"));
      
      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x10, 8, "Windows NT Workstation", "Not Windows NT Workstation"));
      
      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x20, 8, "Windows NT Server", "Not Windows NT Server"));

      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x40, 8, "Unknown", "Not used"));

      proto_tree_add_text(OSflags, NullTVB, loc_offset + 3, 1, "%s",
			  decode_boolean_bitfield(ElectionOS, 0x80, 8, "Unknown", "Not used"));

      proto_tree_add_text(ec, NullTVB, loc_offset + 1, 2, "Election Revision: %u (0x%04X)", ElectionRevision, ElectionRevision);

      ti = proto_tree_add_text(ec, NullTVB, loc_offset, 1, "Election Desire Summary: %u (0x%02X)", ElectionDesire, ElectionDesire);

      DesireFlags = proto_item_add_subtree(ti, ett_browse_election_desire);

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x01, 8, "Backup Browse Server", "Not Backup Browse Server"));
      
      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x02, 8, "Standby Browse Server", "Not Standby Browse Server"));

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x04, 8, "Master Browser", "Not Master Browser"));

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x08, 8, "Domain Master Browse Server", "Not Domain Master Browse Server"));

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x10, 8, "Unknown", "Not used"));

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x20, 8, "WINS Client", "Not WINS Client"));

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x40, 8, "Unknown", "Not used"));

      proto_tree_add_text(DesireFlags, NullTVB, loc_offset, 1, "%s",
			  decode_boolean_bitfield(ElectionDesire, 0x80, 8, "Windows NT Advanced Server", "Not Windows NT Advanced Server"));

    }

    loc_offset += 4;

    ServerUpTime = GWORD(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 4, "Server Up Time: %u Sec (%ums)", ServerUpTime/1000, ServerUpTime);

    }

    loc_offset += 4;

    MBZ = GWORD(pd, loc_offset);

    loc_offset += 4;

    ServerName = pd + loc_offset;

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, strlen(ServerName) + 1, "Election Server Name: %s", ServerName);

    }

    break;

  case GETBACKUPLISTREQ:

    BackupServerCount = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Backup List Requested Count: %u", BackupServerCount);

    }

    loc_offset += 1;

    Token = GWORD(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 4, "Backup Request Token: %u", Token);

    }

    break;

  case GETBACKUPLISTRESP:

    BackupServerCount = GBYTE(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 1, "Backup Server Count: %u", BackupServerCount);

    }

    loc_offset += 1;

    Token = GWORD(pd, loc_offset);

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, 4, "Backup Response Token: %u", Token);

    }

    loc_offset += 4;

    ServerName = pd + loc_offset;

    for (count = 1; count <= BackupServerCount; count++) {

      if (tree) {

	proto_tree_add_text(browse_tree, NullTVB, loc_offset, strlen(ServerName) + 1, "Backup Server: %s", ServerName);

      }

      loc_offset += strlen(ServerName) + 1;

      ServerName = pd + loc_offset;

    }

    break;

  case BECOMEBACKUPBROWSER:

    ServerName = pd + loc_offset;

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, strlen(ServerName) + 1, "Browser to Promote: %s", ServerName);

    }

    break;

  case MASTERANNOUNCEMENT:

    ServerName = pd + loc_offset;

    if (tree) {

      proto_tree_add_text(browse_tree, NullTVB, loc_offset, strlen(ServerName) + 1, "Server Name: %s", ServerName);

    }

    break;

  default:
    break;
  }
  
  return 1;  /* Success */

}


void
register_proto_smb_browse( void){


	static gint *ett[] = {
		&ett_browse,
		&ett_browse_flags,
		&ett_browse_election_criteria,
		&ett_browse_election_os,
		&ett_browse_election_desire
	};

    	proto_smb_browse = proto_register_protocol("Microsoft Windows Browser Protocol", "browser");           

	proto_register_subtree_array(ett, array_length(ett));          
}
