/* packet-smb.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb.c,v 1.6 1999/05/11 00:00:40 sharpe Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include <arpa/tftp.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "etypes.h"
#include "smb.h"
#include "alignment.h"

extern packet_info pi;

char *decode_smb_name(unsigned char);
void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, int, int);

char *SMB_names[256] = {
  "unknown-0x00",
  "unknown-0x01",
  "SMBopen",
  "SMBcreate",
  "SMBclose",
  "SMBflush",
  "SMBunlink",
  "SMBmv",
  "SMBgetatr",
  "SMBsetatr",
  "SMBread",
  "SMBwrite",
  "SMBlock",
  "SMBunlock",
  "SMBctemp",
  "SMBmknew",
  "SMBchkpth",
  "SMBexit",
  "SMBlseek",
  "SMBlockread",
  "SMBwriteunlock",
  "unknown-0x15",
  "unknown-0x16",
  "unknown-0x17",
  "unknown-0x18",
  "unknown-0x19",
  "SMBreadBraw",
  "SMBreadBmpx",
  "SMBreadBs",
  "SMBwriteBraw",
  "SMBwriteBmpx",
  "SMBwriteBs",
  "SMBwriteC",
  "unknown-0x21",
  "SMBsetattrE",
  "SMBgetattrE",
  "SMBlockingX",
  "SMBtrans",
  "SMBtranss",
  "SMBioctl",
  "SMBioctls",
  "SMBcopy",
  "SMBmove",
  "SMBecho",
  "SMBwriteclose",
  "SMBopenX",
  "SMBreadX",
  "SMBwriteX",
  "unknown-0x30",
  "unknown-0x31",
  "unknown-0x32",
  "unknown-0x33",
  "unknown-0x34",
  "unknown-0x35",
  "unknown-0x36",
  "unknown-0x37",
  "unknown-0x38",
  "unknown-0x39",
  "unknown-0x3A",
  "unknown-0x3B",
  "unknown-0x3C",
  "unknown-0x3D",
  "unknown-0x3E",
  "unknown-0x3F",
  "unknown-0x40",
  "unknown-0x41",
  "unknown-0x42",
  "unknown-0x43",
  "unknown-0x44",
  "unknown-0x45",
  "unknown-0x46",
  "unknown-0x47",
  "unknown-0x48",
  "unknown-0x49",
  "unknown-0x4A",
  "unknown-0x4B",
  "unknown-0x4C",
  "unknown-0x4D",
  "unknown-0x4E",
  "unknown-0x4F",
  "unknown-0x50",
  "unknown-0x51",
  "unknown-0x52",
  "unknown-0x53",
  "unknown-0x54",
  "unknown-0x55",
  "unknown-0x56",
  "unknown-0x57",
  "unknown-0x58",
  "unknown-0x59",
  "unknown-0x5A",
  "unknown-0x5B",
  "unknown-0x5C",
  "unknown-0x5D",
  "unknown-0x5E",
  "unknown-0x5F",
  "unknown-0x60",
  "unknown-0x61",
  "unknown-0x62",
  "unknown-0x63",
  "unknown-0x64",
  "unknown-0x65",
  "unknown-0x66",
  "unknown-0x67",
  "unknown-0x68",
  "unknown-0x69",
  "unknown-0x6A",
  "unknown-0x6B",
  "unknown-0x6C",
  "unknown-0x6D",
  "unknown-0x6E",
  "unknown-0x6F",
  "SMBtcon",
  "SMBtdis",
  "SMBnegprot",
  "SMBsesssetupX",
  "unknown-0x74",
  "SMBtconX",
  "unknown-0x76",
  "unknown-0x77",
  "unknown-0x78",
  "unknown-0x79",
  "unknown-0x7A",
  "unknown-0x7B",
  "unknown-0x7C",
  "unknown-0x7D",
  "unknown-0x7E",
  "unknown-0x7F",
  "SMBdskattr",
  "SMBsearch",
  "SMBffirst",
  "SMBfunique",
  "SMBfclose",
  "unknown-0x85",
  "unknown-0x86",
  "unknown-0x87",
  "unknown-0x88",
  "unknown-0x89",
  "unknown-0x8A",
  "unknown-0x8B",
  "unknown-0x8C",
  "unknown-0x8D",
  "unknown-0x8E",
  "unknown-0x8F",
  "unknown-0x90",
  "unknown-0x91",
  "unknown-0x92",
  "unknown-0x93",
  "unknown-0x94",
  "unknown-0x95",
  "unknown-0x96",
  "unknown-0x97",
  "unknown-0x98",
  "unknown-0x99",
  "unknown-0x9A",
  "unknown-0x9B",
  "unknown-0x9C",
  "unknown-0x9D",
  "unknown-0x9E",
  "unknown-0x9F",
  "unknown-0xA0",
  "unknown-0xA1",
  "unknown-0xA2",
  "unknown-0xA3",
  "unknown-0xA4",
  "unknown-0xA5",
  "unknown-0xA6",
  "unknown-0xA7",
  "unknown-0xA8",
  "unknown-0xA9",
  "unknown-0xAA",
  "unknown-0xAB",
  "unknown-0xAC",
  "unknown-0xAD",
  "unknown-0xAE",
  "unknown-0xAF",
  "unknown-0xB0",
  "unknown-0xB1",
  "unknown-0xB2",
  "unknown-0xB3",
  "unknown-0xB4",
  "unknown-0xB5",
  "unknown-0xB6",
  "unknown-0xB7",
  "unknown-0xB8",
  "unknown-0xB9",
  "unknown-0xBA",
  "unknown-0xBB",
  "unknown-0xBC",
  "unknown-0xBD",
  "unknown-0xBE",
  "unknown-0xBF",
  "SMBsplopen",
  "SMBsplwr",
  "SMBsplclose",
  "SMBsplretq",
  "unknown-0xC4",
  "unknown-0xC5",
  "unknown-0xC6",
  "unknown-0xC7",
  "unknown-0xC8",
  "unknown-0xC9",
  "unknown-0xCA",
  "unknown-0xCB",
  "unknown-0xCC",
  "unknown-0xCD",
  "unknown-0xCE",
  "unknown-0xCF",
  "SMBsends",
  "SMBsendb",
  "SMBfwdname",
  "SMBcancelf",
  "SMBgetmac",
  "SMBsendstrt",
  "SMBsendend",
  "SMBsendtxt",
  "unknown-0xD8",
  "unknown-0xD9",
  "unknown-0xDA",
  "unknown-0xDB",
  "unknown-0xDC",
  "unknown-0xDD",
  "unknown-0xDE",
  "unknown-0xDF",
  "unknown-0xE0",
  "unknown-0xE1",
  "unknown-0xE2",
  "unknown-0xE3",
  "unknown-0xE4",
  "unknown-0xE5",
  "unknown-0xE6",
  "unknown-0xE7",
  "unknown-0xE8",
  "unknown-0xE9",
  "unknown-0xEA",
  "unknown-0xEB",
  "unknown-0xEC",
  "unknown-0xED",
  "unknown-0xEE",
  "unknown-0xEF",
  "unknown-0xF0",
  "unknown-0xF1",
  "unknown-0xF2",
  "unknown-0xF3",
  "unknown-0xF4",
  "unknown-0xF5",
  "unknown-0xF6",
  "unknown-0xF7",
  "unknown-0xF8",
  "unknown-0xF9",
  "unknown-0xFA",
  "unknown-0xFB",
  "unknown-0xFC",
  "unknown-0xFD",
  "SMBinvalid",
  "unknown-0xFF"
};

void 
dissect_unknown_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data, int dirn)
{

  if (tree) {

    proto_tree_add_item(tree, offset, END_OF_FRAME, "Data (%u bytes)", 
			END_OF_FRAME); 

  }

}

/*
 * Each dissect routine is passed an offset to wct and works from there 
 */

void
dissect_tcon_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data, int dirn)

{
  guint8      wct, andxcmd;
  guint16     andxoffs, flags, passwdlen, bcc, optionsup;
  const char  *str;
  proto_tree  *flags_tree;
  proto_item  *ti;

  wct = pd[offset];

  /* Now figure out what format we are talking about, 2, 3, or 4 response
   * words ...
   */

  if (!((dirn == 1) && (wct == 4)) && !((dirn == 0) && (wct == 2)) &&
      !((dirn == 0) && (wct == 3))) {

    if (tree) {

      proto_tree_add_item(tree, offset, 1, "Invalid TCON_ANDX format. WCT should be 2, 3, or 4 ..., not %u", wct);

      proto_tree_add_item(tree, offset, END_OF_FRAME, "Data");

      return;

    }
    
  }

  if (tree) {

    proto_tree_add_item(tree, offset, 1, "Word Count (WCT): %u", wct);

  }

  offset += 1;

  andxcmd = pd[offset];

  if (tree) {

    proto_tree_add_item(tree, offset, 1, "Next Command: %s",
			(andxcmd == 0xFF) ? "No further commands":
			decode_smb_name(andxcmd));
		
    proto_tree_add_item(tree, offset + 1, 1, "Reserved (MBZ): %u", pd[offset+1]);

  }

  offset += 2;

  andxoffs = GSHORT(pd, offset);

  if (tree) {

    proto_tree_add_item(tree, offset, 2, "Offset to next command: %u", andxoffs);

  }

  offset += 2;

  switch (wct) {

  case 4:

    flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_item(tree, offset, 2, "Additional Flags: 0x%02x", flags);
      flags_tree = proto_tree_new();
      proto_item_add_subtree(ti, flags_tree, ETT_SMB_AFLAGS);
      proto_tree_add_item(flags_tree, offset, 2, "%s", 
			  decode_boolean_bitfield(flags, 0x01, 16,
						  "Disconnect TID",
						  "Don't disconnect TID"));

    }

    offset += 2;

    passwdlen = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Password Length: %u", passwdlen);

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str) + 1, "Password: %s", str);

    }

    offset += strlen(str) + 1;

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str) + 1, "Path: %s", str);

    }

    offset += strlen(str) + 1;

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str) + 1, "Service: %s", str);

    }

    break;

  case 2:

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str) + 1, "Service Type: %s",
			  str);

    }

    offset += strlen(str) + 1;

    break;

  case 3:

    optionsup = GSHORT(pd, offset);

    if (tree) {  /* Should break out the bits */

      proto_tree_add_item(tree, offset, 2, "Optional Support: 0x%04x", 
			  optionsup);

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str) + 1, "Service: %s", str);

    }

    offset += strlen(str) + 1;

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str) + 1, "Native File System: %s", str);

    }

    offset += strlen(str) + 1;

    
    break;

  default:

  }

  if (andxcmd != 0xFF) /* Process that next command ... ??? */

    (dissect[andxcmd])(pd, offset, fd, tree, max_data - offset, dirn);

}

void 
dissect_negprot_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data, int dirn)
{
  guint8        wct, enckeylen;
  guint16       bcc, mode, rawmode, dialect;
  guint32       caps;
  proto_tree    *dialects = NULL, *mode_tree, *caps_tree, *rawmode_tree;
  proto_item    *ti;
  const char    *str;

  wct = pd[offset];    /* Should be 0, 1 or 13 or 17, I think */

  if (!((wct == 0) && (dirn == 1)) && !((wct == 1) && (dirn == 0)) &&
      !((wct == 13) && (dirn == 0)) && !((wct == 17) && (dirn == 0))) {
    if (tree) {

      proto_tree_add_item(tree, offset, 1, "Invalid Negotiate Protocol format. WCT should be zero or 1 or 13 or 17 ..., not %u", wct);

      proto_tree_add_item(tree, offset, END_OF_FRAME, "Data");

      return;
    }
  }

  if (tree) {

    proto_tree_add_item(tree, offset, 1, "Word Count (WCT): %d", wct);

  }

  offset += 1; 

  /* Now decode the various formats ... */

  switch (wct) {

  case 0:     /* A request */

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    if (tree) {

      ti = proto_tree_add_item(tree, offset, END_OF_FRAME, "Dialects");
      dialects = proto_tree_new();
      proto_item_add_subtree(ti, dialects, ETT_SMB_DIALECTS);

    }

    while (END_OF_FRAME > 0) {
      const char *str;

      if (tree) {

	proto_tree_add_item(dialects, offset, 1, "Dialect Marker: %d", pd[offset]);

      }

      offset += 1;

      str = pd + offset;

      if (tree) {

	proto_tree_add_item(dialects, offset, strlen(str)+1, "Dialect: %s", str);

      }

      offset += strlen(str) + 1;

    }
    break;

  case 1:     /* PC NETWORK PROGRAM 1.0 */

    dialect = GSHORT(pd, offset);

    if (tree) {  /* Hmmmm, what if none of the dialects is recognized */

      if (dialect == 0xFFFF) { /* Server didn't like them dialects */

	proto_tree_add_item(tree, offset, 2, "Dialect Index: %u, Supplied dialects not recognized");

      }
      else {

	proto_tree_add_item(tree, offset, 2, "Dialect Index: %u, PC NETWORK PROTGRAM 1.0", dialect);

      }

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    break;

  case 13:    /* Greater than Core and up to and incl LANMAN2.1  */

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Dialect Index: %d, Greater than CORE PROTOCOL and up to LANMAN2.1", GSHORT(pd, offset));

    }

    /* Much of this is similar to response 17 below */

    offset += 2;

    mode = GBYTE(pd, offset);

    if (tree) {

      ti = proto_tree_add_item(tree, offset, 2, "Security Mode: 0x%04x", mode);
      mode_tree = proto_tree_new();
      proto_item_add_subtree(ti, mode_tree, ETT_SMB_MODE);
      proto_tree_add_item(mode_tree, offset, 2, "%s",
			  decode_boolean_bitfield(mode, 0x0001, 16,
						  "Security  = User",
						  "Security  = Share"));
      proto_tree_add_item(mode_tree, offset, 2, "%s",
			  decode_boolean_bitfield(mode, 0x0002, 16,
						  "Passwords = Encrypted",
						  "Passwords = Plaintext"));

    }

    offset += 1;

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Max multiplex count: %d", GSHORT(pd, offset));

    }
    
    offset += 2;

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Max vcs:             %d", GSHORT(pd, offset));

    }

    offset += 2;

    rawmode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_item(tree, offset, 2, "Raw Mode: 0x%04x", rawmode);
      rawmode_tree = proto_tree_new();
      proto_item_add_subtree(ti, rawmode_tree, ETT_SMB_RAWMODE);
      proto_tree_add_item(rawmode_tree, offset, 2, "%s",
			  decode_boolean_bitfield(rawmode, 0x01, 16,
						  "Read Raw supported",
						  "Read Raw not supported"));
      proto_tree_add_item(rawmode_tree, offset, 2, "%s",
			  decode_boolean_bitfield(rawmode, 0x02, 16,
						  "Write Raw supported",
						  "Write Raw not supported"));

    }

    offset += 2;

    /* Now the server time, two short parameters ... */

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Server Time: 0x%04x", GSHORT(pd, offset));
      proto_tree_add_item(tree, offset + 2, 2, "Server Date: 0x%04x", GSHORT(pd, offset + 2));

      proto_tree_add_item(tree, offset + 4, 2, "Server Time Zone: 0x%04x", GSHORT(pd, offset + 4));

    }

    offset += 6;

    /* Encryption Key Length, should be zero */

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Encryption Key Length: %u (should be zero)", GSHORT(pd, offset));

    }

    offset += 2;

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Reserved: %u (MBZ)", GSHORT(pd, offset));

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    /* Encryption key, might be a null string ??? Not sure */

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str)+1, "Encryption Key: %s", str);

    }

    offset += strlen(str) + 1;

    /* Primary Domain ... */

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str)+1, "Primary Domain: %s", str);

    }

    break;

  case 17:    /* Greater than LANMAN2.1 */

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Dialect Index: %u, Greater than LANMAN2.1", GSHORT(pd, offset));

    }

    offset += 2;

    mode = GBYTE(pd, offset);

    if (tree) {

      ti = proto_tree_add_item(tree, offset, 1, "Security Mode: 0x%02x", mode);
      mode_tree = proto_tree_new();
      proto_item_add_subtree(ti, mode_tree, ETT_SMB_MODE);
      proto_tree_add_item(mode_tree, offset, 1, "%s",
			  decode_boolean_bitfield(mode, 0x01, 8,
						  "Security  = User",
						  "Security  = Share"));
      proto_tree_add_item(mode_tree, offset, 1, "%s",
			  decode_boolean_bitfield(mode, 0x02, 8,
						  "Passwords = Encrypted",
						  "Passwords = Plaintext"));

    }

    offset += 1;

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Max multiplex count: %u", GSHORT(pd, offset));

    }
    
    offset += 2;

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Max vcs:             %u", GSHORT(pd, offset));

    }

    offset += 2;

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Max buffer size:     %u", GWORD(pd, offset));

    }

    offset += 4;

    if (tree) {

      proto_tree_add_item(tree, offset, 4, "Max raw size:        %u", GWORD(pd, offset));

    }

    offset += 4;

    if (tree) {

      proto_tree_add_item(tree, offset, 4, "Session key:         %08x", GWORD(pd, offset));

    }

    offset += 4;

    caps = GWORD(pd, offset);

    if (tree) {

      ti = proto_tree_add_item(tree, offset, 4, "Capabilities: 0x%04x", caps);
      caps_tree = proto_tree_new();
      proto_item_add_subtree(ti, caps_tree, ETT_SMB_CAPS);
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0001, 32,
						  "Raw Mode supported",
						  "Raw Mode not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0002, 32,
						  "MPX Mode supported",
						  "MPX Mode not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0004, 32,
						  "Unicode supported",
						  "Unicode not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0008, 32,
						  "Large files supported",
						  "Large files not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0010, 32, 
						  "NT LM 0.12 SMBs supported",
						  "NT LM 0.12 SMBs not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0020, 32,
						  "RPC remote APIs supported",
						  "RPC remote APIs not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0040, 32,
						  "NT status codes supported",
						  "NT status codes  not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0080, 32,
						  "Level 2 OpLocks supported",
						  "Level 2 OpLocks not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0100, 32,
						  "Lock&Read supported",
						  "Lock&Read not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x0200, 32,
						  "NT Find supported",
						  "NT Find not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x1000, 32,
						  "DFS supported",
						  "DFS not supported"));
      proto_tree_add_item(caps_tree, offset, 4, "%s",
			  decode_boolean_bitfield(caps, 0x4000, 32,
						  "Large READX supported",
						  "Large READX not supported"));
    }

    offset += 4;

    /* Server time, 2 WORDS */

    if (tree) {

      proto_tree_add_item(tree, offset, 4, "System Time Low: 0x%08x", GWORD(pd, offset));
      proto_tree_add_item(tree, offset + 4, 4, "System Time High: 0x%08x", GWORD(pd, offset + 4)); 

    }

    offset += 8;

    /* Server Time Zone, SHORT */

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Server time zone: %i min from UTC",
			  (signed)GSSHORT(pd, offset));

    }

    offset += 2;

    /* Encryption key len */

    enckeylen = pd[offset];

    if (tree) {

      proto_tree_add_item(tree, offset, 1, "Encryption key len: %u", enckeylen);

    }

    offset += 1;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_item(tree, offset, 2, "Byte count (BCC): %u", bcc);

    }

    offset += 2;

    if (enckeylen) { /* only if non-zero key len */

      /* Encryption challenge key, a NULL terminated string */

      str = pd + offset;

      if (tree) {

	proto_tree_add_item(tree, offset, strlen(str)+1, "Challenge encryption key: %s", str);

      }

      offset += strlen(str) + 1;

    }

    /* The domain, another null terminated string */

    str = pd + offset;

    if (tree) {

      proto_tree_add_item(tree, offset, strlen(str)+1, "OEM domain name: %s", str);

    }

    break;

  default:    /* Baddd */

    if (tree)
      proto_tree_add_item(tree, offset, 1, "Bad format, should never get here");
    return;

  }

}

void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, int, int) = {

  dissect_unknown_smb,      /* unknown SMB 0x00 */
  dissect_unknown_smb,      /* unknown SMB 0x01 */
  dissect_unknown_smb,      /* SMBopen open a file */
  dissect_unknown_smb,      /* SMBcreate create a file */
  dissect_unknown_smb,      /* SMBclose close a file */
  dissect_unknown_smb,      /* SMBflush flush a file */
  dissect_unknown_smb,      /* SMBunlink delete a file */
  dissect_unknown_smb,      /* SMBmv rename a file */
  dissect_unknown_smb,      /* SMBgetatr get file attributes */
  dissect_unknown_smb,      /* SMBsetatr set file attributes */
  dissect_unknown_smb,      /* SMBread read from a file */
  dissect_unknown_smb,      /* SMBwrite write to a file */
  dissect_unknown_smb,      /* SMBlock lock a byte range */
  dissect_unknown_smb,      /* SMBunlock unlock a byte range */
  dissect_unknown_smb,      /* SMBctemp create a temporary file */
  dissect_unknown_smb,      /* SMBmknew make a new file */
  dissect_unknown_smb,      /* SMBchkpth check a directory path */
  dissect_unknown_smb,      /* SMBexit process exit */
  dissect_unknown_smb,      /* SMBlseek seek */
  dissect_unknown_smb,      /* SMBlockread Lock a range and read it */
  dissect_unknown_smb,      /* SMBwriteunlock Unlock a range and then write */
  dissect_unknown_smb,      /* unknown SMB 0x15 */
  dissect_unknown_smb,      /* unknown SMB 0x16 */
  dissect_unknown_smb,      /* unknown SMB 0x17 */
  dissect_unknown_smb,      /* unknown SMB 0x18 */
  dissect_unknown_smb,      /* unknown SMB 0x19 */
  dissect_unknown_smb,      /* SMBreadBraw read block raw */
  dissect_unknown_smb,      /* SMBreadBmpx read block multiplexed */
  dissect_unknown_smb,      /* SMBreadBs read block (secondary response) */
  dissect_unknown_smb,      /* SMBwriteBraw write block raw */
  dissect_unknown_smb,      /* SMBwriteBmpx write block multiplexed */
  dissect_unknown_smb,      /* SMBwriteBs write block (secondary request) */
  dissect_unknown_smb,      /* SMBwriteC write complete response */
  dissect_unknown_smb,      /* unknown SMB 0x21 */
  dissect_unknown_smb,      /* SMBsetattrE set file attributes expanded */
  dissect_unknown_smb,      /* SMBgetattrE get file attributes expanded */
  dissect_unknown_smb,      /* SMBlockingX lock/unlock byte ranges and X */
  dissect_unknown_smb,      /* SMBtrans transaction - name, bytes in/out */
  dissect_unknown_smb,      /* SMBtranss transaction (secondary request/response) */
  dissect_unknown_smb,      /* SMBioctl IOCTL */
  dissect_unknown_smb,      /* SMBioctls IOCTL (secondary request/response) */
  dissect_unknown_smb,      /* SMBcopy copy */
  dissect_unknown_smb,      /* SMBmove move */
  dissect_unknown_smb,      /* SMBecho echo */
  dissect_unknown_smb,      /* SMBwriteclose write a file and then close it */
  dissect_unknown_smb,      /* SMBopenX open and X */
  dissect_unknown_smb,      /* SMBreadX read and X */
  dissect_unknown_smb,      /* SMBwriteX write and X */
  dissect_unknown_smb,      /* unknown SMB 0x30 */
  dissect_unknown_smb,      /* unknown SMB 0x31 */
  dissect_unknown_smb,      /* unknown SMB 0x32 */
  dissect_unknown_smb,      /* unknown SMB 0x33 */
  dissect_unknown_smb,      /* unknown SMB 0x34 */
  dissect_unknown_smb,      /* unknown SMB 0x35 */
  dissect_unknown_smb,      /* unknown SMB 0x36 */
  dissect_unknown_smb,      /* unknown SMB 0x37 */
  dissect_unknown_smb,      /* unknown SMB 0x38 */
  dissect_unknown_smb,      /* unknown SMB 0x39 */
  dissect_unknown_smb,      /* unknown SMB 0x3a */
  dissect_unknown_smb,      /* unknown SMB 0x3b */
  dissect_unknown_smb,      /* unknown SMB 0x3c */
  dissect_unknown_smb,      /* unknown SMB 0x3d */
  dissect_unknown_smb,      /* unknown SMB 0x3e */
  dissect_unknown_smb,      /* unknown SMB 0x3f */
  dissect_unknown_smb,      /* unknown SMB 0x40 */
  dissect_unknown_smb,      /* unknown SMB 0x41 */
  dissect_unknown_smb,      /* unknown SMB 0x42 */
  dissect_unknown_smb,      /* unknown SMB 0x43 */
  dissect_unknown_smb,      /* unknown SMB 0x44 */
  dissect_unknown_smb,      /* unknown SMB 0x45 */
  dissect_unknown_smb,      /* unknown SMB 0x46 */
  dissect_unknown_smb,      /* unknown SMB 0x47 */
  dissect_unknown_smb,      /* unknown SMB 0x48 */
  dissect_unknown_smb,      /* unknown SMB 0x49 */
  dissect_unknown_smb,      /* unknown SMB 0x4a */
  dissect_unknown_smb,      /* unknown SMB 0x4b */
  dissect_unknown_smb,      /* unknown SMB 0x4c */
  dissect_unknown_smb,      /* unknown SMB 0x4d */
  dissect_unknown_smb,      /* unknown SMB 0x4e */
  dissect_unknown_smb,      /* unknown SMB 0x4f */
  dissect_unknown_smb,      /* unknown SMB 0x50 */
  dissect_unknown_smb,      /* unknown SMB 0x51 */
  dissect_unknown_smb,      /* unknown SMB 0x52 */
  dissect_unknown_smb,      /* unknown SMB 0x53 */
  dissect_unknown_smb,      /* unknown SMB 0x54 */
  dissect_unknown_smb,      /* unknown SMB 0x55 */
  dissect_unknown_smb,      /* unknown SMB 0x56 */
  dissect_unknown_smb,      /* unknown SMB 0x57 */
  dissect_unknown_smb,      /* unknown SMB 0x58 */
  dissect_unknown_smb,      /* unknown SMB 0x59 */
  dissect_unknown_smb,      /* unknown SMB 0x5a */
  dissect_unknown_smb,      /* unknown SMB 0x5b */
  dissect_unknown_smb,      /* unknown SMB 0x5c */
  dissect_unknown_smb,      /* unknown SMB 0x5d */
  dissect_unknown_smb,      /* unknown SMB 0x5e */
  dissect_unknown_smb,      /* unknown SMB 0x5f */
  dissect_unknown_smb,      /* unknown SMB 0x60 */
  dissect_unknown_smb,      /* unknown SMB 0x61 */
  dissect_unknown_smb,      /* unknown SMB 0x62 */
  dissect_unknown_smb,      /* unknown SMB 0x63 */
  dissect_unknown_smb,      /* unknown SMB 0x64 */
  dissect_unknown_smb,      /* unknown SMB 0x65 */
  dissect_unknown_smb,      /* unknown SMB 0x66 */
  dissect_unknown_smb,      /* unknown SMB 0x67 */
  dissect_unknown_smb,      /* unknown SMB 0x68 */
  dissect_unknown_smb,      /* unknown SMB 0x69 */
  dissect_unknown_smb,      /* unknown SMB 0x6a */
  dissect_unknown_smb,      /* unknown SMB 0x6b */
  dissect_unknown_smb,      /* unknown SMB 0x6c */
  dissect_unknown_smb,      /* unknown SMB 0x6d */
  dissect_unknown_smb,      /* unknown SMB 0x6e */
  dissect_unknown_smb,      /* unknown SMB 0x6f */
  dissect_unknown_smb,      /* SMBtcon tree connect */
  dissect_unknown_smb,      /* SMBtdis tree disconnect */
  dissect_negprot_smb,      /* SMBnegprot negotiate a protocol */
  dissect_unknown_smb,      /* SMBsesssetupX Session Set Up & X (including User Logon) */
  dissect_unknown_smb,      /* unknown SMB 0x74 */
  dissect_tcon_andx_smb,    /* SMBtconX tree connect and X */
  dissect_unknown_smb,      /* unknown SMB 0x76 */
  dissect_unknown_smb,      /* unknown SMB 0x77 */
  dissect_unknown_smb,      /* unknown SMB 0x78 */
  dissect_unknown_smb,      /* unknown SMB 0x79 */
  dissect_unknown_smb,      /* unknown SMB 0x7a */
  dissect_unknown_smb,      /* unknown SMB 0x7b */
  dissect_unknown_smb,      /* unknown SMB 0x7c */
  dissect_unknown_smb,      /* unknown SMB 0x7d */
  dissect_unknown_smb,      /* unknown SMB 0x7e */
  dissect_unknown_smb,      /* unknown SMB 0x7f */
  dissect_unknown_smb,      /* SMBdskattr get disk attributes */
  dissect_unknown_smb,      /* SMBsearch search a directory */
  dissect_unknown_smb,      /* SMBffirst find first */
  dissect_unknown_smb,      /* SMBfunique find unique */
  dissect_unknown_smb,      /* SMBfclose find close */
  dissect_unknown_smb,      /* unknown SMB 0x85 */
  dissect_unknown_smb,      /* unknown SMB 0x86 */
  dissect_unknown_smb,      /* unknown SMB 0x87 */
  dissect_unknown_smb,      /* unknown SMB 0x88 */
  dissect_unknown_smb,      /* unknown SMB 0x89 */
  dissect_unknown_smb,      /* unknown SMB 0x8a */
  dissect_unknown_smb,      /* unknown SMB 0x8b */
  dissect_unknown_smb,      /* unknown SMB 0x8c */
  dissect_unknown_smb,      /* unknown SMB 0x8d */
  dissect_unknown_smb,      /* unknown SMB 0x8e */
  dissect_unknown_smb,      /* unknown SMB 0x8f */
  dissect_unknown_smb,      /* unknown SMB 0x90 */
  dissect_unknown_smb,      /* unknown SMB 0x91 */
  dissect_unknown_smb,      /* unknown SMB 0x92 */
  dissect_unknown_smb,      /* unknown SMB 0x93 */
  dissect_unknown_smb,      /* unknown SMB 0x94 */
  dissect_unknown_smb,      /* unknown SMB 0x95 */
  dissect_unknown_smb,      /* unknown SMB 0x96 */
  dissect_unknown_smb,      /* unknown SMB 0x97 */
  dissect_unknown_smb,      /* unknown SMB 0x98 */
  dissect_unknown_smb,      /* unknown SMB 0x99 */
  dissect_unknown_smb,      /* unknown SMB 0x9a */
  dissect_unknown_smb,      /* unknown SMB 0x9b */
  dissect_unknown_smb,      /* unknown SMB 0x9c */
  dissect_unknown_smb,      /* unknown SMB 0x9d */
  dissect_unknown_smb,      /* unknown SMB 0x9e */
  dissect_unknown_smb,      /* unknown SMB 0x9f */
  dissect_unknown_smb,      /* unknown SMB 0xa0 */
  dissect_unknown_smb,      /* unknown SMB 0xa1 */
  dissect_unknown_smb,      /* unknown SMB 0xa2 */
  dissect_unknown_smb,      /* unknown SMB 0xa3 */
  dissect_unknown_smb,      /* unknown SMB 0xa4 */
  dissect_unknown_smb,      /* unknown SMB 0xa5 */
  dissect_unknown_smb,      /* unknown SMB 0xa6 */
  dissect_unknown_smb,      /* unknown SMB 0xa7 */
  dissect_unknown_smb,      /* unknown SMB 0xa8 */
  dissect_unknown_smb,      /* unknown SMB 0xa9 */
  dissect_unknown_smb,      /* unknown SMB 0xaa */
  dissect_unknown_smb,      /* unknown SMB 0xab */
  dissect_unknown_smb,      /* unknown SMB 0xac */
  dissect_unknown_smb,      /* unknown SMB 0xad */
  dissect_unknown_smb,      /* unknown SMB 0xae */
  dissect_unknown_smb,      /* unknown SMB 0xaf */
  dissect_unknown_smb,      /* unknown SMB 0xb0 */
  dissect_unknown_smb,      /* unknown SMB 0xb1 */
  dissect_unknown_smb,      /* unknown SMB 0xb2 */
  dissect_unknown_smb,      /* unknown SMB 0xb3 */
  dissect_unknown_smb,      /* unknown SMB 0xb4 */
  dissect_unknown_smb,      /* unknown SMB 0xb5 */
  dissect_unknown_smb,      /* unknown SMB 0xb6 */
  dissect_unknown_smb,      /* unknown SMB 0xb7 */
  dissect_unknown_smb,      /* unknown SMB 0xb8 */
  dissect_unknown_smb,      /* unknown SMB 0xb9 */
  dissect_unknown_smb,      /* unknown SMB 0xba */
  dissect_unknown_smb,      /* unknown SMB 0xbb */
  dissect_unknown_smb,      /* unknown SMB 0xbc */
  dissect_unknown_smb,      /* unknown SMB 0xbd */
  dissect_unknown_smb,      /* unknown SMB 0xbe */
  dissect_unknown_smb,      /* unknown SMB 0xbf */
  dissect_unknown_smb,      /* SMBsplopen open a print spool file */
  dissect_unknown_smb,      /* SMBsplwr write to a print spool file */
  dissect_unknown_smb,      /* SMBsplclose close a print spool file */
  dissect_unknown_smb,      /* SMBsplretq return print queue */
  dissect_unknown_smb,      /* unknown SMB 0xc4 */
  dissect_unknown_smb,      /* unknown SMB 0xc5 */
  dissect_unknown_smb,      /* unknown SMB 0xc6 */
  dissect_unknown_smb,      /* unknown SMB 0xc7 */
  dissect_unknown_smb,      /* unknown SMB 0xc8 */
  dissect_unknown_smb,      /* unknown SMB 0xc9 */
  dissect_unknown_smb,      /* unknown SMB 0xca */
  dissect_unknown_smb,      /* unknown SMB 0xcb */
  dissect_unknown_smb,      /* unknown SMB 0xcc */
  dissect_unknown_smb,      /* unknown SMB 0xcd */
  dissect_unknown_smb,      /* unknown SMB 0xce */
  dissect_unknown_smb,      /* unknown SMB 0xcf */
  dissect_unknown_smb,      /* SMBsends send a single block message */
  dissect_unknown_smb,      /* SMBsendb send a broadcast message */
  dissect_unknown_smb,      /* SMBfwdname forward user name */
  dissect_unknown_smb,      /* SMBcancelf cancel forward */
  dissect_unknown_smb,      /* SMBgetmac get a machine name */
  dissect_unknown_smb,      /* SMBsendstrt send start of multi-block message */
  dissect_unknown_smb,      /* SMBsendend send end of multi-block message */
  dissect_unknown_smb,      /* SMBsendtxt send text of multi-block message */
  dissect_unknown_smb,      /* unknown SMB 0xd8 */
  dissect_unknown_smb,      /* unknown SMB 0xd9 */
  dissect_unknown_smb,      /* unknown SMB 0xda */
  dissect_unknown_smb,      /* unknown SMB 0xdb */
  dissect_unknown_smb,      /* unknown SMB 0xdc */
  dissect_unknown_smb,      /* unknown SMB 0xdd */
  dissect_unknown_smb,      /* unknown SMB 0xde */
  dissect_unknown_smb,      /* unknown SMB 0xdf */
  dissect_unknown_smb,      /* unknown SMB 0xe0 */
  dissect_unknown_smb,      /* unknown SMB 0xe1 */
  dissect_unknown_smb,      /* unknown SMB 0xe2 */
  dissect_unknown_smb,      /* unknown SMB 0xe3 */
  dissect_unknown_smb,      /* unknown SMB 0xe4 */
  dissect_unknown_smb,      /* unknown SMB 0xe5 */
  dissect_unknown_smb,      /* unknown SMB 0xe6 */
  dissect_unknown_smb,      /* unknown SMB 0xe7 */
  dissect_unknown_smb,      /* unknown SMB 0xe8 */
  dissect_unknown_smb,      /* unknown SMB 0xe9 */
  dissect_unknown_smb,      /* unknown SMB 0xea */
  dissect_unknown_smb,      /* unknown SMB 0xeb */
  dissect_unknown_smb,      /* unknown SMB 0xec */
  dissect_unknown_smb,      /* unknown SMB 0xed */
  dissect_unknown_smb,      /* unknown SMB 0xee */
  dissect_unknown_smb,      /* unknown SMB 0xef */
  dissect_unknown_smb,      /* unknown SMB 0xf0 */
  dissect_unknown_smb,      /* unknown SMB 0xf1 */
  dissect_unknown_smb,      /* unknown SMB 0xf2 */
  dissect_unknown_smb,      /* unknown SMB 0xf3 */
  dissect_unknown_smb,      /* unknown SMB 0xf4 */
  dissect_unknown_smb,      /* unknown SMB 0xf5 */
  dissect_unknown_smb,      /* unknown SMB 0xf6 */
  dissect_unknown_smb,      /* unknown SMB 0xf7 */
  dissect_unknown_smb,      /* unknown SMB 0xf8 */
  dissect_unknown_smb,      /* unknown SMB 0xf9 */
  dissect_unknown_smb,      /* unknown SMB 0xfa */
  dissect_unknown_smb,      /* unknown SMB 0xfb */
  dissect_unknown_smb,      /* unknown SMB 0xfc */
  dissect_unknown_smb,      /* unknown SMB 0xfd */
  dissect_unknown_smb,      /* SMBinvalid invalid command */
  dissect_unknown_smb       /* unknown SMB 0xff */

};

static const value_string errcls_types[] = {
  { SMB_SUCCESS, "Success"},
  { SMB_ERRDOS, "DOS Error"},
  { SMB_ERRSRV, "Server Error"},
  { SMB_ERRHRD, "Hardware Error"},
  { SMB_ERRCMD, "Command Error - Not an SMB format command"},
  { 0, 0}
};

char *decode_smb_name(unsigned char cmd)
{

  return(SMB_names[cmd]);

}

static const value_string DOS_errors[] = {
  {SMBE_badfunc, "Invalid function (or system call)"},
  {SMBE_badfile, "File not found (pathname error)"},
  {SMBE_badpath, "Directory not found"},
  {SMBE_nofids, "Too many open files"},
  {SMBE_noaccess, "Access denied"},
  {SMBE_badfid, "Invalid fid"},
  {SMBE_nomem,  "Out of memory"},
  {SMBE_badmem, "Invalid memory block address"},
  {SMBE_badenv, "Invalid environment"},
  {SMBE_badaccess, "Invalid open mode"},
  {SMBE_baddata, "Invalid data (only from ioctl call)"},
  {SMBE_res, "Reserved error code?"}, 
  {SMBE_baddrive, "Invalid drive"},
  {SMBE_remcd, "Attempt to delete current directory"},
  {SMBE_diffdevice, "Rename/move across different filesystems"},
  {SMBE_nofiles, "no more files found in file search"},
  {SMBE_badshare, "Share mode on file conflict with open mode"},
  {SMBE_lock, "Lock request conflicts with existing lock"},
  {SMBE_unsup, "Request unsupported, returned by Win 95"},
  {SMBE_filexists, "File in operation already exists"},
  {SMBE_cannotopen, "Cannot open the file specified"},
  {SMBE_unknownlevel, "Unknown level??"},
  {SMBE_badpipe, "Named pipe invalid"},
  {SMBE_pipebusy, "All instances of pipe are busy"},
  {SMBE_pipeclosing, "Named pipe close in progress"},
  {SMBE_notconnected, "No process on other end of named pipe"},
  {SMBE_moredata, "More data to be returned"},
  {SMBE_baddirectory,  "Invalid directory name in a path."},
  {SMBE_eas_didnt_fit, "Extended attributes didn't fit"},
  {SMBE_eas_nsup, "Extended attributes not supported"},
  {SMBE_notify_buf_small, "Buffer too small to return change notify."},
  {SMBE_unknownipc, "Unknown IPC Operation"},
  {SMBE_noipc, "Don't support ipc"},
  {0, 0}
  };

/* Error codes for the ERRSRV class */

static const value_string SRV_errors[] = {
  {SMBE_error, "Non specific error code"},
  {SMBE_badpw, "Bad password"},
  {SMBE_badtype, "Reserved"},
  {SMBE_access, "No permissions to perform the requested operation"},
  {SMBE_invnid, "TID invalid"},
  {SMBE_invnetname, "Invalid servername"},
  {SMBE_invdevice, "Invalid device"},
  {SMBE_unknownsmb, "Unknown SMB, from NT 3.5 response"},
  {SMBE_qfull, "Print queue full"},
  {SMBE_qtoobig, "Queued item too big"},
  {SMBE_invpfid, "Invalid print file in smb_fid"},
  {SMBE_smbcmd, "Unrecognised command"},
  {SMBE_srverror, "SMB server internal error"},
  {SMBE_filespecs, "Fid and pathname invalid combination"},
  {SMBE_badlink, "Bad link in request ???"},
  {SMBE_badpermits, "Access specified for a file is not valid"},
  {SMBE_badpid, "Bad process id in request"},
  {SMBE_setattrmode, "Attribute mode invalid"},
  {SMBE_paused, "Message server paused"},
  {SMBE_msgoff, "Not receiving messages"},
  {SMBE_noroom, "No room for message"},
  {SMBE_rmuns, "Too many remote usernames"},
  {SMBE_timeout, "Operation timed out"},
  {SMBE_noresource, "No resources currently available for request."},
  {SMBE_toomanyuids, "Too many userids"},
  {SMBE_baduid, "Bad userid"},
  {SMBE_useMPX, "Temporarily unable to use raw mode, use MPX mode"},
  {SMBE_useSTD, "Temporarily unable to use raw mode, use standard mode"},
  {SMBE_contMPX, "Resume MPX mode"},
  {SMBE_badPW, "Bad Password???"},
  {SMBE_nosupport, "Operation not supported???"},
  { 0, 0}
};

/* Error codes for the ERRHRD class */

static const value_string HRD_errors[] = {
  {SMBE_nowrite, "read only media"},
  {SMBE_badunit, "Unknown device"},
  {SMBE_notready, "Drive not ready"},
  {SMBE_badcmd, "Unknown command"},
  {SMBE_data, "Data (CRC) error"},
  {SMBE_badreq, "Bad request structure length"},
  {SMBE_seek, "Seek error???"},
  {SMBE_badmedia, "Bad media???"},
  {SMBE_badsector, "Bad sector???"},
  {SMBE_nopaper, "No paper in printer???"},
  {SMBE_write, "Write error???"},
  {SMBE_read, "Read error???"},
  {SMBE_general, "General error???"},
  {SMBE_wrongdisk,  "Wrong disk???"},
  {SMBE_FCBunavail, "FCB unavailable???"},
  {SMBE_sharebufexc, "Share buffer excluded???"},
  {SMBE_diskfull, "Disk full???"},
  {0, 0}
};

char *decode_smb_error(guint8 errcls, guint8 errcode)
{

  switch (errcls) {

  case SMB_SUCCESS:

    return("No Error");   /* No error ??? */
    break;

  case SMB_ERRDOS:

    return(val_to_str(errcode, DOS_errors, "Unknown DOS error (%x)"));
    break;

  case SMB_ERRSRV:

    return(val_to_str(errcode, SRV_errors, "Unknown SRV error (%x)"));
    break;

  case SMB_ERRHRD:

    return(val_to_str(errcode, HRD_errors, "Unknown HRD error(%x)"));
    break;

  default:

    return("Unknown error class!");

  }

}

#define SMB_FLAGS_DIRN 0x80

void
dissect_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int max_data)
{
        proto_tree      *smb_tree = tree, *flags_tree, *flags2_tree;
	proto_item      *ti, *tf;
	guint8          cmd, errcls, errcode1, flags;
	guint16         flags2, errcode, tid, pid, uid, mid;

	cmd = pd[offset + SMB_hdr_com_offset];

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SMB");

	/* Hmmm, poor coding here ... Also, should check the type */

	if (check_col(fd, COL_INFO)) {

	  col_add_fstr(fd, COL_INFO, "%s %s", decode_smb_name(cmd), (pi.match_port == pi.destport)? "Request" : "Response");

	}

	if (tree) {

	  ti = proto_tree_add_item(tree, offset, END_OF_FRAME,
				"Server Message Block Protocol");
	  smb_tree = proto_tree_new();
	  proto_item_add_subtree(ti, smb_tree, ETT_SMB);

	  /* 0xFFSMB is actually a 1 byte msg type and 3 byte server
	   * component ... SMB is only one used
	   */

	  proto_tree_add_item(smb_tree, offset, 1, "Message Type: 0xFF");
	  proto_tree_add_item(smb_tree, offset+1, 3, "Server Component: SMB");

	}

	offset += 4;  /* Skip the marker */

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 1, "Command: %s", decode_smb_name(cmd));

	}

	offset += 1;

	/* Next, look at the error class, SMB_RETCLASS */

	errcls = pd[offset];

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 1, "Error Class: %s", 
			      val_to_str((guint8)pd[offset], errcls_types, "Unknown Error Class (%x)"));
	}

	offset += 1;

	/* Error code, SMB_HEINFO ... */

	errcode1 = pd[offset];

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 1, "Reserved: %i", errcode1); 

	}

	offset += 1;

	errcode = GSHORT(pd, offset); 

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 2, "Error Code: %s",
			      decode_smb_error(errcls, errcode));

	}

	offset += 2;

	/* Now for the flags: Bit 0 = 0 means cmd, 0 = 1 means resp */

	flags = pd[offset];

	if (tree) {

	  tf = proto_tree_add_item(smb_tree, offset, 1, "Flags: 0x%02x", flags);

	  flags_tree = proto_tree_new();
	  proto_item_add_subtree(tf, flags_tree, ETT_SMB_FLAGS);
	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x01, 8,
						      "Lock&Read, Write&Unlock supported",
						      "Lock&Read, Write&Unlock not supported"));
	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x02, 8,
						      "Receive buffer posted",
						      "Receive buffer not posted"));
	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x08, 8, 
						      "Path names caseless",
						      "Path names case sensitive"));
	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x10, 8,
						      "Pathnames canonicalized",
						      "Pathnames not canonicalized"));
	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x20, 8,
						      "OpLocks requested/granted",
						      "OpLocks not requested/granted"));
	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, 0x40, 8, 
						      "Notify all",
						      "Notify open only"));

	  proto_tree_add_item(flags_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags, SMB_FLAGS_DIRN,
						      8, "Response to client/redirector", "Request to server"));

	}

	offset += 1;

	flags2 = GSHORT(pd, offset);

	if (tree) {

	  tf = proto_tree_add_item(smb_tree, offset, 1, "Flags2: 0x%04x", flags2);

	  flags2_tree = proto_tree_new();
	  proto_item_add_subtree(tf, flags2_tree, ETT_SMB_FLAGS2);
	  proto_tree_add_item(flags2_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x0001, 16,
						      "Long file names supported",
						      "Long file names not supported"));
	  proto_tree_add_item(flags2_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x0002, 16,
						      "Extended attributes supported",
						      "Extended attributes not supported"));
	  proto_tree_add_item(flags2_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x1000, 16, 
						      "Resolve pathnames with DFS",
						      "Don't resolve pathnames with DFS"));
	  proto_tree_add_item(flags2_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x2000, 16,
						      "Permit reads if execute-only",
						      "Don't permit reads if execute-only"));
	  proto_tree_add_item(flags2_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x4000, 16,
						      "Error codes are NT error codes",
						      "Error codes are DOS error codes"));
	  proto_tree_add_item(flags2_tree, offset, 1, "%s",
			      decode_boolean_bitfield(flags2, 0x8000, 16, 
						      "Strings are Unicode",
						      "Strings are ASCII"));

	}

	offset += 2;

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 12, "Reserved: 6 WORDS");

	}

	offset += 12;

	/* Now the TID, tree ID */

	tid = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 2, "Network Path/Tree ID (TID): %i (%04x)", tid, tid); 

	}

	offset += 2;

	/* Now the PID, Process ID */

	pid = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 2, "Process ID (PID): %i (%04x)", pid, pid); 

	}

	offset += 2;

        /* Now the UID, User ID */

	uid = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 2, "User ID (UID): %i (%04x)", uid, uid); 

	}
	
	offset += 2;

        /* Now the MID, Multiplex ID */

	mid = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_item(smb_tree, offset, 2, "Multiplex ID (MID): %i (%04x)", mid, mid); 

	}

	offset += 2;

	/* Now vector through the table to dissect them */

	(dissect[cmd])(pd, offset, fd, smb_tree, max_data, 
		       ((flags & 0x80) == 0));


}
