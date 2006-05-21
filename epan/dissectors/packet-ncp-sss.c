
/* packet-ncp-sss.c
 * Routines for Novell SecretStore Services
 * Greg Morris <gmorris@novell.com>
 * Copyright (c) Novell, Inc. 2002-2003
 *
 * $Id: packet-ncp-sss.c,v 1.00 2003/06/26 11:36:14 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "prefs.h"
#include "packet-ncp-int.h"
#include "packet-ncp-sss.h"

static guint32 subverb=0;

static gint ett_sss = -1;

static int proto_sss = -1;
static int hf_buffer_size = -1;
static int hf_ping_version = -1;
static int hf_flags = -1;
static int hf_context = -1;
static int hf_frag_handle = -1;
static int hf_length = -1;
static int hf_verb = -1;
static int hf_user = -1;
static int hf_secret = -1;
static int hf_sss_version = -1;
static int hf_return_code = -1;
static int hf_enc_cred = -1;
static int hf_enc_data = -1;
static int hfbit1 = -1;
static int hfbit2 = -1;
static int hfbit3 = -1;
static int hfbit4 = -1;
static int hfbit5 = -1;
static int hfbit6 = -1;
static int hfbit7 = -1;
static int hfbit8 = -1;
static int hfbit9 = -1;
static int hfbit10 = -1;
static int hfbit11 = -1;
static int hfbit12 = -1;
static int hfbit13 = -1;
static int hfbit14 = -1;
static int hfbit15 = -1;
static int hfbit16 = -1;
static int hfbit17 = -1;
static int hfbit18 = -1;
static int hfbit19 = -1;
static int hfbit20 = -1;
static int hfbit21 = -1;
static int hfbit22 = -1;
static int hfbit23 = -1;
static int hfbit24 = -1;
static int hfbit25 = -1;
static int hfbit26 = -1;
static int hfbit27 = -1;
static int hfbit28 = -1;
static int hfbit29 = -1;
static int hfbit30 = -1;
static int hfbit31 = -1;
static int hfbit32 = -1;

static proto_item *expert_item = NULL;

static const value_string sss_func_enum[] = {
    { 0x00000001, "Ping Server" },
    { 0x00000002, "Fragment" },
    { 0x00000003, "Write App Secrets" },
    { 0x00000004, "Add Secret ID" },
    { 0x00000005, "Remove Secret ID" },
    { 0x00000006, "Remove SecretStore" },
    { 0x00000007, "Enumerate Secret IDs" },
    { 0x00000008, "Unlock Store" },
    { 0x00000009, "Set Master Password" },
    { 0x0000000a, "Get Service Information" },
    { 0,          NULL }
};


static const value_string sss_verb_enum[] = {
    { 0x00000000, "Query Server" },
    { 0x00000001, "Read App Secrets" },
    { 0x00000002, "Write App Secrets" },
    { 0x00000003, "Add Secret ID" },
    { 0x00000004, "Remove Secret ID" },
    { 0x00000005, "Remove SecretStore" },
    { 0x00000006, "Enumerate Secret IDs" },
    { 0x00000007, "Unlock Store" },
    { 0x00000008, "Set Master Password" },
    { 0x00000009, "Get Service Information" },
    { 0x000000ff, "Fragment"},
    { 0,          NULL }
};

static const value_string sss_subverb_enum[] = {
    { 0, "Fragmented Ping" },
    { 2, "Client Put Data" },
    { 4, "Client Get Data" },
    { 6, "Client Get User NDS Credentials" },
    { 8, "Login Store Management" },
    { 10, "Writable Object Check" },
    { 1242, "Message Handler" },
    { 0,          NULL }
};

static const value_string sss_msgverb_enum[] = {
    { 1, "Echo Data" },
    { 3, "Start Session" },
    { 5, "Client Write Data" },
    { 7, "Client Read Data" },
    { 9, "End Session" },
    { 0,          NULL }
};

static const value_string sss_attribute_enum[] = {
    { 1, "User Name" },
    { 2, "Tree Name" },
    { 4, "Clearence" },
    { 11, "Login Sequence" },
    { 0,          NULL }
};

static const value_string sss_lsmverb_enum[] = {
    { 1, "Put Login Configuration" },
    { 2, "Get Login Configuration" },
    { 4, "Delete Login Configuration" },
    { 5, "Put Login Secret" },
    { 6, "Delete Login Secret" },
    { 0,          NULL }
};

static const value_string sss_errors_enum[] = {
    { 0xFFFFFCE0, "(-800) Target object could not be found" },
    { 0xFFFFFCDF, "(-801) NICI operations have failed" },
    { 0xFFFFFCDE, "(-802) The Secret ID is not in the user secret store" },
    { 0xFFFFFCDD, "(-803) Some internal operating system services have not been available" },
    { 0xFFFFFCDC, "(-804) Access to the target Secret Store has been denied" },
    { 0xFFFFFCDB, "(-805) NDS internal NDS services have not been available" },
    { 0xFFFFFCDA, "(-806) Secret has not been initialized with a write" },
    { 0xFFFFFCD9, "(-807) Size of the buffer is not in a nominal range between minimum and maximum" },
    { 0xFFFFFCD8, "(-808) Client and server components are not of the compatible versions" },
    { 0xFFFFFCD7, "(-809) Secret Store data on the server has been corrupted" },
    { 0xFFFFFCD6, "(-810) Secret ID already exists in the SecretStore" },
    { 0xFFFFFCD5, "(-811) User NDS password has been changed by the administrator" },
    { 0xFFFFFCD4, "(-812) Target NDS user object not found" },
    { 0xFFFFFCD3, "(-813) Target NDS user object does not have a Secret Store" },
    { 0xFFFFFCD2, "(-814) Secret Store is not on the network" },
    { 0xFFFFFCD1, "(-815) Length of the Secret ID buffer exceeds the limit" },
    { 0xFFFFFCD0, "(-816) Length of the enumeration buffer is too short" },
    { 0xFFFFFCCF, "(-817) User not authenticated" },
    { 0xFFFFFCCE, "(-818) Not supported operations" },
    { 0xFFFFFCCD, "(-819) Typed in NDS password not valid" },
    { 0xFFFFFCCC, "(-820) Session keys of the client and server NICI are out of sync" },
    { 0xFFFFFCCB, "(-821) Requested service not yet supported" },
    { 0xFFFFFCCA, "(-822) NDS authentication type not supported" },
    { 0xFFFFFCC9, "(-823) Unicode text conversion operation failed" },
    { 0xFFFFFCC8, "(-824) Connection to server is lost" },
    { 0xFFFFFCC7, "(-825) Cryptographic operation failed" },
    { 0xFFFFFCC6, "(-826) Opening a connection to the server failed" },
    { 0xFFFFFCC5, "(-827) Access to server connection failed" },
    { 0xFFFFFCC4, "(-828) Size of the enumeration buffer exceeds the limit" },
    { 0xFFFFFCC3, "(-829) Size of the Secret buffer exceeds the limit" },
    { 0xFFFFFCC2, "(-830) Length of the Secret ID should be greater than zero" },
    { 0xFFFFFCC1, "(-831) Protocol data corrupted on the wire" },
    { 0xFFFFFCC0, "(-832) Enhanced protection's password validation failed. Access to the secret denied" },
    { 0xFFFFFCBF, "(-833) Schema is not extended to support SecretStore on the target tree" },
    { 0xFFFFFCBE, "(-834) One of the optional service attributes is not instantiated" },
    { 0xFFFFFCBD, "(-835) Server has been upgraded and the users SecretStore should be updated" },
    { 0xFFFFFCBC, "(-836) Master password could not be verified to read or unlock the secrets" },
    { 0xFFFFFCBB, "(-837) Master password has not been set on the SecretStore" },
    { 0xFFFFFCBA, "(-838) Ability to use master password has been disabled" },
    { 0xFFFFFCB9, "(-839) Not a writeable replica of NDS" },
    { 0xFFFFFCB8, "(-840) The API was unable to find a value for an attribute in the Directory" },
    { 0xFFFFFCB7, "(-841) A parameter passed to the API has not been properly initialized" },
    { 0xFFFFFCB6, "(-842) The connection to SecretStore requires SSL to be secure" },
    { 0xFFFFFCB5, "(-843) The client could not locate a server that supports the policy override required by the caller" },
    { 0xFFFFFCB4, "(-844) Attempt to unlock SecretStore failed because the store is not locked" },
    { 0xFFFFFCB3, "(-845) NDS Replica on the server that holds SecretStore is out of sync with the replica ring" },
    { 0xFFFFFC88, "(-888) Feature not yet implemented" },
    { 0xFFFFFC7D, "(-899) Products BETA life has expired" },
    { 0,          NULL }
};


static void
process_flags(proto_tree *sss_tree, tvbuff_t *tvb, guint32 foffset)
{
    gchar                   flags_str[1024];
    gchar                   *sep;
    proto_item		        *tinew;
    proto_tree		        *flags_tree;
    guint32                 i;
    guint32                 bvalue = 0;
    guint32                 flags = 0;

    bvalue = 0x00000001;
    flags_str[0]='\0';
    sep="";
    flags = tvb_get_ntohl(tvb, foffset);
    for (i = 0 ; i < 256; i++) 
    {
        if (flags & bvalue) 
        {
            strcat(flags_str, sep);
            switch(bvalue)
            {
                case 0x00000001:
                        strcat(flags_str, "Enhanced Protection");
                        break;
                case 0x00000002:        
                        strcat(flags_str, "Create ID");
                        break;
                case 0x00000004:        
                        strcat(flags_str, "Remove Lock");
                        break;
                case 0x00000008:        
                        strcat(flags_str, "Repair");
                        break;
                case 0x00000010:        
                        strcat(flags_str, "Unicode");
                        break;
                case 0x00000020:        
                        strcat(flags_str, "EP Master Password Used");
                        break;
                case 0x00000040:        
                        strcat(flags_str, "EP Password Used");
                        break;
                case 0x00000080:        
                        strcat(flags_str, "Set Tree Name");
                        break;
                case 0x00000100:        
                        strcat(flags_str, "Get Context");
                        break;
                case 0x00000200:        
                        strcat(flags_str, "Destroy Context");
                        break;
                case 0x00000400:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x00000800:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x00001000:
                        strcat(flags_str, "EP Lock");
                        break;
                case 0x00002000:        
                        strcat(flags_str, "Not Initialized");
                        break;
                case 0x00004000:        
                        strcat(flags_str, "Enhanced Protection");
                        break;
                case 0x00008000:        
                        strcat(flags_str, "Store Not Synced");
                        break;
                case 0x00010000:        
                        strcat(flags_str, "Admin Last Modified");
                        break;
                case 0x00020000:        
                        strcat(flags_str, "EP Password Present");
                        break;
                case 0x00040000:        
                        strcat(flags_str, "EP Master Password Present");
                        break;
                case 0x00080000:        
                        strcat(flags_str, "MP Disabled");
                        break;
                case 0x00100000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x00200000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x00400000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x00800000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x01000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x02000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x04000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x08000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x10000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x20000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x40000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                case 0x80000000:        
                        strcat(flags_str, "Not Defined");
                        break;
                default:
                        break;
            }                
            sep = ", ";
        }
            bvalue = bvalue*2;
    }
    tinew = proto_tree_add_uint_format(sss_tree, hf_flags, tvb, foffset, 4, flags, "%s 0x%08x", "Flags:", flags);
	flags_tree = proto_item_add_subtree(tinew, ett_nds);
                                                
    bvalue = 0x00000001;
    
    for (i = 0 ; i < 256; i++ ) 
    {
        if (flags & bvalue) 
        {
            switch(bvalue)
            {
                case 0x00000001:
                        proto_tree_add_item(flags_tree, hfbit1, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000002:
                    proto_tree_add_item(flags_tree, hfbit2, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000004:
                    proto_tree_add_item(flags_tree, hfbit3, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000008:
                        proto_tree_add_item(flags_tree, hfbit4, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000010:
                        proto_tree_add_item(flags_tree, hfbit5, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000020:
                        proto_tree_add_item(flags_tree, hfbit6, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000040:
                        proto_tree_add_item(flags_tree, hfbit7, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000080:
                        proto_tree_add_item(flags_tree, hfbit8, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000100:
                        proto_tree_add_item(flags_tree, hfbit9, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000200:
                        proto_tree_add_item(flags_tree, hfbit10, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000400:
                        proto_tree_add_item(flags_tree, hfbit11, tvb, foffset, 4, FALSE);
                        break;
                case 0x00000800:
                        proto_tree_add_item(flags_tree, hfbit12, tvb, foffset, 4, FALSE);
                        break;
                case 0x00001000:
                        proto_tree_add_item(flags_tree, hfbit13, tvb, foffset, 4, FALSE);
                        break;
                case 0x00002000:
                        proto_tree_add_item(flags_tree, hfbit14, tvb, foffset, 4, FALSE);
                        break;
                case 0x00004000:
                        proto_tree_add_item(flags_tree, hfbit15, tvb, foffset, 4, FALSE);
                        break;
                case 0x00008000:
                        proto_tree_add_item(flags_tree, hfbit16, tvb, foffset, 4, FALSE);
                        break;
                case 0x00010000:
                        proto_tree_add_item(flags_tree, hfbit17, tvb, foffset, 4, FALSE);
                        break;
                case 0x00020000:
                        proto_tree_add_item(flags_tree, hfbit18, tvb, foffset, 4, FALSE);
                        break;
                case 0x00040000:
                        proto_tree_add_item(flags_tree, hfbit19, tvb, foffset, 4, FALSE);
                        break;
                case 0x00080000:
                        proto_tree_add_item(flags_tree, hfbit20, tvb, foffset, 4, FALSE);
                        break;
                case 0x00100000:
                        proto_tree_add_item(flags_tree, hfbit21, tvb, foffset, 4, FALSE);
                        break;
                case 0x00200000:
                        proto_tree_add_item(flags_tree, hfbit22, tvb, foffset, 4, FALSE);
                        break;
                case 0x00400000:
                        proto_tree_add_item(flags_tree, hfbit23, tvb, foffset, 4, FALSE);
                        break;
                case 0x00800000:
                        proto_tree_add_item(flags_tree, hfbit24, tvb, foffset, 4, FALSE);
                        break;
                case 0x01000000:
                        proto_tree_add_item(flags_tree, hfbit25, tvb, foffset, 4, FALSE);
                        break;
                case 0x02000000:
                        proto_tree_add_item(flags_tree, hfbit26, tvb, foffset, 4, FALSE);
                        break;
                case 0x04000000:
                        proto_tree_add_item(flags_tree, hfbit27, tvb, foffset, 4, FALSE);
                        break;
                case 0x08000000:
                        proto_tree_add_item(flags_tree, hfbit28, tvb, foffset, 4, FALSE);
                        break;
                case 0x10000000:
                        proto_tree_add_item(flags_tree, hfbit29, tvb, foffset, 4, FALSE);
                        break;
                case 0x20000000:
                        proto_tree_add_item(flags_tree, hfbit30, tvb, foffset, 4, FALSE);
                        break;
                case 0x40000000:
                        proto_tree_add_item(flags_tree, hfbit31, tvb, foffset, 4, FALSE);
                        break;
                case 0x80000000:
                        proto_tree_add_item(flags_tree, hfbit32, tvb, foffset, 4, FALSE);
                        break;
                default:
                        break;
            }
        }
        bvalue = bvalue*2;
    }
    return;
}

static int
find_delimiter(tvbuff_t *tvb, int foffset)
{
    int i;
    int length = 0;
    guint16 c_char;

    for (i=0; i < 256; i++) 
    {
        c_char = tvb_get_guint8(tvb, foffset);
        if (c_char == 0x2a || tvb_length_remaining(tvb, foffset)==0) 
        {
            break;
        }
        foffset++;
        length++;
    }
    return length;
}

static int
sss_string(tvbuff_t* tvb, int hfinfo, proto_tree *sss_tree, int offset, gboolean little, guint32 length)
{
        int     foffset = offset;
        guint32 str_length;
        char    buffer[1024];
        guint32 i;
        guint16 c_char;
        guint32 length_remaining = 0;
        
        if (length==0) 
        {
            if (little) {
                str_length = tvb_get_letohl(tvb, foffset);
            }
            else
            {
                str_length = tvb_get_ntohl(tvb, foffset);
            }
            foffset += 4;
        }
        else
        {
            str_length = length;
        }
        length_remaining = tvb_length_remaining(tvb, foffset);
        if(str_length > (guint)length_remaining || str_length > 1024)
        {
                proto_tree_add_string(sss_tree, hfinfo, tvb, foffset,
                    length_remaining + 4, "<String too long to process>");
                foffset += length_remaining;
                return foffset;
        }
        if(str_length == 0)
        {
       	    proto_tree_add_string(sss_tree, hfinfo, tvb, offset,
                4, "<Not Specified>");
            return foffset;
        }
        for ( i = 0; i < str_length; i++ )
        {
                c_char = tvb_get_guint8(tvb, foffset );
                if (c_char<0x20 || c_char>0x7e)
                {
                        if (c_char != 0x00)
                        { 
                                c_char = 0x2e;
                                buffer[i] = c_char & 0xff;
                        }
                        else
                        {
                                i--;
                                str_length--;
                        }
                }
                else
                {
                        buffer[i] = c_char & 0xff;
                }
                foffset++;
                length_remaining--;
                
                if(length_remaining==1)
                {
                	i++;
                	break;
                }        
        }
        buffer[i] = '\0';
        
        if (length==0) 
        {
            if (little) {
                str_length = tvb_get_letohl(tvb, offset);
            }
            else
            {
                str_length = tvb_get_ntohl(tvb, offset);
            }
            offset += 4;
        }
        else
        {
            str_length = length;
        }
        proto_tree_add_string(sss_tree, hfinfo, tvb, offset,
                str_length, buffer);
        return foffset;
}

void
dissect_sss_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ncp_tree, ncp_req_hash_value *request_value)
{
	guint8			    func, subfunc = 0;
    guint32             msg_length=0;
    guint32             foffset= 0;
    proto_tree          *atree;
    proto_item          *aitem;
    
    
    if (tvb_length_remaining(tvb, foffset)<4) {
        return;
    }
    foffset = 6;
    func = tvb_get_guint8(tvb, foffset);
    foffset += 1;
    subfunc = tvb_get_guint8(tvb, foffset);
    foffset += 1;
    
	/* Fill in the INFO column. */
	if (check_col(pinfo->cinfo, COL_INFO)) {
       col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSSS");
       col_add_fstr(pinfo->cinfo, COL_INFO, "C SecretStore - %s", match_strval(subfunc, sss_func_enum));
    }
    switch (subfunc) {
    case 1:
        aitem = proto_tree_add_text(ncp_tree, tvb, foffset, tvb_length_remaining(tvb, foffset), "Packet Type: %s", match_strval(subfunc, sss_func_enum));
        atree = proto_item_add_subtree(aitem, ett_sss);
        proto_tree_add_item(atree, hf_ping_version, tvb, foffset, 4, TRUE);
        foffset += 4;
        proto_tree_add_item(atree, hf_flags, tvb, foffset, 4, TRUE);
        foffset += 4;
        break;
    case 2:
        proto_tree_add_item(ncp_tree, hf_frag_handle, tvb, foffset, 4, TRUE);
        if (tvb_get_letohl(tvb, foffset)==0xffffffff) 
        {
            foffset += 4;
            proto_tree_add_item(ncp_tree, hf_buffer_size, tvb, foffset, 4, TRUE);
            foffset += 4;
            proto_tree_add_item(ncp_tree, hf_length, tvb, foffset, 4, TRUE);
            foffset += 4;
            foffset += 12; /* Blank Context */
            subverb = tvb_get_letohl(tvb, foffset);
            if (check_col(pinfo->cinfo, COL_INFO)) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", match_strval(subverb, sss_verb_enum));
            }
            aitem = proto_tree_add_item(ncp_tree, hf_verb, tvb, foffset, 4, TRUE);
            atree = proto_item_add_subtree(aitem, ett_sss);
            if (request_value) {
                request_value->req_nds_flags=subverb;
            }
            foffset += 4;
            process_flags(atree, tvb, foffset);
            foffset += 4;
            proto_tree_add_item(atree, hf_context, tvb, foffset, 4, FALSE);
            foffset += 4;
            switch (subverb) {
            case 0:
                foffset += 4;
                foffset = sss_string(tvb, hf_user, atree, foffset, TRUE, 0);
                break;
            case 1:
                foffset = sss_string(tvb, hf_secret, atree, foffset, TRUE, 0);
                msg_length = tvb_get_letohl(tvb, foffset);
                foffset += (msg_length+4);   /* Unsure of what this length and parameter are */
                /* A bad secret of length greater then 256 characters will cause frag
                   packets and then we will see these as malformed packets.
                   So check to make sure we still have data in the packet anytime
                   we read a secret. */
                if (tvb_length_remaining(tvb, foffset) > 4)
                {
                    foffset = sss_string(tvb, hf_user, atree, foffset, TRUE, 0);
                }
                break;
            case 2:
                foffset += 4;
                foffset = sss_string(tvb, hf_secret, atree, foffset, TRUE, 0);
                if (tvb_length_remaining(tvb, foffset) > 4)
                {
                    msg_length = tvb_get_letohl(tvb, foffset);
                    foffset += 4;
                    proto_tree_add_item(atree, hf_enc_data, tvb, foffset, msg_length, TRUE);
                }
                break;
            case 3:
            case 4:
                foffset = sss_string(tvb, hf_secret, atree, foffset, TRUE, 0);
                if (tvb_length_remaining(tvb, foffset) > 4)
                {
                    foffset = sss_string(tvb, hf_user, atree, foffset, TRUE, 0);
                }
                break;
            case 5:
                break;
            case 6:
                foffset = sss_string(tvb, hf_secret, atree, foffset, TRUE, 0);
                if (tvb_length_remaining(tvb, foffset) > 4)
                {
                    foffset = sss_string(tvb, hf_user, atree, foffset, TRUE, 0);
                }
                break;
            case 7:
                msg_length = tvb_get_letohl(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(atree, hf_enc_cred, tvb, foffset, msg_length, FALSE);
                break;
            case 8:
            case 9:
            default:
                break;
            }

        }
        else
        {
            if (check_col(pinfo->cinfo, COL_INFO)) {
               col_add_fstr(pinfo->cinfo, COL_INFO, "C SecretStore - fragment");
               proto_tree_add_text(ncp_tree, tvb, foffset, 4, "Fragment");
            }
            /* Fragments don't really carry a subverb so store 0xff as the subverb number */
            if (request_value) {
                request_value->req_nds_flags=255;
            }
            if (tvb_length_remaining(tvb, foffset) > 8) 
            {
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_enc_data, tvb, foffset, tvb_length_remaining(tvb, foffset), TRUE);
            }
        }
        break;
    case 3:
        /* No Op */
        break;
    default:
        break;
    }
}

void
dissect_sss_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ncp_tree, guint8 subfunc, ncp_req_hash_value	*request_value)
{
    guint32             foffset=0;
    guint32             subverb=0;
    guint8              msgverb=0;
    guint32             msg_length=0;
    guint32             return_code=0;
    guint32             number_of_items=0;
    gint32              length_of_string=0;
    guint32             i = 0;
    
    proto_tree          *atree;
    proto_item          *aitem;
    
    foffset = 8;
    if (request_value) {
        subverb = request_value->req_nds_flags;
        msgverb = request_value->nds_request_verb;
    }
	if (check_col(pinfo->cinfo, COL_INFO)) {
       col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSSS");
    }
    if (tvb_length_remaining(tvb, foffset)<4) {
        return;
    }
    aitem = proto_tree_add_text(ncp_tree, tvb, foffset, tvb_length_remaining(tvb, foffset), "Function: %s", match_strval(subfunc, sss_func_enum));
    atree = proto_item_add_subtree(aitem, ett_sss);
    switch (subfunc) {
    case 1:
        proto_tree_add_item(atree, hf_flags, tvb, foffset, 4, TRUE);
        foffset += 4;
        proto_tree_add_item(atree, hf_sss_version, tvb, foffset, 4, TRUE);
        foffset += 4;
        break;
    case 2:
        if (match_strval(subverb, sss_verb_enum)) {
            proto_tree_add_text(atree, tvb, foffset, tvb_length_remaining(tvb, foffset), "Verb: %s", match_strval(subverb, sss_verb_enum));
        }
        proto_tree_add_item(atree, hf_length, tvb, foffset, 4, TRUE);
        msg_length = tvb_get_letohl(tvb, foffset);
        return_code = tvb_get_ntohl(tvb, foffset+msg_length);
        foffset += 4;
        proto_tree_add_item(atree, hf_frag_handle, tvb, foffset, 4, TRUE);
        foffset += 4;
        msg_length -= 4;
        if ((tvb_get_letohl(tvb, foffset-4)==0xffffffff) && (msg_length > 4)) 
        {
            foffset += 4;
            return_code = tvb_get_letohl(tvb, foffset);
            if ( match_strval(return_code, sss_errors_enum) != NULL ) 
            {
                expert_item = proto_tree_add_item(atree, hf_return_code, tvb, foffset, 4, TRUE);
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "SSS Error: %s", match_strval(return_code, sss_errors_enum));
                if (check_col(pinfo->cinfo, COL_INFO)) {
                   col_add_fstr(pinfo->cinfo, COL_INFO, "R Error - %s", match_strval(return_code, sss_errors_enum));
                }
                foffset+=4;
            }
            else
            {
                proto_tree_add_text(atree, tvb, foffset, 4, "Return Code: Success (0x00000000)");
                if (tvb_length_remaining(tvb, foffset) > 8) {
                    foffset += 4;
                    if (subverb == 6) 
                    {
                        foffset += 4;
                        number_of_items = tvb_get_letohl(tvb, foffset);
                        foffset += 8;
                        for (i=0; i<number_of_items; i++) 
                        {
                            length_of_string = find_delimiter(tvb, foffset);
                            if (length_of_string > tvb_length_remaining(tvb, foffset)) 
                            {
                                return;
                            }
                            foffset = sss_string(tvb, hf_secret, atree, foffset, TRUE, length_of_string);
                            if (tvb_length_remaining(tvb, foffset) < 8) 
                            {
                                return;
                            }
                            foffset++;
                        }

                    }
                    else
                    {
                        proto_tree_add_item(atree, hf_enc_data, tvb, foffset, tvb_length_remaining(tvb, foffset), TRUE);
                    }
                }
            }
        }
        else
        {
            proto_tree_add_text(atree, tvb, foffset, 4, "Return Code: Success (0x00000000)");
            if (tvb_length_remaining(tvb, foffset) > 8) {
                foffset += 4;
                proto_tree_add_item(atree, hf_enc_data, tvb, foffset, tvb_length_remaining(tvb, foffset), TRUE);
            }
        }
        break;
    case 3:
        break;
    default:
        break;
    }
}

void
proto_register_sss(void)
{
	static hf_register_info hf_sss[] = {
		{ &hf_buffer_size,
		{ "Buffer Size",		"sss.buffer", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Buffer Size", HFILL }},

		{ &hf_ping_version,
		{ "Ping Version",		"sss.ping_version", FT_UINT32, BASE_HEX, NULL, 0x0,
			"Ping Version", HFILL }},

		{ &hf_flags,
		{ "Flags",		"sss.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
			"Flags", HFILL }},

		{ &hf_context,
		{ "Context",		"sss.context", FT_UINT32, BASE_HEX, NULL, 0x0,
			"Context", HFILL }},

		{ &hf_frag_handle,
		{ "Fragment Handle",		"sss.frag_handle", FT_UINT32, BASE_HEX, NULL, 0x0,
			"Fragment Handle", HFILL }},

		{ &hf_length,
		{ "Length",		"sss.length", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Length", HFILL }},

        { &hf_verb,
        { "Verb",    "sss.verb",
          FT_UINT32,    BASE_HEX,   VALS(sss_verb_enum),   0x0,
          "Verb", HFILL }},

        { &hf_user,
        { "User",    "sss.user",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "User", HFILL }},

        { &hf_secret,
        { "Secret ID",    "sss.secret",
          FT_STRING,    BASE_NONE,   NULL,   0x0,
          "Secret ID", HFILL }},

		{ &hf_sss_version,
		{ "SecretStore Protocol Version",		"sss.version", FT_UINT32, BASE_HEX, NULL, 0x0,
			"SecretStore Protocol Version", HFILL }},

        { &hf_return_code,
		{ "Return Code",		"sss.return_code", FT_UINT32, BASE_HEX, VALS(sss_errors_enum), 0x0,
			"Return Code", HFILL }},
       
        { &hf_enc_cred,
        { "Encrypted Credential",    "sss.enc_cred",
          FT_BYTES,    BASE_NONE,   NULL,   0x0,
          "Encrypted Credential", HFILL }},

        { &hf_enc_data,
        { "Encrypted Data",    "sss.enc_data",
          FT_BYTES,    BASE_NONE,   NULL,   0x0,
          "Encrypted Data", HFILL }},
    
        { &hfbit1,
        { "Enhanced Protection", "ncp.sss_bit1", FT_BOOLEAN, 32, NULL, 0x00000001, "", HFILL }},

        { &hfbit2,
        { "Create ID", "ncp.sss_bit2", FT_BOOLEAN, 32, NULL, 0x00000002, "", HFILL }},

        { &hfbit3,
        { "Remove Lock", "ncp.sss_bit3", FT_BOOLEAN, 32, NULL, 0x00000004, "", HFILL }},

        { &hfbit4,
        { "Repair", "ncp.sss_bit4", FT_BOOLEAN, 32, NULL, 0x00000008, "", HFILL }},

        { &hfbit5,
        { "Unicode", "ncp.sss_bit5", FT_BOOLEAN, 32, NULL, 0x00000010, "", HFILL }},

        { &hfbit6,
        { "EP Master Password Used", "ncp.sss_bit6", FT_BOOLEAN, 32, NULL, 0x00000020, "", HFILL }},

        { &hfbit7,
        { "EP Password Used", "ncp.sss_bit7", FT_BOOLEAN, 32, NULL, 0x00000040, "", HFILL }},

        { &hfbit8,
        { "Set Tree Name", "ncp.sss_bit8", FT_BOOLEAN, 32, NULL, 0x00000080, "", HFILL }},

        { &hfbit9,
        { "Get Context", "ncp.sss_bit9", FT_BOOLEAN, 32, NULL, 0x00000100, "", HFILL }},

        { &hfbit10,
        { "Destroy Context", "ncp.sss_bit10", FT_BOOLEAN, 32, NULL, 0x00000200, "", HFILL }},

        { &hfbit11,
        { "Not Defined", "ncp.sss_bit11", FT_BOOLEAN, 32, NULL, 0x00000400, "", HFILL }},

        { &hfbit12,
        { "Not Defined", "ncp.sss_bit12", FT_BOOLEAN, 32, NULL, 0x00000800, "", HFILL }},

        { &hfbit13,
        { "Not Defined", "ncp.sss_bit13", FT_BOOLEAN, 32, NULL, 0x00001000, "", HFILL }},

        { &hfbit14,
        { "Not Defined", "ncp.sss_bit14", FT_BOOLEAN, 32, NULL, 0x00002000, "", HFILL }},

        { &hfbit15,
        { "Not Defined", "ncp.sss_bit15", FT_BOOLEAN, 32, NULL, 0x00004000, "", HFILL }},

        { &hfbit16,
        { "Not Defined", "ncp.sss_bit16", FT_BOOLEAN, 32, NULL, 0x00008000, "", HFILL }},
    
        { &hfbit17,
        { "EP Lock", "ncp.sss_bit17", FT_BOOLEAN, 32, NULL, 0x00010000, "", HFILL }},
    
        { &hfbit18,
        { "Not Initialized", "ncp.sss_bit18", FT_BOOLEAN, 32, NULL, 0x00020000, "", HFILL }},
    
        { &hfbit19,
        { "Enhanced Protection", "ncp.sss_bit19", FT_BOOLEAN, 32, NULL, 0x00040000, "", HFILL }},
    
        { &hfbit20,
        { "Store Not Synced", "ncp.sss_bit20", FT_BOOLEAN, 32, NULL, 0x00080000, "", HFILL }},
    
        { &hfbit21,
        { "Admin Last Modified", "ncp.sss_bit21", FT_BOOLEAN, 32, NULL, 0x00100000, "", HFILL }},
    
        { &hfbit22,
        { "EP Password Present", "ncp.sss_bit22", FT_BOOLEAN, 32, NULL, 0x00200000, "", HFILL }},
    
        { &hfbit23,
        { "EP Master Password Present", "ncp.sss_bit23", FT_BOOLEAN, 32, NULL, 0x00400000, "", HFILL }},
    
        { &hfbit24,
        { "MP Disabled", "ncp.sss_bit24", FT_BOOLEAN, 32, NULL, 0x00800000, "", HFILL }},
    
        { &hfbit25,
        { "Not Defined", "ncp.sss_bit25", FT_BOOLEAN, 32, NULL, 0x01000000, "", HFILL }},
    
        { &hfbit26,
        { "Not Defined", "ncp.sss_bit26", FT_BOOLEAN, 32, NULL, 0x02000000, "", HFILL }},
    
        { &hfbit27,
        { "Not Defined", "ncp.sss_bit27", FT_BOOLEAN, 32, NULL, 0x04000000, "", HFILL }},
    
        { &hfbit28,
        { "Not Defined", "ncp.sss_bit28", FT_BOOLEAN, 32, NULL, 0x08000000, "", HFILL }},
    
        { &hfbit29,
        { "Not Defined", "ncp.sss_bit29", FT_BOOLEAN, 32, NULL, 0x10000000, "", HFILL }},
    
        { &hfbit30,
        { "Not Defined", "ncp.sss_bit30", FT_BOOLEAN, 32, NULL, 0x20000000, "", HFILL }},
    
        { &hfbit31,
        { "Not Defined", "ncp.sss_bit31", FT_BOOLEAN, 32, NULL, 0x40000000, "", HFILL }},
    
        { &hfbit32,
        { "Not Defined", "ncp.sss_bit32", FT_BOOLEAN, 32, NULL, 0x80000000, "", HFILL }},
    
    };

	static gint *ett[] = {
		&ett_sss,
	};
	/*module_t *sss_module;*/
	
	proto_sss = proto_register_protocol("Novell SecretStore Services", "SSS", "sss");
	proto_register_field_array(proto_sss, hf_sss, array_length(hf_sss));
	proto_register_subtree_array(ett, array_length(ett));
}
