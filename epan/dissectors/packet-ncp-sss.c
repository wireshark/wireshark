/* packet-ncp-sss.c
 * Routines for Novell SecretStore Services
 * Greg Morris <gmorris@novell.com>
 * Copyright (c) Novell, Inc. 2002-2003
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-ncp-int.h"
#include "packet-ncp-sss.h"

void proto_register_sss(void);

static int ett_sss;

static int proto_sss;
static int hf_sss_buffer_size;
static int hf_sss_ping_version;
static int hf_sss_flags;
static int hf_sss_context;
static int hf_sss_frag_handle;
static int hf_sss_length;
static int hf_sss_verb;
static int hf_sss_user;
static int hf_sss_secret;
static int hf_sss_sss_version;
static int hf_sss_return_code;
static int hf_sss_enc_cred;
static int hf_sss_enc_data;
static int hf_sss_bit1;
static int hf_sss_bit2;
static int hf_sss_bit3;
static int hf_sss_bit4;
static int hf_sss_bit5;
static int hf_sss_bit6;
static int hf_sss_bit7;
static int hf_sss_bit8;
static int hf_sss_bit9;
static int hf_sss_bit10;
static int hf_sss_bit11;
static int hf_sss_bit12;
static int hf_sss_bit13;
static int hf_sss_bit14;
static int hf_sss_bit15;
static int hf_sss_bit16;
static int hf_sss_bit17;
static int hf_sss_bit18;
static int hf_sss_bit19;
static int hf_sss_bit20;
static int hf_sss_bit21;
static int hf_sss_bit22;
static int hf_sss_bit23;
static int hf_sss_bit24;
static int hf_sss_bit25;
static int hf_sss_bit26;
static int hf_sss_bit27;
static int hf_sss_bit28;
static int hf_sss_bit29;
static int hf_sss_bit30;
static int hf_sss_bit31;
static int hf_sss_bit32;

static expert_field ei_return_code;

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
process_flags(proto_tree *sss_tree, tvbuff_t *tvb, uint32_t foffset)
{
    char                    flags_str[1024];
    const char             *sep;
    proto_item             *tinew;
    proto_tree             *flags_tree;
    uint32_t                i;
    uint32_t                bvalue = 0;
    uint32_t                flags = 0;

    bvalue = 0x00000001;
    flags_str[0]='\0';
    sep="";
    flags = tvb_get_ntohl(tvb, foffset);
    for (i = 0 ; i < 256; i++) {
        if (flags & bvalue) {
            (void) g_strlcat(flags_str, sep, 1024);
            switch(bvalue) {
                case 0x00000001:
                        (void) g_strlcat(flags_str, "Enhanced Protection", 1024);
                        break;
                case 0x00000002:
                        (void) g_strlcat(flags_str, "Create ID", 1024);
                        break;
                case 0x00000004:
                        (void) g_strlcat(flags_str, "Remove Lock", 1024);
                        break;
                case 0x00000008:
                        (void) g_strlcat(flags_str, "Repair", 1024);
                        break;
                case 0x00000010:
                        (void) g_strlcat(flags_str, "Unicode", 1024);
                        break;
                case 0x00000020:
                        (void) g_strlcat(flags_str, "EP Master Password Used", 1024);
                        break;
                case 0x00000040:
                        (void) g_strlcat(flags_str, "EP Password Used", 1024);
                        break;
                case 0x00000080:
                        (void) g_strlcat(flags_str, "Set Tree Name", 1024);
                        break;
                case 0x00000100:
                        (void) g_strlcat(flags_str, "Get Context", 1024);
                        break;
                case 0x00000200:
                        (void) g_strlcat(flags_str, "Destroy Context", 1024);
                        break;
                case 0x00000400:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x00000800:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x00001000:
                        (void) g_strlcat(flags_str, "EP Lock", 1024);
                        break;
                case 0x00002000:
                        (void) g_strlcat(flags_str, "Not Initialized", 1024);
                        break;
                case 0x00004000:
                        (void) g_strlcat(flags_str, "Enhanced Protection", 1024);
                        break;
                case 0x00008000:
                        (void) g_strlcat(flags_str, "Store Not Synced", 1024);
                        break;
                case 0x00010000:
                        (void) g_strlcat(flags_str, "Admin Last Modified", 1024);
                        break;
                case 0x00020000:
                        (void) g_strlcat(flags_str, "EP Password Present", 1024);
                        break;
                case 0x00040000:
                        (void) g_strlcat(flags_str, "EP Master Password Present", 1024);
                        break;
                case 0x00080000:
                        (void) g_strlcat(flags_str, "MP Disabled", 1024);
                        break;
                case 0x00100000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x00200000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x00400000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x00800000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x01000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x02000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x04000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x08000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x10000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x20000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x40000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                case 0x80000000:
                        (void) g_strlcat(flags_str, "Not Defined", 1024);
                        break;
                default:
                        break;
            }
            sep = ", ";
        }
            bvalue = bvalue*2;
    }

    tinew = proto_tree_add_uint(sss_tree, hf_sss_flags, tvb, foffset, 4, flags);
    flags_tree = proto_item_add_subtree(tinew, ett_nds);

    bvalue = 0x00000001;

    for (i = 0 ; i < 256; i++ ) {
        if (flags & bvalue) {
            switch(bvalue) {
                case 0x00000001:
                        proto_tree_add_item(flags_tree, hf_sss_bit1, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000002:
                    proto_tree_add_item(flags_tree, hf_sss_bit2, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000004:
                    proto_tree_add_item(flags_tree, hf_sss_bit3, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000008:
                        proto_tree_add_item(flags_tree, hf_sss_bit4, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000010:
                        proto_tree_add_item(flags_tree, hf_sss_bit5, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000020:
                        proto_tree_add_item(flags_tree, hf_sss_bit6, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000040:
                        proto_tree_add_item(flags_tree, hf_sss_bit7, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000080:
                        proto_tree_add_item(flags_tree, hf_sss_bit8, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000100:
                        proto_tree_add_item(flags_tree, hf_sss_bit9, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000200:
                        proto_tree_add_item(flags_tree, hf_sss_bit10, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000400:
                        proto_tree_add_item(flags_tree, hf_sss_bit11, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00000800:
                        proto_tree_add_item(flags_tree, hf_sss_bit12, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00001000:
                        proto_tree_add_item(flags_tree, hf_sss_bit13, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00002000:
                        proto_tree_add_item(flags_tree, hf_sss_bit14, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00004000:
                        proto_tree_add_item(flags_tree, hf_sss_bit15, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00008000:
                        proto_tree_add_item(flags_tree, hf_sss_bit16, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00010000:
                        proto_tree_add_item(flags_tree, hf_sss_bit17, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00020000:
                        proto_tree_add_item(flags_tree, hf_sss_bit18, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00040000:
                        proto_tree_add_item(flags_tree, hf_sss_bit19, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00080000:
                        proto_tree_add_item(flags_tree, hf_sss_bit20, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00100000:
                        proto_tree_add_item(flags_tree, hf_sss_bit21, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00200000:
                        proto_tree_add_item(flags_tree, hf_sss_bit22, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00400000:
                        proto_tree_add_item(flags_tree, hf_sss_bit23, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x00800000:
                        proto_tree_add_item(flags_tree, hf_sss_bit24, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x01000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit25, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x02000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit26, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x04000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit27, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x08000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit28, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x10000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit29, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x20000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit30, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x40000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit31, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                case 0x80000000:
                        proto_tree_add_item(flags_tree, hf_sss_bit32, tvb, foffset, 4, ENC_BIG_ENDIAN);
                        break;
                default:
                        break;
            }
        }
        bvalue = bvalue*2;
    }
    return;
}

/* Find the delimiter, '*'.
 * Returns the number of bytes from foffset to the delimiter or 0 if not
 * found within 256 bytes from foffset */
static int
find_delimiter(tvbuff_t *tvb, int foffset)
{
    int offset;

    offset = tvb_find_guint8(tvb, foffset, 256, '*');
    if (offset >= foffset) {
        return offset - foffset;
    }
    return 0;
}

static int
sss_string(tvbuff_t* tvb, int hfinfo, proto_tree *sss_tree, int offset, bool little, uint32_t length)
{
    int     foffset = offset;
    uint32_t str_length;
    char    buffer[1024];
    uint32_t i;
    uint8_t c_char;
    int length_remaining;

    if (length==0) {
        if (little) {
            str_length = tvb_get_letohl(tvb, foffset);
        } else {
            str_length = tvb_get_ntohl(tvb, foffset);
        }
        foffset += 4;
    } else {
        str_length = length;
    }
    length_remaining = tvb_captured_length_remaining(tvb, foffset);
    if (length_remaining <= 0) {
        return foffset;
    }
    if (str_length > (unsigned)length_remaining || str_length > (sizeof(buffer)-1)) {
        proto_tree_add_string(sss_tree, hfinfo, tvb, foffset,
            length_remaining + 4, "<String too long to process>");
        foffset += length_remaining;
        return foffset;
    }
    if (str_length == 0) {
        proto_tree_add_string(sss_tree, hfinfo, tvb, offset, 4, "<Not Specified>");
        return foffset;
    }
    for ( i = 0; i < str_length; i++ ) {
        c_char = tvb_get_uint8(tvb, foffset);
        if (g_ascii_isprint(c_char)) {
            buffer[i] = c_char;
        } else {
            if (c_char) {
                buffer[i] = '.';
            } else {
                /* Skip NULL-terminators */
                i--;
                str_length--;
            }
        }
        foffset++;
    }
    buffer[i] = '\0';

    if (length==0) {
        if (little) {
            str_length = tvb_get_letohl(tvb, offset);
        } else {
            str_length = tvb_get_ntohl(tvb, offset);
        }
        offset += 4;
    } else {
        str_length = length;
    }
    proto_tree_add_string(sss_tree, hfinfo, tvb, offset, str_length, buffer);
    return foffset;
}

void
dissect_sss_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ncp_tree, ncp_req_hash_value *request_value)
{
    uint8_t             /*func,*/ subfunc = 0;
    uint32_t            subverb=0;
    uint32_t            msg_length=0;
    uint32_t            foffset= 0;
    proto_tree          *atree;
    proto_item          *aitem;


    if (tvb_reported_length_remaining(tvb, foffset)<4) {
        return;
    }
    foffset = 6;
    /*func = tvb_get_uint8(tvb, foffset);*/
    foffset += 1;
    subfunc = tvb_get_uint8(tvb, foffset);
    foffset += 1;

    /* Fill in the PROTOCOL & INFO  columns. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSSS");
    col_add_fstr(pinfo->cinfo, COL_INFO, "C SecretStore - %s", val_to_str(subfunc, sss_func_enum, "Unknown (%d)"));

    switch (subfunc) {
    case 1:
        atree = proto_tree_add_subtree_format(ncp_tree, tvb, foffset, -1, ett_sss, NULL, "Packet Type: %s", val_to_str(subfunc, sss_func_enum, "Unknown (%d)"));
        proto_tree_add_item(atree, hf_sss_ping_version, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        foffset += 4;
        proto_tree_add_item(atree, hf_sss_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        /*foffset += 4;*/
        break;
    case 2:
        proto_tree_add_item(ncp_tree, hf_sss_frag_handle, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        if (tvb_get_letohl(tvb, foffset)==0xffffffff) { /* Fragment handle of -1 means no fragment. So process packet */
            foffset += 4;
            proto_tree_add_item(ncp_tree, hf_sss_buffer_size, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
            foffset += 4;
            proto_tree_add_item(ncp_tree, hf_sss_length, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
            foffset += 4;
            foffset += 12; /* Blank Context */
            subverb = tvb_get_letohl(tvb, foffset);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(subverb, sss_verb_enum, "Unknown (%d)"));

            aitem = proto_tree_add_item(ncp_tree, hf_sss_verb, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
            atree = proto_item_add_subtree(aitem, ett_sss);
            if (request_value) {
                request_value->req_nds_flags=subverb;
            }
            foffset += 4;
            process_flags(atree, tvb, foffset);
            foffset += 4;
            proto_tree_add_item(atree, hf_sss_context, tvb, foffset, 4, ENC_BIG_ENDIAN);
            foffset += 4;
            switch (subverb) {
            case 0:
                foffset += 4;
                /*foffset =*/ sss_string(tvb, hf_sss_user, atree, foffset, true, 0);
                break;
            case 1:
                foffset = sss_string(tvb, hf_sss_secret, atree, foffset, true, 0);
                msg_length = tvb_get_letohl(tvb, foffset);
                foffset += (msg_length+4);   /* Unsure of what this length and parameter are */
                /* A bad secret of length greater then 256 characters will cause frag
                   packets and then we will see these as malformed packets.
                   So check to make sure we still have data in the packet anytime
                   we read a secret. */
                if (tvb_reported_length_remaining(tvb, foffset) > 4) {
                    /*foffset =*/ sss_string(tvb, hf_sss_user, atree, foffset, true, 0);
                }
                break;
            case 2:
                foffset += 4;
                foffset = sss_string(tvb, hf_sss_secret, atree, foffset, true, 0);
                if (tvb_reported_length_remaining(tvb, foffset) > 4) {
                    msg_length = tvb_get_letohl(tvb, foffset);
                    foffset += 4;
                    if (tvb_captured_length_remaining(tvb, foffset) < (int) msg_length) {
                        proto_tree_add_item(atree, hf_sss_enc_data, tvb, foffset, -1, ENC_NA);
                    } else {
                        proto_tree_add_item(atree, hf_sss_enc_data, tvb, foffset, msg_length, ENC_NA);
                    }
                }
                break;
            case 3:
            case 4:
                foffset = sss_string(tvb, hf_sss_secret, atree, foffset, true, 0);
                if (tvb_reported_length_remaining(tvb, foffset) > 4) {
                    /*foffset =*/ sss_string(tvb, hf_sss_user, atree, foffset, true, 0);
                }
                break;
            case 5:
                break;
            case 6:
                foffset = sss_string(tvb, hf_sss_secret, atree, foffset, true, 0);
                if (tvb_reported_length_remaining(tvb, foffset) > 4) {
                    /*foffset =*/ sss_string(tvb, hf_sss_user, atree, foffset, true, 0);
                }
                break;
            case 7:
                msg_length = tvb_get_letohl(tvb, foffset);
                foffset += 4;
                proto_tree_add_item(atree, hf_sss_enc_cred, tvb, foffset, msg_length, ENC_NA);
                break;
            case 8:
            case 9:
            default:
                break;
            }
        } else {
            col_set_str(pinfo->cinfo, COL_INFO, "C SecretStore - fragment");

            /* Fragments don't really carry a subverb so store 0xff as the subverb number */
            if (request_value) {
                request_value->req_nds_flags=255;
            }
            if (tvb_reported_length_remaining(tvb, foffset) > 8) {
                foffset += 4;
                proto_tree_add_item(ncp_tree, hf_sss_enc_data, tvb, foffset, -1, ENC_NA);
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
dissect_sss_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ncp_tree, uint8_t subfunc, ncp_req_hash_value *request_value)
{
    uint32_t            foffset=0;
    uint32_t            subverb=0;
    uint32_t            msg_length=0;
    uint32_t            return_code=0;
    uint32_t            number_of_items=0;
    int32_t             length_of_string=0;
    uint32_t            i = 0;
    const char          *str;

    proto_tree          *atree;
    proto_item          *expert_item;

    foffset = 8;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSSS");
    if (tvb_captured_length_remaining(tvb, foffset)<4) {
        return;
    }
    atree = proto_tree_add_subtree_format(ncp_tree, tvb, foffset, -1, ett_sss, NULL, "Function: %s", val_to_str_const(subfunc, sss_func_enum, "Unknown"));
    switch (subfunc) {
    case 1:
        proto_tree_add_item(atree, hf_sss_flags, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        foffset += 4;
        proto_tree_add_item(atree, hf_sss_sss_version, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        /*foffset += 4;*/
        break;
    case 2:
        if (request_value) {
            subverb = request_value->req_nds_flags;
            str = try_val_to_str(subverb, sss_verb_enum);
            if (str) {
                proto_tree_add_uint(atree, hf_sss_verb, tvb, foffset, -1, subverb);
            }
        }
        proto_tree_add_item(atree, hf_sss_length, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        msg_length = tvb_get_letohl(tvb, foffset);
        foffset += 4;
        proto_tree_add_item(atree, hf_sss_frag_handle, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
        foffset += 4;
        msg_length -= 4;
        if ((tvb_get_letohl(tvb, foffset-4)==0xffffffff) && (msg_length > 4)) {
            foffset += 4;
            return_code = tvb_get_letohl(tvb, foffset);
            str = try_val_to_str(return_code, sss_errors_enum);
            if (str) {
                expert_item = proto_tree_add_item(atree, hf_sss_return_code, tvb, foffset, 4, ENC_LITTLE_ENDIAN);
                expert_add_info_format(pinfo, expert_item, &ei_return_code, "SSS Error: %s", str);
                col_add_fstr(pinfo->cinfo, COL_INFO, "R Error - %s", val_to_str(return_code, sss_errors_enum, "Unknown (%d)"));
                /*foffset+=4;*/
            } else {
                proto_tree_add_uint_format_value(atree, hf_sss_return_code, tvb, foffset, 4, 0, "Success (0x00000000)");
                if (tvb_reported_length_remaining(tvb, foffset) > 8) {
                    foffset += 4;
                    if (request_value && subverb == 6) {
                        foffset += 4;
                        number_of_items = tvb_get_letohl(tvb, foffset);
                        foffset += 8;
                        for (i=0; i<number_of_items; i++) {
                            length_of_string = find_delimiter(tvb, foffset);
                            if (length_of_string > tvb_reported_length_remaining(tvb, foffset)) {
                                return;
                            }
                            foffset = sss_string(tvb, hf_sss_secret, atree, foffset, true, length_of_string);
                            if (tvb_reported_length_remaining(tvb, foffset) < 8) {
                                return;
                            }
                            foffset++;
                        }
                    } else {
                        proto_tree_add_item(atree, hf_sss_enc_data, tvb, foffset, tvb_captured_length_remaining(tvb, foffset), ENC_NA);
                    }
                }
            }
        } else {
            proto_tree_add_uint_format_value(atree, hf_sss_return_code, tvb, foffset, 4, 0, "Success (0x00000000)");
            if (tvb_reported_length_remaining(tvb, foffset) > 8) {
                foffset += 4;
                proto_tree_add_item(atree, hf_sss_enc_data, tvb, foffset, tvb_captured_length_remaining(tvb, foffset), ENC_NA);
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
        { &hf_sss_buffer_size,
        { "Buffer Size", "sss.buffer", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_ping_version,
        { "Ping Version", "sss.ping_version", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_flags,
        { "Flags", "sss.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_context,
        { "Context", "sss.context", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_frag_handle,
        { "Fragment Handle", "sss.frag_handle", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_length,
        { "Length", "sss.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_verb,
        { "Verb", "sss.verb", FT_UINT32, BASE_HEX,   VALS(sss_verb_enum), 0x0, NULL, HFILL }},

        { &hf_sss_user,
        { "User",  "sss.user", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_secret,
        { "Secret ID", "sss.secret", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_sss_version,
        { "SecretStore Protocol Version", "sss.version", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_return_code,
        { "Return Code", "sss.return_code", FT_UINT32, BASE_HEX, VALS(sss_errors_enum), 0x0, NULL, HFILL }},

        { &hf_sss_enc_cred,
        { "Encrypted Credential", "sss.enc_cred", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_enc_data,
        { "Encrypted Data", "sss.enc_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_sss_bit1,
        { "Enhanced Protection", "sss.bit1", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }},

        { &hf_sss_bit2,
        { "Create ID", "sss.bit2", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }},

        { &hf_sss_bit3,
        { "Remove Lock", "sss.bit3", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }},

        { &hf_sss_bit4,
        { "Repair", "sss.bit4", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }},

        { &hf_sss_bit5,
        { "Unicode", "sss.bit5", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL }},

        { &hf_sss_bit6,
        { "EP Master Password Used", "sss.bit6", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL }},

        { &hf_sss_bit7,
        { "EP Password Used", "sss.bit7", FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL }},

        { &hf_sss_bit8,
        { "Set Tree Name", "sss.bit8", FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL }},

        { &hf_sss_bit9,
        { "Get Context", "sss.bit9", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL }},

        { &hf_sss_bit10,
        { "Destroy Context", "sss.bit10", FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL }},

        { &hf_sss_bit11,
        { "Not Defined", "sss.bit11", FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL }},

        { &hf_sss_bit12,
        { "Not Defined", "sss.bit12", FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL }},

        { &hf_sss_bit13,
        { "Not Defined", "sss.bit13", FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL }},

        { &hf_sss_bit14,
        { "Not Defined", "sss.bit14", FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL }},

        { &hf_sss_bit15,
        { "Not Defined", "sss.bit15", FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL }},

        { &hf_sss_bit16,
        { "Not Defined", "sss.bit16", FT_BOOLEAN, 32, NULL, 0x00008000, NULL, HFILL }},

        { &hf_sss_bit17,
        { "EP Lock", "sss.bit17", FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL }},

        { &hf_sss_bit18,
        { "Not Initialized", "sss.bit18", FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL }},

        { &hf_sss_bit19,
        { "Enhanced Protection", "sss.bit19", FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL }},

        { &hf_sss_bit20,
        { "Store Not Synced", "sss.bit20", FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL }},

        { &hf_sss_bit21,
        { "Admin Last Modified", "sss.bit21", FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL }},

        { &hf_sss_bit22,
        { "EP Password Present", "sss.bit22", FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL }},

        { &hf_sss_bit23,
        { "EP Master Password Present", "sss.bit23", FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL }},

        { &hf_sss_bit24,
        { "MP Disabled", "sss.bit24", FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL }},

        { &hf_sss_bit25,
        { "Not Defined", "sss.bit25", FT_BOOLEAN, 32, NULL, 0x01000000, NULL, HFILL }},

        { &hf_sss_bit26,
        { "Not Defined", "sss.bit26", FT_BOOLEAN, 32, NULL, 0x02000000, NULL, HFILL }},

        { &hf_sss_bit27,
        { "Not Defined", "sss.bit27", FT_BOOLEAN, 32, NULL, 0x04000000, NULL, HFILL }},

        { &hf_sss_bit28,
        { "Not Defined", "sss.bit28", FT_BOOLEAN, 32, NULL, 0x08000000, NULL, HFILL }},

        { &hf_sss_bit29,
        { "Not Defined", "sss.bit29", FT_BOOLEAN, 32, NULL, 0x10000000, NULL, HFILL }},

        { &hf_sss_bit30,
        { "Not Defined", "sss.bit30", FT_BOOLEAN, 32, NULL, 0x20000000, NULL, HFILL }},

        { &hf_sss_bit31,
        { "Not Defined", "sss.bit31", FT_BOOLEAN, 32, NULL, 0x40000000, NULL, HFILL }},

        { &hf_sss_bit32,
        { "Not Defined", "sss.bit32", FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_sss
    };

    static ei_register_info ei[] = {
        { &ei_return_code, { "sss.return_code.expert", PI_RESPONSE_CODE, PI_NOTE, "SSS Error", EXPFILL }}
    };

    expert_module_t* expert_sss;
    /*module_t *sss_module;*/

    proto_sss = proto_register_protocol("Novell SecretStore Services", "SSS", "sss");
    proto_register_field_array(proto_sss, hf_sss, array_length(hf_sss));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sss = expert_register_protocol(proto_sss);
    expert_register_field_array(expert_sss, ei, array_length(ei));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

