/* packet-llrp.c
 * EPCglobal Low-Level Reader Protocol Packet Dissector
 *
 * Copyright 2008, Intermec Technologies Corp. <matt.poduska@intermec.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

/* Configurable Options */
#define LLRP_RESOLVE_VENDOR_ID
#define LLRP_DISSECTOR_DEBUG
#define LLRP_PARSER_DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <epan/pint.h> /* For pntohl */
#include <epan/filesystem.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/report_err.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/emem.h>
#include <epan/expert.h>

#ifdef LLRP_RESOLVE_VENDOR_ID
#include <epan/value_string.h>
#include <epan/sminmpec.h>
#endif /* LLRP_RESOLVE_VENDOR_ID */

#include <epan/dissectors/packet-tcp.h>

#include "llrpparsetypes.h"
#include "llrpparseinc.h"
#include "llrpparsehelp.h"
#include "llrpparse.h"

#define TCP_PORT_EPC_LLRP            5084    /* IANA assigned TCP port number */
#define PROTO_NAME_LLRP              "llrp"  /* must be lowercase */
#define PROTO_SHORT_DESCRIPTION_LLRP "LLRP"
#define PROTO_DESCRIPTION_LLRP       "EPCglobal RFID Low-Level Reader Protocol"
#define LLRP_MAX_PARAMETER_DEPTH     10

#ifdef LLRP_RESOLVE_VENDOR_ID
static const char *llrp_ws_find_vendor_id(const unsigned long vendor_id);
#endif /* LLRP_RESOLVE_VENDOR_ID */

static gint gbl_llrpTcpPort = TCP_PORT_EPC_LLRP;

typedef struct
{
    proto_tree *tree[LLRP_MAX_PARAMETER_DEPTH];
    tvbuff_t *tvb;
    unsigned long tvb_offset;       
    packet_info *pinfo;
    int quiet_parse;  /* When nonzero, don't display any parse info */
} t_llrp_parse_info;
static t_llrp_parse_info llrp_parse_info;

/* --------------------------------------------------------------------------------------- */
/* Dissector Display Tree Information                                                      */

static int proto_epc_llrp = -1;

static gint hf_llrp_message_version = -1;
static gint hf_llrp_message_type = -1;
static gint hf_llrp_message_length = -1;
static gint hf_llrp_message_id = -1;
static gint hf_llrp_message_parm = -1;
static gint hf_llrp_message_field = -1;
static gint hf_llrp_field_type = -1;
static gint hf_llrp_field_count = -1;
static gint hf_llrp_field_bitlength = -1;
static gint hf_llrp_field_value_u1 = -1;
static gint hf_llrp_field_value_u2 = -1;
static gint hf_llrp_field_value_u8 = -1;
static gint hf_llrp_field_value_s8 = -1;
static gint hf_llrp_field_value_u16 = -1;
static gint hf_llrp_field_value_s16 = -1;
static gint hf_llrp_field_value_u32 = -1;
static gint hf_llrp_field_value_s32 = -1;
static gint hf_llrp_field_value_u64 = -1;
static gint hf_llrp_field_value_s64 = -1;
static gint hf_llrp_field_value_variable = -1;
static gint hf_llrp_field_enumeration = -1;
static gint hf_llrp_parameter_type= -1;
static gint hf_llrp_parameter_length= -1;
static gint hf_llrp_custparm_vendorid= -1;
static gint hf_llrp_custparm_subtype= -1;
static hf_register_info hf_llrp[] =
{
    /* Message/header */
    { &hf_llrp_message_version, { "Version", PROTO_NAME_LLRP ".version", FT_UINT8,
                                  BASE_DEC, NULL, 0x00, "llrp message protocol version", HFILL }},
    { &hf_llrp_message_type,    { "Message Type", PROTO_NAME_LLRP ".type", FT_UINT16,
                                  BASE_DEC, NULL, 0x00, "llrp message type", HFILL }},
    { &hf_llrp_message_length,  { "Message Length", PROTO_NAME_LLRP ".length", FT_UINT32,
                                  BASE_DEC, NULL, 0x00, "llrp message total length", HFILL }},
    { &hf_llrp_message_id,      { "Message ID", PROTO_NAME_LLRP ".id", FT_UINT32,
                                  BASE_DEC, NULL, 0x00, "llrp message ID", HFILL }},
    { &hf_llrp_message_parm,    { "Parameter", PROTO_NAME_LLRP ".parameter", FT_UINT16, BASE_DEC,
                                  NULL, 0x00, "llrp message parameter", HFILL }},
    { &hf_llrp_message_field,   { "Field", PROTO_NAME_LLRP ".field", FT_UINT16, BASE_DEC,
                                 NULL, 0x00, "llrp message field", HFILL }},

    /* Parameter */
    { &hf_llrp_parameter_type,   { "Type", PROTO_NAME_LLRP ".parameter.type", FT_UINT16, BASE_DEC,
                                   NULL, 0x00, "llrp parameter type", HFILL }},
    { &hf_llrp_parameter_length, { "Length (bytes)", PROTO_NAME_LLRP ".parameter.length", FT_UINT16, BASE_DEC,
                                   NULL, 0x00, "llrp parameter length", HFILL }},
    { &hf_llrp_custparm_vendorid,{ "VendorID", PROTO_NAME_LLRP ".custparam.vendorid", FT_UINT32, BASE_HEX,
                                   NULL, 0x00, "llrp custom parameter vendor ID", HFILL }},
    { &hf_llrp_custparm_subtype, { "Subtype", PROTO_NAME_LLRP ".custparam.subtype", FT_UINT16, BASE_DEC,
                                   NULL, 0x00, "llrp custom parameter subtype", HFILL }},

    /* Field */
    { &hf_llrp_field_type, { "Type", PROTO_NAME_LLRP ".field.type", FT_UINT16, BASE_DEC, NULL,
                             0x00, "llrp field type", HFILL }},
    { &hf_llrp_field_count, { "Count (items)", PROTO_NAME_LLRP ".field.count", FT_UINT16,
                                  BASE_DEC, NULL, 0x00, "llrp field count", HFILL }},
    { &hf_llrp_field_bitlength, { "Length (bits)", PROTO_NAME_LLRP ".field.length", FT_UINT16,
                                  BASE_DEC, NULL, 0x00, "llrp field bitlength", HFILL }},
    { &hf_llrp_field_value_u1, { "Value", PROTO_NAME_LLRP ".field.value", FT_UINT8,
                                  BASE_DEC, NULL, 0x00, "llrp field u1 value", HFILL }},
    { &hf_llrp_field_value_u2, { "Value", PROTO_NAME_LLRP ".field.value", FT_UINT8,
                                  BASE_DEC, NULL, 0x00, "llrp field u2 value", HFILL }},
    { &hf_llrp_field_value_u8, { "Value", PROTO_NAME_LLRP ".field.value", FT_UINT8,
                                  BASE_DEC, NULL, 0x00, "llrp field u8 value", HFILL }},
    { &hf_llrp_field_value_s8, { "Value", PROTO_NAME_LLRP ".field.value", FT_INT8,
                                  BASE_DEC, NULL, 0x00, "llrp field s8 value", HFILL }},
    { &hf_llrp_field_value_u16, { "Value", PROTO_NAME_LLRP ".field.value", FT_UINT16,
                                  BASE_DEC, NULL, 0x00, "llrp field u16 value", HFILL }},
    { &hf_llrp_field_value_s16, { "Value", PROTO_NAME_LLRP ".field.value", FT_INT16,
                                  BASE_DEC, NULL, 0x00, "llrp field s16 value", HFILL }},
    { &hf_llrp_field_value_u32, { "Value", PROTO_NAME_LLRP ".field.value", FT_UINT32,
                                  BASE_DEC, NULL, 0x00, "llrp field u32 value", HFILL }},
    { &hf_llrp_field_value_s32, { "Value", PROTO_NAME_LLRP ".field.value", FT_INT32,
                                  BASE_DEC, NULL, 0x00, "llrp field s32 value", HFILL }},
    { &hf_llrp_field_value_u64, { "Value", PROTO_NAME_LLRP ".field.value", FT_UINT64,
                                  BASE_DEC, NULL, 0x00, "llrp field u64 value", HFILL }},
    { &hf_llrp_field_value_s64, { "Value", PROTO_NAME_LLRP ".field.value", FT_INT64,
                                  BASE_DEC, NULL, 0x00, "llrp field s64 value", HFILL }},
    { &hf_llrp_field_value_variable, { "Value", PROTO_NAME_LLRP ".field.variable", FT_STRING,
                                  BASE_NONE, NULL, 0x00, "llrp field variable-length value", HFILL }},
    { &hf_llrp_field_enumeration, { "Enumeration", PROTO_NAME_LLRP ".field.enumeration", FT_STRING,
                                  BASE_NONE, NULL, 0x00, "llrp field enumeration", HFILL }},
};

/* All LLRP dissection display subtrees */
static gint ett_llrp_message = -1;
static gint ett_llrp_field = -1;
static gint ett_llrp_parameter = -1;
static gint *ett_llrp[]=
{
    &ett_llrp_message,
    &ett_llrp_field,
    &ett_llrp_parameter
};  


unsigned long llrp_ws_ntohl(unsigned long source)
{
    return pntohl(&source);
}
t_llrp_ntohl llrp_ntohl = llrp_ws_ntohl;

unsigned short llrp_ws_ntohs(unsigned short source)
{
    return pntohs(&source);
}
t_llrp_ntohs llrp_ntohs = llrp_ws_ntohs;

/* --------------------------------------------------------------------------------------- */
/* WireShark-Specific Parser Callbacks                                                     */

static void llrp_ws_DescendParseTree(t_llrp_parse_context *context, t_llrp_parse_info *info,
 proto_tree *tree)
{
    if(context->depth>= LLRP_MAX_PARAMETER_DEPTH)
    {
        #ifdef LLRP_DISSECTOR_DEBUG
        g_warning("Maximum parse depth exceeded (%u)", context->depth);
        #endif /* LLRP_DISSECTOR_DEBUG */
        info->quiet_parse= 1;
        return;
    }

    info->quiet_parse= 0;
    info->tree[context->depth]= tree;
}

static void llrp_ws_AscendParseTree(t_llrp_parse_context *context, t_llrp_parse_info *info)
{
    if(context->depth< LLRP_MAX_PARAMETER_DEPTH)
        info->quiet_parse= 0;
}

unsigned char *llrp_ws_StreamRead(void *context, const unsigned long length,
 const int wait_forever, unsigned long *consumed)
{
    t_llrp_parse_context *ctxt = (t_llrp_parse_context *) context;
    t_llrp_parse_info *info = (t_llrp_parse_info *) ctxt->data;
    unsigned char *buffer;

    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("llrp_ws_StreamRead (offset %u, length %u)", info->tvb_offset, length);
    #endif /* LLRP_DISSECTOR_DEBUG */

    buffer = (unsigned char *) tvb_get_ptr(info->tvb, info->tvb_offset, length);
    if(buffer != NULL)
    {
        info->tvb_offset += length;
        *consumed = length;
    }

    return buffer;
}

unsigned long llrp_ws_StreamGetOffset(void *context)
{
    t_llrp_parse_context *ctxt = (t_llrp_parse_context *) context;
    t_llrp_parse_info *info = (t_llrp_parse_info *) ctxt->data;
    
    g_warning("llrp_ws_StreamGetOffset (offset %u)", info->tvb_offset);
    return info->tvb_offset;
}                                                                  

int llrp_ws_HandleMessageStart(void *context, const unsigned char version,
 const unsigned short type, const unsigned long length, const unsigned long id, const char *name)
{
    proto_item *item;
    proto_tree *tree;
    t_llrp_parse_context *ctxt = (t_llrp_parse_context *) context;
    t_llrp_parse_info *info = (t_llrp_parse_info *) ctxt->data;

    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("llrp_ws_HandleMessageStart (type %d)", type);
    #endif /* LLRP_DISSECTOR_DEBUG */

    if(ctxt->depth != 0)
    {
        #ifdef LLRP_DISSECTOR_DEBUG
        g_warning("Invalid parse depth (%d)", ctxt->depth);
        #endif /* LLRP_DISSECTOR_DEBUG */
        return 0; /* abort parsing */
    }

    if(info->tree[0] == NULL)
    {
        #ifdef LLRP_DISSECTOR_DEBUG
        g_warning("llrp_ws_HandleMessageStart: no display tree!", type);
        #endif /* LLRP_DISSECTOR_DEBUG */
        tree = NULL;
        info->quiet_parse = 1;
    }
    else
    {
        info->quiet_parse = 0;
        if(check_col(info->pinfo->cinfo, COL_INFO))
            col_add_fstr(info->pinfo->cinfo, COL_INFO, "%s (type %u, ID %u)", name, type, id);

        /* Show a dissection tree node for the standard LLRP header information */
        item = proto_tree_add_item(proto_tree_get_root(info->tree[0]), proto_epc_llrp, info->tvb, 0, -1, FALSE);
        proto_item_append_text(item, ": %s (ID %u)", name, id);
        tree = proto_item_add_subtree(item, ett_llrp_message);      

        /* Display the standard header data */
        proto_tree_add_uint(tree, hf_llrp_message_version, info->tvb, 0, 1, version);
        proto_tree_add_uint(tree, hf_llrp_message_type, info->tvb, 0, 2, type);
        proto_tree_add_uint(tree, hf_llrp_message_length, info->tvb, 2, 4, length);
        proto_tree_add_uint(tree, hf_llrp_message_id, info->tvb, 6, 4, id);
    }

    llrp_ws_DescendParseTree(ctxt, info, tree);
    return 1; /* continue parsing */
}     

void llrp_ws_HandleField(void *context, const unsigned short field_index, const unsigned char type,
 const char *name, const unsigned long bitlength, const unsigned char *data,
 t_llrp_enumeration *enumeration)
{
    proto_tree *tree= NULL;
    const char *enumeration_name;
    unsigned short enumeration_value;
    t_llrp_parse_context *ctxt= (t_llrp_parse_context *) context;
    t_llrp_parse_info *info= (t_llrp_parse_info *) ctxt->data;
    unsigned long bytelength= (bitlength/8)+((bitlength%8) ? 1 : 0);
    unsigned long total_length= bytelength+(LLRP_FIELDTYPE_IS_VARIABLE(type) ? 2 : 0);
    unsigned long count= 0;
    gint tvb_offset = info->tvb_offset;

    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("llrp_ws_HandleField (type %d)", type);
    #endif /* LLRP_DISSECTOR_DEBUG */

    if(ctxt->depth> 0 && !info->quiet_parse)
    {
        proto_item *item;
        proto_tree *parent_tree= info->tree[(ctxt->depth)-1];

        if(parent_tree!= NULL)
        {
            item= proto_tree_add_uint_format_value(parent_tree, hf_llrp_message_field, info->tvb,
             tvb_offset-total_length, total_length, type, "%s (%s)", name,
             llrp_field_type_to_name(type));
            tree= proto_item_add_subtree(item, ett_llrp_field);
            proto_tree_add_uint_format_value(tree, hf_llrp_field_type, info->tvb,
             tvb_offset-total_length, total_length, type, "%s (%u)",
             llrp_field_type_to_name(type), type);
            if(LLRP_FIELDTYPE_IS_VARIABLE(type))
            {
                count= bitlength/llrp_variable_field_bitlength[LLRP_FIELDTYPE_INDEX_VARIABLE(type)];
                proto_tree_add_uint(tree, hf_llrp_field_count, info->tvb,
                 tvb_offset-total_length, 2, count);                 
            }
            proto_tree_add_uint(tree, hf_llrp_field_bitlength, info->tvb,
             tvb_offset-total_length, total_length, bitlength);
            switch(type)
            {
                case LLRP_FIELDTYPE_u1:
                    proto_tree_add_uint_format_value(tree, hf_llrp_field_value_u1, info->tvb,
                     tvb_offset-bytelength, bytelength, *data, "%d (%s)", *data,
                     (*data) ? "True" : "False");
                    enumeration_value= *data;
                    break;
                case LLRP_FIELDTYPE_u2:
                    proto_tree_add_uint(tree, hf_llrp_field_value_u2, info->tvb,
                     tvb_offset-bytelength, bytelength, *data);
                    enumeration_value= *data;
                    break;
                case LLRP_FIELDTYPE_u8:
                    proto_tree_add_uint_format_value(tree, hf_llrp_field_value_u8, info->tvb,
                     tvb_offset-bytelength, bytelength, *data, "0x%02x (%u)", *data, *data);
                    enumeration_value= *data;
                    break;
                case LLRP_FIELDTYPE_s8:
                    proto_tree_add_int_format_value(tree, hf_llrp_field_value_s8, info->tvb,
                     tvb_offset-bytelength, bytelength, *data, "0x%02x (%d)", *data, *data);
                    enumeration_value= *data;
                    break;
                case LLRP_FIELDTYPE_u16:
                {
                    unsigned short value= pntohs(((unsigned short*)data));
                    proto_tree_add_uint_format_value(tree, hf_llrp_field_value_u16, info->tvb,
                     tvb_offset-bytelength, bytelength, value, "0x%04x (%u)", value, value);
                    enumeration_value= value;
                    break;
                }
                case LLRP_FIELDTYPE_s16:
                {
                    unsigned short value= pntohs(((unsigned short*)data));
                    proto_tree_add_int_format_value(tree, hf_llrp_field_value_s16, info->tvb,
                     tvb_offset-bytelength, bytelength, value, "0x%04x (%d)", value, value);
                    enumeration_value= value;
                    break;
                }
                case LLRP_FIELDTYPE_u32:
                {
                    unsigned long value= pntohl(((unsigned long*)data));

                    #ifdef LLRP_RESOLVE_VENDOR_ID
                    /* Note: this is a little hackish - anyone could name a field
                     *  "VendorIdentifier" in their vendor extension and potentially
                     *  get bogus extra information... */
                    if(strcmp(name, "VendorIdentifier") == 0)
                    {
                        proto_tree_add_uint_format_value(tree, hf_llrp_field_value_u32, info->tvb,
                         tvb_offset-bytelength, bytelength, value, "%s (0x%08x, %u)",
                         llrp_ws_find_vendor_id(value), value, value);
                    }
                    else
                    #endif /* LLRP_RESOLVE_VENDOR_ID */
                    {
                        proto_tree_add_uint_format_value(tree, hf_llrp_field_value_u32, info->tvb,
                         tvb_offset-bytelength, bytelength, value, "0x%08x (%u)", value, value);
                    }
                    break;
                }
                case LLRP_FIELDTYPE_s32:
                {
                    unsigned long value= pntohl(((unsigned long*)data));
                    proto_tree_add_int_format_value(tree, hf_llrp_field_value_s32, info->tvb,
                     tvb_offset-bytelength, bytelength, value, "0x%08x (%d)", value, value);
                    break;
                }
                case LLRP_FIELDTYPE_u64:
                {
                    guint64 value= pntoh64((guint64*)data);
                    proto_tree_add_uint64_format_value(tree, hf_llrp_field_value_u64, info->tvb,
                     tvb_offset-bytelength, bytelength, value,
                     "0x%0" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "u)", value, value);
                    break;
                }
                case LLRP_FIELDTYPE_s64:
                {
                    guint64 value= pntoh64((guint64*)data);
                    proto_tree_add_int64_format_value(tree, hf_llrp_field_value_s64, info->tvb,
                     tvb_offset-bytelength, bytelength, value,
                     "0x%0" G_GINT64_MODIFIER "x (%" G_GINT64_MODIFIER "d)", value, value);
                    break;
                }
                case LLRP_FIELDTYPE_utf8v:
                {
                    char *string;
                    string= (char *) malloc(bytelength+3);
                    if(string!= NULL)
                    {
                        memcpy(string+1, data, bytelength);
                        string[0]= '"';
                        string[bytelength+1]= '"';
                        string[bytelength+2]= '\0';
                        proto_tree_add_string(tree, hf_llrp_field_value_variable, info->tvb,
                         tvb_offset-bytelength, bytelength, string);
                        free(string);
                    }
                    break;
                }
                case LLRP_FIELDTYPE_u8v:
                case LLRP_FIELDTYPE_s8v:
                {
                    char *string;
                    string= (char *) malloc(6*count);
                    if(string!= NULL)
                    {
                        unsigned short idx;
                        string[0]= '\0';
                        for(idx= 0; idx< count; idx++)
                        {
                            sprintf(string+strlen(string), "%s%d",
                             (idx>0) ? ", " : "", data[idx]);
                        }
                        proto_tree_add_string(tree, hf_llrp_field_value_variable, info->tvb,
                         tvb_offset-bytelength, bytelength, string);
                        free(string);
                    }
                    break;
                }                
                case LLRP_FIELDTYPE_u16v:
                case LLRP_FIELDTYPE_s16v:
                {
                    char *string;
                    string= (char *) malloc(8*count);
                    if(string!= NULL)
                    {
                        unsigned short idx;
                        string[0]= '\0';
                        for(idx= 0; idx< count; idx++)
                        {
                            sprintf(string+strlen(string), "%s%d",
                             (idx>0) ? ", " : "", pntohs(&data[idx*2]));
                        }
                        proto_tree_add_string(tree, hf_llrp_field_value_variable, info->tvb,
                         tvb_offset-bytelength, bytelength, string);
                        free(string);
                    }
                    break;
                }
                case LLRP_FIELDTYPE_u32v:
                case LLRP_FIELDTYPE_s32v:
                {
                    char *string;
                    string= (char *) malloc(13*count);
                    if(string!= NULL)
                    {
                        unsigned short idx;
                        string[0]= '\0';
                        for(idx= 0; idx< count; idx++)
                        {
                            sprintf(string+strlen(string), "%s%d",
                             (idx>0) ? ", " : "", pntohl(&data[idx*4]));
                        }
                        proto_tree_add_string(tree, hf_llrp_field_value_variable, info->tvb,
                         tvb_offset-bytelength, bytelength, string);
                        free(string);
                    }
                    break;
                }
                case LLRP_FIELDTYPE_u64v:
                case LLRP_FIELDTYPE_s64v:
                {
                    char *string;
                    string= (char *) malloc(23*count);
                    if(string!= NULL)
                    {
                        unsigned short idx;
                        string[0]= '\0';
                        for(idx= 0; idx< count; idx++)
                        {
                            sprintf(string+strlen(string), "%s%d",
                             (idx>0) ? ", " : "", pntoh64(&data[idx*8]));
                        }
                        proto_tree_add_string(tree, hf_llrp_field_value_variable, info->tvb,
                         tvb_offset-bytelength, bytelength, string);
                        free(string);
                    }
                    break;
                }
                default:
                    break;
            }

            if(enumeration!= NULL)
            {
                enumeration_name= llrp_enumeration_to_name(enumeration, enumeration_value);
                if(enumeration_name!= NULL)
                {
                    proto_tree_add_string(tree, hf_llrp_field_enumeration, info->tvb,
                     tvb_offset-bytelength, bytelength, enumeration_name);
                }
            }
        }
    }
}

void llrp_ws_HandleParameterStart(void *context, const unsigned short type, const char *name,
 const unsigned short length)
{
    proto_tree *tree = NULL;
    t_llrp_parse_context *ctxt = (t_llrp_parse_context *) context;
    t_llrp_parse_info *info = (t_llrp_parse_info *) ctxt->data;
    gint tvb_offset, tvb_length, type_length;

    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("llrp_ws_HandleParameterStart (type %d)", type);
    #endif /* LLRP_DISSECTOR_DEBUG */

    if(ctxt->depth> 0 && !info->quiet_parse)
    {
        proto_item *item;
        proto_tree *parent_tree = info->tree[(ctxt->depth)-1];

        if(parent_tree!= NULL)
        {
            if(LLRP_PARAMETER_IS_TV(type))
            {
                tvb_offset = info->tvb_offset - 1;
                tvb_length = length + 1;
                type_length = 1;
            }
            else
            {
                tvb_offset = info->tvb_offset - 4;
                tvb_length = length + 4;
                type_length = 2;
            }

            item = proto_tree_add_uint_format_value(parent_tree, hf_llrp_message_parm, info->tvb,
             tvb_offset, tvb_length, type, "%s (type %u)", name, type);
            tree = proto_item_add_subtree(item, ett_llrp_parameter);
            proto_tree_add_uint_format_value(tree, hf_llrp_parameter_type, info->tvb,
             tvb_offset, type_length, type,
             (LLRP_PARAMETER_IS_TV(type)) ? "%u (TV-encoded)" : "%u (TLV-encoded)", type);
            if(LLRP_PARAMETER_IS_TLV(type))
                proto_tree_add_uint(tree, hf_llrp_parameter_length, info->tvb, tvb_offset+2, 2, length);
        }
    }

    llrp_ws_DescendParseTree(ctxt, info, tree);
}

void llrp_ws_HandleCustomParameterStart(void *context, const unsigned short type,
 const unsigned long vendorID, const unsigned long subtype, const char *name,
 const unsigned short length)
{
    proto_tree *tree = NULL;
    t_llrp_parse_context *ctxt = (t_llrp_parse_context *) context;
    t_llrp_parse_info *info = (t_llrp_parse_info *) ctxt->data;
    gint tvb_offset, tvb_length, type_length;

    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("llrp_ws_HandleCustomParameterStart (type %u, vendorID %u, subtype %u)", type, vendorID, subtype);
    #endif /* LLRP_DISSECTOR_DEBUG */

    if(ctxt->depth> 0 && !info->quiet_parse)
    {
        proto_item *item;
        proto_tree *parent_tree = info->tree[(ctxt->depth)-1];

        if(parent_tree!= NULL)
        {
            /* All custom parameters are TLV */
            tvb_offset = info->tvb_offset - 4;
            tvb_length = length + 4;
            type_length = 2;

            #ifdef LLRP_RESOLVE_VENDOR_ID
            item = proto_tree_add_uint_format_value(parent_tree, hf_llrp_message_parm, info->tvb,
             tvb_offset, tvb_length, type, "%s (%s (%u), subtype %u)", name,
             llrp_ws_find_vendor_id(vendorID), vendorID, subtype);
            #else
            item = proto_tree_add_uint_format_value(parent_tree, hf_llrp_message_parm, info->tvb,
             tvb_offset, tvb_length, type, "%s (%u, subtype %u)", name, vendorID, subtype);
            #endif
            tree = proto_item_add_subtree(item, ett_llrp_parameter);

            #ifdef LLRP_RESOLVE_VENDOR_ID
            proto_tree_add_uint_format_value(tree, hf_llrp_custparm_vendorid, info->tvb,
             tvb_offset, type_length, vendorID, "%u (%s)", vendorID, llrp_ws_find_vendor_id(vendorID));
            #else
            proto_tree_add_uint_format_value(tree, hf_llrp_custparm_vendorid, info->tvb,
             tvb_offset, type_length, vendorID, "%u", vendorID);
            #endif /* LLRP_RESOLVE_VENDOR_ID */  
            proto_tree_add_uint_format_value(tree, hf_llrp_custparm_subtype, info->tvb,
             tvb_offset, type_length, subtype, "%u", subtype);
            proto_tree_add_uint(tree, hf_llrp_parameter_length, info->tvb, tvb_offset+2, 2, length);
        }
    }

    llrp_ws_DescendParseTree(ctxt, info, tree);
}

void llrp_ws_HandleParameterFinished(void *context, const unsigned short type, const char *name,
 const unsigned short length)
{
    t_llrp_parse_context *ctxt= (t_llrp_parse_context *) context;
    t_llrp_parse_info *info= (t_llrp_parse_info *) ctxt->data;

    llrp_ws_AscendParseTree(ctxt, info);
}

void llrp_ws_HandleCustomParameterFinished(void *context, const unsigned short type,
 const unsigned long vendorID, const unsigned long subtype, const char *name,
 const unsigned short length)
{
    t_llrp_parse_context *ctxt= (t_llrp_parse_context *) context;
    t_llrp_parse_info *info= (t_llrp_parse_info *) ctxt->data;

    llrp_ws_AscendParseTree(ctxt, info);
}

#define LLRP_DEBUG_MAX_STRING_LENGTH 160 /* characters */
void llrp_ws_HandleParseError(void *context, const unsigned char code, const unsigned short item,
 const char *function_name, const char *format, ...)
{
    t_llrp_parse_context *ctxt= (t_llrp_parse_context *) context;
    t_llrp_parse_info *info= (t_llrp_parse_info *) ctxt->data;
    va_list argList;
    char message[LLRP_DEBUG_MAX_STRING_LENGTH+1];

    if(ctxt->depth> 0 && !info->quiet_parse)
    {
        proto_tree *parent_tree= info->tree[(ctxt->depth)-1];
        if(parent_tree!= NULL)
        {
            va_start(argList, format);
            g_vsnprintf(message, LLRP_DEBUG_MAX_STRING_LENGTH, format, argList);
            message[LLRP_DEBUG_MAX_STRING_LENGTH] = '\0';
            proto_tree_add_text(parent_tree, info->tvb, 0, 0, message);
            va_end(argList);
        }
    }
}

void llrp_ws_HandleDebugMessage(void *context, const char *function_name, const char *format, ...)
{
    #ifdef LLRP_PARSER_DEBUG
    va_list argList;
    char message[LLRP_DEBUG_MAX_STRING_LENGTH+1];

    va_start(argList, format);
    g_vsnprintf(message, LLRP_DEBUG_MAX_STRING_LENGTH, format, argList);
    message[LLRP_DEBUG_MAX_STRING_LENGTH]= '\0';
    g_warning(message);
    va_end(argList);
    #endif /* LLRP_PARSER_DEBUG */
}

/* --------------------------------------------------------------------------------------- */
/* Dissector                                                                               */

static t_llrp_parse_validator *llrp_parse_validator_list[]=
{
    &llrp_v1_0_parse_validator,
    &llrp_llrp_Intermec_parse_validator
};

static t_llrp_parse_context parse_context = {
    0 /*depth*/, llrp_parse_validator_list,
    sizeof(llrp_parse_validator_list)/sizeof(llrp_parse_validator_list[0]),
    llrp_ws_StreamRead, llrp_ws_StreamGetOffset, llrp_ws_HandleMessageStart,
    NULL /*message finished*/, llrp_ws_HandleField, NULL /*field complete*/,
    llrp_ws_HandleParameterStart, llrp_ws_HandleParameterFinished,
    llrp_ws_HandleCustomParameterStart, llrp_ws_HandleCustomParameterFinished,
    NULL /*all parameters complete*/, llrp_ws_HandleParseError, llrp_ws_HandleDebugMessage,
    (void *) &llrp_parse_info
};

static guint get_epc_llrp_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    guint length;
    /* Peek into the header to determine the total message length */
    length = (guint) tvb_get_ntohl(tvb, offset+2); 
    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("get_epc_llrp_message_len: offset=%d, length=%u", offset, length);
    #endif /* LLRP_DISSECTOR_DEBUG */
    return length;
}

static int dissect_epc_llrp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{   
    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("dissect_epc_llrp_message start");
    #endif /* LLRP_DISSECTOR_DEBUG */

    /* Make the protocol column in the packet list display the protocol name */
    if(check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_DESCRIPTION_LLRP);

    /* Start with a clean info column */
    if(check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    if(tree)
    {
        memset(&llrp_parse_info, 0, sizeof(llrp_parse_info));

        /* Dissect the contents of the message */
        llrp_parse_info.tree[0] = tree;
        llrp_parse_info.tvb = tvb;
        llrp_parse_info.pinfo = pinfo;
        llrp_ParseMessage(&parse_context);
    }

    #ifdef LLRP_DISSECTOR_DEBUG
    g_warning("dissect_epc_llrp_message finished");
    #endif /* LLRP_DISSECTOR_DEBUG */

    return 0;
}

static int dissect_epc_llrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Allow the TCP stream to be automatically reassembled. The message dissector should
     *  not be called until an entire message is available. */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LLRP_HEADER_LENGTH, get_epc_llrp_message_len,
     dissect_epc_llrp_message);
    return 0;
}

void proto_reg_handoff_epc_llrp(void)
{
    static int llrp_prefs_initialized = FALSE;
    static dissector_handle_t epc_llrp_handle;

    if(!llrp_prefs_initialized)
    {
        epc_llrp_handle = create_dissector_handle(dissect_epc_llrp, proto_epc_llrp);
        llrp_prefs_initialized = TRUE;
    }
    else
    {
        dissector_delete("tcp.port", gbl_llrpTcpPort, epc_llrp_handle);
    }

    /* The only binding for LLRP is TCP */
    dissector_add("tcp.port", gbl_llrpTcpPort, epc_llrp_handle);
}    

static void prefs_register_epc_llrp()
{
    module_t *llrp_module;

    /* Register a configuration option for port */
    llrp_module = prefs_register_protocol(proto_epc_llrp, proto_reg_handoff_epc_llrp);

    /* Allow specification of an alternate TCP port number */
    prefs_register_uint_preference(llrp_module, "tcp.port", "LLRP TCP Port",
     "Set the TCP port for LLRP messages", 10, &gbl_llrpTcpPort);
} /* prefs_register_epc_llrp */

/* Filtering engine registration */
void proto_register_epc_llrp(void)
{
    /* Register the LLRP protocol */
    if(proto_epc_llrp == -1)
    {
        proto_epc_llrp = proto_register_protocol(PROTO_DESCRIPTION_LLRP,
         PROTO_SHORT_DESCRIPTION_LLRP, PROTO_NAME_LLRP);
    }

    proto_register_field_array(proto_epc_llrp, hf_llrp, array_length(hf_llrp));
    proto_register_subtree_array(ett_llrp, array_length(ett_llrp));

    /* Allow dissector to find be found by name. */
    new_register_dissector(PROTO_NAME_LLRP, dissect_epc_llrp, proto_epc_llrp);

    /* Register a list of settable preferences for the LLRP dissector */
    prefs_register_epc_llrp();
}

/* --------------------------------------------------------------------------------------- */
/* Private Helper Functions                                                                */

#ifdef LLRP_RESOLVE_VENDOR_ID
static const char llrp_ws_unknown_vendor_id[] = "Unknown Vendor ID";

static const char *llrp_ws_find_vendor_id(const unsigned long vendor_id)
{
    return val_to_str((guint32) vendor_id, sminmpec_values, llrp_ws_unknown_vendor_id);
}
#endif /* LLRP_RESOLVE_VENDOR_ID */

