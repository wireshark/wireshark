/* EPCglobal Low-Level Reader Protocol Packet Dissector
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

#ifndef _LLRP_PARSE_TYPES_H
#define _LLRP_PARSE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#define LLRP_ITEM_NONE        0x00
#define LLRP_ITEM_FIELD       0x01
#define LLRP_ITEM_RESERVED    0x02
#define LLRP_ITEM_PARAMETER   0x03
#define LLRP_ITEM_CHOICE      0x04
#define LLRP_ITEM_MESSAGE     0x05

typedef struct {
    char *name;
    unsigned char item_type; /* one of LLRP_ITEM_* */
    unsigned short min_repeat_count;
        #define LLRP_REPEAT_INDEFINITELY  0xFFFF
    unsigned short max_repeat_count;
    unsigned char field_type;
        #define LLRP_FIELDTYPE_NONE       0x00
        #define LLRP_FIELDTYPE_u1         0x01
        #define LLRP_FIELDTYPE_u2         0x02
        #define LLRP_FIELDTYPE_u8         0x03
        #define LLRP_FIELDTYPE_s8         0x04
        #define LLRP_FIELDTYPE_u16        0x05
        #define LLRP_FIELDTYPE_s16        0x06
        #define LLRP_FIELDTYPE_u32        0x07
        #define LLRP_FIELDTYPE_s32        0x08
        #define LLRP_FIELDTYPE_u64        0x09
        #define LLRP_FIELDTYPE_s64        0x0a
        #define LLRP_FIELDTYPE_u96        0x0b
        #define LLRP_FIELDTYPE_u1v        0x40
        #define LLRP_FIELDTYPE_u8v        0x41
        #define LLRP_FIELDTYPE_s8v        0x42
        #define LLRP_FIELDTYPE_utf8v      0x43
        #define LLRP_FIELDTYPE_u16v       0x44
        #define LLRP_FIELDTYPE_s16v       0x45
        #define LLRP_FIELDTYPE_u32v       0x46
        #define LLRP_FIELDTYPE_s32v       0x47
        #define LLRP_FIELDTYPE_u64v       0x48
        #define LLRP_FIELDTYPE_s64v       0x49
        #define LLRP_FIELDTYPE_bytesToEnd 0x60
    void *data;         /* pointer to field_type specific data */
} t_llrp_item;
#define LLRP_FIELDTYPE_IS_VARIABLE(ft) ((ft)>= 0x40 && (ft)< 0x60)
#define LLRP_FIELDTYPE_INDEX_VARIABLE(ft) ((ft)-0x40)

typedef struct {
    char *name;
    unsigned short value;
} t_llrp_enumeration_item;

typedef struct {
    t_llrp_enumeration_item *list;
    unsigned short count;
} t_llrp_enumeration;

typedef struct {
    char *name;
    unsigned char type; /* one of LLRP_ITEM* */
    unsigned short number;
    unsigned short item_count;
    void *item_list;
} t_llrp_compound_item;

typedef struct {
    unsigned short number;
    t_llrp_compound_item *item;
} t_llrp_standard_map_item;

typedef struct {
    unsigned long vendor_id;
    unsigned short subtype;
    t_llrp_compound_item *item;
} t_llrp_custom_map_item;

typedef struct {
    char *validator_name;

    t_llrp_standard_map_item *parameter_list;
    unsigned short parameter_count;

    t_llrp_custom_map_item *custom_parameter_list;
    unsigned short custom_parameter_count;

    t_llrp_standard_map_item *message_list;
    unsigned short message_count;

    t_llrp_custom_map_item *custom_message_list;
    unsigned short custom_message_count;
} t_llrp_parse_validator;

/* ----------------------------------------------------------------------- */
/* Common Constants/Declarations/Functions                                 */

#define LLRP_HEADER_LENGTH 10
#define LLRP_PARAMETER_IS_TLV(usType) ((usType) > 127)
#define LLRP_PARAMETER_IS_TV(usType)  ((usType) < 128)

extern unsigned short llrp_fixed_field_bitlength[];
extern unsigned short llrp_variable_field_bitlength[];
extern char *llrp_fixed_field_name[];
extern char *llrp_variable_field_name[];
extern char *llrp_compound_item_name[];

/* ----------------------------------------------------------------------- */
/* Message Versions                                                        */

#define LLRP_v1_0_VERSION  1

#ifdef __cplusplus
}
#endif

#endif /* _LLRP_PARSE_TYPES_H */
