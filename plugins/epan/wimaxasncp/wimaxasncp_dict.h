/*
 ** wimaxasncp_dict.h
 ** WIMAXASNCP Dictionary Import Routines
 **
 ** (c) 2007, Stephen Croll <stephen.d.croll@gmail.com>
 **
 ** This library is free software; you can redistribute it and/or
 ** modify it under the terms of the GNU Library General Public
 ** License as published by the Free Software Foundation; either
 ** version 2 of the License, or (at your option) any later version.
 **
 ** This library is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 ** Library General Public License for more details.
 **
 ** You should have received a copy of the GNU Library General Public
 ** License along with this library; if not, write to the
 ** Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 ** Boston, MA  02110-1301 USA.
 */

#ifndef _WIMAXASNCP_DICT_H_
#define _WIMAXASNCP_DICT_H_

/* -------------------------------------------------------------------------
 * NWG versions
 * ------------------------------------------------------------------------- */

#define WIMAXASNCP_NWGVER_R10_V100  0
#define WIMAXASNCP_NWGVER_R10_V120  1
#define WIMAXASNCP_NWGVER_R10_V121  2
#define WIMAXASNCP_NWGVER_NUM       3

/* -------------------------------------------------------------------------
 * decode types
 * ------------------------------------------------------------------------- */

enum
{
    WIMAXASNCP_TLV_UNKNOWN,
    WIMAXASNCP_TLV_TBD,
    WIMAXASNCP_TLV_COMPOUND,
    WIMAXASNCP_TLV_BYTES,
    WIMAXASNCP_TLV_ENUM8,
    WIMAXASNCP_TLV_ENUM16,
    WIMAXASNCP_TLV_ENUM32,
    WIMAXASNCP_TLV_ETHER,
    WIMAXASNCP_TLV_ASCII_STRING,
    WIMAXASNCP_TLV_FLAG0,
    WIMAXASNCP_TLV_BITFLAGS8,
    WIMAXASNCP_TLV_BITFLAGS16,
    WIMAXASNCP_TLV_BITFLAGS32,
    WIMAXASNCP_TLV_ID,
    WIMAXASNCP_TLV_HEX8,
    WIMAXASNCP_TLV_HEX16,
    WIMAXASNCP_TLV_HEX32,
    WIMAXASNCP_TLV_DEC8,
    WIMAXASNCP_TLV_DEC16,
    WIMAXASNCP_TLV_DEC32,
    WIMAXASNCP_TLV_IP_ADDRESS,   /* Note: IPv4 or IPv6, determined by length */
    WIMAXASNCP_TLV_IPV4_ADDRESS,
    WIMAXASNCP_TLV_PROTOCOL_LIST,
    WIMAXASNCP_TLV_PORT_RANGE_LIST,
    WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST,
    WIMAXASNCP_TLV_EAP,
    WIMAXASNCP_TLV_VENDOR_SPECIFIC
};

/* -------------------------------------------------------------------------
 * structures and functions
 * ------------------------------------------------------------------------- */

struct _wimaxasncp_dict_namecode_t {
    gchar *name;
    guint code;
    struct _wimaxasncp_dict_namecode_t *next;
};

typedef struct _wimaxasncp_dict_namecode_t wimaxasncp_dict_enum_t;

typedef struct _wimaxasncp_dict_tlv_t {
    guint16 type;
    gchar *name;
    gchar *description;
    gint decoder;
    guint since;
    int hf_root;
    int hf_value;
    int hf_ipv4;
    int hf_ipv6;
    int hf_bsid;
    int hf_protocol;
    int hf_port_low;
    int hf_port_high;
    int hf_ipv4_mask;
    int hf_ipv6_mask;
    int hf_vendor_id;
    int hf_vendor_rest_of_info;
    value_string *enum_vs;
    wimaxasncp_dict_enum_t *enums;
    struct _wimaxasncp_dict_tlv_t *next;
} wimaxasncp_dict_tlv_t;

typedef struct _wimaxasncp_dict_xmlpi_t {
    gchar *name;
    gchar *key;
    gchar *value;
    struct _wimaxasncp_dict_xmlpi_t *next;
} wimaxasncp_dict_xmlpi_t;

typedef struct _wimaxasncp_dict_t {
    wimaxasncp_dict_tlv_t *tlvs;
    wimaxasncp_dict_xmlpi_t *xmlpis;
} wimaxasncp_dict_t;

extern void wimaxasncp_dict_print(
    FILE *fh, wimaxasncp_dict_t *d);

extern wimaxasncp_dict_t *wimaxasncp_dict_scan(
    const gchar *system_directory, const gchar *filename, int dbg,
    gchar **error);

extern void wimaxasncp_dict_free(
    wimaxasncp_dict_t *d);

#endif
