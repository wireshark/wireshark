/* packet-kerberos.c
 * Routines for Kerberos
 * Wes Hardaker (c) 2000
 * wjhardaker@ucdavis.edu
 *
 * $Id: packet-kerberos.c,v 1.1 2000/08/11 03:32:43 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
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
#include <string.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>

#include "packet.h"

#include "asn1.h"

#include "packet-kerberos.h"

#define UDP_PORT_KERBEROS		88
#define TCP_PORT_KERBEROS		88

static gint ett_kerberos   = -1;
static gint ett_preauth    = -1;
static gint ett_addresses  = -1;
static gint ett_request    = -1;
static gint ett_princ      = -1;
static gint ett_ticket     = -1;
static gint ett_encrypted  = -1;
static gint ett_etype      = -1;
static gint proto_kerberos = -1;

#define KRB5_MSG_AS_REQ   0x0a
#define KRB5_MSG_AS_RESP  0x0b
#define KRB5_MSG_TGS_REQ  0x0c
#define KRB5_MSG_TGS_RESP 0x0d

#define KRB5_KDC_REQ_PVNO     0x01
#define KRB5_KDC_REQ_MSG_TYPE 0x02
#define KRB5_KDC_REQ_PADATA   0x03
#define KRB5_KDC_REQ_REQBODY  0x04

#define KRB5_KDC_RESP_PVNO     0x00
#define KRB5_KDC_RESP_MSG_TYPE 0x01
#define KRB5_KDC_RESP_PADATA   0x02
#define KRB5_KDC_RESP_CREALM   0x03
#define KRB5_KDC_RESP_CNAME    0x04
#define KRB5_KDC_RESP_TICKET   0x05
#define KRB5_KDC_RESP_ENC_PART 0x06

#define KRB5_BODY_KDC_OPTIONS            0x00
#define KRB5_BODY_CNAME                  0x01
#define KRB5_BODY_REALM                  0x02
#define KRB5_BODY_SNAME                  0x03
#define KRB5_BODY_FROM                   0x04
#define KRB5_BODY_TILL                   0x05
#define KRB5_BODY_RTIME                  0x06
#define KRB5_BODY_NONCE                  0x07
#define KRB5_BODY_ETYPE                  0x08
#define KRB5_BODY_ADDRESSES              0x09
#define KRB5_BODY_ENC_AUTHORIZATION_DATA 0x0a
#define KRB5_BODY_ADDITIONAL_TICKETS     0x0b

#define KRB5_ADDR_IPv4       0x02
#define KRB5_ADDR_CHAOS      0x05
#define KRB5_ADDR_XEROX      0x06
#define KRB5_ADDR_ISO        0x07
#define KRB5_ADDR_DECNET     0x0c
#define KRB5_ADDR_APPLETALK  0x10

#define KRB5_ETYPE_NULL                0
#define KRB5_ETYPE_DES_CBC_CRC         1
#define KRB5_ETYPE_DES_CBC_MD4         2
#define KRB5_ETYPE_DES_CBC_MD5         3

#define KRB5_PA_TGS_REQ       0x01
#define KRB5_PA_ENC_TIMESTAMP 0x02
#define KRB5_PA_PW_SALT       0x03

static const value_string krb5_preauthentication_types[] = {
    { KRB5_PA_TGS_REQ      , "PA-TGS-REQ" },
    { KRB5_PA_ENC_TIMESTAMP, "PA-ENC-TIMESTAMP" },
    { KRB5_PA_PW_SALT      , "PA-PW-SALT" },
};

static const value_string krb5_encryption_types[] = {
    { KRB5_ETYPE_NULL           , "NULL" },
    { KRB5_ETYPE_DES_CBC_CRC    , "des-cbc-crc" },
    { KRB5_ETYPE_DES_CBC_MD4    , "des-cbc-md4" },
    { KRB5_ETYPE_DES_CBC_MD5    , "des-cbc-md5" },
};

static const value_string krb5_address_types[] = {
    { KRB5_ADDR_IPv4,	"IPv4"},
    { KRB5_ADDR_CHAOS,	"CHAOS"},
    { KRB5_ADDR_XEROX,	"XEROX"},
    { KRB5_ADDR_ISO,	"ISO"},
    { KRB5_ADDR_DECNET,	"DECNET"},
    { KRB5_ADDR_APPLETALK,	"APPLETALK"}
};

static const value_string krb5_msg_types[] = {
	{ KRB5_MSG_TGS_REQ,	"TGS-REQ" },
	{ KRB5_MSG_TGS_RESP,    "TGS-RESP" },
	{ KRB5_MSG_AS_REQ,	"AS-REQ" },
	{ KRB5_MSG_AS_RESP,	"AS-RESP" }
};

const char *
to_error_str(int ret) {
    switch (ret) {

        case ASN1_ERR_EMPTY:
            return("Ran out of data");

        case ASN1_ERR_EOC_MISMATCH:
            return("EOC mismatch");

        case ASN1_ERR_WRONG_TYPE:
            return("Wrong type for that item");

        case ASN1_ERR_LENGTH_NOT_DEFINITE:
            return("Length was indefinite");

        case ASN1_ERR_LENGTH_MISMATCH:
            return("Length mismatch");

        case ASN1_ERR_WRONG_LENGTH_FOR_TYPE:
            return("Wrong length for that item's type");

    }
    return("Unknown error");
}

void
krb_proto_tree_add_time(proto_tree *tree, int offset, int str_len,
                        char *name, guchar *str) {
    if (tree)
        proto_tree_add_text(tree, NullTVB, offset, str_len,
                            "%s: %.4s-%.2s-%.2s %.2s:%.2s:%.2s (%.1s)",
                            name, str, str+4, str+6,
                            str+8, str+10, str+12,
                            str+14);
}


/*
 * You must be kidding.  I'm going to actually use a macro to do something?
 *   bad me.  Bad me.
 */

#define KRB_HEAD_DECODE_OR_DIE(token) \
   start = asn1p->pointer; \
   ret = asn1_header_decode (asn1p, &cls, &con, &tag, &def, &item_len); \
   if (ret != ASN1_ERR_NOERROR && ret != ASN1_ERR_EMPTY) {\
       col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s", \
                    token, to_error_str(ret)); \
       return; \
   } \
   if (!def) {\
       col_add_fstr(fd, COL_INFO, "not definite: %s", token); \
       fprintf(stderr,"not definite: %s\n", token); \
       return; \
   } \
   offset += (asn1p->pointer - start);


#define KRB_DECODE_OR_DIE(token, fn, val) \
    ret = fn (asn1p, &val, &length); \
    if (ret != ASN1_ERR_NOERROR) { \
        col_add_fstr(fd, COL_INFO, "ERROR: Problem at %s: %s", \
                     token, to_error_str(ret)); \
        return; \
    } \

/* dissect_type_value_pair decodes (roughly) this:

    SEQUENCE  {
                        INTEGER,
                        OCTET STRING
    }

    which is all over the place in krb5 */

void
dissect_type_value_pair(ASN1_SCK *asn1p, int *inoff,
                        int *type, int *type_len, int *type_off,
                        guchar **val, int *val_len, int *val_off) {
    int offset = *inoff;
    guint cls, con, tag;
    gboolean def;
    const guchar *start;
    guint tmp_len;
    int ret;

    /* SEQUENCE */
    start = asn1p->pointer;
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, &tmp_len);
    offset += (asn1p->pointer - start);

    /* INT */
    /* wrapper */
    start = asn1p->pointer;
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, &tmp_len);
    offset += (asn1p->pointer - start);

    if (type_off)
        *type_off = offset;

    /* value */
    ret =  asn1_int32_decode(asn1p, type, type_len);
    if (ret != ASN1_ERR_NOERROR) {
        fprintf(stderr,"die: type_value_pair: type, %s\n", to_error_str(ret));
        return;
    }
    offset += tmp_len;

    /* OCTET STRING (or generic data) */
    /* wrapper */
    start = asn1p->pointer;
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, val_len);
    asn1_header_decode (asn1p, &cls, &con, &tag, &def, val_len);
    offset += asn1p->pointer - start;
    
    if (val_off)
        *val_off = offset;

    /* value */
    asn1_octet_string_value_decode (asn1p, *val_len, val);

    *inoff = offset + *val_len;
}


void
dissect_kerberos(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_tree *kerberos_tree = NULL;
    proto_tree *etype_tree = NULL;
    proto_tree *preauth_tree = NULL;
    proto_tree *request_tree = NULL;
    ASN1_SCK asn1, *asn1p = &asn1;
    proto_item *item = NULL;

    guint length;
    guint cls, con, tag;
    gboolean def;
    guint item_len, total_len;
    const guchar *start;

    int ret;

    guint protocol_message_type;
    
    gint32 version;
    gint32 msg_type;
    gint32 preauth_type;
    gint32 tmp_int;

    /* simple holders */
    int str_len;
    guchar *str;
    int tmp_pos1, tmp_pos2;

    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "KRB5");

    if (tree) {
        item = proto_tree_add_item(tree, proto_kerberos, NullTVB, offset,
                                   END_OF_FRAME, FALSE);
        kerberos_tree = proto_item_add_subtree(item, ett_kerberos);
    }

    asn1_open(&asn1, &pd[offset], END_OF_FRAME);

    /* top header */
    KRB_HEAD_DECODE_OR_DIE("top");
    protocol_message_type = tag;
    
    /* second header */
    KRB_HEAD_DECODE_OR_DIE("top2");

    /* version number */
    KRB_HEAD_DECODE_OR_DIE("version-wrap");
    KRB_DECODE_OR_DIE("version", asn1_int32_decode, version);

    if (kerberos_tree) {
        proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
                            "Version: %d",
                            version);
    }
    offset += length;

    /* message type */
    KRB_HEAD_DECODE_OR_DIE("message-type-wrap");
    KRB_DECODE_OR_DIE("message-type", asn1_int32_decode, msg_type);

    if (kerberos_tree) {
        proto_tree_add_text(kerberos_tree, NullTVB, offset, length,
                            "MSG Type: %s",
                            val_to_str(msg_type, krb5_msg_types,
                                       "Unknown msg type %#x"));
    }
    offset += length;

    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, val_to_str(msg_type, krb5_msg_types,
                                             "Unknown msg type %#x"));

        /* is preauthentication present? */
    KRB_HEAD_DECODE_OR_DIE("padata-or-body");
    if (((protocol_message_type == KRB5_MSG_AS_REQ ||
          protocol_message_type == KRB5_MSG_TGS_REQ) &&
         tag == KRB5_KDC_REQ_PADATA) ||
        ((protocol_message_type == KRB5_MSG_AS_RESP ||
          protocol_message_type == KRB5_MSG_TGS_RESP) &&
         tag == KRB5_KDC_RESP_PADATA)) {
        /* pre-authentication supplied */

        if (tree) {
            item = proto_tree_add_text(kerberos_tree, NullTVB, offset,
                                       item_len, "Pre-Authentication");
            preauth_tree = proto_item_add_subtree(item, ett_preauth);
        }

        KRB_HEAD_DECODE_OR_DIE("sequence of pa-data");
        start = asn1p->pointer + item_len;

        while(start > asn1p->pointer) {
            dissect_type_value_pair(asn1p, &offset,
                                    &preauth_type, &item_len, &tmp_pos1,
                                    &str, &str_len, &tmp_pos2);

            if (preauth_tree) {
                proto_tree_add_text(preauth_tree, NullTVB, tmp_pos1,
                                    item_len, "Type: %s",
                                    val_to_str(preauth_type,
                                               krb5_preauthentication_types,
                                               "Unknown preauth type %#x"));
                proto_tree_add_text(preauth_tree, NullTVB, tmp_pos2,
                                    str_len, "Value: %s",
                                    bytes_to_str(str, str_len));
            }
        }
        KRB_HEAD_DECODE_OR_DIE("message-body");
    }

    if (protocol_message_type == KRB5_MSG_AS_REQ ||
        protocol_message_type == KRB5_MSG_TGS_REQ) {
    
        /* request body */
        KRB_HEAD_DECODE_OR_DIE("body-sequence");
        if (tree) {
            item = proto_tree_add_text(kerberos_tree, NullTVB, offset,
                                       item_len, "Request");
            request_tree = proto_item_add_subtree(item, ett_request);
        }

        /* kdc options */
        KRB_HEAD_DECODE_OR_DIE("kdc options");

        KRB_HEAD_DECODE_OR_DIE("kdc options:bits");

        if (request_tree) {
                proto_tree_add_text(request_tree, NullTVB, offset, item_len,
                                    "Options: %s",
                                    bytes_to_str(asn1.pointer, item_len));
        }
        offset += item_len;
        asn1.pointer += item_len;

        KRB_HEAD_DECODE_OR_DIE("Principal Name");

        if (tag == KRB5_BODY_CNAME) {
            dissect_PrincipalName("Client Name", asn1p, fd, request_tree,
                                   &offset);
            KRB_HEAD_DECODE_OR_DIE("realm name");
        }

        if (tag == KRB5_BODY_REALM) {
            dissect_GeneralString(asn1p, &str, &str_len, &item_len);
            offset += item_len - str_len;
            if (request_tree) {
                proto_tree_add_text(request_tree, NullTVB, offset, str_len,
                                    "Realm: %.*s", str_len, str);
            }
            offset += str_len;
            KRB_HEAD_DECODE_OR_DIE("realm name");
        } else {
            return;
        }

        if (tag == KRB5_BODY_SNAME) {
            dissect_PrincipalName("Server Name", asn1p, fd, request_tree, &offset);
            KRB_HEAD_DECODE_OR_DIE("realm name");
        }

        if (tag == KRB5_BODY_FROM) {
            dissect_GeneralString(asn1p, &str, &str_len, &item_len);
            offset += item_len - str_len;
            krb_proto_tree_add_time(request_tree, offset, str_len,
                                    "Start Time", str);
            offset += str_len;
            KRB_HEAD_DECODE_OR_DIE("realm name");
        }

        if (tag == KRB5_BODY_TILL) {
            dissect_GeneralString(asn1p, &str, &str_len, &item_len);
            offset += item_len - str_len;
            krb_proto_tree_add_time(request_tree, offset, str_len,
                                    "End Time", str);
            offset += str_len;
            KRB_HEAD_DECODE_OR_DIE("realm name");
        } else {
            return;
        }
        
        if (tag == KRB5_BODY_RTIME) {
            dissect_GeneralString(asn1p, &str, &str_len, &item_len);
            offset += item_len - str_len;
            krb_proto_tree_add_time(request_tree, offset, str_len,
                                    "Renewable Until", str);
            offset += str_len;
            KRB_HEAD_DECODE_OR_DIE("realm name");
        }
            
        if (tag == KRB5_BODY_NONCE) {
            ret =  asn1_int32_decode(asn1p, &tmp_int, &length);
            if (ret != ASN1_ERR_NOERROR) {
                fprintf(stderr,"die: nonce, %s\n", to_error_str(ret));
                return;
            }
            if (request_tree) {
                proto_tree_add_text(request_tree, NullTVB, offset, length,
                                    "Random Number: %d",
                                    tmp_int);
            }
            offset += length;
        } else {
            return;
        }
        
        KRB_HEAD_DECODE_OR_DIE("encryption type spot");
        if (tag == KRB5_BODY_ETYPE) {
            KRB_HEAD_DECODE_OR_DIE("encryption type list");
            if (kerberos_tree) {
                item = proto_tree_add_text(request_tree, NullTVB, offset,
                                           item_len, "Encryption Types");
                etype_tree = proto_item_add_subtree(item, ett_etype);
            }
            total_len = item_len;
            while(total_len > 0) {
                ret =  asn1_int32_decode(asn1p, &tmp_int, &length);
                if (ret != ASN1_ERR_NOERROR) {
                    fprintf(stderr,"die: etype, %s\n", to_error_str(ret));
                    return;
                }
                if (etype_tree) {
                    proto_tree_add_text(etype_tree, NullTVB, offset, length,
                                        "Type: %s",
                                        val_to_str(tmp_int,
                                                   krb5_encryption_types,
                                                   "Unknown encryption type %#x"));
                }
                offset += length;
                total_len -= length;
            }
        } else {
            return;
        }

        KRB_HEAD_DECODE_OR_DIE("addresses");
        if (tag == KRB5_BODY_ADDRESSES) {
            /* pre-authentication supplied */

            dissect_Addresses("Addresses", asn1p, fd, kerberos_tree, &offset);
            KRB_HEAD_DECODE_OR_DIE("auth-data");
        }
    } else if (protocol_message_type == KRB5_MSG_AS_RESP ||
               protocol_message_type == KRB5_MSG_TGS_RESP) {
        if (tag == KRB5_KDC_RESP_CREALM) {
            dissect_GeneralString(asn1p, &str, &str_len, &item_len);
            offset += item_len - str_len;
            if (kerberos_tree) {
                proto_tree_add_text(kerberos_tree, NullTVB, offset, str_len,
                                    "Realm: %.*s", str_len, str);
            }
            offset += str_len;
        } else {
            return;
        }

        KRB_HEAD_DECODE_OR_DIE("cname");
        if (tag == KRB5_KDC_RESP_CNAME) {
            dissect_PrincipalName("Client Name", asn1p, fd, kerberos_tree,
                                   &offset);
        } else {
            return;
        }
        
        KRB_HEAD_DECODE_OR_DIE("ticket");
        if (tag == KRB5_KDC_RESP_TICKET) {
            dissect_ticket("ticket", asn1p, fd, kerberos_tree, &offset);
        } else {
            return;
        }

        KRB_HEAD_DECODE_OR_DIE("enc-msg-part");
        if (tag == KRB5_KDC_RESP_TICKET) {
            dissect_EncryptedData("Encrypted Payload", asn1p, fd, kerberos_tree,
                                  &offset);
        } else {
            return;
        }
    }
}

void
dissect_GeneralString(ASN1_SCK *asn1p, guchar **where,
                      guint *item_len, guint *pkt_len)
{
    guint cls, con, tag;
    gboolean def;
    const guchar *start = asn1p->pointer;

    asn1_header_decode (asn1p, &cls, &con, &tag, &def, item_len);
    asn1_octet_string_value_decode (asn1p, *item_len, where);
    *pkt_len = asn1p->pointer - start;
}

void
dissect_PrincipalName(char *title, ASN1_SCK *asn1p, frame_data *fd,
                       proto_tree *tree, int *inoff) {
    proto_tree *princ_tree = NULL;
    int offset = 0;

    gint32 princ_type;

    const guchar *start;
    guint cls, con, tag;
    guint item_len, total_len, type_len;
    int ret;

    proto_item *item = NULL;
    guint length;
    gboolean def;

    int type_offset;

    guchar *name;
    guint name_len;

    if (inoff)
        offset = *inoff;
    
    /* principal name */
    KRB_HEAD_DECODE_OR_DIE("principal section");

    KRB_HEAD_DECODE_OR_DIE("principal type");
    KRB_DECODE_OR_DIE("princ-type", asn1_int32_decode, princ_type);
    type_offset = offset;
    type_len = item_len;
    offset += length;

    KRB_HEAD_DECODE_OR_DIE("cname header");
    total_len = item_len;

    dissect_GeneralString(asn1p, &name, &name_len, &item_len);
    offset += item_len - name_len;
    
    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, *inoff, total_len,
                                   "%s: %.*s", title, (int) name_len, name);
        princ_tree = proto_item_add_subtree(item, ett_princ);

        proto_tree_add_text(princ_tree, NullTVB, type_offset, type_len,
                            "Type: %d", princ_type);
        proto_tree_add_text(princ_tree, NullTVB, offset, name_len,
                            "Name: %.*s", (int) name_len, name);
    }

    total_len -= item_len;
    offset += name_len;
    
    while(total_len > 0) {
        dissect_GeneralString(asn1p, &name, &name_len, &item_len);
        offset += item_len - name_len;
        if (princ_tree) {
            proto_tree_add_text(princ_tree, NullTVB, offset, name_len,
                                "Name: %.*s", (int) name_len, name);
        }
        total_len -= item_len;
        offset += name_len;
    }
    if (inoff)
        *inoff = offset;
}

void
dissect_Addresses(char *title, ASN1_SCK *asn1p, frame_data *fd,
                  proto_tree *tree, int *inoff) {
    proto_tree *address_tree = NULL;
    int offset = 0;

    const guchar *start;
    guint cls, con, tag;
    guint item_len;
    int ret;

    proto_item *item = NULL;
    gboolean def;

    int tmp_pos1, tmp_pos2;
    gint32 address_type;

    int str_len;
    guchar *str;

    if (inoff)
        offset = *inoff;

    KRB_HEAD_DECODE_OR_DIE("sequence of addresses");
    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, offset,
                                   item_len, "Addresses");
        address_tree = proto_item_add_subtree(item, ett_addresses);
    }

    start = asn1p->pointer + item_len;

    while(start > asn1p->pointer) {
        dissect_type_value_pair(asn1p, &offset,
                                &address_type, &item_len, &tmp_pos1,
                                &str, &str_len, &tmp_pos2);

        if (address_tree) {
            proto_tree_add_text(address_tree, NullTVB, tmp_pos1,
                                item_len, "Type: %s",
                                val_to_str(address_type, krb5_address_types,
                                           "Unknown address type %#x"));
            switch(address_type) {
                case KRB5_ADDR_IPv4:
                    proto_tree_add_text(address_tree, NullTVB, tmp_pos2,
                                        str_len, "Value: %d.%d.%d.%d",
                                        str[0], str[1], str[2], str[3]);
                    break;
                    
                default:
                    proto_tree_add_text(address_tree, NullTVB, tmp_pos2,
                                        str_len, "Value: %s",
                                        bytes_to_str(str, str_len));
            }
        }
    }
    
    if (inoff)
        *inoff = offset;
}

void
dissect_EncryptedData(char *title, ASN1_SCK *asn1p, frame_data *fd,
                      proto_tree *tree, int *inoff) {
    proto_tree *encr_tree = NULL;
    int offset = 0;

    const guchar *start;
    guint cls, con, tag;
    guint item_len;
    int ret;

    proto_item *item = NULL;
    guint length;
    gboolean def;
    int val;

    guchar *data;

    if (inoff)
        offset = *inoff;
    
    KRB_HEAD_DECODE_OR_DIE("encrypted data section");

    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, *inoff, item_len,
                                   "Encrypted Data: %s", title);
        encr_tree = proto_item_add_subtree(item, ett_princ);
    }

    /* type */
    KRB_HEAD_DECODE_OR_DIE("encryption type");
    KRB_DECODE_OR_DIE("encr-type", asn1_int32_decode, val);

    if (encr_tree) {
        proto_tree_add_text(encr_tree, NullTVB, offset, length,
                            "Type: %s",
                            val_to_str(val, krb5_encryption_types,
                                       "Unknown encryption type %#x"));
    }
    offset += length;

    /* kvno */
    KRB_HEAD_DECODE_OR_DIE("kvno-wrap");
    KRB_DECODE_OR_DIE("kvno", asn1_int32_decode, val);

    if (encr_tree) {
        proto_tree_add_text(encr_tree, NullTVB, offset, length,
                            "KVNO: %d", val);
    }
    offset += length;

    KRB_HEAD_DECODE_OR_DIE("cipher-wrap");
    KRB_HEAD_DECODE_OR_DIE("cipher");
    asn1_octet_string_value_decode (asn1p, item_len, &data);

    if (encr_tree) {
        proto_tree_add_text(encr_tree, NullTVB, offset, length,
                            "Cipher: %s", bytes_to_str(data, item_len));
    }
    offset += item_len;
    
    if (inoff)
        *inoff = offset;
}

void
dissect_ticket(char *title, ASN1_SCK *asn1p, frame_data *fd, proto_tree *tree,
               int *inoff) {
/*
   Ticket ::=                    [APPLICATION 1] SEQUENCE {
                                 tkt-vno[0]                   INTEGER,
                                 realm[1]                     Realm,
                                 sname[2]                     PrincipalName,
                                 enc-part[3]                  EncryptedData
   }
*/
    proto_tree *ticket_tree = NULL;
    int offset = 0;

    const guchar *start;
    guint cls, con, tag;
    guint item_len;
    int ret;

    proto_item *item = NULL;
    guint length;
    gboolean def;
    int val;

    int str_len;
    guchar *str;

    if (inoff)
        offset = *inoff;
    
    KRB_HEAD_DECODE_OR_DIE("ticket section");
    KRB_HEAD_DECODE_OR_DIE("ticket sequence");

    if (tree) {
        item = proto_tree_add_text(tree, NullTVB, *inoff, item_len,
                                   "Ticket");
        ticket_tree = proto_item_add_subtree(item, ett_ticket);
    }

    /* type */
    KRB_HEAD_DECODE_OR_DIE("ticket type");
    KRB_DECODE_OR_DIE("ticket-type", asn1_int32_decode, val);

    if (ticket_tree) {
        proto_tree_add_text(ticket_tree, NullTVB, offset, length,
                            "Version: %d", val);
    }
    offset += length;

    /* realm name */
    KRB_HEAD_DECODE_OR_DIE("realm");
    dissect_GeneralString(asn1p, &str, &str_len, &item_len);
    offset += item_len - str_len;
    if (ticket_tree) {
        proto_tree_add_text(ticket_tree, NullTVB, offset, str_len,
                            "Realm: %.*s", str_len, str);
    }
    offset += str_len;

    /* server name (sname) */
    KRB_HEAD_DECODE_OR_DIE("sname");
    dissect_PrincipalName("Service Name", asn1p, fd, ticket_tree, &offset);

    /* ticket */
    KRB_HEAD_DECODE_OR_DIE("enc-part");
    dissect_EncryptedData("ticket data", asn1p, fd, ticket_tree, &offset);

    if (inoff)
        *inoff = offset;
}


void
proto_register_kerberos(void) {
    static hf_register_info hf[] = {
    };
    static gint *ett[] = {
        &ett_kerberos,
        &ett_preauth,
        &ett_request,
        &ett_princ,
        &ett_encrypted,
        &ett_ticket,
        &ett_addresses,
        &ett_etype,
    };
    proto_kerberos = proto_register_protocol("Kerberos", "kerberos");
    proto_register_field_array(proto_kerberos, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_kerberos(void)
{
	old_dissector_add("udp.port", UDP_PORT_KERBEROS, dissect_kerberos);
	old_dissector_add("tcp.port", TCP_PORT_KERBEROS, dissect_kerberos);
}

/*

  MISC definitions from RFC1510:
  
   KerberosTime ::=   GeneralizedTime
   Realm ::=           GeneralString
   PrincipalName ::=   SEQUENCE {
                       name-type[0]     INTEGER,
                       name-string[1]   SEQUENCE OF GeneralString
   }
    HostAddress ::=     SEQUENCE  {
                        addr-type[0]             INTEGER,
                        address[1]               OCTET STRING
    }

    HostAddresses ::=   SEQUENCE OF SEQUENCE {
                        addr-type[0]             INTEGER,
                        address[1]               OCTET STRING
    }

    AS-REQ ::=         [APPLICATION 10] KDC-REQ
    TGS-REQ ::=        [APPLICATION 12] KDC-REQ
    
    KDC-REQ ::=        SEQUENCE {
           pvno[1]               INTEGER,
           msg-type[2]           INTEGER,
           padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
           req-body[4]           KDC-REQ-BODY
    }

    PA-DATA ::=        SEQUENCE {
           padata-type[1]        INTEGER,
           padata-value[2]       OCTET STRING,
                         -- might be encoded AP-REQ
    }

KDC-REQ-BODY ::=   SEQUENCE {
            kdc-options[0]       KDCOptions,
            cname[1]             PrincipalName OPTIONAL,
                         -- Used only in AS-REQ
            realm[2]             Realm, -- Server's realm
                         -- Also client's in AS-REQ
            sname[3]             PrincipalName OPTIONAL,
            from[4]              KerberosTime OPTIONAL,
            till[5]              KerberosTime,
            rtime[6]             KerberosTime OPTIONAL,
            nonce[7]             INTEGER,
            etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
                         -- in preference order
            addresses[9]         HostAddresses OPTIONAL,
            enc-authorization-data[10]   EncryptedData OPTIONAL,
                         -- Encrypted AuthorizationData encoding
            additional-tickets[11]       SEQUENCE OF Ticket OPTIONAL
}

   AS-REP ::=    [APPLICATION 11] KDC-REP
   TGS-REP ::=   [APPLICATION 13] KDC-REP

   KDC-REP ::=   SEQUENCE {
                 pvno[0]                    INTEGER,
                 msg-type[1]                INTEGER,
                 padata[2]                  SEQUENCE OF PA-DATA OPTIONAL,
                 crealm[3]                  Realm,
                 cname[4]                   PrincipalName,
                 ticket[5]                  Ticket,
                 enc-part[6]                EncryptedData
   }

   EncASRepPart ::=    [APPLICATION 25[25]] EncKDCRepPart
   EncTGSRepPart ::=   [APPLICATION 26] EncKDCRepPart

   EncKDCRepPart ::=   SEQUENCE {
               key[0]                       EncryptionKey,
               last-req[1]                  LastReq,
               nonce[2]                     INTEGER,
               key-expiration[3]            KerberosTime OPTIONAL,
               flags[4]                     TicketFlags,
               authtime[5]                  KerberosTime,
               starttime[6]                 KerberosTime OPTIONAL,
               endtime[7]                   KerberosTime,
               renew-till[8]                KerberosTime OPTIONAL,
               srealm[9]                    Realm,
               sname[10]                    PrincipalName,
               caddr[11]                    HostAddresses OPTIONAL
   }

   Ticket ::=                    [APPLICATION 1] SEQUENCE {
                                 tkt-vno[0]                   INTEGER,
                                 realm[1]                     Realm,
                                 sname[2]                     PrincipalName,
                                 enc-part[3]                  EncryptedData
   }


*/
