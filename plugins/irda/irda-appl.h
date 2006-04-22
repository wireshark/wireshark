/* irda-appl.h
 * Interface for IrDA application dissectors
 * By Jan Kiszka <jan.kiszka@web.de>
 * Copyright 2003 Jan Kiszka
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifndef __IRDA_APPL_H__
#define __IRDA_APPL_H__

/*
 * Prototypes, defines, and typedefs needed for implementing IrDA application
 * layer dissectors.
 * There should be no need to modify this part.
 */

/* LM-IAS Attribute types */
#define IAS_MISSING         0
#define IAS_INTEGER         1
#define IAS_OCT_SEQ         2
#define IAS_STRING          3

/* Maximum number of handled list entries of an IAP result */
#define MAX_IAP_ENTRIES     32


typedef enum {
    CONNECT_PDU,
    DISCONNECT_PDU,
    DATA_PDU
} pdu_type_t;

typedef gboolean (*ias_value_dissector_t)(tvbuff_t* tvb, unsigned offset, packet_info* pinfo, proto_tree* tree,
                                          unsigned list_index, guint8 attr_type);

typedef const struct ias_attr_dissector {
    const char*             attr_name;
    ias_value_dissector_t   value_dissector;
} ias_attr_dissector_t;

typedef const struct ias_class_dissector {
    const char*             class_name;
    ias_attr_dissector_t*   pattr_dissector;
} ias_class_dissector_t;


extern gboolean check_iap_octet_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                       const char* attr_name, guint8 attr_type);
extern guint8 check_iap_lsap_result(tvbuff_t* tvb, proto_tree* tree, unsigned offset,
                                    const char* attr_name, guint8 attr_type);

extern void add_lmp_conversation(packet_info* pinfo, guint8 dlsap, gboolean ttp, dissector_t proto_dissector);

extern unsigned dissect_param_tuple(tvbuff_t* tvb, proto_tree* tree, unsigned offset);


extern dissector_handle_t data_handle;


/*
 * Protocol exports.
 * Modify the lines below to add new protocols.
 */

/* IrCOMM/IrLPT protocol */
extern void proto_register_ircomm(void);
extern ias_attr_dissector_t ircomm_attr_dissector[];
extern ias_attr_dissector_t irlpt_attr_dissector[];

/* Serial Infrared (SIR) */
extern void proto_register_irsir(void);


/*
 * Protocol hooks
 */

/* IAS class dissectors */
#define CLASS_DISSECTORS                                    \
    { "Device",         device_attr_dissector },            \
    { "IrDA:IrCOMM",    ircomm_attr_dissector },            \
    { "IrLPT",          irlpt_attr_dissector },             \
    { NULL,             NULL }

#endif /* __IRDA_APPL_H__ */
