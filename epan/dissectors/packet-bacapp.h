/* packet-bacapp.h
 * by fkraemer, SAUTER
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BACAPP_H__
#define __PACKET_BACAPP_H__

#define BACINFO_SERVICE         0
#define BACINFO_INVOKEID        1
#define BACINFO_INSTANCEID      2
#define BACINFO_OBJECTID        4


/* Used for BACnet statistics */
typedef struct _bacapp_info_value_t {
    const char      *service_type;
    const char      *invoke_id;
    const char      *instance_ident;
    const char      *object_ident;
} bacapp_info_value_t;

/* Possible datatypes of the present_value property.
   Follows the order of Application Tag Number. */
typedef enum BacappPresentValueType {
    BACAPP_PRESENT_VALUE_NULL,
    BACAPP_PRESENT_VALUE_BOOL,
    BACAPP_PRESENT_VALUE_UNSIGNED,
    BACAPP_PRESENT_VALUE_SIGNED,
    BACAPP_PRESENT_VALUE_REAL,
    BACAPP_PRESENT_VALUE_DOUBLE,
    BACAPP_PRESENT_VALUE_OCTET_STRING,
    BACAPP_PRESENT_VALUE_CHARACTER_STRING,
    BACAPP_PRESENT_VALUE_BIT_STRING,
    BACAPP_PRESENT_VALUE_ENUM,
    BACAPP_PRESENT_VALUE_DATE,
    BACAPP_PRESENT_VALUE_TIME,
    BACAPP_PRESENT_VALUE_OBJECT_IDENTIFIER
} BacappPresentValueType;

#endif /* __PACKET_BACNET_H__ */

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
