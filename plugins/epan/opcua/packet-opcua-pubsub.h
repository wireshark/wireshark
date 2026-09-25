/* packet-opcua-pubsub.h
 *  Define includes, constants, and auxiliary functions for OPC UA PubSub UADP dissection.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * OPC UA PubSub UADP Dissector
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Includes */
#include <stdio.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-windows-common.h>
#include "epan/proto.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "opcua_simpletypes.h"
#include "opcua_hfindeces.h"
#include "opcua_complextypeparser.h"
#include "opcua_enumparser.h"


/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings) */
void proto_reg_handoff_opcua_pubsub(void);
void proto_register_opcua_pubsub(void);


/* default preferences */
#define OPCUA_PUBSUB_UDP_PORT_RANGE "4840-4850"
#define OPCUA_PUBSUB_ETHERTYPE 0xB62C
#define OPCUA_PUBSUB_DSAP 0x00

/* bitmasks for several flag fields */
#define OPCUA_PUBSUB_FLAGS_PID_ENABLED 0x10
#define OPCUA_PUBSUB_FLAGS_GROUP_HDR_ENABLED 0x20
#define OPCUA_PUBSUB_FLAGS_PAYLOAD_HDR_ENABLED 0x40
#define OPCUA_PUBSUB_FLAGS_EXT_F1_ENABLED 0x80

#define OPCUA_PUBSUB_EXT_F1_PID_TYPE 0x07
#define OPCUA_PUBSUB_EXT_F1_DATASET_CLASSID_ENABLED 0x08
#define OPCUA_PUBSUB_EXT_F1_SECURITY_ENABLED 0x10
#define OPCUA_PUBSUB_EXT_F1_TIMESTAMP_ENABLED 0x20
#define OPCUA_PUBSUB_EXT_F1_PICO_ENABLED 0x40
#define OPCUA_PUBSUB_EXT_F1_EXT_F2_ENABLED 0x80

#define OPCUA_PUBSUB_EXT_F2_CHUNK_ENABLED 0x01
#define OPCUA_PUBSUB_EXT_F2_PROMOTED_FIELDS_ENABLED 0x02
#define OPCUA_PUBSUB_EXT_F2_NM_TYPE 0x1C

#define OPCUA_PUBSUB_GROUP_HDR_FLAGS_WRITER_GID_ENABLED 0x01
#define OPCUA_PUBSUB_GROUP_HDR_FLAGS_GROUP_VERSION_ENABLED 0x02
#define OPCUA_PUBSUB_GROUP_HDR_FLAGS_NM_NUM_ENABLED 0x04
#define OPCUA_PUBSUB_GROUP_HDR_FLAGS_SEQ_NUM_ENABLED 0x08

#define OPCUA_PUBSUB_SEC_FLAGS_SIGN_ENABLED 0x01
#define OPCUA_PUBSUB_SEC_FLAGS_ENCRYPT_ENABLED 0x02
#define OPCUA_PUBSUB_SEC_FLAGS_SEC_FOOTER_ENABLED 0x04
#define OPCUA_PUBSUB_SEC_FLAGS_KEY_RESET 0x08

#define OPCUA_PUBSUB_DSM_F1_VALID_ENABLED 0x01
#define OPCUA_PUBSUB_DSM_F1_FIELD_ENC 0x06
#define OPCUA_PUBSUB_DSM_F1_SEQNUM_ENABLED 0x08
#define OPCUA_PUBSUB_DSM_F1_STATUS_ENABLED 0x10
#define OPCUA_PUBSUB_DSM_F1_CONF_MAJOR_VER_ENABLED 0x20
#define OPCUA_PUBSUB_DSM_F1_CONF_MINOR_VER_ENABLED 0x40
#define OPCUA_PUBSUB_DSM_F1_DSM_F2_ENABLED 0x80

#define OPCUA_PUBSUB_DSM_F2_DSM_TYPE 0x0F
#define OPCUA_PUBSUB_DSM_F2_TIMESTAMP_ENABLED 0x10
#define OPCUA_PUBSUB_DSM_F2_PICO_ENABLED 0x20

/* the various Security Policies (TODO: enum?) */
#define OPCUA_PUBSUB_SECURITY_POLICY_NONE 0
#define OPCUA_PUBSUB_SECURITY_POLICY_AES128_CTR 1
#define OPCUA_PUBSUB_SECURITY_POLICY_AES256_CTR 2


/* other macros */
#define DATASETFIELD_NAME_LENGTH 32
