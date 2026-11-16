/* packet-mctp.c
 * Definitions for Management Component Transport Protocol (MCTP) packet
 * disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MCTP_H__
#define __PACKET_MCTP_H__

#include <epan/expert.h>

/* MCTP type values (DSP0239 1.12.0 Table 1, "MCTP Message Types") */

#define MCTP_TYPE_CONTROL   0
#define MCTP_TYPE_PLDM      1
#define MCTP_TYPE_NCSI      2
#define MCTP_TYPE_ETHERNET  3
#define MCTP_TYPE_NVME      4
#define MCTP_TYPE_SPDM      5
#define MCTP_TYPE_SECURED   6
#define MCTP_TYPE_CXL_FM    7
#define MCTP_TYPE_CXL_CCI   8
#define MCTP_TYPE_PCIE_MI   9
#define MCTP_TYPE_VDM_PCI   0x7e
#define MCTP_TYPE_VDM_IANA  0x7f

typedef enum {
    MCTP_SCOPE_NONE = 0,    /* no capture-domain identity */
    MCTP_SCOPE_I2C_BUS,     /* the binding's physical bus (DSP0236 8.3) */
    MCTP_SCOPE_INTERFACE,   /* the pcapng interface */
} mctp_scope_kind;          /* EIDs are unique per network only (DSP0236 3) */

typedef struct {
    uint32_t kind;          /* mctp_scope_kind */
    uint32_t section;       /* pcapng section; interface IDs are per section */
    uint32_t value;         /* bus number or interface ID, per kind */
    uint32_t interface_id_valid;
    uint32_t interface_id;  /* the record's interface; a bus number refines it */
} mctp_ingress_scope;       /* message and transaction key material */

typedef struct {
    bool has_ingress_scope;
    uint32_t ingress_scope_kind;
    uint32_t ingress_scope_value;
    bool drop_from_assembly;
} mctp_dissector_data;      /* optional binding-to-MCTP dissector data */

void mctp_ingress_scope_get(const packet_info *pinfo,
                            mctp_ingress_scope *scope);

/* The 7-bit SMBus/I2C slave address packet-mctp-smbus.c put in addr. */
bool mctp_smbus_slave_addr(const address *addr, uint8_t *slave);

#endif /* __PACKET_MCTP_H__ */
