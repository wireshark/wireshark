/* packet-iuup.h
 *
 * IuUP Protocol 3GPP TS 25.415 V6.2.0 (2005-03)

 * (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Written by Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * (c) 2005 Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IUUP_H__
#define __PACKET_IUUP_H__

#include <stdint.h>

#include "epan/packet.h"

#define ACKNACK_MASK  0x0c
#define PROCEDURE_MASK  0x0f
#define FQC_MASK 0xc0
#define PDUTYPE_MASK 0xf0

typedef struct _iuup_rfci_t {
    unsigned id;
    unsigned sum_len;
    unsigned num_of_subflows;
    struct {
        unsigned len;
    } subflow[8];
    struct _iuup_rfci_t* next;
} iuup_rfci_t;

typedef struct {
    uint32_t id;
    unsigned num_of_subflows;
    iuup_rfci_t* rfcis;
    iuup_rfci_t* last_rfci;
} iuup_circuit_t;

struct _iuup_info {
	iuup_circuit_t *iuup_circuit;
};

#define PDUTYPE_DATA_WITH_CRC 0
#define PDUTYPE_DATA_NO_CRC 1
#define PDUTYPE_DATA_CONTROL_PROC 14

#define PDUTYPE_DATA_WITH_CRC_HDR_LEN 4
#define PDUTYPE_DATA_NO_CRC_HDR_LEN 3
#define PDUTYPE_DATA_CONTROL_PROC_HDR_LEN 4

#endif /*__PACKET_IUUP_H__*/
