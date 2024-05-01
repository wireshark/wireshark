/* packet-irdma.h
 *
 * Definitions for IBM i RDMA packet dissection
 * Copyright 2018, 2024 IBM Corporation
 * Brian Jongekryg (bej@us.ibm.com, bej@arbin.net)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IRDMA_H__
#define __PACKET_IRDMA_H__

#define IRDMAEP_DATA_TYPE     0
#define IRDMAEP_USERRDMA_TYPE 1

typedef struct irdmaep_pdata
{
    unsigned pdata_type;
    uint32_t userrdma_offset;

} irdmaep_pdata_t;

#endif
