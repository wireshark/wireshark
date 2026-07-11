/* packet-rdm.h
 * Declarations for dissecting RDM PIDs
 * Copyright 2014, Claudius Zingerli <czingerl@gmail.com>
 *
 * RDM Parameter IDs (PIDs) are used in
 *   - packet-rdm.c (Ansi E1.20,E1.33 (ACN))
 *   - packet-artnet.c (Art-Net3)
 * -> Declarations remain in packet-rdm.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RDM_H__
#define __PACKET_RDM_H__

#include <stdint.h>

extern value_string_ext rdm_param_id_vals_ext;

typedef struct _rdm_pid_info {
    uint16_t pid;
    uint8_t command_class;
} rdm_pid_info;

/* Information for each manufacturer */
#define RDM_MANUFACTURER_ID_ETC 0x6574
extern const value_string etc_model_id_vals[];
extern value_string_ext etc_param_id_vals_ext;

#endif /* #ifndef __PACKET_RDM_H__ */
