/* packet-gsm_osmux.h
 *
 * Routines for packet dissection of Osmux voice/signalling multiplex protocol

 * (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Written by Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GSM_OSMUX_H__
#define __PACKET_GSM_OSMUX_H__

#include "config.h"

#include <stdint.h>

#include "epan/packet.h"

void
osmux_add_address(packet_info *pinfo, address *addr, int port, int other_port, uint32_t setup_frame_number);

#endif /*__PACKET_GSM_OSMUX_H__*/
