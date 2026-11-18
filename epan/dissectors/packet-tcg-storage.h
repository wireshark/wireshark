/* packet-tcg-storage.h
 * TCG Storage queries shared with the NVMe-MI transport
 * Copyright 2026, Brandon Chiu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TCG_STORAGE_H__
#define __PACKET_TCG_STORAGE_H__

#include <epan/packet.h>

struct nvme_security_info;

/* True if an IF-SEND/IF-RECV with these selectors may advance tracked TCG
 * state.  A selector-level potential only, not an outcome. */
bool tcg_storage_selector_may_advance_state(bool send, uint8_t secp, uint16_t spsp);

/* A completed Security Send: true if it is a TPer Reset candidate (Opal SSC
 * 2.30 3.2.3), whatever its integrity or 'apply'.  The reset is applied, on
 * the first pass only, when 'apply' and sec->state_valid are also true. */
bool tcg_storage_security_send_completed(packet_info *pinfo,
                                         const struct nvme_security_info *sec,
                                         bool apply);

/* A Security Send completed with an error, so no data was transferred (SIIS
 * 1.20 Table 25): on the first pass, undo the TCG session state that the
 * Send in 'request_frame' (the 'request_ordinal'th that ends there) advanced. */
void tcg_storage_security_send_failed(packet_info *pinfo, uint32_t request_frame,
                                      uint16_t request_ordinal);

#endif /* __PACKET_TCG_STORAGE_H__ */
