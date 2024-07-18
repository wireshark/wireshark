/* packet-pw-atm.h
 * Interface of pw-atm module
 * Copyright 2009, Artem Tamazov <artem.tamazov@tellabs.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PW_ATM_H
#define PACKET_PW_ATM_H

#include "packet-pw-common.h"

struct pw_atm_phdr {
	struct atm_phdr info;
	bool enable_fill_columns_by_atm_dissector;
};

#endif /*PACKET_PW_ATM_H*/
