/* packet-IEEE1609dot2.h
 * Routines for IEEE 1609.2
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _IEEE1609DOT2_H_
#define _IEEE1609DOT2_H_

#include "ws_symbol_export.h"

#include "packet-ieee1609dot2-val.h"

/*
 * When dissecting IEEE1609.2 structure containing only unsecured data, no PSID
 * is provided inside. Caller has to provide a ITS-AID/PSID before calling the
 * dissector to have a chance to dissect the data part.
 * For signed data, PSID is provided and the caller do not have to provide the
 * PSID. If he does, the provided PSID takes precedence on the PSID inside the
 * structure.
 */
WS_DLL_PUBLIC
void ieee1609dot2_set_next_default_psid(packet_info *pinfo, uint32_t psid);

#include "packet-ieee1609dot2-exp.h"

#endif /* _IEEE1609DOT2_H_ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
