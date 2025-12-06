/* event-dissectors.h
 * Definitions for event dissector registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EVENT_DISSECTOR_REGISTER_H__
#define __EVENT_DISSECTOR_REGISTER_H__

#include "dissectors.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern dissector_reg_t const event_dissector_reg_proto[];
extern dissector_reg_t const event_dissector_reg_handoff[];

extern const unsigned long event_dissector_reg_proto_count;
extern const unsigned long event_dissector_reg_handoff_count;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EVENT_DISSECTOR_REGISTER_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
