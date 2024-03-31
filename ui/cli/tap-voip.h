/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_VOIP_H__
#define __TAP_VOIP_H__

#include "ui/voip_calls.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* store the chosen calls in a bit-array */
#define VOIP_CONV_BITS          (sizeof(int) * 8)
#define VOIP_CONV_NUM           ((1<<(sizeof(uint16_t) * 8))/VOIP_CONV_BITS)
#define VOIP_CONV_MAX           (VOIP_CONV_BITS * VOIP_CONV_NUM)

extern voip_calls_tapinfo_t tapinfo_;
extern int voip_conv_sel[VOIP_CONV_NUM];
extern void voip_stat_init_tapinfo(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_VOIP_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
