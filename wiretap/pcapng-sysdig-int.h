/** @file
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __WTAP_PCAPNG_SYSDIG_INT_H__
#define __WTAP_PCAPNG_SYSDIG_INT_H__

#include "wtap.h"
#include "pcapng.h"
#include "pcapng_module.h"

extern bool
pcapng_write_sysdig_event_block(wtap_dumper* wdh, const wtap_rec* rec,
    int* err, char** err_info);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
