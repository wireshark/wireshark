/**
 * Support for Apple Legacy and Custom pcapng blocks and options
 * Copyright 2025, Omer Shapira <oesh@apple.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WTAP_PCAPNG_DARWIN_CUSTOM_H__
#define __WTAP_PCAPNG_DARWIN_CUSTOM_H__

#include "wtap.h"
#include "pcapng.h"
#include "pcapng_module.h"
#include "wtap_opttypes.h"
#include <stdbool.h>

extern bool
pcapng_write_legacy_darwin_process_event_block(wtap_dumper *wdh, wtap_block_t sdata, int *err);

extern uint32_t
pcapng_compute_epb_legacy_darwin_size(unsigned option_id, wtap_optval_t *optval);

extern bool
pcapng_write_epb_legacy_darwin_option(wtap_dumper *wdh, wtap_block_t sdata,
        unsigned option_id, wtap_opttype_e option_type, wtap_optval_t *optval, int *err, char **err_info);

#endif /* __WTAP_PCAPNG_DARWIN_CUSTOM_H__ */

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
