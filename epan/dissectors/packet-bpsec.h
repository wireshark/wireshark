/* packet-bpsec.h
 * Definitions for Bundle Protocol Version 7 Security (BPSec) dissection
 * References:
 *     RFC 9172: https://www.rfc-editor.org/rfc/rfc9172.html
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef PACKET_BPSEC_H
#define PACKET_BPSEC_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include "packet-bpv7.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A human-friendly name for a security context ID can be registered with
 * the dissector table "bpsec.ctx". This dissector is used only for its
 * description and not to actually dissect anything.
 *
 * BPSec per-context parameter types and result types are registered with the
 * dissector table "bpsec.param" and "bpsec.result" respectively.
 * Both use bpsec_id_t* table keys, to identify both the context and the type
 * code points.
 */

/** Abstract Security Block Security Context Flags.
 * RFC 9172 Section 3.6.
 */
typedef enum {
    /// Security Context Parameters present
    BPSEC_ASB_HAS_PARAMS = 0x01,
} BpsecAsbFlag;

/// Parameter/Result dissector lookup
typedef struct {
    /// Security context ID
    int64_t context_id;
    /// Parameter/Result ID
    int64_t type_id;
} bpsec_id_t;

typedef struct {
    /// Specific type being dissected
    bpsec_id_t id;
    /// Pointer to containing block/bundle context
    const bp_dissector_data_t *bp;
} bpsec_dissector_data_t;

/** Construct a new ID.
 */
WS_DLL_PUBLIC
bpsec_id_t * bpsec_id_new(wmem_allocator_t *alloc, int64_t context_id, int64_t type_id);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_BPSEC_H */
