/** @file
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "epan.h"
#include "tvbuff.h"
#include "proto.h"
#include "packet_info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Holds all state for the dissection of a single byte array, including session, buffer, and protocol tree.
 *
 * Dissection of a single byte array. Holds tvbuff info as
 * well as proto_tree info. As long as the epan_dissect_t for a byte
 * array is in existence, you must not free or move that byte array,
 * as the structures that the epan_dissect_t contains might have pointers
 * to addresses in your byte array.
 */
struct epan_dissect {
    struct epan_session* session; /**< The epan session context under which this dissection is taking place. */
    tvbuff_t*            tvb;     /**< Tvbuff representing the byte array being dissected. */
    proto_tree*          tree;    /**< Protocol tree built up during dissection of the byte array. */
    packet_info          pi;      /**< Packet metadata and state populated during dissection. */
};
#ifdef __cplusplus
}
#endif /* __cplusplus */

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
