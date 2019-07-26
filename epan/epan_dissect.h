/* epan_dissect.h
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EPAN_DISSECT_H
#define EPAN_DISSECT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "epan.h"
#include "tvbuff.h"
#include "proto.h"
#include "packet_info.h"

/* Dissection of a single byte array. Holds tvbuff info as
 * well as proto_tree info. As long as the epan_dissect_t for a byte
 * array is in existence, you must not free or move that byte array,
 * as the structures that the epan_dissect_t contains might have pointers
 * to addresses in your byte array.
 */
struct epan_dissect {
	struct epan_session *session;
	tvbuff_t	*tvb;
	proto_tree	*tree;
	packet_info	pi;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EPAN_DISSECT_H */

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
