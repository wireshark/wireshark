/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_PROTO_HIER_STAT_H__
#define __TAP_PROTO_HIER_STAT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern int pc_proto_id;

typedef struct _phs_t {
	struct _phs_t *sibling;
	struct _phs_t *child;
	struct _phs_t *parent;
	char *filter;
	int protocol;
	const char *proto_name;
	uint32_t frames;
	uint64_t bytes;
} phs_t;

extern phs_t * new_phs_t(phs_t *parent, const char *filter);
extern void free_phs(phs_t *rs);
extern tap_packet_status protohierstat_packet(void *prs, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_PROTO_HIER_STAT_H__ */

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
