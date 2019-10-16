/* packet-bicc_mst.c
 * (Incomplete) Dissector for the 3GPP TS 29.205 BICC MST (Mobile Service Transport)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BICC_MST_H__
#define __PACKET_BICC_MST_H__

guint
dissect_bicc_mst_lcls_gcr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

#endif

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
