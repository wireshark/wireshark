/*
 *
 * Copyright (c) 2003 Endace Technology Ltd, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This software and documentation has been developed by Endace Technology Ltd.
 * along with the DAG PCI network capture cards. For further information please
 * visit https://www.endace.com/.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __W_ERF_COMMON_H__
#define __W_ERF_COMMON_H__

/*
 * Declarations of functions exported to file readers that handle
 * LINKTYPE_ERF packets.
 */

typedef struct erf_private erf_t;

erf_t* erf_priv_create(void);
erf_t* erf_priv_free(erf_t* erf_priv);

int erf_populate_interface_from_header(erf_t* erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header);

#endif /* __W_ERF_COMMON_H__ */

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
