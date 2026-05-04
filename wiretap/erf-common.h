/** @file
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

/**
 * @brief Create a new erf_priv structure.
 *
 * @return Pointer to the newly created erf_priv structure, or NULL on failure.
 */
erf_t* erf_priv_create(void);

/**
 * @brief Frees an erf_t structure and its associated resources.
 *
 * @param erf_priv Pointer to the erf_t structure to be freed.
 * @return Always returns NULL.
 */
erf_t* erf_priv_free(erf_t* erf_priv);

/**
 * @brief Populates interface information from ERF header.
 *
 * @param erf_priv Pointer to ERF private data structure.
 * @param wth Pointer to wtap structure.
 * @param pseudo_header Pointer to union wtap_pseudo_header containing ERF pseudo-header.
 * @param err Pointer to integer for error code.
 * @param err_info Pointer to char pointer for error information.
 * @return int -1 on failure, 0 on success.
 */
int erf_populate_interface_from_header(erf_t* erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header, int *err, char **err_info);

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
