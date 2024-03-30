/** @file
 *
 * "Decode As" UI utility routines.
 *
 * By David Hampton <dhampton@mac.com>
 * Copyright 2001 David Hampton
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 */

#ifndef __DECODE_AS_UTILS_H__
#define __DECODE_AS_UTILS_H__

#include "ws_symbol_export.h"

/** @file
 *  "Decode As" / "User Specified Decodes" dialog box.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
* This is the template for the decode as option; it is shared between the
* various functions that output the usage for this parameter.
*/
#define DECODE_AS_ARG_TEMPLATE "<layer_type>==<selector>,<decode_as_protocol>"

bool decode_as_command_option(const char *cl_param);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DECODE_AS_UTILS_H__ */
