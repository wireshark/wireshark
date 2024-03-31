/* simple_dialog.c
 * simple_dialog   2023 Niels Widger
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides a minimal cli implementation of simple dialogs.
 * It is only used by tshark and not wireshark.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <stdio.h>
#include <ui/simple_dialog.h>
#include "ws_attributes.h"

void *
simple_dialog(
  ESD_TYPE_E    type _U_,
  int           btn_mask _U_,
  const char * msg_format,
  ...
  )
{
  va_list       ap;

  va_start(ap, msg_format);
  vfprintf(stderr, msg_format, ap);
  va_end(ap);

  return NULL;
}

void
simple_message_box(ESD_TYPE_E type _U_, bool *notagain _U_,
                   const char *secondary_msg, const char *msg_format, ...)
{
  va_list ap;
  va_start(ap, msg_format);
  vfprintf(stderr, msg_format, ap);
  va_end(ap);

  fprintf(stderr, "%s\n", secondary_msg);
}

/*
 * Error alert box, taking a format and a va_list argument.
 */
void
vsimple_error_message_box(const char *msg_format, va_list ap)
{
  vfprintf(stderr, msg_format, ap);
}
