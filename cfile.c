/* cfile.c
 * capture_file GUI-independent manipulation
 * Vassilii Khachaturov <vassilii@tarunz.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <epan/packet.h>
#include <wiretap/pcapng.h>

#include "cfile.h"

void
cap_file_init(capture_file *cf)
{
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
