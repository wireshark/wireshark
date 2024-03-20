/** @file
 *
 * Copyright 2018, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __RUBY_MARSHAL_H__
#define __RUBY_MARSHAL_H__

#include <glib.h>

#include "wtap.h"

// Current Ruby Marshal library version
#define RUBY_MARSHAL_MAJOR 4
#define RUBY_MARSHAL_MINOR 8

wtap_open_return_val ruby_marshal_open(wtap *wth, int *err, char **err_info);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
