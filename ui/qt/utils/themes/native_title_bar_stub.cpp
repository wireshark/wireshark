/* native_title_bar_stub.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NativeTitleBar backend for platforms where the window manager draws the
 * title bar (X11, Wayland server-side decorations) and the application
 * cannot color it.  Title bars stay native.
 */

#include "ui/qt/utils/themes/native_title_bar.h"

bool NativeTitleBar::applyNative(QWidget *, const Style &)
{
    return true;
}

bool NativeTitleBar::isSupported()
{
    return false;
}
