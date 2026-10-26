/* native_title_bar_win.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NativeTitleBar backend for Windows.  Windows 11 (build 22000 and later)
 * colors the caption through DWM window attributes.  Windows 10 does not
 * support the caption color, so isSupported() is false there and its
 * caption keeps the light/dark look Qt gives it.
 */

#include "ui/qt/utils/themes/native_title_bar.h"

#include <QOperatingSystemVersion>
#include <QWidget>

#include <windows.h>
#include <dwmapi.h>

namespace {

// DWM attribute ids by value, so SDK headers that predate them still build.
constexpr DWORD dwmUseImmersiveDarkMode = 20;  // DWMWA_USE_IMMERSIVE_DARK_MODE
constexpr DWORD dwmCaptionColor = 35;          // DWMWA_CAPTION_COLOR
constexpr DWORD dwmTextColor = 36;             // DWMWA_TEXT_COLOR
constexpr COLORREF dwmColorDefault = 0xFFFFFFFF; // DWMWA_COLOR_DEFAULT

COLORREF toColorRef(const QColor &color)
{
    return RGB(color.red(), color.green(), color.blue());
}

} // namespace

bool NativeTitleBar::isSupported()
{
    // DWMWA_CAPTION_COLOR exists from Windows 11, build 22000, on.  The
    // result of that call is still checked in applyNative().
    static const bool supported = QOperatingSystemVersion::current()
            >= QOperatingSystemVersion(QOperatingSystemVersion::Windows, 10, 0, 22000);
    return supported;
}

bool NativeTitleBar::applyNative(QWidget *window, const Style &style)
{
    HWND hwnd = reinterpret_cast<HWND>(window->winId());
    if (!hwnd)
        return false;

    const bool tinted = style.background.isValid();
    const COLORREF caption = tinted ? toColorRef(style.background) : dwmColorDefault;
    const COLORREF text = tinted ? toColorRef(style.text) : dwmColorDefault;
    // The caption buttons follow the dark mode attribute, which Qt sets from
    // the application color scheme.  While tinted it follows the caption
    // color instead; on reset it gets back the application's mode.
    const BOOL dark = (tinted ? style.darkBackground : style.appDark) ? TRUE : FALSE;

    // Windows 10 rejects the caption color but accepts the dark mode
    // attribute.  Writing the dark mode attribute only after the caption
    // color was accepted leaves the Windows 10 caption exactly as Qt set it.
    // The text color result does not matter: it is supported wherever the
    // caption color is.
    if (FAILED(DwmSetWindowAttribute(hwnd, dwmCaptionColor, &caption, sizeof(caption))))
        return true;
    DwmSetWindowAttribute(hwnd, dwmTextColor, &text, sizeof(text));
    DwmSetWindowAttribute(hwnd, dwmUseImmersiveDarkMode, &dark, sizeof(dark));
    return true;
}
