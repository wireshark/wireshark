/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef NATIVE_TITLE_BAR_H
#define NATIVE_TITLE_BAR_H

#include <QColor>
#include <QObject>

class QEvent;
class QWidget;

/**
 * Paints the native title bar of top-level windows in the theme's window
 * color.
 *
 * Owned by ThemeManager, which creates it before any window exists.  A
 * theme that declares palette.window gets title bars in that color with
 * readable title text; any other theme keeps the platform title bar.  The
 * style is applied when a window is shown and re-applied to every open
 * window on ThemeManager::themeChanged.
 *
 * Qt has no API for the title bar color, so the native call lives in one
 * backend per platform:
 *   ui/qt/utils/themes/native_title_bar_mac.mm   (macOS, AppKit)
 *   ui/qt/utils/themes/native_title_bar_win.cpp  (Windows 11, DWM)
 *   ui/qt/utils/themes/native_title_bar_stub.cpp (all others; the window
 *                                                 manager draws the title bar)
 *
 * CMake selects exactly one of those for the build.
 *
 * previewStyle() gives a preview of a theme that is not applied yet
 * (ThemePreviewWidget) the same colors the real windows get.  It shows the
 * tint on every platform, also where the real title bar stays native.
 */
class NativeTitleBar : public QObject
{
    Q_OBJECT
public:
    /** What a backend paints.  An invalid background restores the native title bar. */
    struct Style {
        QColor background;          ///< Title bar fill, or invalid for the native look
        QColor text;                ///< Title text, readable on background
        bool darkBackground = false; ///< background is dark (light title text and buttons)
        bool appDark = false;       ///< Light/dark mode of the application
    };

    /** Installs the application event filter. */
    explicit NativeTitleBar(QObject *parent = nullptr);

    /** Applies the current style to every open window with a title bar. */
    void applyToAll();

    /**
     * The title bar a theme preview draws for a theme that is not applied
     * yet.  Tinted when the theme declares palette.window (@p declaresWindow)
     * and @p window is valid, on every platform: the preview shows what the
     * theme asks for, even where the platform keeps its own title bar
     * (Linux, Windows 10).  Colors are derived exactly as for the real
     * windows: background @p window, text @p windowText made readable
     * against it.  An invalid background means the native look.  appDark
     * is left false.
     */
    static Style previewStyle(bool declaresWindow, const QColor &window, const QColor &windowText);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    static Style currentStyle();

    /**
     * The one style derivation for real windows and previews.  With
     * @p tinted and a valid @p window: background @p window, text
     * @p windowText made readable against it, dark flag from its luminance.
     * Otherwise the native style.
     */
    static Style styleFor(bool tinted, const QColor &window, const QColor &windowText);

    /**
     * Whether this platform colors real title bars.  True on macOS and on
     * Windows 11; false where the window manager or Windows 10 draws the
     * title bar.  Defined by the platform backend.  Only currentStyle()
     * asks; a preview tints everywhere.
     */
    static bool isSupported();
    static bool hasTitleBar(const QWidget *widget);
    static void applyTo(QWidget *window, const Style &style);
    static bool applyAndMark(QWidget *window, const Style &style);

    /**
     * Platform backend.  Paints, or with an invalid background resets, the
     * title bar of @p window, whose native window has been created.
     *
     * @return false when the platform window is not available yet.
     */
    static bool applyNative(QWidget *window, const Style &style);
};

#endif /* NATIVE_TITLE_BAR_H */
