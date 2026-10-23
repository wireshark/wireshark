/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_STYLER_H
#define THEME_STYLER_H

#include <QProxyStyle>

class ThemeStyler : public QProxyStyle {
    Q_OBJECT
public:
    ThemeStyler(QStyle *style = nullptr);
    ThemeStyler(const QString &key);

    int styleHint(StyleHint hint, const QStyleOption *option = nullptr,
        const QWidget *widget = nullptr, QStyleHintReturn *returnData = nullptr) const override;

    /**
     * Draw a primitive through the base style, with two adjustments.
     *
     * On macOS 26 and later, item view check boxes are drawn on a
     * translated painter, since the native style ignores the indicator
     * position there.
     *
     * At High contrast with the Fusion base style, push button, combo box
     * and line edit frames (PE_PanelButtonCommand, PE_FrameLineEdit) are
     * painted again in the FieldBorder color.  Fusion's own outline is
     * Window.darker(140), about 2:1, below the non-text contrast target.
     * Native styles (macOS, windows11, windowsvista) draw their frames
     * from their own colors and are left alone.
     */
    void drawPrimitive(PrimitiveElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override;

    // The object name of the underlying (native) style, e.g. "windows11",
    // "windowsvista", "fusion", or "macos". QApplication::style() returns
    // either this proxy or a QStyleSheetStyle wrapping it, neither of which
    // has a useful objectName().
    static QString baseStyleName();

    /**
     * Style sheet for a filled push button.
     *
     * @param objectname Object name the rules are scoped to
     *                   (QPushButton#objectname).
     * @param baseColor  Fill seed, darkened until a white label
     *                   reaches the active readable-text ratio; hover and
     *                   pressed are darker still, and the label
     *                   is white in every state.
     * @return The style sheet text.
     */
    static QString buttonStyleSheet(const QString &objectname, const QColor &baseColor);
};


#endif /* THEME_STYLER_H */
