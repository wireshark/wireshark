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
     * Return a pixel metric of the base style, scaled with the application
     * zoom for a fixed set of metrics.
     *
     * Icon sizes and the splitter width are scaled on every base style.
     * Indicator (check box, radio button), scroll bar, slider and tool bar
     * extension/handle metrics are scaled on every base style except macOS,
     * where AppKit draws those controls at fixed control sizes. All other
     * metrics are returned unchanged.
     *
     * Native styles compute some metrics from other metrics through
     * proxy()->pixelMetric(), which calls back into this proxy. Only the
     * outermost call is scaled; nested calls return the base value, so no
     * metric is scaled twice. At Normal Size the base value is returned.
     *
     * @param metric The metric to return.
     * @param option The style option, may be null.
     * @param widget The widget the metric is for, may be null.
     * @return The metric in pixels.
     */
    int pixelMetric(PixelMetric metric, const QStyleOption *option = nullptr,
        const QWidget *widget = nullptr) const override;

    /**
     * Return the size of a control for the given contents size.
     *
     * The macOS style draws a non-flat push button as the rounded themed
     * bezel only when the button has exactly its default height. Zoomed
     * fonts make the content taller, the base style then returns a taller
     * button and draws it as an opaque square bezel. On the macOS base
     * style the push button height is held at the bezel height as long as
     * the content still fits the bezel's title rect; above that the base
     * result stands, so the text is never clipped. Both limits are queried
     * from the base style. On all other styles and controls the base result
     * is returned unchanged.
     *
     * @param type The contents type.
     * @param option The style option, may be null.
     * @param contentsSize The size of the contents.
     * @param widget The widget the size is for, may be null.
     * @return The size of the control.
     */
    QSize sizeFromContents(ContentsType type, const QStyleOption *option,
        const QSize &contentsSize, const QWidget *widget = nullptr) const override;

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

    using QProxyStyle::polish;
    using QProxyStyle::unpolish;

    /**
     * Draw a control through the base style, with one adjustment.
     *
     * On macOS the native style erases top toolbars in a main window's
     * unified title and toolbar area to transparent, so the system
     * content border shows instead of the palette. When the active
     * theme sets palette.window, those toolbars are filled with the
     * palette window color, with a separator line below the last
     * visible toolbar row. Themes without palette.window keep the
     * native look.
     */
    void drawControl(ControlElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override;

    /**
     * Polish a widget through the base style. On macOS, toolbars also
     * get this style as event filter, so the separator below the last
     * toolbar row moves when a toolbar is shown, hidden or moved.
     */
    void polish(QWidget *widget) override;

    /** Undo polish(): remove the toolbar event filter, then unpolish. */
    void unpolish(QWidget *widget) override;

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

protected:
    /**
     * On macOS, repaint the other top toolbars of a unified main window
     * when one of its toolbars is shown, hidden, moved or resized.
     */
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    // Nesting depth of pixelMetric() calls. Styles run on the GUI thread
    // only, so a plain counter is enough.
    mutable int metric_depth_ = 0;
};


#endif /* THEME_STYLER_H */
