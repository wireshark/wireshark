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

class QStyleOptionButton;
#ifdef Q_OS_MACOS
namespace NativePushButton { struct BezelState; }
#endif

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
     * The macOS style draws a non-flat push button as the rounded themed bezel
     * only when the button has exactly its default height. Zoomed fonts make
     * the content taller, the base style then returns a taller button and draws
     * it as an opaque square bezel. On the macOS base style the push button
     * height is held at the bezel height as long as the content still fits the
     * bezel's title rect; above that the base result stands, so the text is
     * never clipped, and drawControl() draws AppKit's flexible-height rounded
     * bezel instead of the square one. The macOS style also gives OK and Cancel
     * buttons a fixed width whatever their font, so on the macOS base style a
     * non-flat push button is widened until its title rect holds the content.
     * The limits are queried from the base style. On all other styles and
     * controls the base result is returned unchanged.
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
     * painted again in the ControlBorder color.  Fusion's own outline is
     * Window.darker(140), about 2:1, below the non-text contrast target.
     * Native styles (macOS, windows11, windowsvista) draw their frames
     * from their own colors and are left alone.
     */
    void drawPrimitive(PrimitiveElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override;

    using QProxyStyle::polish;
    using QProxyStyle::unpolish;

    /**
     * Draw a control through the base style, with adjustments on macOS.
     *
     * The native style erases top toolbars in a main window's unified
     * title and toolbar area to transparent, so the system content
     * border shows instead of the palette. When the active theme sets
     * palette.window, those toolbars are filled with the palette window
     * color, with a separator line below the last visible toolbar row.
     * Themes without palette.window keep the native look.
     *
     * A non-flat push button taller than the native bezel is drawn by the
     * native style as a flat square bezel. For those buttons the bevel
     * (CE_PushButtonBevel) is drawn as AppKit's flexible-height rounded
     * push bezel, the label color (CE_PushButtonLabel) follows that
     * bezel's accent state, and the keyboard focus ring (CE_FocusFrame)
     * is the native ring of that bezel. Buttons of the native bezel
     * height are left to the base style.
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

#ifdef Q_OS_MACOS
    /**
     * Height of the native push button bezel for @p button, as the base
     * style reports it for empty content (32, 28 or 24 px depending on the
     * control size).
     *
     * @param button        The button option.
     * @param contentsWidth Width of the content, passed through to the base.
     * @param widget        The push button, may be null.
     * @return The bezel height in pixels.
     */
    int pushButtonBezelHeight(const QStyleOptionButton *button, int contentsWidth,
        const QWidget *widget) const;

    /**
     * True if @p button is drawn with AppKit's flexible-height bezel instead
     * of the base style's square one: macOS base style, a raised, sunken or
     * checked non-flat push button that is not a command link, a widget with
     * a native window, and a height above the native bezel height.
     *
     * @param button The option; its rect must be the button's own rect, not
     *               a sub rect such as the label rect.
     * @param widget The QPushButton, whose size attributes the base style reads.
     * @return true if ThemeStyler draws the button.
     */
    bool takesFlexibleBezel(const QStyleOptionButton *button, const QWidget *widget) const;

    /**
     * True if the push button shows the accent (default) look when its
     * window is active: checked, the default button, or a focused
     * auto-default button.
     *
     * @param button The button option.
     * @return true if the button is emphasized.
     */
    static bool pushButtonEmphasized(const QStyleOptionButton *button);

    /**
     * State of the flexible bezel for @p button: enabled, pressed
     * (sunken) and highlighted (window active and the button
     * emphasized, see pushButtonEmphasized()). The bevel and the label
     * color both read it, so they always agree.
     *
     * @param button The button option.
     * @return The bezel state.
     */
    static NativePushButton::BezelState flexibleBezelState(const QStyleOptionButton *button);

    /**
     * Visible outline of the flexible bezel for @p button: the horizontal
     * extent and the top and bottom insets the base style uses for the
     * native bezel, stretched to the button height.
     *
     * @param button The option with the button's own rect.
     * @param widget The QPushButton.
     * @return The visible bezel rect in the option's coordinates.
     */
    QRect flexibleBezelRect(const QStyleOptionButton *button, const QWidget *widget) const;
#endif
};


#endif /* THEME_STYLER_H */
