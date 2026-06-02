/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ADAPTIVE_TOOL_BUTTON_H
#define ADAPTIVE_TOOL_BUTTON_H

#include <QToolButton>
#include <QSize>

/**
 * @brief A flat, icon-only tool button whose footprint hugs its icon and whose
 *        icon scales with the application zoom.
 *
 * AdaptiveToolButton exists for inline use inside a line edit's content area
 * (bookmark / clear / apply / history affordances). It solves two problems the
 * native QLineEdit side-action button could not:
 *
 *   1. **Tight box.** A plain QToolButton (and the internal QLineEditIconButton)
 *      sizes itself from the style, which pads the icon with fixed dead space
 *      (the side-widget box is `PM_SmallIconSize + 6`, leaving ~3px each side and
 *      a centred glyph). This widget overrides sizeHint()/minimumSizeHint() to
 *      return exactly `iconSize + 2*iconPadding`, so the host can place a box that
 *      hugs the glyph instead of a fixed, oversized one.
 *
 *   2. **Zoom-aware icon.** The icon is sized from a *base* (logical) size taken
 *      at zoom 1.0 and scaled by FontManager::zoomFactor(), recomputed whenever
 *      the zoom changes. The glyph therefore grows and shrinks with the
 *      surrounding text instead of staying a fixed pixel size.
 *
 * It deliberately does NOT position itself. Placement within the host (anchoring,
 * text-margin reservation, dividers) is the container's job; this widget only
 * reports how much room it needs. The flat appearance (no frame or fill) is
 * supplied by the global AdaptiveToolButton rule in application.qss.
 *
 * Defaults: the base icon size is the style's PM_SmallIconSize (so the platform
 * icon contract is honoured unless a caller sets something else, e.g. a wide
 * apply glyph via setBaseIconSize(QSize(24, 14))), and the icon padding is the
 * style's PM_DefaultFrameWidth (~1px).
 */
class AdaptiveToolButton : public QToolButton
{
    Q_OBJECT

public:
    explicit AdaptiveToolButton(QWidget *parent = nullptr);

    /**
     * @brief Sets the logical icon size at zoom 1.0.
     *
     * The effective icon size (QToolButton::iconSize()) is this value scaled by
     * the current zoom factor; it updates automatically on zoom changes. Pass a
     * non-square size for glyphs that are not 1:1 (e.g. the apply chevron).
     *
     * If never set, the base size defaults to the style's PM_SmallIconSize.
     */
    void setBaseIconSize(const QSize &size);

    /** @brief The logical icon size at zoom 1.0. */
    QSize baseIconSize() const { return base_icon_size_; }

    /**
     * @brief Sets the symmetric padding (px) added around the icon in the size
     *        hint. Not zoom-scaled, so it stays a crisp hairline gap at any zoom.
     *
     * If never set, the padding defaults to the style's PM_DefaultFrameWidth
     * (~1px).
     */
    void setIconPadding(int padding);

    /** @brief The symmetric padding (px) around the icon. */
    int iconPadding() const { return icon_padding_; }

    /** @brief Icon footprint plus padding; tight, ignoring style margins. */
    QSize sizeHint() const override;

    /** @brief Same as sizeHint(): the button never shrinks below its glyph. */
    QSize minimumSizeHint() const override;

private:
    /** @brief Recomputes the effective icon size from base size * zoom factor. */
    void applyZoom();

    QSize base_icon_size_; /**< Logical icon size at zoom 1.0. */
    int   icon_padding_;   /**< Symmetric px padding around the icon. */
};

#endif // ADAPTIVE_TOOL_BUTTON_H
