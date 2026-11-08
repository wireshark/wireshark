/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef NATIVE_PUSH_BUTTON_H
#define NATIVE_PUSH_BUTTON_H

#include <QtGlobal>

#ifdef Q_OS_MACOS

class QPainter;
class QRect;
class QWidget;

/**
 * Native drawing of AppKit's variable-height rounded push button bezel.
 *
 * The macOS style draws a push button with the rounded native bezel only
 * when the button has exactly the native height; any taller button gets a
 * flat square bezel.  AppKit has a rounded push bezel that grows with the
 * button (NSBezelStyleFlexiblePush), which these functions draw for
 * ThemeStyler.  Implemented in native_push_button_mac.mm; GUI thread only.
 */
namespace NativePushButton {

/** The button state the bezel shows. */
struct BezelState {
    bool enabled = true;        ///< Draws the enabled bezel; false greys it out
    bool pressed = false;       ///< Draws the pressed (highlighted by mouse) bezel
    bool highlighted = false;   ///< Default/checked button: accent fill
};

/**
 * Draws AppKit's flexible-height rounded push bezel so that its visible
 * outline covers @p visibleRect.
 *
 * @param painter     Painter of the button paint event.
 * @param visibleRect Rect of the visible bezel outline, in painter coordinates.
 * @param state       Button state the bezel shows.
 * @param widget      The button; its window's native view provides the
 *                    appearance and key state.  No native window is created.
 * @return false if nothing was drawn (no native window, context failure);
 *         the caller then falls back to the base style.
 */
bool drawFlexibleBezel(QPainter *painter, const QRect &visibleRect,
                       const BezelState &state, const QWidget *widget);

/**
 * Draws the native keyboard focus ring of that bezel around @p visibleRect.
 *
 * @param painter     Painter of the focus frame paint event.
 * @param visibleRect Rect of the visible bezel outline, in painter coordinates.
 * @param widget      The button; see drawFlexibleBezel().
 * @return false if nothing was drawn; the caller then falls back.
 */
bool drawFocusRing(QPainter *painter, const QRect &visibleRect,
                   const QWidget *widget);

} // namespace NativePushButton

#endif /* Q_OS_MACOS */

#endif /* NATIVE_PUSH_BUTTON_H */
