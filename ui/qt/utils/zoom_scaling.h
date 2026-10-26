/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QString>

class QLayout;
class QWidget;

/**
 * @brief Text zoom scaling of pixel lengths and widget metrics.
 *
 * The functions that take a factor depend on nothing but Qt and are covered by
 * qt_zoom_scaling_test; the others use the current zoom level of FontManager
 * and follow its zoom changes.
 */
namespace ZoomScaling {

/**
 * @brief Scales a pixel value designed for zoom level 0 by @p factor.
 *
 * 0 stays 0; any other value is at least 1.
 */
int scaledPixels(int px, qreal factor);

/**
 * @brief Scales one component of a widget size limit by @p factor.
 *
 * 0, 1 and QWIDGETSIZE_MAX (unlimited) are returned unchanged, so resets,
 * hairlines and "no limit" stay; any other value goes through
 * scaledPixels(design, factor).
 */
int scaledSizeLimit(int design, qreal factor);

/**
 * @brief Scales the pixel lengths of a stylesheet by @p factor.
 *
 * Qt stylesheets only support absolute px/pt units (no relative em/%), so
 * themed text and the lengths around it (heights, radii, padding, margins,
 * sizes) are scaled here to follow the rest of the UI:
 *  - the size in "font:" / "font-size:" values, px and pt, always;
 *  - every other "Npx" length in a declaration, through scaledPixels(),
 *    except 0 and 1 (resets and hairline borders keep their value).
 * Text inside comments and url(...) is left alone.  No-op at a factor of 1.0.
 */
QString scaleStyleSheetLengths(const QString &qss, qreal factor);

/** @name Current zoom level */
///@{

/**
 * Scales a pixel value that is designed for zoom level 0 by the current
 * zoom factor, FontManager::zoomFactor().  0 stays 0; any other value is at
 * least 1.
 *
 * @param px  non-negative pixel value at zoom level 0.
 * @return    the value at the current zoom level.
 */
int scaledPixels(int px);

/**
 * Scales one component of a widget size limit (minimum or maximum width
 * or height) designed for zoom level 0.  0, 1 and QWIDGETSIZE_MAX
 * (unlimited) are returned unchanged at every zoom level, so resets,
 * hairlines and "no limit" stay; any other value goes through
 * scaledPixels().
 *
 * @param design  the limit at zoom level 0.
 * @return        the limit at the current zoom level.
 */
int scaledSizeLimit(int design);

/**
 * Makes the minimum and maximum size of @p widget follow the zoom level.
 *
 * The first call stores the widget's current minimumSize() and
 * maximumSize() as its zoom level 0 design values (call it after
 * setupUi() or after the widget's own size limit calls), and updates the
 * limits on every zoom change for the widget's lifetime.  Later calls
 * only re-apply the stored values.  Each component goes through
 * scaledSizeLimit().  Do not use it on a widget that writes its own size
 * limits at runtime (an animated AccordionFrame), as the two writers
 * would overwrite each other.
 *
 * @param widget  the widget to scale; nullptr is ignored.
 */
void scaleSizeLimits(QWidget *widget);

/**
 * Makes the icon size of @p widget follow the zoom level.
 *
 * The first call stores the widget's current iconSize as its zoom level 0
 * design value (call it after setupUi() or after the one setIconSize()
 * call), and updates the icon size on every zoom change for the widget's
 * lifetime.  Later calls only re-apply the stored value.  Each component
 * goes through scaledPixels().  Works on any widget with an iconSize
 * property (QAbstractButton, QToolBar, QAbstractItemView); other widgets
 * are ignored.
 *
 * @param widget  the widget to scale; nullptr is ignored.
 */
void scaleIconSize(QWidget *widget);

/**
 * Makes the contents margins and spacing of @p layout follow the zoom
 * level.
 *
 * The first call stores the layout's current contentsMargins() and
 * spacing() as their zoom level 0 design values (call it after setupUi()
 * or after the layout's own margin and spacing calls), and updates them on
 * every zoom change for the layout's lifetime.  Later calls only re-apply
 * the stored values.  Each component goes through scaledPixels(); a
 * negative spacing (the style default) stays negative.
 *
 * @param layout  the layout to scale; nullptr is ignored.
 */
void scaleLayoutMetrics(QLayout *layout);

/**
 * Side in pixels of the display filter toolbar and status bar icons at
 * the current zoom level (14 at zoom 0).  Not derived from the status bar
 * font, which is smaller on macOS, nor from a style metric.
 */
int barIconSize();

#ifdef Q_OS_MACOS
/**
 * Makes the macOS control size of @p widget follow the zoom level.
 *
 * macOS draws native controls (pop-up buttons, check box and radio
 * button indicators, push button bezels) at a fixed height for each
 * control size, whatever the font.  Up to zoom level 0 the widget uses
 * the small control size (Qt::WA_MacSmallSize) and the small font;
 * above it, the regular control size and the regular font, so the
 * controls grow with the zoomed text.  A QComboBox also drops the
 * explicit font Qt gives it on each control size change, so its text
 * follows the zoom.  The widget follows every later zoom change for its
 * lifetime; a repeated call only re-applies.  Declared on macOS only;
 * guard every call with Q_OS_MACOS.
 *
 * @param widget  the widget; nullptr is ignored.
 */
void scaleMacControlSize(QWidget *widget);

/**
 * Calls scaleMacControlSize() for every descendant widget of @p parent
 * (not @p parent itself).  Call it after all child widgets exist.
 *
 * @param parent  the parent widget; nullptr is ignored.
 */
void scaleMacControlSizes(QWidget *parent);
#endif // Q_OS_MACOS

///@}

} // namespace ZoomScaling
