/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_PREVIEW_WIDGET_H
#define THEME_PREVIEW_WIDGET_H

#include <QHash>
#include <QWidget>

#include <ui/qt/utils/theme_manager.h>

/**
 * Static, hand-painted 3-pane mockup of a Wireshark capture window
 * (filter bar + packet list + details/bytes).  Used by the Font and
 * Colors preferences page to show the user what the selected theme
 * looks like before the change is committed.
 *
 * The widget never reads from the live ThemeManager except as a
 * fallback.  Callers push a token → color hash via setPreviewColors()
 * whenever the selection changes; missing entries fall back to the
 * live ThemeManager value so the widget always paints something.
 */
class ThemePreviewWidget : public QWidget
{
    Q_OBJECT
public:
    explicit ThemePreviewWidget(QWidget *parent = nullptr);

    /**
     * Replaces the preview's color table.  Triggers a repaint.
     *
     * @param colors  token → resolved QColor map, typically obtained
     *                from ThemeManager::previewTheme().  Passing an
     *                empty hash is valid — every lookup will fall back
     *                to the live ThemeManager.
     */
    void setPreviewColors(const QHash<ThemeManager::ThemeToken, QColor> &colors);

protected:
    void paintEvent(QPaintEvent *evt) override;
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

private:
    QHash<ThemeManager::ThemeToken, QColor> colors_;

    /**
     * Resolves a token to a QColor.  Looks up @p token in the preview
     * map first; if absent or invalid, consults the live
     * ThemeManager; if that also yields an invalid color, returns
     * @p fallback.
     */
    QColor c(ThemeManager::ThemeToken token,
             const QColor &fallback = QColor()) const;
};

#endif // THEME_PREVIEW_WIDGET_H
