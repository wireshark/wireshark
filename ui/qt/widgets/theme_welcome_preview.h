/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_WELCOME_PREVIEW_H
#define THEME_WELCOME_PREVIEW_H

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/widgets/theme_preview_pick.h>

#include <QFont>
#include <QFrame>
#include <QHash>
#include <QImage>
#include <QList>
#include <QPalette>

#include <memory>

class QAction;
class QContextMenuEvent;
class QMenu;
class QMouseEvent;

namespace Ui {
class ThemeWelcomePreview;
}

/**
 * Compact, static copy of the Welcome Page for the Theme Designer.
 *
 * The widget tree reuses the object names of the real welcome widgets and
 * styles itself from the real welcome style sheets, resolved against a draft
 * token map instead of the live theme.  The widget never reads the live
 * theme: colors and palette come only from setTheme(), so the draft can be
 * shown without touching the application.  The learn card is the real
 * LearnCardWidget, told to leave its styling to this widget's sheet.
 *
 * With picking enabled (picker()) a click names the theme color that
 * paints the spot, found with ThemePreviewPick's key render of a hidden copy
 * of this widget.
 */
class ThemeWelcomePreview : public QFrame
{
    Q_OBJECT
public:
    explicit ThemeWelcomePreview(QWidget *parent = nullptr);
    ~ThemeWelcomePreview();

    /**
     * Applies a draft to the preview.
     *
     * @param tokens   draft token map (both sides of every color pair)
     * @param dark     which side of the pairs to show
     * @param palette  palette for the preview (the draft's Palette* tokens)
     */
    void setTheme(const QHash<ThemeManager::ThemeToken, ThemeColorPair> &tokens,
                  bool dark, const QPalette &palette);

    /** Sets the regular (proportional) font used for all preview text; an unchanged font is ignored. */
    void setPreviewFont(const QFont &regular);

    /**
     * Click-to-pick support, off by default.  While on, a pickable spot
     * shows a hand cursor, a left click emits layerPicked() and the context
     * menu offers the colors of the spot.
     */
    ThemePreviewPicker &picker() { return picker_; }

signals:
    /** A left click while picking; @p layer has token NoRole on a spot without theme color. */
    void layerPicked(const ThemePreviewPick::Layer &layer);

    /**
     * Emitted synchronously before the context menu opens, only while
     * picking is enabled.  Receivers insert color actions before @p before.
     */
    void pickMenuRequested(QMenu *menu, QAction *before,
                           const QList<ThemePreviewPick::Layer> &layers);

    /** A dialog opened from this widget (Save Image As) was closed. */
    void childDialogClosed();

protected:
    void mouseMoveEvent(QMouseEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;

private:
    /** Tallest line height of the key fonts, for ThemePreviewPick. */
    int pickTextHeight() const;

    /** Sizes the never shown copy like this widget and renders its key image. */
    QImage renderPickImage();

    /**
     * Builds the preview style sheet. palette(<role>) references are resolved
     * here because Qt resolves them against the application palette, not the
     * widget's.
     */
    QString buildStyleSheet(const QHash<ThemeManager::ThemeToken, ThemeColorPair> &tokens,
                            bool dark, const QPalette &palette) const;

    Ui::ThemeWelcomePreview *ui;
    /** Pick state; renders through renderPickImage(). */
    ThemePreviewPicker picker_;
    /** Font last passed to setPreviewFont(), so an unchanged font is ignored. */
    QFont preview_font_;
    bool  has_preview_font_ = false;
    std::unique_ptr<ThemeWelcomePreview> pick_probe_;
};

#endif // THEME_WELCOME_PREVIEW_H
