/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_LUA_CODE_PREVIEW_H
#define THEME_LUA_CODE_PREVIEW_H

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/widgets/theme_preview_pick.h>

#include <QColor>
#include <QFont>
#include <QHash>
#include <QImage>
#include <QList>
#include <QWidget>

#include <memory>

class LuaSyntaxHighlighter;
class QAction;
class QContextMenuEvent;
class QMenu;
class QMouseEvent;
class QPaintEvent;
class QTextDocument;

/**
 * Static copy of the Lua Debugger script editor for the Theme Designer.
 *
 * Shows the udprtt.lua example of the Lua debugger chapter of the
 * Developer's Guide, highlighted by the debugger's own LuaSyntaxHighlighter,
 * with a breakpoint, the line the debugger is paused on and a selection, so
 * every color of the theme's @c code section is on screen.  Colors come only
 * from setPreviewColors(), so a draft can be shown without touching the
 * application.  Built only with Lua, like the debugger.
 *
 * With picking enabled (picker()) a click names the theme color that
 * paints the spot, found with ThemePreviewPick's key render of a hidden copy
 * of this widget.
 */
class ThemeLuaCodePreview : public QWidget
{
    Q_OBJECT
public:
    explicit ThemeLuaCodePreview(QWidget *parent = nullptr);
    ~ThemeLuaCodePreview();

    /**
     * Replaces the preview's color table and repaints.
     *
     * @param colors  token to resolved color, typically one side of
     *                ThemeManager::resolveDraftTokens().  When the map is
     *                empty, the live theme is shown.
     */
    void setPreviewColors(const QHash<ThemeManager::ThemeToken, QColor> &colors);

    /** Sets the monospace font of the code and the gutter; an unchanged font is ignored. */
    void setPreviewFont(const QFont &monospace);

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
    void paintEvent(QPaintEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    QSize minimumSizeHint() const override;

private:
    /**
     * The color of @p token: from the preview map, else @p fallback.  Only
     * without a map the live theme is consulted.
     */
    QColor c(ThemeManager::ThemeToken token, const QColor &fallback = QColor()) const;

    /** The font of a paint pass: the preview font, else the application monospace font. */
    QFont resolvedFont() const;

    /** Width of the line-number gutter, as LuaDebuggerCodeView::lineNumberAreaWidth() computes it. */
    int gutterWidth(const QFont &font) const;

    /** Sizes the never shown copy like this widget and renders its key image. */
    QImage renderPickImage();

    /** Tallest line height of the key font, for ThemePreviewPick. */
    int pickTextHeight() const;

    QTextDocument *document_;
    LuaSyntaxHighlighter *highlighter_;
    QHash<ThemeManager::ThemeToken, QColor> colors_;
    QFont preview_font_;
    bool  has_preview_font_ = false;

    /// Never shown copy that paints the key render.
    std::unique_ptr<ThemeLuaCodePreview> pick_probe_;

    /** Pick state; renders through renderPickImage(). */
    ThemePreviewPicker picker_;
};

#endif // THEME_LUA_CODE_PREVIEW_H
