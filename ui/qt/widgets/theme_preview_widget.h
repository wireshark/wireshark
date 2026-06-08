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

#include <QColor>
#include <QFont>
#include <QFontMetricsF>
#include <QHash>
#include <QPair>
#include <QPainterPath>
#include <QRect>
#include <QRectF>
#include <QWidget>

class QPainter;
class QPaintEvent;
class QContextMenuEvent;
class QSize;

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

    /**
     * Toggles overlaying the live coloring rules on the sample packet rows.
     *
     * Off by default: the preview shows theme colors only — alternating base
     * shading plus the selection / marked / ignored state tokens.  When on,
     * each sample row is tinted with the matching rule from the user's current
     * color-filter set, looked up by rule name (e.g. "TCP", "HTTP", "Bad
     * TCP"); rows whose rule is disabled or absent keep their theme color, and
     * the state tokens still take precedence.  The rule set is snapshotted at
     * the moment it is enabled, not re-read on every repaint.
     *
     * Also reachable from the right-click menu; setting it emits
     * showColoringRulesChanged() so an external control (e.g. a checkbox on the
     * preferences page) can stay in sync with the menu toggle.
     */
    void setShowColoringRules(bool show);
    bool showColoringRules() const { return show_coloring_rules_; }

signals:
    void showColoringRulesChanged(bool show);

protected:
    void paintEvent(QPaintEvent *evt) override;
    void contextMenuEvent(QContextMenuEvent *event) override;
    QSize minimumSizeHint() const override;

private:
    QHash<ThemeManager::ThemeToken, QColor> colors_;

    /// Whether the sample rows overlay the live coloring rules (off = theme
    /// colors only).  Toggled via setShowColoringRules() or the context menu.
    bool show_coloring_rules_ = false;

    /// Snapshot of the live color-filter set: rule name → (background,
    /// foreground).  Rebuilt by rebuildRuleColors() whenever the overlay is
    /// enabled, so paints stay cheap and don't re-clone the filter list.
    QHash<QString, QPair<QColor, QColor>> ruleColors_;

    /**
     * Resolves a token to a QColor.  Looks up @p token in the preview
     * map first; if absent or invalid, consults the live
     * ThemeManager; if that also yields an invalid color, returns
     * @p fallback.
     */
    QColor c(ThemeManager::ThemeToken token,
             const QColor &fallback = QColor()) const;

    /**
     * Geometry and fonts for a single paint pass.  Built once by
     * buildLayout() from the content rectangle and then handed to every
     * band-drawing helper, so they all share identical fonts, row heights
     * and column boundaries without re-deriving them.
     *
     * Two fonts are carried deliberately: @ref monoFont draws the data
     * surfaces (packet rows, protocol tree, byte dump) while @ref labelFont
     * draws every label (filter text, column titles, token tags, status
     * bar).  The six band rectangles are laid out top-down, with the status
     * strip reserved at the very bottom first so the other bands cannot
     * overrun it.
     */
    struct Layout {
        QRect content;          ///< Packet content area, below the title bar.
        QFont labelFont;        ///< Proportional font: chrome labels, header.
        QFont monoFont;         ///< Monospace data font, at its true size.
        QFontMetricsF labelFm;  ///< Metrics for @ref labelFont.
        QFontMetricsF monoFm;   ///< Metrics for @ref monoFont.
        int rowH;               ///< Height of one monospace data row.
        QRect toolbarRect;      ///< Band 1: main icon toolbar.
        QRect filterRect;       ///< Band 2: display-filter bar.
        QRect headerRect;       ///< Band 3: column header.
        QRect listRect;         ///< Band 4: packet list.
        QRect detailsRect;      ///< Band 5a: protocol tree (left 60%).
        QRect bytesRect;        ///< Band 5b: hex/ASCII dump (right 40%).
        QRect statusRect;       ///< Band 6: status strip.
    };

    /**
     * Outcome of painting the faux OS window chrome.  @ref framePath and
     * @ref border are retained by paintEvent() so the rounded outline can be
     * stroked on top of the finished content (strokeWindowFrame()); @ref
     * content is the rectangle left for the packet mockup.
     */
    struct WindowChrome {
        QPainterPath framePath; ///< Rounded outer frame; also the paint clip.
        QColor       border;    ///< Colour for the final outline stroke.
        QRect        content;   ///< Area left for content, below the title bar.
    };

    /**
     * Derives fonts, row height and the six band rectangles from @p content.
     * Pure geometry: paints nothing.
     */
    Layout buildLayout(const QRect &content) const;

    /**
     * Paints the rounded frame, title bar and window controls, installs the
     * rounded clip path, and returns what strokeWindowFrame() needs plus the
     * content rectangle.  @p window selects the light/dark chrome variant.
     */
    WindowChrome paintWindowChrome(QPainter &p, const QRect &outer,
                                   const QColor &window);

    /**
     * Draws the per-platform window buttons into @p titleRect: macOS traffic
     * lights on the left, Windows/Linux min/max/close glyphs on the right
     * (tinted for @p darkChrome).
     */
    void drawWindowControls(QPainter &p, const QRectF &titleRect, bool darkChrome);

    /** Strokes the rounded outer border on top of the finished content. */
    void strokeWindowFrame(QPainter &p, const WindowChrome &chrome);

    /**
     * Geometry of packet-list column @p idx within @p content, padded by the
     * cell margin.  Column widths are fractions of the content width, so the
     * proportional-font header and the monospace rows share identical
     * boundaries.  @p top / @p h give the row's vertical placement.
     */
    QRectF cellRect(const QRect &content, int idx, int top, int h) const;

    /** Text-alignment flags for packet-list column @p idx. */
    int cellFlags(int idx) const;

    /** Band 1: main toolbar — the real colour application StockIcons. The
     *  toolbar tracks the icon theme, not the colour theme, so it carries no
     *  ThemeManager colour token. */
    void drawToolbar(QPainter &p, const Layout &layout);

    /**
     * Band 2: display-filter bar.  Tinted with the active Filter* state token
     * and carrying the real stock-icon affordances (bookmark / clear / apply)
     * plus the combo's recent-filters caret.
     */
    void drawFilterBar(QPainter &p, const Layout &layout);

    /** Band 3: native grey column header + divider grips, real column titles. */
    void drawColumnHeader(QPainter &p, const Layout &layout);

    /**
     * Band 4: sample packet rows.  By default paints theme colors only —
     * alternating-row shading plus the packet-state tokens (selection / marked
     * / ignored) — and a native scrollbar.  When the coloring-rules overlay is
     * enabled (see setShowColoringRules()), each row is first tinted from the
     * snapshotted live rule of its name (user/default colors, not tokens),
     * which the state tokens then override.
     */
    void drawPacketList(QPainter &p, const Layout &layout);

    /** Snapshots the current color-filter set into ruleColors_. */
    void rebuildRuleColors();

    /** Band 5a: a dense protocol tree with native disclosure triangles. */
    void drawDetailsPane(QPainter &p, const Layout &layout);

    /** Band 5b: aligned offset · hex · ASCII byte dump. */
    void drawBytesPane(QPainter &p, const Layout &layout);

    /** Band 6: expert-severity dot, "Ready", packet counts, resize grip. */
    void drawStatusBar(QPainter &p, const Layout &layout);

    /**
     * Prompts for a destination and writes the current preview to a PNG file.
     * The image is captured with grab(), so it matches what is on screen at
     * the device pixel ratio.  Invoked from the right-click context menu.
     */
    void saveAsImage();
};

#endif // THEME_PREVIEW_WIDGET_H
