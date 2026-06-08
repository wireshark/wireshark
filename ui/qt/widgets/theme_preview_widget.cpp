/* theme_preview_widget.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include "theme_preview_widget.h"
#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/themes/color_math.h>

#include <epan/color_filters.h>

#include <QAction>
#include <QApplication>
#include <QContextMenuEvent>
#include <QFileDialog>
#include <QFontMetricsF>
#include <QIcon>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPen>
#include <QPixmap>
#include <QPointF>
#include <QPolygonF>
#include <QRectF>
#include <QSvgRenderer>

namespace {

// Faux OS window-chrome geometry, fixed regardless of the previewed theme.
const int   kTitleBarH  = 24;
const qreal kFrameRadius = 8.0;

// Width reserved on the right of the packet list for the native scrollbar.
const int kScrollW = 11;

// Real default packet-list columns (with Delta).  Widths are fractions of the
// content width so the proportional-font header and the monospace rows share
// identical boundaries.  No. / Delta / Length are right-aligned to match the
// live packet list.
const struct { double frac; bool right; const char *title; } kColumns[] = {
    { 0.06, true,  QT_TRANSLATE_NOOP("ThemePreviewWidget", "No.")         },
    { 0.11, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Time")        },
    { 0.09, true,  QT_TRANSLATE_NOOP("ThemePreviewWidget", "Delta")       },
    { 0.14, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Source")      },
    { 0.14, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Destination") },
    { 0.09, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Protocol")    },
    { 0.06, true,  QT_TRANSLATE_NOOP("ThemePreviewWidget", "Length")      },
    { 0.31, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Info")        },
};
const int kColumnCount = static_cast<int>(sizeof(kColumns) / sizeof(kColumns[0]));
const int kCellPad = 4;

// Number of sample packets in the list; mirrored by the status bar's
// "Packets:" figure.  Keep in step with the rows built in drawPacketList().
const int kPreviewPacketCount = 9;

// Renders an SVG silhouette flattened to a single colour, the same
// CompositionMode_SourceIn technique ThemedIcon uses — but taking an explicit
// colour so the preview can tint to its *previewed-theme* token (via c())
// rather than the live ThemeManager value ThemedIcon would resolve.
QPixmap tintedSvg(const QString &path, const QColor &color, const QSize &size, qreal dpr)
{
    QSvgRenderer renderer(path);
    QPixmap pm(size * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter pp(&pm);
    pp.setRenderHint(QPainter::Antialiasing, true);
    renderer.render(&pp, QRectF(QPointF(0, 0), QSizeF(size)));
    pp.setCompositionMode(QPainter::CompositionMode_SourceIn);
    pp.fillRect(QRectF(QPointF(0, 0), QSizeF(size)), color);
    pp.end();
    return pm;
}

// color_filters_clone() callback.  It hands us a freshly allocated clone we
// own, so we copy the rule name and its colours (color_t is 16-bit per channel,
// hence >> 8) into the QHash passed as user_data, then delete the clone.
// Disabled rules are skipped — the overlay should match what the live packet
// list would actually paint.
void collectRuleColor(color_filter_t *colorf, void *user_data)
{
    if (colorf && !colorf->disabled && colorf->filter_name) {
        auto *map = static_cast<QHash<QString, QPair<QColor, QColor>> *>(user_data);
        const color_t &b = colorf->bg_color;
        const color_t &f = colorf->fg_color;
        map->insert(QString::fromUtf8(colorf->filter_name),
                    qMakePair(QColor(b.red >> 8, b.green >> 8, b.blue >> 8),
                              QColor(f.red >> 8, f.green >> 8, f.blue >> 8)));
    }
    if (colorf)
        color_filter_delete(colorf);
}

// Three small grip dots for a splitter handle, centred on @p center and laid
// out vertically or horizontally per @p vertical.
void drawGripDots(QPainter &p, const QPointF &center, bool vertical, const QColor &col)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(col);
    for (int i = -1; i <= 1; ++i) {
        const QPointF d = vertical ? QPointF(0, i * 3.0) : QPointF(i * 3.0, 0);
        p.drawEllipse(center + d, 0.8, 0.8);
    }
    p.restore();
}

} // namespace

ThemePreviewWidget::ThemePreviewWidget(QWidget *parent)
    : QWidget(parent)
{
    setAutoFillBackground(true);
    setContentsMargins(0, 0, 0, 0);
}

void ThemePreviewWidget::setPreviewColors(const QHash<ThemeManager::ThemeToken, QColor> &colors)
{
    colors_ = colors;
    update();
}

void ThemePreviewWidget::setShowColoringRules(bool show)
{
    if (show_coloring_rules_ == show)
        return;
    show_coloring_rules_ = show;
    if (show)
        rebuildRuleColors();    // snapshot once, on enable
    update();
    emit showColoringRulesChanged(show);
}

void ThemePreviewWidget::rebuildRuleColors()
{
    ruleColors_.clear();
    // No-op if the color filters were never initialised (color_filter_list is
    // empty): the rows then simply keep their theme colours.
    color_filters_clone(&ruleColors_, collectRuleColor);
}

QColor ThemePreviewWidget::c(ThemeManager::ThemeToken token, const QColor &fallback) const
{
    auto it = colors_.constFind(token);
    if (it != colors_.constEnd() && it.value().isValid())
        return it.value();
    QColor live = ThemeManager::instance()->color(token);
    return live.isValid() ? live : fallback;
}

QSize ThemePreviewWidget::minimumSizeHint() const
{
    return QSize(180, 120);
}

ThemePreviewWidget::Layout ThemePreviewWidget::buildLayout(const QRect &content) const
{
    // Proportional font for chrome (toolbar/filter/header/status); the
    // monospace font for the data surfaces.  Both come from FontManager at their
    // true size — this is a font preview, so the data font must show the user's
    // actual size, not a scaled-down approximation.  Fall back to the widget
    // font if a family is unset.
    QFont labelFont = FontManager::font();
    QFont monoFont  = FontManager::monospaceFont();
    if (labelFont.family().isEmpty()) labelFont = font();
    if (monoFont.family().isEmpty())  monoFont  = font();

    const QFontMetricsF labelFm(labelFont);
    const QFontMetricsF monoFm(monoFont);

    const int toolbarH   = qMax(28, qRound(labelFm.height() + 12));
    const int filterBarH = qRound(labelFm.height() + 12);
    const int headerH    = qRound(labelFm.height() + 6);
    const int statusH    = qRound(labelFm.height() + 8);
    const int rowH       = qRound(monoFm.height()  + 3);
    const int listH      = rowH * kPreviewPacketCount;

    // Reserve the status strip at the very bottom first, so the top-down bands
    // never overrun it.  contentBottom is the last y available to them.
    const int contentBottom = content.bottom() - statusH;

    int y = content.top();
    const QRect toolbarRect(content.left(), y, content.width(), toolbarH);
    y += toolbarH;
    const QRect filterRect(content.left(), y, content.width(), filterBarH);
    y += filterBarH;
    const QRect headerRect(content.left(), y, content.width(), headerH);
    y += headerH;
    const QRect listRect(content.left(), y, content.width(), listH);
    y += listH;

    // Bottom band: details (60%) + bytes (40%).  bottomH collapses to zero on
    // a very short widget, leaving the panes as no-ops.
    const int bottomH  = qMax(0, contentBottom - y);
    const int detailsW = content.width() * 60 / 100;
    const int bytesW   = content.width() - detailsW;
    const QRect detailsRect(content.left(),            y, detailsW, bottomH);
    const QRect bytesRect  (content.left() + detailsW, y, bytesW,   bottomH);

    const QRect statusRect(content.left(), contentBottom + 1, content.width(), statusH);

    return Layout{ content, labelFont, monoFont, labelFm, monoFm, rowH,
                   toolbarRect, filterRect, headerRect, listRect,
                   detailsRect, bytesRect, statusRect };
}

ThemePreviewWidget::WindowChrome
ThemePreviewWidget::paintWindowChrome(QPainter &p, const QRect &outer, const QColor &window)
{
    // Hard-coded grey shades imitating the host window manager, chosen light
    // or dark to match the previewed appearance.  None of these are
    // ThemeManager tokens — they are OS furniture; only the light/dark variant
    // tracks the mode.  The traffic-light dots keep their fixed OS colours.
    const bool   darkChrome   = window.lightness() < 128;
    const QColor chromeBg      = darkChrome ? QColor("#2c2d30") : QColor("#e4e4e6");
    const QColor chromeBorder  = darkChrome ? QColor("#1f2023") : QColor("#c4c4c8");

    // Inset by half the 1px pen so the stroked border stays inside the widget
    // rather than being clipped at its edges.
    const QRectF frameRect = QRectF(outer).adjusted(0.5, 0.5, -0.5, -0.5);
    QPainterPath framePath;
    framePath.addRoundedRect(frameRect, kFrameRadius, kFrameRadius);

    // Clip to the rounded frame so the title bar's top corners and the packet
    // content's bottom corners both follow the rounding.
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setClipPath(framePath);

    // Title bar — bottom edge square; top corners rounded by the clip.
    const QRectF titleRect(frameRect.left(), frameRect.top(),
                           frameRect.width(), kTitleBarH);
    p.fillRect(titleRect, chromeBg);
    drawWindowControls(p, titleRect, darkChrome);

    // Reset brush so the content's drawRect() outlines below aren't filled with
    // a leftover chrome colour, and drop AA for crisp packet rows.
    p.setBrush(Qt::NoBrush);
    p.setRenderHint(QPainter::Antialiasing, false);

    // Content area: inset 1px for the border (sides/bottom) and the full
    // title-bar height on top.
    const QRect content = outer.adjusted(1, kTitleBarH, -1, -1);

    return WindowChrome{ framePath, chromeBorder, content };
}

void ThemePreviewWidget::drawWindowControls(QPainter &p, const QRectF &titleRect, bool darkChrome)
{
    // Window controls, hard-coded per platform: macOS draws traffic
    // lights on the left, Windows/Linux draw min/max/close on the right.
#if defined(Q_OS_MAC)
    Q_UNUSED(darkChrome);

    const qreal dotD   = 12.0;
    const qreal dotGap = 8.0;
    const qreal dotX   = titleRect.left() + 12.0;
    const qreal dotY   = titleRect.center().y() - dotD / 2.0;
    const QColor trafficLights[3] = {
        QColor("#ff5f57"), QColor("#febc2e"), QColor("#28c840")
    };
    p.setPen(Qt::NoPen);
    for (int i = 0; i < 3; ++i) {
        p.setBrush(trafficLights[i]);
        p.drawEllipse(QRectF(dotX + i * (dotD + dotGap), dotY, dotD, dotD));
    }
#else
    const qreal glyph      = 10.0;
    const qreal glyphPitch = 18.0;   // 10px glyph box + 8px gap
    const qreal cy         = titleRect.center().y();
    const QColor glyphColor = darkChrome ? QColor("#c8c9cd") : QColor("#4a4a4a");
    p.setBrush(Qt::NoBrush);
    p.setPen(QPen(glyphColor, 1.2));
    // Close (rightmost): an X.
    const QRectF closeBox(titleRect.right() - 12.0 - glyph,
                          cy - glyph / 2.0, glyph, glyph);
    p.drawLine(closeBox.topLeft(), closeBox.bottomRight());
    p.drawLine(closeBox.topRight(), closeBox.bottomLeft());
    // Maximize (middle): a square.
    const QRectF maxBox(closeBox.left() - glyphPitch,
                        cy - glyph / 2.0, glyph, glyph);
    p.drawRect(maxBox);
    // Minimize (leftmost): a horizontal line.
    const QRectF minBox(maxBox.left() - glyphPitch,
                        cy - glyph / 2.0, glyph, glyph);
    p.drawLine(QPointF(minBox.left(), cy), QPointF(minBox.right(), cy));
#endif
}

void ThemePreviewWidget::strokeWindowFrame(QPainter &p, const WindowChrome &chrome)
{
    // Stroke the rounded outer border on top of the content.
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setClipping(false);
    p.setPen(QPen(chrome.border, 1));
    p.setBrush(Qt::NoBrush);
    p.drawPath(chrome.framePath);
}

QRectF ThemePreviewWidget::cellRect(const QRect &content, int idx, int top, int h) const
{
    double start = 0.0;
    for (int k = 0; k < idx; ++k) start += kColumns[k].frac;
    const double x = content.left() + start * content.width();
    const double w = kColumns[idx].frac * content.width();
    return QRectF(x, top, w, h).adjusted(kCellPad, 0, -kCellPad, 0);
}

int ThemePreviewWidget::cellFlags(int idx) const
{
    return (kColumns[idx].right ? Qt::AlignRight : Qt::AlignLeft) | Qt::AlignVCenter;
}

void ThemePreviewWidget::drawToolbar(QPainter &p, const Layout &layout)
{
    const QPalette pal = QApplication::palette();
    const QColor window = c(ThemeManager::PaletteWindow, pal.color(QPalette::Window));
    const QColor sep    = c(ThemeManager::Separator,     pal.color(QPalette::Mid));

    p.fillRect(layout.toolbarRect, window);
    p.setPen(sep);
    p.drawLine(layout.toolbarRect.bottomLeft(), layout.toolbarRect.bottomRight());

    // The real, colour application toolbar icons.  The toolbar reflects the
    // *icon* theme, not the colour theme, so these are the app's own StockIcons
    // (capture/file icons are full-colour rasters; zoom falls back to a
    // WindowText-tinted template mask) rather than ThemeManager tokens.  A
    // nullptr entry is a separator.
    static const char *const icons[] = {
        "x-capture-start", "x-capture-stop", "x-capture-restart", nullptr,
        "x-capture-file-save", "x-capture-file-close", "x-capture-file-reload", nullptr,
        "zoom-in", "zoom-out"
    };
    const int count = static_cast<int>(sizeof(icons) / sizeof(icons[0]));
    const int btn = layout.toolbarRect.height() - 8;
    int x = layout.toolbarRect.left() + 6;
    const int y = layout.toolbarRect.top() + 4;
    for (int i = 0; i < count; ++i) {
        if (!icons[i]) {
            p.setPen(sep);
            const int sx = x + 4;
            p.drawLine(QPointF(sx, y + 3), QPointF(sx, y + btn - 3));
            x += 9;
            continue;
        }
        StockIcon(QString::fromLatin1(icons[i])).paint(&p, QRect(x, y, btn, btn), Qt::AlignCenter);
        x += btn + 2;
    }
}

void ThemePreviewWidget::drawFilterBar(QPainter &p, const Layout &layout)
{
    const QPalette pal = QApplication::palette();
    const QColor window     = c(ThemeManager::PaletteWindow,     pal.color(QPalette::Window));
    const QColor fieldBdr   = c(ThemeManager::FieldBorder,       pal.color(QPalette::Mid));
    const QColor sep        = c(ThemeManager::Separator,         pal.color(QPalette::Mid));
    const QColor windowText = c(ThemeManager::PaletteWindowText, pal.color(QPalette::WindowText));
    const QColor validBg    = c(ThemeManager::FilterValid,       QColor("#296700"));

    // Band background and bottom separator.
    p.fillRect(layout.filterRect, window);
    p.setPen(sep);
    p.drawLine(layout.filterRect.bottomLeft(), layout.filterRect.bottomRight());

    // The filter combo: a FieldBorder-framed field on the window background.
    // Crucially, the FilterValid tint fills ONLY the central text box — the
    // bookmark (left) and clear/apply (right) sit in the margin zones on the
    // window colour, exactly like the real DisplayFilterEdit, where those
    // buttons live in the line edit's Qt margins (outside the styled
    // background) so the green never paints behind them.
    QRect field = layout.filterRect.adjusted(8, 4, -8, -4);
    p.setRenderHint(QPainter::Antialiasing, false);
    p.setPen(fieldBdr);
    p.setBrush(Qt::NoBrush);
    p.drawRect(field.adjusted(0, 0, -1, -1));

    const int   iconH = qMin(14, field.height() - 4);
    const int   pad   = 5;
    const qreal dpr   = devicePixelRatioF();

    // Left affordance: bookmark, tinted to FilterBookmark, on the window bg.
    QRect bookmark(field.left() + pad, field.center().y() - iconH / 2, iconH, iconH);
    p.drawPixmap(bookmark,
                 tintedSvg(QStringLiteral(":/svg_icons/x-display-filter-bookmark.svg"),
                           c(ThemeManager::FilterBookmark, windowText),
                           QSize(iconH, iconH), dpr));

    // Right affordances: apply pill (24:14), clear ✕, and the combo caret —
    // each tinted to its own Filter* token so the preview surfaces them.
    const int applyW = iconH * 24 / 14;
    QRect caret(field.right() - pad - 9, field.center().y() - 4, 9, 8);
    QRect apply(caret.left() - 6 - applyW, field.center().y() - iconH / 2, applyW, iconH);
    QRect clear(apply.left() - 4 - iconH,  field.center().y() - iconH / 2, iconH, iconH);
    p.drawPixmap(clear,
                 tintedSvg(QStringLiteral(":/svg_icons/x-filter-clear.svg"),
                           c(ThemeManager::FilterClear, windowText),
                           QSize(iconH, iconH), dpr));
    p.drawPixmap(apply,
                 tintedSvg(QStringLiteral(":/svg_icons/x-filter-apply.svg"),
                           c(ThemeManager::FilterApply, windowText),
                           QSize(applyW, iconH), dpr));

    // Recent-filters dropdown caret (combo chrome), on the window background.
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(windowText);
    QPolygonF tri;
    tri << caret.topLeft() << caret.topRight()
        << QPointF(caret.center().x(), caret.bottom());
    p.drawPolygon(tri);

    // Central green text box, between the two affordance zones — the only part
    // carrying the FilterValid tint.  Text uses the contrasting colour of the
    // green (white for the default theme's saturated #296700), the same choice
    // ColorMath::contrastingText drives in the live filter edit.
    const int greenLeft  = bookmark.right() + pad;
    const int greenRight = clear.left() - pad;
    if (greenRight > greenLeft) {
        QRect green(greenLeft, field.top() + 1, greenRight - greenLeft, field.height() - 2);
        p.setRenderHint(QPainter::Antialiasing, false);
        p.fillRect(green, validBg);
        p.setFont(layout.labelFont);
        p.setPen(ColorMath::contrastingText(validBg));
        p.drawText(green.adjusted(pad, 0, -pad, 0),
                   Qt::AlignVCenter | Qt::AlignLeft, QStringLiteral("tcp.port == 443"));
    }
}

void ThemePreviewWidget::drawColumnHeader(QPainter &p, const Layout &layout)
{
    const QPalette pal = QApplication::palette();
    const QColor window     = c(ThemeManager::PaletteWindow,     pal.color(QPalette::Window));
    const QColor fieldBdr   = c(ThemeManager::FieldBorder,       pal.color(QPalette::Mid));
    const QColor sep        = c(ThemeManager::Separator,         pal.color(QPalette::Mid));
    const QColor windowText = c(ThemeManager::PaletteWindowText, pal.color(QPalette::WindowText));

    // Header background is the previewed window colour used verbatim — no
    // light/dark detection or shade derivation, so it always matches the mode
    // ThemeManager handed us.  FieldBorder frames the header view; Separator
    // draws the lighter inter-column dividers.
    p.fillRect(layout.headerRect, window);
    p.setPen(fieldBdr);
    p.setBrush(Qt::NoBrush);    // outline only; don't let a leaked brush refill the band
    p.drawRect(layout.headerRect.adjusted(0, 0, -1, -1));

    // Column titles align to the list content, which is narrowed by the
    // scrollbar so the header and rows keep identical boundaries.
    const QRect colContent = layout.content.adjusted(0, 0, -kScrollW, 0);
    p.setFont(layout.labelFont);
    double accum = 0.0;
    for (int i = 0; i < kColumnCount; ++i) {
        // Re-set the title pen every iteration: the divider below switches the
        // pen to Separator, which would otherwise bleed into the next column's
        // title.
        p.setPen(windowText);
        p.drawText(cellRect(colContent, i, layout.headerRect.top(), layout.headerRect.height()),
                   cellFlags(i), tr(kColumns[i].title));
        // Divider grip between columns.
        accum += kColumns[i].frac;
        if (i < kColumnCount - 1) {
            const double gx = colContent.left() + accum * colContent.width();
            p.setPen(sep);
            p.drawLine(QPointF(gx, layout.headerRect.top() + 3),
                       QPointF(gx, layout.headerRect.bottom() - 3));
        }
    }
}

void ThemePreviewWidget::drawPacketList(QPainter &p, const Layout &layout)
{
    const QPalette pal = QApplication::palette();
    const QColor base    = c(ThemeManager::PaletteBase,          pal.color(QPalette::Base));
    const QColor altBase = c(ThemeManager::PaletteAlternateBase, pal.color(QPalette::AlternateBase));
    const QColor text    = c(ThemeManager::PaletteText,          pal.color(QPalette::Text));
    const QColor mid     = c(ThemeManager::PaletteMid,           pal.color(QPalette::Mid));
    const QColor midLight= c(ThemeManager::PaletteMidLight,      pal.color(QPalette::Midlight));

    // Theme packet-state tokens (these ARE theme-controlled).
    const QColor selBg = c(ThemeManager::PacketsSelection,     pal.color(QPalette::Highlight));
    const QColor selFg = c(ThemeManager::PacketsSelectionText, pal.color(QPalette::HighlightedText));
    const QColor mkBg  = c(ThemeManager::PacketsMarked,        QColor("#ec2a93"));
    const QColor mkFg  = c(ThemeManager::PacketsMarkedText,    QColor("#ffffff"));
    const QColor igFg  = c(ThemeManager::PacketsIgnoredText,   mid);

    // Each row is tagged with the NAME of the default coloring rule it would
    // match in the live packet list (TLS-over-TCP falls through to "TCP"; DNS
    // is UDP).  The names are only consulted when the coloring-rules overlay is
    // on, in which case the colours come from the user's current filter set
    // (ruleColors_), not from this widget — coloring rules are not theme tokens.
    enum State { StateNone, StateSel, StateMark, StateIgn };
    struct PreviewRow { const char *cells[8]; const char *rule; int state; };
    static const PreviewRow rows[] = {
        { { "1","0.000000","0.000000","10.0.0.5","1.1.1.1","TCP",    "74",  "52123 → 443 [SYN] Seq=0"      }, "TCP SYN/FIN", StateNone },
        { { "2","0.000124","0.000124","1.1.1.1","10.0.0.5","TCP",    "74",  "443 → 52123 [SYN, ACK]"       }, "TCP SYN/FIN", StateSel  },
        { { "3","0.000256","0.000132","10.0.0.5","1.1.1.1","TLSv1.3","583", "Client Hello"                 }, "TCP",         StateMark },
        { { "4","0.000301","0.000045","10.0.0.5","1.1.1.1","TCP",    "66",  "52123 → 443 [ACK] Seq=1"      }, "TCP",         StateNone },
        { { "5","0.014870","0.014569","10.0.0.5","1.1.1.1","HTTP",   "441", "GET /index.html HTTP/1.1"     }, "HTTP",        StateNone },
        { { "6","0.029233","0.014363","1.1.1.1","10.0.0.5","TCP",    "60",  "[TCP Retransmission] 443 → …" }, "Bad TCP",     StateNone },
        { { "7","0.030001","0.000768","10.0.0.5","1.1.1.1","TCP",    "66",  "[TCP Dup ACK] 52123 → 443"    }, "Bad TCP",     StateIgn  },
        { { "8","0.044120","0.014119","8.8.8.8", "10.0.0.5","DNS",   "90",  "Standard query response"      }, "UDP",         StateNone },
        { { "9","0.061002","0.016882","1.1.1.1","10.0.0.5","TLSv1.3","1514","Application Data"             }, "TCP",         StateNone },
    };
    const int rowCount = static_cast<int>(sizeof(rows) / sizeof(rows[0]));

    p.fillRect(layout.listRect, base);
    const QRect colContent = layout.content.adjusted(0, 0, -kScrollW, 0);
    const int rowH = layout.rowH;

    for (int i = 0; i < rowCount; ++i) {
        const PreviewRow &row = rows[i];
        const QRect rowRect(layout.content.left(), layout.listRect.top() + i * rowH,
                            layout.content.width(), rowH);

        QColor bg, fg = text;
        bool strike = false;
        // Base layer: alternating-row shading (theme token).
        if (i % 2 == 1) bg = altBase;
        // Optional coloring-rule layer: only when the overlay is on, using the
        // colours from the user's current filter set (not theme tokens).  Rows
        // whose rule is disabled or absent keep their theme colour.
        if (show_coloring_rules_ && row.rule && row.rule[0]) {
            auto it = ruleColors_.constFind(QString::fromUtf8(row.rule));
            if (it != ruleColors_.constEnd()) {
                bg = it.value().first;
                fg = it.value().second;
            }
        }
        // Theme packet-state layer (tokens) overrides the rule colour.
        switch (row.state) {
        case StateSel:  bg = selBg; fg = selFg; break;
        case StateMark: bg = mkBg;  fg = mkFg;  break;
        case StateIgn:  bg = base;  fg = igFg;  strike = true; break;
        default: break;
        }

        if (bg.isValid())
            p.fillRect(rowRect, bg);

        QFont rowFont = layout.monoFont;
        rowFont.setStrikeOut(strike);
        p.setFont(rowFont);
        p.setPen(fg);
        for (int ci = 0; ci < kColumnCount; ++ci) {
            p.drawText(cellRect(colContent, ci, rowRect.top(), rowRect.height()),
                       cellFlags(ci), QString::fromUtf8(row.cells[ci]));
        }
    }

    // Native vertical scrollbar on the right edge of the list.
    const QRect track(layout.listRect.right() - kScrollW + 1, layout.listRect.top(),
                      kScrollW, layout.listRect.height());
    p.fillRect(track, midLight);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(mid);
    const QRectF thumb(track.left() + 2, track.top() + 3,
                       track.width() - 4, track.height() * 0.45);
    p.drawRoundedRect(thumb, 3, 3);
    p.setRenderHint(QPainter::Antialiasing, false);
}

void ThemePreviewWidget::drawDetailsPane(QPainter &p, const Layout &layout)
{
    if (layout.detailsRect.height() <= 0)
        return;   // collapses on a very short widget

    const QPalette pal = QApplication::palette();
    const QColor base     = c(ThemeManager::PaletteBase, pal.color(QPalette::Base));
    const QColor text     = c(ThemeManager::PaletteText, pal.color(QPalette::Text));
    const QColor fieldBdr = c(ThemeManager::FieldBorder, pal.color(QPalette::Mid));
    const QColor sep      = c(ThemeManager::Separator,   pal.color(QPalette::Mid));

    // Dense protocol tree.  Collapsed nodes get a right-pointing triangle, the
    // expanded node a down-pointing one; leaf fields indent a level with none.
    p.fillRect(layout.detailsRect, base);
    p.setPen(fieldBdr);
    p.setBrush(Qt::NoBrush);    // outline only; don't let a leaked brush refill the pane
    p.drawRect(layout.detailsRect.adjusted(0, 0, -1, -1));
    p.setFont(layout.monoFont);
    p.setPen(text);

    // The selected packet (row 2) is the SYN,ACK, so the tree is Frame 2's.  The
    // first line is its expert "Chat" item, tinted with the ExpertChat token and
    // kept at the top so it stays visible even when the pane is short — the
    // protocol tree is the one place the preview can surface the Expert* family.
    // bg == NoRole means an ordinary (untinted) row.
    enum { TriNone = 0, TriCollapsed = 1, TriExpanded = 2 };
    static const struct { int depth; int tri; ThemeManager::ThemeToken bg; const char *text; } treeLines[] = {
        { 0, TriNone,      ThemeManager::ExpertChat, "[Connection establish acknowledge (SYN+ACK)]" },
        { 0, TriCollapsed, ThemeManager::NoRole,     "Frame 2: 74 bytes on wire (592 bits)"         },
        { 0, TriCollapsed, ThemeManager::NoRole,     "Ethernet II, Src: aa:bb:cc:dd:ee:ff"          },
        { 0, TriCollapsed, ThemeManager::NoRole,     "Internet Protocol Version 4, Src: 1.1.1.1"    },
        { 0, TriExpanded,  ThemeManager::NoRole,     "Transmission Control Protocol, Src Port: 443" },
        { 1, TriNone,      ThemeManager::NoRole,     "Source Port: 443"                             },
        { 1, TriNone,      ThemeManager::NoRole,     "Destination Port: 52123"                      },
        { 1, TriExpanded,  ThemeManager::NoRole,     "Flags: 0x012 (SYN, ACK)"                      },
        { 2, TriNone,      ThemeManager::NoRole,     "Acknowledgment: Set"                          },
        { 2, TriNone,      ThemeManager::NoRole,     "Syn: Set"                                     },
    };
    const int    rowH       = layout.rowH;
    const double indentStep = layout.monoFm.height();
    const double triSize    = layout.monoFm.height() * 0.28;
    int dy = layout.detailsRect.top() + 2;
    for (const auto &tl : treeLines) {
        if (dy + rowH > layout.detailsRect.bottom()) break;
        // Expert-info rows carry a severity-tinted background (Expert* token).
        if (tl.bg != ThemeManager::NoRole) {
            const QColor ebg = c(tl.bg);
            if (ebg.isValid())
                p.fillRect(QRectF(layout.detailsRect.left() + 1, dy,
                                  layout.detailsRect.width() - 2, rowH), ebg);
        }
        const double indent = layout.detailsRect.left() + 6 + tl.depth * indentStep;
        const double cy     = dy + rowH / 2.0;
        if (tl.tri != TriNone) {
            QPolygonF tri;
            if (tl.tri == TriCollapsed)
                tri << QPointF(indent, cy - triSize)
                    << QPointF(indent, cy + triSize)
                    << QPointF(indent + triSize * 1.4, cy);
            else
                tri << QPointF(indent - triSize, cy - triSize * 0.6)
                    << QPointF(indent + triSize, cy - triSize * 0.6)
                    << QPointF(indent, cy + triSize * 0.8);
            p.save();
            p.setRenderHint(QPainter::Antialiasing, true);
            p.setPen(Qt::NoPen);
            p.setBrush(text);
            p.drawPolygon(tri);
            p.restore();
        }
        const double textX = indent + indentStep * 0.6;
        p.drawText(QRectF(textX, dy, layout.detailsRect.right() - textX - 4, rowH),
                   Qt::AlignVCenter | Qt::AlignLeft, QString::fromUtf8(tl.text));
        dy += rowH;
    }

    // Splitter grip between the list and the lower panes.
    drawGripDots(p, QPointF(layout.detailsRect.center().x(), layout.detailsRect.top()),
                 false, sep);
}

void ThemePreviewWidget::drawBytesPane(QPainter &p, const Layout &layout)
{
    if (layout.bytesRect.height() <= 0)
        return;   // collapses on a very short widget

    const QPalette pal = QApplication::palette();
    const QColor base     = c(ThemeManager::PaletteBase, pal.color(QPalette::Base));
    const QColor text     = c(ThemeManager::PaletteText, pal.color(QPalette::Text));
    const QColor fieldBdr = c(ThemeManager::FieldBorder, pal.color(QPalette::Mid));
    const QColor sep      = c(ThemeManager::Separator,   pal.color(QPalette::Mid));
    // The real byte view is monochrome; its only colour is the highlight on the
    // bytes of the field selected in the tree.  We mirror that with the same
    // PacketsSelection tokens the packet list uses.
    const QColor selBg = c(ThemeManager::PacketsSelection,     pal.color(QPalette::Highlight));
    const QColor selFg = c(ThemeManager::PacketsSelectionText, pal.color(QPalette::HighlightedText));

    p.fillRect(layout.bytesRect, base);
    p.setPen(fieldBdr);
    p.setBrush(Qt::NoBrush);    // outline only; don't let a leaked brush refill the pane
    p.drawRect(layout.bytesRect.adjusted(0, 0, -1, -1));

    // Vertical splitter grip between the details and bytes panes.
    drawGripDots(p, QPointF(layout.bytesRect.left(), layout.bytesRect.center().y()),
                 true, sep);

    static const struct { const char *off; const char *hex; const char *asc; } byteLines[] = {
        { "0000", "00 11 22 33 44 55 aa bb", "..\"3DU.." },
        { "0008", "cc dd ee ff 08 00 45 00", "......E."  },
        { "0010", "00 40 12 34 40 00 40 06", ".@.4@.@."  },
        { "0018", "ff ff c0 a8 01 02 0a 00", "........"  },
        { "0020", "00 68 cb 7b 01 bb 9e 3f", ".h.{...?"  },
        { "0028", "00 00 00 00 a0 02 fa f0", "........"  },
    };
    // One field's bytes are "selected" — bytes 2-3 on the third row — mirroring a
    // field clicked in the tree above.  In the hex column each byte spans three
    // characters ("XX "), in the ASCII column one; selStart/selCount index bytes.
    const int selRow = 2, selStart = 2, selCount = 2;

    p.setFont(layout.monoFont);
    const int rowH = layout.rowH;
    const double offW = layout.monoFm.horizontalAdvance(QStringLiteral("0000")) + 6;
    const double hexW = layout.monoFm.horizontalAdvance(QStringLiteral("00 11 22 33 44 55 aa bb")) + 12;
    const double x0 = layout.bytesRect.left() + 8;
    const double ascX = x0 + offW + hexW + 8;
    int by = layout.bytesRect.top() + 2;

    // Draws @p full at @p segX, monochrome, then re-draws characters
    // [chStart, chStart+chCount) over a selection-tinted background when @p sel.
    auto drawSeg = [&](const QString &full, double segX, double segW,
                       int chStart, int chCount, bool sel) {
        if (sel) {
            const double sx = segX + layout.monoFm.horizontalAdvance(full.left(chStart));
            const double sw = layout.monoFm.horizontalAdvance(full.mid(chStart, chCount));
            p.fillRect(QRectF(sx, by, sw, rowH), selBg);
        }
        p.setPen(text);
        p.drawText(QRectF(segX, by, segW, rowH), Qt::AlignVCenter | Qt::AlignLeft, full);
        if (sel) {
            const double sx = segX + layout.monoFm.horizontalAdvance(full.left(chStart));
            p.setPen(selFg);
            p.drawText(QRectF(sx, by, segW, rowH), Qt::AlignVCenter | Qt::AlignLeft,
                       full.mid(chStart, chCount));
        }
    };

    int r = 0;
    for (const auto &bl : byteLines) {
        if (by + rowH > layout.bytesRect.bottom()) break;
        const bool sel = (r == selRow);
        p.setPen(text);
        p.drawText(QRectF(x0, by, offW, rowH), Qt::AlignVCenter | Qt::AlignLeft,
                   QString::fromUtf8(bl.off));
        drawSeg(QString::fromUtf8(bl.hex), x0 + offW, hexW,
                selStart * 3, selCount * 3 - 1, sel);
        drawSeg(QString::fromUtf8(bl.asc), ascX, layout.bytesRect.right() - ascX - 4,
                selStart, selCount, sel);
        by += rowH;
        ++r;
    }
}

void ThemePreviewWidget::drawStatusBar(QPainter &p, const Layout &layout)
{
    const QPalette pal = QApplication::palette();
    const QColor window     = c(ThemeManager::PaletteWindow,     pal.color(QPalette::Window));
    const QColor mid        = c(ThemeManager::PaletteMid,        pal.color(QPalette::Mid));
    const QColor sep        = c(ThemeManager::Separator,         pal.color(QPalette::Mid));
    const QColor windowText = c(ThemeManager::PaletteWindowText, pal.color(QPalette::WindowText));
    // The expert-severity LED.  The sample packets include Bad-TCP items
    // (retransmission / dup ack), so the worst displayed severity is a warning —
    // the dot uses ExpertWarn, the same token the live status bar would show.
    const QColor expertWarn = c(ThemeManager::ExpertWarn, QColor("#e8b500"));

    const QRect &statusRect = layout.statusRect;
    p.fillRect(statusRect, window);
    p.setPen(sep);
    p.drawLine(statusRect.topLeft(), statusRect.topRight());

    const double expertDotD = layout.labelFm.height() * 0.5;
    const QRectF expertDotRect(statusRect.left() + 8,
                               statusRect.center().y() - expertDotD / 2.0,
                               expertDotD, expertDotD);
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(expertWarn);
    p.drawEllipse(expertDotRect);
    p.restore();

    p.setFont(layout.labelFont);
    p.setPen(windowText);
    p.drawText(QRectF(expertDotRect.right() + 6, statusRect.top(),
                      statusRect.width(), statusRect.height()),
               Qt::AlignVCenter | Qt::AlignLeft,
               tr("Ready"));

    // Reserve the bottom-right corner for the resize grip.
    const int gripW = 16;
    const QString stats = tr("Profile: Default") + QStringLiteral("    ")
        + tr("Packets: %1").arg(kPreviewPacketCount) + QStringLiteral(" · ")
        + tr("Displayed: %1 (100.0%)").arg(kPreviewPacketCount);
    p.drawText(statusRect.adjusted(8, 0, -8 - gripW, 0),
               Qt::AlignVCenter | Qt::AlignRight, stats);

    // Resize grip: a small triangle of dots in the corner.
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(mid);
    const double gx = statusRect.right() - 4;
    const double gy = statusRect.bottom() - 4;
    for (int row = 0; row < 3; ++row)
        for (int col = 0; col <= row; ++col)
            p.drawEllipse(QPointF(gx - col * 4.0, gy - row * 4.0), 0.9, 0.9);
}

void ThemePreviewWidget::paintEvent(QPaintEvent *)
{
    QPainter p(this);

    const QRect outer = contentsRect();
    if (outer.isEmpty())
        return;

    // The window chrome picks its light/dark shade from the previewed window
    // colour, so resolve that one token up front and hand it to the chrome.
    const QColor window = c(ThemeManager::PaletteWindow,
                            QApplication::palette().color(QPalette::Window));

    // Faux OS window chrome: rounded frame, title bar and window controls.
    // Installs the rounded clip; returns the content rect plus what the final
    // border stroke needs.
    const WindowChrome chrome = paintWindowChrome(p, outer, window);

    // Geometry + fonts for every content band, derived once.
    const Layout layout = buildLayout(chrome.content);

    // Content bands, painted top-down within the clipped frame.
    drawToolbar(p, layout);
    drawFilterBar(p, layout);
    drawColumnHeader(p, layout);
    drawPacketList(p, layout);
    drawDetailsPane(p, layout);
    drawBytesPane(p, layout);
    drawStatusBar(p, layout);

    // Outer rounded border, stroked on top of the finished content.
    strokeWindowFrame(p, chrome);
}

void ThemePreviewWidget::contextMenuEvent(QContextMenuEvent *event)
{
    // Heap-allocated with WA_DeleteOnClose so popup() can return immediately;
    // the menu cleans itself up when dismissed.
    QMenu *menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);

    QAction *rulesAction = menu->addAction(tr("Show Coloring Rules"));
    rulesAction->setCheckable(true);
    rulesAction->setChecked(show_coloring_rules_);
    connect(rulesAction, &QAction::toggled, this, &ThemePreviewWidget::setShowColoringRules);

    menu->addSeparator();

    QAction *saveAction = menu->addAction(tr("Save Image As…"));
    connect(saveAction, &QAction::triggered, this, &ThemePreviewWidget::saveAsImage);
    menu->popup(event->globalPos());
}

void ThemePreviewWidget::saveAsImage()
{
    QString fileName = QFileDialog::getSaveFileName(
        this, tr("Save Theme Preview"),
        QStringLiteral("theme-preview.png"),
        tr("PNG Image (*.png)"));
    if (fileName.isEmpty())
        return;
    // The dialog may return a name without the extension (e.g. the user typed
    // a bare name or "All files" was selected); ensure a .png suffix so the
    // format written below matches the file name.
    if (!fileName.endsWith(QStringLiteral(".png"), Qt::CaseInsensitive))
        fileName += QStringLiteral(".png");

    // grab() repaints into an off-screen pixmap carrying the widget's device
    // pixel ratio, so the saved image is crisp on HiDPI displays.
    const QPixmap pixmap = grab();
    if (!pixmap.save(fileName, "PNG")) {
        QMessageBox::warning(this, tr("Save Theme Preview"),
                             tr("Could not write the image to \"%1\".").arg(fileName));
    }
}
