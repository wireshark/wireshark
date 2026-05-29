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

#include <QApplication>
#include <QFontMetricsF>
#include <QLinearGradient>
#include <QList>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPen>
#include <QPointF>
#include <QPolygonF>
#include <QRectF>

ThemePreviewWidget::ThemePreviewWidget(QWidget *parent)
    : QWidget(parent)
{
    setAutoFillBackground(true);
}

void ThemePreviewWidget::setPreviewColors(const QHash<ThemeManager::ThemeToken, QColor> &colors)
{
    colors_ = colors;
    update();
}

QColor ThemePreviewWidget::c(ThemeManager::ThemeToken token, const QColor &fallback) const
{
    auto it = colors_.constFind(token);
    if (it != colors_.constEnd() && it.value().isValid())
        return it.value();
    QColor live = ThemeManager::instance()->color(token);
    return live.isValid() ? live : fallback;
}

QSize ThemePreviewWidget::sizeHint() const
{
    return QSize(480, 320);
}

QSize ThemePreviewWidget::minimumSizeHint() const
{
    return QSize(360, 240);
}

void ThemePreviewWidget::paintEvent(QPaintEvent *)
{
    QPainter p(this);

    const QRect outer = contentsRect();
    if (outer.isEmpty())
        return;

    // Resolve the previewed palette up front: the window chrome picks its
    // light/dark shade from it, and the packet content below reuses it.
    const QPalette pal = QApplication::palette();
    const QColor base       = c(ThemeManager::PaletteBase,       pal.color(QPalette::Base));
    const QColor window     = c(ThemeManager::PaletteWindow,     pal.color(QPalette::Window));
    const QColor text       = c(ThemeManager::PaletteText,       pal.color(QPalette::Text));
    const QColor windowText = c(ThemeManager::PaletteWindowText, pal.color(QPalette::WindowText));
    const QColor mid        = c(ThemeManager::PaletteMid,        pal.color(QPalette::Mid));

    // ---- Faux OS window chrome -------------------------------------
    // Hard-coded grey shades imitating the host window manager, chosen
    // light or dark to match the previewed appearance.  The traffic-light
    // dots keep their fixed OS colours.  None of this is a ThemeManager
    // token — it is OS furniture, only its light/dark variant tracks mode.
    const bool   darkChrome  = window.lightness() < 128;
    const qreal  frameRadius = 8.0;
    const int    titleBarH   = 24;
    const QColor chromeBg     = darkChrome ? QColor("#2c2d30") : QColor("#e4e4e6");
    const QColor chromeBorder = darkChrome ? QColor("#1f2023") : QColor("#c4c4c8");

    // Inset by half the 1px pen so the stroked border stays inside the
    // widget rather than being clipped at its edges.
    const QRectF frameRect = QRectF(outer).adjusted(0.5, 0.5, -0.5, -0.5);
    QPainterPath framePath;
    framePath.addRoundedRect(frameRect, frameRadius, frameRadius);

    // Clip to the rounded frame so the title bar's top corners and the
    // packet content's bottom corners both follow the rounding.
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setClipPath(framePath);

    // Title bar — bottom edge square; top corners rounded by the clip.
    const QRectF titleRect(frameRect.left(), frameRect.top(),
                           frameRect.width(), titleBarH);
    p.fillRect(titleRect, chromeBg);

    // Window controls, hard-coded per platform: macOS draws traffic
    // lights on the left, Windows/Linux draw min/max/close on the right.
#if defined(Q_OS_MAC)
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

    // Reset brush so the content's drawRect() outlines below aren't filled
    // with a leftover chrome colour, and drop AA for crisp packet rows.
    p.setBrush(Qt::NoBrush);
    p.setRenderHint(QPainter::Antialiasing, false);

    // Content area: inset 1px for the border (sides/bottom) and the full
    // title-bar height on top.  The packet mockup paints into this rect.
    const QRect r = outer.adjusted(1, titleBarH, -1, -1);

    // Status-bar "expert info" dot.  AccentSuccess so it tracks the
    // previewed theme (a "Ready / no expert info" green); falls back to a
    // fixed green when the theme omits the token.
    const QColor accentOk = c(ThemeManager::AccentSuccess, QColor("#36c46a"));

    // Two fonts, per the task split: monospace draws the packet list and the
    // byte pane (the data surfaces), the regular font draws every label
    // (filter, column header, protocol tree, status bar, token tags).  Both
    // come from ThemeManager so a font-preference change live-updates the
    // mockup.  Fall back to the painter's font if a family is unset.
    QFont labelFont = ThemeManager::instance()->regularFont();
    QFont monoFont  = ThemeManager::instance()->monospaceFont();
    if (labelFont.family().isEmpty()) labelFont = p.font();
    if (monoFont.family().isEmpty())  monoFont  = p.font();

    const QFontMetricsF labelFm(labelFont);
    const QFontMetricsF monoFm(monoFont);

    const int filterBarH = qRound(labelFm.height() + 8);
    const int headerH    = qRound(labelFm.height() + 6);
    const int statusH    = qRound(labelFm.height() + 8);
    const int rowH       = qRound(monoFm.height()  + 4);
    const int listRows   = 5;
    const int listH      = rowH * listRows;

    // Reserve the status strip at the very bottom up front, so the
    // filter/header/list/details+bytes bands laid out top-down never overrun
    // it.  contentBottom is the last y available to those bands (inclusive).
    const int contentBottom = r.bottom() - statusH;

    // Real default packet-list columns.  No. and Len are right-aligned to
    // match the live list.  Column widths are fractions of the content width
    // so the (regular-font) header and every (monospace) packet row share
    // identical column boundaries regardless of which font draws into them.
    static const struct { double frac; bool right; const char *title; } columns[] = {
        { 0.07, true,  QT_TRANSLATE_NOOP("ThemePreviewWidget", "No.")         },
        { 0.13, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Time")        },
        { 0.16, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Source")      },
        { 0.16, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Destination") },
        { 0.10, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Proto")       },
        { 0.07, true,  QT_TRANSLATE_NOOP("ThemePreviewWidget", "Len")         },
        { 0.31, false, QT_TRANSLATE_NOOP("ThemePreviewWidget", "Info")        },
    };
    const int columnCount = static_cast<int>(sizeof(columns) / sizeof(columns[0]));
    const int cellPad = 4;
    auto cellRect = [&](int idx, int top, int h) -> QRectF {
        double start = 0.0;
        for (int k = 0; k < idx; ++k) start += columns[k].frac;
        const double x = r.left() + start * r.width();
        const double w = columns[idx].frac * r.width();
        return QRectF(x, top, w, h).adjusted(cellPad, 0, -cellPad, 0);
    };
    auto cellFlags = [&](int idx) -> int {
        return (columns[idx].right ? Qt::AlignRight : Qt::AlignLeft) | Qt::AlignVCenter;
    };

    int y = r.top();

    // 1. Filter bar (FilterValid tint) — label font.
    QRect filterRect(r.left(), y, r.width(), filterBarH);
    p.fillRect(filterRect, c(ThemeManager::FilterValid, QColor("#ddffdd")));
    p.setPen(mid);
    p.drawRect(filterRect.adjusted(0, 0, -1, -1));
    p.setFont(labelFont);
    p.setPen(windowText);
    p.drawText(filterRect.adjusted(8, 0, -8, 0),
               Qt::AlignVCenter | Qt::AlignLeft,
               QStringLiteral("tcp.port == 443"));
    y += filterBarH;

    // 2. Column header (HeaderGradient) — label font, real column titles.
    QRect headerRect(r.left(), y, r.width(), headerH);
    QLinearGradient grad(headerRect.topLeft(), headerRect.bottomLeft());
    grad.setColorAt(0.0, c(ThemeManager::HeaderGradientStart, window));
    grad.setColorAt(1.0, c(ThemeManager::HeaderGradientEnd,   window.darker(110)));
    p.fillRect(headerRect, grad);
    p.setPen(mid);
    p.drawRect(headerRect.adjusted(0, 0, -1, -1));
    p.setFont(labelFont);
    p.setPen(c(ThemeManager::TextOnDark, windowText));
    for (int i = 0; i < columnCount; ++i) {
        p.drawText(cellRect(i, headerRect.top(), headerRect.height()),
                   cellFlags(i), tr(columns[i].title));
    }
    y += headerH;

    // 3. Packet list — five sample rows, monospace like the live list.
    // The tinted rows carry their matching *Text foreground token plus a
    // right-aligned tag naming the responsible theme token, so each reads as
    // a theme swatch and cannot be mistaken for a user coloring rule (which
    // the theme does not control).  The ignored row is dimmed + struck
    // through with no background fill, matching the live list's treatment.
    struct PreviewRow {
        const char *cells[7];
        QColor bg;
        QColor fg;
        bool strike;
        QString tag;
    };
    const QColor selBg = c(ThemeManager::PacketsSelection,     pal.color(QPalette::Highlight));
    const QColor selFg = c(ThemeManager::PacketsSelectionText, pal.color(QPalette::HighlightedText));
    const QColor mkBg  = c(ThemeManager::PacketsMarked,        QColor("#ec2a93"));
    const QColor mkFg  = c(ThemeManager::PacketsMarkedText,    QColor("#ffffff"));
    const QColor igFg  = c(ThemeManager::PacketsIgnoredText,   mid);
    const QList<PreviewRow> rows = {
        { { "1", "0.000000", "10.0.0.5", "1.1.1.1",  "TCP",     "74",  "52123 → 443 [SYN] Seq=0" }, QColor(), text,  false, QString() },
        { { "2", "0.000124", "1.1.1.1",  "10.0.0.5", "TCP",     "74",  "443 → 52123 [SYN, ACK]"  }, selBg,    selFg, false, tr("Selection") },
        { { "3", "0.000256", "10.0.0.5", "1.1.1.1",  "TLSv1.3", "583", "Client Hello"                 }, mkBg,     mkFg,  false, tr("Marked (theme)") },
        { { "4", "0.000301", "10.0.0.5", "1.1.1.1",  "TCP",     "66",  "52123 → 443 [ACK]"       }, QColor(), igFg,  true,  tr("Ignored (theme)") },
        { { "5", "0.044120", "8.8.8.8",  "10.0.0.5", "DNS",     "90",  "Standard query response"      }, QColor(), text,  false, QString() },
    };

    QRect listRect(r.left(), y, r.width(), listH);
    p.fillRect(listRect, base);

    for (int i = 0; i < rows.size(); ++i) {
        const PreviewRow &row = rows.at(i);
        QRect rowRect(r.left(), y + i * rowH, r.width(), rowH);
        if (row.bg.isValid())
            p.fillRect(rowRect, row.bg);

        QFont rowFont = monoFont;
        rowFont.setStrikeOut(row.strike);
        p.setFont(rowFont);
        p.setPen(row.fg.isValid() ? row.fg : text);

        // Right-aligned token tag (label font, never struck through).  Drawn
        // first so the Info cell can be clipped short of it to avoid overlap.
        double tagLeft = rowRect.right();
        if (!row.tag.isEmpty()) {
            const double tagW = labelFm.horizontalAdvance(row.tag) + 12;
            const QRectF tagRect(rowRect.right() - tagW, rowRect.top(), tagW, rowRect.height());
            p.save();
            p.setFont(labelFont);
            p.drawText(tagRect.adjusted(0, 0, -6, 0),
                       Qt::AlignVCenter | Qt::AlignRight, row.tag);
            p.restore();
            tagLeft = tagRect.left();
            p.setFont(rowFont);
        }

        for (int ci = 0; ci < columnCount; ++ci) {
            QRectF cr = cellRect(ci, rowRect.top(), rowRect.height());
            if (ci == columnCount - 1 && !row.tag.isEmpty())
                cr.setRight(qMin(cr.right(), tagLeft - cellPad));
            p.drawText(cr, cellFlags(ci), QString::fromUtf8(row.cells[ci]));
        }
    }
    y += listH;

    // 4. Bottom band: details (60%) + bytes (40%).  bottomH collapses to zero
    // on a very short widget, leaving the fills/loops below as no-ops.
    const int bottomH = qMax(0, contentBottom - y);

    const int detailsW = r.width() * 60 / 100;
    const int bytesW   = r.width() - detailsW;
    QRect detailsRect(r.left(),            y, detailsW, bottomH);
    QRect bytesRect  (r.left() + detailsW, y, bytesW,   bottomH);

    // Details pane — small protocol tree.  Collapsed nodes get a right-
    // pointing triangle, the expanded node a down-pointing one, and the
    // expanded node's two leaf fields are indented a level with no triangle.
    p.fillRect(detailsRect, base);
    p.setPen(mid);
    p.drawRect(detailsRect.adjusted(0, 0, -1, -1));
    p.setFont(labelFont);
    p.setPen(text);

    enum { TriNone = 0, TriCollapsed = 1, TriExpanded = 2 };
    static const struct { int depth; int tri; const char *text; } treeLines[] = {
        { 0, TriCollapsed, "Frame 2: 74 bytes on wire (592 bits)"        },
        { 0, TriCollapsed, "Ethernet II, Src: aa:bb:cc:dd:ee:ff"          },
        { 0, TriCollapsed, "Internet Protocol Version 4, Src: 1.1.1.1"    },
        { 0, TriExpanded,  "Transmission Control Protocol, Src Port: 443" },
        { 1, TriNone,      "Source Port: 443"                             },
        { 1, TriNone,      "Destination Port: 52123"                      },
    };
    const double indentStep = labelFm.height();
    const double triSize     = labelFm.height() * 0.30;
    int dy = detailsRect.top() + 2;
    for (const auto &tl : treeLines) {
        if (dy + rowH > detailsRect.bottom()) break;
        const double indent = detailsRect.left() + 6 + tl.depth * indentStep;
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
        p.drawText(QRectF(textX, dy, detailsRect.right() - textX - 4, rowH),
                   Qt::AlignVCenter | Qt::AlignLeft, QString::fromUtf8(tl.text));
        dy += rowH;
    }

    // Bytes pane — offset + hex + ASCII gutter, monospace.
    p.fillRect(bytesRect, base);
    p.setPen(mid);
    p.drawRect(bytesRect.adjusted(0, 0, -1, -1));
    p.setFont(monoFont);
    p.setPen(c(ThemeManager::SyntaxNumber, text));
    static const char *byteLines[] = {
        "0000  00 11 22 33 44 55 aa bb  ..\"3DU..",
        "0008  cc dd ee ff 08 00 45 00  ......E.",
        "0010  00 40 12 34 40 00 40 06  .@.4@.@.",
        "0018  ff ff c0 a8 01 02 0a 00  ........",
    };
    int by = bytesRect.top() + 2;
    for (const char *bl : byteLines) {
        if (by + rowH > bytesRect.bottom()) break;
        p.drawText(QRectF(bytesRect.left() + 8, by, bytesRect.width() - 12, rowH),
                   Qt::AlignVCenter | Qt::AlignLeft, QString::fromUtf8(bl));
        by += rowH;
    }

    // 5. Status bar — expert-severity dot + "Ready" on the left; profile and
    // packet counts on the right.  Painted on the window (chrome) colour so
    // it reads as a status strip distinct from the packet base.
    QRect statusRect(r.left(), contentBottom + 1, r.width(), statusH);
    p.fillRect(statusRect, window);
    p.setPen(mid);
    p.drawLine(statusRect.topLeft(), statusRect.topRight());

    const double expertDotD = labelFm.height() * 0.5;
    const QRectF expertDotRect(statusRect.left() + 8,
                               statusRect.center().y() - expertDotD / 2.0,
                               expertDotD, expertDotD);
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    p.setBrush(accentOk);
    p.drawEllipse(expertDotRect);
    p.restore();

    p.setFont(labelFont);
    p.setPen(windowText);
    p.drawText(QRectF(expertDotRect.right() + 6, statusRect.top(),
                      statusRect.width(), statusRect.height()),
               Qt::AlignVCenter | Qt::AlignLeft, tr("Ready"));

    const int pkts = static_cast<int>(rows.size());
    const QString stats = tr("Profile: Default") + QStringLiteral("    ")
        + tr("Packets: %1").arg(pkts) + QStringLiteral(" · ")
        + tr("Displayed: %1 (100.0%)").arg(pkts);
    p.drawText(statusRect.adjusted(8, 0, -8, 0),
               Qt::AlignVCenter | Qt::AlignRight, stats);

    // 6. Stroke the rounded outer border on top of the content.
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setClipping(false);
    p.setPen(QPen(chromeBorder, 1));
    p.setBrush(Qt::NoBrush);
    p.drawPath(framePath);
}
