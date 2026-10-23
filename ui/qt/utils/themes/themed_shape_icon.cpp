/* themed_shape_icon.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/utils/themes/themed_shape_icon.h>
#include <ui/qt/utils/themes/color_math.h>
#include <ui/qt/utils/themes/icon_engine_utils.h>
#include <ui/qt/utils/themes/token_palette.h>

#include <QApplication>
#include <QFont>
#include <QIconEngine>
#include <QPaintDevice>
#include <QPainter>
#include <QPainterPath>
#include <QPainterPathStroker>
#include <QPen>
#include <QPixmap>
#include <QRectF>

#include <cmath>

namespace {

// Logical size used when a caller asks for a pixmap of null size.
constexpr QSize kDefaultSize(16, 16);
// Outline width as a share of the icon side: one pixel at the default size.
constexpr qreal kOutlineFraction = 1.0 / kDefaultSize.width();
// Glyph pixel size as a share of the icon side: one or two digits fit inside
// the outline.
constexpr qreal kGlyphFraction = 0.6;
// Width of each bar of the cross as a share of the shape's side.
constexpr qreal kCrossBarFraction = 1.0 / 5.0;
// Marks an engine whose fill is a fixed colour, not a palette entry.
constexpr int kNoPaletteIndex = -1;

QColor grey(const QColor &c)
{
    const int g = qGray(c.rgb());
    return QColor(g, g, g, c.alpha());
}

/**
 * QIconEngine that draws a ThemedShapeIcon with QPainter primitives at the
 * requested size.  Holds plain values only, so clone() is a member copy.
 */
class ThemedShapeIconEngine : public QIconEngine
{
public:
    ThemedShapeIconEngine(ThemedShapeIcon::Shape shape, const QColor &fill,
                          int fill_index, const QColor &outline,
                          ThemeManager::ThemeToken outline_token,
                          const QString &glyph) :
        shape_(shape), fill_(fill), fill_index_(fill_index), outline_(outline),
        outline_token_(outline_token), glyph_(glyph) {}

    void paint(QPainter *painter, const QRect &rect,
               QIcon::Mode mode, QIcon::State /*state*/) override
    {
        if (rect.isEmpty())
            return;

        // The requested outline is only a starting point: a black outline on a
        // dark series colour, or a white one on a pale one, would vanish.  The
        // ratio is measured against the fill made opaque, because contrast is
        // defined for opaque colours and the surface under a translucent fill
        // is unknown here.
        const QColor fill = baseFill();
        const QColor base = baseOutline();
        QColor opaque_fill = fill;
        opaque_fill.setAlpha(255);
        const QColor outline = ColorMath::ensureContrast(base, opaque_fill,
                                                         ColorMath::activeRatios().nonText);
        // The glyph is text, so it has to read, not just be visible.
        const QColor glyph = glyph_.isEmpty() ? outline
                                              : ColorMath::readableText(base, opaque_fill);

        if (mode != QIcon::Disabled) {
            draw(painter, rect, fill, outline, glyph);
            return;
        }

        // Adapt first, then grey: qGray() keeps the luminance difference, so
        // the separation found in colour survives the greying.
        // Dim the finished icon as a whole, as ThemedIcon and ContrastAdaptIcon
        // do.  Fill, outline and glyph overlap, so dimming each one on its own
        // would let the fill show through the outline and the glyph.
        const qreal scale = painter->device() ? painter->device()->devicePixelRatioF() : 1.0;
        QPixmap layer = transparentIconPixmap(rect.size(), scale);
        {
            QPainter layer_painter(&layer);
            draw(&layer_painter, QRect(QPoint(0, 0), rect.size()),
                 grey(fill), grey(outline), grey(glyph));
        }
        painter->save();
        painter->setOpacity(painter->opacity() * kIconDisabledOpacity);
        painter->drawPixmap(rect, layer);
        painter->restore();
    }

    QPixmap pixmap(const QSize &size, QIcon::Mode mode, QIcon::State state) override
    {
        return scaledPixmap(size, mode, state, 1.0);
    }

    QPixmap scaledPixmap(const QSize &size, QIcon::Mode mode, QIcon::State state,
                         qreal scale) override
    {
        const QSize logical = size.isEmpty() ? kDefaultSize : size;
        QPixmap pm = transparentIconPixmap(logical, scale);
        QPainter painter(&pm);
        // Logical coordinates: the pixmap carries the device-pixel ratio.
        paint(&painter, QRect(QPoint(0, 0), logical), mode, state);
        return pm;
    }

    QIconEngine *clone() const override
    {
        return new ThemedShapeIconEngine(shape_, fill_, fill_index_, outline_,
                                         outline_token_, glyph_);
    }

private:
    QColor baseFill() const
    {
        return fill_index_ != kNoPaletteIndex
                ? ThemeManager::instance()->graphColor(fill_index_)
                : fill_;
    }

    QColor baseOutline() const
    {
        return outline_token_ != ThemeManager::NoRole
                ? resolveIconToken(outline_token_, nullptr)
                : outline_;
    }

    void draw(QPainter *painter, const QRect &rect, const QColor &fill,
              const QColor &outline, const QColor &glyph) const
    {
        // Callers may ask for non-square sizes (menus on some platforms); use
        // the largest centred square so the shape keeps its proportions.
        const qreal side = qMin(rect.width(), rect.height());
        const QRectF box(QRectF(rect).center() - QPointF(side / 2.0, side / 2.0),
                         QSizeF(side, side));
        // The outline scales with the icon.  Inset by half its width so the
        // stroke lies inside the box instead of being clipped at the edge.
        const qreal pen_width = qMax(1.0, side * kOutlineFraction);
        const qreal half = pen_width / 2.0;

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setRenderHint(QPainter::TextAntialiasing);
        painter->setPen(QPen(outline, pen_width));
        painter->setBrush(fill);
        painter->drawPath(shapePath(box.adjusted(half, half, -half, -half)));

        if (!glyph_.isEmpty()) {
            QFont font = QApplication::font();
            // Pixel size, not point size: the glyph must take the same share
            // of the icon whatever the screen DPI.
            font.setPixelSize(qMax(1, qRound(side * kGlyphFraction)));
            painter->setFont(font);
            painter->setPen(glyph);
            painter->drawText(box, Qt::AlignCenter, glyph_);
        }
        painter->restore();
    }

    QPainterPath shapePath(const QRectF &r) const
    {
        QPainterPath path;
        switch (shape_) {
        case ThemedShapeIcon::Circle:
            path.addEllipse(r);
            break;
        case ThemedShapeIcon::Triangle:
            path.moveTo(r.left(), r.bottom());
            path.lineTo(r.right(), r.bottom());
            path.lineTo(r.center().x(), r.top());
            path.closeSubpath();
            break;
        case ThemedShapeIcon::Cross: {
            // An X has no area of its own.  Stroke both diagonals into one
            // band so it can be filled with the data colour and outlined like
            // the other shapes.  A flat-capped bar's end corners stick out by
            // bar / (2 * sqrt(2)) on each axis, so the diagonals are shortened
            // by that much to keep the band inside the rect.
            const qreal bar = r.width() * kCrossBarFraction;
            const qreal d = bar / (2.0 * std::sqrt(2.0));
            const QRectF inner = r.adjusted(d, d, -d, -d);
            QPainterPath diagonals;
            diagonals.moveTo(inner.topLeft());
            diagonals.lineTo(inner.bottomRight());
            diagonals.moveTo(inner.bottomLeft());
            diagonals.lineTo(inner.topRight());
            QPainterPathStroker stroker;
            stroker.setWidth(bar);
            stroker.setCapStyle(Qt::FlatCap);
            stroker.setJoinStyle(Qt::MiterJoin);
            // simplified() merges the two bars, so no outline is drawn
            // across their intersection.
            path = stroker.createStroke(diagonals).simplified();
            break;
        }
        case ThemedShapeIcon::Square:
        default:
            path.addRect(r);
            break;
        }
        return path;
    }

    ThemedShapeIcon::Shape shape_;
    QColor fill_;
    int fill_index_;
    QColor outline_;
    ThemeManager::ThemeToken outline_token_;
    QString glyph_;
};

} // namespace

ThemedShapeIcon::ThemedShapeIcon(Shape shape, const QColor &fill,
                                 const QColor &outline, const QString &glyph) :
    QIcon(new ThemedShapeIconEngine(shape, fill, kNoPaletteIndex, outline,
                                    ThemeManager::NoRole, glyph))
{
}

ThemedShapeIcon::ThemedShapeIcon(Shape shape, const QColor &fill,
                                 ThemeManager::ThemeToken outline_token,
                                 const QString &glyph) :
    QIcon(new ThemedShapeIconEngine(shape, fill, kNoPaletteIndex, QColor(),
                                    outline_token, glyph))
{
}

ThemedShapeIcon::ThemedShapeIcon(Shape shape, PaletteColor fill,
                                 ThemeManager::ThemeToken outline_token) :
    QIcon(new ThemedShapeIconEngine(shape, QColor(), fill.index, QColor(),
                                    outline_token, QString()))
{
    // A negative index would be taken for the fixed-colour marker.
    Q_ASSERT(fill.index >= 0);
}
