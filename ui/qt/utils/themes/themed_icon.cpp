/* themed_icon.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/utils/themes/themed_icon.h>

#include <QApplication>
#include <QIconEngine>
#include <QPaintDevice>
#include <QPainter>
#include <QPixmap>
#include <QPixmapCache>
#include <QRectF>
#include <QSvgRenderer>

namespace {

// Fit @p src into @p box preserving aspect ratio, centred.  Apply's source
// viewBox is 24x14, so it letterboxes into a square icon box rather than
// stretching.
QRectF aspectFit(QSizeF src, const QRectF &box)
{
    if (src.isEmpty())
        return box;
    const qreal k = qMin(box.width() / src.width(), box.height() / src.height());
    const QSizeF out = src * k;
    return QRectF(box.center() - QPointF(out.width() / 2.0, out.height() / 2.0), out);
}

/**
 * QIconEngine that renders an SVG and tints it to a ThemeManager token.
 *
 * The token colour is resolved live on every render, so the engine always
 * reflects the current theme.  Resolving through the token (rather than a
 * widget's palette) also sidesteps FilterEdit::setState()'s per-state
 * QPalette::Text override: a glyph sitting on the un-tinted icon strip stays
 * coloured for that strip, not for the tinted text area.
 */
class ThemedIconEngine : public QIconEngine
{
public:
    ThemedIconEngine(const QString &path, ThemeManager::ThemeToken token,
                     ThemeManager::ThemeToken active_token,
                     ThemeManager::ThemeToken selected_token, QSize size) :
        path_(path), token_(token), active_token_(active_token),
        selected_token_(selected_token), size_(size) {}

    void paint(QPainter *painter, const QRect &rect,
               QIcon::Mode mode, QIcon::State state) override
    {
        const qreal scale = painter->device() ? painter->device()->devicePixelRatioF() : 1.0;
        painter->drawPixmap(rect, scaledPixmap(rect.size(), mode, state, scale));
    }

    QPixmap pixmap(const QSize &size, QIcon::Mode mode, QIcon::State state) override
    {
        return scaledPixmap(size, mode, state, 1.0);
    }

    QPixmap scaledPixmap(const QSize &size, QIcon::Mode mode, QIcon::State /*state*/,
                         qreal scale) override
    {
        const QColor color = modeColor(mode);
        const QSize logical = (size.isValid() && !size.isEmpty()) ? size : size_;

        // The resolved colour is part of the key, so a theme/light-dark flip
        // (which changes the token's colour) is a natural cache miss — no
        // explicit invalidation needed.
        const QString key = QStringLiteral("themedicon:%1:%2:%3:%4x%5@%6")
                                .arg(path_)
                                .arg(int(mode))
                                .arg(color.rgba())
                                .arg(logical.width())
                                .arg(logical.height())
                                .arg(scale);

        QPixmap pm;
        if (QPixmapCache::find(key, &pm))
            return pm;

        pm = render(logical, scale, color);
        QPixmapCache::insert(key, pm);
        return pm;
    }

    QIconEngine *clone() const override
    {
        return new ThemedIconEngine(path_, token_, active_token_, selected_token_, size_);
    }

private:
    QColor modeColor(QIcon::Mode mode) const
    {
        auto resolve = [](ThemeManager::ThemeToken t) {
            QColor c = ThemeManager::instance()->color(t);
            if (!c.isValid())
                c = qApp->palette().color(QPalette::Text);
            return c;
        };

        switch (mode) {
        case QIcon::Disabled: {
            QColor c = resolve(token_);
            c.setAlphaF(c.alphaF() * 0.4);
            return c;
        }
        case QIcon::Active:
            // Explicit hover colour when given, else a slight emphasis of normal.
            return active_token_ != ThemeManager::NoRole ? resolve(active_token_)
                                                         : resolve(token_).lighter(115);
        case QIcon::Selected:
            return selected_token_ != ThemeManager::NoRole ? resolve(selected_token_)
                 : active_token_   != ThemeManager::NoRole ? resolve(active_token_)
                                                           : resolve(token_).lighter(115);
        case QIcon::Normal:
        default:
            return resolve(token_);
        }
    }

    QPixmap render(const QSize &logical, qreal scale, const QColor &color) const
    {
        QPixmap pm(logical * scale);
        pm.setDevicePixelRatio(scale);
        pm.fill(Qt::transparent);

        QSvgRenderer renderer(path_);
        QPainter p(&pm);
        // Coordinates are logical (the pixmap carries the device-pixel ratio).
        const QRectF box(QPointF(0, 0), QSizeF(logical));
        renderer.render(&p, aspectFit(renderer.defaultSize(), box));
        // Replace the rendered colours with the tint, keeping the alpha shape.
        p.setCompositionMode(QPainter::CompositionMode_SourceIn);
        p.fillRect(box, color);
        p.end();
        return pm;
    }

    QString path_;
    ThemeManager::ThemeToken token_;
    ThemeManager::ThemeToken active_token_;
    ThemeManager::ThemeToken selected_token_;
    QSize size_;
};

} // namespace

ThemedIcon::ThemedIcon(const QString &svg_resource_path,
                       ThemeManager::ThemeToken token, QSize size) :
    QIcon(new ThemedIconEngine(svg_resource_path, token,
                               ThemeManager::NoRole, ThemeManager::NoRole, size))
{
}

ThemedIcon::ThemedIcon(const QString &svg_resource_path,
                       ThemeManager::ThemeToken token,
                       ThemeManager::ThemeToken active_token,
                       ThemeManager::ThemeToken selected_token, QSize size) :
    QIcon(new ThemedIconEngine(svg_resource_path, token,
                               active_token, selected_token, size))
{
}
