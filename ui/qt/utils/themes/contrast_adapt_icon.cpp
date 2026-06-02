/* contrast_adapt_icon.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/utils/themes/contrast_adapt_icon.h>
#include <ui/qt/utils/themes/color_math.h>
#include <ui/qt/utils/theme_manager.h>

#include <QApplication>
#include <QFile>
#include <QHash>
#include <QIconEngine>
#include <QMetaEnum>
#include <QPaintDevice>
#include <QPainter>
#include <QPixmap>
#include <QPixmapCache>
#include <QRectF>
#include <QRegularExpression>
#include <QSvgRenderer>

namespace {

// Global minimum contrast ratio, captured by each icon at construction.
// Function-local static avoids static-init-order issues.
qreal &defaultMinContrastRef()
{
    static qreal value = 1.6;
    return value;
}

// Opacity applied to the whole icon in QIcon::Disabled mode (matches ThemedIcon).
constexpr qreal kDisabledOpacity = 0.4;

// Fit @p src into @p box preserving aspect ratio, centred.
QRectF aspectFit(QSizeF src, const QRectF &box)
{
    if (src.isEmpty())
        return box;
    const qreal k = qMin(box.width() / src.width(), box.height() / src.height());
    const QSizeF out = src * k;
    return QRectF(box.center() - QPointF(out.width() / 2.0, out.height() / 2.0), out);
}

// Matches a fill/stroke/stop-color paint property and captures its hex value, so
// we can rewrite the colour while leaving "none", "currentColor" and url(#...)
// references untouched.
const QRegularExpression &paintColorRe()
{
    static const QRegularExpression re(
        QStringLiteral("(?:fill|stroke|stop-color)\\s*[:=]\\s*[\"']?\\s*(#[0-9a-fA-F]{3,8})"));
    return re;
}

/**
 * @brief QIconEngine that recolours an SVG for contrast against its background.
 *
 * Loads the SVG once, then on each render resolves a background, runs every
 * paint colour through ColorMath::ensureContrast() against it, substitutes the
 * results back into the markup and renders the (still multi-colour) result.
 */
class ContrastAdaptIconEngine : public QIconEngine
{
public:
    ContrastAdaptIconEngine(const QString &path, qreal min_contrast,
                            QPalette::ColorRole surface_role,
                            QColor explicit_bg, QSize size) :
        min_contrast_(min_contrast), surface_role_(surface_role),
        explicit_bg_(explicit_bg), size_(size)
    {
        path_ = path;
        QFile f(path);
        if (f.open(QIODevice::ReadOnly))
            svg_ = QString::fromUtf8(f.readAll());
        parseSwaps();
        parseTokenMaps();
    }

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

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    QPixmap scaledPixmap(const QSize &size, QIcon::Mode mode, QIcon::State state,
                         qreal scale) override
#else
    QPixmap scaledPixmap(const QSize &size, QIcon::Mode mode, QIcon::State state,
                         qreal scale)
#endif
    {
        const QColor bg = backgroundFor(mode);
        const QSize logical = (size.isValid() && !size.isEmpty()) ? size : size_;

        // Background colour is part of the key, so a theme/light-dark flip (which
        // changes the resolved background) is a natural cache miss.
        const QString key = QStringLiteral("contrastadapt:%1:%2:%3:%4:%5:%6x%7@%8")
                                .arg(path_)
                                .arg(int(mode))
                                .arg(int(state))
                                .arg(bg.rgba())
                                .arg(tokenSignature())
                                .arg(logical.width())
                                .arg(logical.height())
                                .arg(scale);

        QPixmap pm;
        if (QPixmapCache::find(key, &pm))
            return pm;

        pm = render(logical, scale, mode, state, bg);
        QPixmapCache::insert(key, pm);
        return pm;
    }

    QIconEngine *clone() const override
    {
        ContrastAdaptIconEngine *e =
            new ContrastAdaptIconEngine(path_, min_contrast_, surface_role_, explicit_bg_, size_);
        e->svg_ = svg_;
        e->swaps_ = swaps_;
        e->token_maps_ = token_maps_;
        return e;
    }

private:
    // Why the background is derived from QIcon::Mode rather than read from the
    // paint device:
    //
    // A QIconEngine is entered through two methods, and the ones that matter most
    // have no painter at all.  QToolButton and QMenu rasterise their icon via
    // QIcon::pixmap() -> scaledPixmap(size, mode, state) — no QPainter, no widget,
    // no access to whatever is painted behind the icon.  Only item-view delegates
    // reach paint(QPainter*, rect, mode, state), where a painter exists.  The one
    // piece of context present on *every* path is QIcon::Mode, and it already
    // distinguishes the cases that change the background: Selected means the icon
    // sits on the selection highlight, the other modes mean it sits on the normal
    // surface.  So the background is resolved from the mode against the
    // application palette; trying to sample the destination would only work for
    // item views and is unavailable to the toolbar/menu path.
    //
    // The surface role (Window vs Base) is the one thing the mode cannot tell us —
    // a toolbar (Window) and a tree (Base) both paint in Normal mode — so it is a
    // construction-time hint, and an explicit background overrides everything for
    // call sites whose surface is neither (e.g. colour-rule-tinted rows).
    //
    // NOTE: backgrounds are read from QPalette roles (Window/Base/Highlight) here.
    // ThemeManager carries richer surface tokens than the palette exposes (e.g.
    // PaletteBase, PacketsSelection); guiding the surface through a
    // ThemeManager::ThemeToken instead of a QPalette::ColorRole is worth
    // investigating later, so an icon can track a theme-specific surface the
    // palette does not model.
    QColor backgroundFor(QIcon::Mode mode) const
    {
        if (explicit_bg_.isValid())
            return explicit_bg_;
        const QPalette pal = qApp->palette();
        if (mode == QIcon::Selected)
            return pal.color(QPalette::Highlight);
        return pal.color(surface_role_);
    }

    // Per-state colours an icon may declare for one of its base colours, via a
    // <ws:swap base="#.." active="#.." selected="#.."/> element (ignored by the
    // SVG renderer).  This is the whole "state contract": an icon that should
    // recolour on hover/press names the alternates; everything else just keeps
    // its drawn colour and is contrast-adapted as-is.
    // XXX Would it make sense to use the term "normal" instead of "base", as in
    // "map the color x in the normal/off state to y in the active state"? "
    struct StateColors {
        QColor active;
        QColor selected;
        QColor normal_on;
    };

    void parseSwaps()
    {
        static const QRegularExpression swapEl(QStringLiteral("<[\\w:]*swap\\b[^>]*>"));
        static const QRegularExpression baseAttr(QStringLiteral("\\bbase\\s*=\\s*\"([^\"]+)\""));
        static const QRegularExpression activeAttr(QStringLiteral("\\bactive\\s*=\\s*\"([^\"]+)\""));
        static const QRegularExpression selectedAttr(QStringLiteral("\\bselected\\s*=\\s*\"([^\"]+)\""));
        static const QRegularExpression normal_onAttr(QStringLiteral("\\bnormal-on\\s*=\\s*\"([^\"]+)\""));

        auto it = swapEl.globalMatch(svg_);
        while (it.hasNext()) {
            const QString el = it.next().captured(0);
            const QRegularExpressionMatch bm = baseAttr.match(el);
            const QColor base = bm.hasMatch() ? QColor::fromString(bm.captured(1)) : QColor();
            if (!base.isValid())
                continue;
            StateColors sc;
            const QRegularExpressionMatch am = activeAttr.match(el);
            const QRegularExpressionMatch sm = selectedAttr.match(el);
            const QRegularExpressionMatch nom = normal_onAttr.match(el);
            if (am.hasMatch())
                sc.active = QColor::fromString(am.captured(1));
            if (sm.hasMatch())
                sc.selected = QColor::fromString(sm.captured(1));
            if (nom.hasMatch())
                sc.normal_on = QColor::fromString(nom.captured(1));
            // Key on the canonical #rrggbb form so it matches the drawn literal
            // regardless of how either was spelled.
            swaps_.insert(base.name(), sc);
        }
    }

    // Colours an icon may bind to a ThemeManager token, via a
    // <ws:map-token color="#212121" token="PaletteText"/> element (ignored by the
    // SVG renderer).  The token is named as in the ThemeManager::ThemeToken enum.
    // Every drawn occurrence of "color" is painted with the token's current theme
    // colour instead, in all modes.  The token's colour is the theme's own choice
    // for that role, so it is used as-is rather than contrast-adapted, and takes
    // precedence over a <ws:swap> for the same colour.
    void parseTokenMaps()
    {
        static const QRegularExpression mapEl(QStringLiteral("<[\\w:]*map-token\\b[^>]*>"));
        static const QRegularExpression colorAttr(QStringLiteral("\\bcolor\\s*=\\s*\"([^\"]+)\""));
        static const QRegularExpression tokenAttr(QStringLiteral("\\btoken\\s*=\\s*\"([^\"]+)\""));

        const QMetaEnum me = QMetaEnum::fromType<ThemeManager::ThemeToken>();
        auto it = mapEl.globalMatch(svg_);
        while (it.hasNext()) {
            const QString el = it.next().captured(0);
            const QRegularExpressionMatch cm = colorAttr.match(el);
            const QRegularExpressionMatch tm = tokenAttr.match(el);
            if (!cm.hasMatch() || !tm.hasMatch())
                continue;
            const QColor color = QColor::fromString(cm.captured(1));
            if (!color.isValid())
                continue;
            // Accept an optional "ThemeToken:" / "ThemeManager::" style prefix.
            QString name = tm.captured(1);
            name = name.mid(name.lastIndexOf(QLatin1Char(':')) + 1);
            bool ok = false;
            const int value = me.keyToValue(name.toUtf8().constData(), &ok);
            if (!ok || value == ThemeManager::NoRole)
                continue;
            token_maps_.insert(color.name(), static_cast<ThemeManager::ThemeToken>(value));
        }
    }

    // Current colour of a mapped token, falling back to the palette text colour
    // when the theme does not supply it.
    QColor tokenColor(ThemeManager::ThemeToken token) const
    {
        QColor c = ThemeManager::instance()->color(token);
        return c.isValid() ? c : qApp->palette().color(QPalette::Text);
    }

    // Folded into the pixmap cache key so a theme change that alters a mapped
    // token's colour (without altering the background) still misses the cache.
    quint32 tokenSignature() const
    {
        quint32 sig = 0;
        for (auto it = token_maps_.cbegin(); it != token_maps_.cend(); ++it)
            sig ^= qHash(it.key()) ^ quint32(tokenColor(it.value()).rgba());
        return sig;
    }

    // Resolve a drawn colour to what should actually be painted: swap to the
    // declared per-state colour when one exists for this mode, then adapt that
    // for contrast against the mode's background.
    QColor finalColor(const QColor &base, QIcon::Mode mode, QIcon::State state,
                      const QColor &bg) const
    {
        const auto mapped = token_maps_.constFind(base.name());
        if (mapped != token_maps_.constEnd())
            return tokenColor(mapped.value());

        QColor src = base;
        const auto it = swaps_.constFind(base.name());
        if (it != swaps_.constEnd()) {
            if (mode == QIcon::Active && it->active.isValid())
                src = it->active;
            else if (mode == QIcon::Selected && it->selected.isValid())
                src = it->selected;
            else if (state == QIcon::On && it->normal_on.isValid())
                src = it->normal_on;
        }
        return ColorMath::ensureContrast(src, bg, min_contrast_);
    }

    QString adaptedSvg(QIcon::Mode mode, QIcon::State state, const QColor &bg) const
    {
        QString out;
        out.reserve(svg_.size());
        const QRegularExpression &re = paintColorRe();
        qsizetype last = 0;
        auto it = re.globalMatch(svg_);
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            out += QStringView{svg_}.mid(last, m.capturedStart(1) - last);
            const QColor c = QColor::fromString(m.captured(1));
            const QColor a = c.isValid() ? finalColor(c, mode, state, bg) : c;
            out += a.isValid() ? a.name() : m.captured(1);
            last = m.capturedEnd(1);
        }
        out += QStringView{svg_}.mid(last);
        return out;
    }

    QPixmap render(const QSize &logical, qreal scale, QIcon::Mode mode,
                   QIcon::State state, const QColor &bg) const
    {
        QPixmap pm(logical * scale);
        pm.setDevicePixelRatio(scale);
        pm.fill(Qt::transparent);
        if (svg_.isEmpty())
            return pm;

        QSvgRenderer renderer(adaptedSvg(mode, state, bg).toUtf8());
        QPainter p(&pm);
        // Disabled: dim the whole rendering, as ThemedIcon does, rather than
        // per-colour so overlapping shapes don't show through each other.
        if (mode == QIcon::Disabled)
            p.setOpacity(kDisabledOpacity);
        const QRectF box(QPointF(0, 0), QSizeF(logical));
        renderer.render(&p, aspectFit(renderer.defaultSize(), box));
        p.end();
        return pm;
    }

    QString path_;
    QString svg_;
    qreal min_contrast_;
    QPalette::ColorRole surface_role_;
    QColor explicit_bg_;
    QSize size_;
    QHash<QString, StateColors> swaps_;
    QHash<QString, ThemeManager::ThemeToken> token_maps_;
};

} // namespace

ContrastAdaptIcon::ContrastAdaptIcon(const QString &svg_resource_path,
                                     QPalette::ColorRole surface_role, QSize size) :
    QIcon(new ContrastAdaptIconEngine(svg_resource_path, defaultMinContrastRef(),
                                      surface_role, QColor(), size))
{
}

ContrastAdaptIcon::ContrastAdaptIcon(const QString &svg_resource_path,
                                     const QColor &explicit_background, QSize size) :
    QIcon(new ContrastAdaptIconEngine(svg_resource_path, defaultMinContrastRef(),
                                      QPalette::Window, explicit_background, size))
{
}

void ContrastAdaptIcon::setDefaultMinContrast(qreal ratio)
{
    defaultMinContrastRef() = ratio;
}

qreal ContrastAdaptIcon::defaultMinContrast()
{
    return defaultMinContrastRef();
}
