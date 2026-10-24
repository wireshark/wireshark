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
#include <ui/qt/utils/themes/token_palette.h>
#include <ui/qt/utils/themes/icon_engine_utils.h>

#include <QApplication>
#include <QFile>
#include <QHash>
#include <QIconEngine>
#include <QPaintDevice>
#include <QPainter>
#include <QPixmap>
#include <QPixmapCache>
#include <QRectF>
#include <QRegularExpression>
#include <QStringList>
#include <QSvgRenderer>

namespace {

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

// The start tags of every <name ...> element in @p svg, with or without a
// namespace prefix (<ws:swap ...>, <swap ...>).  The icon engine reads its
// own elements this way; the SVG renderer ignores them.
QStringList elementTags(const QString &svg, const QString &name)
{
    const QRegularExpression re(QStringLiteral("<[\\w:]*%1\\b[^>]*>")
                                    .arg(QRegularExpression::escape(name)));
    QStringList tags;
    auto it = re.globalMatch(svg);
    while (it.hasNext())
        tags << it.next().captured(0);
    return tags;
}

// The attributes of one start tag, as name -> value.  Names match exactly,
// so "base" never matches inside "data-base".  An empty value counts as
// absent, and the first occurrence of a name wins.
QHash<QString, QString> elementAttributes(const QString &tag)
{
    static const QRegularExpression re(QStringLiteral("([\\w:-]+)\\s*=\\s*\"([^\"]*)\""));
    QHash<QString, QString> attrs;
    auto it = re.globalMatch(tag);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        if (!m.captured(2).isEmpty() && !attrs.contains(m.captured(1)))
            attrs.insert(m.captured(1), m.captured(2));
    }
    return attrs;
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
    ContrastAdaptIconEngine(const QString &path,
                            QPalette::ColorRole surface_role,
                            QColor explicit_bg, QSize size,
                            IconPaletteRef palette,
                            IconTokenColorsRef token_colors) :
        path_(path),
        surface_role_(surface_role),
        explicit_bg_(explicit_bg),
        size_(size),
        palette_(palette),
        token_colors_(token_colors)
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
        const qreal min_contrast = ColorMath::activeRatios().icon;
        const QSize logical = (size.isValid() && !size.isEmpty()) ? size : size_;

        // Background colour and contrast ratio are part of the key, so a
        // theme/light-dark flip (which changes the resolved background) or a
        // contrast level change is a natural cache miss.
        const QString key = QStringLiteral("contrastadapt:%1:%2:%3:%4:%5:%6:%7x%8@%9")
                                .arg(path_)
                                .arg(int(mode))
                                .arg(int(state))
                                .arg(bg.rgba())
                                .arg(min_contrast)
                                .arg(tokenSignature(mode, state, bg, min_contrast))
                                .arg(logical.width())
                                .arg(logical.height())
                                .arg(scale);

        QPixmap pm;
        if (QPixmapCache::find(key, &pm))
            return pm;

        pm = render(logical, scale, mode, state, bg, min_contrast);
        QPixmapCache::insert(key, pm);
        return pm;
    }

    QIconEngine *clone() const override
    {
        ContrastAdaptIconEngine *e =
            new ContrastAdaptIconEngine(path_, surface_role_, explicit_bg_,
                                        size_, palette_, token_colors_);
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
        const QPalette *override_pal = iconPalettePtr(palette_);
        const QPalette pal = override_pal ? *override_pal : qApp->palette();
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
        const QStringList tags = elementTags(svg_, QStringLiteral("swap"));
        for (const QString &tag : tags) {
            const QHash<QString, QString> attrs = elementAttributes(tag);
            const QColor base(attrs.value(QStringLiteral("base")));
            if (!base.isValid())
                continue;
            // An absent attribute gives an invalid colour: no swap for that state.
            StateColors sc;
            sc.active = QColor(attrs.value(QStringLiteral("active")));
            sc.selected = QColor(attrs.value(QStringLiteral("selected")));
            sc.normal_on = QColor(attrs.value(QStringLiteral("normal-on")));
            // Key on the canonical #rrggbb form so it matches the drawn literal
            // regardless of how either was spelled.
            swaps_.insert(base.name(), sc);
        }
    }

    // How a <ws:map-token> binding paints its colour in Active or Selected
    // mode: a token, or "emphasis" (ColorMath::hoverEmphasis() of the binding's
    // "token" colour).  Neither set: the mode is not bound.
    struct ModeBinding {
        ThemeManager::ThemeToken token = ThemeManager::NoRole;
        bool emphasis = false;
        bool isSet() const { return emphasis || token != ThemeManager::NoRole; }
    };

    // One <ws:map-token> element.  "token" binds the colour in every mode;
    // "active"/"selected" bind it in that mode only and win over "token"
    // there; Selected falls back to "active".  "adapt" guards the painted
    // colour for contrast like a drawn colour.
    struct TokenBinding {
        ThemeManager::ThemeToken token = ThemeManager::NoRole;
        ModeBinding active;
        ModeBinding selected;
        bool adapt = false;

        ModeBinding forMode(QIcon::Mode mode) const
        {
            if (mode == QIcon::Active)
                return active;
            if (mode == QIcon::Selected)
                return selected.isSet() ? selected : active;
            return ModeBinding();
        }
    };

    // A token named as in the ThemeManager::ThemeToken enum, with an optional
    // "ThemeToken:" / "ThemeManager::" style prefix.
    static ThemeManager::ThemeToken tokenNamed(QString name)
    {
        name = name.mid(name.lastIndexOf(QLatin1Char(':')) + 1);
        return ThemeManager::tokenFromName(name);
    }

    // Parse an "active"/"selected" value into @p mb.  False when it names
    // neither "emphasis" nor a known token.
    static bool parseModeBinding(const QString &value, ModeBinding *mb)
    {
        if (value == QLatin1String("emphasis")) {
            mb->emphasis = true;
            return true;
        }
        mb->token = tokenNamed(value);
        return mb->token != ThemeManager::NoRole;
    }

    // Colours an icon may bind to a ThemeManager token, via a
    // <ws:map-token color="#212121" token="PaletteText"/> element (ignored by the
    // SVG renderer).  Tokens are named as in the ThemeManager::ThemeToken enum.
    // "token" paints every drawn occurrence of "color" with the token's current
    // theme colour in every mode.  "active" and "selected" bind one mode only
    // (a token name, or "emphasis" for a slight brightening of the "token"
    // colour); Selected falls back to "active".  Without "token", the other
    // modes keep the drawn colour, swapped and adapted like an unbound colour.
    // Token colours are used as-is, unless adapt="contrast" asks for the same
    // contrast adaptation drawn colours get.  A mapping wins over a <ws:swap>
    // for the same colour.
    void parseTokenMaps()
    {
        const QStringList tags = elementTags(svg_, QStringLiteral("map-token"));
        for (const QString &tag : tags) {
            const QHash<QString, QString> attrs = elementAttributes(tag);
            const QColor color(attrs.value(QStringLiteral("color")));
            if (!color.isValid())
                continue;
            // Any attribute naming something unknown drops the whole element,
            // so a misspelling paints the drawn colour rather than half a binding.
            TokenBinding b;
            bool ok = true;
            const QString token = attrs.value(QStringLiteral("token"));
            if (!token.isEmpty()) {
                b.token = tokenNamed(token);
                ok = b.token != ThemeManager::NoRole;
            }
            const QString active = attrs.value(QStringLiteral("active"));
            if (ok && !active.isEmpty())
                ok = parseModeBinding(active, &b.active);
            const QString selected = attrs.value(QStringLiteral("selected"));
            if (ok && !selected.isEmpty())
                ok = parseModeBinding(selected, &b.selected);
            const QString adapt = attrs.value(QStringLiteral("adapt"));
            if (ok && !adapt.isEmpty()) {
                b.adapt = adapt == QLatin1String("contrast");
                ok = b.adapt;
            }
            // "emphasis" brightens the "token" colour, so it needs one.
            if ((b.active.emphasis || b.selected.emphasis) && b.token == ThemeManager::NoRole)
                ok = false;
            if (!ok || (b.token == ThemeManager::NoRole && !b.active.isSet() && !b.selected.isSet()))
                continue;
            // Key on the canonical #rrggbb form, like parseSwaps().
            token_maps_.insert(color.name(), b);
        }
    }

    // Current colour of a mapped token: a caller-supplied override first, then the
    // live theme, falling back to the palette text colour when the theme does not
    // supply it.
    QColor tokenColor(ThemeManager::ThemeToken token) const
    {
        if (token_colors_) {
            const QColor c = token_colors_->value(token);
            if (c.isValid())
                return c;
        }
        return resolveIconToken(token, iconPalettePtr(palette_));
    }

    // Folded into the pixmap cache key so a theme change that alters the
    // colour a binding paints in this mode (without altering the background)
    // still misses the cache.
    quint32 tokenSignature(QIcon::Mode mode, QIcon::State state, const QColor &bg,
                           qreal min_contrast) const
    {
        quint32 sig = 0;
        for (auto it = token_maps_.cbegin(); it != token_maps_.cend(); ++it)
            sig ^= qHash(it.key())
                   ^ quint32(finalColor(QColor(it.key()), mode, state, bg, min_contrast).rgba());
        return sig;
    }

    // Resolve a drawn colour to what should actually be painted: swap to the
    // declared per-state colour when one exists for this mode, then adapt that
    // for contrast against the mode's background.  A mapped colour paints its
    // token for this mode (guarded only with adapt="contrast").
    QColor finalColor(const QColor &base, QIcon::Mode mode, QIcon::State state,
                      const QColor &bg, qreal min_contrast) const
    {
        const auto mapped = token_maps_.constFind(base.name());
        if (mapped != token_maps_.constEnd()) {
            const TokenBinding &b = mapped.value();
            const ModeBinding mb = b.forMode(mode);
            QColor c;
            if (mb.token != ThemeManager::NoRole)
                c = tokenColor(mb.token);
            else if (b.token != ThemeManager::NoRole)
                c = mb.emphasis ? ColorMath::hoverEmphasis(tokenColor(b.token)) : tokenColor(b.token);
            if (c.isValid())
                return b.adapt ? ColorMath::ensureContrast(c, bg, min_contrast) : c;
            // No token binds this mode: paint the drawn colour below.
        }

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
        return ColorMath::ensureContrast(src, bg, min_contrast);
    }

    QString adaptedSvg(QIcon::Mode mode, QIcon::State state, const QColor &bg,
                       qreal min_contrast) const
    {
        QString out;
        out.reserve(svg_.size());
        const QRegularExpression &re = paintColorRe();
        qsizetype last = 0;
        auto it = re.globalMatch(svg_);
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            out += QStringView{svg_}.mid(last, m.capturedStart(1) - last);
            const QColor c = QColor(m.captured(1));
            const QColor a = c.isValid() ? finalColor(c, mode, state, bg, min_contrast) : c;
            out += a.isValid() ? a.name() : m.captured(1);
            last = m.capturedEnd(1);
        }
        out += QStringView{svg_}.mid(last);
        return out;
    }

    QPixmap render(const QSize &logical, qreal scale, QIcon::Mode mode,
                   QIcon::State state, const QColor &bg, qreal min_contrast) const
    {
        QPixmap pm = transparentIconPixmap(logical, scale);
        if (svg_.isEmpty())
            return pm;

        QSvgRenderer renderer(adaptedSvg(mode, state, bg, min_contrast).toUtf8());
        QPainter p(&pm);
        // Disabled: dim the whole rendering, as ThemedIcon does, rather than
        // per-colour so overlapping shapes don't show through each other.
        if (mode == QIcon::Disabled)
            p.setOpacity(kIconDisabledOpacity);
        const QRectF box(QPointF(0, 0), QSizeF(logical));
        renderer.render(&p, aspectFit(renderer.defaultSize(), box));
        p.end();
        return pm;
    }

    QString path_;
    QString svg_;
    QPalette::ColorRole surface_role_;
    QColor explicit_bg_;
    QSize size_;
    IconPaletteRef palette_;
    IconTokenColorsRef token_colors_;
    QHash<QString, StateColors> swaps_;
    QHash<QString, TokenBinding> token_maps_;
};

} // namespace

ContrastAdaptIcon::ContrastAdaptIcon(const QString &svg_resource_path,
                                     QPalette::ColorRole surface_role, QSize size) :
    ContrastAdaptIcon(svg_resource_path, surface_role, QColor(), size,
                      makeIconPaletteRef(), makeIconTokenColorsRef())
{
}

ContrastAdaptIcon::ContrastAdaptIcon(const QString &svg_resource_path,
                                     const QColor &explicit_background, QSize size) :
    ContrastAdaptIcon(svg_resource_path, QPalette::Window, explicit_background,
                      size, makeIconPaletteRef(), makeIconTokenColorsRef())
{
}

ContrastAdaptIcon::ContrastAdaptIcon(const QString &svg_resource_path,
                                     QPalette::ColorRole surface_role,
                                     const QColor &explicit_background,
                                     QSize size, IconPaletteRef palette,
                                     IconTokenColorsRef token_colors) :
    QIcon(new ContrastAdaptIconEngine(svg_resource_path,
                                      surface_role, explicit_background, size,
                                      palette, token_colors)),
    palette_(palette),
    token_colors_(token_colors)
{
}

void ContrastAdaptIcon::setTokenColors(const QHash<ThemeManager::ThemeToken, QColor> &colors)
{
    *token_colors_ = colors;
}

void ContrastAdaptIcon::setPalette(const QPalette &palette)
{
    *palette_ = palette;
}
