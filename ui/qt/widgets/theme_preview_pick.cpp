/* theme_preview_pick.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include "theme_preview_pick.h"

#include <ui/qt/utils/themes/theme_palette_builder.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>

#include <QHash>
#include <QMessageBox>
#include <QMetaEnum>
#include <QMouseEvent>
#include <QPixmap>
#include <QVector>
#include <QWidget>

#include <algorithm>
#include <cstdlib>
#include <utility>

namespace {

// A key color is opaque, has this blue byte, and carries the upper six bits
// of the key in the low bits of green, tagged with kKeyGreenTag.  The red
// byte holds the low eight bits.  The fixed blue byte and green tag make it
// unlikely that a stray color (antialiasing, fixed colors) decodes as a key.
constexpr int kKeyBlue = 0xa7;
constexpr int kKeyGreenTag = 0x40;
constexpr int kKeyGreenBits = 0x3f;

// A click this close to a key pixel still picks it, so edges and thin
// glyph strokes are easy to hit.
constexpr int kNearestKeyRadius = 2;
// A region no thicker than this, and longer than a text line, is a line.
constexpr int kMaxLineWidth = 2;
// A text region is at most this many text heights wide.
constexpr int kMaxTextWidthFactor = 4;
// A border band is at most this thick, measured outward from the region.
constexpr int kMaxBorderBand = 3;
// Share of the ring around a region one key must cover to be its border.
constexpr int kBorderRingPercent = 50;
// Share of that key's ring pixels that must belong to a thin band.
constexpr int kBorderThinPercent = 60;

/** Read access to a key image in one fixed 32-bit format. */
class KeyImage
{
public:
    explicit KeyImage(const QImage &image) :
        image_(image.convertToFormat(QImage::Format_ARGB32)),
        width_(image_.width()),
        height_(image_.height())
    {}

    int width() const { return width_; }
    int height() const { return height_; }
    bool contains(int x, int y) const { return x >= 0 && y >= 0 && x < width_ && y < height_; }
    QRgb pixel(int x, int y) const { return reinterpret_cast<const QRgb *>(image_.constScanLine(y))[x]; }
    int index(int x, int y) const { return y * width_ + x; }

private:
    const QImage image_;
    const int width_;
    const int height_;
};

/** An 8-connected region of one key color. */
struct Component {
    QRgb key = 0;
    int left = 0;
    int top = 0;
    int right = -1;
    int bottom = -1;
    bool complete = false;      ///< False when the fill stopped early.
    QVector<quint8> mask;       ///< One per image pixel, 1 inside the region.

    int width() const { return right - left + 1; }
    int height() const { return bottom - top + 1; }
};

bool isKey(QRgb rgb)
{
    return ThemePreviewPick::decode(rgb).token != ThemeManager::NoRole;
}

bool mayBeText(int width, int height, int text_height)
{
    return height <= text_height && width <= kMaxTextWidthFactor * text_height;
}

/** The role a region of this size paints. */
ThemePreviewPick::Role classify(int width, int height, int text_height)
{
    if (mayBeText(width, height, text_height))
        return ThemePreviewPick::Role::Text;
    if (std::min(width, height) <= kMaxLineWidth && std::max(width, height) > text_height)
        return ThemePreviewPick::Role::Border;
    return ThemePreviewPick::Role::Background;
}

/**
 * Collects the region of @p seed's key around @p seed.  With @p stop_early
 * the fill ends as soon as the region is too big for a text or a line, since
 * it can only grow from there and stays a background.
 */
Component fillComponent(const KeyImage &keys, int seed_x, int seed_y, int text_height, bool stop_early)
{
    Component c;
    c.key = keys.pixel(seed_x, seed_y);
    c.left = c.right = seed_x;
    c.top = c.bottom = seed_y;
    c.mask.fill(0, keys.width() * keys.height());

    QVector<int> stack;
    stack.append(keys.index(seed_x, seed_y));
    c.mask[stack.last()] = 1;
    while (!stack.isEmpty()) {
        const int idx = stack.takeLast();
        const int x = idx % keys.width();
        const int y = idx / keys.width();
        c.left = std::min(c.left, x);
        c.right = std::max(c.right, x);
        c.top = std::min(c.top, y);
        c.bottom = std::max(c.bottom, y);
        if (stop_early && !mayBeText(c.width(), c.height(), text_height)
                && std::min(c.width(), c.height()) > kMaxLineWidth) {
            return c;
        }
        for (int dy = -1; dy <= 1; ++dy) {
            for (int dx = -1; dx <= 1; ++dx) {
                const int nx = x + dx;
                const int ny = y + dy;
                if (!keys.contains(nx, ny))
                    continue;
                const int nidx = keys.index(nx, ny);
                if (c.mask[nidx] || keys.pixel(nx, ny) != c.key)
                    continue;
                c.mask[nidx] = 1;
                stack.append(nidx);
            }
        }
    }
    c.complete = true;
    return c;
}

/** The key pixel a click at @p pos means: @p pos itself, else the nearest within the radius. */
bool findSeed(const KeyImage &keys, const QPoint &pos, QPoint *seed)
{
    if (!keys.contains(pos.x(), pos.y()))
        return false;
    if (isKey(keys.pixel(pos.x(), pos.y()))) {
        *seed = pos;
        return true;
    }
    for (int r = 1; r <= kNearestKeyRadius; ++r) {
        int best_distance = -1;
        for (int dy = -r; dy <= r; ++dy) {
            for (int dx = -r; dx <= r; ++dx) {
                if (std::max(std::abs(dx), std::abs(dy)) != r)
                    continue;
                const int x = pos.x() + dx;
                const int y = pos.y() + dy;
                if (!keys.contains(x, y) || !isKey(keys.pixel(x, y)))
                    continue;
                const int distance = dx * dx + dy * dy;
                if (best_distance < 0 || distance < best_distance) {
                    best_distance = distance;
                    *seed = QPoint(x, y);
                }
            }
        }
        if (best_distance >= 0)
            return true;
    }
    return false;
}

/**
 * The most frequent key among the pixels bordering @p c, which is the
 * background a text or line is drawn on.  @p seed receives one pixel of it.
 */
bool borderingKey(const KeyImage &keys, const Component &c, QRgb *key, QPoint *seed)
{
    QHash<QRgb, int> counts;
    QHash<QRgb, QPoint> first_seen;
    int best_count = 0;
    for (int y = c.top; y <= c.bottom; ++y) {
        for (int x = c.left; x <= c.right; ++x) {
            if (!c.mask[keys.index(x, y)])
                continue;
            for (int dy = -1; dy <= 1; ++dy) {
                for (int dx = -1; dx <= 1; ++dx) {
                    const int nx = x + dx;
                    const int ny = y + dy;
                    if (!keys.contains(nx, ny) || c.mask[keys.index(nx, ny)])
                        continue;
                    const QRgb rgb = keys.pixel(nx, ny);
                    if (!isKey(rgb))
                        continue;
                    if (!first_seen.contains(rgb))
                        first_seen.insert(rgb, QPoint(nx, ny));
                    const int count = ++counts[rgb];
                    if (count > best_count) {
                        best_count = count;
                        *key = rgb;
                    }
                }
            }
        }
    }
    if (best_count == 0)
        return false;
    *seed = first_seen.value(*key);
    return true;
}

/**
 * The border key of the background region @p c: the most frequent key on
 * the ring of pixels around the region with its holes (texts, inner
 * widgets) filled, accepted only when it covers enough of the ring and
 * forms a thin band there.  A thick neighbor is the parent's background.
 */
bool ringBorderKey(const KeyImage &keys, const Component &c, QRgb *key)
{
    // Work on the bounding box grown by one pixel, clipped to the image.
    const int left = std::max(c.left - 1, 0);
    const int top = std::max(c.top - 1, 0);
    const int right = std::min(c.right + 1, keys.width() - 1);
    const int bottom = std::min(c.bottom + 1, keys.height() - 1);
    const int box_width = right - left + 1;
    const int box_height = bottom - top + 1;
    auto boxIndex = [&](int x, int y) { return (y - top) * box_width + (x - left); };

    // Mark everything reachable from the box edge without crossing the
    // region (4-connected, the dual of the region's 8-connectivity).  What
    // stays unmarked is the region with its holes filled.
    QVector<quint8> outside(box_width * box_height, 0);
    QVector<int> stack;
    auto seedOutside = [&](int x, int y) {
        const int bidx = boxIndex(x, y);
        if (!outside[bidx] && !c.mask[keys.index(x, y)]) {
            outside[bidx] = 1;
            stack.append(bidx);
        }
    };
    for (int x = left; x <= right; ++x) {
        seedOutside(x, top);
        seedOutside(x, bottom);
    }
    for (int y = top; y <= bottom; ++y) {
        seedOutside(left, y);
        seedOutside(right, y);
    }
    static const int kSteps[4][2] = { { 1, 0 }, { -1, 0 }, { 0, 1 }, { 0, -1 } };
    while (!stack.isEmpty()) {
        const int bidx = stack.takeLast();
        const int x = left + bidx % box_width;
        const int y = top + bidx / box_width;
        for (const auto &step : kSteps) {
            const int nx = x + step[0];
            const int ny = y + step[1];
            if (nx < left || ny < top || nx > right || ny > bottom)
                continue;
            seedOutside(nx, ny);
        }
    }
    auto filled = [&](int x, int y) {
        return x >= left && y >= top && x <= right && y <= bottom && !outside[boxIndex(x, y)];
    };

    // The ring: outside pixels next to the filled region.  The direction
    // pointing away from the region is kept for the band thickness test.
    struct RingPixel {
        int x;
        int y;
        int dx;
        int dy;
        QRgb rgb;
    };
    QVector<RingPixel> ring;
    QHash<QRgb, int> counts;
    int best_count = 0;
    for (int y = top; y <= bottom; ++y) {
        for (int x = left; x <= right; ++x) {
            if (filled(x, y))
                continue;
            int out_dx = 0;
            int out_dy = 0;
            bool next_to_region = false;
            for (const auto &step : kSteps) {
                if (filled(x + step[0], y + step[1])) {
                    out_dx = -step[0];
                    out_dy = -step[1];
                    next_to_region = true;
                    break;
                }
            }
            for (int dy = -1; dy <= 1 && !next_to_region; ++dy) {
                for (int dx = -1; dx <= 1 && !next_to_region; ++dx) {
                    if ((dx || dy) && filled(x + dx, y + dy)) {
                        out_dx = -dx;
                        out_dy = -dy;
                        next_to_region = true;
                    }
                }
            }
            if (!next_to_region)
                continue;
            const QRgb rgb = keys.pixel(x, y);
            ring.append({ x, y, out_dx, out_dy, rgb });
            if (rgb == c.key || !isKey(rgb))
                continue;
            const int count = ++counts[rgb];
            if (count > best_count) {
                best_count = count;
                *key = rgb;
            }
        }
    }
    if (best_count == 0 || best_count * 100 < ring.size() * kBorderRingPercent)
        return false;

    int thin = 0;
    for (const RingPixel &p : ring) {
        if (p.rgb != *key)
            continue;
        int band = 0;
        int x = p.x;
        int y = p.y;
        while (band <= kMaxBorderBand && keys.contains(x, y) && keys.pixel(x, y) == *key) {
            ++band;
            x += p.dx;
            y += p.dy;
        }
        if (band <= kMaxBorderBand)
            ++thin;
    }
    return thin * 100 >= best_count * kBorderThinPercent;
}

} // namespace

QColor ThemePreviewPick::keyColor(int key)
{
    Q_ASSERT(key >= 0 && key <= kLinkKey);
    return QColor(key & 0xff, kKeyGreenTag | ((key >> 8) & kKeyGreenBits), kKeyBlue);
}

ThemePreviewPick::Layer ThemePreviewPick::decode(QRgb rgb)
{
    Layer layer;
    if (qAlpha(rgb) != 0xff || qBlue(rgb) != kKeyBlue || (qGreen(rgb) & ~kKeyGreenBits) != kKeyGreenTag)
        return layer;
    const int key = qRed(rgb) | ((qGreen(rgb) & kKeyGreenBits) << 8);
    if (key == kLinkKey) {
        layer.token = ThemeManager::instance()->paletteRoleToken(ThemePaletteBuilder::kLinkSourceRole);
        layer.role = Role::Text;
        layer.link = true;
        return layer;
    }
    if (key == ThemeManager::NoRole || !QMetaEnum::fromType<ThemeManager::ThemeToken>().valueToKey(key))
        return layer;
    layer.token = static_cast<ThemeManager::ThemeToken>(key);
    return layer;
}

ThemePreviewPick::TokenMap ThemePreviewPick::keyTokens()
{
    TokenMap tokens;
    const QMetaEnum meta = QMetaEnum::fromType<ThemeManager::ThemeToken>();
    for (int i = 0; i < meta.keyCount(); ++i) {
        const int value = meta.value(i);
        if (value == ThemeManager::NoRole)
            continue;
        const QColor key = keyColor(value);
        tokens.insert(static_cast<ThemeManager::ThemeToken>(value), ThemeColorPair{ key, key });
    }
    return tokens;
}

QPalette ThemePreviewPick::keyPalette()
{
    const ThemeManager *manager = ThemeManager::instance();
    QPalette palette;
    for (int r = 0; r < QPalette::NColorRoles; ++r) {
        const QPalette::ColorRole role = static_cast<QPalette::ColorRole>(r);
        if (role == QPalette::NoRole)
            continue;
        const ThemeManager::ThemeToken token = manager->paletteRoleToken(role);
        palette.setColor(QPalette::All, role,
                         token == ThemeManager::NoRole ? QColor(Qt::black) : keyColor(token));
    }
    if (manager->paletteRoleToken(QPalette::Link) == ThemeManager::NoRole)
        palette.setColor(QPalette::All, QPalette::Link, keyColor(kLinkKey));
    return palette;
}

QFont ThemePreviewPick::keyFont(const QFont &font)
{
    QFont key_font(font);
    key_font.setStyleStrategy(static_cast<QFont::StyleStrategy>(key_font.styleStrategy() | QFont::NoAntialias));
    return key_font;
}

QImage ThemePreviewPick::keyCanvas(const QSize &size)
{
    QImage image(size, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    return image;
}

ThemePreviewPick::Layer ThemePreviewPick::layerAt(const QImage &keys, const QPoint &pos, int text_height)
{
    const KeyImage image(keys);
    QPoint seed;
    if (!findSeed(image, pos, &seed))
        return Layer();
    Layer layer = decode(image.pixel(seed.x(), seed.y()));
    const Component c = fillComponent(image, seed.x(), seed.y(), text_height, true);
    layer.role = c.complete ? classify(c.width(), c.height(), text_height) : Role::Background;
    return layer;
}

QList<ThemePreviewPick::Layer> ThemePreviewPick::layersAt(const QImage &keys, const QPoint &pos, int text_height)
{
    QList<Layer> layers;
    const KeyImage image(keys);
    QPoint seed;
    if (!findSeed(image, pos, &seed))
        return layers;

    Layer primary = decode(image.pixel(seed.x(), seed.y()));
    const Component c = fillComponent(image, seed.x(), seed.y(), text_height, false);
    primary.role = classify(c.width(), c.height(), text_height);
    layers.append(primary);

    // The region whose border is looked for: the primary when it is a
    // background, else the background under the text or line.
    Component background_region;
    const Component *background = &c;
    if (primary.role != Role::Background) {
        background = nullptr;
        QRgb background_key = 0;
        QPoint background_seed;
        if (borderingKey(image, c, &background_key, &background_seed)) {
            Layer layer = decode(background_key);
            layer.role = Role::Background;
            layers.append(layer);
            background_region = fillComponent(image, background_seed.x(), background_seed.y(), text_height, false);
            background = &background_region;
        }
    }
    QRgb border_key = 0;
    if (background && ringBorderKey(image, *background, &border_key)) {
        Layer layer = decode(border_key);
        layer.role = Role::Border;
        layers.append(layer);
    }

    std::stable_sort(layers.begin(), layers.end(), [](const Layer &a, const Layer &b) {
        return static_cast<int>(a.role) < static_cast<int>(b.role);
    });
    QList<Layer> unique;
    for (const Layer &layer : layers) {
        const bool seen = std::any_of(unique.cbegin(), unique.cend(), [&layer](const Layer &u) {
            return u.token == layer.token;
        });
        if (!seen)
            unique.append(layer);
    }
    return unique;
}

QString ThemePreviewPick::roleName(const Layer &layer)
{
    if (layer.link)
        return tr("Link text");
    switch (layer.role) {
    case Role::Text:
        return tr("Text");
    case Role::Border:
        return tr("Border");
    case Role::Background:
        break;
    }
    return tr("Background");
}

void ThemePreviewPick::saveImage(QWidget *source, const QString &suggested_name,
                                 const std::function<void()> &dialog_closed)
{
    QString fileName = WiresharkFileDialog::getSaveFileName(
        source, tr("Save Theme Preview"),
        suggested_name,
        tr("PNG Image (*.png)"));
    if (dialog_closed)
        dialog_closed();
    if (fileName.isEmpty())
        return;
    // The dialog may return a name without the extension (e.g. the user typed
    // a bare name or "All files" was selected); ensure a .png suffix so the
    // format written below matches the file name.
    if (!fileName.endsWith(QStringLiteral(".png"), Qt::CaseInsensitive))
        fileName += QStringLiteral(".png");

    // grab() repaints into an off-screen pixmap carrying the widget's device
    // pixel ratio, so the saved image is crisp on HiDPI displays.
    const QPixmap pixmap = source->grab();
    if (!pixmap.save(fileName, "PNG")) {
        QMessageBox::warning(source, tr("Save Theme Preview"),
                             tr("Could not write the image to \"%1\".").arg(fileName));
        if (dialog_closed)
            dialog_closed();
    }
}

ThemePreviewPicker::ThemePreviewPicker(QWidget *owner, Render render, TextHeight text_height)
    : owner_(owner),
      render_(std::move(render)),
      text_height_(std::move(text_height))
{
}

void ThemePreviewPicker::setEnabled(bool enabled)
{
    if (enabled_ == enabled)
        return;
    enabled_ = enabled;
    owner_->setMouseTracking(enabled);
    if (!enabled) {
        owner_->unsetCursor();
        image_ = QImage();
        resetHover();
    }
}

void ThemePreviewPicker::invalidate()
{
    image_ = QImage();
    resetHover();
}

void ThemePreviewPicker::setHoverChanged(HoverChanged hover_changed)
{
    hover_changed_ = std::move(hover_changed);
}

void ThemePreviewPicker::resetHover()
{
    const bool had_token = hover_token_;
    hover_token_ = false;
    if (had_token && hover_changed_)
        hover_changed_(ThemePreviewPick::Layer(), QPoint());
}

const QImage &ThemePreviewPicker::keyImage()
{
    if (image_.isNull() || image_.size() != owner_->size())
        image_ = render_();
    return image_;
}

ThemePreviewPick::Layer ThemePreviewPicker::layerAt(const QPoint &pos)
{
    if (!enabled_)
        return ThemePreviewPick::Layer();
    // The text height is read after the render: a sample may measure it on
    // the copy that paints the key image.
    const QImage &keys = keyImage();
    return ThemePreviewPick::layerAt(keys, pos, text_height_());
}

QList<ThemePreviewPick::Layer> ThemePreviewPicker::layersAt(const QPoint &pos)
{
    if (!enabled_)
        return QList<ThemePreviewPick::Layer>();
    const QImage &keys = keyImage();
    return ThemePreviewPick::layersAt(keys, pos, text_height_());
}

bool ThemePreviewPicker::hover(const QPoint &pos)
{
    if (!enabled_)
        return false;
    const ThemePreviewPick::Layer layer = layerAt(pos);
    if (layer.token != ThemeManager::NoRole) {
        owner_->setCursor(Qt::PointingHandCursor);
        hover_token_ = true;
        // Reported on every move, not only on a change: the owner can then
        // move its tooltip with the pointer and show it again after Qt hid
        // it on its own (wheel, key, focus change, expiry).
        if (hover_changed_)
            hover_changed_(layer, owner_->mapToGlobal(pos));
    } else {
        owner_->unsetCursor();
        resetHover();  // reports NoRole once, on the move off a color
    }
    return true;
}

bool ThemePreviewPicker::isPickClick(const QMouseEvent *event) const
{
    return enabled_ && event->button() == Qt::LeftButton;
}
