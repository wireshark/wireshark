/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_PREVIEW_PICK_H
#define THEME_PREVIEW_PICK_H

#include <ui/qt/utils/theme_manager.h>

#include <QColor>
#include <QCoreApplication>
#include <QFont>
#include <QHash>
#include <QImage>
#include <QList>
#include <QPalette>
#include <QPoint>
#include <QSize>
#include <QString>

#include <functional>

class QMouseEvent;
class QWidget;

/**
 * Shared support for picking theme colors by clicking a Theme Designer
 * sample.
 *
 * A sample finds out which theme token painted a pixel by rendering a
 * second, never shown copy of itself into an image ("key render").  That
 * copy is themed with keyTokens() and keyPalette(): every token gets its
 * own unique opaque key color, so each pixel of the key image names the
 * token that painted it.  The sample's own paint code and Qt's style sheet
 * cascade decide the token; nothing here mirrors that logic.  Fonts of the
 * copy go through keyFont() so text is drawn without antialiasing and glyph
 * pixels keep their exact key.
 *
 * Text, background and border of one spot are told apart from the shape of
 * the key regions around the pixel (see layerAt() and layersAt()), so a
 * single key image is enough.
 *
 * The class also holds the "Save Image As..." flow shared by the samples.
 */
class ThemePreviewPick
{
    Q_DECLARE_TR_FUNCTIONS(ThemePreviewPick)
public:
    /** What part of a spot a color paints. */
    enum class Role { Text, Background, Border };

    /** One theme color found at a spot of a sample. */
    struct Layer {
        ThemeManager::ThemeToken token = ThemeManager::NoRole;
        Role role = Role::Background;
        bool link = false;   ///< Painted with QPalette::Link, which follows token.
    };

    using TokenMap = QHash<ThemeManager::ThemeToken, ThemeColorPair>;

    /**
     * The key value QPalette::Link gets in keyPalette().  Link has no token
     * of its own; it is derived from ThemePaletteBuilder::kLinkSourceRole.
     */
    static constexpr int kLinkKey = 0x3fff;

    /**
     * The opaque key color of @p key.
     *
     * @param key  a ThemeManager::ThemeToken value, or kLinkKey.
     */
    static QColor keyColor(int key);

    /**
     * The token a key image pixel names.
     *
     * @return the layer; its token is NoRole when @p rgb is not a key color.
     *         The role is Text for the link key, else Background.
     */
    static Layer decode(QRgb rgb);

    /** Every token but NoRole, mapped to its key color on both sides. */
    static TokenMap keyTokens();

    /**
     * A palette for the key render: each role with a Palette<Role> token
     * gets that token's key color in all groups, Link gets kLinkKey when it
     * has no token, and every other role is opaque black (never a key).
     */
    static QPalette keyPalette();

    /** @p font with antialiasing turned off, for the key render. */
    static QFont keyFont(const QFont &font);

    /**
     * A blank, transparent image of @p size for a key render.  It is
     * premultiplied because CoreGraphics cannot paint native style elements
     * into non-premultiplied ARGB images; key decoding only reads opaque
     * pixels, which are the same in both formats.
     */
    static QImage keyCanvas(const QSize &size);

    /**
     * The color a click at @p pos picks: the token of the pixel, or of the
     * nearest key pixel within 2 pixels, and whether it paints text, a
     * border line or a background.
     *
     * @param keys         the key image.
     * @param pos          position in @p keys.
     * @param text_height  tallest line height of the key fonts, in image pixels.
     * @return the layer; its token is NoRole when no key is near @p pos.
     */
    static Layer layerAt(const QImage &keys, const QPoint &pos, int text_height);

    /**
     * All colors of the spot at @p pos: the picked color (layerAt()), the
     * background under a text or line, and the border around a background.
     *
     * @return the layers ordered Text, Background, Border, no token twice;
     *         empty when no key is near @p pos.
     */
    static QList<Layer> layersAt(const QImage &keys, const QPoint &pos, int text_height);

    /** The translated role word: "Text", "Background", "Border" or "Link text". */
    static QString roleName(const Layer &layer);

    /**
     * Asks for a file name and saves a PNG image of @p source.
     *
     * @param source          the widget to grab; also the dialogs' parent.
     * @param suggested_name  file name proposed in the save dialog.
     * @param dialog_closed   called each time a dialog of this flow closes,
     *                        so the caller can restore focus or state; may
     *                        be empty.
     */
    static void saveImage(QWidget *source, const QString &suggested_name,
                          const std::function<void()> &dialog_closed);
};

/**
 * Pick state of one Theme Designer sample: the cached key image, the hand
 * cursor and the lookups.  Each sample owns one and keeps only what differs
 * between samples: how its key image is rendered and how tall its key fonts
 * are.
 *
 * The key image is rendered on demand and kept until invalidate() is called
 * or the owner's size changes.  Owners call invalidate() when something that
 * shapes the key render changes (fonts, visible content), not on color
 * changes: the key render has its own fixed key colors.
 */
class ThemePreviewPicker
{
public:
    /** Renders the owner's key image at the owner's current size. */
    using Render = std::function<QImage()>;
    /** Tallest line height of the key fonts, in image pixels; called after Render. */
    using TextHeight = std::function<int()>;

    /**
     * Called on every mouse move over a color, and once with a NoRole
     * layer when the pointer leaves all colors, the sample, or picking
     * goes off.
     *
     * @param layer       the layer under the pointer, or NoRole.
     * @param global_pos  the pointer in global coordinates; null for NoRole
     *                    reports from resetHover().
     */
    using HoverChanged = std::function<void(const ThemePreviewPick::Layer &layer, const QPoint &global_pos)>;

    /**
     * @param owner        the sample; gets mouse tracking and the cursor.
     * @param render       renders the key image of @p owner.
     * @param text_height  tallest line height of the key fonts.
     */
    ThemePreviewPicker(QWidget *owner, Render render, TextHeight text_height);

    /**
     * Turns picking on or off.  Off (the default) turns mouse tracking off,
     * restores the arrow cursor and drops the key image.
     */
    void setEnabled(bool enabled);

    /** Whether picking is on. */
    bool isEnabled() const { return enabled_; }

    /**
     * Marks the key image stale; the next lookup renders it again.  Also
     * resetHover(), as the spot under the pointer may now be another color.
     */
    void invalidate();

    /** Sets the function called when the hovered layer changes; may be empty. */
    void setHoverChanged(HoverChanged hover_changed);

    /**
     * Forgets the hover.  When the last move was over a color, the hover
     * function gets a NoRole layer, so the owner can hide what it shows;
     * the next mouse move reports the layer again.
     */
    void resetHover();

    /** ThemePreviewPick::layerAt() on the key image; token NoRole when off. */
    ThemePreviewPick::Layer layerAt(const QPoint &pos);

    /** ThemePreviewPick::layersAt() on the key image; empty when off. */
    QList<ThemePreviewPick::Layer> layersAt(const QPoint &pos);

    /**
     * Mouse move handling: a hand cursor over a pickable spot, else the
     * arrow.  Reports the layer under the pointer to the hover function
     * (see setHoverChanged()).
     *
     * @return false when picking is off, so the owner passes the event on.
     */
    bool hover(const QPoint &pos);

    /** Whether @p event is a click that picks: picking on, left button. */
    bool isPickClick(const QMouseEvent *event) const;

private:
    /** The key image, rendered again when null or of another size than the owner. */
    const QImage &keyImage();

    QWidget *owner_;
    Render render_;
    TextHeight text_height_;
    bool enabled_ = false;
    QImage image_;
    bool hover_token_ = false;  // The last move was over a color
    HoverChanged hover_changed_;

    Q_DISABLE_COPY_MOVE(ThemePreviewPicker)
};

#endif // THEME_PREVIEW_PICK_H
