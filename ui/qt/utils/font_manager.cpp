/* font_manager.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/font_manager.h"

#include <ui/qt/main_application.h>

#include <epan/prefs.h>
#include <epan/wmem_scopes.h>

#include <wsutil/wmem/wmem.h>

#include <ui/recent.h>

#include <QApplication>
#include <QEvent>
#include <QFontDatabase>
#include <QFontInfo>
#include <QStringList>
#include <QtMath>

FontManager *FontManager::instance_{nullptr};
QMutex       FontManager::mutex_;

// --------------------------------------------------------------------
// File-local helpers (moved here from theme_parser.cpp, where the font
// resolution policy used to live).
// --------------------------------------------------------------------

static QStringList monospaceFallbacks()
{
#if defined(Q_OS_MACOS)
    return QStringList() << "SF Mono" << "Menlo" << "Monaco" << "Courier New";
#elif defined(Q_OS_WIN)
    return QStringList() << "Cascadia Mono" << "Cascadia Code" << "Consolas" << "Lucida Console" << "Courier New";
#else // Linux / X11 / other Unix
    return QStringList() << "DejaVu Sans Mono" << "Liberation Mono" << "Noto Sans Mono" << "Ubuntu Mono"
                         << "Bitstream Vera Sans Mono" << "FreeMono";
#endif
}

// --------------------------------------------------------------------
// Singleton plumbing
// --------------------------------------------------------------------

FontManager *FontManager::instance()
{
    QMutexLocker locker(&mutex_);
    if (instance_ == nullptr) {
        instance_ = new FontManager();
    }
    return instance_;
}

FontManager::FontManager(QObject *parent)
    : QObject(parent)
{
    // v1: fixed here.  v2 replaces this with a preference read.
    zoom_scope_ = ZoomScope::AppWide;

    // Seed the zoom level from the recent file (the persisted state of
    // record).  No listeners exist yet at construction time, so we only
    // store the value — applying it happens when the first font is set.
    zoom_level_ = recent.gui_zoom_level;

    // Start from sane system defaults; ThemeManager replaces these via
    // setRegularFont()/setMonospaceFont() during the first theme load.
    base_regular_   = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
    base_monospace_ = guaranteeMonospace(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    // Catch external (OS) application-font changes.  See eventFilter().
    if (qApp)
        qApp->installEventFilter(this);

    // Mirror the resolved monospace font into prefs.gui_font_name once the
    // app is up, so the preferences dialog and anything else reading the
    // pref see a concrete value.  Previously done by a lambda in
    // ThemeManager's constructor.
    if (mainApp) {
        mainApp->whenInitialized(this, [this]() { syncMonospacePref(); });
    }
}

FontManager::~FontManager()
{
    instance_ = nullptr;
}

// --------------------------------------------------------------------
// Static value accessors
// --------------------------------------------------------------------

QFont FontManager::font()
{
    return instance()->base_regular_;
}

QFont FontManager::monospaceFont()
{
    return instance()->base_monospace_;
}

QFont FontManager::zoomedFont()
{
    FontManager *self = instance();
    return self->zoomed(self->base_regular_);
}

QFont FontManager::zoomedMonospaceFont()
{
    FontManager *self = instance();
    return self->zoomed(self->base_monospace_);
}

qreal FontManager::zoomFactor()
{
    FontManager *self = instance();
    qreal base = self->base_regular_.pointSizeF();
    if (base <= 0)
        base = QFontInfo(self->base_regular_).pointSizeF();
    if (base <= 0)
        return qreal(1.0);
    return self->zoomed(self->base_regular_).pointSizeF() / base;
}

// --------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------

void FontManager::setRegularFont(const QString &fontName)
{
    const QFont resolved = fontName.isEmpty()
        ? QFontDatabase::systemFont(QFontDatabase::GeneralFont)
        : fontFromName(fontName);

    const QString prev = base_regular_.toString();
    base_regular_       = resolved;
    regular_overridden_ = !fontName.isEmpty();

    // Always reconcile the QApplication font (cheap no-op if already
    // current); only signal on a real change.
    applyApplicationFont();
    if (base_regular_.toString() != prev)
        emit applicationFontChanged(zoomed(base_regular_));
}

void FontManager::setMonospaceFont(const QString &fontName)
{
    // The user preference gui.font_name ALWAYS wins when set; otherwise the
    // name handed in by ThemeManager; otherwise the system fixed font.
    const QString prefName = prefs.gui_font_name
        ? QString::fromUtf8(prefs.gui_font_name) : QString();

    QFont resolved;
    if (!prefName.isEmpty())
        resolved = fontFromName(prefName);
    else if (!fontName.isEmpty())
        resolved = fontFromName(fontName);
    else
        resolved = QFontDatabase::systemFont(QFontDatabase::FixedFont);

    resolved = guaranteeMonospace(resolved);

    const QString prev = base_monospace_.toString();
    base_monospace_    = resolved;

    if (base_monospace_.toString() != prev)
        emit monospaceFontChanged(zoomed(base_monospace_));
}

// --------------------------------------------------------------------
// Zoom
// --------------------------------------------------------------------

void FontManager::zoomIn()       { setZoomLevel(zoom_level_ + 1); }
void FontManager::zoomOut()      { setZoomLevel(zoom_level_ - 1); }
void FontManager::resetZoom()    { setZoomLevel(0); }

void FontManager::setZoomLevel(int level)
{
    if (level == zoom_level_)
        return;

    zoom_level_ = level;
    recent.gui_zoom_level = level;   // keep the persisted state in sync
    applyZoom();
}

void FontManager::applyZoom()
{
    // AppWide pushes the zoomed regular onto qApp (chrome scales); ContentOnly
    // leaves qApp at the base size (applyApplicationFont is then a no-op).
    applyApplicationFont();
    emit applicationFontChanged(zoomed(base_regular_));
    emit monospaceFontChanged(zoomed(base_monospace_));
    // Stylesheet font sizes are scaled at load time by the zoom factor, so ask
    // stylesheet consumers to reload (ThemeManager re-emits themeChanged).
    emit zoomChanged();
}

// --------------------------------------------------------------------
// Internals
// --------------------------------------------------------------------

QFont FontManager::applicationFont() const
{
    return (zoom_scope_ == ZoomScope::AppWide) ? zoomed(base_regular_)
                                               : base_regular_;
}

QFont FontManager::zoomed(const QFont &base) const
{
    if (zoom_level_ == 0)
        return base;

    qreal basePt = base.pointSizeF();
    if (basePt <= 0)
        basePt = QFontInfo(base).pointSizeF();

    // Scale by 10% per level, rounding to the nearest half point, min 1pt.
    // (Formula preserved from the former MainApplication::zoomTextFont.)
    qreal zoom_size = basePt * 2 * qPow(qreal(1.1), zoom_level_);
    zoom_size = qRound(zoom_size) / qreal(2.0);
    zoom_size = qMax(zoom_size, qreal(1.0));

    QFont f = base;
    f.setPointSizeF(zoom_size);
    return f;
}

void FontManager::applyApplicationFont()
{
    if (!qApp)
        return;

    const QFont desired = applicationFont();
    // Only push when it differs, to avoid a redundant ApplicationFontChange.
    if (qApp->font().toString() != desired.toString())
        qApp->setFont(desired);
}

void FontManager::syncMonospacePref()
{
    wmem_free(wmem_epan_scope(), prefs.gui_font_name);
    prefs.gui_font_name = wmem_strdup(wmem_epan_scope(),
                                      base_monospace_.toString().toUtf8().constData());
}

QFont FontManager::fontFromName(const QString &name)
{
    QFont f;

    // A QFont descriptor string (QFont::toString()) is comma-separated; a
    // bare family name is not.
    if (name.contains(QLatin1Char(','))) {
        QString trimmedName(name.trimmed());
#if QT_VERSION < QT_VERSION_CHECK(6, 11, 0)
        // Qt 6.11 added two extra attributes to the comma separated list.
        // https://doc.qt.io/qt-6/qfont.html#toString
        // https://doc.qt.io/qt-6.10/qfont.html#toString
        // On earlier versions, strip any attributes after 17.
        const auto parts = name.trimmed().split(QLatin1Char(','));
        constexpr qsizetype maxAttributes = 17;
        const qsizetype size = parts.size();

        if (size > maxAttributes) {
            // QList.first is Qt 6.0
            trimmedName = parts.mid(0, maxAttributes).join(QLatin1Char(','));
        }
#endif
        f.fromString(trimmedName);
    } else if (!name.isEmpty()) {
        f.setFamily(name);
    }

    return f;
}

QFont FontManager::guaranteeMonospace(const QFont &font)
{
    QFont cleanFont = font;

    // On some systems (Linux in particular) Qt may hand back a non-
    // fixed-pitch font when asked for the monospace face.  Force a
    // known-good fallback in that case.
    if (!QFontInfo(cleanFont).fixedPitch()) {
        cleanFont.setFamilies(monospaceFallbacks());
        cleanFont.setStyleHint(QFont::Monospace);
    }

    cleanFont.setStyle(QFont::StyleNormal);

    return cleanFont;
}

// --------------------------------------------------------------------
// External / OS font-change handling
// --------------------------------------------------------------------

bool FontManager::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == qApp && event->type() == QEvent::ApplicationFontChange) {
        const QFont desired = applicationFont();
        // If qApp's font matches what we want, this is our own push (or a
        // coincidental no-op) — ignore it.  Otherwise the OS/Qt changed the
        // application font from outside.
        if (qApp->font().toString() != desired.toString()) {
            if (regular_overridden_) {
                // A theme/pref explicitly set the regular font; re-assert it
                // over the OS change.
                applyApplicationFont();
            } else {
                // Adopt the external change as the new base regular, then
                // re-apply zoom on top of it.
                base_regular_ = qApp->font();
                applyApplicationFont();
                emit applicationFontChanged(zoomed(base_regular_));
            }
        }
    }
    return QObject::eventFilter(watched, event);
}
