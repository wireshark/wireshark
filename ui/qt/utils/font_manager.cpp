/* font_manager.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include <config.h>

#include "ui/qt/utils/font_manager.h"

#include <ui/qt/main_application.h>

#include <epan/prefs.h>
#include <epan/wmem_scopes.h>

#include <wsutil/wmem/wmem.h>
#include <wsutil/wslog.h>

#include <ui/recent.h>

#include <QApplication>
#include <QEvent>
#include <QFontDatabase>
#include <QFontInfo>
#include <QPointer>
#include <QStringList>
#include <QStyle>
#include <QWidget>
#include <QtMath>

FontManager *FontManager::instance_{nullptr};
QMutex       FontManager::mutex_;

// --------------------------------------------------------------------
// Per-class platform fonts
// --------------------------------------------------------------------

// The widget classes Qt gives their own platform font, as
// QPlatformTheme::Font enumerator and widget font hash key.  Copied from Qt's
// QApplicationPrivate::initializeWidgetFontHash() (Qt 6.12), which is private
// and cannot be enumerated.  test/suite_qt_fonts.py checks this table against
// the enumerators in qpa/qplatformtheme.h, so a Qt change is caught.
struct PlatformClassFont {
    const char *platformFont;
    const char *className;
};

static const PlatformClassFont platform_class_fonts[] = {
    { "MenuFont", "QMenu" },
    { "MenuBarFont", "QMenuBar" },
    { "MenuItemFont", "QMenuItem" },
    { "MessageBoxFont", "QMessageBox" },
    { "LabelFont", "QLabel" },
    { "TipLabelFont", "QTipLabel" },
    { "TitleBarFont", "QTitleBar" },
    { "StatusBarFont", "QStatusBar" },
    { "MdiSubWindowTitleFont", "QMdiSubWindowTitleBar" },
    { "DockWidgetTitleFont", "QDockWidgetTitle" },
    { "PushButtonFont", "QPushButton" },
    { "CheckBoxFont", "QCheckBox" },
    { "RadioButtonFont", "QRadioButton" },
    { "ToolButtonFont", "QToolButton" },
    { "ItemViewFont", "QAbstractItemView" },
    { "ListViewFont", "QListView" },
    { "HeaderViewFont", "QHeaderView" },
    { "ListBoxFont", "QListBox" },
    { "ComboMenuItemFont", "QComboMenuItem" },
    { "ComboLineEditFont", "QComboLineEdit" },
    { "SmallFont", "QSmallFont" },
    { "MiniFont", "QMiniFont" },
};

// Point size of @p font, also for a font that was specified in pixels.
static qreal pointSizeOf(const QFont &font)
{
    qreal pt = font.pointSizeF();
    if (pt <= 0)
        pt = QFontInfo(font).pointSizeF();
    return pt;
}

static qreal roundToHalfPoint(qreal pt)
{
    return qRound(pt * 2) / qreal(2.0);
}

// Calls @p fn for every widget that exists now and is still alive when its
// turn comes.  QApplication::allWidgets() returns raw pointers, and an
// event or a polish sent to one widget can run code that deletes other
// widgets synchronously (a layout rebuilt on a resize or a theme change),
// so each entry is held in a QPointer and the deleted ones are skipped.
// Widgets created during the walk are not visited.
template <typename Fn>
static void forEachLiveWidget(Fn fn)
{
    const QWidgetList widgets = QApplication::allWidgets();
    QList<QPointer<QWidget>> live;
    live.reserve(widgets.size());
    for (QWidget *widget : widgets)
        live.append(widget);

    for (const QPointer<QWidget> &widget : std::as_const(live)) {
        if (widget)
            fn(widget.data());
    }
}

// The style metrics follow the zoom factor, but widgets keep what they
// derived from them (size hints, layouts, the style sheet style's rules
// per widget).  Polish every polished widget again and send it
// StyleChange, as QApplication::setStyleSheet() does, but without walking
// the style sheet style's cache of raw widget pointers, which can hold a
// widget deleted in the meantime.  Widgets that were never polished get
// the current metrics when they are first shown.
static void repolishWidgets()
{
    forEachLiveWidget([](QWidget *widget) {
        if (!widget->testAttribute(Qt::WA_WState_Polished))
            return;
        const QPointer<QWidget> guard(widget);
        widget->style()->polish(widget);
        if (!guard)
            return;
        QEvent event(QEvent::StyleChange);
        QCoreApplication::sendEvent(widget, &event);
    });
}

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

    // Start from sane system defaults; ThemeManager replaces these via
    // setRegularFont()/setMonospaceFont() during the first theme load.
    base_regular_   = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
    base_monospace_ = guaranteeMonospace(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    base_platform_general_ = base_regular_;
    last_system_general_   = base_regular_;

    if (qApp) {
        // Capture the per-class platform fonts before anything calls
        // QApplication::setFont(), which discards them.  QApplication::font()
        // returns the application font for a key the platform did not set,
        // so an absent key cannot be told from one equal to the general
        // font.  Both cases matter: re-pushing an absent key would shadow a
        // superclass entry (QTipLabel under QLabel), and dropping a present
        // one would expose it.  So the application font is set to a font no
        // platform reports, every key is read, and the font is restored.
        // QGuiApplication::setFont() keeps the per-class table, unlike
        // QApplication::setFont().  Side effect: Qt marks the application
        // font as explicitly set and no longer replaces it on a platform
        // theme change.  Qt replaced it silently there, without an event, and
        // any font push sets the same flag anyway, so the ThemeChange handler
        // in eventFilter() adopts OS font changes instead.
        const QFont previous = QGuiApplication::font();
        const QFont probe(QStringLiteral("Wireshark class font probe"), 1);
        QGuiApplication::setFont(probe);
        for (const PlatformClassFont &entry : platform_class_fonts) {
            const QFont class_font = QApplication::font(entry.className);
            if (class_font == probe)
                continue;
            base_class_fonts_.append(qMakePair(QByteArray(entry.className), class_font));
            ws_debug("Platform class font %s (%s): %s, %.1f pt", entry.platformFont, entry.className,
                     qUtf8Printable(class_font.family()), pointSizeOf(class_font));
        }
        QGuiApplication::setFont(previous);
        ws_debug("Platform general font: %s, %.1f pt", qUtf8Printable(base_platform_general_.family()),
                 pointSizeOf(base_platform_general_));

        // Catch external (OS) font changes.  See eventFilter().
        qApp->installEventFilter(this);
    }

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
    const qreal base = pointSizeOf(self->base_regular_);
    if (base <= 0)
        return qreal(1.0);
    return pointSizeOf(self->zoomed(self->base_regular_)) / base;
}

QFont FontManager::scaledFont(const QFont &base)
{
    return instance()->zoomed(base);
}

// --------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------

void FontManager::setRegularFont(const QString &fontName)
{
    const QFont resolved = themeFont(fontName, false);

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

    const QFont resolved = prefName.isEmpty()
        ? themeFont(fontName, true)
        : preferenceMonospaceFont(fontFromName(prefName));

    const QString prev = base_monospace_.toString();
    base_monospace_    = resolved;

    if (base_monospace_.toString() != prev)
        emit monospaceFontChanged(zoomed(base_monospace_));
}

QFont FontManager::themeFont(const QString &fontName, bool monospace)
{
    const QFont font = fontName.isEmpty()
        ? QFontDatabase::systemFont(monospace ? QFontDatabase::FixedFont
                                              : QFontDatabase::GeneralFont)
        : fontFromName(fontName);
    return monospace ? guaranteeMonospace(font) : font;
}

QFont FontManager::preferenceMonospaceFont(const QFont &font)
{
    // The Fonts preferences page can list every family, so a family the
    // user picked is applied as chosen. The fallback is only for a family
    // that is missing, or a fixed-pitch family that Qt matched to a
    // proportional face.
    const QString family = font.family();
    if (QFontDatabase::hasFamily(family) && !QFontDatabase::isFixedPitch(family)) {
        return font;
    }
    return guaranteeMonospace(font);
}

// --------------------------------------------------------------------
// Zoom
// --------------------------------------------------------------------

void FontManager::zoomIn()       { setZoomLevel(zoom_level_ + 1); }
void FontManager::zoomOut()      { setZoomLevel(zoom_level_ - 1); }
void FontManager::resetZoom()    { setZoomLevel(0); }

void FontManager::setZoomLevel(int level)
{
    level = qBound(MinZoomLevel, level, MaxZoomLevel);
    // Store it even when it is unchanged, so a stored or command line
    // level out of range is written back clamped.
    recent.gui_zoom_level = level;
    if (level == zoom_level_)
        return;

    zoom_level_ = level;
    applyZoom();
}

void FontManager::restoreZoomLevel()
{
    setZoomLevel(recent.gui_zoom_level);
}

void FontManager::applyZoom()
{
    // AppWide pushes the zoomed regular onto qApp (chrome scales); ContentOnly
    // leaves qApp at the base size (applyApplicationFont is then a no-op).
    applyApplicationFont();
    emit applicationFontChanged(zoomed(base_regular_));
    emit monospaceFontChanged(zoomed(base_monospace_));
    // Let every widget re-read the zoom-scaled style metrics before the
    // zoomChanged receivers measure size hints.
    repolishWidgets();
    // Stylesheet font sizes and lengths are scaled at load time by the zoom
    // factor, so ask stylesheet consumers to reload (ThemeManager re-emits
    // themeChanged).
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

    // Scale by 10% per level, rounding to the nearest half point, min 1pt.
    // (Formula preserved from the former MainApplication::zoomTextFont.)
    qreal zoom_size = roundToHalfPoint(pointSizeOf(base) * qPow(qreal(1.1), zoom_level_));
    zoom_size = qMax(zoom_size, qreal(1.0));

    QFont f = base;
    f.setPointSizeF(zoom_size);
    return f;
}

QFont FontManager::classFont(const QFont &platformClass) const
{
    // Unchanged platform general font: the platform class font as it is.
    if (base_regular_ == base_platform_general_)
        return platformClass;

    // A theme, preference or OS change set another regular font: use it for
    // the class too, keeping only the platform's size ratio between the
    // class and the general font.
    QFont f = base_regular_;
    const qreal general_pt = pointSizeOf(base_platform_general_);
    const qreal class_pt = pointSizeOf(platformClass);
    const qreal regular_pt = pointSizeOf(base_regular_);
    if (general_pt > 0 && class_pt > 0 && regular_pt > 0) {
        f.setPointSizeF(qMax(roundToHalfPoint(regular_pt * class_pt / general_pt), qreal(1.0)));
    }
    return f;
}

void FontManager::applyApplicationFont(bool force)
{
    if (!qApp)
        return;

    const QFont desired = applicationFont();
    // Only push when it differs, to avoid a redundant ApplicationFontChange.
    const bool general_changed = qApp->font().toString() != desired.toString();
    if (!general_changed && !force)
        return;

    // Without a class name this also clears Qt's per-class font table.
    if (general_changed)
        qApp->setFont(desired);

    for (const QPair<QByteArray, QFont> &entry : std::as_const(base_class_fonts_)) {
        const QFont class_font = classFont(entry.second);
        QApplication::setFont((zoom_scope_ == ZoomScope::AppWide) ? zoomed(class_font) : class_font,
                              entry.first.constData());
    }

    // A per-class push only notifies non-window widgets that inherit the
    // class.  Open menus and tool tips are windows, and the macOS small and
    // mini fonts match no class, so they would keep the general font from
    // the push above.  Let every widget resolve its font again.
    forEachLiveWidget([](QWidget *widget) {
        QEvent event(QEvent::ApplicationFontChange);
        QCoreApplication::sendEvent(widget, &event);
    });
}

void FontManager::adoptRegularFont(const QFont &font)
{
    base_regular_ = font;
    reapplyApplicationFonts();
    emit applicationFontChanged(zoomed(base_regular_));
}

void FontManager::reapplyApplicationFonts()
{
    applyApplicationFont(true);
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
        cleanFont.setStyle(QFont::StyleNormal);
    }

    return cleanFont;
}

// --------------------------------------------------------------------
// External / OS font-change handling
// --------------------------------------------------------------------

bool FontManager::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == qApp && event->type() == QEvent::ThemeChange) {
        // Qt does not adopt a new OS font once the application font was set
        // (see the constructor), so read it from the platform here.  A
        // light/dark switch sends the same event with an unchanged font.
        const QFont system_general = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
        if (system_general != last_system_general_) {
            last_system_general_ = system_general;
            if (!regular_overridden_) {
                adoptRegularFont(system_general);
            }
        }
    }

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
                adoptRegularFont(qApp->font());
            }
        }
    }
    return QObject::eventFilter(watched, event);
}
