/* native_title_bar_mac.mm
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * NativeTitleBar backend for macOS.  A transparent title bar lets AppKit
 * draw the title bar strip in the window background color.
 */

#include "ui/qt/utils/themes/native_title_bar.h"

#include <QEvent>
#include <QMainWindow>
#include <QOperatingSystemVersion>
#include <QPainter>
#include <QWidget>
#include <QWindow>

#import <AppKit/AppKit.h>

namespace {

// The window's own titlebarAppearsTransparent from before the first tint.
// A unified main window has a transparent title bar of its own (Qt sets it
// for unifiedTitleAndToolBarOnMac), which a reset must give back.
const char *const nativeTransparentProperty = "_ws_title_bar_native_transparent";

#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
const char *const stripPainterName = "_ws_title_bar_strip_painter";

// Before macOS 26 Qt puts a titlebar-material effect view behind the title
// bar and unified toolbars of a main window with
// unifiedTitleAndToolBarOnMac, above the NSWindow background, and the
// window itself is translucent, so the title bar strip shows that material
// instead of the tint.  This filter fills the strip, the window's top safe
// area margin, before the window paints itself.  Qt paints the toolbars
// below it in the same palette color.
class UnifiedStripPainter : public QObject
{
public:
    UnifiedStripPainter(QWidget *window, const QColor &color)
        : QObject(window), color_(color)
    {
        setObjectName(QString::fromLatin1(stripPainterName));
        window->installEventFilter(this);
        // The strip height follows the title bar, for example when the
        // window enters or leaves full screen.  The QWindow signal is used
        // because it is documented to fire on the window itself.
        if (QWindow *handle = window->windowHandle()) {
            connect(handle, &QWindow::safeAreaMarginsChanged, this,
                    [window]() { window->update(); });
        }
    }

    void setColor(const QColor &color)
    {
        color_ = color;
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (event->type() == QEvent::Paint) {
            QWidget *window = static_cast<QWidget *>(watched);
            const int top = window->windowHandle()
                    ? window->windowHandle()->safeAreaMargins().top() : 0;
            if (top > 0) {
                QPainter painter(window);
                painter.fillRect(QRect(0, 0, window->width(), top), color_);
            }
        }
        return false;
    }

private:
    QColor color_;
};

bool needsStripPainter(const QWidget *window)
{
    const QMainWindow *mainWindow = qobject_cast<const QMainWindow *>(window);
    return mainWindow && mainWindow->unifiedTitleAndToolBarOnMac()
            && QOperatingSystemVersion::current()
                   < QOperatingSystemVersion(QOperatingSystemVersion::MacOS, 26);
}

// Installs, recolors or (invalid color) removes the strip painter.
void updateStripPainter(QWidget *window, const QColor &color)
{
    QObject *existing = window->findChild<QObject *>(QString::fromLatin1(stripPainterName),
                                                     Qt::FindDirectChildrenOnly);
    if (!color.isValid() || !needsStripPainter(window)) {
        if (existing) {
            delete existing;
            window->update();
        }
        return;
    }
    if (existing)
        static_cast<UnifiedStripPainter *>(existing)->setColor(color);
    else
        new UnifiedStripPainter(window, color);
    window->update();
}
#else
void updateStripPainter(QWidget *, const QColor &)
{
    // The strip is the expanded client area Qt 6.9 introduced for unified
    // main windows; older Qt is not handled.
}
#endif

} // namespace

bool NativeTitleBar::isSupported()
{
    return true;
}

bool NativeTitleBar::applyNative(QWidget *window, const Style &style)
{
    // For a top-level widget winId() is its NSView; the widget is created,
    // so this does not create anything.
    NSView *view = reinterpret_cast<NSView *>(window->winId());
    NSWindow *nsWindow = view.window;
    if (!nsWindow)
        return false;

    if (!style.background.isValid()) {
        const QVariant saved = window->property(nativeTransparentProperty);
        nsWindow.titlebarAppearsTransparent = saved.isValid() && saved.toBool() ? YES : NO;
        window->setProperty(nativeTransparentProperty, QVariant());
        nsWindow.backgroundColor = [NSColor windowBackgroundColor];
        nsWindow.appearance = nil;
        updateStripPainter(window, QColor());
        return true;
    }

    if (!window->property(nativeTransparentProperty).isValid())
        window->setProperty(nativeTransparentProperty, nsWindow.titlebarAppearsTransparent == YES);

    // Qt draws the window content in the window's color space; using the
    // same space for the title bar avoids a seam against the toolbar below.
    NSColorSpace *space = nsWindow.colorSpace;
    if (!space || space.colorSpaceModel != NSColorSpaceModelRGB)
        space = [NSColorSpace sRGBColorSpace];
    const CGFloat components[] = {
        static_cast<CGFloat>(style.background.redF()),
        static_cast<CGFloat>(style.background.greenF()),
        static_cast<CGFloat>(style.background.blueF()),
        1.0
    };
    nsWindow.backgroundColor = [NSColor colorWithColorSpace:space components:components count:4];
    nsWindow.titlebarAppearsTransparent = YES;

    // Before macOS 26 a unified main window covers this background with
    // Qt's titlebar material; updateStripPainter() paints over it.

    // AppKit takes the title text color from the window appearance alone,
    // light or dark.  A per-window appearance also switches every native
    // control in the window, so override it only when the title bar color
    // disagrees with the appearance the application renders in.
    NSAppearanceName appName = [NSApp.effectiveAppearance bestMatchFromAppearancesWithNames:
            @[NSAppearanceNameAqua, NSAppearanceNameDarkAqua]];
    const bool appDark = [appName isEqualToString:NSAppearanceNameDarkAqua];
    if (style.darkBackground == appDark) {
        nsWindow.appearance = nil;
    } else {
        nsWindow.appearance = [NSAppearance appearanceNamed:
                style.darkBackground ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua];
    }
    updateStripPainter(window, style.background);
    return true;
}
