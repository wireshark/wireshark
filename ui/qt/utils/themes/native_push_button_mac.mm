/* native_push_button_mac.mm
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Draws AppKit's flexible-height rounded push bezel for push buttons that
 * are taller than the native bezel.  Qt's macOS style maps such buttons to
 * a flat square bezel; NSBezelStyleFlexiblePush is the rounded push bezel
 * AppKit itself uses for buttons of any height.
 *
 * Qt's helper that wraps a QPainter in a CoreGraphics context is private
 * QtGui API, so the bezel is rendered into an offscreen QImage through a
 * CGBitmapContext with the same memory layout and then painted.
 */

#include "ui/qt/utils/themes/native_push_button.h"

#include <QImage>
#include <QPaintDevice>
#include <QPainter>
#include <QRect>
#include <QRectF>
#include <QWidget>

#include <cmath>

#import <AppKit/AppKit.h>

namespace {

// One button for the whole process, created on first use and never
// released, like the cell cache of Qt's macOS style.  GUI thread only.
NSButton *flexibleButton()
{
    static NSButton *button = nil;
    if (!button) {
        button = [[NSButton alloc] initWithFrame:NSZeroRect];
        button.buttonType = NSButtonTypeMomentaryPushIn;
        // The macOS 14 SDK renamed NSBezelStyleRegularSquare to
        // NSBezelStyleFlexiblePush; both are the same value (2), the
        // variable-height rounded push bezel.
#if defined(MAC_OS_VERSION_14_0)
        button.bezelStyle = NSBezelStyleFlexiblePush;
#else
        button.bezelStyle = NSBezelStyleRegularSquare;
#endif
        button.title = @"";
        button.controlSize = NSControlSizeRegular;
        // Layer backing keeps the temporary subview from marking the
        // window's backing-store view dirty while a paint event runs.
        button.wantsLayer = YES;
    }
    return button;
}

/*
 * Renders the cached button with @p draw into an offscreen image covering
 * the button frame for @p visibleRect (with @p withFocusRing also the focus
 * ring mask bounds) and paints that image with @p painter.
 *
 * The button is added as subview of the window's native view for the
 * draw, as Qt's macOS style does, so AppKit draws it with the window's
 * effective appearance and key state.
 */
template<typename DrawFunction>
bool renderButton(QPainter *painter, const QRect &visibleRect, const QWidget *widget,
                  bool withFocusRing, DrawFunction draw)
{
    if (!painter || !widget || visibleRect.isEmpty())
        return false;

    // effectiveWinId() never creates a native window from inside a paint.
    const WId hostId = widget->window()->effectiveWinId();
    if (!hostId)
        return false;
    NSView *host = reinterpret_cast<NSView *>(hostId);

    bool drawn = false;
    @autoreleasepool {
        NSButton *pb = flexibleButton();
        // AppKit knows its own shadow and alignment insets per macOS
        // version; map the wanted visible outline to the button frame.
        const NSRect frame = [pb frameForAlignmentRect:visibleRect.toCGRect()];
        pb.frame = frame;
        pb.wantsLayer = YES;
        [host addSubview:pb];

        QRectF renderArea = QRectF::fromCGRect(frame);
        if (withFocusRing)
            renderArea |= QRectF::fromCGRect([pb.cell focusRingMaskBoundsForFrame:frame inView:pb]);
        const QRect renderRect = renderArea.toAlignedRect();

        const qreal dpr = painter->device() ? painter->device()->devicePixelRatioF() : 1.0;
        QImage image(static_cast<int>(std::ceil(renderRect.width() * dpr)),
                     static_cast<int>(std::ceil(renderRect.height() * dpr)),
                     QImage::Format_ARGB32_Premultiplied);
        CGContextRef ctx = nullptr;
        if (!renderRect.isEmpty() && !image.isNull()) {
            image.fill(Qt::transparent);
            CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
            ctx = CGBitmapContextCreate(image.bits(), image.width(), image.height(), 8,
                                        image.bytesPerLine(), colorSpace,
                                        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Host);
            CGColorSpaceRelease(colorSpace);
        }

        if (ctx) {
            // Top-left origin in device pixels, then logical coordinates
            // of the painter with the render rect at the image origin.
            CGContextTranslateCTM(ctx, 0, image.height());
            CGContextScaleCTM(ctx, 1, -1);
            CGContextScaleCTM(ctx, dpr, dpr);
            CGContextTranslateCTM(ctx, -renderRect.x(), -renderRect.y());

            [NSGraphicsContext saveGraphicsState];
            [NSGraphicsContext setCurrentContext:
                [NSGraphicsContext graphicsContextWithCGContext:ctx flipped:YES]];
            draw(pb, frame);
            [NSGraphicsContext restoreGraphicsState];
            CGContextRelease(ctx);
            drawn = true;
        }

        // A plain removeFromSuperview could mark the window view dirty
        // from inside a paint event and cause a repaint loop.
        [pb removeFromSuperviewWithoutNeedingDisplay];

        if (drawn) {
            image.setDevicePixelRatio(dpr);
            painter->drawImage(renderRect.topLeft(), image);
        }
    }
    return drawn;
}

} // namespace

namespace NativePushButton {

bool drawFlexibleBezel(QPainter *painter, const QRect &visibleRect,
                       const BezelState &state, const QWidget *widget)
{
    return renderButton(painter, visibleRect, widget, false,
                        [&state](NSButton *pb, const NSRect &frame) {
        pb.enabled = state.enabled ? YES : NO;
        // The return key equivalent gives the accent fill of the default
        // button, as in Qt's own push button drawing.
        pb.keyEquivalent = state.highlighted ? @"\r" : @"";
        [pb highlight:state.pressed ? YES : NO];
        [pb.cell drawBezelWithFrame:frame inView:pb];
        // The button is shared; leave no state behind.
        [pb highlight:NO];
    });
}

bool drawFocusRing(QPainter *painter, const QRect &visibleRect,
                   const QWidget *widget)
{
    return renderButton(painter, visibleRect, widget, true,
                        [](NSButton *pb, const NSRect &frame) {
        // AppKit draws its ring around the bezel shape the cell masks out,
        // in the system focus color.
        NSSetFocusRingStyle(NSFocusRingOnly);
        [pb.cell drawFocusRingMaskWithFrame:frame inView:pb];
    });
}

} // namespace NativePushButton
