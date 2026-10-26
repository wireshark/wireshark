/* zoom_scaling.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <ui/qt/utils/zoom_scaling.h>

#include <QRegularExpression>
#include <QWidget>
#include <QtMath>

int ZoomScaling::scaledPixels(int px, qreal factor)
{
    if (px == 0)
        return 0;
    return qMax(1, qRound(px * factor));
}

int ZoomScaling::scaledSizeLimit(int design, qreal factor)
{
    if (design > 1 && design < QWIDGETSIZE_MAX)
        return scaledPixels(design, factor);
    return design;
}

// Scales the size component of a "font:" / "font-size:" value: px and pt
// tokens, whatever their size (a 1px font is still a font).
static QString scaleFontValue(const QString &value, qreal factor)
{
    // A size token (the only px/pt token inside a font value).
    static const QRegularExpression sizeRe(
        QStringLiteral("([0-9]+(?:\\.[0-9]+)?)(px|pt)"));

    QString scaledValue;
    scaledValue.reserve(value.size());
    qsizetype vlast = 0;
    auto vit = sizeRe.globalMatch(value);
    while (vit.hasNext()) {
        const QRegularExpressionMatch vm = vit.next();
        scaledValue += value.mid(vlast, vm.capturedStart() - vlast);
        const double scaled = vm.captured(1).toDouble() * factor;
        scaledValue += QStringLiteral("%1%2")
                           .arg(qMax(1, qRound(scaled)))
                           .arg(vm.captured(2));
        vlast = vm.capturedEnd();
    }
    scaledValue += value.mid(vlast);
    return scaledValue;
}

// Qt stylesheets only support absolute px/pt units (no relative em/%), so
// themed text and the lengths around it (heights, radii, padding, margins,
// sizes) are scaled by the current zoom factor here to follow the rest of
// the UI:
//  - the size in "font:" / "font-size:" values, px and pt, always;
//  - every other "Npx" length in a declaration, through
//    ZoomScaling::scaledPixels(), except 0 and 1 (resets and hairline
//    borders keep their value).
// Text inside comments and url(...) is left alone.  No-op at zoom level 0
// (factor 1.0).
QString ZoomScaling::scaleStyleSheetLengths(const QString &qss, qreal factor)
{
    if (qFuzzyCompare(factor, qreal(1.0)))
        return qss;

    // One pass over the text; the alternatives are tried in this order at
    // each position.  The optional "-size" of the font property is anchored
    // to ':' so this never matches font-weight/-family/etc.
    static const QRegularExpression tokenRe(
        QStringLiteral("(/\\*.*?\\*/|url\\([^)]*\\))"                 // 1: kept as is
                       "|\\bfont(?:-size)?\\s*:\\s*([^;}]*)"           // 2: font value
                       "|\\b([0-9]+(?:\\.[0-9]+)?)px\\b"),             // 3: other length
        QRegularExpression::DotMatchesEverythingOption);

    QString out;
    out.reserve(qss.size());
    qsizetype last = 0;
    auto it = tokenRe.globalMatch(qss);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        if (m.capturedStart(1) >= 0)
            continue;   // comment or url(): copied with the next gap

        if (m.capturedStart(2) >= 0) {
            out += qss.mid(last, m.capturedStart(2) - last);
            out += scaleFontValue(m.captured(2), factor);
            last = m.capturedEnd(2);
            continue;
        }

        const int px = qRound(m.captured(3).toDouble());
        if (px <= 1)
            continue;
        out += qss.mid(last, m.capturedStart(3) - last);
        out += QStringLiteral("%1px").arg(scaledPixels(px, factor));
        last = m.capturedEnd(0);
    }
    out += qss.mid(last);
    return out;
}
