/* zoom_scaling_test.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// Regression test for ZoomScaling (Qt Core and the QtWidgets headers, no
// QApplication).
//
// qt_zoom_scaling_test
//     runs the built-in case table.
// qt_zoom_scaling_test <factor> <file>...
//     additionally scales every file (UTF-8 stylesheet) by <factor> and fails
//     on a doubled or glued unit ("Npxpx") or a changed length token count.

#include <config.h>

#include <ui/qt/utils/zoom_scaling.h>

#include <cstdio>

#include <QFile>
#include <QRegularExpression>
#include <QString>
#include <QWidget>

namespace {

struct StyleSheetCase {
    const char *input;
    qreal factor;
    const char *expected;
};

const StyleSheetCase styleSheetCases[] = {
    { "border-radius: 4px; padding: 3px 9px;", 1.21,
      "border-radius: 5px; padding: 4px 11px;" },
    { "padding: 2px 8px;", 1.21, "padding: 2px 10px;" },
    { "border: 1px solid red; margin: 0px;", 1.21,
      "border: 1px solid red; margin: 0px;" },
    { "font-size: 9px;", 1.21, "font-size: 11px;" },
    { "font: bold 12pt \"Sans\";", 1.21, "font: bold 15pt \"Sans\";" },
    { "/* padding: 8px */ background: url(:/a_10px.png); min-height: 64px;", 1.21,
      "/* padding: 8px */ background: url(:/a_10px.png); min-height: 77px;" },
    { "border-radius: 4px; padding: 3px 9px;", 1.0,
      "border-radius: 4px; padding: 3px 9px;" },
};

struct PixelCase {
    int px;
    qreal factor;
    int expected;
};

const PixelCase pixelCases[] = {
    { 0, 1.21, 0 },
    { 1, 0.5, 1 },
    { 14, 1.21, 17 },
};

struct SizeLimitCase {
    int design;
    qreal factor;
    int expected;
};

const SizeLimitCase sizeLimitCases[] = {
    { 0, 1.21, 0 },
    { 1, 1.21, 1 },
    { QWIDGETSIZE_MAX, 1.21, QWIDGETSIZE_MAX },
    { 40, 1.21, 48 },
    { 3, 0.5, 2 },
};

bool runCaseTable()
{
    bool ok = true;

    for (const StyleSheetCase &c : styleSheetCases) {
        const QString actual = ZoomScaling::scaleStyleSheetLengths(
            QString::fromUtf8(c.input), c.factor);
        if (actual != QString::fromUtf8(c.expected)) {
            fprintf(stderr, "FAIL scaleStyleSheetLengths(factor %g)\n"
                            "  input:    %s\n  expected: %s\n  actual:   %s\n",
                    c.factor, c.input, c.expected, qPrintable(actual));
            ok = false;
        }
    }

    for (const PixelCase &c : pixelCases) {
        const int actual = ZoomScaling::scaledPixels(c.px, c.factor);
        if (actual != c.expected) {
            fprintf(stderr, "FAIL scaledPixels(%d, %g): expected %d, actual %d\n",
                    c.px, c.factor, c.expected, actual);
            ok = false;
        }
    }

    for (const SizeLimitCase &c : sizeLimitCases) {
        const int actual = ZoomScaling::scaledSizeLimit(c.design, c.factor);
        if (actual != c.expected) {
            fprintf(stderr, "FAIL scaledSizeLimit(%d, %g): expected %d, actual %d\n",
                    c.design, c.factor, c.expected, actual);
            ok = false;
        }
    }

    return ok;
}

bool checkFile(const QString &path, qreal factor)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        fprintf(stderr, "FAIL cannot read %s\n", qPrintable(path));
        return false;
    }
    const QString input = QString::fromUtf8(file.readAll());
    const QString output = ZoomScaling::scaleStyleSheetLengths(input, factor);

    static const QRegularExpression gluedUnitRe(QStringLiteral("[0-9]px[A-Za-z]"));
    static const QRegularExpression tokenRe(
        QStringLiteral("\\b[0-9]+(\\.[0-9]+)?(px|pt)\\b"));

    bool ok = true;
    if (output.contains(gluedUnitRe)) {
        fprintf(stderr, "FAIL %s: doubled or glued unit after scaling\n",
                qPrintable(path));
        ok = false;
    }
    const qsizetype inCount = input.count(tokenRe);
    const qsizetype outCount = output.count(tokenRe);
    if (inCount != outCount) {
        fprintf(stderr, "FAIL %s: %lld length tokens before, %lld after scaling\n",
                qPrintable(path), static_cast<long long>(inCount),
                static_cast<long long>(outCount));
        ok = false;
    }
    return ok;
}

} // namespace

int main(int argc, char *argv[])
{
    bool ok = runCaseTable();

    if (argc > 1) {
        bool factorOk = false;
        const double factor = QString::fromLocal8Bit(argv[1]).toDouble(&factorOk);
        if (!factorOk || factor <= 0.0) {
            fprintf(stderr, "usage: %s [<factor> <file>...]\n", argv[0]);
            return 2;
        }
        for (int i = 2; i < argc; i++) {
            if (!checkFile(QString::fromLocal8Bit(argv[i]), factor))
                ok = false;
        }
    }

    return ok ? 0 : 1;
}
