/* plot_theme.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/utils/plot_theme.h"

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>
#include <ui/qt/widgets/qcustomplot.h>

namespace {

QPen recolored(const QPen &pen, const QColor &color)
{
    QPen p(pen);
    p.setColor(color);
    return p;
}

} // namespace

QColor PlotTheme::textColor()
{
    return ThemeManager::instance()->color(ThemeManager::PaletteText);
}

void PlotTheme::applyToAxis(QCPAxis *axis)
{
    if (!axis) {
        return;
    }

    ThemeManager *tm = ThemeManager::instance();
    const QColor base = tm->color(ThemeManager::PaletteBase);
    const QColor text = tm->color(ThemeManager::PaletteText);
    const QColor border = tm->color(ThemeManager::FieldBorder);
    const QColor grid = ColorMath::mix(base, text, 0.22);

    axis->setBasePen(recolored(axis->basePen(), text));
    axis->setTickPen(recolored(axis->tickPen(), text));
    axis->setSubTickPen(recolored(axis->subTickPen(), text));
    axis->setLabelColor(text);
    axis->setTickLabelColor(text);

    QCPGrid *g = axis->grid();
    g->setPen(recolored(g->pen(), grid));
    g->setSubGridPen(recolored(g->subGridPen(), grid));
    if (g->zeroLinePen().style() != Qt::NoPen) {
        g->setZeroLinePen(recolored(g->zeroLinePen(), border));
    }
}

void PlotTheme::apply(QCustomPlot *plot)
{
    if (!plot) {
        return;
    }

    ThemeManager *tm = ThemeManager::instance();
    const QColor base = tm->color(ThemeManager::PaletteBase);
    const QColor text = tm->color(ThemeManager::PaletteText);
    const QColor border = tm->color(ThemeManager::FieldBorder);

    plot->setBackground(QBrush(base));

    for (QCPAxisRect *rect : plot->axisRects()) {
        for (QCPAxis *axis : rect->axes()) {
            applyToAxis(axis);
        }
    }

    if (plot->legend) {
        plot->legend->setBrush(QBrush(base));
        plot->legend->setBorderPen(recolored(plot->legend->borderPen(), border));
        plot->legend->setTextColor(text);
    }

    const QList<QCPLayoutElement *> elements = plot->plotLayout()->elements(true);
    for (QCPLayoutElement *element : elements) {
        if (QCPTextElement *title = qobject_cast<QCPTextElement *>(element)) {
            title->setTextColor(text);
        }
    }
}

void PlotTheme::track(QCustomPlot *plot, std::function<void()> afterApply)
{
    if (!plot) {
        return;
    }

    auto refresh = [plot, afterApply]() {
        apply(plot);
        if (afterApply) {
            afterApply();
        }
        plot->replot();
    };

    refresh();
    QObject::connect(ThemeManager::instance(), &ThemeManager::themeChanged, plot, refresh);
}
