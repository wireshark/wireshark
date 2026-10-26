/* collapsible_section.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "collapsible_section.h"

#include <QFont>
#include <QHBoxLayout>
#include <QSplitter>
#include <QSizePolicy>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/zoom_scaling.h>

CollapsibleSection::CollapsibleSection(const QString &title, QWidget *parent)
    : QWidget(parent), savedHeight(100)
{
    // Toggle button with arrow indicator
    toggleButton = new QToolButton(this);
    toggleButton->setStyleSheet(
        QStringLiteral("QToolButton { border: none; font-weight: bold; }"));
    toggleButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toggleButton->setArrowType(Qt::ArrowType::RightArrow);
    toggleButton->setText(title);
    toggleButton->setCheckable(true);
    toggleButton->setChecked(false);
    toggleButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Horizontal line after header
    headerLine = new QFrame(this);
    headerLine->setFrameShape(QFrame::HLine);
    headerLine->setFrameShadow(QFrame::Sunken);
    headerLine->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Header layout: title, rule, then optional trailing (see setHeaderTrailingWidget)
    headerLayout_ = new QHBoxLayout();
    headerLayout_->setContentsMargins(0, 0, 0, 0);
    headerLayout_->setSpacing(4);
    ZoomScaling::scaleLayoutMetrics(headerLayout_);
    headerLayout_->addWidget(toggleButton, 0, Qt::AlignVCenter);
    headerLayout_->addWidget(headerLine, 1, Qt::AlignVCenter);

    /* Wrap headerLayout_ in a fixed-height container so the row size is
     * driven by titleH_ rather than by the (variable) max child sizeHint.
     * This is what stops the HLine from drifting on toggle. */
    headerContainer_ = new QWidget(this);
    headerContainer_->setLayout(headerLayout_);
    headerContainer_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Content area - initially hidden
    contentArea = new QWidget(this);
    contentArea->setVisible(false);
    contentArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(2);
    ZoomScaling::scaleLayoutMetrics(mainLayout);
    mainLayout->addWidget(headerContainer_);
    mainLayout->addWidget(contentArea, 1);

    applyTitleMetrics();

    /* Size policy in splitter: Expanding-Y so an expanded section actively
     * pulls surplus vertical space rather than leaving it unallocated; when
     * collapsed, setMaximumHeight(headerHeight()) in onToggle still caps the
     * section at hh regardless of policy. */
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    /* Use clicked (not toggled): clicked is only emitted on user interaction,
     * while toggled also fires on programmatic setChecked(). setExpanded()
     * already calls onToggle() explicitly after setChecked(), so a toggled
     * connection would invoke onToggle() twice. */
    connect(toggleButton, &QToolButton::clicked, this,
            &CollapsibleSection::onToggle);

    /* The title font and the title row height derive from the application
     * font and the zoom level, so measure and pin them again when either
     * changes. */
    connect(FontManager::instance(), &FontManager::applicationFontChanged, this,
            &CollapsibleSection::refreshTitleMetrics);
    connect(FontManager::instance(), &FontManager::zoomChanged, this,
            &CollapsibleSection::refreshTitleMetrics);
}

void CollapsibleSection::applyTitleMetrics()
{
    QFont font(FontManager::zoomedFont());
    font.setBold(true);
    toggleButton->setFont(font);

    /* Cache the title row height from the sizeHint with RightArrow and use
     * it to pin headerContainer_. The platform style's
     * sizeFromContents(CT_ToolButton) consults opt.arrowType, so a live
     * sizeHint() varies by 1-2px between RightArrow and DownArrow; pinning
     * the container at this fixed value keeps the header row, the HLine
     * (AlignVCenter), and headerHeight()/titleButtonHeight() stable. */
    const Qt::ArrowType arrow = toggleButton->arrowType();
    toggleButton->setArrowType(Qt::ArrowType::RightArrow);
    titleH_ = toggleButton->sizeHint().height();
    toggleButton->setArrowType(arrow);

    headerContainer_->setFixedHeight(titleH_);
    if (headerTrailingWidget_)
    {
        headerTrailingWidget_->setFixedHeight(titleH_);
    }
}

void CollapsibleSection::refreshTitleMetrics()
{
    applyTitleMetrics();
    if (!toggleButton->isChecked())
    {
        setMinimumHeight(titleH_);
        setMaximumHeight(titleH_);
    }
    emit titleMetricsChanged();
}

void CollapsibleSection::setContentWidget(QWidget *contentWidget)
{
    // Remove old layout if exists
    if (contentArea->layout())
    {
        QLayoutItem *item;
        while ((item = contentArea->layout()->takeAt(0)) != nullptr)
        {
            delete item->widget();
            delete item;
        }
        delete contentArea->layout();
    }

    // Create new layout with the content widget
    QVBoxLayout *layout = new QVBoxLayout(contentArea);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(contentWidget);
}

void CollapsibleSection::setHeaderTrailingWidget(QWidget *widget)
{
    if (headerTrailingWidget_)
    {
        headerLayout_->removeWidget(headerTrailingWidget_);
        delete headerTrailingWidget_;
        headerTrailingWidget_ = nullptr;
    }
    if (widget)
    {
        headerTrailingWidget_ = widget;
        widget->setParent(this);
        /* One line only: do not let controls force a taller header than the title. */
        widget->setFixedHeight(titleButtonHeight());
        widget->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
        /* Match vertical centering of the title, rule, and toggle row. */
        headerLayout_->addWidget(widget, 0, Qt::AlignVCenter);
    }
}

void CollapsibleSection::setExpanded(bool expanded)
{
    toggleButton->setChecked(expanded);
    onToggle(expanded);
}

bool CollapsibleSection::isExpanded() const
{
    return toggleButton->isChecked();
}

void CollapsibleSection::setTitle(const QString &title)
{
    toggleButton->setText(title);
}

int CollapsibleSection::headerHeight() const
{
    /* Stable across toggles: see titleH_ docs and constructor for why we
     * cache instead of calling toggleButton->sizeHint().height() live. */
    return titleH_;
}

int CollapsibleSection::titleButtonHeight() const
{
    return titleH_;
}

QFont CollapsibleSection::titleButtonFont() const
{
    return toggleButton->font();
}

void CollapsibleSection::onToggle(bool checked)
{
    toggleButton->setArrowType(checked ? Qt::ArrowType::DownArrow
                                       : Qt::ArrowType::RightArrow);

    // Find parent splitter to adjust sizes
    QSplitter *splitter = qobject_cast<QSplitter *>(parentWidget());

    if (checked)
    {
        // Expanding
        contentArea->setVisible(true);
        setMinimumHeight(0);
        setMaximumHeight(QWIDGETSIZE_MAX);

        if (splitter)
        {
            int idx = splitter->indexOf(this);
            if (idx >= 0)
            {
                QList<int> sizes = splitter->sizes();
                // Restore saved height or use reasonable default
                sizes[idx] = qMax(savedHeight, headerHeight() + 50);
                splitter->setSizes(sizes);
            }
        }
    }
    else
    {
        // Collapsing - save current height first
        if (splitter)
        {
            int idx = splitter->indexOf(this);
            if (idx >= 0)
            {
                QList<int> sizes = splitter->sizes();
                if (sizes[idx] > headerHeight())
                {
                    savedHeight = sizes[idx];
                }
            }
        }

        contentArea->setVisible(false);
        int hh = headerHeight();
        setMinimumHeight(hh);
        setMaximumHeight(hh);
    }

    emit toggled(checked);
}
