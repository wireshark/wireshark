/* welcome_page_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "welcome_page_preferences_frame.h"
#include <ui_welcome_page_preferences_frame.h>

#include <ui/recent.h>

WelcomePagePreferencesFrame::WelcomePagePreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::WelcomePagePreferencesFrame)
{
    ui->setupUi(this);

    connect(ui->learnVisibleCheckBox, &QCheckBox::toggled, this, &WelcomePagePreferencesFrame::learnVisibleToggled);
    connect(ui->tipsVisibleCheckBox, &QCheckBox::toggled, this, &WelcomePagePreferencesFrame::tipsVisibleToggled);
    connect(ui->tipsEventsCheckBox, &QCheckBox::toggled, this, &WelcomePagePreferencesFrame::tipsEventsToggled);
    connect(ui->tipsSponsorshipCheckBox, &QCheckBox::toggled, this, &WelcomePagePreferencesFrame::tipsSponsorshipToggled);
    connect(ui->tipsTipsCheckBox, &QCheckBox::toggled, this, &WelcomePagePreferencesFrame::tipsTipsToggled);
    connect(ui->tipsIntervalSpinBox, qOverload<int>(&QSpinBox::valueChanged), this, &WelcomePagePreferencesFrame::tipsIntervalValueChanged);
    connect(ui->restoreButtonBox, &QDialogButtonBox::clicked, this, &WelcomePagePreferencesFrame::restoreButtonBoxClicked);

    stashed_learn_visible_ = recent.gui_welcome_page_sidebar_learn_visible;
    stashed_tips_visible_ = recent.gui_welcome_page_sidebar_tips_visible;
    stashed_tips_events_ = recent.gui_welcome_page_sidebar_tips_events;
    stashed_tips_sponsorship_ = recent.gui_welcome_page_sidebar_tips_sponsorship;
    stashed_tips_tips_ = recent.gui_welcome_page_sidebar_tips_tips;
    stashed_tips_interval_ = recent.gui_welcome_page_sidebar_tips_interval;

    ui->learnVisibleCheckBox->setChecked(stashed_learn_visible_);
    ui->tipsVisibleCheckBox->setChecked(stashed_tips_visible_);
    ui->tipsEventsCheckBox->setChecked(stashed_tips_events_);
    ui->tipsSponsorshipCheckBox->setChecked(stashed_tips_sponsorship_);
    ui->tipsTipsCheckBox->setChecked(stashed_tips_tips_);
    ui->tipsIntervalSpinBox->setValue(static_cast<int>(stashed_tips_interval_));

    updateTipsSubCheckboxes();
}

WelcomePagePreferencesFrame::~WelcomePagePreferencesFrame()
{
    delete ui;
}

void WelcomePagePreferencesFrame::unstash()
{
    recent.gui_welcome_page_sidebar_learn_visible = stashed_learn_visible_;
    recent.gui_welcome_page_sidebar_tips_visible = stashed_tips_visible_;
    recent.gui_welcome_page_sidebar_tips_events = stashed_tips_events_;
    recent.gui_welcome_page_sidebar_tips_sponsorship = stashed_tips_sponsorship_;
    recent.gui_welcome_page_sidebar_tips_tips = stashed_tips_tips_;
    recent.gui_welcome_page_sidebar_tips_interval = stashed_tips_interval_;
}

void WelcomePagePreferencesFrame::updateTipsSubCheckboxes()
{
    bool tips_enabled = ui->tipsVisibleCheckBox->isChecked();
    ui->tipsEventsCheckBox->setEnabled(tips_enabled);
    ui->tipsSponsorshipCheckBox->setEnabled(tips_enabled);
    ui->tipsTipsCheckBox->setEnabled(tips_enabled);
}

void WelcomePagePreferencesFrame::learnVisibleToggled(bool checked)
{
    stashed_learn_visible_ = checked;
}

void WelcomePagePreferencesFrame::tipsVisibleToggled(bool checked)
{
    stashed_tips_visible_ = checked;
    ui->tipsSlidesSectionLayout->setEnabled(checked);
    updateTipsSubCheckboxes();
}

void WelcomePagePreferencesFrame::tipsEventsToggled(bool checked)
{
    stashed_tips_events_ = checked;
}

void WelcomePagePreferencesFrame::tipsSponsorshipToggled(bool checked)
{
    stashed_tips_sponsorship_ = checked;
}

void WelcomePagePreferencesFrame::tipsTipsToggled(bool checked)
{
    stashed_tips_tips_ = checked;
}

void WelcomePagePreferencesFrame::tipsIntervalValueChanged(int value)
{
    stashed_tips_interval_ = static_cast<unsigned>(value);
}

void WelcomePagePreferencesFrame::restoreButtonBoxClicked(QAbstractButton *)
{
    stashed_learn_visible_ = true;
    stashed_tips_visible_ = true;
    stashed_tips_events_ = true;
    stashed_tips_sponsorship_ = true;
    stashed_tips_tips_ = true;
    stashed_tips_interval_ = 8;

    ui->learnVisibleCheckBox->setChecked(stashed_learn_visible_);
    ui->tipsVisibleCheckBox->setChecked(stashed_tips_visible_);
    ui->tipsEventsCheckBox->setChecked(stashed_tips_events_);
    ui->tipsSponsorshipCheckBox->setChecked(stashed_tips_sponsorship_);
    ui->tipsTipsCheckBox->setChecked(stashed_tips_tips_);
    ui->tipsIntervalSpinBox->setValue(static_cast<int>(stashed_tips_interval_));

    updateTipsSubCheckboxes();
}
