/* traffic_table_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "traffic_table_dialog.h"
#include <ui_traffic_table_dialog.h>

#include <epan/addr_resolv.h>
#include <epan/prefs.h>

#include "ui/recent.h"

#include "progress_frame.h"
#include "main_application.h"

#include <ui/qt/widgets/traffic_tab.h>
#include <ui/qt/widgets/traffic_types_list.h>

#include <QCheckBox>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDialogButtonBox>
#include <QList>
#include <QMap>
#include <QMessageBox>
#include <QPushButton>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTextStream>
#include <QToolButton>
#include <QTreeView>

// To do:
// - Add "copy" items to the menu.

// Bugs:
// - Tabs and menu items don't always end up in the same order.
// - Columns don't resize correctly.
// - Closing the capture file clears conversation data.

TrafficTableDialog::TrafficTableDialog(QWidget &parent, CaptureFile &cf, const QString &table_name) :
    WiresharkDialog(parent, cf),
    ui(new Ui::TrafficTableDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width(), parent.height() * 3 / 4);

    ui->absoluteTimeCheckBox->hide();
    setWindowSubtitle(QString("%1s").arg(table_name));
    ui->grpSettings->setTitle(QString("%1 Settings").arg(table_name));

    copy_bt_ = buttonBox()->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    copy_bt_->setMenu(ui->trafficTab->createCopyMenu(copy_bt_));

    ui->trafficTab->setFocus();
    ui->trafficTab->useNanosecondTimestamps(cf.timestampPrecision() == WTAP_TSPREC_NSEC);
    connect(ui->trafficList, &TrafficTypesList::protocolsChanged, ui->trafficTab, &TrafficTab::setOpenTabs);
    connect(ui->trafficTab, &TrafficTab::tabsChanged, ui->trafficList, &TrafficTypesList::selectProtocols);

    connect(mainApp, SIGNAL(addressResolutionChanged()), this, SLOT(currentTabChanged()));
    connect(ui->trafficTab, SIGNAL(currentChanged(int)), this, SLOT(currentTabChanged()));
    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)), this, SLOT(captureEvent(CaptureEvent)));

    connect(ui->absoluteTimeCheckBox, &QCheckBox::toggled, ui->trafficTab, &TrafficTab::useAbsoluteTime);
    connect(ui->trafficTab, &TrafficTab::retapRequired, &cap_file_, &CaptureFile::delayedRetapPackets);

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt)
        close_bt->setDefault(true);

    addProgressFrame(&parent);
}

TrafficTableDialog::~TrafficTableDialog()
{
    delete ui;
}

void TrafficTableDialog::addProgressFrame(QObject *parent)
{
    ProgressFrame::addToButtonBox(ui->buttonBox, parent);
}

QDialogButtonBox *TrafficTableDialog::buttonBox() const
{
    return ui->btnBoxSettings;
}

QCheckBox *TrafficTableDialog::displayFilterCheckBox() const
{
    return ui->displayFilterCheckBox;
}

QCheckBox *TrafficTableDialog::absoluteTimeCheckBox() const
{
    return ui->absoluteTimeCheckBox;
}

TrafficTab *TrafficTableDialog::trafficTab() const
{
    return ui->trafficTab;
}

TrafficTypesList *TrafficTableDialog::trafficList() const
{
    return ui->trafficList;
}

void TrafficTableDialog::currentTabChanged()
{
    bool has_resolution = ui->trafficTab->hasNameResolution();
    copy_bt_->setMenu(ui->trafficTab->createCopyMenu(copy_bt_));

    ui->nameResolutionCheckBox->setEnabled(has_resolution);
    if (! has_resolution) {
        ui->nameResolutionCheckBox->setChecked(false);
        ui->trafficTab->setNameResolution(false);
    }
}

void TrafficTableDialog::on_nameResolutionCheckBox_toggled(bool checked)
{
    ui->trafficTab->setNameResolution(checked);
}

void TrafficTableDialog::on_displayFilterCheckBox_toggled(bool checked)
{
    if (!cap_file_.isValid()) {
        return;
    }

    if (checked)
        trafficTab()->setFilter(cap_file_.capFile()->dfilter);
    else
        trafficTab()->setFilter(QString());

    cap_file_.retapPackets();
}

void TrafficTableDialog::captureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap)
    {
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            ui->displayFilterCheckBox->setEnabled(false);
            break;
        case CaptureEvent::Finished:
            ui->displayFilterCheckBox->setEnabled(true);
            break;
        default:
            break;
        }
    }

}
