/* expert_info_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "expert_info_dialog.h"
#include <ui_expert_info_dialog.h>

#include "file.h"

#include <epan/epan_dissect.h>
#include <epan/expert.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>

#include "main_application.h"

#include <QAction>
#include <QHash>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>

// To do:
// - Test with custom expert levels (Preferences -> Expert).
// - Test with large captures.
// - Promote to a fourth pane in the main window?
// - Make colors configurable? In theory we could condense image/expert_indicators.svg,
//   down to one item, make sure it uses a single (or a few) base color(s), and generate
//   icons on the fly.

ExpertInfoDialog::ExpertInfoDialog(QWidget &parent, CaptureFile &capture_file, QString displayFilter) :
    WiresharkDialog(parent, capture_file),
    ui(new Ui::ExpertInfoDialog),
    expert_info_model_(new ExpertInfoModel(capture_file)),
    proxyModel_(new ExpertInfoProxyModel(this)),
    display_filter_(displayFilter)
{
    ui->setupUi(this);

    proxyModel_->setSourceModel(expert_info_model_);
    ui->expertInfoTreeView->setModel(proxyModel_);

    setWindowSubtitle(tr("Expert Information"));

    // Clicking on an item jumps to its associated packet. Make the dialog
    // narrow so that we avoid obscuring the packet list.
    int dlg_width = parent.width() * 3 / 5;
    if (dlg_width < width()) dlg_width = width();
    loadGeometry(dlg_width, parent.height());

    int one_em = fontMetrics().height();
    ui->expertInfoTreeView->setColumnWidth(ExpertInfoProxyModel::colProxySummary, one_em * 25); // Arbitrary

    //Unfortunately this has to be done manually and not through .ui
    ui->severitiesPushButton->setMenu(ui->menuShowExpert);

    ui->expertInfoTreeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->expertInfoTreeView, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showExpertInfoMenu(QPoint)));

    QMenu *submenu;

    FilterAction::Action cur_action = FilterAction::ActionApply;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    cur_action = FilterAction::ActionPrepare;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    FilterAction *fa;
    QList<FilterAction::Action> extra_actions =
            QList<FilterAction::Action>() << FilterAction::ActionFind
                                          << FilterAction::ActionColorize
                                          << FilterAction::ActionWebLookup
                                          << FilterAction::ActionCopy;

    foreach (FilterAction::Action extra_action, extra_actions) {
        fa = new FilterAction(&ctx_menu_, extra_action);
        ctx_menu_.addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    //Add collapse/expand all menu options
    QAction *collapse = new QAction(tr("Collapse All"), this);
    ctx_menu_.addAction(collapse);
    connect(collapse, SIGNAL(triggered()), this, SLOT(collapseTree()));

    QAction *expand = new QAction(tr("Expand All"), this);
    ctx_menu_.addAction(expand);
    connect(expand, SIGNAL(triggered()), this, SLOT(expandTree()));

    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)),
            this, SLOT(captureEvent(CaptureEvent)));

    updateWidgets();
    QTimer::singleShot(0, this, SLOT(retapPackets()));
}

ExpertInfoDialog::~ExpertInfoDialog()
{
    delete ui;
    delete proxyModel_;
    delete expert_info_model_;
}

void ExpertInfoDialog::clearAllData()
{
    expert_info_model_->clear();
}

ExpertInfoTreeView* ExpertInfoDialog::getExpertInfoView()
{
    return ui->expertInfoTreeView;
}

void ExpertInfoDialog::retapPackets()
{
    if (file_closed_) return;

    clearAllData();
    removeTapListeners();

    if (!registerTapListener("expert",
                             expert_info_model_,
                             ui->limitCheckBox->isChecked() ? display_filter_.toUtf8().constData(): NULL,
                             TL_REQUIRES_COLUMNS,
                             ExpertInfoModel::tapReset,
                             ExpertInfoModel::tapPacket,
                             ExpertInfoModel::tapDraw)) {
        return;
    }

    cap_file_.retapPackets();
}

void ExpertInfoDialog::captureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap)
    {
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            ui->limitCheckBox->setEnabled(false);
            ui->groupBySummaryCheckBox->setEnabled(false);
            break;
        case CaptureEvent::Finished:
            updateWidgets();
            break;
        default:
            break;
        }
    }
}

void ExpertInfoDialog::updateWidgets()
{
    ui->limitCheckBox->setEnabled(! file_closed_ && ! display_filter_.isEmpty());
    ui->limitCheckBox->setChecked(! display_filter_.isEmpty());

    ui->actionShowError->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityError) > 0);
    ui->actionShowWarning->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityWarn) > 0);
    ui->actionShowNote->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityNote) > 0);
    ui->actionShowChat->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityChat) > 0);
    ui->actionShowComment->setEnabled(expert_info_model_->numEvents(ExpertInfoModel::severityComment) > 0);

    QString tooltip;
    QString hint;

    if (file_closed_) {
        tooltip = tr("Capture file closed.");
        hint = tr("Capture file closed.");
    } else if (display_filter_.isEmpty()) {
         tooltip = tr("No display filter");
         hint = tr("No display filter set.");
    } else {
        tooltip = tr("Limit information to \"%1\".").arg(display_filter_);
        hint = tr("Display filter: \"%1\"").arg(display_filter_);
    }

    ui->limitCheckBox->setToolTip(tooltip);
    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);

    ui->groupBySummaryCheckBox->setEnabled(!file_closed_);
}

void ExpertInfoDialog::on_actionShowError_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_ERROR, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowWarning_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_WARN, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowNote_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_NOTE, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowChat_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_CHAT, !checked);
    updateWidgets();
}

void ExpertInfoDialog::on_actionShowComment_toggled(bool checked)
{
    proxyModel_->setSeverityFilter(PI_COMMENT, !checked);
    updateWidgets();
}


void ExpertInfoDialog::showExpertInfoMenu(QPoint pos)
{
    bool enable = true;
    QModelIndex expertIndex = ui->expertInfoTreeView->indexAt(pos);
    if (!expertIndex.isValid()) {
        return;
    }

    if (proxyModel_->data(expertIndex.sibling(expertIndex.row(), ExpertInfoModel::colHf), Qt::DisplayRole).toInt() < 0) {
        enable = false;
    }

    foreach (QMenu *submenu, ctx_menu_.findChildren<QMenu*>()) {
        submenu->setEnabled(enable && !file_closed_);
    }
    foreach (QAction *action, ctx_menu_.actions()) {
        FilterAction *fa = qobject_cast<FilterAction *>(action);
        bool action_enable = enable && !file_closed_;
        if (fa && (fa->action() == FilterAction::ActionWebLookup || fa->action() == FilterAction::ActionCopy)) {
            action_enable = enable;
        }
        action->setEnabled(action_enable);
    }

    ctx_menu_.popup(ui->expertInfoTreeView->viewport()->mapToGlobal(pos));
}

void ExpertInfoDialog::filterActionTriggered()
{
    QModelIndex modelIndex = ui->expertInfoTreeView->currentIndex();
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());

    if (!fa || !modelIndex.isValid()) {
        return;
    }

    int hf_index = proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colHf), Qt::DisplayRole).toInt();

    if (hf_index > -1) {
        QString filter_string;
        if (fa->action() == FilterAction::ActionWebLookup) {
            filter_string = QString("%1 %2")
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colProtocol), Qt::DisplayRole).toString())
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colSummary), Qt::DisplayRole).toString());
        } else if (fa->action() == FilterAction::ActionCopy) {
            filter_string = QString("%1 %2: %3")
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colPacket), Qt::DisplayRole).toUInt())
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colProtocol), Qt::DisplayRole).toString())
                    .arg(proxyModel_->data(modelIndex.sibling(modelIndex.row(), ExpertInfoModel::colSummary), Qt::DisplayRole).toString());
        } else {
            filter_string = proto_registrar_get_abbrev(hf_index);
        }

        if (! filter_string.isEmpty()) {
            emit filterAction(filter_string, fa->action(), fa->actionType());
        }
    }
}

void ExpertInfoDialog::collapseTree()
{
    ui->expertInfoTreeView->collapseAll();
}

void ExpertInfoDialog::expandTree()
{
    ui->expertInfoTreeView->expandAll();
}

void ExpertInfoDialog::on_limitCheckBox_toggled(bool)
{
    retapPackets();
}

void ExpertInfoDialog::on_groupBySummaryCheckBox_toggled(bool)
{
    expert_info_model_->setGroupBySummary(ui->groupBySummaryCheckBox->isChecked());
}

// Show child (packet list) items that match the contents of searchLineEdit.
void ExpertInfoDialog::on_searchLineEdit_textChanged(const QString &search_re)
{
    proxyModel_->setSummaryFilter(search_re);
}

void ExpertInfoDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_EXPERT_INFO_DIALOG);
}

// Stat command + args

static void
expert_info_init(const char *, void*) {
    mainApp->emitStatCommandSignal("ExpertInfo", NULL, NULL);
}

static stat_tap_ui expert_info_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "expert",
    expert_info_init,
    0,
    NULL
};

extern "C" {

void register_tap_listener_qt_expert_info(void);

void
register_tap_listener_qt_expert_info(void)
{
    register_stat_tap_ui(&expert_info_stat_ui, NULL);
}

}
