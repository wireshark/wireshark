/* tap_parameter_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * @file Tap parameter dialog class
 *
 * Base class for statistics dialogs. Subclasses must implement:
 * - fillTree. Called when the dialog is first displayed and when a display
 *   filter is applied. In most cases the subclass should clear the tree and
 *   retap packets here.
 * - filterExpression. If the subclass supports filtering context menu items
 *   ("Apply As Filter", etc.) it should fill in ctx_menu_ and implement
 *   filterExpression.
 * - getTreeAsString or treeItemData. Used for "Copy" and "Save As...".
 * -
 */

#include "tap_parameter_dialog.h"
#include <ui_tap_parameter_dialog.h>

#include "epan/stat_tap_ui.h"

#include <wsutil/utf8_entities.h>

#include "progress_frame.h"
#include <ui/qt/utils/stat_table_exporter.h>
#include "main_application.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QTreeWidgetItemIterator>

// The GTK+ counterpart uses tap_param_dlg, which we don't use. If we
// need tap parameters we should probably create a TapParameterDialog
// class based on WiresharkDialog and subclass it here.

// To do:
// - Add tap parameters? SCSI SRT uses PARAM_ENUM. Everything appears to use
//   PARAM_FILTER. Nothing uses _UINT, _STRING, or _UUID.
// - Update to match bug 9452 / r53657.
// - Create a TapParameterTreeWidgetItem class?
// - Better / more usable XML output.

const int expand_all_threshold_ = 100; // Arbitrary

static QHash<const QString, tpdCreator> cfg_str_to_creator_;
const QString TapParameterDialog::action_name_ = "TapParameterAction";

TapParameterDialog::TapParameterDialog(QWidget &parent, CaptureFile &cf, int help_topic) :
    WiresharkDialog(parent, cf),
    ui(new Ui::TapParameterDialog),
    help_topic_(help_topic)
{
    ui->setupUi(this);

    // Only show a hint label if a subclass provides a hint.
    ui->hintLabel->hide();

    ctx_menu_.addAction(ui->actionCopyToClipboard);
    ctx_menu_.addAction(ui->actionSaveAs);

    QPushButton *button;
    button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(button, &QPushButton::clicked, this, &TapParameterDialog::on_actionCopyToClipboard_triggered);

    button = ui->buttonBox->addButton(tr("Save as…"), QDialogButtonBox::ActionRole);
    connect(button, &QPushButton::clicked, this, &TapParameterDialog::on_actionSaveAs_triggered);

    connect(ui->displayFilterLineEdit, SIGNAL(textChanged(QString)),
            this, SLOT(updateWidgets()));

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    if (help_topic_ < 1) {
        ui->buttonBox->button(QDialogButtonBox::Help)->hide();
    }

    if (!ui->displayFilterLineEdit->text().isEmpty()) {
        QString filter = ui->displayFilterLineEdit->text();
        emit updateFilter(filter);
    }
    updateWidgets();
    show_timer_ = new QTimer(this);
    setRetapOnShow(true);
}

TapParameterDialog::~TapParameterDialog()
{
    delete ui;
    show_timer_->stop();
    delete show_timer_;
}

void TapParameterDialog::registerDialog(const QString title, const char *cfg_abbr, register_stat_group_t group, stat_tap_init_cb tap_init_cb, tpdCreator creator)
{
    stat_tap_ui ui_info;

    ui_info.group = group;
    ui_info.title = title.toUtf8().constData();
    ui_info.cli_string = cfg_abbr;
    ui_info.tap_init_cb = tap_init_cb;
    ui_info.nparams = 0; // We'll need this for SCSI SRT
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, NULL);

    QString cfg_str = cfg_abbr;
    cfg_str_to_creator_[cfg_str] = creator;

    QAction *tpd_action = new QAction(title, mainApp);
    tpd_action->setObjectName(action_name_);
    tpd_action->setData(cfg_str);
    mainApp->addDynamicMenuGroupItem(group, tpd_action);
}

TapParameterDialog *TapParameterDialog::showTapParameterStatistics(QWidget &parent, CaptureFile &cf, const QString cfg_str, const QString arg, void *)
{
    if (cfg_str_to_creator_.contains(cfg_str)) {
        TapParameterDialog *tpd = cfg_str_to_creator_[cfg_str](parent, cfg_str, arg, cf);
        return tpd;
    }
    return NULL;
}

QTreeWidget *TapParameterDialog::statsTreeWidget()
{
    return ui->statsTreeWidget;
}

QLineEdit *TapParameterDialog::displayFilterLineEdit()
{
    return ui->displayFilterLineEdit;
}

QPushButton *TapParameterDialog::applyFilterButton()
{
    return ui->applyFilterButton;
}

QVBoxLayout *TapParameterDialog::verticalLayout()
{
    return ui->verticalLayout;
}

QHBoxLayout *TapParameterDialog::filterLayout()
{
    return ui->filterLayout;
}

QString TapParameterDialog::displayFilter()
{
    return ui->displayFilterLineEdit->text();
}

// This assumes that we're called before signals are connected or show()
// is called.
void TapParameterDialog::setDisplayFilter(const QString &filter)
{
    ui->displayFilterLineEdit->setText(filter);
}

void TapParameterDialog::setHint(const QString &hint)
{
    ui->hintLabel->setText(hint);
    ui->hintLabel->show();
}

void TapParameterDialog::setRetapOnShow(bool retap)
{
    show_timer_->stop();
    if (retap) {
        show_timer_->singleShot(0, this, SLOT(on_applyFilterButton_clicked()));
    }
}

void TapParameterDialog::filterActionTriggered()
{
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());
    QString filter_expr = filterExpression();

    if (!fa || filter_expr.isEmpty()) {
        return;
    }

    emit filterAction(filter_expr, fa->action(), fa->actionType());
}

void TapParameterDialog::collapseAllActionTriggered() {
    ui->statsTreeWidget->collapseAll();
}
void TapParameterDialog::expandAllActionTriggered() {
    ui->statsTreeWidget->expandAll();
}

QList<QVariant> TapParameterDialog::treeItemData(QTreeWidgetItem *) const
{
    return QList<QVariant>();
}

QByteArray TapParameterDialog::getTreeAsString(st_format_type format)
{
    StatTableExporter::Table table;
    table.title = windowSubtitle();
    table.file_name = cap_file_.fileDisplayName();
    for (int col = 0; col < ui->statsTreeWidget->columnCount(); col++) {
        table.headers << ui->statsTreeWidget->headerItem()->text(col);
    }
    QTreeWidgetItemIterator it(ui->statsTreeWidget, QTreeWidgetItemIterator::NotHidden);
    while (*it) {
        table.rows << treeItemData(*it);
        ++it;
    }
    return StatTableExporter::toByteArray(format, table);
}

void TapParameterDialog::drawTreeItems()
{
    // ui->statsTreeWidget->model()->rowCount() only counts the number
    // of children of the root element, not all the nodes
    int nodeCount = 0;
    for (QTreeWidgetItemIterator iter(ui->statsTreeWidget); *iter; ++iter) {
        if (++nodeCount >= expand_all_threshold_) {
            break;
        }
    }
    if (nodeCount < expand_all_threshold_) {
        ui->statsTreeWidget->expandAll();
    }

    for (int col = 0; col < ui->statsTreeWidget->columnCount(); col++) {
        ui->statsTreeWidget->resizeColumnToContents(col);
    }
}

void TapParameterDialog::contextMenuEvent(QContextMenuEvent *event)
{
    bool enable = filterExpression().length() > 0 ? true : false;

    foreach (QAction *fa, filter_actions_) {
        fa->setEnabled(enable);
    }

    ctx_menu_.popup(event->globalPos());
}

void TapParameterDialog::addFilterActions()
{
    QAction *insert_action = ctx_menu_.actions().first();

    const QList<FilterAction *> actions = FilterAction::addActionSubmenus(&ctx_menu_, insert_action);
    for (FilterAction *fa : actions) {
        connect(fa, &QAction::triggered, this, &TapParameterDialog::filterActionTriggered);
        filter_actions_ << fa;
    }
    ctx_menu_.insertSeparator(insert_action);
}

void TapParameterDialog::addTreeCollapseAllActions()
{
    ctx_menu_.addSeparator();

    QAction *collapse = new QAction(tr("Collapse All"), this);
    ctx_menu_.addAction(collapse);
    connect(collapse, SIGNAL(triggered()), this, SLOT(collapseAllActionTriggered()));

    QAction *expand = new QAction(tr("Expand All"), this);
    ctx_menu_.addAction(expand);
    connect(expand, SIGNAL(triggered()), this, SLOT(expandAllActionTriggered()));
}

void TapParameterDialog::updateWidgets()
{
    bool edit_enable = true;
    bool apply_enable = true;

    if (file_closed_ || !cap_file_.isValid()) {
        edit_enable = false;
        apply_enable = false;
    } else if (!ui->displayFilterLineEdit->checkFilter()) {
        // XXX Tell the user why the filter is invalid.
        apply_enable = false;
    }
    ui->displayFilterLineEdit->setEnabled(edit_enable);
    ui->applyFilterButton->setEnabled(apply_enable);

    WiresharkDialog::updateWidgets();
}

void TapParameterDialog::on_applyFilterButton_clicked()
{
    if (!ui->displayFilterLineEdit->checkFilter()) {
        return;
    }

    QString filter = ui->displayFilterLineEdit->text();
    emit updateFilter(filter);
    // If we wanted to be fancy we could add an isRetapping function to
    // either WiresharkDialog or CaptureFile and use it in updateWidgets
    // to enable and disable the apply button as needed.
    // For now we use more simple but less useful logic.
    bool df_enabled = ui->displayFilterLineEdit->isEnabled();
    bool af_enabled = ui->applyFilterButton->isEnabled();
    ui->displayFilterLineEdit->setEnabled(false);
    ui->applyFilterButton->setEnabled(false);
    fillTree();
    ui->applyFilterButton->setEnabled(af_enabled);
    ui->displayFilterLineEdit->setEnabled(df_enabled);
}

void TapParameterDialog::on_actionCopyToClipboard_triggered()
{
    mainApp->clipboard()->setText(getTreeAsString(ST_FORMAT_PLAIN));
}

void TapParameterDialog::on_actionSaveAs_triggered()
{
    StatTableExporter::saveAs(this, [this](st_format_type f) { return getTreeAsString(f); });
}

void TapParameterDialog::on_buttonBox_helpRequested()
{
    if (help_topic_ > 0) {
        mainApp->helpTopicAction((topic_action_e) help_topic_);
    }
}
