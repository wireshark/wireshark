/* tagging_rules_dialog.cpp
 *
 * Dialog for managing tagging rules
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "tagging_rules_dialog.h"
#include <ui_tagging_rules_dialog.h>
#include "coloring_rules_dialog.h"

#include "ui/simple_dialog.h"
#include "app/application_flavor.h"
#include "epan/dfilter/dfilter.h"
#include "epan/tag_rules.h"
#include "wsutil/filesystem.h"

#include "main_application.h"

#include "ui/qt/utils/qt_ui_utils.h"
#include "ui/qt/widgets/copy_from_profile_button.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QAbstractButton>
#include <QPushButton>
#include <QUrl>

TaggingRulesDialog::TaggingRulesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::TaggingRulesDialog),
    import_button_(nullptr),
    export_button_(nullptr),
    profilePath_(),
    tagRuleModel_(this),
    tagRuleDelegate_(this)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 4 / 5);

    setWindowTitle(mainApp->windowTitleString(tr("Tagging Rules %1").arg(get_profile_name())));

    ui->taggingRulesTreeView->setModel(&tagRuleModel_);
    ui->taggingRulesTreeView->setItemDelegate(&tagRuleDelegate_);
    ui->taggingRulesTreeView->viewport()->setAcceptDrops(true);

    for (int i = 0; i < tagRuleModel_.columnCount(); i++) {
        ui->taggingRulesTreeView->resizeColumnToContents(i);
    }

    ui->newToolButton->setIconByName("list-add");
    ui->deleteToolButton->setIconByName("list-remove");
    ui->copyToolButton->setIconByName("list-copy");
    ui->clearToolButton->setIconByName("list-clear");

#ifdef Q_OS_MAC
    ui->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->clearToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    connect(ui->taggingRulesTreeView->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &TaggingRulesDialog::tagRuleSelectionChanged);
    connect(&tagRuleDelegate_, &TaggingRulesDelegate::invalidField, this, &TaggingRulesDialog::invalidField);
    connect(&tagRuleDelegate_, &TaggingRulesDelegate::validField, this, &TaggingRulesDialog::validField);
    connect(ui->taggingRulesTreeView, &QTreeView::clicked, this, &TaggingRulesDialog::treeItemClicked);
    connect(&tagRuleModel_, &TaggingRulesModel::rowsInserted, this, &TaggingRulesDialog::rowCountChanged);
    connect(&tagRuleModel_, &TaggingRulesModel::rowsRemoved, this, &TaggingRulesDialog::rowCountChanged);
    rowCountChanged();

    // Load prefs and wire up the prefs widgets.
    originalPrefs_ = tag_rules_get_prefs();
    pendingPrefs_  = originalPrefs_;
    // combobox index 0 = Ctrl+Shift+Click, 1 = Click, 2 = Right-click only
#ifdef Q_OS_MAC
    ui->linkClickComboBox->setItemText(0, tr("Shift+Command+Click"));
#endif
    int clickIdx = 0;
    if (pendingPrefs_.link_click == TAG_LINK_CLICK_SINGLE) clickIdx = 1;
    else if (pendingPrefs_.link_click == TAG_LINK_CLICK_NONE) clickIdx = 2;
    ui->linkClickComboBox->setCurrentIndex(clickIdx);
    // Map stored percentage to combobox index: 100%=0, 90%=1, 80%=2, 70%=3, 60%=4, 50%=5
    {
        static const int pcts[] = {100, 90, 80, 70, 60, 50};
        int idx = 0;
        for (int i = 0; i < 6; i++) {
            if (pendingPrefs_.emoji_size == pcts[i] || (pendingPrefs_.emoji_size == 0 && pcts[i] == 100)) {
                idx = i; break;
            }
        }
        ui->fontSizeComboBox->setCurrentIndex(idx);
    }
    if (pendingPrefs_.separator != '\0')
        ui->separatorLineEdit->setText(QString(QChar::fromLatin1(pendingPrefs_.separator)));
    else
        ui->separatorLineEdit->clear();
    ui->separatorLineEdit->setMaxLength(1);

    connect(ui->linkClickComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TaggingRulesDialog::linkClickChanged);
    connect(ui->fontSizeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &TaggingRulesDialog::fontSizeChanged);
    connect(ui->separatorLineEdit, &QLineEdit::textChanged,
            this, &TaggingRulesDialog::separatorChanged);

    import_button_ = ui->buttonBox->addButton(tr("Import…"), QDialogButtonBox::ApplyRole);
    import_button_->setToolTip(tr("Select a file and add its rules to the end of the list."));
    export_button_ = ui->buttonBox->addButton(tr("Export…"), QDialogButtonBox::ApplyRole);
    export_button_->setToolTip(tr("Save rules to a file."));

    CopyFromProfileButton *copy_button = new CopyFromProfileButton(this, TAGRULES_FILE_NAME,
                                                                   tr("Copy tagging rules from another profile."));
    ui->buttonBox->addButton(copy_button, QDialogButtonBox::ActionRole);
    connect(copy_button, &CopyFromProfileButton::copyProfile, this, &TaggingRulesDialog::copyFromProfile);

    // Initial path: editing the current active profile's file only
    char *pp = get_persconffile_path(TAGRULES_FILE_NAME, true,
                                     application_configuration_environment_prefix());
    profilePath_ = QString::fromUtf8(pp);
    g_free(pp);

    // Load the current profile's file
    {
        QString err;
        tagRuleModel_.loadFromPath(profilePath_, err);
    }

    if (file_exists(profilePath_.toUtf8().constData())) {
        ui->pathLabel->setText(profilePath_);
        ui->pathLabel->setUrl(QUrl::fromLocalFile(profilePath_).toString());
        ui->pathLabel->setToolTip(tr("Open ") + TAGRULES_FILE_NAME);
        ui->pathLabel->setEnabled(true);
    } else {
        ui->pathLabel->setText(tr("(no tagrules file yet — will be created on save)"));
        ui->pathLabel->setEnabled(false);
    }

    ui->taggingRulesTreeView->setCurrentIndex(QModelIndex());
    updateHint();
}

TaggingRulesDialog::~TaggingRulesDialog()
{
    delete ui;
}

void TaggingRulesDialog::reject()
{
    // Restore in-memory prefs to what they were when the dialog opened.
    tag_rules_set_prefs(&originalPrefs_);
    QDialog::reject();
}

void TaggingRulesDialog::copyFromProfile(QString filename)
{
    QString err;
    if (!tagRuleModel_.importRules(filename, err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
    }
    for (int i = 0; i < tagRuleModel_.columnCount(); i++) {
        ui->taggingRulesTreeView->resizeColumnToContents(i);
    }
}

void TaggingRulesDialog::rowCountChanged()
{
    ui->clearToolButton->setEnabled(tagRuleModel_.rowCount() > 0);
}

void TaggingRulesDialog::tagRuleSelectionChanged(const QItemSelection &, const QItemSelection &)
{
    QModelIndexList selectedList = ui->taggingRulesTreeView->selectionModel()->selectedIndexes();

    QHash<int, QModelIndex> selectedRows;
    foreach (const QModelIndex &index, selectedList) {
        selectedRows.insert(index.row(), index);
    }

    qsizetype num_selected = selectedRows.count();

    ui->copyToolButton->setEnabled(num_selected == 1);
    ui->deleteToolButton->setEnabled(num_selected > 0);

    ui->copyToColoringRuleButton->setEnabled(num_selected == 1);
}

void TaggingRulesDialog::treeItemClicked(const QModelIndex &index)
{
    QModelIndex filterIdx = tagRuleModel_.index(index.row(), TaggingRulesModel::colFilter);
    QString filter = filterIdx.data(Qt::DisplayRole).toString();
    QString err;
    if (!isValidFilter(filter, &err) && index.data(Qt::CheckStateRole).toInt() == Qt::Checked) {
        errors_.insert(index, err);
        updateHint(index);
    } else {
        QList<QModelIndex> keys = errors_.keys();
        bool update = false;
        foreach (QModelIndex key, keys) {
            if (key.row() == index.row()) {
                errors_.remove(key);
                update = true;
            }
        }
        if (update) updateHint(index);
    }
}

void TaggingRulesDialog::invalidField(const QModelIndex &index, const QString &errMessage)
{
    errors_.insert(index, errMessage);
    updateHint(index);
}

void TaggingRulesDialog::validField(const QModelIndex &index)
{
    QList<QModelIndex> keys = errors_.keys();
    bool update = false;
    foreach (QModelIndex key, keys) {
        if (key.row() == index.row()) {
            errors_.remove(key);
            update = true;
        }
    }
    if (update) updateHint(index);
}

void TaggingRulesDialog::updateHint(QModelIndex idx)
{
    QString hint = "<small><i>";
    QString error_text;
    bool enable_save = true;

    if (errors_.count() > 0) {
        QList<QModelIndex> keys = errors_.keys();
        std::sort(keys.begin(), keys.end());
        const QModelIndex &error_key = keys[0];
        error_text = QStringLiteral("%1: %2")
            .arg(tagRuleModel_.data(tagRuleModel_.index(error_key.row(), TaggingRulesModel::colName), Qt::DisplayRole).toString())
            .arg(errors_[error_key]);
    }

    if (error_text.isEmpty()) {
        hint += tr("Click to edit. Drag to move. Sample Emojis <a href=\"https://emojipedia.org\">here</a>. All matching rules are applied.");
    } else {
        hint += error_text;
        if (idx.isValid()) {
            QModelIndex fiIdx = tagRuleModel_.index(idx.row(), TaggingRulesModel::colName);
            if (fiIdx.data(Qt::CheckStateRole).toInt() == Qt::Checked)
                enable_save = false;
        } else {
            enable_save = false;
        }
    }

    hint += "</i></small>";
    ui->hintLabel->setText(hint);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(enable_save);
}

bool TaggingRulesDialog::isValidFilter(QString filter, QString *error)
{
    dfilter_t *dfp = nullptr;
    df_error_t *df_err = nullptr;

    if (dfilter_compile(filter.toUtf8().constData(), &dfp, &df_err)) {
        dfilter_free(dfp);
        return true;
    }

    if (df_err) {
        error->append(df_err->msg);
        df_error_free(&df_err);
    }

    return false;
}

void TaggingRulesDialog::addRule(bool copy_from_current)
{
    const QModelIndex &current = ui->taggingRulesTreeView->currentIndex();
    if (copy_from_current && !current.isValid()) return;

    if (!tagRuleModel_.insertRows(0, 1)) return;

    QModelIndex dstName = tagRuleModel_.index(0, TaggingRulesModel::colName);

    if (copy_from_current) {
        /* Copy all editable columns from the source row (now shifted to row+1) */
        for (int col = 0; col < tagRuleModel_.columnCount(); col++) {
            QModelIndex srcIdx = tagRuleModel_.index(current.row() + 1, col);
            QModelIndex dstIdx = tagRuleModel_.index(0, col);
            tagRuleModel_.setData(dstIdx, tagRuleModel_.data(srcIdx, Qt::EditRole), Qt::EditRole);
        }
        QModelIndex srcName = tagRuleModel_.index(current.row() + 1, TaggingRulesModel::colName);
        tagRuleModel_.setData(dstName, tagRuleModel_.data(srcName, Qt::CheckStateRole), Qt::CheckStateRole);
    }

    ui->taggingRulesTreeView->setCurrentIndex(tagRuleModel_.index(0, 0));
    ui->taggingRulesTreeView->edit(tagRuleModel_.index(0, TaggingRulesModel::colFilter));
}

void TaggingRulesDialog::on_newToolButton_clicked()
{
    addRule(false);
}

void TaggingRulesDialog::on_deleteToolButton_clicked()
{
    QModelIndexList selectedList = ui->taggingRulesTreeView->selectionModel()->selectedIndexes();
    qsizetype num_selected = selectedList.count() / tagRuleModel_.columnCount();
    if (num_selected > 0) {
        std::sort(selectedList.begin(), selectedList.end());
        for (int i = static_cast<int>(selectedList.count()) - 1; i >= 0; i--) {
            QModelIndex deleteIndex = selectedList[i];
            if (deleteIndex.isValid() && deleteIndex.column() == 0) {
                tagRuleModel_.removeRows(deleteIndex.row(), 1);
            }
        }
    }
}

void TaggingRulesDialog::on_copyToolButton_clicked()
{
    addRule(true);
}

void TaggingRulesDialog::on_clearToolButton_clicked()
{
    tagRuleModel_.removeRows(0, tagRuleModel_.rowCount());
}

void TaggingRulesDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QString err;

    if (button == import_button_) {
        QString file_name = WiresharkFileDialog::getOpenFileName(this, mainApp->windowTitleString(tr("Import Tagging Rules")),
                                                                 mainApp->openDialogInitialDir().path());
        if (!file_name.isEmpty()) {
            if (!tagRuleModel_.importRules(file_name, err)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
            }
        }
    } else if (button == export_button_) {
        int num_items = static_cast<int>(ui->taggingRulesTreeView->selectionModel()->selectedIndexes().count()) / tagRuleModel_.columnCount();
        if (num_items < 1) num_items = tagRuleModel_.rowCount();
        if (num_items < 1) return;

        QString caption = mainApp->windowTitleString(tr("Export %1 Tagging Rules").arg(num_items));
        QString file_name = WiresharkFileDialog::getSaveFileName(this, caption,
                                                                 mainApp->openDialogInitialDir().path());
        if (!file_name.isEmpty()) {
            if (!tagRuleModel_.exportRules(file_name, err)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
            }
        }
    }
}

void TaggingRulesDialog::on_buttonBox_accepted()
{
    QString err;
    tag_prefs_t p = tag_rules_get_prefs();

    if (!tagRuleModel_.writeToPath(profilePath_, &p, err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
        done(QDialog::Rejected);
        return;
    }

    // Reload the active list so packet list picks up changes
    tag_rules_reload();
    // Explicitly trigger packet list redraw so font/prefs changes take effect immediately
    if (coloring_accepted_cb_)
        coloring_accepted_cb_();
    done(QDialog::Accepted);
}

void TaggingRulesDialog::fontSizeChanged(int idx)
{
    static const int pcts[] = {100, 90, 80, 70, 60, 50};
    pendingPrefs_.emoji_size = (idx >= 0 && idx < 6) ? pcts[idx] : 100;
    tag_rules_set_prefs(&pendingPrefs_);
}

void TaggingRulesDialog::separatorChanged(const QString &text)
{
    pendingPrefs_.separator = text.isEmpty() ? '\0' : text.at(0).toLatin1();
    tag_rules_set_prefs(&pendingPrefs_);
}

void TaggingRulesDialog::linkClickChanged(int idx)
{
    // idx 0 = Ctrl+Shift+Click, 1 = Click, 2 = Right-click only
    if (idx == 1) pendingPrefs_.link_click = TAG_LINK_CLICK_SINGLE;
    else if (idx == 2) pendingPrefs_.link_click = TAG_LINK_CLICK_NONE;
    else pendingPrefs_.link_click = TAG_LINK_CLICK_CTRL;
    tag_rules_set_prefs(&pendingPrefs_);
}

void TaggingRulesDialog::on_copyToColoringRuleButton_clicked()
{
    QModelIndex current = ui->taggingRulesTreeView->currentIndex();
    if (!current.isValid()) return;

    QModelIndex nameIdx   = tagRuleModel_.index(current.row(), TaggingRulesModel::colName);
    QModelIndex filterIdx = tagRuleModel_.index(current.row(), TaggingRulesModel::colFilter);
    QString name   = tagRuleModel_.data(nameIdx,   Qt::DisplayRole).toString();
    QString filter = tagRuleModel_.data(filterIdx, Qt::DisplayRole).toString();

    // Save tagging rules (same as clicking OK)
    if (!tagRuleModel_.writeTags()) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Failed to write tagging rules.");
        return;
    }

    // Open coloring rules dialog with name and filter pre-filled.
    // Connect its accepted signal to the callback registered by the main window
    // (which calls packet_list_->recolorPackets()). The callback is captured by
    // value so it outlives this dialog.
    QWidget *pw = parentWidget();
    ColoringRulesDialog *coloring_dialog = new ColoringRulesDialog(pw, filter, name);
    std::function<void()> cb = coloring_accepted_cb_;
    if (cb) {
        connect(coloring_dialog, &ColoringRulesDialog::accepted, coloring_dialog, [cb]() {
            cb();
        });
    }
    coloring_dialog->setWindowModality(Qt::ApplicationModal);
    coloring_dialog->setAttribute(Qt::WA_DeleteOnClose);
    coloring_dialog->show();

    done(QDialog::Accepted);
}
