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
#include <ui/qt/utils/themes/themed_icon.h>
#include "ui/qt/widgets/copy_from_profile_button.h"
#include "ui/qt/widgets/profile_inherit_combo_box.h"
#include "ui/qt/utils/inherit_selection.h"
#include <ui/qt/utils/hide_overridden_rows.h>
#include <ui/qt/widgets/list_edit_buttons.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QAbstractButton>
#include <QPushButton>
#include <QSet>
#include <QUrl>

TaggingRulesDialog::TaggingRulesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::TaggingRulesDialog),
    import_button_(nullptr),
    export_button_(nullptr),
    copy_button_(nullptr),
    inherit_combo_(nullptr),
    profilePath_(),
    tagRuleModel_(this),
    tagRuleDelegate_(this)
{
    ui->setupUi(this);

    ListEditButtons::ToolTips tool_tips;
    tool_tips.add = tr("Add a new tagging rule.");
    tool_tips.remove = tr("Delete the selected tagging rules.");
    tool_tips.copy = tr("Duplicate this tagging rule.");
    tool_tips.moveUp = tr("Move the selected tagging rules up.");
    tool_tips.moveDown = tr("Move the selected tagging rules down.");
    tool_tips.clear = tr("Clear all tagging rules.");
    ui->editButtons->setToolTips(tool_tips);
    connect(ui->editButtons, &ListEditButtons::newClicked, this, &TaggingRulesDialog::newClicked);
    connect(ui->editButtons, &ListEditButtons::deleteClicked, this, &TaggingRulesDialog::deleteClicked);
    connect(ui->editButtons, &ListEditButtons::copyClicked, this, &TaggingRulesDialog::copyClicked);
    connect(ui->editButtons, &ListEditButtons::clearClicked, this, &TaggingRulesDialog::clearClicked);
    connect(ui->editButtons, &ListEditButtons::moveUpClicked, ui->taggingRulesTreeView, &RowMoveTreeView::moveSelectedRowsUp);
    connect(ui->editButtons, &ListEditButtons::moveDownClicked, ui->taggingRulesTreeView, &RowMoveTreeView::moveSelectedRowsDown);
    ui->buttonBox->button(QDialogButtonBox::Help)->setFocusPolicy(Qt::NoFocus);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 4 / 5);

    setWindowTitle(mainApp->windowTitleString(tr("Tagging Rules %1").arg(get_profile_name())));

    ui->taggingRulesTreeView->setModel(&tagRuleModel_);
    ui->taggingRulesTreeView->setItemDelegate(&tagRuleDelegate_);

    for (int i = 0; i < tagRuleModel_.columnCount(); i++) {
        ui->taggingRulesTreeView->resizeColumnToContents(i);
    }

#ifdef Q_OS_MACOS
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    connect(ui->taggingRulesTreeView->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &TaggingRulesDialog::tagRuleSelectionChanged);
    connect(&tagRuleDelegate_, &TaggingRulesDelegate::invalidField, this, &TaggingRulesDialog::invalidField);
    connect(&tagRuleDelegate_, &TaggingRulesDelegate::validField, this, &TaggingRulesDialog::validField);
    connect(ui->taggingRulesTreeView, &QTreeView::clicked, this, &TaggingRulesDialog::treeItemClicked);
    connect(&tagRuleModel_, &TaggingRulesModel::rowsInserted, this, &TaggingRulesDialog::rowCountChanged);
    connect(&tagRuleModel_, &TaggingRulesModel::rowsRemoved, this, &TaggingRulesDialog::rowCountChanged);
    connect(&tagRuleModel_, &TaggingRulesModel::rowsMoved, this, &TaggingRulesDialog::updateWidgets);
    connect(&tagRuleModel_, &TaggingRulesModel::modelReset, this, &TaggingRulesDialog::rowCountChanged);

    // Where the rules come from, next to the button clearing them
    inherit_combo_ = ProfileInheritComboBox::addNextTo(this, ui->horizontalLayout, ui->editButtons, TAGRULES_FILE_NAME);
    connect(inherit_combo_, &ProfileInheritComboBox::modeChanged, this, &TaggingRulesDialog::inheritModeChanged);

    // Not used entries can be hidden, which is not stored
    addHideNotUsedCheckBox(this, ui->horizontalLayout, inherit_combo_, ui->taggingRulesTreeView, &tagRuleModel_);

    // Load prefs and wire up the prefs widgets.
    originalPrefs_ = tag_rules_get_prefs();
    pendingPrefs_  = originalPrefs_;
    // combobox index 0 = Ctrl+Shift+Click, 1 = Click, 2 = Right-click only
#ifdef Q_OS_MACOS
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

    copy_button_ = new CopyFromProfileButton(this, TAGRULES_FILE_NAME,
                                             tr("Copy tagging rules from another profile."));
    ui->buttonBox->addButton(copy_button_, QDialogButtonBox::ActionRole);
    connect(copy_button_, &CopyFromProfileButton::copyProfile, this, &TaggingRulesDialog::copyFromProfile);

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

    updatePathLabel();
    followInheritedProfiles(&tagRuleModel_, this, &TaggingRulesDialog::updatePathLabel);
    updateWidgets();

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
    updateWidgets();
}

void TaggingRulesDialog::updatePathLabel()
{
    bool own_used = inherit_combo_->mode() != PROFILE_INHERIT_PARENT_ONLY;
    bool exists = own_used && file_exists(profilePath_.toUtf8().constData());
    // The hint about a missing file only matters when using the own rules only
    QString own_text = exists ? profilePath_ :
                       inherit_combo_->mode() == PROFILE_INHERIT_PROFILE_ONLY ?
                       tr("(no tagrules.jsonc file yet — will be created on save)") : QString();

    inherit_combo_->setPathText(ui->pathLabel, own_text, inheritedProfiles(&tagRuleModel_));
    ui->pathLabel->setUrl(exists ? QUrl::fromLocalFile(profilePath_).toString() : QString());
    ui->pathLabel->setToolTip(exists ? tr("Open ") + TAGRULES_FILE_NAME : QString());
    ui->pathLabel->setEnabled(exists);
}

void TaggingRulesDialog::updateWidgets()
{
    if (!inherit_combo_)
        return;

    InheritSelection sel = inheritSelection(&tagRuleModel_, ui->taggingRulesTreeView->selectionModel()->selectedIndexes(), ui->taggingRulesTreeView);

    // Inherited rules can be copied into the own rules, but not changed
    ui->editButtons->setSelection(sel);
    if (copy_button_) {
        copy_button_->setOwnEntriesUsed(sel.own_used);
    }

    ui->copyToColoringRuleButton->setEnabled(sel.selected_count == 1);
    ProfileInheritComboBox::setOwnEntriesUsed(import_button_, sel.own_used);
    if (import_button_)
        import_button_->setEnabled(sel.own_used);
}

void TaggingRulesDialog::inheritModeChanged(profile_inherit_e mode)
{
    tagRuleModel_.setInheritMode(mode);
    for (int i = 0; i < tagRuleModel_.columnCount(); i++) {
        ui->taggingRulesTreeView->resizeColumnToContents(i);
    }
    updatePathLabel();
    updateWidgets();
}

void TaggingRulesDialog::tagRuleSelectionChanged(const QItemSelection &, const QItemSelection &)
{
    updateWidgets();
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

    /* Take the source values first: a copy of an inherited rule hides that rule */
    QVariantList src_values;
    QVariant src_check = Qt::Checked;
    if (copy_from_current) {
        for (int col = 0; col < tagRuleModel_.columnCount(); col++) {
            src_values << tagRuleModel_.data(tagRuleModel_.index(current.row(), col), Qt::EditRole);
        }
        /* An inherited rule is always enabled, and shows no check box */
        if (!tagRuleModel_.isInherited(current.row()))
            src_check = tagRuleModel_.data(tagRuleModel_.index(current.row(), TaggingRulesModel::colName), Qt::CheckStateRole);
    }

    if (!tagRuleModel_.insertRows(0, 1)) return;

    QModelIndex dstName = tagRuleModel_.index(0, TaggingRulesModel::colName);

    if (copy_from_current) {
        /* Copy all editable columns from the source row */
        for (int col = 0; col < src_values.count(); col++) {
            tagRuleModel_.setData(tagRuleModel_.index(0, col), src_values[col], Qt::EditRole);
        }
        tagRuleModel_.setData(dstName, src_check, Qt::CheckStateRole);
    }

    ui->taggingRulesTreeView->setCurrentIndex(tagRuleModel_.index(0, 0));
    ui->taggingRulesTreeView->edit(tagRuleModel_.index(0, TaggingRulesModel::colFilter));
}

void TaggingRulesDialog::newClicked()
{
    addRule(false);
}

void TaggingRulesDialog::deleteClicked()
{
    for (int row : rowsLastFirst(ui->taggingRulesTreeView->selectionModel()->selectedRows()))
        tagRuleModel_.removeRows(row, 1);
}

void TaggingRulesDialog::copyClicked()
{
    addRule(true);
}

void TaggingRulesDialog::clearClicked()
{
    removeVisibleOwnRows(ui->taggingRulesTreeView, &tagRuleModel_);
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

bool TaggingRulesDialog::prefsChanged(const tag_prefs_t &prefs) const
{
    return prefs.separator != originalPrefs_.separator || prefs.emoji_size != originalPrefs_.emoji_size ||
           prefs.link_click != originalPrefs_.link_click;
}

void TaggingRulesDialog::on_buttonBox_accepted()
{
    QString err;
    tag_prefs_t p = tag_rules_get_prefs();

    if (!tagRuleModel_.writeToPath(profilePath_, &p, prefsChanged(p), err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
        done(QDialog::Rejected);
        return;
    }

    // The mode is only kept with the rules written for it, and before reloading them
    if (!inherit_combo_->saveMode(err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
    }

    // Reload the active list so packet list picks up changes
    tag_rules_reload();
    // Explicitly trigger packet list redraw so font/prefs changes take effect immediately
    if (coloring_accepted_cb_)
        coloring_accepted_cb_();
    done(QDialog::Accepted);
}

void TaggingRulesDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_TAGGING_RULES_DIALOG);
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

    // Save tagging rules (same as clicking OK), for the mode selected here
    QString err;
    tag_prefs_t p = tag_rules_get_prefs();
    if (!tagRuleModel_.writeToPath(profilePath_, &p, prefsChanged(p), err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
        return;
    }
    if (!inherit_combo_->saveMode(err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
    }
    tag_rules_reload();

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
