/* theme_designer_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/theme_designer_dialog.h>
#include <ui_theme_designer_dialog.h>
#include <ui_theme_import_error_dialog.h>
#include <ui_theme_name_dialog.h>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/themes/theme_parser.h>
#include <ui/qt/utils/themes/theme_writer.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include "main_application.h"

#include <epan/prefs.h>
#include <ui/recent.h>

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTextCursor>
#include <QTextDocument>
#include <QTimer>
#include <QToolTip>
#include <QTreeWidgetItem>
#include <QUrl>
#include <QtMath>

#include <algorithm>

namespace {

const int kStemRole = Qt::UserRole;
const int kNameRole = Qt::UserRole + 1;

QList<ThemeInfo> sortedThemes()
{
    QList<ThemeInfo> themes = ThemeManager::availableThemes();
    std::sort(themes.begin(), themes.end(), [](const ThemeInfo &a, const ThemeInfo &b) {
        return a.name.localeAwareCompare(b.name) < 0;
    });
    return themes;
}

void shrinkFont(QWidget *widget)
{
    QFont font = widget->font();
    if (font.pointSizeF() > 0)
        font.setPointSizeF(font.pointSizeF() * 0.9);
    widget->setFont(font);
}

// Height of a QPlainTextEdit that shows `lines` lines of its font.
// QFrame keeps its frame in contentsMargins(); the document margin lies
// around the text.  Polish the edit first when a style sheet sets its
// frame.
int plainTextHeightForLines(const QPlainTextEdit *edit, int lines)
{
    const QMargins margins = edit->contentsMargins();
    return lines * edit->fontMetrics().lineSpacing()
           + qCeil(2 * edit->document()->documentMargin())
           + margins.top() + margins.bottom();
}

// The proposed name for a copy of a theme.
QString copyName(const QString &name)
{
    return ThemeDesignerDialog::tr("%1 Copy").arg(name);
}

// Imports are read completely into memory, so their size is capped.
const qint64 kMaxImportSize = 1024 * 1024;

// Asks for a theme name and shows the personal file it is stored in.
class ThemeNameDialog : public QDialog
{
public:
    enum class Mode { Copy, SaveAs, New, Rename };

    /**
     * @param source      theme the new one is made from; shown for Copy and Save As.
     * @param prefill     initial name.
     * @param ignoreStem  stem that counts as free (the theme being renamed).
     */
    ThemeNameDialog(QWidget *parent, Mode mode, const ThemeInfo &source,
                    const QString &prefill, const QString &ignoreStem = QString()) :
        QDialog(parent),
        ignore_stem_(ignoreStem)
    {
        ui_.setupUi(this);

        QString title;
        QString action;
        switch (mode) {
        case Mode::Copy:
            title = ThemeDesignerDialog::tr("Copy Theme");
            action = ThemeDesignerDialog::tr("Copy");
            break;
        case Mode::SaveAs:
            title = ThemeDesignerDialog::tr("Save Theme As");
            action = ThemeDesignerDialog::tr("Save");
            break;
        case Mode::New:
            title = ThemeDesignerDialog::tr("New Theme");
            action = ThemeDesignerDialog::tr("Create");
            break;
        case Mode::Rename:
            title = ThemeDesignerDialog::tr("Rename Theme");
            action = ThemeDesignerDialog::tr("Rename");
            break;
        }
        setWindowTitle(mainApp->windowTitleString(title));
        ui_.buttonBox->button(QDialogButtonBox::Ok)->setText(action);

        const bool show_source = mode == Mode::Copy || mode == Mode::SaveAs;
        ui_.sourceTitleLabel->setVisible(show_source);
        ui_.sourceLabel->setVisible(show_source);
        ui_.sourceLabel->setText(source.builtIn
                                 ? ThemeDesignerDialog::tr("%1 (bundled)").arg(source.name)
                                 : source.name);

        ui_.folderLabel->setText(QDir::toNativeSeparators(ThemeManager::personalThemesDir()));
        shrinkFont(ui_.folderLabel);
        shrinkFont(ui_.ruleLabel);

        connect(ui_.nameLineEdit, &QLineEdit::textChanged, this, &ThemeNameDialog::nameChanged);
        ui_.nameLineEdit->setText(prefill);
        ui_.nameLineEdit->selectAll();
        nameChanged();
    }

    QString name() const { return ui_.nameLineEdit->text().trimmed(); }

private:
    void nameChanged()
    {
        const QString theme_name = name();
        ui_.fileNameLabel->setText(theme_name.isEmpty()
                                   ? QString()
                                   : ThemeWriter::uniqueStem(theme_name, ignore_stem_) + QStringLiteral(".jsonc"));
        ui_.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(!theme_name.isEmpty());
    }

    Ui::ThemeNameDialog ui_;
    QString ignore_stem_;
};

// Lists why a file could not be imported.  A QMessageBox cannot place the
// message list between the two texts.
class ThemeImportErrorDialog : public QDialog
{
public:
    ThemeImportErrorDialog(QWidget *parent, const QString &fileName, const QStringList &messages) :
        QDialog(parent)
    {
        ui_.setupUi(this);
        setWindowTitle(mainApp->windowTitleString(ThemeDesignerDialog::tr("Import Theme")));

        ui_.headlineLabel->setText(ThemeDesignerDialog::tr("\"%1\" could not be imported.").arg(fileName));
        shrinkFont(ui_.noteLabel);

        QPlainTextEdit *edit = ui_.messagesTextEdit;
        edit->setFont(FontManager::monospaceFont());
        ThemeManager::setNoticeState(edit, "error");
        edit->setPlainText(messages.join('\n'));

        // As tall as the messages, up to eight lines; longer lists scroll.
        // Polishing first applies the banner's border and padding.
        edit->ensurePolished();
        const int lines = std::clamp(static_cast<int>(messages.size()), 1, 8);
        edit->setFixedHeight(plainTextHeightForLines(edit, lines));
    }

private:
    Ui::ThemeImportErrorDialog ui_;
};

} // namespace

ThemeDesignerDialog::ThemeDesignerDialog(QWidget *parent, Context context,
                                         const QString &initialTheme) :
    GeometryStateDialog(parent),
    ui_(new Ui::ThemeDesignerDialog),
    context_(context),
    side_dark_(ThemeManager::instance()->isDarkMode()),
    fonts_filled_(false)
{
    ui_->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    base_title_ = mainApp->windowTitleString(tr("Theme Designer"));
    setWindowTitle(base_title_);

    ui_->splitter->setStretchFactor(0, 0);
    ui_->splitter->setStretchFactor(1, 1);
    ui_->splitter->setStretchFactor(2, 1);
    ui_->splitter->setSizes({ 240, 500, 660 });
    loadGeometry(1400, 820);
    loadSplitterState(ui_->splitter);

    // Secondary information under the theme list uses a smaller font.
    for (QLabel *label : { ui_->themeOriginLabel, ui_->folderTitleLabel, ui_->folderPathLabel })
        shrinkFont(label);
    const QString themes_dir = ThemeManager::personalThemesDir();
    ui_->folderPathLabel->setText(QStringLiteral("<a href=\"%1\">%2</a>")
            .arg(QUrl::fromLocalFile(themes_dir).toString().toHtmlEscaped(),
                 QDir::toNativeSeparators(themes_dir).toHtmlEscaped()));
    // Not through runChildDialog(): keepInFront() would raise the designer
    // over the file manager that this click brings to the front.
    connect(ui_->folderPathLabel, &QLabel::linkActivated, this, [this]() {
        desktop_open_folder(ThemeManager::personalThemesDir(), this);
    });
    ui_->descriptionEdit->installEventFilter(this);
    updateDescriptionHeight();

    ui_->useThemeButton->setVisible(context_ == Context::Standalone);

    if (side_dark_)
        ui_->darkRadioButton->setChecked(true);
    else
        ui_->lightRadioButton->setChecked(true);

    // The monospace font preference of the Fonts page wins over a theme's
    // monospace font (FontManager::setMonospaceFont), so say so where that
    // font is edited.
    const QString pref_font = QString::fromUtf8(prefs.gui_font_name);
    if (pref_font.isEmpty()) {
        ui_->fontOverrideBannerLabel->hide();
    } else {
        ui_->fontOverrideBannerLabel->setText(
            tr("Your monospace font preference on the Fonts page (%1) overrides the theme's monospace font, "
               "so this setting only applies where that preference is not set. "
               "The preview shows the theme's font.")
            .arg(FontManager::displayName(FontManager::fontFromName(pref_font))));
    }

    ui_->codeView->setViewFont(FontManager::monospaceFont());

    connect(ui_->themeTree, &QTreeWidget::currentItemChanged,
            this, &ThemeDesignerDialog::themeSelectionChanged);
    connect(ui_->newButton, &QPushButton::clicked, this, &ThemeDesignerDialog::newTheme);
    connect(ui_->copyButton, &QPushButton::clicked, this, &ThemeDesignerDialog::copyTheme);
    connect(ui_->renameButton, &QPushButton::clicked, this, &ThemeDesignerDialog::renameTheme);
    connect(ui_->deleteButton, &QPushButton::clicked, this, &ThemeDesignerDialog::deleteTheme);
    connect(ui_->importButton, &QPushButton::clicked, this, &ThemeDesignerDialog::importTheme);
    connect(ui_->exportButton, &QPushButton::clicked, this, &ThemeDesignerDialog::exportTheme);

    connect(ui_->nameLineEdit, &QLineEdit::textEdited, this, &ThemeDesignerDialog::metaEdited);
    connect(ui_->authorLineEdit, &QLineEdit::textEdited, this, &ThemeDesignerDialog::metaEdited);
    connect(ui_->descriptionEdit, &QPlainTextEdit::textChanged, this, &ThemeDesignerDialog::descriptionEdited);
    connect(ui_->darkRadioButton, &QRadioButton::toggled, this, &ThemeDesignerDialog::sideToggled);

    connect(ui_->colorEditor, &ThemeColorEditor::draftChanged,
            this, &ThemeDesignerDialog::colorDraftChanged);
    connect(ui_->colorEditor, &ThemeColorEditor::childDialogClosed,
            this, &ThemeDesignerDialog::keepInFront);
    connect(ui_->packetListPreview, &ThemePreviewWidget::childDialogClosed,
            this, &ThemeDesignerDialog::keepInFront);
    connect(ui_->welcomePreview, &ThemeWelcomePreview::childDialogClosed,
            this, &ThemeDesignerDialog::keepInFront);

    // Clicking a sample selects the theme color that paints the spot.
    pickers_.insert(ui_->welcomePreview, &ui_->welcomePreview->picker());
    pickers_.insert(ui_->packetListPreview, &ui_->packetListPreview->picker());
    for (auto it = pickers_.cbegin(); it != pickers_.cend(); ++it) {
        QWidget *sample = static_cast<QWidget *>(it.key());
        sample->installEventFilter(this);
        it.value()->setHoverChanged([this, sample](const ThemePreviewPick::Layer &layer,
                                                   const QPoint &global_pos) {
            showPickTip(sample, layer, global_pos);
        });
        it.value()->setEnabled(true);
    }
    connect(ui_->welcomePreview, &ThemeWelcomePreview::layerPicked,
            this, &ThemeDesignerDialog::previewLayerPicked);
    connect(ui_->packetListPreview, &ThemePreviewWidget::layerPicked,
            this, &ThemeDesignerDialog::previewLayerPicked);
    connect(ui_->welcomePreview, &ThemeWelcomePreview::pickMenuRequested,
            this, &ThemeDesignerDialog::previewPickMenu);
    connect(ui_->packetListPreview, &ThemePreviewWidget::pickMenuRequested,
            this, &ThemeDesignerDialog::previewPickMenu);

    // The preview tab shown last is remembered across openings.
    if (recent.gui_theme_designer_preview) {
        QWidget *page = ui_->previewTabWidget->findChild<QWidget *>(
            QString::fromUtf8(recent.gui_theme_designer_preview));
        const int index = page ? ui_->previewTabWidget->indexOf(page) : -1;
        ui_->previewTabWidget->setCurrentIndex(index >= 0 ? index : 0);
    }
    connect(ui_->previewTabWidget, &QTabWidget::currentChanged,
            this, &ThemeDesignerDialog::previewTabChanged);
    connect(ui_->editorTabWidget, &QTabWidget::currentChanged, this, &ThemeDesignerDialog::tabChanged);

    connect(ui_->regularFamilyComboBox, &QComboBox::activated, this, [this]() { fontFamilyChanged(false); });
    connect(ui_->monospaceFamilyComboBox, &QComboBox::activated, this, [this]() { fontFamilyChanged(true); });
    connect(ui_->regularSizeComboBox, &QComboBox::activated, this, [this]() { fontSizeChanged(false); });
    connect(ui_->monospaceSizeComboBox, &QComboBox::activated, this, [this]() { fontSizeChanged(true); });

    // A font group and its title offer to revert that font.
    const struct {
        QWidget *widget;
        bool monospace;
    } font_menu_sources[] = {
        { ui_->regularFontGroupBox, false },
        { ui_->regularFontTitleLabel, false },
        { ui_->monospaceFontGroupBox, true },
        { ui_->monospaceFontTitleLabel, true },
    };
    for (const auto &source : font_menu_sources) {
        QWidget *widget = source.widget;
        const bool monospace = source.monospace;
        connect(widget, &QWidget::customContextMenuRequested, this, [this, widget, monospace](const QPoint &pos) {
            showFontContextMenu(monospace, widget, pos);
        });
    }

    connect(ui_->compareComboBox, &QComboBox::activated, this, &ThemeDesignerDialog::compareChanged);
    connect(ui_->codeView, &ThemeCodeView::countsChanged, this, &ThemeDesignerDialog::updateCodeCounts);
    connect(ui_->previousChangeButton, &QPushButton::clicked, ui_->codeView, &ThemeCodeView::previousChange);
    connect(ui_->nextChangeButton, &QPushButton::clicked, ui_->codeView, &ThemeCodeView::nextChange);
    connect(ui_->copyCodeButton, &QPushButton::clicked, this, &ThemeDesignerDialog::copyCode);

    connect(ui_->helpButton, &QPushButton::clicked, this, []() {
        mainApp->helpTopicAction(HELP_THEME_DESIGNER_DIALOG);
    });
    connect(ui_->revertButton, &QPushButton::clicked, this, &ThemeDesignerDialog::revertDraft);
    connect(ui_->useThemeButton, &QPushButton::clicked, this, &ThemeDesignerDialog::useTheme);
    connect(ui_->saveButton, &QPushButton::clicked, this, &ThemeDesignerDialog::saveDraft);
    ui_->saveButton->setToolTip(tr("Save the theme (%1)")
        .arg(QKeySequence(QKeySequence::Save).toString(QKeySequence::NativeText)));
    connect(ui_->closeButton, &QPushButton::clicked, this, &ThemeDesignerDialog::reject);

    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &ThemeDesignerDialog::themeChanged);

    ThemeManager::setNoticeState(ui_->bundledBannerLabel, "info");
    ThemeManager::setNoticeState(ui_->fontOverrideBannerLabel, "info");
    refreshThemeDependentLabels();

    QString stem = initialTheme.isEmpty() ? ThemeManager::selectedThemeName() : initialTheme;
    populateThemeList(stem);
    if (!themeItem(stem))
        stem = ThemeManager::defaultThemeName();
    if (loadTheme(stem))
        populateThemeList(stem);
}

ThemeDesignerDialog::~ThemeDesignerDialog()
{
    // The samples outlive this body as child widgets; their hover
    // callbacks use ui_.
    for (ThemePreviewPicker *picker : std::as_const(pickers_))
        picker->setHoverChanged(ThemePreviewPicker::HoverChanged());
    delete ui_;
}

void ThemeDesignerDialog::reject()
{
    // QDialog::closeEvent() and the Escape key both end up here.
    if (!maybeSaveChanges())
        return;
    GeometryStateDialog::reject();
}

bool ThemeDesignerDialog::event(QEvent *event)
{
    // Claim the save shortcut before any QAction sees it.  On macOS the
    // native menu bar is shared by all windows, so the main window's
    // File > Save would otherwise take Cmd+S while this window is active.
    // keyPressEvent() then saves.  This is why the save key is not a
    // QShortcut: an accepted override suppresses QShortcuts as well.
    if (event->type() == QEvent::ShortcutOverride
            && static_cast<QKeyEvent *>(event)->matches(QKeySequence::Save)) {
        event->accept();
        return true;
    }

    // Another designer instance may have added, renamed or removed files
    // while this window was in the background.
    if (event->type() == QEvent::WindowActivate && !current_stem_.isEmpty())
        populateThemeList(current_stem_);
    return GeometryStateDialog::event(event);
}

void ThemeDesignerDialog::keyPressEvent(QKeyEvent *event)
{
    if (event->matches(QKeySequence::Save)) {
        event->accept();
        if (ui_->saveButton->isEnabled())
            saveDraft();
        return;
    }

    // Return and Enter end a field edit.  They never save or close the
    // designer: colors apply while typing, and an accidental save would
    // write the file and drop the undo history.
    if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        event->accept();
        return;
    }
    GeometryStateDialog::keyPressEvent(event);
}

// --------------------------------------------------------------------
// Theme list
// --------------------------------------------------------------------

void ThemeDesignerDialog::populateThemeList(const QString &selectStem)
{
    QSignalBlocker blocker(ui_->themeTree);
    ui_->themeTree->clear();

    QFont group_font = ui_->themeTree->font();
    group_font.setBold(true);

    QTreeWidgetItem *bundled = new QTreeWidgetItem(ui_->themeTree, { tr("Bundled") });
    QTreeWidgetItem *personal = new QTreeWidgetItem(ui_->themeTree, { tr("Personal") });
    for (QTreeWidgetItem *group : { bundled, personal }) {
        group->setFlags(Qt::ItemIsEnabled);
        group->setFont(0, group_font);
    }

    themes_ = sortedThemes();
    for (const ThemeInfo &info : themes_) {
        QTreeWidgetItem *item = new QTreeWidgetItem(info.builtIn ? bundled : personal, { info.name });
        item->setData(0, kStemRole, info.internalName);
        item->setData(0, kNameRole, info.name);
        item->setToolTip(0, info.description);
    }

    if (personal->childCount() == 0) {
        QTreeWidgetItem *empty = new QTreeWidgetItem(personal, { tr("No personal themes yet") });
        empty->setFlags(Qt::NoItemFlags);
        QFont empty_font = empty->font(0);
        empty_font.setItalic(true);
        empty->setFont(0, empty_font);
    }

    ui_->themeTree->expandAll();

    QTreeWidgetItem *selected = themeItem(selectStem);
    if (selected)
        ui_->themeTree->setCurrentItem(selected);
    updateListMarker();
}

QTreeWidgetItem *ThemeDesignerDialog::themeItem(const QString &stem) const
{
    if (stem.isEmpty())
        return nullptr;
    for (int g = 0; g < ui_->themeTree->topLevelItemCount(); ++g) {
        QTreeWidgetItem *group = ui_->themeTree->topLevelItem(g);
        for (int i = 0; i < group->childCount(); ++i) {
            if (group->child(i)->data(0, kStemRole).toString() == stem)
                return group->child(i);
        }
    }
    return nullptr;
}

void ThemeDesignerDialog::updateListMarker()
{
    QTreeWidgetItem *item = themeItem(current_stem_);
    if (!item)
        return;
    const QString name = item->data(0, kNameRole).toString();
    item->setText(0, isDirty() ? name + QStringLiteral(" *") : name);
}

void ThemeDesignerDialog::themeSelectionChanged(QTreeWidgetItem *current, QTreeWidgetItem *)
{
    const QString stem = current ? current->data(0, kStemRole).toString() : QString();
    if (stem.isEmpty() || stem == current_stem_)
        return;

    // Saving may rebuild the list, so only the stem is used from here on.
    if (!maybeSaveChanges() || !loadTheme(stem)) {
        QSignalBlocker blocker(ui_->themeTree);
        QTreeWidgetItem *previous = themeItem(current_stem_);
        if (previous)
            ui_->themeTree->setCurrentItem(previous);
        return;
    }

    QSignalBlocker blocker(ui_->themeTree);
    QTreeWidgetItem *item = themeItem(stem);
    if (item)
        ui_->themeTree->setCurrentItem(item);
}

bool ThemeDesignerDialog::loadTheme(const QString &stem)
{
    ThemeDraft draft;
    QString error;
    ThemeParseReport report;
    if (!ThemeManager::instance()->loadDraft(stem, draft, &error, &report)) {
        QMessageBox box(QMessageBox::Warning, base_title_,
                        tr("The theme \"%1\" could not be loaded.").arg(stem),
                        QMessageBox::Ok, this);
        box.setInformativeText(error);
        runChildDialog([&] { return box.exec(); });
        return false;
    }

    // Base and draft are cleaned the same way, so dropping entries that
    // are not colors does not count as an edit.
    draft.removeInvalidEntries();
    load_report_ = report;
    current_stem_ = stem;
    takeDrafts(draft, draft);
    return true;
}

void ThemeDesignerDialog::takeDrafts(const ThemeDraft &base, const ThemeDraft &draft)
{
    base_ = base;
    draft_ = draft;

    ui_->colorEditor->setDrafts(base_, draft_);
    ui_->colorEditor->setDarkSide(side_dark_);

    const bool bundled = isBundledDraft();
    ui_->bundledBannerLabel->setVisible(bundled);
    ui_->themeOriginLabel->setText(bundled
                                   ? tr("Bundled with Wireshark, read-only")
                                   : tr("Personal theme, %1.jsonc").arg(current_stem_));

    updateMetaFields();
    updateFontControls();
    updateCompareCombo();
    draftChanged();
}

// --------------------------------------------------------------------
// Unsaved changes
// --------------------------------------------------------------------

bool ThemeDesignerDialog::isDirty() const
{
    return draft_ != base_;
}

bool ThemeDesignerDialog::isBundledDraft() const
{
    return base_.info.builtIn;
}

int ThemeDesignerDialog::metaEditedCount() const
{
    return (draft_.info.name != base_.info.name
            || draft_.info.author != base_.info.author
            || draft_.info.description != base_.info.description) ? 1 : 0;
}

int ThemeDesignerDialog::fontEditedCount() const
{
    return (draft_.regularFont != base_.regularFont
            || draft_.monospaceFont != base_.monospaceFont) ? 1 : 0;
}

bool ThemeDesignerDialog::canSave() const
{
    return isDirty() && ui_->colorEditor->invalidCount() == 0 && validation_error_.isEmpty();
}

bool ThemeDesignerDialog::maybeSaveChanges()
{
    if (!isDirty())
        return true;

    // A draft that cannot be saved offers only Discard and Cancel.
    const bool can_save = canSave();
    QMessageBox::StandardButtons buttons = QMessageBox::Discard | QMessageBox::Cancel;
    if (can_save)
        buttons |= QMessageBox::Save;
    const QMessageBox::StandardButton answer = runChildDialog([&] { return QMessageBox::question(
            this, base_title_, tr("The theme \"%1\" has unsaved changes.").arg(draft_.info.name),
            buttons, can_save ? QMessageBox::Save : QMessageBox::Cancel); });
    switch (answer) {
    case QMessageBox::Save:
        saveDraft();
        return !isDirty();
    case QMessageBox::Discard:
        return true;
    default:
        return false;
    }
}

void ThemeDesignerDialog::revertDraft()
{
    takeDrafts(base_, base_);
}

// --------------------------------------------------------------------
// Editor
// --------------------------------------------------------------------

void ThemeDesignerDialog::updateMetaFields()
{
    ui_->nameLineEdit->setText(draft_.info.name);
    ui_->authorLineEdit->setText(draft_.info.author);
    {
        // Loading a theme is not an edit.
        const QSignalBlocker blocker(ui_->descriptionEdit);
        ui_->descriptionEdit->setPlainText(draft_.info.description);
    }
}

void ThemeDesignerDialog::metaEdited()
{
    draft_.info.name = ui_->nameLineEdit->text();
    draft_.info.author = ui_->authorLineEdit->text();
    draft_.info.description = ui_->descriptionEdit->toPlainText();
    draftChanged();
}

// meta.description is one line: the Theme page shows it in a label and a
// tooltip.  The field wraps it over two lines for reading; line breaks a
// paste brings in, with the whitespace around them, become one space
// (join_lines()).  The replacement joins the paste's undo step, so one undo
// restores the text before the paste and never brings a line break back.
// It emits textChanged again, which records the edit.
void ThemeDesignerDialog::descriptionEdited()
{
    QPlainTextEdit *edit = ui_->descriptionEdit;
    const QString text = edit->toPlainText();
    const QString joined = join_lines(text);
    if (joined == text) {
        metaEdited();
        return;
    }
    const int position = edit->textCursor().position();
    QTextCursor cursor(edit->document());
    cursor.joinPreviousEditBlock();
    cursor.select(QTextCursor::Document);
    cursor.insertText(joined);
    cursor.endEditBlock();
    cursor.setPosition(qMin(position, static_cast<int>(joined.size())));
    edit->setTextCursor(cursor);
}

void ThemeDesignerDialog::updateDescriptionHeight()
{
    ui_->descriptionEdit->setFixedHeight(plainTextHeightForLines(ui_->descriptionEdit, 2));
}

void ThemeDesignerDialog::sideToggled()
{
    // Only the side shown and edited changes; the live app keeps its mode.
    side_dark_ = ui_->darkRadioButton->isChecked();
    ui_->colorEditor->setDarkSide(side_dark_);
    updatePlayground();
}

void ThemeDesignerDialog::colorDraftChanged()
{
    const ThemeDraft &edited = ui_->colorEditor->draft();
    draft_.colors = edited.colors;
    draft_.graphColors = edited.graphColors;
    draftChanged();
}

void ThemeDesignerDialog::draftChanged()
{
    status_note_.clear();
    status_note_tool_tip_.clear();
    updateValidation();
    updateCodeBanner();
    updateCodeView();
    updatePlayground();
    updateFontLabels();
    updateStatus();
    updateButtons();
    updateTitle();
    updateListMarker();
}

// --------------------------------------------------------------------
// Fonts tab
// --------------------------------------------------------------------

void ThemeDesignerDialog::tabChanged(int index)
{
    if (ui_->editorTabWidget->widget(index) == ui_->fontsTab)
        fillFontFamilies();
}

void ThemeDesignerDialog::fillFontFamilies()
{
    // Enumerating fonts can take a while on systems with many fonts, so it
    // happens once, when the Fonts tab is first shown.
    if (fonts_filled_)
        return;

    QApplication::setOverrideCursor(Qt::WaitCursor);
    families_ = QFontDatabase::families();
    monospace_families_.clear();
    for (const QString &family : std::as_const(families_)) {
        if (QFontDatabase::isFixedPitch(family))
            monospace_families_ << family;
    }
    fonts_filled_ = true;
    updateFontControls();
    QApplication::restoreOverrideCursor();
}

void ThemeDesignerDialog::updateFontControls()
{
    fillFamilyCombo(ui_->regularFamilyComboBox, families_, draft_.regularFont.family);
    fillFamilyCombo(ui_->monospaceFamilyComboBox, monospace_families_, draft_.monospaceFont.family);
    fillSizeCombo(ui_->regularSizeComboBox, draft_.regularFont.pointSize);
    fillSizeCombo(ui_->monospaceSizeComboBox, draft_.monospaceFont.pointSize);
    updateFontLabels();
}

void ThemeDesignerDialog::fillFamilyCombo(QComboBox *combo, const QStringList &families,
                                          const QString &current)
{
    QSignalBlocker blocker(combo);
    combo->clear();
    combo->addItem(tr("Platform default"), QString());
    for (const QString &family : families)
        combo->addItem(family, family);

    int index = 0;
    if (!current.isEmpty()) {
        index = combo->findData(current);
        if (index < 0) {
            // Until the font list is filled only the draft's own family is
            // known; afterwards a family missing from it is not installed.
            const bool missing = fonts_filled_ && !families_.contains(current);
            combo->insertItem(1, missing ? tr("%1 (not installed)").arg(current) : current, current);
            index = 1;
        }
    }
    combo->setCurrentIndex(index);
}

void ThemeDesignerDialog::fillSizeCombo(QComboBox *combo, int current)
{
    QSignalBlocker blocker(combo);
    combo->clear();
    combo->addItem(tr("Default"), 0);

    QList<int> sizes = QFontDatabase::standardSizes();
    if (current > 0 && !sizes.contains(current)) {
        sizes << current;
        std::sort(sizes.begin(), sizes.end());
    }
    for (int size : std::as_const(sizes))
        combo->addItem(tr("%1 pt").arg(size), size);

    const int index = combo->findData(current);
    combo->setCurrentIndex(index < 0 ? 0 : index);
}

void ThemeDesignerDialog::fontFamilyChanged(bool monospace)
{
    QComboBox *combo = monospace ? ui_->monospaceFamilyComboBox : ui_->regularFamilyComboBox;
    ThemeFontHint &hint = monospace ? draft_.monospaceFont : draft_.regularFont;
    hint.family = combo->currentData().toString();
    draftChanged();
}

void ThemeDesignerDialog::fontSizeChanged(bool monospace)
{
    QComboBox *combo = monospace ? ui_->monospaceSizeComboBox : ui_->regularSizeComboBox;
    ThemeFontHint &hint = monospace ? draft_.monospaceFont : draft_.regularFont;
    hint.pointSize = combo->currentData().toInt();
    draftChanged();
}

void ThemeDesignerDialog::showFontContextMenu(bool monospace, QWidget *source, const QPoint &pos)
{
    ThemeFontHint &hint = monospace ? draft_.monospaceFont : draft_.regularFont;
    const ThemeFontHint &base_hint = monospace ? base_.monospaceFont : base_.regularFont;
    if (hint == base_hint)
        return;

    QMenu menu(this);
    QAction *revert_action = menu.addAction(tr("Revert Font"));
    if (menu.exec(source->mapToGlobal(pos)) != revert_action)
        return;

    hint = base_hint;
    updateFontControls();
    draftChanged();
}

void ThemeDesignerDialog::updateFontLabels()
{
    // Group titles with an "edited" mark, and samples in the draft fonts.
    const QString edited_mark = ThemeColorEditor::editedMarkHtml();
    const bool regular_edited = draft_.regularFont != base_.regularFont;
    const bool monospace_edited = draft_.monospaceFont != base_.monospaceFont;

    ui_->regularFontTitleLabel->setText(QStringLiteral("<b>%1</b>%2")
                                        .arg(tr("Regular font").toHtmlEscaped(),
                                             regular_edited ? edited_mark : QString()));
    ui_->monospaceFontTitleLabel->setText(QStringLiteral("<b>%1</b>%2")
                                          .arg(tr("Monospace font").toHtmlEscaped(),
                                               monospace_edited ? edited_mark : QString()));

    ui_->regularSampleLabel->setFont(resolvedFont(draft_.regularFont, false));
    ui_->monospaceSampleLabel->setFont(resolvedFont(draft_.monospaceFont, true));
}

QFont ThemeDesignerDialog::resolvedFont(const ThemeFontHint &hint, bool monospace) const
{
    return FontManager::themeFont(ThemeParser::fontDescriptor(hint), monospace);
}

// --------------------------------------------------------------------
// Code tab
// --------------------------------------------------------------------

void ThemeDesignerDialog::updateCompareCombo()
{
    QSignalBlocker blocker(ui_->compareComboBox);
    ui_->compareComboBox->clear();

    const bool bundled = isBundledDraft();
    if (!bundled)
        ui_->compareComboBox->addItem(tr("Saved file"), QString());
    for (const ThemeInfo &info : themes_) {
        if (info.builtIn)
            ui_->compareComboBox->addItem(tr("%1 (bundled)").arg(info.name), info.internalName);
    }

    const int index = bundled ? ui_->compareComboBox->findData(current_stem_) : 0;
    ui_->compareComboBox->setCurrentIndex(index < 0 ? 0 : index);
    // The caller refreshes the code view once the draft is serialized.
    compare_ = compareText();
}

QString ThemeDesignerDialog::compareText()
{
    const QString stem = ui_->compareComboBox->currentData().toString();
    return QString::fromUtf8(stem.isEmpty() ? ThemeWriter::toJsonc(base_) : bundledJsonc(stem));
}

void ThemeDesignerDialog::compareChanged()
{
    compare_ = compareText();
    updateCodeView();
}

QByteArray ThemeDesignerDialog::bundledJsonc(const QString &stem)
{
    auto it = bundled_jsonc_.constFind(stem);
    if (it != bundled_jsonc_.constEnd())
        return it.value();

    ThemeDraft draft;
    QByteArray jsonc;
    if (ThemeManager::instance()->loadDraft(stem, draft)) {
        draft.removeInvalidEntries();
        jsonc = ThemeWriter::toJsonc(draft);
    }
    bundled_jsonc_.insert(stem, jsonc);
    return jsonc;
}

void ThemeDesignerDialog::updateCodeView()
{
    ui_->codeView->setTexts(compare_, QString::fromUtf8(draft_jsonc_));
    updateCodeCounts();
}

void ThemeDesignerDialog::updateCodeCounts()
{
    ui_->codeCountLabel->setText(tr("%1 changed, %2 added, %3 removed")
                                 .arg(ui_->codeView->changedLines())
                                 .arg(ui_->codeView->addedLines())
                                 .arg(ui_->codeView->removedLines()));
}

void ThemeDesignerDialog::updateValidation()
{
    // The Code tab shows the serialized draft even when it is not valid, so
    // it is serialized first, once, together with the round trip the save
    // path requires.
    const bool round_trips = roundTrips(draft_, current_stem_, &draft_jsonc_);

    validation_error_.clear();
    if (ui_->colorEditor->invalidCount() > 0) {
        validation_error_ = tr("Not valid: %1 is not a color. The theme cannot be saved.")
                            .arg(ui_->colorEditor->firstInvalidPath());
        return;
    }

    const ThemeManager::ThemeToken missing = draft_.firstMissingRequired();
    if (missing != ThemeManager::NoRole) {
        validation_error_ = tr("Not valid: %1 is required. The theme cannot be saved.")
                            .arg(ThemeWriter::keyPath(missing));
        return;
    }

    if (!round_trips)
        validation_error_ = tr("Not valid: the file does not read back unchanged. The theme cannot be saved.");
}

bool ThemeDesignerDialog::roundTrips(const ThemeDraft &draft, const QString &stem, QByteArray *jsonc) const
{
    // The writer output must parse back to exactly this draft.
    const QByteArray text = ThemeWriter::toJsonc(draft);
    if (jsonc)
        *jsonc = text;
    ThemeDraft reread;
    return ThemeManager::instance()->parseDraft(text, stem, reread) && reread == draft;
}

void ThemeDesignerDialog::updateCodeBanner()
{
    const bool error = !validation_error_.isEmpty();
    ThemeManager::setNoticeState(ui_->codeBannerLabel, error ? "error" : "info");
    ui_->codeBannerLabel->setText(error
                                  ? validation_error_
                                  : tr("Valid. Parses with the theme parser and reads back unchanged."));
}

void ThemeDesignerDialog::copyCode()
{
    QApplication::clipboard()->setText(ui_->codeView->currentText());
}

// --------------------------------------------------------------------
// Playground, status and chrome
// --------------------------------------------------------------------

void ThemeDesignerDialog::updatePlayground()
{
    QPalette palette;
    const QHash<ThemeManager::ThemeToken, ThemeColorPair> tokens =
        ThemeManager::instance()->resolveDraftTokens(draft_, side_dark_, &palette);
    ui_->welcomePreview->setTheme(tokens, side_dark_, palette);
    ui_->packetListPreview->setPreviewColors(ThemeManager::flattenTokens(tokens, side_dark_),
                                             draft_.declaresWindow());

    const QFont regular = resolvedFont(draft_.regularFont, false);
    const QFont monospace = resolvedFont(draft_.monospaceFont, true);
    ui_->welcomePreview->setPreviewFont(regular);
    ui_->packetListPreview->setPreviewFonts(regular, monospace);
}

void ThemeDesignerDialog::updateStatus()
{
    const int invalid = ui_->colorEditor->invalidCount();
    QString text;
    QString tool_tip;

    if (!status_note_.isEmpty()) {
        text = status_note_;
        tool_tip = status_note_tool_tip_;
    } else if (invalid > 0) {
        // Two strings instead of %n: English numerus forms only exist
        // after translators run lupdate.
        text = invalid == 1
               ? tr("1 color is not valid. Fix it to save.")
               : tr("%1 colors are not valid. Fix them to save.").arg(invalid);
    } else if (isDirty()) {
        const int edited = ui_->colorEditor->editedCount() + metaEditedCount() + fontEditedCount();
        text = tr("%1 edited, %2 changed as a consequence. Not saved.")
               .arg(edited).arg(ui_->colorEditor->changedCount());
    } else if (!load_report_.messages.isEmpty()) {
        text = tr("Loaded with problems. Saving rewrites the file without the invalid entries.");
        tool_tip = load_report_.messages.join('\n');
    } else if (isBundledDraft()) {
        text = tr("Bundled theme, no changes.");
    } else {
        text = tr("No unsaved changes.");
    }

    ui_->statusLabel->setText(text);
    ui_->statusLabel->setToolTip(tool_tip);
    ThemeManager::setValidationState(ui_->statusLabel,
                                     invalid > 0 && status_note_.isEmpty() ? "invalid" : QString());
}

void ThemeDesignerDialog::updateButtons()
{
    const bool have_theme = !current_stem_.isEmpty();
    const bool bundled = isBundledDraft();
    const bool dirty = isDirty();
    const bool invalid = ui_->colorEditor->invalidCount() > 0;

    ui_->copyButton->setEnabled(have_theme);
    ui_->exportButton->setEnabled(have_theme);
    ui_->renameButton->setEnabled(have_theme && !bundled);
    ui_->deleteButton->setEnabled(have_theme && !bundled);

    ui_->revertButton->setEnabled(dirty);
    ui_->saveButton->setText(bundled ? tr("Save As…") : tr("Save"));
    ui_->saveButton->setEnabled(have_theme && canSave());

    if (context_ == Context::Standalone) {
        const bool unsaved = dirty || invalid;
        ui_->useThemeButton->setEnabled(have_theme && !unsaved && !isActiveTheme(current_stem_));
        ui_->useThemeButton->setToolTip(unsaved ? tr("Save the theme first.") : QString());
    }
}

void ThemeDesignerDialog::updateTitle()
{
    setWindowTitle(isDirty() ? QStringLiteral("*") + base_title_ : base_title_);
}

void ThemeDesignerDialog::themeChanged()
{
    refreshThemeDependentLabels();
    updatePlayground();
}

void ThemeDesignerDialog::refreshThemeDependentLabels()
{
    updateCodeBanner();
    updateFontLabels();
}

// --------------------------------------------------------------------
// Preview samples
// --------------------------------------------------------------------

void ThemeDesignerDialog::previewTabChanged(int index)
{
    QWidget *page = ui_->previewTabWidget->widget(index);
    if (!page)
        return;
    g_free(recent.gui_theme_designer_preview);
    recent.gui_theme_designer_preview = g_strdup(page->objectName().toUtf8().constData());
}

void ThemeDesignerDialog::previewLayerPicked(const ThemePreviewPick::Layer &layer)
{
    if (layer.token == ThemeManager::NoRole) {
        status_note_ = tr("Not a theme color.");
        status_note_tool_tip_.clear();
        updateStatus();
        return;
    }

    picked_once_ = true;
    ui_->editorTabWidget->setCurrentWidget(ui_->colorsTab);
    bool cleared = false;
    ui_->colorEditor->selectToken(layer.token, &cleared);
    const QString label = ui_->colorEditor->tokenLabel(layer.token);
    if (layer.link) {
        status_note_ = tr("Links have no color of their own; they follow %1.").arg(label);
    } else if (cleared) {
        status_note_ = tr("Cleared the color filter to show %1.").arg(label);
    } else {
        status_note_.clear();
    }
    status_note_tool_tip_.clear();
    updateStatus();
}

void ThemeDesignerDialog::previewPickMenu(QMenu *menu, QAction *before,
                                          const QList<ThemePreviewPick::Layer> &layers)
{
    if (layers.isEmpty()) {
        QAction *none = new QAction(tr("Not a theme color"), menu);
        none->setEnabled(false);
        menu->insertAction(before, none);
        return;
    }
    for (const ThemePreviewPick::Layer &layer : layers) {
        QAction *action = new QAction(
            ui_->colorEditor->tokenSwatch(layer.token),
            //: Theme Designer sample context menu entry: the part a color
            //: paints (Text, Background, Border, Link text), then the color name.
            tr("%1  %2").arg(ThemePreviewPick::roleName(layer),
                             ui_->colorEditor->tokenLabel(layer.token)),
            menu);
        connect(action, &QAction::triggered, this, [this, layer]() { previewLayerPicked(layer); });
        menu->insertAction(before, action);
    }
}

bool ThemeDesignerDialog::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == ui_->descriptionEdit) {
        if (event->type() == QEvent::KeyPress) {
            const int key = static_cast<QKeyEvent *>(event)->key();
            // Return and Enter never insert a line break: the description
            // is one line, and Enter never saves or closes the designer.
            if (key == Qt::Key_Return || key == Qt::Key_Enter)
                return true;
        } else if (event->type() == QEvent::FontChange) {
            // Follows the text zoom and font preference changes.
            updateDescriptionHeight();
        }
    }
    ThemePreviewPicker *picker = pickers_.value(watched);
    if (picker) {
        switch (event->type()) {
        case QEvent::ToolTip:
            // The tooltip follows mouse moves (showPickTip()); Qt's delayed
            // tooltip would show a stale or second one.
            return true;
        case QEvent::Leave:
        case QEvent::MouseButtonPress:
            // Hides the tooltip; the next move shows it again, after a
            // pick without the hint line.
            picker->resetHover();
            break;
        default:
            break;
        }
    }
    return GeometryStateDialog::eventFilter(watched, event);
}

void ThemeDesignerDialog::showPickTip(QWidget *sample, const ThemePreviewPick::Layer &layer,
                                      const QPoint &global_pos)
{
    if (layer.token == ThemeManager::NoRole) {
        QToolTip::hideText();
        return;
    }
    const QString label = ui_->colorEditor->tokenLabel(layer.token).toHtmlEscaped();
    const QString role = ThemePreviewPick::roleName(layer).toHtmlEscaped();
    //: Tooltip over a Theme Designer sample: color name, then the part it paints.
    QString text = layer.link ? tr("<b>%1</b> (links follow it) · %2").arg(label, role)
                              : tr("<b>%1</b> · %2").arg(label, role);
    if (!picked_once_)
        text += QStringLiteral("<br>") + tr("Click to select it in Colors. Right-click for all colors here.").toHtmlEscaped();
    // A 1x1 rect at the pointer: Qt re-places the visible label on every
    // move (no hide and show), and a label Qt hid on its own is created
    // again.
    QToolTip::showText(global_pos, text, sample,
                       QRect(sample->mapFromGlobal(global_pos), QSize(1, 1)));
}

// --------------------------------------------------------------------
// File operations
// --------------------------------------------------------------------

bool ThemeDesignerDialog::isActiveTheme(const QString &stem) const
{
    return stem == ThemeManager::selectedThemeName();
}

void ThemeDesignerDialog::showError(const QString &text)
{
    runChildDialog([&] { return QMessageBox::warning(this, base_title_, text, QMessageBox::Ok); });
}

bool ThemeDesignerDialog::writeDraft(const ThemeDraft &draft, const QString &stem)
{
    if (ThemeManager::personalThemesDir().isEmpty()) {
        showError(tr("The personal themes folder is not available, so the theme cannot be saved."));
        return false;
    }

    // A personal file named like a bundled theme would never be loaded, and
    // bundled themes themselves are never written.
    if (stem.isEmpty() || ThemeManager::isBuiltInTheme(stem)) {
        showError(tr("\"%1\" is the name of a bundled theme, so the theme cannot be saved under it.")
                  .arg(stem));
        return false;
    }

    // Only write what the parser reads back as exactly this draft.
    if (!roundTrips(draft, stem)) {
        showError(tr("The theme does not read back unchanged, so it was not saved."));
        return false;
    }

    const QString path = ThemeManager::personalThemePath(stem);
    QString error;
    if (!ThemeWriter::writeFile(draft, path, &error)) {
        showError(tr("The theme could not be saved to %1: %2")
                  .arg(QDir::toNativeSeparators(path), error));
        return false;
    }
    if (!ThemeManager::instance()->validateThemeFile(path)) {
        showError(tr("The saved file %1 does not load as a theme.")
                  .arg(QDir::toNativeSeparators(path)));
        return false;
    }
    return true;
}

bool ThemeDesignerDialog::saveAsPersonal(const ThemeDraft &draft, const QString &stem)
{
    if (!writeDraft(draft, stem))
        return false;
    selectWrittenTheme(stem);
    notifySaved(stem);
    return true;
}

void ThemeDesignerDialog::selectWrittenTheme(const QString &stem)
{
    // The file is the new saved state, so base and draft both come from it.
    loadTheme(stem);
    populateThemeList(current_stem_);
}

void ThemeDesignerDialog::notifySaved(const QString &stem, const QString &removedStem)
{
    if (context_ == Context::Preferences) {
        // The Preferences page activates themes on OK/Apply; it only needs
        // to know which files changed.
        if (!removedStem.isEmpty() && removedStem != stem)
            emit themeRemoved(removedStem);
        emit themeSaved(stem);
        return;
    }

    // A saved or renamed active theme is reloaded so the change shows.
    if (isActiveTheme(removedStem.isEmpty() ? stem : removedStem))
        activateTheme(stem);
}

void ThemeDesignerDialog::activateTheme(const QString &stem)
{
    if (context_ != Context::Standalone)
        return;

    ThemeManager::setSelectedThemeName(stem);
    mainApp->emitAppSignal(MainApplication::PreferencesChanged);
    updateButtons();
    keepInFront();
}

// Reloading the theme restyles the main window and re-shows its tool
// bars, which can bring it in front of this window. On macOS a closing
// child dialog or native panel (color, file) can do the same: this window
// has the main window as parent and so never becomes the application's
// main window, and AppKit hands the front back to the main window. The
// window system may do that only after the current event, so assert the
// order now and once more from the event loop.
void ThemeDesignerDialog::keepInFront()
{
    // A designer that is closing stays closed.
    if (!isVisible())
        return;
    raise();
    activateWindow();
    QTimer::singleShot(0, this, [this]() {
        if (!isVisible())
            return;
        raise();
        activateWindow();
    });
}

void ThemeDesignerDialog::newTheme()
{
    if (!maybeSaveChanges())
        return;

    ThemeNameDialog name_dialog(this, ThemeNameDialog::Mode::New, ThemeInfo(), tr("New Theme"));
    if (runChildDialog([&] { return name_dialog.exec(); }) != QDialog::Accepted)
        return;

    // A new theme only sets the colors that have no derivation, taken
    // from the default theme; everything else is derived.
    ThemeDraft defaults;
    if (!ThemeManager::instance()->loadDraft(ThemeManager::defaultThemeName(), defaults)) {
        showError(tr("The theme \"%1\" could not be loaded.").arg(ThemeManager::defaultThemeName()));
        return;
    }
    ThemeDraft draft;
    draft.info.name = name_dialog.name();
    for (ThemeManager::ThemeToken token : ThemeDraft::requiredTokens()) {
        const auto it = defaults.colors.constFind(token);
        if (it != defaults.colors.constEnd())
            draft.colors.insert(token, it.value());
    }

    saveAsPersonal(draft, ThemeWriter::uniqueStem(draft.info.name));
}

void ThemeDesignerDialog::copyTheme()
{
    if (current_stem_.isEmpty() || !maybeSaveChanges())
        return;

    // The copy is made from the saved state of the selected theme.
    ThemeDraft draft = base_;
    ThemeNameDialog name_dialog(this, ThemeNameDialog::Mode::Copy, base_.info,
                                copyName(base_.info.name));
    if (runChildDialog([&] { return name_dialog.exec(); }) != QDialog::Accepted)
        return;
    draft.info.name = name_dialog.name();

    saveAsPersonal(draft, ThemeWriter::uniqueStem(draft.info.name));
}

void ThemeDesignerDialog::renameTheme()
{
    if (current_stem_.isEmpty() || isBundledDraft())
        return;

    // The rename writes the draft, so unsaved edits must be savable.
    if (isDirty() && !canSave()) {
        showError(tr("The theme has changes that cannot be saved. Fix or revert them before renaming it."));
        return;
    }

    const QString old_stem = current_stem_;
    ThemeNameDialog name_dialog(this, ThemeNameDialog::Mode::Rename, base_.info,
                                draft_.info.name, old_stem);
    if (runChildDialog([&] { return name_dialog.exec(); }) != QDialog::Accepted)
        return;

    ThemeDraft draft = draft_;
    draft.info.name = name_dialog.name();
    const QString new_stem = ThemeWriter::uniqueStem(draft.info.name, old_stem);
    if (!writeDraft(draft, new_stem))
        return;

    QString removed_stem;
    if (new_stem != old_stem) {
        const QString old_path = ThemeManager::personalThemePath(old_stem);
        if (QFile::remove(old_path)) {
            removed_stem = old_stem;
        } else {
            showError(tr("The theme was saved as %1, but the old file %2 could not be removed.")
                      .arg(QDir::toNativeSeparators(ThemeManager::personalThemePath(new_stem)),
                           QDir::toNativeSeparators(old_path)));
        }
    }

    selectWrittenTheme(new_stem);
    notifySaved(new_stem, removed_stem);
}

void ThemeDesignerDialog::deleteTheme()
{
    if (current_stem_.isEmpty() || isBundledDraft())
        return;

    const QString stem = current_stem_;
    const QString path = ThemeManager::personalThemePath(stem);
    QMessageBox confirm(QMessageBox::Question, base_title_,
                        tr("Delete the theme \"%1\"?").arg(base_.info.name),
                        QMessageBox::Yes | QMessageBox::Cancel, this);
    confirm.setInformativeText(tr("The file %1 is removed. This cannot be undone.")
                               .arg(QDir::toNativeSeparators(path)));
    confirm.button(QMessageBox::Yes)->setText(tr("Delete"));
    confirm.setDefaultButton(QMessageBox::Cancel);
    if (runChildDialog([&] { return confirm.exec(); }) != QMessageBox::Yes)
        return;

    if (!QFile::remove(path)) {
        showError(tr("The file %1 could not be removed.").arg(QDir::toNativeSeparators(path)));
        return;
    }

    // Deleting the active theme falls back to the flavor default.
    const bool was_active = isActiveTheme(stem);
    if (was_active)
        activateTheme(ThemeManager::defaultThemeName());

    QString next = ThemeManager::selectedThemeName();
    if (next == stem)
        next = ThemeManager::defaultThemeName();

    // The unsaved edits belonged to the removed file and are dropped.
    current_stem_.clear();
    if (!loadTheme(next))
        draftChanged();
    populateThemeList(current_stem_);

    if (context_ == Context::Preferences)
        emit themeRemoved(stem);
}

void ThemeDesignerDialog::importTheme()
{
    if (!maybeSaveChanges())
        return;

    const QString path = runChildDialog([&] { return WiresharkFileDialog::getOpenFileName(
            this, mainApp->windowTitleString(tr("Import Theme")),
            mainApp->openDialogInitialDir().path(), tr("Theme files (*.jsonc *.json)")); });
    if (path.isEmpty())
        return;
    mainApp->setLastOpenDirFromFilename(path);

    const QFileInfo file_info(path);
    QString fatal;
    QByteArray bytes;
    QFile file(path);
    if (file.size() > kMaxImportSize) {
        fatal = tr("The file is larger than 1 MiB.");
    } else if (!file.open(QIODevice::ReadOnly)) {
        fatal = tr("The file could not be read: %1").arg(file.errorString());
    } else {
        bytes = file.read(kMaxImportSize + 1);
        if (bytes.size() > kMaxImportSize)
            fatal = tr("The file is larger than 1 MiB.");
    }

    // Imports are strict: anything that would be dropped or guessed at
    // while loading is a reason to refuse the file.
    ThemeDraft draft;
    ThemeParseReport report;
    if (fatal.isEmpty()) {
        QString error;
        if (!ThemeManager::instance()->parseDraft(bytes, file_info.completeBaseName(), draft,
                                                  &error, &report)) {
            fatal = error.isEmpty() ? tr("The file is not a theme.") : error;
        }
    }
    const bool refused = !fatal.isEmpty() || report.invalidValues > 0
                         || report.unknownTopLevelKeys > 0 || !draft.hasRequiredColors();
    if (refused) {
        QStringList messages = report.messages;
        if (!fatal.isEmpty())
            messages.prepend(fatal);
        runChildDialog([&] { return ThemeImportErrorDialog(this, file_info.fileName(), messages).exec(); });
        return;
    }

    draft.removeInvalidEntries();
    if (draft.info.name.trimmed().isEmpty())
        draft.info.name = file_info.completeBaseName();

    const QString stem = ThemeWriter::uniqueStem(draft.info.name);
    if (!saveAsPersonal(draft, stem))
        return;

    // Two strings instead of %n: English numerus forms only exist after
    // translators run lupdate.
    const int notes = static_cast<int>(report.messages.size());
    if (notes == 0)
        status_note_ = tr("Imported.");
    else if (notes == 1)
        status_note_ = tr("Imported with 1 note.");
    else
        status_note_ = tr("Imported with %1 notes.").arg(notes);
    status_note_tool_tip_ = report.messages.join('\n');
    updateStatus();
}

void ThemeDesignerDialog::exportTheme()
{
    const QString stem = current_stem_.isEmpty() ? ThemeWriter::sanitizeStem(draft_.info.name)
                                                 : current_stem_;
    const QString path = runChildDialog([&] { return WiresharkFileDialog::getSaveFileName(
            this, mainApp->windowTitleString(tr("Export Theme")),
            mainApp->openDialogInitialDir().filePath(stem + QStringLiteral(".jsonc")),
            tr("Theme files (*.jsonc *.json)")); });
    if (path.isEmpty())
        return;
    mainApp->setLastOpenDirFromFilename(path);

    QString error;
    if (!ThemeWriter::writeFile(draft_, path, &error)) {
        showError(tr("The theme could not be exported to %1: %2")
                  .arg(QDir::toNativeSeparators(path), error));
    }
}

void ThemeDesignerDialog::saveDraft()
{
    if (current_stem_.isEmpty() || !canSave())
        return;

    if (!isBundledDraft()) {
        saveAsPersonal(draft_, current_stem_);
        return;
    }

    // Bundled themes are never written; their changes become a new
    // personal theme.
    ThemeNameDialog name_dialog(this, ThemeNameDialog::Mode::SaveAs, base_.info,
                                copyName(draft_.info.name));
    if (runChildDialog([&] { return name_dialog.exec(); }) != QDialog::Accepted)
        return;

    ThemeDraft draft = draft_;
    draft.info.name = name_dialog.name();
    saveAsPersonal(draft, ThemeWriter::uniqueStem(draft.info.name));
}

void ThemeDesignerDialog::useTheme()
{
    if (current_stem_.isEmpty() || isDirty() || ui_->colorEditor->invalidCount() > 0)
        return;
    activateTheme(current_stem_);
}
