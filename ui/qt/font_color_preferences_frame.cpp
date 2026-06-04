/* font_color_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include "font_color_preferences_frame.h"
#include <ui/qt/models/pref_models.h>
#include <ui_font_color_preferences_frame.h>
#include <ui/qt/utils/theme_manager.h>
#include "main_application.h"
#include "wsutil/array.h"

#include <ui/recent.h>

#include <QApplication>
#include <QFontDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPalette>
#include <QVBoxLayout>

#include <epan/prefs-int.h>

//: These are pangrams. Feel free to replace with nonsense text that spans your alphabet.
//: https://en.wikipedia.org/wiki/Pangram
static const char *font_pangrams_[] = {
    QT_TRANSLATE_NOOP("FontColorPreferencesFrame", "Example GIF query packets have jumbo window sizes"),
    QT_TRANSLATE_NOOP("FontColorPreferencesFrame", "Lazy badgers move unique waxy jellyfish packets")
};
const int num_font_pangrams_ = array_length(font_pangrams_);

FontColorPreferencesFrame::FontColorPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::FontColorPreferencesFrame),
    colorSchemeComboBox_(nullptr),
    themeComboBox_(nullptr)
{
    ui->setupUi(this);

    // Appearance mode — System / Dark / Light.  Wired to prefs.gui_color_scheme
    // via the existing pref_stashed machinery.  Drives ThemeManager's light/
    // dark selection independently of which theme is active.
    colorSchemeComboBox_ = new QComboBox();
    colorSchemeComboBox_->addItem(tr("System"), COLOR_SCHEME_DEFAULT);
    colorSchemeComboBox_->addItem(tr("Light"),  COLOR_SCHEME_LIGHT);
    colorSchemeComboBox_->addItem(tr("Dark"),   COLOR_SCHEME_DARK);
    connect(colorSchemeComboBox_, QOverload<int>::of(&QComboBox::currentIndexChanged),
        this, &FontColorPreferencesFrame::colorSchemeIndexChanged);

    // Theme picker — populated from ThemeManager::availableThemes().
    // Persists its selection in recent_common.gui_theme_name via the
    // frame's stash/unstash flow, so the choice survives profile switches.
    themeComboBox_ = new QComboBox();
    // Resolve empty/legacy "default" to the flavor's preferred default so
    // the dropdown shows a real, currently-shipped theme selected on
    // first run instead of an entry that no longer exists.
    stashed_theme_name_ = ThemeManager::resolveThemeName(
            QString::fromUtf8(recent.gui_theme_name));
    const QList<ThemeInfo> themes = ThemeManager::availableThemes();
    int selectedIdx = -1;
    for (int i = 0; i < themes.size(); ++i) {
        const ThemeInfo &t = themes.at(i);
        // Show the theme name only; the author moves to a hint label below
        // the preview (set in refreshPreview()) so the dropdown stays clean.
        // The author is stashed in a private item-data role to feed it.
        themeComboBox_->addItem(t.name, t.internalName);
        themeComboBox_->setItemData(i, t.author, Qt::UserRole + 1);
        if (!t.description.isEmpty())
            themeComboBox_->setItemData(i, t.description, Qt::ToolTipRole);
        if (t.internalName == stashed_theme_name_)
            selectedIdx = i;
    }
    if (selectedIdx >= 0)
        themeComboBox_->setCurrentIndex(selectedIdx);
    connect(themeComboBox_, QOverload<int>::of(&QComboBox::currentIndexChanged),
        this, &FontColorPreferencesFrame::themeIndexChanged);

    // Place both controls into the Theme group's QFormLayout so the
    // labels right-align in a column.
    ui->themeGroupLayout->addRow(tr("Appearance mode:"), colorSchemeComboBox_);
    ui->themeGroupLayout->addRow(tr("Theme:"),           themeComboBox_);

    pref_color_scheme_ = prefFromPrefPtr(&prefs.gui_color_scheme);
    pref_qt_gui_font_name_ = prefFromPrefPtr(&prefs.gui_font_name);

    cur_font_.fromString(prefs_get_string_value(pref_qt_gui_font_name_, pref_stashed));

    // Embed the hand-painted mockup into the placeholder container
    // reserved in font_color_preferences_frame.ui.  refreshPreview()
    // populates it lazily via showEvent → updateWidgets, so no initial
    // setPreviewColors() call is needed here.
    QVBoxLayout *previewLayout = new QVBoxLayout(ui->themePreviewContainer);
    previewLayout->setContentsMargins(0, 0, 0, 0);
    previewWidget_ = new ThemePreviewWidget(ui->themePreviewContainer);
    previewLayout->addWidget(previewWidget_);

    // Repaint the preview when the live theme changes underneath us.
    // ThemeManager emits themeChanged whenever the OS scheme flips while
    // the live mode is System (the detector hook re-applies and signals),
    // so keeping the dialog in sync requires nothing more than re-running
    // refreshPreview — the stashed dropdown choice doesn't change, but
    // the OS-resolved side of it does.
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &FontColorPreferencesFrame::refreshPreview);

    // Section headers: bold and 2pt larger than the body font.  Qt propagates
    // a widget's font to its children, so set the emphasized font on each
    // group box (which renders its title with it) then restore the body font
    // on the controls inside — including the combos and preview created above
    // — so only the titles grow.  Done last, after those children exist.
    QFont bodyFont = QApplication::font();
    QFont headerFont = bodyFont;
    headerFont.setBold(true);
    headerFont.setPointSizeF(bodyFont.pointSizeF() + 2);
    const QList<QGroupBox *> sectionBoxes = { ui->fontGroupBox, ui->themeGroupBox };
    for (QGroupBox *box : sectionBoxes) {
        box->setFont(headerFont);
        const QList<QWidget *> boxChildren = box->findChildren<QWidget *>();
        for (QWidget *child : boxChildren)
            child->setFont(bodyFont);
    }

    // Theme author and description hints: muted + italic like the page's
    // other hint labels.  Styled after the body-font reset above so the
    // italics survive it.  Description is shown verbatim from the theme's
    // meta.description; author is shown as "Theme by <author>".
    QFont hintFont = bodyFont;
    hintFont.setItalic(true);
    QPalette hintPalette = ui->themeAuthorLabel->palette();
    hintPalette.setColor(QPalette::WindowText,
                         hintPalette.color(QPalette::Disabled, QPalette::WindowText));
    for (QLabel *hint : { ui->themeAuthorLabel, ui->themeDescriptionLabel }) {
        hint->setFont(hintFont);
        hint->setPalette(hintPalette);
    }
}

FontColorPreferencesFrame::~FontColorPreferencesFrame()
{
    delete ui;
}

void FontColorPreferencesFrame::showEvent(QShowEvent *)
{
    GRand *rand_state = g_rand_new();
    QString pangram = QStringLiteral("%1 0123456789").arg(font_pangrams_[g_rand_int_range(rand_state, 0, num_font_pangrams_)]);
    ui->fontSampleLineEdit->setText(pangram);
    ui->fontSampleLineEdit->setCursorPosition(0);
    g_rand_free(rand_state);

    updateWidgets();
}

void FontColorPreferencesFrame::updateWidgets()
{
    int margin = style()->pixelMetric(QStyle::PM_LayoutLeftMargin);

    ui->fontPushButton->setText(
        cur_font_.family() + " " + cur_font_.styleName() + " " +
        QString::number(cur_font_.pointSizeF(), 'f', 1));

    QString line_edit_ss =
        QStringLiteral("QLineEdit { margin-left: %1px; }").arg(margin);
    ui->fontSampleLineEdit->setStyleSheet(line_edit_ss);
    ui->fontSampleLineEdit->setFont(cur_font_);

    if (colorSchemeComboBox_) {
        colorSchemeComboBox_->setCurrentIndex(
            colorSchemeComboBox_->findData(
                prefs_get_enum_value(pref_color_scheme_, pref_stashed)));
    }

    refreshPreview();
}

void FontColorPreferencesFrame::colorSchemeIndexChanged(int)
{
    if (colorSchemeComboBox_) {
        prefs_set_enum_value(pref_color_scheme_, colorSchemeComboBox_->currentData().toInt(), pref_stashed);
        // COLOR_SCHEME_DEFAULT is 0 so we don't need to check failure
        updateWidgets();
    }
}

void FontColorPreferencesFrame::themeIndexChanged(int)
{
    if (!themeComboBox_)
        return;
    // Stash the picked theme's internal name; unstash() commits to
    // recent_common on Apply.  Not applied live — a switch here requires
    // the user to accept the preferences dialog.
    stashed_theme_name_ = themeComboBox_->currentData().toString();
    refreshPreview();
}

void FontColorPreferencesFrame::unstash()
{
    g_free(recent.gui_theme_name);
    recent.gui_theme_name = stashed_theme_name_.isEmpty()
        ? nullptr
        : g_strdup(stashed_theme_name_.toUtf8().constData());
}

void FontColorPreferencesFrame::on_fontPushButton_clicked()
{
    bool ok;
    // QFontDialog::MonospacedFonts might not be supported on Mac by the native
    // dialog (or Linux GTK3 prior to Qt 6.12). Use DontUseNativeDialog option?
    QFont new_font = QFontDialog::getFont(&ok, cur_font_, this, mainApp->windowTitleString(tr("Font")), QFontDialog::MonospacedFonts);
    if (ok) {
        prefs_set_string_value(pref_qt_gui_font_name_, new_font.toString().toStdString().c_str(), pref_stashed);
        cur_font_ = new_font;
        updateWidgets();
    }
}

void FontColorPreferencesFrame::refreshPreview()
{
    // Constructor signal-firing safety: themeComboBox_->setCurrentIndex()
    // in the ctor fires themeIndexChanged before previewWidget_ is built.
    if (!previewWidget_)
        return;

    // Author and description hints below the preview, fed from the
    // stashed roles on the selected theme item (the dropdown itself
    // shows the name only).  Description is also kept on ToolTipRole so
    // it surfaces while browsing the dropdown.
    if (themeComboBox_) {
        const int idx = themeComboBox_->currentIndex();
        const QString author = themeComboBox_->itemData(
            idx, Qt::UserRole + 1).toString();
        ui->themeAuthorLabel->setText(
            author.isEmpty() ? QString() : tr("Theme by %1").arg(author));
        const QString description = themeComboBox_->itemData(
            idx, Qt::ToolTipRole).toString();
        ui->themeDescriptionLabel->setText(description);
    }

    // Map the stashed gui_color_scheme onto previewTheme's PreviewScheme
    // enum.  Default forwards "no preference" to previewTheme, which
    // resolves against the live OS detector — so picking System in the
    // dropdown immediately reflects the current OS appearance instead of
    // the previously-applied Light/Dark mode.  Resolving via the stashed
    // value (not isDarkMode()) is what fixes the bug where the live mode_
    // short-circuited the answer before the user pressed Apply.
    ThemeManager::PreviewScheme previewScheme;
    switch (prefs_get_enum_value(pref_color_scheme_, pref_stashed)) {
    case COLOR_SCHEME_LIGHT:
        previewScheme = ThemeManager::PreviewScheme::PreferLight;
        break;
    case COLOR_SCHEME_DARK:
        previewScheme = ThemeManager::PreviewScheme::PreferDark;
        break;
    default:
        previewScheme = ThemeManager::PreviewScheme::Default;
        break;
    }

    // The widget falls back per-token if the hash is empty (e.g. a
    // corrupt theme name or missing file), so passing an empty hash is
    // safe — the preview just falls back to the live ThemeManager's
    // colors token-by-token.
    previewWidget_->setPreviewColors(
        ThemeManager::instance()->previewTheme(stashed_theme_name_, previewScheme));
}
