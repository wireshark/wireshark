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
#include <ui_font_color_preferences_frame.h>
#include <ui/qt/utils/theme_manager.h>

#include <ui/recent.h>

#include <QFormLayout>
#include <QVBoxLayout>

FontColorPreferencesFrame::FontColorPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::FontColorPreferencesFrame)
{
    ui->setupUi(this);

    // Appearance mode — System / Dark / Light.  Stashed in
    // stashed_color_scheme_ and committed to recent.gui_color_scheme (global
    // recent_common storage) on Apply.  Drives ThemeManager's light/dark
    // selection independently of which theme is active.
    stashed_color_scheme_ = recent.gui_color_scheme;

    ui->colorSchemeComboBox->clear();
    ui->colorSchemeComboBox->addItem(tr("System"), COLOR_SCHEME_DEFAULT);
    ui->colorSchemeComboBox->addItem(tr("Light"),  COLOR_SCHEME_LIGHT);
    ui->colorSchemeComboBox->addItem(tr("Dark"),   COLOR_SCHEME_DARK);
    connect(ui->colorSchemeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
        this, &FontColorPreferencesFrame::colorSchemeIndexChanged);

    // Theme picker — populated from ThemeManager::availableThemes().
    // Persists its selection in recent_common.gui_theme_name via the
    // frame's stash/unstash flow, so the choice survives profile switches.
    ui->themeComboBox->clear();
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
        ui->themeComboBox->addItem(t.name, t.internalName);
        ui->themeComboBox->setItemData(i, t.author, Qt::UserRole + 1);
        if (!t.description.isEmpty())
            ui->themeComboBox->setItemData(i, t.description, Qt::ToolTipRole);
        if (t.internalName == stashed_theme_name_)
            selectedIdx = i;
    }
    if (selectedIdx >= 0)
        ui->themeComboBox->setCurrentIndex(selectedIdx);
    connect(ui->themeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
        this, &FontColorPreferencesFrame::themeIndexChanged);

    // Repaint the preview when the live theme changes underneath us.
    // ThemeManager emits themeChanged whenever the OS scheme flips while
    // the live mode is System (the detector hook re-applies and signals),
    // so keeping the dialog in sync requires nothing more than re-running
    // refreshPreview — the stashed dropdown choice doesn't change, but
    // the OS-resolved side of it does.
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &FontColorPreferencesFrame::refreshPreview);

    // Section title and theme hints share their styling with the Fonts page.
    // Done last, after the combos and the preview above exist.
    set_section_title_font(ui->themeGroupBox);
    set_hint_label_style(ui->themeAuthorLabel);
    set_hint_label_style(ui->themeDescriptionLabel);
}

FontColorPreferencesFrame::~FontColorPreferencesFrame()
{
    delete ui;
}

void FontColorPreferencesFrame::showEvent(QShowEvent *)
{
    updateWidgets();
}

void FontColorPreferencesFrame::updateWidgets()
{
    if (ui->colorSchemeComboBox) {
        ui->colorSchemeComboBox->setCurrentIndex(
            ui->colorSchemeComboBox->findData(stashed_color_scheme_));
    }

    refreshPreview();
}

void FontColorPreferencesFrame::colorSchemeIndexChanged(int)
{
    if (ui->colorSchemeComboBox) {
        stashed_color_scheme_ = ui->colorSchemeComboBox->currentData().toInt();
        updateWidgets();
    }
}

void FontColorPreferencesFrame::themeIndexChanged(int)
{
    if (!ui->themeComboBox)
        return;
    // Stash the picked theme's internal name; unstash() commits to
    // recent_common on Apply.  Not applied live — a switch here requires
    // the user to accept the preferences dialog.
    stashed_theme_name_ = ui->themeComboBox->currentData().toString();
    refreshPreview();
}

void FontColorPreferencesFrame::unstash()
{
    g_free(recent.gui_theme_name);
    recent.gui_theme_name = stashed_theme_name_.isEmpty()
        ? nullptr
        : g_strdup(stashed_theme_name_.toUtf8().constData());

    recent.gui_color_scheme = stashed_color_scheme_;
}

void FontColorPreferencesFrame::refreshPreview()
{
    // Author and description hints below the preview, fed from the
    // stashed roles on the selected theme item (the dropdown itself
    // shows the name only).  Description is also kept on ToolTipRole so
    // it surfaces while browsing the dropdown.
    if (ui->themeComboBox) {
        const int idx = ui->themeComboBox->currentIndex();
        const QString author = ui->themeComboBox->itemData(
            idx, Qt::UserRole + 1).toString();
        ui->themeAuthorLabel->setText(
            author.isEmpty() ? QString() : tr("Theme by %1").arg(author));
        const QString description = ui->themeComboBox->itemData(
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
    switch (stashed_color_scheme_) {
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
    ui->previewWidget->setPreviewColors(
        ThemeManager::instance()->previewTheme(stashed_theme_name_, previewScheme));
}
