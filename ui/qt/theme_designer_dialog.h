/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_DESIGNER_DIALOG_H
#define THEME_DESIGNER_DIALOG_H

#include <ui/qt/geometry_state_dialog.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/widgets/theme_preview_pick.h>

#include <QFont>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

class QAction;
class QComboBox;
class QLabel;
class QMenu;
class QPoint;
class QTreeWidgetItem;

namespace Ui {
class ThemeDesignerDialog;
}

/**
 * Creates, copies, edits, imports and exports personal themes.
 *
 * The dialog edits a draft of the selected theme and previews it on a
 * compact Welcome Page and a fake packet list window.  Nothing it shows
 * touches the live theme; bundled themes are never written.
 */
class ThemeDesignerDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /** Where the dialog was opened from; decides how a theme is activated. */
    enum class Context {
        Standalone,     ///< View > Internals: "Use Theme" activates directly
        Preferences     ///< Preferences page: activation happens on OK/Apply
    };

    /**
     * @param parent        parent widget.
     * @param context       where the dialog was opened from.
     * @param initialTheme  internal name of the theme to select first; the
     *                      active theme when empty.
     */
    explicit ThemeDesignerDialog(QWidget *parent, Context context = Context::Standalone,
                                 const QString &initialTheme = QString());
    ~ThemeDesignerDialog();

signals:
    /** A personal theme file was written under @p internalName. */
    void themeSaved(const QString &internalName);
    /** The personal theme file @p internalName was removed. */
    void themeRemoved(const QString &internalName);

public slots:
    void reject() override;

protected:
    bool event(QEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    // Theme list
    void populateThemeList(const QString &selectStem);
    QTreeWidgetItem *themeItem(const QString &stem) const;
    void updateListMarker();
    void themeSelectionChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    bool loadTheme(const QString &stem);
    void takeDrafts(const ThemeDraft &base, const ThemeDraft &draft);

    // Unsaved changes
    bool isDirty() const;
    bool isBundledDraft() const;
    int metaEditedCount() const;
    int fontEditedCount() const;
    bool canSave() const;
    bool maybeSaveChanges();
    void revertDraft();

    // Editor
    void metaEdited();
    void descriptionEdited();
    void updateDescriptionHeight();
    void sideToggled();
    void colorDraftChanged();
    void draftChanged();
    void updateMetaFields();

    // Fonts tab
    void tabChanged(int index);
    void fillFontFamilies();
    void updateFontControls();
    void fillFamilyCombo(QComboBox *combo, const QStringList &families, const QString &current);
    void fillSizeCombo(QComboBox *combo, int current);
    void fontFamilyChanged(bool monospace);
    void fontSizeChanged(bool monospace);
    void showFontContextMenu(bool monospace, QWidget *source, const QPoint &pos);
    void updateFontLabels();
    QFont resolvedFont(const ThemeFontHint &hint, bool monospace) const;

    // Code tab
    void updateCompareCombo();
    QString compareText();
    void compareChanged();
    void updateCodeView();
    void updateCodeCounts();
    void updateValidation();
    bool roundTrips(const ThemeDraft &draft, const QString &stem, QByteArray *jsonc = nullptr) const;
    void updateCodeBanner();
    QByteArray bundledJsonc(const QString &stem);
    void copyCode();

    // Playground, status and chrome
    void updatePlayground();
    void updateStatus();
    void updateButtons();
    void updateTitle();
    void refreshThemeDependentLabels();
    /** Re-applies the chrome colors and re-resolves the playground after the live theme or appearance changed. */
    void themeChanged();

    // Preview samples
    void previewTabChanged(int index);
    void previewLayerPicked(const ThemePreviewPick::Layer &layer);
    void previewPickMenu(QMenu *menu, QAction *before, const QList<ThemePreviewPick::Layer> &layers);
    /** Shows the tooltip naming @p layer at @p global_pos over @p sample, or hides it for NoRole. */
    void showPickTip(QWidget *sample, const ThemePreviewPick::Layer &layer, const QPoint &global_pos);

    // File operations
    void newTheme();
    void copyTheme();
    void renameTheme();
    void deleteTheme();
    void importTheme();
    void exportTheme();
    void saveDraft();
    void useTheme();
    bool isActiveTheme(const QString &stem) const;
    void showError(const QString &text);
    bool writeDraft(const ThemeDraft &draft, const QString &stem);
    bool saveAsPersonal(const ThemeDraft &draft, const QString &stem);
    void selectWrittenTheme(const QString &stem);
    void notifySaved(const QString &stem, const QString &removedStem = QString());
    void activateTheme(const QString &stem);
    void keepInFront();

    /**
     * Runs a child dialog and then keeps this window in front.  On macOS a
     * closing native panel or dialog hands the front to the main window,
     * because a window with a parent cannot be the application's main window.
     *
     * @param dialog  callable that shows the dialog and returns its result.
     * @return what @p dialog returned.
     */
    template <typename Dialog>
    auto runChildDialog(Dialog &&dialog) -> decltype(dialog())
    {
        auto result = dialog();
        keepInFront();
        return result;
    }

    Ui::ThemeDesignerDialog *ui_;
    Context context_;

    ThemeDraft base_;
    ThemeDraft draft_;
    ThemeParseReport load_report_;
    QString current_stem_;
    bool side_dark_;
    QString compare_;
    bool fonts_filled_;
    QStringList families_;
    QStringList monospace_families_;
    QHash<QString, QByteArray> bundled_jsonc_;
    QByteArray draft_jsonc_;        // The draft as written, updated with the validation
    QString validation_error_;
    QString status_note_;           // Shown instead of the status until the next edit or load
    QString status_note_tool_tip_;
    bool picked_once_ = false;      // The hover hint is shown until the first pick
    QHash<QObject *, ThemePreviewPicker *> pickers_;  // Pick state per preview sample, for eventFilter() and the hover tooltip
    QList<ThemeInfo> themes_;       // Sorted by name, filled by populateThemeList()
    QString base_title_;
};

#endif // THEME_DESIGNER_DIALOG_H
