/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_INHERIT_COMBO_BOX_H
#define PROFILE_INHERIT_COMBO_BOX_H

#include <config.h>

#include <wsutil/profile_inherit.h>

#include <QComboBox>
#include <functional>

class ElidedLabel;
class ListEditButtons;
class QBoxLayout;
#include <QIcon>
#include <QStringList>
#include <QStyleOptionViewItem>

/**
 * @brief A combo box selecting where the entries of a configuration file come from.
 *
 * The entries can come from the current profile only, from the profile and
 * its parent profiles, or from the parent profiles only. The combo box is
 * hidden for the Default profile, which has no parent.
 */
class ProfileInheritComboBox : public QComboBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ProfileInheritComboBox.
     * @param parent The parent widget.
     * @param filename The configuration file name, as used by CopyFromProfileButton.
     */
    explicit ProfileInheritComboBox(QWidget *parent = nullptr, const QString &filename = QString());

    /**
     * @brief Creates the combo box next to the buttons editing a list, reached by Tab after the button clearing it.
     * @param parent The parent widget, the dialog.
     * @param layout The layout holding the edit buttons.
     * @param edit_buttons The buttons editing the list.
     * @param filename The configuration file name, as used by CopyFromProfileButton.
     * @return The combo box.
     */
    static ProfileInheritComboBox *addNextTo(QWidget *parent, QBoxLayout *layout, ListEditButtons *edit_buttons,
                                             const QString &filename,
                                             std::function<bool()> has_unsaved_changes = nullptr,
                                             std::function<bool()> save_changes = nullptr);

    /**
     * @brief Sets how to tell that the entries of this profile have changes not saved.
     *
     * "Parent only" drops the entries of this profile, and reads them again for
     * another mode, so choosing it asks first if there are such changes: to
     * save them, to discard them, or to keep the mode.
     * @param has_unsaved_changes Returns true if there are changes not saved.
     * @param save_changes Saves the changes without closing the dialog and returns true on success; without it the question has no save button.
     */
    void setUnsavedChangesCheck(std::function<bool()> has_unsaved_changes, std::function<bool()> save_changes = nullptr)
    {
        has_unsaved_ = has_unsaved_changes;
        save_ = save_changes;
    }

    /**
     * @brief Sets the configuration file name and selects its saved inherit mode.
     * @param filename The configuration file name, empty to hide the combo box.
     */
    void setFilename(const QString &filename);

    /**
     * @brief The selected inherit mode.
     * @return The mode, PROFILE_INHERIT_PROFILE_ONLY if the profile cannot inherit.
     */
    profile_inherit_e mode() const;

    /**
     * @brief Selects an inherit mode, as the user would.
     * @param mode The mode.
     */
    void setMode(profile_inherit_e mode);

    /**
     * @brief Selects "Profile and Parent" if only the parent's entries are used, and tells why in the tool tip.
     *
     * For a dialog opened to add an entry, which is an own entry.
     */
    void useOwnEntries();

    /**
     * @brief Shows the mode in use, e.g. after another dialog changed it, without emitting modeChanged().
     * @param mode The mode.
     */
    void syncMode(profile_inherit_e mode);

    /**
     * @brief Saves the selected mode in the profile settings, if it differs from the stored mode.
     * @param err Set to an error message on failure.
     * @return true on success.
     */
    bool saveMode(QString &err);

    /**
     * @brief Sets the text of a path label, naming the profiles entries are inherited from.
     *
     * The label's text is the own path followed by the profiles, e.g.
     * "/path + from 'Corporate', 'Default'".
     * @param label The path label.
     * @param own_path The path of the own file, or an empty string if not in use or not there.
     * @param source_profiles The parent profiles the entries in use come from, nearest first,
     * as given by inheritedProfiles(). A parent without such entries is not named.
     */
    void setPathText(ElidedLabel *label, const QString &own_path, const QStringList &source_profiles) const;

    /**
     * @brief Shows the path of the own file of the configuration file, if it is there and in use, and the profiles entries come from.
     *
     * The path links to the file.
     * @param label The path label.
     * @param source_profiles The parent profiles the entries in use come from, as for setPathText().
     */
    void updatePathLabel(ElidedLabel *label, const QStringList &source_profiles) const;

    /**
     * @brief Tells why a button is disabled while only the parent's entries are used.
     * @param widget The button, which keeps its own tool tip otherwise.
     * @param own_used False if the entries of the profile are not used.
     */
    static void setOwnEntriesUsed(QWidget *widget, bool own_used);

    /**
     * @brief Why a button adding entries is disabled while only the parent's entries are used.
     * @return The explanation.
     */
    static QString ownEntriesNotUsedText();

    /**
     * @brief The look of an entry inherited from a parent profile.
     *
     * Italics, the disabled text color and a description naming the profile.
     * @param role The item data role.
     * @param profile The profile the entry comes from.
     * @return The data, or an invalid QVariant for a role not styled.
     */
    static QVariant inheritedData(int role, const QString &profile);

    /**
     * @brief The lock marking an entry inherited from a parent profile.
     *
     * Sized like a check box, which it replaces, so that rows keep their height.
     * @param color The color to draw the icon in, an invalid color for the theme's.
     * @return The icon.
     */
    static QIcon inheritedIcon(const QColor &color = QColor());

    /**
     * @brief The icon marking an inherited entry not used, as an own entry overrides it.
     *
     * Sized like inheritedIcon().
     * @param color The color to draw the icon in, an invalid color for the theme's.
     * @return The icon.
     */
    static QIcon overriddenIcon(const QColor &color = QColor());

    /**
     * @brief An empty icon the size of inheritedIcon(), lining up own entries with inherited ones.
     * @return The icon.
     */
    static QIcon inheritedPlaceholderIcon();

    /**
     * @brief The size of an item showing inheritedIcon() or inheritedPlaceholderIcon().
     *
     * The style adds room around an icon, which makes a row with the lock taller than
     * a row of text only. The height is the one of the item without the icon, or with
     * a check box when the column has check boxes, which the lock replaces.
     * For use in QStyledItemDelegate::sizeHint().
     * @param opt The style options of the item, set up by QStyledItemDelegate::initStyleOption().
     * @param size The size from QStyledItemDelegate::sizeHint().
     * @param check_box True if the column has check boxes, also when no row shows one.
     * @return The size.
     */
    static QSize inheritedSizeHint(QStyleOptionViewItem opt, QSize size, bool check_box);

    /**
     * @brief The description of an entry inherited from a parent profile, e.g. for its tool tip.
     * @param profile The parent profile the entry comes from.
     * @return The text.
     */
    static QString inheritedText(const QString &profile);

    /**
     * @brief Tells why an inherited entry is not used.
     * @param profile The profile the entry comes from.
     * @return The explanation: an entry of this profile overrides it.
     */
    static QString notUsedText(const QString &profile);

protected:
    void wheelEvent(QWheelEvent *event) override;

signals:
    /**
     * @brief Emitted when the user selects another inherit mode.
     * @param mode The new mode.
     */
    void modeChanged(profile_inherit_e mode);

private:
    QString filename_;

    /** The mode before the last change, to go back to if the change is not confirmed. */
    profile_inherit_e last_mode_;

    /** Tells if the entries of this profile have changes not saved. */
    std::function<bool()> has_unsaved_;

    /** Saves the entries of this profile without closing the dialog. */
    std::function<bool()> save_;

    bool canInherit() const;
    profile_inherit_e savedMode() const;
    void updateToolTips();

private slots:
    void indexChanged(int);
};

#endif // PROFILE_INHERIT_COMBO_BOX_H
