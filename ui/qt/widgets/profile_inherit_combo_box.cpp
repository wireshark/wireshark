/* profile_inherit_combo_box.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/profile_inherit_combo_box.h>

#include <ui/qt/widgets/elided_label.h>
#include <ui/qt/widgets/list_edit_buttons.h>

#include <app/application_flavor.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>

#include <ui/qt/utils/themes/themed_icon.h>

#include <QApplication>
#include <QBoxLayout>
#include <QFontMetrics>
#include <QHash>
#include <QMessageBox>
#include <QPushButton>
#include <QColor>
#include <QPainter>
#include <QPixmap>
#include <QStyle>
#include <QStyleOptionViewItem>
#include <QUrl>
#include <QWheelEvent>

ProfileInheritComboBox::ProfileInheritComboBox(QWidget *parent, const QString &filename) :
    QComboBox(parent),
    last_mode_(PROFILE_INHERIT_PROFILE_ONLY)
{
    addItem(tr("Profile only"), PROFILE_INHERIT_PROFILE_ONLY);
    addItem(tr("Profile and Parent"), PROFILE_INHERIT_PROFILE_AND_PARENT);
    addItem(tr("Parent only"), PROFILE_INHERIT_PARENT_ONLY);
    // Like the other combo boxes in the button rows, e.g. the I/O Graphs
    // interval, so it follows the application font and zoom
    setSizeAdjustPolicy(QComboBox::AdjustToContents);
    // Scrolling the list past the combo box must not change where entries come from
    setFocusPolicy(Qt::StrongFocus);
    setAccessibleName(tr("Entry source"));

    connect(this, &QComboBox::currentIndexChanged, this, &ProfileInheritComboBox::indexChanged);

    setFilename(filename);
}

ProfileInheritComboBox *ProfileInheritComboBox::addNextTo(QWidget *parent, QBoxLayout *layout, ListEditButtons *edit_buttons,
                                                          const QString &filename,
                                                          std::function<bool()> has_unsaved_changes,
                                                          std::function<bool()> save_changes)
{
    ProfileInheritComboBox *combo = new ProfileInheritComboBox(parent, filename);
    combo->setUnsavedChangesCheck(has_unsaved_changes, save_changes);
    layout->insertWidget(layout->indexOf(edit_buttons) + 1, combo);
    QWidget::setTabOrder(edit_buttons->clearButton(), combo);
    return combo;
}

bool ProfileInheritComboBox::canInherit() const
{
    return !filename_.isEmpty() && profile_can_inherit(NULL);
}

profile_inherit_e ProfileInheritComboBox::savedMode() const
{
    if (!canInherit())
        return PROFILE_INHERIT_PROFILE_ONLY;

    return profile_get_inherit(application_configuration_environment_prefix(), NULL,
                               filename_.toUtf8().constData());
}

void ProfileInheritComboBox::setFilename(const QString &filename)
{
    filename_ = filename;

    // The Default profile has no parent, so there is nothing to select
    if (!canInherit()) {
        hide();
    } else if (isHidden() && parentWidget()) {
        show();
    }

    syncMode(savedMode());
    updateToolTips();
}

profile_inherit_e ProfileInheritComboBox::mode() const
{
    if (!canInherit())
        return PROFILE_INHERIT_PROFILE_ONLY;

    return static_cast<profile_inherit_e>(currentData().toInt());
}

void ProfileInheritComboBox::setMode(profile_inherit_e mode)
{
    setCurrentIndex(findData(mode));
}

void ProfileInheritComboBox::useOwnEntries()
{
    if (mode() != PROFILE_INHERIT_PARENT_ONLY)
        return;

    setMode(PROFILE_INHERIT_PROFILE_AND_PARENT);
    setToolTip(tr("%1\nSwitched so that the new entry of this profile is used.").arg(toolTip()));
}

void ProfileInheritComboBox::syncMode(profile_inherit_e mode)
{
    QSignalBlocker blocker(this);
    setCurrentIndex(findData(mode));
    last_mode_ = mode;
}

bool ProfileInheritComboBox::saveMode(QString &err)
{
    // Compare with the stored mode, which another dialog may have changed
    if (!canInherit() || mode() == savedMode())
        return true;

    char *err_info = NULL;
    if (!profile_set_inherit(application_configuration_environment_prefix(), NULL,
                             filename_.toUtf8().constData(), mode(), &err_info)) {
        err = gchar_free_to_qstring(err_info);
        return false;
    }

    return true;
}

QString ProfileInheritComboBox::ownEntriesNotUsedText()
{
    return tr("Not available while only the entries of the parent profile are used. "
              "Choose \u201cProfile and Parent\u201d to add entries of your own.");
}

void ProfileInheritComboBox::setOwnEntriesUsed(QWidget *widget, bool own_used)
{
    if (widget == nullptr)
        return;

    // The tool tip describing what the button does, kept to bring back
    const char *saved = "_ws_own_tooltip";
    if (!widget->property(saved).isValid())
        widget->setProperty(saved, widget->toolTip());
    QString base = widget->property(saved).toString();
    widget->setToolTip(own_used ? base : QStringLiteral("%1\n%2").arg(base, ownEntriesNotUsedText()));
}

void ProfileInheritComboBox::setPathText(ElidedLabel *label, const QString &own_path, const QStringList &source_profiles) const
{
    QStringList names;
    for (const QString &profile : source_profiles)
        names << QStringLiteral("'%1'").arg(profile);
    QString profiles = names.join(QStringLiteral(", "));

    if (profiles.isEmpty()) {
        label->setText(own_path);
    } else if (mode() == PROFILE_INHERIT_PARENT_ONLY || own_path.isEmpty()) {
        label->setText(tr("From %1").arg(profiles));
    } else {
        label->setText(own_path + tr(" + from %1").arg(profiles));
    }
}

void ProfileInheritComboBox::updatePathLabel(ElidedLabel *label, const QStringList &source_profiles) const
{
    QString abs_path = gchar_free_to_qstring(get_persconffile_path(filename_.toUtf8().constData(), true,
                                                                   application_configuration_environment_prefix()));
    bool exists = mode() != PROFILE_INHERIT_PARENT_ONLY && file_exists(abs_path.toUtf8().constData());

    setPathText(label, exists ? abs_path : QString(), source_profiles);
    label->setUrl(exists ? QUrl::fromLocalFile(abs_path).toString() : QString());
    label->setToolTip(exists ? tr("Open ") + filename_ : QString());
    label->setEnabled(exists);
}

// The size of a check box, but not taller than a row of text
static int inherited_icon_size()
{
    int size = QApplication::style()->pixelMetric(QStyle::PM_IndicatorHeight);
    size = qMin(size, QFontMetrics(QApplication::font()).height());

    // The lock is drawn on a 24 unit grid with 1.5 unit strokes. Snap the
    // size in device pixels to a multiple of 16, where the strokes are
    // whole pixels, as the shackle and the body are uneven otherwise.
    qreal ratio = qApp->devicePixelRatio();
    int snapped = qMax(1, qRound(size * ratio / 16.0)) * 16;
    return qRound(snapped / ratio);
}

QVariant ProfileInheritComboBox::inheritedData(int role, const QString &profile)
{
    switch (role) {
    case Qt::FontRole:
    {
        QFont font;
        font.setItalic(true);
        return font;
    }
    case Qt::ForegroundRole:
        return ColorUtils::disabledForeground();
    case Qt::ToolTipRole:
    case Qt::AccessibleDescriptionRole:
        return inheritedText(profile);
    default:
        return QVariant();
    }
}

/* Fixed size pixmaps of a themed icon, as a scalable icon would take the view's icon size */
static QIcon inheritedSizedIcon(const char *name, const QColor &color)
{
    // Fixed size pixmaps, as a scalable icon would take the view's icon size.
    // Rendered from the file each time, so the lock follows the current
    // theme and screen scale. The pixmaps must be rendered at the device
    // pixel ratio, or they are drawn at 1x and scaled up, which blurs the
    // thin strokes of the lock.
    QSize size(inherited_icon_size(), inherited_icon_size());
    qreal ratio = qApp->devicePixelRatio();
    QIcon icon;
    ThemedIcon themed(name);
    QPixmap normal = themed.pixmap(size, ratio, QIcon::Normal);
    if (color.isValid()) {
        // Draw the icon in the given color, keeping its shape
        QPainter painter(&normal);
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(normal.rect(), color);
    }
    icon.addPixmap(normal, QIcon::Normal);
    icon.addPixmap(themed.pixmap(size, ratio, QIcon::Selected), QIcon::Selected);
    icon.addPixmap(themed.pixmap(size, ratio, QIcon::Disabled), QIcon::Disabled);
    return icon;
}

QIcon ProfileInheritComboBox::inheritedIcon(const QColor &color)
{
    return inheritedSizedIcon("lock-closed", color);
}

QIcon ProfileInheritComboBox::overriddenIcon(const QColor &color)
{
    return inheritedSizedIcon("overridden", color);
}

QIcon ProfileInheritComboBox::inheritedPlaceholderIcon()
{
    static QHash<int, QIcon> icons;
    int size = inherited_icon_size();
    if (!icons.contains(size)) {
        QPixmap pixmap(size, size);
        pixmap.fill(Qt::transparent);
        icons.insert(size, QIcon(pixmap));
    }
    return icons.value(size);
}

QSize ProfileInheritComboBox::inheritedSizeHint(QStyleOptionViewItem opt, QSize size, bool check_box)
{
    if (!(opt.features & QStyleOptionViewItem::HasDecoration) ||
        opt.decorationSize.height() > inherited_icon_size()) {
        return size;
    }

    opt.features &= ~QStyleOptionViewItem::HasDecoration;
    if (check_box) {
        opt.features |= QStyleOptionViewItem::HasCheckIndicator;
    }
    const QWidget *widget = opt.widget;
    QStyle *style = widget ? widget->style() : QApplication::style();
    int height = style->sizeFromContents(QStyle::CT_ItemViewItem, &opt, QSize(), widget).height();
    size.setHeight(qMax(height, opt.decorationSize.height()));
    return size;
}

QString ProfileInheritComboBox::notUsedText(const QString &profile)
{
    return tr("Not used: this profile has a matching entry that overrides the entry inherited from \"%1\".").arg(profile);
}

QString ProfileInheritComboBox::inheritedText(const QString &profile)
{
    return tr("Inherited from profile '%1'").arg(profile);
}

void ProfileInheritComboBox::wheelEvent(QWheelEvent *event)
{
    if (!hasFocus()) {
        event->ignore();
        return;
    }
    QComboBox::wheelEvent(event);
}

void ProfileInheritComboBox::updateToolTips()
{
    char *parent_name = profile_parent_name(NULL);
    QString parent = parent_name ? QString::fromUtf8(parent_name) : QString();
    g_free(parent_name);

    setToolTip(tr("Choose where entries come from. The parent profile is '%1'.").arg(parent));
    setItemData(findData(PROFILE_INHERIT_PROFILE_ONLY),
                tr("Use the entries of this profile only."),
                Qt::ToolTipRole);
    setItemData(findData(PROFILE_INHERIT_PROFILE_AND_PARENT),
                tr("Use the entries of this profile first, then the entries from '%1' and its parents. "
                   "Entries from a parent with the same name as an entry of this profile are not used, "
                   "and neither are entries disabled in a parent.").arg(parent),
                Qt::ToolTipRole);
    setItemData(findData(PROFILE_INHERIT_PARENT_ONLY),
                tr("Use only the entries from '%1' and its parents. "
                   "The entries of this profile are kept, but not used. "
                   "Changes to them that are not saved are discarded.").arg(parent),
                Qt::ToolTipRole);
}

void ProfileInheritComboBox::indexChanged(int)
{
    if (mode() == PROFILE_INHERIT_PARENT_ONLY && has_unsaved_ && has_unsaved_()) {
        // The entries of this profile are dropped, and read again for another mode
        QMessageBox box(QMessageBox::Question, tr("Parent only"),
                        tr("The entries of this profile have changes that are not saved. "
                           "Only the entries of the parent profile are used, and the changes are discarded.%1")
                        .arg(save_ ? tr("\n\nSave and Continue writes the file now; closing the dialog with Cancel does not undo that.") : QString()),
                        QMessageBox::NoButton, this);
        QPushButton *save_button = save_ ? box.addButton(tr("Save and Continue"), QMessageBox::AcceptRole) : nullptr;
        QPushButton *discard_button = box.addButton(tr("Discard and Continue"), QMessageBox::DestructiveRole);
        QPushButton *cancel_button = box.addButton(QMessageBox::Cancel);
        box.setDefaultButton(cancel_button);
        box.exec();

        QAbstractButton *clicked = box.clickedButton();
        bool proceed = clicked == discard_button || (clicked == save_button && save_());
        if (!proceed) {
            syncMode(last_mode_);
            return;
        }
    }
    last_mode_ = mode();
    emit modeChanged(mode());
}
