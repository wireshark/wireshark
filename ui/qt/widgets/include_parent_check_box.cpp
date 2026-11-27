/* include_parent_check_box.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/include_parent_check_box.h>

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
#include <QColor>
#include <QPainter>
#include <QPixmap>
#include <QStyle>
#include <QStyleOptionViewItem>
#include <QUrl>
#include <QEvent>

IncludeParentCheckBox::IncludeParentCheckBox(QWidget *parent, const QString &filename) :
    QCheckBox(tr("Include parent"), parent)
{
    setAccessibleName(tr("Include the entries of the parent profiles"));

    connect(this, &QCheckBox::toggled, this, &IncludeParentCheckBox::includeParentChanged);

    setFilename(filename);
}

IncludeParentCheckBox *IncludeParentCheckBox::addNextTo(QWidget *parent, QBoxLayout *layout, ListEditButtons *edit_buttons,
                                                        const QString &filename)
{
    IncludeParentCheckBox *check_box = new IncludeParentCheckBox(parent, filename);
    layout->insertWidget(layout->indexOf(edit_buttons) + 1, check_box);
    QWidget::setTabOrder(edit_buttons->clearButton(), check_box);
    return check_box;
}

bool IncludeParentCheckBox::hasParent() const
{
    return !filename_.isEmpty() && profile_has_parent(NULL);
}

bool IncludeParentCheckBox::savedIncludeParent() const
{
    return hasParent() &&
           profile_get_include_parent(application_configuration_environment_prefix(), NULL, filename_.toUtf8().constData());
}

void IncludeParentCheckBox::setFilename(const QString &filename)
{
    filename_ = filename;

    // The Default profile has no parent, so there is nothing to select
    if (!hasParent()) {
        hide();
    } else if (isHidden() && parentWidget()) {
        show();
    }

    syncIncludeParent(savedIncludeParent());
    updateToolTip();
}

bool IncludeParentCheckBox::includesParent() const
{
    return hasParent() && isChecked();
}

void IncludeParentCheckBox::syncIncludeParent(bool include_parent)
{
    QSignalBlocker blocker(this);
    setChecked(include_parent);
}

bool IncludeParentCheckBox::saveIncludeParent(QString &err)
{
    // Compare with the stored setting, which another dialog may have changed
    if (!hasParent() || includesParent() == savedIncludeParent())
        return true;

    char *err_info = NULL;
    if (!profile_set_include_parent(application_configuration_environment_prefix(), NULL,
                                    filename_.toUtf8().constData(), includesParent(), &err_info)) {
        err = gchar_free_to_qstring(err_info);
        return false;
    }

    return true;
}

void IncludeParentCheckBox::setPathText(ElidedLabel *label, const QString &own_path, const QStringList &source_profiles) const
{
    QStringList names;
    for (const QString &profile : source_profiles)
        names << QStringLiteral("'%1'").arg(profile);
    QString profiles = names.join(QStringLiteral(", "));

    // Only the own path is linked; the profiles follow as plain text
    if (profiles.isEmpty()) {
        label->setText(own_path);
        label->setSuffix(QString());
    } else if (own_path.isEmpty()) {
        label->setText(QString());
        label->setSuffix(tr("From %1").arg(profiles));
    } else {
        label->setText(own_path);
        label->setSuffix(tr(" + from %1").arg(profiles));
    }
}

void IncludeParentCheckBox::updatePathLabel(ElidedLabel *label, const QStringList &source_profiles) const
{
    QString abs_path = gchar_free_to_qstring(get_persconffile_path(filename_.toUtf8().constData(), true,
                                                                   application_configuration_environment_prefix()));
    bool exists = file_exists(abs_path.toUtf8().constData());

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

QVariant IncludeParentCheckBox::inheritedData(int role, const QString &profile)
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

QIcon IncludeParentCheckBox::inheritedIcon(const QColor &color)
{
    return inheritedSizedIcon("lock-closed", color);
}

QIcon IncludeParentCheckBox::overriddenIcon(const QColor &color)
{
    return inheritedSizedIcon("overridden", color);
}

QIcon IncludeParentCheckBox::inheritedPlaceholderIcon()
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

QSize IncludeParentCheckBox::inheritedSizeHint(const QStyleOptionViewItem &option, QSize size, bool check_box)
{
    if (!(option.features & QStyleOptionViewItem::HasDecoration) ||
        option.decorationSize.height() > inherited_icon_size()) {
        return size;
    }

    QStyleOptionViewItem opt(option);
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

QString IncludeParentCheckBox::notUsedText(const QString &profile)
{
    return tr("Not used: this profile has a matching entry that overrides the entry included from \"%1\".").arg(profile);
}

QString IncludeParentCheckBox::inheritedText(const QString &profile)
{
    return tr("Included from profile '%1'").arg(profile);
}

bool IncludeParentCheckBox::event(QEvent *event)
{
    // The parents may have changed what they include since the last time
    if (event->type() == QEvent::ToolTip)
        updateToolTip();
    return QCheckBox::event(event);
}

void IncludeParentCheckBox::updateToolTip()
{
    if (!hasParent()) {
        setToolTip(QString());
        return;
    }

    // The profiles the entries come from when including the parent profiles, nearest first
    QStringList names;
    GPtrArray *layers = profile_inherit_layers(application_configuration_environment_prefix(), NULL,
                                               filename_.toUtf8().constData(), true);
    for (unsigned i = 0; i < layers->len; i++) {
        const profile_inherit_layer_t *layer = static_cast<const profile_inherit_layer_t *>(g_ptr_array_index(layers, i));
        names << QStringLiteral("'%1'").arg(QString::fromUtf8(layer->source));
    }
    g_ptr_array_unref(layers);

    setToolTip(tr("Also use the entries of each parent profile: %1.\n"
                  "An entry of this profile overrides an entry with the same name.\n"
                  "Entries disabled in a parent are not used.").arg(names.join(QStringLiteral(", "))));
}
