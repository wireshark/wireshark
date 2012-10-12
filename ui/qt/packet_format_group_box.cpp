#include "packet_format_group_box.h"
#include "ui_packet_format_group_box.h"

#include <QStyle>
#include <QDebug>

PacketFormatGroupBox::PacketFormatGroupBox(QWidget *parent) :
    QGroupBox(parent),
    pf_ui_(new Ui::PacketFormatGroupBox)
{
    pf_ui_->setupUi(this);

    setStyleSheet(QString(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(style()->pixelMetric(QStyle::PM_LayoutLeftMargin)));
}

PacketFormatGroupBox::~PacketFormatGroupBox()
{
    delete pf_ui_;
}

bool PacketFormatGroupBox::summaryEnabled()
{
    return pf_ui_->summaryCheckBox->isChecked();
}

bool PacketFormatGroupBox::detailsEnabled()
{
    return pf_ui_->detailsCheckBox->isChecked();
}

bool PacketFormatGroupBox::bytesEnabled()
{
    return pf_ui_->bytesCheckBox->isChecked();
}

bool PacketFormatGroupBox::allCollapsedEnabled()
{
    return pf_ui_->allCollapsedButton->isChecked();
}

bool PacketFormatGroupBox::asDisplayedEnabled()
{
    return pf_ui_->asDisplayedButton->isChecked();
}

bool PacketFormatGroupBox::allExpandedEnabled()
{
    return pf_ui_->allExpandedButton->isChecked();
}

void PacketFormatGroupBox::on_summaryCheckBox_toggled(bool checked)
{
    Q_UNUSED(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_detailsCheckBox_toggled(bool checked)
{
    pf_ui_->allCollapsedButton->setEnabled(checked);
    pf_ui_->asDisplayedButton->setEnabled(checked);
    pf_ui_->allExpandedButton->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_bytesCheckBox_toggled(bool checked)
{
    Q_UNUSED(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_allCollapsedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_asDisplayedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_allExpandedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}
