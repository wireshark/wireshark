#ifndef PACKET_FORMAT_GROUP_BOX_H
#define PACKET_FORMAT_GROUP_BOX_H

#include <QGroupBox>

namespace Ui {
class PacketFormatGroupBox;
}

class PacketFormatGroupBox : public QGroupBox
{
    Q_OBJECT
    
public:
    explicit PacketFormatGroupBox(QWidget *parent = 0);
    ~PacketFormatGroupBox();

    bool summaryEnabled();
    bool detailsEnabled();
    bool bytesEnabled();

    bool allCollapsedEnabled();
    bool asDisplayedEnabled();
    bool allExpandedEnabled();

signals:
    void formatChanged();

private slots:
    void on_detailsCheckBox_toggled(bool checked);
    void on_summaryCheckBox_toggled(bool checked);
    void on_bytesCheckBox_toggled(bool checked);
    void on_allCollapsedButton_toggled(bool checked);
    void on_asDisplayedButton_toggled(bool checked);
    void on_allExpandedButton_toggled(bool checked);

private:
    Ui::PacketFormatGroupBox *pf_ui_;
};

#endif // PACKET_FORMAT_GROUP_BOX_H
