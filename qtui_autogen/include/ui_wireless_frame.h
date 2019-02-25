/********************************************************************************
** Form generated from reading UI file 'wireless_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WIRELESS_FRAME_H
#define UI_WIRELESS_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_WirelessFrame
{
public:
    QHBoxLayout *horizontalLayout_3;
    QStackedWidget *stackedWidget;
    QWidget *interfacePage;
    QHBoxLayout *horizontalLayout;
    QLabel *interfaceLabel;
    QComboBox *interfaceComboBox;
    QSpacerItem *horizontalSpacer_3;
    QLabel *channelLabel;
    QComboBox *channelComboBox;
    QComboBox *channelTypeComboBox;
    QFrame *fcsFilterFrame;
    QHBoxLayout *fcsFilterHLayout;
    QSpacerItem *horizontalSpacer_2;
    QLabel *fcsLabel;
    QComboBox *fcsComboBox;
    QWidget *noWirelessPage;
    QHBoxLayout *horizontalLayout_2;
    QLabel *noWirelessLabel;
    QSpacerItem *horizontalSpacer;
    QToolButton *helperToolButton;
    QToolButton *prefsToolButton;

    void setupUi(QFrame *WirelessFrame)
    {
        if (WirelessFrame->objectName().isEmpty())
            WirelessFrame->setObjectName(QString::fromUtf8("WirelessFrame"));
        WirelessFrame->resize(955, 20);
        WirelessFrame->setFrameShape(QFrame::NoFrame);
        WirelessFrame->setFrameShadow(QFrame::Plain);
        horizontalLayout_3 = new QHBoxLayout(WirelessFrame);
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        horizontalLayout_3->setContentsMargins(-1, 0, -1, 0);
        stackedWidget = new QStackedWidget(WirelessFrame);
        stackedWidget->setObjectName(QString::fromUtf8("stackedWidget"));
        interfacePage = new QWidget();
        interfacePage->setObjectName(QString::fromUtf8("interfacePage"));
        horizontalLayout = new QHBoxLayout(interfacePage);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(-1, 0, -1, 0);
        interfaceLabel = new QLabel(interfacePage);
        interfaceLabel->setObjectName(QString::fromUtf8("interfaceLabel"));

        horizontalLayout->addWidget(interfaceLabel);

        interfaceComboBox = new QComboBox(interfacePage);
        interfaceComboBox->setObjectName(QString::fromUtf8("interfaceComboBox"));
        interfaceComboBox->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        horizontalLayout->addWidget(interfaceComboBox);

        horizontalSpacer_3 = new QSpacerItem(12, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        channelLabel = new QLabel(interfacePage);
        channelLabel->setObjectName(QString::fromUtf8("channelLabel"));

        horizontalLayout->addWidget(channelLabel);

        channelComboBox = new QComboBox(interfacePage);
        channelComboBox->setObjectName(QString::fromUtf8("channelComboBox"));
        channelComboBox->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        horizontalLayout->addWidget(channelComboBox);

        channelTypeComboBox = new QComboBox(interfacePage);
        channelTypeComboBox->setObjectName(QString::fromUtf8("channelTypeComboBox"));
        channelTypeComboBox->setSizeAdjustPolicy(QComboBox::AdjustToContents);

        horizontalLayout->addWidget(channelTypeComboBox);

        fcsFilterFrame = new QFrame(interfacePage);
        fcsFilterFrame->setObjectName(QString::fromUtf8("fcsFilterFrame"));
        fcsFilterFrame->setFrameShape(QFrame::NoFrame);
        fcsFilterFrame->setFrameShadow(QFrame::Plain);
        fcsFilterFrame->setLineWidth(0);
        fcsFilterHLayout = new QHBoxLayout(fcsFilterFrame);
        fcsFilterHLayout->setObjectName(QString::fromUtf8("fcsFilterHLayout"));
        fcsFilterHLayout->setContentsMargins(-1, 0, -1, 0);
        horizontalSpacer_2 = new QSpacerItem(37, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        fcsFilterHLayout->addItem(horizontalSpacer_2);

        fcsLabel = new QLabel(fcsFilterFrame);
        fcsLabel->setObjectName(QString::fromUtf8("fcsLabel"));

        fcsFilterHLayout->addWidget(fcsLabel);

        fcsComboBox = new QComboBox(fcsFilterFrame);
        fcsComboBox->addItem(QString());
        fcsComboBox->addItem(QString());
        fcsComboBox->addItem(QString());
        fcsComboBox->setObjectName(QString::fromUtf8("fcsComboBox"));

        fcsFilterHLayout->addWidget(fcsComboBox);


        horizontalLayout->addWidget(fcsFilterFrame);

        stackedWidget->addWidget(interfacePage);
        noWirelessPage = new QWidget();
        noWirelessPage->setObjectName(QString::fromUtf8("noWirelessPage"));
        horizontalLayout_2 = new QHBoxLayout(noWirelessPage);
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        horizontalLayout_2->setContentsMargins(-1, 0, -1, 0);
        noWirelessLabel = new QLabel(noWirelessPage);
        noWirelessLabel->setObjectName(QString::fromUtf8("noWirelessLabel"));

        horizontalLayout_2->addWidget(noWirelessLabel);

        stackedWidget->addWidget(noWirelessPage);

        horizontalLayout_3->addWidget(stackedWidget);

        horizontalSpacer = new QSpacerItem(40, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer);

        helperToolButton = new QToolButton(WirelessFrame);
        helperToolButton->setObjectName(QString::fromUtf8("helperToolButton"));

        horizontalLayout_3->addWidget(helperToolButton);

        prefsToolButton = new QToolButton(WirelessFrame);
        prefsToolButton->setObjectName(QString::fromUtf8("prefsToolButton"));

        horizontalLayout_3->addWidget(prefsToolButton);


        retranslateUi(WirelessFrame);

        QMetaObject::connectSlotsByName(WirelessFrame);
    } // setupUi

    void retranslateUi(QFrame *WirelessFrame)
    {
        WirelessFrame->setWindowTitle(QApplication::translate("WirelessFrame", "Frame", nullptr));
        interfaceLabel->setText(QApplication::translate("WirelessFrame", "Interface", nullptr));
#ifndef QT_NO_TOOLTIP
        channelLabel->setToolTip(QApplication::translate("WirelessFrame", "<html><head/><body><p>Set the 802.11 channel.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        channelLabel->setText(QApplication::translate("WirelessFrame", "Channel", nullptr));
#ifndef QT_NO_TOOLTIP
        fcsLabel->setToolTip(QApplication::translate("WirelessFrame", "<html><head/><body><p>When capturing, show all frames, ones that have a valid frame check sequence (FCS), or ones with an invalid FCS.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        fcsLabel->setText(QApplication::translate("WirelessFrame", "FCS Filter", nullptr));
        fcsComboBox->setItemText(0, QApplication::translate("WirelessFrame", "All Frames", nullptr));
        fcsComboBox->setItemText(1, QApplication::translate("WirelessFrame", "Valid Frames", nullptr));
        fcsComboBox->setItemText(2, QApplication::translate("WirelessFrame", "Invalid Frames", nullptr));

        noWirelessLabel->setText(QApplication::translate("WirelessFrame", "Wireless controls are not supported in this version of Wireshark.", nullptr));
        helperToolButton->setText(QApplication::translate("WirelessFrame", "External Helper", nullptr));
#ifndef QT_NO_TOOLTIP
        prefsToolButton->setToolTip(QApplication::translate("WirelessFrame", "<html><head/><body><p>Show the IEEE 802.11 preferences, including decryption keys.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        prefsToolButton->setText(QApplication::translate("WirelessFrame", "802.11 Preferences", nullptr));
    } // retranslateUi

};

namespace Ui {
    class WirelessFrame: public Ui_WirelessFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WIRELESS_FRAME_H
