/********************************************************************************
** Form generated from reading UI file 'layout_preferences_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LAYOUT_PREFERENCES_FRAME_H
#define UI_LAYOUT_PREFERENCES_FRAME_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_LayoutPreferencesFrame
{
public:
    QVBoxLayout *verticalLayout_4;
    QHBoxLayout *horizontalLayout;
    QToolButton *layout5ToolButton;
    QToolButton *layout2ToolButton;
    QToolButton *layout1ToolButton;
    QToolButton *layout4ToolButton;
    QToolButton *layout3ToolButton;
    QToolButton *layout6ToolButton;
    QHBoxLayout *horizontalLayout_2;
    QVBoxLayout *verticalLayout_3;
    QLabel *label;
    QRadioButton *pane1PacketListRadioButton;
    QRadioButton *pane1PacketDetailsRadioButton;
    QRadioButton *pane1PacketBytesRadioButton;
    QRadioButton *pane1NoneRadioButton;
    QVBoxLayout *verticalLayout_2;
    QLabel *label_2;
    QRadioButton *pane2PacketListRadioButton;
    QRadioButton *pane2PacketDetailsRadioButton;
    QRadioButton *pane2PacketBytesRadioButton;
    QRadioButton *pane2NoneRadioButton;
    QVBoxLayout *verticalLayout;
    QLabel *label_3;
    QRadioButton *pane3PacketListRadioButton;
    QRadioButton *pane3PacketDetailsRadioButton;
    QRadioButton *pane3PacketBytesRadioButton;
    QRadioButton *pane3NoneRadioButton;
    QSpacerItem *verticalSpacer_2;
    QLabel *packetListSettings;
    QCheckBox *packetListSeparatorCheckBox;
    QSpacerItem *verticalSpacer_3;
    QLabel *statusBarSettings;
    QCheckBox *statusBarShowSelectedPacketCheckBox;
    QCheckBox *statusBarShowFileLoadTimeCheckBox;
    QSpacerItem *verticalSpacer;
    QDialogButtonBox *restoreButtonBox;
    QButtonGroup *layoutButtonGroup;
    QButtonGroup *pane2ButtonGroup;
    QButtonGroup *pane3ButtonGroup;
    QButtonGroup *pane1ButtonGroup;

    void setupUi(QFrame *LayoutPreferencesFrame)
    {
        if (LayoutPreferencesFrame->objectName().isEmpty())
            LayoutPreferencesFrame->setObjectName(QString::fromUtf8("LayoutPreferencesFrame"));
        LayoutPreferencesFrame->resize(414, 287);
        LayoutPreferencesFrame->setFrameShape(QFrame::NoFrame);
        LayoutPreferencesFrame->setFrameShadow(QFrame::Plain);
        LayoutPreferencesFrame->setLineWidth(0);
        verticalLayout_4 = new QVBoxLayout(LayoutPreferencesFrame);
        verticalLayout_4->setObjectName(QString::fromUtf8("verticalLayout_4"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        layout5ToolButton = new QToolButton(LayoutPreferencesFrame);
        layoutButtonGroup = new QButtonGroup(LayoutPreferencesFrame);
        layoutButtonGroup->setObjectName(QString::fromUtf8("layoutButtonGroup"));
        layoutButtonGroup->addButton(layout5ToolButton);
        layout5ToolButton->setObjectName(QString::fromUtf8("layout5ToolButton"));
        layout5ToolButton->setMinimumSize(QSize(0, 0));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/layout/layout_5.png"), QSize(), QIcon::Normal, QIcon::Off);
        layout5ToolButton->setIcon(icon);
        layout5ToolButton->setIconSize(QSize(48, 48));
        layout5ToolButton->setCheckable(true);

        horizontalLayout->addWidget(layout5ToolButton);

        layout2ToolButton = new QToolButton(LayoutPreferencesFrame);
        layoutButtonGroup->addButton(layout2ToolButton);
        layout2ToolButton->setObjectName(QString::fromUtf8("layout2ToolButton"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/layout/layout_2.png"), QSize(), QIcon::Normal, QIcon::Off);
        layout2ToolButton->setIcon(icon1);
        layout2ToolButton->setIconSize(QSize(48, 48));
        layout2ToolButton->setCheckable(true);

        horizontalLayout->addWidget(layout2ToolButton);

        layout1ToolButton = new QToolButton(LayoutPreferencesFrame);
        layoutButtonGroup->addButton(layout1ToolButton);
        layout1ToolButton->setObjectName(QString::fromUtf8("layout1ToolButton"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/layout/layout_1.png"), QSize(), QIcon::Normal, QIcon::Off);
        layout1ToolButton->setIcon(icon2);
        layout1ToolButton->setIconSize(QSize(48, 48));
        layout1ToolButton->setCheckable(true);

        horizontalLayout->addWidget(layout1ToolButton);

        layout4ToolButton = new QToolButton(LayoutPreferencesFrame);
        layoutButtonGroup->addButton(layout4ToolButton);
        layout4ToolButton->setObjectName(QString::fromUtf8("layout4ToolButton"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/layout/layout_4.png"), QSize(), QIcon::Normal, QIcon::Off);
        layout4ToolButton->setIcon(icon3);
        layout4ToolButton->setIconSize(QSize(48, 48));
        layout4ToolButton->setCheckable(true);

        horizontalLayout->addWidget(layout4ToolButton);

        layout3ToolButton = new QToolButton(LayoutPreferencesFrame);
        layoutButtonGroup->addButton(layout3ToolButton);
        layout3ToolButton->setObjectName(QString::fromUtf8("layout3ToolButton"));
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/layout/layout_3.png"), QSize(), QIcon::Normal, QIcon::Off);
        layout3ToolButton->setIcon(icon4);
        layout3ToolButton->setIconSize(QSize(48, 48));
        layout3ToolButton->setCheckable(true);

        horizontalLayout->addWidget(layout3ToolButton);

        layout6ToolButton = new QToolButton(LayoutPreferencesFrame);
        layoutButtonGroup->addButton(layout6ToolButton);
        layout6ToolButton->setObjectName(QString::fromUtf8("layout6ToolButton"));
        QIcon icon5;
        icon5.addFile(QString::fromUtf8(":/layout/layout_6.png"), QSize(), QIcon::Normal, QIcon::Off);
        layout6ToolButton->setIcon(icon5);
        layout6ToolButton->setIconSize(QSize(48, 48));
        layout6ToolButton->setCheckable(true);

        horizontalLayout->addWidget(layout6ToolButton);


        verticalLayout_4->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        verticalLayout_3 = new QVBoxLayout();
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        label = new QLabel(LayoutPreferencesFrame);
        label->setObjectName(QString::fromUtf8("label"));

        verticalLayout_3->addWidget(label);

        pane1PacketListRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane1ButtonGroup = new QButtonGroup(LayoutPreferencesFrame);
        pane1ButtonGroup->setObjectName(QString::fromUtf8("pane1ButtonGroup"));
        pane1ButtonGroup->addButton(pane1PacketListRadioButton);
        pane1PacketListRadioButton->setObjectName(QString::fromUtf8("pane1PacketListRadioButton"));

        verticalLayout_3->addWidget(pane1PacketListRadioButton);

        pane1PacketDetailsRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane1ButtonGroup->addButton(pane1PacketDetailsRadioButton);
        pane1PacketDetailsRadioButton->setObjectName(QString::fromUtf8("pane1PacketDetailsRadioButton"));

        verticalLayout_3->addWidget(pane1PacketDetailsRadioButton);

        pane1PacketBytesRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane1ButtonGroup->addButton(pane1PacketBytesRadioButton);
        pane1PacketBytesRadioButton->setObjectName(QString::fromUtf8("pane1PacketBytesRadioButton"));

        verticalLayout_3->addWidget(pane1PacketBytesRadioButton);

        pane1NoneRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane1ButtonGroup->addButton(pane1NoneRadioButton);
        pane1NoneRadioButton->setObjectName(QString::fromUtf8("pane1NoneRadioButton"));

        verticalLayout_3->addWidget(pane1NoneRadioButton);


        horizontalLayout_2->addLayout(verticalLayout_3);

        verticalLayout_2 = new QVBoxLayout();
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        label_2 = new QLabel(LayoutPreferencesFrame);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        verticalLayout_2->addWidget(label_2);

        pane2PacketListRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane2ButtonGroup = new QButtonGroup(LayoutPreferencesFrame);
        pane2ButtonGroup->setObjectName(QString::fromUtf8("pane2ButtonGroup"));
        pane2ButtonGroup->addButton(pane2PacketListRadioButton);
        pane2PacketListRadioButton->setObjectName(QString::fromUtf8("pane2PacketListRadioButton"));

        verticalLayout_2->addWidget(pane2PacketListRadioButton);

        pane2PacketDetailsRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane2ButtonGroup->addButton(pane2PacketDetailsRadioButton);
        pane2PacketDetailsRadioButton->setObjectName(QString::fromUtf8("pane2PacketDetailsRadioButton"));

        verticalLayout_2->addWidget(pane2PacketDetailsRadioButton);

        pane2PacketBytesRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane2ButtonGroup->addButton(pane2PacketBytesRadioButton);
        pane2PacketBytesRadioButton->setObjectName(QString::fromUtf8("pane2PacketBytesRadioButton"));

        verticalLayout_2->addWidget(pane2PacketBytesRadioButton);

        pane2NoneRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane2ButtonGroup->addButton(pane2NoneRadioButton);
        pane2NoneRadioButton->setObjectName(QString::fromUtf8("pane2NoneRadioButton"));

        verticalLayout_2->addWidget(pane2NoneRadioButton);


        horizontalLayout_2->addLayout(verticalLayout_2);

        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        label_3 = new QLabel(LayoutPreferencesFrame);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        verticalLayout->addWidget(label_3);

        pane3PacketListRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane3ButtonGroup = new QButtonGroup(LayoutPreferencesFrame);
        pane3ButtonGroup->setObjectName(QString::fromUtf8("pane3ButtonGroup"));
        pane3ButtonGroup->addButton(pane3PacketListRadioButton);
        pane3PacketListRadioButton->setObjectName(QString::fromUtf8("pane3PacketListRadioButton"));

        verticalLayout->addWidget(pane3PacketListRadioButton);

        pane3PacketDetailsRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane3ButtonGroup->addButton(pane3PacketDetailsRadioButton);
        pane3PacketDetailsRadioButton->setObjectName(QString::fromUtf8("pane3PacketDetailsRadioButton"));

        verticalLayout->addWidget(pane3PacketDetailsRadioButton);

        pane3PacketBytesRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane3ButtonGroup->addButton(pane3PacketBytesRadioButton);
        pane3PacketBytesRadioButton->setObjectName(QString::fromUtf8("pane3PacketBytesRadioButton"));

        verticalLayout->addWidget(pane3PacketBytesRadioButton);

        pane3NoneRadioButton = new QRadioButton(LayoutPreferencesFrame);
        pane3ButtonGroup->addButton(pane3NoneRadioButton);
        pane3NoneRadioButton->setObjectName(QString::fromUtf8("pane3NoneRadioButton"));

        verticalLayout->addWidget(pane3NoneRadioButton);


        horizontalLayout_2->addLayout(verticalLayout);


        verticalLayout_4->addLayout(horizontalLayout_2);

        verticalSpacer_2 = new QSpacerItem(20, 10, QSizePolicy::Minimum, QSizePolicy::Fixed);

        verticalLayout_4->addItem(verticalSpacer_2);

        packetListSettings = new QLabel(LayoutPreferencesFrame);
        packetListSettings->setObjectName(QString::fromUtf8("packetListSettings"));

        verticalLayout_4->addWidget(packetListSettings);

        packetListSeparatorCheckBox = new QCheckBox(LayoutPreferencesFrame);
        packetListSeparatorCheckBox->setObjectName(QString::fromUtf8("packetListSeparatorCheckBox"));

        verticalLayout_4->addWidget(packetListSeparatorCheckBox);

        verticalSpacer_3 = new QSpacerItem(20, 10, QSizePolicy::Minimum, QSizePolicy::Fixed);

        verticalLayout_4->addItem(verticalSpacer_3);

        statusBarSettings = new QLabel(LayoutPreferencesFrame);
        statusBarSettings->setObjectName(QString::fromUtf8("statusBarSettings"));

        verticalLayout_4->addWidget(statusBarSettings);

        statusBarShowSelectedPacketCheckBox = new QCheckBox(LayoutPreferencesFrame);
        statusBarShowSelectedPacketCheckBox->setObjectName(QString::fromUtf8("statusBarShowSelectedPacketCheckBox"));

        verticalLayout_4->addWidget(statusBarShowSelectedPacketCheckBox);

        statusBarShowFileLoadTimeCheckBox = new QCheckBox(LayoutPreferencesFrame);
        statusBarShowFileLoadTimeCheckBox->setObjectName(QString::fromUtf8("statusBarShowFileLoadTimeCheckBox"));

        verticalLayout_4->addWidget(statusBarShowFileLoadTimeCheckBox);

        verticalSpacer = new QSpacerItem(68, 13, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_4->addItem(verticalSpacer);

        restoreButtonBox = new QDialogButtonBox(LayoutPreferencesFrame);
        restoreButtonBox->setObjectName(QString::fromUtf8("restoreButtonBox"));
        restoreButtonBox->setStandardButtons(QDialogButtonBox::RestoreDefaults);

        verticalLayout_4->addWidget(restoreButtonBox);


        retranslateUi(LayoutPreferencesFrame);

        QMetaObject::connectSlotsByName(LayoutPreferencesFrame);
    } // setupUi

    void retranslateUi(QFrame *LayoutPreferencesFrame)
    {
        LayoutPreferencesFrame->setWindowTitle(QApplication::translate("LayoutPreferencesFrame", "Frame", nullptr));
        layout5ToolButton->setText(QString());
        layout2ToolButton->setText(QString());
        layout1ToolButton->setText(QString());
        layout4ToolButton->setText(QString());
        layout3ToolButton->setText(QString());
        layout6ToolButton->setText(QString());
        label->setText(QApplication::translate("LayoutPreferencesFrame", "Pane 1:", nullptr));
        pane1PacketListRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet List", nullptr));
        pane1PacketDetailsRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet Details", nullptr));
        pane1PacketBytesRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet Bytes", nullptr));
        pane1NoneRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "None", nullptr));
        label_2->setText(QApplication::translate("LayoutPreferencesFrame", "Pane 2:", nullptr));
        pane2PacketListRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet List", nullptr));
        pane2PacketDetailsRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet Details", nullptr));
        pane2PacketBytesRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet Bytes", nullptr));
        pane2NoneRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "None", nullptr));
        label_3->setText(QApplication::translate("LayoutPreferencesFrame", "Pane 3:", nullptr));
        pane3PacketListRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet List", nullptr));
        pane3PacketDetailsRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet Details", nullptr));
        pane3PacketBytesRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "Packet Bytes", nullptr));
        pane3NoneRadioButton->setText(QApplication::translate("LayoutPreferencesFrame", "None", nullptr));
        packetListSettings->setText(QApplication::translate("LayoutPreferencesFrame", "Packet List settings:", nullptr));
        packetListSeparatorCheckBox->setText(QApplication::translate("LayoutPreferencesFrame", "Show packet separator", nullptr));
        statusBarSettings->setText(QApplication::translate("LayoutPreferencesFrame", "Status Bar settings:", nullptr));
        statusBarShowSelectedPacketCheckBox->setText(QApplication::translate("LayoutPreferencesFrame", "Show selected packet number", nullptr));
        statusBarShowFileLoadTimeCheckBox->setText(QApplication::translate("LayoutPreferencesFrame", "Show file load time", nullptr));
    } // retranslateUi

};

namespace Ui {
    class LayoutPreferencesFrame: public Ui_LayoutPreferencesFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LAYOUT_PREFERENCES_FRAME_H
