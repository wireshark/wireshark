/********************************************************************************
** Form generated from reading UI file 'capture_interfaces_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CAPTURE_INTERFACES_DIALOG_H
#define UI_CAPTURE_INTERFACES_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include "widgets/capture_filter_combo.h"

QT_BEGIN_NAMESPACE

class Ui_CaptureInterfacesDialog
{
public:
    QVBoxLayout *verticalLayout_12;
    QTabWidget *tabWidget;
    QWidget *inputTab;
    QVBoxLayout *verticalLayout_2;
    QTreeWidget *interfaceTree;
    QHBoxLayout *horizontalLayout;
    QCheckBox *capturePromModeCheckBox;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *manageButton;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label_4;
    CaptureFilterCombo *captureFilterComboBox;
    QSpacerItem *horizontalSpacer_4;
    QPushButton *compileBPF;
    QWidget *outputTab;
    QVBoxLayout *verticalLayout_9;
    QGroupBox *gbCaptureToFile;
    QGridLayout *gridLayout_3;
    QPushButton *browseButton;
    QLabel *label_2;
    QLineEdit *filenameLineEdit;
    QHBoxLayout *horizontalLayout_3;
    QLabel *label;
    QRadioButton *rbPcapng;
    QRadioButton *rbPcap;
    QSpacerItem *horizontalSpacer_7;
    QGroupBox *gbNewFileAuto;
    QGridLayout *gridLayout;
    QSpacerItem *horizontalSpacer_8;
    QCheckBox *MBCheckBox;
    QCheckBox *SecsCheckBox;
    QSpinBox *SecsSpinBox;
    QComboBox *SecsComboBox;
    QSpinBox *MBSpinBox;
    QComboBox *MBComboBox;
    QCheckBox *PktCheckBox;
    QSpinBox *PktSpinBox;
    QLabel *PktLabel;
    QHBoxLayout *horizontalLayout_4;
    QCheckBox *RbCheckBox;
    QSpinBox *RbSpinBox;
    QLabel *label_3;
    QSpacerItem *horizontalSpacer_9;
    QSpacerItem *verticalSpacer_2;
    QWidget *optionsTab;
    QFormLayout *formLayout;
    QHBoxLayout *horizontalLayout_8;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout;
    QCheckBox *cbUpdatePacketsRT;
    QCheckBox *cbAutoScroll;
    QCheckBox *cbExtraCaptureInfo;
    QSpacerItem *horizontalSpacer_3;
    QGroupBox *groupBox_2;
    QVBoxLayout *verticalLayout_3;
    QCheckBox *cbResolveMacAddresses;
    QCheckBox *cbResolveNetworkNames;
    QCheckBox *cbResolveTransportNames;
    QSpacerItem *horizontalSpacer_5;
    QGroupBox *gbStopCaptureAuto;
    QGridLayout *gridLayout_2;
    QSpinBox *stopPktSpinBox;
    QSpinBox *stopMBSpinBox;
    QCheckBox *stopMBCheckBox;
    QLabel *label_7;
    QCheckBox *stopSecsCheckBox;
    QComboBox *stopSecsComboBox;
    QCheckBox *stopPktCheckBox;
    QComboBox *stopMBComboBox;
    QSpinBox *stopSecsSpinBox;
    QSpacerItem *horizontalSpacer;
    QSpinBox *stopFilesSpinBox;
    QLabel *label_8;
    QCheckBox *stopFilesCheckBox;
    QSpacerItem *verticalSpacer_3;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *CaptureInterfacesDialog)
    {
        if (CaptureInterfacesDialog->objectName().isEmpty())
            CaptureInterfacesDialog->setObjectName(QString::fromUtf8("CaptureInterfacesDialog"));
        CaptureInterfacesDialog->resize(950, 440);
        verticalLayout_12 = new QVBoxLayout(CaptureInterfacesDialog);
        verticalLayout_12->setObjectName(QString::fromUtf8("verticalLayout_12"));
        tabWidget = new QTabWidget(CaptureInterfacesDialog);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        inputTab = new QWidget();
        inputTab->setObjectName(QString::fromUtf8("inputTab"));
        verticalLayout_2 = new QVBoxLayout(inputTab);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        interfaceTree = new QTreeWidget(inputTab);
        interfaceTree->setObjectName(QString::fromUtf8("interfaceTree"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(interfaceTree->sizePolicy().hasHeightForWidth());
        interfaceTree->setSizePolicy(sizePolicy);
        interfaceTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
        interfaceTree->setTextElideMode(Qt::ElideMiddle);
        interfaceTree->setSortingEnabled(true);

        verticalLayout_2->addWidget(interfaceTree);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        capturePromModeCheckBox = new QCheckBox(inputTab);
        capturePromModeCheckBox->setObjectName(QString::fromUtf8("capturePromModeCheckBox"));

        horizontalLayout->addWidget(capturePromModeCheckBox);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        manageButton = new QPushButton(inputTab);
        manageButton->setObjectName(QString::fromUtf8("manageButton"));
        manageButton->setEnabled(true);

        horizontalLayout->addWidget(manageButton);


        verticalLayout_2->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        label_4 = new QLabel(inputTab);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        horizontalLayout_2->addWidget(label_4);

        captureFilterComboBox = new CaptureFilterCombo(inputTab);
        captureFilterComboBox->setObjectName(QString::fromUtf8("captureFilterComboBox"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(captureFilterComboBox->sizePolicy().hasHeightForWidth());
        captureFilterComboBox->setSizePolicy(sizePolicy1);

        horizontalLayout_2->addWidget(captureFilterComboBox);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_4);

        compileBPF = new QPushButton(inputTab);
        compileBPF->setObjectName(QString::fromUtf8("compileBPF"));

        horizontalLayout_2->addWidget(compileBPF);

        horizontalLayout_2->setStretch(1, 1);

        verticalLayout_2->addLayout(horizontalLayout_2);

        tabWidget->addTab(inputTab, QString());
        outputTab = new QWidget();
        outputTab->setObjectName(QString::fromUtf8("outputTab"));
        verticalLayout_9 = new QVBoxLayout(outputTab);
        verticalLayout_9->setObjectName(QString::fromUtf8("verticalLayout_9"));
        gbCaptureToFile = new QGroupBox(outputTab);
        gbCaptureToFile->setObjectName(QString::fromUtf8("gbCaptureToFile"));
        gbCaptureToFile->setEnabled(true);
        gbCaptureToFile->setAutoFillBackground(false);
        gbCaptureToFile->setFlat(true);
        gbCaptureToFile->setCheckable(false);
        gridLayout_3 = new QGridLayout(gbCaptureToFile);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        browseButton = new QPushButton(gbCaptureToFile);
        browseButton->setObjectName(QString::fromUtf8("browseButton"));

        gridLayout_3->addWidget(browseButton, 0, 2, 1, 1);

        label_2 = new QLabel(gbCaptureToFile);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        gridLayout_3->addWidget(label_2, 0, 0, 1, 1);

        filenameLineEdit = new QLineEdit(gbCaptureToFile);
        filenameLineEdit->setObjectName(QString::fromUtf8("filenameLineEdit"));

        gridLayout_3->addWidget(filenameLineEdit, 0, 1, 1, 1);


        verticalLayout_9->addWidget(gbCaptureToFile);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        label = new QLabel(outputTab);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout_3->addWidget(label);

        rbPcapng = new QRadioButton(outputTab);
        rbPcapng->setObjectName(QString::fromUtf8("rbPcapng"));

        horizontalLayout_3->addWidget(rbPcapng);

        rbPcap = new QRadioButton(outputTab);
        rbPcap->setObjectName(QString::fromUtf8("rbPcap"));

        horizontalLayout_3->addWidget(rbPcap);

        horizontalSpacer_7 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_7);


        verticalLayout_9->addLayout(horizontalLayout_3);

        gbNewFileAuto = new QGroupBox(outputTab);
        gbNewFileAuto->setObjectName(QString::fromUtf8("gbNewFileAuto"));
        gbNewFileAuto->setFlat(true);
        gbNewFileAuto->setCheckable(true);
        gridLayout = new QGridLayout(gbNewFileAuto);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        horizontalSpacer_8 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout->addItem(horizontalSpacer_8, 0, 3, 4, 1);

        MBCheckBox = new QCheckBox(gbNewFileAuto);
        MBCheckBox->setObjectName(QString::fromUtf8("MBCheckBox"));

        gridLayout->addWidget(MBCheckBox, 2, 0, 1, 1);

        SecsCheckBox = new QCheckBox(gbNewFileAuto);
        SecsCheckBox->setObjectName(QString::fromUtf8("SecsCheckBox"));

        gridLayout->addWidget(SecsCheckBox, 3, 0, 1, 1);

        SecsSpinBox = new QSpinBox(gbNewFileAuto);
        SecsSpinBox->setObjectName(QString::fromUtf8("SecsSpinBox"));
        SecsSpinBox->setWrapping(true);
        SecsSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        SecsSpinBox->setMinimum(1);
        SecsSpinBox->setMaximum(1000000);
        SecsSpinBox->setValue(1);

        gridLayout->addWidget(SecsSpinBox, 3, 1, 1, 1);

        SecsComboBox = new QComboBox(gbNewFileAuto);
        SecsComboBox->addItem(QString());
        SecsComboBox->addItem(QString());
        SecsComboBox->addItem(QString());
        SecsComboBox->setObjectName(QString::fromUtf8("SecsComboBox"));

        gridLayout->addWidget(SecsComboBox, 3, 2, 1, 1);

        MBSpinBox = new QSpinBox(gbNewFileAuto);
        MBSpinBox->setObjectName(QString::fromUtf8("MBSpinBox"));
        MBSpinBox->setWrapping(true);
        MBSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        MBSpinBox->setMinimum(1);
        MBSpinBox->setMaximum(1000000);
        MBSpinBox->setValue(1);

        gridLayout->addWidget(MBSpinBox, 2, 1, 1, 1);

        MBComboBox = new QComboBox(gbNewFileAuto);
        MBComboBox->addItem(QString());
        MBComboBox->addItem(QString());
        MBComboBox->addItem(QString());
        MBComboBox->setObjectName(QString::fromUtf8("MBComboBox"));

        gridLayout->addWidget(MBComboBox, 2, 2, 1, 1);

        PktCheckBox = new QCheckBox(gbNewFileAuto);
        PktCheckBox->setObjectName(QString::fromUtf8("PktCheckBox"));

        gridLayout->addWidget(PktCheckBox, 1, 0, 1, 1);

        PktSpinBox = new QSpinBox(gbNewFileAuto);
        PktSpinBox->setObjectName(QString::fromUtf8("PktSpinBox"));
        PktSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        PktSpinBox->setMaximum(2147483647);
        PktSpinBox->setValue(100000);

        gridLayout->addWidget(PktSpinBox, 1, 1, 1, 1);

        PktLabel = new QLabel(gbNewFileAuto);
        PktLabel->setObjectName(QString::fromUtf8("PktLabel"));

        gridLayout->addWidget(PktLabel, 1, 2, 1, 1);


        verticalLayout_9->addWidget(gbNewFileAuto);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        RbCheckBox = new QCheckBox(outputTab);
        RbCheckBox->setObjectName(QString::fromUtf8("RbCheckBox"));

        horizontalLayout_4->addWidget(RbCheckBox);

        RbSpinBox = new QSpinBox(outputTab);
        RbSpinBox->setObjectName(QString::fromUtf8("RbSpinBox"));
        RbSpinBox->setWrapping(true);
        RbSpinBox->setMinimum(2);
        RbSpinBox->setMaximum(1000);
        RbSpinBox->setValue(2);

        horizontalLayout_4->addWidget(RbSpinBox);

        label_3 = new QLabel(outputTab);
        label_3->setObjectName(QString::fromUtf8("label_3"));

        horizontalLayout_4->addWidget(label_3);

        horizontalSpacer_9 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_4->addItem(horizontalSpacer_9);


        verticalLayout_9->addLayout(horizontalLayout_4);

        verticalSpacer_2 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_9->addItem(verticalSpacer_2);

        tabWidget->addTab(outputTab, QString());
        gbNewFileAuto->raise();
        gbCaptureToFile->raise();
        optionsTab = new QWidget();
        optionsTab->setObjectName(QString::fromUtf8("optionsTab"));
        formLayout = new QFormLayout(optionsTab);
        formLayout->setObjectName(QString::fromUtf8("formLayout"));
        horizontalLayout_8 = new QHBoxLayout();
        horizontalLayout_8->setObjectName(QString::fromUtf8("horizontalLayout_8"));
        groupBox = new QGroupBox(optionsTab);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        groupBox->setFlat(true);
        verticalLayout = new QVBoxLayout(groupBox);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        cbUpdatePacketsRT = new QCheckBox(groupBox);
        cbUpdatePacketsRT->setObjectName(QString::fromUtf8("cbUpdatePacketsRT"));

        verticalLayout->addWidget(cbUpdatePacketsRT);

        cbAutoScroll = new QCheckBox(groupBox);
        cbAutoScroll->setObjectName(QString::fromUtf8("cbAutoScroll"));

        verticalLayout->addWidget(cbAutoScroll);

        cbExtraCaptureInfo = new QCheckBox(groupBox);
        cbExtraCaptureInfo->setObjectName(QString::fromUtf8("cbExtraCaptureInfo"));

        verticalLayout->addWidget(cbExtraCaptureInfo);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        verticalLayout->addItem(horizontalSpacer_3);


        horizontalLayout_8->addWidget(groupBox);

        groupBox_2 = new QGroupBox(optionsTab);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        groupBox_2->setFlat(true);
        verticalLayout_3 = new QVBoxLayout(groupBox_2);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        cbResolveMacAddresses = new QCheckBox(groupBox_2);
        cbResolveMacAddresses->setObjectName(QString::fromUtf8("cbResolveMacAddresses"));

        verticalLayout_3->addWidget(cbResolveMacAddresses);

        cbResolveNetworkNames = new QCheckBox(groupBox_2);
        cbResolveNetworkNames->setObjectName(QString::fromUtf8("cbResolveNetworkNames"));

        verticalLayout_3->addWidget(cbResolveNetworkNames);

        cbResolveTransportNames = new QCheckBox(groupBox_2);
        cbResolveTransportNames->setObjectName(QString::fromUtf8("cbResolveTransportNames"));

        verticalLayout_3->addWidget(cbResolveTransportNames);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        verticalLayout_3->addItem(horizontalSpacer_5);


        horizontalLayout_8->addWidget(groupBox_2);


        formLayout->setLayout(0, QFormLayout::LabelRole, horizontalLayout_8);

        gbStopCaptureAuto = new QGroupBox(optionsTab);
        gbStopCaptureAuto->setObjectName(QString::fromUtf8("gbStopCaptureAuto"));
        gbStopCaptureAuto->setEnabled(true);
        gbStopCaptureAuto->setFlat(true);
        gridLayout_2 = new QGridLayout(gbStopCaptureAuto);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        stopPktSpinBox = new QSpinBox(gbStopCaptureAuto);
        stopPktSpinBox->setObjectName(QString::fromUtf8("stopPktSpinBox"));
        QSizePolicy sizePolicy2(QSizePolicy::Minimum, QSizePolicy::Fixed);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(stopPktSpinBox->sizePolicy().hasHeightForWidth());
        stopPktSpinBox->setSizePolicy(sizePolicy2);
        stopPktSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        stopPktSpinBox->setMaximum(2147483647);
        stopPktSpinBox->setValue(1);

        gridLayout_2->addWidget(stopPktSpinBox, 0, 1, 1, 1);

        stopMBSpinBox = new QSpinBox(gbStopCaptureAuto);
        stopMBSpinBox->setObjectName(QString::fromUtf8("stopMBSpinBox"));
        stopMBSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        stopMBSpinBox->setMaximum(2147483647);
        stopMBSpinBox->setValue(1);

        gridLayout_2->addWidget(stopMBSpinBox, 2, 1, 1, 1);

        stopMBCheckBox = new QCheckBox(gbStopCaptureAuto);
        stopMBCheckBox->setObjectName(QString::fromUtf8("stopMBCheckBox"));

        gridLayout_2->addWidget(stopMBCheckBox, 2, 0, 1, 1);

        label_7 = new QLabel(gbStopCaptureAuto);
        label_7->setObjectName(QString::fromUtf8("label_7"));

        gridLayout_2->addWidget(label_7, 0, 2, 1, 1);

        stopSecsCheckBox = new QCheckBox(gbStopCaptureAuto);
        stopSecsCheckBox->setObjectName(QString::fromUtf8("stopSecsCheckBox"));

        gridLayout_2->addWidget(stopSecsCheckBox, 3, 0, 1, 1);

        stopSecsComboBox = new QComboBox(gbStopCaptureAuto);
        stopSecsComboBox->addItem(QString());
        stopSecsComboBox->addItem(QString());
        stopSecsComboBox->addItem(QString());
        stopSecsComboBox->setObjectName(QString::fromUtf8("stopSecsComboBox"));

        gridLayout_2->addWidget(stopSecsComboBox, 3, 2, 1, 1);

        stopPktCheckBox = new QCheckBox(gbStopCaptureAuto);
        stopPktCheckBox->setObjectName(QString::fromUtf8("stopPktCheckBox"));

        gridLayout_2->addWidget(stopPktCheckBox, 0, 0, 1, 1);

        stopMBComboBox = new QComboBox(gbStopCaptureAuto);
        stopMBComboBox->addItem(QString());
        stopMBComboBox->addItem(QString());
        stopMBComboBox->addItem(QString());
        stopMBComboBox->setObjectName(QString::fromUtf8("stopMBComboBox"));

        gridLayout_2->addWidget(stopMBComboBox, 2, 2, 1, 1);

        stopSecsSpinBox = new QSpinBox(gbStopCaptureAuto);
        stopSecsSpinBox->setObjectName(QString::fromUtf8("stopSecsSpinBox"));
        stopSecsSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        stopSecsSpinBox->setMaximum(2147483647);
        stopSecsSpinBox->setValue(1);

        gridLayout_2->addWidget(stopSecsSpinBox, 3, 1, 1, 1);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        gridLayout_2->addItem(horizontalSpacer, 0, 3, 4, 1);

        stopFilesSpinBox = new QSpinBox(gbStopCaptureAuto);
        stopFilesSpinBox->setObjectName(QString::fromUtf8("stopFilesSpinBox"));
        sizePolicy2.setHeightForWidth(stopFilesSpinBox->sizePolicy().hasHeightForWidth());
        stopFilesSpinBox->setSizePolicy(sizePolicy2);
        stopFilesSpinBox->setButtonSymbols(QAbstractSpinBox::PlusMinus);
        stopFilesSpinBox->setMaximum(2147483647);
        stopFilesSpinBox->setValue(1);

        gridLayout_2->addWidget(stopFilesSpinBox, 1, 1, 1, 1);

        label_8 = new QLabel(gbStopCaptureAuto);
        label_8->setObjectName(QString::fromUtf8("label_8"));

        gridLayout_2->addWidget(label_8, 1, 2, 1, 1);

        stopFilesCheckBox = new QCheckBox(gbStopCaptureAuto);
        stopFilesCheckBox->setObjectName(QString::fromUtf8("stopFilesCheckBox"));

        gridLayout_2->addWidget(stopFilesCheckBox, 1, 0, 1, 1);


        formLayout->setWidget(1, QFormLayout::LabelRole, gbStopCaptureAuto);

        verticalSpacer_3 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        formLayout->setItem(2, QFormLayout::LabelRole, verticalSpacer_3);

        tabWidget->addTab(optionsTab, QString());

        verticalLayout_12->addWidget(tabWidget);

        buttonBox = new QDialogButtonBox(CaptureInterfacesDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout_12->addWidget(buttonBox);


        retranslateUi(CaptureInterfacesDialog);

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(CaptureInterfacesDialog);
    } // setupUi

    void retranslateUi(QDialog *CaptureInterfacesDialog)
    {
        QTreeWidgetItem *___qtreewidgetitem = interfaceTree->headerItem();
        ___qtreewidgetitem->setText(7, QApplication::translate("CaptureInterfacesDialog", "Capture Filter", nullptr));
        ___qtreewidgetitem->setText(6, QApplication::translate("CaptureInterfacesDialog", "Monitor Mode", nullptr));
        ___qtreewidgetitem->setText(5, QApplication::translate("CaptureInterfacesDialog", "Buffer (MB)", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("CaptureInterfacesDialog", "Snaplen (B)", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("CaptureInterfacesDialog", "Promiscuous", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("CaptureInterfacesDialog", "Link-layer Header", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("CaptureInterfacesDialog", "Traffic", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("CaptureInterfacesDialog", "Interface", nullptr));
#ifndef QT_NO_TOOLTIP
        capturePromModeCheckBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>You probably want to enable this. Usually a network card will only capture the traffic sent to its own network address. If you want to capture all traffic that the network card can &quot;see&quot;, mark this option. See the FAQ for some more details of capturing packets from a switched network.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        capturePromModeCheckBox->setText(QApplication::translate("CaptureInterfacesDialog", "Enable promiscuous mode on all interfaces", nullptr));
#ifndef QT_NO_TOOLTIP
        manageButton->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Show and hide interfaces, add comments, and manage pipes and remote interfaces.", nullptr));
#endif // QT_NO_TOOLTIP
        manageButton->setText(QApplication::translate("CaptureInterfacesDialog", "Manage Interfaces\342\200\246", nullptr));
        label_4->setText(QApplication::translate("CaptureInterfacesDialog", "Capture filter for selected interfaces:", nullptr));
        compileBPF->setText(QApplication::translate("CaptureInterfacesDialog", "Compile BPFs", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(inputTab), QApplication::translate("CaptureInterfacesDialog", "Input", nullptr));
#ifndef QT_NO_TOOLTIP
        gbCaptureToFile->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Enter the file name to which captured data will be written. By default, a temporary file will be used.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        gbCaptureToFile->setTitle(QApplication::translate("CaptureInterfacesDialog", "Capture to a permanent file", nullptr));
        browseButton->setText(QApplication::translate("CaptureInterfacesDialog", "Browse\342\200\246", nullptr));
        label_2->setText(QApplication::translate("CaptureInterfacesDialog", "File:", nullptr));
        label->setText(QApplication::translate("CaptureInterfacesDialog", "Output format:", nullptr));
        rbPcapng->setText(QApplication::translate("CaptureInterfacesDialog", "pcapng", nullptr));
        rbPcap->setText(QApplication::translate("CaptureInterfacesDialog", "pcap", nullptr));
#ifndef QT_NO_TOOLTIP
        gbNewFileAuto->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Instead of using a single capture file, multiple files will be created.</p><p>The generated file names will contain an incrementing number and the start time of the capture.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        gbNewFileAuto->setTitle(QApplication::translate("CaptureInterfacesDialog", "Create a new file automatically after\342\200\246", nullptr));
        MBCheckBox->setText(QString());
        SecsCheckBox->setText(QString());
#ifndef QT_NO_TOOLTIP
        SecsSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "If the selected file size is exceeded, capturing switches to the next file.\n"
"PLEASE NOTE: One option MUST be selected.", nullptr));
#endif // QT_NO_TOOLTIP
        SecsComboBox->setItemText(0, QApplication::translate("CaptureInterfacesDialog", "seconds", nullptr));
        SecsComboBox->setItemText(1, QApplication::translate("CaptureInterfacesDialog", "minutes", nullptr));
        SecsComboBox->setItemText(2, QApplication::translate("CaptureInterfacesDialog", "hours", nullptr));

#ifndef QT_NO_TOOLTIP
        SecsComboBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "If the selected file size is exceeded, capturing switches to the next file.\n"
"PLEASE NOTE: One option MUST be selected.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        MBSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>If the selected file size is exceeded, capturing switches to the next file.</p><p>PLEASE NOTE: One option MUST be selected.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        MBComboBox->setItemText(0, QApplication::translate("CaptureInterfacesDialog", "kilobytes", nullptr));
        MBComboBox->setItemText(1, QApplication::translate("CaptureInterfacesDialog", "megabytes", nullptr));
        MBComboBox->setItemText(2, QApplication::translate("CaptureInterfacesDialog", "gigabytes", nullptr));

#ifndef QT_NO_TOOLTIP
        MBComboBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "If the selected file size is exceeded, capturing switches to the next file.\n"
"PLEASE NOTE: One option MUST be selected.", nullptr));
#endif // QT_NO_TOOLTIP
        PktCheckBox->setText(QString());
#ifndef QT_NO_TOOLTIP
        PktSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Switch to the next file after the specified number of packets have been captured.", nullptr));
#endif // QT_NO_TOOLTIP
        PktLabel->setText(QApplication::translate("CaptureInterfacesDialog", "packets", nullptr));
#ifndef QT_NO_TOOLTIP
        RbCheckBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>After capturing has switched to the next file and the given number of files has exceeded, the oldest file will be removed.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        RbCheckBox->setText(QApplication::translate("CaptureInterfacesDialog", "Use a ring buffer with ", nullptr));
        label_3->setText(QApplication::translate("CaptureInterfacesDialog", "files", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(outputTab), QApplication::translate("CaptureInterfacesDialog", "Output", nullptr));
        groupBox->setTitle(QApplication::translate("CaptureInterfacesDialog", "Display Options", nullptr));
#ifndef QT_NO_TOOLTIP
        cbUpdatePacketsRT->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Using this option will show the captured packets immediately on the main screen. Please note: this will slow down capturing, so increased packet drops might appear.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        cbUpdatePacketsRT->setText(QApplication::translate("CaptureInterfacesDialog", "Update list of packets in real-time", nullptr));
#ifndef QT_NO_TOOLTIP
        cbAutoScroll->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>This will scroll the &quot;Packet List&quot; automatically to the latest captured packet, when the &quot;Update list of packets in real-time&quot; option is used.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        cbAutoScroll->setText(QApplication::translate("CaptureInterfacesDialog", "Automatically scroll during live capture", nullptr));
#ifndef QT_NO_TOOLTIP
        cbExtraCaptureInfo->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Show the capture info dialog while capturing.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        cbExtraCaptureInfo->setText(QApplication::translate("CaptureInterfacesDialog", "Show capture information during live capture", nullptr));
        groupBox_2->setTitle(QApplication::translate("CaptureInterfacesDialog", "Name Resolution", nullptr));
#ifndef QT_NO_TOOLTIP
        cbResolveMacAddresses->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Perform MAC layer name resolution while capturing.", nullptr));
#endif // QT_NO_TOOLTIP
        cbResolveMacAddresses->setText(QApplication::translate("CaptureInterfacesDialog", "Resolve MAC Addresses", nullptr));
#ifndef QT_NO_TOOLTIP
        cbResolveNetworkNames->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Perform network layer name resolution while capturing.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        cbResolveNetworkNames->setText(QApplication::translate("CaptureInterfacesDialog", "Resolve network names", nullptr));
#ifndef QT_NO_TOOLTIP
        cbResolveTransportNames->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Perform transport layer name resolution while capturing.", nullptr));
#endif // QT_NO_TOOLTIP
        cbResolveTransportNames->setText(QApplication::translate("CaptureInterfacesDialog", "Resolve transport names", nullptr));
        gbStopCaptureAuto->setTitle(QApplication::translate("CaptureInterfacesDialog", "Stop capture automatically after\342\200\246", nullptr));
#ifndef QT_NO_TOOLTIP
        stopPktSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified number of packets have been captured.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        stopMBSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified amount of data has been captured.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        stopMBCheckBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Stop capturing after the specified amount of data has been captured.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        stopMBCheckBox->setText(QString());
        label_7->setText(QApplication::translate("CaptureInterfacesDialog", "packets", nullptr));
#ifndef QT_NO_TOOLTIP
        stopSecsCheckBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified amount of time has passed.", nullptr));
#endif // QT_NO_TOOLTIP
        stopSecsCheckBox->setText(QString());
        stopSecsComboBox->setItemText(0, QApplication::translate("CaptureInterfacesDialog", "seconds", nullptr));
        stopSecsComboBox->setItemText(1, QApplication::translate("CaptureInterfacesDialog", "minutes", nullptr));
        stopSecsComboBox->setItemText(2, QApplication::translate("CaptureInterfacesDialog", "hours", nullptr));

#ifndef QT_NO_TOOLTIP
        stopSecsComboBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified amount of time has passed.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        stopPktCheckBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Stop capturing after the specified number of packets have been captured.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        stopPktCheckBox->setText(QString());
        stopMBComboBox->setItemText(0, QApplication::translate("CaptureInterfacesDialog", "kilobytes", nullptr));
        stopMBComboBox->setItemText(1, QApplication::translate("CaptureInterfacesDialog", "megabytes", nullptr));
        stopMBComboBox->setItemText(2, QApplication::translate("CaptureInterfacesDialog", "gigabytes", nullptr));

#ifndef QT_NO_TOOLTIP
        stopMBComboBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified amount of data has been captured.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        stopSecsSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified amount of time has passed.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        stopFilesSpinBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "Stop capturing after the specified number of packets have been captured.", nullptr));
#endif // QT_NO_TOOLTIP
        label_8->setText(QApplication::translate("CaptureInterfacesDialog", "files", nullptr));
#ifndef QT_NO_TOOLTIP
        stopFilesCheckBox->setToolTip(QApplication::translate("CaptureInterfacesDialog", "<html><head/><body><p>Stop capturing after the specified number of files have been created.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        stopFilesCheckBox->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(optionsTab), QApplication::translate("CaptureInterfacesDialog", "Options", nullptr));
        Q_UNUSED(CaptureInterfacesDialog);
    } // retranslateUi

};

namespace Ui {
    class CaptureInterfacesDialog: public Ui_CaptureInterfacesDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CAPTURE_INTERFACES_DIALOG_H
