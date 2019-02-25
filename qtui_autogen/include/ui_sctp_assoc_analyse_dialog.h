/********************************************************************************
** Form generated from reading UI file 'sctp_assoc_analyse_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SCTP_ASSOC_ANALYSE_DIALOG_H
#define UI_SCTP_ASSOC_ANALYSE_DIALOG_H

#include <QtCore/QLocale>
#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_SCTPAssocAnalyseDialog
{
public:
    QTabWidget *SCTPAssocAnalyseTab;
    QWidget *Statistics;
    QPushButton *chunkStatisticsButton;
    QPushButton *setFilterButton;
    QPushButton *pushButton;
    QWidget *gridLayoutWidget_3;
    QGridLayout *gridLayout_3;
    QLabel *label_17;
    QLabel *label_15;
    QLabel *label_16;
    QLabel *label_13;
    QLabel *label_18;
    QLabel *data12Label;
    QLabel *checksumLabel;
    QLabel *bytes12Label;
    QLabel *data21Label;
    QLabel *bytes21Label;
    QWidget *Endpoint_1;
    QPushButton *GraphTSN_1;
    QPushButton *GraphBytes_1;
    QLabel *labelEP1;
    QWidget *gridLayoutWidget;
    QGridLayout *gridLayout;
    QLabel *label_213;
    QLabel *label_211;
    QLabel *label_222;
    QLabel *label_212;
    QLabel *label_224;
    QLabel *label_214;
    QLabel *label_221;
    QLabel *label_215;
    QLabel *label_223;
    QLabel *label_225;
    QLabel *label_216;
    QLabel *label_226;
    QPushButton *pushButton_2;
    QListWidget *listWidgetEP1;
    QPushButton *GraphArwnd_1;
    QWidget *Endpoint_2;
    QPushButton *GraphTSN_2;
    QPushButton *GraphBytes_2;
    QWidget *gridLayoutWidget_2;
    QGridLayout *gridLayout_2;
    QLabel *label_313;
    QLabel *label_324;
    QLabel *label_321;
    QLabel *label_312;
    QLabel *label_316;
    QLabel *label_311;
    QLabel *label_314;
    QLabel *label_322;
    QLabel *label_323;
    QLabel *label_326;
    QLabel *label_315;
    QLabel *label_325;
    QLabel *labelEP2;
    QPushButton *pushButton_3;
    QListWidget *listWidgetEP2;
    QPushButton *GraphArwnd_2;

    void setupUi(QDialog *SCTPAssocAnalyseDialog)
    {
        if (SCTPAssocAnalyseDialog->objectName().isEmpty())
            SCTPAssocAnalyseDialog->setObjectName(QString::fromUtf8("SCTPAssocAnalyseDialog"));
        SCTPAssocAnalyseDialog->resize(537, 385);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(SCTPAssocAnalyseDialog->sizePolicy().hasHeightForWidth());
        SCTPAssocAnalyseDialog->setSizePolicy(sizePolicy);
        SCTPAssocAnalyseDialog->setLocale(QLocale(QLocale::English, QLocale::UnitedStates));
        SCTPAssocAnalyseTab = new QTabWidget(SCTPAssocAnalyseDialog);
        SCTPAssocAnalyseTab->setObjectName(QString::fromUtf8("SCTPAssocAnalyseTab"));
        SCTPAssocAnalyseTab->setGeometry(QRect(5, 10, 529, 371));
        Statistics = new QWidget();
        Statistics->setObjectName(QString::fromUtf8("Statistics"));
        Statistics->setFocusPolicy(Qt::NoFocus);
        chunkStatisticsButton = new QPushButton(Statistics);
        chunkStatisticsButton->setObjectName(QString::fromUtf8("chunkStatisticsButton"));
        chunkStatisticsButton->setGeometry(QRect(0, 310, 131, 32));
        chunkStatisticsButton->setFocusPolicy(Qt::NoFocus);
        setFilterButton = new QPushButton(Statistics);
        setFilterButton->setObjectName(QString::fromUtf8("setFilterButton"));
        setFilterButton->setGeometry(QRect(130, 310, 141, 32));
        setFilterButton->setFocusPolicy(Qt::NoFocus);
        pushButton = new QPushButton(Statistics);
        pushButton->setObjectName(QString::fromUtf8("pushButton"));
        pushButton->setGeometry(QRect(390, 310, 114, 32));
        pushButton->setFocusPolicy(Qt::NoFocus);
        gridLayoutWidget_3 = new QWidget(Statistics);
        gridLayoutWidget_3->setObjectName(QString::fromUtf8("gridLayoutWidget_3"));
        gridLayoutWidget_3->setGeometry(QRect(20, 40, 481, 201));
        gridLayout_3 = new QGridLayout(gridLayoutWidget_3);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        gridLayout_3->setContentsMargins(0, 0, 0, 0);
        label_17 = new QLabel(gridLayoutWidget_3);
        label_17->setObjectName(QString::fromUtf8("label_17"));

        gridLayout_3->addWidget(label_17, 3, 0, 1, 1);

        label_15 = new QLabel(gridLayoutWidget_3);
        label_15->setObjectName(QString::fromUtf8("label_15"));

        gridLayout_3->addWidget(label_15, 0, 0, 1, 1);

        label_16 = new QLabel(gridLayoutWidget_3);
        label_16->setObjectName(QString::fromUtf8("label_16"));

        gridLayout_3->addWidget(label_16, 1, 0, 1, 1);

        label_13 = new QLabel(gridLayoutWidget_3);
        label_13->setObjectName(QString::fromUtf8("label_13"));

        gridLayout_3->addWidget(label_13, 2, 0, 1, 1);

        label_18 = new QLabel(gridLayoutWidget_3);
        label_18->setObjectName(QString::fromUtf8("label_18"));

        gridLayout_3->addWidget(label_18, 4, 0, 1, 1);

        data12Label = new QLabel(gridLayoutWidget_3);
        data12Label->setObjectName(QString::fromUtf8("data12Label"));

        gridLayout_3->addWidget(data12Label, 1, 1, 1, 1);

        checksumLabel = new QLabel(gridLayoutWidget_3);
        checksumLabel->setObjectName(QString::fromUtf8("checksumLabel"));

        gridLayout_3->addWidget(checksumLabel, 0, 1, 1, 1);

        bytes12Label = new QLabel(gridLayoutWidget_3);
        bytes12Label->setObjectName(QString::fromUtf8("bytes12Label"));

        gridLayout_3->addWidget(bytes12Label, 2, 1, 1, 1);

        data21Label = new QLabel(gridLayoutWidget_3);
        data21Label->setObjectName(QString::fromUtf8("data21Label"));

        gridLayout_3->addWidget(data21Label, 3, 1, 1, 1);

        bytes21Label = new QLabel(gridLayoutWidget_3);
        bytes21Label->setObjectName(QString::fromUtf8("bytes21Label"));

        gridLayout_3->addWidget(bytes21Label, 4, 1, 1, 1);

        SCTPAssocAnalyseTab->addTab(Statistics, QString());
        Endpoint_1 = new QWidget();
        Endpoint_1->setObjectName(QString::fromUtf8("Endpoint_1"));
        GraphTSN_1 = new QPushButton(Endpoint_1);
        GraphTSN_1->setObjectName(QString::fromUtf8("GraphTSN_1"));
        GraphTSN_1->setGeometry(QRect(0, 310, 114, 32));
        GraphTSN_1->setFocusPolicy(Qt::NoFocus);
        GraphBytes_1 = new QPushButton(Endpoint_1);
        GraphBytes_1->setObjectName(QString::fromUtf8("GraphBytes_1"));
        GraphBytes_1->setGeometry(QRect(110, 310, 114, 32));
        GraphBytes_1->setFocusPolicy(Qt::NoFocus);
        labelEP1 = new QLabel(Endpoint_1);
        labelEP1->setObjectName(QString::fromUtf8("labelEP1"));
        labelEP1->setGeometry(QRect(10, 10, 441, 16));
        gridLayoutWidget = new QWidget(Endpoint_1);
        gridLayoutWidget->setObjectName(QString::fromUtf8("gridLayoutWidget"));
        gridLayoutWidget->setGeometry(QRect(10, 170, 520, 138));
        gridLayout = new QGridLayout(gridLayoutWidget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        gridLayout->setContentsMargins(0, 0, 0, 0);
        label_213 = new QLabel(gridLayoutWidget);
        label_213->setObjectName(QString::fromUtf8("label_213"));

        gridLayout->addWidget(label_213, 2, 0, 1, 1);

        label_211 = new QLabel(gridLayoutWidget);
        label_211->setObjectName(QString::fromUtf8("label_211"));

        gridLayout->addWidget(label_211, 0, 0, 1, 1);

        label_222 = new QLabel(gridLayoutWidget);
        label_222->setObjectName(QString::fromUtf8("label_222"));

        gridLayout->addWidget(label_222, 1, 1, 1, 1);

        label_212 = new QLabel(gridLayoutWidget);
        label_212->setObjectName(QString::fromUtf8("label_212"));

        gridLayout->addWidget(label_212, 1, 0, 1, 1);

        label_224 = new QLabel(gridLayoutWidget);
        label_224->setObjectName(QString::fromUtf8("label_224"));

        gridLayout->addWidget(label_224, 3, 1, 1, 1);

        label_214 = new QLabel(gridLayoutWidget);
        label_214->setObjectName(QString::fromUtf8("label_214"));

        gridLayout->addWidget(label_214, 3, 0, 1, 1);

        label_221 = new QLabel(gridLayoutWidget);
        label_221->setObjectName(QString::fromUtf8("label_221"));

        gridLayout->addWidget(label_221, 0, 1, 1, 1);

        label_215 = new QLabel(gridLayoutWidget);
        label_215->setObjectName(QString::fromUtf8("label_215"));

        gridLayout->addWidget(label_215, 4, 0, 1, 1);

        label_223 = new QLabel(gridLayoutWidget);
        label_223->setObjectName(QString::fromUtf8("label_223"));

        gridLayout->addWidget(label_223, 2, 1, 1, 1);

        label_225 = new QLabel(gridLayoutWidget);
        label_225->setObjectName(QString::fromUtf8("label_225"));

        gridLayout->addWidget(label_225, 4, 1, 1, 1);

        label_216 = new QLabel(gridLayoutWidget);
        label_216->setObjectName(QString::fromUtf8("label_216"));

        gridLayout->addWidget(label_216, 5, 0, 1, 1);

        label_226 = new QLabel(gridLayoutWidget);
        label_226->setObjectName(QString::fromUtf8("label_226"));

        gridLayout->addWidget(label_226, 5, 1, 1, 1);

        pushButton_2 = new QPushButton(Endpoint_1);
        pushButton_2->setObjectName(QString::fromUtf8("pushButton_2"));
        pushButton_2->setGeometry(QRect(390, 310, 114, 32));
        pushButton_2->setFocusPolicy(Qt::NoFocus);
        listWidgetEP1 = new QListWidget(Endpoint_1);
        listWidgetEP1->setObjectName(QString::fromUtf8("listWidgetEP1"));
        listWidgetEP1->setGeometry(QRect(10, 30, 501, 131));
        GraphArwnd_1 = new QPushButton(Endpoint_1);
        GraphArwnd_1->setObjectName(QString::fromUtf8("GraphArwnd_1"));
        GraphArwnd_1->setGeometry(QRect(220, 310, 114, 32));
        SCTPAssocAnalyseTab->addTab(Endpoint_1, QString());
        Endpoint_2 = new QWidget();
        Endpoint_2->setObjectName(QString::fromUtf8("Endpoint_2"));
        GraphTSN_2 = new QPushButton(Endpoint_2);
        GraphTSN_2->setObjectName(QString::fromUtf8("GraphTSN_2"));
        GraphTSN_2->setGeometry(QRect(0, 310, 114, 32));
        GraphTSN_2->setFocusPolicy(Qt::NoFocus);
        GraphBytes_2 = new QPushButton(Endpoint_2);
        GraphBytes_2->setObjectName(QString::fromUtf8("GraphBytes_2"));
        GraphBytes_2->setGeometry(QRect(110, 310, 114, 32));
        GraphBytes_2->setFocusPolicy(Qt::NoFocus);
        gridLayoutWidget_2 = new QWidget(Endpoint_2);
        gridLayoutWidget_2->setObjectName(QString::fromUtf8("gridLayoutWidget_2"));
        gridLayoutWidget_2->setGeometry(QRect(10, 170, 511, 141));
        gridLayout_2 = new QGridLayout(gridLayoutWidget_2);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        gridLayout_2->setContentsMargins(0, 0, 0, 0);
        label_313 = new QLabel(gridLayoutWidget_2);
        label_313->setObjectName(QString::fromUtf8("label_313"));

        gridLayout_2->addWidget(label_313, 2, 0, 1, 1);

        label_324 = new QLabel(gridLayoutWidget_2);
        label_324->setObjectName(QString::fromUtf8("label_324"));

        gridLayout_2->addWidget(label_324, 3, 1, 1, 1);

        label_321 = new QLabel(gridLayoutWidget_2);
        label_321->setObjectName(QString::fromUtf8("label_321"));

        gridLayout_2->addWidget(label_321, 0, 1, 1, 1);

        label_312 = new QLabel(gridLayoutWidget_2);
        label_312->setObjectName(QString::fromUtf8("label_312"));

        gridLayout_2->addWidget(label_312, 1, 0, 1, 1);

        label_316 = new QLabel(gridLayoutWidget_2);
        label_316->setObjectName(QString::fromUtf8("label_316"));

        gridLayout_2->addWidget(label_316, 5, 0, 1, 1);

        label_311 = new QLabel(gridLayoutWidget_2);
        label_311->setObjectName(QString::fromUtf8("label_311"));

        gridLayout_2->addWidget(label_311, 0, 0, 1, 1);

        label_314 = new QLabel(gridLayoutWidget_2);
        label_314->setObjectName(QString::fromUtf8("label_314"));

        gridLayout_2->addWidget(label_314, 3, 0, 1, 1);

        label_322 = new QLabel(gridLayoutWidget_2);
        label_322->setObjectName(QString::fromUtf8("label_322"));

        gridLayout_2->addWidget(label_322, 1, 1, 1, 1);

        label_323 = new QLabel(gridLayoutWidget_2);
        label_323->setObjectName(QString::fromUtf8("label_323"));

        gridLayout_2->addWidget(label_323, 2, 1, 1, 1);

        label_326 = new QLabel(gridLayoutWidget_2);
        label_326->setObjectName(QString::fromUtf8("label_326"));

        gridLayout_2->addWidget(label_326, 5, 1, 1, 1);

        label_315 = new QLabel(gridLayoutWidget_2);
        label_315->setObjectName(QString::fromUtf8("label_315"));

        gridLayout_2->addWidget(label_315, 4, 0, 1, 1);

        label_325 = new QLabel(gridLayoutWidget_2);
        label_325->setObjectName(QString::fromUtf8("label_325"));

        gridLayout_2->addWidget(label_325, 4, 1, 1, 1);

        labelEP2 = new QLabel(Endpoint_2);
        labelEP2->setObjectName(QString::fromUtf8("labelEP2"));
        labelEP2->setGeometry(QRect(10, 10, 441, 16));
        pushButton_3 = new QPushButton(Endpoint_2);
        pushButton_3->setObjectName(QString::fromUtf8("pushButton_3"));
        pushButton_3->setGeometry(QRect(390, 310, 114, 32));
        pushButton_3->setFocusPolicy(Qt::NoFocus);
        listWidgetEP2 = new QListWidget(Endpoint_2);
        listWidgetEP2->setObjectName(QString::fromUtf8("listWidgetEP2"));
        listWidgetEP2->setGeometry(QRect(10, 30, 501, 131));
        GraphArwnd_2 = new QPushButton(Endpoint_2);
        GraphArwnd_2->setObjectName(QString::fromUtf8("GraphArwnd_2"));
        GraphArwnd_2->setGeometry(QRect(220, 310, 121, 32));
        SCTPAssocAnalyseTab->addTab(Endpoint_2, QString());

        retranslateUi(SCTPAssocAnalyseDialog);
        QObject::connect(pushButton_2, SIGNAL(clicked()), SCTPAssocAnalyseDialog, SLOT(close()));
        QObject::connect(pushButton, SIGNAL(clicked()), SCTPAssocAnalyseDialog, SLOT(close()));
        QObject::connect(pushButton_3, SIGNAL(clicked()), SCTPAssocAnalyseDialog, SLOT(close()));

        SCTPAssocAnalyseTab->setCurrentIndex(2);


        QMetaObject::connectSlotsByName(SCTPAssocAnalyseDialog);
    } // setupUi

    void retranslateUi(QDialog *SCTPAssocAnalyseDialog)
    {
        SCTPAssocAnalyseDialog->setWindowTitle(QApplication::translate("SCTPAssocAnalyseDialog", "Wireshark - Analyse Association", nullptr));
        SCTPAssocAnalyseTab->setWindowTitle(QApplication::translate("SCTPAssocAnalyseDialog", "TabWidget", nullptr));
        chunkStatisticsButton->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Chunk Statistics", nullptr));
        setFilterButton->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Filter Association", nullptr));
        pushButton->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Close", nullptr));
        label_17->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Number of Data Chunks from EP2 to EP1: ", nullptr));
        label_15->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Checksum Type:", nullptr));
        label_16->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Number of Data Chunks from EP1 to EP2: ", nullptr));
        label_13->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Number of Data Bytes from EP1 to EP2:", nullptr));
        label_18->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Number of Data Bytes from EP2 to EP1: ", nullptr));
        data12Label->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        checksumLabel->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        bytes12Label->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        data21Label->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        bytes21Label->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        SCTPAssocAnalyseTab->setTabText(SCTPAssocAnalyseTab->indexOf(Statistics), QApplication::translate("SCTPAssocAnalyseDialog", "Statistics", nullptr));
        GraphTSN_1->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Graph TSN", nullptr));
        GraphBytes_1->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Graph Bytes", nullptr));
        labelEP1->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Complete list of IP Addresses as provided in the INIT Chunk", nullptr));
        label_213->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Requested Number of Inbound Streams:", nullptr));
        label_211->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Port:", nullptr));
        label_222->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_212->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Sent Verification Tag:", nullptr));
        label_224->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_214->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Minimum Number of Inbound Streams:", nullptr));
        label_221->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_215->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Minimum Number of Outbound Streams:", nullptr));
        label_223->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_225->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_216->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_226->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        pushButton_2->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Close", nullptr));
        GraphArwnd_1->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Graph Arwnd", nullptr));
        SCTPAssocAnalyseTab->setTabText(SCTPAssocAnalyseTab->indexOf(Endpoint_1), QApplication::translate("SCTPAssocAnalyseDialog", "Endpoint 1", nullptr));
        GraphTSN_2->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Graph TSN", nullptr));
        GraphBytes_2->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Graph Bytes", nullptr));
        label_313->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Requested Number of Inbound Streams:", nullptr));
        label_324->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_321->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_312->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Sent Verification Tag:", nullptr));
        label_316->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Minimum Number of Outbound Streams:", nullptr));
        label_311->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Port:", nullptr));
        label_314->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Minimum Number of Inbound Streams:", nullptr));
        label_322->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_323->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_326->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        label_315->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Provided Number of Outbound Streams:", nullptr));
        label_325->setText(QApplication::translate("SCTPAssocAnalyseDialog", "TextLabel", nullptr));
        labelEP2->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Complete list of IP Addresses as provided in the INIT-ACK Chunk", nullptr));
        pushButton_3->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Close", nullptr));
        GraphArwnd_2->setText(QApplication::translate("SCTPAssocAnalyseDialog", "Graph a_rwnd", nullptr));
        SCTPAssocAnalyseTab->setTabText(SCTPAssocAnalyseTab->indexOf(Endpoint_2), QApplication::translate("SCTPAssocAnalyseDialog", "Endpoint 2", nullptr));
    } // retranslateUi

};

namespace Ui {
    class SCTPAssocAnalyseDialog: public Ui_SCTPAssocAnalyseDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SCTP_ASSOC_ANALYSE_DIALOG_H
