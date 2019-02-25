/********************************************************************************
** Form generated from reading UI file 'rsa_keys_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_RSA_KEYS_FRAME_H
#define UI_RSA_KEYS_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_RsaKeysFrame
{
public:
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_2;
    QLabel *keysLabel;
    QListView *keysView;
    QHBoxLayout *horizontalLayout;
    QPushButton *addFileButton;
    QPushButton *addItemButton;
    QPushButton *deleteItemButton;
    QSpacerItem *horizontalSpacer;
    QLabel *libsLabel;
    QListView *libsView;
    QHBoxLayout *horizontalLayout_2;
    QPushButton *addLibraryButton;
    QPushButton *deleteLibraryButton;
    QSpacerItem *horizontalSpacer_2;

    void setupUi(QFrame *RsaKeysFrame)
    {
        if (RsaKeysFrame->objectName().isEmpty())
            RsaKeysFrame->setObjectName(QString::fromUtf8("RsaKeysFrame"));
        RsaKeysFrame->resize(400, 300);
        verticalLayout = new QVBoxLayout(RsaKeysFrame);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        groupBox = new QGroupBox(RsaKeysFrame);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        verticalLayout_2 = new QVBoxLayout(groupBox);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        keysLabel = new QLabel(groupBox);
        keysLabel->setObjectName(QString::fromUtf8("keysLabel"));

        verticalLayout_2->addWidget(keysLabel);

        keysView = new QListView(groupBox);
        keysView->setObjectName(QString::fromUtf8("keysView"));

        verticalLayout_2->addWidget(keysView);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        addFileButton = new QPushButton(groupBox);
        addFileButton->setObjectName(QString::fromUtf8("addFileButton"));

        horizontalLayout->addWidget(addFileButton);

        addItemButton = new QPushButton(groupBox);
        addItemButton->setObjectName(QString::fromUtf8("addItemButton"));

        horizontalLayout->addWidget(addItemButton);

        deleteItemButton = new QPushButton(groupBox);
        deleteItemButton->setObjectName(QString::fromUtf8("deleteItemButton"));
        deleteItemButton->setEnabled(false);

        horizontalLayout->addWidget(deleteItemButton);

        horizontalSpacer = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);


        verticalLayout_2->addLayout(horizontalLayout);

        libsLabel = new QLabel(groupBox);
        libsLabel->setObjectName(QString::fromUtf8("libsLabel"));

        verticalLayout_2->addWidget(libsLabel);

        libsView = new QListView(groupBox);
        libsView->setObjectName(QString::fromUtf8("libsView"));
        libsView->setMaximumSize(QSize(16777215, 54));

        verticalLayout_2->addWidget(libsView);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        addLibraryButton = new QPushButton(groupBox);
        addLibraryButton->setObjectName(QString::fromUtf8("addLibraryButton"));

        horizontalLayout_2->addWidget(addLibraryButton);

        deleteLibraryButton = new QPushButton(groupBox);
        deleteLibraryButton->setObjectName(QString::fromUtf8("deleteLibraryButton"));
        deleteLibraryButton->setEnabled(false);

        horizontalLayout_2->addWidget(deleteLibraryButton);

        horizontalSpacer_2 = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);


        verticalLayout_2->addLayout(horizontalLayout_2);


        verticalLayout->addWidget(groupBox);


        retranslateUi(RsaKeysFrame);

        QMetaObject::connectSlotsByName(RsaKeysFrame);
    } // setupUi

    void retranslateUi(QFrame *RsaKeysFrame)
    {
        groupBox->setTitle(QApplication::translate("RsaKeysFrame", "RSA Keys", nullptr));
        keysLabel->setText(QApplication::translate("RsaKeysFrame", "RSA private keys are loaded from a file or PKCS #11 token.", nullptr));
        addFileButton->setText(QApplication::translate("RsaKeysFrame", "Add new keyfile\342\200\246", nullptr));
        addItemButton->setText(QApplication::translate("RsaKeysFrame", "Add new token\342\200\246", nullptr));
        deleteItemButton->setText(QApplication::translate("RsaKeysFrame", "Remove key", nullptr));
        libsLabel->setText(QApplication::translate("RsaKeysFrame", "PKCS #11 provider libraries.", nullptr));
        addLibraryButton->setText(QApplication::translate("RsaKeysFrame", "Add new provider\342\200\246", nullptr));
        deleteLibraryButton->setText(QApplication::translate("RsaKeysFrame", "Remove provider", nullptr));
        Q_UNUSED(RsaKeysFrame);
    } // retranslateUi

};

namespace Ui {
    class RsaKeysFrame: public Ui_RsaKeysFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_RSA_KEYS_FRAME_H
