/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ATAP_DATA_MODEL_H
#define ATAP_DATA_MODEL_H

#include "config.h"

#include "glib.h"

#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>

#include <QAbstractListModel>

/**
 * @brief DataModel for tap user data
 *
 * This datamodel provides the management for all tap data for the conversation
 * and endpoint dialogs. It predominantly is implemented to work with conversation
 * tap data. The management of displaying and correctly presenting the information
 * is done in the corresponding type classes
 *
 * @see EndpointDataModel
 * @see ConversationDataModel
 */
class ATapDataModel : public QAbstractListModel
{
    Q_OBJECT
public:

    enum {
        DISPLAY_FILTER = Qt::UserRole,
        UNFORMATTED_DISPLAYDATA,
#ifdef HAVE_MAXMINDDB
        GEODATA_AVAILABLE,
        GEODATA_LOOKUPTABLE,
        GEODATA_ADDRESS,
#endif
        TIMELINE_DATA,
        ENDPOINT_DATATYPE,
        CONVERSATION_ID,
        ROW_IS_FILTERED,
        DATA_ADDRESS_TYPE,
        DATA_IPV4_INTEGER,
        DATA_IPV6_LIST,
    };

    typedef enum {
        DATAMODEL_ENDPOINT,
        DATAMODEL_CONVERSATION,
        DATAMODEL_UNKNOWN
    } dataModelType;

    /**
     * @brief Construct a new ATapDataModel object
     *
     * The tap will not be created automatically, but must be enabled by calling enableTap
     *
     * @param type an element of dataModelType. Either DATAMODEL_ENDPOINT or DATAMODEL_CONVERSATION are supported
     *   at this time
     * @param protoId the protocol id for which the tap is created
     * @param filter a potential filter to be used for the tap
     * @param parent the parent for the class
     *
     * @see enableTap
     */
    explicit ATapDataModel(dataModelType type, int protoId, QString filter, QObject *parent = nullptr);
    virtual ~ATapDataModel();

    /**
     * @brief Number of rows in this model
     *
     * @param idx not used
     * @return int the number of rows
     */
    int rowCount(const QModelIndex &idx = QModelIndex()) const;

    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const = 0;
    virtual QVariant headerData(int section, Qt::Orientation orientation = Qt::Horizontal, int role = Qt::DisplayRole) const = 0;
    virtual QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const = 0;

    /**
     * @brief Returns the name for the tap being used
     *
     * @return QString the tap name, normally identical with the protocol name
     */
    QString tap() const;

    /**
     * @brief The protocol id for the tap
     *
     * @return int the id given in the constructor
     */
    int protoId() const;

    /**
     * @brief Set the filter string.
     *
     * A set filter can be reset by providing an empty string
     *
     * @param filter the filter for the tap
     */
    void setFilter(QString filter);

    /**
     * @brief Return a filter set for the model
     *
     * @return QString the filter string for the model
     */
    QString filter() const;

    /**
     * @brief Is the model set to resolve names in address and ports columns
     *
     * @return true yes, names will be resolved
     * @return false no they won't
     */
    bool resolveNames() const;

    /**
     * @brief Enable or disable if names should be resolved
     *
     * @param resolve true if names should be resolved
     */
    void setResolveNames(bool resolve);

    /**
     * @brief Does the model allow names to be resolved
     *
     * @return true yes, names may be resolved (set via setResolveNames)
     * @return false no, they won't be resolved
     *
     * @see setResolveNames
     * @see resolveNames
     */
    bool allowsNameResolution() const;

    /**
     * @brief Use absolute time for any column supporting it
     *
     * @param absolute true to use absolute time values
     */
    void useAbsoluteTime(bool absolute);

    /**
     * @brief Use nanosecond timestamps if requested
     *
     * @param nanoseconds use nanosecond timestamps if required and requested
     */
    void useNanosecondTimestamps(bool nanoseconds);

    /**
     * @brief Are ports hidden for this model
     *
     * @return true the ports are hidden
     * @return false the ports are not hidden
     */
    bool portsAreHidden() const;

    /**
     * @brief A total column is filled
     *
     * @return true if the column is filled
     * @return false the column is empty
     */
    bool showTotalColumn() const;

    /**
     * @brief Enable tapping in this model.
     *
     * This will register the tap listener with the corresponding packet function.
     * @note if the tap has not been disabled, this method will do nothing
     *
     * @return true the tap has been enabled
     * @return false the tap has not been enabled
     */
    bool enableTap();

    /**
     * @brief Disable the tapping for this model
     */
    void disableTap();

    /**
     * @brief Return the model type
     *
     * @return dataModelType
     */
    dataModelType modelType() const;

#ifdef HAVE_MAXMINDDB
    /**
     * @brief Does this model have geoip data available
     *
     * @return true it has
     * @return false it has not
     */
    bool hasGeoIPData();
#endif

signals:
    void tapListenerChanged(bool enable);

protected:

    static void tapReset(void *tapdata);
    static void tapDraw(void *tap_data);

    virtual tap_packet_cb conversationPacketHandler();

    conv_hash_t * hash();

    void resetData();
    void updateData(GArray * data);

    dataModelType _type;
    GArray * storage_;
    QString _filter;

    bool _absoluteTime;
    bool _nanoseconds;
    bool _resolveNames;
    bool _disableTap;

    double _minRelStartTime;
    double _maxRelStopTime;

    register_ct_t* registerTable() const;

private:
    int _protoId;

    conv_hash_t hash_;
};

class EndpointDataModel : public ATapDataModel
{
    Q_OBJECT
public:

    typedef enum
    {
        ENDP_COLUMN_ADDR,
        ENDP_COLUMN_PORT,
        ENDP_COLUMN_PACKETS,
        ENDP_COLUMN_BYTES,
        ENDP_COLUMN_PACKETS_TOTAL,
        ENDP_COLUMN_BYTES_TOTAL,
        ENDP_COLUMN_PKT_AB,
        ENDP_COLUMN_BYTES_AB,
        ENDP_COLUMN_PKT_BA,
        ENDP_COLUMN_BYTES_BA,
        ENDP_NUM_COLUMNS,
        ENDP_COLUMN_GEO_COUNTRY = ENDP_NUM_COLUMNS,
        ENDP_COLUMN_GEO_CITY,
        ENDP_COLUMN_GEO_AS_NUM,
        ENDP_COLUMN_GEO_AS_ORG,
        ENDP_NUM_GEO_COLUMNS
    } endpoint_column_type_e;

    explicit EndpointDataModel(int protoId, QString filter, QObject *parent = nullptr);

    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant headerData(int section, Qt::Orientation orientation = Qt::Horizontal, int role = Qt::DisplayRole) const;
    QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const;

};

class ConversationDataModel : public ATapDataModel
{
    Q_OBJECT
public:

    typedef enum {
        CONV_COLUMN_SRC_ADDR,
        CONV_COLUMN_SRC_PORT,
        CONV_COLUMN_DST_ADDR,
        CONV_COLUMN_DST_PORT,
        CONV_COLUMN_PACKETS,
        CONV_COLUMN_BYTES,
        CONV_COLUMN_CONV_ID,
        CONV_COLUMN_PACKETS_TOTAL,
        CONV_COLUMN_BYTES_TOTAL,
        CONV_COLUMN_PKT_AB,
        CONV_COLUMN_BYTES_AB,
        CONV_COLUMN_PKT_BA,
        CONV_COLUMN_BYTES_BA,
        CONV_COLUMN_START,
        CONV_COLUMN_DURATION,
        CONV_COLUMN_BPS_AB,
        CONV_COLUMN_BPS_BA,
        CONV_NUM_COLUMNS,
        CONV_INDEX_COLUMN = CONV_NUM_COLUMNS
    } conversation_column_type_e;

    explicit ConversationDataModel(int protoId, QString filter, QObject *parent = nullptr);

    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant headerData(int section, Qt::Orientation orientation = Qt::Horizontal, int role = Qt::DisplayRole) const;
    QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const;

    void doDataUpdate();

    conv_item_t * itemForRow(int row);

    /**
     * @brief Show the conversation id if available
     *
     * @return true a conversation id exists
     * @return false none available
     */
    bool showConversationId(int row = 0) const;

};

#endif // ATAP_DATA_MODEL_H
