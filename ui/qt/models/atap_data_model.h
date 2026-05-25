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

/**
 * @brief Qt model data roles for endpoint and conversation table items.
 */
enum {
    DISPLAY_FILTER        = Qt::UserRole, /**< Display filter string constructed from this row's address/port data */
    UNFORMATTED_DISPLAYDATA,              /**< Raw, unformatted cell value used for sorting and clipboard export */
#ifdef HAVE_MAXMINDDB
    GEODATA_AVAILABLE,    /**< True if MaxMind DB geo-location data is available for this address */
    GEODATA_LOOKUPTABLE,  /**< Pointer to the MaxMind DB lookup table used to resolve geo data */
    GEODATA_ADDRESS,      /**< IP address string submitted to the MaxMind DB geo-location lookup */
#endif
    TIMELINE_DATA,        /**< Timing data used to render the traffic timeline bar in the row */
    ENDPOINT_DATATYPE,    /**< Endpoint address type tag (e.g. IPv4, IPv6, Ethernet) */
    PROTO_ID,             /**< Protocol ID (proto_id) associated with this endpoint or conversation */
    CONVERSATION_ID,      /**< Unique conversation identifier for this row */
    ROW_IS_FILTERED,      /**< True if this row is currently hidden by the active display filter */
    DATA_ADDRESS_TYPE,    /**< Address type enum value (::address_type) for the primary address */
    DATA_IPV4_INTEGER,    /**< IPv4 address as a packed 32-bit integer, used for numeric sorting */
    DATA_IPV6_LIST,       /**< IPv6 address as a byte list, used for numeric sorting */
};

/**
 * @brief Identifies which statistical data model is active in the endpoint/conversation dialog.
 */
typedef enum {
    DATAMODEL_ENDPOINT,     /**< Model is displaying per-endpoint traffic statistics */
    DATAMODEL_CONVERSATION, /**< Model is displaying per-conversation traffic statistics */
    DATAMODEL_UNKNOWN       /**< Model type has not been initialised or is unrecognised */
} dataModelType;

conv_hash_t hash_; /**< Hash table mapping address/port tuples to their conversation or endpoint entries */

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

    /** @brief Destructor */
    virtual ~ATapDataModel();

    /**
     * @brief Number of rows under the given parent in this model, which
     * is the total number of rows for the empty QModelIndex, and 0 for
     * any valid parent index (as no row has children; this is a flat table.)
     *
     * @param parent index of parent, QModelIndex() for the root
     * @return int the number of rows under the parent
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Return the number of columns in the model.
     *
     * @param parent index of parent, QModelIndex() for the root
     * @return int the number of columns under the parent
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const  override= 0;

    /**
     * @brief Return the header data for the specified section and orientation.
     *
     * @param section The column or row index.
     * @param orientation The orientation of the header.
     * @param role The data role.
     * @return QVariant The header data.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation = Qt::Horizontal, int role = Qt::DisplayRole) const  override= 0;

    /**
     * @brief Return the data for the specified index and role.
     *
     * @param idx The model index.
     * @param role The data role.
     * @return QVariant The data for the specified index and role.
     */
    virtual QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const  override= 0;

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
    virtual void setResolveNames(bool resolve) = 0;

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
    virtual void useAbsoluteTime(bool absolute) = 0;

    /**
     * @brief Use nanosecond timestamps if requested
     *
     * Otherwise, microsecond time resolution will be displayed
     *
     * @param nanoseconds use nanosecond timestamps if required and requested
     */
    virtual void useNanosecondTimestamps(bool nanoseconds) = 0;

    /**
     * @brief Sets whether the data should be presented in a machine-readable format.
     * @param machineReadable True to enable machine-readable format, false otherwise.
     */
    void setMachineReadable(bool machineReadable);

    /**
     * @brief Limits the data model to the currently active display filter.
     * @param limit True to apply the display filter limit, false otherwise.
     */
    void limitToDisplayFilter(bool limit);

    /**
     * @brief Are ports hidden for this model
     *
     * @return true the ports are hidden
     * @return false the ports are not hidden
     */
    bool portsAreHidden() const;

    /**
     * @brief Checks if a display filter has to be applied
     *
     * Controls which columns to display, and in some cases their content
     *
     * @return true a display filter has to be applied
     * @return false no display filter has to be applied
     */
    bool isFilterApplied() const;

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

    /**
     * @brief Return the conversation hash table for this model
     *
     * @return conv_hash_t * pointer to the hash table
     */
    conv_hash_t * hash();

    /**
     * @brief Update the flags
     */
    void updateFlags(unsigned flag);

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
    /**
     * @brief Signal emitted when the tap listener state changes.
     * @param enable True to enable the listener, false to disable.
     */
    void tapListenerChanged(bool enable);

protected:

    /**
     * @brief Callback to reset the tap data.
     * @param tapdata Pointer to the tap data to reset.
     */
    static void tapReset(void *tapdata);

    /**
     * @brief Callback to draw or update the tap data.
     * @param tap_data Pointer to the tap data to draw.
     */
    static void tapDraw(void *tap_data);

    /**
     * @brief Retrieves the callback function used to handle conversation packets.
     * @return The tap packet callback function.
     */
    virtual tap_packet_cb conversationPacketHandler();

    /**
     * @brief Resets the internal model data.
     */
    void resetData();

    /**
     * @brief Updates the model with new data.
     * @param data Pointer to a GArray containing the new data.
     */
    void updateData(GArray * data);

    dataModelType _type; /**< The specific type of the data model. */
    GArray * storage_; /**< Internal storage for the tap data records. */
    QString _filter; /**< The display filter applied to the tap. */

    bool _absoluteTime; /**< Flag indicating whether to use absolute time formats. */
    // XXX - There are other possible time precisions besides
    // microseconds and nanoseconds; e.g., Netmon 2.3 uses
    // 100 ns, and pcapng can have one of many values.
    bool _nanoseconds; /**< Flag indicating whether to use nanosecond precision. */
    bool _resolveNames; /**< Flag indicating whether name resolution is enabled. */
    bool _machineReadable; /**< Flag indicating whether data is formatted for machine readability. */
    bool _disableTap; /**< Flag indicating whether the underlying tap is disabled. */

    double _minRelStartTime; /**< The minimum relative start time of the processed packets. */
    double _maxRelStopTime; /**< The maximum relative stop time of the processed packets. */

    unsigned _tapFlags; /**< Bitmask of flags configuring the tap behavior. */

    /**
     * @brief Gets the conversation registration table for this tap.
     * @return Pointer to the register_ct_t table.
     */
    register_ct_t* registerTable() const;

private:
    int _protoId; /**< The protocol identifier for the tap. */

};

/**
 * @brief Tap data model for the Endpoints statistics dialog.
 */
class EndpointDataModel : public ATapDataModel
{
    Q_OBJECT
public:
    /**
     * @brief Column indices for the endpoint statistics table.
     */
    typedef enum
    {
        ENDP_COLUMN_ADDR,           /**< Endpoint address. */
        ENDP_COLUMN_PORT,           /**< Endpoint port (transport protocols only). */
        ENDP_COLUMN_PACKETS,        /**< Total packets in the filtered set. */
        ENDP_COLUMN_BYTES,          /**< Total bytes in the filtered set. */
        ENDP_COLUMN_PACKETS_TOTAL,  /**< Total packets across all traffic. */
        ENDP_COLUMN_BYTES_TOTAL,    /**< Total bytes across all traffic. */
        ENDP_COLUMN_PKT_AB,         /**< Packets transmitted from this endpoint. */
        ENDP_COLUMN_BYTES_AB,       /**< Bytes transmitted from this endpoint. */
        ENDP_COLUMN_PKT_BA,         /**< Packets received by this endpoint. */
        ENDP_COLUMN_BYTES_BA,       /**< Bytes received by this endpoint. */
        ENDP_NUM_COLUMNS,           /**< Total number of standard columns. */
        ENDP_COLUMN_GEO_COUNTRY  = ENDP_NUM_COLUMNS, /**< GeoIP country name. */
        ENDP_COLUMN_GEO_CITY,       /**< GeoIP city name. */
        ENDP_COLUMN_GEO_LATITUDE,   /**< GeoIP latitude coordinate. */
        ENDP_COLUMN_GEO_LONGITUDE,  /**< GeoIP longitude coordinate. */
        ENDP_COLUMN_GEO_AS_NUM,     /**< GeoIP autonomous system number. */
        ENDP_COLUMN_GEO_AS_ORG,     /**< GeoIP autonomous system organisation name. */
        ENDP_NUM_GEO_COLUMNS        /**< Total column count including GeoIP columns. */
    } endpoint_column_type_e;

    /**
     * @brief Construct an EndpointDataModel for a given protocol and filter.
     * @param protoId The protocol ID whose endpoint tap should be registered.
     * @param filter  Optional display filter string; empty means no filter.
     * @param parent  The parent QObject.
     */
    explicit EndpointDataModel(int protoId, QString filter, QObject *parent = nullptr);

    /**
     * @brief Return the number of columns, including GeoIP columns if available.
     * @param parent Unused; present for API compatibility.
     * @return @c ENDP_NUM_GEO_COLUMNS when GeoIP data is loaded, otherwise
     *         @c ENDP_NUM_COLUMNS.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Return header data for the endpoint table.
     * @param section     Column index.
     * @param orientation Must be Qt::Horizontal.
     * @param role        The data role; typically Qt::DisplayRole.
     * @return The column header label, or an invalid QVariant if unavailable.
     */
    QVariant headerData(int section, Qt::Orientation orientation = Qt::Horizontal,
                        int role = Qt::DisplayRole) const override;

    /**
     * @brief Return data for a cell in the endpoint table.
     * @param idx  The model index of the cell to query.
     * @param role The data role (Qt::DisplayRole, Qt::UserRole, etc.).
     * @return The cell data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const override;

    /**
     * @brief Enable or disable address name resolution for all address cells.
     * @param resolve true to resolve addresses to hostnames; false to show
     *                raw addresses.
     */
    void setResolveNames(bool resolve) override;

    /**
     * @brief Switch timestamp display between absolute and relative time.
     * @param absolute true for absolute (wall-clock) timestamps; false for
     *                 relative timestamps.
     */
    void useAbsoluteTime(bool absolute) override;

    /**
     * @brief Enable or disable nanosecond precision in timestamp display.
     * @param nanoseconds true to show nanosecond-resolution timestamps;
     *                    false for microsecond resolution.
     */
    void useNanosecondTimestamps(bool nanoseconds) override;
};


/**
 * @brief Tap data model for the Conversations statistics dialog.
 *
 * Collects per-conversation traffic statistics via the ATapDataModel tap
 * infrastructure and exposes them as a table with address, port, packet
 * count, byte count, timing, and throughput columns. An optional extended
 * TCP column block is appended when the selected protocol is TCP.
 */
class ConversationDataModel : public ATapDataModel
{
    Q_OBJECT

public:
    /**
     * @brief Column indices for the standard conversation statistics table.
     *
     * @c CONV_INDEX_COLUMN is a virtual column (equal to @c CONV_NUM_COLUMNS)
     * used to store the internal conversation index and is never displayed.
     */
    typedef enum {
        CONV_COLUMN_SRC_ADDR,       /**< Source address. */
        CONV_COLUMN_SRC_PORT,       /**< Source port (transport protocols only). */
        CONV_COLUMN_DST_ADDR,       /**< Destination address. */
        CONV_COLUMN_DST_PORT,       /**< Destination port (transport protocols only). */
        CONV_COLUMN_PACKETS,        /**< Total packets in the filtered set. */
        CONV_COLUMN_BYTES,          /**< Total bytes in the filtered set. */
        CONV_COLUMN_CONV_ID,        /**< Protocol-assigned conversation identifier. */
        CONV_COLUMN_PACKETS_TOTAL,  /**< Total packets across all traffic. */
        CONV_COLUMN_BYTES_TOTAL,    /**< Total bytes across all traffic. */
        CONV_COLUMN_PKT_AB,         /**< Packets from source to destination. */
        CONV_COLUMN_BYTES_AB,       /**< Bytes from source to destination. */
        CONV_COLUMN_PKT_BA,         /**< Packets from destination to source. */
        CONV_COLUMN_BYTES_BA,       /**< Bytes from destination to source. */
        CONV_COLUMN_START,          /**< Timestamp of the first packet in the conversation. */
        CONV_COLUMN_DURATION,       /**< Duration of the conversation. */
        CONV_COLUMN_BPS_AB,         /**< Throughput (bits/s) from source to destination. */
        CONV_COLUMN_BPS_BA,         /**< Throughput (bits/s) from destination to source. */
        CONV_NUM_COLUMNS,           /**< Total number of standard columns. */
        CONV_INDEX_COLUMN = CONV_NUM_COLUMNS /**< Virtual index column (not displayed). */
    } conversation_column_type_e;

    /**
     * @brief Additional column indices for the TCP extended column block.
     *
     * These columns are appended after @c CONV_INDEX_COLUMN when the
     * selected protocol is TCP.
     */
    typedef enum {
        CONV_TCP_EXT_COLUMN_A = CONV_INDEX_COLUMN, /**< First TCP extended column. */
        CONV_TCP_EXT_NUM_COLUMNS,                  /**< Total columns including TCP extensions. */
        CONV_TCP_EXT_INDEX_COLUMN = CONV_TCP_EXT_NUM_COLUMNS /**< Virtual index for TCP ext block. */
    } conversation_tcp_ext_column_type_e;

    /**
     * @brief Construct a ConversationDataModel for a given protocol and filter.
     * @param protoId The protocol ID whose conversation tap should be registered.
     * @param filter  Optional display filter string; empty means no filter.
     * @param parent  The parent QObject.
     */
    explicit ConversationDataModel(int protoId, QString filter, QObject *parent = nullptr);

    /**
     * @brief Return the number of columns, including any TCP extended columns.
     * @param parent Unused; present for API compatibility.
     * @return The total column count for the active protocol.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Return header data for the conversation table.
     * @param section     Column index.
     * @param orientation Must be Qt::Horizontal.
     * @param role        The data role; typically Qt::DisplayRole.
     * @return The column header label, or an invalid QVariant if unavailable.
     */
    QVariant headerData(int section, Qt::Orientation orientation = Qt::Horizontal,
                        int role = Qt::DisplayRole) const override;

    /**
     * @brief Return data for a cell in the conversation table.
     * @param idx  The model index of the cell to query.
     * @param role The data role (Qt::DisplayRole, Qt::UserRole, etc.).
     * @return The cell data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const override;

    /**
     * @brief Recalculate derived values (throughput, duration) after a tap update.
     *
     * Called after the tap has finished processing a batch of packets to
     * update computed columns such as @c CONV_COLUMN_BPS_AB and
     * @c CONV_COLUMN_DURATION.
     */
    void doDataUpdate();

    /**
     * @brief Return the raw @c conv_item_t for a given table row.
     * @param row Zero-based row index.
     * @return A pointer to the @c conv_item_t for @p row, or nullptr if
     *         @p row is out of range.
     */
    conv_item_t *itemForRow(int row);

    /**
     * @brief Return whether a conversation ID column should be shown.
     *
     * The conversation ID column is only meaningful for protocols that
     * assign explicit conversation identifiers (e.g. stream index for TCP).
     *
     * @param row Zero-based row index used to probe the data; defaults to 0.
     * @return true if a valid conversation ID is available for @p row.
     */
    bool showConversationId(int row = 0) const;

    /**
     * @brief Enable or disable address name resolution for all address cells.
     * @param resolve true to resolve addresses to hostnames; false to show
     *                raw addresses.
     */
    void setResolveNames(bool resolve) override;

    /**
     * @brief Switch timestamp display between absolute and relative time.
     * @param absolute true for absolute (wall-clock) timestamps; false for
     *                 relative timestamps.
     */
    void useAbsoluteTime(bool absolute) override;

    /**
     * @brief Enable or disable nanosecond precision in timestamp display.
     * @param nanoseconds true to show nanosecond-resolution timestamps;
     *                    false for microsecond resolution.
     */
    void useNanosecondTimestamps(bool nanoseconds) override;
};

#endif // ATAP_DATA_MODEL_H
