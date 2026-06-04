/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_FILE_H
#define RTP_AUDIO_FILE_H

#include "config.h"
#include <ui/rtp_media.h>

#include <QIODevice>
#include <QDir>
#include <QTemporaryFile>
#include <QDebug>
#include <QBuffer>

struct _rtp_info;

/**
 * @brief Defines the type of an RTP frame.
 */
typedef enum {
    RTP_FRAME_AUDIO = 0, /**< The frame contains actual audio data. */
    RTP_FRAME_SILENCE    /**< The frame represents inserted silence. */
} rtp_frame_type;

/**
 * @brief Structure used for storing frame num during visual waveform decoding.
 */
typedef struct {
    qint64  real_pos;   /**< The real position in the byte stream. */
    qint64  sample_pos; /**< The logical sample position. */
    qint64  len;        /**< The length of the frame data. */
    uint32_t frame_num; /**< The RTP frame number. */
    rtp_frame_type type;/**< The type of the RTP frame. */
} rtp_frame_info;

/**
 * @brief A QIODevice subclass that handles reading and writing of RTP audio files and frames.
 */
class RtpAudioFile: public QIODevice
{
public:
    /**
     * @brief Constructs an RtpAudioFile object.
     * @param use_disk_for_temp Indicates whether to use disk for temporary files.
     * @param use_disk_for_frames Indicates whether to use disk for storing frame data.
     */
    explicit RtpAudioFile(bool use_disk_for_temp, bool use_disk_for_frames);

    /**
     * @brief Destroys the RtpAudioFile object.
     */
    ~RtpAudioFile();

    // Functions for writing Frames
    /**
     * @brief Sets the file to the frame write stage.
     */
    void setFrameWriteStage();

    /**
     * @brief Writes a silence frame.
     * @param frame_num The frame number.
     * @param samples The number of silence samples.
     */
    void frameWriteSilence(uint32_t frame_num, qint64 samples);

    /**
     * @brief Writes actual audio sample data for a frame.
     * @param frame_num The frame number.
     * @param data Pointer to the audio data to write.
     * @param max_size The maximum size of the data to write.
     * @return The number of bytes successfully written.
     */
    qint64 frameWriteSamples(uint32_t frame_num, const char *data, qint64 max_size);

    // Functions for reading Frames
    /**
     * @brief Sets the file to the frame read stage.
     * @param prepend_samples Number of samples to prepend.
     */
    void setFrameReadStage(qint64 prepend_samples);

    /**
     * @brief Reads samples for a single frame.
     * @param read_buff_bytes Pointer to store the number of bytes read into the buffer.
     * @param read_buff Pointer to the buffer containing the read samples.
     * @param read_len Pointer to store the number of samples read.
     * @param frame_num Pointer to store the frame number.
     * @param type Pointer to store the type of the frame.
     * @return True if successful, false otherwise.
     */
    bool readFrameSamples(int32_t *read_buff_bytes, SAMPLE **read_buff, uint32_t *read_len, uint32_t *frame_num, rtp_frame_type *type);

    // Functions for reading data during play
    /**
     * @brief Sets the file to the data read stage for playback.
     */
    void setDataReadStage();

    /**
     * @brief Opens the device with the specified mode.
     * @param mode The mode to open the device in.
     * @return True if successfully opened, false otherwise.
     */
    bool open(QIODevice::OpenMode mode) override;

    /**
     * @brief Gets the size of the file.
     * @return The size in bytes.
     */
    qint64 size() const override;

    /**
     * @brief Gets the current byte position in the file.
     * @return The current position in bytes.
     */
    qint64 pos() const override;

    /**
     * @brief Seeks to a specific byte offset.
     * @param off The byte offset to seek to.
     * @return True if successful, false otherwise.
     */
    bool seek(qint64 off) override;

    /**
     * @brief Retrieves the underlying sample file size.
     * @return The sample file size in bytes.
     */
    qint64 sampleFileSize();

    /**
     * @brief Seeks to a specific sample position.
     * @param samples The sample index to seek to.
     */
    void seekSample(qint64 samples);

    /**
     * @brief Reads a single sample.
     * @param sample Pointer to store the read sample.
     * @return The number of bytes read.
     */
    qint64 readSample(SAMPLE *sample);

    /**
     * @brief Gets the total number of samples.
     * @return The total sample count.
     */
    qint64 getTotalSamples();

    /**
     * @brief Gets the sample index at the end of inserted silence.
     * @return The sample index.
     */
    qint64 getEndOfSilenceSample();

protected:
    // Functions for reading data during play
    /**
     * @brief Reads up to maxSize bytes of data into the given buffer.
     * @param data Pointer to the buffer to store read data.
     * @param maxSize Maximum number of bytes to read.
     * @return The number of bytes read.
     */
    qint64 readData(char *data, qint64 maxSize) override;

    /**
     * @brief Writes up to maxSize bytes of data from the given buffer.
     * @param data Pointer to the data to write.
     * @param maxSize Maximum number of bytes to write.
     * @return The number of bytes written.
     */
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    /** @brief Stores waveform samples */
    QIODevice *sample_file_;

    /** @brief Stores rtp_packet_info per packet */
    QIODevice *sample_file_frame_;

    /** @brief The actual position in the underlying data stream. */
    qint64 real_pos_;

    /** @brief The actual size of the underlying data stream. */
    qint64 real_size_;

    /** @brief The position in the logical sample stream. */
    qint64 sample_pos_;

    /** @brief The size of the logical sample stream. */
    qint64 sample_size_;

    /** @brief Metadata about the currently processed frame. */
    rtp_frame_info cur_frame_;

    // Functions for writing Frames
    /**
     * @brief Records a frame write operation metadata.
     * @param frame_num The frame number.
     * @param real_pos The real file position.
     * @param sample_pos The logical sample position.
     * @param len The length of the frame.
     * @param type The frame type.
     * @return The amount of frame tracking data written.
     */
    qint64 frameWriteFrame(uint32_t frame_num, qint64 real_pos, qint64 sample_pos, qint64 len, rtp_frame_type type);

    /**
     * @brief Updates counters for real byte tracking.
     * @param written_bytes The number of bytes written.
     */
    void frameUpdateRealCounters(qint64 written_bytes);

    /**
     * @brief Updates counters for sample data tracking.
     * @param written_bytes The number of bytes written representing samples.
     */
    void frameUpdateSampleCounters(qint64 written_bytes);

    // Functions for reading Frames

    // Functions for reading data during play
    /**
     * @brief Internal helper to read frame data during playback.
     * @param data Pointer to the destination buffer.
     * @param want_read The desired number of bytes to read.
     * @return The actual number of bytes read.
     */
    qint64 readFrameData(char *data , qint64 want_read);
};

#endif // RTP_AUDIO_FILE_H
