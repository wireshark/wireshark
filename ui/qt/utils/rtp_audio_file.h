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

#include <speex/speex_resampler.h>

#include <QIODevice>
#include <QDir>
#include <QTemporaryFile>
#include <QDebug>
#include <QBuffer>

struct _rtp_info;

typedef enum {
    RTP_FRAME_AUDIO = 0,
    RTP_FRAME_SILENCE
} rtp_frame_type;

// Structure used for storing frame num during visual waveform decoding
typedef struct {
    qint64  real_pos;
    qint64  sample_pos;
    qint64  len;
    uint32_t frame_num;
    rtp_frame_type type;
} rtp_frame_info;


class RtpAudioFile: public QIODevice
{
public:
    explicit RtpAudioFile(bool use_disk_for_temp, bool use_disk_for_frames);
    ~RtpAudioFile();

    // Functions for writing Frames
    void setFrameWriteStage();
    void frameWriteSilence(uint32_t frame_num, qint64 samples);
    qint64 frameWriteSamples(uint32_t frame_num, const char *data, qint64 max_size);

    // Functions for reading Frames
    void setFrameReadStage(qint64 prepend_samples);
    bool readFrameSamples(int32_t *read_buff_bytes, SAMPLE **read_buff, spx_uint32_t *read_len, uint32_t *frame_num, rtp_frame_type *type);

    // Functions for reading data during play
    void setDataReadStage();
    bool open(QIODevice::OpenMode mode) override;
    qint64 size() const override;
    qint64 pos() const override;
    bool seek(qint64 off) override;
    qint64 sampleFileSize();
    void seekSample(qint64 samples);
    qint64 readSample(SAMPLE *sample);
    qint64 getTotalSamples();
    qint64 getEndOfSilenceSample();

protected:
    // Functions for reading data during play
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    QIODevice *sample_file_;       // Stores waveform samples
    QIODevice *sample_file_frame_; // Stores rtp_packet_info per packet
    qint64 real_pos_;
    qint64 real_size_;
    qint64 sample_pos_;
    qint64 sample_size_;
    rtp_frame_info cur_frame_;

    // Functions for writing Frames
    qint64 frameWriteFrame(uint32_t frame_num, qint64 real_pos, qint64 sample_pos, qint64 len, rtp_frame_type type);
    void frameUpdateRealCounters(qint64 written_bytes);
    void frameUpdateSampleCounters(qint64 written_bytes);

    // Functions for reading Frames

    // Functions for reading data during play
    qint64 readFrameData(char *data , qint64 want_read);
};

#endif // RTP_AUDIO_FILE_H
