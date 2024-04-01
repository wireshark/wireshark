/* rtp_audio_file.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * RTP samples are stored in "sparse" file. File knows where are silence gaps
 * and they are handled special way (not stored).
 *
 * File uses Frame as piece of information. One Frame match audio of one
 * decoded packet or audio silence in between them. Frame holds information
 * about frame type (audio/silence), its length and realtime position and
 * sample position (where decoded audio is really stored, with gaps omitted).
 *
 * There are three stages of the object use
 * - writing data by frames during decoding of the stream
 * - reading data by frames during creating the visual waveform
 * - reading data by bytes/samples during audio play or audio save
 *
 * There is no stage indication in the object, but there are different calls
 * used by the code. For last stage the object looks like QIODevice therefore
 * any read of it looks like reading of sequence of bytes.
 *
 * If audio starts later than start of the file, first Frame contains silence
 * record. It is leaved out at some cases.
 */

#include "rtp_audio_file.h"
#include <ws_attributes.h>

RtpAudioFile::RtpAudioFile(bool use_disk_for_temp, bool use_disk_for_frames):
      real_pos_(0)
    , real_size_(0)
    , sample_pos_(0)
    , sample_size_(0)
{
    QString tempname;

    // ReadOnly because we write different way
    QIODevice::open(QIODevice::ReadOnly);

    tempname = "memory";
    if (use_disk_for_temp) {
        tempname = QString("%1/wireshark_rtp_stream").arg(QDir::tempPath());
        sample_file_ = new QTemporaryFile(tempname, this);
    } else {
        sample_file_ = new QBuffer(this);
    }
    if (!sample_file_->open(QIODevice::ReadWrite)) {
        // We are out of file resources
        delete sample_file_;
        qWarning() << "Can't create temp file in " << tempname;
        throw -1;
    }

    tempname = "memory";
    if (use_disk_for_frames) {
        tempname = QString("%1/wireshark_rtp_frames").arg(QDir::tempPath());
        sample_file_frame_ = new QTemporaryFile(tempname, this);
    } else {
        sample_file_frame_ = new QBuffer(this);
    }
    if (!sample_file_frame_->open(QIODevice::ReadWrite)) {
        // We are out of file resources
        delete sample_file_;
        delete sample_file_frame_;
        qWarning() << "Can't create frame file in " << tempname;
        throw -1;
    }
}

RtpAudioFile::~RtpAudioFile()
{
    if (sample_file_) delete sample_file_;
    if (sample_file_frame_) delete sample_file_frame_;
}

/*
 * Functions for writing Frames
 */
void RtpAudioFile::setFrameWriteStage()
{
    sample_file_->seek(0);
    sample_file_frame_->seek(0);
    real_pos_ = 0;
    real_size_ = 0;
    sample_pos_ = 0;
    sample_size_ = 0;
}

void RtpAudioFile::frameUpdateRealCounters(qint64 written_bytes)
{
    if (real_pos_ < real_size_) {
        // We are writing before end, calculate if we are over real_size_
        qint64 diff = real_pos_ + written_bytes - real_size_;

        if (diff > 0) {
            // Update size
            real_size_ += diff;
        }
    } else {
        real_size_ += written_bytes;
    }
    real_pos_ += written_bytes;
}

void RtpAudioFile::frameUpdateSampleCounters(qint64 written_bytes)
{
    if (sample_pos_ < sample_size_) {
        // We are writing before end, calculate if we are over sample_size_
        qint64 diff = sample_pos_ + written_bytes - sample_size_;

        if (diff > 0) {
            // Update size
            sample_size_ += diff;
        }
    } else {
        sample_size_ += written_bytes;
    }
    sample_pos_ += written_bytes;
}

qint64 RtpAudioFile::frameWriteFrame(uint32_t frame_num, qint64 real_pos, qint64 sample_pos, qint64 len, rtp_frame_type type)
{
    rtp_frame_info frame_info;

    frame_info.real_pos = real_pos;
    frame_info.sample_pos = sample_pos;
    frame_info.len = len;
    frame_info.frame_num = frame_num;
    frame_info.type = type;

    return sample_file_frame_->write((char *)&frame_info, sizeof(frame_info));
}

void RtpAudioFile::frameWriteSilence(uint32_t frame_num, qint64 samples)
{
    if (samples < 1) return;

    qint64 silence_bytes = samples * SAMPLE_BYTES;

    frameWriteFrame(frame_num, real_pos_, sample_pos_, silence_bytes, RTP_FRAME_SILENCE);
    frameUpdateRealCounters(silence_bytes);
}

qint64 RtpAudioFile::frameWriteSamples(uint32_t frame_num, const char *data, qint64 max_size)
{
    int64_t written;

    written = sample_file_->write(data, max_size);

    if (written != -1) {
        frameWriteFrame(frame_num, real_pos_, sample_pos_, written, RTP_FRAME_AUDIO);
        frameUpdateRealCounters(written);
        frameUpdateSampleCounters(written);
    }

    return written;
}

/*
 * Functions for reading Frames
 */

void RtpAudioFile::setFrameReadStage(qint64 prepend_samples)
{
    sample_file_frame_->seek(0);
    if (prepend_samples > 0) {
        // Skip first frame which contains openning silence
        sample_file_frame_->read((char *)&cur_frame_, sizeof(cur_frame_));
    }
}

bool RtpAudioFile::readFrameSamples(int32_t *read_buff_bytes, SAMPLE **read_buff, spx_uint32_t *read_len, uint32_t *frame_num, rtp_frame_type *type)
{
    rtp_frame_info frame_info;
    uint64_t read_bytes = 0;

    if (!sample_file_frame_->read((char *)&frame_info, sizeof(frame_info))) {
        // Can't read frame, some error occurred
        return false;
    }

    *frame_num = frame_info.frame_num;
    *type = frame_info.type;

    if (frame_info.type == RTP_FRAME_AUDIO) {
        // Resize buffer when needed
        if (frame_info.len > *read_buff_bytes) {
            while ((frame_info.len > *read_buff_bytes)) {
                *read_buff_bytes *= 2;
            }
            *read_buff = (SAMPLE *) g_realloc(*read_buff, *read_buff_bytes);
        }

        sample_file_->seek(frame_info.sample_pos);
        read_bytes = sample_file_->read((char *)*read_buff, frame_info.len);
    } else {
        // For silence we do nothing
        read_bytes = frame_info.len;
    }

    *read_len = (spx_uint32_t)(read_bytes / SAMPLE_BYTES);

    return true;
}

/*
 * Functions for reading data during play
 */
void RtpAudioFile::setDataReadStage()
{
    sample_file_frame_->seek(0);
    sample_file_frame_->read((char *)&cur_frame_, sizeof(cur_frame_));
    real_pos_ = cur_frame_.real_pos;
}

bool RtpAudioFile::open(QIODevice::OpenMode mode)
{
    if (mode == QIODevice::ReadOnly) {
       return true;
    }

    return false;
}

qint64 RtpAudioFile::size() const
{
    return real_size_;
}

qint64 RtpAudioFile::pos() const
{
    return real_pos_;
}

/*
 * Seek starts from beginning of Frames and search one where offset belongs
 * to. It looks inefficient, but seek is used usually just to jump to 0 or
 * to skip first Frame where silence is stored.
 */
bool RtpAudioFile::seek(qint64 off)
{
    if (real_size_ <= off) {
        // Can't seek above end of file
        return false;
    }

    // Search for correct offset from first frame
    sample_file_frame_->seek(0);
    while (1) {
        // Read frame
        if (!sample_file_frame_->read((char *)&cur_frame_, sizeof(cur_frame_))) {
            // Can't read frame, some error occurred
            return false;
        }

        if ((cur_frame_.real_pos + cur_frame_.len) > off) {
            // We found correct frame
            // Calculate offset in frame
            qint64 diff = off - cur_frame_.real_pos;
            qint64 new_real_pos = cur_frame_.real_pos + diff;
            qint64 new_sample_pos = cur_frame_.sample_pos + diff;

            if (cur_frame_.type == RTP_FRAME_AUDIO) {
                // For audio frame we should to seek to correct place
                if (!sample_file_->seek(new_sample_pos)) {
                    return false;
                }
                // Real seek was successful
                real_pos_ = new_real_pos;
                return true;
            } else {
                // For silence frame we blindly confirm it
                real_pos_ = new_real_pos;
                return true;
            }
        }
    }
    return false;
}

qint64 RtpAudioFile::sampleFileSize()
{
    return real_size_;
}

void RtpAudioFile::seekSample(qint64 samples)
{
    seek(sizeof(SAMPLE) * samples);
}

qint64 RtpAudioFile::readFrameData(char *data , qint64 want_read)
{
    // Calculate remaining data in frame
    qint64 remaining = cur_frame_.len - (real_pos_ - cur_frame_.real_pos);
    qint64 was_read;

    if (remaining < want_read) {
        // Incorrect call, can't read more than is stored in frame
        return -1;
    }

    if (cur_frame_.type == RTP_FRAME_AUDIO) {
        was_read = sample_file_->read(data, want_read);
        real_pos_ += was_read;
    } else {
        memset(data, 0, want_read);
        real_pos_ += want_read;
        was_read = want_read;
    }

    return was_read;
}

qint64 RtpAudioFile::readSample(SAMPLE *sample)
{
    return read((char *)sample, sizeof(SAMPLE));
}

qint64 RtpAudioFile::getTotalSamples()
{
    return (real_size_/(qint64)sizeof(SAMPLE));
}

qint64 RtpAudioFile::getEndOfSilenceSample()
{
    if (cur_frame_.type == RTP_FRAME_SILENCE) {
        return (cur_frame_.real_pos + cur_frame_.len) / (qint64)sizeof(SAMPLE);
    } else {
        return -1;
    }
}

qint64 RtpAudioFile::readData(char *data, qint64 maxSize)
{
    qint64 to_read = maxSize;
    qint64 can_read;
    qint64 was_read = 0;
    qint64 remaining;

    while (1) {
        // Calculate remaining data in frame
        remaining = cur_frame_.len - (real_pos_ - cur_frame_.real_pos);
        if (remaining > to_read) {
            // Even we want to read more, we can read just till end of frame
            can_read = to_read;
        } else {
            can_read = remaining;
        }
        if (can_read==readFrameData(data, can_read)) {
            to_read -= can_read;
            data += can_read;
            was_read += can_read;
            if (real_pos_ >= cur_frame_.real_pos + cur_frame_.len) {
                // We exhausted the frame, read next one
                if (!sample_file_frame_->read((char *)&cur_frame_, sizeof(cur_frame_))) {
                    // We are at the end of the file
                    return was_read;
                }
                if ((cur_frame_.type == RTP_FRAME_AUDIO) && (!sample_file_->seek(cur_frame_.sample_pos))) {
                    // We tried to seek to correct place, but it failed
                    return -1;
                }
            }
            if (to_read == 0) {
                return was_read;
            }
        } else {
            return -1;
        }
    }
}

qint64 RtpAudioFile::writeData(const char *data _U_, qint64 maxSize _U_)
{
    // Writing is not supported
    return -1;
}

