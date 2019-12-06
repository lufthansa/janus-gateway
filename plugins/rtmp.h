#ifndef JANUS_SRS_RTMP_H
#define JANUS_SRS_RTMP_H

#include <glib.h>
#include <opus/opus.h>
#include <faac.h>
#include <faaccfg.h>
#include <samplerate.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/error.h>
#include "../mutex.h"
#include "rtp2h264.h"


typedef enum {
    Media_Audio = 0,
    Media_Video
} Media_Type;

// Audio sample deep
typedef enum {
    Format_16Bit = 1,
    Format_24Bit = 2,
    Format_32Bit = 3,
    Format_Float = 4
} AudioInputFormat;

typedef struct Video_Param {
    int width;
    int height;
} Video_Param;

typedef struct Audio_Param {
    int channels;
    int sample_rate;
    AudioInputFormat input_format;
} Audio_Param;

// Video and Audio temprate data
typedef struct AV_Data {
    uint8_t*	v_buf;					// h264 frame buf, parsed from rtp
    int 		v_len;					// one h264 frame length
    uint32_t 	v_pts;					// video frame's timestamp
    uint8_t*   	a_buf;					// audio pcm format buf
    int 		a_begin;     			// audio pcm buf begin pos
    int 		a_end;       			// audio pcm buf end pos
    uint32_t    a_pts;                  // audio frame' timestamp
	ulong 		a_input_samples;		// audio sample format
	ulong 		a_max_output_bytes;		// aac buf's max length    
} AV_Data;

// Context of stream
typedef struct Stream_Context {
	RTPDemuxContext*	rtp_ctx;	        // rtp decoder handle
	OpusDecoder* 		opus_dec;			// opus decoder handle
    SRC_STATE*          sample_handle;      // samplerate handle
    double              sample_ratio;       // resample ratio
	faacEncHandle 		aac_enc;			// aac encoder handle
    AVFormatContext*	ff_ofmt_ctx;        // ffmpeg rtmp client
	AV_Data				avdata;				// video & audio cache
    Audio_Param         ap;                 // audio params
} Stream_Context;

// Save different Stream_Context by room_id
static GHashTable* context_table = NULL;
static janus_mutex context_mutex = JANUS_MUTEX_INITIALIZER;

// External interfaces
// Module init
void rtmp_module_init(void);
// open stream
int rtmp_stream_open(char* room_id, char* url, Audio_Param* ap, Video_Param* vp);
// close stream
void rtmp_stream_close(char* room_id);
// push stream
int rtmp_stream_push(char* room_id, char *buf, int len, Media_Type av);

Stream_Context* context_create(Audio_Param* ap, Video_Param* vp, char* url);
void context_destroy(Stream_Context* ctx);

// Internal interfaces
// rtp
static int rtp_decoder_create_(Stream_Context* ctx);
static void rtp_decoder_destroy_(Stream_Context* ctx);
// opus
static int opus_decoder_create_(Stream_Context* ctx, Audio_Param* ap);
static void opus_decoder_destroy_(Stream_Context* ctx);
// resample
static int resample_create_(Stream_Context* ctx, Audio_Param* ap);
static void resample_destroy_(Stream_Context* ctx);
// faac
static int faac_encoder_create_(Stream_Context* ctx, Audio_Param* ap);
static void faac_encoder_destroy_(Stream_Context* ctx);
// ffmpeg-rtmp
static int rtmp_create_(Stream_Context* ctx, Video_Param* vp, char* url);
static void rtmp_destroy_(Stream_Context* ctx);
#endif
