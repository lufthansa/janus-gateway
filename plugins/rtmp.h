#ifndef JANUS_SRS_RTMP_H
#define JANUS_SRS_RTMP_H

#include <glib.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/error.h>
#include <libavformat/rtpdec.h>
#include <srs_librtmp.h>
#include <opus/opus.h>
#include <faac.h>
#include <faaccfg.h>
#include <samplerate.h>
#include "../mutex.h"
	

typedef enum {
    Media_Audio = 0,
    Media_Video
} Media_Type;

// 音频采样精度枚举
typedef enum {
    Format_16Bit = 1,
    Format_24Bit = 2,
    Format_32Bit = 3,
    Format_Float = 4
} AudioInputFormat;

// 视频参数定义
typedef struct Video_Param {
    int width;
    int height;
} Video_Param;

// 音频参数定义
typedef struct Audio_Param {
    int channels;
    int sample_rate;
    AudioInputFormat input_format;
} Audio_Param;

// 用于组装音视频完整帧
typedef struct AV_Data {
    uint8_t*	v_buf;					// 视频h264帧buf
    int 		v_len;					// 视频h264帧有效长度
    uint32_t 	v_pts;					// 视频h264帧时间戳
    uint8_t* 	a_buf;					// 音频pcm数据buf
    int 		a_begin;     			// 音频pcm有效数据起始位置
    int 		a_end;       			// 音频pcm有效数据结束位置
    uint32_t    a_pts;                  // 音频帧时间戳
	ulong 		a_input_samples;		// pcm解码样本数，一个采样深度(16bit)算一个样本
	ulong 		a_max_output_bytes;		// aac编码后缓存最大长度    
} AV_Data;

// 推流上下文参数
typedef struct Stream_Context {
	AVFormatContext*	ff_ofmt_ctx;		// ffmpeg 上下文句柄
	AVStream* 			ff_stream;			// ffmpeg 视频流参数
	RTPDemuxContext*	ff_rtp_demux_ctx;	// ffmpeg rtp上下文句柄
	OpusDecoder* 		opus_dec;			// opus 解码器句柄
    SRC_STATE*          sample_handle;      // samplerate 重采样句柄
    double              sample_ratio;       // 重采样转换率
	faacEncHandle 		aac_enc;			// aac 编码器句柄
	srs_rtmp_t			rtmp;				// srs-librtmp 推流句柄
	AV_Data				avdata;				// 音视频缓存
    Audio_Param         ap;                 // 源pcm音频参数     
} Stream_Context;

// 保存不同roomid的参数
static GHashTable* context_table = NULL;
static janus_mutex context_mutex = JANUS_MUTEX_INITIALIZER;

// 对外接口函数
// 模块初始化
void rtmp_module_init(void);
// 准备推流
int rtmp_stream_open(char* room_id, char* url, Video_Param* vp, Audio_Param* ap);
// 结束推流
void rtmp_stream_close(char* room_id);
// 推流
int rtmp_stream_push(char* room_id, char *buf, int len, Media_Type av);

// stream_context创建函数
Stream_Context* context_create(Video_Param* vp, Audio_Param* ap, char* url);
// stream_context销毁函数
void context_destroy(Stream_Context* ctx);

// 内部函数
// ffmpeg
static int ffmpeg_decoder_create_(Stream_Context* ctx, Video_Param* vp);
static void ffmpeg_decoder_destroy_(Stream_Context* ctx);
// opus
static int opus_decoder_create_(Stream_Context* ctx, Audio_Param* ap);
static void opus_decoder_destroy_(Stream_Context* ctx);
// resample
static int resample_create_(Stream_Context* ctx, Audio_Param* ap);
static void resample_destroy_(Stream_Context* ctx);
// faac
static int faac_encoder_create_(Stream_Context* ctx, Audio_Param* ap);
static void faac_encoder_destroy_(Stream_Context* ctx);
// srs-rtmp
static int srs_rtmp_create_(Stream_Context* ctx, char* url);
static void srs_rtmp_destroy_(Stream_Context* ctx);
#endif
