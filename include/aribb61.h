#ifndef ARIBB61_H
#define ARIBB61_H
#pragma once
#ifdef __cplusplus
extern "C"
{
#endif

struct arib_b61_decoder;

enum arib_b61_log_level
{
    ARIB_B61_LOG_ERROR,
    ARIB_B61_LOG_VERBOSE,
};

enum arib_b61_status
{
    ARIB_B61_SUCCESS,
    ARIB_B61_FAILED,
};

enum arib_b61_status arib_b61_decoder_create(struct arib_b61_decoder** decoder, enum arib_b61_log_level level);
enum arib_b61_status arib_b61_decoder_put(struct arib_b61_decoder* decoder, const void* data, size_t size);
enum arib_b61_status arib_b61_decoder_get_buffer(struct arib_b61_decoder* decoder, const void** data, size_t* size);
enum arib_b61_status arib_b61_decoder_consume_buffer(struct arib_b61_decoder* decoder);
enum arib_b61_status arib_b61_decoder_finish(struct arib_b61_decoder* decoder);
void arib_b61_decoder_set_initial_buffering(struct arib_b61_decoder* decoder, int enable);
void arib_b61_decoder_set_strip(struct arib_b61_decoder* decoder, int enable);
void arib_b61_decoder_set_strip_invalid_data(struct arib_b61_decoder* decoder, int enable);
void arib_b61_decoder_set_async_ecm(struct arib_b61_decoder* decoder, int enable);
void arib_b61_decoder_release(struct arib_b61_decoder** decoder);

#ifdef __cplusplus
}
#endif
#endif
