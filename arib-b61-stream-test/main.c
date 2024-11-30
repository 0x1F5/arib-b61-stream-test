#include <stdio.h>
#include <stdlib.h>
#include "aribb61.h"

int main(void)
{
    struct arib_b61_decoder *decoder;
    FILE *in = stdin, *out = stdout;
    size_t buf_size = 1024 * 64;
    void *read_buf = malloc(buf_size);
    const void *decode_buf;
    size_t decode_size;

    if (!read_buf)
    {
        return 1;
    }
    if (arib_b61_decoder_create(&decoder, ARIB_B61_LOG_ERROR) != ARIB_B61_SUCCESS)
    {
        return 1;
    }
    while (!feof(in))
    {
        size_t read_size = fread(read_buf, 1, buf_size, in);
        if (read_size == 0)
        {
            break;
        }
        arib_b61_decoder_put(decoder, read_buf, read_size);
        arib_b61_decoder_get_buffer(decoder, &decode_buf, &decode_size);
        if (fwrite(decode_buf, 1, decode_size, out) < decode_size)
        {
            perror("write error");
            arib_b61_decoder_release(&decoder);
            return 1;
        }
        arib_b61_decoder_consume_buffer(decoder);
    }
    arib_b61_decoder_finish(decoder);
    arib_b61_decoder_get_buffer(decoder, &decode_buf, &decode_size);
    fwrite(decode_buf, 1, decode_size, out);
    arib_b61_decoder_consume_buffer(decoder);
    arib_b61_decoder_release(&decoder);
}
