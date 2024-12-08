#include "aribb61.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void help(void)
{
    fprintf(stderr, "arib-b61-stream-test\n");
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  -s strip\n");
    fprintf(stderr, "    0: keep null packets (default)\n");
    fprintf(stderr, "    1: strip null packets\n");
    fprintf(stderr, "  -i strip invalid data\n");
    fprintf(stderr, "    0: keep invalid data\n");
    fprintf(stderr, "    1: strip invalid data (default)\n");
    fprintf(stderr, "  -v loglevel\n");
    fprintf(stderr, "    error (default)\n");
    fprintf(stderr, "    verbose\n");
}

int main(int argc, const char **argv)
{
    struct arib_b61_decoder *decoder;
    FILE *in = stdin, *out = stdout;
    size_t buf_size = 188 * 87;
    void *read_buf = malloc(buf_size);
    const void *decode_buf;
    size_t decode_size;
    int strip = 0;
    int strip_invalid_data = 1;
    enum arib_b61_log_level log_level = ARIB_B61_LOG_ERROR;

    if (!read_buf)
    {
        return 1;
    }
    for (int i = 1; i < argc; i++)
    {
        const char *name = argv[i];
        if (name[0] == '-')
        {
            const char *value = i + 1 < argc ? argv[i + 1] : "";
            switch (name[1])
            {
            case 's':
                i++;
                if (!strcmp(value, "0"))
                {
                    strip = 0;
                }
                else if (!strcmp(value, "1"))
                {
                    strip = 1;
                }
                else
                {
                    help();
                    return 1;
                }
                break;
            case 'v':
                i++;
                if (!strcmp(value, "error"))
                {
                    log_level = ARIB_B61_LOG_ERROR;
                }
                else if (!strcmp(value, "verbose"))
                {
                    log_level = ARIB_B61_LOG_VERBOSE;
                }
                else
                {
                    help();
                    return 1;
                }
                break;
            default:
                help();
                return 1;
            }
        }
    }
    if (arib_b61_decoder_create(&decoder, log_level) != ARIB_B61_SUCCESS)
    {
        return 1;
    }
    arib_b61_decoder_set_strip(decoder, strip);
    arib_b61_decoder_set_strip_invalid_data(decoder, strip_invalid_data);
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
