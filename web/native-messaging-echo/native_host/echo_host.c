/*
 * Minimal Chrome Native Messaging echo host.
 *
 * Protocol:
 *   stdin : [uint32_t length in native byte order][UTF-8 JSON bytes]
 *   stdout: [uint32_t length in native byte order][UTF-8 JSON bytes]
 *
 * The JSON message is not parsed.  It is echoed byte-for-byte.
 *
 * IMPORTANT:
 *   Never print diagnostics to stdout, because stdout is the Native
 *   Messaging protocol stream.  Use stderr for logs.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_ECHO_MESSAGE (1024U * 1024U)

static int
read_exact(FILE *fp, void *buf, size_t size)
{
    unsigned char *p = (unsigned char *)buf;
    size_t done = 0;

    while (done < size) {
        size_t n = fread(p + done, 1, size - done, fp);

        if (n == 0) {
            if (feof(fp))
                return 0;
            if (ferror(fp)) {
                fprintf(stderr, "fread failed\n");
                return -1;
            }
        }

        done += n;
    }

    return 1;
}

static int
write_exact(FILE *fp, const void *buf, size_t size)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t done = 0;

    while (done < size) {
        size_t n = fwrite(p + done, 1, size - done, fp);

        if (n == 0) {
            fprintf(stderr, "fwrite failed\n");
            return -1;
        }

        done += n;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    /*
     * Chrome normally passes the calling extension origin as argv[1].
     * Log it only to stderr; stdout must contain protocol data only.
     */
    if (argc > 1)
        fprintf(stderr, "Native host started by: %s\n", argv[1]);

    for (;;) {
        uint32_t len = 0;
        unsigned char *message = NULL;
        int rc;

        rc = read_exact(stdin, &len, sizeof(len));
        if (rc == 0) {
            /* Clean EOF. */
            return EXIT_SUCCESS;
        }
        if (rc < 0)
            return EXIT_FAILURE;

        /*
         * Chrome accepts at most 1 MiB from a native host.
         * Because this program echoes the request, reject anything larger.
         */
        if (len == 0 || len > MAX_ECHO_MESSAGE) {
            fprintf(stderr, "Invalid/too-large message length: %u\n", len);
            return EXIT_FAILURE;
        }

        message = malloc(len);
        if (message == NULL) {
            fprintf(stderr, "malloc(%u) failed\n", len);
            return EXIT_FAILURE;
        }

        rc = read_exact(stdin, message, len);
        if (rc <= 0) {
            fprintf(stderr, "Unexpected EOF/error while reading payload\n");
            free(message);
            return EXIT_FAILURE;
        }

        /*
         * Echo exactly the same Native Messaging frame back to Chrome.
         */
        if (write_exact(stdout, &len, sizeof(len)) < 0 ||
            write_exact(stdout, message, len) < 0) {
            free(message);
            return EXIT_FAILURE;
        }

        if (fflush(stdout) != 0) {
            fprintf(stderr, "fflush(stdout) failed\n");
            free(message);
            return EXIT_FAILURE;
        }

        free(message);

        /*
         * Keep looping so the same binary also works with connectNative().
         * With sendNativeMessage(), Chrome uses the first reply.
         */
    }
}
