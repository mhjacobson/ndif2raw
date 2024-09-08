/*
 * ndif2raw
 * author: Matt Jacobson
 * date: September 2024
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define READ_8(buf) (*(buf++))
#define READ_BE_16(buf) (buf += 2, ((buf[-2] << 8) | buf[-1]))
#define READ_BE_24(buf) (buf += 3, ((buf[-3] << 16) | (buf[-2] << 8) | buf[-1]))
#define READ_BE_32(buf) (buf += 4, ((buf[-4] << 24) | (buf[-3] << 16) | (buf[-2] << 8) | buf[-1]))

#ifndef DEBUG_ADC
#define DEBUG_ADC 0
#endif /* DEBUG_ADC */

#define BLOCK_SIZE 512

const uint8_t zero_buf[BLOCK_SIZE];

// Copies forward from src to dest a byte at a time; the buffers may overlap (and frequently will).
void copy_bytes(uint8_t *const dst, const uint8_t *const src, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

size_t adc_decompress(const uint8_t *const src, const size_t srclen, uint8_t *const dst, const size_t dstlen) {
    const uint8_t *ptr = src;
    uint8_t *dstptr = dst;

    memset(dst, 0, dstlen);

    while (ptr < src + srclen) {
        assert(dstptr < dst + dstlen);
        // TODO: add asserts before memcpys to ensure enough dst space
        // TODO: add asserts before reads to ensure enough src space

        uint8_t len;

        if (*ptr & 0x80) {
            // Command 1: copy literal bytes from source.
            len = (*ptr & 0x7F) + 1;
            ptr++;

#if DEBUG_ADC
            fprintf(stderr, "%#tx: copy literal %#hhx bytes (%#tx src)\n", dstptr - dst, len, ptr - src - 1);
#endif /* DEBUG_ADC */

            memcpy(dstptr, ptr, len);
            ptr += len;
            dstptr += len;
        } else if (*ptr & 0x40) {
            // Command 2: copy relative bytes from destination, with 16-bit negative offset.
            len = (*ptr & 0x3F) + 4;
            ptr++;

            // NOTE: offset range is [1, 65536], even though stored values are [0, 65535].  Since 65536 doesn't fit in a uint16_t, use uint32_t for offset.
            const uint32_t offset = READ_BE_16(ptr) + 1;
            assert(offset > 0);
            assert(offset <= dstptr - dst);

#if DEBUG_ADC
            fprintf(stderr, "%#tx: copy relative (16-bit offset: %#x) %#hhx bytes (%#tx src)\n", dstptr - dst, offset, len, ptr - src - 3);
#endif /* DEBUG_ADC */

            copy_bytes(dstptr, dstptr - offset, len);
            dstptr += len;
        } else {
            // Command 3: copy relative bytes from destination, with 10-bit negative offset.
            len = (*ptr >> 2) + 3;
            // NOTE: no ptr increment here, as low two bits are used for offset.

            const uint16_t offset = (READ_BE_16(ptr) & 0x3FF) + 1;
            assert(offset > 0);
            assert(offset <= dstptr - dst);

#if DEBUG_ADC
            fprintf(stderr, "%#tx: copy relative (10-bit offset: %#hx) %#hhx bytes (%#tx src)\n", dstptr - dst, offset, len, ptr - src - 2);
#endif /* DEBUG_ADC */

            copy_bytes(dstptr, dstptr - offset, len);
            dstptr += len;
        }

#if DEBUG_ADC
        for (int i = 0; i < len; i++) { fprintf(stderr, "%02hhx ", dstptr[i - len]); }
        fprintf(stderr, "\n");
#endif /* DEBUG_ADC */
    }

    return dstptr - dst;
}

struct ndif_header {
    uint16_t version;
    uint16_t fsid;
    uint8_t namelen;
    uint8_t name[63];
    uint32_t nblock;
    uint32_t max_chunk_size_blocks;
    uint32_t backing_offset;
    uint32_t crc32;
    uint32_t segmented;
    uint32_t reserved[9];
    uint32_t nchunk;
};

struct ndif_chunk {
    uint32_t logical_offset; /* NOTE: only 24 bits on disk */
    uint8_t type;
    uint32_t backing_offset;
    uint32_t backing_size;
};

#define NDIF_CHUNK_ZERO 0
#define NDIF_CHUNK_RAW 2
#define NDIF_CHUNK_ADC 131
#define NDIF_CHUNK_TERMINATOR 255

uint8_t *read_data(FILE *const fp, size_t *const size_out) {
    int rv;

    const long orig = ftell(fp);
    assert(orig != -1);

    rv = fseek(fp, 0, SEEK_END);
    assert(!rv);

    const size_t size = ftell(fp);
    assert(size != -1);
    uint8_t *const buffer = malloc(size);
    assert(buffer);

    rv = fseek(fp, 0, SEEK_SET);
    assert(!rv);
    const size_t nread = fread(buffer, size, 1, fp);
    assert(nread == 1);

    rv = fseek(fp, orig, SEEK_SET);
    assert(!rv);

    if (size_out) *size_out = size;
    return buffer;
}

// TODO: provide a non-Macintosh implementation
#include <CoreServices/CoreServices.h>
uint8_t *read_resource(const char *const file, const ResType type, const ResID id, size_t *const size_out) {
    OSStatus err;
    FSRef ref;

    err = FSPathMakeRef((UInt8 *)file, &ref, NULL);
    assert(err == noErr);

    const ResFileRefNum rsrc = FSOpenResFile(&ref, fsRdPerm);
    UseResFile(rsrc);
    const Handle handle = GetResource(type, id);
    assert(handle);
    const Size size = GetHandleSize(handle);

    uint8_t *const buffer = malloc(size);
    assert(buffer);
    memcpy(buffer, *handle, size);

    ReleaseResource(handle);
    CloseResFile(rsrc);

    if (size_out) *size_out = size;
    return buffer;
}

const uint8_t *read_header(struct ndif_header *const header, const uint8_t *buf) {
    header->version = READ_BE_16(buf);
    header->fsid = READ_BE_16(buf);
    header->namelen = READ_8(buf);

    memcpy(header->name, buf, 63);
    buf += 63;

    header->nblock = READ_BE_32(buf);
    header->max_chunk_size_blocks = READ_BE_32(buf);
    header->backing_offset = READ_BE_32(buf);
    header->crc32 = READ_BE_32(buf);
    header->segmented = READ_BE_32(buf);

    for (int i = 0; i < 9; i++) {
        header->reserved[i] = READ_BE_32(buf);
    }

    header->nchunk = READ_BE_32(buf);
    return buf;
}

const uint8_t *read_chunks(struct ndif_chunk *const chunks, const size_t nchunk, const uint8_t *buf) {
    for (size_t i = 0; i < nchunk; i++) {
        chunks[i].logical_offset = READ_BE_24(buf);
        chunks[i].type = READ_8(buf);
        chunks[i].backing_offset = READ_BE_32(buf);
        chunks[i].backing_size = READ_BE_32(buf);
    }

    return buf;
}

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage:\n\tndif2raw <input NDIF path> <output raw path>\n");
        return 1;
    }

    const char *const in_path = argv[1];
    const char *const out_path = argv[2];
    FILE *input, *output;

    input = fopen(in_path, "r");

    if (input == NULL) {
        perror("cannot open input file");
        return 1;
    }

    if (!strcmp(out_path, "-")) {
        output = stdout;
    } else {
        output = fopen(out_path, "wx");

        if (output == NULL) {
            perror("cannot open output file");
            return 1;
        }
    }

    size_t dsize, rsize;
    size_t n;
    uint8_t *const dbuffer = read_data(input, &dsize);
    uint8_t *const rbuffer = read_resource(in_path, 'bcem', 128, &rsize);
    const uint8_t *rbuf = rbuffer;

    assert(rsize >= sizeof (struct ndif_header));
    struct ndif_header header;
    rbuf = read_header(&header, rbuf);

    switch (header.version) {
        case 10:
        case 11:
        case 12:
            break;
        default:
            // NOTE: version 2 uses a different header/chunk format and is not compatible with this code as is
            abort();
    }

    // NOTE: don't use sizeof (struct ndif_chunk) for this assert, since it differs from the disk format
    assert(rsize - sizeof (struct ndif_header) == header.nchunk * 3 * sizeof (uint32_t));
    struct ndif_chunk *const chunks = malloc(header.nchunk * sizeof (struct ndif_chunk));
    rbuf = read_chunks(chunks, header.nchunk, rbuf);
    const struct ndif_chunk *chunk = NULL;

    uint32_t chunknum;
    uint8_t chunk_type;

    const size_t chunkbuf_size = header.max_chunk_size_blocks * BLOCK_SIZE;
    uint8_t *const chunkbuf = malloc(chunkbuf_size);
    size_t chunkbuf_valid_size = 0;

    for (uint32_t i = 0; i < header.nblock; i++) {
        bool prepare_chunk = false;

        // Determine if next chunk needs to be prepared.
        if (i == 0) {
            chunknum = 0;
            assert(chunknum < header.nchunk);
            chunk = chunks;
            prepare_chunk = true;
        } else if (chunknum + 1 < header.nchunk && i >= chunks[chunknum + 1].logical_offset) {
            chunknum++;
            assert(chunknum < header.nchunk);
            chunk++;
            prepare_chunk = true;
        }

        // Prepare chunk if necessary.
        if (prepare_chunk) {
            chunk_type = chunk->type;

            switch (chunk_type) {
                case NDIF_CHUNK_ZERO:
                case NDIF_CHUNK_RAW:
                    chunkbuf_valid_size = 0;
                    break;
                case NDIF_CHUNK_ADC:
                    chunkbuf_valid_size = adc_decompress(dbuffer + header.backing_offset + chunk->backing_offset, chunk->backing_size, chunkbuf, chunkbuf_size);
                    break;
                case NDIF_CHUNK_TERMINATOR:
                    fprintf(stderr, "unexpectedly reached terminator chunk\n");
                    abort();
                    break;
                default:
                    fprintf(stderr, "unrecognized chunk type %#x\n", chunk_type);
                    abort();
            }
        }

        // Write out a block.
        assert(i >= chunk->logical_offset);
        const size_t block_offset = i - chunk->logical_offset;

        switch (chunk_type) {
            case NDIF_CHUNK_ZERO:
                n = fwrite(zero_buf, BLOCK_SIZE, 1, output);
                assert(n == 1);
                break;
            case NDIF_CHUNK_RAW:
                assert(BLOCK_SIZE * block_offset + BLOCK_SIZE <= dsize);
                n = fwrite(dbuffer + chunk->backing_offset + BLOCK_SIZE * block_offset, BLOCK_SIZE, 1, output);;
                assert(n == 1);
                break;
            default:
                assert(BLOCK_SIZE * block_offset + BLOCK_SIZE <= chunkbuf_valid_size);
                n = fwrite(chunkbuf + BLOCK_SIZE * block_offset, BLOCK_SIZE, 1, output);
                assert(n == 1);
        }
    }

    free(chunks);
    free(chunkbuf);
    free(rbuffer);
    free(dbuffer);
}
