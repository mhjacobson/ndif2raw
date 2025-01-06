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

struct kencode_state {
    size_t node_count;
    const uint8_t *src_buf;
    size_t src_bitlen;
    size_t src_bitpos;
};

uint32_t kencode_popbits(struct kencode_state *state, size_t bit_len) {
    // no bits to read -> 0
    if (bit_len == 0) {
        return 0;
    }

    // make sure we have enough bits remaining
    assert(bit_len <= 32);
    assert((state->src_bitpos + bit_len) <= state->src_bitlen);

    // always read 32bit and shift and mask-out the requested bits
    size_t cur_bitpos = state->src_bitpos;
    state->src_bitpos += bit_len;
    const uint8_t *src_ptr = state->src_buf + (cur_bitpos / 8);
    uint32_t src_dword = (src_ptr[0] << 24) | (src_ptr[1] << 16) | (src_ptr[2] << 8) | src_ptr[3];
    return (src_dword >> (32 - bit_len - (cur_bitpos & 7))) & (0xFFFFFFFF >> (32 - bit_len));
}

size_t kencode_decode_copy_len(struct kencode_state *state) {
    // get length index (number of 1 bits, limited to 10)
    size_t len_idx = 0;
    while ((len_idx < 10) && (kencode_popbits(state, 1) != 0)) {
        len_idx += 1;
    }

    // decode length according to index
    switch (len_idx) {
    case 0:
        return kencode_popbits(state, 1);
    case 1:
        if (!kencode_popbits(state, 1)) {
            return 2;
        } else {
            return kencode_popbits(state, 1) + 3;
        }
    case 2:
        if (kencode_popbits(state, 1)) {
            return kencode_popbits(state, 2) + 7;
        } else {
            return kencode_popbits(state, 1) + 5;
        }
    case 3:
        return kencode_popbits(state, 3) + 11;
    case 4:
        return kencode_popbits(state, 3) + 19;
    case 5:
        return kencode_popbits(state, 5) + 27;
    case 6:
        return kencode_popbits(state, 6) + 59;
    case 7:
        return kencode_popbits(state, 7) + 123;
    case 8:
        return kencode_popbits(state, 8) + 251;
    case 9:
        return kencode_popbits(state, 9) + 507;
    default:
        return kencode_popbits(state, 10) + 1019;
    }
}

size_t kencode_decode_lit_len(struct kencode_state *state) {
    if (!kencode_popbits(state, 1)) {
        return 1;
    }

    switch (kencode_popbits(state, 2)) {
    case 0:
        return 2;
    case 1:
        return 3;
    case 2:
        return kencode_popbits(state, 2) + 4;
    case 3: {
        size_t read_bits = kencode_popbits(state, 4);
        if (read_bits < 8) {
            return read_bits + 8;
        } else if (read_bits < 12) {
            return kencode_popbits(state, 2) + (read_bits * 4) - 16;
        } else {
            return kencode_popbits(state, 3) + (read_bits * 8) - 64;
        }
    }
    default:
        assert(0 && "unreachable");
    }
}

size_t kencode_decode_copy_offs(struct kencode_state *state, size_t dst_pos) {
    // The bit length is dependent on the position in the output buffer and the maximum node count
    size_t bit_len = 0;
    if (dst_pos > 172032 && state->node_count > 131072) {
        bit_len = 14;
    } else if (dst_pos > 70000 && state->node_count > 65536) {
        bit_len = 13;
    } else if (dst_pos > 43008 && state->node_count > 32768) {
        bit_len = 12;
    } else if (dst_pos > 21504 && state->node_count > 16384) {
        bit_len = 11;
    } else if (dst_pos > 10752 && state->node_count > 8192) {
        bit_len = 10;
    } else if (dst_pos > 5376 && state->node_count > 4096) {
        bit_len = 9;
    } else if (dst_pos > 2688 && state->node_count > 2048) {
        bit_len = 8;
    } else if (dst_pos > 1000) {
        bit_len = 7;
    } else if (dst_pos > 672) {
        bit_len = 6;
    } else if (dst_pos > 160) {
        bit_len = 5;
    } else if (dst_pos > 80) {
        bit_len = 4;
    } else if (dst_pos > 40) {
        bit_len = 3;
    } else if (dst_pos > 20) {
        bit_len = 2;
    } else if (dst_pos > 10) {
        bit_len = 1;
    }

    if (!kencode_popbits(state, 1)) {
        return kencode_popbits(state, bit_len) + 1;
    }

    size_t base_len = 1 << bit_len;
    if (kencode_popbits(state, 1)) {
        base_len = 5 * base_len + 1;
        if (base_len + 1 >= dst_pos) {
            return base_len + kencode_popbits(state, 1);
        }
        if (base_len + 3 >= dst_pos) {
            return base_len + kencode_popbits(state, 2);
        }

        size_t j = base_len + 3;
        for (size_t i = 3; i <= (bit_len + 4); ++i) {
            j += (1U << (i - 1));
            size_t k = (j != 1664) ? j : 1644;
            if (k >= dst_pos || i == (bit_len + 4)) {
                return base_len + kencode_popbits(state, i);
            }
        }
    }
    return base_len + kencode_popbits(state, bit_len + 2) + 1;
}

size_t kencode_decompress(const uint8_t *const src, const size_t srclen, uint8_t *const dst,
                          const size_t dstlen) {
    // Setup state
    struct kencode_state state = {0};
    state.node_count = 10240; // The original Apple decoder always uses 10240 for NDIF-Images
    state.src_buf = src;
    state.src_bitlen = srclen * 8;
    state.src_bitpos = 0;

    // Decode loop
    uint8_t allow_lit = 1;
    size_t dst_pos = 0;
    while ((dst_pos < dstlen) && (state.src_bitpos < state.src_bitlen)) {
        // Decode copy length (Length 0 -> Copy literal)
        size_t copy_len = kencode_decode_copy_len(&state);
        if (copy_len == 0 && allow_lit) {
            // Decode literal length
            size_t lit_len = kencode_decode_lit_len(&state);
            assert((state.src_bitpos + (lit_len * 8)) <= state.src_bitlen);

            // Copy literal from src to dst
            const uint8_t *src_ptr = state.src_buf + (state.src_bitpos / 8);
            if ((state.src_bitpos & 7) == 0) {
                // If the bit position is aligned to a byte boundary, we can just use memcpy
                memcpy(dst + dst_pos, src_ptr, lit_len);
                dst_pos += lit_len;
            } else {
                // Otherwise we need to decode each byte separately
                for (size_t i = 0; i < lit_len; ++i) {
                    const uint16_t src_word = (src_ptr[0] << 8) | src_ptr[1];
                    src_ptr += 1;
                    dst[dst_pos] = (src_word >> (8 - (state.src_bitpos & 7))) & 0xff;
                    dst_pos += 1;
                }
            }
            state.src_bitpos += lit_len * 8;
            allow_lit = (lit_len > 62);
        } else {
            // Adjust copy length
            copy_len += (allow_lit != 0) ? 2 : 3;
            assert((dst_pos + copy_len) <= dstlen);

            // Decode copy offset
            size_t copy_offs = kencode_decode_copy_offs(&state, dst_pos);
            assert(copy_offs <= dst_pos);

            // Copy relative to dst_pos
            copy_bytes(dst + dst_pos, dst + dst_pos - copy_offs, copy_len);
            dst_pos += copy_len;
            allow_lit = 1;
        }
    }
    
    return dst_pos;
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
#define NDIF_CHUNK_KEN_CODE 128
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

            // Calculate the decompressed size. At least the KenCode algorithm relies on
            // the correct output size to stop decompressing
            size_t decomp_size = chunkbuf_size;
            if ((chunknum + 1) < header.nchunk) {
                decomp_size = (chunks[chunknum + 1].logical_offset - chunk->logical_offset) * BLOCK_SIZE;
            }

            switch (chunk_type) {
                case NDIF_CHUNK_ZERO:
                case NDIF_CHUNK_RAW:
                    chunkbuf_valid_size = 0;
                    break;
                case NDIF_CHUNK_KEN_CODE:
                    assert(decomp_size <= chunkbuf_size);
                    chunkbuf_valid_size = kencode_decompress(dbuffer + header.backing_offset + chunk->backing_offset, chunk->backing_size, chunkbuf, decomp_size);
                    break;
                case NDIF_CHUNK_ADC:
                    assert(decomp_size <= chunkbuf_size);
                    chunkbuf_valid_size = adc_decompress(dbuffer + header.backing_offset + chunk->backing_offset, chunk->backing_size, chunkbuf, decomp_size);
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
