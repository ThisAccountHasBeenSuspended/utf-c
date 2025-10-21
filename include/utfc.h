/**
 * Written by Nick Ilhan Atamgüc <nickatamguec@outlook.com>
 */

#if !defined(UTFC_H)
#define UTFC_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>

typedef enum {
    UTFC_ERROR_NONE,
    UTFC_ERROR_COMPRESS_OOF, // Out-Of-Memory
    UTFC_ERROR_COMPRESS_LENGTH,
    UTFC_ERROR_COMPRESS_UNKNOWN,
    UTFC_ERROR_DECOMPRESS_LENGTH,
    UTFC_ERROR_DECOMPRESS_UNKNOWN,
} UTFC_ERROR;

typedef struct {
    UTFC_ERROR status;
    uint32_t length;
    char *value;
} UTFC_RESULT;

/* ==================== #!PRIVATE!# ==================== */

/**
 * Returns the byte length for the next char of a UTF-8 string.
 * 
 * Notices:
 * - The bytes from `idx` up to `idx` + `return` represent the prefix.
 * - `idx` + `return` is the index of the actual char.
 * - The `return` value 0 means that something went wrong.
 */
static uint8_t _utfc_char_len(const char *value, uint32_t length, uint32_t idx) {
    uint8_t byte = value[idx];

    // One-byte character (0xxxxxxx)
    if ((byte & 0x80) == 0x00) {
        return 1;
    }

    // Two-byte character (110xxxxx 10xxxxxx)
    if ((byte & 0xE0) == 0xC0) {
        // Check the remaining bytes
        if ((length - idx) < 2) return 0;
        // Check the second byte
        byte = value[idx + 1];
        if ((byte & 0xC0) != 0x80) return 0;
        return 2;
    }

    // Three-byte character (1110xxxx 10xxxxxx 10xxxxxx)
    if ((byte & 0xF0) == 0xE0) {
        // Check the remaining bytes
        if ((length - idx) < 3) return 0;
        // Check the second byte
        byte = value[idx + 1];
        if ((byte & 0xC0) != 0x80) return 0;
        // Check the third byte
        byte = value[idx + 2];
        if ((byte & 0xC0) != 0x80) return 0;
        return 3;
    }

    // Four-byte character (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
    if ((byte & 0xF8) == 0xF0) {
        // Check the remaining bytes
        if ((length - idx) < 4) return 0;
        // Check the second byte
        byte = value[idx + 1];
        if ((byte & 0xC0) != 0x80) return 0;
        // Check the third byte
        byte = value[idx + 2];
        if ((byte & 0xC0) != 0x80) return 0;
        // Check the third byte
        byte = value[idx + 3];
        if ((byte & 0xC0) != 0x80) return 0;
        return 4;
    }

    return 0;
}

static inline UTFC_RESULT _utfc_result_init(UTFC_ERROR error) {
    UTFC_RESULT result = { error, 0, NULL };
    return result;
}

/* ==================== #!PUBLIC!# ==================== */

void utfc_result_deinit(UTFC_RESULT *result) {
    if (result != NULL && result->value != NULL) {
        free(result->value);
        result->value = NULL;
    }
}

UTFC_RESULT utfc_compress(const char *data, uint32_t length) {
    UTFC_RESULT result = _utfc_result_init(UTFC_ERROR_NONE);

    if (length == 0) {
        result.status = UTFC_ERROR_NONE;
        return result;
    }

    const uint32_t header_size = (length / 255) + 1;
    const uint32_t estimated_size = header_size + length + 1;
    
    result.value = (char *)malloc(estimated_size);
    if (result.value == NULL) {
        result.status = UTFC_ERROR_COMPRESS_OOF;
        return result;
    }

    uint32_t write_pos = 0;
    const uint32_t full_chunks = length / 255;
    const uint32_t remainder = length % 255;

    for (uint32_t i = 0; i < full_chunks; i++) {
        result.value[write_pos++] = 255;
    }
    result.value[write_pos++] = remainder;

    uint8_t *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    for (uint32_t read_pos = 0; read_pos < length; read_pos++) {
        const uint8_t char_len = _utfc_char_len(data, length, read_pos);
        if (char_len == 0) {
            // TODO: What should happen? 
        }
        const uint8_t prefix_len = char_len - 1;

        if (prefix_len > 0) {
            bool prefix_changed = (prefix_len != cached_prefix_len);
            if (prefix_changed == false) {
                for (uint8_t i = 0; i < prefix_len; i++) {
                    if (cached_prefix[i] != (uint8_t)data[read_pos + i]) {
                        prefix_changed = true;
                        break;
                    }
                }
            }
            if (prefix_changed == true) {
                cached_prefix = (uint8_t *)&data[read_pos];
                cached_prefix_len = prefix_len;

                for (uint8_t i = 0; i < prefix_len; i++) {
                    result.value[write_pos++] = data[read_pos + i];
                }
            }

            read_pos += prefix_len;
        }

        const uint8_t byte = (uint8_t)data[read_pos];
        result.value[write_pos++] = byte;
        if (byte == '\0') {
            // End reached
            break;
        }
    }

    result.length = write_pos;
    result.value = (char *)realloc(result.value, write_pos);

    return result;
}

UTFC_RESULT utfc_decompress(const char *data, uint32_t length) {
    UTFC_RESULT result = _utfc_result_init(UTFC_ERROR_NONE);

    // TODO

    return result;
}

#endif // !defined(UTFC_H)