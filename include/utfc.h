/**
 * Written by Nick Ilhan Atamgüc <nickatamguec@outlook.com>
 */

#if !defined(UTFC_H)
#define UTFC_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    /// No error.
    UTFC_ERROR_NONE,
    /// An unknown error occurred.
    UTFC_ERROR_UNKNOWN,
    /// A (re)allocation failed.
    UTFC_ERROR_OUT_OF_MEMORY,
    /// A character contains an invalid byte.
    UTFC_ERROR_INVALID_BYTE,
} UTFC_ERROR;

typedef struct {
    UTFC_ERROR status;
    uint32_t length;
    int8_t *value;
} UTFC_RESULT;

/* ==================== #!PRIVATE!# ==================== */

#define _UTFC_MAX_CHAR_LEN 4

/**
 * Returns the byte length for the next char of a UTF-8 string.
 * 
 * Notices:
 * - The bytes from `idx` up to `idx` + `return` represent the prefix.
 * - `idx` + `return` is the index of the actual char.
 * - The `return` value 0 means that something went wrong.
 */
static uint32_t _utfc_char_len(const char *value, uint32_t length, uint32_t idx) {
    const int8_t byte = (int8_t)value[idx];
    uint8_t char_len = 1;

    // Single-byte character
    if ((byte & 0x80) == 0) return 1;
    // Two-byte character
    else if ((byte & 0xE0) == 0xC0) char_len = 2;
    // Three-byte character
    else if ((byte & 0xF0) == 0xE0) char_len = 3;
    // Four-byte character
    else if ((byte & 0xF8) == 0xF0) char_len = 4;
    // Invalid start byte
    else return 0;

    if ((length - idx) < char_len) return 0;

    for (uint32_t i = 1; i < char_len; ++i) {
        if ((value[idx + i] & 0xC0) != 0x80) {
            // No valid continuation byte
            return 0;
        }
    }

    return char_len;
}

static inline UTFC_RESULT _utfc_result_init() {
    UTFC_RESULT result = (UTFC_RESULT){
        .status = UTFC_ERROR_NONE,
        .length = 0,
        .value = NULL
    };
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
    UTFC_RESULT result = _utfc_result_init();

    if (length == 0) {
        result.status = UTFC_ERROR_NONE;
        result.value = (int8_t *)malloc(1);
        if (result.value != NULL) {
            result.length = 1;
            result.value[0] = 0;
        }
        return result;
    }

    const uint32_t header_size = (length / 255) + 1;
    const uint32_t estimated_size = header_size + length;
    
    result.value = (int8_t *)malloc(estimated_size);
    if (result.value == NULL) {
        result.status = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    uint32_t write_pos = 0;
    const uint32_t full_chunks = length / 255;
    const uint32_t remainder = length % 255;

    for (uint32_t i = 0; i < full_chunks; i++) {
        result.value[write_pos++] = (int8_t)255;
    }
    result.value[write_pos++] = remainder;

    int8_t *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    for (uint32_t read_pos = 0; read_pos < length; read_pos++) {
        const int8_t char_len = _utfc_char_len(data, length, read_pos);
        if (char_len == 0) {
            // Something is wrong with the next character, so we return
            // the maximum of 4 checked bytes as the value to check them.
            result.status = UTFC_ERROR_INVALID_BYTE;

            // No longer needed.
            // Instead, we use the pointer starting at read_pos for data.
            free(result.value);

            uint32_t remaining_bytes = length - read_pos;
            if (remaining_bytes > _UTFC_MAX_CHAR_LEN) {
                remaining_bytes = _UTFC_MAX_CHAR_LEN;
            }
            result.length = remaining_bytes;
            result.value = (int8_t *)&data[read_pos];

            return result;
        }
        const uint8_t prefix_len = char_len - 1;

        if (prefix_len > 0) {
            bool prefix_changed = (prefix_len != cached_prefix_len);

            // If the length is not different, we check if the bytes are identical.
            if (prefix_changed == false) {
                for (int8_t i = 0; i < prefix_len; i++) {
                    if (cached_prefix[i] != (int8_t)data[read_pos + i]) {
                        prefix_changed = true;
                        break;
                    }
                }
            }

            // When we have a new prefix, it is cached and written.
            if (prefix_changed == true) {
                cached_prefix = (int8_t *)&data[read_pos];
                cached_prefix_len = prefix_len;

                for (int8_t i = 0; i < prefix_len; i++) {
                    result.value[write_pos++] = (int8_t)data[read_pos + i];
                }
            }

            read_pos += prefix_len;
        }

        const int8_t byte = (int8_t)data[read_pos];
        result.value[write_pos++] = byte;
        if (byte == '\0') {
            // End of string reached
            break;
        }
    }

    result.length = write_pos;
    int8_t *final_value = (int8_t *)realloc(result.value, write_pos);
    if (final_value != NULL) {
        result.value = final_value;
    }

    return result;
}

UTFC_RESULT utfc_decompress(const char *data, uint32_t length) {
    UTFC_RESULT result = _utfc_result_init();

    // TODO

    return result;
}

#endif // !defined(UTFC_H)