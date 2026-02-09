// // funciones.h
// #ifndef FUNCIONES_H
// #define FUNCIONES_H

// // Declaración de las funciones
// void ParaHash_V3(const uint8_t* input, uint8_t* tag, uint8x16_t *roundKeys_1, const uint64_t lenght);
// void KeyExpansion(const uint8_t* key, uint8x16_t* roundKeys);
// #endif // FUNCIONES_H

#pragma once
#include <arm_neon.h>
#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

void NHT(
    const uint8_t* input, uint8_t* tag, const uint8x16_t * keys_1, const uint8x16_t* keys_2, const uint32_t lenght
);

void generate_keys(
    uint8x16_t* roundKeys, uint64_t length, uint8x16_t * obtained_keys
);

void KeyExpansion(
    const uint8_t* key, uint8x16_t* roundKeys
);



#ifdef __cplusplus
}
#endif
