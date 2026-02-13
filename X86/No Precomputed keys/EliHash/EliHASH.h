#pragma once
#include <cstddef>
#include <cstdint>
#include <immintrin.h>

void EliHASH(const uint8_t* input,
                 uint8_t* tag,
                 __m128i* roundKeys,
                 uint64_t length);

void AES_128_Key_Expansion(const unsigned char* userkey,
                           void* key);

void generate_keys(__m128i* roundKeys,
                   uint64_t length,
                   __m128i* obtained_keys);
