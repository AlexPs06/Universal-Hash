#include <arm_neon.h>
#include <stdint.h>
#include <stdio.h>
#include <cstring>
#include <stdlib.h>
#include "EliHash.h"

void KeyExpansion(const uint8_t* key, uint8x16_t* roundKeys);
void generate_keys(uint8x16_t* roundKeys, uint64_t length, uint8x16_t * obtained_keys);
void EliMAC(const uint8_t* input, uint8_t* tag, const uint8x16_t * keys_1, const uint8x16_t* keys_2, const uint32_t lenght);
uint8x16_t AES_Encrypt_rounds( uint8x16_t block, const uint8x16_t* roundKeys, int rounds);

static uint64_t gf_reduce_128(uint64_t hi, uint64_t lo);

#define Nr 10   // Número de rondas para AES-128
#define size_message 16777216   // Tamaño del mensaje a procesar

#define ALIGN(n) __attribute__ ((aligned(n)))



static const uint8x16_t roundKeys_zero[Nr + 1] = {
    [0 ... Nr] = { 0 }
};

static const uint8x16_t roundKeys_ones[Nr + 1] = {
    [0 ... Nr] = {
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01
    }
};
unsigned char Sbox[256]={
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

void print_array_16bits(uint8_t * message, uint8_t size){
    for (int i = 0; i < size; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
}

void print_array_32bits(uint32_t * message, uint8_t size){
    for (int i = 0; i < size; i++) {
        printf("%08x ", message[i]);
    }
    printf("\n");
}

uint32_t rotate_left(uint32_t value, unsigned int shift) {
    // Asegurarse de que el desplazamiento esté dentro del rango adecuado (0-31)
    shift %= 32;

    // Rotar a la izquierda usando desplazamientos y operaciones OR
    return (value << shift) | (value >> (32 - shift));
}

// Convertir un uint32_t a un arreglo de uint8_t (big-endian)
void uint32_to_uint8_array(uint32_t value, uint8_t* array) {
    array[0] = (value >> 24) & 0xFF;  // Byte más significativo
    array[1] = (value >> 16) & 0xFF;
    array[2] = (value >> 8) & 0xFF;
    array[3] = value & 0xFF;          // Byte menos significativo
}

// Convertir un arreglo de uint8_t a uint32_t (big-endian)
uint32_t uint8_array_to_uint32(uint8_t* array) {
    return ((uint32_t)array[0] << 24) |
           ((uint32_t)array[1] << 16) |
           ((uint32_t)array[2] << 8)  |
           (uint32_t)array[3];
}

// Expansión de clave AES para AES-128
void KeyExpansion(const uint8_t* key, uint8x16_t* roundKeys) {
    uint32x4_t temp;
    uint8x16_t key_schedule[11];
    uint32x4_t key_schedule_temp=vdupq_n_u32(0);
    // uint8x16_t rcon = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  // Ejemplo para la primera ronda (Rcon = 0x01)
    uint32x4_t rcon = {0x01000000, 0, 0, 0};

    const unsigned char matrizRcon[10]={ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    key_schedule[0] = vld1q_u8(key);  // La primera clave es la clave original

    for (int i = 1; i <= Nr; i++) {
        rcon[0]=matrizRcon[i-1];
        
        temp = vreinterpretq_u32_u8(key_schedule[i - 1]);  // Convertir a uint32_t
        key_schedule_temp = vreinterpretq_u32_u8(key_schedule[i - 1]);  // Convertir a uint32_t

        // Rotar
        temp  = vextq_u32(temp, temp, 3);   // Rotar una palabra (32 bits)
        temp[0] =rotate_left(temp[0], 24);


        // S-box
        uint8_t byte [4] ={0,0,0,0};
        uint32_to_uint8_array(temp[0], byte);
        for (int j = 0; j < 4; j++){
            byte[j]=Sbox[byte[j]];
        }
        temp[0]=uint8_array_to_uint32(byte);

        //XOR con la misma palabra rotword
        for (int j = 0; j < 4; j++){
            if (j==0){
                temp[j]=temp[j]^key_schedule_temp[0]^rcon[0];
            }else{
                temp[j]=temp[j-1]^key_schedule_temp[j];
            }
            
        }
        key_schedule[i] = vreinterpretq_u8_u32(temp);
    }

    // Guardar todas las claves de ronda
    for (int i = 0; i <= Nr; i++) {
        roundKeys[i] = key_schedule[i];
    }
}

void generate_keys(uint8x16_t* roundKeys, uint64_t length, uint8x16_t * obtained_keys){
    
    int64_t i = 0;
     /*
     * Define a constant counter increment (used as domain separator /
     * block index for key generation).
     */
    uint32_t constant = 1;

    /*
     * Vectorized version of the constant and the running index.
     */
    uint32x4_t const_vec = vdupq_n_u32(constant);
    uint32x4_t index     = vdupq_n_u32(constant);

    /*
     * Compute the number of 128-bit input blocks.
     * Only full blocks are processed.
     */
    int64_t size = length / 16;  // truncation intentional

    
    /*
     * Main processing loop:
     * Blocks are processed in pairs (X, Y).
     */
    for (i = 0; i < size - 1; i = i + 2) {

  
        /*
        * Extra inside index for a better pipeline for the processor.
        */
        uint32x4_t idx0 = index;
        index = vaddq_u32(index, const_vec);
        uint32x4_t idx1 = index;
        index = vaddq_u32(index, const_vec);

        /*
         * Generate a pseudo-random mask for block X
         * using AES with roundKeys_1 and the current index.
         */
        uint8x16_t generate_key_x =
            AES_Encrypt_rounds(vreinterpretq_u8_u32(idx0),
                               roundKeys, 8);

        

        /*
         * Generate a pseudo-random mask for block Y.
         */
        uint8x16_t generate_key_y =
            AES_Encrypt_rounds(vreinterpretq_u8_u32(idx1),
                               roundKeys, 8);


       

        /*
         * Save the keys in memory.
         */
        obtained_keys[i] = generate_key_x;
        obtained_keys[i+1] = generate_key_y;
    }
}

// Realizar cifrado AES de un bloque de 128 bits (10 rondas para AES-128)
uint8x16_t AES_Encrypt(uint8x16_t block, const uint8x16_t* roundKeys) {

    // Primera ronda (AddRoundKey)
    // Rondas intermedias (9 rondas para AES-128)
    for (int round = 0; round < Nr-1; round++) {
        block = vaeseq_u8(block, roundKeys[round]);   // SubBytes y ShiftRows
        block = vaesmcq_u8(block);                    // MixColumns
    }
    // print_array_16bits((uint8_t*)&roundKeys[round], 16);

    // Última ronda (sin MixColumns)
    block = vaeseq_u8(block, roundKeys[Nr-1]);          // SubBytes y ShiftRows
    block = veorq_u8(block, roundKeys[Nr]);           // AddRoundKey
    
    // Guardar el bloque cifrado
    return block;
}


uint8x16_t AES_Encrypt_rounds( uint8x16_t block, const uint8x16_t* roundKeys, int rounds) {
    // Rondas intermedias 
    for (int round = 0; round < rounds-1; round++) {
        block = vaeseq_u8(block, roundKeys[round]);   // SubBytes y ShiftRows
        block = vaesmcq_u8(block);                    // MixColumns
    }
    block = vaeseq_u8(block, roundKeys[rounds-1]);    // SubBytes y ShiftRows
    block = vaesmcq_u8(block);                        // MixColumns
    block = veorq_u8(block, roundKeys[rounds]);       // AddRoundKey
    // Guardar el bloque cifrado
    // vst1q_u8(output, block);
    return block;
}


static inline void update_function(uint32x4_t X,
                    uint32x4_t Y,
                    const uint8x16_t *roundKeys_zero,
                    const uint8x16_t *roundKeys_ones,
                    uint64x2_t * output)
{

   
    /*
     * Perform two rounds of AES encryption on X using an all-zero round key.
     * The result is reinterpreted as two 64-bit polynomials.
     */
    poly64x2_t X_prime = vreinterpretq_p64_u8(
        AES_Encrypt_rounds(vreinterpretq_u8_u32(X), roundKeys_zero, 2)
    );

    /*
     * Perform two rounds of AES encryption on Y using an all-ones round key.
     * The result is reinterpreted as two 64-bit polynomials.
     */
    poly64x2_t Y_prime = vreinterpretq_p64_u8(
        AES_Encrypt_rounds(vreinterpretq_u8_u32(Y), roundKeys_ones, 2)
    );

    

    /*
     * Reinterpret X and Y to 64-bit polynomial components.
     */
    poly64x2_t Xp = vreinterpretq_p64_u32(X);
    poly64x2_t Yp = vreinterpretq_p64_u32(Y);


    /*
     * Split X into its lower and higher 64-bit polynomial components.
     */
    poly64x1_t low_X  = vget_low_p64(Xp);   // Lower 64-bit polynomial of X
    poly64x1_t high_X = vget_high_p64(Xp);  // Higher 64-bit polynomial of X

    /*
     * Split Y into its lower and higher 64-bit polynomial components.
     */
    poly64x1_t low_Y  = vget_low_p64(Yp);   // Lower 64-bit polynomial of Y
    poly64x1_t high_Y = vget_high_p64(Yp);  // Higher 64-bit polynomial of Y

    /*
     * Split U (AES(X)) into its lower and higher 64-bit polynomial components.
     */
    poly64x1_t low_X_prime  = vget_low_p64(X_prime);   // Lower 64-bit polynomial of X_prime
    poly64x1_t high_X_prime = vget_high_p64(X_prime);  // Higher 64-bit polynomial of X_prime

    /*
     * Split T (AES(Y)) into its lower and higher 64-bit polynomial components.
     */
    poly64x1_t low_Y_prime  = vget_low_p64(Y_prime);   // Lower 64-bit polynomial of T
    poly64x1_t high_Y_prime = vget_high_p64(Y_prime);  // Higher 64-bit polynomial of T

    /*
     * Temporary storage for the 128-bit results of carry-less
     * polynomial multiplications (PMULL), reinterpreted as
     * two 64-bit unsigned integers.
     */
    uint64x2_t mul_acc[4];

    /*
     * Carry-less polynomial multiplications over GF(2):
     *   mul_acc[0] = X_low  * T_low
     *   mul_acc[1] = X_high * T_high
     *   mul_acc[2] = U_low  * Y_low
     *   mul_acc[3] = U_low  * Y_high
     *
     * Each vmull_p64 produces a 128-bit polynomial result.
     */
    mul_acc[0] = vreinterpretq_u64_p128(vmull_p64(low_X[0],  low_Y_prime[0]));
    mul_acc[1] = vreinterpretq_u64_p128(vmull_p64(high_X[0], high_Y_prime[0]));
    mul_acc[2] = vreinterpretq_u64_p128(vmull_p64(low_X_prime[0],  low_Y[0]));
    mul_acc[3] = vreinterpretq_u64_p128(vmull_p64(high_X_prime[0],  high_Y[0]));


    /*
     * Final reduction step:
     * Each 128-bit accumulator is reduced to a 64-bit value
     * x64+x4+x3+x+1
     * using the GF(2^128) reduction function.
     */
    uint64x2_t output_reduction_1;
    output_reduction_1[0] =  gf_reduce_128(mul_acc[0][1], mul_acc[0][0]);
    output_reduction_1[1] =  gf_reduce_128(mul_acc[1][1], mul_acc[1][0]);

    uint64x2_t output_reduction_2;
    output_reduction_2[0] =  gf_reduce_128(mul_acc[2][1], mul_acc[2][0]);
    output_reduction_2[1] =  gf_reduce_128(mul_acc[3][1], mul_acc[3][0]);

    /*
     * Accumulate the results into the output buffer using
     * standard 64-bit integer addition (with carry per lane).
     */
    output[0] = vaddq_u64(output_reduction_1, output[0]);
    output[1] = vaddq_u64(output_reduction_2, output[1]);

    



}


void EliMAC(const uint8_t* input, uint8_t* tag, const uint8x16_t * keys_1, const uint8x16_t* keys_2, const uint32_t lenght)
{
 
    uint64_t i = 0;

    /*
     * Accumulators for the hash computation.
     * Each entry stores a 128-bit value split into two 64-bit lanes.
     */
    uint32_t constant = 1;
    uint32x4_t const_vec = vdupq_n_u32(constant);
    uint32x4_t index = vdupq_n_u32(constant);

    uint8x16_t roundKeys_zero[Nr + 1];
    uint8x16_t S = vdupq_n_u8(0);

     for (int i = 0; i < Nr; i++)
    {
        roundKeys_zero[i] = vdupq_n_u8(0);
    }

    /*
     * Compute the number of 128-bit input blocks.
     * Only full blocks are processed.
     */
    uint64_t size = 0;
    if (lenght % 16 == 0)
        size = lenght / 16; 

    /*
     * Main processing loop:
     * Blocks are processed in pairs (X, Y).
     */
    for (i = 0; i < size - 1; i = i + 1) {

        /*
         * Load input blocks into NEON registers.
         */
        uint8x16_t block_x = vld1q_u8(input + 16*i);

        /*
         * Load keys blocks into NEON registers.
         */
        uint8x16_t generate_key_x = keys_1[i];

        /*
         * XOR input blocks with the generated masks and
         * reinterpret them as 32-bit word vectors.
         */
        uint32x4_t X = vreinterpretq_u32_u8(veorq_u8(block_x,   generate_key_x));

        //Function i
        uint8x16_t block_I = AES_Encrypt_rounds( X, roundKeys_zero, 4); 
        //checksum
        S = veorq_u8(block_I, S);

        index=vaddq_u32(index, const_vec);
    }

    /*
     * Final tag generation.
     * Currently, the tag is obtained by reinterpreting the
     * reduced output values as a byte array.
     */

    //Ultimo bloque
    S = veorq_u8(vld1q_u8(input + 16*i), S);
    S = AES_Encrypt(S, keys_2);
    memcpy(tag, &S, 16);  

}



static uint64_t gf_reduce_128(uint64_t hi, uint64_t lo)
{

    
    /* First fold: reduce x^64 terms */
    lo ^= hi;
    lo ^= hi << 1;
    lo ^= hi << 3;
    lo ^= hi << 4;

    /* Bits that overflowed beyond bit 63 */
    uint64_t carry =
        (hi >> 63) ^
        (hi >> 62) ^
        (hi >> 60) ^
        (hi >> 59);

    /* Second fold */
    lo ^= carry;
    lo ^= carry << 1;
    lo ^= carry << 3;
    lo ^= carry << 4;

    return lo;
}

void store_u64_be(uint8_t *dst, uint64_t x)
{
    for (int i = 0; i < 8; i++)
        dst[i] = (uint8_t)(x >> (56 - 8*i));
}

void store_tag(uint8_t *tag, uint64_t r[4])
{
    for (int i = 0; i < 4; i++)
        store_u64_be(tag + 8*i, r[i]);
}









