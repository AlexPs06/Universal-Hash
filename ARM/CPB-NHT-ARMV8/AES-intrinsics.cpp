#include <arm_neon.h>
#include <stdint.h>
#include <stdio.h>
#include <cstring>
#include "AES-intrinsics.h"

void ExpansionKeys128(const unsigned char *k,  unsigned char keys[11][16] );


#define Nb 4    // Número de columnas en el estado AES (siempre 4)
#define Nk 4    // Número de palabras en la clave AES (4 para AES-128)
#define Nr 10   // Número de rondas para AES-128
#define size_message 16777216   // Tamaño del mensaje a procesar
#define Toeplitz_matrix 4   // Tamaño del mensaje a procesar

#define ALIGN(n) __attribute__ ((aligned(n)))

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
    uint32x4_t rcon = {0x01000000, 0, 0, 0};Tamaño del mensaje a procesar

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



void update_funtion(uint32x4_t *X,uint32x4_t *Y,  uint64x2_t * output){
    
    // X = M1+K1||M2+K2||M3+K3||M4+K4
    // Y = M5+K5||M6+K6||M7+K7||M8+K8

    //Separacion de las partes bajas y altas
    uint32x2_t low_X[Toeplitz_matrix];
    uint32x2_t high_X[Toeplitz_matrix];
    uint32x2_t low_Y[Toeplitz_matrix];
    uint32x2_t high_Y[Toeplitz_matrix];
    

    for (int i = 0; i < Toeplitz_matrix; i++){
        low_X[i] = vget_low_u32(X[i]);   // Contiene {1, 2} de X_i
        high_X[i] = vget_high_u32(X[i]); // Contiene {3, 4} de X_i
        low_Y[i] = vget_low_u32(Y[i]);   // Contiene {1, 2} de y_i
        high_Y[i] = vget_high_u32(Y[i]); // Contiene {3, 4} de Y_i
    }
    

    uint64x2_t result_low[Toeplitz_matrix];
    uint64x2_t result_high[Toeplitz_matrix];
    for (int i = 0; i < Toeplitz_matrix; i++){
        // Multiplicacion de las partes altas y bajas x0y0||x1y1||...||u4v4    
        result_low[i] = vmull_u32(low_X[i], low_Y[i]);    // x0y0||y1y1
        result_high[i] = vmull_u32(high_X[i], high_Y[i]); // x2y2||y3y3

    }
    
    // Suma de las partes altas y bajas    
    uint64x2_t result[Toeplitz_matrix]; 
    for (int i = 0; i < Toeplitz_matrix; i++){
        // suma de las partes altas y bajas x0y0||x1y1||...||u4v4    
        result[i] = vaddq_u64(result_low[i], result_high[i]);    // x0y0||y1y1 + x2y2||y3y3
    }

    for (int i = 0; i < 4; i++){
        output[i] =vaddq_u64(result[i], output[i]);
    }
    
}

uint8x16_t block[size_message];

void NHT(const uint8_t* input, uint8_t* tag, const uint8_t* key_1, const uint64_t lenght){
    // Llaves de ronda (11 llaves de 128 bits para AES-128)
    uint8x16_t roundKeys_1[Toeplitz_matrix][Nr + 1];
    uint8x16_t roundKeys_2[Nr + 1];
    uint8x16_t roundKeys_zero[Nr + 1];
    int i=0;

    for (int i = 0; i < Nr; i++)
    {
        roundKeys_zero[i] = vdupq_n_u8(0);
    }
    uint8_t key_temp[16];

    for (int i = 0; i < 16; i++){
        key_temp[i]=key_1[i];

    }
    

    // Generar las llaves de ronda
    for (int i = 0; i < Toeplitz_matrix; i++){
        KeyExpansion(key_temp, roundKeys_1[i]);
        key_temp[0]=key_temp[0]+1;
    }
    


    
    // Definir una constante a sumar
    uint32_t constant = 1;

    // Crear un vector donde cada elemento es la constante
    uint32x4_t const_vec = vdupq_n_u32(constant);
    uint32x4_t index = vdupq_n_u32(constant);
    uint64x2_t output[Toeplitz_matrix];

    for (i = 0; i < 4; i++){
        output[i]= vdupq_n_u64(0);
    }
     

    int size=0;

    if (lenght%16==0)
        size=lenght/16;


    for (i = 0; i < size; i++){
        block[i] = vld1q_u8(input+(16*i));
    }

    for (i = 0; i < size-1; i=i+2){


        uint8x16_t generate_key_x[Toeplitz_matrix];

        for (int j = 0; j < Toeplitz_matrix; j++){
            generate_key_x[j] = AES_Encrypt_rounds( vreinterpretq_u8_u32(index), roundKeys_1[j], 8); 
        }

        index=vaddq_u32(index, const_vec);
        uint8x16_t generate_key_y[Toeplitz_matrix];

        for (int j = 0; j < Toeplitz_matrix; j++){
            generate_key_x[j] = AES_Encrypt_rounds( vreinterpretq_u8_u32(index), roundKeys_1[j], 8); 
        }



        uint32x4_t X[Toeplitz_matrix];
        uint32x4_t Y[Toeplitz_matrix]; 
        for (int j = 0; j < Toeplitz_matrix; j++){
            X[j] = vreinterpretq_u32_u8(veorq_u8(block[i], generate_key_x[j]));
            Y[j] = vreinterpretq_u32_u8(veorq_u8(block[i+1], generate_key_y[j]));


        }

        update_funtion(X, Y, output);


       index=vaddq_u32(index, const_vec);

    }
    uint64_t S[Toeplitz_matrix];
    for (int i = 0; i < Toeplitz_matrix; i++){
        S[i]=output[i][0]+output[i][1];

    }


    // Convierte cada uint64_t a 8 uint8_t
    for (int i = 0; i < Toeplitz_matrix; i++) {
        for (int j = 0; j < 8; j++) {
            tag[(i * 8) + j] = (S[i] >> (j * 8)) & 0xFF;
        }
    }

}

// int main() {

//     // Clave de 128 bits (16 bytes)
//     ALIGN(16) uint8_t key_1[16] = {
//         0x2b,0x28,0xab,0x09, 
//         0x7e,0xae,0xf7,0xff, 
//         0x15,0xd2,0x15,0x4f, 
//         0x16,0xa6,0x88,0x3c
//     };

//     // Clave de 128 bits (16 bytes)
//     ALIGN(16) uint8_t key_2[16] = {
//         0x3b,0x28,0xab,0x09, 
//         0x7e,0xae,0xf7,0xff, 
//         0x15,0xd2,0x15,0x4f, 
//         0x16,0xa6,0x88,0x3c
//     };

//     // Texto plano de 128 bits (16 bytes)
//     ALIGN(16) uint8_t plaintext[size_message] = {
//         0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x07, 0x07,  
//         0x0f, 0x0f, 0x1f, 0x1f, 0x3f, 0x3f, 0x7f, 0x7f,
//     };

//     for (int i = 0; i < size_message; i++)
//     {
//         plaintext[i]=i;
//     }
//     plaintext[0]=20;
        
//     // Resultado del cifrado (16 bytes)
//     ALIGN(16) uint8_t tag[8*Toeplitz_matrix];
//     for (int i = 0; i < 8*Toeplitz_matrix; i++){
//         tag[i]=0;
//     }
    

//     NHT(plaintext, tag, key_1, key_2, size_message);

//     // Imprimir el resultado cifrado
//     printf("TAG: ");
//     for (int i = 0; i < 8*Toeplitz_matrix; i++) {
//         printf("%02x ", tag[i]);
//     }
//     printf("\n");

//     return 0;
// }








