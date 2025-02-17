#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <arm_neon.h>
#include <stdint.h>
#include <stdio.h>
#include <cstring>


void ExpansionKeys128(const unsigned char *k,  unsigned char keys[11][16] );


#define Nb 4    // Número de columnas en el estado AES (siempre 4)
#define Nk 4    // Número de palabras en la clave AES (4 para AES-128)
#define Nr 10   // Número de rondas para AES-128
#define size_message 16777216   // Tamaño del mensaje a procesar

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

uint8x16_t block[size_message];

void EliMAC(const uint8_t* input, uint8_t* tag, const uint8_t* key_1, const uint8_t* key_2, const uint32_t lenght){
    // Llaves de ronda (11 llaves de 128 bits para AES-128)
    uint8x16_t roundKeys_1[Nr + 1];
    uint8x16_t roundKeys_2[Nr + 1];
    uint8x16_t roundKeys_zero[Nr + 1];
    uint8x16_t S = vdupq_n_u8(0);
    int i=0;

    for (int i = 0; i < Nr; i++)
    {
        roundKeys_zero[i] = vdupq_n_u8(0);
    }
    
    // Generar las llaves de ronda
    KeyExpansion(key_1, roundKeys_1);
    KeyExpansion(key_2, roundKeys_2);

    // Definir una constante a sumar
    uint32_t constant = 1;

    // Crear un vector donde cada elemento es la constante
    uint32x4_t const_vec = vdupq_n_u32(constant);
    uint32x4_t index = vdupq_n_u32(constant);

    int size=0;

    if (lenght%16==0)
        size=lenght/16;


    for (i = 0; i < size; i++){
        block[i] = vld1q_u8(input+(16*i));
    }

    for (i = 0; i < size-1; i++){
        //Funcion H
        uint8x16_t block_H = AES_Encrypt_rounds( vreinterpretq_u8_u32(index), roundKeys_1, 7); 
        //Funcion i
        uint8x16_t block_I = AES_Encrypt_rounds( veorq_u8(block[i], block_H), roundKeys_zero, 4); 
        //checksum
        S = veorq_u8(block_I, S);

       index=vaddq_u32(index, const_vec);

    }
        //Ultimo bloque
        S = veorq_u8(block[i], S);
        S = AES_Encrypt(S, roundKeys_2);

        vst1q_u8(tag, S);

}


void EliHASH(const uint8_t* input, uint8_t* tag, const uint8_t* key_1, const uint32_t lenght){
    // Llaves de ronda (11 llaves de 128 bits para AES-128)
    uint8x16_t roundKeys_1[Nr + 1];
    uint8x16_t roundKeys_2[Nr + 1];
    uint8x16_t roundKeys_zero[Nr + 1];
    uint8x16_t S = vdupq_n_u8(0);
    int i=0;

    for (int i = 0; i < Nr; i++)
    {
        roundKeys_zero[i] = vdupq_n_u8(0);
    }
    
    // Generar las llaves de ronda
    KeyExpansion(key_1, roundKeys_1);

    // Definir una constante a sumar
    uint32_t constant = 1;

    // Crear un vector donde cada elemento es la constante
    uint32x4_t const_vec = vdupq_n_u32(constant);
    uint32x4_t index = vdupq_n_u32(constant);

    int size=0;

    if (lenght%16==0)
        size=lenght/16;


    for (i = 0; i < size; i++){
        block[i] = vld1q_u8(input+(16*i));
    }

    for (i = 0; i < size; i++){
        //Funcion H
        uint8x16_t block_H = AES_Encrypt_rounds( vreinterpretq_u8_u32(index), roundKeys_1, 7); 
        //Funcion i
        uint8x16_t block_I = AES_Encrypt_rounds( veorq_u8(block[i], block_H), roundKeys_zero, 4); 
        //checksum
        S = veorq_u8(block_I, S);

       index=vaddq_u32(index, const_vec);

    }

        vst1q_u8(tag, S);

}

char infoString[] = "EliMAC ARM CORTEX A76 RaspberryPi5";  /* Each AE implementation must have a global one */

#ifndef MAX_ITER
#define MAX_ITER 1024
#endif

    ALIGN(16) uint8_t AD[size_message];
    ALIGN(16) uint8_t ciphertext[size_message];
    ALIGN(16) uint8_t plaintext[size_message];

int main(int argc, char **argv)
{
	/* Allocate locals */
	ALIGN(16) char pt[8*1024] = {0};
	ALIGN(16) uint8_t tag[16];
	ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
	ALIGN(16) unsigned char nonce[] = "abcdefghijklmnop";
    
    uint8x16_t roundKeys_1[Nr + 1];
    int suma_vectorizada =1;
	char outbuf[MAX_ITER*15+1024];
	unsigned int iter_list[2048]; /* Populate w/ test lengths, -1 terminated */
	char *outp = outbuf;
	int iters, i, j, len;
	double Hz,sec;
	double ipi=0, tmpd;
	clock_t c;

	/* populate iter_list, terminate list with negative number */
	iter_list[0] = 32;
	iter_list[1] = 64;
	iter_list[2] = 128;
	iter_list[3] = 256;
	iter_list[4] = 512;
	iter_list[5] = 1024;
	iter_list[6] = 2048;
	iter_list[7] = 4096;
	iter_list[8] = 8192;
	iter_list[9] = 16384;
	iter_list[10] = 32768;
	iter_list[11] = size_message/16;
	iter_list[12] = size_message/8;
	iter_list[13] = size_message/4;
	iter_list[14] =size_message/2;
	iter_list[15] =size_message;
	iter_list[16] = -1;

    /* Create file for writing data */
	FILE *fp = NULL;
    char str_time[25];
	time_t tmp_time = time(NULL);
	struct tm *tp = localtime(&tmp_time);
	strftime(str_time, sizeof(str_time), "%F %R", tp);
	if ((argc < 2) || (argc > 3)) {
		printf("Usage: %s MHz [output_filename]\n", argv[0]);
		return 0;
	} else {
		Hz = 1e6 * strtol(argv[1], (char **)NULL, 10);
		if (argc == 3)
			fp = fopen(argv[2], "w");
	}
	
    outp += sprintf(outp, "%s ", infoString);
    #if __INTEL_COMPILER
        outp += sprintf(outp, "- Intel C %d.%d.%d ",
            (__ICC/100), ((__ICC/10)%10), (__ICC%10));
    #elif _MSC_VER
        outp += sprintf(outp, "- Microsoft C %d.%d ",
            (_MSC_VER/100), (_MSC_VER%100));
    #elif __clang_major__
        outp += sprintf(outp, "- Clang C %d.%d.%d ",
            __clang_major__, __clang_minor__, __clang_patchlevel__);
    #elif __clang__
        outp += sprintf(outp, "- Clang C 1.x ");
    #elif __GNUC__
        outp += sprintf(outp, "- GNU C %d.%d.%d ",
            __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    #endif

    #if __x86_64__ || _M_X64
    outp += sprintf(outp, "x86_64 ");
    #elif __i386__ || _M_IX86
    outp += sprintf(outp, "x86_32 ");
    #elif __ARM_ARCH_7__ || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH_7M__
    outp += sprintf(outp, "ARMv7 ");
    #elif __ARM__ || __ARMEL__
    outp += sprintf(outp, "ARMv5 ");
    #elif __MIPS__ || __MIPSEL__
    outp += sprintf(outp, "MIPS32 ");
    #elif __ppc64__
    outp += sprintf(outp, "PPC64 ");
    #elif __ppc__
    outp += sprintf(outp, "PPC32 ");
    #elif __sparc__
    outp += sprintf(outp, "SPARC ");
    #endif

    outp += sprintf(outp, "- Run %s\n\n",str_time);

	// outp += sprintf(outp, "Context: %d bytes\n", ae_ctx_sizeof());

	printf("Starting run...\n");fflush(stdout);

	/*
	 * Get time for key setup
	 */
	iters = (int)(Hz/520);
	do {
	
        KeyExpansion(key, roundKeys_1);

		c = clock();
		for (j = 0; j < iters; j++) {
            KeyExpansion(key, roundKeys_1);
		}
		c = clock() - c;
		sec = c/(double)CLOCKS_PER_SEC;
		tmpd = (sec * Hz) / (iters);
		
		if ((sec < 1.2)||(sec > 1.3))
			iters = (int)(iters * 5.0/(4.0 * sec));
		printf("%f\n", sec);
	} while ((sec < 1.2) || (sec > 1.3));
	
	printf("key -- %.2f (%d cycles)\n",sec,(int)tmpd);fflush(stdout);
	outp += sprintf(outp, "Key setup: %d cycles\n\n", (int)tmpd);

	/*
	 * Get times over different lengths
	 */
	iters = (int)(Hz/1000);
	i=0;
	len = iter_list[0];
	while (len >= 0) {
	
		do {
            EliHASH(plaintext, tag, key, len);
			c = clock();
			for (j = 0; j < iters; j++) {
                EliHASH(plaintext, tag, key, len);

				nonce[11] += 1;
			}
			c = clock() - c;
			sec = c/(double)CLOCKS_PER_SEC;
			tmpd = (sec * Hz) / ((double)len * iters);
			
			if ((sec < 1.2)||(sec > 1.3))
				iters = (int)(iters * 5.0/(4.0 * sec));
			
		} while ((sec < 1.2) || (sec > 1.3));
		
		printf("%d -- %.2f  (%6.2f cpb)\n",len,sec,tmpd);fflush(stdout);
		outp += sprintf(outp, "%5d  %6.2f\n", len, tmpd);
		if (len==44) {
			ipi += 0.05 * tmpd;
		} else if (len==552) {
			ipi += 0.15 * tmpd;
		} else if (len==576) {
			ipi += 0.2 * tmpd;
		} else if (len==1500) {
			ipi += 0.6 * tmpd;
		}
		
		++i;
		len = iter_list[i];
	}
	outp += sprintf(outp, "ipi %.2f\n", ipi);
	if (fp) {
        fprintf(fp, "%s", outbuf);
        fclose(fp);
    } else
        fprintf(stdout, "%s", outbuf);

	return ((pt[0]==12) && (pt[10]==34) && (pt[20]==56) && (pt[30]==78));
}







