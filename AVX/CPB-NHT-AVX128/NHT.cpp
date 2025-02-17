#include <iostream>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include "NHT.h"
using namespace std;
#define size_message 16777216   // Tamaño del mensaje a procesar


#define ALIGN(n) __attribute__ ((aligned(n)))
#define pipeline 4
#define Toeplitz_matrix 4   // Numero de multiplciaciones

#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)



void H(__m128i input,__m128i * output,  __m128i key[Toeplitz_matrix][11], unsigned rounds,unsigned nblks);
static void AES_128_Key_Expansion(const unsigned char *userkey, void *key);
void NHT(unsigned char *K, unsigned char *M, int size, unsigned char *T);
void F(__m128i *x,__m128i *y, __m128i *output );



static __m128i plain_text[size_message]; 


void NHT(unsigned char *K, unsigned char *M, int size, unsigned char *T){
    uint64_t i=0;
    int m_blocks = 0;
    if (size%16==0)
        m_blocks=(size/16);
    else
        m_blocks=(size/16) + 1;

    // static __m128i * plain_text = (__m128i*) M;
    for (uint64_t i = 0; i < m_blocks; i++)
	{
		plain_text[i] = _mm_load_si128((__m128i*) M+(i));
	}

    static __m128i * Keys = (__m128i*) K;
    static __m128i Keys_rounds;
    static __m128i Keys_rounds_X[Toeplitz_matrix];
    static __m128i Keys_rounds_Y[Toeplitz_matrix];

    __m128i keys_128[Toeplitz_matrix][11];
    __m128i key[11];
    __m128i Tag;
    __m128i X[Toeplitz_matrix];
    __m128i Y[Toeplitz_matrix];
    __m128i S[Toeplitz_matrix];
    __m128i checksum[Toeplitz_matrix];
    __m128i add = _mm_set_epi32(0,0,0,1);
	unsigned char k_0 = K[0];
    for (size_t j = 0; j < Toeplitz_matrix; j++){
	    AES_128_Key_Expansion(K, keys_128[i]);
		K[0]=K[0]+1;
    }
    for (size_t j = 0; j < Toeplitz_matrix; j++){
		Keys_rounds_X[i] = _mm_setzero_si128();
		Keys_rounds_Y[i] = _mm_setzero_si128();
	}
    Keys_rounds=_mm_setzero_si128();;
	
    for (i = 0; i < m_blocks; i=i+2){


        H(Keys_rounds,Keys_rounds_X, keys_128, 8,Toeplitz_matrix);

        Keys_rounds=_mm_add_epi64(Keys_rounds, add);

        H(Keys_rounds,Keys_rounds_Y, keys_128, 8,Toeplitz_matrix);


        for (size_t j = 0; j < Toeplitz_matrix; j++){
			X[j]=_mm_add_epi32(Keys_rounds_X[j],plain_text[i]);
			Y[j]=_mm_add_epi32(Keys_rounds_Y[j],plain_text[i+1]);
        }

		F(X,Y,S);

    }
	union {__m128i bl128; uint64_t bl64[2];} blk_1;
	union {__m128i bl128; uint64_t bl64[2];} blk_2;
	

	//S[0] =  x0y0||x2y2
	//S[1] =  x1y1||x3y3
	//S[2] =  u0v0||u2v2
	//S[3] =  u1v1||u3v3
	blk_1.bl128=S[0];  //x0y0||x2y2
	blk_2.bl128=S[1]; //x1y1||x3y3

	uint64_t x2y2 = blk_1.bl64[1]; //x2y2
	blk_1.bl64[1]=blk_2.bl64[0]; //x1y1
	blk_2.bl64[0]=x2y2;
	
	S[0] = blk_1.bl128;
	S[1] = blk_2.bl128;

	blk_1.bl128=S[2];//u0v0||u2v2
	blk_2.bl128=S[3];//u1v1||u3v3
	uint64_t u2v2 = blk_1.bl64[1];//u2v2
	blk_1.bl64[1]=blk_2.bl64[0];//u1v1
	blk_2.bl64[0]=u2v2;
	
	S[2] = blk_1.bl128;
	S[3] = blk_2.bl128;


	for (int i = 0; i < 4; i++){
		Tag = _mm_xor_si128(S[i],Tag);

	}
	// AES_encrypt(Tag, &Tag, keys_128_k_2, 10);
	_mm_store_si128 ((__m128i*)T,Tag);
}


void H(__m128i input,__m128i * output,  __m128i key[Toeplitz_matrix][11], unsigned rounds,unsigned nblks){
    int i = 0;
    int j = 0;

	__m128i (*sched)[11] = key; // Asigna el puntero directamente
    // Ahora `sched` apunta a los mismos datos que `key`
	
    for (i=0; i<nblks; ++i)
	    output[i] =_mm_xor_si128(input, sched[nblks][0]);//4cc
	for(j=1; j<rounds; ++j)
	    for (i=0; i<nblks; ++i)
		    output[i] = _mm_aesenc_si128(output[i], sched[i][j]); //80cc
    for (i=0; i<nblks; ++i)
	    output[i] =_mm_aesenclast_si128(output[i], sched[i][j]);
}



static void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}

void F(__m128i *x,__m128i *y, __m128i *output ){
    __m128i ones_key,zkey,u,v,R[4];
    __m128i Resutlt_low[Toeplitz_matrix];
    __m128i Resutlt_high[Toeplitz_matrix];
    __m128i Resutlt[Toeplitz_matrix];


	for (size_t i = 0; i < Toeplitz_matrix; i++)
	{
		//hay un ligero detalle aca tengo x0y0||x2y2
		Resutlt_low[i] = _mm_mul_epi32(x[i],y[i]); // x0y0||y2y2
		// x1y1||x3y3
		Resutlt_high[i] = _mm_mul_epi32(_mm_srli_epi64(x[i],32),_mm_srli_epi64(y[i],32)); // x1y1||y3y3
	}
	for (size_t i = 0; i < Toeplitz_matrix; i++)
	{
		Resutlt[i] = _mm_add_epi64(Resutlt_low[i],Resutlt_high[i]);
	}
	for (size_t i = 0; i < Toeplitz_matrix; i++)
	{
		output[i] = _mm_add_epi64(output[i],Resutlt[i]);
	}

    // print_m128i_with_string("",x);
    // print_m128i_with_string("",_mm_mul_epi32(x,y));
    // print_m128i_with_string("",_mm_srli_epi64(x,32));
    // print_m128i_with_string("",_mm_srli_epi64(y,32));
    // print_m128i_with_string("",_mm_mul_epi32(_mm_srli_epi64(x,32),_mm_srli_epi64(y,32)));
}