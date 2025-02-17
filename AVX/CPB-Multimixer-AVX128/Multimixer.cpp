#include <iostream>
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>

#define ALIGN(n) __attribute__ ((aligned(n)))
#define pipeline 1
#define size_message 16777216   // Tamaño del mensaje a procesar


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

using namespace std;

static void H(__m128i * nonce,  __m128i *key, unsigned rounds,unsigned nblks);
static void I(__m128i * nonce,  __m128i  key, unsigned rounds,unsigned nblks);
static void Multimixer(unsigned char *K_1, unsigned char *K_2, unsigned char *M, int size, unsigned char *T);
static void AES_128_Key_Expansion(const unsigned char *userkey, void *key);
static inline void AES_encrypt(__m128i tmp, __m128i *out,__m128i *key, unsigned rounds);
static void imprimiArreglo(int tam, unsigned char *in );
static void F(__m128i x,__m128i y, __m128i output[4] );

// int main(){

//     ALIGN(64) unsigned char plaintext[128]=  {
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 
                                             
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
//                                              0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 

//                                             };
//     ALIGN(16) unsigned char tag[16 ]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
//     ALIGN(16) unsigned char K_1[16 ]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
//     ALIGN(16) unsigned char K_2[16 ]={ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

//     ELIMAC(K_1, K_2, plaintext,  128, tag);

//     printf("\n");
//     imprimiArreglo(16, tag);11
//     return 0;
// }


 char infoString[]= "Multimixer AVX128";  /* Each AE implementation must have a global one */

#ifndef MAX_ITER
#define MAX_ITER 16384
#endif

	ALIGN(16) unsigned char pt[size_message] = {0};

int main(int argc, char **argv)
{
	/* Allocate locals */
	ALIGN(16) unsigned char key[16]={ 0x00,0x01,0x02,0x03,
                                       0x04,0x05,0x06,0x07,
                                       0x08,0x09,0x0a,0x0b,
                                       0x0c,0x0d,0x0e,0x0f};
    ALIGN(16) unsigned char key_2[16]={ 0x00,0x01,0x02,0x03,
                                       0x04,0x05,0x06,0x07,
                                       0x08,0x09,0x0a,0x0b,
                                       0x0c,0x0d,0x0e,0x0f};

     ALIGN(16) unsigned char tag[16 ]={ 0x00,0x01,0x02,0x03,
                                       0x04,0x05,0x06,0x07,
                                       0x08,0x09,0x0a,0x0b,
                                       0x0c,0x0d,0x0e,0x0f};
    ALIGN(16) unsigned char nonce[16 ]={ 0x00,0x01,0x02,0x03,
                                       0x04,0x05,0x06,0x07,
                                       0x08,0x09,0x0a,0x0b,
                                       0x0c,0x0d,0x0e,0x0f};
	char outbuf[MAX_ITER*15+1024];
	int iter_list[2048]; /* Populate w/ test lengths, -1 terminated */
	char *outp = outbuf;
	int iters, i, j, len;
	double Hz,sec;
	double ipi=0, tmpd;
	clock_t c;
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

    outp += sprintf(outp, "- Run %s\n\n",str_time);

	// outp += sprintf(outp, "Context: %d bytes\n");
    
	printf("Starting run...\n");fflush(stdout);


	/*
	 * Get time for key setup
	 */
	// iters = (int)(Hz/520);
	// do {
	
	// 	c = clock();
	// 	for (j = 0; j < iters; j++) {

	// 	}
	// 	c = clock() - c;
	// 	sec = c/(double)CLOCKS_PER_SEC;
	// 	tmpd = (sec * Hz) / (iters);
		
	// 	if ((sec < 1.2)||(sec > 1.3))
	// 		iters = (int)(iters * 5.0/(4.0 * sec));
	// 	printf("%f\n", sec);
	// } while ((sec < 1.2) || (sec > 1.3));

	
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
		

            Multimixer(key, key_2, pt,iter_list[i], tag);

			c = clock();
			for (j = 0; j < iters; j++) {
                Multimixer(key, key_2, pt,iter_list[i], tag);
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


static __m128i plain_text[size_message]; 


void Multimixer(unsigned char *K_1, unsigned char *K_2, unsigned char *M, int size, unsigned char *T){

    int m_blocks = 0;
    if (size%16==0)
        m_blocks=(size/16);
    else
        m_blocks=(size/16) + 1;


	for (uint64_t i = 0; i < m_blocks; i++)
	{
		plain_text[i] = _mm_load_si128((__m128i*) M+(i));
	}

    __m128i nonce;
    __m128i X;
    __m128i Y;
    __m128i nonce_temp[1];
    __m128i Tag;
    __m128i S[4];
    __m128i keys_128[11];
    __m128i keys_128_k_2[11];
    __m128i keys_0 = _mm_setzero_si128();
    __m128i sum_nonce= _mm_set_epi32(0,0,0,1);

    for (int i = 0; i < 4; i++){
		S[i] = _mm_setzero_si128();
	}
	
    Tag=_mm_setzero_si128();
	X = _mm_setzero_si128();
	Y = _mm_setzero_si128();
    AES_128_Key_Expansion(K_1, keys_128);
    AES_128_Key_Expansion(K_2, keys_128_k_2);

    nonce = _mm_set_epi64x(0,0);
    size_t i=0;
    for (i = 0; i < m_blocks; i=i+2){

        nonce_temp[0]=nonce; 
        
        H(nonce_temp,  keys_128, 8, pipeline);
        nonce=_mm_add_epi64(nonce, sum_nonce);
		X=_mm_xor_si128(plain_text[i],nonce_temp[0]);


        nonce=_mm_add_epi64(nonce, sum_nonce);
		nonce_temp[0]=nonce; 
		H(nonce_temp,  keys_128, 8, pipeline);
		Y=_mm_xor_si128(plain_text[i+1],nonce_temp[0]);


		F(X,Y,S);

        nonce=_mm_add_epi64(nonce, sum_nonce);

    }

	
	// Tag = _mm_xor_si128(S[0],Tag);
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




void H(__m128i * nonce,  __m128i *key, unsigned rounds,unsigned nblks){
    int i = 0;
    int j = 0;
	const __m128i *sched = ((__m128i *)(key));
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm_xor_si128(nonce[i], sched[0]);//4cc
	for(j=1; j<rounds; ++j)
	    for (i=0; i<nblks; ++i)
		    nonce[i] = _mm_aesenc_si128(nonce[i], sched[j]); //80cc
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm_aesenclast_si128(nonce[i], sched[j]);
}

void I(__m128i * nonce,  __m128i  key, unsigned rounds,unsigned nblks){
    int i = 0;
    int j = 0;
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm_xor_si128(nonce[i], key);//4cc
	for(j=1; j<rounds; ++j)
	    for (i=0; i<nblks; ++i)
		    nonce[i] = _mm_aesenc_si128(nonce[i], key); //80cc
    for (i=0; i<nblks; ++i)
	    nonce[i] =_mm_aesenclast_si128(nonce[i], key);
}


static inline void AES_encrypt(__m128i tmp, __m128i *out,__m128i *key, unsigned rounds){
	int j;
	tmp = _mm_xor_si128 (tmp,key[0]);
	for (j=1; j<rounds; j++)  tmp = _mm_aesenc_si128 (tmp,key[j]);
	tmp = _mm_aesenclast_si128 (tmp,key[j]);
	_mm_store_si128 ((__m128i*)out,tmp);
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



void imprimiArreglo(int tam, unsigned char *in )
{

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
    }
    printf("\n" );

}


///**********************************/
void print_m128i_with_string(char* string,__m128i data) {
    unsigned char *pointer = (unsigned char*)&data;
    int i;
    printf("%-40s[0x",string);
    for (i=0; i<16; i++)
        printf("%02x",pointer[i]);
    printf("]\n");
}


void F(__m128i x,__m128i y, __m128i output[4] ){
    __m128i u,v,R[4], checksum_x,checksum_y;


	for (size_t i = 0; i < 4; i++)
	{
    	checksum_x = _mm_add_epi32(checksum_x, _mm_shuffle_epi32(x, _MM_SHUFFLE((0+i)%4, (1+i)%4, (2+i)%4, (3+i)%4))); 
    	checksum_y = _mm_add_epi32(checksum_y, _mm_shuffle_epi32(y, _MM_SHUFFLE((0+i)%4, (1+i)%4, (2+i)%4, (3+i)%4))); 
	}
	

    u = _mm_sub_epi32(checksum_x,_mm_shuffle_epi32(x,_MM_SHUFFLE(3, 0, 1, 2))); 
    v = _mm_sub_epi32(checksum_y,_mm_shuffle_epi32(y,_MM_SHUFFLE(3, 0, 1, 2)));  

	

    R[0] = _mm_mul_epi32(x,y);
    R[1] = _mm_mul_epi32(_mm_srli_epi64(x,32),_mm_srli_epi64(y,32));
    R[2] = _mm_mul_epi32(u,v);
	R[3] = _mm_mul_epi32(_mm_srli_epi64(u,32),_mm_srli_epi64(v,32));

	output[0] = _mm_xor_si128(R[0],output[0]);
	output[1] = _mm_xor_si128(R[1],output[1]);
	output[2] = _mm_xor_si128(R[2],output[2]);
	output[3] = _mm_xor_si128(R[3],output[3]);

    // print_m128i_with_string("",x);
    // print_m128i_with_string("",_mm_mul_epi32(x,y));
    // print_m128i_with_string("",_mm_srli_epi64(x,32));
    // print_m128i_with_string("",_mm_srli_epi64(y,32));
    // print_m128i_with_string("",_mm_mul_epi32(_mm_srli_epi64(x,32),_mm_srli_epi64(y,32)));
}