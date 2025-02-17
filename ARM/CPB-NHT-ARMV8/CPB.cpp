#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <arm_neon.h>
#include <stdint.h>
#include <stdio.h>
#include <cstring>
#include "AES-intrinsics.h"

#define ALIGN(n) __attribute__ ((aligned(n)))
#define size_message 16777216   // Tamaño del mensaje a procesar
#define Nr 10   // Número de rondas para AES-128



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
	ALIGN(16) uint8_t tag[32];
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

            NHT(plaintext,  tag, key, len);

			c = clock();
			for (j = 0; j < iters; j++) {
                NHT(plaintext,  tag, key, len);

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







