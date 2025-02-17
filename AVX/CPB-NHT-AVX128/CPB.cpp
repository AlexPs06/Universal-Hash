#include <iostream>
#include <wmmintrin.h>
#include <emmintrin.h>
#include "NHT.h"


#define ALIGN(n) __attribute__ ((aligned(n)))
#define size_message 16777216   // Tamaño del mensaje a procesar

char infoString[]= "NHT AVX128 i7-11700";  /* Each AE implementation must have a global one */
using namespace std;

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

    ALIGN(16) unsigned char tag[32 ]={ 0x00,0x01,0x02,0x03,
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
	long int iters, i, j, len;
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
	iter_list[16] =-1;
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
		

            NHT(key,pt,iter_list[i], tag);

			c = clock();
			for (j = 0; j < iters; j++) {
                NHT(key,pt,iter_list[i], tag);
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