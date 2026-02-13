#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include "EliHASH.h"

#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>


#include <ctime>
#include <iomanip>
#include <string>
#include <sstream>

#define tag_size 16



void write_tag_hex(std::ofstream& file, const uint8_t* tag, size_t len = 64) {
    file << "Tag: ";
    file << std::hex << std::setfill('0');

    for (size_t i = 0; i < len; i++) {
        file << std::setw(2)
             << static_cast<unsigned>(tag[i]);
    }

    file << std::dec << "\n";
}



std::string get_cpu_name() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo.is_open()) {
        return "Unknown CPU";
    }

    std::string line;
    while (std::getline(cpuinfo, line)) {
        // x86
        if (line.find("model name") != std::string::npos) {
            return line.substr(line.find(":") + 2);
        }

        // ARM (por si portas a AArch64 en Linux)
        if (line.find("Hardware") != std::string::npos) {
            return line.substr(line.find(":") + 2);
        }
    }

    return "Unknown CPU";
}

std::string get_compiler_info() {
#ifdef __clang__
    return "Clang C++" +
           std::to_string(__clang_major__) + "." +
           std::to_string(__clang_minor__) + "." +
           std::to_string(__clang_patchlevel__);
#elif defined(__GNUC__)
    return "GCC " + std::to_string(__GNUC__);
#else
    return "Unknown Compiler";
#endif
}


std::string get_cpp_standard() {
#if __cplusplus >= 202002L
    return "C++20";
#elif __cplusplus >= 201703L
    return "C++17";
#elif __cplusplus >= 201402L
    return "C++14";
#else
    return "Pre-C++14";
#endif
}

// Compiler barrier to prevent optimization
static inline void clobber_memory() {
    asm volatile("" : : : "memory");
}

std::string get_arch_info() {
    std::string arch;

#if defined(__aarch64__)
    arch = "ARM64";
#else
    arch = "Unknown Arch";
#endif

#if defined(__ARM_NEON)
    arch += " + NEON";
#endif

#if defined(__ARM_FEATURE_CRYPTO)
    arch += " + Crypto";
#endif

    return arch;
}

std::string get_datetime() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&t);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}



int main(int argc, char **argv) {

    if ((argc < 2) || (argc > 3)) {
		printf("Usage: ./test [base_frequency_GHz] [output_filename]\n");
		return 0;
	} 
    
    double CPU_FREQ = std::atof(argv[1]) * 1.e9; // Apple M1 ≈ 3.2 GHz
    constexpr int ITER = 100000;
    std::ofstream file(argv[2]);

    file << "EliHash-AVX128\n";
    file << get_cpu_name() << "\n";
    file << get_compiler_info() << " (" << get_cpp_standard() << ")\n";
    file << get_arch_info() << "\n";
    file << "Run " << get_datetime() << "\n\n";


    #if defined(__aarch64__) || defined(__arm__)
        file << "Architecture: ARM\n";

    #if defined(__ARM_FEATURE_CRYPTO)
        file << "ARM Crypto Extensions: ENABLED\n";
    #else
        file << "ARM Crypto Extensions: DISABLED\n";
    #endif

    #elif defined(__x86_64__) || defined(__i386__)
        file << "Architecture: x86\n";

        #if defined(__AVX2__)
            file << "AVX2: ENABLED\n";
        #else
            file << "AVX2: DISABLED\n";
        #endif

        #if defined(__AES__)
            file << "AES-NI: ENABLED\n";
        #else
            file << "AES-NI: DISABLED\n";
        #endif

        #if defined(__PCLMUL__)
            file << "PCLMULQDQ: ENABLED\n";
        #else
            file << "PCLMULQDQ: DISABLED\n";
        #endif
    #endif

    // Dummy round keys
    alignas (16) uint8_t key[] = "abcdefghijklmnop";    
    __m128i roundKeys[11];

    uint8_t output[tag_size] = {};
    

    std::vector<size_t> sizes = {
        256, 512, 1024, 2048, 4096, 8192, 16384, 32768
    };

    for (size_t size : sizes) {
        std::vector<uint8_t> msg(size);
        for (size_t i = 0; i < size; i++) {
            msg[i] = static_cast<uint8_t>(i);
            // printf("%i\n",msg[i]);
        }
        
        auto start = std::chrono::steady_clock::now();
        clobber_memory();

        AES_128_Key_Expansion(key, roundKeys);
        __m128i *obtained_keys = NULL;
        size_t num_blocks = size / 16;
        size_t bytes = num_blocks * sizeof(__m128i);
        if (posix_memalign((void**)&obtained_keys, 16, bytes) != 0) {
            perror("posix_memalign");
            exit(EXIT_FAILURE);
        }

        for (int it = 0; it < ITER; it++) {
            generate_keys(roundKeys, size, obtained_keys);
            asm volatile("" :: "r"(output[0]) : "memory");
            
        }


        auto end = std::chrono::steady_clock::now();

        double seconds =
            std::chrono::duration<double>(end - start).count();

        double total_bytes = double(size) * ITER;
        double cycles = seconds * CPU_FREQ;
        double cpb = cycles / total_bytes;

        // file << size << " -- "
        //      << seconds << " s  ("
        //      << cpb << " cpb) Key generation\n";


        clobber_memory();

        start = std::chrono::steady_clock::now();

        for (int it = 0; it < ITER; it++) {
            EliHASH(
                msg.data(),
                output,
                roundKeys,
                size
            );

            // Make output observable
            asm volatile("" :: "r"(output[0]) : "memory");
        }

        end = std::chrono::steady_clock::now();

        seconds =
            std::chrono::duration<double>(end - start).count();

        total_bytes = double(size) * ITER;
        cycles = seconds * CPU_FREQ;
        cpb = cycles / total_bytes;

        file << size << " -- "
             << seconds << " s  ("
             << cpb << " cpb) Para-Hash\n";
        write_tag_hex(file, output,tag_size);

        free(obtained_keys);
    }

    file.close();
    std::cout << "Benchmark completed.\n";
    return 0;
}
