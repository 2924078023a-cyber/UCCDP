    /* include/util.h */
    #ifndef UTIL_H
    #define UTIL_H

    #include <gmp.h>
    #include <stdint.h>
    #include <map>
    #include <string>
    #include <iostream>
    #include <iomanip>

    // Profiler 类定义
    class CommProfiler {
    public:
        std::map<std::string, size_t> traffic_log;
        
        void log(std::string label, size_t size_in_bytes) {
            traffic_log[label] += size_in_bytes;
        }

        void print_report() {
            std::cout << "\n========== Communication Overhead Report ==========\n";
            size_t total = 0;
            for (auto const& [key, val] : traffic_log) {
                std::cout << "| " << std::left << std::setw(30) << key 
                        << "| " << std::setw(10) << val << " Bytes |\n";
                total += val;
            }
            std::cout << "| TOTAL                         | " << total << " Bytes |\n";
            std::cout << "===================================================\n";
        }
    };

    extern CommProfiler g_comm_profiler;

    // === [修复点] 补上这个缺失的声明 ===
    size_t get_size_gmp(mpz_t val);

    // 原有的 GMP 工具函数声明
    void generate_random(mpz_t res, uint64_t bit_count);
    void generate_prime(mpz_t p, uint64_t bit_count);
    void generate_strong_prime(mpz_t p, uint64_t bit_count);
    void random_group_element(mpz_t res, mpz_t N);

    #endif