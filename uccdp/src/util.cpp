/* src/util.cpp - Complete implementation */
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>

// 全局实例
CommProfiler g_comm_profiler;

// === [修复点] 补上这个缺失的函数实现 ===
size_t get_size_gmp(mpz_t val) {
    // mpz_sizeinbase(val, 2) 返回比特数
    // 除以 8 得到字节数，+1 是为了防止整除误差
    size_t bits = mpz_sizeinbase(val, 2);
    return (bits + 7) / 8;
}

// 【安全修复】获取安全种子：优先读取 /dev/urandom，失败时回退 OpenSSL RAND_bytes
static unsigned long secure_seed() {
    unsigned long seed = 0;
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        if (fread(&seed, sizeof(seed), 1, fp) != 1) seed = 0;
        fclose(fp);
    }
    if (seed == 0) {
        RAND_bytes((unsigned char *)&seed, sizeof(seed));
    }
    return seed;
}

// 【安全修复】进程级全局随机状态：首次调用时用安全种子初始化一次，
// 之后 generate_random / generate_strong_prime 全部复用同一状态。
// 旧实现每次调用都用 gmp_randseed_ui(state, rand()) 重新播种：
//   1) libc 的 rand() 从未被 srand() 播种，种子恒为 1，导致每次运行
//      产生完全相同的“随机”序列（实验数据不可复现为真实随机样本）；
//   2) 同一进程内每次调用都从序列头部重新开始，ZKprove / LHP_PGen
//      每次拿到的是同一个 r。
static gmp_randstate_t &util_rand_state() {
    static gmp_randstate_t state;
    static bool initialized = false;
    if (!initialized) {
        gmp_randinit_default(state);
        gmp_randseed_ui(state, secure_seed());
        initialized = true;
    }
    return state;
}

void generate_random(mpz_t res, uint64_t bit_count) {
    mpz_urandomb(res, util_rand_state(), bit_count);
}

void generate_prime(mpz_t p, uint64_t bit_count) {
    mpz_t p_temp;
    mpz_init2(p_temp, bit_count);
    mpz_set_ui(p_temp, 0);
    mpz_setbit(p_temp, bit_count - 1);

    mpz_urandomb(p, util_rand_state(), bit_count);
    mpz_ior(p, p, p_temp);
    mpz_nextprime(p, p);

    mpz_clear(p_temp);
}

// 【正确性修复】真正的强素数：p = 2*k*q + 1，其中 q 为大素因子，
// 保证 p-1 含有约 (bit_count - 65) 比特的大素因子 q。
// 旧实现直接返回普通素数（原注释自认“绕过了强素数生成”），
// 与论文中“p、q 为强素数”的表述不符。
// 注意：本函数只在 Setup 阶段被调用（不在任何计时区域内），
// 生成耗时约增加数秒，但不会影响 Commit/Verify/Solve 等计时指标。
void generate_strong_prime(mpz_t p, uint64_t bit_count) {
    // 位长过小时无法构造有意义的大素因子，退化为普通素数
    if (bit_count <= 66) {
        generate_prime(p, bit_count);
        return;
    }

    mpz_t q, k, cand;
    mpz_inits(q, k, cand, NULL);

    // 1. 生成大素因子 q：为 64 比特随机系数 k 预留空间，
    //    使 p = 2*k*q + 1 的位长能够精确等于 bit_count
    generate_prime(q, bit_count - 65);

    // 2. 反复尝试随机 k，直到 p = 2*k*q + 1 为素数且位长精确
    do {
        mpz_urandomb(k, util_rand_state(), 64);
        if (mpz_sgn(k) == 0) continue;

        mpz_mul(cand, k, q);         // cand = k*q
        mpz_mul_2exp(cand, cand, 1); // cand = 2*k*q
        mpz_add_ui(cand, cand, 1);   // p   = 2*k*q + 1
    } while (mpz_sizeinbase(cand, 2) != bit_count ||
             mpz_probab_prime_p(cand, 25) == 0);

    mpz_set(p, cand);
    mpz_clears(q, k, cand, NULL);
}

void random_group_element(mpz_t res, mpz_t N) {
    mpz_t gcd_val;
    mpz_init(gcd_val);
    size_t bits = mpz_sizeinbase(N, 2);

    do {
        generate_random(res, bits);
        mpz_mod(res, res, N);
        mpz_gcd(gcd_val, res, N);
    } while (mpz_cmp_ui(gcd_val, 1) != 0);

    mpz_clear(gcd_val);
}
