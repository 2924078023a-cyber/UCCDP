/* include/lhp.h */
#ifndef LHP_H
#define LHP_H

#include <gmp.h>

// 合并 LHP_param_t 定义
struct LHP_param_t {
    mpz_t N;
    mpz_t N2; // 新增：保存 N^2 以加速计算并统一模空间
    mpz_t g;
    mpz_t h;
    mpz_t T; // 恢复为 mpz_t，解决 invalid conversion 报错

    LHP_param_t();
    ~LHP_param_t();
};

// 合并 LHP_Puzzle 定义
struct LHP_Puzzle {
    mpz_t u;
    mpz_t v;

    LHP_Puzzle();
    ~LHP_Puzzle();
};

// 函数声明
void LHP_PSetup(LHP_param_t& pp, int lambda, unsigned long T_val);
void LHP_PGen(LHP_Puzzle& Z, LHP_param_t& pp, mpz_t s);
void LHP_PSolve(mpz_t s, LHP_param_t& pp, LHP_Puzzle& Z);

#endif