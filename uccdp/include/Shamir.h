/* include/Shamir.h - 纯大数重构版 */
#ifndef __Shamir__
#define __Shamir__

#include <gmp.h>
#include <vector> // [关键修复] 必须引入 vector，否则编译不认识 std::vector

void safe_mod(mpz_t res, const mpz_t a, const mpz_t m);
void compute_lagrange_basis_at_zero(mpz_t L, int target_x, const std::vector<int>& point_x_set, mpz_t prime);
void generate_shares(int n, int t, mpz_t secret, mpz_t prime, mpz_t* shares);
void recover_secret(int t, const std::vector<int>& x_coords, mpz_t* y_shares, mpz_t prime, mpz_t recover_secret);
#endif