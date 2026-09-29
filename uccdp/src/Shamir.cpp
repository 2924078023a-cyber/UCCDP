#include "Shamir.h"
#include "util.h"

void safe_mod(mpz_t res, const mpz_t a, const mpz_t m) {
    mpz_mod(res, a, m);
    if (mpz_sgn(res) < 0) mpz_add(res, res, m);
}

void compute_lagrange_basis_at_zero(mpz_t L, int target_x, const std::vector<int>& point_x_set, mpz_t prime) {
    mpz_set_ui(L, 1);
    mpz_t num, den, inv_den;
    mpz_inits(num, den, inv_den, NULL);

    for (size_t k = 0; k < point_x_set.size(); k++) {
        int j = point_x_set[k];
        if (j != target_x) {
            mpz_set_si(num, -j);
            safe_mod(num, num, prime);

            mpz_set_si(den, target_x - j);
            safe_mod(den, den, prime);

            mpz_invert(inv_den, den, prime);

            mpz_mul(L, L, num);
            mpz_mod(L, L, prime);

            mpz_mul(L, L, inv_den);
            mpz_mod(L, L, prime);
        }
    }
    mpz_clears(num, den, inv_den, NULL);
}

void generate_shares(int n, int t, mpz_t secret, mpz_t prime, mpz_t* shares) {
    // 采用 0-based 数组索引，但是 X 坐标是 i+1
    for (int i = 0; i < t - 1; i++) {
        generate_random(shares[i], 256); 
        mpz_mod(shares[i], shares[i], prime);
    }

    mpz_t sum, L_j, L_i, L_i_inv, temp;
    mpz_inits(sum, L_j, L_i, L_i_inv, temp, NULL);

    for (int i = t - 1; i < n; i++) {
        int current_x = i + 1;
        std::vector<int> point_x_set;
        for (int k = 0; k < t - 1; k++) point_x_set.push_back(k + 1);
        point_x_set.push_back(current_x);

        mpz_set_ui(sum, 0);

        for (int j = 0; j < t - 1; j++) {
            compute_lagrange_basis_at_zero(L_j, j + 1, point_x_set, prime);
            mpz_mul(temp, shares[j], L_j);
            mpz_mod(temp, temp, prime);
            mpz_add(sum, sum, temp);
            mpz_mod(sum, sum, prime);
        }

        compute_lagrange_basis_at_zero(L_i, current_x, point_x_set, prime);
        mpz_invert(L_i_inv, L_i, prime);

        mpz_sub(temp, secret, sum);
        safe_mod(temp, temp, prime);
        mpz_mul(shares[i], temp, L_i_inv);
        mpz_mod(shares[i], shares[i], prime);
    }
    mpz_clears(sum, L_j, L_i, L_i_inv, temp, NULL);
}

void recover_secret(int t, const std::vector<int>& x_coords, mpz_t* y_shares, mpz_t prime, mpz_t recover_secret) {
    mpz_set_ui(recover_secret, 0);
    mpz_t L_i, term;
    mpz_inits(L_i, term, NULL);

    // 【致命 Bug 修复】原代码未把点推入集合，这里直接接收包含有效 x 坐标的 vector
    for (int k = 0; k < t; k++) {
        int current_x = x_coords[k];
        compute_lagrange_basis_at_zero(L_i, current_x, x_coords, prime);
        
        mpz_mul(term, y_shares[k], L_i);
        mpz_mod(term, term, prime);

        mpz_add(recover_secret, recover_secret, term);
        mpz_mod(recover_secret, recover_secret, prime);
    }
    mpz_clears(L_i, term, NULL);
}