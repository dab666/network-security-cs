#include "crypto_dh.h"

#include "util.h"

#include <string.h>

static const uint64_t P[4] = {
	0xfffffffefffffc2fULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL,
	0xffffffffffffffffULL,
};

static int geq_p(const uint64_t a[4]) {
	for (int i = 3; i >= 0; i--) {
		if (a[i] > P[i]) {
			return 1;
		}
		if (a[i] < P[i]) {
			return 0;
		}
	}
	return 1;
}

static void sub_p(uint64_t a[4]) {
	uint64_t borrow = 0;
	for (int i = 0; i < 4; i++) {
		uint64_t bi = P[i] + borrow;
		uint64_t ai = a[i];
		a[i] = ai - bi;
		borrow = (ai < bi) ? 1 : 0;
	}
}

static void add_u64(uint64_t out[5], const uint64_t a[5], const uint64_t b[5]) {
	__uint128_t carry = 0;
	for (int i = 0; i < 5; i++) {
		__uint128_t v = (__uint128_t)a[i] + b[i] + carry;
		out[i] = (uint64_t)v;
		carry = v >> 64;
	}
}

static void add_u64_4_5(uint64_t out[5], const uint64_t a4[4], const uint64_t b5[5]) {
	__uint128_t carry = 0;
	for (int i = 0; i < 4; i++) {
		__uint128_t v = (__uint128_t)a4[i] + b5[i] + carry;
		out[i] = (uint64_t)v;
		carry = v >> 64;
	}
	out[4] = (uint64_t)(b5[4] + (uint64_t)carry);
}

static void mod_normalize(uint64_t a[4]) {
	while (geq_p(a)) {
		sub_p(a);
	}
}

static void mod_reduce(uint64_t out[4], const uint64_t t[8]) {
	uint64_t lo[4] = {t[0], t[1], t[2], t[3]};
	uint64_t hi[4] = {t[4], t[5], t[6], t[7]};

	uint64_t hi_shift[5] = {0};
	for (int i = 0; i < 4; i++) {
		uint64_t cur = hi[i];
		hi_shift[i] = cur << 32;
		if (i > 0) {
			hi_shift[i] |= hi[i - 1] >> 32;
		}
	}
	hi_shift[4] = hi[3] >> 32;

	uint64_t hi_mul[5] = {0};
	__uint128_t carry = 0;
	for (int i = 0; i < 4; i++) {
		__uint128_t v = (__uint128_t)hi[i] * 977U + carry;
		hi_mul[i] = (uint64_t)v;
		carry = v >> 64;
	}
	hi_mul[4] = (uint64_t)carry;

	uint64_t m[5] = {0};
	add_u64(m, hi_shift, hi_mul);

	uint64_t s[5] = {0};
	add_u64_4_5(s, lo, m);

	while (s[4] != 0) {
		uint64_t extra = s[4];
		s[4] = 0;

		uint64_t tmp[5] = {0};
		tmp[0] = extra * 977U;
		tmp[0] += extra << 32;
		tmp[1] = extra >> 32;

		uint64_t r[5] = {0};
		add_u64(r, s, tmp);
		memcpy(s, r, sizeof(s));
	}

	out[0] = s[0];
	out[1] = s[1];
	out[2] = s[2];
	out[3] = s[3];
	mod_normalize(out);
}

static void mod_mul(uint64_t out[4], const uint64_t a[4], const uint64_t b[4]) {
	uint64_t t[8] = {0};
	for (int i = 0; i < 4; i++) {
		__uint128_t carry = 0;
		for (int j = 0; j < 4; j++) {
			__uint128_t v = (__uint128_t)a[i] * b[j] + t[i + j] + carry;
			t[i + j] = (uint64_t)v;
			carry = v >> 64;
		}
		t[i + 4] = (uint64_t)(t[i + 4] + (uint64_t)carry);
	}
	mod_reduce(out, t);
}

static void mod_sqr(uint64_t out[4], const uint64_t a[4]) {
	mod_mul(out, a, a);
}

static void mod_pow(uint64_t out[4], const uint64_t base[4], const uint8_t exp[32]) {
	uint64_t r[4] = {1, 0, 0, 0};
	uint64_t b[4];
	memcpy(b, base, sizeof(b));

	for (int i = 0; i < 32; i++) {
		uint8_t byte = exp[i];
		for (int bit = 7; bit >= 0; bit--) {
			mod_sqr(r, r);
			if ((byte >> bit) & 1) {
				mod_mul(r, r, b);
			}
		}
	}
	memcpy(out, r, sizeof(r));
}

static void fe_from_be(uint64_t out[4], const uint8_t in[32]) {
	for (int i = 0; i < 4; i++) {
		int off = (3 - i) * 8;
		uint64_t v = 0;
		for (int j = 0; j < 8; j++) {
			v = (v << 8) | in[off + j];
		}
		out[i] = v;
	}
	mod_normalize(out);
}

static void fe_to_be(uint8_t out[32], const uint64_t in[4]) {
	for (int i = 0; i < 4; i++) {
		uint64_t v = in[3 - i];
		for (int j = 0; j < 8; j++) {
			out[i * 8 + (7 - j)] = (uint8_t)(v >> (j * 8));
		}
	}
}

void crypto_dh_pub_from_priv(uint8_t pub[32], const uint8_t priv[32]) {
	uint64_t g[4] = {2, 0, 0, 0};
	uint64_t y[4];
	mod_pow(y, g, priv);
	fe_to_be(pub, y);
}

int crypto_dh_keypair(uint8_t priv[32], uint8_t pub[32]) {
	for (;;) {
		if (util_random_bytes(priv, 32) != 0) {
			return -1;
		}
		int all_zero = 1;
		for (int i = 0; i < 32; i++) {
			if (priv[i] != 0) {
				all_zero = 0;
				break;
			}
		}
		if (!all_zero) {
			break;
		}
	}

	crypto_dh_pub_from_priv(pub, priv);
	return 0;
}

int crypto_dh_shared(uint8_t out_shared[32], const uint8_t priv[32], const uint8_t peer_pub[32]) {
	uint64_t x[4];
	fe_from_be(x, peer_pub);
	uint64_t s[4];
	mod_pow(s, x, priv);
	fe_to_be(out_shared, s);
	return 0;
}
