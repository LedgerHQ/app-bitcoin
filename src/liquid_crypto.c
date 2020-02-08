/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifdef HAVE_LIQUID

#include "btchip_internal.h"

static uint8_t const SECP256K1_FIELD[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f };

void cx_math_shiftr(unsigned char  *r,  unsigned int len, int n) {
  unsigned int j;
  unsigned char  ri_1, ri;
  // shift word
  j = n / 8;
  if (j) {
    len -= j;
    memmove(r+j,r,len);
    while(j) {
      *r = 0;
      j--;
      r++;
    }
  }

  //shift bit
  n = n % 8;
  if (n) {
    ri_1 = 0;
    for (j = 0; j<len; j++) {
      ri   = r[j];
      r[j] = ri>>n | ri_1;
      ri_1 = ri<<(8-n);
    }
  }
}

#if 0
bool liquid_crypto_is_quad_var(unsigned char *a) {
	unsigned char *x2 = G_io_apdu_buffer;
	unsigned char *x3 = G_io_apdu_buffer + 32;
	unsigned char *x6 = G_io_apdu_buffer + 64;
	unsigned char *x9 = G_io_apdu_buffer + 96;
	unsigned char *x11 = G_io_apdu_buffer + 128;
	unsigned char *x22 = G_io_apdu_buffer + 160;
	unsigned char *x44 = G_io_apdu_buffer + 192;
	unsigned char *x88 = G_io_apdu_buffer + 224;
	unsigned char x176[32];
	unsigned char x220[32];
	unsigned char x223[32];
	unsigned char t1[32];
	unsigned char *r = x2;
	int j;

	cx_math_multm(x2, a, a, SECP256K1_FIELD, 32);
	cx_math_multm(x2, x2, a, SECP256K1_FIELD, 32);

	cx_math_multm(x3, x2, x2, SECP256K1_FIELD, 32);
	cx_math_multm(x3, x3, a, SECP256K1_FIELD, 32);

	os_memmove(x6, x3, 32);
	for (j=0; j<3; j++) {
		cx_math_multm(x6, x6, x6, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x6, x6, x3, SECP256K1_FIELD, 32);

	os_memmove(x9, x6, 32);
	for (j=0; j<3; j++) {
		cx_math_multm(x9, x9, x9, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x9, x9, x3, SECP256K1_FIELD, 32);

	os_memmove(x11, x9, 32);
	for (j=0; j<2; j++) {
		cx_math_multm(x11, x11, x11, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x11, x11, x2, SECP256K1_FIELD, 32);

	os_memmove(x22, x11, 32);
	for (j=0; j<11; j++) {
		cx_math_multm(x22, x22, x22, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x22, x22, x11, SECP256K1_FIELD, 32);

	os_memmove(x44, x22, 32);
	for (j=0; j<22; j++) {
		cx_math_multm(x44, x44, x44, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x44, x44, x22, SECP256K1_FIELD, 32);

	os_memmove(x88, x44, 32);
	for (j=0; j<44; j++) {
		cx_math_multm(x88, x88, x88, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x88, x88, x44, SECP256K1_FIELD, 32);
    

	os_memmove(x176, x88, 32);
	for (j=0; j<88; j++) {
		cx_math_multm(x176, x176, x176, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x176, x176, x88, SECP256K1_FIELD, 32);

	os_memmove(x220, x176, 32);
	for (j=0; j<44; j++) {
		cx_math_multm(x220, x220, x220, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x220, x220, x44, SECP256K1_FIELD, 32);

	os_memmove(x223, x220, 32);
	for (j=0; j<3; j++) {
		cx_math_multm(x223, x223, x223, SECP256K1_FIELD, 32);
	}
	cx_math_multm(x223, x223, x3, SECP256K1_FIELD, 32);

	/* The final result is then assembled using a sliding window over the blocks. */

	os_memmove(t1, x223, 32);
	for (j=0; j<23; j++) {
		cx_math_multm(t1, t1, t1, SECP256K1_FIELD, 32);
	}
	cx_math_multm(t1, t1, x22, SECP256K1_FIELD, 32);
	for (j=0; j<6; j++) {
		cx_math_multm(t1, t1, t1, SECP256K1_FIELD, 32);
	}
	cx_math_multm(t1, t1, x2, SECP256K1_FIELD, 32);
	cx_math_multm(t1, t1, t1, SECP256K1_FIELD, 32);
	cx_math_multm(r, t1, t1, SECP256K1_FIELD, 32);
    
	/* Check that a square root was actually calculated */

	cx_math_multm(t1, r, r, SECP256K1_FIELD, 32);

	return (os_memcmp(t1, a, 32) == 0);
}
#endif


bool liquid_crypto_is_quad_var(unsigned char *a) {
	uint8_t p_one_shr[32];
	uint8_t res[32];

	os_memset(p_one_shr, 0, sizeof(p_one_shr));
	p_one_shr[31] = 1;
	cx_math_sub(p_one_shr, SECP256K1_FIELD, p_one_shr, 32);
	cx_math_shiftr(p_one_shr, 32, 1);
	cx_math_powm(res, a, p_one_shr, 32, SECP256K1_FIELD, 32);
	return (res[31] == 1);
}


// secp256k1 G
static uint8_t const PEDERSEN_GENERATOR[] = { 
	0x04,
  0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
  0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
 	0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
  0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
};

void liquid_crypto_pedersen_commit(unsigned char *blindingFactor, uint8_t *value64BE, unsigned char *generator, unsigned char *output) {
	uint8_t scalar[32];
	uint8_t *point1 = G_io_apdu_buffer;
	uint8_t *point2 = G_io_apdu_buffer + 65;
	os_memset(scalar, 0, 32);
	os_memmove(scalar + 24, value64BE, 8);
	os_memmove(point1, PEDERSEN_GENERATOR, 65);
	cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, point1, 65, blindingFactor, 32);
	os_memmove(point2, generator, 65);
	cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, point2, 65, scalar, 32);
	cx_ecfp_add_point(CX_CURVE_SECP256K1, point1, point1, point2, 65);
	output[0]	= 9 ^ liquid_crypto_is_quad_var(point1 + 33);
	os_memmove(output + 1, point1 + 1, 32);
}

void liquid_crypto_generator_tweak_full(unsigned char *generator, unsigned char *blindingFactor, unsigned char *output, unsigned char *tmp65) {
	uint8_t *point1 = tmp65;
	os_memmove(point1, PEDERSEN_GENERATOR, 65);
	cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, point1, 65, blindingFactor, 32);
	cx_ecfp_add_point(CX_CURVE_SECP256K1, output, generator, point1, 65);
}

void liquid_crypto_generator_compress(unsigned char *generator) {
	generator[0] = 11 ^ liquid_crypto_is_quad_var(generator + 33);
}

#if 0

const unsigned char TEST1[] = { 0x56,0xc5,0xaa,0x7c,0x2f,0xf9,0xe7,0x19,0xcf,0x28,0x7d,0xad,0x2d,0xe2,0xb1,0x02,0xca,0x4e,0x7d,0x1b,0x0e,0x21,0xa8,0x30,0x96,0x48,0xfe,0x71,0x32,0x0a,0x0f,0xa1 };
const unsigned char TEST2[] = { 0xc4,0x10,0x61,0x8e,0x98,0x79,0x7e,0xca,0x4e,0x7c,0x0a,0xed,0xd5,0xc5,0xbc,0x1e,0x43,0xe9,0xd9,0x91,0x3d,0x8f,0x8c,0x73,0x43,0xd9,0x88,0x3e,0xff,0xaa,0xbf,0xef };

const unsigned char TEST_PEDERSEN_BLIND[] = { 0x1d,0x68,0xe8,0x3e,0xa6,0xd6,0x15,0xd1,0x78,0x0a,0x82,0x00,0xee,0x02,0x0e,0xbf,0xb4,0xa8,0x54,0x89,0xba,0x6b,0x34,0x30,0xbe,0x9e,0xae,0xf8,0x09,0x59,0xc1, 0x0c };
const unsigned char TEST_PEDERSEN_GENERATOR[] = { 	
	0x04, 
	0x94,0xad,0x09,0x5e,0x9f,0x1a,0x7c,0x3b,
	0xb8,0xc7,0xe9,0x60,0x6b,0x68,0x61,0x02,
	0xd4,0xb3,0x57,0xc3,0x0f,0x9d,0xf9,0xfa,
	0x3a,0xf3,0xe3,0xfa,0x54,0x91,0xf0,0x19,

	0x56,0xc5,0xaa,0x7c,0x2f,0xf9,0xe7,0x19,
	0xcf,0x28,0x7d,0xad,0x2d,0xe2,0xb1,0x02,
	0xca,0x4e,0x7d,0x1b,0x0e,0x21,0xa8,0x30,
	0x96,0x48,0xfe,0x71,0x32,0x0a,0x0f,0xa1
};
const uint64_t TEST_PEDERSEN_VALUE = 0x42;	
const unsigned char TEST_SOURCE_GENERATOR[] = {
	0x04,
	0x0e,0x0a,0xe8,0xb7,0x27,0xb4,0x7e,0xab,
	0xc2,0x58,0x08,0x7a,0xd8,0x9c,0xcc,0x36,
	0xf1,0x02,0xe2,0x08,0x84,0xcf,0x6b,0xe9,
	0xab,0x15,0xbb,0xf7,0xca,0xa9,0x23,0xc1,

	0x90,0xb1,0x07,0x51,0x4c,0xb4,0xc3,0x56,
	0xd1,0x17,0x65,0xa7,0x55,0x7a,0x12,0x61,
	0x44,0xd8,0x5d,0xa6,0x60,0x87,0x34,0x50,
	0x2d,0x16,0xfd,0xa3,0xe4,0xa4,0x18,0x7b
};
const unsigned char TEST_GENERATOR_BLIND[] = { 0x1b,0x99,0x4a,0xed,0x58,0x3d,0x6a,0x52,0x36,0xd5,0x24,0x4a,0x68,0x8e,0xad,0x95,0x5f,0x3c,0x35,0xb5,0xc4,0x8c,0xdd,0x6c,0x11,0x32,0x3d,0xe2,0xb4,0xb4,0x59,0xcf,0x0b};

void liquid_crypto_test() {
	unsigned char output[33];
	PRINTF("LIQUID CRYPTO TEST\n");
	PRINTF("quad1 %d\n", liquid_crypto_is_quad_var(TEST1)); // 0
	PRINTF("quad2 %d\n", liquid_crypto_is_quad_var(TEST2)); // 1
	liquid_crypto_pedersen_commit(TEST_PEDERSEN_BLIND, TEST_PEDERSEN_VALUE, TEST_PEDERSEN_GENERATOR, output);
	PRINTF("Pedersen %.*H\n", 33, output); // 09944C3436B9D972864CFC89F003EF93507682F2FEC5EF0F2029A52EC0291A5FED
	liquid_crypto_generator_tweak(TEST_SOURCE_GENERATOR, TEST_GENERATOR_BLIND, output);
	PRINTF("Tweaked generator %.*H\n", 33, output); // 0B94AD095E9F1A7C3BB8C7E9606B686102D4B357C30F9DF9FA3AF3E3FA5491F019
}

#endif

#endif

