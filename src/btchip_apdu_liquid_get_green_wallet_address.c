/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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
#include "btchip_apdu_constants.h"

#ifndef HAVE_LIQUID_TEST

static uint8_t const GA_ROOT_PUBKEY[] = {
  0x04,
  0xc4,0x08,0xc3,0xbb,0x8a,0x3d,0x52,0x61,0x03,0xfb,0x93,0x24,0x6f,0x54,0x89,0x7b,0xdd,0x99,0x79,0x04,0xd3,0xe1,0x82,0x95,0xb4,0x9a,0x26,0x96,0x5c,0xb4,0x1b,0x7f,
  0x6c,0xa1,0xec,0x19,0x09,0xbb,0xe2,0x11,0x78,0x9d,0xfc,0xcc,0x4e,0xe0,0x2c,0x37,0xc0,0xac,0x25,0x27,0x20,0x99,0x0c,0x3b,0x02,0x4f,0x38,0xae,0xc2,0xb5,0xfb,0x2a
};

static uint8_t const GA_ROOT_CHAINCODE[] = {
  0x02,0x72,0x1c,0xc5,0x09,0xaa,0x0c,0x2f,0x4a,0x90,0x62,0x8e,0x9d,0xa0,0x39,0x1b,0x19,0x6a,0xbe,0xab,0xc6,0x39,0x3e,0xd4,0x78,0x9d,0xd6,0x22,0x2c,0x43,0xc4,0x89
};

#else

static uint8_t const GA_ROOT_PUBKEY[] = {
  0x04,
  0x63,0x07,0xe5,0x60,0x07,0x2e,0xd6,0xce,0x0a,0xa5,0x46,0x55,0x34,0xfb,0x5c,0x25,0x8a,0x2c,0xcf,0xbc,0x25,0x7f,0x36,0x9e,0x8e,0x7a,0x18,0x1b,0x16,0xd8,0x97,0xb3,
  0x06,0x5d,0xd3,0x6d,0x36,0x83,0x54,0xa0,0xb3,0x29,0xd4,0xa5,0xb2,0xc5,0x02,0x09,0xf9,0x38,0x99,0xf3,0x3c,0xdb,0xeb,0x17,0x70,0xa0,0x5a,0x03,0xa1,0x07,0x45,0x8f  
};

static uint8_t const GA_ROOT_CHAINCODE[] = {
  0xb6,0x0b,0xef,0xcc,0x61,0x9b,0xb1,0xc2,0x12,0x73,0x27,0x70,0xfe,0x18,0x1f,0x2f,0x1a,0xa8,0x24,0xab,0x89,0xf8,0xaa,0xb4,0x9f,0x2e,0x13,0xe3,0xa5,0x6f,0x0f,0x04
};


#endif

static uint8_t const GA_MASTER_KEYPATH[] = {
	0x01, 0x80, 0x00, 0x47, 0x41
};

static uint8_t const GA_KEY[] = {
	'G','r','e','e','n','A','d','d','r','e','s','s','.','i','t',' ','H','D',' ','w','a','l','l','e','t',' ','p','a','t','h'
};

#define P1_NO_DISPLAY 0x00
#define P1_DISPLAY 0x01

#define P2_CSV 0x00
#define P2_P2WSH 0x01

#define OFFSET_TMP_SERVICEKEY_PUB 64
#define OFFSET_TMP_SERVICEKEY_CHAINCODE 64 + 65
#define OFFSET_TMP_SCRIPT 120

#define INIT_SERVICEPATH_NO_SUBACCOUNT 1
#define INIT_SERVICEPATH_SUBACCOUNT 3

#define HARDENED_PATH 0x80000000

#define OP_DEPTH 0x74
#define OP_1SUB 0x8c
#define OP_IF 0x63
#define OP_CHECKSIGVERIFY 0xad
#define OP_ELSE 0x67
#define OP_CHECKSEQUENCEVERIFY 0xb2
#define OP_DROP 0x75
#define OP_ENDIF 0x68
#define OP_CHECKSIG 0xac
#define OP_CHECKMULTISIG 0xae
#define OP_1 0x51
#define OP_EQUAL 0x87
#define OP_HASH160 0xa9

#define WITNESS_VERSION 0
#define SHA256_LENGTH 0x20
#define HASH160_LENGTH 0x14

/* From libwally */
static size_t scriptint_get_length(uint32_t v)
{
    size_t len = 0;
    unsigned char last = 0;

    while (v) {
        last = v & 0xff;
        len += 1;
        v >>= 8;
    }
    return len + (last & 0x80 ? 1 : 0);
}

/* From libwally */
static size_t scriptint_to_bytes(uint32_t v, unsigned char *bytes_out)
{
    size_t len = 0;
    unsigned char last = 0;

    while (v) {
        last = v & 0xff;
        *bytes_out++ = last;
        len += 1;
        v >>= 8;
    }
    if (last & 0x80) {
        *bytes_out = 0;
        ++len;
    } 
    return len;
}

void derive_bip32_public(uint8_t *pubkey, uint8_t *chaincode, uint32_t index) {
	uint8_t tmp[65];
	uint8_t tmp2[65];
	os_memmove(tmp, pubkey, 65);
	btchip_compress_public_key_value(tmp);
	U4BE_ENCODE(tmp, 33, index);
	cx_hmac_sha512(chaincode, 32, tmp, 33 + 4, tmp, 64);
	liquid_crypto_generator_tweak_full(pubkey, tmp, pubkey, tmp2);
	os_memmove(chaincode, tmp + 32, 32);
}

unsigned short btchip_apdu_liquid_get_green_wallet_address() {
	uint8_t masterBlindingKey[32], tmp[33];
	cx_ecfp_private_key_t privateKey;
	cx_ecfp_public_key_t publicKey;	
	uint8_t p1 = G_io_apdu_buffer[ISO_OFFSET_P1], p2 = G_io_apdu_buffer[ISO_OFFSET_P2];
	uint32_t subaccount, branch, pointer, csvBlocks, i;
	size_t outputLen;

	switch(p1) {
		case P1_NO_DISPLAY:
		case P1_DISPLAY:
			break;
		default:
			 return BTCHIP_SW_INCORRECT_P1_P2;
	}

	switch(p2) {
		case P2_CSV:
		case P2_P2WSH:
			break;
		default:
			return BTCHIP_SW_INCORRECT_P1_P2;
	}

	if (G_io_apdu_buffer[ISO_OFFSET_LC] < 4 + 4 + 4 + 4) {
		return BTCHIP_SW_INCORRECT_LENGTH;
	}

	if (!os_global_pin_is_validated()) {
		return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
	}

	subaccount = U4BE(G_io_apdu_buffer, ISO_OFFSET_CDATA);
	branch = U4BE(G_io_apdu_buffer, ISO_OFFSET_CDATA + 4);
	pointer = U4BE(G_io_apdu_buffer, ISO_OFFSET_CDATA + 8);
	csvBlocks = U4BE(G_io_apdu_buffer, ISO_OFFSET_CDATA + 12);

 	// Derive remote path

 	btchip_private_derive_keypair((uint8_t*)PIC(GA_MASTER_KEYPATH), 1, G_io_apdu_buffer);
 	btchip_compress_public_key_value(btchip_public_key_D.W);
 	os_memmove(G_io_apdu_buffer + 32, btchip_public_key_D.W, 33);
 	cx_hmac_sha512(GA_KEY, sizeof(GA_KEY), G_io_apdu_buffer, 32 + 33, G_io_apdu_buffer, 64);

 	// Get service key

 	os_memmove(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB, GA_ROOT_PUBKEY, 65);
 	os_memmove(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_CHAINCODE, GA_ROOT_CHAINCODE, 32);
 	derive_bip32_public(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB, G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_CHAINCODE, 
 		(subaccount == 0 ? INIT_SERVICEPATH_NO_SUBACCOUNT : INIT_SERVICEPATH_SUBACCOUNT));
 	for (i=0; i<64; i+=2) {
		derive_bip32_public(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB, G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_CHAINCODE, 
			U2BE(G_io_apdu_buffer, i)); 		
 	}
	if (subaccount != 0) {
		derive_bip32_public(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB, G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_CHAINCODE, 
			subaccount); 		
	}
	derive_bip32_public(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB, G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_CHAINCODE, 
			pointer); 		
	btchip_compress_public_key_value(G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB);
	os_memmove(G_io_apdu_buffer, G_io_apdu_buffer + OFFSET_TMP_SERVICEKEY_PUB, 33);

	// Get user key

	tmp[0] = (subaccount == 0 ? 2 : 4);
	i = 1;
	if (subaccount != 0) {
		U4BE_ENCODE(tmp, i, HARDENED_PATH | INIT_SERVICEPATH_SUBACCOUNT);
		U4BE_ENCODE(tmp, i + 4, HARDENED_PATH | subaccount);
		i += 4 + 4;
	}
	U4BE_ENCODE(tmp, i, branch);
	U4BE_ENCODE(tmp, i + 4, pointer);

	btchip_private_derive_keypair(tmp, 1, NULL);
	btchip_compress_public_key_value(btchip_public_key_D.W);

	// Build script 

	i = OFFSET_TMP_SCRIPT;
	if (p2 == P2_CSV) {
		size_t csv_len = scriptint_get_length(csvBlocks);
		G_io_apdu_buffer[i++] = OP_DEPTH;
		G_io_apdu_buffer[i++] = OP_1SUB;
		G_io_apdu_buffer[i++] = OP_IF;
		G_io_apdu_buffer[i++] = 33;
		os_memmove(G_io_apdu_buffer + i, G_io_apdu_buffer, 33);
		i += 33;
		G_io_apdu_buffer[i++] = OP_CHECKSIGVERIFY;
		G_io_apdu_buffer[i++] = OP_ELSE;
		G_io_apdu_buffer[i++] = csv_len;
		i += scriptint_to_bytes(csvBlocks, G_io_apdu_buffer + i);
		G_io_apdu_buffer[i++] = OP_CHECKSEQUENCEVERIFY;
		G_io_apdu_buffer[i++] = OP_DROP;
		G_io_apdu_buffer[i++] = OP_ENDIF;
		G_io_apdu_buffer[i++] = 33;
		os_memmove(G_io_apdu_buffer + i, btchip_public_key_D.W, 33);
		i += 33;
		G_io_apdu_buffer[i++] = OP_CHECKSIG;
	}
	else {
		G_io_apdu_buffer[i++] = OP_1 + 1;
		G_io_apdu_buffer[i++] = 33;
		os_memmove(G_io_apdu_buffer + i, G_io_apdu_buffer, 33);
		i += 33;
		G_io_apdu_buffer[i++] = 33;
		os_memmove(G_io_apdu_buffer + i, btchip_public_key_D.W, 33);
		i += 33;
		G_io_apdu_buffer[i++] = OP_1 + 1;
		G_io_apdu_buffer[i++] = OP_CHECKMULTISIG;
	}

	// Compute the witness program and scriptPubKey

	G_io_apdu_buffer[0] = WITNESS_VERSION;
	G_io_apdu_buffer[1] = SHA256_LENGTH;
	cx_hash_sha256(G_io_apdu_buffer + OFFSET_TMP_SCRIPT, i - OFFSET_TMP_SCRIPT, G_io_apdu_buffer + 2, 32);
	btchip_public_key_hash160(G_io_apdu_buffer, 2 + SHA256_LENGTH, tmp);

	// Compute the blinding key

	btchip_derive_master_blinding_key(masterBlindingKey);

	G_io_apdu_buffer[0] = OP_HASH160;
	G_io_apdu_buffer[1] = HASH160_LENGTH;
	os_memmove(G_io_apdu_buffer + 2, tmp, HASH160_LENGTH);
	G_io_apdu_buffer[2 + HASH160_LENGTH] = OP_EQUAL;

 	cx_hmac_sha256(masterBlindingKey, sizeof(masterBlindingKey), 
 		G_io_apdu_buffer, 
 		2 + HASH160_LENGTH + 1, 
		masterBlindingKey, sizeof(masterBlindingKey));

 	// Compute the confidential address

 	i = OFFSET_TMP_SCRIPT;
 	G_io_apdu_buffer[i++] = COIN_BLINDED_VERSION;
 	G_io_apdu_buffer[i++] = COIN_P2SH_VERSION;
	cx_ecdsa_init_private_key(BTCHIP_CURVE, masterBlindingKey, 32, &privateKey);
	cx_ecfp_generate_pair(BTCHIP_CURVE, &publicKey, &privateKey, 1);
	os_memset(&privateKey, 0, sizeof(privateKey));
	btchip_compress_public_key_value(publicKey.W);
	os_memmove(G_io_apdu_buffer + i, publicKey.W, 33);
	i += 33;
	os_memmove(G_io_apdu_buffer + i, tmp, HASH160_LENGTH);
	i += HASH160_LENGTH;

	// Add checksum
	cx_hash_sha256(G_io_apdu_buffer + OFFSET_TMP_SCRIPT, i - OFFSET_TMP_SCRIPT, tmp, sizeof(tmp));
	cx_hash_sha256(tmp, 32, tmp, sizeof(tmp));
	os_memmove(G_io_apdu_buffer + i, tmp, 4);
	i += 4;

	outputLen = OFFSET_TMP_SCRIPT;
	btchip_encode_base58(G_io_apdu_buffer + OFFSET_TMP_SCRIPT, i - OFFSET_TMP_SCRIPT, G_io_apdu_buffer, &outputLen);	
	G_io_apdu_buffer[outputLen] = '\0';
	
	btchip_context_D.outLength = outputLen; 	

	if (p1 == P1_DISPLAY) {
		btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
		btchip_bagl_liquid_display_green_address();
	}

	return BTCHIP_SW_OK;
}

#endif
