/* Vendored from poc-crypto/gmssljs (guanzhi/GmSSL-JS, Apache-2.0).
   Includes SM3 multi-block fixes. ESM port removes ineffective local-variable deletes. */
// ===== sm3.js =====
/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


function sm3_memcpy(dst, dst_offset, src, src_offset, len) {
	while (len--) {
		dst[dst_offset++] = src[src_offset++];
	}
}

function sm3_memset(dst, offset, value, len) {
	while (len--) {
		dst[offset++] = value;
	}
}

function SM3_GETU32(data, offset) {
	return ((data[offset] << 24)
		| (data[offset + 1] << 16)
		| (data[offset + 2] << 8)
		| data[offset + 3]) >>> 0;
}

function SM3_PUTU32(data, offset, value) {
	data[offset + 3] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset + 2] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset + 1] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset] = (value & 0xff) >>> 0;
}

const SM3_DIGEST_LENGTH = 32;
const SM3_BLOCK_SIZE = 64;
const SM3_HMAC_SIZE = SM3_DIGEST_LENGTH;

function sm3_ctx_new() {
	var ctx = {
		state: new Array(8),
		block: new Array(64),
		nblocks: 0,
		num: 0
	};
	sm3_init(ctx);
	return ctx;
}

function sm3_init(ctx) {
	for (var i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx.block[i] = 0;
	}
	ctx.nblocks = 0;
	ctx.num = 0;
	ctx.state[0] = 0x7380166F;
	ctx.state[1] = 0x4914B2B9;
	ctx.state[2] = 0x172442D7;
	ctx.state[3] = 0xDA8A0600;
	ctx.state[4] = 0xA96F30BC;
	ctx.state[5] = 0x163138AA;
	ctx.state[6] = 0xE38DEE4D;
	ctx.state[7] = 0xB0FB0E4E;
}

function sm3_compress(state, block) {
	return sm3_compress_blocks(state, block, 0, 1);
}

function sm3_update(ctx, data) {

	var data_offset = 0;
	var data_len = data.length;
	var blocks;

	if (ctx.num) {
		var left = SM3_BLOCK_SIZE - ctx.num;
		if (data_len < left) {
			sm3_memcpy(ctx.block, ctx.num, data, 0, data_len);
			ctx.num += data_len;
			return;
		} else {
			sm3_memcpy(ctx.block, ctx.num, data, 0, left);
			sm3_compress_blocks(ctx.state, ctx.block, 0, 1);
			ctx.nblocks++;
			data_offset += left;
			data_len -= left;
		}
	}

	blocks = Math.floor(data_len / SM3_BLOCK_SIZE);
	if (blocks > 0) {
		sm3_compress_blocks(ctx.state, data, data_offset, blocks);
		ctx.nblocks += blocks;
		data_offset += SM3_BLOCK_SIZE * blocks;
		data_len -= SM3_BLOCK_SIZE * blocks;
	}

	ctx.num = data_len;
	if (data_len) {
		sm3_memcpy(ctx.block, 0, data, data_offset, data_len);
	}
}

function sm3_final(ctx, digest)
{
	ctx.block[ctx.num] = 0x80;

	if (ctx.num + 9 <= SM3_BLOCK_SIZE) {
		sm3_memset(ctx.block, ctx.num + 1, 0, SM3_BLOCK_SIZE - ctx.num - 9);
	} else {
		sm3_memset(ctx.block, ctx.num + 1, 0, SM3_BLOCK_SIZE - ctx.num - 1);
		sm3_compress(ctx.state, ctx.block);
		sm3_memset(ctx.block, 0, 0, SM3_BLOCK_SIZE - 8);
	}

	var hi = ctx.nblocks >>> 23;
	var lo = (((ctx.nblocks << 9) + (ctx.num << 3)) & 0xffffffff) >>> 0;

	SM3_PUTU32(ctx.block, 56, hi);
	SM3_PUTU32(ctx.block, 60, lo);

	sm3_compress(ctx.state, ctx.block);

	for (let i = 0; i < 8; i++) {
		SM3_PUTU32(digest, i*4, ctx.state[i]);
	}
}

function SM3_ROL32(x, n) {
	return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function SM3_P0(x) {
	return ((x) ^ SM3_ROL32((x), 9) ^ SM3_ROL32((x),17)) >>> 0;
}

function SM3_P1(x) {
	return ((x) ^ SM3_ROL32((x),15) ^ SM3_ROL32((x),23)) >>> 0;
}

function SM3_FF00(x, y, z) {
	return ((x) ^ (y) ^ (z)) >>> 0;
}

function SM3_FF16(x,y,z) {
	return (((x)&(y)) | ((x)&(z)) | ((y)&(z))) >>> 0;
}

function SM3_GG00(x,y,z) {
	return ((x) ^ (y) ^ (z)) >>> 0;
}

function SM3_GG16(x,y,z) {
	return ((((y)^(z)) & (x)) ^ (z)) >>> 0;
}

function sm3_compress_blocks(state, data, offset, blocks) {
	var A;
	var B;
	var C;
	var D;
	var E;
	var F;
	var G;
	var H;
	var W = new Array(68);
	var SS1, SS2, TT1, TT2;
	var j;

	const K = [
		0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
		0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
		0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
		0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
		0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
		0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
		0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
		0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
		0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53,
		0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
		0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4,
		0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
		0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
		0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
		0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
		0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
	];


	while (blocks--) {
		A = state[0];
		B = state[1];
		C = state[2];
		D = state[3];
		E = state[4];
		F = state[5];
		G = state[6];
		H = state[7];

		for (j = 0; j < 16; j++) {
			W[j] = SM3_GETU32(data, offset + j*4);
		}

		for (; j < 68; j++) {
			W[j] = SM3_P1(W[j - 16] ^ W[j - 9] ^ SM3_ROL32(W[j - 3], 15))
				^ SM3_ROL32(W[j - 13], 7) ^ W[j - 6];
			W[j] >>>= 0;
		}


		j = 0;

		for (; j < 16; j++) {
			SS1 = SM3_ROL32(A, 12) + E + K[j];
			SS1 = (SS1 & 0xffffffff) >>> 0;
			SS1 = SM3_ROL32(SS1, 7);
			SS2 = SS1 ^ SM3_ROL32(A, 12);
			SS2 = (SS2 & 0xffffffff) >>> 0;
			TT1 = W[j] ^ W[j + 4];
			TT1 = (TT1 & 0xffffffff) >>> 0;
			TT1 = SM3_FF00(A, B, C) + D + SS2 + TT1;
			TT1 = (TT1 & 0xffffffff) >>> 0;
			TT2 = SM3_GG00(E, F, G) + H + SS1 + W[j];
			TT2 = (TT2 & 0xffffffff) >>> 0;
			D = C;
			C = SM3_ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = SM3_ROL32(F, 19);
			F = E;
			E = SM3_P0(TT2);
		}

		for (; j < 64; j++) {
			SS1 = SM3_ROL32(A, 12) + E + K[j];
			SS1 = (SS1 & 0xffffffff) >>> 0;
			SS1 = SM3_ROL32(SS1, 7);
			SS2 = SS1 ^ SM3_ROL32(A, 12);
			SS2 = (SS2 & 0xffffffff) >>> 0;
			TT1 = W[j] ^ W[j + 4];
			TT1 = (TT1 & 0xffffffff) >>> 0;
			TT1 = SM3_FF16(A, B, C) + D + SS2 + TT1;
			TT1 = (TT1 & 0xffffffff) >>> 0;
			TT2 = SM3_GG16(E, F, G) + H + SS1 + W[j];
			TT2 = (TT2 & 0xffffffff) >>> 0;
			D = C;
			C = SM3_ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = SM3_ROL32(F, 19);
			F = E;
			E = SM3_P0(TT2);
		}

		state[0] ^= A;
		state[1] ^= B;
		state[2] ^= C;
		state[3] ^= D;
		state[4] ^= E;
		state[5] ^= F;
		state[6] ^= G;
		state[7] ^= H;

		offset += SM3_BLOCK_SIZE;   // [毕设修复] 上游 bug：多分块时未推进读偏移，导致每块都重复读第1块、
		                            // 中间块被忽略 → 长消息(>64B 且≥2整块)摘要错误。此处补上每块推进 64 字节。
	}
}

function sm3(m) {
	var digest = new Array(SM3_DIGEST_LENGTH);
	var ctx = sm3_ctx_new();
	sm3_init(ctx);
	sm3_update(ctx, m);
	sm3_final(ctx, digest);
	return digest;
}

function sm3_compute_z(z, id, pk) {
	const Z_CONST = [
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
		0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
		0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
		0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
		0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
		0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
		0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
		0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
		0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
		0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
		0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
	];

	var ctx = sm3_ctx_new();
	sm3_init(ctx);
	sm3_update(ctx, [Math.floor(id.length / 65536), id.length % 65536]);
	sm3_update(ctx, id);
	sm3_update(ctx, Z_CONST);
	sm3_update(ctx, pk);
	sm3_final(ctx, z);
	sm3_ctx_free(ctx);
}

function sm3_test() {
	const test1 = [0x61, 0x62, 0x63];
	const test2 = [
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
		0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64];
	const dgst1 = [
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0];
	const dgst2 = [
		0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
		0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
		0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
		0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32];


	dgst = sm3(test1);

	for (var i = 0; i < 32; i++) {
		if (dgst[i] != dgst1[i]) {
			console.log("test1 error at " + i);
			return 0;
		}
	}
	console.log("test1 ok");

	dgst = sm3(test2);
	for (var i = 0; i < 32; i++) {
		if (dgst[i] != dgst2[i]) {
			console.log("test2 error at " + i);
			return 0;
		}
	}
	console.log("test2 ok");

	return 1;
}

const SM3_HMAC_IPAD = 0x36;
const SM3_HMAC_OPAD = 0x5C;

function sm3_hmac_ctx_new() {
	var ctx = {
		sm3_ctx: sm3_ctx_new(),
		key : new Array(SM3_BLOCK_SIZE),
	};
	return ctx;
}

function sm3_hmac_ctx_free(ctx) {
	sm3_ctx_free(ctx.sm3_ctx);
	for (var i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx.key[i] = 0;
	}
}

function sm3_hmac_init(ctx, key)
{
	var i;
	var key_len = key.length;

	if (key_len <= SM3_BLOCK_SIZE) {
		sm3_memcpy(ctx.key, 0, key, 0, key_len);
		sm3_memset(ctx.key, key_len, 0, SM3_BLOCK_SIZE - key_len);
	} else {
		sm3_init(ctx.sm3_ctx);
		sm3_update(ctx.sm3_ctx, key);
		sm3_final(ctx.sm3_ctx, ctx.key);
		sm3_memset(ctx.key, SM3_DIGEST_LENGTH, 0,
			SM3_BLOCK_SIZE - SM3_DIGEST_LENGTH);
	}
	for (i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx.key[i] ^= SM3_HMAC_IPAD;
	}

	sm3_init(ctx.sm3_ctx);
	sm3_update(ctx.sm3_ctx, ctx.key);
}

function sm3_speed() {
	var data = new Array(1000 * 1000);
	for (var i = 0; i < data.length; i++) {
		data[i] = 0x23;
	}
	var dgst = sm3(data);
	console.log(dgst);
}

function sm3_hmac_update(ctx, data) {
	sm3_update(ctx.sm3_ctx, data);
}

function sm3_hmac_final(ctx, mac)
{
	for (var i = 0; i < SM3_BLOCK_SIZE; i++) {
		ctx.key[i] ^= (SM3_HMAC_IPAD ^ SM3_HMAC_OPAD);
	}
	sm3_final(ctx.sm3_ctx, mac);
	sm3_init(ctx.sm3_ctx);
	sm3_update(ctx.sm3_ctx, ctx.key);
	sm3_update(ctx.sm3_ctx, mac);
	sm3_final(ctx.sm3_ctx, mac);
}

function sm3_hmac(data, key, mac) {
	ctx = sm3_hmac_ctx_new();
	sm3_hmac_init(ctx, key);
	sm3_hmac_update(ctx, data);
	sm3_hmac_final(ctx, mac);
	sm3_hmac_ctx_free(ctx);
}

function sm3_kdf(Z, klen) {
	var key = [];
	var ct = 1;
	var buf = new Array(4);
	var ctx = sm3_ctx_new();

	for (var i = 0; i < Math.ceil(klen / SM3_DIGEST_LENGTH); i++) {
		sm3_init(ctx);
		sm3_update(ctx, Z);
		SM3_PUTU32(buf, 0, ct);
		sm3_update(ctx, buf);
		sm3_final(ctx, dgst);
		key.concat(dgst);
		ct++;
	}
	return key.slice(0, klen);
}
// ===== sm4.js =====
/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


function sm4_memcpy(dst, dst_offset, src, src_offset, len) {
	while (len--) {
		dst[dst_offset++] = src[src_offset++];
	}
}

function SM4_GETU32(data, offset) {
	return ((data[offset] << 24)
		| (data[offset + 1] << 16)
		| (data[offset + 2] << 8)
		| data[offset + 3]) >>> 0;
}

function SM4_PUTU32(data, offset, value) {
	data[offset + 3] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset + 2] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset + 1] = (value & 0xff) >>> 0;
	value >>>= 8;
	data[offset] = (value & 0xff) >>> 0;
}

const SM4_KEY_LENGTH = 16
const SM4_BLOCK_SIZE = 16
const SM4_IV_LENGTH = SM4_BLOCK_SIZE
const SM4_NUM_ROUNDS = 32

const SM4_S = [
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const SM4_FK = [
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
];

const SM4_CK = [
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

function SM4_ROL32(x, n) {
	return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function SM4_S32(A) {
	return (
		(SM4_S[A >>> 24] << 24) ^
		(SM4_S[(A >>> 16) & 0xff] << 16) ^
		(SM4_S[(A >>> 8) & 0xff] << 8) ^
		(SM4_S[A & 0xff])) >>> 0;
}

function SM4_L32(x) {
	return (
		x ^
		SM4_ROL32(x, 2) ^
		SM4_ROL32(x, 10) ^
		SM4_ROL32(x, 18) ^
		SM4_ROL32(x, 24)) >>> 0;
}

function SM4_L32_(x) {
	return (
		x ^
		SM4_ROL32(x, 13) ^
		SM4_ROL32(x, 23)) >>> 0;
}


function sm4_key_new() {
	var key = {
		rk: new Array(SM4_NUM_ROUNDS),
	};
	return key;
}

function sm4_key_free(key) {
	for (var i = 0; i < SM4_NUM_ROUNDS; i++) {
		key.rk[i] = 0;
	}
}

function sm4_set_encrypt_key(key, user_key) {
	var x0, x1, x2, x3, x4;
	x0 = SM4_GETU32(user_key,  0) ^ SM4_FK[0];
	x1 = SM4_GETU32(user_key,  4) ^ SM4_FK[1];
	x2 = SM4_GETU32(user_key,  8) ^ SM4_FK[2];
	x3 = SM4_GETU32(user_key, 12) ^ SM4_FK[3];
	key.rk[ 0] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 0]))) >>> 0;
	key.rk[ 1] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 1]))) >>> 0;
	key.rk[ 2] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 2]))) >>> 0;
	key.rk[ 3] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 3]))) >>> 0;
	key.rk[ 4] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 4]))) >>> 0;
	key.rk[ 5] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 5]))) >>> 0;
	key.rk[ 6] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 6]))) >>> 0;
	key.rk[ 7] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 7]))) >>> 0;
	key.rk[ 8] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 8]))) >>> 0;
	key.rk[ 9] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 9]))) >>> 0;
	key.rk[10] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[10]))) >>> 0;
	key.rk[11] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[11]))) >>> 0;
	key.rk[12] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[12]))) >>> 0;
	key.rk[13] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[13]))) >>> 0;
	key.rk[14] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[14]))) >>> 0;
	key.rk[15] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[15]))) >>> 0;
	key.rk[16] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[16]))) >>> 0;
	key.rk[17] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[17]))) >>> 0;
	key.rk[18] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[18]))) >>> 0;
	key.rk[19] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[19]))) >>> 0;
	key.rk[20] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[20]))) >>> 0;
	key.rk[21] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[21]))) >>> 0;
	key.rk[22] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[22]))) >>> 0;
	key.rk[23] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[23]))) >>> 0;
	key.rk[24] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[24]))) >>> 0;
	key.rk[25] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[25]))) >>> 0;
	key.rk[26] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[26]))) >>> 0;
	key.rk[27] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[27]))) >>> 0;
	key.rk[28] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[28]))) >>> 0;
	key.rk[29] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[29]))) >>> 0;
	key.rk[30] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[30]))) >>> 0;
	key.rk[31] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[31]))) >>> 0;
	x0 = x1 = x3 = x3 = x4 = 0;
}

function sm4_set_decrypt_key(key, user_key) {
	var x0, x1, x2, x3, x4;
	x0 = SM4_GETU32(user_key,  0) ^ SM4_FK[0];
	x1 = SM4_GETU32(user_key,  4) ^ SM4_FK[1];
	x2 = SM4_GETU32(user_key,  8) ^ SM4_FK[2];
	x3 = SM4_GETU32(user_key, 12) ^ SM4_FK[3];
	key.rk[31] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 0]))) >>> 0;
	key.rk[30] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 1]))) >>> 0;
	key.rk[29] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 2]))) >>> 0;
	key.rk[28] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 3]))) >>> 0;
	key.rk[27] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 4]))) >>> 0;
	key.rk[26] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[ 5]))) >>> 0;
	key.rk[25] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[ 6]))) >>> 0;
	key.rk[24] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[ 7]))) >>> 0;
	key.rk[23] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[ 8]))) >>> 0;
	key.rk[22] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[ 9]))) >>> 0;
	key.rk[21] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[10]))) >>> 0;
	key.rk[20] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[11]))) >>> 0;
	key.rk[19] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[12]))) >>> 0;
	key.rk[18] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[13]))) >>> 0;
	key.rk[17] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[14]))) >>> 0;
	key.rk[16] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[15]))) >>> 0;
	key.rk[15] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[16]))) >>> 0;
	key.rk[14] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[17]))) >>> 0;
	key.rk[13] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[18]))) >>> 0;
	key.rk[12] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[19]))) >>> 0;
	key.rk[11] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[20]))) >>> 0;
	key.rk[10] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[21]))) >>> 0;
	key.rk[ 9] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[22]))) >>> 0;
	key.rk[ 8] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[23]))) >>> 0;
	key.rk[ 7] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[24]))) >>> 0;
	key.rk[ 6] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[25]))) >>> 0;
	key.rk[ 5] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[26]))) >>> 0;
	key.rk[ 4] = x1 = (x2 ^ SM4_L32_(SM4_S32(x3 ^ x4 ^ x0 ^ SM4_CK[27]))) >>> 0;
	key.rk[ 3] = x2 = (x3 ^ SM4_L32_(SM4_S32(x4 ^ x0 ^ x1 ^ SM4_CK[28]))) >>> 0;
	key.rk[ 2] = x3 = (x4 ^ SM4_L32_(SM4_S32(x0 ^ x1 ^ x2 ^ SM4_CK[29]))) >>> 0;
	key.rk[ 1] = x4 = (x0 ^ SM4_L32_(SM4_S32(x1 ^ x2 ^ x3 ^ SM4_CK[30]))) >>> 0;
	key.rk[ 0] = x0 = (x1 ^ SM4_L32_(SM4_S32(x2 ^ x3 ^ x4 ^ SM4_CK[31]))) >>> 0;
	x0 = x1 = x3 = x3 = x4 = 0;
}

function sm4_encrypt(inbuf, in_offset, outbuf, out_offset, key) {
	var x0, x1, x2, x3, x4;
	x0 = SM4_GETU32(inbuf, in_offset);
	x1 = SM4_GETU32(inbuf, in_offset + 4);
	x2 = SM4_GETU32(inbuf, in_offset + 8);
	x3 = SM4_GETU32(inbuf, in_offset + 12);
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[0]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[1]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[2]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[3]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[4]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[5]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[6]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[7]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[8]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[9]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[10]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[11]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[12]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[13]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[14]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[15]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[16]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[17]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[18]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[19]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[20]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[21]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[22]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[23]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[24]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[25]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[26]));
	x1 = x2 ^ SM4_L32(SM4_S32(x3 ^ x4 ^ x0 ^ key.rk[27]));
	x2 = x3 ^ SM4_L32(SM4_S32(x4 ^ x0 ^ x1 ^ key.rk[28]));
	x3 = x4 ^ SM4_L32(SM4_S32(x0 ^ x1 ^ x2 ^ key.rk[29]));
	x4 = x0 ^ SM4_L32(SM4_S32(x1 ^ x2 ^ x3 ^ key.rk[30]));
	x0 = x1 ^ SM4_L32(SM4_S32(x2 ^ x3 ^ x4 ^ key.rk[31]));
	SM4_PUTU32(outbuf, out_offset, x0);
	SM4_PUTU32(outbuf, out_offset + 4, x4);
	SM4_PUTU32(outbuf, out_offset + 8, x3);
	SM4_PUTU32(outbuf, out_offset + 12, x2);
}

function sm4_decrypt(inbuf, in_offset, outbuf, out_offset, key) {
	return sm4_encrypt(inbuf, in_offset, outbuf, out_offset, key);
}

function sm4_test() {
	const user_key = [
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	];
	const rk = [
		0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
		0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
		0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
		0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
		0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
		0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
		0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
		0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,
	];
	const plaintext = [
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	];
	const ciphertext = [
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	];
	const ciphertext2 = [
		0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
		0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
	];

	var key = sm4_key_new();
	var buf = new Array(SM4_BLOCK_SIZE);

	sm4_set_encrypt_key(key, user_key);

	for (var i = 0; i < SM4_NUM_ROUNDS; i++) {
		if (key.rk[i] != rk[i]) {
			console.log("sm4_set_encrypt_key failed");
			return 0;
		}
	}

	sm4_encrypt(plaintext, 0, buf, 0, key);

	console.log("sm4 test1");
	for (var i = 0; i < SM4_BLOCK_SIZE; i++) {
		if (buf[i] != ciphertext[i]) {
			console.log("sm4_encrypt failed");
			return 0;
		}
	}

	sm4_memcpy(buf, 0, plaintext, 0, SM4_BLOCK_SIZE);

	console.log("sm4 test2");
	for (var i = 0; i < 1000000; i++) {
		sm4_encrypt(buf, 0, buf, 0, key);
	}

	for (var i = 0; i < SM4_BLOCK_SIZE; i++) {
		if (buf[i] != ciphertext2[i]) {
			console.log("sm4_encrypt 1000000 failed");
			return 0;
		}
	}

	sm4_set_decrypt_key(key, user_key);
	sm4_encrypt(ciphertext, 0, buf, 0, key);

	for (var i = 0; i < SM4_BLOCK_SIZE; i++) {
		if (buf[i] != plaintext[i]) {
			console.log("sm4_decrypt failed");
			return 0;
		}
	}

	sm4_key_free(key);
	return 1;
}
// ===== sm9.js =====
/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


const SM9_P = 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457dn;

const SM9_N = 0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25n;

const SM9_P1 = {
	X : 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDDn,
	Y : 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616n,
	Z : 1n,
};

const SM9_P2 = {
	X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
	     0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n],
	Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
	     0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n],
	Z : [1n, 0n],
}

const SM9_Ppubs = {
	X : [0x29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32n,
	     0x9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408n],
	Y : [0x41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216Dn,
	     0x69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25n],
	Z : [1n, 0n],
}

function fp_new() {
	return 0n;
}

function fp_zero() {
	return 0n;
}

function fp_one() {
	return 1n;
}

function fp_from_hex(s) {
	return BigInt("0x" + s);
}

function fp_is_zero(a) {
	return a == 0n;
}

function fp_is_one(a) {
	return a == 1n;
}

function fp_equ(a, b) {
	return a == b;
}

function fp_add(a, b) {
	return (a + b) % SM9_P;
}

function fp_dbl(a) {
	return (a + a) % SM9_P;
}

function fp_tri(a) {
	return (a + a + a) % SM9_P;
}

function fp_div2(a) {
	if (a % 2n == 1n)
		a += SM9_P;
	return a/2n;
}

function fp_sub(a, b) {
	if (a >= b) {
		return a - b;
	} else {
		return SM9_P + a - b;
	}
}

function fp_neg(a) {
	if (a == 0n)
		return 0n;
	return SM9_P - a;
}

function fp_mul(a, b) {
	return (a * b) % SM9_P;
}

function fp_sqr(a) {
	return (a * a) % SM9_P;
}

function fp_inv(a) {
	let u = a;
	let v = SM9_P;
	let x1 = 1n;
	let x2 = 0n;
	let q = 0n;
	let r = 0n;
	let x = 0n;

	while (u != 1) {
		q = v / u;
		r = v - q * u;
		x = x2 - q * x1;
		v = u;
		u = r;
		x2 = x1;
		x1 = x;
	}

	if (x1 < 0)
		return x1 + SM9_P;
	else
		return x1 % SM9_P;
}

function fp2_new() {
	return [0n, 0n];
}

function fp2_set_hex(a, s) {
	a[0] = fp_from_hex(s[0]);
	a[1] = fp_from_hex(s[1]);
}

function fp2_from_hex(s) {
	let r = fp2_new();
	fp2_set_hex(r, s);
	return r;
}

function fp2_is_zero(a) {
	return a[0] == 0n
		&& a[1] == 0n;
}

function fp2_is_one(a) {
	return a[0] == 1n
		&& a[1] == 0n;
}

function fp2_set_zero(a) {
	a[0] = 0n;
	a[1] = 0n;
}

function fp2_set_one(a) {
	a[0] = 1n;
	a[1] = 0n;
}

function fp2_copy(r, a) {
	r[0] = a[0];
	r[1] = a[1];
}

function fp2_set(a, a0, a1) {
	a[0] = a0;
	a[1] = a1;
}

function fp2_set_u(a) {
	a[0] = 0n;
	a[1] = 1n;
}

function fp2_set_5u(a) {
	a[0] = 0n;
	a[1] = 5n;
}

function fp2_set_bn(a, a0) {
	a[0] = a0 % SM9_P;
	a[1] = 0n;
}

function fp2_equ(a, b) {
	return a[0] == b[0] && a[1] == b[1];
}

function fp2_add(r, a, b) {
	r[0] = fp_add(a[0], b[0]);
	r[1] = fp_add(a[1], b[1]);
}

function fp2_dbl(r, a) {
	r[0] = fp_dbl(a[0]);
	r[1] = fp_dbl(a[1]);
}

function fp2_tri(r, a) {
	let t = fp2_new();
	fp2_dbl(t, a);
	fp2_add(r, t, a);
}

function fp2_div2(r, a) {
	r[0] = fp_div2(a[0]);
	r[1] = fp_div2(a[1]);
}

function fp2_sub(r, a, b) {
	r[0] = fp_sub(a[0], b[0]);
	r[1] = fp_sub(a[1], b[1]);
}

function fp2_neg(r, a) {
	r[0] = fp_neg(a[0]);
	r[1] = fp_neg(a[1]);
}

function fp2_mul(r, a, b) {
	let r0 = fp_sub(fp_mul(a[0], b[0]), fp_dbl(fp_mul(a[1], b[1])));
	let r1 = fp_add(fp_mul(a[0], b[1]), fp_mul(a[1], b[0]));
	r[0] = r0;
	r[1] = r1;
}

function fp2_mul_u(r, a, b) {
	let r0 = fp_neg(fp_dbl(fp_add(fp_mul(a[0], b[1]), fp_mul(a[1], b[0]))));
	let r1 = fp_sub(fp_mul(a[0], b[0]), fp_dbl(fp_mul(a[1], b[1])));
	r[0] = r0;
	r[1] = r1;
}

function fp2_mul_fp(r, a, k) {
	r[0] = fp_mul(a[0], k);
	r[1] = fp_mul(a[1], k);
}

function fp2_sqr(r, a) {
	let r0 = fp_sub(fp_sqr(a[0]), fp_dbl(fp_sqr(a[1])));
	let r1 = fp_dbl(fp_mul(a[0], a[1]));
	r[0] = r0;
	r[1] = r1;
}

function fp2_sqr_u(r, a) {
	let r0 = fp_neg(fp_dbl(fp_dbl(fp_mul(a[0], a[1]))));
	let r1 = fp_sub(fp_sqr(a[0]), fp_dbl(fp_sqr(a[1])));
	r[0] = r0;
	r[1] = r1;
}

function fp2_inv(r, a) {
	if (fp_is_zero(a[0])) {
		r[0] = fp_zero();
		r[1] = fp_neg(fp_inv(fp_dbl(a[1])));

	} else if (fp_is_zero(a[1])) {
		r[0] = fp_inv(a[0]);
		r[1] = fp_zero();

	} else {
		let k = fp_inv(fp_add(fp_sqr(a[0]), fp_dbl(fp_sqr(a[1]))));
		r[0] = fp_mul(a[0], k);
		r[1] = fp_neg(fp_mul(a[1], k));
	}
}

function fp2_div(r, a, b) {
	let t = fp2_new();
	fp2_inv(t, b);
	fp2_mul(r, a, t);
}

function fp4_new() {
	return [fp2_new(), fp2_new()];
}

function fp4_set_hex(r, s) {
	fp2_set_hex(r[0], s.slice(0, 2));
	fp2_set_hex(r[1], s.slice(2, 4));
}

function fp4_from_hex(s) {
	let r = fp4_new();
	fp4_set_hex(r, s);
	return r;
}

function fp4_is_zero(a) {
	return fp2_is_zero(a[0])
		&& fp2_is_zero(a[1]);
}

function fp4_is_one(a) {
	return fp2_is_one(a[0])
		&& fp2_is_zero(a[1]);
}

function fp4_set_zero(a) {
	fp2_set_zero(a[0]);
	fp2_set_zero(a[1]);
}

function fp4_set_one(a) {
	fp2_set_one(a[0]);
	fp2_set_zero(a[1]);
}

function fp4_set_bn(r, a) {
	fp2_set_bn(r[0], a);
	fp2_set_zero(r[1]);
}

function fp4_set_fp2(r, a) {
	fp2_copy(r[0], a);
	fp2_set_zero(r[1]);
}

function fp4_set(r, a0, a1) {
	fp2_copy(r[0], a0);
	fp2_copy(r[1], a1);
}

function fp4_copy(r, a) {
	fp2_copy(r[0], a[0]);
	fp2_copy(r[1], a[1]);
}

function fp4_set_u(r) {
	fp2_set_u(r[0]);
	fp2_set_zero(r[1]);
}

function fp4_set_v(r) {
	fp2_set_zero(r[0]);
	fp2_set_one(r[1]);
}

function fp4_equ(a, b) {
	return fp2_equ(a[0], b[0])
		&& fp2_equ(a[1], b[1]);
}

function fp4_add(r, a, b) {
	fp2_add(r[0], a[0], b[0]);
	fp2_add(r[1], a[1], b[1]);
}

function fp4_dbl(r, a) {
	fp2_dbl(r[0], a[0]);
	fp2_dbl(r[1], a[1]);
}

function fp4_sub(r, a, b) {
	fp2_sub(r[0], a[0], b[0]);
	fp2_sub(r[1], a[1], b[1]);
}

function fp4_neg(r, a) {
	fp2_neg(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

function fp4_mul(r, a, b) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_mul(r0, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[1]);
	fp2_mul(t, a[1], b[0]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_mul_fp(r, a, k) {
	fp2_mul_fp(r[0], a[0], k);
	fp2_mul_fp(r[1], a[1], k);
}

function fp4_mul_fp2(r, a, b) {
	fp2_mul(r[0], a[0], b);
	fp2_mul(r[1], a[1], b);
}

function fp4_mul_v(r, a, b) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_mul_u(r0, a[0], b[1]);
	fp2_mul_u(t, a[1], b[0]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], b[0]);
	fp2_mul_u(t, a[1], b[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_sqr(r, a) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_sqr(r0, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r0, r0, t);

	fp2_mul(r1, a[0], a[1]);
	fp2_dbl(r1, r1);
	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_sqr_v(r, a) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let t = fp2_new();

	fp2_mul_u(t, a[0], a[1]);
	fp2_dbl(r0, t);

	fp2_sqr(r1, a[0]);
	fp2_sqr_u(t, a[1]);
	fp2_add(r1, r1, t);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp4_inv(r, a) {
	let r0 = fp2_new();
	let r1 = fp2_new();
	let k = fp2_new();

	fp2_sqr_u(k, a[1]);
	fp2_sqr(r0, a[0]);
	fp2_sub(k, k, r0);
	fp2_inv(k, k);

	fp2_mul(r0, a[0], k);
	fp2_neg(r0, r0);

	fp2_mul(r1, a[1], k);

	fp2_copy(r[0], r0);
	fp2_copy(r[1], r1);
}

function fp12_new() {
	return [fp4_new(),
		fp4_new(),
		fp4_new()];
}

function fp12_set_hex(r, s) {
	fp4_set_hex(r[0], s.slice(0, 4));
	fp4_set_hex(r[1], s.slice(4, 8));
	fp4_set_hex(r[2], s.slice(8, 12));
}

function fp12_from_hex(s) {
	let r = fp12_new();
	fp12_set_hex(r, s);
	return r;
}

function fp12_is_zero(a) {
	return fp4_is_zero(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

function fp12_is_one(a) {
	return fp4_is_one(a[0])
		&& fp4_is_zero(a[1])
		&& fp4_is_zero(a[2]);
}

function fp12_set_zero(a) {
	fp4_set_zero(a[0]);
	fp4_set_zero(a[1]);
	fp4_set_zero(a[2]);
}

function fp12_set_one(a) {
	fp4_set_one(a[0]);
	fp4_set_zero(a[1]);
	fp4_set_zero(a[2]);
}

function fp12_copy(r, a) {
	fp4_copy(r[0], a[0]);
	fp4_copy(r[1], a[1]);
	fp4_copy(r[2], a[2]);
}

function fp12_set(r, a0, a1, a2) {
	fp4_copy(r[0], a0);
	fp4_copy(r[1], a1);
	fp4_copy(r[2], a2);
}

function fp12_set_fp4(r, a) {
	fp4_copy(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_fp2(r, a) {
	fp4_set_fp2(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_bn(r, a) {
	fp4_set_bn(r[0], a);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_u(r) {
	fp4_set_u(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_v(r) {
	fp4_set_v(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_w(r) {
	fp4_set_zero(r[0]);
	fp4_set_one(r[1]);
	fp4_set_zero(r[2]);
}

function fp12_set_w_sqr(r) {
	fp4_set_zero(r[0]);
	fp4_set_zero(r[1]);
	fp4_set_one(r[2]);
}

function fp12_equ(a, b) {
	return fp4_equ(a[0], b[0])
		&& fp4_equ(a[1], b[1])
		&& fp4_equ(a[2], b[2]);
}

function fp12_add(r, a, b) {
	fp4_add(r[0], a[0], b[0]);
	fp4_add(r[1], a[1], b[1]);
	fp4_add(r[2], a[2], b[2]);
}

function fp12_dbl(r, a) {
	fp4_dbl(r[0], a[0]);
	fp4_dbl(r[1], a[1]);
	fp4_dbl(r[2], a[2]);
}

function fp12_tri(r, a) {
	let t = fp12_new();
	fp12_dbl(t, a);
	fp12_add(r, t, a);
}

function fp12_sub(r, a, b) {
	fp4_sub(r[0], a[0], b[0]);
	fp4_sub(r[1], a[1], b[1]);
	fp4_sub(r[2], a[2], b[2]);
}

function fp12_neg(r, a) {
	fp4_neg(r[0], a[0]);
	fp4_neg(r[1], a[1]);
	fp4_neg(r[2], a[2]);
}

function fp12_mul(r, a, b) {
	let r0 = fp12_new();
	let r1 = fp12_new();
	let r2 = fp12_new();
	let t = fp12_new();

	fp4_mul(r0, a[0], b[0]);
	fp4_mul_v(t, a[1], b[2]);
	fp4_add(r0, r0, t);
	fp4_mul_v(t, a[2], b[1]);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0], b[1]);
	fp4_mul(t, a[1], b[0]);
	fp4_add(r1, r1, t);
	fp4_mul_v(t, a[2], b[2]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0], b[2]);
	fp4_mul(t, a[1], b[1]);
	fp4_add(r2, r2, t);
	fp4_mul(t, a[2], b[0]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0], r0);
	fp4_copy(r[1], r1);
	fp4_copy(r[2], r2);
}

function fp12_sqr(r, a, b) {
	let r0 = fp12_new();
	let r1 = fp12_new();
	let r2 = fp12_new();
	let t = fp12_new();

	fp4_sqr(r0, a[0]);
	fp4_mul_v(t, a[1], a[2]);
	fp4_dbl(t, t);
	fp4_add(r0, r0, t);

	fp4_mul(r1, a[0], a[1]);
	fp4_dbl(r1, r1);
	fp4_sqr_v(t, a[2]);
	fp4_add(r1, r1, t);

	fp4_mul(r2, a[0], a[2]);
	fp4_dbl(r2, r2);
	fp4_sqr(t, a[1]);
	fp4_add(r2, r2, t);

	fp4_copy(r[0], r0);
	fp4_copy(r[1], r1);
	fp4_copy(r[2], r2);
}

function fp12_inv(r, a) {

	if (fp4_is_zero(a[2])) {
		let k = fp4_new();
		let t = fp4_new();

		fp4_sqr(k, a[0]);
		fp4_mul(k, k, a[0]);
		fp4_sqr_v(t, a[1]);
		fp4_mul(t, t, a[1]);
		fp4_add(k, k, t);
		fp4_inv(k, k);

		fp4_sqr(r[2], a[1]);
		fp4_mul(r[2], r[2], k);

		fp4_mul(r[1], a[0], a[1]);
		fp4_mul(r[1], r[1], k);
		fp4_neg(r[1], r[1]);

		fp4_sqr(r[0], a[0]);
		fp4_mul(r[0], r[0], k);

	} else {
		let t0 = fp4_new();
		let t1 = fp4_new();
		let t2 = fp4_new();
		let t3 = fp4_new();

		fp4_sqr(t0, a[1]);
		fp4_mul(t1, a[0], a[2]);
		fp4_sub(t0, t0, t1);

		fp4_mul(t1, a[0], a[1]);
		fp4_sqr_v(t2, a[2]);
		fp4_sub(t1, t1, t2);

		fp4_sqr(t2, a[0]);
		fp4_mul_v(t3, a[1], a[2]);
		fp4_sub(t2, t2, t3);

		fp4_sqr(t3, t1);
		fp4_mul(r[0], t0, t2);
		fp4_sub(t3, t3, r[0]);
		fp4_inv(t3, t3);
		fp4_mul(t3, a[2], t3);

		fp4_mul(r[0], t2, t3);

		fp4_mul(r[1], t1, t3);
		fp4_neg(r[1], r[1]);

		fp4_mul(r[2], t0, t3);
	}
}


function fp12_pow(r, a, k) {
	k %= SM9_P;
	if (k == 0n) {
		fp12_set_one(r);
		return;
	}

	let t = fp12_new();
	let kbits = k.toString(2);

	fp12_copy(t, a);
	for (let i = 1; i < kbits.length; i++) {
		fp12_sqr(t, t);
		if (kbits[i] == 1) {
			fp12_mul(t, t, a);
		}
	}
	fp12_copy(r, t);
}

function fp2_conjugate(r, a) {
	r[0] = a[0];
	r[1] = fp_neg(a[1]);
}

function fp2_frobenius(r, a) {
	return fp2_conjugate(r, a);
}

function fp4_frobenius(r, a) {
	const beta = [
		0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n,
		0n];
	fp2_conjugate(r[0], a[0]);
	fp2_conjugate(r[1], a[1]);
	fp2_mul(r[1], r[1], beta);
}

function fp4_conjugate(r, a) {
	fp2_copy(r[0], a[0]);
	fp2_neg(r[1], a[1]);
}

function fp4_frobenius2(r, a) {
	return fp4_conjugate(r, a);
}

function fp4_frobenius3(r, a) {
	const beta = [
		0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n,
		0n];
	fp2_conjugate(r[0], a[0]);
	fp2_conjugate(r[1], a[1]);
	fp2_mul(r[1], r[1], beta);
	fp2_neg(r[1], r[1]);
}

function fp12_frobenius(r, x) {
	const alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
	const alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	const alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n;
	const alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n;
	const alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686n;

	let xa = x[0];
	let xb = x[1];
	let xc = x[2];
	let ra = fp4_new();
	let rb = fp4_new();
	let rc = fp4_new();

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul_fp(ra[1], ra[1], alpha3);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul_fp(rb[0], rb[0], alpha1);
	fp2_conjugate(rb[1], xb[1]);
	fp2_mul_fp(rb[1], rb[1], alpha4);

	fp2_conjugate(rc[0], xc[0]);
	fp2_mul_fp(rc[0], rc[0], alpha2);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul_fp(rc[1], rc[1], alpha5);

	fp12_set(r, ra, rb, rc);
}

function fp12_frobenius2(r, x) {
	const alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	const alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333n;

	let a = fp4_new();
	let b = fp4_new();
	let c = fp4_new();

	fp4_conjugate(a, x[0]);
	fp4_conjugate(b, x[1]);
	fp4_mul_fp(b, b, alpha2);
	fp4_conjugate(c, x[2]);
	fp4_mul_fp(c, c, alpha4);

	fp4_copy(r[0], a);
	fp4_copy(r[1], b);
	fp4_copy(r[2], c);
}

function fp12_frobenius3(r, x) {
	const beta = [
		0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011n,
		0n];

	let ra = fp4_new();
	let rb = fp4_new();
	let rc = fp4_new();

	let xa = x[0];
	let xb = x[1];
	let xc = x[2];

	fp2_conjugate(ra[0], xa[0]);
	fp2_conjugate(ra[1], xa[1]);
	fp2_mul(ra[1], ra[1], beta);
	fp2_neg(ra[1], ra[1]);

	fp2_conjugate(rb[0], xb[0]);
	fp2_mul(rb[0], rb[0], beta);
	fp2_conjugate(rb[1], xb[1]);

	fp2_conjugate(rc[0], xc[0]);
	fp2_neg(rc[0], rc[0]);
	fp2_conjugate(rc[1], xc[1]);
	fp2_mul(rc[1], rc[1], beta);

	fp4_copy(r[0], ra);
	fp4_copy(r[1], rb);
	fp4_copy(r[2], rc);
}

function fp12_frobenius6(r, x) {
	let a = fp4_new();
	let b = fp4_new();
	let c = fp4_new();

	fp4_copy(a, x[0]);
	fp4_copy(b, x[1]);
	fp4_copy(c, x[2]);

	fp4_conjugate(a, a);
	fp4_conjugate(b, b);
	fp4_neg(b, b);
	fp4_conjugate(c, c);

	fp4_copy(r[0], a);
	fp4_copy(r[1], b);
	fp4_copy(r[2], c);
}

function point_new() {
	let R = {
		X : 1n,
		Y : 1n,
		Z : 0n,
	}
	return R;
}

function point_set_hex(R, s) {
	R.X = fp_from_hex(s[0]);
	R.Y = fp_from_hex(s[1]);
	R.Z = fp_one();
}

function point_from_hex(s) {
	let R = point_new();
	point_set_hex(R, s);
	return R;
}

function point_copy(R, P) {
	R.X = P.X;
	R.Y = P.Y;
	R.Z = P.Z;
}

function point_is_at_infinity(P) {
	return P.Z == 0n;
}

function point_set_infinity(R) {
	R.X = 1n;
	R.Y = 1n;
	R.Z = 0n;
}

function point_get_affine(R, P) {
	point_copy(R, P);
	if (R.Z == 0 || R.Z == 1) {
		return;
	}
	R.Z = fp_inv(R.Z);
	R.Y = fp_mul(R.Y, R.Z);
	R.Z = fp_sqr(R.Z);
	R.X = fp_mul(R.X, R.Z);
	R.Y = fp_mul(R.Y, R.Z);
	R.Z = 1n;
}

function point_equ(P, Q) {
	let t1 = fp_sqr(P.Z);
	let t2 = fp_sqr(Q.Z);
	let t3 = fp_mul(P.X, t2);
	let t4 = fp_mul(Q.X, t1);
	if (t3 != t4) {
		return false;
	}
	t1 = fp_mul(t1, P.Z);
	t2 = fp_mul(t2, Q.Z);
	t3 = fp_mul(P.Y, t2);
	t4 = fp_mul(Q.Y, t1);
	return t3 == t4;
}

function point_is_on_curve(P) {
	let t0 = fp_new();
	let t1 = fp_new();
	let t2 = fp_new();

	if (fp_is_one(P.Z)) {
		t0 = fp_sqr(P.Y);
		t1 = fp_sqr(P.X);
		t1 = fp_mul(t1, P.X);
		t1 = fp_add(t1, 5n);
	} else {
		t0 = fp_sqr(P.X);
		t0 = fp_mul(t0, P.X);
		t1 = fp_sqr(P.Z);
		t2 = fp_sqr(t1);
		t1 = fp_mul(t1, t2);
		t1 = fp_mul(t1, 5n);
		t1 = fp_add(t0, t1);
		t0 = fp_sqr(P.Y);
	}

	return fp_equ(t0, t1);
}

function point_double(R, P) {
	if (point_is_at_infinity(P)) {
		return point_copy(R, P);
	}
	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let T1 = fp_new();
	let T2 = fp_new();
	let T3 = fp_new();
	let X3 = fp_new();
	let Y3 = fp_new();
	let Z3 = fp_new();

	T2 = fp_sqr(X1);
	T2 = fp_tri(T2);
	Y3 = fp_dbl(Y1);
	Z3 = fp_mul(Y3, Z1);
	Y3 = fp_sqr(Y3);
	T3 = fp_mul(Y3, X1);
	Y3 = fp_sqr(Y3);
	Y3 = fp_div2(Y3);
	X3 = fp_sqr(T2);
	T1 = fp_dbl(T3);
	X3 = fp_sub(X3, T1);
	T1 = fp_sub(T3, X3);
	T1 = fp_mul(T1, T2);
	Y3 = fp_sub(T1, Y3);

	R.X = X3;
	R.Y = Y3;
	R.Z = Z3;
}

function point_add(R, P, Q) {
	if (point_is_at_infinity(Q)) {
		point_copy(R, P);
		return;
	}
	if (point_is_at_infinity(P)) {
		point_copy(R, Q);
		return;
	}

	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let x2 = Q.X;
	let y2 = Q.Y;
	let T1 = 0n;
	let T2 = 0n;
	let T3 = 0n;
	let T4 = 0n;
	let X3 = 0n;
	let Y3 = 0n;
	let Z3 = 0n;

	T1 = fp_sqr(Z1);
	T2 = fp_mul(T1, Z1);
	T1 = fp_mul(T1, x2);
	T2 = fp_mul(T2, y2);
	T1 = fp_sub(T1, X1);
	T2 = fp_sub(T2, Y1);
	if (T1 == 0n) {
		if (T2 == 0n) {
			return point_double(R, Q);
		} else {
			return point_set_infinity(R);
		}
	}
	Z3 = fp_mul(Z1, T1);
	T3 = fp_sqr(T1);
	T4 = fp_mul(T3, T1);
	T3 = fp_mul(T3, X1);
	T1 = fp_dbl(T3);
	X3 = fp_sqr(T2);
	X3 = fp_sub(X3, T1);
	X3 = fp_sub(X3, T4);
	T3 = fp_sub(T3, X3);
	T3 = fp_mul(T3, T2);
	T4 = fp_mul(T4, Y1);
	Y3 = fp_sub(T3, T4);

	R.X = X3;
	R.Y = Y3;
	R.Z = Z3;
}

function point_sub(R, P, Q) {
	let T = point_new();
	point_neg(T, Q);
	point_add(R, P, T);
}

function point_neg(R, P) {
	R.X = P.X;
	R.Y = fp_neg(P.Y);
	R.Z = P.Z;
}

function point_mul(R, k, P) {
	let Q = point_new();
	let kbits = k.toString(2);
	for (let i = 0; i < kbits.length; i++) {
		point_double(Q, Q);
		if (kbits[i] == 1) {
			point_add(Q, Q, P);
		}
	}
	point_copy(R, Q);
}

function point_mul_G(R, k) {
	point_mul(R, k, SM9_P1)
}

function twist_point_new() {
	let R = {
		X : fp2_new(),
		Y : fp2_new(),
		Z : fp2_new(),
	};
	fp2_set_one(R.X);
	fp2_set_one(R.Y);
	fp2_set_zero(R.Z);
	return R;
}

function twist_point_set_hex(R, s) {
	fp2_set_hex(R.X, s.slice(0, 2));
	fp2_set_hex(R.Y, s.slice(2, 4));
	fp2_set_one(R.Z);
}

function twist_point_from_hex(s) {
	let R = twist_point_new();
	twist_point_set_hex(R, s);
	return R;
}

function twist_point_copy(R, P) {
	fp2_copy(R.X, P.X);
	fp2_copy(R.Y, P.Y);
	fp2_copy(R.Z, P.Z);
}

function twist_point_is_at_infinity(P) {
	return fp2_is_zero(P.Z);
}

function twist_point_set_infinity(R) {
	fp2_set_one(R.X);
	fp2_set_one(R.Y);
	fp2_set_zero(R.Z);
}

function twist_point_get_affine(R, P) {
	twist_point_copy(R, P);
	if (fp2_is_zero(R.Z) || fp2_is_one(R.Z)) {
		return;
	}
	fp2_inv(R.Z, R.Z);
	fp2_mul(R.Y, R.Y, R.Z);
	fp2_sqr(R.Z, R.Z);
	fp2_mul(R.X, R.X, R.Z);
	fp2_mul(R.Y, R.Y, R.Z);
	fp2_set_one(R.Z);
}

function twist_point_equ(P, Q) {
	let t1 = fp2_new();
	let t2 = fp2_new();
	let t3 = fp2_new();
	let t4 = fp2_new();

	fp2_sqr(t1, P.Z);
	fp2_sqr(t2, Q.Z);
	fp2_mul(t3, P.X, t2);
	fp2_mul(t4, Q.X, t1);
	if (!fp2_equ(t3, t4)) {
		return false;
	}
	fp2_mul(t1, t1, P.Z);
	fp2_mul(t2, t2, Q.Z);
	fp2_mul(t3, P.Y, t2);
	fp2_mul(t4, Q.Y, t1);
	return fp2_equ(t3, t4);
}

function twist_point_is_on_curve(P) {
	let t0 = fp2_new();
	let t1 = fp2_new();
	let t2 = fp2_new();

	if (fp2_is_one(P.Z)) {
		fp2_sqr(t0, P.Y);
		fp2_sqr(t1, P.X);
		fp2_mul(t1, t1, P.X);
		fp2_add(t1, t1, [0n, 5n]);
	} else {
		fp2_sqr(t0, P.X);
		fp2_mul(t0, t0, P.X);
		fp2_sqr(t1, P.Z);
		fp2_sqr(t2, t1);
		fp2_mul(t1, t1, t2);
		fp2_mul(t1, t1, [0n, 5n]);
		fp2_add(t1, t0, t1);
		fp2_sqr(t0, P.Y);
	}

	return fp2_equ(t0, t1);
}

function twist_point_sub(R, P, Q) {
	let T = twist_point_new();
	twist_point_neg(T, Q);
	twist_point_add(R, P, T);
}

function twist_point_neg(R, P) {
	fp2_copy(R.X, P.X);
	fp2_neg(R.Y, P.Y);
	fp2_copy(R.Z, P.Z);
}

function twist_point_double(R, P) {
	if (twist_point_is_at_infinity(P)) {
		return twist_point_copy(R, P);
	}
	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let X3 = fp2_new();
	let Y3 = fp2_new();
	let Z3 = fp2_new();

	fp2_sqr(T2, X1);
	fp2_tri(T2, T2);
	fp2_dbl(Y3, Y1);
	fp2_mul(Z3, Y3, Z1);
	fp2_sqr(Y3, Y3);
	fp2_mul(T3, Y3, X1);
	fp2_sqr(Y3, Y3);
	fp2_div2(Y3, Y3);
	fp2_sqr(X3, T2);
	fp2_dbl(T1, T3);
	fp2_sub(X3, X3, T1);
	fp2_sub(T1, T3, X3);
	fp2_mul(T1, T1, T2);
	fp2_sub(Y3, T1, Y3);

	fp2_copy(R.X, X3);
	fp2_copy(R.Y, Y3);
	fp2_copy(R.Z, Z3);
}

function twist_point_add(R, P, Q) {
	if (twist_point_is_at_infinity(Q)) {
		twist_point_copy(R, P);
		return;
	}
	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, Q);
		return;
	}

	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let x2 = Q.X;
	let y2 = Q.Y;
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let T4 = fp2_new();
	let X3 = fp2_new();
	let Y3 = fp2_new();
	let Z3 = fp2_new();

	fp2_sqr(T1, Z1);
	fp2_mul(T2, T1, Z1);
	fp2_mul(T1, T1, x2);
	fp2_mul(T2, T2, y2);
	fp2_sub(T1, T1, X1);
	fp2_sub(T2, T2, Y1);
	if (fp2_is_zero(T1)) {
		if (fp2_is_zero(T2)) {
			return twist_point_double(R, Q);
		} else {
			return twist_point_set_infinity(R);
		}
	}
	fp2_mul(Z3, Z1, T1);
	fp2_sqr(T3, T1);
	fp2_mul(T4, T3, T1);
	fp2_mul(T3, T3, X1);
	fp2_dbl(T1, T3);
	fp2_sqr(X3, T2);
	fp2_sub(X3, X3, T1);
	fp2_sub(X3, X3, T4);
	fp2_sub(T3, T3, X3);
	fp2_mul(T3, T3, T2);
	fp2_mul(T4, T4, Y1);
	fp2_sub(Y3, T3, T4);

	fp2_copy(R.X, X3);
	fp2_copy(R.Y, Y3);
	fp2_copy(R.Z, Z3);
}

function twist_point_add_full(R, P, Q) {
	if (twist_point_is_at_infinity(Q)) {
		twist_point_copy(R, P);
		return;
	}
	if (twist_point_is_at_infinity(P)) {
		twist_point_copy(R, Q);
		return;
	}

	let X1 = P.X;
	let Y1 = P.Y;
	let Z1 = P.Z;
	let X2 = Q.X;
	let Y2 = Q.Y;
	let Z2 = Q.Z;
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let T4 = fp2_new();
	let T5 = fp2_new();
	let T6 = fp2_new();
	let T7 = fp2_new();
	let T8 = fp2_new();

	fp2_sqr(T1, Z1);
	fp2_sqr(T2, Z2);
	fp2_mul(T3, X2, T1);
	fp2_mul(T4, X1, T2);
	fp2_add(T5, T3, T4);
	fp2_sub(T3, T3, T4);
	fp2_mul(T1, T1, Z1);
	fp2_mul(T1, T1, Y2);
	fp2_mul(T2, T2, Z2);
	fp2_mul(T2, T2, Y1);
	fp2_add(T6, T1, T2);
	fp2_sub(T1, T1, T2);

	if (fp2_is_zero(T1) && fp2_is_zero(T3)) {
		return twist_point_double(R, P);
	}
	if (fp2_is_zero(T1) && fp2_is_zero(T6)) {
		return twist_point_set_infinity(R);
	}

	fp2_sqr(T6, T1);
	fp2_mul(T7, T3, Z1);
	fp2_mul(T7, T7, Z2);
	fp2_sqr(T8, T3);
	fp2_mul(T5, T5, T8);
	fp2_mul(T3, T3, T8);
	fp2_mul(T4, T4, T8);
	fp2_sub(T6, T6, T5);
	fp2_sub(T4, T4, T6);
	fp2_mul(T1, T1, T4);
	fp2_mul(T2, T2, T3);
	fp2_sub(T1, T1, T2);

	fp2_copy(R.X, T6);
	fp2_copy(R.Y, T1);
	fp2_copy(R.Z, T7);
}

function twist_point_mul(R, k, P) {
	let Q = twist_point_new();
	let kbits = k.toString(2);
	for (let i = 0; i < kbits.length; i++) {
		twist_point_double(Q, Q);
		if (kbits[i] == 1) {
			twist_point_add(Q, Q, P);
		}
	}
	twist_point_copy(R, Q);
}

function twist_point_mul_G(R, k) {
	twist_point_mul(R, k, SM9_P2);
}

function eval_g_tangent(num, den, P, Q) {
	let XP = P.X;
	let YP = P.Y;
	let ZP = P.Z;
	let xQ = Q.X;
	let yQ = Q.Y;
	let a0 = num[0][0];
	let a1 = num[0][1];
	let a4 = num[2][0];
	let b1 = den[0][1];
	let t0 = fp2_new();
	let t1 = fp2_new();
	let t2 = fp2_new();

	fp12_set_zero(num);
	fp12_set_zero(den);

	fp2_sqr(t0, ZP);
	fp2_mul(t1, t0, ZP);
	fp2_mul(b1, t1, YP);

	fp2_mul_fp(t2, b1, yQ);
	fp2_neg(a1, t2);

	fp2_sqr(t1, XP);
	fp2_mul(t0, t0, t1);
	fp2_mul_fp(t0, t0, xQ);
	fp2_tri(t0, t0);
	fp2_div2(a4, t0);

	fp2_mul(t1, t1, XP);
	fp2_tri(t1, t1);
	fp2_div2(t1, t1);
	fp2_sqr(t0, YP);
	fp2_sub(a0, t0, t1);
}

function eval_g_line(num, den, T, P, Q) {
	let XT = T.X;
	let YT = T.Y;
	let ZT = T.Z;
	let XP = P.X;
	let YP = P.Y;
	let ZP = P.Z;
	let xQ = Q.X;
	let yQ = Q.Y;
	let a0 = num[0][0];
	let a1 = num[0][1];
	let a4 = num[2][0];
	let b1 = den[0][1];
	let T0 = fp2_new();
	let T1 = fp2_new();
	let T2 = fp2_new();
	let T3 = fp2_new();
	let T4 = fp2_new();

	fp12_set_zero(num);
	fp12_set_zero(den);

	fp2_sqr(T0, ZP);
	fp2_mul(T1, T0, XT);
	fp2_mul(T0, T0, ZP);
	fp2_sqr(T2, ZT);
	fp2_mul(T3, T2, XP);
	fp2_mul(T2, T2, ZT);
	fp2_mul(T2, T2, YP);
	fp2_sub(T1, T1, T3);
	fp2_mul(T1, T1, ZT);
	fp2_mul(T1, T1, ZP);
	fp2_mul(T4, T1, T0);
	fp2_copy(b1, T4);
	fp2_mul(T1, T1, YP);
	fp2_mul(T3, T0, YT);
	fp2_sub(T3, T3, T2);
	fp2_mul(T0, T0, T3);
	fp2_mul_fp(T0, T0, xQ);
	fp2_copy(a4, T0);
	fp2_mul(T3, T3, XP);
	fp2_mul(T3, T3, ZP);
	fp2_sub(T1, T1, T3);
	fp2_copy(a0, T1);
	fp2_mul_fp(T2, T4, yQ);
	fp2_neg(T2, T2);
	fp2_copy(a1, T2);
}

function twist_point_pi1(R, P) {
	const c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698bn;
	fp2_conjugate(R.X, P.X);
	fp2_conjugate(R.Y, P.Y);
	fp2_conjugate(R.Z, P.Z);
	fp2_mul_fp(R.Z, R.Z, c);

}

function twist_point_pi2(R, P) {
	const c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	fp2_copy(R.X, P.X);
	fp2_copy(R.Y, P.Y);
	fp2_mul_fp(R.Z, P.Z, c);
}

function twist_point_neg_pi2(R, P) {
	const c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334n;
	fp2_copy(R.X, P.X);
	fp2_neg(R.Y, P.Y);
	fp2_mul_fp(R.Z, P.Z, c);
}

function final_exponent_hard_part(r, f) {
	const a2 = 0xd8000000019062ed0000b98b0cb27659n;
	const a3 = 0x2400000000215d941n;

	let t0 = fp12_new();
	let t1 = fp12_new();
	let t2 = fp12_new();
	let t3 = fp12_new();

	fp12_pow(t0, f, a3);
	fp12_inv(t0, t0);
	fp12_frobenius(t1, t0);
	fp12_mul(t1, t0, t1);

	fp12_mul(t0, t0, t1);
	fp12_frobenius(t2, f);
	fp12_mul(t3, t2, f);
	fp12_pow(t3, t3, 9n);

	fp12_mul(t0, t0, t3);
	fp12_pow(t3, f, 4n);
	fp12_mul(t0, t0, t3);
	fp12_sqr(t2, t2);
	fp12_mul(t2, t2, t1);
	fp12_frobenius2(t1, f);
	fp12_mul(t1, t1, t2);

	fp12_pow(t2, t1, a2);
	fp12_mul(t0, t2, t0);
	fp12_frobenius3(t1, f);
	fp12_mul(t1, t1, t0);

	fp12_copy(r, t1);
}

function final_exponent(r, f) {
	let t0 = fp12_new();
	let t1 = fp12_new();

	fp12_frobenius6(t0, f);
	fp12_inv(t1, f);
	fp12_mul(t0, t0, t1);
	fp12_frobenius2(t1, t0);
	fp12_mul(t0, t0, t1);
	final_exponent_hard_part(t0, t0);

	fp12_copy(r, t0);
}

function sm9_pairing(r, Q, P) {
	const abits = '00100000000000000000000000000000000000010000101011101100100111110';

	let T = twist_point_new();
	let Q1 = twist_point_new();
	let Q2 = twist_point_new();

	let f_num = fp12_new();
	let f_den = fp12_new();
	let g_num = fp12_new();
	let g_den = fp12_new();

	twist_point_copy(T, Q);

	fp12_set_one(f_num);
	fp12_set_one(f_den);

	for (let i = 0; i < abits.length; i++) {

		fp12_sqr(f_num, f_num);
		fp12_sqr(f_den, f_den);
		eval_g_tangent(g_num, g_den, T, P);
		fp12_mul(f_num, f_num, g_num);
		fp12_mul(f_den, f_den, g_den);

		twist_point_double(T, T);

		if (abits[i] == 1) {
			eval_g_line(g_num, g_den, T, Q, P);
			fp12_mul(f_num, f_num, g_num);
			fp12_mul(f_den, f_den, g_den);
			twist_point_add(T, T, Q);
		}
	}

	twist_point_pi1(Q1, Q);
	twist_point_neg_pi2(Q2, Q);

	eval_g_line(g_num, g_den, T, Q1, P);
	fp12_mul(f_num, f_num, g_num);
	fp12_mul(f_den, f_den, g_den);
	twist_point_add_full(T, T, Q1);

	eval_g_line(g_num, g_den, T, Q2, P);
	fp12_mul(f_num, f_num, g_num);
	fp12_mul(f_den, f_den, g_den);
	twist_point_add_full(T, T, Q2);

	fp12_inv(f_den, f_den);
	fp12_mul(r, f_num, f_den);

	final_exponent(r, r);
}

function pairing_test() {

	let r = fp12_new();
	const g = [
		"aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb",
		"84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a",
		"4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b",
		"b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d",
		"93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439",
		"1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b",
		"5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6",
		"67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f",
		"a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db",
		"38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f",
		"28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000",
		"4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d"];

	sm9_pairing(r, SM9_Ppubs, SM9_P1);
	console.log("test pairing: ", fp12_equ(r, fp12_from_hex(g)));
}
// pairing_test(); // [vendored] 关闭加载期自测，避免浏览器每次加载跑配对

export {
	sm3,
	sm4_key_new, sm4_set_encrypt_key, sm4_set_decrypt_key, sm4_encrypt,
	point_new, point_mul, point_mul_G, point_add, point_get_affine,
	fp12_new, fp12_pow, sm9_pairing, SM9_N, SM9_P2,
};
