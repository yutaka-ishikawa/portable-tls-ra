/*
 * The data structure and functions in this file are derived from
 * Intel SGX SDK.
 *   1) ./ttls/cert_verifier.cpp
 *	- static b64revtb[256]
 *	- static raw_base64_decode()
 *	- static PEM_strip() from PEM_strip_header_and_footer()
 *	- static PEM2DER() from PEM2DER_PublicKey_converter()
 *   2)./ttls/ttls.cpp
 *	- static cbor_bstr_from_pk_sha() from generate_cbor_pkhash_entry()
 *	- static make_cbor_pkhash_entry() from generate_cbor_pkhash_entry()
 *	- make_cbor_sgx_claims() from generate_cbor_claims()
 *	- make_cbor_sgx_evidence() from generate_cbor_evidence()
 */

/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "libcert.h"
#include <cbor.h>

static char b64revtb[256] = {
  -3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*0-15*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16-31*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /*32-47*/
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1, /*48-63*/
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /*64-79*/
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /*80-95*/
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*96-111*/
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*112-127*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128-143*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*144-159*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*160-175*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*176-191*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*192-207*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*208-223*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*224-239*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /*240-255*/
};

static unsigned int
raw_base64_decode(uint8_t *in,
		  uint8_t *out, int strict, int *err)
{
    unsigned int  result = 0;
    int x = 0;
    unsigned char buf[3] = {0, 0, 0};
    unsigned char *p = in, pad = 0;

    *err = 0;
    while (!pad) {
        switch ((x = b64revtb[*p++])) {
            case -3: /* NULL TERMINATOR */
                if (((p - 1) - in) % 4) *err = 1;
                return result;
            case -2: /* PADDING CHARACTER. INVALID HERE */
                if (((p - 1) - in) % 4 < 2) {
                    *err = 1;
                    return result;
                } else if (((p - 1) - in) % 4 == 2) {
                    /* Make sure there's appropriate padding */
                    if (*p != '=') {
                        *err = 1;
                        return result;
                    }
                    buf[2] = 0;
                    pad = 2;
                    result++;
                    break;
                } else {
                    pad = 1;
                    result += 2;
                    break;
                }
                return result;
            case -1:
                if (strict) {
                    *err = 2;
                    return result;
                }
                break;
            default:
                switch (((p - 1) - in) % 4) {
                    case 0:
                        buf[0] = (unsigned char)(x << 2);
                        break;
                    case 1:
                        buf[0] |= (unsigned char)(x >> 4);
                        buf[1] = (unsigned char)(x << 4);
                        break;
                    case 2:
                        buf[1] |= (unsigned char)(x >> 2);
                        buf[2] = (unsigned char)(x << 6);
                        break;
                    case 3:
                        buf[2] |= (unsigned char)x;
                        result += 3;
                        for (x = 0;  x < 3 - pad;  x++) *out++ = buf[x];
                        break;
                }
                break;
        }
    }
    for (x = 0;  x < 3 - pad;  x++) *out++ = buf[x];
    return result;
}

/*
 * strip header and footer
 */
static void
PEM_strip(uint8_t *pem, int pem_len,
	  uint8_t *stripped_pem, int *real_pem_len)
{
    int i = 0;
    int j = 0;
    int real_begin = 0;
    int real_end = 0;
    /* first line is skipped */
    for (i = 0; i < pem_len; i++) {
        if (pem[i] == '\n' || pem[i] == '\r') break;
    }
    real_begin = i + 1; // the character right after \n

    // do not search \n from the exact end, 
    // which may contain one '\n' that we don't want
    // to strip the footer "---- END Public Key -----"
    for (i = pem_len - 5; i >= 0; i--) {
        if (pem[i] == '\n' || pem[i] == '\r') break;
    }
    real_end = i;
    // remove carriage return if any
    for (i = real_begin, j = 0; i < real_end; i++) {
        if (pem[i] != '\n' && pem[i] != '\r') {
            stripped_pem[j] = pem[i];
            j++;
        }
    }
    *real_pem_len = j;
}

static int
PEM2DER(const uint8_t *pem_pub, size_t pem_len, uint8_t *der, size_t *der_len)
{
    uint8_t	*pem = NULL;
    int		len = 0;
    int		tlen = 0;
    int		rc = 0;

    if (pem_pub == NULL || pem_len == 0)
        return 1;
    pem = (uint8_t*) malloc(pem_len);
    if (pem == NULL) return 1;
    memset(pem, 0, pem_len);
    PEM_strip((uint8_t*)pem_pub, pem_len, pem, &len);
    if (len <= 0) {
        free(pem);
        return -1;
    }
    tlen = raw_base64_decode(pem, der, 0, &rc);
    free(pem);
    printf("%s: length = %d\n", __func__, tlen);
    if (!rc) {
        *der_len = len;
    }
    return rc;
}

static int
cbor_bstr_from_pk_sha(const uint8_t *pub_key,
		      int key_len, cbor_item_t **hash)
{
    uint8_t	pk_sha[SHA512_DIGEST_LENGTH] = {0}; // big enough to hold hash for different algo
    uint8_t	pk_der[PUB_KEY_MAX_SIZE];
    size_t	pk_der_size_byte = 0;
    uint8_t	*temp_sha = NULL;
    size_t	sha_len = 0;
    uint8_t	*ret_sha = NULL;

    memset(pk_der, 0, PUB_KEY_MAX_SIZE);
    if (PEM2DER(pub_key, key_len, pk_der, &pk_der_size_byte)) {
	return -1;
    }
    ret_sha = SHA256(pk_der, pk_der_size_byte, pk_sha);
    sha_len = SHA256_DIGEST_LENGTH;
    if (ret_sha == NULL || memcmp(ret_sha, pk_sha, SHA256_DIGEST_LENGTH)!=0) {
	return -1;
    }
    temp_sha = (uint8_t*)malloc(sha_len);
    if (temp_sha == NULL) {
	return -1;
    }

    memcpy(temp_sha, pk_sha, sha_len);
    cbor_item_t* cbor_bstr = cbor_build_bytestring(temp_sha, sha_len);
    free(temp_sha);
    if (!cbor_bstr) {
        return -1;
    }
    *hash = cbor_bstr;
    return 0;
}

static int
make_cbor_pkhash_entry(const uint8_t *p_pub_key, size_t key_size,
            uint8_t **out_hash_entry_buf,
            size_t *out_hash_entry_buf_size)
{
    cbor_item_t* cbor_hash_entry = cbor_new_definite_array(2);
    if (!cbor_hash_entry)
        return -1;
    /* SGX : RA-TLS always generates SHA256 hash over pubkey */
    cbor_item_t* cbor_hash_alg_id = cbor_build_uint8(IANA_HASH_ALG_REGISTRY_SHA256);
    if (!cbor_hash_alg_id) {
        cbor_decref(&cbor_hash_entry);
        return -1;
    }
    cbor_item_t* cbor_hash_value;
    int ret = cbor_bstr_from_pk_sha(p_pub_key, key_size, &cbor_hash_value);
    if (ret < 0) {
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return ret;
    }
    int bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_alg_id);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return -1;
    }
    bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_value);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return -1;
    }
    /* cbor_hash_entry took ownership of hash_alg_id and hash_value cbor items */
    cbor_decref(&cbor_hash_alg_id);
    cbor_decref(&cbor_hash_value);

    uint8_t* hash_entry_buf;
    size_t hash_entry_buf_size;
    /* for the serialize_alloced buf, we need to free it seperately, as the pointer */
    /* passed to outside invoker, free it in outside invoker */
    cbor_serialize_alloc(cbor_hash_entry, &hash_entry_buf, &hash_entry_buf_size);
    if (!hash_entry_buf)  {
	return -1;
    }
    cbor_decref(&cbor_hash_entry);
    *out_hash_entry_buf = hash_entry_buf;
    *out_hash_entry_buf_size = hash_entry_buf_size;
    return 0;
}

/*
 *
 */
int
make_cbor_sgx_claims(uint8_t *pubkey, int pubksz,
		 uint8_t **claims, size_t *csz)
{
    cbor_item_t		*cbor_claims;
    cbor_item_t		*cbor_pubkey_hash_key;
    cbor_item_t		*cbor_pubkey_hash_val;
    uint8_t		*hash_entry_buf;
    size_t		hash_entry_buf_size;
    uint8_t		*claims_buf;
    size_t		claims_bufsz;
    int	rc;

    cbor_claims = cbor_new_definite_map(1);
    cbor_pubkey_hash_key = cbor_build_string("pubkey-hash");
    rc = make_cbor_pkhash_entry(pubkey, pubksz, &hash_entry_buf, &hash_entry_buf_size);
    cbor_pubkey_hash_val = cbor_build_bytestring(hash_entry_buf, hash_entry_buf_size);
    free(hash_entry_buf);
    {
	struct cbor_pair cbor_pubkey_hash_pair =
	    { .key = cbor_pubkey_hash_key,
	      .value = cbor_pubkey_hash_val };
	rc = cbor_map_add(cbor_claims, cbor_pubkey_hash_pair);
    }
    cbor_serialize_alloc(cbor_claims, &claims_buf, &claims_bufsz);
    *claims = claims_buf;
    *csz = claims_bufsz;
    return 0;
}

/*
 * make_cbor_sgx_evidence: 
 *	tagged evidence (IANA_CBOR_TAG_INTEL_TEE_QUOTE) contains
 *		cbor quote and claim	
 */
int
make_cbor_sgx_evidence(uint8_t *quote, size_t quotesz,
		   uint8_t *claim, size_t claimsz,
		   uint8_t **out_evidence, size_t *evidence_size)
{
    cbor_item_t	*evidence = NULL;
    cbor_item_t	*tagged_evidence = NULL;
    uint8_t	*ebuf;
    size_t	ebufsz;
    int	rc;

    evidence = cbor_new_definite_array(2);
    { /* cbor_evidence: quote and claim bytestring */
	cbor_item_t	*cbor_quote;
	cbor_item_t	*cbor_claims;
	cbor_quote = cbor_build_bytestring(quote, quotesz);
	cbor_claims = cbor_build_bytestring(claim, claimsz);
	rc = cbor_array_push(evidence, cbor_quote);
	rc = cbor_array_push(evidence, cbor_claims);
	cbor_decref(&cbor_claims);
	cbor_decref(&cbor_quote);
    }
    tagged_evidence = cbor_new_tag(IANA_CBOR_TAG_INTEL_TEE_QUOTE);
    cbor_tag_set_item(tagged_evidence, evidence);

    /* tagged evidence is serialized */
    cbor_serialize_alloc(tagged_evidence, &ebuf, &ebufsz);
    cbor_decref(&evidence);
    cbor_decref(&tagged_evidence);
    *out_evidence = ebuf;
    *evidence_size = ebufsz;
    return 0;
}
