/*
 * attestation evidence data tags,
 * https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
 */
#define TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG 60000
#define IANA_CBOR_TAG_INTEL_TEE_QUOTE	60000
#define IANA_CBOR_TAG_INTEL_TEE_REPORT	60001
#define IANA_CBOR_TAG_INTEL_SGX_REPORT	60002
/*
 *
 */
#define X509_OID_FOR_QUOTE_STRING "1.2.840.113741.1.13.1"
/*
 * TCG DICE(Device Identifier Composition Engine）definition
 *	2.23.133.5.4.9  -- "tagged evidence"
 * https://datatracker.ietf.org/doc/draft-ietf-rats-evidence-trans/00/
 */
#define TCG_DICE_TAGGED_OID_STR "2.23.133.5.4.9"
/*
 * hash IDs per IANA:
 *  https://www.iana.org/assignments/named-information/named-information.xhtml
 */
#define PUB_KEY_MAX_SIZE 626
#define IANA_HASH_ALG_REGISTRY_RESERVED 0
#define IANA_HASH_ALG_REGISTRY_SHA256   1
#define IANA_HASH_ALG_REGISTRY_SHA384   7
#define IANA_HASH_ALG_REGISTRY_SHA512   8
#define RAW_QUOTE_MAX_SIZE 8192
#define CBOR_QUOTE_MAX_SIZE ((RAW_QUOTE_MAX_SIZE)*2)
#define QUOTE_MIN_SIZE 1020

#define TLSRA_LIBCALL0(label, val, lib)		\
do {				\
    val = lib;			\
    if (val == 0) {		\
	goto label;		\
    }				\
} while(0)

#define TLSRA_SYSCALL(label, val, lib, msg)	\
do {				\
    val = lib;			\
    if (val != 0) {		\
	perror(msg);		\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALL0(label, val, lib)		\
do {				\
    val = lib;			\
    if (val == 0) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALL1(label, val, lib) \
do {				\
    val = lib;			\
    if (val != 1) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALLP(label, val, lib)		\
do {				\
    val = lib;			\
    if (val <= 0) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)

extern int	make_cbor_sgx_claims(uint8_t *pubkey, int pubk_sz,
				     uint8_t **claims, size_t *cl_sz);
extern int	make_cbor_sgx_evidence(uint8_t *quote, size_t quote_sz,
				       uint8_t *claim, size_t claim_sz,
				       uint8_t **o_evd, size_t *o_evd_sz);
