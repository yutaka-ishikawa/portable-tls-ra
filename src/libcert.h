#define VERIFIED_QUOTE		0x01
#define VERIFIED_EVIDENCE	0x02

/*
 * attestation evidence data tags,
 * https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
 */
#define TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG 60000
#define TCG_DICE_TAGGED_EVIDENCE_TEE_TPM2_CBOR_TAG 60005
#define IANA_CBOR_TAG_INTEL_TEE_QUOTE	60000
#define IANA_CBOR_TAG_INTEL_TEE_REPORT	60001
#define IANA_CBOR_TAG_INTEL_SGX_REPORT	60002
/* The following TAGs are experimental only */
#define LOCAL_CBOR_TAG_INTEL_TEE_TPM2_QUOTE 60004 /* Intel SGX with TPM2 */
#define LOCAL_CBOR_TAG_INTEL_TPM2_QUOTE 60005 /* Intel TPM2 */
/* End of Local definition */
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_RESERVED 0
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256   1
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384   7
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA512   8
/*
 * Our definition for TRINITY
 *	using the unassiagned number at the time of 2026-07-20
 *	      See https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
 */
#define IANA_CBOR_TAG_TRINITY_TPM2_QUOTE	60011
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

extern int	make_cbor_sgx_claims(uint8_t *pubkey, int pubk_sz,
				     uint8_t **claims, size_t *cl_sz);
extern int	make_cbor_sgx_evidence(uint8_t *quote, size_t quote_sz,
				       uint8_t *claim, size_t claim_sz,
				       uint8_t **o_evd, size_t *o_evd_sz,
				       int ctype);
extern int	make_cbor_tpm2_claims(uint8_t *pubkey, int pubk_sz,
				      uint8_t *nonce, int nsize,
				      uint8_t **claims, size_t *cl_sz);
extern int	make_cbor_tpm2_claims_from_enclave(uint8_t *pubkey, int pubksz,
						   uint8_t *nonce, int nsize,
						   uint8_t **claims, size_t *csz);
/**/
extern EVP_PKEY	*make_keypair(uint8_t **pbkey, int *pbsz,
			      uint8_t **prkey, int *prsz);
extern int	make_certificate_evidence(uint8_t *pubkey, int pubksz,
					  uint8_t *nonce, int nsize,
					  uint8_t **quote, uint32_t *qsz,
					  uint8_t **evidence, size_t *evsz);
extern int	make_x509cert(X509 **px509, EVP_PKEY *pkey,
			      uint8_t *quote, int qtsz,
			      uint8_t *evidence, int evsz);
extern int	verify_cert(X509 *x509, uint8_t *nonce);


#define CERT_DEBUG	if (cert_dflag)
#define CERT_VFLAG	if (cert_vflag)
