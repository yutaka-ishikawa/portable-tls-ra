```sh
$ sudo apt install libseccomp-dev
$ sudo apt install libcbor-dev
```

## Quote
```sh
make_tpm2_quote(nonce, nsize,
			 TPM2_ALG_SHA256, pcrs, count, 0x81018001,
			 &t_quote);
```
marashaled quote is stored in t_quote.quote_sign, whose size is
t_quote.qsize.  marashaled signature is stored in
&t_quote.quote_sign[t_quote.qsize], whose size is t_quote.ssize.

## Verify
unmarshal_sign()


/usr/include/tss2/tss2_tpm2_types.h

struct TPM2B_ATTEST {
    UINT16 size;
    BYTE attestationData[sizeof(TPMS_ATTEST)];
};

/* Definition of TPMS_ATTEST Structure <OUT> */
typedef struct TPMS_ATTEST TPMS_ATTEST;
struct TPMS_ATTEST {
    TPM2_GENERATED magic;       /* the indication that this structure was created by a TPM always TPM2_GENERATED_VALUE */
    TPMI_ST_ATTEST type;        /* type of the attestation structure */
    TPM2B_NAME qualifiedSigner; /* Qualified Name of the signing key */
    TPM2B_DATA extraData;       /* external information supplied by caller. NOTE A TPM2B_DATA structure provides room for a digest and a method indicator to indicate the components of the digest. The definition of this method indicator is outside the scope of this specification. */
    TPMS_CLOCK_INFO clockInfo;  /* Clock resetCount restartCount and Safe */
    UINT64 firmwareVersion;     /* TPM vendor-specific value identifying the version number of the firmware */
    TPMU_ATTEST attested;       /* the type-specific attestation information */
};

struct TPMT_SIGNATURE {
    TPMI_ALG_SIG_SCHEME sigAlg; /* selector of the algorithm used to construct the signature */
    TPMU_SIGNATURE signature;   /* This shall be the actual signature information. */
};

typedef struct TPMS_QUOTE_INFO TPMS_QUOTE_INFO;
struct TPMS_QUOTE_INFO {
    TPML_PCR_SELECTION pcrSelect; /* information on algID PCR selected and digest */
    TPM2B_DIGEST pcrDigest;       /* digest of the selected PCR using the hash of the signing key */
};