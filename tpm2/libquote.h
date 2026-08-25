/*
 * In the current implementation, TPM2 is only assumed other than Intel DSCP
 */
#define MAX_QUOTESIZE	256
#define SIGNSIZE	518 /* this value is sizeof (TPMT_SIGNATURE) */
#define QUOTE_NONE	0
#define QUOTE_TPM2	1
/*
 * trinity_quote contains marasahlled quote and signature
 */
struct tpm2_quote {
    int16_t	qtype;	/* quote type: e.g. QUOTE_TPM2 */
    int16_t	qsize;
    int16_t	ssize;
    uint8_t	quote[MAX_QUOTESIZE]; /* marashal data */
    uint8_t	sign[SIGNSIZE]; /* marashal data */
};

extern int	hash_extend_sha256(const uint8_t *old_hash, const uint8_t *digest,
				   uint8_t *new_hash);
extern int	make_tpm2_quote(uint8_t *nonce, int nsize,
				int alg, uint8_t *pcrs, int count, uint32_t handle,
				struct tpm2_quote *t_quote);
extern void	show_tpm2quote_info(const char *msg, TPMS_QUOTE_INFO *qinfo);
extern int	verify_tpm2_quote(const uint8_t *s_quoted, int sq_size,
				  const TPMT_SIGNATURE *sig, EVP_PKEY *ak_pubkey);
extern int	comp_pcr_selection(const TPML_PCR_SELECTION *a,
				   const TPML_PCR_SELECTION *b);
