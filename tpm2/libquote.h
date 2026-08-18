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

extern int
make_tpm2_quote(uint8_t *nonce, int nsize,
		int alg, uint8_t *pcrs, int count, uint32_t handle,
		struct tpm2_quote *t_quote);
