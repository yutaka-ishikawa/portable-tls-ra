/*
 * Atester Daemon
 *   request: nonce
 *   reply: CBOR MAP [ "nonce":bstr, "tpm2_quote": CBOR MAP ]
 *		where tpm2_quote CBOR MAP
 *		     ["quote":TPM2quote, "sign":bstr, "app-hash":bstr]
 *		TPM2quote: extraData = extend(nonce || app-hash)
 *			   PCRs
 */
#define TPMD_REQ_HELLO	0x0001
#define TPMD_RPL_HELLO	0x0101
#define TPMD_REQ_ATTEST	0x0002
#define TPMD_RPL_ATTEST	0x0102
#define TPMD_AUX_OK	0x0
#define TPMD_AUX_ERR	0x1

/*
 * data is cbor
 */
struct tpmd_packet {
    uint16_t	cmd;
    uint16_t	aux;
    uint32_t	len;	/* payload length */
    uint8_t	data[];
} __attribute__((packed));
