#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <stdint.h>

#define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N)}

/* See https://kib.kiev.ua/x86docs/Intel/TDX/348987-001.pdf
 * 1.2.840.113741.1337.2
 *	 1	iso
 *	 2	member-body
 *	 840	us
 *	 113741	Intel
 *	 1337	SGX
 * 2	Quote
 */

/* SGX quote 1.2.840.113741.1337.2 */
uint8_t ias_response_body_oid[]    = OID(0x02);
/* SGX enclave identity 1.2.840.113741.1337.3 */
uint8_t ias_root_cert_oid[]        = OID(0x03);
/* SGX platform identity 1.2.840.113741.1337.4 */
uint8_t ias_leaf_cert_oid[]        = OID(0x04);
/* SGX report signature 1.2.840.113741.1337.5 */
uint8_t ias_report_signature_oid[] = OID(0x05);

size_t ias_oid_len = sizeof(ias_response_body_oid);

int
main()
{
    char	buf[1024];
    ASN1_OBJECT *obj;
    obj = ASN1_OBJECT_create(0, /* nid */
			     ias_response_body_oid + 2, /* data */
			     ias_oid_len - 2, /* len */
			     0, /* sn */
			     0 /* ln */ );
    OBJ_obj2txt(buf, sizeof(buf), obj, 0);
    printf("oid = %s\n", buf);
    /* oid = 1.2.840.113741.1337.2 */
    return 0;
}
