/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_T_304_H_
#define	_T_304_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum T_304 {
	T_304_ms100	= 0,
	T_304_ms200	= 1,
	T_304_ms400	= 2,
	T_304_ms1000	= 3,
	T_304_ms2000	= 4,
	T_304_spare3	= 5,
	T_304_spare2	= 6,
	T_304_spare1	= 7
} e_T_304;

/* T-304 */
typedef long	 T_304_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_T_304;
asn_struct_free_f T_304_free;
asn_struct_print_f T_304_print;
asn_constr_check_f T_304_constraint;
ber_type_decoder_f T_304_decode_ber;
der_type_encoder_f T_304_encode_der;
xer_type_decoder_f T_304_decode_xer;
xer_type_encoder_f T_304_encode_xer;
per_type_decoder_f T_304_decode_uper;
per_type_encoder_f T_304_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _T_304_H_ */
#include <asn_internal.h>
