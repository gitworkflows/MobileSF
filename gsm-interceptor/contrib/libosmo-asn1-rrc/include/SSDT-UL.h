/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SSDT_UL_H_
#define	_SSDT_UL_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SSDT_UL {
	SSDT_UL_ul	= 0,
	SSDT_UL_ul_AndDL	= 1
} e_SSDT_UL;

/* SSDT-UL */
typedef long	 SSDT_UL_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SSDT_UL;
asn_struct_free_f SSDT_UL_free;
asn_struct_print_f SSDT_UL_print;
asn_constr_check_f SSDT_UL_constraint;
ber_type_decoder_f SSDT_UL_decode_ber;
der_type_encoder_f SSDT_UL_encode_der;
xer_type_decoder_f SSDT_UL_decode_xer;
xer_type_encoder_f SSDT_UL_encode_xer;
per_type_decoder_f SSDT_UL_decode_uper;
per_type_encoder_f SSDT_UL_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _SSDT_UL_H_ */
#include <asn_internal.h>
