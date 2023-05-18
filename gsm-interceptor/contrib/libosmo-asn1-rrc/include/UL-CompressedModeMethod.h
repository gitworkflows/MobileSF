/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UL_CompressedModeMethod_H_
#define	_UL_CompressedModeMethod_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_CompressedModeMethod {
	UL_CompressedModeMethod_sf_2	= 0,
	UL_CompressedModeMethod_higherLayerScheduling	= 1
} e_UL_CompressedModeMethod;

/* UL-CompressedModeMethod */
typedef long	 UL_CompressedModeMethod_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_CompressedModeMethod;
asn_struct_free_f UL_CompressedModeMethod_free;
asn_struct_print_f UL_CompressedModeMethod_print;
asn_constr_check_f UL_CompressedModeMethod_constraint;
ber_type_decoder_f UL_CompressedModeMethod_decode_ber;
der_type_encoder_f UL_CompressedModeMethod_encode_der;
xer_type_decoder_f UL_CompressedModeMethod_decode_xer;
xer_type_encoder_f UL_CompressedModeMethod_encode_xer;
per_type_decoder_f UL_CompressedModeMethod_decode_uper;
per_type_encoder_f UL_CompressedModeMethod_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_CompressedModeMethod_H_ */
#include <asn_internal.h>
