/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_FrameType_H_
#define	_DL_FrameType_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_FrameType {
	DL_FrameType_dl_FrameTypeA	= 0,
	DL_FrameType_dl_FrameTypeB	= 1
} e_DL_FrameType;

/* DL-FrameType */
typedef long	 DL_FrameType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_FrameType;
asn_struct_free_f DL_FrameType_free;
asn_struct_print_f DL_FrameType_print;
asn_constr_check_f DL_FrameType_constraint;
ber_type_decoder_f DL_FrameType_decode_ber;
der_type_encoder_f DL_FrameType_encode_der;
xer_type_decoder_f DL_FrameType_decode_xer;
xer_type_encoder_f DL_FrameType_encode_xer;
per_type_decoder_f DL_FrameType_decode_uper;
per_type_encoder_f DL_FrameType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_FrameType_H_ */
#include <asn_internal.h>
