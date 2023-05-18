/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_ReleaseCause_H_
#define	_ReleaseCause_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ReleaseCause {
	ReleaseCause_normalEvent	= 0,
	ReleaseCause_unspecified	= 1,
	ReleaseCause_pre_emptiveRelease	= 2,
	ReleaseCause_congestion	= 3,
	ReleaseCause_re_establishmentReject	= 4,
	ReleaseCause_directedsignallingconnectionre_establishment	= 5,
	ReleaseCause_userInactivity	= 6,
	ReleaseCause_spare	= 7
} e_ReleaseCause;

/* ReleaseCause */
typedef long	 ReleaseCause_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ReleaseCause;
asn_struct_free_f ReleaseCause_free;
asn_struct_print_f ReleaseCause_print;
asn_constr_check_f ReleaseCause_constraint;
ber_type_decoder_f ReleaseCause_decode_ber;
der_type_encoder_f ReleaseCause_encode_der;
xer_type_decoder_f ReleaseCause_decode_xer;
xer_type_encoder_f ReleaseCause_encode_xer;
per_type_decoder_f ReleaseCause_decode_uper;
per_type_encoder_f ReleaseCause_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ReleaseCause_H_ */
#include <asn_internal.h>
