/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_AICH_TransmissionTiming_H_
#define	_AICH_TransmissionTiming_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AICH_TransmissionTiming {
	AICH_TransmissionTiming_e0	= 0,
	AICH_TransmissionTiming_e1	= 1
} e_AICH_TransmissionTiming;

/* AICH-TransmissionTiming */
typedef long	 AICH_TransmissionTiming_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AICH_TransmissionTiming;
asn_struct_free_f AICH_TransmissionTiming_free;
asn_struct_print_f AICH_TransmissionTiming_print;
asn_constr_check_f AICH_TransmissionTiming_constraint;
ber_type_decoder_f AICH_TransmissionTiming_decode_ber;
der_type_encoder_f AICH_TransmissionTiming_encode_der;
xer_type_decoder_f AICH_TransmissionTiming_decode_xer;
xer_type_encoder_f AICH_TransmissionTiming_encode_xer;
per_type_decoder_f AICH_TransmissionTiming_decode_uper;
per_type_encoder_f AICH_TransmissionTiming_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AICH_TransmissionTiming_H_ */
#include <asn_internal.h>
