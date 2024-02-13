/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_Feedback_cycle_H_
#define	_Feedback_cycle_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Feedback_cycle {
	Feedback_cycle_fc0	= 0,
	Feedback_cycle_fc2	= 1,
	Feedback_cycle_fc4	= 2,
	Feedback_cycle_fc8	= 3,
	Feedback_cycle_fc10	= 4,
	Feedback_cycle_fc20	= 5,
	Feedback_cycle_fc40	= 6,
	Feedback_cycle_fc80	= 7,
	Feedback_cycle_fc160	= 8
} e_Feedback_cycle;

/* Feedback-cycle */
typedef long	 Feedback_cycle_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Feedback_cycle;
asn_struct_free_f Feedback_cycle_free;
asn_struct_print_f Feedback_cycle_print;
asn_constr_check_f Feedback_cycle_constraint;
ber_type_decoder_f Feedback_cycle_decode_ber;
der_type_encoder_f Feedback_cycle_encode_der;
xer_type_decoder_f Feedback_cycle_decode_xer;
xer_type_encoder_f Feedback_cycle_encode_xer;
per_type_decoder_f Feedback_cycle_decode_uper;
per_type_encoder_f Feedback_cycle_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Feedback_cycle_H_ */
#include <asn_internal.h>
