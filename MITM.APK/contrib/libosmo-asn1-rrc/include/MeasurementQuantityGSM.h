/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MeasurementQuantityGSM_H_
#define	_MeasurementQuantityGSM_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MeasurementQuantityGSM {
	MeasurementQuantityGSM_gsm_CarrierRSSI	= 0,
	MeasurementQuantityGSM_dummy	= 1
} e_MeasurementQuantityGSM;

/* MeasurementQuantityGSM */
typedef long	 MeasurementQuantityGSM_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementQuantityGSM;
asn_struct_free_f MeasurementQuantityGSM_free;
asn_struct_print_f MeasurementQuantityGSM_print;
asn_constr_check_f MeasurementQuantityGSM_constraint;
ber_type_decoder_f MeasurementQuantityGSM_decode_ber;
der_type_encoder_f MeasurementQuantityGSM_encode_der;
xer_type_decoder_f MeasurementQuantityGSM_decode_xer;
xer_type_encoder_f MeasurementQuantityGSM_encode_xer;
per_type_decoder_f MeasurementQuantityGSM_decode_uper;
per_type_encoder_f MeasurementQuantityGSM_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementQuantityGSM_H_ */
#include <asn_internal.h>
