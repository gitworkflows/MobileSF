/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_Tutran_Ganss_DriftRate_H_
#define	_Tutran_Ganss_DriftRate_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Tutran_Ganss_DriftRate {
	Tutran_Ganss_DriftRate_ugdr0	= 0,
	Tutran_Ganss_DriftRate_ugdr1	= 1,
	Tutran_Ganss_DriftRate_ugdr2	= 2,
	Tutran_Ganss_DriftRate_ugdr5	= 3,
	Tutran_Ganss_DriftRate_ugdr10	= 4,
	Tutran_Ganss_DriftRate_ugdr15	= 5,
	Tutran_Ganss_DriftRate_ugdr25	= 6,
	Tutran_Ganss_DriftRate_ugdr50	= 7,
	Tutran_Ganss_DriftRate_ugdr_1	= 8,
	Tutran_Ganss_DriftRate_ugdr_2	= 9,
	Tutran_Ganss_DriftRate_ugdr_5	= 10,
	Tutran_Ganss_DriftRate_ugdr_10	= 11,
	Tutran_Ganss_DriftRate_ugdr_15	= 12,
	Tutran_Ganss_DriftRate_ugdr_25	= 13,
	Tutran_Ganss_DriftRate_ugdr_50	= 14,
	Tutran_Ganss_DriftRate_spare	= 15
} e_Tutran_Ganss_DriftRate;

/* Tutran-Ganss-DriftRate */
typedef long	 Tutran_Ganss_DriftRate_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Tutran_Ganss_DriftRate;
asn_struct_free_f Tutran_Ganss_DriftRate_free;
asn_struct_print_f Tutran_Ganss_DriftRate_print;
asn_constr_check_f Tutran_Ganss_DriftRate_constraint;
ber_type_decoder_f Tutran_Ganss_DriftRate_decode_ber;
der_type_encoder_f Tutran_Ganss_DriftRate_encode_der;
xer_type_decoder_f Tutran_Ganss_DriftRate_decode_xer;
xer_type_encoder_f Tutran_Ganss_DriftRate_encode_xer;
per_type_decoder_f Tutran_Ganss_DriftRate_decode_uper;
per_type_encoder_f Tutran_Ganss_DriftRate_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Tutran_Ganss_DriftRate_H_ */
#include <asn_internal.h>
