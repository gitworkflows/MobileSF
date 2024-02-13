/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MaxNoDPDCH_BitsTransmitted_H_
#define	_MaxNoDPDCH_BitsTransmitted_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MaxNoDPDCH_BitsTransmitted {
	MaxNoDPDCH_BitsTransmitted_b600	= 0,
	MaxNoDPDCH_BitsTransmitted_b1200	= 1,
	MaxNoDPDCH_BitsTransmitted_b2400	= 2,
	MaxNoDPDCH_BitsTransmitted_b4800	= 3,
	MaxNoDPDCH_BitsTransmitted_b9600	= 4,
	MaxNoDPDCH_BitsTransmitted_b19200	= 5,
	MaxNoDPDCH_BitsTransmitted_b28800	= 6,
	MaxNoDPDCH_BitsTransmitted_b38400	= 7,
	MaxNoDPDCH_BitsTransmitted_b48000	= 8,
	MaxNoDPDCH_BitsTransmitted_b57600	= 9
} e_MaxNoDPDCH_BitsTransmitted;

/* MaxNoDPDCH-BitsTransmitted */
typedef long	 MaxNoDPDCH_BitsTransmitted_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MaxNoDPDCH_BitsTransmitted;
asn_struct_free_f MaxNoDPDCH_BitsTransmitted_free;
asn_struct_print_f MaxNoDPDCH_BitsTransmitted_print;
asn_constr_check_f MaxNoDPDCH_BitsTransmitted_constraint;
ber_type_decoder_f MaxNoDPDCH_BitsTransmitted_decode_ber;
der_type_encoder_f MaxNoDPDCH_BitsTransmitted_encode_der;
xer_type_decoder_f MaxNoDPDCH_BitsTransmitted_decode_xer;
xer_type_encoder_f MaxNoDPDCH_BitsTransmitted_encode_xer;
per_type_decoder_f MaxNoDPDCH_BitsTransmitted_decode_uper;
per_type_encoder_f MaxNoDPDCH_BitsTransmitted_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _MaxNoDPDCH_BitsTransmitted_H_ */
#include <asn_internal.h>
