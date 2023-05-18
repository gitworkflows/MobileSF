/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_AverageRLC_BufferPayload_H_
#define	_AverageRLC_BufferPayload_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AverageRLC_BufferPayload {
	AverageRLC_BufferPayload_pla0	= 0,
	AverageRLC_BufferPayload_pla4	= 1,
	AverageRLC_BufferPayload_pla8	= 2,
	AverageRLC_BufferPayload_pla16	= 3,
	AverageRLC_BufferPayload_pla32	= 4,
	AverageRLC_BufferPayload_pla64	= 5,
	AverageRLC_BufferPayload_pla128	= 6,
	AverageRLC_BufferPayload_pla256	= 7,
	AverageRLC_BufferPayload_pla512	= 8,
	AverageRLC_BufferPayload_pla1024	= 9,
	AverageRLC_BufferPayload_pla2k	= 10,
	AverageRLC_BufferPayload_pla4k	= 11,
	AverageRLC_BufferPayload_pla8k	= 12,
	AverageRLC_BufferPayload_pla16k	= 13,
	AverageRLC_BufferPayload_pla32k	= 14,
	AverageRLC_BufferPayload_pla64k	= 15,
	AverageRLC_BufferPayload_pla128k	= 16,
	AverageRLC_BufferPayload_pla256k	= 17,
	AverageRLC_BufferPayload_pla512k	= 18,
	AverageRLC_BufferPayload_pla1024k	= 19,
	AverageRLC_BufferPayload_spare12	= 20,
	AverageRLC_BufferPayload_spare11	= 21,
	AverageRLC_BufferPayload_spare10	= 22,
	AverageRLC_BufferPayload_spare9	= 23,
	AverageRLC_BufferPayload_spare8	= 24,
	AverageRLC_BufferPayload_spare7	= 25,
	AverageRLC_BufferPayload_spare6	= 26,
	AverageRLC_BufferPayload_spare5	= 27,
	AverageRLC_BufferPayload_spare4	= 28,
	AverageRLC_BufferPayload_spare3	= 29,
	AverageRLC_BufferPayload_spare2	= 30,
	AverageRLC_BufferPayload_spare1	= 31
} e_AverageRLC_BufferPayload;

/* AverageRLC-BufferPayload */
typedef long	 AverageRLC_BufferPayload_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AverageRLC_BufferPayload;
asn_struct_free_f AverageRLC_BufferPayload_free;
asn_struct_print_f AverageRLC_BufferPayload_print;
asn_constr_check_f AverageRLC_BufferPayload_constraint;
ber_type_decoder_f AverageRLC_BufferPayload_decode_ber;
der_type_encoder_f AverageRLC_BufferPayload_encode_der;
xer_type_decoder_f AverageRLC_BufferPayload_decode_xer;
xer_type_encoder_f AverageRLC_BufferPayload_encode_xer;
per_type_decoder_f AverageRLC_BufferPayload_decode_uper;
per_type_encoder_f AverageRLC_BufferPayload_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AverageRLC_BufferPayload_H_ */
#include <asn_internal.h>
