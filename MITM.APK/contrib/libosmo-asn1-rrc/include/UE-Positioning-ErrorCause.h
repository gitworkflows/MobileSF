/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_Positioning_ErrorCause_H_
#define	_UE_Positioning_ErrorCause_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_Positioning_ErrorCause {
	UE_Positioning_ErrorCause_notEnoughOTDOA_Cells	= 0,
	UE_Positioning_ErrorCause_notEnoughGPS_Satellites	= 1,
	UE_Positioning_ErrorCause_assistanceDataMissing	= 2,
	UE_Positioning_ErrorCause_notAccomplishedGPS_TimingOfCellFrames	= 3,
	UE_Positioning_ErrorCause_undefinedError	= 4,
	UE_Positioning_ErrorCause_requestDeniedByUser	= 5,
	UE_Positioning_ErrorCause_notProcessedAndTimeout	= 6,
	UE_Positioning_ErrorCause_referenceCellNotServingCell	= 7
} e_UE_Positioning_ErrorCause;

/* UE-Positioning-ErrorCause */
typedef long	 UE_Positioning_ErrorCause_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_ErrorCause;
asn_struct_free_f UE_Positioning_ErrorCause_free;
asn_struct_print_f UE_Positioning_ErrorCause_print;
asn_constr_check_f UE_Positioning_ErrorCause_constraint;
ber_type_decoder_f UE_Positioning_ErrorCause_decode_ber;
der_type_encoder_f UE_Positioning_ErrorCause_encode_der;
xer_type_decoder_f UE_Positioning_ErrorCause_decode_xer;
xer_type_encoder_f UE_Positioning_ErrorCause_encode_xer;
per_type_decoder_f UE_Positioning_ErrorCause_decode_uper;
per_type_encoder_f UE_Positioning_ErrorCause_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_ErrorCause_H_ */
#include <asn_internal.h>
