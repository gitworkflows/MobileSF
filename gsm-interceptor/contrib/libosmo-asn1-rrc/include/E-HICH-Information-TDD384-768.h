/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_E_HICH_Information_TDD384_768_H_
#define	_E_HICH_Information_TDD384_768_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <NativeEnumerated.h>
#include "DL-TS-ChannelisationCode.h"
#include "DL-TS-ChannelisationCode-VHCR.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum E_HICH_Information_TDD384_768__modeSpecificInfo_PR {
	E_HICH_Information_TDD384_768__modeSpecificInfo_PR_NOTHING,	/* No components present */
	E_HICH_Information_TDD384_768__modeSpecificInfo_PR_tdd384,
	E_HICH_Information_TDD384_768__modeSpecificInfo_PR_tdd768
} E_HICH_Information_TDD384_768__modeSpecificInfo_PR;
typedef enum E_HICH_Information_TDD384_768__burst_Type {
	E_HICH_Information_TDD384_768__burst_Type_type1	= 0,
	E_HICH_Information_TDD384_768__burst_Type_type2	= 1
} e_E_HICH_Information_TDD384_768__burst_Type;
typedef enum E_HICH_Information_TDD384_768__midamble_Allocation_Mode {
	E_HICH_Information_TDD384_768__midamble_Allocation_Mode_default	= 0,
	E_HICH_Information_TDD384_768__midamble_Allocation_Mode_common	= 1
} e_E_HICH_Information_TDD384_768__midamble_Allocation_Mode;

/* E-HICH-Information-TDD384-768 */
typedef struct E_HICH_Information_TDD384_768 {
	long	 n_E_HICH;
	long	 tS_Number;
	struct E_HICH_Information_TDD384_768__modeSpecificInfo {
		E_HICH_Information_TDD384_768__modeSpecificInfo_PR present;
		union E_HICH_Information_TDD384_768__modeSpecificInfo_u {
			DL_TS_ChannelisationCode_t	 tdd384;
			DL_TS_ChannelisationCode_VHCR_t	 tdd768;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	long	 burst_Type;
	long	 midamble_Allocation_Mode;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_HICH_Information_TDD384_768_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_burst_Type_7;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_midamble_Allocation_Mode_10;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_E_HICH_Information_TDD384_768;

#ifdef __cplusplus
}
#endif

#endif	/* _E_HICH_Information_TDD384_768_H_ */
#include <asn_internal.h>
