/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_E_DCH_RL_InfoOtherCell_r11_H_
#define	_E_DCH_RL_InfoOtherCell_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PrimaryCPICH-Info.h"
#include "E-HICH-Information-r11.h"
#include <NULL.h>
#include <constr_CHOICE.h>
#include "E-RGCH-Information.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR {
	E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR_NOTHING,	/* No components present */
	E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR_e_HICH_Information,
	E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR_releaseIndicator,
	E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR_secondaryReleaseIndicator
} E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR;
typedef enum E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_PR {
	E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_PR_NOTHING,	/* No components present */
	E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_PR_e_RGCH_Information,
	E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_PR_releaseIndicator
} E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_PR;

/* E-DCH-RL-InfoOtherCell-r11 */
typedef struct E_DCH_RL_InfoOtherCell_r11 {
	PrimaryCPICH_Info_t	 primaryCPICH_Info;
	struct E_DCH_RL_InfoOtherCell_r11__e_HICH_Info {
		E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_PR present;
		union E_DCH_RL_InfoOtherCell_r11__e_HICH_Info_u {
			E_HICH_Information_r11_t	 e_HICH_Information;
			NULL_t	 releaseIndicator;
			NULL_t	 secondaryReleaseIndicator;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *e_HICH_Info;
	struct E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info {
		E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_PR present;
		union E_DCH_RL_InfoOtherCell_r11__e_RGCH_Info_u {
			E_RGCH_Information_t	 e_RGCH_Information;
			NULL_t	 releaseIndicator;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *e_RGCH_Info;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_DCH_RL_InfoOtherCell_r11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_DCH_RL_InfoOtherCell_r11;

#ifdef __cplusplus
}
#endif

#endif	/* _E_DCH_RL_InfoOtherCell_r11_H_ */
#include <asn_internal.h>
