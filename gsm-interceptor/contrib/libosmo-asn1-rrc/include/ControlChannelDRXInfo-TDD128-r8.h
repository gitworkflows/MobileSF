/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_ControlChannelDRXInfo_TDD128_r8_H_
#define	_ControlChannelDRXInfo_TDD128_r8_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EnablingDelay-TDD128.h"
#include <constr_SEQUENCE.h>
#include "HS-SCCH-DRX-Info-TDD128.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_PR {
	ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_PR_NOTHING,	/* No components present */
	ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_PR_continue,
	ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_PR_newOperation
} ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_PR;

/* Forward declarations */
struct E_AGCH_DRX_Info_TDD128;

/* ControlChannelDRXInfo-TDD128-r8 */
typedef struct ControlChannelDRXInfo_TDD128_r8 {
	struct ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation {
		ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_PR present;
		union ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation_u {
			struct ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation__Continue {
				EnablingDelay_TDD128_t	*enablingDelay	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} Continue;
			struct ControlChannelDRXInfo_TDD128_r8__controlChannelDrxOperation__newOperation {
				HS_SCCH_DRX_Info_TDD128_t	 hS_SCCH_Drx_Info;
				struct E_AGCH_DRX_Info_TDD128	*e_AGCH_Drx_Info	/* OPTIONAL */;
				EnablingDelay_TDD128_t	 enablingDelay;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} newOperation;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} controlChannelDrxOperation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ControlChannelDRXInfo_TDD128_r8_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ControlChannelDRXInfo_TDD128_r8;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "E-AGCH-DRX-Info-TDD128.h"

#endif	/* _ControlChannelDRXInfo_TDD128_r8_H_ */
#include <asn_internal.h>
