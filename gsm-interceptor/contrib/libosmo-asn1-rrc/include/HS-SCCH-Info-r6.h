/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_HS_SCCH_Info_r6_H_
#define	_HS_SCCH_Info_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SecondaryScramblingCode.h"
#include "HS-SCCH-Codes.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>
#include <NativeInteger.h>
#include "HS-SICH-Power-Control-Info-TDD384.h"
#include "DHS-Sync.h"
#include "Bler-Target.h"
#include <NativeEnumerated.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HS_SCCH_Info_r6__modeSpecificInfo_PR {
	HS_SCCH_Info_r6__modeSpecificInfo_PR_NOTHING,	/* No components present */
	HS_SCCH_Info_r6__modeSpecificInfo_PR_fdd,
	HS_SCCH_Info_r6__modeSpecificInfo_PR_tdd
} HS_SCCH_Info_r6__modeSpecificInfo_PR;
typedef enum HS_SCCH_Info_r6__modeSpecificInfo__tdd_PR {
	HS_SCCH_Info_r6__modeSpecificInfo__tdd_PR_NOTHING,	/* No components present */
	HS_SCCH_Info_r6__modeSpecificInfo__tdd_PR_tdd384,
	HS_SCCH_Info_r6__modeSpecificInfo__tdd_PR_tdd128
} HS_SCCH_Info_r6__modeSpecificInfo__tdd_PR;
typedef enum HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__tpc_step_size {
	HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__tpc_step_size_s1	= 0,
	HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__tpc_step_size_s2	= 1,
	HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__tpc_step_size_s3	= 2,
	HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__tpc_step_size_spare1	= 3
} e_HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__tpc_step_size;

/* Forward declarations */
struct HS_SCCH_TDD384_r6;
struct HS_SCCH_TDD128_r6;

/* HS-SCCH-Info-r6 */
typedef struct HS_SCCH_Info_r6 {
	struct HS_SCCH_Info_r6__modeSpecificInfo {
		HS_SCCH_Info_r6__modeSpecificInfo_PR present;
		union HS_SCCH_Info_r6__modeSpecificInfo_u {
			struct HS_SCCH_Info_r6__modeSpecificInfo__fdd {
				struct HS_SCCH_Info_r6__modeSpecificInfo__fdd__hS_SCCHChannelisationCodeInfo {
					A_SEQUENCE_OF(HS_SCCH_Codes_t) list;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} hS_SCCHChannelisationCodeInfo;
				SecondaryScramblingCode_t	*dl_ScramblingCode	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct HS_SCCH_Info_r6__modeSpecificInfo__tdd {
				HS_SCCH_Info_r6__modeSpecificInfo__tdd_PR present;
				union HS_SCCH_Info_r6__modeSpecificInfo__tdd_u {
					struct HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd384 {
						long	 nack_ack_power_offset;
						HS_SICH_Power_Control_Info_TDD384_t	 hs_SICH_PowerControl_Info;
						DHS_Sync_t	*dhs_sync	/* OPTIONAL */;
						Bler_Target_t	 bler_target;
						struct HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd384__hS_SCCH_SetConfiguration {
							A_SEQUENCE_OF(struct HS_SCCH_TDD384_r6) list;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} hS_SCCH_SetConfiguration;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} tdd384;
					struct HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128 {
						long	 nack_ack_power_offset;
						long	 power_level_HSSICH;
						long	 tpc_step_size;
						Bler_Target_t	 bler_target;
						struct HS_SCCH_Info_r6__modeSpecificInfo__tdd__tdd128__hS_SCCH_SetConfiguration {
							A_SEQUENCE_OF(struct HS_SCCH_TDD128_r6) list;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} hS_SCCH_SetConfiguration;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} tdd128;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HS_SCCH_Info_r6_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_tpc_step_size_18;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_HS_SCCH_Info_r6;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "HS-SCCH-TDD384-r6.h"
#include "HS-SCCH-TDD128-r6.h"

#endif	/* _HS_SCCH_Info_r6_H_ */
#include <asn_internal.h>
