/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RB_InformationReconfig_r5_H_
#define	_RB_InformationReconfig_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include "PDCP-SN-Info.h"
#include "RB-StopContinue.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PDCP_InfoReconfig_r4;
struct RLC_Info_r5;
struct RB_MappingInfo_r5;

/* RB-InformationReconfig-r5 */
typedef struct RB_InformationReconfig_r5 {
	RB_Identity_t	 rb_Identity;
	struct PDCP_InfoReconfig_r4	*pdcp_Info	/* OPTIONAL */;
	PDCP_SN_Info_t	*pdcp_SN_Info	/* OPTIONAL */;
	struct RLC_Info_r5	*rlc_Info	/* OPTIONAL */;
	struct RB_MappingInfo_r5	*rb_MappingInfo	/* OPTIONAL */;
	RB_StopContinue_t	*rb_StopContinue	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_InformationReconfig_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_InformationReconfig_r5;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PDCP-InfoReconfig-r4.h"
#include "RLC-Info-r5.h"
#include "RB-MappingInfo-r5.h"

#endif	/* _RB_InformationReconfig_r5_H_ */
#include <asn_internal.h>
