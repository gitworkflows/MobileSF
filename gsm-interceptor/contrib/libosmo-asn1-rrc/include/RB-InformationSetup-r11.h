/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RB_InformationSetup_r11_H_
#define	_RB_InformationSetup_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RB-Identity.h"
#include "RLC-InfoChoice-r11.h"
#include "RB-MappingInfo-r8.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PDCP_Info_r4;

/* RB-InformationSetup-r11 */
typedef struct RB_InformationSetup_r11 {
	RB_Identity_t	 rb_Identity;
	struct PDCP_Info_r4	*pdcp_Info	/* OPTIONAL */;
	RLC_InfoChoice_r11_t	 rlc_InfoChoice;
	RB_MappingInfo_r8_t	 rb_MappingInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RB_InformationSetup_r11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RB_InformationSetup_r11;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PDCP-Info-r4.h"

#endif	/* _RB_InformationSetup_r11_H_ */
#include <asn_internal.h>
