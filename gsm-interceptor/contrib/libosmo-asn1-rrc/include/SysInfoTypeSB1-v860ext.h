/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SysInfoTypeSB1_v860ext_H_
#define	_SysInfoTypeSB1_v860ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExtSIBTypeInfoSchedulingInfo_List2;
struct ExtGANSS_SIBTypeInfoSchedulingInfoList;

/* SysInfoTypeSB1-v860ext */
typedef struct SysInfoTypeSB1_v860ext {
	struct ExtSIBTypeInfoSchedulingInfo_List2	*extSIBTypeInfoSchedulingInfo_List	/* OPTIONAL */;
	struct ExtGANSS_SIBTypeInfoSchedulingInfoList	*extGANSS_SIBTypeInfoSchedulingInfoList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoTypeSB1_v860ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoTypeSB1_v860ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ExtSIBTypeInfoSchedulingInfo-List2.h"
#include "ExtGANSS-SIBTypeInfoSchedulingInfoList.h"

#endif	/* _SysInfoTypeSB1_v860ext_H_ */
#include <asn_internal.h>
