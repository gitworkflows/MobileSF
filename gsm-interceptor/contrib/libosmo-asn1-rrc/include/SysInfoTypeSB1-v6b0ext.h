/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SysInfoTypeSB1_v6b0ext_H_
#define	_SysInfoTypeSB1_v6b0ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExtSIBTypeInfoSchedulingInfo_List;

/* SysInfoTypeSB1-v6b0ext */
typedef struct SysInfoTypeSB1_v6b0ext {
	struct ExtSIBTypeInfoSchedulingInfo_List	*extSIBTypeInfoSchedulingInfo_List	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoTypeSB1_v6b0ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoTypeSB1_v6b0ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ExtSIBTypeInfoSchedulingInfo-List.h"

#endif	/* _SysInfoTypeSB1_v6b0ext_H_ */
#include <asn_internal.h>
