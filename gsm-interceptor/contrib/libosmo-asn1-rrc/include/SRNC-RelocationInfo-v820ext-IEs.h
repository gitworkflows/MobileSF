/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SRNC_RelocationInfo_v820ext_IEs_H_
#define	_SRNC_RelocationInfo_v820ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RAB_InformationSetupList_v820ext;

/* SRNC-RelocationInfo-v820ext-IEs */
typedef struct SRNC_RelocationInfo_v820ext_IEs {
	struct RAB_InformationSetupList_v820ext	*rab_InformationList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SRNC_RelocationInfo_v820ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SRNC_RelocationInfo_v820ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RAB-InformationSetupList-v820ext.h"

#endif	/* _SRNC_RelocationInfo_v820ext_IEs_H_ */
#include <asn_internal.h>
