/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SysInfoType11_v770ext_IEs_H_
#define	_SysInfoType11_v770ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBSFNFrequencyList;

/* SysInfoType11-v770ext-IEs */
typedef struct SysInfoType11_v770ext_IEs {
	struct MBSFNFrequencyList	*mbsfnFrequencyList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType11_v770ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType11_v770ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBSFNFrequencyList.h"

#endif	/* _SysInfoType11_v770ext_IEs_H_ */
#include <asn_internal.h>
