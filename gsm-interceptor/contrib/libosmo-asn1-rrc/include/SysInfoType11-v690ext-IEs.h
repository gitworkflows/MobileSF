/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SysInfoType11_v690ext_IEs_H_
#define	_SysInfoType11_v690ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Dummy_InterFreqRACHReportingInfo;

/* SysInfoType11-v690ext-IEs */
typedef struct SysInfoType11_v690ext_IEs {
	struct Dummy_InterFreqRACHReportingInfo	*dummy	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType11_v690ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType11_v690ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Dummy-InterFreqRACHReportingInfo.h"

#endif	/* _SysInfoType11_v690ext_IEs_H_ */
#include <asn_internal.h>
