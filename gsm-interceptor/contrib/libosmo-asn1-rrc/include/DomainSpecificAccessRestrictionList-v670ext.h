/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DomainSpecificAccessRestrictionList_v670ext_H_
#define	_DomainSpecificAccessRestrictionList_v670ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DomainSpecificAccessRestrictionParam_v670ext;

/* DomainSpecificAccessRestrictionList-v670ext */
typedef struct DomainSpecificAccessRestrictionList_v670ext {
	struct DomainSpecificAccessRestrictionParam_v670ext	*domainSpecificAccessRestrictionParametersForOperator1	/* OPTIONAL */;
	struct DomainSpecificAccessRestrictionParam_v670ext	*domainSpecificAccessRestrictionParametersForOperator2	/* OPTIONAL */;
	struct DomainSpecificAccessRestrictionParam_v670ext	*domainSpecificAccessRestrictionParametersForOperator3	/* OPTIONAL */;
	struct DomainSpecificAccessRestrictionParam_v670ext	*domainSpecificAccessRestrictionParametersForOperator4	/* OPTIONAL */;
	struct DomainSpecificAccessRestrictionParam_v670ext	*domainSpecificAccessRestrictionParametersForOperator5	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DomainSpecificAccessRestrictionList_v670ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DomainSpecificAccessRestrictionList_v670ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DomainSpecificAccessRestrictionParam-v670ext.h"

#endif	/* _DomainSpecificAccessRestrictionList_v670ext_H_ */
#include <asn_internal.h>
