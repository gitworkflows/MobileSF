/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_HandoverToUTRANCommand_v820ext_IEs_H_
#define	_HandoverToUTRANCommand_v820ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RAB_InformationSetupList_v820ext;

/* HandoverToUTRANCommand-v820ext-IEs */
typedef struct HandoverToUTRANCommand_v820ext_IEs {
	struct RAB_InformationSetupList_v820ext	*rab_InformationSetupList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HandoverToUTRANCommand_v820ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HandoverToUTRANCommand_v820ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RAB-InformationSetupList-v820ext.h"

#endif	/* _HandoverToUTRANCommand_v820ext_IEs_H_ */
#include <asn_internal.h>
