/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RAB_InformationSetup_r5_H_
#define	_RAB_InformationSetup_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RAB-Info.h"
#include "RB-InformationSetupList-r5.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RAB-InformationSetup-r5 */
typedef struct RAB_InformationSetup_r5 {
	RAB_Info_t	 rab_Info;
	RB_InformationSetupList_r5_t	 rb_InformationSetupList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RAB_InformationSetup_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RAB_InformationSetup_r5;

#ifdef __cplusplus
}
#endif

#endif	/* _RAB_InformationSetup_r5_H_ */
#include <asn_internal.h>
