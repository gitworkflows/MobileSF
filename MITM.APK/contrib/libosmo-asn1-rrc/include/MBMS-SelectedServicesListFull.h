/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_SelectedServicesListFull_H_
#define	_MBMS_SelectedServicesListFull_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_ServiceIdentity_r6;

/* MBMS-SelectedServicesListFull */
typedef struct MBMS_SelectedServicesListFull {
	A_SEQUENCE_OF(struct MBMS_ServiceIdentity_r6) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_SelectedServicesListFull_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_SelectedServicesListFull;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-ServiceIdentity-r6.h"

#endif	/* _MBMS_SelectedServicesListFull_H_ */
#include <asn_internal.h>
