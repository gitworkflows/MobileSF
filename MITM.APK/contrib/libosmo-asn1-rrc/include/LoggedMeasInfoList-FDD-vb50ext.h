/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_LoggedMeasInfoList_FDD_vb50ext_H_
#define	_LoggedMeasInfoList_FDD_vb50ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LoggedMeasInfo_FDD_vb50ext;

/* LoggedMeasInfoList-FDD-vb50ext */
typedef struct LoggedMeasInfoList_FDD_vb50ext {
	A_SEQUENCE_OF(struct LoggedMeasInfo_FDD_vb50ext) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LoggedMeasInfoList_FDD_vb50ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LoggedMeasInfoList_FDD_vb50ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LoggedMeasInfo-FDD-vb50ext.h"

#endif	/* _LoggedMeasInfoList_FDD_vb50ext_H_ */
#include <asn_internal.h>
