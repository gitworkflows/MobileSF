/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CellUpdate_v6b0ext_IEs_H_
#define	_CellUpdate_v6b0ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_SelectedServicesShort;

/* CellUpdate-v6b0ext-IEs */
typedef struct CellUpdate_v6b0ext_IEs {
	struct MBMS_SelectedServicesShort	*mbmsSelectedServices	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellUpdate_v6b0ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellUpdate_v6b0ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-SelectedServicesShort.h"

#endif	/* _CellUpdate_v6b0ext_IEs_H_ */
#include <asn_internal.h>
