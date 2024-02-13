/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CellIDListItem_H_
#define	_CellIDListItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CellIdentity.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PLMN_Identity;

/* CellIDListItem */
typedef struct CellIDListItem {
	CellIdentity_t	 cell_Identity;
	struct PLMN_Identity	*plmn_Identity	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellIDListItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellIDListItem;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PLMN-Identity.h"

#endif	/* _CellIDListItem_H_ */
#include <asn_internal.h>
