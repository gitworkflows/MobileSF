/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DataVolumePerRB_List_H_
#define	_DataVolumePerRB_List_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DataVolumePerRB;

/* DataVolumePerRB-List */
typedef struct DataVolumePerRB_List {
	A_SEQUENCE_OF(struct DataVolumePerRB) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DataVolumePerRB_List_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DataVolumePerRB_List;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DataVolumePerRB.h"

#endif	/* _DataVolumePerRB_List_H_ */
#include <asn_internal.h>
