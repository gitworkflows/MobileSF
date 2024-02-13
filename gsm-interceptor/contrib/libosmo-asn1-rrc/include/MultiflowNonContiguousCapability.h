/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MultiflowNonContiguousCapability_H_
#define	_MultiflowNonContiguousCapability_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MultiflowNonContiguousCapability__gapSize {
	MultiflowNonContiguousCapability__gapSize_fiveMHz	= 0,
	MultiflowNonContiguousCapability__gapSize_tenMHz	= 1,
	MultiflowNonContiguousCapability__gapSize_anyGapSize	= 2,
	MultiflowNonContiguousCapability__gapSize_spare5	= 3,
	MultiflowNonContiguousCapability__gapSize_spare4	= 4,
	MultiflowNonContiguousCapability__gapSize_spare3	= 5,
	MultiflowNonContiguousCapability__gapSize_spare2	= 6,
	MultiflowNonContiguousCapability__gapSize_spare1	= 7
} e_MultiflowNonContiguousCapability__gapSize;

/* MultiflowNonContiguousCapability */
typedef struct MultiflowNonContiguousCapability {
	long	 gapSize;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MultiflowNonContiguousCapability_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_gapSize_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_MultiflowNonContiguousCapability;

#ifdef __cplusplus
}
#endif

#endif	/* _MultiflowNonContiguousCapability_H_ */
#include <asn_internal.h>
