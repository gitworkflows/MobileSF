/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_EllipsoidPointUncertCircle_H_
#define	_EllipsoidPointUncertCircle_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EllipsoidPointUncertCircle__latitudeSign {
	EllipsoidPointUncertCircle__latitudeSign_north	= 0,
	EllipsoidPointUncertCircle__latitudeSign_south	= 1
} e_EllipsoidPointUncertCircle__latitudeSign;

/* EllipsoidPointUncertCircle */
typedef struct EllipsoidPointUncertCircle {
	long	 latitudeSign;
	long	 latitude;
	long	 longitude;
	long	 uncertaintyCode;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EllipsoidPointUncertCircle_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_latitudeSign_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_EllipsoidPointUncertCircle;

#ifdef __cplusplus
}
#endif

#endif	/* _EllipsoidPointUncertCircle_H_ */
#include <asn_internal.h>
