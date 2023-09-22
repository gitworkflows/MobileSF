/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_NavModel_NAVKeplerianSet_H_
#define	_NavModel_NAVKeplerianSet_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NavModel-NAVKeplerianSet */
typedef struct NavModel_NAVKeplerianSet {
	BIT_STRING_t	 navURA;
	BIT_STRING_t	 navFitFlag;
	BIT_STRING_t	 navToe;
	BIT_STRING_t	 navOmega;
	BIT_STRING_t	 navDeltaN;
	BIT_STRING_t	 navM0;
	BIT_STRING_t	 navOmegaADot;
	BIT_STRING_t	 navE;
	BIT_STRING_t	 navIDot;
	BIT_STRING_t	 navAPowerHalf;
	BIT_STRING_t	 navI0;
	BIT_STRING_t	 navOmegaA0;
	BIT_STRING_t	 navCrs;
	BIT_STRING_t	 navCis;
	BIT_STRING_t	 navCus;
	BIT_STRING_t	 navCrc;
	BIT_STRING_t	 navCic;
	BIT_STRING_t	 navCuc;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NavModel_NAVKeplerianSet_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NavModel_NAVKeplerianSet;

#ifdef __cplusplus
}
#endif

#endif	/* _NavModel_NAVKeplerianSet_H_ */
#include <asn_internal.h>
