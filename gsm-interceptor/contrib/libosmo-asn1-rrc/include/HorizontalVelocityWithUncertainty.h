/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_HorizontalVelocityWithUncertainty_H_
#define	_HorizontalVelocityWithUncertainty_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HorizontalVelocityWithUncertainty */
typedef struct HorizontalVelocityWithUncertainty {
	long	 bearing;
	long	 horizontalSpeed;
	long	 horizontalSpeedUncertainty;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HorizontalVelocityWithUncertainty_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HorizontalVelocityWithUncertainty;

#ifdef __cplusplus
}
#endif

#endif	/* _HorizontalVelocityWithUncertainty_H_ */
#include <asn_internal.h>
