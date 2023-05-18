/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_ChannelCodes_MBSFN_IMB384_H_
#define	_DL_ChannelCodes_MBSFN_IMB384_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DL-ChannelCodes-MBSFN-IMB384 */
typedef struct DL_ChannelCodes_MBSFN_IMB384 {
	long	 firstChannelisationCode;
	long	*lastChannelisationCode	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_ChannelCodes_MBSFN_IMB384_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_ChannelCodes_MBSFN_IMB384;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_ChannelCodes_MBSFN_IMB384_H_ */
#include <asn_internal.h>
