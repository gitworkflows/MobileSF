/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_TransportChannelReconfiguration_v7f0ext_IEs_H_
#define	_TransportChannelReconfiguration_v7f0ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MIMO_PilotConfiguration_v7f0ext;

/* TransportChannelReconfiguration-v7f0ext-IEs */
typedef struct TransportChannelReconfiguration_v7f0ext_IEs {
	struct MIMO_PilotConfiguration_v7f0ext	*mimoParameters	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TransportChannelReconfiguration_v7f0ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TransportChannelReconfiguration_v7f0ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MIMO-Parameters-v7f0ext.h"

#endif	/* _TransportChannelReconfiguration_v7f0ext_IEs_H_ */
#include <asn_internal.h>
