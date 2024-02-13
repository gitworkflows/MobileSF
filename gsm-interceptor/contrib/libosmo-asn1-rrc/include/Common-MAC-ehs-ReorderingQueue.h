/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_Common_MAC_ehs_ReorderingQueue_H_
#define	_Common_MAC_ehs_ReorderingQueue_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MAC-ehs-QueueId.h"
#include "T1-ReleaseTimer.h"
#include "Treset-ResetTimer.h"
#include "MAC-hs-WindowSize.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common-MAC-ehs-ReorderingQueue */
typedef struct Common_MAC_ehs_ReorderingQueue {
	MAC_ehs_QueueId_t	 mac_ehs_QueueId;
	T1_ReleaseTimer_t	 t1_ReleaseTimer;
	Treset_ResetTimer_t	*reorderingResetTimer	/* OPTIONAL */;
	MAC_hs_WindowSize_t	 mac_ehsWindowSize;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Common_MAC_ehs_ReorderingQueue_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Common_MAC_ehs_ReorderingQueue;

#ifdef __cplusplus
}
#endif

#endif	/* _Common_MAC_ehs_ReorderingQueue_H_ */
#include <asn_internal.h>
