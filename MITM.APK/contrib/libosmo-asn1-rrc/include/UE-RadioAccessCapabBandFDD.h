/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_RadioAccessCapabBandFDD_H_
#define	_UE_RadioAccessCapabBandFDD_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RadioFrequencyBandFDD.h"
#include "MeasurementCapabilityExt.h"
#include "UE-PowerClassExt.h"
#include "TxRxFrequencySeparation.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-RadioAccessCapabBandFDD */
typedef struct UE_RadioAccessCapabBandFDD {
	RadioFrequencyBandFDD_t	 radioFrequencyBandFDD;
	struct UE_RadioAccessCapabBandFDD__fddRF_Capability {
		UE_PowerClassExt_t	 ue_PowerClass;
		TxRxFrequencySeparation_t	 txRxFrequencySeparation;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *fddRF_Capability;
	MeasurementCapabilityExt_t	 measurementCapability;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_RadioAccessCapabBandFDD_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapabBandFDD;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_RadioAccessCapabBandFDD_H_ */
#include <asn_internal.h>
