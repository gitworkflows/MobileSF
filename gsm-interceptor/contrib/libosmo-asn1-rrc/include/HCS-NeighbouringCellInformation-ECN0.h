/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_HCS_NeighbouringCellInformation_ECN0_H_
#define	_HCS_NeighbouringCellInformation_ECN0_H_


#include <asn_application.h>

/* Including external dependencies */
#include "HCS-PRIO.h"
#include "Q-HCS.h"
#include "HCS-CellReselectInformation-ECN0.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HCS-NeighbouringCellInformation-ECN0 */
typedef struct HCS_NeighbouringCellInformation_ECN0 {
	HCS_PRIO_t	 hcs_PRIO	/* DEFAULT 0 */;
	Q_HCS_t	 q_HCS	/* DEFAULT 0 */;
	HCS_CellReselectInformation_ECN0_t	 hcs_CellReselectInformation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HCS_NeighbouringCellInformation_ECN0_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HCS_NeighbouringCellInformation_ECN0;

#ifdef __cplusplus
}
#endif

#endif	/* _HCS_NeighbouringCellInformation_ECN0_H_ */
#include <asn_internal.h>
