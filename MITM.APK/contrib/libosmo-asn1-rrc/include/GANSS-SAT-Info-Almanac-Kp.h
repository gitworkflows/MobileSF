/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_GANSS_SAT_Info_Almanac_Kp_H_
#define	_GANSS_SAT_Info_Almanac_Kp_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GANSS-SAT-Info-Almanac-Kp */
typedef struct GANSS_SAT_Info_Almanac_Kp {
	long	 svId;
	BIT_STRING_t	 ganss_alm_e;
	BIT_STRING_t	 ganss_delta_I_alm;
	BIT_STRING_t	 ganss_omegadot_alm;
	BIT_STRING_t	 ganss_svhealth_alm;
	BIT_STRING_t	 ganss_delta_a_sqrt_alm;
	BIT_STRING_t	 ganss_omegazero_alm;
	BIT_STRING_t	 ganss_m_zero_alm;
	BIT_STRING_t	 ganss_omega_alm;
	BIT_STRING_t	 ganss_af_zero_alm;
	BIT_STRING_t	 ganss_af_one_alm;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GANSS_SAT_Info_Almanac_Kp_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GANSS_SAT_Info_Almanac_Kp;

#ifdef __cplusplus
}
#endif

#endif	/* _GANSS_SAT_Info_Almanac_Kp_H_ */
#include <asn_internal.h>
