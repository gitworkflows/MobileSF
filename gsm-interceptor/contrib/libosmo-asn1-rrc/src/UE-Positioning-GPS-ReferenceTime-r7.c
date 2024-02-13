/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UE-Positioning-GPS-ReferenceTime-r7.h"

static int
memb_gps_Week_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 1023)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_gps_Week_constr_2 = {
	{ APC_CONSTRAINED,	 10,  10,  0,  1023 }	/* (0..1023) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_UE_Positioning_GPS_ReferenceTime_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, gps_Week),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_gps_Week_constraint_1,
		&asn_PER_memb_gps_Week_constr_2,
		0,
		"gps-Week"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, gps_tow_1msec),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GPS_TOW_1msec,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gps-tow-1msec"
		},
	{ ATF_POINTER, 5, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, utran_GPSReferenceTime),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_GPSReferenceTime,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"utran-GPSReferenceTime"
		},
	{ ATF_POINTER, 4, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, ue_Positioning_GPS_ReferenceTimeUncertainty),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GPS_ReferenceTimeUncertainty,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ue-Positioning-GPS-ReferenceTimeUncertainty"
		},
	{ ATF_POINTER, 3, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, sfn_tow_Uncertainty),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_TOW_Uncertainty,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sfn-tow-Uncertainty"
		},
	{ ATF_POINTER, 2, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, utran_GPS_DriftRate),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_GPS_DriftRate,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"utran-GPS-DriftRate"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, gps_TOW_AssistList),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GPS_TOW_AssistList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gps-TOW-AssistList"
		},
};
static int asn_MAP_UE_Positioning_GPS_ReferenceTime_r7_oms_1[] = { 2, 3, 4, 5, 6 };
static ber_tlv_tag_t asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UE_Positioning_GPS_ReferenceTime_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gps-Week at 19290 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* gps-tow-1msec at 19291 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* utran-GPSReferenceTime at 19292 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* ue-Positioning-GPS-ReferenceTimeUncertainty at 19294 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* sfn-tow-Uncertainty at 19295 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* utran-GPS-DriftRate at 19296 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* gps-TOW-AssistList at 19297 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_GPS_ReferenceTime_r7_specs_1 = {
	sizeof(struct UE_Positioning_GPS_ReferenceTime_r7),
	offsetof(struct UE_Positioning_GPS_ReferenceTime_r7, _asn_ctx),
	asn_MAP_UE_Positioning_GPS_ReferenceTime_r7_tag2el_1,
	7,	/* Count of tags in the map */
	asn_MAP_UE_Positioning_GPS_ReferenceTime_r7_oms_1,	/* Optional members */
	5, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_GPS_ReferenceTime_r7 = {
	"UE-Positioning-GPS-ReferenceTime-r7",
	"UE-Positioning-GPS-ReferenceTime-r7",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1,
	sizeof(asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1)
		/sizeof(asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1)
		/sizeof(asn_DEF_UE_Positioning_GPS_ReferenceTime_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UE_Positioning_GPS_ReferenceTime_r7_1,
	7,	/* Elements count */
	&asn_SPC_UE_Positioning_GPS_ReferenceTime_r7_specs_1	/* Additional specs */
};

