/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "GANSSGenericData.h"

static int
memb_ganssId_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 7)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_ganssId_constr_2 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_GANSSGenericData_1[] = {
	{ ATF_POINTER, 9, offsetof(struct GANSSGenericData, ganssId),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ganssId_constraint_1,
		&asn_PER_memb_ganssId_constr_2,
		0,
		"ganssId"
		},
	{ ATF_POINTER, 8, offsetof(struct GANSSGenericData, ganssTimeModelsList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GANSSTimeModelsList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ganssTimeModelsList"
		},
	{ ATF_POINTER, 7, offsetof(struct GANSSGenericData, uePositioningDGANSSCorrections),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_DGANSSCorrections,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningDGANSSCorrections"
		},
	{ ATF_POINTER, 6, offsetof(struct GANSSGenericData, uePositioningGANSSNavigationModel),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_NavigationModel,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningGANSSNavigationModel"
		},
	{ ATF_POINTER, 5, offsetof(struct GANSSGenericData, uePositioningGANSSRealTimeIntegrity),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_RealTimeIntegrity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningGANSSRealTimeIntegrity"
		},
	{ ATF_POINTER, 4, offsetof(struct GANSSGenericData, uePositioningGANSSDataBitAssistance),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_Data_Bit_Assistance,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningGANSSDataBitAssistance"
		},
	{ ATF_POINTER, 3, offsetof(struct GANSSGenericData, uePositioningGANSSReferenceMeasurementInfo),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_ReferenceMeasurementInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningGANSSReferenceMeasurementInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct GANSSGenericData, uePositioningGANSSAlmanac),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_Almanac,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningGANSSAlmanac"
		},
	{ ATF_POINTER, 1, offsetof(struct GANSSGenericData, uePositioningGANSSUTCModel),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_Positioning_GANSS_UTCModel,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uePositioningGANSSUTCModel"
		},
};
static int asn_MAP_GANSSGenericData_oms_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
static ber_tlv_tag_t asn_DEF_GANSSGenericData_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_GANSSGenericData_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ganssId at 14469 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ganssTimeModelsList at 14470 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* uePositioningDGANSSCorrections at 14471 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* uePositioningGANSSNavigationModel at 14472 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* uePositioningGANSSRealTimeIntegrity at 14473 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* uePositioningGANSSDataBitAssistance at 14474 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* uePositioningGANSSReferenceMeasurementInfo at 14476 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* uePositioningGANSSAlmanac at 14477 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 } /* uePositioningGANSSUTCModel at 14478 */
};
static asn_SEQUENCE_specifics_t asn_SPC_GANSSGenericData_specs_1 = {
	sizeof(struct GANSSGenericData),
	offsetof(struct GANSSGenericData, _asn_ctx),
	asn_MAP_GANSSGenericData_tag2el_1,
	9,	/* Count of tags in the map */
	asn_MAP_GANSSGenericData_oms_1,	/* Optional members */
	9, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_GANSSGenericData = {
	"GANSSGenericData",
	"GANSSGenericData",
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
	asn_DEF_GANSSGenericData_tags_1,
	sizeof(asn_DEF_GANSSGenericData_tags_1)
		/sizeof(asn_DEF_GANSSGenericData_tags_1[0]), /* 1 */
	asn_DEF_GANSSGenericData_tags_1,	/* Same as above */
	sizeof(asn_DEF_GANSSGenericData_tags_1)
		/sizeof(asn_DEF_GANSSGenericData_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_GANSSGenericData_1,
	9,	/* Elements count */
	&asn_SPC_GANSSGenericData_specs_1	/* Additional specs */
};

