/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "E-DPDCH-Info-r7.h"

static int
memb_threeIndexStepThreshold_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 37)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_twoIndexStepThreshold_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 37)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_threeIndexStepThreshold_constr_8 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  37 }	/* (0..37) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_twoIndexStepThreshold_constr_9 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  37 }	/* (0..37) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_E_DPDCH_Info_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_DPDCH_Info_r7, e_TFCI_TableIndex),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_TFCI_TableIndex,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-TFCI-TableIndex"
		},
	{ ATF_POINTER, 1, offsetof(struct E_DPDCH_Info_r7, e_DCH_MinimumSet_E_TFCI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DCH_MinimumSet_E_TFCI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-DCH-MinimumSet-E-TFCI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DPDCH_Info_r7, reference_E_TFCIs),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_Reference_E_TFCIList_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reference-E-TFCIs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DPDCH_Info_r7, maxChannelisationCodes),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_MaxChannelisationCodes,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxChannelisationCodes"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DPDCH_Info_r7, pl_NonMax),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_PL_NonMax,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pl-NonMax"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DPDCH_Info_r7, schedulingInfoConfiguration),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_SchedulingInfoConfiguration,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"schedulingInfoConfiguration"
		},
	{ ATF_POINTER, 2, offsetof(struct E_DPDCH_Info_r7, threeIndexStepThreshold),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_threeIndexStepThreshold_constraint_1,
		&asn_PER_memb_threeIndexStepThreshold_constr_8,
		0,
		"threeIndexStepThreshold"
		},
	{ ATF_POINTER, 1, offsetof(struct E_DPDCH_Info_r7, twoIndexStepThreshold),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_twoIndexStepThreshold_constraint_1,
		&asn_PER_memb_twoIndexStepThreshold_constr_9,
		0,
		"twoIndexStepThreshold"
		},
};
static int asn_MAP_E_DPDCH_Info_r7_oms_1[] = { 1, 6, 7 };
static ber_tlv_tag_t asn_DEF_E_DPDCH_Info_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_E_DPDCH_Info_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-TFCI-TableIndex at 8342 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* e-DCH-MinimumSet-E-TFCI at 8343 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* reference-E-TFCIs at 8344 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* maxChannelisationCodes at 8345 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* pl-NonMax at 8346 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* schedulingInfoConfiguration at 8347 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* threeIndexStepThreshold at 8348 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 } /* twoIndexStepThreshold at 8349 */
};
static asn_SEQUENCE_specifics_t asn_SPC_E_DPDCH_Info_r7_specs_1 = {
	sizeof(struct E_DPDCH_Info_r7),
	offsetof(struct E_DPDCH_Info_r7, _asn_ctx),
	asn_MAP_E_DPDCH_Info_r7_tag2el_1,
	8,	/* Count of tags in the map */
	asn_MAP_E_DPDCH_Info_r7_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_E_DPDCH_Info_r7 = {
	"E-DPDCH-Info-r7",
	"E-DPDCH-Info-r7",
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
	asn_DEF_E_DPDCH_Info_r7_tags_1,
	sizeof(asn_DEF_E_DPDCH_Info_r7_tags_1)
		/sizeof(asn_DEF_E_DPDCH_Info_r7_tags_1[0]), /* 1 */
	asn_DEF_E_DPDCH_Info_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_DPDCH_Info_r7_tags_1)
		/sizeof(asn_DEF_E_DPDCH_Info_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_E_DPDCH_Info_r7_1,
	8,	/* Elements count */
	&asn_SPC_E_DPDCH_Info_r7_specs_1	/* Additional specs */
};

