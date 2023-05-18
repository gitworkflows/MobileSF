/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UE-Positioning-IPDL-Parameters-TDD-r4-ext.h"

static int
memb_ip_slot_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 14)) {
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
memb_ip_Start_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 4095)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_ip_slot_constr_3 = {
	{ APC_CONSTRAINED,	 4,  4,  0,  14 }	/* (0..14) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_ip_Start_constr_4 = {
	{ APC_CONSTRAINED,	 12,  12,  0,  4095 }	/* (0..4095) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_UE_Positioning_IPDL_Parameters_TDD_r4_ext_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext, ip_Spacing),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IP_Spacing_TDD,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ip-Spacing"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext, ip_slot),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ip_slot_constraint_1,
		&asn_PER_memb_ip_slot_constr_3,
		0,
		"ip-slot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext, ip_Start),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ip_Start_constraint_1,
		&asn_PER_memb_ip_Start_constr_4,
		0,
		"ip-Start"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext, ip_PCCPCG),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IP_PCCPCH_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ip-PCCPCG"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext, burstModeParameters),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BurstModeParameters,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"burstModeParameters"
		},
};
static int asn_MAP_UE_Positioning_IPDL_Parameters_TDD_r4_ext_oms_1[] = { 3 };
static ber_tlv_tag_t asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ip-Spacing at 19357 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ip-slot at 19358 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* ip-Start at 19359 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* ip-PCCPCG at 19360 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* burstModeParameters at 19362 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_IPDL_Parameters_TDD_r4_ext_specs_1 = {
	sizeof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext),
	offsetof(struct UE_Positioning_IPDL_Parameters_TDD_r4_ext, _asn_ctx),
	asn_MAP_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_UE_Positioning_IPDL_Parameters_TDD_r4_ext_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext = {
	"UE-Positioning-IPDL-Parameters-TDD-r4-ext",
	"UE-Positioning-IPDL-Parameters-TDD-r4-ext",
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
	asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1,
	sizeof(asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1)
		/sizeof(asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1[0]), /* 1 */
	asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1)
		/sizeof(asn_DEF_UE_Positioning_IPDL_Parameters_TDD_r4_ext_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UE_Positioning_IPDL_Parameters_TDD_r4_ext_1,
	5,	/* Elements count */
	&asn_SPC_UE_Positioning_IPDL_Parameters_TDD_r4_ext_specs_1	/* Additional specs */
};

