/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "PhysicalChannelCapability-edch-r6.h"

static int
memb_edch_PhysicalLayerCategory_constraint_3(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 16)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_edch_PhysicalLayerCategory_constr_4 = {
	{ APC_CONSTRAINED,	 4,  4,  1,  16 }	/* (1..16) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_fdd_edch_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_supported_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability_edch_r6__fdd_edch__supported, edch_PhysicalLayerCategory),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_edch_PhysicalLayerCategory_constraint_3,
		&asn_PER_memb_edch_PhysicalLayerCategory_constr_4,
		0,
		"edch-PhysicalLayerCategory"
		},
};
static ber_tlv_tag_t asn_DEF_supported_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_supported_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* edch-PhysicalLayerCategory at 3382 */
};
static asn_SEQUENCE_specifics_t asn_SPC_supported_specs_3 = {
	sizeof(struct PhysicalChannelCapability_edch_r6__fdd_edch__supported),
	offsetof(struct PhysicalChannelCapability_edch_r6__fdd_edch__supported, _asn_ctx),
	asn_MAP_supported_tag2el_3,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supported_3 = {
	"supported",
	"supported",
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
	asn_DEF_supported_tags_3,
	sizeof(asn_DEF_supported_tags_3)
		/sizeof(asn_DEF_supported_tags_3[0]) - 1, /* 1 */
	asn_DEF_supported_tags_3,	/* Same as above */
	sizeof(asn_DEF_supported_tags_3)
		/sizeof(asn_DEF_supported_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_supported_3,
	1,	/* Elements count */
	&asn_SPC_supported_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_edch_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability_edch_r6__fdd_edch, choice.supported),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_supported_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"supported"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability_edch_r6__fdd_edch, choice.unsupported),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"unsupported"
		},
};
static asn_TYPE_tag2member_t asn_MAP_fdd_edch_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* supported at 3383 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* unsupported at 3384 */
};
static asn_CHOICE_specifics_t asn_SPC_fdd_edch_specs_2 = {
	sizeof(struct PhysicalChannelCapability_edch_r6__fdd_edch),
	offsetof(struct PhysicalChannelCapability_edch_r6__fdd_edch, _asn_ctx),
	offsetof(struct PhysicalChannelCapability_edch_r6__fdd_edch, present),
	sizeof(((struct PhysicalChannelCapability_edch_r6__fdd_edch *)0)->present),
	asn_MAP_fdd_edch_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_edch_2 = {
	"fdd-edch",
	"fdd-edch",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_fdd_edch_constr_2,
	asn_MBR_fdd_edch_2,
	2,	/* Elements count */
	&asn_SPC_fdd_edch_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_PhysicalChannelCapability_edch_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PhysicalChannelCapability_edch_r6, fdd_edch),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_fdd_edch_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd-edch"
		},
};
static ber_tlv_tag_t asn_DEF_PhysicalChannelCapability_edch_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PhysicalChannelCapability_edch_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* fdd-edch at 3383 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PhysicalChannelCapability_edch_r6_specs_1 = {
	sizeof(struct PhysicalChannelCapability_edch_r6),
	offsetof(struct PhysicalChannelCapability_edch_r6, _asn_ctx),
	asn_MAP_PhysicalChannelCapability_edch_r6_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PhysicalChannelCapability_edch_r6 = {
	"PhysicalChannelCapability-edch-r6",
	"PhysicalChannelCapability-edch-r6",
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
	asn_DEF_PhysicalChannelCapability_edch_r6_tags_1,
	sizeof(asn_DEF_PhysicalChannelCapability_edch_r6_tags_1)
		/sizeof(asn_DEF_PhysicalChannelCapability_edch_r6_tags_1[0]), /* 1 */
	asn_DEF_PhysicalChannelCapability_edch_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_PhysicalChannelCapability_edch_r6_tags_1)
		/sizeof(asn_DEF_PhysicalChannelCapability_edch_r6_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PhysicalChannelCapability_edch_r6_1,
	1,	/* Elements count */
	&asn_SPC_PhysicalChannelCapability_edch_r6_specs_1	/* Additional specs */
};

