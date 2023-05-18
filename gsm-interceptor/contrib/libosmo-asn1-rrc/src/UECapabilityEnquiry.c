/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UECapabilityEnquiry.h"

static asn_per_constraints_t asn_PER_type_UECapabilityEnquiry_constr_1 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_14[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_14 = {
	sizeof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_14 = {
	"nonCriticalExtensions",
	"nonCriticalExtensions",
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
	asn_DEF_nonCriticalExtensions_tags_14,
	sizeof(asn_DEF_nonCriticalExtensions_tags_14)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_14[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_14,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_14)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_14[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_14	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v860NonCriticalExtensions_12[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions, ueCapabilityEnquiry_v860ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UECapabilityEnquiry_v860ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueCapabilityEnquiry-v860ext"
		},
	{ ATF_POINTER, 1, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_14,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonCriticalExtensions"
		},
};
static int asn_MAP_v860NonCriticalExtensions_oms_12[] = { 1 };
static ber_tlv_tag_t asn_DEF_v860NonCriticalExtensions_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v860NonCriticalExtensions_tag2el_12[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueCapabilityEnquiry-v860ext at 10348 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions at 10349 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v860NonCriticalExtensions_specs_12 = {
	sizeof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions),
	offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions, _asn_ctx),
	asn_MAP_v860NonCriticalExtensions_tag2el_12,
	2,	/* Count of tags in the map */
	asn_MAP_v860NonCriticalExtensions_oms_12,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v860NonCriticalExtensions_12 = {
	"v860NonCriticalExtensions",
	"v860NonCriticalExtensions",
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
	asn_DEF_v860NonCriticalExtensions_tags_12,
	sizeof(asn_DEF_v860NonCriticalExtensions_tags_12)
		/sizeof(asn_DEF_v860NonCriticalExtensions_tags_12[0]) - 1, /* 1 */
	asn_DEF_v860NonCriticalExtensions_tags_12,	/* Same as above */
	sizeof(asn_DEF_v860NonCriticalExtensions_tags_12)
		/sizeof(asn_DEF_v860NonCriticalExtensions_tags_12[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v860NonCriticalExtensions_12,
	2,	/* Elements count */
	&asn_SPC_v860NonCriticalExtensions_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v770NonCriticalExtensions_10[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions, ueCapabilityEnquiry_v770ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UECapabilityEnquiry_v770ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueCapabilityEnquiry-v770ext"
		},
	{ ATF_POINTER, 1, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions, v860NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v860NonCriticalExtensions_12,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v860NonCriticalExtensions"
		},
};
static int asn_MAP_v770NonCriticalExtensions_oms_10[] = { 1 };
static ber_tlv_tag_t asn_DEF_v770NonCriticalExtensions_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v770NonCriticalExtensions_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueCapabilityEnquiry-v770ext at 10346 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v860NonCriticalExtensions at 10348 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v770NonCriticalExtensions_specs_10 = {
	sizeof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions),
	offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v770NonCriticalExtensions, _asn_ctx),
	asn_MAP_v770NonCriticalExtensions_tag2el_10,
	2,	/* Count of tags in the map */
	asn_MAP_v770NonCriticalExtensions_oms_10,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v770NonCriticalExtensions_10 = {
	"v770NonCriticalExtensions",
	"v770NonCriticalExtensions",
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
	asn_DEF_v770NonCriticalExtensions_tags_10,
	sizeof(asn_DEF_v770NonCriticalExtensions_tags_10)
		/sizeof(asn_DEF_v770NonCriticalExtensions_tags_10[0]) - 1, /* 1 */
	asn_DEF_v770NonCriticalExtensions_tags_10,	/* Same as above */
	sizeof(asn_DEF_v770NonCriticalExtensions_tags_10)
		/sizeof(asn_DEF_v770NonCriticalExtensions_tags_10[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v770NonCriticalExtensions_10,
	2,	/* Elements count */
	&asn_SPC_v770NonCriticalExtensions_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v590NonCriticalExtensions_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions, ueCapabilityEnquiry_v590ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UECapabilityEnquiry_v590ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueCapabilityEnquiry-v590ext"
		},
	{ ATF_POINTER, 1, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions, v770NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v770NonCriticalExtensions_10,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v770NonCriticalExtensions"
		},
};
static int asn_MAP_v590NonCriticalExtensions_oms_8[] = { 1 };
static ber_tlv_tag_t asn_DEF_v590NonCriticalExtensions_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v590NonCriticalExtensions_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueCapabilityEnquiry-v590ext at 10344 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v770NonCriticalExtensions at 10346 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v590NonCriticalExtensions_specs_8 = {
	sizeof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions),
	offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions__v590NonCriticalExtensions, _asn_ctx),
	asn_MAP_v590NonCriticalExtensions_tag2el_8,
	2,	/* Count of tags in the map */
	asn_MAP_v590NonCriticalExtensions_oms_8,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v590NonCriticalExtensions_8 = {
	"v590NonCriticalExtensions",
	"v590NonCriticalExtensions",
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
	asn_DEF_v590NonCriticalExtensions_tags_8,
	sizeof(asn_DEF_v590NonCriticalExtensions_tags_8)
		/sizeof(asn_DEF_v590NonCriticalExtensions_tags_8[0]) - 1, /* 1 */
	asn_DEF_v590NonCriticalExtensions_tags_8,	/* Same as above */
	sizeof(asn_DEF_v590NonCriticalExtensions_tags_8)
		/sizeof(asn_DEF_v590NonCriticalExtensions_tags_8[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v590NonCriticalExtensions_8,
	2,	/* Elements count */
	&asn_SPC_v590NonCriticalExtensions_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v4b0NonCriticalExtensions_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions, ueCapabilityEnquiry_v4b0ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UECapabilityEnquiry_v4b0ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueCapabilityEnquiry-v4b0ext"
		},
	{ ATF_POINTER, 1, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions, v590NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v590NonCriticalExtensions_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v590NonCriticalExtensions"
		},
};
static int asn_MAP_v4b0NonCriticalExtensions_oms_6[] = { 1 };
static ber_tlv_tag_t asn_DEF_v4b0NonCriticalExtensions_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v4b0NonCriticalExtensions_tag2el_6[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueCapabilityEnquiry-v4b0ext at 10342 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v590NonCriticalExtensions at 10344 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v4b0NonCriticalExtensions_specs_6 = {
	sizeof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions),
	offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions__v4b0NonCriticalExtensions, _asn_ctx),
	asn_MAP_v4b0NonCriticalExtensions_tag2el_6,
	2,	/* Count of tags in the map */
	asn_MAP_v4b0NonCriticalExtensions_oms_6,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v4b0NonCriticalExtensions_6 = {
	"v4b0NonCriticalExtensions",
	"v4b0NonCriticalExtensions",
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
	asn_DEF_v4b0NonCriticalExtensions_tags_6,
	sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_6[0]) - 1, /* 1 */
	asn_DEF_v4b0NonCriticalExtensions_tags_6,	/* Same as above */
	sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_v4b0NonCriticalExtensions_tags_6[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v4b0NonCriticalExtensions_6,
	2,	/* Elements count */
	&asn_SPC_v4b0NonCriticalExtensions_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_laterNonCriticalExtensions_4[] = {
	{ ATF_POINTER, 2, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions, ueCapabilityEnquiry_r3_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueCapabilityEnquiry-r3-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions, v4b0NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v4b0NonCriticalExtensions_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v4b0NonCriticalExtensions"
		},
};
static int asn_MAP_laterNonCriticalExtensions_oms_4[] = { 0, 1 };
static ber_tlv_tag_t asn_DEF_laterNonCriticalExtensions_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_laterNonCriticalExtensions_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueCapabilityEnquiry-r3-add-ext at 10340 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v4b0NonCriticalExtensions at 10342 */
};
static asn_SEQUENCE_specifics_t asn_SPC_laterNonCriticalExtensions_specs_4 = {
	sizeof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions),
	offsetof(struct UECapabilityEnquiry__r3__laterNonCriticalExtensions, _asn_ctx),
	asn_MAP_laterNonCriticalExtensions_tag2el_4,
	2,	/* Count of tags in the map */
	asn_MAP_laterNonCriticalExtensions_oms_4,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_laterNonCriticalExtensions_4 = {
	"laterNonCriticalExtensions",
	"laterNonCriticalExtensions",
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
	asn_DEF_laterNonCriticalExtensions_tags_4,
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_4[0]) - 1, /* 1 */
	asn_DEF_laterNonCriticalExtensions_tags_4,	/* Same as above */
	sizeof(asn_DEF_laterNonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_laterNonCriticalExtensions_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_laterNonCriticalExtensions_4,
	2,	/* Elements count */
	&asn_SPC_laterNonCriticalExtensions_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r3_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__r3, ueCapabilityEnquiry_r3),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UECapabilityEnquiry_r3_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueCapabilityEnquiry-r3"
		},
	{ ATF_POINTER, 1, offsetof(struct UECapabilityEnquiry__r3, laterNonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_laterNonCriticalExtensions_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"laterNonCriticalExtensions"
		},
};
static int asn_MAP_r3_oms_2[] = { 1 };
static ber_tlv_tag_t asn_DEF_r3_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_r3_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ueCapabilityEnquiry-r3 at 10337 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* laterNonCriticalExtensions at 10340 */
};
static asn_SEQUENCE_specifics_t asn_SPC_r3_specs_2 = {
	sizeof(struct UECapabilityEnquiry__r3),
	offsetof(struct UECapabilityEnquiry__r3, _asn_ctx),
	asn_MAP_r3_tag2el_2,
	2,	/* Count of tags in the map */
	asn_MAP_r3_oms_2,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_r3_2 = {
	"r3",
	"r3",
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
	asn_DEF_r3_tags_2,
	sizeof(asn_DEF_r3_tags_2)
		/sizeof(asn_DEF_r3_tags_2[0]) - 1, /* 1 */
	asn_DEF_r3_tags_2,	/* Same as above */
	sizeof(asn_DEF_r3_tags_2)
		/sizeof(asn_DEF_r3_tags_2[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_r3_2,
	2,	/* Elements count */
	&asn_SPC_r3_specs_2	/* Additional specs */
};

static ber_tlv_tag_t asn_DEF_criticalExtensions_tags_17[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_criticalExtensions_specs_17 = {
	sizeof(struct UECapabilityEnquiry__later_than_r3__criticalExtensions),
	offsetof(struct UECapabilityEnquiry__later_than_r3__criticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_17 = {
	"criticalExtensions",
	"criticalExtensions",
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
	asn_DEF_criticalExtensions_tags_17,
	sizeof(asn_DEF_criticalExtensions_tags_17)
		/sizeof(asn_DEF_criticalExtensions_tags_17[0]) - 1, /* 1 */
	asn_DEF_criticalExtensions_tags_17,	/* Same as above */
	sizeof(asn_DEF_criticalExtensions_tags_17)
		/sizeof(asn_DEF_criticalExtensions_tags_17[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_criticalExtensions_specs_17	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_later_than_r3_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__later_than_r3, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rrc-TransactionIdentifier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry__later_than_r3, criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_criticalExtensions_17,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"criticalExtensions"
		},
};
static ber_tlv_tag_t asn_DEF_later_than_r3_tags_15[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_later_than_r3_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier at 10357 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions at 10358 */
};
static asn_SEQUENCE_specifics_t asn_SPC_later_than_r3_specs_15 = {
	sizeof(struct UECapabilityEnquiry__later_than_r3),
	offsetof(struct UECapabilityEnquiry__later_than_r3, _asn_ctx),
	asn_MAP_later_than_r3_tag2el_15,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_later_than_r3_15 = {
	"later-than-r3",
	"later-than-r3",
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
	asn_DEF_later_than_r3_tags_15,
	sizeof(asn_DEF_later_than_r3_tags_15)
		/sizeof(asn_DEF_later_than_r3_tags_15[0]) - 1, /* 1 */
	asn_DEF_later_than_r3_tags_15,	/* Same as above */
	sizeof(asn_DEF_later_than_r3_tags_15)
		/sizeof(asn_DEF_later_than_r3_tags_15[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_later_than_r3_15,
	2,	/* Elements count */
	&asn_SPC_later_than_r3_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_UECapabilityEnquiry_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry, choice.r3),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r3_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"r3"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UECapabilityEnquiry, choice.later_than_r3),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_later_than_r3_15,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"later-than-r3"
		},
};
static asn_TYPE_tag2member_t asn_MAP_UECapabilityEnquiry_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r3 at 10337 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* later-than-r3 at 10357 */
};
static asn_CHOICE_specifics_t asn_SPC_UECapabilityEnquiry_specs_1 = {
	sizeof(struct UECapabilityEnquiry),
	offsetof(struct UECapabilityEnquiry, _asn_ctx),
	offsetof(struct UECapabilityEnquiry, present),
	sizeof(((struct UECapabilityEnquiry *)0)->present),
	asn_MAP_UECapabilityEnquiry_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_UECapabilityEnquiry = {
	"UECapabilityEnquiry",
	"UECapabilityEnquiry",
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
	&asn_PER_type_UECapabilityEnquiry_constr_1,
	asn_MBR_UECapabilityEnquiry_1,
	2,	/* Elements count */
	&asn_SPC_UECapabilityEnquiry_specs_1	/* Additional specs */
};

