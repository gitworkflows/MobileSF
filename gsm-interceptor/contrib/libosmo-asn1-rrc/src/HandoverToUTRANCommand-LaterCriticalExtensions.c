/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "HandoverToUTRANCommand-LaterCriticalExtensions.h"

static asn_per_constraints_t asn_PER_type_criticalExtensions_constr_7 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_HandoverToUTRANCommand_LaterCriticalExtensions_constr_1 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_6 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10__v9c0NonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10__v9c0NonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_6 = {
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
	asn_DEF_nonCriticalExtensions_tags_6,
	sizeof(asn_DEF_nonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_6[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_6,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_6)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_6[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v9c0NonCriticalExtensions_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10__v9c0NonCriticalExtensions, handoverToUTRANCommand_v9c0ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HandoverToUTRANCommand_v9c0ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverToUTRANCommand-v9c0ext"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10__v9c0NonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonCriticalExtensions"
		},
};
static int asn_MAP_v9c0NonCriticalExtensions_oms_4[] = { 1 };
static ber_tlv_tag_t asn_DEF_v9c0NonCriticalExtensions_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v9c0NonCriticalExtensions_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverToUTRANCommand-v9c0ext at 2970 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions at 2971 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v9c0NonCriticalExtensions_specs_4 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10__v9c0NonCriticalExtensions),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10__v9c0NonCriticalExtensions, _asn_ctx),
	asn_MAP_v9c0NonCriticalExtensions_tag2el_4,
	2,	/* Count of tags in the map */
	asn_MAP_v9c0NonCriticalExtensions_oms_4,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v9c0NonCriticalExtensions_4 = {
	"v9c0NonCriticalExtensions",
	"v9c0NonCriticalExtensions",
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
	asn_DEF_v9c0NonCriticalExtensions_tags_4,
	sizeof(asn_DEF_v9c0NonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_v9c0NonCriticalExtensions_tags_4[0]) - 1, /* 1 */
	asn_DEF_v9c0NonCriticalExtensions_tags_4,	/* Same as above */
	sizeof(asn_DEF_v9c0NonCriticalExtensions_tags_4)
		/sizeof(asn_DEF_v9c0NonCriticalExtensions_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v9c0NonCriticalExtensions_4,
	2,	/* Elements count */
	&asn_SPC_v9c0NonCriticalExtensions_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r10_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10, handoverToUTRANCommand_r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HandoverToUTRANCommand_r10_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverToUTRANCommand-r10"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10, v9c0NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v9c0NonCriticalExtensions_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v9c0NonCriticalExtensions"
		},
};
static int asn_MAP_r10_oms_2[] = { 1 };
static ber_tlv_tag_t asn_DEF_r10_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_r10_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverToUTRANCommand-r10 at 2967 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v9c0NonCriticalExtensions at 2970 */
};
static asn_SEQUENCE_specifics_t asn_SPC_r10_specs_2 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__r10, _asn_ctx),
	asn_MAP_r10_tag2el_2,
	2,	/* Count of tags in the map */
	asn_MAP_r10_oms_2,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_r10_2 = {
	"r10",
	"r10",
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
	asn_DEF_r10_tags_2,
	sizeof(asn_DEF_r10_tags_2)
		/sizeof(asn_DEF_r10_tags_2[0]) - 1, /* 1 */
	asn_DEF_r10_tags_2,	/* Same as above */
	sizeof(asn_DEF_r10_tags_2)
		/sizeof(asn_DEF_r10_tags_2[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_r10_2,
	2,	/* Elements count */
	&asn_SPC_r10_specs_2	/* Additional specs */
};

static ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_11 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11__nonCriticalExtensions),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_11 = {
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
	asn_DEF_nonCriticalExtensions_tags_11,
	sizeof(asn_DEF_nonCriticalExtensions_tags_11)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_11[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_11,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_11)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_11[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r11_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11, handoverToUTRANCommand_r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HandoverToUTRANCommand_r11_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverToUTRANCommand-r11"
		},
	{ ATF_POINTER, 2, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11, handoverToUTRANCommand_r11_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverToUTRANCommand-r11-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonCriticalExtensions"
		},
};
static int asn_MAP_r11_oms_8[] = { 1, 2 };
static ber_tlv_tag_t asn_DEF_r11_tags_8[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_r11_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverToUTRANCommand-r11 at 2976 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* handoverToUTRANCommand-r11-add-ext at 2978 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* nonCriticalExtensions at 2979 */
};
static asn_SEQUENCE_specifics_t asn_SPC_r11_specs_8 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__r11, _asn_ctx),
	asn_MAP_r11_tag2el_8,
	3,	/* Count of tags in the map */
	asn_MAP_r11_oms_8,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_r11_8 = {
	"r11",
	"r11",
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
	asn_DEF_r11_tags_8,
	sizeof(asn_DEF_r11_tags_8)
		/sizeof(asn_DEF_r11_tags_8[0]) - 1, /* 1 */
	asn_DEF_r11_tags_8,	/* Same as above */
	sizeof(asn_DEF_r11_tags_8)
		/sizeof(asn_DEF_r11_tags_8[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_r11_8,
	3,	/* Elements count */
	&asn_SPC_r11_specs_8	/* Additional specs */
};

static ber_tlv_tag_t asn_DEF_criticalExtensions_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_criticalExtensions_specs_12 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__criticalExtensions),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions__criticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_12 = {
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
	asn_DEF_criticalExtensions_tags_12,
	sizeof(asn_DEF_criticalExtensions_tags_12)
		/sizeof(asn_DEF_criticalExtensions_tags_12[0]) - 1, /* 1 */
	asn_DEF_criticalExtensions_tags_12,	/* Same as above */
	sizeof(asn_DEF_criticalExtensions_tags_12)
		/sizeof(asn_DEF_criticalExtensions_tags_12[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_criticalExtensions_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_criticalExtensions_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions, choice.r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r11_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"r11"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions, choice.criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_criticalExtensions_12,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"criticalExtensions"
		},
};
static asn_TYPE_tag2member_t asn_MAP_criticalExtensions_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r11 at 2976 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions at 2981 */
};
static asn_CHOICE_specifics_t asn_SPC_criticalExtensions_specs_7 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions, _asn_ctx),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions, present),
	sizeof(((struct HandoverToUTRANCommand_LaterCriticalExtensions__criticalExtensions *)0)->present),
	asn_MAP_criticalExtensions_tag2el_7,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_7 = {
	"criticalExtensions",
	"criticalExtensions",
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
	&asn_PER_type_criticalExtensions_constr_7,
	asn_MBR_criticalExtensions_7,
	2,	/* Elements count */
	&asn_SPC_criticalExtensions_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_HandoverToUTRANCommand_LaterCriticalExtensions_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions, choice.r10),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r10_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"r10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions, choice.criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_criticalExtensions_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"criticalExtensions"
		},
};
static asn_TYPE_tag2member_t asn_MAP_HandoverToUTRANCommand_LaterCriticalExtensions_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r10 at 2967 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions at 2980 */
};
static asn_CHOICE_specifics_t asn_SPC_HandoverToUTRANCommand_LaterCriticalExtensions_specs_1 = {
	sizeof(struct HandoverToUTRANCommand_LaterCriticalExtensions),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions, _asn_ctx),
	offsetof(struct HandoverToUTRANCommand_LaterCriticalExtensions, present),
	sizeof(((struct HandoverToUTRANCommand_LaterCriticalExtensions *)0)->present),
	asn_MAP_HandoverToUTRANCommand_LaterCriticalExtensions_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_HandoverToUTRANCommand_LaterCriticalExtensions = {
	"HandoverToUTRANCommand-LaterCriticalExtensions",
	"HandoverToUTRANCommand-LaterCriticalExtensions",
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
	&asn_PER_type_HandoverToUTRANCommand_LaterCriticalExtensions_constr_1,
	asn_MBR_HandoverToUTRANCommand_LaterCriticalExtensions_1,
	2,	/* Elements count */
	&asn_SPC_HandoverToUTRANCommand_LaterCriticalExtensions_specs_1	/* Additional specs */
};

