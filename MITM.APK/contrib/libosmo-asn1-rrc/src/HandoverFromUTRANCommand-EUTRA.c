/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "HandoverFromUTRANCommand-EUTRA.h"

static asn_per_constraints_t asn_PER_type_criticalExtensions_constr_8 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_criticalExtensions_constr_3 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_7 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8__nonCriticalExtensions),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_7 = {
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
	asn_DEF_nonCriticalExtensions_tags_7,
	sizeof(asn_DEF_nonCriticalExtensions_tags_7)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_7[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_7,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_7)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_7[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r8_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8, handoverFromUTRANCommand_EUTRA_r8),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HandoverFromUTRANCommand_EUTRA_r8_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverFromUTRANCommand-EUTRA-r8"
		},
	{ ATF_POINTER, 2, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8, handoverFromUTRANCommand_EUTRA_r8_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverFromUTRANCommand-EUTRA-r8-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonCriticalExtensions"
		},
};
static int asn_MAP_r8_oms_4[] = { 1, 2 };
static ber_tlv_tag_t asn_DEF_r8_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_r8_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverFromUTRANCommand-EUTRA-r8 at 3431 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* handoverFromUTRANCommand-EUTRA-r8-add-ext at 3433 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* nonCriticalExtensions at 3434 */
};
static asn_SEQUENCE_specifics_t asn_SPC_r8_specs_4 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__r8, _asn_ctx),
	asn_MAP_r8_tag2el_4,
	3,	/* Count of tags in the map */
	asn_MAP_r8_oms_4,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_r8_4 = {
	"r8",
	"r8",
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
	asn_DEF_r8_tags_4,
	sizeof(asn_DEF_r8_tags_4)
		/sizeof(asn_DEF_r8_tags_4[0]) - 1, /* 1 */
	asn_DEF_r8_tags_4,	/* Same as above */
	sizeof(asn_DEF_r8_tags_4)
		/sizeof(asn_DEF_r8_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_r8_4,
	3,	/* Elements count */
	&asn_SPC_r8_specs_4	/* Additional specs */
};

static ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_12[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_12 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11__nonCriticalExtensions),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11__nonCriticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_nonCriticalExtensions_12 = {
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
	asn_DEF_nonCriticalExtensions_tags_12,
	sizeof(asn_DEF_nonCriticalExtensions_tags_12)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_12[0]) - 1, /* 1 */
	asn_DEF_nonCriticalExtensions_tags_12,	/* Same as above */
	sizeof(asn_DEF_nonCriticalExtensions_tags_12)
		/sizeof(asn_DEF_nonCriticalExtensions_tags_12[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_nonCriticalExtensions_specs_12	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_r11_9[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11, handoverFromUTRANCommand_EUTRA_r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HandoverFromUTRANCommand_EUTRA_r11_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverFromUTRANCommand-EUTRA-r11"
		},
	{ ATF_POINTER, 2, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11, handoverFromUTRANCommand_EUTRA_r11_add_ext),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"handoverFromUTRANCommand-EUTRA-r11-add-ext"
		},
	{ ATF_POINTER, 1, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_12,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonCriticalExtensions"
		},
};
static int asn_MAP_r11_oms_9[] = { 1, 2 };
static ber_tlv_tag_t asn_DEF_r11_tags_9[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_r11_tag2el_9[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* handoverFromUTRANCommand-EUTRA-r11 at 3438 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* handoverFromUTRANCommand-EUTRA-r11-add-ext at 3439 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* nonCriticalExtensions at 3440 */
};
static asn_SEQUENCE_specifics_t asn_SPC_r11_specs_9 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__r11, _asn_ctx),
	asn_MAP_r11_tag2el_9,
	3,	/* Count of tags in the map */
	asn_MAP_r11_oms_9,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_r11_9 = {
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
	asn_DEF_r11_tags_9,
	sizeof(asn_DEF_r11_tags_9)
		/sizeof(asn_DEF_r11_tags_9[0]) - 1, /* 1 */
	asn_DEF_r11_tags_9,	/* Same as above */
	sizeof(asn_DEF_r11_tags_9)
		/sizeof(asn_DEF_r11_tags_9[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_r11_9,
	3,	/* Elements count */
	&asn_SPC_r11_specs_9	/* Additional specs */
};

static ber_tlv_tag_t asn_DEF_criticalExtensions_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_criticalExtensions_specs_13 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__criticalExtensions),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions__criticalExtensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_13 = {
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
	asn_DEF_criticalExtensions_tags_13,
	sizeof(asn_DEF_criticalExtensions_tags_13)
		/sizeof(asn_DEF_criticalExtensions_tags_13[0]) - 1, /* 1 */
	asn_DEF_criticalExtensions_tags_13,	/* Same as above */
	sizeof(asn_DEF_criticalExtensions_tags_13)
		/sizeof(asn_DEF_criticalExtensions_tags_13[0]), /* 2 */
	0,	/* No PER visible constraints */
	0, 0,	/* No members */
	&asn_SPC_criticalExtensions_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_criticalExtensions_8[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions, choice.r11),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r11_9,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"r11"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions, choice.criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_criticalExtensions_13,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"criticalExtensions"
		},
};
static asn_TYPE_tag2member_t asn_MAP_criticalExtensions_tag2el_8[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r11 at 3438 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions at 3442 */
};
static asn_CHOICE_specifics_t asn_SPC_criticalExtensions_specs_8 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions, _asn_ctx),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions, present),
	sizeof(((struct HandoverFromUTRANCommand_EUTRA__criticalExtensions__criticalExtensions *)0)->present),
	asn_MAP_criticalExtensions_tag2el_8,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_8 = {
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
	&asn_PER_type_criticalExtensions_constr_8,
	asn_MBR_criticalExtensions_8,
	2,	/* Elements count */
	&asn_SPC_criticalExtensions_specs_8	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_criticalExtensions_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions, choice.r8),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_r8_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"r8"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions, choice.criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_criticalExtensions_8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"criticalExtensions"
		},
};
static asn_TYPE_tag2member_t asn_MAP_criticalExtensions_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* r8 at 3431 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions at 3441 */
};
static asn_CHOICE_specifics_t asn_SPC_criticalExtensions_specs_3 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions, _asn_ctx),
	offsetof(struct HandoverFromUTRANCommand_EUTRA__criticalExtensions, present),
	sizeof(((struct HandoverFromUTRANCommand_EUTRA__criticalExtensions *)0)->present),
	asn_MAP_criticalExtensions_tag2el_3,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_criticalExtensions_3 = {
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
	&asn_PER_type_criticalExtensions_constr_3,
	asn_MBR_criticalExtensions_3,
	2,	/* Elements count */
	&asn_SPC_criticalExtensions_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_HandoverFromUTRANCommand_EUTRA_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rrc-TransactionIdentifier"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HandoverFromUTRANCommand_EUTRA, criticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_criticalExtensions_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"criticalExtensions"
		},
};
static ber_tlv_tag_t asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_HandoverFromUTRANCommand_EUTRA_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier at 3428 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* criticalExtensions at 3435 */
};
static asn_SEQUENCE_specifics_t asn_SPC_HandoverFromUTRANCommand_EUTRA_specs_1 = {
	sizeof(struct HandoverFromUTRANCommand_EUTRA),
	offsetof(struct HandoverFromUTRANCommand_EUTRA, _asn_ctx),
	asn_MAP_HandoverFromUTRANCommand_EUTRA_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_HandoverFromUTRANCommand_EUTRA = {
	"HandoverFromUTRANCommand-EUTRA",
	"HandoverFromUTRANCommand-EUTRA",
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
	asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1,
	sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1[0]), /* 1 */
	asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1,	/* Same as above */
	sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1)
		/sizeof(asn_DEF_HandoverFromUTRANCommand_EUTRA_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_HandoverFromUTRANCommand_EUTRA_1,
	2,	/* Elements count */
	&asn_SPC_HandoverFromUTRANCommand_EUTRA_specs_1	/* Additional specs */
};

