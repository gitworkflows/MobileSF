/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "MasterInformationBlock.h"

static ber_tlv_tag_t asn_DEF_nonCriticalExtensions_tags_11[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_nonCriticalExtensions_specs_11 = {
	sizeof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions__v860NonCriticalExtensions__nonCriticalExtensions),
	offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions__v860NonCriticalExtensions__nonCriticalExtensions, _asn_ctx),
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

static asn_TYPE_member_t asn_MBR_v860NonCriticalExtensions_9[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions__v860NonCriticalExtensions, masterInformationBlock_v860ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MasterInformationBlock_v860ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"masterInformationBlock-v860ext"
		},
	{ ATF_POINTER, 1, offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions__v860NonCriticalExtensions, nonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_nonCriticalExtensions_11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"nonCriticalExtensions"
		},
};
static int asn_MAP_v860NonCriticalExtensions_oms_9[] = { 1 };
static ber_tlv_tag_t asn_DEF_v860NonCriticalExtensions_tags_9[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v860NonCriticalExtensions_tag2el_9[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* masterInformationBlock-v860ext at 20354 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* nonCriticalExtensions at 20355 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v860NonCriticalExtensions_specs_9 = {
	sizeof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions__v860NonCriticalExtensions),
	offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions__v860NonCriticalExtensions, _asn_ctx),
	asn_MAP_v860NonCriticalExtensions_tag2el_9,
	2,	/* Count of tags in the map */
	asn_MAP_v860NonCriticalExtensions_oms_9,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v860NonCriticalExtensions_9 = {
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
	asn_DEF_v860NonCriticalExtensions_tags_9,
	sizeof(asn_DEF_v860NonCriticalExtensions_tags_9)
		/sizeof(asn_DEF_v860NonCriticalExtensions_tags_9[0]) - 1, /* 1 */
	asn_DEF_v860NonCriticalExtensions_tags_9,	/* Same as above */
	sizeof(asn_DEF_v860NonCriticalExtensions_tags_9)
		/sizeof(asn_DEF_v860NonCriticalExtensions_tags_9[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v860NonCriticalExtensions_9,
	2,	/* Elements count */
	&asn_SPC_v860NonCriticalExtensions_specs_9	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v6b0NonCriticalExtensions_7[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions, masterInformationBlock_v6b0ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MasterInformationBlock_v6b0ext_IEs,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"masterInformationBlock-v6b0ext"
		},
	{ ATF_POINTER, 1, offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions, v860NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v860NonCriticalExtensions_9,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v860NonCriticalExtensions"
		},
};
static int asn_MAP_v6b0NonCriticalExtensions_oms_7[] = { 1 };
static ber_tlv_tag_t asn_DEF_v6b0NonCriticalExtensions_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v6b0NonCriticalExtensions_tag2el_7[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* masterInformationBlock-v6b0ext at 20352 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v860NonCriticalExtensions at 20354 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v6b0NonCriticalExtensions_specs_7 = {
	sizeof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions),
	offsetof(struct MasterInformationBlock__v690NonCriticalExtensions__v6b0NonCriticalExtensions, _asn_ctx),
	asn_MAP_v6b0NonCriticalExtensions_tag2el_7,
	2,	/* Count of tags in the map */
	asn_MAP_v6b0NonCriticalExtensions_oms_7,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v6b0NonCriticalExtensions_7 = {
	"v6b0NonCriticalExtensions",
	"v6b0NonCriticalExtensions",
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
	asn_DEF_v6b0NonCriticalExtensions_tags_7,
	sizeof(asn_DEF_v6b0NonCriticalExtensions_tags_7)
		/sizeof(asn_DEF_v6b0NonCriticalExtensions_tags_7[0]) - 1, /* 1 */
	asn_DEF_v6b0NonCriticalExtensions_tags_7,	/* Same as above */
	sizeof(asn_DEF_v6b0NonCriticalExtensions_tags_7)
		/sizeof(asn_DEF_v6b0NonCriticalExtensions_tags_7[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v6b0NonCriticalExtensions_7,
	2,	/* Elements count */
	&asn_SPC_v6b0NonCriticalExtensions_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_v690NonCriticalExtensions_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MasterInformationBlock__v690NonCriticalExtensions, masterInformationBlock_v690ext),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MasterInformationBlock_v690ext,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"masterInformationBlock-v690ext"
		},
	{ ATF_POINTER, 1, offsetof(struct MasterInformationBlock__v690NonCriticalExtensions, v6b0NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_v6b0NonCriticalExtensions_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v6b0NonCriticalExtensions"
		},
};
static int asn_MAP_v690NonCriticalExtensions_oms_5[] = { 1 };
static ber_tlv_tag_t asn_DEF_v690NonCriticalExtensions_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_v690NonCriticalExtensions_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* masterInformationBlock-v690ext at 20350 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* v6b0NonCriticalExtensions at 20352 */
};
static asn_SEQUENCE_specifics_t asn_SPC_v690NonCriticalExtensions_specs_5 = {
	sizeof(struct MasterInformationBlock__v690NonCriticalExtensions),
	offsetof(struct MasterInformationBlock__v690NonCriticalExtensions, _asn_ctx),
	asn_MAP_v690NonCriticalExtensions_tag2el_5,
	2,	/* Count of tags in the map */
	asn_MAP_v690NonCriticalExtensions_oms_5,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_v690NonCriticalExtensions_5 = {
	"v690NonCriticalExtensions",
	"v690NonCriticalExtensions",
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
	asn_DEF_v690NonCriticalExtensions_tags_5,
	sizeof(asn_DEF_v690NonCriticalExtensions_tags_5)
		/sizeof(asn_DEF_v690NonCriticalExtensions_tags_5[0]) - 1, /* 1 */
	asn_DEF_v690NonCriticalExtensions_tags_5,	/* Same as above */
	sizeof(asn_DEF_v690NonCriticalExtensions_tags_5)
		/sizeof(asn_DEF_v690NonCriticalExtensions_tags_5[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_v690NonCriticalExtensions_5,
	2,	/* Elements count */
	&asn_SPC_v690NonCriticalExtensions_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_MasterInformationBlock_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MasterInformationBlock, mib_ValueTag),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MIB_ValueTag,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mib-ValueTag"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MasterInformationBlock, plmn_Type),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PLMN_Type,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"plmn-Type"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MasterInformationBlock, sibSb_ReferenceList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SIBSb_ReferenceList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sibSb-ReferenceList"
		},
	{ ATF_POINTER, 1, offsetof(struct MasterInformationBlock, v690NonCriticalExtensions),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_v690NonCriticalExtensions_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"v690NonCriticalExtensions"
		},
};
static int asn_MAP_MasterInformationBlock_oms_1[] = { 3 };
static ber_tlv_tag_t asn_DEF_MasterInformationBlock_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_MasterInformationBlock_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mib-ValueTag at 20343 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* plmn-Type at 20346 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* sibSb-ReferenceList at 20347 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* v690NonCriticalExtensions at 20350 */
};
static asn_SEQUENCE_specifics_t asn_SPC_MasterInformationBlock_specs_1 = {
	sizeof(struct MasterInformationBlock),
	offsetof(struct MasterInformationBlock, _asn_ctx),
	asn_MAP_MasterInformationBlock_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_MasterInformationBlock_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_MasterInformationBlock = {
	"MasterInformationBlock",
	"MasterInformationBlock",
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
	asn_DEF_MasterInformationBlock_tags_1,
	sizeof(asn_DEF_MasterInformationBlock_tags_1)
		/sizeof(asn_DEF_MasterInformationBlock_tags_1[0]), /* 1 */
	asn_DEF_MasterInformationBlock_tags_1,	/* Same as above */
	sizeof(asn_DEF_MasterInformationBlock_tags_1)
		/sizeof(asn_DEF_MasterInformationBlock_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_MasterInformationBlock_1,
	4,	/* Elements count */
	&asn_SPC_MasterInformationBlock_specs_1	/* Additional specs */
};

