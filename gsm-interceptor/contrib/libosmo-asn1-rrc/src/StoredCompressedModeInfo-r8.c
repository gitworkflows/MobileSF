/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "StoredCompressedModeInfo-r8.h"

static asn_TYPE_member_t asn_MBR_StoredCompressedModeInfo_r8_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct StoredCompressedModeInfo_r8, storedTGP_SequenceList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_StoredTGP_SequenceList_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"storedTGP-SequenceList"
		},
	{ ATF_POINTER, 1, offsetof(struct StoredCompressedModeInfo_r8, codeChangeStatusList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CodeChangeStatusList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"codeChangeStatusList"
		},
};
static int asn_MAP_StoredCompressedModeInfo_r8_oms_1[] = { 1 };
static ber_tlv_tag_t asn_DEF_StoredCompressedModeInfo_r8_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_StoredCompressedModeInfo_r8_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* storedTGP-SequenceList at 740 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* codeChangeStatusList at 741 */
};
static asn_SEQUENCE_specifics_t asn_SPC_StoredCompressedModeInfo_r8_specs_1 = {
	sizeof(struct StoredCompressedModeInfo_r8),
	offsetof(struct StoredCompressedModeInfo_r8, _asn_ctx),
	asn_MAP_StoredCompressedModeInfo_r8_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_StoredCompressedModeInfo_r8_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_StoredCompressedModeInfo_r8 = {
	"StoredCompressedModeInfo-r8",
	"StoredCompressedModeInfo-r8",
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
	asn_DEF_StoredCompressedModeInfo_r8_tags_1,
	sizeof(asn_DEF_StoredCompressedModeInfo_r8_tags_1)
		/sizeof(asn_DEF_StoredCompressedModeInfo_r8_tags_1[0]), /* 1 */
	asn_DEF_StoredCompressedModeInfo_r8_tags_1,	/* Same as above */
	sizeof(asn_DEF_StoredCompressedModeInfo_r8_tags_1)
		/sizeof(asn_DEF_StoredCompressedModeInfo_r8_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_StoredCompressedModeInfo_r8_1,
	2,	/* Elements count */
	&asn_SPC_StoredCompressedModeInfo_r8_specs_1	/* Additional specs */
};

