/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "InterFreqCellInfoList-r8.h"

static asn_TYPE_member_t asn_MBR_InterFreqCellInfoList_r8_1[] = {
	{ ATF_POINTER, 3, offsetof(struct InterFreqCellInfoList_r8, removedInterFreqCellList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RemovedInterFreqCellList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"removedInterFreqCellList"
		},
	{ ATF_POINTER, 2, offsetof(struct InterFreqCellInfoList_r8, newInterFreqCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NewInterFreqCellList_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"newInterFreqCellList"
		},
	{ ATF_POINTER, 1, offsetof(struct InterFreqCellInfoList_r8, cellsForInterFreqMeasList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellsForInterFreqMeasList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cellsForInterFreqMeasList"
		},
};
static int asn_MAP_InterFreqCellInfoList_r8_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_InterFreqCellInfoList_r8_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_InterFreqCellInfoList_r8_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* removedInterFreqCellList at 15026 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* newInterFreqCellList at 15027 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* cellsForInterFreqMeasList at 15028 */
};
static asn_SEQUENCE_specifics_t asn_SPC_InterFreqCellInfoList_r8_specs_1 = {
	sizeof(struct InterFreqCellInfoList_r8),
	offsetof(struct InterFreqCellInfoList_r8, _asn_ctx),
	asn_MAP_InterFreqCellInfoList_r8_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_InterFreqCellInfoList_r8_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_InterFreqCellInfoList_r8 = {
	"InterFreqCellInfoList-r8",
	"InterFreqCellInfoList-r8",
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
	asn_DEF_InterFreqCellInfoList_r8_tags_1,
	sizeof(asn_DEF_InterFreqCellInfoList_r8_tags_1)
		/sizeof(asn_DEF_InterFreqCellInfoList_r8_tags_1[0]), /* 1 */
	asn_DEF_InterFreqCellInfoList_r8_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterFreqCellInfoList_r8_tags_1)
		/sizeof(asn_DEF_InterFreqCellInfoList_r8_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_InterFreqCellInfoList_r8_1,
	3,	/* Elements count */
	&asn_SPC_InterFreqCellInfoList_r8_specs_1	/* Additional specs */
};

