/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "InterRATCellInfoList-r6.h"

static asn_TYPE_member_t asn_MBR_InterRATCellInfoList_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATCellInfoList_r6, removedInterRATCellList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_RemovedInterRATCellList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"removedInterRATCellList"
		},
	{ ATF_POINTER, 3, offsetof(struct InterRATCellInfoList_r6, newInterRATCellList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NewInterRATCellList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"newInterRATCellList"
		},
	{ ATF_POINTER, 2, offsetof(struct InterRATCellInfoList_r6, cellsForInterRATMeasList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellsForInterRATMeasList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cellsForInterRATMeasList"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATCellInfoList_r6, interRATCellInfoIndication_r6),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATCellInfoIndication,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATCellInfoIndication-r6"
		},
};
static int asn_MAP_InterRATCellInfoList_r6_oms_1[] = { 1, 2, 3 };
static ber_tlv_tag_t asn_DEF_InterRATCellInfoList_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_InterRATCellInfoList_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* removedInterRATCellList at 15499 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* newInterRATCellList at 15500 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* cellsForInterRATMeasList at 15501 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* interRATCellInfoIndication-r6 at 15502 */
};
static asn_SEQUENCE_specifics_t asn_SPC_InterRATCellInfoList_r6_specs_1 = {
	sizeof(struct InterRATCellInfoList_r6),
	offsetof(struct InterRATCellInfoList_r6, _asn_ctx),
	asn_MAP_InterRATCellInfoList_r6_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_InterRATCellInfoList_r6_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_InterRATCellInfoList_r6 = {
	"InterRATCellInfoList-r6",
	"InterRATCellInfoList-r6",
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
	asn_DEF_InterRATCellInfoList_r6_tags_1,
	sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1)
		/sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1[0]), /* 1 */
	asn_DEF_InterRATCellInfoList_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1)
		/sizeof(asn_DEF_InterRATCellInfoList_r6_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_InterRATCellInfoList_r6_1,
	4,	/* Elements count */
	&asn_SPC_InterRATCellInfoList_r6_specs_1	/* Additional specs */
};

