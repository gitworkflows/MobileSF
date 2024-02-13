/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "InterRATMeasurement-r6.h"

static asn_TYPE_member_t asn_MBR_InterRATMeasurement_r6_1[] = {
	{ ATF_POINTER, 3, offsetof(struct InterRATMeasurement_r6, interRATCellInfoList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATCellInfoList_r6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATCellInfoList"
		},
	{ ATF_POINTER, 2, offsetof(struct InterRATMeasurement_r6, interRATMeasQuantity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATMeasQuantity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATMeasQuantity"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATMeasurement_r6, interRATReportingQuantity),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATReportingQuantity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATReportingQuantity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATMeasurement_r6, reportCriteria),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_InterRATReportCriteria,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reportCriteria"
		},
};
static int asn_MAP_InterRATMeasurement_r6_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_InterRATMeasurement_r6_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_InterRATMeasurement_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interRATCellInfoList at 15599 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* interRATMeasQuantity at 15600 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* interRATReportingQuantity at 15601 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* reportCriteria at 15603 */
};
static asn_SEQUENCE_specifics_t asn_SPC_InterRATMeasurement_r6_specs_1 = {
	sizeof(struct InterRATMeasurement_r6),
	offsetof(struct InterRATMeasurement_r6, _asn_ctx),
	asn_MAP_InterRATMeasurement_r6_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_InterRATMeasurement_r6_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_InterRATMeasurement_r6 = {
	"InterRATMeasurement-r6",
	"InterRATMeasurement-r6",
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
	asn_DEF_InterRATMeasurement_r6_tags_1,
	sizeof(asn_DEF_InterRATMeasurement_r6_tags_1)
		/sizeof(asn_DEF_InterRATMeasurement_r6_tags_1[0]), /* 1 */
	asn_DEF_InterRATMeasurement_r6_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATMeasurement_r6_tags_1)
		/sizeof(asn_DEF_InterRATMeasurement_r6_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_InterRATMeasurement_r6_1,
	4,	/* Elements count */
	&asn_SPC_InterRATMeasurement_r6_specs_1	/* Additional specs */
};

