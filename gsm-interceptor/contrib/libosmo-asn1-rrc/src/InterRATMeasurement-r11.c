/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "InterRATMeasurement-r11.h"

static asn_per_constraints_t asn_PER_type_interRATMeasurementObjects_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_interRATMeasurementObjects_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATMeasurement_r11__interRATMeasurementObjects, choice.interRATCellInfoList),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATCellInfoList_r6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATCellInfoList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATMeasurement_r11__interRATMeasurementObjects, choice.eutra_FrequencyList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_EUTRA_FrequencyList_r11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"eutra-FrequencyList"
		},
};
static asn_TYPE_tag2member_t asn_MAP_interRATMeasurementObjects_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interRATCellInfoList at 15629 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* eutra-FrequencyList at 15631 */
};
static asn_CHOICE_specifics_t asn_SPC_interRATMeasurementObjects_specs_2 = {
	sizeof(struct InterRATMeasurement_r11__interRATMeasurementObjects),
	offsetof(struct InterRATMeasurement_r11__interRATMeasurementObjects, _asn_ctx),
	offsetof(struct InterRATMeasurement_r11__interRATMeasurementObjects, present),
	sizeof(((struct InterRATMeasurement_r11__interRATMeasurementObjects *)0)->present),
	asn_MAP_interRATMeasurementObjects_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_interRATMeasurementObjects_2 = {
	"interRATMeasurementObjects",
	"interRATMeasurementObjects",
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
	&asn_PER_type_interRATMeasurementObjects_constr_2,
	asn_MBR_interRATMeasurementObjects_2,
	2,	/* Elements count */
	&asn_SPC_interRATMeasurementObjects_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_InterRATMeasurement_r11_1[] = {
	{ ATF_POINTER, 3, offsetof(struct InterRATMeasurement_r11, interRATMeasurementObjects),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_interRATMeasurementObjects_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATMeasurementObjects"
		},
	{ ATF_POINTER, 2, offsetof(struct InterRATMeasurement_r11, interRATMeasQuantity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATMeasQuantity_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATMeasQuantity"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATMeasurement_r11, interRATReportingQuantity),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRATReportingQuantity_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRATReportingQuantity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterRATMeasurement_r11, reportCriteria),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_InterRATReportCriteria,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reportCriteria"
		},
	{ ATF_POINTER, 1, offsetof(struct InterRATMeasurement_r11, idleIntervalInfo),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IdleIntervalInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"idleIntervalInfo"
		},
};
static int asn_MAP_InterRATMeasurement_r11_oms_1[] = { 0, 1, 2, 4 };
static ber_tlv_tag_t asn_DEF_InterRATMeasurement_r11_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_InterRATMeasurement_r11_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interRATMeasurementObjects at 15629 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* interRATMeasQuantity at 15632 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* interRATReportingQuantity at 15633 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* reportCriteria at 15634 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* idleIntervalInfo at 15635 */
};
static asn_SEQUENCE_specifics_t asn_SPC_InterRATMeasurement_r11_specs_1 = {
	sizeof(struct InterRATMeasurement_r11),
	offsetof(struct InterRATMeasurement_r11, _asn_ctx),
	asn_MAP_InterRATMeasurement_r11_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_InterRATMeasurement_r11_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_InterRATMeasurement_r11 = {
	"InterRATMeasurement-r11",
	"InterRATMeasurement-r11",
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
	asn_DEF_InterRATMeasurement_r11_tags_1,
	sizeof(asn_DEF_InterRATMeasurement_r11_tags_1)
		/sizeof(asn_DEF_InterRATMeasurement_r11_tags_1[0]), /* 1 */
	asn_DEF_InterRATMeasurement_r11_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATMeasurement_r11_tags_1)
		/sizeof(asn_DEF_InterRATMeasurement_r11_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_InterRATMeasurement_r11_1,
	5,	/* Elements count */
	&asn_SPC_InterRATMeasurement_r11_specs_1	/* Additional specs */
};

