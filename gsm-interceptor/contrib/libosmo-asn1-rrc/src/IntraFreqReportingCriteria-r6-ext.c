/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "IntraFreqReportingCriteria-r6-ext.h"

static asn_TYPE_member_t asn_MBR_IntraFreqReportingCriteria_r6_ext_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFreqReportingCriteria_r6_ext, event),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Event1j_r6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFreqReportingCriteria_r6_ext, hysteresis),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Hysteresis,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"hysteresis"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IntraFreqReportingCriteria_r6_ext, timeToTrigger),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeToTrigger,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeToTrigger"
		},
	{ ATF_POINTER, 1, offsetof(struct IntraFreqReportingCriteria_r6_ext, reportingCellStatus),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ReportingCellStatus,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reportingCellStatus"
		},
};
static int asn_MAP_IntraFreqReportingCriteria_r6_ext_oms_1[] = { 3 };
static ber_tlv_tag_t asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_IntraFreqReportingCriteria_r6_ext_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* event at 1639 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* hysteresis at 1640 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timeToTrigger at 1641 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* reportingCellStatus at 1642 */
};
static asn_SEQUENCE_specifics_t asn_SPC_IntraFreqReportingCriteria_r6_ext_specs_1 = {
	sizeof(struct IntraFreqReportingCriteria_r6_ext),
	offsetof(struct IntraFreqReportingCriteria_r6_ext, _asn_ctx),
	asn_MAP_IntraFreqReportingCriteria_r6_ext_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_IntraFreqReportingCriteria_r6_ext_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_IntraFreqReportingCriteria_r6_ext = {
	"IntraFreqReportingCriteria-r6-ext",
	"IntraFreqReportingCriteria-r6-ext",
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
	asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1,
	sizeof(asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1)
		/sizeof(asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1[0]), /* 1 */
	asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1,	/* Same as above */
	sizeof(asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1)
		/sizeof(asn_DEF_IntraFreqReportingCriteria_r6_ext_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_IntraFreqReportingCriteria_r6_ext_1,
	4,	/* Elements count */
	&asn_SPC_IntraFreqReportingCriteria_r6_ext_specs_1	/* Additional specs */
};

