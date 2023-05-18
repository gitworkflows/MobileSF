/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "QualityReportCriteria.h"

static asn_per_constraints_t asn_PER_type_QualityReportCriteria_constr_1 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_QualityReportCriteria_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportCriteria, choice.qualityReportingCriteria),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_QualityReportingCriteria,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"qualityReportingCriteria"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportCriteria, choice.periodicalReportingCriteria),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PeriodicalReportingCriteria,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"periodicalReportingCriteria"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct QualityReportCriteria, choice.noReporting),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"noReporting"
		},
};
static asn_TYPE_tag2member_t asn_MAP_QualityReportCriteria_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* qualityReportingCriteria at 17860 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* periodicalReportingCriteria at 17861 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* noReporting at 17862 */
};
static asn_CHOICE_specifics_t asn_SPC_QualityReportCriteria_specs_1 = {
	sizeof(struct QualityReportCriteria),
	offsetof(struct QualityReportCriteria, _asn_ctx),
	offsetof(struct QualityReportCriteria, present),
	sizeof(((struct QualityReportCriteria *)0)->present),
	asn_MAP_QualityReportCriteria_tag2el_1,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_QualityReportCriteria = {
	"QualityReportCriteria",
	"QualityReportCriteria",
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
	&asn_PER_type_QualityReportCriteria_constr_1,
	asn_MBR_QualityReportCriteria_1,
	3,	/* Elements count */
	&asn_SPC_QualityReportCriteria_specs_1	/* Additional specs */
};

