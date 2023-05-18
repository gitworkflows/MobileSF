/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DownlinkAdditionalTimeslots-r7.h"

static asn_per_constraints_t asn_PER_type_parameters_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_sameAsLast_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkAdditionalTimeslots_r7__parameters__sameAsLast, timeslotNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeslotNumber"
		},
};
static ber_tlv_tag_t asn_DEF_sameAsLast_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_sameAsLast_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* timeslotNumber at 7838 */
};
static asn_SEQUENCE_specifics_t asn_SPC_sameAsLast_specs_3 = {
	sizeof(struct DownlinkAdditionalTimeslots_r7__parameters__sameAsLast),
	offsetof(struct DownlinkAdditionalTimeslots_r7__parameters__sameAsLast, _asn_ctx),
	asn_MAP_sameAsLast_tag2el_3,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_sameAsLast_3 = {
	"sameAsLast",
	"sameAsLast",
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
	asn_DEF_sameAsLast_tags_3,
	sizeof(asn_DEF_sameAsLast_tags_3)
		/sizeof(asn_DEF_sameAsLast_tags_3[0]) - 1, /* 1 */
	asn_DEF_sameAsLast_tags_3,	/* Same as above */
	sizeof(asn_DEF_sameAsLast_tags_3)
		/sizeof(asn_DEF_sameAsLast_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_sameAsLast_3,
	1,	/* Elements count */
	&asn_SPC_sameAsLast_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_newParameters_5[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkAdditionalTimeslots_r7__parameters__newParameters, individualTimeslotInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IndividualTimeslotInfo_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"individualTimeslotInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkAdditionalTimeslots_r7__parameters__newParameters, dl_TS_ChannelisationCodesShort),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TS_ChannelisationCodesShort,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-TS-ChannelisationCodesShort"
		},
};
static ber_tlv_tag_t asn_DEF_newParameters_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_newParameters_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* individualTimeslotInfo at 7840 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* dl-TS-ChannelisationCodesShort at 7842 */
};
static asn_SEQUENCE_specifics_t asn_SPC_newParameters_specs_5 = {
	sizeof(struct DownlinkAdditionalTimeslots_r7__parameters__newParameters),
	offsetof(struct DownlinkAdditionalTimeslots_r7__parameters__newParameters, _asn_ctx),
	asn_MAP_newParameters_tag2el_5,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_newParameters_5 = {
	"newParameters",
	"newParameters",
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
	asn_DEF_newParameters_tags_5,
	sizeof(asn_DEF_newParameters_tags_5)
		/sizeof(asn_DEF_newParameters_tags_5[0]) - 1, /* 1 */
	asn_DEF_newParameters_tags_5,	/* Same as above */
	sizeof(asn_DEF_newParameters_tags_5)
		/sizeof(asn_DEF_newParameters_tags_5[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_newParameters_5,
	2,	/* Elements count */
	&asn_SPC_newParameters_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_parameters_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkAdditionalTimeslots_r7__parameters, choice.sameAsLast),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_sameAsLast_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sameAsLast"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkAdditionalTimeslots_r7__parameters, choice.newParameters),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_newParameters_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"newParameters"
		},
};
static asn_TYPE_tag2member_t asn_MAP_parameters_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* sameAsLast at 7838 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* newParameters at 7840 */
};
static asn_CHOICE_specifics_t asn_SPC_parameters_specs_2 = {
	sizeof(struct DownlinkAdditionalTimeslots_r7__parameters),
	offsetof(struct DownlinkAdditionalTimeslots_r7__parameters, _asn_ctx),
	offsetof(struct DownlinkAdditionalTimeslots_r7__parameters, present),
	sizeof(((struct DownlinkAdditionalTimeslots_r7__parameters *)0)->present),
	asn_MAP_parameters_tag2el_2,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_parameters_2 = {
	"parameters",
	"parameters",
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
	&asn_PER_type_parameters_constr_2,
	asn_MBR_parameters_2,
	2,	/* Elements count */
	&asn_SPC_parameters_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_DownlinkAdditionalTimeslots_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DownlinkAdditionalTimeslots_r7, parameters),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_parameters_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"parameters"
		},
};
static ber_tlv_tag_t asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DownlinkAdditionalTimeslots_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* parameters at 7838 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DownlinkAdditionalTimeslots_r7_specs_1 = {
	sizeof(struct DownlinkAdditionalTimeslots_r7),
	offsetof(struct DownlinkAdditionalTimeslots_r7, _asn_ctx),
	asn_MAP_DownlinkAdditionalTimeslots_r7_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DownlinkAdditionalTimeslots_r7 = {
	"DownlinkAdditionalTimeslots-r7",
	"DownlinkAdditionalTimeslots-r7",
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
	asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1,
	sizeof(asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1)
		/sizeof(asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1[0]), /* 1 */
	asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1)
		/sizeof(asn_DEF_DownlinkAdditionalTimeslots_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DownlinkAdditionalTimeslots_r7_1,
	1,	/* Elements count */
	&asn_SPC_DownlinkAdditionalTimeslots_r7_specs_1	/* Additional specs */
};

