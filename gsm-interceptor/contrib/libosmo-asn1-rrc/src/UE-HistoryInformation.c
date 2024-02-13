/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UE-HistoryInformation.h"

static int
memb_ue_InactivityPeriod_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 120)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_ue_InactivityPeriod_constr_2 = {
	{ APC_CONSTRAINED,	 7,  7,  1,  120 }	/* (1..120) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_UE_HistoryInformation_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_HistoryInformation, ue_InactivityPeriod),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_ue_InactivityPeriod_constraint_1,
		&asn_PER_memb_ue_InactivityPeriod_constr_2,
		0,
		"ue-InactivityPeriod"
		},
	{ ATF_POINTER, 3, offsetof(struct UE_HistoryInformation, ueMobilityStateIndicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_High_MobilityDetected,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ueMobilityStateIndicator"
		},
	{ ATF_POINTER, 2, offsetof(struct UE_HistoryInformation, ul_dataVolumeHistory),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DataVolumeHistory,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-dataVolumeHistory"
		},
	{ ATF_POINTER, 1, offsetof(struct UE_HistoryInformation, dl_dataVolumeHistory),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DataVolumeHistory,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-dataVolumeHistory"
		},
};
static int asn_MAP_UE_HistoryInformation_oms_1[] = { 1, 2, 3 };
static ber_tlv_tag_t asn_DEF_UE_HistoryInformation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UE_HistoryInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ue-InactivityPeriod at 21900 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ueMobilityStateIndicator at 21901 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* ul-dataVolumeHistory at 21902 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* dl-dataVolumeHistory at 21903 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UE_HistoryInformation_specs_1 = {
	sizeof(struct UE_HistoryInformation),
	offsetof(struct UE_HistoryInformation, _asn_ctx),
	asn_MAP_UE_HistoryInformation_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_UE_HistoryInformation_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UE_HistoryInformation = {
	"UE-HistoryInformation",
	"UE-HistoryInformation",
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
	asn_DEF_UE_HistoryInformation_tags_1,
	sizeof(asn_DEF_UE_HistoryInformation_tags_1)
		/sizeof(asn_DEF_UE_HistoryInformation_tags_1[0]), /* 1 */
	asn_DEF_UE_HistoryInformation_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_HistoryInformation_tags_1)
		/sizeof(asn_DEF_UE_HistoryInformation_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UE_HistoryInformation_1,
	4,	/* Elements count */
	&asn_SPC_UE_HistoryInformation_specs_1	/* Additional specs */
};

