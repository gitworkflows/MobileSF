/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "GANSS-SAT-Info-Almanac-MIDIkpList.h"

static asn_per_constraints_t asn_PER_type_GANSS_SAT_Info_Almanac_MIDIkpList_constr_1 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 6,  6,  1,  64 }	/* (SIZE(1..64)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_GANSS_SAT_Info_Almanac_MIDIkpList_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_GANSS_SAT_Info_Almanac_MIDIkp,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		""
		},
};
static ber_tlv_tag_t asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_GANSS_SAT_Info_Almanac_MIDIkpList_specs_1 = {
	sizeof(struct GANSS_SAT_Info_Almanac_MIDIkpList),
	offsetof(struct GANSS_SAT_Info_Almanac_MIDIkpList, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList = {
	"GANSS-SAT-Info-Almanac-MIDIkpList",
	"GANSS-SAT-Info-Almanac-MIDIkpList",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	SEQUENCE_OF_decode_uper,
	SEQUENCE_OF_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1,
	sizeof(asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1)
		/sizeof(asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1[0]), /* 1 */
	asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1,	/* Same as above */
	sizeof(asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1)
		/sizeof(asn_DEF_GANSS_SAT_Info_Almanac_MIDIkpList_tags_1[0]), /* 1 */
	&asn_PER_type_GANSS_SAT_Info_Almanac_MIDIkpList_constr_1,
	asn_MBR_GANSS_SAT_Info_Almanac_MIDIkpList_1,
	1,	/* Single element */
	&asn_SPC_GANSS_SAT_Info_Almanac_MIDIkpList_specs_1	/* Additional specs */
};

