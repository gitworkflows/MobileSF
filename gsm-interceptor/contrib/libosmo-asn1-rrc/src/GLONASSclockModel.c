/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "GLONASSclockModel.h"

static int
memb_gloTau_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 22)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_gloGamma_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 11)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_gloDeltaTau_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	if(st->size > 0) {
		/* Size in bits */
		size = 8 * st->size - (st->bits_unused & 0x07);
	} else {
		size = 0;
	}
	
	if((size == 5)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_gloTau_constr_2 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  22,  22 }	/* (SIZE(22..22)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_gloGamma_constr_3 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  11,  11 }	/* (SIZE(11..11)) */,
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_gloDeltaTau_constr_4 = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 0,  0,  5,  5 }	/* (SIZE(5..5)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_GLONASSclockModel_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GLONASSclockModel, gloTau),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		memb_gloTau_constraint_1,
		&asn_PER_memb_gloTau_constr_2,
		0,
		"gloTau"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct GLONASSclockModel, gloGamma),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		memb_gloGamma_constraint_1,
		&asn_PER_memb_gloGamma_constr_3,
		0,
		"gloGamma"
		},
	{ ATF_POINTER, 1, offsetof(struct GLONASSclockModel, gloDeltaTau),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		memb_gloDeltaTau_constraint_1,
		&asn_PER_memb_gloDeltaTau_constr_4,
		0,
		"gloDeltaTau"
		},
};
static int asn_MAP_GLONASSclockModel_oms_1[] = { 2 };
static ber_tlv_tag_t asn_DEF_GLONASSclockModel_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_GLONASSclockModel_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* gloTau at 14845 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* gloGamma at 14846 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* gloDeltaTau at 14847 */
};
static asn_SEQUENCE_specifics_t asn_SPC_GLONASSclockModel_specs_1 = {
	sizeof(struct GLONASSclockModel),
	offsetof(struct GLONASSclockModel, _asn_ctx),
	asn_MAP_GLONASSclockModel_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_GLONASSclockModel_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_GLONASSclockModel = {
	"GLONASSclockModel",
	"GLONASSclockModel",
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
	asn_DEF_GLONASSclockModel_tags_1,
	sizeof(asn_DEF_GLONASSclockModel_tags_1)
		/sizeof(asn_DEF_GLONASSclockModel_tags_1[0]), /* 1 */
	asn_DEF_GLONASSclockModel_tags_1,	/* Same as above */
	sizeof(asn_DEF_GLONASSclockModel_tags_1)
		/sizeof(asn_DEF_GLONASSclockModel_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_GLONASSclockModel_1,
	3,	/* Elements count */
	&asn_SPC_GLONASSclockModel_specs_1	/* Additional specs */
};

