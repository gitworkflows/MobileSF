/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "E-DCH-RL-InfoNewServingCell-r7.h"

static int
primary_Secondary_GrantSelector_6_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	/* Replace with underlying type checker */
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void
primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_NativeEnumerated.free_struct;
	td->print_struct   = asn_DEF_NativeEnumerated.print_struct;
	td->ber_decoder    = asn_DEF_NativeEnumerated.ber_decoder;
	td->der_encoder    = asn_DEF_NativeEnumerated.der_encoder;
	td->xer_decoder    = asn_DEF_NativeEnumerated.xer_decoder;
	td->xer_encoder    = asn_DEF_NativeEnumerated.xer_encoder;
	td->uper_decoder   = asn_DEF_NativeEnumerated.uper_decoder;
	td->uper_encoder   = asn_DEF_NativeEnumerated.uper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
	td->elements       = asn_DEF_NativeEnumerated.elements;
	td->elements_count = asn_DEF_NativeEnumerated.elements_count;
     /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined explicitly */
}

static void
primary_Secondary_GrantSelector_6_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
primary_Secondary_GrantSelector_6_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
primary_Secondary_GrantSelector_6_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
primary_Secondary_GrantSelector_6_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
primary_Secondary_GrantSelector_6_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
primary_Secondary_GrantSelector_6_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
primary_Secondary_GrantSelector_6_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
primary_Secondary_GrantSelector_6_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	primary_Secondary_GrantSelector_6_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
memb_value_constraint_4(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 38)) {
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
memb_powerOffsetForSchedInfo_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 6)) {
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
memb_threeIndexStepThreshold_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 37)) {
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
memb_twoIndexStepThreshold_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 37)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_primary_Secondary_GrantSelector_constr_6 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_value_constr_5 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  38 }	/* (0..38) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_e_RGCH_Info_constr_15 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_powerOffsetForSchedInfo_constr_11 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  6 }	/* (0..6) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_threeIndexStepThreshold_constr_12 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  37 }	/* (0..37) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_twoIndexStepThreshold_constr_13 = {
	{ APC_CONSTRAINED,	 6,  6,  0,  37 }	/* (0..37) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_primary_Secondary_GrantSelector_value2enum_6[] = {
	{ 0,	7,	"primary" },
	{ 1,	9,	"secondary" }
};
static unsigned int asn_MAP_primary_Secondary_GrantSelector_enum2value_6[] = {
	0,	/* primary(0) */
	1	/* secondary(1) */
};
static asn_INTEGER_specifics_t asn_SPC_primary_Secondary_GrantSelector_specs_6 = {
	asn_MAP_primary_Secondary_GrantSelector_value2enum_6,	/* "tag" => N; sorted by tag */
	asn_MAP_primary_Secondary_GrantSelector_enum2value_6,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_primary_Secondary_GrantSelector_tags_6[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_primary_Secondary_GrantSelector_6 = {
	"primary-Secondary-GrantSelector",
	"primary-Secondary-GrantSelector",
	primary_Secondary_GrantSelector_6_free,
	primary_Secondary_GrantSelector_6_print,
	primary_Secondary_GrantSelector_6_constraint,
	primary_Secondary_GrantSelector_6_decode_ber,
	primary_Secondary_GrantSelector_6_encode_der,
	primary_Secondary_GrantSelector_6_decode_xer,
	primary_Secondary_GrantSelector_6_encode_xer,
	primary_Secondary_GrantSelector_6_decode_uper,
	primary_Secondary_GrantSelector_6_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_primary_Secondary_GrantSelector_tags_6,
	sizeof(asn_DEF_primary_Secondary_GrantSelector_tags_6)
		/sizeof(asn_DEF_primary_Secondary_GrantSelector_tags_6[0]) - 1, /* 1 */
	asn_DEF_primary_Secondary_GrantSelector_tags_6,	/* Same as above */
	sizeof(asn_DEF_primary_Secondary_GrantSelector_tags_6)
		/sizeof(asn_DEF_primary_Secondary_GrantSelector_tags_6[0]), /* 2 */
	&asn_PER_type_primary_Secondary_GrantSelector_constr_6,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_primary_Secondary_GrantSelector_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_servingGrant_4[] = {
	{ ATF_POINTER, 1, offsetof(struct E_DCH_RL_InfoNewServingCell_r7__servingGrant, value),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_value_constraint_4,
		&asn_PER_memb_value_constr_5,
		0,
		"value"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_RL_InfoNewServingCell_r7__servingGrant, primary_Secondary_GrantSelector),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_primary_Secondary_GrantSelector_6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primary-Secondary-GrantSelector"
		},
};
static int asn_MAP_servingGrant_oms_4[] = { 0 };
static ber_tlv_tag_t asn_DEF_servingGrant_tags_4[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_servingGrant_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* value at 8207 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* primary-Secondary-GrantSelector at 8208 */
};
static asn_SEQUENCE_specifics_t asn_SPC_servingGrant_specs_4 = {
	sizeof(struct E_DCH_RL_InfoNewServingCell_r7__servingGrant),
	offsetof(struct E_DCH_RL_InfoNewServingCell_r7__servingGrant, _asn_ctx),
	asn_MAP_servingGrant_tag2el_4,
	2,	/* Count of tags in the map */
	asn_MAP_servingGrant_oms_4,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_servingGrant_4 = {
	"servingGrant",
	"servingGrant",
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
	asn_DEF_servingGrant_tags_4,
	sizeof(asn_DEF_servingGrant_tags_4)
		/sizeof(asn_DEF_servingGrant_tags_4[0]) - 1, /* 1 */
	asn_DEF_servingGrant_tags_4,	/* Same as above */
	sizeof(asn_DEF_servingGrant_tags_4)
		/sizeof(asn_DEF_servingGrant_tags_4[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_servingGrant_4,
	2,	/* Elements count */
	&asn_SPC_servingGrant_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_e_RGCH_Info_15[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_RL_InfoNewServingCell_r7__e_RGCH_Info, choice.e_RGCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RGCH_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-RGCH-Information"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_RL_InfoNewServingCell_r7__e_RGCH_Info, choice.releaseIndicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"releaseIndicator"
		},
};
static asn_TYPE_tag2member_t asn_MAP_e_RGCH_Info_tag2el_15[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-RGCH-Information at 8217 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* releaseIndicator at 8218 */
};
static asn_CHOICE_specifics_t asn_SPC_e_RGCH_Info_specs_15 = {
	sizeof(struct E_DCH_RL_InfoNewServingCell_r7__e_RGCH_Info),
	offsetof(struct E_DCH_RL_InfoNewServingCell_r7__e_RGCH_Info, _asn_ctx),
	offsetof(struct E_DCH_RL_InfoNewServingCell_r7__e_RGCH_Info, present),
	sizeof(((struct E_DCH_RL_InfoNewServingCell_r7__e_RGCH_Info *)0)->present),
	asn_MAP_e_RGCH_Info_tag2el_15,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_e_RGCH_Info_15 = {
	"e-RGCH-Info",
	"e-RGCH-Info",
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
	&asn_PER_type_e_RGCH_Info_constr_15,
	asn_MBR_e_RGCH_Info_15,
	2,	/* Elements count */
	&asn_SPC_e_RGCH_Info_specs_15	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_E_DCH_RL_InfoNewServingCell_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primaryCPICH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, e_AGCH_Information),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_AGCH_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-AGCH-Information"
		},
	{ ATF_POINTER, 8, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, servingGrant),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_servingGrant_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"servingGrant"
		},
	{ ATF_POINTER, 7, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, e_DPCCH_DPCCH_PowerOffset),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPCCH_DPCCH_PowerOffset,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-DPCCH-DPCCH-PowerOffset"
		},
	{ ATF_POINTER, 6, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, reference_E_TFCIs),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_Reference_E_TFCIList_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reference-E-TFCIs"
		},
	{ ATF_POINTER, 5, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, powerOffsetForSchedInfo),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_powerOffsetForSchedInfo_constraint_1,
		&asn_PER_memb_powerOffsetForSchedInfo_constr_11,
		0,
		"powerOffsetForSchedInfo"
		},
	{ ATF_POINTER, 4, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, threeIndexStepThreshold),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_threeIndexStepThreshold_constraint_1,
		&asn_PER_memb_threeIndexStepThreshold_constr_12,
		0,
		"threeIndexStepThreshold"
		},
	{ ATF_POINTER, 3, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, twoIndexStepThreshold),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_twoIndexStepThreshold_constraint_1,
		&asn_PER_memb_twoIndexStepThreshold_constr_13,
		0,
		"twoIndexStepThreshold"
		},
	{ ATF_POINTER, 2, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, e_HICH_Information),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_HICH_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-HICH-Information"
		},
	{ ATF_POINTER, 1, offsetof(struct E_DCH_RL_InfoNewServingCell_r7, e_RGCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_e_RGCH_Info_15,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-RGCH-Info"
		},
};
static int asn_MAP_E_DCH_RL_InfoNewServingCell_r7_oms_1[] = { 2, 3, 4, 5, 6, 7, 8, 9 };
static ber_tlv_tag_t asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_E_DCH_RL_InfoNewServingCell_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info at 8204 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* e-AGCH-Information at 8205 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* servingGrant at 8207 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* e-DPCCH-DPCCH-PowerOffset at 8210 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* reference-E-TFCIs at 8211 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* powerOffsetForSchedInfo at 8212 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* threeIndexStepThreshold at 8213 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* twoIndexStepThreshold at 8214 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* e-HICH-Information at 8215 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 } /* e-RGCH-Info at 8217 */
};
static asn_SEQUENCE_specifics_t asn_SPC_E_DCH_RL_InfoNewServingCell_r7_specs_1 = {
	sizeof(struct E_DCH_RL_InfoNewServingCell_r7),
	offsetof(struct E_DCH_RL_InfoNewServingCell_r7, _asn_ctx),
	asn_MAP_E_DCH_RL_InfoNewServingCell_r7_tag2el_1,
	10,	/* Count of tags in the map */
	asn_MAP_E_DCH_RL_InfoNewServingCell_r7_oms_1,	/* Optional members */
	8, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_E_DCH_RL_InfoNewServingCell_r7 = {
	"E-DCH-RL-InfoNewServingCell-r7",
	"E-DCH-RL-InfoNewServingCell-r7",
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
	asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1,
	sizeof(asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1)
		/sizeof(asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1[0]), /* 1 */
	asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1)
		/sizeof(asn_DEF_E_DCH_RL_InfoNewServingCell_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_E_DCH_RL_InfoNewServingCell_r7_1,
	10,	/* Elements count */
	&asn_SPC_E_DCH_RL_InfoNewServingCell_r7_specs_1	/* Additional specs */
};

