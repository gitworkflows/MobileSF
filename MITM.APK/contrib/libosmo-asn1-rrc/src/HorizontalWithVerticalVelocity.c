/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "HorizontalWithVerticalVelocity.h"

static int
verticalSpeedDirection_2_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
verticalSpeedDirection_2_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
verticalSpeedDirection_2_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
verticalSpeedDirection_2_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
verticalSpeedDirection_2_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
verticalSpeedDirection_2_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
verticalSpeedDirection_2_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
verticalSpeedDirection_2_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
verticalSpeedDirection_2_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
verticalSpeedDirection_2_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	verticalSpeedDirection_2_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
memb_bearing_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 359)) {
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
memb_horizontalSpeed_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 2047)) {
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
memb_verticalSpeed_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 255)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_type_verticalSpeedDirection_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_bearing_constr_5 = {
	{ APC_CONSTRAINED,	 9,  9,  0,  359 }	/* (0..359) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_horizontalSpeed_constr_6 = {
	{ APC_CONSTRAINED,	 11,  11,  0,  2047 }	/* (0..2047) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_memb_verticalSpeed_constr_7 = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_verticalSpeedDirection_value2enum_2[] = {
	{ 0,	6,	"upward" },
	{ 1,	8,	"downward" }
};
static unsigned int asn_MAP_verticalSpeedDirection_enum2value_2[] = {
	1,	/* downward(1) */
	0	/* upward(0) */
};
static asn_INTEGER_specifics_t asn_SPC_verticalSpeedDirection_specs_2 = {
	asn_MAP_verticalSpeedDirection_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_verticalSpeedDirection_enum2value_2,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_verticalSpeedDirection_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_verticalSpeedDirection_2 = {
	"verticalSpeedDirection",
	"verticalSpeedDirection",
	verticalSpeedDirection_2_free,
	verticalSpeedDirection_2_print,
	verticalSpeedDirection_2_constraint,
	verticalSpeedDirection_2_decode_ber,
	verticalSpeedDirection_2_encode_der,
	verticalSpeedDirection_2_decode_xer,
	verticalSpeedDirection_2_encode_xer,
	verticalSpeedDirection_2_decode_uper,
	verticalSpeedDirection_2_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_verticalSpeedDirection_tags_2,
	sizeof(asn_DEF_verticalSpeedDirection_tags_2)
		/sizeof(asn_DEF_verticalSpeedDirection_tags_2[0]) - 1, /* 1 */
	asn_DEF_verticalSpeedDirection_tags_2,	/* Same as above */
	sizeof(asn_DEF_verticalSpeedDirection_tags_2)
		/sizeof(asn_DEF_verticalSpeedDirection_tags_2[0]), /* 2 */
	&asn_PER_type_verticalSpeedDirection_constr_2,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_verticalSpeedDirection_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_HorizontalWithVerticalVelocity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct HorizontalWithVerticalVelocity, verticalSpeedDirection),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_verticalSpeedDirection_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"verticalSpeedDirection"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HorizontalWithVerticalVelocity, bearing),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_bearing_constraint_1,
		&asn_PER_memb_bearing_constr_5,
		0,
		"bearing"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HorizontalWithVerticalVelocity, horizontalSpeed),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_horizontalSpeed_constraint_1,
		&asn_PER_memb_horizontalSpeed_constr_6,
		0,
		"horizontalSpeed"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct HorizontalWithVerticalVelocity, verticalSpeed),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_verticalSpeed_constraint_1,
		&asn_PER_memb_verticalSpeed_constr_7,
		0,
		"verticalSpeed"
		},
};
static ber_tlv_tag_t asn_DEF_HorizontalWithVerticalVelocity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_HorizontalWithVerticalVelocity_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* verticalSpeedDirection at 14969 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* bearing at 14970 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* horizontalSpeed at 14971 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* verticalSpeed at 14972 */
};
static asn_SEQUENCE_specifics_t asn_SPC_HorizontalWithVerticalVelocity_specs_1 = {
	sizeof(struct HorizontalWithVerticalVelocity),
	offsetof(struct HorizontalWithVerticalVelocity, _asn_ctx),
	asn_MAP_HorizontalWithVerticalVelocity_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_HorizontalWithVerticalVelocity = {
	"HorizontalWithVerticalVelocity",
	"HorizontalWithVerticalVelocity",
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
	asn_DEF_HorizontalWithVerticalVelocity_tags_1,
	sizeof(asn_DEF_HorizontalWithVerticalVelocity_tags_1)
		/sizeof(asn_DEF_HorizontalWithVerticalVelocity_tags_1[0]), /* 1 */
	asn_DEF_HorizontalWithVerticalVelocity_tags_1,	/* Same as above */
	sizeof(asn_DEF_HorizontalWithVerticalVelocity_tags_1)
		/sizeof(asn_DEF_HorizontalWithVerticalVelocity_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_HorizontalWithVerticalVelocity_1,
	4,	/* Elements count */
	&asn_SPC_HorizontalWithVerticalVelocity_specs_1	/* Additional specs */
};

