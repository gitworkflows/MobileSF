/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "MaxHcContextSpace.h"

int
MaxHcContextSpace_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
MaxHcContextSpace_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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

void
MaxHcContextSpace_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
MaxHcContextSpace_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
MaxHcContextSpace_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
MaxHcContextSpace_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
MaxHcContextSpace_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
MaxHcContextSpace_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

asn_dec_rval_t
MaxHcContextSpace_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

asn_enc_rval_t
MaxHcContextSpace_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	MaxHcContextSpace_1_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_MaxHcContextSpace_constr_1 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  4 }	/* (0..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_MaxHcContextSpace_value2enum_1[] = {
	{ 0,	5,	"dummy" },
	{ 1,	6,	"by1024" },
	{ 2,	6,	"by2048" },
	{ 3,	6,	"by4096" },
	{ 4,	6,	"by8192" }
};
static unsigned int asn_MAP_MaxHcContextSpace_enum2value_1[] = {
	1,	/* by1024(1) */
	2,	/* by2048(2) */
	3,	/* by4096(3) */
	4,	/* by8192(4) */
	0	/* dummy(0) */
};
static asn_INTEGER_specifics_t asn_SPC_MaxHcContextSpace_specs_1 = {
	asn_MAP_MaxHcContextSpace_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_MaxHcContextSpace_enum2value_1,	/* N => "tag"; sorted by N */
	5,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_MaxHcContextSpace_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_MaxHcContextSpace = {
	"MaxHcContextSpace",
	"MaxHcContextSpace",
	MaxHcContextSpace_free,
	MaxHcContextSpace_print,
	MaxHcContextSpace_constraint,
	MaxHcContextSpace_decode_ber,
	MaxHcContextSpace_encode_der,
	MaxHcContextSpace_decode_xer,
	MaxHcContextSpace_encode_xer,
	MaxHcContextSpace_decode_uper,
	MaxHcContextSpace_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_MaxHcContextSpace_tags_1,
	sizeof(asn_DEF_MaxHcContextSpace_tags_1)
		/sizeof(asn_DEF_MaxHcContextSpace_tags_1[0]), /* 1 */
	asn_DEF_MaxHcContextSpace_tags_1,	/* Same as above */
	sizeof(asn_DEF_MaxHcContextSpace_tags_1)
		/sizeof(asn_DEF_MaxHcContextSpace_tags_1[0]), /* 1 */
	&asn_PER_type_MaxHcContextSpace_constr_1,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_MaxHcContextSpace_specs_1	/* Additional specs */
};

