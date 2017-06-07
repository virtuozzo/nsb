#ifndef NSB_VZP_X_INCL
#define NSB_VZP_X_INCL

#ifndef VZP_PREFIX
#define VZP_PREFIX				vzpatch_
#endif

#ifndef VZP_SECTION
#define VZP_SECTION 				"VZP"
#endif

#ifndef VZP_ALLOW_STATIC
#define VZP_STATIC_DEF_LINKAGE			extern
#define VZP_STATIC_ALT_LINKAGE			BAD_LINKAGE
#else
#define VZP_STATIC_DEF_LINKAGE			static
#define VZP_STATIC_ALT_LINKAGE			extern
#endif

#define VZP_VIS_STATIC				1
#define VZP_VIS_INTERNAL			2
#define VZP_VIS_HIDDEN				3
#define VZP_VIS_PROTECTED			4

#define VZP_X_PASTE(prefix, middle, suffix)				\
	prefix ## middle ## suffix

#define VZP_X_JOIN(...)							\
	VZP_X_PASTE(__VA_ARGS__)

#define VZP_X_JOIN_2(prefix, suffix)					\
	VZP_X_PASTE(prefix, , suffix)

#define VZP_X_FILE_T							\
	VZP_X_JOIN(VZP_PREFIX, file, _t)

typedef struct {
	char *filename;
	unsigned int line;
	char *target_filename;
} VZP_X_FILE_T;

#define VZP_X_SYMBOL_T							\
	VZP_X_JOIN(VZP_PREFIX, symbol, _t)

typedef struct {
	char *filename;
	unsigned int line;
	char *target_filename;
	char *symbol;
	int visibility;
} VZP_X_SYMBOL_T;

#define VZP_X_ALIAS_T							\
	VZP_X_JOIN(VZP_PREFIX, alias, _t)

typedef struct {
	char *patch_symbol;
	char *target_symbol;
} VZP_X_ALIAS_T;

#ifdef __COUNTER__
#define VZP_X_NEXT_NUM		__COUNTER__
#else
#define VZP_X_NEXT_NUM		__LINE__
#endif

#define VZP_X_CREATE_ID(basename, num)					\
	VZP_X_JOIN(VZP_PREFIX, basename, num)

#define VZP_X_FILE_ID							\
	VZP_X_CREATE_ID(file_, VZP_X_NEXT_NUM)

#define VZP_X_SYMBOL_ID							\
	VZP_X_CREATE_ID(sym_, VZP_X_NEXT_NUM)

#define VZP_X_ALIAS_ID							\
	VZP_X_CREATE_ID(alias_, VZP_X_NEXT_NUM)

#define VZP_X_ATTRS							\
	__attribute__((used, section(VZP_SECTION)))

#define VZP_X_AT_POS(_0, _1, _2, _3, _4, N, ...)			\
	N

#define VZP_X_COUNT(...)						\
	VZP_X_AT_POS(, ##__VA_ARGS__, 4, 3, 2, 1, 0)

#define VZP_X_COND_1(true_arg, false_arg)				\
	false_arg

#define VZP_X_COND_2(true_arg, false_arg)				\
	true_arg

#define VZP_X_COND_SELECT(n)						\
	VZP_X_JOIN_2(VZP_X_COND_, n)

#define VZP_X_VALUE_1							\
	^,^

#define VZP_X_RESCAN(macro, ...)					\
	macro(__VA_ARGS__)

#define VZP_X_COND(macro, arg_true, arg_false)				\
	VZP_X_COND_SELECT(VZP_X_RESCAN(					\
		VZP_X_COUNT, VZP_X_JOIN_2(VZP_X_VALUE_, macro)))	\
			(arg_true, arg_false)

#define VZP_X_LINKAGE(suffix)						\
	VZP_X_COND(VZP_X_JOIN_2(VZP_NO_STATIC_, suffix),		\
		     VZP_STATIC_ALT_LINKAGE, VZP_STATIC_DEF_LINKAGE)

#define VZP_X_DECL_VAR(type, name)					\
	VZP_X_LINKAGE(__LINE__) type name;

#define VZP_X_DECL_FUNC(type, name, args)				\
	extern type name args;

#define VZP_X_SYM_FILENAME(vis, name, fn)				\
	static const VZP_X_SYMBOL_T VZP_X_SYMBOL_ID VZP_X_ATTRS = {	\
		.filename		= __FILE__,			\
		.line			= __LINE__,			\
		.target_filename	= fn,				\
		.symbol			= #name,			\
		.visibility		= vis				\
	};

#define VZP_X_SYM(vis, name)						\
	VZP_X_SYM_FILENAME(vis, name, 0)

#define VZP_X_GET_HANDLER(prefix, n)					\
	VZP_X_PASTE(prefix, n, )

#define VZP_X_CALL(prefix, ...)						\
	VZP_X_GET_HANDLER(prefix, VZP_X_COUNT(__VA_ARGS__))(__VA_ARGS__)

#define VZP_X_STATIC_VAR_REF_2(type, name)				\
	VZP_X_DECL_VAR(type, name)					\
	VZP_X_SYM(VZP_VIS_STATIC, name)

#define VZP_X_STATIC_VAR_REF_3(type, name, filename)			\
	VZP_X_DECL_VAR(type, name)					\
	VZP_X_SYM_FILENAME(VZP_VIS_STATIC, name, filename)

#define VZP_X_STATIC_FUNC_REF_3(type, name, args)			\
	VZP_X_DECL_FUNC(type, name, args)				\
	VZP_X_SYM(VZP_VIS_STATIC, name)

#define VZP_X_STATIC_FUNC_REF_4(type, name, args, filename)		\
	VZP_X_DECL_FUNC(type, name, args)				\
	VZP_X_SYM_FILENAME(VZP_VIS_STATIC, name, filename)

// --- User API ---

#define VZP_FILE(name)							\
	static const VZP_X_FILE_T VZP_X_FILE_ID VZP_X_ATTRS = {		\
		.filename		= __FILE__,			\
		.line			= __LINE__,			\
		.target_filename =	name				\
	};

#define VZP_STATIC_SYM_ALIAS(patch_sym, target_sym)			\
	static const VZP_X_ALIAS_T VZP_X_ALIAS_ID VZP_X_ATTRS = { 	\
		.patch_symbol		= #patch_sym,			\
		.target_symbol		= #target_sym			\
	};

#define VZP_STATIC_VAR_REF(type, name, ...)				\
	VZP_X_CALL(VZP_X_STATIC_VAR_REF_, type, name, ##__VA_ARGS__)

#define VZP_INTERNAL_VAR_REF(type, name)				\
	VZP_X_DECL_VAR(type, name)					\
	VZP_X_SYM(VZP_VIS_INTERNAL, name)

#define VZP_HIDDEN_VAR_REF(type, name)					\
	VZP_X_DECL_VAR(type, name)					\
	VZP_X_SYM(VZP_VIS_HIDDEN, name)

#define VZP_PROTECTED_VAR_REF(type, name)				\
	VZP_X_DECL_VAR(type, name)					\
	VZP_X_SYM(VZP_VIS_PROTECTED, name)

#define VZP_STATIC_FUNC_REF(type, name, args, ...)			\
	VZP_X_CALL(VZP_X_STATIC_FUNC_REF_, type, name, args, ##__VA_ARGS__)

#define VZP_INTERNAL_FUNC_REF(type, name, args)				\
	VZP_X_DECL_FUNC(type, name, args)				\
	VZP_X_SYM(VZP_VIS_INTERNAL, name)

#define VZP_HIDDEN_FUNC_REF(type, name, args)				\
	VZP_X_DECL_FUNC(type, name, args)				\
	VZP_X_SYM(VZP_VIS_HIDDEN, name)

#define VZP_PROTECTED_FUNC_REF(type, name, args)			\
	VZP_X_DECL_FUNC(type, name, args)				\
	VZP_X_SYM(VZP_VIS_PROTECTED, name)


#endif	// NSB_VZP_X_INCL

