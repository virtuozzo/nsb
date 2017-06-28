META_SECTION		= "vzp_meta"

META_TAG_FILE		= 1
META_TAG_SYMBOL		= 2
META_TAG_ALIAS		= 3

VIS_EXTERNAL		= 0
VIS_INTERNAL		= 1
VIS_HIDDEN		= 2
VIS_PROTECTED		= 3
VIS_STATIC		= 100

class RAW(object):
	pass

class STR(object):
	pass

def set_const_raw(const_dict, prefix=None):
	for name, value in const_dict.iteritems():
		if name.startswith('_'):
			continue
		if prefix and not name.startswith(prefix):
			continue
		setattr(RAW, name, value)

def set_const_str(const_dict, prefix=None):
	for name in const_dict:
		if name.startswith('_'):
			continue
		if prefix and not name.startswith(prefix):
			continue
		setattr(STR, name, name)

