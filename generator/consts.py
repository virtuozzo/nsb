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

