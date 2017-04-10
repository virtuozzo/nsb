'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

class RAW(object):
	pass

class STR(object):
	pass

def set_const_raw(const_dict):
	for name, value in const_dict.iteritems():
		if name.startswith('_'):
			continue
		setattr(RAW, name, value)

def set_const_str(const_dict):
	for name in const_dict:
		if name.startswith('_'):
			continue
		setattr(STR, name, name)

