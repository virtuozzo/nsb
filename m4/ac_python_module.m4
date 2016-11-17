dnl macro that checks for specific modules in python 
AC_DEFUN([AC_PYTHON_MODULE], 
	[AC_MSG_CHECKING(for module $1 in python) 
	echo "import $1" | python - 2> /dev/null
	if test $? -ne 0 ; then 
	AC_MSG_RESULT(not found) 
	AC_MSG_ERROR(You need the module $1 available to python for this package) 
	fi 
	AC_MSG_RESULT(found) 
	])
