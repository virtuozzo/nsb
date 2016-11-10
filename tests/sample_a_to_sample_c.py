import testrunner

lpt = testrunner.LivePatchTest("sample_a", "sample_c")
ret = lpt.run()
exit(ret)
