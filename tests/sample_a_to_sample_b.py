import testrunner

lpt = testrunner.LivePatchTest("sample_a", "sample_b")
ret = lpt.run()
exit(ret)
