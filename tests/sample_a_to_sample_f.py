import testrunner

lpt = testrunner.LivePatchTest("./sample_a", "./sample_f")
ret = lpt.run()
exit(ret)
