# Remediation Verification

After a security fix:
1. rerun the original failing test;
2. validate expected rejection;
3. confirm legitimate flow still passes;
4. test a nearby variant;
5. review security log;
6. keep the case as regression coverage.

A fix is complete only when behavior is verified.