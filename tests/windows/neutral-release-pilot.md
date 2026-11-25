# Verify a Windows release

Use two test profiles with distinguishable servers and icons, one original Actions artifact and a clean Windows x64 snapshot. Record the workflow commit, run ID and attempt, ZIP digest, tool versions and test results. Use synthetic connection settings in shared reports.

- [ ] Run the Windows resource tests and the two PowerShell test files in this directory on a disposable test system. The signing test imports a temporary test certificate into the current user's trust store.
- [ ] Build both profiles from the same ZIP using the publisher script and the intended signing card. Verify the signer, SHA-256 digest and RFC 3161 timestamp for each portable EXE and MSI.
- [ ] From a clean snapshot, run each portable client. Check the icon, ID server and API login. Establish a session with a consenting second test client through the configured relay. Confirm that an incorrect server public key prevents the expected authenticated connection.
- [ ] Install each MSI from a clean snapshot. Repeat the connection checks after a service restart and verify that the application uninstalls successfully.
- [ ] Exercise the failure paths with a different run attempt, a modified ZIP, invalid PNG and wrong certificate. Cancel the second signing round. Confirm that the previous release remains intact and that the failed attempt produces no new release directory. Retry from the original artifact.
