---
"evervault-go": patch
---

In the event that a Nitro Enclave Attestation Document was returned omitting the standard set of PCRs, the expected PCRs check was unsound due to its treatment of empty values.

This release corrects the check by validating attestation documents before storing in the cache, and replacing the naive equality checks with a new `SatisfiedBy` check.