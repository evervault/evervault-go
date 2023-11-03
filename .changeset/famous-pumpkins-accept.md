---
"evervault-go": major
---

Making encrypt/decrypt type specific

Previously the Encrypt function accepted input of type `any`, and the Decrypt function had a return type of `any`. In keeping with Go best practices, we have updated our encryption functions to accept and return specific types. For example, we now support `EncryptString` and `DecryptString` functions, as well as the respective functions for `int`, `float64`, `bool` and `[]byte`. For more details check out https://docs.evervault.com/sdks/go#reference