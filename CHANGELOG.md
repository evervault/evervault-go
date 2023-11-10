# evervault-go

## 1.0.0

### Major Changes

- 6b3906a: Making encrypt/decrypt type specific

  Previously the Encrypt function accepted input of type `any`, and the Decrypt function had a return type of `any`. In keeping with Go best practices, we have updated our encryption functions to accept and return specific types. For example, we now support `EncryptString` and `DecryptString` functions, as well as the respective functions for `int`, `float64`, `bool` and `[]byte`. For more details check out https://docs.evervault.com/sdks/go#reference

- dfb9c09: The `Encrypt` functions have been enhanced to accept an optional Data Role.

  This role, once specified, is associated with the data upon encryption. Data Roles can be created in the Evervault Dashboard (Data Roles section) and provide a mechanism for setting clear rules that dictate how and when data, tagged with that role, can be decrypted. For more details check out https://docs.evervault.com/sdks/go#reference

  evervault.EncryptString("hello world!", "allow-all");

- 7fa1634: Cages attestation: Remove deprecated attestation with CageClient and replace with CagesClient. Add the option to provide callback instead of static PCRs to allow automatic refresh of PCRs without the need to restart clients
- d3f0550: Migrated Function run requests to new API.

  We have released a new API for Function run requests which is more robust, more extensible, and which provides more useful error messages when Function runs fail. For more details check out https://docs.evervault.com/sdks/go#reference
