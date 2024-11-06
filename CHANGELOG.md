# evervault-go

## 1.3.0

### Minor Changes

- 1255ba5: Patch Decrypt calls and Enclave Attestation Document fetching

## 1.2.0

### Minor Changes

- ffa079e: deprecate byte array encryption

## 1.1.0

### Minor Changes

- f35e6f3: Introduce enclave functions to the Go SDK and add a deprecation notice to the existing Cage functions. Users of the Cages Client are encouraged to migrate to the new Enclave Client.

  Users of the `CagesClient` should be able to directly replace with the `EnclaveClient` as follows:

  ```go
  // Deprecated Cage client implementation
  cageURL = "<CAGE_NAME>.<APP_UUID>.cages.evervault.com"
  expectedPCRs := evervault.PCRs{
    PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
    PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
    PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
    PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
  }

  cageClient, err := evClient.CagesClient(cageURL, []evervault.PCRs{expectedPCRs})

  // Updated Enclave client implementation
  enclaveURL = "<ENCLAVE_NAME>.<APP_UUID>.enclave.evervault.com"
  expectedPCRs := evervault.PCRs{
    PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
    PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
    PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
    PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
  }

  enclaveClient, err := evClient.EnclaveClient(enclaveURL, []evervault.PCRs{expectedPCRs})
  ```

  Users of the newer Clients with Providers should follow a similar migration pattern:

  ```go
  // Deprecated Cage client implementation
  cageURL = "<CAGE_NAME>.<APP_UUID>.cages.evervault.com"
  func GetPCRs() ([]attestation.PCRs, error) {
    // logic to get PCRs
    return pcrs, nil
  }

  cageClient, err := evClient.CagesClientWithProvider(cageURL, GetPCRs)

  // Updated Enclave client implementation
  enclaveURL = "<ENCLAVE_NAME>.<APP_UUID>.enclave.evervault.com"
  func GetPCRs() ([]attestation.PCRs, error) {
    // logic to get PCRs
    return pcrs, nil
  }

  enclaveClient, err := evClient.EnclaveClientWithProvider(enclaveURL, GetPCRs)
  ```

  We also recommend users of the Provider pattern update their custom polling interval environment variable from `EV_CAGES_POLLING_INTERVAL` to `EV_ATTESTATION_POLLING_INTERVAL` where relevant.

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
