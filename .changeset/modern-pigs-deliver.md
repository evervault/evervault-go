---
"evervault-go": minor
---

Introduce enclave functions to GoSDK and add a deprecation notice to the existing Cage functions. Users of the Cages Client are encouraged to migrate to the new Enclave Client.

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