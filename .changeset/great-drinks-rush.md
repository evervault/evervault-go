---
"evervault-go": major
---

The `Encrypt` functions have been enhanced to accept an optional Data Role.

This role, once specified, is associated with the data upon encryption. Data Roles can be created in the Evervault Dashboard (Data Roles section) and provide a mechanism for setting clear rules that dictate how and when data, tagged with that role, can be decrypted. For more details check out https://docs.evervault.com/sdks/go#reference

evervault.EncryptString("hello world!", "allow-all");