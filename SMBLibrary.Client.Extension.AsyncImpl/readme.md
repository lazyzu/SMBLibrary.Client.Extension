### About SMBLibrary.Client.Extension.AsyncImpl
`SMBLibrary.Client.Extension.AsyncImpl` is an asynchronous implementation of the Client functionality within [SMBLibrary](https://github.com/TalAloni/SMBLibrary).

### Differences from the Original Project's Client Functionality
* All methods are asynchronous.
* Supports cancellation tokens.
* Supports response time configuration.
* Returns results using the Result Pattern.
* The minimum target framework is .NET 4.6 and .NET Standard 2.0.

### Implementation Details
* `TaskCompletionSource` is used to replace the return wait in `WaitForMessage`.

### Licensing
`SMBLibrary.Client.Extension.AsyncImpl` can be used in any scenario without any cost. However, please note the [commercial usage restrictions of the underlying SMBLibrary](https://github.com/TalAloni/SMBLibrary?tab=readme-ov-file#licensing).