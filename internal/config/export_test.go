// export_test.go exposes unexported functions for use by external test packages
// (package config_test). These symbols are compiled ONLY for test builds; the
// production binary never includes this file.
package config

// IsKnownAcceptableEndpointForTest exposes isKnownAcceptableEndpoint for
// external test packages (internal/config/config_test.go).
var IsKnownAcceptableEndpointForTest = isKnownAcceptableEndpoint

// IsKnownNonEUEndpointForTest exposes isKnownNonEUEndpoint for external test
// packages (internal/config/config_test.go).
var IsKnownNonEUEndpointForTest = isKnownNonEUEndpoint
