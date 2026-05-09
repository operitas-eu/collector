// Package ptrs holds tiny pointer helpers shared across the collector.
package ptrs

// String returns a pointer to s, or nil if s is empty. Useful when an event
// field is *string and an empty value should mean "absent" rather than "".
func String(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
