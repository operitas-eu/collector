// export_test.go exposes unexported methods for use by external test packages
// (package datadog_test). Compiled ONLY for test builds; not included in the
// production binary.
package datadog

import "context"

// PollForTest triggers a single poll cycle. Intended only for external test
// packages to verify poller behaviour (e.g. redirect refusal) without
// starting the full RunPoller ticker loop.
func (s *Source) PollForTest(ctx context.Context) error {
	return s.poll(ctx)
}
