// Package hardware provides hardware accelerated implementations.
package hardware

import "gitlab.com/yawning/aegis.git/internal/api"

// Factory is a factory that will construct hardware backed AEGIS
// implementations if supported.
var Factory api.Factory
