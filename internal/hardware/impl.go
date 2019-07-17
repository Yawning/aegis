// Copryright (C) 2019 Yawning Angel
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
// Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

// Package hardware provides hardware accelerated implementations.
package hardware

import "gitlab.com/yawning/aegis.git/internal/api"

// Factory is a factory that will construct hardware backed AEGIS
// implementations if supported.
var Factory api.Factory
