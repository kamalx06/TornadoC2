package transport

import (
	"tornadoc2/agent/crypto"
	"tornadoc2/agent/features"
	"tornadoc2/agent/protocol"
)

type Identity = protocol.Identity
type CheckinRequest = protocol.CheckinRequest
type CheckinResponse = protocol.CheckinResponse
type Task = protocol.Task
type Result = protocol.Result
type Profile = protocol.Profile
type WireSession = crypto.WireSession
type ShapingSpec = features.ShapingSpec