package protocol

var (
	ScheduleSleep  int     = -1
	ScheduleJitter float64 = -1
	ScheduleKill   int64   = 0
	WorkHoursStart int = 480  // 08:00
	WorkHoursEnd   int = 1140 // 19:00
	WireTLSProfile string = "go"
	DNSVerbB            string = ""
	DNSVerbT            string = ""
	DNSVerbR            string = ""
	DNSPayloadChunkSize int    = 0
	DNSLabelTemplate string = ""
)