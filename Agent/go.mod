module Watchtower_EDR/agent

go 1.25.5

require (
	golang.org/x/sys v0.41.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	Watchtower_EDR/shared v0.0.0
)

replace Watchtower_EDR/shared => ../shared
