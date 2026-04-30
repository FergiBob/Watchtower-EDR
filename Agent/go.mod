module Watchtower_EDR/agent

go 1.25.5

require (
	Watchtower_EDR/shared v0.0.0
	golang.org/x/sys v0.41.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require github.com/kardianos/service v1.2.4 // indirect

replace Watchtower_EDR/shared => ../shared
