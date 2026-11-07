package collector

// Supported action constants.
const (
	ActionDF              = "df"
	ActionTop             = "top"
	ActionDockerStats     = "docker_stats"
	ActionDockerInspect   = "docker_inspect"
	ActionDockerLogs      = "docker_logs"
	ActionDockerStop      = "docker_stop"
	ActionComposeServices = "compose_services"
	ActionComposePS       = "compose_ps"
	ActionComposeUp       = "compose_up"
	ActionAuthLog         = "auth_log"
)

// Request defines the typed JSON payload sent to dpanel-collector.
type Request struct {
	Token   string `json:"token"`
	Action  string `json:"action"`
	ID      string `json:"id,omitempty"`
	Path    string `json:"path,omitempty"`
	Service string `json:"service,omitempty"`
	Tail    int    `json:"tail,omitempty"`
	Lines   int    `json:"lines,omitempty"`
}

// Response defines the typed JSON response returned by dpanel-collector.
type Response struct {
	Success    bool   `json:"success"`
	Output     string `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}
