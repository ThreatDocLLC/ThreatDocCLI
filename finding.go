package finding

type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	ExternalID  string `json:"-"`
}
