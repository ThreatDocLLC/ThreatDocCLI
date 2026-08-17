package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type State struct {
	path string
	data map[string]map[string][]string // reportID -> tool -> []externalID
}

func Load(path string) (*State, error) {
	s := &State{path: path, data: map[string]map[string][]string{}}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) Seen(reportID, tool, externalID string) bool {
	if externalID == "" {
		return false
	}
	for _, id := range s.data[reportID][tool] {
		if id == externalID {
			return true
		}
	}
	return false
}

func (s *State) MarkSeen(reportID, tool, externalID string) error {
	if externalID == "" {
		return nil
	}
	if s.data[reportID] == nil {
		s.data[reportID] = map[string][]string{}
	}
	s.data[reportID][tool] = append(s.data[reportID][tool], externalID)
	return s.save()
}

func (s *State) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".threatdoc-seen.json"
	}
	return filepath.Join(home, ".threatdoc", "seen.json")
}
