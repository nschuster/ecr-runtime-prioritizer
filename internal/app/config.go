package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

type FileConfig struct {
	Clusters map[string]model.ClusterTunnel `json:"clusters"`
}

func DefaultConfigPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "ecr-prioritizer", "config.json")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".ecr-prioritizer.json")
	}
	return "ecr-prioritizer.json"
}

func LoadFileConfig(path string) (FileConfig, error) {
	var cfg FileConfig
	if path == "" {
		path = DefaultConfigPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func SaveFileConfig(path string, cfg FileConfig) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	if cfg.Clusters == nil {
		cfg.Clusters = map[string]model.ClusterTunnel{}
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
