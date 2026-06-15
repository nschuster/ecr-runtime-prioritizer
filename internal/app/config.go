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

func DefaultKubeconfigPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "ecr-prioritizer", "kubeconfig")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".config", "ecr-prioritizer", "kubeconfig")
	}
	return filepath.Join(".ecr-prioritizer", "kubeconfig")
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
