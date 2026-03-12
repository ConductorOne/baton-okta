package main

import (
	cfg "github.com/conductorone/baton-okta/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("okta", cfg.Config)
}
