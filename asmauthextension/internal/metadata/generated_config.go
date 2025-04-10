// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"go.opentelemetry.io/collector/confmap"
)

// ResourceAttributeConfig provides common config for a particular resource attribute.
type ResourceAttributeConfig struct {
	Enabled bool `mapstructure:"enabled"`

	enabledSetByUser bool
}

func (rac *ResourceAttributeConfig) Unmarshal(parser *confmap.Conf) error {
	if parser == nil {
		return nil
	}
	err := parser.Unmarshal(rac)
	if err != nil {
		return err
	}
	rac.enabledSetByUser = parser.IsSet("enabled")
	return nil
}

// ResourceAttributesConfig provides config for asmauthextension resource attributes.
type ResourceAttributesConfig struct {
	AwsRegion     ResourceAttributeConfig `mapstructure:"aws.region"`
	AwsSecretName ResourceAttributeConfig `mapstructure:"aws.secret_name"`
}

func DefaultResourceAttributesConfig() ResourceAttributesConfig {
	return ResourceAttributesConfig{
		AwsRegion: ResourceAttributeConfig{
			Enabled: true,
		},
		AwsSecretName: ResourceAttributeConfig{
			Enabled: true,
		},
	}
}
