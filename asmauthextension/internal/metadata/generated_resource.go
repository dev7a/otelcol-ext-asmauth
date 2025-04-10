// Code generated by mdatagen. DO NOT EDIT.

package metadata

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// ResourceBuilder is a helper struct to build resources predefined in metadata.yaml.
// The ResourceBuilder is not thread-safe and must not to be used in multiple goroutines.
type ResourceBuilder struct {
	config ResourceAttributesConfig
	res    pcommon.Resource
}

// NewResourceBuilder creates a new ResourceBuilder. This method should be called on the start of the application.
func NewResourceBuilder(rac ResourceAttributesConfig) *ResourceBuilder {
	return &ResourceBuilder{
		config: rac,
		res:    pcommon.NewResource(),
	}
}

// SetAwsRegion sets provided value as "aws.region" attribute.
func (rb *ResourceBuilder) SetAwsRegion(val string) {
	if rb.config.AwsRegion.Enabled {
		rb.res.Attributes().PutStr("aws.region", val)
	}
}

// SetAwsSecretName sets provided value as "aws.secret_name" attribute.
func (rb *ResourceBuilder) SetAwsSecretName(val string) {
	if rb.config.AwsSecretName.Enabled {
		rb.res.Attributes().PutStr("aws.secret_name", val)
	}
}

// Emit returns the built resource and resets the internal builder state.
func (rb *ResourceBuilder) Emit() pcommon.Resource {
	r := rb.res
	rb.res = pcommon.NewResource()
	return r
}
