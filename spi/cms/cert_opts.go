package cms

// certOpts holds options for Create
type certOpts struct {
	chainID string
}

// NewCertOpts creates a new empty cert options.
// Not to be used directly. It's intended for implementations of KeyManager interface
func NewCertOpts() *certOpts { // nolint
	return &certOpts{}
}

func (c *certOpts) ChainID() string {
	return c.chainID
}

// CertOpt are the create cert option.
type CertOpt func(opts *certOpts)

func WithChainID(id string) CertOpt {
	return func(opts *certOpts) {
		opts.chainID = id
	}
}
