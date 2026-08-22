package cidrpolicy

import "errors"

var (
	ErrClosed   = errors.New("cidrpolicy: closed")
	ErrInvalid  = errors.New("cidrpolicy: invalid")
	ErrNotFound = errors.New("cidrpolicy: not found")
	ErrConflict = errors.New("cidrpolicy: conflict")
	ErrBadCIDR  = errors.New("cidrpolicy: bad cidr")
	ErrNoTable  = errors.New("cidrpolicy: no table")
)
