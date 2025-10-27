package wire

import (
	"fmt"
	"io"
)

// ParseMwebBlock parses a Litecoin MWEB extension block from an io.Reader.
// The expected format is [MwebHeader][MwebTxBody] per libmw's network format.
// It returns the decoded header and tx body.
func ParseMwebBlock(r io.Reader) (*MwebHeader, *MwebTxBody, error) {
	mh := &MwebHeader{}
	if err := mh.read(r); err != nil {
		return nil, nil, fmt.Errorf("parse mweb header: %w", err)
	}

	tb := &MwebTxBody{}
	if err := tb.read(r, ProtocolVersion); err != nil {
		return nil, nil, fmt.Errorf("parse mweb txbody: %w", err)
	}

	return mh, tb, nil
}
