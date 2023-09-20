package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Decode reads fields from a buffer
func Decode(buf *bytes.Buffer, fields []interface{}) error {
	var err error
	for _, field := range fields {
		err = binary.Read(buf, binary.BigEndian, field)
		if err != nil {
			return fmt.Errorf("unable to read from buffer: %w", err)
		}
	}
	return nil
}

// DecodeUint8 decodes an uint8
func DecodeUint8(buf *bytes.Buffer, x *uint8) error {
	y, err := buf.ReadByte()
	if err != nil {
		return err
	}

	*x = y
	return nil
}

// DecodeUint16 decodes an uint16
func DecodeUint16(buf *bytes.Buffer, x *uint16) error {
	a, err := buf.ReadByte()
	if err != nil {
		return err
	}

	b, err := buf.ReadByte()
	if err != nil {
		return err
	}

	*x = uint16(a)<<8 + uint16(b)
	return nil
}

// DecodeUint32 decodes an uint32
func DecodeUint32(buf *bytes.Buffer, x *uint32) error {
	a, err := buf.ReadByte()
	if err != nil {
		return err
	}

	b, err := buf.ReadByte()
	if err != nil {
		return err
	}

	c, err := buf.ReadByte()
	if err != nil {
		return err
	}

	d, err := buf.ReadByte()
	if err != nil {
		return err
	}

	*x = uint32(a)<<24 + uint32(b)<<16 + uint32(c)<<8 + uint32(d)
	return nil
}

// DecodeUint32 decodes an uint32
func DecodeUint64(buf *bytes.Buffer, x *uint64) error {
	a, err := buf.ReadByte()
	if err != nil {
		return err
	}

	b, err := buf.ReadByte()
	if err != nil {
		return err
	}

	c, err := buf.ReadByte()
	if err != nil {
		return err
	}

	d, err := buf.ReadByte()
	if err != nil {
		return err
	}

	e, err := buf.ReadByte()
	if err != nil {
		return err
	}

	f, err := buf.ReadByte()
	if err != nil {
		return err
	}
	g, err := buf.ReadByte()
	if err != nil {
		return err
	}
	h, err := buf.ReadByte()
	if err != nil {
		return err
	}

	*x = uint64(a)<<56 + uint64(b)<<48 + uint64(c)<<40 + uint64(d)<<32 + uint64(e)<<24 + uint64(f)<<16 + uint64(g)<<8 + uint64(h)
	return nil
}
