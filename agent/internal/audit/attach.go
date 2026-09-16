package audit

import (
	"fmt"
	"io"
)

// Attachments takes the objects that rode with the record out of the file the
// module passed with it. Every attach locator names an offset and a size; a
// span outside the file is a broken record, not a short object, and is
// refused whole rather than read as garbage.
func Attachments(raw []byte, file io.ReaderAt, size int64) (map[string][]byte, error) {
	section, err := ParseStore(raw)
	if err != nil {
		return nil, err
	}

	var out map[string][]byte

	for _, kind := range Kinds {
		loc, ok := section.Attach(kind)
		if !ok {
			continue
		}

		if loc.Offset < 0 || loc.Size < 0 || loc.Offset > size-loc.Size {
			return nil, fmt.Errorf("audit: %s attachment [%d+%d] is outside "+
				"the %d byte file", kind, loc.Offset, loc.Size, size)
		}

		if file == nil {
			return nil, fmt.Errorf("audit: %s is attached, but no file came "+
				"with the record", kind)
		}

		data := make([]byte, loc.Size)

		if _, err := file.ReadAt(data, loc.Offset); err != nil && err != io.EOF {
			return nil, fmt.Errorf("audit: %s attachment: %w", kind, err)
		}

		if out == nil {
			out = make(map[string][]byte, len(Kinds))
		}

		out[kind] = data
	}

	return out, nil
}
