package mock

// IOWriter is a mock replacement for any place that accepts an io.Writer. Only used by
// test programs, it appends each write to a []byte slice and makes it available via the
// String() function. In the case of autoreverse, it's most often used to replace the log
// package output to capture logging activity and compare it against expected.
type IOWriter struct {
	line []byte
}

// Reset clears the byte slice such that String() will now return an empty string.
func (t *IOWriter) Reset() {
	t.line = make([]byte, 0)
}

// Write helps meet the io.Writer interface. Is appends the bytes to the internal byte slice.
func (t *IOWriter) Write(b []byte) (int, error) {
	t.line = append(t.line, b...)

	return len(b), nil
}

// String returns the complete byte slice as a string. The byte slice is not changed by
// this function call. If you want the slice to be reset, called the Reset() function.
func (t *IOWriter) String() string {
	return string(t.line)
}

// Len is a helper function which returns the size of the byte slice.
func (t *IOWriter) Len() int {
	return len(t.line)
}
