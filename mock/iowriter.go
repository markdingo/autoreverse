package mock

type IOWriter struct {
	line []byte
}

func (t *IOWriter) Reset() {
	t.line = make([]byte, 0)
}

func (t *IOWriter) Write(b []byte) (int, error) {
	t.line = append(t.line, b...)

	return len(b), nil
}

func (t *IOWriter) String() string {
	return string(t.line)
}

func (t *IOWriter) Len() int {
	return len(t.line)
}
