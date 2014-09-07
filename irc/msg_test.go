package irc

import (
	"bufio"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Tests Parse called on messages that do not contain errors.
func TestParseOK(t *testing.T) {
	tests := []struct {
		raw string
		msg Message
	}{
		{
			raw: ":e!foo@bar.com JOIN #test54321",
			msg: Message{
				Origin:    "e",
				User:      "foo",
				Host:      "bar.com",
				Command:   "JOIN",
				Arguments: []string{"#test54321"},
			},
		},
		{
			raw: ":e JOIN #test54321",
			msg: Message{
				Origin:    "e",
				Command:   "JOIN",
				Arguments: []string{"#test54321"},
			},
		},
		{
			raw: "JOIN #test54321",
			msg: Message{
				Command:   "JOIN",
				Arguments: []string{"#test54321"},
			},
		},
		{
			raw: "JOIN #test54321 :foo bar",
			msg: Message{
				Command:   "JOIN",
				Arguments: []string{"#test54321", "foo bar"},
			},
		},
		{
			raw: "JOIN #test54321 ::foo bar",
			msg: Message{
				Command:   "JOIN",
				Arguments: []string{"#test54321", ":foo bar"},
			},
		},
		{
			raw: "JOIN    #test54321    foo       bar   ",
			msg: Message{
				Command:   "JOIN",
				Arguments: []string{"#test54321", "foo", "bar"},
			},
		},
		{
			raw: "JOIN :",
			msg: Message{
				Command:   "JOIN",
				Arguments: []string{""},
			},
		},
	}

	for _, test := range tests {
		m, err := Parse(test.raw)
		if err != nil {
			t.Errorf(err.Error())
		}
		if !reflect.DeepEqual(m, test.msg) {
			t.Errorf("failed to correctly parse %#v\nGot: %#v", test, m)
		}
	}
}

// Tests read (the unexported version that does not call parse) on messages without errors.
func TestReadOk(t *testing.T) {
	max := make([]byte, MaxBytes)
	for i := range max {
		max[i] = 'a'
	}
	max[len(max)-2] = '\r'
	max[len(max)-1] = '\n'

	tests := []struct {
		s  string
		ms []string
	}{
		{"a\r\nb\r\nc\r\n", []string{"a", "b", "c"}},
		{"a\r\nb\r\n\r\nc\r\n", []string{"a", "b", "c"}},
		{"a \r\nb	\r\n\r\nc\r\n", []string{"a ", "b	", "c"}},
		{
			":e!foo@bar.com JOIN #test54321\r\n",
			[]string{":e!foo@bar.com JOIN #test54321"},
		},
		{string(max), []string{string(max[:len(max)-2])}},
	}

	for _, test := range tests {
		in := bufio.NewReader(strings.NewReader(test.s))
		i := 0
		for {
			m, err := read(in)
			if err == io.EOF && i == len(test.ms) {
				break
			}
			if i >= len(test.ms) {
				t.Errorf("expected end of messages")
			}
			if err != nil {
				t.Errorf(err.Error())
			}
			if m != test.ms[i] {
				t.Errorf("expected message %s, got %s",
					test.ms[i], m)
			}
			i++
		}
	}
}

// Tests read (the unexported version that does not call parse) on messages with errors.
func TestReadError(t *testing.T) {
	tooLong := make([]byte, MaxBytes)
	for i := range tooLong {
		tooLong[i] = 'a'
	}
	tooLong[len(tooLong)-1] = '\r'

	tests := []struct {
		s      string
		errStr string
	}{
		// EOF if there's nothing left.
		{"", io.EOF.Error()},

		{"a", "unexpected end of file in message stream"},
		{"a\r\r\n", "unexpected carrage return in message stream"},
		{"hello there\000\r\n", "unexpected null in message stream"},
		{string(tooLong), ErrTooLong.Error()},
	}

	for _, test := range tests {
		in := bufio.NewReader(strings.NewReader(test.s))
		_, err := read(in)
		if err == nil {
			t.Errorf("expected error [%s], got none", test.errStr)
		} else if matched, _ := regexp.MatchString(test.errStr, err.Error()); !matched {
			t.Errorf("unexpected error [%s], expected [%s]",
				err, test.errStr)
		}
	}
}
