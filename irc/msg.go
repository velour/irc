package irc

// Parsing of IRC messages as specified in RFC 1459.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxBytes is the maximum size of a message in bytes.
const MaxBytes = 512

// delimiter is the marker delineating messages in the TCP stream.
const delimiter = "\r\n"

// MsgTooLong is returned as an error when a message is received that is longer
// than the maximum message size.
type MsgTooLong struct {
	// Message is the truncated message text.
	Message string
	// NTrunc is the number of truncated bytes.
	NTrunc int
}

func (m MsgTooLong) Error() string {
	return fmt.Sprintf("Message is too long (%d bytes truncated): %s", m.NTrunc, m.Message)
}

// A Command is an IRC command as specified by RFC 2812.
type Command string

func (c Command) String() string {
	return string(c)
}

// Commands as specified by RFC 2812.
const (
	PASS                 Command = "PASS"
	NICK                         = "NICK"
	USER                         = "USER"
	OPER                         = "OPER"
	MODE                         = "MODE"
	SERVICE                      = "SERVICE"
	QUIT                         = "QUIT"
	SQUIT                        = "SQUIT"
	JOIN                         = "JOIN"
	PART                         = "PART"
	TOPIC                        = "TOPIC"
	NAMES                        = "NAMES"
	LIST                         = "LIST"
	INVITE                       = "INVITE"
	KICK                         = "KICK"
	PRIVMSG                      = "PRIVMSG"
	NOTICE                       = "NOTICE"
	MOTD                         = "MOTD"
	LUSERS                       = "LUSERS"
	VERSION                      = "VERSION"
	STATS                        = "STATS"
	LINKS                        = "LINKS"
	TIME                         = "TIME"
	CONNECT                      = "CONNECT"
	TRACE                        = "TRACE"
	ADMIN                        = "ADMIN"
	INFO                         = "INFO"
	SERVLIST                     = "SERVLIST"
	SQUERY                       = "SQUERY"
	WHO                          = "WHO"
	WHOIS                        = "WHOIS"
	WHOWAS                       = "WHOWAS"
	KILL                         = "KILL"
	PING                         = "PING"
	PONG                         = "PONG"
	ERROR                        = "ERROR"
	AWAY                         = "AWAY"
	REHASH                       = "REHASH"
	DIE                          = "DIE"
	RESTART                      = "RESTART"
	SUMMON                       = "SUMMON"
	USERS                        = "USERS"
	WALLOPS                      = "WALLOPS"
	USERHOST                     = "USERHOST"
	ISON                         = "ISON"
	RplWELCOME                   = "001"
	RplYOURHOST                  = "002"
	RplCREATED                   = "003"
	RplMYINFO                    = "004"
	RplBOUNCE                    = "005"
	RplUSERHOST                  = "302"
	RplISON                      = "303"
	RplAWAY                      = "301"
	RplUNAWAY                    = "305"
	RplNOWAWAY                   = "306"
	RplWHOISUSER                 = "311"
	RplWHOISSERVER               = "312"
	RplWHOISOPERATOR             = "313"
	RplWHOISIDLE                 = "317"
	RplENDOFWHOIS                = "318"
	RplWHOISCHANNELS             = "319"
	RplWHOWASUSER                = "314"
	RplENDOFWHOWAS               = "369"
	RplLISTSTART                 = "321"
	RplLIST                      = "322"
	RplLISTEND                   = "323"
	RplUNIQOPIS                  = "325"
	RplCHANNELMODEIS             = "324"
	RplNOTOPIC                   = "331"
	RplTOPIC                     = "332"
	RplTOPICWHOTIME              = "333" // ircu specific (not in the RFC)
	RplINVITING                  = "341"
	RplSUMMONING                 = "342"
	RplINVITELIST                = "346"
	RplENDOFINVITELIST           = "347"
	RplEXCEPTLIST                = "348"
	RplENDOFEXCEPTLIST           = "349"
	RplVERSION                   = "351"
	RplWHOREPLY                  = "352"
	RplENDOFWHO                  = "315"
	RplNAMREPLY                  = "353"
	RplENDOFNAMES                = "366"
	RplLINKS                     = "364"
	RplENDOFLINKS                = "365"
	RplBANLIST                   = "367"
	RplENDOFBANLIST              = "368"
	RplINFO                      = "371"
	RplENDOFINFO                 = "374"
	RplMOTDSTART                 = "375"
	RplMOTD                      = "372"
	RplENDOFMOTD                 = "376"
	RplYOUREOPER                 = "381"
	RplREHASHING                 = "382"
	RplYOURESERVICE              = "383"
	RplTIME                      = "391"
	RplUSERSSTART                = "392"
	RplUSERS                     = "393"
	RplENDOFUSERS                = "394"
	RplNOUSERS                   = "395"
	RplTRACELINK                 = "200"
	RplTRACECONNECTING           = "201"
	RplTRACEHANDSHAKE            = "202"
	RplTRACEUNKNOWN              = "203"
	RplTRACEOPERATOR             = "204"
	RplTRACEUSER                 = "205"
	RplTRACESERVER               = "206"
	RplTRACESERVICE              = "207"
	RplTRACENEWTYPE              = "208"
	RplTRACECLASS                = "209"
	RplTRACERECONNECT            = "210"
	RplTRACELOG                  = "261"
	RplTRACEEND                  = "262"
	RplSTATSLINKINFO             = "211"
	RplSTATSCOMMANDS             = "212"
	RplENDOFSTATS                = "219"
	RplSTATSUPTIME               = "242"
	RplSTATSOLINE                = "243"
	RplUMODEIS                   = "221"
	RplSERVLIST                  = "234"
	RplSERVLISTEND               = "235"
	RplLUSERCLIENT               = "251"
	RplLUSEROP                   = "252"
	RplLUSERUNKNOWN              = "253"
	RplLUSERCHANNELS             = "254"
	RplLUSERME                   = "255"
	RplADMINME                   = "256"
	RplADMINLOC1                 = "257"
	RplADMINLOC2                 = "258"
	RplADMINEMAIL                = "259"
	RplTRYAGAIN                  = "263"
	ErrNOSUCHNICK                = "401"
	ErrNOSUCHSERVER              = "402"
	ErrNOSUCHCHANNEL             = "403"
	ErrCANNOTSENDTOCHAN          = "404"
	ErrTOOMANYCHANNELS           = "405"
	ErrWASNOSUCHNICK             = "406"
	ErrTOOMANYTARGETS            = "407"
	ErrNOSUCHSERVICE             = "408"
	ErrNOORIGIN                  = "409"
	ErrNORECIPIENT               = "411"
	ErrNOTEXTTOSEND              = "412"
	ErrNOTOPLEVEL                = "413"
	ErrWILDTOPLEVEL              = "414"
	ErrBADMASK                   = "415"
	ErrUNKNOWNCOMMAND            = "421"
	ErrNOMOTD                    = "422"
	ErrNOADMININFO               = "423"
	ErrFILEERROR                 = "424"
	ErrNONICKNAMEGIVEN           = "431"
	ErrERRONEUSNICKNAME          = "432"
	ErrNICKNAMEINUSE             = "433"
	ErrNICKCOLLISION             = "436"
	ErrUNAVAILRESOURCE           = "437"
	ErrUSERNOTINCHANNEL          = "441"
	ErrNOTONCHANNEL              = "442"
	ErrUSERONCHANNEL             = "443"
	ErrNOLOGIN                   = "444"
	ErrSUMMONDISABLED            = "445"
	ErrUSERSDISABLED             = "446"
	ErrNOTREGISTERED             = "451"
	ErrNEEDMOREPARAMS            = "461"
	ErrALREADYREGISTRED          = "462"
	ErrNOPERMFORHOST             = "463"
	ErrPASSWDMISMATCH            = "464"
	ErrYOUREBANNEDCREEP          = "465"
	ErrYOUWILLBEBANNED           = "466"
	ErrKEYSET                    = "467"
	ErrCHANNELISFULL             = "471"
	ErrUNKNOWNMODE               = "472"
	ErrINVITEONLYCHAN            = "473"
	ErrBANNEDFROMCHAN            = "474"
	ErrBADCHANNELKEY             = "475"
	ErrBADCHANMASK               = "476"
	ErrNOCHANMODES               = "477"
	ErrBANLISTFULL               = "478"
	ErrNOPRIVILEGES              = "481"
	ErrCHANOPRIVSNEEDED          = "482"
	ErrCANTKILLSERVER            = "483"
	ErrRESTRICTED                = "484"
	ErrUNIQOPPRIVSNEEDED         = "485"
	ErrNOOPERHOST                = "491"
	ErrUMODEUNKNOWNFLAG          = "501"
	ErrUSERSDONTMATCH            = "502"
)

// A Message is the basic unit of communication in the IRC protocol.
type Message struct {
	// Raw is the raw message string.
	Raw string

	// Origin is either the nick or server that originated the message.
	Origin string

	// User is the name of the user that originated the message.
	//
	// This field is typically set in server to client communication when the
	// message originated from a client.
	User string

	// Host is the name of the host that originated the message.
	//
	// This field is typically set in server to client communication when the
	// message originated from a client.
	Host string

	// Command is the message's command.
	Command Command

	// Arguments is the message's argument list.
	Arguments []string
}

// RawString returns the raw string representation of a message.
// If Raw is non-empty then it is returned, otherwise a raw string
// is built from the fields of the message.  If there is an error
// generating the raw string then the string is invalid and an
// error is returned.
func (m Message) RawString() (string, error) {
	raw := ""
	if m.Raw != "" {
		raw = m.Raw
		goto out
	}
	if m.Origin != "" {
		raw += ":" + m.Origin
		if m.User != "" {
			raw += "!" + m.User + "@" + m.Host
		}
		raw += " "
	}
	raw += m.Command.String()
	for i, a := range m.Arguments {
		if i == len(m.Arguments)-1 {
			raw += " :" + a
		} else {
			raw += " " + a
		}
	}
out:
	if len(raw) > MaxBytes-len(delimiter) {
		return "", MsgTooLong{raw, len(raw) - (MaxBytes - len(delimiter))}
	}
	return strings.TrimRight(raw, "\n"), nil
}

// Parse parses a message from a raw message string.
//
// BUG(eaburns): Doesn't validate the command.
// BUG(eaburns): Doesn't validate that all fields are present for the
// respective command.
func Parse(data string) (Message, error) {
	var msg Message
	msg.Raw = data

	if data[0] == ':' {
		var prefix string
		prefix, data = splitString(data[1:], " ")
		msg.Origin, prefix = splitString(prefix, "!")
		msg.User, msg.Host = splitString(prefix, "@")
	}

	var cmd string
	cmd, data = splitString(data, " ")
	msg.Command = Command(cmd)

	for len(data) > 0 {
		var arg string
		if data[0] == ':' {
			arg, data = data[1:], ""
		} else {
			arg, data = splitString(data, " ")
		}
		msg.Arguments = append(msg.Arguments, arg)
	}
	return msg, nil
}

// Read returns the next message from the stream or an error.
func read(in *bufio.Reader) (Message, error) {
	data, err := readMsgData(in)
	if err != nil {
		if long, ok := err.(MsgTooLong); ok {
			m, err := Parse(long.Message)
			if err != nil {
				return Message{}, err
			}
			return m, long
		}
		return Message{}, err
	}
	return Parse(data)
}

// splitStrings returns two strings, the first is the portion of the string before
// the delimiter and the second is the portion after the delimiter. If the
// delimiter is not in the string then the entire string is before the delimiter.
//
// If the delimiter is a space ' ' then the second argument has all leading
// space characters stripped.
func splitString(s string, delim string) (head string, cons string) {
	parts := strings.SplitN(s, delim, 2)
	head, cons = parts[0], strings.Join(parts[1:], delim)
	if delim == " " {
		cons = strings.TrimLeft(cons, delim)
	}
	return
}

// ReadMsgData returns the raw data for the next message from the stream.
// On error the returned string will be empty.
func readMsgData(in *bufio.Reader) (string, error) {
	var msg []byte
	for {
		switch c, err := in.ReadByte(); {
		case err == io.EOF && len(msg) > 0:
			return "", unexpected("end of file")

		case err != nil:
			return "", err

		case c == '\000':
			return "", unexpected("null")

		case c == '\n':
			// Technically an invalid message, but instead we just strip it.

		case c == '\r':
			c, err = in.ReadByte()
			if err != nil {
				if err == io.EOF {
					err = unexpected("end of file")
				}
				return "", err
			}
			if c != '\n' {
				return "", unexpected("carrage return")
			}
			if len(msg) == 0 {
				continue
			}
			return string(msg), nil

		case len(msg) >= MaxBytes-len(delimiter):
			n, _ := junk(in)
			return "", MsgTooLong{Message: string(msg[:len(msg)-1]), NTrunc: n + 1}

		default:
			msg = append(msg, c)
		}
	}
}

// Junk reads and discards bytes until the next message marker is found,
// returning the number of discarded non-marker bytes.
func junk(in *bufio.Reader) (int, error) {
	var last byte
	n := 0
	for {
		c, err := in.ReadByte()
		if err != nil {
			return n, err
		}
		n++
		if last == delimiter[0] && c == delimiter[1] {
			break
		}
		last = c
	}
	return n - 1, nil
}

// Unexpected returns an error that describes an unexpected character
// in the message stream.
func unexpected(what string) error {
	return errors.New("unexpected " + what + " in message stream")
}
