package irc

// Parsing of IRC messages as specified in RFC 1459.

import (
	"errors"
	"io"
	"strings"
)

// MaxBytes is the maximum size of a message in bytes.
const MaxBytes = 512

// delimiter is the marker delineating messages in the TCP stream.
const delimiter = "\r\n"

// ErrTooLong denotes a message that is greater than MaxBytes in size.
var ErrTooLong = errors.New("message too long")

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

// String returns the raw string representation of a message.
// The returned string may be longer than MaxBytes.
func (m Message) String() string {
	raw := ""
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
	return strings.TrimRight(raw, "\n")
}

// Parse parses a string into a message.
//
// BUG(eaburns): Doesn't validate the command.
// BUG(eaburns): Doesn't validate that all fields are present for the
func Parse(data string) (Message, error) {
	var msg Message

	if data[0] == ':' {
		var prefix string
		prefix, data = split(data[1:], " ")
		msg.Origin, prefix = split(prefix, "!")
		msg.User, msg.Host = split(prefix, "@")
	}

	var cmd string
	cmd, data = split(data, " ")
	msg.Command = Command(cmd)

	for len(data) > 0 {
		var arg string
		if data[0] == ':' {
			arg, data = data[1:], ""
		} else {
			arg, data = split(data, " ")
		}
		msg.Arguments = append(msg.Arguments, arg)
	}
	return msg, nil
}

// Split returns two strings, the first is the portion of the string before
// the delimiter and the second is the portion after the delimiter. If the
// delimiter is not in the string then the entire string is before the delimiter.
//
// If the delimiter is a space ' ' then the second argument has all leading
// space characters stripped.
func split(s string, delim string) (head string, tail string) {
	parts := strings.SplitN(s, delim, 2)
	head, tail = parts[0], strings.Join(parts[1:], delim)
	if delim == " " {
		tail = strings.TrimLeft(tail, delim)
	}
	return
}

// Read returns the next message from the reader or an error.
// io.EOF is returned with a zero-message if there are no more messages to read.
func Read(in io.ByteReader) (Message, error) {
	data, err := read(in)
	if err != nil {
		return Message{}, err
	}
	return Parse(data)
}

func read(in io.ByteReader) (string, error) {
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
			junk(in)
			return "", ErrTooLong

		default:
			msg = append(msg, c)
		}
	}
}

func junk(in io.ByteReader) (int, error) {
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
