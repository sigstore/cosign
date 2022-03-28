package log

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	gsyslog "github.com/hashicorp/go-syslog"
	"github.com/jmhodges/clock"
)

// A Logger logs messages with explicit priority levels. It is
// implemented by a logging back-end as provided by New() or
// NewMock().
type Logger interface {
	Err(msg string)
	Errf(format string, a ...interface{})
	Warning(msg string)
	Warningf(format string, a ...interface{})
	Info(msg string)
	Infof(format string, a ...interface{})
	Debug(msg string)
	Debugf(format string, a ...interface{})
	AuditPanic()
	AuditInfo(msg string)
	AuditInfof(format string, a ...interface{})
	AuditObject(string, interface{})
	AuditErr(string)
	AuditErrf(format string, a ...interface{})
}

// impl implements Logger.
type impl struct {
	w writer
}

// singleton defines the object of a Singleton pattern
type singleton struct {
	once sync.Once
	log  Logger
}

// _Singleton is the single impl entity in memory
var _Singleton singleton

// The constant used to identify audit-specific messages
const auditTag = "[AUDIT]"

// New returns a new Logger that uses the given syslog.Writer as a backend.
func New(log gsyslog.Syslogger, stdoutLogLevel int, syslogLogLevel int) (Logger, error) {
	if log == nil {
		return nil, errors.New("Attempted to use a nil System Logger.")
	}
	return &impl{
		&bothWriter{log, stdoutLogLevel, syslogLogLevel, clock.New(), os.Stdout},
	}, nil
}

// initialize should only be used in unit tests.
func initialize() {
	// defaultPriority is never used because we always use specific priority-based
	// logging methods.
	const defaultPriority = gsyslog.LOG_INFO
	syslogger, err := gsyslog.DialLogger("", "", defaultPriority, "LOCAL0", "test")
	if err != nil {
		panic(err)
	}
	logger, err := New(syslogger, int(gsyslog.LOG_DEBUG), int(gsyslog.LOG_DEBUG))
	if err != nil {
		panic(err)
	}

	_ = Set(logger)
}

// Set configures the singleton Logger. This method
// must only be called once, and before calling Get the
// first time.
func Set(logger Logger) (err error) {
	if _Singleton.log != nil {
		err = errors.New("You may not call Set after it has already been implicitly or explicitly set.")
		_Singleton.log.Warning(err.Error())
	} else {
		_Singleton.log = logger
	}
	return
}

// Get obtains the singleton Logger. If Set has not been called first, this
// method initializes with basic defaults.  The basic defaults cannot error, and
// subsequent access to an already-set Logger also cannot error, so this method is
// error-safe.
func Get() Logger {
	_Singleton.once.Do(func() {
		if _Singleton.log == nil {
			initialize()
		}
	})

	return _Singleton.log
}

type writer interface {
	logAtLevel(gsyslog.Priority, string)
}

// bothWriter implements writer and writes to both syslog and stdout.
type bothWriter struct {
	gsyslog.Syslogger
	stdoutLevel int
	syslogLevel int
	clk         clock.Clock
	stdout      io.Writer
}

func LogLineChecksum(line string) string {
	crc := crc32.ChecksumIEEE([]byte(line))
	// Using the hash.Hash32 doesn't make this any easier
	// as it also returns a uint32 rather than []byte
	buf := make([]byte, binary.MaxVarintLen32)
	binary.PutUvarint(buf, uint64(crc))
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Log the provided message at the appropriate level, writing to
// both stdout and the Logger
func (w *bothWriter) logAtLevel(level gsyslog.Priority, msg string) {
	var prefix string
	var err error

	const red = "\033[31m\033[1m"
	const yellow = "\033[33m"

	// Since messages are delimited by newlines, we have to escape any internal or
	// trailing newlines before generating the checksum or outputting the message.
	msg = strings.Replace(msg, "\n", "\\n", -1)
	msg = fmt.Sprintf("%s %s", LogLineChecksum(msg), msg)

	switch syslogAllowed := int(level) <= w.syslogLevel; level {
	case gsyslog.LOG_ERR:
		if syslogAllowed {
			err = w.WriteLevel(gsyslog.LOG_ERR, []byte(msg))
		}
		prefix = red + "E"
	case gsyslog.LOG_WARNING:
		if syslogAllowed {
			err = w.WriteLevel(gsyslog.LOG_WARNING, []byte(msg))
		}
		prefix = yellow + "W"
	case gsyslog.LOG_INFO:
		if syslogAllowed {
			err = w.WriteLevel(gsyslog.LOG_INFO, []byte(msg))
		}
		prefix = "I"
	case gsyslog.LOG_DEBUG:
		if syslogAllowed {
			err = w.WriteLevel(gsyslog.LOG_DEBUG, []byte(msg))
		}
		prefix = "D"
	default:
		_, err = w.Write([]byte(fmt.Sprintf("%s (unknown logging level: %d)", msg, int(level))))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to syslog: %s (%s)\n", msg, err)
	}

	var reset string
	if strings.HasPrefix(prefix, "\033") {
		reset = "\033[0m"
	}

	if int(level) <= w.stdoutLevel {
		if _, err := fmt.Fprintf(w.stdout, "%s%s %s %s%s\n",
			prefix,
			w.clk.Now().Format("150405"),
			path.Base(os.Args[0]),
			msg,
			reset); err != nil {
			panic(fmt.Sprintf("failed to write to stdout: %v\n", err))
		}
	}
}

func (log *impl) auditAtLevel(level gsyslog.Priority, msg string) {
	text := fmt.Sprintf("%s %s", auditTag, msg)
	log.w.logAtLevel(level, text)
}

// AuditPanic catches panicking executables. This method should be added
// in a defer statement as early as possible
func (log *impl) AuditPanic() {
	err := recover()
	if err != nil {
		buf := make([]byte, 8192)
		log.AuditErrf("Panic caused by err: %s", err)

		runtime.Stack(buf, false)
		log.AuditErrf("Stack Trace (Current frame) %s", buf)

		runtime.Stack(buf, true)
		log.Warningf("Stack Trace (All frames): %s", buf)
	}
}

// Err level messages are always marked with the audit tag, for special handling
// at the upstream system logger.
func (log *impl) Err(msg string) {
	log.auditAtLevel(gsyslog.LOG_ERR, msg)
}

// Errf level messages are always marked with the audit tag, for special handling
// at the upstream system logger.
func (log *impl) Errf(format string, a ...interface{}) {
	log.Err(fmt.Sprintf(format, a...))
}

// Warning level messages pass through normally.
func (log *impl) Warning(msg string) {
	log.w.logAtLevel(gsyslog.LOG_WARNING, msg)
}

// Warningf level messages pass through normally.
func (log *impl) Warningf(format string, a ...interface{}) {
	log.Warning(fmt.Sprintf(format, a...))
}

// Info level messages pass through normally.
func (log *impl) Info(msg string) {
	log.w.logAtLevel(gsyslog.LOG_INFO, msg)
}

// Infof level messages pass through normally.
func (log *impl) Infof(format string, a ...interface{}) {
	log.Info(fmt.Sprintf(format, a...))
}

// Debug level messages pass through normally.
func (log *impl) Debug(msg string) {
	log.w.logAtLevel(gsyslog.LOG_DEBUG, msg)
}

// Debugf level messages pass through normally.
func (log *impl) Debugf(format string, a ...interface{}) {
	log.Debug(fmt.Sprintf(format, a...))
}

// AuditInfo sends an INFO-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *impl) AuditInfo(msg string) {
	log.auditAtLevel(gsyslog.LOG_INFO, msg)
}

// AuditInfof sends an INFO-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *impl) AuditInfof(format string, a ...interface{}) {
	log.AuditInfo(fmt.Sprintf(format, a...))
}

// AuditObject sends an INFO-severity JSON-serialized object message that is prefixed
// with the audit tag, for special handling at the upstream system logger.
func (log *impl) AuditObject(msg string, obj interface{}) {
	jsonObj, err := json.Marshal(obj)
	if err != nil {
		log.auditAtLevel(gsyslog.LOG_ERR, fmt.Sprintf("Object could not be serialized to JSON. Raw: %+v", obj))
		return
	}

	log.auditAtLevel(gsyslog.LOG_INFO, fmt.Sprintf("%s JSON=%s", msg, jsonObj))
}

// AuditErr can format an error for auditing; it does so at ERR level.
func (log *impl) AuditErr(msg string) {
	log.auditAtLevel(gsyslog.LOG_ERR, msg)
}

// AuditErrf can format an error for auditing; it does so at ERR level.
func (log *impl) AuditErrf(format string, a ...interface{}) {
	log.AuditErr(fmt.Sprintf(format, a...))
}
