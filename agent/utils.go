//go:build windows
// +build windows

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/danieljoos/wincred"
	"github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows/registry"
)

const (
	WINCRED_NAME = "WinAFL_Pet_Agent"
)

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var atArgRe = regexp.MustCompile(`@@\S*`)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func splitList(text string) []string {
	// Split on newlines / commas / semicolons; keep spaces inside tokens (paths).
	s := strings.ReplaceAll(text, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, ";", ",")

	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == ','
	})

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func parseEnvVars(text string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		low := strings.ToLower(line)
		if strings.HasPrefix(low, "#") || strings.HasPrefix(low, "//") || strings.HasPrefix(low, ";") {
			continue
		}

		// Accept common prefixes from shell snippets.
		if strings.HasPrefix(low, "set ") {
			line = strings.TrimSpace(line[4:])
		} else if strings.HasPrefix(low, "export ") {
			line = strings.TrimSpace(line[7:])
		}

		i := strings.Index(line, "=")
		if i <= 0 {
			return nil, fmt.Errorf("invalid env var line (expected KEY=VALUE): %q", raw)
		}

		key := strings.TrimSpace(line[:i])
		val := ""
		if i+1 < len(line) {
			val = line[i+1:]
		}

		if !envKeyRe.MatchString(key) {
			return nil, fmt.Errorf("invalid env var name %q (line: %q)", key, raw)
		}

		out = append(out, fmt.Sprintf("%s=%s", key, val))
	}

	return out, nil
}

func applyEnvOverrides(base []string, overrides []string) []string {
	if len(overrides) == 0 {
		return base
	}

	overrideKeys := map[string]struct{}{}
	for _, kv := range overrides {
		if i := strings.Index(kv, "="); i > 0 {
			// Windows treats env var names as case-insensitive.
			overrideKeys[strings.ToUpper(kv[:i])] = struct{}{}
		}
	}

	out := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		i := strings.Index(kv, "=")
		if i <= 0 {
			continue
		}
		if _, ok := overrideKeys[strings.ToUpper(kv[:i])]; ok {
			continue
		}
		out = append(out, kv)
	}

	out = append(out, overrides...)
	return out
}
func mergeEnvMissing(base []string, add []string) []string {
	if len(add) == 0 {
		return base
	}

	keys := map[string]struct{}{}
	for _, kv := range base {
		if i := strings.Index(kv, "="); i > 0 {
			keys[strings.ToUpper(kv[:i])] = struct{}{}
		}
	}

	out := make([]string, 0, len(base)+len(add))
	out = append(out, base...)
	for _, kv := range add {
		i := strings.Index(kv, "=")
		if i <= 0 {
			continue
		}
		k := strings.ToUpper(kv[:i])
		if _, ok := keys[k]; ok {
			continue
		}
		keys[k] = struct{}{}
		out = append(out, kv)
	}
	return out
}

// readSystemEnvVars reads HKLM "system" environment variables.
// This is useful when the agent runs as a service and its process env is incomplete.
func readSystemEnvVars() ([]string, error) {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		val, valType, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		if valType != registry.SZ && valType != registry.EXPAND_SZ {
			continue
		}
		out = append(out, fmt.Sprintf("%s=%s", name, val))
	}
	return out, nil
}

func stripAnsi(s string) string {
	ansi := "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	re := regexp.MustCompile(ansi)
	return re.ReplaceAllString(s, "")
}

func killProcess(p ps.Process) error {
	proc, err := os.FindProcess(p.Pid())
	if err != nil {
		logger.Error(err)
		return err
	}

	err = proc.Kill()
	if err != nil {
		logger.Error(err)
		return err
	}

	logger.Infof("Killed %s process (PID %d, PPID %d)\n", p.Executable(), p.Pid(), p.PPid())

	return nil
}

func parseStats(content string) (Stats, error) {
	var stats Stats
	var fields = make(map[string]interface{})

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if len(line) == 0 {
			break
		}

		s := strings.Split(line, ":")
		name := strings.TrimSpace(s[0])
		value := strings.Replace(strings.TrimSpace(s[1]), "inf", "0.0", 1)
		fields[name] = value

		if strings.Contains(value, ".") {
			if f, err := strconv.ParseFloat(value, 64); err == nil {
				fields[name] = f
			}
		} else if i, err := strconv.Atoi(value); err == nil {
			fields[name] = i
		}
	}

	b, err := json.Marshal(fields)
	if err != nil {
		logger.Error(err)
		return stats, err
	}

	if err := json.Unmarshal([]byte(b), &stats); err != nil {
		logger.Error(err)
		return stats, err
	}

	return stats, nil
}

func genKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	k := hex.EncodeToString(b)
	fmt.Println("\nSecret key of service account:", k)
	return k
}

func initKey() error {
	cred := wincred.NewGenericCredential(WINCRED_NAME)
	cred.CredentialBlob = []byte(genKey())
	return cred.Write()
}

func getKey() (string, error) {
	cred, err := wincred.GetGenericCredential(WINCRED_NAME)
	if err != nil {
		return "", err
	}

	return string(cred.CredentialBlob), nil
}

func delKey() error {
	cred, err := wincred.GetGenericCredential(WINCRED_NAME)
	if err != nil {
		return err
	}
	return cred.Delete()
}

func splitCmdLine(cmdLine string) (string, string) {
	cmdFields := strings.Fields(cmdLine)

	cmd := cmdFields[0]
	args := ""

	if len(cmdFields) > 1 {
		args = strings.Join(cmdFields[1:], " ")
	}

	return cmd, args
}

func quoteWindowsArg(s string) string {
	if s == "" {
		return `""`
	}

	needsQuotes := strings.ContainsAny(s, " \t")
	if strings.Contains(s, `"`) {
		needsQuotes = true
		s = strings.ReplaceAll(s, `"`, `\"`)
	}

	if needsQuotes {
		return `"` + s + `"`
	}
	return s
}

// expandAtArgs replaces @@ placeholders in a free-form argument string.
// Rules:
//   - "@@"  -> basePath
//   - "@@x" -> basePath + "x" (suffix concatenation)
//
// The replacement is only intended to be used when AFL "-f" mode is enabled.
func expandAtArgs(args string, basePath string) string {
	if strings.TrimSpace(args) == "" || basePath == "" {
		return args
	}

	return atArgRe.ReplaceAllStringFunc(args, func(m string) string {
		if len(m) < 2 {
			return m
		}
		suffix := ""
		if len(m) > 2 {
			suffix = m[2:]
		}
		return quoteWindowsArg(basePath + suffix)
	})
}

func joinPath(workingDir string, outputDir string, pathNames ...string) string {
	e := append([]string{outputDir}, pathNames...)

	if !filepath.IsAbs(outputDir) {
		e = append([]string{workingDir}, e...)
	}

	p := filepath.Join(e...)

	return p
}

func readStdout(c chan error, rd *bufio.Reader) {
	for {
		l, _, err := rd.ReadLine()
		if err != nil || err == io.EOF {
			c <- err
		}

		s := string(l)
		if strings.Contains(s, AFL_SUCCESS_MSG) {
			c <- nil
		}

		m := regexp.MustCompile(AFL_FAIL_REGEX).FindStringSubmatch(s)
		if len(m) > 0 {
			c <- errors.New(stripAnsi(m[1]))
		}
	}
}

func sequentialName(name string, fID int) string {
	i := strings.LastIndex(name, ".exe")
	if i == -1 {
		return name
	}

	return fmt.Sprintf("%s%d%s", name[:i], fID, name[i:])
}

func getFuncAddr(path string) string {
	re := regexp.MustCompile(`id_\d{6}_([^_]+)`)
	if m := re.FindStringSubmatch(path); len(m) > 1 {
		return m[1]
	}
	return "Unknown"
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%X", h.Sum(nil)), nil
}

func copyFile(src, dst string) (err error) {
	if err = os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	if _, err := os.Stat(dst); err == nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}

	if err = out.Sync(); err != nil {
		out.Close()
		return err
	}

	if err = out.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, dst)
}
