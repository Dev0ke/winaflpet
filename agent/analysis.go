//go:build windows
// +build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	analysisMu      sync.Mutex
	analysisRunning = map[string]context.CancelFunc{}
)

func startAnalysisScheduler(jobGUID string) {
	analysisMu.Lock()
	defer analysisMu.Unlock()

	// Don't start twice.
	if _, ok := analysisRunning[jobGUID]; ok {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	analysisRunning[jobGUID] = cancel

	go analysisLoop(ctx, jobGUID)
	_ = logger.Infof("ANALYSIS scheduler started guid=%s", jobGUID)
}

func stopAnalysisScheduler(jobGUID string) {
	analysisMu.Lock()
	cancel, ok := analysisRunning[jobGUID]
	if ok {
		delete(analysisRunning, jobGUID)
	}
	analysisMu.Unlock()

	if ok {
		cancel()
		_ = logger.Infof("ANALYSIS scheduler stopped guid=%s", jobGUID)
	}
}

func analysisLoop(ctx context.Context, jobGUID string) {
	// Run immediately, then on interval.
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Re-load job from project each cycle so config changes take effect.
			job, _, err := project.GetJob(jobGUID)
			if err != nil {
				// Job no longer running.
				stopAnalysisScheduler(jobGUID)
				return
			}

			intervalMin := job.AnalysisIntervalMin
			if intervalMin <= 0 {
				// Disabled.
				timer.Reset(60 * time.Second)
				continue
			}

			if err := runAnalysisOnce(job); err != nil {
				_ = logger.Infof("ANALYSIS guid=%s error: %v", job.GUID.String(), err)
			}

			timer.Reset(time.Duration(intervalMin) * time.Minute)
		}
	}
}

func normalizeExtNoDot(s string) string {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(v, ".")
	return v
}

func normalizeExtWithDot(s string) string {
	v := normalizeExtNoDot(s)
	if v == "" {
		return ""
	}
	return "." + v
}

func buildTargetArgsForScript(j Job) ([]string, error) {
	// Use the raw user-provided strings; we still must split into argv.
	cmd, args := splitCmdLine(j.TargetApp)
	if strings.TrimSpace(cmd) == "" {
		return nil, errors.New("target_app is empty")
	}

	out := []string{cmd}
	if strings.TrimSpace(j.TargetArgs) != "" {
		out = append(out, strings.Fields(strings.TrimSpace(j.TargetArgs))...)
	} else if strings.TrimSpace(args) != "" {
		out = append(out, strings.Fields(strings.TrimSpace(args))...)
	}
	return out, nil
}

func runAnalysisOnce(job Job) error {
	if strings.TrimSpace(job.AnalysisScript) == "" {
		return nil
	}


	// Collect/normalize crashes first.
	newCrashes, err := job.Collect()
	if err != nil {
		return err
	}

	// Directories:
	outputDir := joinPath(job.AFLDir, job.Output)
	crashDir := filepath.Join(outputDir, "crashes")
	resultDir := filepath.Join(outputDir, "crashes_result")

	pythonExe, err := exec.LookPath("python.exe")
	if err != nil {
		return fmt.Errorf("python.exe not found in PATH: %w", err)
	}

	targetArgv, err := buildTargetArgsForScript(job)
	if err != nil {
		return err
	}

	mem := job.AnalysisMem
	if mem <= 0 {
		mem = 1600
	}
	timeout := job.AnalysisTimeout
	if timeout <= 0 {
		timeout = 60
	}
	retries := job.AnalysisRetries
	if retries < 0 {
		retries = 0
	}

	ext := normalizeExtNoDot(job.AFLFSuffix)

	args := []string{
		job.AnalysisScript,
		"-i", crashDir,
		"-o", resultDir,
		"-m", strconv.Itoa(mem),
		"-t", strconv.Itoa(timeout),
		"-r", strconv.Itoa(retries),
	}
	if job.AnalysisPageHeap != 0 {
		args = append(args, "--pageheap")
	}
	if ext != "" {
		args = append(args, "-ext", ext)
	}
	args = append(args, "--")
	args = append(args, targetArgv...)

	_ = os.MkdirAll(resultDir, 0755)
	_ = logger.Infof("ANALYSIS guid=%s new_crashes=%d cmd=%s %s", job.GUID.String(), len(newCrashes), pythonExe, strings.Join(args, " "))

	cmd := exec.Command(pythonExe, args...)
	cmd.Dir = resultDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		// Keep logs lightweight.
		s := string(out)
		if len(s) > 8192 {
			s = s[:8192] + " ...(truncated)"
		}
		_ = logger.Infof("ANALYSIS guid=%s output=%s", job.GUID.String(), s)
	}
	if err != nil {
		return err
	}
	return nil
}


