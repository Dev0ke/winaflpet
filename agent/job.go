//go:build windows
// +build windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karrick/godirwalk"
	"github.com/mitchellh/go-ps"
	"github.com/rs/xid"
)

const (
	AFL_EXECUTABLE  = "afl-fuzz.exe"
	AFL_SUCCESS_MSG = "All set and ready to roll!"
	AFL_FAIL_REGEX  = `(?:PROGRAM ABORT|OS message) : (.*)`
	AFL_STATS_FILE  = "fuzzer_stats"
	AFL_PLOT_FILE   = "plot_data"
)

type Job struct {
	GUID           xid.ID `json:"guid"`
	Name           string `json:"name"`
	Description    string `json:"desc"`
	Banner         string `json:"banner"`
	Cores          int    `json:"cores"`
	Input          string `json:"input"`
	Output         string `json:"output"`
	Timeout        int    `json:"timeout"`
	InstMode       string `json:"inst_mode"`
	DelivMode      string `json:"deliv_mode"`
	AFLFMode       int    `json:"afl_f_mode"`
	AFLFDir        string `json:"afl_f_dir"`
	AFLFSuffix     string `json:"afl_f_suffix"`
	DrioPersistenceInApp int `json:"drio_persistence_in_app"`
	TinyPersist    int    `json:"ti_persist"`
	TinyLoop       int    `json:"ti_loop"`
	BasicExtraArgs string `json:"basic_extra_args"`
	InstExtraArgs  string `json:"inst_extra_args"`
	CoverageType   string `json:"cov_type"`
	CoverageModule string `json:"cov_module"`
	IgnoreHitcount int    `json:"ignore_hitcount"`
	FuzzIter       int    `json:"fuzz_iter"`
	InstrumentTransitive string `json:"instrument_transitive"`
	TargetModule   string `json:"target_module"`
	TargetMethod   string `json:"target_method"`
	TargetOffset   string `json:"target_offset"`
	TargetNArgs    int    `json:"target_nargs"`
	TargetApp      string `json:"target_app"`
	TargetArgs     string `json:"target_args"`
	TargetArch     string `json:"target_arch"`
	AFLDir         string `json:"afl_dir"`
	DrioDir        string `json:"drio_dir"`
	PyDir          string `json:"py_dir"`
	BugIdDir       string `json:"bugid_dir"`
	ExtrasDir      string `json:"extras_dir"`
	AttachLib      string `json:"attach_lib"`
	CustomLib      string `json:"custom_lib"`
	MemoryLimit    string `json:"memory_limit"`
	PersistCache   int    `json:"persist_cache"`
	DirtyMode      int    `json:"dirty_mode"`
	DumbMode       int    `json:"dumb_mode"`
	CrashMode      int    `json:"crash_mode"`
	BugBucket      int    `json:"bug_bucket"`
	ExpertMode     int    `json:"expert_mode"`
	VariableMode   int    `json:"variable_mode"`
	SequentialMode int    `json:"sequential_mode"`
	NoAffinity     int    `json:"no_affinity"`
	SkipCrashes    int    `json:"skip_crashes"`
	ShuffleQueue   int    `json:"shuffle_queue"`
	Autoresume     int    `json:"autoresume"`
	EnvVars        string `json:"env_vars"`
	Status         int    `json:"status"`
}

func newJob(GUID string) Job {
	j := new(Job)
	j.Cores = 1
	j.GUID, _ = xid.FromString(GUID)
	return *j
}

func (j Job) Start(fID int) error {
	fuzzerID := fmt.Sprintf("%s%d", j.Banner, fID)

	binDir := "bin32"
	if j.TargetArch == "x64" {
		binDir = "bin64"
	}

	j.AFLDir = path.Join(j.AFLDir, binDir)
	j.DrioDir = path.Join(j.DrioDir, binDir)

	if j.VariableMode != 0 {
		j.CoverageType = []string{"edge", "bb"}[rand.Intn(2)]
		j.FuzzIter = int(float64(j.FuzzIter) * (1 + (rand.Float64() - 0.5)))
	}

	afl, err := exec.LookPath(path.Join(j.AFLDir, AFL_EXECUTABLE))
	if err != nil {
		logger.Error(err)
		return err
	}

	targetCmd, targetArgs := splitCmdLine(j.TargetApp)
	if j.SequentialMode != 0 {
		targetCmd = sequentialName(targetCmd, fID)
		j.TargetModule = sequentialName(j.TargetModule, fID)
	}

	targetApp = targetCmd


	envs := os.Environ()
	// Merge in HKLM system environment variables (best-effort). This helps when the
	// agent runs as a Windows service and its process environment is incomplete.
	if sysEnvs, err := readSystemEnvVars(); err == nil {
		envs = mergeEnvMissing(envs, sysEnvs)
	}
	if j.Autoresume != 0 {
		envs = append(envs, "AFL_AUTORESUME=1")
	} else {
		fuzzerDir := joinPath(j.AFLDir, j.Output, fuzzerID)
		statsFile := joinPath(fuzzerDir, AFL_STATS_FILE)
		if fileExists(statsFile) {
			err := os.RemoveAll(fuzzerDir)
			if err != nil {
				logger.Error(err)
				return err
			}
		}
	}

	if j.SkipCrashes != 0 || j.Autoresume != 0 {
		envs = append(envs, "AFL_SKIP_CRASHES=1")
	}

	if j.ShuffleQueue != 0 {
		envs = append(envs, "AFL_SHUFFLE_QUEUE=1")
	}

	if j.NoAffinity != 0 {
		envs = append(envs, "AFL_NO_AFFINITY=1")
	}

	if strings.TrimSpace(j.EnvVars) != "" {
		customEnvs, err := parseEnvVars(j.EnvVars)
		if err != nil {
			logger.Error(err)
			return err
		}
		envs = applyEnvOverrides(envs, customEnvs)
	}

	args := []string{}

	// Allow specifying the "last args" in WebUI. If set, it overrides any args that
	// were included in TargetApp.
	if strings.TrimSpace(j.TargetArgs) != "" {
		targetArgs = strings.TrimSpace(j.TargetArgs)
	}

	// AFL "-f" file mode:
	// - Generate a per-fuzzer input file path (random 4 chars + suffix) to support multi-core.
	// - Pass it to afl-fuzz via "-f <file>".
	// - Replace @@ placeholders in TargetArgs with the generated absolute file path.
	//
	// When not enabled: do NOT replace @@, and do NOT inject "-f @@" into target args.
	if j.AFLFMode != 0 {
		if strings.TrimSpace(j.AFLFDir) == "" {
			return errors.New("AFL -f mode enabled but afl_f_dir is empty")
		}

		dir := strings.TrimSpace(j.AFLFDir)
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(j.AFLDir, dir)
		}

		r4 := xid.New().String()
		if len(r4) > 4 {
			r4 = r4[:4]
		}

		fuzzFilePath := filepath.Clean(filepath.Join(dir, r4+strings.TrimSpace(j.AFLFSuffix)))
		args = append(args, fmt.Sprintf("-f %s", quoteWindowsArg(fuzzFilePath)))
		targetArgs = expandAtArgs(targetArgs, fuzzFilePath)
	}

	// Delivery mode: shared memory option is controlled by afl-fuzz "-s".
	if j.DelivMode == "sm" {
		args = append(args, "-s")
	}

	opRole := "-S"
	if j.Cores > 1 && fID == 1 {
		opRole = "-M"
	}

	args = append(args, fmt.Sprintf("%s %s", opRole, fuzzerID))
	args = append(args, fmt.Sprintf("-i %s", j.Input))
	args = append(args, fmt.Sprintf("-o %s", j.Output))

	if j.InstMode == "TinyInst" {
		args = append(args, "-y")
	} else {
		args = append(args, fmt.Sprintf("-D %s", j.DrioDir))
	}

	timeoutSuffix := ""
	if j.Autoresume != 0 || j.Input == "-" {
		timeoutSuffix = "+" // Skip queue entries that time out.
	}

	args = append(args, fmt.Sprintf("-t %d%s", j.Timeout, timeoutSuffix))

	if j.InstMode == "DynamoRIO" {
		if j.PersistCache != 0 {
			args = append(args, "-p")
		}
		if j.ExpertMode != 0 {
			args = append(args, "-e")
		}
	}

	if j.DirtyMode != 0 {
		args = append(args, "-d")
	}

	if j.BugBucket != 0 {
		args = append(args, "-b")
	}

	if j.CrashMode != 0 && j.DumbMode == 0 {
		args = append(args, "-C")
	}

	if j.DumbMode != 0 && j.CrashMode == 0 {
		args = append(args, "-n")
	}

	if j.MemoryLimit != "0" && j.MemoryLimit != "" {
		args = append(args, fmt.Sprintf("-m %s", j.MemoryLimit))
	}

	if j.AttachLib != "" {
		args = append(args, fmt.Sprintf("-A %s", j.AttachLib))
	}

	if j.CustomLib != "" {
		args = append(args, fmt.Sprintf("-l %s", j.CustomLib))
	}

	if j.ExtrasDir != "" {
		args = append(args, fmt.Sprintf("-x %s", j.ExtrasDir))
	}

	if strings.TrimSpace(j.BasicExtraArgs) != "" {
		args = append(args, strings.TrimSpace(j.BasicExtraArgs))
	}

	args = append(args, "--")
	args = append(args, fmt.Sprintf("-covtype %s", j.CoverageType))

	if j.InstMode == "DynamoRIO" && j.DrioPersistenceInApp != 0 {
		args = append(args, "-persistence_mode in_app")
	}

	for _, m := range splitList(j.CoverageModule) {
		if j.InstMode == "TinyInst" {
			args = append(args, fmt.Sprintf("-instrument_module %s", m))
		} else {
			args = append(args, fmt.Sprintf("-coverage_module %s", m))
		}
	}

	if j.IgnoreHitcount != 0 {
		args = append(args, "-ignore_hitcount")
	}

	if j.InstMode == "TinyInst" {
		for _, m := range splitList(j.InstrumentTransitive) {
			args = append(args, fmt.Sprintf("-instrument_transitive %s", m))
		}
		if j.TinyPersist != 0 {
			args = append(args, "-persist")
		}
		if j.TinyLoop != 0 {
			args = append(args, "-loop")
		}
		args = append(args, fmt.Sprintf("-iterations %d", j.FuzzIter))
	} else {
		args = append(args, fmt.Sprintf("-fuzz_iterations %d", j.FuzzIter))
	}

	args = append(args, fmt.Sprintf("-target_module %s", j.TargetModule))
	args = append(args, fmt.Sprintf("-target_method %s", j.TargetMethod))
	args = append(args, fmt.Sprintf("-target_offset %s", j.TargetOffset))
	args = append(args, fmt.Sprintf("-nargs %d", j.TargetNArgs))

	if strings.TrimSpace(j.InstExtraArgs) != "" {
		args = append(args, strings.TrimSpace(j.InstExtraArgs))
	}

	args = append(args, "--")
	args = append(args, targetApp)
	args = append(args, targetArgs)

	cmd := exec.Command(afl, strings.Join(args, " "))
	cmd.Dir = j.AFLDir
	cmd.Env = envs
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.CmdLine = strings.Join(cmd.Args, ` `)
	stdoutPipe, _ := cmd.StdoutPipe()
	stdoutReader := bufio.NewReader(stdoutPipe)

	if err := cmd.Start(); err != nil {
		logger.Error(err)
		return err
	}

	c := make(chan error)

	go readStdout(c, stdoutReader)

	select {
	case err := <-c:
		return err
	case <-time.After(4 * time.Minute):
		return nil
	}
}

func (j Job) Stop() error {
	processes, err := ps.Processes()
	if err != nil {
		logger.Error(err)
		return err
	}

	targetCmd, _ := splitCmdLine(j.TargetApp)
	targetExe := filepath.Base(targetCmd)
	targetProcs := []ps.Process{}

	i := strings.LastIndex(targetExe, ".exe")
	expr := fmt.Sprintf("^%s\\d*%s$", targetExe[:i], targetExe[i:])
	re, _ := regexp.Compile(expr)

	for _, p := range processes {
		if re.MatchString(p.Executable()) {
			p1, _ := ps.FindProcess(p.Pid())
			if p1 != nil {
				targetProcs = append(targetProcs, p1)
				p2, _ := ps.FindProcess(p1.PPid())
				if p2 != nil {
					targetProcs = append(targetProcs, p2)
					p3, _ := ps.FindProcess(p2.PPid())
					if p3 != nil {
						targetProcs = append(targetProcs, p3)
					}
				}
			}
		}
	}

	for _, p := range targetProcs {
		killProcess(p)
	}

	return nil
}

func (j Job) View() ([]Stats, error) {
	var stats []Stats

	for c := 1; c <= j.Cores; c++ {
		fuzzerID := fmt.Sprintf("%s%d", j.Banner, c)
		fileName := joinPath(j.AFLDir, j.Output, fuzzerID, AFL_STATS_FILE)

		if !fileExists(fileName) {
			text := fmt.Sprintf("Statistics are unavailable for fuzzer instance #%d in job %s", c, j.Name)
			err := errors.New(text)
			return stats, err
		}

		content, err := os.ReadFile(fileName)
		if err != nil {
			continue
		}

		newStats, err := parseStats(string(content))
		if err != nil {
			continue
		}

		stats = append(stats, newStats)
	}

	return stats, nil
}

func (j Job) Check(pid int) (bool, error) {
	p, err := ps.FindProcess(pid)
	if err != nil {
		return false, err
	}

	if p != nil && strings.Contains(p.Executable(), "afl-fuzz.exe") {
		return true, nil
	}

	return false, nil
}

func (j Job) Collect() ([]Crash, error) {
	var crashes []Crash

	outputDir := joinPath(j.AFLDir, j.Output)
	re := regexp.MustCompile(`\\crashes(_\d{14})?\\id_\d{6}_\w+$`)
	err := godirwalk.Walk(outputDir, &godirwalk.Options{
		Callback: func(osPathname string, de *godirwalk.Dirent) error {
			if !re.MatchString(osPathname) {
				return nil
			}

			fileHash, err := hashFile(osPathname)
			if err != nil {
				return err
			}

			crashPath := joinPath(outputDir, "crashes", fileHash)
			if err := copyFile(osPathname, crashPath); err != nil {
				return err
			}

			crashDir := strings.Split(filepath.Dir(osPathname), "\\")
			fuzzerID := crashDir[len(crashDir)-2]
			funcAddr := getFuncAddr(osPathname)
			newCrash := newCrash(j.GUID, fuzzerID, funcAddr, crashPath)
			crashes = append(crashes, newCrash)

			return nil
		},
		Unsorted: true,
	})

	return crashes, err
}

func startJob(c *gin.Context) {
	j := newJob(c.Param("guid"))

	fID, err := strconv.Atoi(c.DefaultQuery("fid", "1"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	if err := c.ShouldBindJSON(&j); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	if err := j.Start(fID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"guid":  j.GUID,
			"error": err.Error(),
		})
		return
	}

	if ok, _ := project.FindJob(j.GUID); !ok {
		project.AddJob(j)
	}

	c.JSON(http.StatusCreated, gin.H{
		"guid": j.GUID,
		"msg":  fmt.Sprintf("Fuzzer instance #%d of job %s has been successfuly started!", fID, j.Name),
	})
}

func stopJob(c *gin.Context) {
	j, i, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	if err := j.Stop(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"guid":  j.GUID,
			"error": err.Error(),
		})
		return
	}

	project.RemoveJob(i)

	c.JSON(http.StatusOK, gin.H{
		"guid": j.GUID,
		"msg":  fmt.Sprintf("Job %s has been successfully stopped!", j.Name),
	})
}

func viewJob(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	Stats, err := j.View()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"guid":  j.GUID,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Stats)
}

func checkJob(c *gin.Context) {
	processIDs := []int{}
	msg := ""

	c.Bind(&processIDs)
	if len(processIDs) < 1 || len(processIDs) > 40 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid number of arguments provided.",
		})
		return
	}

	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	for _, processID := range processIDs {
		ok, err := j.Check(processID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{
				"msg": fmt.Sprintf("Fuzzer instance with PID %d cannot be found.", processID),
				"pid": processID,
			})
			return
		}
	}

	if len(processIDs) > 1 {
		msg = "All fuzzer instances seem to be up and running."
	} else {
		msg = fmt.Sprintf("Fuzzer instance with PID %d is up and running.", processIDs[0])
	}

	c.JSON(http.StatusOK, gin.H{
		"msg": msg,
	})
}

func collectJob(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	Crashes, err := j.Collect()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"guid":  j.GUID,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Crashes)
}

func plotJob(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	fID, err := strconv.Atoi(c.Query("fid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"guid":  c.Param("guid"),
			"error": err.Error(),
		})
		return
	}

	fuzzerID := fmt.Sprintf("%s%d", j.Banner, fID)
	filePath := joinPath(j.AFLDir, j.Output, fuzzerID, AFL_PLOT_FILE)
	// TODO: Add a security check for filepath.
	// if !strings.HasPrefix(filepath.Clean(filePath), "C:\\Tools\\") {
	// 	c.String(403, "Invalid file path!")
	// 	return
	// }

	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+AFL_PLOT_FILE)
	c.Header("Content-Type", "application/octet-stream")
	c.File(filePath)
}
