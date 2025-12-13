package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/Masterminds/squirrel"
	"github.com/parnurzeal/gorequest"
	"github.com/rs/xid"
	"github.com/sgabe/structable"
)

type Alert struct {
	Jobs []Job
}

func (a *Alert) AddJob(j Job) []Job {
	a.Jobs = append(a.Jobs, j)
	return a.Jobs
}

func (a *Alert) RemoveJob(i int) []Job {
	copy(a.Jobs[i:], a.Jobs[i+1:])

	if len(a.Jobs) == 1 {
		a.Jobs = nil
	} else {
		a.Jobs[i] = a.Jobs[len(a.Jobs)-1]
		a.Jobs = a.Jobs[:len(a.Jobs)-1]
	}

	return a.Jobs
}

func (a *Alert) GetJob(GUID xid.ID) (Job, int, error) {
	var j Job

	for index, j := range a.Jobs {
		if j.GUID == GUID {
			return j, index, nil
		}
	}

	return j, 0, errors.New("Job not found")
}

func (a *Alert) FindJob(GUID xid.ID) (bool, error) {
	for _, j := range a.Jobs {
		if j.GUID == GUID {
			return true, nil
		}
	}

	return false, nil
}

func (a *Alert) MonitorOnce(u *User) {
	if u == nil {
		return
	}
	if u.AlertEnabled == 0 {
		return
	}
	if strings.TrimSpace(u.AlertAPIKey) == "" {
		return
	}

	// Agents selected in profile
	if u.AlertCheckAgent != 0 {
		for _, guidStr := range strings.Split(strings.TrimSpace(u.AlertAgents), ",") {
			guidStr = strings.TrimSpace(guidStr)
			if guidStr == "" {
				continue
			}
			ag := newAgent()
			if g, err := xid.FromString(guidStr); err == nil {
				ag.GUID = g
			} else {
				continue
			}
			if err := ag.loadByGUID(); err != nil {
				continue
			}

			request := gorequest.New().Timeout(1500 * time.Millisecond)
			request.Debug = false
			targetURL := fmt.Sprintf("http://%s:%d/ping", ag.Host, ag.Port)
			_, body, errs := request.Post(targetURL).Set("X-Auth-Key", ag.Key).End()
			if len(errs) > 0 || body != "pong" {
				reason := body
				if len(errs) > 0 {
					reason = errs[0].Error()
				}
				title := fmt.Sprintf("Agent DOWN: %s", ag.Name)
				desp := fmt.Sprintf("## Agent 状态异常\n\n- **Agent**: %s (`%s:%d`)\n- **原因**: `%s`\n", ag.Name, ag.Host, ag.Port, reason)
				_ = a.sendServerChan(u, title, desp, title)
			}
		}
	}

	// Jobs selected in profile
	for _, guidStr := range strings.Split(strings.TrimSpace(u.AlertJobs), ",") {
		guidStr = strings.TrimSpace(guidStr)
		if guidStr == "" {
			continue
		}
		j := newJob()
		if g, err := xid.FromString(guidStr); err == nil {
			j.GUID = g
		} else {
			continue
		}
		if err := j.LoadByGUID(); err != nil {
			continue
		}
		if j.Status == 0 {
			// Not running -> skip (avoid noisy alerts).
			continue
		}

		agent, _ := j.GetAgent()

		// job running status check
		if u.AlertCheckJob != 0 {
			request := gorequest.New()
			request.Debug = false

			processIDs := []int{}
			missingStats := []int{}
			for fID := 1; fID <= j.Cores; fID++ {
				if !hasStatus(j.Status, fID) {
					continue
				}
				s := newStat()
				s.JobID = j.ID
				s.AFLBanner = fmt.Sprintf("%s%d", j.Banner, fID)
				if err := s.LoadJobIDFuzzerID(); err != nil || s.FuzzerProcessID == 0 {
					missingStats = append(missingStats, fID)
					continue
				}
				processIDs = append(processIDs, s.FuzzerProcessID)
			}

			if len(missingStats) > 0 {
				title := fmt.Sprintf("Job WARN: %s", j.Name)
				desp := fmt.Sprintf("## Job 运行状态异常\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **异常实例**: fids=%v\n- **原因**: `missing stats/pid`\n",
					j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, missingStats)
				_ = a.sendServerChan(u, title, desp, title)
			}

			if len(processIDs) > 0 {
				targetURL := fmt.Sprintf("http://%s:%d/job/%s/check", agent.Host, agent.Port, j.GUID)
				checkResp := APIResponse{}
				_, _, errs := request.Post(targetURL).Set("X-Auth-Key", agent.Key).Send(processIDs).EndStruct(&checkResp)
				if len(errs) > 0 {
					title := fmt.Sprintf("Job DOWN: %s", j.Name)
					desp := fmt.Sprintf("## Job 运行状态异常\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **原因**: `%s`\n",
						j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, errs[0].Error())
					_ = a.sendServerChan(u, title, desp, title)
				} else if checkResp.PID != 0 {
					s := newStat()
					s.JobID = j.ID
					s.FuzzerProcessID = checkResp.PID
					_ = s.LoadJobIDProcessID()
					if fid := s.GetFID(); fid != 0 {
						j.Status = clearStatus(j.Status, statusMap[fid])
						_ = j.Update()
					}
					title := fmt.Sprintf("Job DOWN: %s", j.Name)
					desp := fmt.Sprintf("## Job 运行状态异常\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **异常进程**: pid=%d\n- **消息**: %s\n",
						j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, checkResp.PID, strings.TrimSpace(checkResp.Msg))
					_ = a.sendServerChan(u, title, desp, title)
				}
			}
		}

		// crash check
		if u.AlertCheckCrash != 0 {
			request := gorequest.New()
			request.Debug = false

			targetURL := fmt.Sprintf("http://%s:%d/job/%s/collect", agent.Host, agent.Port, j.GUID)
			var crashesTemp []Crash
			resp, _, errs := request.Post(targetURL).Set("X-Auth-Key", agent.Key).EndStruct(&crashesTemp)
			if len(errs) > 0 || resp.StatusCode != http.StatusOK {
				continue
			}

			resumedJob := false
			if j.Input == "-" {
				resumedJob = true
			}

			var crashes []Crash
			for _, crash := range crashesTemp {
				c := newCrash()
				c.JobID = j.ID
				c.FuzzerID = crash.FuzzerID

				recentCrash := false
				for _, i := range crashesTemp {
					if i.FuzzerID == c.FuzzerID && strings.Contains(i.Args, "\\crashes\\") {
						recentCrash = true
						break
					}
				}

				re := regexp.MustCompile(c.FuzzerID + `\\crashes_\d{14}\\`)
				backedUpCrash := re.MatchString(crash.Args)

				if resumedJob && !recentCrash && backedUpCrash {
					c.Args = re.ReplaceAllString(crash.Args, c.FuzzerID+"\\crashes\\")
					if err := c.LoadByJobIDArgs(); err == nil {
						c.Args = crash.Args
						_ = c.Update()
						continue
					}
				}

				c.Args = crash.Args
				if err := c.LoadByJobIDArgs(); err != nil {
					if err := c.Insert(); err != nil {
						break
					}
					crashes = append(crashes, *c)
				}
			}

			if len(crashes) > 0 {
				title := fmt.Sprintf("Crash x%d: %s", len(crashes), j.Name)
				desp := fmt.Sprintf("## 新 Crash\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **数量**: %d\n\n### 文件列表\n",
					j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, len(crashes))
				for _, crash := range crashes {
					filePath := strings.Split(crash.Args, "\\")
					fileName := filePath[len(filePath)-1]
					desp += fmt.Sprintf("- `%s`\n", fileName)
				}
				_ = a.sendServerChan(u, title, desp, title)
			}
		}
	}
}

func maskAPIKey(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	return "****"
}

func (a *Alert) sendServerChan(u *User, title, desp, short string) error {
	if u == nil {
		return errors.New("user is nil")
	}

	apiKey := strings.TrimSpace(u.AlertAPIKey)
	if apiKey == "" {
		return errors.New("alert apikey is empty")
	}

	// title max 32 by Server酱 API
	title = strings.TrimSpace(title)
	if title == "" {
		title = "WinAFL Pet Alert"
	}
	if len([]rune(title)) > 32 {
		title = string([]rune(title)[:32])
	}

	if strings.TrimSpace(short) == "" {
		short = title
	}
	if len([]rune(short)) > 64 {
		short = string([]rune(short)[:64])
	}

	targetURL := fmt.Sprintf("https://sctapi.ftqq.com/%s.send", apiKey)
	req := map[string]string{
		"title":   title,
		"desp":    desp,
		"short":   short,
		"noip":    "1",
		"channel": "9",
	}

	request := gorequest.New().Timeout(10 * time.Second)
	request.Debug = false
	resp, body, errs := request.Post(targetURL).Type("form").Send(req).End()
	if len(errs) > 0 {
		return errs[0]
	}
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("serverchan http status=%d body=%s", resp.StatusCode, body)
	}
	return nil
}

func (a *Alert) Monitor(j Job, u *User) {
	intervalMin := u.AlertIntervalMin
	if intervalMin <= 0 {
		intervalMin = DEFAULT_ALERT_INTERVAL
	}
	d := time.Duration(intervalMin) * time.Minute
	ticker := time.NewTicker(d)

	for _ = range ticker.C {
		j.Recorder.Load()
		if j.Status == 0 {
			ticker.Stop()
			if _, i, err := a.GetJob(j.GUID); err == nil {
				a.RemoveJob(i)
			}
			return
		}

		agent, _ := j.GetAgent()

		// 1) Agent health check
		agentErr := ""
		{
			request := gorequest.New().Timeout(1500 * time.Millisecond)
			request.Debug = false
			targetURL := fmt.Sprintf("http://%s:%d/ping", agent.Host, agent.Port)
			resp, body, errs := request.Post(targetURL).Set("X-Auth-Key", agent.Key).End()
			if len(errs) > 0 {
				agentErr = errs[0].Error()
			} else if body != "pong" {
				agentErr = body
			} else if resp != nil {
				// ok
			}
		}
		if agentErr != "" {
			title := fmt.Sprintf("Agent DOWN: %s", agent.Name)
			desp := fmt.Sprintf("## Agent 状态异常\n\n- **Agent**: %s (`%s:%d`)\n- **Job**: %s (`%s`)\n- **原因**: `%s`\n\n> ServerChan: `https://sctapi.ftqq.com/%s.send`\n",
				agent.Name, agent.Host, agent.Port, j.Name, j.GUID.String(), agentErr, maskAPIKey(u.AlertAPIKey))
			if err := a.sendServerChan(u, title, desp, title); err != nil {
				log.Println(err)
			}
			// Keep monitoring; agent might recover.
			continue
		}

		request := gorequest.New()
		request.Debug = false

		// 2) Job process health check (master/slaves)
		{
			// Only check instances that are marked started in the status bitmask.
			processIDs := []int{}
			missingStats := []int{}
			for fID := 1; fID <= j.Cores; fID++ {
				if !hasStatus(j.Status, fID) {
					continue
				}
				s := newStat()
				s.JobID = j.ID
				s.AFLBanner = fmt.Sprintf("%s%d", j.Banner, fID)
				if err := s.LoadJobIDFuzzerID(); err != nil || s.FuzzerProcessID == 0 {
					missingStats = append(missingStats, fID)
					continue
				}
				processIDs = append(processIDs, s.FuzzerProcessID)
			}

			if len(missingStats) > 0 {
				title := fmt.Sprintf("Job WARN: %s", j.Name)
				desp := fmt.Sprintf("## Job 运行状态异常\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **异常实例**: fids=%v\n- **原因**: `missing stats/pid for started instance(s)`\n",
					j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, missingStats)
				if err := a.sendServerChan(u, title, desp, title); err != nil {
					log.Println(err)
				}
			}

			if len(processIDs) > 0 {
				targetURL := fmt.Sprintf("http://%s:%d/job/%s/check", agent.Host, agent.Port, j.GUID)
				checkResp := APIResponse{}
				_, _, errs := request.Post(targetURL).Set("X-Auth-Key", agent.Key).Send(processIDs).EndStruct(&checkResp)
				if len(errs) > 0 {
					title := fmt.Sprintf("Job DOWN: %s", j.Name)
					desp := fmt.Sprintf("## Job 运行状态异常\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **原因**: `%s`\n",
						j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, errs[0].Error())
					if err := a.sendServerChan(u, title, desp, title); err != nil {
						log.Println(err)
					}
				} else if checkResp.PID != 0 {
					// Agent reported a missing fuzzer instance. Reflect it in server status and alert.
					s := newStat()
					s.JobID = j.ID
					s.FuzzerProcessID = checkResp.PID
					_ = s.LoadJobIDProcessID()
					if fid := s.GetFID(); fid != 0 {
						j.Status = clearStatus(j.Status, statusMap[fid])
						_ = j.Update()
					}
					title := fmt.Sprintf("Job DOWN: %s", j.Name)
					desp := fmt.Sprintf("## Job 运行状态异常\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **异常进程**: pid=%d\n- **消息**: %s\n",
						j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, checkResp.PID, strings.TrimSpace(checkResp.Msg))
					if err := a.sendServerChan(u, title, desp, title); err != nil {
						log.Println(err)
					}
				}
			}
		}

		// 3) Crash collection (existing behavior), but push via Server酱
		targetURL := fmt.Sprintf("http://%s:%d/job/%s/collect", agent.Host, agent.Port, j.GUID)

		var crashesTemp []Crash
		resp, _, errs := request.Post(targetURL).Set("X-Auth-Key", agent.Key).EndStruct(&crashesTemp)
		if errs != nil || resp.StatusCode != http.StatusOK {
			// Agent/job may be temporarily unavailable; keep monitoring.
			continue
		}

		resumedJob := false
		if j.Input == "-" {
			resumedJob = true
		}

		var crashes []Crash
		for _, crash := range crashesTemp {
			c := newCrash()
			c.JobID = j.ID
			c.FuzzerID = crash.FuzzerID

			recentCrash := false
			for _, i := range crashesTemp {
				if i.FuzzerID == c.FuzzerID && strings.Contains(i.Args, "\\crashes\\") {
					recentCrash = true
					break
				}
			}

			re := regexp.MustCompile(c.FuzzerID + `\\crashes_\d{14}\\`)
			backedUpCrash := re.MatchString(crash.Args)

			// Avoid duplicate crash records when resuming aborted jobs.
			if resumedJob && !recentCrash && backedUpCrash {
				c.Args = re.ReplaceAllString(crash.Args, c.FuzzerID+"\\crashes\\")
				if err := c.LoadByJobIDArgs(); err == nil {
					c.Args = crash.Args
					if err := c.Update(); err != nil {
						log.Println(err)
					}
					continue
				}
			}

			c.Args = crash.Args
			if err := c.LoadByJobIDArgs(); err != nil {
				if err := c.Insert(); err != nil {
					log.Println(err)
					break
				}
				crashes = append(crashes, *c)
			}
		}

		if len(crashes) > 0 {
			title := fmt.Sprintf("Crash x%d: %s", len(crashes), j.Name)
			desp := fmt.Sprintf("## 新 Crash\n\n- **Job**: %s (`%s`)\n- **Agent**: %s (`%s:%d`)\n- **数量**: %d\n\n### 文件列表\n",
				j.Name, j.GUID.String(), agent.Name, agent.Host, agent.Port, len(crashes))
			for _, crash := range crashes {
				filePath := strings.Split(crash.Args, "\\")
				fileName := filePath[len(filePath)-1]
				desp += fmt.Sprintf("- `%s`\n", fileName)
			}

			if err := a.sendServerChan(u, title, desp, title); err != nil {
				log.Println(err)
			}
		}
	}
}

func alertTestUser(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user := newUser()
	user.UserName = claims[identityKey].(string)
	if err := user.LoadByUsername(); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}

	if strings.TrimSpace(user.AlertAPIKey) == "" {
		otherError(c, map[string]string{"alert": "API key is empty. Please set it in profile first."})
		return
	}

	title := "WinAFL Pet Alert Test"
	desp := fmt.Sprintf("## 测试推送\n\n- **时间**: %s\n- **channel**: 9\n- **noip**: 1\n- **apikey**: %s\n\n如果你看到这条消息，说明推送配置成功。",
		time.Now().Format(time.RFC3339), maskAPIKey(user.AlertAPIKey))

	if err := alert.sendServerChan(user, title, desp, title); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alert":   "Test push sent.",
		"context": "success",
	})
}

func loadUsers() ([]*User, error) {
	u := &User{}
	su := structable.New(db, DB_FLAVOR).Bind(TB_NAME_USERS, u)

	fn := func(d structable.Describer, q squirrel.SelectBuilder) (squirrel.SelectBuilder, error) {
		return q.Limit(1000), nil
	}

	items, err := listWhere(su, fn)
	if err != nil {
		return []*User{}, err
	}

	users := make([]*User, len(items))
	for i, item := range items {
		users[i] = item.Interface().(*User)
	}
	return users, nil
}

// startAlertScheduler periodically reads user preferences and runs monitoring checks.
func startAlertScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	lastRun := map[int]time.Time{}

	for range ticker.C {
		users, err := loadUsers()
		if err != nil {
			log.Println(err)
			continue
		}

		now := time.Now()
		for _, u := range users {
			if u == nil || u.AlertEnabled == 0 {
				continue
			}
			interval := u.AlertIntervalMin
			if interval <= 0 {
				continue
			}
			if strings.TrimSpace(u.AlertAPIKey) == "" {
				continue
			}

			if t, ok := lastRun[u.ID]; ok {
				if now.Sub(t) < time.Duration(interval)*time.Minute {
					continue
				}
			}
			lastRun[u.ID] = now

			// Run checks (best-effort).
			alert.MonitorOnce(u)
		}
	}
}
