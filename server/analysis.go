package main

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/parnurzeal/gorequest"
	"github.com/rs/xid"
)

type analysisBucketReq struct {
	Bucket string `json:"bucket"`
}

type analysisReadReq struct {
	Bucket string `json:"bucket"`
	File   string `json:"file"`
}

type analysisDeleteReq struct {
	Bucket string `json:"bucket"`
	File   string `json:"file"`
}

type analysisDownloadReq struct {
	Hash string `json:"hash"`
}

func analysisJob(c *gin.Context) {
	j := newJob()
	j.GUID, _ = xid.FromString(c.Param("guid"))
	if err := j.LoadByGUID(); err != nil {
		otherError(c, map[string]string{
			"alert":    err.Error(),
			"template": "job_analysis",
		})
		return
	}

	c.HTML(http.StatusOK, "job_analysis", gin.H{
		"title": "Analysis",
		"guid":  j.GUID.String(),
		"path":  c.Request.URL.Path,
	})
}

func analysisBuckets(c *gin.Context) {
	j := newJob()
	j.GUID, _ = xid.FromString(c.Param("guid"))
	if err := j.LoadByGUID(); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}
	a, _ := j.GetAgent()

	request := gorequest.New()
	request.Debug = false
	targetURL := "http://" + a.Host + ":" + strconv.Itoa(a.Port) + "/job/" + j.GUID.String() + "/analysis_buckets"

	var out map[string][]string
	_, _, errs := request.Post(targetURL).Set("X-Auth-Key", a.Key).EndStruct(&out)
	if errs != nil {
		otherError(c, map[string]string{"alert": errs[0].Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func analysisFiles(c *gin.Context) {
	j := newJob()
	j.GUID, _ = xid.FromString(c.Param("guid"))
	if err := j.LoadByGUID(); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}
	a, _ := j.GetAgent()

	var req analysisBucketReq
	_ = c.ShouldBindJSON(&req)

	request := gorequest.New()
	request.Debug = false
	targetURL := "http://" + a.Host + ":" + strconv.Itoa(a.Port) + "/job/" + j.GUID.String() + "/analysis_files"

	var out map[string][]string
	_, _, errs := request.Post(targetURL).Set("X-Auth-Key", a.Key).Send(req).EndStruct(&out)
	if errs != nil {
		otherError(c, map[string]string{"alert": errs[0].Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func analysisRead(c *gin.Context) {
	j := newJob()
	j.GUID, _ = xid.FromString(c.Param("guid"))
	if err := j.LoadByGUID(); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}
	a, _ := j.GetAgent()

	var req analysisReadReq
	if err := c.ShouldBindJSON(&req); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}

	request := gorequest.New()
	request.Debug = false
	targetURL := "http://" + a.Host + ":" + strconv.Itoa(a.Port) + "/job/" + j.GUID.String() + "/analysis_read"

	var out map[string]string
	_, _, errs := request.Post(targetURL).Set("X-Auth-Key", a.Key).Send(req).EndStruct(&out)
	if errs != nil {
		otherError(c, map[string]string{"alert": errs[0].Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func analysisDelete(c *gin.Context) {
	j := newJob()
	j.GUID, _ = xid.FromString(c.Param("guid"))
	if err := j.LoadByGUID(); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}
	a, _ := j.GetAgent()

	var req analysisDeleteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}

	request := gorequest.New()
	request.Debug = false
	targetURL := "http://" + a.Host + ":" + strconv.Itoa(a.Port) + "/job/" + j.GUID.String() + "/analysis_delete"

	resp, bodyBytes, errs := request.Post(targetURL).Set("X-Auth-Key", a.Key).Send(req).EndBytes()
	if errs != nil {
		otherError(c, map[string]string{"alert": errs[0].Error()})
		return
	}
	if resp.StatusCode != http.StatusOK {
		otherError(c, map[string]string{"alert": string(bodyBytes)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"alert": "Report deleted", "context": "success"})
}

func analysisDownloadCrash(c *gin.Context) {
	j := newJob()
	j.GUID, _ = xid.FromString(c.Param("guid"))
	if err := j.LoadByGUID(); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}
	a, _ := j.GetAgent()

	var req analysisDownloadReq
	if err := c.ShouldBindJSON(&req); err != nil {
		otherError(c, map[string]string{"alert": err.Error()})
		return
	}

	request := gorequest.New()
	request.Debug = false
	targetURL := "http://" + a.Host + ":" + strconv.Itoa(a.Port) + "/job/" + j.GUID.String() + "/analysis_download_crash"

	resp, bodyBytes, errs := request.Post(targetURL).Set("X-Auth-Key", a.Key).Send(req).EndBytes()
	if errs != nil {
		otherError(c, map[string]string{"alert": errs[0].Error()})
		return
	}
	if resp.StatusCode != http.StatusOK {
		otherError(c, map[string]string{"alert": string(bodyBytes)})
		return
	}

	// Pass-through as binary. Use hash as filename.
	filename := strings.TrimSpace(req.Hash)
	if filename == "" {
		filename = "crash.bin"
	}
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Data(http.StatusOK, "application/octet-stream", bodyBytes)
}


