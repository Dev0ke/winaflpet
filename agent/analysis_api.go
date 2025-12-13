//go:build windows
// +build windows

package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

type AnalysisListRequest struct {
	Bucket string `json:"bucket"`
}

type AnalysisReadRequest struct {
	Bucket string `json:"bucket"`
	File   string `json:"file"`
}

type AnalysisDeleteRequest struct {
	Bucket string `json:"bucket"`
	File   string `json:"file"`
}

type AnalysisDownloadCrashRequest struct {
	Hash string `json:"hash"`
}

func safeBaseName(s string) (string, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", errors.New("empty value")
	}
	if strings.Contains(v, "/") || strings.Contains(v, "\\") || strings.Contains(v, "..") {
		return "", errors.New("invalid path")
	}
	return v, nil
}

func analysisBaseDirs(j Job) (string, string) {
	outputDir := joinPath(j.AFLDir, j.Output)
	return filepath.Join(outputDir, "crashes"), filepath.Join(outputDir, "crashes_result")
}

func analysisListBuckets(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	_ = logger.Infof("ANALYSIS api=buckets guid=%s", j.GUID.String())

	_, resultDir := analysisBaseDirs(j)
	entries, err := os.ReadDir(resultDir)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"buckets": []string{}})
		return
	}

	buckets := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			buckets = append(buckets, e.Name())
		}
	}
	sort.Strings(buckets)
	c.JSON(http.StatusOK, gin.H{"buckets": buckets})
}

func analysisListFiles(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req AnalysisListRequest
	_ = c.ShouldBindJSON(&req)
	_ = logger.Infof("ANALYSIS api=files guid=%s bucket=%q", j.GUID.String(), req.Bucket)
	bucket, err := safeBaseName(req.Bucket)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, resultDir := analysisBaseDirs(j)
	dir := filepath.Join(resultDir, bucket)
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"files": []string{}})
		return
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func analysisReadFile(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req AnalysisReadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = logger.Infof("ANALYSIS api=read guid=%s bucket=%q file=%q", j.GUID.String(), req.Bucket, req.File)
	bucket, err := safeBaseName(req.Bucket)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	file, err := safeBaseName(req.File)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, resultDir := analysisBaseDirs(j)
	p := filepath.Join(resultDir, bucket, file)
	b, err := os.ReadFile(p)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"text": string(b)})
}

func analysisDeleteFile(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req AnalysisDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = logger.Infof("ANALYSIS api=delete guid=%s bucket=%q file=%q", j.GUID.String(), req.Bucket, req.File)
	bucket, err := safeBaseName(req.Bucket)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	file, err := safeBaseName(req.File)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, resultDir := analysisBaseDirs(j)
	p := filepath.Join(resultDir, bucket, file)
	if err := os.Remove(p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "deleted"})
}

func analysisDownloadCrash(c *gin.Context) {
	j, _, err := project.GetJob(c.Param("guid"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req AnalysisDownloadCrashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = logger.Infof("ANALYSIS api=download_crash guid=%s hash=%q", j.GUID.String(), req.Hash)
	hash, err := safeBaseName(req.Hash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	crashDir, _ := analysisBaseDirs(j)
	p := filepath.Join(crashDir, hash)
	if !fileExists(p) {
		c.JSON(http.StatusNotFound, gin.H{"error": "crash file not found"})
		return
	}

	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+hash)
	c.Header("Content-Type", "application/octet-stream")
	c.File(p)
}


