//go:build windows
// +build windows

package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const agentLogBodyLimit = 64 * 1024 // 64KB

func shouldLogRequestBody(r *http.Request) bool {
	// Only log bodies for endpoints where server sends "instructions"/payload.
	p := r.URL.Path
	if !(strings.HasPrefix(p, "/job/") || strings.HasPrefix(p, "/crash/")) {
		return false
	}
	if r.Method != http.MethodPost {
		return false
	}
	// Skip multipart / huge bodies.
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "multipart/form-data") {
		return false
	}
	return true
}

func agentRequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		var bodySnippet string
		if shouldLogRequestBody(c.Request) && c.Request.Body != nil {
			// Best effort; don't blow up memory.
			b, _ := io.ReadAll(io.LimitReader(c.Request.Body, agentLogBodyLimit+1))
			_ = c.Request.Body.Close()
			c.Request.Body = io.NopCloser(bytes.NewBuffer(b))

			if len(b) > agentLogBodyLimit {
				bodySnippet = string(b[:agentLogBodyLimit]) + " ...(truncated)"
			} else {
				bodySnippet = string(b)
			}
		}

		// Continue request.
		c.Next()

		lat := time.Since(start)
		path := c.Request.URL.Path
		method := c.Request.Method
		status := c.Writer.Status()
		ip := c.ClientIP()

		if bodySnippet != "" {
			_ = logger.Infof("HTTP %s %s ip=%s status=%d dur=%s body=%s", method, path, ip, status, lat, bodySnippet)
		} else if strings.HasPrefix(path, "/job/") || strings.HasPrefix(path, "/crash/") {
			_ = logger.Infof("HTTP %s %s ip=%s status=%d dur=%s", method, path, ip, status, lat)
		}
	}
}


