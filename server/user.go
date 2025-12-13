package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	sq "github.com/Masterminds/squirrel"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/sgabe/structable"
)

const (
	TB_NAME_USERS   = "users"
	TB_SCHEMA_USERS = `CREATE TABLE users (
		"id" INTEGER PRIMARY KEY AUTOINCREMENT,
		"username" TEXT UNIQUE NOT NULL,
		"password" TEXT NOT NULL,
		"firstname" TEXT NOT NULL,
		"lastname" TEXT NOT NULL,
		"email" TEXT NOT NULL,
		"alert_apikey" TEXT,
		"alert_interval_min" INTEGER,
		"alert_enabled" INTEGER,
		"alert_check_agent" INTEGER,
		"alert_check_job" INTEGER,
		"alert_check_crash" INTEGER,
		"alert_agents" TEXT,
		"alert_jobs" TEXT
	);`
)

type User struct {
	structable.Recorder
	ID                      int    `stbl:"id, PRIMARY_KEY, AUTO_INCREMENT"`
	UserName                string `json:"username" form:"username" stbl:"username, UNIQUE"`
	Password                string `json:"password" form:"password" stbl:"password, NOT NULL"`
	NewPassword             string `json:"newPassword" form:"newPassword"`
	NewPasswordConfirmation string `json:"newPasswordConfirmation" form:"newPasswordConfirmation"`
	FirstName               string `json:"firstname" form:"firstname" stbl:"firstname"`
	LastName                string `json:"lastname" form:"lastname" stbl:"lastname"`
	Email                   string `json:"email" form:"email" stbl:"email"`
	AlertAPIKey             string `json:"alert_apikey" form:"alert_apikey" stbl:"alert_apikey"`
	AlertIntervalMin        int    `json:"alert_interval_min" form:"alert_interval_min" stbl:"alert_interval_min"`
	AlertEnabled            int    `json:"alert_enabled" form:"alert_enabled" stbl:"alert_enabled"`
	AlertCheckAgent         int    `json:"alert_check_agent" form:"alert_check_agent" stbl:"alert_check_agent"`
	AlertCheckJob           int    `json:"alert_check_job" form:"alert_check_job" stbl:"alert_check_job"`
	AlertCheckCrash         int    `json:"alert_check_crash" form:"alert_check_crash" stbl:"alert_check_crash"`
	AlertAgents             string `json:"alert_agents" form:"alert_agents" stbl:"alert_agents"`
	AlertJobs               string `json:"alert_jobs" form:"alert_jobs" stbl:"alert_jobs"`
}

func newUser() *User {
	u := new(User)
	u.Recorder = structable.New(db, DB_FLAVOR).Bind(TB_NAME_USERS, u)
	return u
}

func (u *User) LoadByUsername() error {
	return u.Recorder.LoadWhere("username = ?", u.UserName)
}

func initUser() {
	log.Printf("Creating '%s' user\n", DEFAULT_USER_NAME)

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err.Error())
	}

	password, err := generatePassword(hostname)
	if err != nil {
		log.Fatal(err.Error())
	}

	db := getDB()
	if _, err := sq.Insert("users").
		Columns("username", "password", "firstname", "lastname", "email").
		Values(DEFAULT_USER_NAME, password, "", "", "").
		RunWith(db).Exec(); err != nil {
		log.Fatal(err.Error())
	}

	log.Printf("User '%s' created\n", DEFAULT_USER_NAME)
}

func editUser(c *gin.Context) {
	title := "Edit user"

	claims := jwt.ExtractClaims(c)
	user := newUser()
	user.UserName = claims[identityKey].(string)
	user.LoadByUsername()

	agents, _ := loadAgents()
	jobs, _ := loadAllJobs()

	switch c.Request.Method {
	case http.MethodGet:
		c.HTML(http.StatusOK, "user_edit", gin.H{
			"title": title,
			"user":  user,
			"agents": agents,
			"jobs":   jobs,
			"path":  c.Request.URL.Path,
		})
		return
	case http.MethodPost:
		if ok, err := comparePassword(c.PostForm("password"), user.Password); !ok || err != nil {
			c.HTML(http.StatusOK, "user_edit", gin.H{
				"title":   title,
				"alert":   "Password invalid!",
				"user":    user,
				"agents":  agents,
				"jobs":    jobs,
				"context": "danger",
				"path":    c.Request.URL.Path,
			})
			return
		}

		oriPassword := user.Password
		oriAlertAPIKey := user.AlertAPIKey
		if err := c.ShouldBind(&user); err != nil {
			c.HTML(http.StatusOK, "user_edit", gin.H{
				"title":   title,
				"alert":   err.Error(),
				"user":    user,
				"agents":  agents,
				"jobs":    jobs,
				"context": "danger",
				"path":    c.Request.URL.Path,
			})
			return
		}
		user.Password = oriPassword
		// Do not clear the API key if the field is left blank.
		if strings.TrimSpace(user.AlertAPIKey) == "" {
			user.AlertAPIKey = oriAlertAPIKey
		} else {
			user.AlertAPIKey = strings.TrimSpace(user.AlertAPIKey)
		}

		// Multi-select monitoring targets are posted as arrays; store as CSV in DB.
		user.AlertAgents = strings.Join(c.PostFormArray("monitor_agents"), ",")
		user.AlertJobs = strings.Join(c.PostFormArray("monitor_jobs"), ",")

		if user.NewPassword != "" {
			if user.NewPassword != user.NewPasswordConfirmation {
				c.HTML(http.StatusOK, "user_edit", gin.H{
					"title":   title,
					"alert":   "The password confirmation does not match.",
					"user":    user,
					"agents":  agents,
					"jobs":    jobs,
					"context": "danger",
					"path":    c.Request.URL.Path,
				})
				return
			}
			user.Password, _ = generatePassword(user.NewPassword)
		}

		if err := user.Update(); err != nil {
			c.HTML(http.StatusOK, "user_edit", gin.H{
				"title":   title,
				"alert":   err.Error(),
				"user":    user,
				"agents":  agents,
				"jobs":    jobs,
				"context": "danger",
				"path":    c.Request.URL.Path,
			})
			return
		}

		c.HTML(http.StatusOK, "user_edit", gin.H{
			"title":   title,
			"alert":   "User profile successfully updated.",
			"user":    user,
			"agents":  agents,
			"jobs":    jobs,
			"context": "success",
			"path":    c.Request.URL.Path,
		})
		return
	default:
		c.JSON(http.StatusInternalServerError, gin.H{})
	}
}
