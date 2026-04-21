package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Hash      string    `json:"-"`
	IsAdmin   bool      `json:"isAdmin"`
	CreatedAt time.Time `json:"createdAt"`
}

type Activity struct {
	ID       int       `json:"id"`
	Username string    `json:"username"`
	Action   string    `json:"action"`
	Details  string    `json:"details"`
	Time     time.Time `json:"time"`
}

type CodeResult struct {
	ID       int       `json:"id"`
	Username string    `json:"username"`
	Code     string    `json:"code"`
	Output   string    `json:"output"`
	Error    string    `json:"error,omitempty"`
	Time     time.Time `json:"time"`
}

var (
	users      = make(map[string]User)
	activities []Activity
	codeRuns   []CodeResult
	userMu     sync.RWMutex
	actMu      sync.Mutex
	runMu      sync.Mutex
	sessions   = make(map[string]string)
	tmpl       *template.Template
)

func init() {
	rand.Seed(time.Now().UnixNano())
	users["admin"] = User{ID: 1, Username: "admin", Hash: hashpwd("admin123"), IsAdmin: true, CreatedAt: time.Now()}
}

func hashpwd(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

func gensid() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func logact(user, action, details string) {
	actMu.Lock()
	defer actMu.Unlock()
	activities = append(activities, Activity{
		ID:       len(activities) + 1,
		Username: user,
		Action:   action,
		Details:  details,
		Time:     time.Now(),
	})
	saveCSV()
}

func saveCSV() {
	f, _ := os.Create("activities.csv")
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"ID", "Username", "Action", "Details", "Time"})
	for _, a := range activities {
		w.Write([]string{fmt.Sprintf("%d", a.ID), a.Username, a.Action, a.Details, a.Time.Format(time.RFC3339)})
	}
	w.Flush()
}

func loadCSV() {
	f, err := os.Open("activities.csv")
	if err != nil {
		return
	}
	defer f.Close()
	r := csv.NewReader(f)
	_, _ = r.Read()
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if len(rec) >= 5 {
			t, _ := time.Parse(time.RFC3339, rec[4])
			activities = append(activities, Activity{
				ID:       len(activities) + 1,
				Username: rec[1],
				Action:   rec[2],
				Details:  rec[3],
				Time:     t,
			})
		}
	}
}

func getuser(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	userMu.RLock()
	defer userMu.RUnlock()
	return sessions[c.Value]
}

func auth(w http.ResponseWriter, r *http.Request) bool {
	return getuser(w, r) != ""
}

func isadmin(w http.ResponseWriter, r *http.Request) bool {
	u := getuser(w, r)
	if u == "" {
		return false
	}
	userMu.RLock()
	defer userMu.RUnlock()
	return users[u].IsAdmin
}

func main() {
	loadCSV()
	tmpl = template.Must(template.ParseGlob("templates/*.html"))

	http.HandleFunc("/", home)
	http.HandleFunc("/login", loginpg)
	http.HandleFunc("/dologin", dologin)
	http.HandleFunc("/register", registerpg)
	http.HandleFunc("/doregister", doregister)
	http.HandleFunc("/logout", logout)

	http.HandleFunc("/dashboard", dash)
	http.HandleFunc("/terminal", term)
	http.HandleFunc("/run", runcode)
	http.HandleFunc("/logact", logacth)

	http.HandleFunc("/admin", admin)
	http.HandleFunc("/admin/users", adminusers)
	http.HandleFunc("/admin/activities", adminacts)
	http.HandleFunc("/admin/codes", admincodes)
	http.HandleFunc("/admin/deluser", deluser)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	log.Println("BLACKSAUCE running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func home(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "home.html", nil)
}

func loginpg(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "login.html", nil)
}

func registerpg(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "register.html", nil)
}

func dologin(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("username")
	p := r.FormValue("password")

	userMu.RLock()
	usr, ok := users[u]
	userMu.RUnlock()

	if !ok || usr.Hash != hashpwd(p) {
		tmpl.ExecuteTemplate(w, "login.html", map[string]string{"error": "Invalid credentials"})
		return
	}

	sid := gensid()
	userMu.Lock()
	sessions[sid] = u
	userMu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: "session", Value: sid, Path: "/"})
	logact(u, "login", "User logged in")

	if usr.IsAdmin {
		http.Redirect(w, r, "/admin", http.StatusFound)
	} else {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}

func doregister(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("username")
	p := r.FormValue("password")

	if u == "" || p == "" {
		tmpl.ExecuteTemplate(w, "register.html", map[string]string{"error": "All fields required"})
		return
	}

	userMu.Lock()
	if _, exists := users[u]; exists {
		userMu.Unlock()
		tmpl.ExecuteTemplate(w, "register.html", map[string]string{"error": "Username exists"})
		return
	}

	users[u] = User{ID: len(users) + 1, Username: u, Hash: hashpwd(p), CreatedAt: time.Now()}
	userMu.Unlock()

	logact(u, "register", "New user registered")
	tmpl.ExecuteTemplate(w, "login.html", map[string]string{"success": "Registered! Login now."})
}

func logout(w http.ResponseWriter, r *http.Request) {
	u := getuser(w, r)
	if u != "" {
		logact(u, "logout", "Logged out")
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func dash(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpl.ExecuteTemplate(w, "dashboard.html", map[string]string{"username": getuser(w, r)})
}

func term(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	logact(getuser(w, r), "terminal", "Opened terminal")
	tmpl.ExecuteTemplate(w, "terminal.html", map[string]string{"username": getuser(w, r)})
}

func runcode(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) {
		return
	}

	u := getuser(w, r)
	code := r.FormValue("code")

	logact(u, "code_run", fmt.Sprintf("Ran code: %d chars", len(code)))

	out, err := runGo(code)

	runMu.Lock()
	codeRuns = append(codeRuns, CodeResult{
		ID:       len(codeRuns) + 1,
		Username: u,
		Code:     code,
		Output:   out,
		Error:    err,
		Time:     time.Now(),
	})
	runMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"output":%q,"error":%q}`, out, err)
}

func runGo(code string) (string, string) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("code_%d.go", time.Now().UnixNano()))

	f, err := os.Create(tmp)
	if err != nil {
		return "", err.Error()
	}
	f.WriteString("package main\n\nimport \"fmt\"\n\n")
	f.WriteString(code)
	f.Close()
	defer os.Remove(tmp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(out)
	}
	return string(out), ""
}

func logacth(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) {
		return
	}
	u := getuser(w, r)
	act := r.FormValue("action")
	det := r.FormValue("details")
	logact(u, act, det)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"success":true}`)
}

func admin(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) || !isadmin(w, r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	tmpl.ExecuteTemplate(w, "admin.html", map[string]int{
		"userCount":     len(users),
		"activityCount": len(activities),
		"codeCount":     len(codeRuns),
	})
}

func adminusers(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) || !isadmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	userMu.RLock()
	defer userMu.RUnlock()
	fmt.Fprint(w, "{")
	first := true
	for _, u := range users {
		if !first {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `%q:{"id":%d,"username":%q,"isAdmin":%v,"createdAt":%q}`, u.Username, u.ID, u.Username, u.IsAdmin, u.CreatedAt.Format(time.RFC3339))
		first = false
	}
	fmt.Fprint(w, "}")
}

func adminacts(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) || !isadmin(w, r) {
		return
	}
	actMu.Lock()
	defer actMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "[")
	for i, a := range activities {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"id":%d,"username":%q,"action":%q,"details":%q,"timestamp":%q}`, a.ID, a.Username, a.Action, a.Details, a.Time.Format(time.RFC3339))
	}
	fmt.Fprint(w, "]")
}

func admincodes(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) || !isadmin(w, r) {
		return
	}
	runMu.Lock()
	defer runMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "[")
	for i, c := range codeRuns {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"id":%d,"username":%q,"code":%q,"output":%q,"error":%q,"timestamp":%q}`, c.ID, c.Username, c.Code, c.Output, c.Error, c.Time.Format(time.RFC3339))
	}
	fmt.Fprint(w, "]")
}

func deluser(w http.ResponseWriter, r *http.Request) {
	if !auth(w, r) || !isadmin(w, r) {
		return
	}
	u := r.FormValue("username")
	userMu.Lock()
	defer userMu.Unlock()
	if users[u].IsAdmin {
		fmt.Fprint(w, `{"error":"Cannot delete admin"}`)
		return
	}
	delete(users, u)
	logact("admin", "delete_user", fmt.Sprintf("Deleted: %s", u))
	fmt.Fprint(w, `{"success":true}`)
}
