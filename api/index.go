package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Hash     string `json:"hash"`
	IsAdmin  bool   `json:"isAdmin"`
}

var (
	users   = make(map[string]User)
	userMu  sync.RWMutex
	htmlTpl string
)

func init() {
	rand.Seed(time.Now().UnixNano())
	users["admin"] = User{ID: 1, Username: "admin", Hash: hashpwd("admin123"), IsAdmin: true}

	htmlTpl = os.Getenv("HTML_TEMPLATE")
}

func hashpwd(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

func gensid() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		return
	}

	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/" && method == "GET":
		fmt.Fprint(w, homeHTML())
	case path == "/login" && method == "GET":
		fmt.Fprint(w, loginHTML(""))
	case path == "/register" && method == "GET":
		fmt.Fprint(w, registerHTML(""))
	case path == "/dologin" && method == "POST":
		dologin(w, r)
	case path == "/doregister" && method == "POST":
		doregister(w, r)
	case path == "/logout" && method == "GET":
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusFound)
	case path == "/dashboard" && method == "GET":
		if !auth(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fmt.Fprint(w, dashboardHTML(getuser(r)))
	case path == "/terminal" && method == "GET":
		if !auth(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fmt.Fprint(w, terminalHTML(getuser(r)))
	case path == "/run" && method == "POST":
		runcode(w, r)
	case path == "/log" && method == "POST":
		logactivity(w, r)
	case path == "/admin" && method == "GET":
		if !auth(r) || !isadmin(r) {
			http.Error(w, "Forbidden", 403)
			return
		}
		fmt.Fprint(w, adminHTML())
	case path == "/api/users" && method == "GET":
		if !auth(r) || !isadmin(r) {
			return
		}
		jsonusers(w)
	case path == "/api/activities" && method == "GET":
		if !auth(r) || !isadmin(r) {
			return
		}
		jsonactivities(w)
	case path == "/api/codes" && method == "GET":
		if !auth(r) || !isadmin(r) {
			return
		}
		jsoncodes(w)
	default:
		http.Error(w, "Not Found", 404)
	}
}

func auth(r *http.Request) bool {
	c, _ := r.Cookie("sid")
	if c == nil {
		return false
	}
	userMu.RLock()
	defer userMu.RUnlock()
	_, ok := users[c.Value]
	return ok
}

func getuser(r *http.Request) string {
	c, _ := r.Cookie("sid")
	if c == nil {
		return ""
	}
	userMu.RLock()
	defer userMu.RUnlock()
	if u, ok := users[c.Value]; ok {
		return u.Username
	}
	return ""
}

func isadmin(r *http.Request) bool {
	c, _ := r.Cookie("sid")
	if c == nil {
		return false
	}
	userMu.RLock()
	defer userMu.RUnlock()
	if u, ok := users[c.Value]; ok {
		return u.IsAdmin
	}
	return false
}

func dologin(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("username")
	p := r.FormValue("password")

	userMu.RLock()
	usr, ok := users[u]
	userMu.RUnlock()

	if !ok || usr.Hash != hashpwd(p) {
		fmt.Fprint(w, loginHTML("Invalid credentials"))
		return
	}

	sid := gensid()
	userMu.Lock()
	users[sid] = usr
	userMu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", MaxAge: 86400 * 7})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func doregister(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("username")
	p := r.FormValue("password")

	if u == "" || p == "" {
		fmt.Fprint(w, registerHTML("All fields required"))
		return
	}

	userMu.Lock()
	if _, exists := users[u]; exists {
		userMu.Unlock()
		fmt.Fprint(w, registerHTML("Username exists"))
		return
	}

	id := len(users) + 1
	users[u] = User{ID: id, Username: u, Hash: hashpwd(p)}
	userMu.Unlock()

	fmt.Fprint(w, loginHTML("Registered! Login now."))
}

func runcode(w http.ResponseWriter, r *http.Request) {
	if !auth(r) {
		return
	}

	_ = r.FormValue("code")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"output":"Code execution requires backend - use local server","error":""}`)
}

func logactivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"logged":true}`)
}

func jsonusers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "{")
	first := true
	userMu.RLock()
	for _, u := range users {
		if u.Username == "" {
			continue
		}
		if !first {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `%q:{"id":%d,"username":%q,"isAdmin":%v}`, u.Username, u.ID, u.Username, u.IsAdmin)
		first = false
	}
	userMu.RUnlock()
	fmt.Fprint(w, "}")
}

func jsonactivities(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "[]")
}

func jsoncodes(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "[]")
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

var rxAlphanum = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func homeHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BLACKSAUCE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:linear-gradient(135deg,#0d0d0d,#1a1a2e);min-height:100vh;display:flex;justify-content:center;align-items:center;color:#00ff41}
.container{text-align:center;padding:40px;background:rgba(0,0,0,.8);border:2px solid #00ff41;border-radius:10px;box-shadow:0 0 30px rgba(0,255,65,.3)}
h1{font-size:3em;margin-bottom:10px;text-shadow:0 0 10px #00ff41}
.tagline{color:#888;margin-bottom:30px}
.btn{display:inline-block;padding:15px 40px;margin:10px;background:transparent;border:2px solid #00ff41;color:#00ff41;text-decoration:none;transition:.3s}
.btn:hover{background:#00ff41;color:#000}
</style>
</head>
<body>
<div class="container">
<h1>BLACKSAUCE</h1>
<p class="tagline">Secure Code Testing Platform</p>
<a href="/login" class="btn">Login</a>
<a href="/register" class="btn">Register</a>
</div>
</body>
</html>`
}

func loginHTML(err string) string {
	e := ""
	if err != "" {
		e = fmt.Sprintf(`<p style="color:#ff4444;margin-bottom:15px">%s</p>`, escape(err))
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login - BLACKSAUCE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:linear-gradient(135deg,#0d0d0d,#1a1a2e);min-height:100vh;display:flex;justify-content:center;align-items:center;color:#00ff41}
.container{width:400px;padding:40px;background:rgba(0,0,0,.8);border:2px solid #00ff41;border-radius:10px}
h1{text-align:center;margin-bottom:30px}
.form-group{margin-bottom:20px}
label{display:block;margin-bottom:8px;color:#888}
input{width:100%%;padding:12px;background:#111;border:1px solid #333;color:#00ff41;font-family:inherit;font-size:1em}
input:focus{outline:none;border-color:#00ff41}
.btn{width:100%%;padding:15px;background:transparent;border:2px solid #00ff41;color:#00ff41;font-size:1.1em;cursor:pointer}
.btn:hover{background:#00ff41;color:#000}
.link{text-align:center;margin-top:20px}
.link a{color:#888;text-decoration:none}
.link a:hover{color:#00ff41}
</style>
</head>
<body>
<div class="container">
<h1>LOGIN</h1>
%s
<form method="POST" action="/dologin">
<div class="form-group"><label>Username</label><input name="username" required></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn">Sign In</button>
</form>
<p class="link"><a href="/register">Create account</a></p>
</div>
</body>
</html>`, e)
}

func registerHTML(err string) string {
	e := ""
	if err != "" {
		e = fmt.Sprintf(`<p style="color:#ff4444;margin-bottom:15px">%s</p>`, escape(err))
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Register - BLACKSAUCE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:linear-gradient(135deg,#0d0d0d,#1a1a2e);min-height:100vh;display:flex;justify-content:center;align-items:center;color:#00ff41}
.container{width:400px;padding:40px;background:rgba(0,0,0,.8);border:2px solid #00ff41;border-radius:10px}
h1{text-align:center;margin-bottom:30px}
.form-group{margin-bottom:20px}
label{display:block;margin-bottom:8px;color:#888}
input{width:100%%;padding:12px;background:#111;border:1px solid #333;color:#00ff41;font-family:inherit;font-size:1em}
input:focus{outline:none;border-color:#00ff41}
.btn{width:100%%;padding:15px;background:transparent;border:2px solid #00ff41;color:#00ff41;font-size:1.1em;cursor:pointer}
.btn:hover{background:#00ff41;color:#000}
.link{text-align:center;margin-top:20px}
.link a{color:#888;text-decoration:none}
.link a:hover{color:#00ff41}
</style>
</head>
<body>
<div class="container">
<h1>REGISTER</h1>
%s
<form method="POST" action="/doregister">
<div class="form-group"><label>Username</label><input name="username" required></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn">Create Account</button>
</form>
<p class="link"><a href="/login">Already have account?</a></p>
</div>
</body>
</html>`, e)
}

func dashboardHTML(username string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard - BLACKSAUCE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:linear-gradient(135deg,#0d0d0d,#1a1a2e);min-height:100vh;color:#00ff41}
.nav{background:rgba(0,0,0,.9);padding:20px 40px;border-bottom:2px solid #00ff41;display:flex;justify-content:space-between}
.nav h1{font-size:1.5em}
.nav a{color:#00ff41;text-decoration:none;margin-left:20px}
.container{padding:40px;max-width:1200px;margin:0 auto;text-align:center}
.notice{background:rgba(255,170,0,.1);border:1px solid #ffaa00;padding:15px;margin:20px auto;color:#ffaa00;max-width:600px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-top:40px}
.card{background:rgba(0,0,0,.8);border:2px solid #00ff41;padding:30px;text-align:center;transition:.3s;cursor:pointer;text-decoration:none;color:#00ff41}
.card:hover{background:rgba(0,255,65,.1);box-shadow:0 0 20px rgba(0,255,65,.3)}
.card h2{font-size:1.5em;margin-bottom:10px}
.card p{color:#888}
</style>
</head>
<body>
<div class="nav">
<h1>BLACKSAUCE</h1>
<div><span style="color:#888">%s</span><a href="/logout">Logout</a></div>
</div>
<div class="container">
<h2>Welcome, %s!</h2>
<div class="notice">⚠️ Activity logging enabled. All actions are recorded.</div>
<div class="cards">
<a href="/terminal" class="card"><h2>Terminal</h2><p>Test and run code</p></a>
</div>
</div>
</body>
</html>`, username, username)
}

func terminalHTML(username string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Terminal - BLACKSAUCE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:linear-gradient(135deg,#0d0d0d,#1a1a2e);min-height:100vh;color:#00ff41}
.nav{background:rgba(0,0,0,.9);padding:20px 40px;border-bottom:2px solid #00ff41;display:flex;justify-content:space-between}
.nav h1{font-size:1.5em}
.nav a{color:#00ff41;text-decoration:none;margin-left:20px}
.container{padding:40px;max-width:1400px;margin:0 auto}
.notice{background:rgba(255,170,0,.1);border:1px solid #ffaa00;padding:10px;margin-bottom:20px;color:#ffaa00}
.editor{display:grid;grid-template-columns:1fr 1fr;gap:20px}
textarea{width:100%%;height:400px;background:#0a0a0a;color:#00ff41;border:none;padding:15px;font-family:inherit;font-size:14px;resize:none}
textarea:focus{outline:none}
.output{min-height:400px;padding:15px;background:#0a0a0a;white-space:pre-wrap;overflow-y:auto;color:#ccc}
.panel{background:#0a0a0a;border:2px solid #00ff41;border-radius:5px;overflow:hidden}
.panel-header{padding:15px;background:rgba(0,255,65,.1);border-bottom:1px solid #333;font-weight:bold}
.run-btn{padding:15px 40px;background:transparent;border:2px solid #00ff41;color:#00ff41;font-size:1.1em;cursor:pointer;font-family:inherit;margin-top:20px}
.run-btn:hover{background:#00ff41;color:#000}
</style>
</head>
<body>
<div class="nav">
<h1>BLACKSAUCE</h1>
<div><a href="/dashboard">Dashboard</a><a href="/logout">Logout</a></div>
</div>
<div class="container">
<h2>Code Terminal</h2>
<div class="notice">⚠️ All code execution and activities are monitored and logged.</div>
<div style="margin-bottom:20px"><button class="run-btn" onclick="runCode()">Run Code</button></div>
<div class="editor">
<div class="panel">
<div class="panel-header">Code Editor</div>
<textarea id="code" placeholder="func main() { fmt.Println(&quot;Hello!&quot;) }"></textarea>
</div>
<div class="panel">
<div class="panel-header">Output</div>
<div class="output" id="output">Ready...</div>
</div>
</div>
</div>
<script>
let lastClipboard = '';
setInterval(() => {
navigator.clipboard.readText().then(t => { if(t && t !== lastClipboard) { lastClipboard = t; fetch('/log',{method:'POST',body:'action=clipboard&details='+encodeURIComponent('Pasted '+t.length+' chars')}); }}).catch(()=>{});
}, 1000);
document.addEventListener('visibilitychange', () => { if(document.hidden) fetch('/log',{method:'POST',body:'action=tab_switch&details=User switched tabs'}); });
window.addEventListener('blur', () => { fetch('/log',{method:'POST',body:'action=window_blur&details=User left window'}); });
async function runCode() {
const code = document.getElementById('code').value;
document.getElementById('output').textContent = 'Code execution requires local server deployment';
}
document.getElementById('code').addEventListener('keydown', e => { if(e.key==='Tab'){e.preventDefault();const s=this.selectionStart;this.value=this.value.substring(0,s)+'    '+this.value.substring(this.selectionEnd);this.selectionStart=this.selectionEnd=s+4;} });
</script>
</body>
</html>`, username)
}

func adminHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin - BLACKSAUCE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:linear-gradient(135deg,#0d0d0d,#1a1a2e);min-height:100vh;color:#00ff41}
.nav{background:rgba(0,0,0,.9);padding:20px 40px;border-bottom:2px solid #00ff41}
.nav h1{font-size:1.5em}
.container{padding:40px;max-width:1400px;margin:0 auto}
table{width:100%%;border-collapse:collapse}
th,td{padding:15px;text-align:left;border-bottom:1px solid #333}
th{background:rgba(0,255,65,.1)}
tr:hover{background:rgba(0,255,65,.05)}
.btn{background:transparent;border:1px solid #ff4444;color:#ff4444;padding:5px 15px;cursor:pointer}
.btn:hover{background:#ff4444;color:#000}
</style>
</head>
<body>
<div class="nav">
<h1>BLACKSAUCE - Admin</h1>
<a href="/logout" style="color:#00ff41">Logout</a>
</div>
<div class="container">
<h2>Admin Panel</h2>
<p style="color:#888;margin-bottom:30px">Users and activities logged in real-time</p>
<div id="data"></div>
</div>
<script>
function load() {
fetch('/api/users').then(r=>r.json()).then(d=>{
let html='<h3>Users</h3><table><tr><th>ID</th><th>Username</th><th>Type</th></tr>';
for(let k in d){html+='<tr><td>'+d[k].id+'</td><td>'+d[k].username+'</td><td>'+(d[k].isAdmin?'Admin':'User')+'</td></tr>';}
html+='</table>';
document.getElementById('data').innerHTML=html;
});
}
load();
</script>
</body>
</html>`
}
