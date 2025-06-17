# Session Intelligence + Custom LLM python WAF - Installation Guide (Apache 2.0)

🏆 Global-first Open Source: First Python-based WAF with Custom RL-LM Session Intelligence, Apache 2.0 Licensed



Can be used as ADD ON to your existing WAF by following below instructions.(Just use our session intelligence and AI custom LLM.)


You can use any LLM (Qwen tested) , pl get in touch for  RL trained  custom LLM to your needs/ implementation consutling


A Python-based Web Application Firewall (WAF) that integrates with Nginx using `auth_request` module to provide real-time threat detection and blocking.

## 🏗️ Architecture Overview

```
Client Request → Nginx (Client) → Python WAF (Server) → Node.js App (Client)
```

## 📋 Prerequisites

You need **2 machines**:
1. **Server Machine**: Runs the Python WAF
2. **Client Machine**: Runs Nginx + Your Application

**Requirements:**
- Python 3.10 or higher
- Ubuntu/Debian-based systems recommended

## 🖥️ Server Machine Setup (Python WAF)

### Step 1: Install Python 3.10 and Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install -y software-properties-common

# Add deadsnakes PPA for Python 3.10
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update

# Install Python 3.10 and required packages
sudo apt install -y python3.10 python3.10-venv python3.10-distutils git screen sqlite3

# Install pip for Python 3.10
curl -sS https://bootstrap.pypa.io/get-pip.py | sudo python3.10
```

### Step 2: Verify Python and SQLite Installation
```bash
# Check if Python 3.10 is installed
python3.10 --version

# Should output: Python 3.10.x

# Verify SQLite3 installation
sqlite3 --version

# Should output: 3.x.x (version number)
```

### Step 3: Clone and Setup WAF
```bash
# Clone the repository
git clone <your-repo-url>
cd nginx_security_python_2

# Create virtual environment with Python 3.10
python3.10 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install required packages from requirements.txt
pip install -r requirements.txt

# Make run script executable
chmod +x run.sh
```

### Step 4: Configure Firewall
```bash
# Allow WAF port (8080)
sudo ufw allow 8080/tcp
sudo ufw reload
```

### Step 5: Start WAF Service Using Screen (Recommended)
```bash
# Start WAF in a screen session (stays running after logout)
screen -S nginx-waf

# Inside the screen session, activate venv and start WAF
source venv/bin/activate
python3 main.py remote-debug

# Detach from screen (Ctrl+A, then D)
# WAF will keep running in background
```

### Step 6: Managing WAF Service
```bash
# To reconnect to the WAF screen session
screen -r nginx-waf

# To stop the WAF (inside screen session)
# Press Ctrl+C

# To list all screen sessions
screen -ls

# Alternative: Run directly (will stop when terminal closes)
source venv/bin/activate
./run.sh
```

### Step 5: Verify WAF is Running
```bash
# Check if service is running
sudo ss -tlnp | grep :8080

# Test health endpoint
curl http://localhost:8080/health

# Test auth endpoint
curl -H "X-Original-URI: /" http://localhost:8080/auth
```

**Expected Response:**
```json
{"status":"healthy","timestamp":...,"waf":"active","sessions":"active"}
```

---

## 🌐 Client Machine Setup (Nginx + Application)

### Step 1: Existing Nginx(ASSUMES YOU HAVE A WORKING WEB APPLICAION THAT NEEDS PROTECTION AND USES NGINX)


### Step 2: Configure Nginx with WAF Integration

**Important:** We'll configure the existing nginx  `config` file (which we have called nodeApp) instead of creating a new one.

Edit the existing Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/nodeApp
```

Your configuration should look like this (replace `YOUR_WAF_SERVER_IP` with your actual WAF server IP):
```nginx
# Point "security_auth" at your remote Python WAF
upstream security_auth {
    server YOUR_WAF_SERVER_IP:8080 max_fails=3 fail_timeout=30s;
}

server {
    server_name your-domain.com;
    
    # Add more detailed logging for debugging
    access_log /var/log/nginx/waf_access.log;
    error_log /var/log/nginx/waf_error.log debug;
    
    # Internal auth endpoint, forwarded to remote WAF
    location = /auth {
        internal;
        proxy_pass            http://security_auth/auth;
        proxy_pass_request_body off;
        proxy_set_header      Content-Length "";
        proxy_set_header      X-Original-URI          $request_uri;
        proxy_set_header      X-Original-Method       $request_method;
        proxy_set_header      X-Original-Remote-Addr  $remote_addr;
        proxy_set_header      X-Original-User-Agent   $http_user_agent;
        proxy_set_header      X-Original-Referer      $http_referer;
        proxy_set_header      X-Original-Cookie       $http_cookie;
        proxy_set_header      X-Original-Host         $host;
        proxy_connect_timeout 5s;
        proxy_read_timeout    5s;
    }
    
    # Main application (protected by WAF)
    location / {
        auth_request            /auth;
        auth_request_set        $session_id   $upstream_http_x_session_id;
        auth_request_set        $threat_level $upstream_http_x_threat_level;
        
        # Your application backend
        proxy_pass              http://localhost:8000;  # Change to your app port
        proxy_set_header        Host             $host;
        proxy_set_header        X-Real-IP        $remote_addr;
        proxy_set_header        X-Session-ID     $session_id;
        proxy_set_header        X-Threat-Level   $threat_level;
        
        # Error handling for auth failures
        error_page 401 403 500 502 503 504 = @auth_error;
    }
    
    # Error handling location
    location @auth_error {
        return 503 "Authentication service temporarily unavailable";
    }
    
    # Health check (bypasses auth)
    location /health {
        proxy_pass http://localhost:8000/health;
    }
    
    listen 80;
    # Add SSL configuration if needed
}
```

### Step 3: Enable Site and Test Configuration
```bash
# The nodeApp file should already be enabled, but verify
sudo ln -sf /etc/nginx/sites-available/nodeApp /etc/nginx/sites-enabled/

# Test Nginx configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### Step 4: Configure SSL (Optional but Recommended)
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo systemctl enable certbot.timer
```

---

## 🧪 Testing the WAF

### Test 1: Normal Request (Should Work)
```bash
curl https://your-domain.com/
```
**Expected:** `200 OK` - Page loads normally

### Test 2: XSS Attack (Should Block)
```bash
curl "https://your-domain.com/?q=<script>alert('xss')</script>"
```
**Expected:** `503 Service Temporarily Unavailable`

### Test 3: SQL Injection (Should Block)
```bash
curl "https://your-domain.com/?id=1' OR '1'='1"
```
**Expected:** `503 Service Temporarily Unavailable`

### Test 4: Scanner Detection (Should Block)
```bash
curl -H "User-Agent: sqlmap/1.0" https://your-domain.com/
```
**Expected:** `503 Service Temporarily Unavailable`

### Test 5: Direct WAF Test
```bash
# Test WAF directly (replace with your WAF server IP)
curl -H "X-Original-URI: /?q=<script>test</script>" \
     -H "X-Original-Method: GET" \
     http://YOUR_WAF_SERVER_IP:8080/auth
```
**Expected:** `WAF: XSS Attack; XSS Attack`

---

## 🔧 Configuration

### WAF Configuration
Edit `config.py` on the server machine:
```python
@dataclass
class Config:
    port: str = "8080"          # WAF port
    debug: bool = False         # Set to True for debugging
    auth_timeout: timedelta = timedelta(seconds=2)
```

### Security Rules
The WAF includes built-in rules for:
- ✅ XSS Attack Detection
- ✅ SQL Injection Prevention
- ✅ Path Traversal Blocking
- ✅ Scanner Detection
- ✅ Command Injection Prevention

### Session Data Export
```bash
# Export session data to CSV
sqlite3 -header -csv sessions.db "SELECT * FROM sessions;" > sample_session.csv
```
After exporting the file (hardcoded sample_session.csv), you can directly call quick_session_scan.py (from custom_llm folder in this repo) to get LLM analysis of the results

---

## 📊 Monitoring and Logs

### WAF Server Logs
```bash
# View WAF logs
journalctl -u nginx-waf -f

# Check service status
sudo systemctl status nginx-waf
```

### Client Nginx Logs
```bash
# Error logs
sudo tail -f /var/log/nginx/error.log

# Access logs
sudo tail -f /var/log/nginx/access.log
```

---

## 🛠️ Troubleshooting

### Common Issues

1. **503 Service Temporarily Unavailable**
   ```bash
   # Check if WAF server is running
   curl http://YOUR_WAF_SERVER_IP:8080/health
   
   # Check firewall
   sudo ufw status
   
   # Reconnect to screen session
   screen -r nginx-waf
   ```

2. **ModuleNotFoundError: No module named 'sanic'**
   ```bash
   # Make sure virtual environment is activated
   source venv/bin/activate
   
   # Install requirements
   pip install -r requirements.txt
   ```

3. **Virtual environment creation fails**
   ```bash
   # Install missing venv package
   sudo apt install python3.10-venv
   
   # Recreate virtual environment
   python3.10 -m venv venv
   ```

4. **Connection Refused**
   ```bash
   # Check WAF process
   sudo ss -tlnp | grep :8080
   
   # Check network connectivity
   telnet YOUR_WAF_SERVER_IP 8080
   ```

### Screen Session Management
```bash
# List all screen sessions
screen -ls

# Create new screen session
screen -S nginx-waf

# Reconnect to existing session
screen -r nginx-waf

# Detach from screen (inside session)
# Press: Ctrl+A, then D

# Kill a screen session
screen -X -S nginx-waf quit
```

### Getting Help
- Check logs on both machines
- Verify network connectivity between servers
- Test WAF endpoints directly
- Ensure proper firewall configuration

---

## 📝 License

Commercial use allowed under Apache 2.0 license. We welcome you use and update it as per your requriements
## 🤝 Contributing

Currently, this project is maintained by our internal development team.For questions or support, please contact the development team.
