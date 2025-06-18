# Nginx Security WAF - Installation Guide

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

### Step 1: Install Nginx
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Nginx
sudo apt install nginx -y

# Enable Nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

### Step 2: Configure Nginx with WAF Integration

**Important:** We'll configure the existing `nodeApp` file instead of creating a new one.

Edit the existing Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/nodeApp
```

Your configuration should look like this (replace `YOUR_WAF_SERVER_IP` with your actual WAF server IP):
```nginx
# Point "security_auth" at your remote Python WAF
upstream security_auth {
    server YOUR_WAF_SERVER_IP:8080 max_fails=3 fail_timeout=30s;
    # Add backup options if available
    # server YOUR_WAF_SERVER_IP:8001 backup;
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
        proxy_set_header      X-Original-Accept-Language $http_accept_language;
        proxy_set_header      X-Original-Accept-Encoding $http_accept_encoding;

        # Increased timeouts for better reliability
        proxy_connect_timeout 5s;
        proxy_read_timeout    5s;
        proxy_send_timeout    5s;

        # Handle upstream errors better
        proxy_next_upstream error timeout http_500 http_502 http_503 http_504;
    }

    # Temporary bypass location for testing (remove after fixing)
    location /test-bypass {
        proxy_pass              http://localhost:8000;
        proxy_http_version      1.1;
        proxy_set_header        Upgrade          $http_upgrade;
        proxy_set_header        Connection       "upgrade";
        proxy_set_header        Host             $host;
        proxy_cache_bypass      $http_upgrade;
    }

    # All main traffic is authenticated before proxying
    location / {
        # Error handling for auth failures
        error_page 401 = @auth_error;
        error_page 403 = @auth_error;
        error_page 500 = @auth_error;
        error_page 502 = @auth_error;
        error_page 503 = @auth_error;
        error_page 504 = @auth_error;

        auth_request            /auth;
        auth_request_set        $session_id   $upstream_http_x_session_id;
        auth_request_set        $threat_level $upstream_http_x_threat_level;
        auth_request_set        $auth_status  $upstream_status;

        proxy_set_header        X-Session-ID   $session_id;
        proxy_set_header        X-Threat-Level $threat_level;
        proxy_set_header        X-Auth-Status  $auth_status;

        proxy_pass              http://localhost:8000;
        proxy_http_version      1.1;
        proxy_set_header        Upgrade          $http_upgrade;
        proxy_set_header        Connection       "upgrade";
        proxy_set_header        Host             $host;
        proxy_cache_bypass      $http_upgrade;

        # CORS Headers
        add_header 'Access-Control-Allow-Origin'  '*'     always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;
    }

    # Error handling location
    location @auth_error {
        # Log the auth error
        access_log /var/log/nginx/auth_errors.log;

        # Option 1: Return error page
        return 503 "Authentication service temporarily unavailable";

        # Option 2: Bypass authentication temporarily (uncomment if needed)
        # proxy_pass http://localhost:8000;
    }

    # Health check endpoint (bypasses auth)
    location /health {
        proxy_pass http://localhost:8000/health;
    }

    listen 443 ssl;  # managed by Certbot
    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    if ($host = your-domain.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot
    server_name your-domain.com;
    listen 80;
    return 404; # managed by Certbot
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
sqlite3 -header -csv sessions.db "SELECT * FROM sessions;" > sessions.csv
```

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

This project is licensed under Fair Use principles for educational and research purposes. Commercial use requires explicit permission from the development team.

## 🤝 Contributing

Currently, this project is maintained by our internal development team.  For questions or support, please contact the development team.
