# Security Setup Guide

## Critical Security Configuration

### 1. Secret Key Setup (REQUIRED)

The Flask secret key is used to sign session cookies. Without a strong secret key, attackers can forge session data.

**Setup Steps:**

1. Generate a secure secret key:
   ```bash
   python generate_secret_key.py
   ```

2. Create a `.env` file in the project root:
   ```bash
   cp .env.example .env
   ```

3. Copy the generated key to your `.env` file:
   ```
   SECRET_KEY=your-generated-key-here
   ```

4. **NEVER commit the `.env` file to version control** - it's already in `.gitignore`

### 2. Environment Variables

Load environment variables before running the application:

**Windows PowerShell:**
```powershell
# Load .env file manually or use:
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}

# Or set directly:
$env:SECRET_KEY="your-key-here"
```

**Linux/Mac:**
```bash
# Load .env file:
export $(cat .env | xargs)

# Or use python-dotenv:
pip install python-dotenv
# Then add to app.py: from dotenv import load_dotenv; load_dotenv()
```

### 3. Production Deployment Checklist

Before deploying to your test server:

- [ ] Generate and set a strong `SECRET_KEY` environment variable
- [ ] Set `FLASK_DEBUG=False` in environment
- [ ] Change default RSCM credentials from admin/admin
- [ ] Run behind nginx with HTTPS/TLS
- [ ] Configure firewall rules to restrict access
- [ ] Review all TODO security items in code
- [ ] Test in isolated environment first

### 4. Security Warnings

The application will display critical warnings if:
- No `SECRET_KEY` is set (uses insecure fallback)
- Other security misconfigurations are detected

**Never ignore these warnings in production!**

### 5. Additional Security Measures (Recommended)

For production deployment, consider implementing:

1. **Authentication**: Add HTTP Basic Auth or Flask-Login
2. **Rate Limiting**: Use Flask-Limiter to prevent abuse
3. **SSH Host Key Verification**: Replace AutoAddPolicy with proper key checking
4. **Input Validation**: Add stricter validation on all user inputs
5. **Audit Logging**: Log all firmware checks and system changes
6. **HTTPS Only**: Force HTTPS, disable HTTP entirely
7. **Credential Management**: Use Azure Key Vault or similar for credentials

## Quick Start (Development)

```bash
# Generate secret key
python generate_secret_key.py

# Create .env file
cp .env.example .env
# Edit .env and add your SECRET_KEY

# Set environment variable (PowerShell)
$env:SECRET_KEY="your-key-here"

# Run application
python app.py
```

## Quick Start (Production)

```bash
# Set environment variables (do NOT use .env file in production)
export SECRET_KEY="your-production-key"
export FLASK_DEBUG=False

# Use production WSGI server (not Flask dev server)
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## Support

For security issues or questions, contact your security team before deployment.
