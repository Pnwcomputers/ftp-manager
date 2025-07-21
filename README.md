# 🛡️ Secure Web Based FTP/Website File Manager

A **production-ready, enterprise-grade** web-based file manager with advanced security features, user role management, and comprehensive threat protection.

![Security Badge](https://img.shields.io/badge/Security-Enterprise%20Grade-green)
![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Maintenance](https://img.shields.io/badge/Maintained-Yes-green)

## ✨ Features

### 🔐 **Security First**
- **Password Hashing** - Bcrypt encryption, no plain-text storage
- **Brute Force Protection** - Account lockout after failed attempts
- **CSRF Protection** - Prevents cross-site request forgery
- **Directory Traversal Prevention** - Enhanced path validation
- **XSS Protection** - Input sanitization and security headers
- **Session Security** - HTTPOnly, Secure, SameSite cookies
- **Activity Logging** - Comprehensive security event tracking
- **Malware Scanning** - Basic signature detection for uploads

### 👥 **User Management**
- **Role-Based Access** - Admin (full access) vs User (read-only)
- **Session Management** - Auto-logout and session regeneration
- **Account Lockout** - Temporary lockout after failed login attempts
- **Secure Authentication** - Enterprise-grade login system

### 📁 **File Operations**
- **Upload Files** - Drag & drop with security validation
- **Download Files** - Secure file serving
- **Create Folders** - Organize your files
- **Delete Files** - Admin-only with protection for system files
- **Drag & Drop Organization** - Move files between folders
- **File Viewer** - View PDFs, text files, and documents in-browser

### 🎯 **Advanced Features**
- **File Type Validation** - Whitelist/blacklist approach
- **Size Limits** - Configurable upload limits
- **Responsive Design** - Works on desktop and mobile
- **Real-time Updates** - AJAX-powered interface
- **Breadcrumb Navigation** - Easy folder navigation
- **Error Handling** - User-friendly error messages

## 🚀 Quick Start

### Prerequisites
- **PHP 7.4+** with standard extensions
- **Web server** (Apache, Nginx, etc.)
- **Write permissions** for the storage directory

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/secure-file-manager.git
   cd secure-file-manager
   ```

2. **Upload files to your web server**
   ```bash
   # Upload both files to your web directory
   cp index.html /var/www/html/
   cp secure-file-manager.php /var/www/html/ftp-manager.php
   ```

3. **Set permissions**
   ```bash
   # Ensure the web server can create the storage directory
   chmod 755 /var/www/html/
   ```

4. **Access the application**
   ```
   https://yourdomain.com/           # Landing page
   https://yourdomain.com/ftp-manager.php  # Direct access to file manager
   ```
   
   **Navigation Flow:**
   - Visit your domain → Professional landing page
   - Click "FTP Login" → Secure file manager login
   - Enter credentials → Full file management interface

5. **Login with default credentials** (⚠️ Change immediately!)
   ```
   Admin: admin / SecureAdmin2024!
   User:  user1 / User2024!
   Guest: guest / Guest2024!
   ```

## 📁 Project Structure

```
secure-file-manager/
├── index.html              # Landing page with navigation
├── secure-file-manager.php # Main file manager application
├── FTP Storage/            # Auto-created storage directory
├── security.log            # Security events log (auto-created)
└── README.md              # This documentation
```

### 🏠 Landing Page (`index.html`)
The landing page provides a professional entry point to your file manager:

**Features:**
- Clean, modern design matching the file manager theme
- Direct navigation to the secure file manager
- Responsive layout for all devices
- Professional branding opportunity

### 🏠 Landing Page (`index.html`)
The landing page provides a professional entry point to your file manager:

**Features:**
- ✅ Clean, modern design matching the file manager theme
- ✅ Direct navigation to the secure file manager
- ✅ Responsive layout for all devices
- ✅ Professional branding opportunity
- ✅ Fast loading with minimal dependencies
- ✅ SEO-friendly structure

**Customization Options:**
```html
<!-- Company Branding -->
<h1>🏢 YourCompany File Portal</h1>

<!-- Custom Navigation -->
<a href="ftp-manager.php" class="nav-link">Access Files</a>
<a href="help.html" class="nav-link">Help</a>
<a href="contact.html" class="nav-link">Support</a>

<!-- Color Scheme -->
<style>
.header {
    background: linear-gradient(135deg, #your-color 0%, #your-color2 100%);
}
</style>
```

**Use Cases:**
- 🏢 **Corporate File Portal** - Professional entry point for employees
- 🎓 **Educational Institutions** - Student/faculty file access
- 👥 **Client Portals** - Secure document sharing with clients
- 🏠 **Personal Cloud** - Family/personal file management
- 💼 **Project Management** - Team file collaboration

## ⚙️ Configuration

### User Management
Edit the `$users` array in the PHP file to add/modify users:

```php
$users = [
    'admin' => [
        'password' => password_hash('YourSecurePassword!', PASSWORD_DEFAULT),
        'role' => 'admin'
    ],
    'john' => [
        'password' => password_hash('JohnPassword123!', PASSWORD_DEFAULT),
        'role' => 'user'
    ]
];
```

### Security Settings
Customize security parameters:

```php
$max_file_size = 10 * 1024 * 1024; // 10MB max file size
$max_login_attempts = 5;            // Failed attempts before lockout
$lockout_duration = 300;            // 5 minutes lockout duration
```

### File Type Restrictions
Modify allowed/blocked file extensions:

```php
$allowed_extensions = [
    'txt', 'pdf', 'jpg', 'png', 'docx', 'xlsx'
    // Add more as needed
];

$blocked_extensions = [
    'php', 'exe', 'bat', 'script'
    // Add dangerous types
];
```

## 🛡️ Security Features

### **Authentication Security**
| Feature | Description |
|---------|-------------|
| Password Hashing | Bcrypt with salt, no reversible encryption |
| Session Security | HTTPOnly, Secure, SameSite cookies |
| Brute Force Protection | Account lockout after 5 failed attempts |
| Session Regeneration | Prevents session fixation attacks |

### **File Upload Security**
| Protection | Implementation |
|------------|----------------|
| File Type Validation | Whitelist + blacklist approach |
| Malware Scanning | Basic signature detection |
| Size Limits | Configurable maximum file size |
| Filename Sanitization | Removes dangerous characters |
| Path Traversal Prevention | Strict path validation |

### **Attack Prevention**
| Attack Type | Protection Method |
|-------------|-------------------|
| CSRF | Token-based validation |
| XSS | Input sanitization + CSP headers |
| Directory Traversal | Enhanced path validation |
| File Inclusion | Strict file type checking |
| Session Hijacking | Secure session configuration |

## 📊 Activity Logging

The system automatically logs all security events to `security.log`:

```
[2024-07-21 14:30:22] IP: 192.168.1.100 | User: admin | Event: LOGIN_SUCCESS | Details: Username: admin
[2024-07-21 14:31:15] IP: 192.168.1.100 | User: admin | Event: FILE_UPLOADED | Details: Filename: document.pdf
[2024-07-21 14:32:01] IP: 10.0.0.50 | User: anonymous | Event: LOGIN_FAILED | Details: Username: admin
```

### Monitored Events
- ✅ Login attempts (success/failure)
- ✅ File operations (upload/download/delete/view)
- ✅ Security violations (CSRF, traversal attempts)
- ✅ Account lockouts
- ✅ System file access attempts

## 🔄 **User Workflow**

### **Complete User Journey:**
1. **🏠 Landing Page** (`index.html`)
   - User visits your domain
   - Sees professional, branded interface
   - Clicks "FTP Login" button

2. **🔐 Authentication** (`secure-file-manager.php`)
   - Secure login form appears
   - User enters credentials
   - System validates and creates secure session

3. **📁 File Management** (Main Interface)
   - Role-based interface loads (Admin/User)
   - File operations available based on permissions
   - Security monitoring active throughout session

4. **🚪 Session End**
   - Manual logout or auto-timeout
   - Secure session cleanup
   - Return to landing page

### **Integration Benefits:**
- **Professional Appearance** - Clean entry point for users
- **Seamless Navigation** - One-click access to file manager
- **Branding Consistency** - Matching design themes
- **Security Separation** - Landing page publicly accessible, file manager secured
- **SEO Optimization** - Landing page can be indexed, file manager remains private

## 🎯 **Deployment Options**

### **Option 1: With Landing Page (Recommended)**
```
your-domain.com/
├── index.html          # Professional landing page
└── ftp-manager.php     # Secure file manager
```
- **Professional appearance** for visitors
- **Clean URL structure** (domain.com → file manager)
- **Easy branding** and customization
- **SEO-friendly** landing page

### **Option 2: Direct Access**
```
your-domain.com/
└── secure-file-manager.php    # Direct file manager access
```
- **Minimal setup** - single file deployment
- **Direct access** to file manager functionality
- **Suitable for** internal/private use

### **Option 3: Subdirectory Setup**
```
your-domain.com/files/
├── index.html              # Landing page
├── manager.php             # File manager
└── storage/               # File storage
```
- **Organized structure** for larger websites
- **Isolated file management** area
- **Custom URLs** and paths

## 🎨 User Interface

### Admin View
- Full file management capabilities
- Upload, delete, create folders
- Drag & drop file organization
- User management access

### User View
- Read-only access
- Download and view files
- Browse folder structure
- No modification capabilities

## 📱 Mobile Support

The interface is fully responsive and optimized for:
- ✅ Desktop computers
- ✅ Tablets
- ✅ Mobile phones
- ✅ Touch interfaces

## 🔧 Troubleshooting

### Common Issues

**"Access denied to this directory"**
- Check file permissions (755 for directories)
- Verify the storage path exists and is writable

**"FTP extension is not enabled"**
- This system doesn't require FTP extensions
- Works with any standard PHP installation

**"Account temporarily locked"**
- Wait 5 minutes after failed login attempts
- Check `security.log` for details

**File upload fails**
- Verify file type is in allowed extensions
- Check file size doesn't exceed limit
- Ensure sufficient disk space

### Security Checklist

- [ ] Changed default passwords
- [ ] Configured user accounts
- [ ] Set appropriate file size limits
- [ ] Reviewed allowed file types
- [ ] Set up log monitoring
- [ ] Configured HTTPS (recommended)
- [ ] Regular security log review

## 🚨 Security Recommendations

### Production Deployment
1. **Change all default passwords immediately**
2. **Enable HTTPS** - Never run over HTTP in production
3. **Monitor security logs** - Set up automated alerts
4. **Regular updates** - Keep PHP and server updated
5. **Backup configuration** - Save user settings securely
6. **Access control** - Limit who can access the application
7. **Regular audits** - Review user accounts and permissions

### Server Security
```apache
# .htaccess recommendations
<Files "security.log">
    Order deny,allow
    Deny from all
</Files>

# Optional: Hide PHP file
<Files "secure-file-manager.php">
    # Add IP restrictions if needed
</Files>
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Security Reports
If you discover a security vulnerability, please send an email to [security@yourdomain.com] instead of opening a public issue.

## 📋 Changelog

### v2.0.0 - Security Enhanced
- ✅ Added comprehensive security features
- ✅ Implemented user role management
- ✅ Added activity logging
- ✅ Enhanced file upload security
- ✅ Added malware scanning
- ✅ Implemented CSRF protection

### v1.0.0 - Initial Release
- ✅ Basic file management
- ✅ Upload/download functionality
- ✅ Simple authentication

## 🏆 Why Choose This File Manager?

| Feature | Basic File Managers | **Secure File Manager** |
|---------|-------------------|------------------------|
| Security | ❌ Basic or none | ✅ Enterprise-grade |
| User Roles | ❌ Single user | ✅ Admin/User roles |
| Activity Logging | ❌ No tracking | ✅ Comprehensive logs |
| Attack Prevention | ❌ Vulnerable | ✅ Multi-layered protection |
| Mobile Support | ❌ Desktop only | ✅ Fully responsive |
| File Viewer | ❌ Download only | ✅ In-browser viewing |
| Malware Protection | ❌ No scanning | ✅ Basic signature detection |

## 💡 Use Cases

- **Small Business File Sharing** - Secure document sharing
- **Personal Cloud Storage** - Private file management
- **Development Teams** - Project file organization
- **Client Portals** - Secure file delivery
- **Educational Institutions** - Student file access
- **Remote Work** - Secure file collaboration

## 📞 Support

- 📖 **Documentation**: Check this README
- 🐛 **Bug Reports**: Open an issue on GitHub
- 💡 **Feature Requests**: Open an issue with [FEATURE] tag
- 🔒 **Security Issues**: Email support@pnwcomputers.com

---

<div align="center">

**Built with ❤️ for security and simplicity**

[⭐ Star this repo](https://github.com/yourusername/secure-file-manager) if you found it helpful!

</div>
