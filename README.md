# 🛡️ Secure Web Based FTP File Manager

A web-based file manager with advanced security features, user role management, comprehensive threat protection, and **full mobile optimization**.

![Security Badge](https://img.shields.io/badge/Security-Enterprise%20Grade-green)
![Mobile Ready](https://img.shields.io/badge/Mobile-Optimized-blue)
![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-blue)
![Cross Platform](https://img.shields.io/badge/Platform-Cross%20Device-purple)
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

### 📱 **Mobile-First Design** *(NEW)*
- **Touch-Optimized Interface** - Native mobile experience
- **Cross-Device Drag & Drop** - Works on phones, tablets, and desktop
- **Mobile File Upload** - Native file picker integration
- **Touch Gestures** - Pinch-to-zoom, swipe navigation
- **Responsive Layout** - Adaptive design for all screen sizes
- **Full-Screen Viewers** - Immersive file viewing on mobile
- **Touch Feedback** - Visual response to touch interactions

### 👥 **User Management**
- **Role-Based Access** - Admin (full access) vs User (read-only)
- **Session Management** - Auto-logout and session regeneration
- **Account Lockout** - Temporary lockout after failed login attempts
- **Secure Authentication** - Enterprise-grade login system

### 📁 **Enhanced File Operations** *(UPDATED)*
- **Universal Drag & Drop** - Works on desktop AND mobile devices
- **Touch-Based File Movement** - Long press and drag on mobile
- **Smart Upload System** - Multiple upload methods for all devices
- **Advanced File Viewer** - Enhanced viewing with mobile optimizations
- **Cross-Platform Organization** - Seamless file management everywhere
- **Download & View** - Secure file serving with mobile optimization

### 🎯 **Advanced Mobile Features** *(NEW)*
- **Pinch-to-Zoom Images** - Native zoom and pan for photos
- **Touch Scrolling** - Smooth momentum scrolling on mobile
- **Full-Screen Modals** - Immersive viewing experience
- **Mobile Drag Feedback** - Visual indicators during touch drag
- **Native File Picker** - Access device photos, documents, etc.
- **Gesture Support** - Intuitive touch interactions
- **Background Scroll Lock** - Prevents interference during viewing

## 🚀 What's New in v3.0

### 📱 **Complete Mobile Overhaul**
We've completely reimagined the mobile experience:

- **🎯 Touch-First Design**: Every interface element optimized for touch
- **📱 Native Mobile Interactions**: Feels like a native mobile app
- **🔄 Cross-Device Sync**: Seamless experience across all devices
- **⚡ Performance Optimized**: Fast, responsive on mobile networks

### 🎮 **Universal Drag & Drop** *(Major Feature)*
Revolutionary drag and drop that works everywhere:

```javascript
// Desktop: Standard mouse drag & drop
// Mobile: Touch-based long press and drag
// Tablet: Hybrid touch and mouse support
// All Devices: Visual feedback and smart detection
```

**Mobile Drag & Drop Features:**
- **Long Press Detection** - Hold file for 200ms to start drag
- **Visual Feedback** - Floating drag indicator
- **Smart Drop Zones** - Folders highlight during drag
- **Touch Optimization** - Designed for finger interaction

### 🖼️ **Enhanced File Viewing** *(Major Update)*
Next-generation file viewing experience:

**Mobile Optimizations:**
- **Full-Screen Modals** - Immersive viewing on mobile
- **Pinch-to-Zoom** - Natural zoom gestures for images
- **Touch Scrolling** - Smooth scrolling with momentum
- **Gesture Navigation** - Intuitive touch controls

**Cross-Platform Support:**
- **Text Files** - Syntax highlighting with mobile scrolling
- **Images** - Zoom, pan, and gesture support
- **PDFs** - Optimized viewing with mobile fallbacks
- **Documents** - Enhanced preview capabilities

## 🎯 **Device Compatibility**

| Feature | 📱 Mobile | 📱 Tablet | 🖥️ Desktop |
|---------|----------|----------|-----------|
| File Upload | ✅ Native Picker | ✅ Drag/Touch | ✅ Drag & Drop |
| File Movement | ✅ Touch Drag | ✅ Touch/Mouse | ✅ Mouse Drag |
| File Viewing | ✅ Full Screen | ✅ Responsive | ✅ Modal Window |
| Image Zoom | ✅ Pinch-to-Zoom | ✅ Touch Gestures | ✅ Mouse Controls |
| Navigation | ✅ Touch Optimized | ✅ Hybrid | ✅ Traditional |
| Upload Progress | ✅ Toast Messages | ✅ Visual Feedback | ✅ Status Updates |

## 🚀 Quick Start

### Prerequisites
- **PHP 7.4+** with standard extensions
- **Web server** (Apache, Nginx, etc.)
- **Write permissions** for the storage directory
- **Modern browser** with touch support (for mobile features)

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
   https://yourdomain.com/           # Professional landing page
   https://yourdomain.com/ftp-manager.php  # Direct access to file manager
   ```

5. **Login with default credentials** (⚠️ Change immediately!)
   ```
   Admin: admin / SecureAdmin2024!
   User:  user1 / User2024!
   Guest: guest / Guest2024!
   ```

### 📱 **Mobile Setup Notes**
- **HTTPS Required** - Mobile features require secure connections
- **Touch Devices** - Optimized for iOS and Android
- **PWA Ready** - Can be installed as a web app on mobile devices

## 📁 Project Structure

```
secure-file-manager/
├── index.html              # Professional landing page
├── secure-file-manager.php # Main file manager (mobile-optimized)
├── FTP Storage/            # Auto-created storage directory
├── security.log            # Security events log (auto-created)
└── README.md              # This documentation
```

## 🎨 **Mobile User Interface**

### 📱 **Mobile Experience**
- **Touch-Optimized Buttons** - 44px+ touch targets
- **Swipe Navigation** - Intuitive folder browsing
- **Pull-to-Refresh** - Standard mobile interaction
- **Native Scrolling** - Smooth momentum scrolling
- **Visual Feedback** - Immediate response to touches

### 🖥️ **Desktop Experience**
- **Traditional Drag & Drop** - Standard mouse interactions
- **Keyboard Shortcuts** - Power user features
- **Context Menus** - Right-click functionality
- **Multi-Window Support** - Enhanced workflow

### 📱 **Tablet Experience**
- **Hybrid Interface** - Best of both mobile and desktop
- **Touch + Mouse** - Multiple interaction methods
- **Adaptive Layout** - Optimizes for orientation changes
- **Enhanced Multitasking** - Split-screen friendly

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

### Mobile-Specific Settings
```php
// Touch interaction settings
$touch_hold_duration = 200;    // Milliseconds for drag start
$touch_sensitivity = 10;       // Pixels for gesture detection
$mobile_max_file_size = 5 * 1024 * 1024; // 5MB for mobile uploads
```

### Security Settings
Customize security parameters:

```php
$max_file_size = 10 * 1024 * 1024; // 10MB max file size
$max_login_attempts = 5;            // Failed attempts before lockout
$lockout_duration = 300;            // 5 minutes lockout duration
```

## 🛡️ Security Features

### **Authentication Security**
| Feature | Description |
|---------|-------------|
| Password Hashing | Bcrypt with salt, no reversible encryption |
| Session Security | HTTPOnly, Secure, SameSite cookies |
| Brute Force Protection | Account lockout after 5 failed attempts |
| Session Regeneration | Prevents session fixation attacks |
| Mobile CSRF Protection | Touch-aware CSRF validation |

### **Mobile Security Enhancements** *(NEW)*
| Protection | Mobile Implementation |
|------------|----------------------|
| Touch Event Validation | Prevents malicious touch injection |
| Gesture Authentication | Secure touch gesture recognition |
| Mobile Session Security | Optimized for mobile browsers |
| Device Fingerprinting | Enhanced mobile device tracking |

## 📊 Activity Logging

The system automatically logs all security events including mobile interactions:

```
[2024-07-21 14:30:22] IP: 192.168.1.100 | User: admin | Event: LOGIN_SUCCESS | Details: Username: admin
[2024-07-21 14:31:15] IP: 192.168.1.100 | User: admin | Event: MOBILE_FILE_UPLOADED | Details: via touch interface
[2024-07-21 14:32:01] IP: 10.0.0.50 | User: admin | Event: TOUCH_DRAG_OPERATION | Details: File moved via mobile
```

### New Mobile Events *(v3.0)*
- ✅ Touch-based file operations
- ✅ Mobile drag and drop activities
- ✅ Gesture interactions
- ✅ Mobile-specific security events

## 🔄 **Enhanced User Workflow**

### **Mobile User Journey:**
1. **📱 Mobile Access** - Visit on phone/tablet
2. **🔐 Touch Login** - Optimized login form
3. **📁 Touch Navigation** - Swipe and tap to browse
4. **📤 Native Upload** - Use device camera/files
5. **🎯 Drag & Drop** - Move files with touch
6. **👀 Full-Screen Viewing** - Immersive file preview

### **Desktop User Journey:**
1. **🖥️ Professional Interface** - Full desktop experience
2. **🖱️ Traditional Controls** - Mouse and keyboard
3. **📁 Advanced Features** - Power user capabilities
4. **⚡ Enhanced Productivity** - Multiple file operations

## 📱 **Mobile Feature Showcase**

### 🎮 **Touch Drag & Drop**
```javascript
// How mobile drag works:
1. Long press file (200ms)
2. Visual feedback appears
3. Drag to target folder
4. Drop zone highlights
5. Release to move file
```

### 📷 **Mobile File Upload**
```javascript
// Upload options on mobile:
- 📷 Camera (take photo)
- 🖼️ Photo Library
- 📁 Files App
- ☁️ Cloud Storage
- 📋 Clipboard
```

### 🔍 **Mobile File Viewing**
```javascript
// Enhanced viewing features:
- 📱 Full-screen modals
- 🔍 Pinch-to-zoom images
- 📜 Touch scrolling
- 🎯 Gesture navigation
- ⚡ Instant preview
```

## 🎯 **Browser Compatibility**

| Browser | 📱 Mobile | 🖥️ Desktop | Features |
|---------|----------|-----------|----------|
| **Chrome** | ✅ Full Support | ✅ Full Support | All features |
| **Safari** | ✅ Full Support | ✅ Full Support | Touch optimized |
| **Firefox** | ✅ Full Support | ✅ Full Support | All features |
| **Edge** | ✅ Full Support | ✅ Full Support | All features |
| **Samsung Internet** | ✅ Optimized | N/A | Mobile-first |

## 🔧 Troubleshooting

### Mobile-Specific Issues *(NEW)*

**Touch drag not working**
- Ensure HTTPS is enabled
- Check browser touch support
- Verify JavaScript is enabled

**File upload fails on mobile**
- Check mobile data/WiFi connection
- Verify file size limits
- Ensure camera permissions granted

**Images won't zoom on mobile**
- Clear browser cache
- Check touch screen calibration
- Verify device orientation lock

### Common Issues

**"Access denied to this directory"**
- Check file permissions (755 for directories)
- Verify the storage path exists and is writable

**Account temporarily locked**
- Wait 5 minutes after failed login attempts
- Check `security.log` for details

## 🚨 Security Recommendations

### Mobile Security *(NEW)*
1. **Enable HTTPS** - Essential for mobile security
2. **Mobile Device Management** - Control access by device
3. **Touch Security** - Monitor touch-based interactions
4. **Mobile Session Timeouts** - Shorter timeouts for mobile

### Production Deployment
1. **Change all default passwords immediately**
2. **Enable HTTPS** - Required for mobile features
3. **Monitor security logs** - Include mobile events
4. **Regular updates** - Keep PHP and server updated
5. **Mobile testing** - Test on actual devices
6. **Cross-browser validation** - Ensure compatibility

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📋 Changelog

### v3.0.0 - Mobile Revolution *(LATEST)*
- ✅ **Complete mobile optimization** - Touch-first design
- ✅ **Universal drag & drop** - Works on all devices
- ✅ **Enhanced file viewing** - Full-screen, zoom, gestures
- ✅ **Touch interaction system** - Native mobile feel
- ✅ **Cross-device compatibility** - Seamless experience
- ✅ **Mobile security enhancements** - Touch-aware protection
- ✅ **Responsive design overhaul** - Adaptive layouts
- ✅ **Performance optimizations** - Faster mobile loading

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

| Feature | Basic File Managers | Other Solutions | **Secure File Manager v3.0** |
|---------|--------------------|-----------------|-----------------------------|
| Mobile Support | ❌ Desktop only | ⚠️ Basic responsive | ✅ **Mobile-first design** |
| Drag & Drop | ❌ Desktop only | ❌ Desktop only | ✅ **Universal (all devices)** |
| Touch Gestures | ❌ None | ❌ Limited | ✅ **Full gesture support** |
| Security | ❌ Basic or none | ⚠️ Standard | ✅ **Enterprise-grade** |
| File Viewing | ❌ Download only | ⚠️ Basic preview | ✅ **Enhanced viewer** |
| Cross-Platform | ❌ Limited | ⚠️ Partial | ✅ **Complete compatibility** |
| User Experience | ❌ Poor mobile UX | ⚠️ Inconsistent | ✅ **Seamless everywhere** |

## 💡 Use Cases

### 📱 **Mobile-First Scenarios** *(NEW)*
- **Field Work** - Upload photos/documents from job sites
- **Mobile Photography** - Organize and share photos instantly
- **Remote Teams** - Access files from any mobile device
- **Travel & Events** - Upload documents while on the go
- **Real Estate** - Share property photos from mobile
- **Education** - Students submit assignments from phones

### 🏢 **Traditional Use Cases**
- **Small Business File Sharing** - Secure document sharing
- **Personal Cloud Storage** - Private file management
- **Development Teams** - Project file organization
- **Client Portals** - Secure file delivery
- **Educational Institutions** - Student file access

## 📞 Support

- 📖 **Documentation**: Check this README
- 🐛 **Bug Reports**: Open an issue on GitHub
- 💡 **Feature Requests**: Open an issue with [FEATURE] tag
- 📱 **Mobile Issues**: Include device/browser details
- 🔒 **Security Issues**: Email support@pnwcomputer.com

---

<div align="center">

**🚀 Now with Universal Mobile Support!**

**Built with ❤️ for security, simplicity, and cross-device compatibility**

[⭐ Star this repo](https://github.com/yourusername/secure-file-manager) if you found it helpful!

*Works seamlessly on phones, tablets, and desktop computers*

</div>
