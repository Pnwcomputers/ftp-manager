<?php
/**
 * Mobile-Friendly Secure File Manager with Enhanced Security Features
 * Protections against: Directory traversal, CSRF, brute force, malicious uploads, etc.
 * Optimized for mobile devices, tablets, and desktop
 */

// Security Configuration
ini_set('display_errors', 0); // Hide errors in production
error_reporting(0); // Disable error reporting to prevent info disclosure

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
// Updated CSP to allow iframe self-embedding for PDF viewing
header('Content-Security-Policy: default-src \'self\'; style-src \'self\' \'unsafe-inline\'; script-src \'self\' \'unsafe-inline\'; frame-src \'self\';');

// File and directory configuration
$base_directory = __DIR__ . '/FTP Storage';
$max_file_size = 10 * 1024 * 1024; // 10MB max file size
$max_login_attempts = 5; // Max login attempts before lockout
$lockout_duration = 300; // 5 minutes lockout

// Create the FTP Storage directory if it doesn't exist
if (!is_dir($base_directory)) {
    mkdir($base_directory, 0755, true);
}

// Allowed file extensions (whitelist approach)
$allowed_extensions = [
    // Text files
    'txt', 'md', 'log', 'csv', 'json', 'css', 'html', 'htm',
    // Documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    // Images
    'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp',
    // Archives
    'zip', 'rar', '7z', 'tar', 'gz'
];

// Dangerous file extensions to absolutely block
$blocked_extensions = [
    'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'bat', 'cmd', 'com', 'scr',
    'vbs', 'js', 'jar', 'pl', 'py', 'rb', 'sh', 'asp', 'aspx', 'jsp'
];

// User credentials with hashed passwords
$users = [
    'admin' => [
        'password' => password_hash('SecureAdmin2024!', PASSWORD_DEFAULT),
        'role' => 'admin',
        'last_login' => null,
        'failed_attempts' => 0,
        'locked_until' => null
    ],
    'user1' => [
        'password' => password_hash('User2024!', PASSWORD_DEFAULT),
        'role' => 'user',
        'last_login' => null,
        'failed_attempts' => 0,
        'locked_until' => null
    ],
    'guest' => [
        'password' => password_hash('Guest2024!', PASSWORD_DEFAULT),
        'role' => 'user',
        'last_login' => null,
        'failed_attempts' => 0,
        'locked_until' => null
    ]
];

// Security functions
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function getClientIP() {
    $ip_headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    
    foreach ($ip_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = explode(',', $_SERVER[$header])[0];
            if (filter_var(trim($ip), FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return trim($ip);
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function logSecurityEvent($event, $details = '') {
    $log_file = __DIR__ . '/security.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = getClientIP();
    $user = $_SESSION['username'] ?? 'anonymous';
    $log_entry = "[$timestamp] IP: $ip | User: $user | Event: $event | Details: $details\n";
    
    // Append to log file (create if doesn't exist)
    file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
}

function isAccountLocked($username) {
    global $users;
    if (!isset($users[$username])) return false;
    
    $locked_until = $users[$username]['locked_until'] ?? null;
    if ($locked_until && time() < $locked_until) {
        return true;
    }
    
    // Reset lock if time has passed
    if ($locked_until && time() >= $locked_until) {
        $users[$username]['locked_until'] = null;
        $users[$username]['failed_attempts'] = 0;
    }
    
    return false;
}

function incrementFailedAttempt($username) {
    global $users, $max_login_attempts, $lockout_duration;
    
    if (!isset($users[$username])) return;
    
    $users[$username]['failed_attempts'] = ($users[$username]['failed_attempts'] ?? 0) + 1;
    
    if ($users[$username]['failed_attempts'] >= $max_login_attempts) {
        $users[$username]['locked_until'] = time() + $lockout_duration;
        logSecurityEvent('ACCOUNT_LOCKED', "Username: $username after $max_login_attempts failed attempts");
    }
}

function resetFailedAttempts($username) {
    global $users;
    if (isset($users[$username])) {
        $users[$username]['failed_attempts'] = 0;
        $users[$username]['locked_until'] = null;
    }
}

function sanitizeFilename($filename) {
    // Remove any path traversal attempts and dangerous characters
    $filename = basename($filename);
    $filename = preg_replace('/[^a-zA-Z0-9\-_\.]/', '_', $filename);
    $filename = preg_replace('/\.+/', '.', $filename); // Prevent multiple dots
    return $filename;
}

function isAllowedFileType($filename) {
    global $allowed_extensions, $blocked_extensions;
    
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    // Check if extension is explicitly blocked
    if (in_array($extension, $blocked_extensions)) {
        return false;
    }
    
    // Check if extension is in allowed list
    return in_array($extension, $allowed_extensions);
}

function scanFileForThreats($file_path) {
    // Basic malware signature detection
    $malware_signatures = [
        '<?php', '<?=', '<script', 'eval(', 'base64_decode', 'shell_exec',
        'system(', 'exec(', 'passthru(', 'file_get_contents(', 'curl_exec'
    ];
    
    $content = file_get_contents($file_path, false, null, 0, 8192); // Read first 8KB
    
    foreach ($malware_signatures as $signature) {
        if (stripos($content, $signature) !== false) {
            return "Potential malicious content detected: $signature";
        }
    }
    
    return null; // No threats detected
}

// Session security
session_start([
    'cookie_lifetime' => 3600, // 1 hour
    'cookie_secure' => isset($_SERVER['HTTPS']),
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true
]);

// Regenerate session ID periodically
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} else if (time() - $_SESSION['created'] > 1800) { // 30 minutes
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}

// Handle logout
if (isset($_GET['logout'])) {
    logSecurityEvent('LOGOUT', 'User logged out');
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Authentication
if (!isset($_SESSION['authenticated'])) {
    if (isset($_POST['username']) && isset($_POST['password']) && isset($_POST['csrf_token'])) {
        
        if (!validateCSRFToken($_POST['csrf_token'])) {
            logSecurityEvent('CSRF_ATTACK', 'Invalid CSRF token on login');
            $error = "Security error. Please try again.";
        } else {
            $username = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
            $password = $_POST['password'];
            
            if (isAccountLocked($username)) {
                logSecurityEvent('LOGIN_BLOCKED', "Attempted login to locked account: $username");
                $error = "Account temporarily locked. Please try again later.";
            } else if (isset($users[$username]) && password_verify($password, $users[$username]['password'])) {
                resetFailedAttempts($username);
                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $username;
                $_SESSION['role'] = $users[$username]['role'];
                $_SESSION['login_time'] = time();
                
                logSecurityEvent('LOGIN_SUCCESS', "Username: $username");
                
                // Regenerate session ID on successful login
                session_regenerate_id(true);
                
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            } else {
                incrementFailedAttempt($username);
                logSecurityEvent('LOGIN_FAILED', "Username: $username");
                $error = "Invalid username or password";
                
                // Add small delay to slow down brute force
                sleep(2);
            }
        }
    }
    
    if (!isset($_SESSION['authenticated'])) {
        $csrf_token = generateCSRFToken();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure File Manager Login</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
            <style>
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                    max-width: 400px; 
                    margin: 50px auto; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #2c5530 0%, #1e3a21 100%);
                    min-height: 100vh;
                    box-sizing: border-box;
                }
                .login-box { 
                    background: white; 
                    padding: 2rem; 
                    border-radius: 16px; 
                    box-shadow: 0 20px 40px rgba(0,0,0,0.3); 
                }
                input { 
                    width: 100%; 
                    padding: 16px; 
                    margin: 12px 0; 
                    box-sizing: border-box; 
                    border: 2px solid #e1e5e9; 
                    border-radius: 8px; 
                    font-size: 16px; /* Prevents zoom on iOS */
                    -webkit-appearance: none;
                    appearance: none;
                }
                input:focus {
                    border-color: #2c5530;
                    outline: none;
                    box-shadow: 0 0 0 3px rgba(44, 85, 48, 0.1);
                }
                button { 
                    background: #2c5530; 
                    color: white; 
                    padding: 16px 24px; 
                    border: none; 
                    cursor: pointer; 
                    width: 100%; 
                    border-radius: 8px; 
                    font-size: 16px;
                    font-weight: 600;
                    transition: all 0.2s;
                    -webkit-appearance: none;
                    appearance: none;
                    min-height: 50px; /* Touch target */
                }
                button:active { 
                    background: #1e3a21; 
                    transform: scale(0.98);
                }
                .error { 
                    color: #dc2626; 
                    margin: 15px 0; 
                    padding: 12px; 
                    background: #fee2e2; 
                    border-radius: 8px; 
                    border: 1px solid #fecaca;
                }
                h2 { 
                    text-align: center; 
                    color: #333; 
                    margin-bottom: 1.5rem; 
                    font-size: 1.5rem;
                }
                .security-notice {
                    background: #f0fdf4;
                    border: 1px solid #bbf7d0;
                    color: #166534;
                    padding: 12px;
                    border-radius: 8px;
                    margin-top: 1rem;
                    font-size: 13px;
                    line-height: 1.4;
                }
                .demo-accounts {
                    background: #f8fafc;
                    padding: 12px;
                    border-radius: 8px;
                    margin-top: 1rem;
                    font-size: 12px;
                    color: #64748b;
                    line-height: 1.4;
                }
                
                @media (max-width: 480px) {
                    body {
                        margin: 20px auto;
                        padding: 15px;
                    }
                    .login-box {
                        padding: 1.5rem;
                    }
                    h2 {
                        font-size: 1.3rem;
                    }
                }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>🔐 PNW Computer Admin</h2>
                <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="text" name="username" placeholder="Username" required autofocus autocomplete="username">
                    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                    <button type="submit">Access File Manager</button>
                </form>
                <div class="security-notice">
                    🛡️ <strong>Security Features Active:</strong><br>
                    • Account lockout after failed attempts<br>
                    • CSRF protection • Secure sessions<br>
                    • File type validation • Activity logging
                </div>
                <div class="demo-accounts">
                    <strong>Demo Accounts:</strong><br>
                    Admin: admin / SecureAdmin2024!<br>
                    User: user1 / User2024!<br>
                    Guest: guest / Guest2024!
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Helper functions
function formatBytes($size) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $unit = 0;
    while ($size >= 1024 && $unit < count($units) - 1) {
        $size /= 1024;
        $unit++;
    }
    return round($size, 2) . ' ' . $units[$unit];
}

function getFileIcon($filename) {
    if (is_dir($filename)) return '📁';
    
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    switch ($extension) {
        case 'html': case 'htm': return '🌐';
        case 'css': return '🎨';
        case 'js': return '⚡';
        case 'php': return '🐘';
        case 'txt': case 'md': return '📝';
        case 'jpg': case 'jpeg': case 'png': case 'gif': case 'svg': case 'webp': return '🖼️';
        case 'pdf': return '📄';
        case 'zip': case 'rar': case '7z': case 'tar': case 'gz': return '📦';
        case 'docx': case 'doc': return '📄';
        case 'xlsx': case 'xls': return '📊';
        case 'pptx': case 'ppt': return '📊';
        default: return '📄';
    }
}

function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function isViewableFile($filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $viewable_extensions = [
        // Text files (safe to view)
        'txt', 'md', 'log', 'csv', 'json', 'html', 'css',
        // Documents
        'pdf',
        // Images
        'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'
    ];
    return in_array($extension, $viewable_extensions);
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    // CSRF protection for state-changing operations
    $csrf_protected_actions = ['upload', 'delete', 'create_folder', 'move'];
    if (in_array($_GET['action'], $csrf_protected_actions)) {
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            logSecurityEvent('CSRF_ATTACK', 'Invalid CSRF token for action: ' . $_GET['action']);
            http_response_code(403);
            echo json_encode(['error' => 'Security error']);
            exit;
        }
    }
    
    header('Content-Type: application/json');
    
    switch ($_GET['action']) {
        case 'list':
            $path = $_GET['path'] ?? $base_directory;
            
            // Security: prevent directory traversal
            $real_path = realpath($path);
            $real_base = realpath($base_directory);
            
            if (!$real_path || strpos($real_path, $real_base) !== 0) {
                logSecurityEvent('DIRECTORY_TRAVERSAL', "Attempted access to: $path");
                echo json_encode(['error' => 'Access denied']);
                exit;
            }
            
            if (!is_dir($real_path)) {
                echo json_encode(['error' => 'Directory does not exist']);
                exit;
            }
            
            $files = [];
            $items = scandir($real_path);
            
            foreach ($items as $item) {
                if ($item == '.' || $item == '..') continue;
                
                $item_path = $real_path . DIRECTORY_SEPARATOR . $item;
                
                // Skip hidden files, this script, and security logs
                if ($item[0] == '.' || $item == basename(__FILE__) || $item == 'security.log') continue;
                
                $is_dir = is_dir($item_path);
                $size = $is_dir ? 0 : filesize($item_path);
                $modified = filemtime($item_path);
                
                $files[] = [
                    'name' => $item,
                    'path' => $item_path,
                    'is_dir' => $is_dir,
                    'size' => $is_dir ? 'Directory' : formatBytes($size),
                    'modified' => date('M j, Y H:i', $modified),
                    'icon' => getFileIcon($item_path),
                    'viewable' => !$is_dir && isViewableFile($item_path)
                ];
            }
            
            // Sort: directories first, then files
            usort($files, function($a, $b) {
                if ($a['is_dir'] && !$b['is_dir']) return -1;
                if (!$a['is_dir'] && $b['is_dir']) return 1;
                return strcasecmp($a['name'], $b['name']);
            });
            
            echo json_encode([
                'files' => $files, 
                'current_path' => $real_path,
                'is_admin' => isAdmin(),
                'username' => $_SESSION['username'],
                'csrf_token' => generateCSRFToken()
            ]);
            break;
            
        case 'upload':
            if (!isAdmin()) {
                logSecurityEvent('UNAUTHORIZED_UPLOAD', 'Non-admin attempted upload');
                echo json_encode(['error' => 'Permission denied']);
                exit;
            }
            
            if (isset($_FILES['file'])) {
                $upload_path = $_POST['path'] ?? $base_directory;
                
                // Security checks
                $real_upload_path = realpath($upload_path);
                $real_base = realpath($base_directory);
                
                if (!$real_upload_path || strpos($real_upload_path, $real_base) !== 0) {
                    logSecurityEvent('UPLOAD_PATH_TRAVERSAL', "Attempted upload to: $upload_path");
                    echo json_encode(['error' => 'Upload directory access denied']);
                    exit;
                }
                
                // File size check
                if ($_FILES['file']['size'] > $max_file_size) {
                    logSecurityEvent('UPLOAD_SIZE_EXCEEDED', "File size: " . $_FILES['file']['size']);
                    echo json_encode(['error' => 'File too large. Maximum size: ' . formatBytes($max_file_size)]);
                    exit;
                }
                
                // Sanitize filename
                $original_filename = $_FILES['file']['name'];
                $safe_filename = sanitizeFilename($original_filename);
                
                if ($safe_filename !== $original_filename) {
                    logSecurityEvent('FILENAME_SANITIZED', "Original: $original_filename, Sanitized: $safe_filename");
                }
                
                // File type validation
                if (!isAllowedFileType($safe_filename)) {
                    $extension = pathinfo($safe_filename, PATHINFO_EXTENSION);
                    logSecurityEvent('BLOCKED_FILE_TYPE', "Extension: $extension, Filename: $safe_filename");
                    echo json_encode(['error' => 'File type not allowed']);
                    exit;
                }
                
                $target_file = $real_upload_path . DIRECTORY_SEPARATOR . $safe_filename;
                
                // Move uploaded file
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
                    // Scan for threats
                    $threat_result = scanFileForThreats($target_file);
                    if ($threat_result) {
                        unlink($target_file); // Delete potentially malicious file
                        logSecurityEvent('MALICIOUS_UPLOAD_BLOCKED', $threat_result);
                        echo json_encode(['error' => 'File rejected: Security threat detected']);
                        exit;
                    }
                    
                    // Set secure permissions
                    chmod($target_file, 0644);
                    
                    logSecurityEvent('FILE_UPLOADED', "Filename: $safe_filename");
                    echo json_encode(['success' => 'File uploaded successfully']);
                } else {
                    echo json_encode(['error' => 'Upload failed']);
                }
            }
            break;
            
        case 'delete':
            if (!isAdmin()) {
                logSecurityEvent('UNAUTHORIZED_DELETE', 'Non-admin attempted delete');
                echo json_encode(['error' => 'Permission denied']);
                exit;
            }
            
            $file_path = $_GET['file'];
            
            // Security check
            $real_file_path = realpath($file_path);
            $real_base = realpath($base_directory);
            
            if (!$real_file_path || strpos($real_file_path, $real_base) !== 0) {
                logSecurityEvent('DELETE_PATH_TRAVERSAL', "Attempted delete: $file_path");
                echo json_encode(['error' => 'Access denied']);
                exit;
            }
            
            // Prevent deleting this script or security log
            $filename = basename($real_file_path);
            if ($filename == basename(__FILE__) || $filename == 'security.log') {
                logSecurityEvent('CRITICAL_FILE_DELETE_ATTEMPT', "Filename: $filename");
                echo json_encode(['error' => 'Cannot delete system files']);
                exit;
            }
            
            if (is_file($real_file_path)) {
                if (unlink($real_file_path)) {
                    logSecurityEvent('FILE_DELETED', "Filename: $filename");
                    echo json_encode(['success' => 'File deleted']);
                } else {
                    echo json_encode(['error' => 'Delete failed']);
                }
            } else {
                echo json_encode(['error' => 'File not found']);
            }
            break;
            
        case 'create_folder':
            if (!isAdmin()) {
                logSecurityEvent('UNAUTHORIZED_FOLDER_CREATE', 'Non-admin attempted folder creation');
                echo json_encode(['error' => 'Permission denied']);
                exit;
            }
            
            $parent_path = $_POST['path'] ?? $base_directory;
            $folder_name = sanitizeFilename($_POST['folder_name'] ?? '');
            
            if (empty($folder_name)) {
                echo json_encode(['error' => 'Folder name is required']);
                exit;
            }
            
            // Security check
            $real_parent_path = realpath($parent_path);
            $real_base = realpath($base_directory);
            
            if (!$real_parent_path || strpos($real_parent_path, $real_base) !== 0) {
                logSecurityEvent('FOLDER_CREATE_PATH_TRAVERSAL', "Attempted path: $parent_path");
                echo json_encode(['error' => 'Access denied']);
                exit;
            }
            
            $new_folder_path = $real_parent_path . DIRECTORY_SEPARATOR . $folder_name;
            
            if (mkdir($new_folder_path, 0755)) {
                logSecurityEvent('FOLDER_CREATED', "Folder: $folder_name");
                echo json_encode(['success' => 'Folder created']);
            } else {
                echo json_encode(['error' => 'Failed to create folder']);
            }
            break;
            
        case 'move':
            if (!isAdmin()) {
                logSecurityEvent('UNAUTHORIZED_MOVE', 'Non-admin attempted file move');
                echo json_encode(['error' => 'Permission denied']);
                exit;
            }
            
            $source_path = $_POST['source'] ?? '';
            $target_path = $_POST['target'] ?? '';
            
            if (empty($source_path) || empty($target_path)) {
                echo json_encode(['error' => 'Source and target paths required']);
                exit;
            }
            
            // Security checks
            $real_source = realpath($source_path);
            $real_target = realpath($target_path);
            $real_base = realpath($base_directory);
            
            if (!$real_source || strpos($real_source, $real_base) !== 0) {
                logSecurityEvent('MOVE_SOURCE_TRAVERSAL', "Source: $source_path");
                echo json_encode(['error' => 'Source access denied']);
                exit;
            }
            
            if (!$real_target || strpos($real_target, $real_base) !== 0) {
                logSecurityEvent('MOVE_TARGET_TRAVERSAL', "Target: $target_path");
                echo json_encode(['error' => 'Target access denied']);
                exit;
            }
            
            if (!is_dir($real_target)) {
                echo json_encode(['error' => 'Target is not a directory']);
                exit;
            }
            
            $filename = basename($real_source);
            $new_location = $real_target . DIRECTORY_SEPARATOR . $filename;
            
            // Prevent moving system files
            if ($filename == basename(__FILE__) || $filename == 'security.log') {
                logSecurityEvent('SYSTEM_FILE_MOVE_ATTEMPT', "Filename: $filename");
                echo json_encode(['error' => 'Cannot move system files']);
                exit;
            }
            
            if (file_exists($new_location)) {
                echo json_encode(['error' => 'File already exists in target directory']);
                exit;
            }
            
            if (rename($real_source, $new_location)) {
                logSecurityEvent('FILE_MOVED', "From: $filename to: " . basename($real_target));
                echo json_encode(['success' => 'File moved successfully']);
            } else {
                echo json_encode(['error' => 'Failed to move file']);
            }
            break;
            
        case 'view':
            $file_path = $_GET['file'];
            
            // Security check
            $real_file_path = realpath($file_path);
            $real_base = realpath($base_directory);
            
            if (!$real_file_path || strpos($real_file_path, $real_base) !== 0) {
                logSecurityEvent('VIEW_PATH_TRAVERSAL', "Attempted view: $file_path");
                echo json_encode(['error' => 'Access denied']);
                exit;
            }
            
            if (!is_file($real_file_path)) {
                echo json_encode(['error' => 'File not found']);
                exit;
            }
            
            $extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
            $filename = basename($real_file_path);
            
            // Only allow viewing of safe file types
            if (!isViewableFile($real_file_path)) {
                // Check if it's a document type that can't be viewed
                if (in_array($extension, ['docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt'])) {
                    echo json_encode(['error' => 'Document files cannot be previewed. Please download to view.']);
                } else {
                    echo json_encode(['error' => 'File type not supported for viewing']);
                }
                exit;
            }
            
            switch ($extension) {
                case 'txt':
                case 'md':
                case 'log':
                case 'csv':
                case 'json':
                case 'css':
                case 'html':
                    // Read text files (limit size for security)
                    $content = file_get_contents($real_file_path, false, null, 0, 1024 * 1024); // Max 1MB
                    
                    logSecurityEvent('FILE_VIEWED', "Filename: $filename");
                    
                    echo json_encode([
                        'type' => 'text',
                        'content' => $content,
                        'filename' => $filename,
                        'extension' => $extension
                    ]);
                    break;
                    
                case 'pdf':
                    logSecurityEvent('PDF_VIEWED', "Filename: $filename");
                    
                    echo json_encode([
                        'type' => 'pdf',
                        'url' => "?action=serve_file&file=" . urlencode($file_path),
                        'filename' => $filename
                    ]);
                    break;
                    
                case 'jpg':
                case 'jpeg':
                case 'png':
                case 'gif':
                case 'svg':
                case 'webp':
                    logSecurityEvent('IMAGE_VIEWED', "Filename: $filename");
                    
                    echo json_encode([
                        'type' => 'image',
                        'url' => "?action=serve_file&file=" . urlencode($file_path),
                        'filename' => $filename,
                        'extension' => $extension
                    ]);
                    break;
                    
                default:
                    echo json_encode(['error' => 'File type not supported for viewing']);
            }
            exit;
            break;
            
        case 'serve_file':
            $file_path = $_GET['file'];
            
            // Security check
            $real_file_path = realpath($file_path);
            $real_base = realpath($base_directory);
            
            if (!$real_file_path || strpos($real_file_path, $real_base) !== 0) {
                logSecurityEvent('FILE_SERVE_PATH_TRAVERSAL', "Attempted access: $file_path");
                http_response_code(403);
                exit;
            }
            
            if (!is_file($real_file_path)) {
                http_response_code(404);
                exit;
            }
            
            $extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
            $filename = basename($real_file_path);
            
            // Set appropriate content type based on file extension
            $content_types = [
                'pdf' => 'application/pdf',
                'jpg' => 'image/jpeg',
                'jpeg' => 'image/jpeg',
                'png' => 'image/png',
                'gif' => 'image/gif',
                'svg' => 'image/svg+xml',
                'webp' => 'image/webp'
            ];
            
            if (!isset($content_types[$extension])) {
                http_response_code(403);
                exit;
            }
            
            // For PDFs, completely remove frame restrictions to allow iframe viewing
            if ($extension === 'pdf') {
                // Remove any existing X-Frame-Options header
                header_remove('X-Frame-Options');
                // Override with permissive iframe policy
                header('X-Frame-Options: ALLOWALL');
                // Add permissive CSP for this file
                header('Content-Security-Policy: frame-ancestors \'self\';');
            }
            
            // Serve file with proper headers
            header('Content-Type: ' . $content_types[$extension]);
            header('Content-Disposition: inline; filename="' . $filename . '"');
            header('Content-Length: ' . filesize($real_file_path));
            header('Cache-Control: private, max-age=3600'); // Cache for 1 hour
            header('Pragma: public');
            
            // Security headers for images
            if (strpos($content_types[$extension], 'image/') === 0) {
                header('X-Content-Type-Options: nosniff');
            }
            
            readfile($real_file_path);
            exit;
            break;
            
        case 'download':
            $file_path = $_GET['file'];
            
            // Security check
            $real_file_path = realpath($file_path);
            $real_base = realpath($base_directory);
            
            if (!$real_file_path || strpos($real_file_path, $real_base) !== 0) {
                logSecurityEvent('DOWNLOAD_PATH_TRAVERSAL', "Attempted download: $file_path");
                echo json_encode(['error' => 'Access denied']);
                exit;
            }
            
            if (!is_file($real_file_path)) {
                echo json_encode(['error' => 'File not found']);
                exit;
            }
            
            $filename = basename($real_file_path);
            
            // Prevent downloading system files
            if ($filename == basename(__FILE__) || $filename == 'security.log') {
                logSecurityEvent('SYSTEM_FILE_DOWNLOAD_ATTEMPT', "Filename: $filename");
                echo json_encode(['error' => 'Cannot download system files']);
                exit;
            }
            
            logSecurityEvent('FILE_DOWNLOADED', "Filename: $filename");
            
            // Set headers for download
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('Content-Length: ' . filesize($real_file_path));
            header('Cache-Control: must-revalidate');
            
            // Output file content
            readfile($real_file_path);
            exit;
            break;
            
        default:
            logSecurityEvent('INVALID_ACTION', "Action: " . $_GET['action']);
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}

$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>PNW Computer - Secure File Manager</title>
    <style>
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            overflow-x: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c5530 0%, #1e3a21 100%);
            color: white;
            padding: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-main {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .header h1 {
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.8rem;
        }
        
        .role-badge {
            background: rgba(255,255,255,0.2);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.7rem;
        }
        
        .security-indicator {
            background: rgba(34, 197, 94, 0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.6rem;
        }
        
        .logout-btn {
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.3);
            color: white;
            padding: 0.4rem 0.8rem;
            border-radius: 4px;
            font-size: 0.8rem;
            cursor: pointer;
            min-height: 36px;
        }
        
        .logout-btn:active {
            background: rgba(255,255,255,0.2);
        }
        
        .header-subtitle {
            font-size: 0.8rem;
            opacity: 0.9;
        }
        
        .container {
            padding: 1rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .security-banner {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
            font-size: 0.8rem;
            line-height: 1.4;
        }
        
        .access-notice {
            background: #fef3c7;
            color: #92400e;
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            font-size: 0.8rem;
            line-height: 1.4;
        }
        
        .toolbar {
            background: white;
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.75rem;
        }
        
        .btn {
            padding: 12px 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            background: #2c5530;
            color: white;
            font-size: 14px;
            font-weight: 500;
            text-align: center;
            transition: all 0.2s ease;
            touch-action: manipulation;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            min-height: 44px; /* iOS touch target */
        }
        
        .btn:active {
            transform: scale(0.98);
            background: #1e3a21;
        }
        
        .btn:disabled { 
            background: #cbd5e1; 
            cursor: not-allowed; 
            opacity: 0.6;
        }
        
        .breadcrumb {
            background: white;
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            font-size: 14px;
            word-break: break-all;
        }
        
        .breadcrumb span {
            color: #2c5530;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
            transition: background-color 0.2s;
        }
        
        .breadcrumb span:hover,
        .breadcrumb span:active {
            background: #f0f9ff;
        }
        
        .file-area {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .file-row {
            padding: 1rem;
            border-bottom: 1px solid #f1f5f9;
            cursor: pointer;
            transition: background-color 0.2s;
            touch-action: manipulation;
        }
        
        .file-row:active {
            background: #f8fafc;
        }
        
        .file-row:last-child {
            border-bottom: none;
        }
        
        .file-row.drag-over {
            background: #e0f2fe !important;
            border: 2px dashed #0369a1;
        }
        
        .file-row.dragging {
            opacity: 0.5;
            transform: rotate(2deg);
        }
        
        .file-info {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 0.5rem;
        }
        
        .file-icon {
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            font-size: 16px;
            font-weight: bold;
            flex-shrink: 0;
        }
        
        .file-details {
            flex: 1;
            min-width: 0;
        }
        
        .file-name {
            font-weight: 500;
            word-break: break-word;
            margin-bottom: 2px;
        }
        
        .file-meta {
            font-size: 12px;
            color: #64748b;
        }
        
        .file-actions {
            display: flex;
            gap: 8px;
            margin-top: 8px;
            flex-wrap: wrap;
        }
        
        .action-btn {
            padding: 6px 12px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            min-height: 32px;
            touch-action: manipulation;
            transition: all 0.2s;
        }
        
        .view-btn { 
            background: #3b82f6; 
            color: white; 
        }
        .view-btn:active { 
            background: #2563eb; 
            transform: scale(0.95);
        }
        
        .download-btn { 
            background: #10b981; 
            color: white; 
        }
        .download-btn:active { 
            background: #059669; 
            transform: scale(0.95);
        }
        
        .delete-btn { 
            background: #ef4444; 
            color: white; 
        }
        .delete-btn:active { 
            background: #dc2626; 
            transform: scale(0.95);
        }
        
        .drag-drop-hint {
            color: #64748b;
            font-size: 11px;
            margin-top: 4px;
        }
        
        .loading, .error {
            text-align: center;
            padding: 3rem 1rem;
        }
        
        .error {
            background: #fee2e2;
            color: #dc2626;
            border-radius: 8px;
            margin: 1rem;
        }
        
        .hidden-file-input {
            display: none;
        }
        
        /* Modal styles for file viewer */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.8);
        }
        
        .modal-content {
            position: relative;
            background-color: white;
            margin: 2% auto;
            padding: 0;
            border-radius: 12px;
            width: 95%;
            height: 90%;
            max-width: 1200px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            display: flex;
            flex-direction: column;
        }
        
        .modal-header {
            background: linear-gradient(135deg, #2c5530 0%, #1e3a21 100%);
            color: white;
            padding: 1rem;
            border-radius: 12px 12px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-title {
            font-size: 1rem;
            word-break: break-word;
            flex: 1;
            margin-right: 1rem;
        }
        
        .close {
            background: none;
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.5rem;
            border-radius: 4px;
            min-height: 44px;
            min-width: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .close:active {
            background: rgba(255,255,255,0.1);
        }
        
        .modal-body {
            flex: 1;
            padding: 0.5rem;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        .file-viewer {
            flex: 1;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .text-viewer {
            width: 100%;
            height: 100%;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            padding: 1rem;
            border: none;
            outline: none;
            resize: none;
            background: #f8fafc;
            overflow: auto;
        }
        
        .pdf-viewer {
            width: 100%;
            height: 100%;
            border: none;
        }
        
        .image-viewer {
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f8fafc;
        }
        
        .image-viewer img {
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .pdf-error {
            text-align: center;
            padding: 2rem 1rem;
        }
        
        .pdf-error h3 {
            margin-bottom: 1rem;
            color: #333;
        }
        
        .pdf-error p {
            margin: 1rem 0;
            color: #64748b;
            line-height: 1.4;
        }
        
        .pdf-error .btn {
            margin: 0.5rem;
            display: inline-flex;
        }
        
        .loading, .error {
            text-align: center;
            padding: 3rem 1rem;
        }
        
        .error {
            background: #fee2e2;
            color: #dc2626;
            border-radius: 8px;
            margin: 1rem;
        }
        
        .hidden-file-input {
            display: none;
        }
        
        /* Enhanced upload area for mobile and desktop */
        #uploadArea {
            border: 2px dashed #cbd5e1;
            border-radius: 12px;
            padding: 2rem 1rem;
            text-align: center;
            background: white;
            transition: all 0.3s ease;
            cursor: pointer;
            touch-action: manipulation;
        }
        
        #uploadArea:hover,
        #uploadArea:active {
            border-color: #2c5530;
            background: #f0f9ff;
            transform: scale(1.02);
        }
        
        #uploadArea.dragover {
            border-color: #2c5530;
            background: #f0f9ff;
            box-shadow: 0 4px 12px rgba(44, 85, 48, 0.1);
        }
        
        // Close modal events
        window.onclick = function(event) {
            const modal = document.getElementById('fileViewerModal');
            if (event.target === modal) {
                closeViewer();
            }
        }
        
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeViewer();
            }
        });
        
        /* Desktop optimizations */
        @media (min-width: 768px) {
            .modal-content {
                margin: 2% auto;
                width: 90%;
                height: 90%;
                max-width: 1200px;
                border-radius: 12px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            
            .modal-header {
                border-radius: 12px 12px 0 0;
                padding: 1rem 2rem;
            }
            
            .modal-body {
                padding: 1rem;
            }
            
            .file-viewer {
                border: 1px solid #e2e8f0;
                border-radius: 8px;
            }
            
            .image-viewer {
                background: #f8fafc;
            }
            
            .image-viewer img {
                border-radius: 4px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            
            .text-viewer {
                font-size: 14px;
            }
            
            .header {
                padding: 1rem 2rem;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .user-info {
                font-size: 0.9rem;
                gap: 1rem;
            }
            
            .role-badge {
                font-size: 0.8rem;
                padding: 0.25rem 0.5rem;
            }
            
            .security-indicator {
                font-size: 0.7rem;
                padding: 0.25rem 0.5rem;
            }
            
            .logout-btn {
                font-size: 0.9rem;
                padding: 0.5rem 1rem;
            }
            
            .toolbar {
                grid-template-columns: repeat(4, 1fr);
                padding: 1rem;
            }
            
            .container {
                padding: 2rem;
            }
            
            .security-banner {
                font-size: 0.9rem;
                padding: 1rem;
            }
            
            .access-notice {
                font-size: 0.9rem;
                padding: 1rem;
            }
            
            .file-info {
                display: grid;
                grid-template-columns: auto 1fr auto auto;
                align-items: center;
                margin-bottom: 0;
            }
            
            .file-actions {
                margin-top: 0;
                justify-content: flex-end;
            }
        }
        
        /* Large screen optimizations */
        @media (min-width: 1024px) {
            .toolbar {
                grid-template-columns: repeat(4, 1fr);
                gap: 1rem;
            }
            
            .file-row {
                padding: 1rem 1.5rem;
            }
            
            #uploadArea {
                padding: 3rem 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-main">
            <div>
                <h1>🛡️ PNW Computer File Manager</h1>
                <div class="header-subtitle">Enhanced Security • Activity Logging • Threat Protection</div>
            </div>
            <div class="user-info">
                <span><?php echo htmlspecialchars($_SESSION['username']); ?></span>
                <span class="role-badge"><?php echo strtoupper($_SESSION['role']); ?></span>
                <span class="security-indicator">🔒 SECURE</span>
                <button class="logout-btn" onclick="logout()">🚪 Logout</button>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="security-banner">
            🛡️ <strong>Security Features Active:</strong> CSRF Protection • File Type Validation • Path Traversal Prevention • Activity Logging • Brute Force Protection
        </div>
        
        <?php if (!isAdmin()): ?>
        <div class="access-notice">
            📋 <strong>Read-Only Access:</strong> You can browse, view, and download files only.
        </div>
        <?php endif; ?>
        
        <div class="toolbar">
            <button class="btn" onclick="triggerFileUpload()" <?php echo !isAdmin() ? 'disabled' : ''; ?>>
                📁 Upload Files
            </button>
            <button class="btn" onclick="createFolder()" <?php echo !isAdmin() ? 'disabled' : ''; ?>>
                📂 New Folder
            </button>
            <button class="btn" onclick="refreshFiles()">
                🔄 Refresh
            </button>
            <button class="btn" onclick="showUploadArea()">
                📤 Quick Upload
            </button>
        </div>

        <div class="breadcrumb" id="breadcrumb">Loading...</div>

        <div class="file-area">
            <div id="fileList" class="loading">
                Loading files...
            </div>
            
            <div id="uploadSection" style="display: none; padding: 1rem; background: #f8fafc; border-top: 1px solid #e2e8f0;">
                <div style="border: 2px dashed #cbd5e1; border-radius: 12px; padding: 2rem 1rem; text-align: center; background: white; transition: all 0.3s ease; cursor: pointer;" 
                     id="uploadArea" onclick="triggerFileUpload()">
                    <div style="font-size: 2rem; margin-bottom: 0.5rem;">📁</div>
                    <div><strong>Tap to select files</strong></div>
                    <div style="margin-top: 0.5rem; font-size: 14px; color: #64748b;">
                        Or drag and drop files here (desktop)
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- File Viewer Modal -->
    <div id="fileViewerModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle" class="modal-title">File Viewer</h3>
                <button class="close" onclick="closeViewer()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="file-viewer">
                    <textarea id="textViewer" class="text-viewer" readonly style="display: none;"></textarea>
                    <iframe id="pdfViewer" class="pdf-viewer" style="display: none;" onload="handlePdfLoad()" onerror="handlePdfError()"></iframe>
                    <div id="imageViewer" class="image-viewer" style="display: none;">
                        <img id="imageDisplay" src="" alt="Image preview">
                    </div>
                    <div id="pdfError" class="pdf-error" style="display: none;">
                        <h3>📄 PDF Viewing Options</h3>
                        <p>Choose how you'd like to view this PDF document:</p>
                        <button class="btn" onclick="openPdfInNewTab()">📄 Open in New Tab</button>
                        <button class="btn" onclick="downloadCurrentFile()">⬇️ Download PDF</button>
                        <p style="font-size: 0.9rem; color: #94a3b8; margin-top: 1rem;">
                            <em>Note: PDF viewing optimized for better compatibility across hosting environments</em>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <input type="file" id="fileInput" class="hidden-file-input" multiple accept="*/*">

    <script>
        let currentPath = '<?php echo $base_directory; ?>';
        let basePath = '<?php echo $base_directory; ?>';
        let isAdmin = <?php echo isAdmin() ? 'true' : 'false'; ?>;
        let csrfToken = '<?php echo $csrf_token; ?>';
        let currentPdfUrl = '';
        let currentFileName = '';
        let draggedElement = null;
        let uploadSectionVisible = false;
        
        // Touch and mobile optimized functions
        function triggerFileUpload() {
            if (!isAdmin) {
                alert('Permission denied: Admin access required');
                return;
            }
            document.getElementById('fileInput').click();
        }
        
        function showUploadArea() {
            if (!isAdmin) {
                alert('Permission denied: Admin access required');
                return;
            }
            uploadSectionVisible = !uploadSectionVisible;
            const uploadSection = document.getElementById('uploadSection');
            uploadSection.style.display = uploadSectionVisible ? 'block' : 'none';
        }
        
        // Drag and Drop Functions (mobile and desktop)
        let dragSourcePath = null;
        let touchStartPos = { x: 0, y: 0 };
        let isDragging = false;
        let dragStartTime = 0;
        
        // Mouse drag events (desktop)
        function handleDragStart(event, filePath) {
            if (!isAdmin) return false;
            
            draggedElement = event.target;
            dragSourcePath = filePath;
            event.dataTransfer.setData('text/plain', filePath);
            event.target.classList.add('dragging');
        }
        
        function handleDragEnd(event) {
            if (!isAdmin) return false;
            
            event.target.classList.remove('dragging');
            cleanupDragStates();
        }
        
        function handleDragOver(event) {
            if (!isAdmin) return false;
            
            event.preventDefault();
            const fileRow = event.target.closest('.file-row');
            if (fileRow) {
                fileRow.classList.add('drag-over');
            }
        }
        
        function handleDragLeave(event) {
            if (!isAdmin) return false;
            
            const fileRow = event.target.closest('.file-row');
            if (fileRow && !fileRow.contains(event.relatedTarget)) {
                fileRow.classList.remove('drag-over');
            }
        }
        
        function handleDrop(event, targetPath) {
            if (!isAdmin) return false;
            
            event.preventDefault();
            const sourceFile = event.dataTransfer.getData('text/plain') || dragSourcePath;
            
            cleanupDragStates();
            
            if (sourceFile && sourceFile !== targetPath) {
                moveFile(sourceFile, targetPath);
            }
        }
        
        // Touch drag events (mobile)
        function handleTouchStart(event, filePath) {
            if (!isAdmin) return false;
            
            const touch = event.touches[0];
            touchStartPos = { x: touch.clientX, y: touch.clientY };
            dragSourcePath = filePath;
            dragStartTime = Date.now();
            isDragging = false;
            
            // Prevent default to avoid conflicts, but allow normal tap behavior
            setTimeout(() => {
                if (!isDragging) {
                    // This was just a tap, not a drag
                    return;
                }
            }, 200);
        }
        
        function handleTouchMove(event, filePath) {
            if (!isAdmin || !dragSourcePath) return false;
            
            const touch = event.touches[0];
            const deltaX = Math.abs(touch.clientX - touchStartPos.x);
            const deltaY = Math.abs(touch.clientY - touchStartPos.y);
            const timeDelta = Date.now() - dragStartTime;
            
            // Start dragging if moved enough distance and time
            if ((deltaX > 10 || deltaY > 10) && timeDelta > 200) {
                isDragging = true;
                event.preventDefault(); // Now prevent default to enable drag mode
                
                const fileRow = event.target.closest('.file-row');
                if (fileRow) {
                    fileRow.classList.add('dragging');
                }
                
                // Show drag feedback
                showDragFeedback(touch.clientX, touch.clientY);
                
                // Find element under touch point
                const elementBelow = document.elementFromPoint(touch.clientX, touch.clientY);
                updateDropTarget(elementBelow);
            }
        }
        
        function handleTouchEnd(event, filePath) {
            if (!isAdmin || !isDragging) {
                // Reset drag state for taps
                dragSourcePath = null;
                isDragging = false;
                return false;
            }
            
            event.preventDefault();
            
            // Find the drop target
            const touch = event.changedTouches[0];
            const elementBelow = document.elementFromPoint(touch.clientX, touch.clientY);
            const dropRow = elementBelow ? elementBelow.closest('.file-row') : null;
            
            if (dropRow) {
                const targetPath = getFilePathFromRow(dropRow);
                if (targetPath && dragSourcePath && targetPath !== dragSourcePath) {
                    moveFile(dragSourcePath, targetPath);
                }
            }
            
            // Cleanup
            cleanupDragStates();
            hideDragFeedback();
            dragSourcePath = null;
            isDragging = false;
        }
        
        function cleanupDragStates() {
            document.querySelectorAll('.file-row').forEach(row => {
                row.classList.remove('drag-over', 'dragging');
            });
        }
        
        function showDragFeedback(x, y) {
            let feedback = document.getElementById('dragFeedback');
            if (!feedback) {
                feedback = document.createElement('div');
                feedback.id = 'dragFeedback';
                feedback.style.cssText = `
                    position: fixed;
                    background: #2c5530;
                    color: white;
                    padding: 8px 12px;
                    border-radius: 6px;
                    font-size: 12px;
                    z-index: 1002;
                    pointer-events: none;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                `;
                feedback.textContent = '📁 Move file';
                document.body.appendChild(feedback);
            }
            
            feedback.style.left = (x + 10) + 'px';
            feedback.style.top = (y - 10) + 'px';
            feedback.style.display = 'block';
        }
        
        function hideDragFeedback() {
            const feedback = document.getElementById('dragFeedback');
            if (feedback) {
                feedback.remove();
            }
        }
        
        function updateDropTarget(element) {
            // Remove existing drop targets
            document.querySelectorAll('.file-row').forEach(row => {
                row.classList.remove('drag-over');
            });
            
            // Add drop target if valid
            const fileRow = element ? element.closest('.file-row') : null;
            if (fileRow && isValidDropTarget(fileRow)) {
                fileRow.classList.add('drag-over');
            }
        }
        
        function isValidDropTarget(fileRow) {
            const fileName = fileRow.querySelector('.file-name');
            if (!fileName) return false;
            
            const text = fileName.textContent;
            // Valid drop targets: folders and parent directory
            return text.includes('..') || text.includes('Directory') || fileRow.querySelector('.file-meta').textContent.includes('Directory');
        }
        
        function getFilePathFromRow(fileRow) {
            // Extract file path from the row's click handler or data
            const onClick = fileRow.getAttribute('onclick');
            if (onClick && onClick.includes('loadFiles')) {
                const match = onClick.match(/loadFiles\('([^']+)'\)/);
                return match ? match[1] : null;
            }
            return null;
        }
        
        async function moveFile(sourcePath, targetPath) {
            try {
                const formData = new FormData();
                formData.append('source', sourcePath);
                formData.append('target', targetPath);
                formData.append('csrf_token', csrfToken);
                
                const response = await fetch('?action=move', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (data.success) {
                    loadFiles(currentPath);
                    showMessage('File moved successfully!', 'success');
                } else {
                    showMessage('Move failed: ' + data.error, 'error');
                }
            } catch (error) {
                showMessage('Move failed - connection error', 'error');
            }
        }
        
        function handlePdfLoad() {
            // PDF loaded successfully, hide error message
            document.getElementById('pdfError').style.display = 'none';
        }
        
        function handlePdfError() {
            // PDF failed to load in iframe, show alternative options
            document.getElementById('pdfViewer').style.display = 'none';
            document.getElementById('pdfError').style.display = 'block';
        }
        
        function openPdfInNewTab() {
            if (currentPdfUrl) {
                window.open(currentPdfUrl, '_blank');
            }
        }
        
        function downloadCurrentFile() {
            if (currentPdfUrl) {
                // Convert serve_file URL to download URL
                const downloadUrl = currentPdfUrl.replace('action=serve_file', 'action=download');
                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = currentFileName;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        }
        
        async function loadFiles(path = currentPath) {
            const fileList = document.getElementById('fileList');
            fileList.innerHTML = '<div class="loading">Loading files...</div>';
            
            try {
                const response = await fetch(`?action=list&path=${encodeURIComponent(path)}`);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                if (data.error) {
                    fileList.innerHTML = `<div class="error">Error: ${data.error}</div>`;
                    return;
                }
                
                currentPath = data.current_path;
                isAdmin = data.is_admin;
                csrfToken = data.csrf_token;
                updateBreadcrumb();
                displayFiles(data.files);
                
            } catch (error) {
                console.error('Load files error:', error);
                fileList.innerHTML = `
                    <div class="error">
                        Failed to load files: ${error.message}<br>
                        <button class="btn" onclick="loadFiles()" style="margin-top: 0.5rem;">🔄 Try Again</button>
                    </div>
                `;
            }
        }
        
        function displayFiles(files) {
            const fileList = document.getElementById('fileList');
            let html = '';
            
            // Add parent directory if not at base
            if (currentPath !== basePath) {
                const parentPath = currentPath.substring(0, currentPath.lastIndexOf('/')) || basePath;
                // Both mouse and touch events for all devices
                const dragEvents = isAdmin ? `
                    ondrop="handleDrop(event, '${parentPath}')" 
                    ondragover="handleDragOver(event)" 
                    ondragleave="handleDragLeave(event)"
                ` : '';
                
                html += `
                    <div class="file-row" onclick="loadFiles('${parentPath}')" ${dragEvents}>
                        <div class="file-info">
                            <div class="file-icon" style="background: #fbbf24; color: white;">📁</div>
                            <div class="file-details">
                                <div class="file-name">.. (Parent Directory)</div>
                                <div class="file-meta">Go up one level</div>
                            </div>
                        </div>
                        ${isAdmin ? '<div class="drag-drop-hint">📂 Drop files here</div>' : ''}
                    </div>
                `;
            }
            
            files.forEach(file => {
                const clickAction = file.is_dir ? `loadFiles('${file.path}')` : '';
                
                // Enable drag for files on all devices if admin
                const draggable = isAdmin && !file.is_dir ? 'draggable="true"' : '';
                
                // Mouse drag events
                const mouseDragEvents = isAdmin && !file.is_dir ? `
                    ondragstart="handleDragStart(event, '${file.path}')" 
                    ondragend="handleDragEnd(event)"
                ` : '';
                
                // Touch drag events for mobile
                const touchDragEvents = isAdmin && !file.is_dir ? `
                    ontouchstart="handleTouchStart(event, '${file.path}')" 
                    ontouchmove="handleTouchMove(event, '${file.path}')" 
                    ontouchend="handleTouchEnd(event, '${file.path}')"
                ` : '';
                
                // Drop events for folders (both mouse and touch)
                const dropEvents = file.is_dir && isAdmin ? `
                    ondrop="handleDrop(event, '${file.path}')" 
                    ondragover="handleDragOver(event)" 
                    ondragleave="handleDragLeave(event)"
                ` : '';
                
                html += `
                    <div class="file-row" onclick="${clickAction}" ${draggable} ${mouseDragEvents} ${touchDragEvents} ${dropEvents}>
                        <div class="file-info">
                            <div class="file-icon" style="background: ${getIconColor(file.icon)}; color: white;">${file.icon}</div>
                            <div class="file-details">
                                <div class="file-name">${file.name}</div>
                                <div class="file-meta">${file.size} • ${file.modified}</div>
                            </div>
                        </div>
                        <div class="file-actions">
                            ${file.viewable ? `<button class="action-btn view-btn" onclick="event.stopPropagation(); viewFile('${file.path}', '${file.name}')">View</button>` : ''}
                            <button class="action-btn download-btn" onclick="event.stopPropagation(); downloadFile('${file.path}', '${file.name}')">Download</button>
                            ${isAdmin && !file.is_dir ? `<button class="action-btn delete-btn" onclick="event.stopPropagation(); deleteFile('${file.path}')">Delete</button>` : ''}
                        </div>
                        ${file.is_dir && isAdmin ? '<div class="drag-drop-hint">📂 Drop files here</div>' : ''}
                    </div>
                `;
            });
            
            fileList.innerHTML = html || '<div class="loading">No files found in this directory</div>';
        }
        
        function getIconColor(icon) {
            const iconColors = {
                '🌐': '#f97316',
                '🎨': '#3b82f6', 
                '⚡': '#eab308',
                '🐘': '#8b5cf6',
                '📝': '#64748b',
                '🖼️': '#10b981',
                '📄': '#dc2626',
                '📦': '#f59e0b',
                '📊': '#059669',
                '📁': '#fbbf24'
            };
            return iconColors[icon] || '#64748b';
        }
        
        function updateBreadcrumb() {
            const relativePath = currentPath.replace(basePath, '');
            const parts = relativePath.split('/').filter(part => part);
            let breadcrumbHTML = `<span onclick="loadFiles('${basePath}')">🏠 Home</span>`;
            
            let buildPath = basePath;
            parts.forEach((part, index) => {
                buildPath += '/' + part;
                if (index === parts.length - 1) {
                    breadcrumbHTML += ` / <strong>${part}</strong>`;
                } else {
                    breadcrumbHTML += ` / <span onclick="loadFiles('${buildPath}')">${part}</span>`;
                }
            });
            
            document.getElementById('breadcrumb').innerHTML = breadcrumbHTML;
        }
        
        async function deleteFile(filePath) {
            if (!isAdmin) {
                showMessage('Permission denied: Admin access required', 'error');
                return;
            }
            
            if (!confirm('Are you sure you want to delete this file?')) return;
            
            showMessage('Deleting file...', 'loading');
            
            try {
                const formData = new FormData();
                formData.append('csrf_token', csrfToken);
                
                const response = await fetch(`?action=delete&file=${encodeURIComponent(filePath)}`, {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (data.success) {
                    loadFiles(currentPath);
                    showMessage('File deleted successfully!', 'success');
                } else {
                    showMessage('Delete failed: ' + data.error, 'error');
                }
            } catch (error) {
                showMessage('Delete failed - connection error', 'error');
            }
        }
        
        function downloadFile(filePath, fileName) {
            showMessage(`Downloading ${fileName}...`, 'loading');
            const downloadUrl = `?action=download&file=${encodeURIComponent(filePath)}`;
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            setTimeout(() => {
                showMessage('Download started!', 'success');
            }, 1000);
        }
        
        async function viewFile(filePath, fileName) {
            showMessage('Loading file for viewing...', 'loading');
            
            try {
                const response = await fetch(`?action=view&file=${encodeURIComponent(filePath)}`);
                const data = await response.json();
                
                if (data.error) {
                    showMessage('View failed: ' + data.error, 'error');
                    return;
                }
                
                openViewer(data, fileName);
                showMessage('File loaded successfully!', 'success');
                
            } catch (error) {
                showMessage('Failed to load file for viewing', 'error');
            }
        }
        
        async function createFolder() {
            if (!isAdmin) {
                showMessage('Permission denied: Admin access required', 'error');
                return;
            }
            
            const folderName = prompt('Enter folder name:');
            if (!folderName || folderName.trim() === '') return;
            
            // Basic validation
            const invalidChars = /[<>:"/\\|?*]/;
            if (invalidChars.test(folderName)) {
                showMessage('Folder name contains invalid characters. Please avoid: < > : " / \\ | ? *', 'error');
                return;
            }
            
            showMessage('Creating folder...', 'loading');
            
            try {
                const formData = new FormData();
                formData.append('path', currentPath);
                formData.append('folder_name', folderName.trim());
                formData.append('csrf_token', csrfToken);
                
                const response = await fetch('?action=create_folder', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (data.success) {
                    loadFiles(currentPath);
                    showMessage('Folder created successfully!', 'success');
                } else {
                    showMessage('Failed to create folder: ' + data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to create folder: Network error', 'error');
            }
        }
        
        function refreshFiles() {
            loadFiles(currentPath);
        }
        
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                window.location.href = '?logout=1';
            }
        }
        
        function showMessage(message, type) {
            // Simple toast-like message system
            const existingToast = document.getElementById('toast');
            if (existingToast) {
                existingToast.remove();
            }
            
            const toast = document.createElement('div');
            toast.id = 'toast';
            toast.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: ${type === 'error' ? '#dc2626' : type === 'success' ? '#059669' : '#2c5530'};
                color: white;
                padding: 12px 16px;
                border-radius: 8px;
                z-index: 1001;
                font-size: 14px;
                max-width: 300px;
                word-wrap: break-word;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                animation: slideIn 0.3s ease;
            `;
            toast.textContent = message;
            
            // Add slide in animation
            const style = document.createElement('style');
            style.textContent = `
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `;
            document.head.appendChild(style);
            
            document.body.appendChild(toast);
            
            if (type !== 'loading') {
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.style.animation = 'slideIn 0.3s ease reverse';
                        setTimeout(() => toast.remove(), 300);
                    }
                }, 3000);
            }
        }
        
        // File upload handling with mobile optimizations
        document.getElementById('fileInput').addEventListener('change', async function(e) {
            if (!isAdmin) {
                showMessage('Permission denied: Admin access required', 'error');
                e.target.value = '';
                return;
            }
            
            const files = e.target.files;
            if (files.length === 0) return;
            
            let successCount = 0;
            let failCount = 0;
            
            showMessage(`Uploading ${files.length} file(s)...`, 'loading');
            
            for (let file of files) {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('path', currentPath);
                formData.append('csrf_token', csrfToken);
                
                try {
                    const response = await fetch('?action=upload', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        successCount++;
                    } else {
                        failCount++;
                        console.error(`Upload failed for ${file.name}: ${data.error}`);
                    }
                } catch (error) {
                    failCount++;
                    console.error(`Upload error for ${file.name}:`, error);
                }
            }
            
            // Show results
            if (failCount === 0) {
                showMessage(`${successCount} file(s) uploaded successfully!`, 'success');
            } else {
                showMessage(`${successCount} succeeded, ${failCount} failed. Check console for details.`, 'error');
            }
            
            // Refresh file list
            loadFiles(currentPath);
            e.target.value = '';
        });
        
        // Drag and drop for upload area (mobile and desktop)
        const uploadArea = document.getElementById('uploadArea');
        
        // Mouse events (desktop)
        uploadArea.addEventListener('dragover', (e) => {
            if (!isAdmin) return;
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            if (!isAdmin) return;
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            if (!isAdmin) return;
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            
            const fileInput = document.getElementById('fileInput');
            fileInput.files = e.dataTransfer.files;
            fileInput.dispatchEvent(new Event('change'));
        });
        
        // Touch events for mobile upload area
        let uploadTouchStartTime = 0;
        let uploadTouchFiles = null;
        
        uploadArea.addEventListener('touchstart', (e) => {
            if (!isAdmin) return;
            uploadTouchStartTime = Date.now();
        });
        
        uploadArea.addEventListener('touchend', (e) => {
            if (!isAdmin) return;
            
            // Simple tap to upload
            const touchDuration = Date.now() - uploadTouchStartTime;
            if (touchDuration < 500) { // Quick tap
                triggerFileUpload();
            }
        });
        
        // Keyboard shortcuts and accessibility
        document.addEventListener('keydown', function(event) {
            // ESC key closes modal
            if (event.key === 'Escape') {
                closeViewer();
            }
            
            // Ctrl+R or F5 refreshes files (prevent default browser refresh)
            if ((event.ctrlKey && event.key === 'r') || event.key === 'F5') {
                event.preventDefault();
                refreshFiles();
            }
            
            // Ctrl+U opens upload dialog (admin only)
            if (event.ctrlKey && event.key === 'u' && isAdmin) {
                event.preventDefault();
                triggerFileUpload();
            }
        });
        
        // Modal close events
        window.onclick = function(event) {
            const modal = document.getElementById('fileViewerModal');
            if (event.target === modal) {
                closeViewer();
            }
        }
        
        // Global drag and drop cleanup events for desktop
        document.addEventListener('dragend', function(event) {
            if (!isAdmin || window.innerWidth <= 768) return;
            
            // Clean up all drag states
            document.querySelectorAll('.file-row').forEach(row => {
                row.classList.remove('drag-over', 'dragging');
            });
            draggedElement = null;
        });
        
        // Initial load
        loadFiles();
        
        // Update interface based on screen size
        function updateInterfaceForScreenSize() {
            const isMobile = window.innerWidth <= 768;
            const fileRows = document.querySelectorAll('.file-row');
            
            fileRows.forEach(row => {
                if (isMobile) {
                    row.removeAttribute('draggable');
                } else if (isAdmin && !row.querySelector('.file-name').textContent.includes('..') && !row.querySelector('.file-name').textContent.includes('Directory')) {
                    row.setAttribute('draggable', 'true');
                }
            });
        }
        
        // Listen for screen size changes
        window.addEventListener('resize', updateInterfaceForScreenSize);
    </script>
</body>
</html>
