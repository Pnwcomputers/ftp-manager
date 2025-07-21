<?php
/**
 * Secure File Manager with Enhanced Security Features
 * Protections against: Directory traversal, CSRF, brute force, malicious uploads, etc.
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
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 400px; 
                    margin: 100px auto; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }
                .login-box { 
                    background: white; 
                    padding: 2rem; 
                    border-radius: 12px; 
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
                }
                input { 
                    width: 100%; 
                    padding: 12px; 
                    margin: 10px 0; 
                    box-sizing: border-box; 
                    border: 1px solid #ddd; 
                    border-radius: 6px; 
                    font-size: 14px;
                }
                button { 
                    background: #667eea; 
                    color: white; 
                    padding: 12px 20px; 
                    border: none; 
                    cursor: pointer; 
                    width: 100%; 
                    border-radius: 6px; 
                    font-size: 16px;
                    transition: background 0.3s;
                }
                button:hover { background: #5a6fd8; }
                .error { 
                    color: #dc2626; 
                    margin: 10px 0; 
                    padding: 10px; 
                    background: #fee2e2; 
                    border-radius: 6px; 
                    border: 1px solid #fecaca;
                }
                h2 { text-align: center; color: #333; margin-bottom: 1.5rem; }
                .security-notice {
                    background: #f0fdf4;
                    border: 1px solid #bbf7d0;
                    color: #166534;
                    padding: 1rem;
                    border-radius: 6px;
                    margin-top: 1rem;
                    font-size: 12px;
                }
                .demo-accounts {
                    background: #f8fafc;
                    padding: 1rem;
                    border-radius: 6px;
                    margin-top: 1rem;
                    font-size: 12px;
                    color: #64748b;
                }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>🔐 Secure File Manager</h2>
                <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="text" name="username" placeholder="Username" required autofocus autocomplete="username">
                    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                    <button type="submit">Login</button>
                </form>
                <div class="security-notice">
                    🛡️ <strong>Security Features Active:</strong><br>
                    • Account lockout after failed attempts<br>
                    • CSRF protection • Secure sessions<br>
                    • File type validation • Activity logging
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
                    'modified' => date('Y-m-d H:i:s', $modified),
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Manager - PNW Computer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 0.9rem;
        }
        
        .role-badge {
            background: rgba(255,255,255,0.2);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        .security-indicator {
            background: rgba(34, 197, 94, 0.3);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .security-banner {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
            font-size: 0.9rem;
        }
        
        .toolbar {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            background: #667eea;
            color: white;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        .btn:hover { background: #5a6fd8; }
        .btn:disabled { 
            background: #cbd5e1; 
            cursor: not-allowed; 
            opacity: 0.6;
        }
        
        .file-area {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            overflow: hidden;
        }
        
        .file-header {
            background: #f8fafc;
            padding: 1rem;
            border-bottom: 1px solid #e2e8f0;
            display: grid;
            grid-template-columns: 3fr 1fr 1fr 2fr;
            gap: 1rem;
            font-weight: 600;
            color: #475569;
            font-size: 0.9rem;
        }
        
        .file-row {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #f1f5f9;
            display: grid;
            grid-template-columns: 3fr 1fr 1fr 2fr;
            gap: 1rem;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .file-row:hover { background: #f8fafc; }
        
        .action-btn {
            padding: 0.25rem 0.5rem;
            margin: 0 0.25rem;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.75rem;
            transition: all 0.2s;
        }
        
        .view-btn { background: #3b82f6; color: white; }
        .view-btn:hover { background: #2563eb; }
        
        .download-btn { background: #10b981; color: white; }
        .download-btn:hover { background: #059669; }
        
        .delete-btn { background: #ef4444; color: white; }
        .delete-btn:hover { background: #dc2626; }
        
        .loading, .error {
            text-align: center;
            padding: 2rem;
        }
        
        .error {
            background: #fee2e2;
            color: #dc2626;
            border-radius: 4px;
            margin: 1rem;
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
            border-radius: 8px;
            width: 90%;
            height: 90%;
            max-width: 1200px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            display: flex;
            flex-direction: column;
        }
        
        .modal-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            border-radius: 8px 8px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .close {
            background: none;
            border: none;
            color: white;
            font-size: 2rem;
            cursor: pointer;
            padding: 0;
        }
        
        .modal-body {
            flex: 1;
            padding: 1rem;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        .file-viewer {
            flex: 1;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .text-viewer {
            width: 100%;
            height: 100%;
            font-family: 'Courier New', monospace;
            font-size: 14px;
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
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ Secure File Manager</h1>
            <small>Enhanced Security • Activity Logging • Threat Protection</small>
        </div>
        <div class="user-info">
            <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
            <span class="role-badge"><?php echo strtoupper($_SESSION['role']); ?></span>
            <span class="security-indicator">🔒 SECURE</span>
            <button class="btn" onclick="logout()">🚪 Logout</button>
        </div>
    </div>

    <div class="container">
        <div class="security-banner">
            🛡️ <strong>Security Features Active:</strong> CSRF Protection • File Type Validation • Path Traversal Prevention • Activity Logging • Brute Force Protection
        </div>
        
        <?php if (!isAdmin()): ?>
        <div style="background: #fef3c7; color: #92400e; padding: 1rem; border-radius: 6px; margin-bottom: 1rem;">
            📋 <strong>Read-Only Access:</strong> You can browse, view, and download files only.
        </div>
        <?php endif; ?>
        
        <div class="toolbar">
            <input type="file" id="fileInput" style="display: none;" multiple>
            <button class="btn" onclick="document.getElementById('fileInput').click()" <?php echo !isAdmin() ? 'disabled' : ''; ?>>
                📁 Upload Files
            </button>
            <button class="btn" onclick="createFolder()" <?php echo !isAdmin() ? 'disabled' : ''; ?>>
                📂 New Folder
            </button>
            <button class="btn" onclick="refreshFiles()">🔄 Refresh</button>
        </div>

        <div style="background: white; padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
            <span id="breadcrumb">Loading...</span>
        </div>

        <div class="file-area">
            <div class="file-header">
                <div>Name</div>
                <div>Size</div>
                <div>Type</div>
                <div>Actions</div>
            </div>
            <div id="fileList" class="loading">
                Loading files...
            </div>
        </div>
    </div>

    <!-- File Viewer Modal -->
    <div id="fileViewerModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">File Viewer</h3>
                <button class="close" onclick="closeViewer()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="file-viewer">
                    <textarea id="textViewer" class="text-viewer" readonly style="display: none;"></textarea>
                    <iframe id="pdfViewer" class="pdf-viewer" style="display: none;" onload="handlePdfLoad()" onerror="handlePdfError()"></iframe>
                    <div id="imageViewer" class="image-viewer" style="display: none;">
                        <img id="imageDisplay" src="" alt="Image preview">
                    </div>
                    <div id="pdfError" style="display: none; text-align: center; padding: 2rem;">
                        <h3>📄 PDF Viewing Options</h3>
                        <p style="margin: 1rem 0; color: #64748b;">Choose how you'd like to view this PDF document:</p>
                        <button class="btn" onclick="openPdfInNewTab()" style="margin: 0.5rem;">📄 Open in New Tab</button>
                        <button class="btn" onclick="downloadCurrentFile()" style="margin: 0.5rem;">⬇️ Download PDF</button>
                        <p style="font-size: 0.9rem; color: #94a3b8; margin-top: 1rem;">
                            <em>Note: PDF viewing optimized for better compatibility across hosting environments</em>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentPath = '<?php echo $base_directory; ?>';
        let basePath = '<?php echo $base_directory; ?>';
        let isAdmin = <?php echo isAdmin() ? 'true' : 'false'; ?>;
        let csrfToken = '<?php echo $csrf_token; ?>';
        let currentPdfUrl = '';
        let currentFileName = '';
        
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
            document.getElementById('fileList').innerHTML = '<div class="loading">Loading files...</div>';
            
            try {
                const response = await fetch(`?action=list&path=${encodeURIComponent(path)}`);
                const data = await response.json();
                
                if (data.error) {
                    document.getElementById('fileList').innerHTML = `<div class="error">Error: ${data.error}</div>`;
                    return;
                }
                
                currentPath = data.current_path;
                isAdmin = data.is_admin;
                csrfToken = data.csrf_token;
                updateBreadcrumb();
                displayFiles(data.files);
                
            } catch (error) {
                document.getElementById('fileList').innerHTML = '<div class="error">Failed to load files - Network error</div>';
            }
        }
        
        function displayFiles(files) {
            const fileList = document.getElementById('fileList');
            let html = '';
            
            // Add parent directory if not at base
            if (currentPath !== basePath) {
                const parentPath = currentPath.substring(0, currentPath.lastIndexOf('/')) || basePath;
                html += `
                    <div class="file-row" onclick="loadFiles('${parentPath}')">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">📁 .. (Parent Directory)</div>
                        <div>-</div>
                        <div>Folder</div>
                        <div></div>
                    </div>
                `;
            }
            
            files.forEach(file => {
                const clickAction = file.is_dir ? `loadFiles('${file.path}')` : '';
                
                html += `
                    <div class="file-row" onclick="${clickAction}">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">${file.icon} ${file.name}</div>
                        <div>${file.size}</div>
                        <div>${file.is_dir ? 'Folder' : 'File'}</div>
                        <div>
                            ${file.viewable ? `<button class="action-btn view-btn" onclick="event.stopPropagation(); viewFile('${file.path}', '${file.name}')">View</button>` : ''}
                            <button class="action-btn download-btn" onclick="event.stopPropagation(); downloadFile('${file.path}', '${file.name}')">Download</button>
                            ${isAdmin && !file.is_dir ? `<button class="action-btn delete-btn" onclick="event.stopPropagation(); deleteFile('${file.path}')">Delete</button>` : ''}
                        </div>
                    </div>
                `;
            });
            
            fileList.innerHTML = html || '<div class="loading">No files found</div>';
        }
        
        function updateBreadcrumb() {
            const relativePath = currentPath.replace(basePath, '');
            const parts = relativePath.split('/').filter(part => part);
            let breadcrumbHTML = `<span onclick="loadFiles('${basePath}')" style="cursor: pointer; color: #667eea;">🏠 Home</span>`;
            
            let buildPath = basePath;
            parts.forEach((part, index) => {
                buildPath += '/' + part;
                if (index === parts.length - 1) {
                    breadcrumbHTML += ` / <strong>${part}</strong>`;
                } else {
                    breadcrumbHTML += ` / <span onclick="loadFiles('${buildPath}')" style="cursor: pointer; color: #667eea;">${part}</span>`;
                }
            });
            
            document.getElementById('breadcrumb').innerHTML = breadcrumbHTML;
        }
        
        async function deleteFile(filePath) {
            if (!isAdmin) {
                alert('Permission denied: Admin access required');
                return;
            }
            
            if (!confirm('Are you sure you want to delete this file?')) return;
            
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
                } else {
                    alert('Delete failed: ' + data.error);
                }
            } catch (error) {
                alert('Delete failed');
            }
        }
        
        function downloadFile(filePath, fileName) {
            const downloadUrl = `?action=download&file=${encodeURIComponent(filePath)}`;
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        async function viewFile(filePath, fileName) {
            try {
                const response = await fetch(`?action=view&file=${encodeURIComponent(filePath)}`);
                const data = await response.json();
                
                if (data.error) {
                    alert('View failed: ' + data.error);
                    return;
                }
                
                openViewer(data, fileName);
                
            } catch (error) {
                alert('Failed to load file for viewing');
            }
        }
        
        function openViewer(data, fileName) {
            const modal = document.getElementById('fileViewerModal');
            const modalTitle = document.getElementById('modalTitle');
            const textViewer = document.getElementById('textViewer');
            const pdfViewer = document.getElementById('pdfViewer');
            
            // Reset viewers
            textViewer.style.display = 'none';
            pdfViewer.style.display = 'none';
            
            modalTitle.textContent = fileName;
            
            if (data.type === 'text') {
                textViewer.value = data.content;
                textViewer.style.display = 'block';
                
                if (data.extension === 'json') {
                    try {
                        const formatted = JSON.stringify(JSON.parse(data.content), null, 2);
                        textViewer.value = formatted;
                    } catch (e) {
                        // Keep original if not valid JSON
                    }
                }
            } else if (data.type === 'pdf') {
                pdfViewer.src = data.url;
                pdfViewer.style.display = 'block';
            }
            
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        }
        
        function closeViewer() {
            const modal = document.getElementById('fileViewerModal');
            const pdfViewer = document.getElementById('pdfViewer');
            
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
            pdfViewer.src = '';
        }
        
        async function createFolder() {
            if (!isAdmin) {
                alert('Permission denied: Admin access required');
                return;
            }
            
            const folderName = prompt('Enter folder name:');
            if (!folderName) return;
            
            try {
                const formData = new FormData();
                formData.append('path', currentPath);
                formData.append('folder_name', folderName);
                formData.append('csrf_token', csrfToken);
                
                const response = await fetch('?action=create_folder', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (data.success) {
                    loadFiles(currentPath);
                } else {
                    alert('Failed to create folder: ' + data.error);
                }
            } catch (error) {
                alert('Failed to create folder');
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
        
        // File upload handling
        document.getElementById('fileInput').addEventListener('change', async function(e) {
            if (!isAdmin) {
                alert('Permission denied: Admin access required');
                return;
            }
            
            const files = e.target.files;
            if (files.length === 0) return;
            
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
                    if (!data.success) {
                        alert('Upload failed: ' + data.error);
                    }
                } catch (error) {
                    alert('Upload failed for: ' + file.name);
                }
            }
            
            loadFiles(currentPath);
            e.target.value = '';
        });
        
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
        
        // Initial load
        loadFiles();
    </script>
</body>
</html>
