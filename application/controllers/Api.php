<?php
defined('BASEPATH') or exit('No direct script access allowed');

// Ensure Composer autoload is loaded if present
if (file_exists(FCPATH . 'vendor/autoload.php')) {
    require_once FCPATH . 'vendor/autoload.php';
}

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

/**
 * WhatsApp-like 1-to-1 Chat Backend API Controller
 *
 * COMPLETE ENDPOINTS REFERENCE:
 * ---------------------------------------------------------------------------------------------------------------------
 * Method | Endpoint                   | Auth? | Parameters / Description
 * ---------------------------------------------------------------------------------------------------------------------
 * GET    | /api/install                | No    | None. Creates DB tables & upload folders.
 * POST   | /api/register               | No    | name, email|mobile (min 1 required), password (min 6).
 * POST   | /api/login                  | No    | login (email/mobile), password, [fcm_token], [device_info].
 * POST   | /api/logout                 | Yes   | [fcm_token]. Deletes device token and sets is_online = 0.
 * GET    | /api/profile                | Yes   | Returns authenticated user profile.
 * POST   | /api/update_profile         | Yes   | [name], [about], [email], [mobile], [password], [old_password].
 * POST   | /api/update_profile_image   | Yes   | image (multipart file: jpg/png/webp, max 2MB).
 * POST   | /api/save_token             | Yes   | fcm_token, [device_info].
 * GET    | /api/users                  | Yes   | Returns all users except current user with live status.
 * GET    | /api/conversations          | Yes   | Returns conversations with last message, unread count & partner info.
 * GET    | /api/messages               | Yes   | other_user_id | conversation_id, [after_id], [before_id], [limit].
 * POST   | /api/send_message           | Yes   | receiver_id, message_text.
 * POST   | /api/send_media             | Yes   | receiver_id, file (multipart: jpg/png/webp/mp4 <= 2MB), [caption].
 * POST   | /api/mark_read              | Yes   | other_user_id. Marks all messages from that user as read.
 * POST   | /api/heartbeat              | Yes   | Keeps online status active and updates last_seen timestamp.
 * GET    | /api/user_status            | Yes   | other_user_id. Returns live is_online and last_seen.
 * ---------------------------------------------------------------------------------------------------------------------
 */
class Api extends CI_Controller
{
    // =========================================================================
    // CONFIGURATION CONSTANTS
    // =========================================================================
    // Cryptographically secure 256-bit (32-byte / 64-hex) secret key for HS256 JWT tokens.
    // Can also be set/overridden in production via the JWT_SECRET environment variable.
    const JWT_SECRET               = 'f26f33cb5fcdf5eb5c0a14b296f9622639cf9ebcfb13c5ea9d3cc9d9a3ffd9a7';
    // Permanent session: 100 years expiry (36500 days) so users stay permanently logged in like WhatsApp/Telegram
    const JWT_EXPIRY_DAYS          = 36500;
    const FCM_PROJECT_ID           = 'chat-app-test-4bbab';
    // Service account filename or relative path.
    // Dynamic resolution in get_fcm_service_account_path() works across local XAMPP and live production servers.
    const FCM_SERVICE_ACCOUNT_PATH = 'firebase-service-account.json';
    const MAX_UPLOAD_BYTES         = 2097152; // 2MB
    const UPLOAD_PROFILE_DIR       = 'uploads/profile/';
    const UPLOAD_CHAT_DIR          = 'uploads/chat/';

    /**
     * Constructor
     */
    public function __construct()
    {
        parent::__construct();

        // Load built-in CodeIgniter database & URL helper
        $this->load->database();
        $this->load->helper('url');

        // Handle CORS headers and OPTIONS preflight
        $this->handle_cors();

        // Ensure upload directories and index protection exist
        $this->ensure_directories();

        // Ensure database schema migrations exist
        $this->ensure_schema();
    }

    // =========================================================================
    // 1. SYSTEM & INSTALLATION
    // =========================================================================

    /**
     * GET api/install
     * Verifies storage directories and checks database connectivity/tables.
     */
    public function install()
    {
        $this->ensure_directories();

        $required_tables = ['users', 'device_tokens', 'conversations', 'messages', 'notification_logs'];
        $existing_tables = $this->db->list_tables();
        $missing         = array_values(array_diff($required_tables, $existing_tables));

        if (!empty($missing)) {
            $this->response(false, 'Database tables missing. Please run the SQL schema in MySQL/phpMyAdmin.', [
                'missing_tables'  => $missing,
                'existing_tables' => $existing_tables
            ], 422);
        }

        $this->response(true, 'Database connection and storage directories verified successfully', [
            'tables' => $existing_tables
        ], 200);
    }

    // =========================================================================
    // 2. AUTHENTICATION ENDPOINTS
    // =========================================================================

    /**
     * POST api/register
     * Register a new user and generate a JWT token.
     */
    public function register()
    {
        $name        = $this->get_input('name');
        $email       = $this->get_input('email');
        $mobile      = $this->get_input('mobile');
        $password    = $this->get_input('password');
        $fcm_token   = $this->get_input('fcm_token');
        $device_info = $this->get_input('device_info');

        if (empty($name)) {
            $this->response(false, 'Name is required', null, 422);
        }

        if (empty($email) && empty($mobile)) {
            $this->response(false, 'At least one contact method (email or mobile) is required', null, 422);
        }

        if (!empty($email)) {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->response(false, 'Invalid email format', null, 422);
            }
            $count = $this->db->where('email', $email)->count_all_results('users');
            if ($count > 0) {
                $this->response(false, 'Email is already registered', null, 422);
            }
        }

        if (!empty($mobile)) {
            if (!preg_match('/^[0-9+\-\s()]{7,25}$/', $mobile)) {
                $this->response(false, 'Invalid mobile number format', null, 422);
            }
            $count = $this->db->where('mobile', $mobile)->count_all_results('users');
            if ($count > 0) {
                $this->response(false, 'Mobile number is already registered', null, 422);
            }
        }

        if (empty($password) || strlen($password) < 6) {
            $this->response(false, 'Password must be at least 6 characters long', null, 422);
        }

        $now = date('Y-m-d H:i:s');
        $user_data = [
            'name'          => $name,
            'email'         => !empty($email) ? strtolower($email) : null,
            'mobile'        => !empty($mobile) ? $mobile : null,
            'password_hash' => password_hash($password, PASSWORD_BCRYPT),
            'profile_image' => null,
            'about'         => 'Hey there! I am using this app',
            'last_seen'     => $now,
            'is_online'     => 1,
            'created_at'    => $now,
            'updated_at'    => $now
        ];

        $this->db->insert('users', $user_data);
        $user_id = $this->db->insert_id();

        if (!$user_id) {
            $this->response(false, 'Registration failed. Could not create account.', null, 500);
        }

        $user = $this->db->where('id', $user_id)->get('users')->row_array();
        $token = $this->generate_jwt($user_id);

        // Automatically save FCM device token if provided during registration
        if (!empty($fcm_token)) {
            $this->db->where('fcm_token', $fcm_token)->delete('device_tokens');
            $this->db->insert('device_tokens', [
                'user_id'     => $user_id,
                'fcm_token'   => $fcm_token,
                'device_info' => $device_info ?: null,
                'updated_at'  => $now
            ]);
        }

        // Notify other active devices that a new user joined
        $this->broadcast_fcm_notification($user_id, 'New Contact', "{$name} joined", [
            'type'      => 'new_user',
            'user_id'   => (string)$user_id,
            'user_name' => $name
        ]);

        $this->response(true, 'User registered successfully', [
            'user'                 => $this->format_user($user),
            'token'                => $token,
            'fcm_token_registered' => !empty($fcm_token)
        ], 201);
    }

    /**
     * POST api/login
     * Login via email or mobile and issue a JWT token.
     */
    public function login()
    {
        $login       = $this->get_input('login');
        $password    = $this->get_input('password');
        $fcm_token   = $this->get_input('fcm_token');
        $device_info = $this->get_input('device_info');

        if (empty($login) || empty($password)) {
            $this->response(false, 'Login identifier and password are required', null, 422);
        }

        // Auto-detect login identifier: check email or mobile
        $user = $this->db->group_start()
            ->where('email', strtolower($login))
            ->or_where('mobile', $login)
            ->group_end()
            ->get('users')
            ->row_array();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            $this->response(false, 'Invalid login credentials', null, 401);
        }

        $now = date('Y-m-d H:i:s');
        $this->db->where('id', $user['id'])->update('users', [
            'is_online' => 1,
            'last_seen' => $now
        ]);

        // Save FCM token if provided (token belongs to only one user at a time)
        if (!empty($fcm_token)) {
            $this->db->where('fcm_token', $fcm_token)->delete('device_tokens');
            $this->db->insert('device_tokens', [
                'user_id'     => $user['id'],
                'fcm_token'   => $fcm_token,
                'device_info' => $device_info ?: null,
                'updated_at'  => $now
            ]);
        }

        $token = $this->generate_jwt($user['id']);

        $user['is_online'] = 1;
        $user['last_seen'] = $now;

        $this->response(true, 'Login successful', [
            'user'                 => $this->format_user($user),
            'token'                => $token,
            'fcm_token_registered' => !empty($fcm_token)
        ], 200);
    }

    /**
     * POST api/logout
     * Unregisters device token and sets is_online = 0.
     */
    public function logout()
    {
        $user = $this->authenticate();
        $fcm_token = $this->get_input('fcm_token');

        if (!empty($fcm_token)) {
            $this->db->where('user_id', $user['id'])
                ->where('fcm_token', $fcm_token)
                ->delete('device_tokens');
        } else {
            // If no specific token passed, clear all device tokens for this user
            $this->db->where('user_id', $user['id'])->delete('device_tokens');
        }

        $this->db->where('id', $user['id'])->update('users', [
            'is_online' => 0,
            'last_seen' => date('Y-m-d H:i:s')
        ]);

        $this->response(true, 'Logged out successfully', null, 200);
    }

    /**
     * POST api/change_password
     * Authenticated endpoint to change the current user's password.
     * Parameters: old_password, new_password, [confirm_password]
     */
    public function change_password()
    {
        $user             = $this->authenticate();
        $old_password     = $this->get_input('old_password');
        $new_password     = $this->get_input('new_password');
        $confirm_password = $this->get_input('confirm_password');

        if (empty($old_password)) {
            $this->response(false, 'Current password is required', null, 422);
        }

        if (!password_verify($old_password, $user['password_hash'])) {
            $this->response(false, 'Current password is incorrect', null, 400);
        }

        if (empty($new_password) || strlen($new_password) < 6) {
            $this->response(false, 'New password must be at least 6 characters long', null, 422);
        }

        if ($old_password === $new_password) {
            $this->response(false, 'New password must be different from current password', null, 400);
        }

        if ($confirm_password !== null && $confirm_password !== '' && $confirm_password !== $new_password) {
            $this->response(false, 'New password and confirmation do not match', null, 422);
        }

        $now = date('Y-m-d H:i:s');
        $this->db->where('id', $user['id'])->update('users', [
            'password_hash' => password_hash($new_password, PASSWORD_BCRYPT),
            'updated_at'    => $now
        ]);

        $this->response(true, 'Password changed successfully', [
            'user_id'    => (int)$user['id'],
            'updated_at' => $now
        ], 200);
    }

    /**
     * POST api/forgot_password
     * Resets user password by email or mobile.
     */
    public function forgot_password()
    {
        $login        = $this->get_input('login');
        $new_password = $this->get_input('new_password');

        if (empty($login)) {
            $this->response(false, 'Email or mobile number is required', null, 422);
        }

        if (empty($new_password) || strlen($new_password) < 6) {
            $this->response(false, 'New password must be at least 6 characters long', null, 422);
        }

        $user = $this->db->group_start()
            ->where('email', strtolower($login))
            ->or_where('mobile', $login)
            ->group_end()
            ->get('users')
            ->row_array();

        if (!$user) {
            $this->response(false, 'No user found with the provided email or mobile number', null, 404);
        }

        $this->db->where('id', $user['id'])->update('users', [
            'password_hash' => password_hash($new_password, PASSWORD_BCRYPT),
            'updated_at'    => date('Y-m-d H:i:s')
        ]);

        $this->response(true, 'Password has been reset successfully. Please login with your new password.', [
            'user_id' => (int)$user['id']
        ], 200);
    }

    // =========================================================================
    // 3. PROFILE & DEVICE MANAGEMENT
    // =========================================================================

    /**
     * GET api/profile
     * Returns authenticated user profile.
     */
    public function profile()
    {
        $user = $this->authenticate();
        $this->response(true, 'Profile retrieved successfully', [
            'user' => $this->format_user($user)
        ], 200);
    }

    /**
     * POST api/update_profile
     * Updates name, about, email, mobile, and optionally password.
     */
    public function update_profile()
    {
        $user = $this->authenticate();

        $name         = $this->get_input('name');
        $about        = $this->get_input('about');
        $email        = $this->get_input('email');
        $mobile       = $this->get_input('mobile');
        $password     = $this->get_input('password');
        $old_password = $this->get_input('old_password');

        $updates = [];

        if ($name !== null) {
            if (empty($name)) {
                $this->response(false, 'Name cannot be empty', null, 422);
            }
            $updates['name'] = $name;
        }

        if ($about !== null) {
            $updates['about'] = substr($about, 0, 255);
        }

        if ($email !== null && strtolower($email) !== strtolower((string)$user['email'])) {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->response(false, 'Invalid email format', null, 422);
            }
            $exists = $this->db->where('email', strtolower($email))
                ->where('id !=', $user['id'])
                ->count_all_results('users');
            if ($exists > 0) {
                $this->response(false, 'Email is already taken by another account', null, 422);
            }
            $updates['email'] = strtolower($email);
        }

        if ($mobile !== null && $mobile !== (string)$user['mobile']) {
            if (!preg_match('/^[0-9+\-\s()]{7,25}$/', $mobile)) {
                $this->response(false, 'Invalid mobile number format', null, 422);
            }
            $exists = $this->db->where('mobile', $mobile)
                ->where('id !=', $user['id'])
                ->count_all_results('users');
            if ($exists > 0) {
                $this->response(false, 'Mobile number is already taken by another account', null, 422);
            }
            $updates['mobile'] = $mobile;
        }

        if ($password !== null) {
            if (empty($old_password) || !password_verify($old_password, $user['password_hash'])) {
                $this->response(false, 'Current password is required and must be correct to set a new password', null, 400);
            }
            if (strlen($password) < 6) {
                $this->response(false, 'New password must be at least 6 characters long', null, 422);
            }
            $updates['password_hash'] = password_hash($password, PASSWORD_BCRYPT);
        }

        if (!empty($updates)) {
            $updates['updated_at'] = date('Y-m-d H:i:s');
            $this->db->where('id', $user['id'])->update('users', $updates);
            $user = $this->db->where('id', $user['id'])->get('users')->row_array();
        }

        $this->response(true, 'Profile updated successfully', [
            'user' => $this->format_user($user)
        ], 200);
    }

    /**
     * POST api/update_profile_image
     * Uploads avatar (jpg/png/webp <= 2MB), deletes old file, returns full URL.
     */
    public function update_profile_image()
    {
        $user = $this->authenticate();

        if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
            $this->response(false, 'Please select a valid image file to upload', null, 422);
        }

        if ($_FILES['image']['size'] > self::MAX_UPLOAD_BYTES) {
            $this->response(false, 'Profile image must not exceed 2MB', null, 422);
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime  = $finfo->file($_FILES['image']['tmp_name']);

        $allowed_mimes = [
            'image/jpeg'  => 'jpg',
            'image/pjpeg' => 'jpg',
            'image/png'   => 'png',
            'image/webp'  => 'webp'
        ];

        if (!isset($allowed_mimes[$mime])) {
            $this->response(false, 'Invalid image format. Allowed formats: JPG, PNG, WEBP', null, 422);
        }

        $extension = $allowed_mimes[$mime];
        $filename  = bin2hex(random_bytes(16)) . '.' . $extension;
        $target    = FCPATH . self::UPLOAD_PROFILE_DIR . $filename;

        // Delete old profile image if it exists in the uploads directory
        if (!empty($user['profile_image'])) {
            $old_path = FCPATH . ltrim($user['profile_image'], '/');
            if (file_exists($old_path) && is_file($old_path)) {
                $real_dir = realpath(FCPATH . self::UPLOAD_PROFILE_DIR);
                $real_old = realpath($old_path);
                if ($real_dir && $real_old && strpos($real_old, $real_dir) === 0) {
                    @unlink($real_old);
                }
            }
        }

        if (!move_uploaded_file($_FILES['image']['tmp_name'], $target)) {
            $this->response(false, 'Failed to save uploaded image to disk', null, 500);
        }

        $rel_path = self::UPLOAD_PROFILE_DIR . $filename;
        $this->db->where('id', $user['id'])->update('users', [
            'profile_image' => $rel_path,
            'updated_at'    => date('Y-m-d H:i:s')
        ]);

        $user['profile_image'] = $rel_path;

        $this->response(true, 'Profile image updated successfully', [
            'profile_image' => base_url($rel_path),
            'user'          => $this->format_user($user)
        ], 200);
    }

    /**
     * POST api/save_token
     * Register or update an FCM device token.
     */
    public function save_token()
    {

        $user        = $this->authenticate();
        $fcm_token   = $this->get_input('fcm_token');
        $device_info = $this->get_input('device_info');

        if (empty($fcm_token)) {
            $this->response(false, 'FCM token is required', null, 422);
        }

        $now = date('Y-m-d H:i:s');
        // Ensure a token belongs to only one user at a time
        $this->db->where('fcm_token', $fcm_token)->delete('device_tokens');
        $this->db->insert('device_tokens', [
            'user_id'     => $user['id'],
            'fcm_token'   => $fcm_token,
            'device_info' => $device_info ?: null,
            'updated_at'  => $now
        ]);

        $this->response(true, 'Device token registered successfully', [
            'fcm_token' => $fcm_token
        ], 200);
    }

    /**
     * GET api/check_device_token
     * Check if current user has an FCM device token registered.
     */
    public function check_device_token()
    {
        $user   = $this->authenticate();
        $tokens = $this->db->select('id, fcm_token, device_info, updated_at')
            ->where('user_id', $user['id'])
            ->get('device_tokens')
            ->result_array();

        $this->response(true, 'Device tokens status', [
            'has_token' => !empty($tokens),
            'count'     => count($tokens),
            'tokens'    => $tokens
        ], 200);
    }

    // =========================================================================
    // 4. USERS & CHAT ENDPOINTS
    // =========================================================================

    /**
     * GET api/users
     * Returns all other users with active status.
     */
    public function users()
    {
        $current_user = $this->authenticate();

        $users = $this->db->select('id, name, profile_image, about, last_seen, is_online')
            ->where('id !=', $current_user['id'])
            ->order_by('name', 'ASC')
            ->get('users')
            ->result_array();

        $formatted = [];
        foreach ($users as $u) {
            $formatted[] = $this->format_user($u);
        }

        $this->response(true, 'Users retrieved successfully', [
            'users' => $formatted
        ], 200);
    }

    /**
     * GET api/conversations
     * Returns all conversations ordered by recent activity with unread counts.
     */
    public function conversations()
    {
        $current_user = $this->authenticate();
        $my_id = (int)$current_user['id'];

        $sql = "SELECT c.id AS conversation_id, c.user1_id, c.user2_id, c.last_message_id, c.updated_at,
                       u.id AS partner_id, u.name AS partner_name, u.email AS partner_email,
                       u.mobile AS partner_mobile, u.profile_image AS partner_profile_image,
                       u.about AS partner_about, u.last_seen AS partner_last_seen, u.is_online AS partner_is_online,
                       m.id AS msg_id, m.sender_id AS msg_sender_id, m.receiver_id AS msg_receiver_id,
                       m.message_type AS msg_type, m.message_text AS msg_text, m.media_url AS msg_media_url,
                       m.media_size AS msg_media_size, m.status AS msg_status, m.created_at AS msg_created_at,
                       m.is_edited AS msg_is_edited, m.is_deleted AS msg_is_deleted,
                       m.deleted_by_sender AS msg_deleted_by_sender, m.deleted_by_receiver AS msg_deleted_by_receiver,
                       (SELECT COUNT(*) FROM messages msg 
                        WHERE msg.conversation_id = c.id 
                          AND msg.receiver_id = ? 
                          AND msg.status != 'read') AS unread_count
                FROM conversations c
                INNER JOIN users u ON u.id = IF(c.user1_id = ?, c.user2_id, c.user1_id)
                LEFT JOIN messages m ON m.id = c.last_message_id
                WHERE c.user1_id = ? OR c.user2_id = ?
                ORDER BY c.updated_at DESC";

        $rows = $this->db->query($sql, [$my_id, $my_id, $my_id, $my_id])->result_array();

        $list = [];
        foreach ($rows as $r) {
            $partner_online = (int)$r['partner_is_online'];
            if ($partner_online === 1 && !empty($r['partner_last_seen'])) {
                if ((time() - strtotime($r['partner_last_seen'])) > 60) {
                    $partner_online = 0;
                }
            }

            $partner = [
                'id'            => (int)$r['partner_id'],
                'name'          => $r['partner_name'],
                'email'         => $r['partner_email'],
                'mobile'        => $r['partner_mobile'],
                'profile_image' => !empty($r['partner_profile_image']) ? base_url($r['partner_profile_image']) : null,
                'about'         => $r['partner_about'],
                'last_seen'     => $r['partner_last_seen'],
                'is_online'     => $partner_online
            ];

            $last_message = null;
            if (!empty($r['msg_id'])) {
                $is_msg_deleted = !empty($r['msg_is_deleted']);
                $deleted_for_me = ((int)$r['msg_sender_id'] === $my_id && !empty($r['msg_deleted_by_sender'])) ||
                    ((int)$r['msg_receiver_id'] === $my_id && !empty($r['msg_deleted_by_receiver']));

                if (!$deleted_for_me) {
                    $last_message = [
                        'id'           => (int)$r['msg_id'],
                        'sender_id'    => (int)$r['msg_sender_id'],
                        'receiver_id'  => (int)$r['msg_receiver_id'],
                        'message_type' => $r['msg_type'],
                        'message_text' => $is_msg_deleted ? 'This message was deleted' : $r['msg_text'],
                        'media_url'    => ($is_msg_deleted || empty($r['msg_media_url'])) ? null : base_url($r['msg_media_url']),
                        'media_size'   => $is_msg_deleted ? 0 : (int)$r['msg_media_size'],
                        'status'       => $r['msg_status'],
                        'created_at'   => $r['msg_created_at'],
                        'is_edited'    => (bool)(!empty($r['msg_is_edited']) && !$is_msg_deleted),
                        'is_deleted'   => (bool)$is_msg_deleted
                    ];
                }
            }

            $list[] = [
                'id'           => (int)$r['conversation_id'],
                'partner'      => $partner,
                'last_message' => $last_message,
                'unread_count' => (int)$r['unread_count'],
                'updated_at'   => $r['updated_at']
            ];
        }

        $this->response(true, 'Conversations retrieved successfully', [
            'conversations' => $list
        ], 200);
    }

    /**
     * GET api/messages
     * Fetches messages in ascending order. Marks newly fetched 'sent' messages as 'delivered'.
     */
    public function messages()
    {
        $current_user = $this->authenticate();
        $my_id = (int)$current_user['id'];

        $conversation_id = $this->get_input('conversation_id');
        $other_user_id   = $this->get_input('other_user_id');
        $after_id        = (int)$this->get_input('after_id', 0);
        $before_id       = (int)$this->get_input('before_id', 0);
        $limit           = (int)$this->get_input('limit', 50);

        if ($limit <= 0 || $limit > 100) {
            $limit = 50;
        }

        $conv_id = null;
        if (!empty($conversation_id)) {
            $conv = $this->db->where('id', (int)$conversation_id)->get('conversations')->row_array();
            if (!$conv || ($conv['user1_id'] != $my_id && $conv['user2_id'] != $my_id)) {
                $this->response(false, 'Conversation not found or access denied', null, 404);
            }
            $conv_id = (int)$conv['id'];
        } elseif (!empty($other_user_id)) {
            $other_id = (int)$other_user_id;
            $u1 = min($my_id, $other_id);
            $u2 = max($my_id, $other_id);
            $conv = $this->db->where('user1_id', $u1)->where('user2_id', $u2)->get('conversations')->row_array();
            if (!$conv) {
                $this->response(true, 'No messages found', [
                    'conversation_id' => null,
                    'messages'        => []
                ], 200);
            }
            $conv_id = (int)$conv['id'];
        } else {
            $this->response(false, 'Either other_user_id or conversation_id is required', null, 422);
        }

        // When fetching messages sent to me that are 'sent', mark them 'delivered'
        $this->db->where('conversation_id', $conv_id)
            ->where('receiver_id', $my_id)
            ->where('status', 'sent')
            ->update('messages', ['status' => 'delivered']);

        $this->db->where('conversation_id', $conv_id);

        // Exclude messages deleted by current user for "me"
        $this->db->group_start()
            ->where("(sender_id = {$my_id} AND (deleted_by_sender IS NULL OR deleted_by_sender = 0))")
            ->or_where("(receiver_id = {$my_id} AND (deleted_by_receiver IS NULL OR deleted_by_receiver = 0))")
            ->group_end();

        if ($after_id > 0) {
            // Polling forward for new messages
            $this->db->where('id >', $after_id);
            $this->db->order_by('id', 'ASC');
            $this->db->limit($limit);
            $raw_messages = $this->db->get('messages')->result_array();
        } elseif ($before_id > 0) {
            // Pagination scrolling backwards
            $this->db->where('id <', $before_id);
            $this->db->order_by('id', 'DESC');
            $this->db->limit($limit);
            $raw_messages = array_reverse($this->db->get('messages')->result_array());
        } else {
            // Default: most recent messages in ascending order
            $this->db->order_by('id', 'DESC');
            $this->db->limit($limit);
            $raw_messages = array_reverse($this->db->get('messages')->result_array());
        }

        $formatted = [];
        foreach ($raw_messages as $m) {
            $is_del = !empty($m['is_deleted']);
            $is_edt = !empty($m['is_edited']) && !$is_del;
            $formatted[] = [
                'id'              => (int)$m['id'],
                'conversation_id' => (int)$m['conversation_id'],
                'sender_id'       => (int)$m['sender_id'],
                'receiver_id'     => (int)$m['receiver_id'],
                'message_type'    => $m['message_type'],
                'message_text'    => $is_del ? 'This message was deleted' : $m['message_text'],
                'media_url'       => ($is_del || empty($m['media_url'])) ? null : base_url($m['media_url']),
                'media_size'      => $is_del ? 0 : (int)$m['media_size'],
                'status'          => $m['status'],
                'created_at'      => $m['created_at'],
                'is_edited'       => (bool)$is_edt,
                'edited_at'       => $m['edited_at'] ?? null,
                'is_deleted'      => (bool)$is_del
            ];
        }

        $this->response(true, 'Messages retrieved successfully', [
            'conversation_id' => $conv_id,
            'messages'        => $formatted
        ], 200);
    }

    /**
     * POST api/send_message
     * Sends a text message, auto-creates the conversation, and sends an FCM push.
     */
    public function send_message()
    {
        $current_user = $this->authenticate();
        $sender_id    = (int)$current_user['id'];
        $receiver_id  = (int)$this->get_input('receiver_id');
        $message_text = (string)$this->get_input('message_text');

        if (empty($receiver_id)) {
            $this->response(false, 'receiver_id is required', null, 422);
        }

        if ($receiver_id === $sender_id) {
            $this->response(false, 'You cannot send a message to yourself', null, 400);
        }

        if ($message_text === '') {
            $this->response(false, 'message_text cannot be empty', null, 422);
        }

        // Validate receiver existence
        $receiver = $this->db->select('id')->where('id', $receiver_id)->get('users')->row_array();
        if (!$receiver) {
            $this->response(false, 'Recipient user not found', null, 404);
        }

        $conv_id = $this->get_or_create_conversation($sender_id, $receiver_id);
        $now     = date('Y-m-d H:i:s');

        // Multi-step DB transaction
        $this->db->trans_start();

        $msg_data = [
            'conversation_id' => $conv_id,
            'sender_id'       => $sender_id,
            'receiver_id'     => $receiver_id,
            'message_type'    => 'text',
            'message_text'    => $message_text,
            'media_url'       => null,
            'media_size'      => 0,
            'status'          => 'sent',
            'created_at'      => $now
        ];
        $this->db->insert('messages', $msg_data);
        $message_id = $this->db->insert_id();

        $this->db->where('id', $conv_id)->update('conversations', [
            'last_message_id' => $message_id,
            'updated_at'      => $now
        ]);

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
            $this->response(false, 'Failed to save message', null, 500);
        }

        $msg_data['id'] = (int)$message_id;

        // Dispatch FCM push notification
        $sender_avatar = !empty($current_user['avatar']) ? (string)$current_user['avatar'] : '';
        $this->send_fcm_notification($receiver_id, $current_user['name'], $message_text, [
            'type'            => 'chat',
            'conversation_id' => (string)$conv_id,
            'sender_id'       => (string)$sender_id,
            'sender_name'     => (string)$current_user['name'],
            'sender_avatar'   => $sender_avatar,
            'msg_type'        => 'text',
            'message_id'      => (string)$message_id
        ]);

        $this->response(true, 'Message sent successfully', [
            'message' => $msg_data
        ], 201);
    }

    /**
     * POST api/send_media
     * Uploads media (jpg/png/webp/mp4 <= 2MB), sends message, and triggers FCM.
     */
    public function send_media()
    {
        $current_user = $this->authenticate();
        $sender_id    = (int)$current_user['id'];
        $receiver_id  = (int)$this->get_input('receiver_id');
        $caption      = (string)$this->get_input('caption', '');

        if (empty($receiver_id)) {
            $this->response(false, 'receiver_id is required', null, 422);
        }

        if ($receiver_id === $sender_id) {
            $this->response(false, 'You cannot send media to yourself', null, 400);
        }

        $receiver = $this->db->select('id')->where('id', $receiver_id)->get('users')->row_array();
        if (!$receiver) {
            $this->response(false, 'Recipient user not found', null, 404);
        }

        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            $this->response(false, 'Please select a valid file to upload', null, 422);
        }

        $file_size = (int)$_FILES['file']['size'];
        if ($file_size > self::MAX_UPLOAD_BYTES) {
            $this->response(false, 'Media file exceeds maximum allowed size of 2MB', null, 422);
        }

        // Verify true MIME type using finfo
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime  = $finfo->file($_FILES['file']['tmp_name']);

        $allowed_mimes = [
            'image/jpeg'  => ['ext' => 'jpg', 'type' => 'image'],
            'image/pjpeg' => ['ext' => 'jpg', 'type' => 'image'],
            'image/png'   => ['ext' => 'png', 'type' => 'image'],
            'image/webp'  => ['ext' => 'webp', 'type' => 'image'],
            'video/mp4'   => ['ext' => 'mp4', 'type' => 'video']
        ];

        if (!isset($allowed_mimes[$mime])) {
            $this->response(false, 'Invalid file format. Allowed: JPG, PNG, WEBP, MP4', null, 422);
        }

        $meta         = $allowed_mimes[$mime];
        $msg_type     = $meta['type'];
        $filename     = bin2hex(random_bytes(16)) . '.' . $meta['ext'];
        $target_path  = FCPATH . self::UPLOAD_CHAT_DIR . $filename;

        if (!move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) {
            $this->response(false, 'Failed to save media file to server disk', null, 500);
        }

        $rel_media_url = self::UPLOAD_CHAT_DIR . $filename;
        $full_media_url = base_url($rel_media_url);

        $conv_id = $this->get_or_create_conversation($sender_id, $receiver_id);
        $now     = date('Y-m-d H:i:s');

        // Multi-step DB transaction
        $this->db->trans_start();

        $msg_data = [
            'conversation_id' => $conv_id,
            'sender_id'       => $sender_id,
            'receiver_id'     => $receiver_id,
            'message_type'    => $msg_type,
            'message_text'    => $caption !== '' ? $caption : null,
            'media_url'       => $rel_media_url,
            'media_size'      => $file_size,
            'status'          => 'sent',
            'created_at'      => $now
        ];
        $this->db->insert('messages', $msg_data);
        $message_id = $this->db->insert_id();

        $this->db->where('id', $conv_id)->update('conversations', [
            'last_message_id' => $message_id,
            'updated_at'      => $now
        ]);

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
            $this->response(false, 'Failed to record media message', null, 500);
        }

        $msg_data['id'] = (int)$message_id;
        $msg_data['media_url'] = $full_media_url;

        // Push notification body is "📷 Photo" or "🎥 Video"
        $push_body = ($msg_type === 'image') ? '📷 Photo' : '🎥 Video';
        if (!empty($caption)) {
            $push_body .= ': ' . $caption;
        }

        $sender_avatar = !empty($current_user['avatar']) ? (string)$current_user['avatar'] : '';
        $this->send_fcm_notification($receiver_id, $current_user['name'], $push_body, [
            'type'            => 'chat',
            'conversation_id' => (string)$conv_id,
            'sender_id'       => (string)$sender_id,
            'sender_name'     => (string)$current_user['name'],
            'sender_avatar'   => $sender_avatar,
            'msg_type'        => $msg_type,
            'message_id'      => (string)$message_id
        ]);

        $this->response(true, 'Media sent successfully', [
            'message'   => $msg_data,
            'media_url' => $full_media_url
        ], 201);
    }

    /**
     * POST api/mark_read
     * Sets all messages from other_user to me as "read".
     */
    public function mark_read()
    {
        $current_user  = $this->authenticate();
        $my_id         = (int)$current_user['id'];
        $other_user_id = (int)$this->get_input('other_user_id');

        if (empty($other_user_id)) {
            $this->response(false, 'other_user_id is required', null, 422);
        }

        $this->db->where('sender_id', $other_user_id)
            ->where('receiver_id', $my_id)
            ->where('status !=', 'read')
            ->update('messages', ['status' => 'read']);

        $affected = $this->db->affected_rows();

        $this->response(true, 'Messages marked as read', [
            'marked_count' => (int)$affected
        ], 200);
    }

    /**
     * POST api/edit_message
     * Edit text content of an existing message sent by current user.
     * Parameters: message_id (int), message_text (string)
     */
    public function edit_message()
    {
        $this->ensure_schema();
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $message_id   = (int)$this->get_input('message_id');
        $message_text = trim((string)$this->get_input('message_text'));

        if (empty($message_id)) {
            $this->response(false, 'message_id is required', null, 422);
        }

        if ($message_text === '') {
            $this->response(false, 'message_text cannot be empty', null, 422);
        }

        $msg = $this->db->where('id', $message_id)->get('messages')->row_array();
        if (!$msg) {
            $this->response(false, 'Message not found', null, 404);
        }

        if ((int)$msg['sender_id'] !== $my_id) {
            $this->response(false, 'You can only edit your own messages', null, 403);
        }

        if (!empty($msg['is_deleted'])) {
            $this->response(false, 'Deleted messages cannot be edited', null, 400);
        }

        if ($msg['message_type'] !== 'text') {
            $this->response(false, 'Only text messages can be edited', null, 400);
        }

        $now = date('Y-m-d H:i:s');
        $this->db->where('id', $message_id)->update('messages', [
            'message_text' => $message_text,
            'is_edited'    => 1,
            'edited_at'    => $now
        ]);

        $updated_msg = $this->db->where('id', $message_id)->get('messages')->row_array();

        $formatted = [
            'id'              => (int)$updated_msg['id'],
            'conversation_id' => (int)$updated_msg['conversation_id'],
            'sender_id'       => (int)$updated_msg['sender_id'],
            'receiver_id'     => (int)$updated_msg['receiver_id'],
            'message_type'    => $updated_msg['message_type'],
            'message_text'    => $updated_msg['message_text'],
            'media_url'       => !empty($updated_msg['media_url']) ? base_url($updated_msg['media_url']) : null,
            'media_size'      => (int)$updated_msg['media_size'],
            'status'          => $updated_msg['status'],
            'created_at'      => $updated_msg['created_at'],
            'is_edited'       => true,
            'edited_at'       => $updated_msg['edited_at'],
            'is_deleted'      => false
        ];

        $this->response(true, 'Message updated successfully', [
            'message' => $formatted
        ], 200);
    }

    /**
     * POST api/delete_message
     * Deletes a message either for everyone (sender only) or for me.
     * Parameters: message_id (int), delete_type ('everyone' | 'me')
     */
    public function delete_message()
    {
        $this->ensure_schema();
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $message_id   = (int)$this->get_input('message_id');
        $delete_type  = strtolower(trim((string)$this->get_input('delete_type', 'everyone')));

        if (empty($message_id)) {
            $this->response(false, 'message_id is required', null, 422);
        }

        $msg = $this->db->where('id', $message_id)->get('messages')->row_array();
        if (!$msg) {
            $this->response(false, 'Message not found', null, 404);
        }

        $is_sender   = ((int)$msg['sender_id'] === $my_id);
        $is_receiver = ((int)$msg['receiver_id'] === $my_id);

        if (!$is_sender && !$is_receiver) {
            $this->response(false, 'Access denied', null, 403);
        }

        if ($delete_type === 'everyone') {
            if (!$is_sender) {
                $this->response(false, 'Only the sender can delete a message for everyone', null, 403);
            }

            $this->db->where('id', $message_id)->update('messages', [
                'is_deleted'   => 1,
                'message_text' => 'This message was deleted',
                'media_url'    => null,
                'media_size'   => 0
            ]);

            $this->response(true, 'Message deleted for everyone', [
                'message_id'  => $message_id,
                'delete_type' => 'everyone'
            ], 200);
        } else {
            // Delete for me
            if ($is_sender) {
                $this->db->where('id', $message_id)->update('messages', ['deleted_by_sender' => 1]);
            } else {
                $this->db->where('id', $message_id)->update('messages', ['deleted_by_receiver' => 1]);
            }

            $this->response(true, 'Message deleted for you', [
                'message_id'  => $message_id,
                'delete_type' => 'me'
            ], 200);
        }
    }

    /**
     * POST api/heartbeat
     * Updates last_seen timestamp and marks is_online = 1.
     */
    public function heartbeat()
    {
        $current_user = $this->authenticate();
        $now = date('Y-m-d H:i:s');

        $this->db->where('id', $current_user['id'])->update('users', [
            'last_seen' => $now,
            'is_online' => 1
        ]);

        $this->response(true, 'Heartbeat recorded', [
            'is_online' => 1,
            'last_seen' => $now
        ], 200);
    }

    /**
     * GET api/user_status
     * Returns real-time online status and last_seen of another user.
     */
    public function user_status()
    {
        $this->authenticate();
        $other_user_id = (int)$this->get_input('other_user_id');

        if (empty($other_user_id)) {
            $this->response(false, 'other_user_id is required', null, 422);
        }

        $target = $this->db->select('id, last_seen, is_online')
            ->where('id', $other_user_id)
            ->get('users')
            ->row_array();

        if (!$target) {
            $this->response(false, 'User not found', null, 404);
        }

        $is_online = (int)$target['is_online'];
        if ($is_online === 1 && !empty($target['last_seen'])) {
            if ((time() - strtotime($target['last_seen'])) > 60) {
                $is_online = 0;
            }
        }

        $this->response(true, 'User status retrieved successfully', [
            'user_id'   => (int)$target['id'],
            'is_online' => $is_online,
            'last_seen' => $target['last_seen']
        ], 200);
    }









    /**
     * TEMPORARY - GET api/test_push?token=FCM_TOKEN
     * Sends one test push and shows Google's raw reply. DELETE after testing.
     */
    public function test_push()
    {
        $token = $this->get_input('token');
        if (empty($token)) {
            $this->response(false, 'token is required', null, 422);
        }

        $access_token = $this->get_fcm_access_token();
        if (!$access_token) {
            $this->response(false, 'Could not get Google access token. Check the service account path, openssl/curl, and application/logs', null, 500);
        }

        $url = 'https://fcm.googleapis.com/v1/projects/' . self::FCM_PROJECT_ID . '/messages:send';
        $payload = ['message' => [
            'token'        => $token,
            'notification' => ['title' => 'Test', 'body' => 'Hello from backend'],
            'data'         => ['type' => 'test'],
            'android'      => ['priority' => 'HIGH']
        ]];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $access_token,
            'Content-Type: application/json'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $response  = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_err  = curl_error($ch);
        curl_close($ch);

        $this->response($http_code === 200, $http_code === 200 ? 'Push accepted by FCM' : 'Push failed', [
            'http_code'    => $http_code,
            'curl_error'   => $curl_err,
            'fcm_response' => json_decode($response, true)
        ], 200);
    }

    /**
     * GET api/fcm_status
     * Diagnostic endpoint to check Firebase Cloud Messaging service account,
     * token status, registered devices, and recent push notification dispatch logs.
     */
    public function fcm_status()
    {
        $sa_path = $this->get_fcm_service_account_path();
        $file_exists = !empty($sa_path) && file_exists($sa_path);

        $sa_info = null;
        if ($file_exists) {
            $json = json_decode(@file_get_contents($sa_path), true);
            if (is_array($json)) {
                $sa_info = [
                    'project_id'   => $json['project_id'] ?? null,
                    'client_email' => $json['client_email'] ?? null,
                ];
            }
        }

        $token = $this->get_fcm_access_token();
        $device_tokens_count = $this->db->count_all('device_tokens');
        $recent_logs = $this->db->order_by('id', 'DESC')->limit(10)->get('notification_logs')->result_array();

        $this->response(true, 'FCM status retrieved successfully', [
            'database_name'              => $this->db->database,
            'fcm_project_id'             => self::FCM_PROJECT_ID,
            'service_account_configured' => $file_exists,
            'service_account_path'       => $sa_path,
            'service_account_info'       => $sa_info,
            'oauth_token_available'      => !empty($token),
            'registered_device_count'    => (int)$device_tokens_count,
            'recent_notification_logs'   => $recent_logs
        ], 200);
    }

    /**
     * POST api/upload_service_account
     * Installs or updates the Firebase Service Account JSON key.
     */
    public function upload_service_account()
    {
        $json_content = null;

        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $json_content = @file_get_contents($_FILES['file']['tmp_name']);
        } else {
            $json_content = $this->get_input('service_account_json');
        }

        if (empty($json_content)) {
            $this->response(false, 'Please provide service_account_json parameter or upload a JSON file under "file"', null, 422);
        }

        $decoded = json_decode($json_content, true);
        if (!is_array($decoded) || !isset($decoded['client_email']) || !isset($decoded['private_key'])) {
            $this->response(false, 'Invalid service account JSON: missing client_email or private_key fields', null, 422);
        }

        $target = FCPATH . 'firebase-service-account.json';
        $written = @file_put_contents($target, json_encode($decoded, JSON_PRETTY_PRINT));
        if (!$written) {
            $this->response(false, 'Failed to write service account to ' . $target . '. Check write permissions.', null, 500);
        }

        // Invalidate cached OAuth token
        $cache_file = APPPATH . 'cache/fcm_oauth_token.json';
        if (file_exists($cache_file)) {
            @unlink($cache_file);
        }

        $this->response(true, 'Firebase service account successfully installed and activated! Push notifications are now enabled.', [
            'project_id'   => $decoded['project_id'] ?? null,
            'client_email' => $decoded['client_email'],
            'saved_path'   => $target
        ], 200);
    }

    // =========================================================================
    // 4. GROUP CHAT ENDPOINTS
    // =========================================================================

    /**
     * POST api/create_group
     * Creates a new group. The creator is assigned role='admin', status='active'.
     * Any members added by the creator admin are added with status='active' (no permission needed).
     */
    public function create_group()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $title        = trim((string)$this->get_input('title'));
        $description  = trim((string)$this->get_input('description', ''));
        $member_ids   = $this->get_input('member_ids');

        if (empty($title)) {
            $this->response(false, 'Group title is required', null, 422);
        }

        // Handle group icon upload if provided
        $icon_url = null;
        if (isset($_FILES['icon']) && $_FILES['icon']['error'] === UPLOAD_ERR_OK) {
            $ext = strtolower(pathinfo($_FILES['icon']['name'], PATHINFO_EXTENSION));
            if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp'])) {
                $dir = FCPATH . 'uploads/group_icons/';
                if (!is_dir($dir)) {
                    @mkdir($dir, 0755, true);
                }
                $filename = 'grp_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
                if (@move_uploaded_file($_FILES['icon']['tmp_name'], $dir . $filename)) {
                    $icon_url = base_url('uploads/group_icons/' . $filename);
                }
            }
        }

        $now = date('Y-m-d H:i:s');

        $this->db->trans_start();

        $this->db->insert('groups', [
            'title'           => $title,
            'description'     => $description ?: null,
            'icon'            => $icon_url,
            'created_by'      => $my_id,
            'last_message_id' => null,
            'created_at'      => $now,
            'updated_at'      => $now
        ]);
        $group_id = (int)$this->db->insert_id();

        // Add creator as Admin (active)
        $this->db->insert('group_members', [
            'group_id'             => $group_id,
            'user_id'              => $my_id,
            'role'                 => 'admin',
            'status'               => 'active',
            'invited_by'           => $my_id,
            'last_read_message_id' => 0,
            'joined_at'            => $now
        ]);

        // Add initial members directly by admin without needing permission
        $added_user_ids = [];
        if (!empty($member_ids)) {
            $ids = is_array($member_ids) ? $member_ids : explode(',', (string)$member_ids);
            foreach ($ids as $id) {
                $uid = (int)trim($id);
                if ($uid > 0 && $uid !== $my_id) {
                    $exists = $this->db->where('id', $uid)->get('users')->row_array();
                    if ($exists) {
                        $this->db->insert('group_members', [
                            'group_id'             => $group_id,
                            'user_id'              => $uid,
                            'role'                 => 'member',
                            'status'               => 'active',
                            'invited_by'           => $my_id,
                            'last_read_message_id' => 0,
                            'joined_at'            => $now
                        ]);
                        $added_user_ids[] = $uid;
                    }
                }
            }
        }

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
            $this->response(false, 'Failed to create group', null, 500);
        }

        // Notify added members via FCM
        foreach ($added_user_ids as $uid) {
            $this->send_fcm_notification($uid, $title, "{$current_user['name']} added you to group '{$title}'", [
                'type'        => 'group_invite',
                'group_id'    => (string)$group_id,
                'group_title' => $title,
                'group_icon'  => (string)($icon_url ?: '')
            ]);
        }

        $this->response(true, 'Group created successfully', [
            'id'           => $group_id,
            'group_id'     => $group_id,
            'title'        => $title,
            'description'  => $description,
            'icon'         => $icon_url,
            'created_by'   => $my_id,
            'member_count' => count($added_user_ids) + 1
        ], 201);
    }

    /**
     * GET api/groups
     * Returns all groups where the authenticated user is an active member.
     */
    public function groups()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];

        $sql = "SELECT g.id AS group_id, g.title, g.description, g.icon, g.created_by, g.updated_at,
                       gm.role AS my_role, gm.last_read_message_id,
                       m.id AS last_msg_id, m.sender_id AS last_msg_sender_id,
                       m.message_type AS last_msg_type, m.message_text AS last_msg_text,
                       m.media_url AS last_msg_media_url, m.created_at AS last_msg_time,
                       u.name AS last_msg_sender_name,
                       (SELECT COUNT(*) FROM `group_members` WHERE `group_id` = g.id AND `status` = 'active') AS member_count,
                       (SELECT COUNT(*) FROM `group_members` WHERE `group_id` = g.id AND `status` = 'pending') AS pending_requests_count,
                       (SELECT COUNT(*) FROM `messages` WHERE `group_id` = g.id AND `id` > gm.last_read_message_id) AS unread_count
                FROM `group_members` gm
                INNER JOIN `groups` g ON g.id = gm.group_id
                LEFT JOIN `messages` m ON m.id = g.last_message_id
                LEFT JOIN `users` u ON u.id = m.sender_id
                WHERE gm.user_id = ? AND gm.status = 'active'
                ORDER BY g.updated_at DESC";

        $rows = $this->db->query($sql, [$my_id])->result_array();

        $groups = [];
        foreach ($rows as $r) {
            $last_msg = null;
            if (!empty($r['last_msg_id'])) {
                $last_msg = [
                    'id'           => (int)$r['last_msg_id'],
                    'sender_id'    => (int)$r['last_msg_sender_id'],
                    'sender_name'  => $r['last_msg_sender_name'] ?: 'Someone',
                    'message_type' => $r['last_msg_type'],
                    'message_text' => $r['last_msg_text'],
                    'created_at'   => $r['last_msg_time']
                ];
            }

            $groups[] = [
                'id'                     => (int)$r['group_id'],
                'group_id'               => (int)$r['group_id'],
                'title'                  => $r['title'],
                'description'            => $r['description'] ?: '',
                'icon'                   => $r['icon'] ?: '',
                'created_by'             => (int)$r['created_by'],
                'my_role'                => $r['my_role'],
                'member_count'           => (int)$r['member_count'],
                'pending_requests_count' => ($r['my_role'] === 'admin') ? (int)$r['pending_requests_count'] : 0,
                'unread_count'           => (int)$r['unread_count'],
                'last_message'           => $last_msg,
                'updated_at'             => $r['updated_at']
            ];
        }

        $this->response(true, 'Groups retrieved successfully', [
            'groups' => $groups
        ], 200);
    }

    /**
     * GET api/group_details
     * Returns full metadata, member roster, and pending approval requests (for admins).
     */
    public function group_details()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }

        // Verify membership
        $my_membership = $this->db->where('group_id', $group_id)
            ->where('user_id', $my_id)
            ->get('group_members')
            ->row_array();

        if (!$my_membership || $my_membership['status'] !== 'active') {
            $this->response(false, 'Access denied. You are not an active member of this group.', null, 403);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        // Active members
        $members_sql = "SELECT gm.id AS membership_id, gm.role, gm.joined_at,
                               u.id AS user_id, u.name, u.email, u.mobile, u.profile_image,
                               u.about, u.is_online, u.last_seen
                        FROM group_members gm
                        INNER JOIN users u ON u.id = gm.user_id
                        WHERE gm.group_id = ? AND gm.status = 'active'
                        ORDER BY (gm.role = 'admin') DESC, u.name ASC";
        $members = $this->db->query($members_sql, [$group_id])->result_array();

        // Pending approval requests (only visible to admins)
        $pending_requests = [];
        if ($my_membership['role'] === 'admin') {
            $pending_sql = "SELECT gm.id AS request_id, gm.joined_at AS requested_at, gm.invited_by,
                                   u.id AS user_id, u.name, u.email, u.mobile, u.profile_image,
                                   inv.name AS invited_by_name
                            FROM group_members gm
                            INNER JOIN users u ON u.id = gm.user_id
                            LEFT JOIN users inv ON inv.id = gm.invited_by
                            WHERE gm.group_id = ? AND gm.status = 'pending'
                            ORDER BY gm.joined_at ASC";
            $pending_requests = $this->db->query($pending_sql, [$group_id])->result_array();
        }

        $this->response(true, 'Group details retrieved successfully', [
            'group' => [
                'id'                     => (int)$group['id'],
                'group_id'               => (int)$group['id'],
                'title'                  => $group['title'],
                'description'            => $group['description'] ?: '',
                'icon'                   => $group['icon'] ?: '',
                'created_by'             => (int)$group['created_by'],
                'created_at'             => $group['created_at'],
                'my_role'                => $my_membership['role'],
                'member_count'           => count($members),
                'pending_requests_count' => count($pending_requests)
            ],
            'members'          => $members,
            'pending_requests' => $pending_requests
        ], 200);
    }

    /**
     * POST api/send_group_message
     * Sends a text message to a group and broadcasts FCM push notification
     * to all other active members in the group.
     */
    public function send_group_message()
    {
        $current_user = $this->authenticate();
        $sender_id    = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');
        $message_text = trim((string)$this->get_input('message_text'));

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }
        if ($message_text === '') {
            $this->response(false, 'message_text cannot be empty', null, 422);
        }

        // Verify active membership
        $membership = $this->db->where('group_id', $group_id)
            ->where('user_id', $sender_id)
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$membership) {
            $this->response(false, 'You must be an active member of this group to send messages', null, 403);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        $now = date('Y-m-d H:i:s');

        $this->db->trans_start();

        $msg_data = [
            'conversation_id' => null,
            'group_id'        => $group_id,
            'sender_id'       => $sender_id,
            'receiver_id'     => null,
            'message_type'    => 'text',
            'message_text'    => $message_text,
            'media_url'       => null,
            'media_size'      => 0,
            'status'          => 'sent',
            'created_at'      => $now
        ];
        $this->db->insert('messages', $msg_data);
        $message_id = (int)$this->db->insert_id();

        // Update group last message and timestamp
        $this->db->where('id', $group_id)->update('groups', [
            'last_message_id' => $message_id,
            'updated_at'      => $now
        ]);

        // Mark sender as having read this message
        $this->db->where('group_id', $group_id)
            ->where('user_id', $sender_id)
            ->update('group_members', [
                'last_read_message_id' => $message_id
            ]);

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
            $this->response(false, 'Failed to save group message', null, 500);
        }

        $msg_data['id'] = $message_id;
        $msg_data['sender_name']   = $current_user['name'];
        $msg_data['sender_avatar'] = !empty($current_user['profile_image']) ? $current_user['profile_image'] : '';
        $msg_data['is_edited']     = false;
        $msg_data['is_deleted']    = false;

        // Broadcast FCM to all other active members
        $this->broadcast_group_fcm($group_id, $sender_id, $group['title'], $current_user['name'] . ': ' . $message_text, [
            'type'            => 'group_chat',
            'group_id'        => (string)$group_id,
            'group_title'     => (string)$group['title'],
            'group_icon'      => (string)($group['icon'] ?: ''),
            'sender_id'       => (string)$sender_id,
            'sender_name'     => (string)$current_user['name'],
            'sender_avatar'   => (string)($current_user['profile_image'] ?: ''),
            'msg_type'        => 'text',
            'message_id'      => (string)$message_id
        ]);

        $this->response(true, 'Group message sent successfully', [
            'message' => $msg_data
        ], 201);
    }

    /**
     * POST api/send_group_media
     * Uploads media (jpg/png/webp/mp4 <= 2MB) and sends to group.
     */
    public function send_group_media()
    {
        $current_user = $this->authenticate();
        $sender_id    = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');
        $caption      = trim((string)$this->get_input('caption', ''));

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }

        $membership = $this->db->where('group_id', $group_id)
            ->where('user_id', $sender_id)
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$membership) {
            $this->response(false, 'You must be an active member of this group', null, 403);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            $this->response(false, 'Media file is required', null, 422);
        }

        $file      = $_FILES['file'];
        $file_size = (int)$file['size'];
        $ext       = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

        if ($file_size > self::MAX_MEDIA_BYTES) {
            $this->response(false, 'File size exceeds 2 MB limit', null, 413);
        }

        $allowed_images = ['jpg', 'jpeg', 'png', 'webp'];
        $allowed_videos = ['mp4'];
        $msg_type       = null;

        if (in_array($ext, $allowed_images)) {
            $msg_type = 'image';
        } elseif (in_array($ext, $allowed_videos)) {
            $msg_type = 'video';
        } else {
            $this->response(false, 'Unsupported file type. Allowed: jpg, jpeg, png, webp, mp4', null, 415);
        }

        $target_dir = FCPATH . self::UPLOAD_CHAT_DIR;
        if (!is_dir($target_dir)) {
            @mkdir($target_dir, 0755, true);
        }

        $filename       = 'grp_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
        $dest_path      = $target_dir . $filename;
        $rel_media_url  = base_url(self::UPLOAD_CHAT_DIR . $filename);

        if (!@move_uploaded_file($file['tmp_name'], $dest_path)) {
            $this->response(false, 'Failed to save uploaded file', null, 500);
        }

        $now = date('Y-m-d H:i:s');

        $this->db->trans_start();

        $msg_data = [
            'conversation_id' => null,
            'group_id'        => $group_id,
            'sender_id'       => $sender_id,
            'receiver_id'     => null,
            'message_type'    => $msg_type,
            'message_text'    => $caption !== '' ? $caption : null,
            'media_url'       => $rel_media_url,
            'media_size'      => $file_size,
            'status'          => 'sent',
            'created_at'      => $now
        ];
        $this->db->insert('messages', $msg_data);
        $message_id = (int)$this->db->insert_id();

        $this->db->where('id', $group_id)->update('groups', [
            'last_message_id' => $message_id,
            'updated_at'      => $now
        ]);

        $this->db->where('group_id', $group_id)
            ->where('user_id', $sender_id)
            ->update('group_members', [
                'last_read_message_id' => $message_id
            ]);

        $this->db->trans_complete();

        if ($this->db->trans_status() === FALSE) {
            $this->response(false, 'Failed to record media message', null, 500);
        }

        $msg_data['id'] = $message_id;
        $msg_data['sender_name']   = $current_user['name'];
        $msg_data['sender_avatar'] = !empty($current_user['profile_image']) ? $current_user['profile_image'] : '';
        $msg_data['is_edited']     = false;
        $msg_data['is_deleted']    = false;

        $push_body = ($msg_type === 'image') ? '📷 Photo' : '🎥 Video';
        if (!empty($caption)) {
            $push_body .= ': ' . $caption;
        }

        $this->broadcast_group_fcm($group_id, $sender_id, $group['title'], $current_user['name'] . ': ' . $push_body, [
            'type'            => 'group_chat',
            'group_id'        => (string)$group_id,
            'group_title'     => (string)$group['title'],
            'group_icon'      => (string)($group['icon'] ?: ''),
            'sender_id'       => (string)$sender_id,
            'sender_name'     => (string)$current_user['name'],
            'sender_avatar'   => (string)($current_user['profile_image'] ?: ''),
            'msg_type'        => $msg_type,
            'message_id'      => (string)$message_id
        ]);

        $this->response(true, 'Media sent successfully to group', [
            'message'   => $msg_data,
            'media_url' => $rel_media_url
        ], 201);
    }

    /**
     * GET api/group_messages
     * Fetches message history for a group with sender names and avatars.
     */
    public function group_messages()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');
        $after_id     = (int)$this->get_input('after_id', 0);
        $limit        = min(max((int)$this->get_input('limit', 50), 1), 100);

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }

        $membership = $this->db->where('group_id', $group_id)
            ->where('user_id', $my_id)
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$membership) {
            $this->response(false, 'Access denied. You are not an active member of this group.', null, 403);
        }

        $this->db->select('m.*, u.name AS sender_name, u.profile_image AS sender_avatar')
            ->from('messages m')
            ->join('users u', 'u.id = m.sender_id', 'inner')
            ->where('m.group_id', $group_id);

        if ($after_id > 0) {
            $this->db->where('m.id >', $after_id);
        }

        $messages = $this->db->order_by('m.id', 'ASC')
            ->limit($limit)
            ->get()
            ->result_array();

        // Filter soft-deleted messages
        $clean_msgs = [];
        foreach ($messages as $m) {
            $is_del = !empty($m['is_deleted']) && $m['is_deleted'] != '0';
            $is_edt = !empty($m['is_edited']) && $m['is_edited'] != '0' && !$is_del;
            $clean_msgs[] = [
                'id'              => (int)$m['id'],
                'group_id'        => (int)$m['group_id'],
                'sender_id'       => (int)$m['sender_id'],
                'sender_name'     => $m['sender_name'],
                'sender_avatar'   => $m['sender_avatar'] ?: '',
                'message_type'    => $m['message_type'],
                'message_text'    => $is_del ? 'This message was deleted' : $m['message_text'],
                'media_url'       => $is_del ? null : $m['media_url'],
                'media_size'      => (int)($m['media_size'] ?? 0),
                'status'          => $m['status'],
                'is_edited'       => (bool)$is_edt,
                'is_deleted'      => (bool)$is_del,
                'created_at'      => $m['created_at']
            ];
        }

        // Auto mark as read
        if (!empty($clean_msgs)) {
            $latest_id = (int)end($clean_msgs)['id'];
            if ($latest_id > (int)$membership['last_read_message_id']) {
                $this->db->where('group_id', $group_id)
                    ->where('user_id', $my_id)
                    ->update('group_members', [
                        'last_read_message_id' => $latest_id
                    ]);
            }
        }

        $this->response(true, 'Group messages retrieved successfully', [
            'group_id' => $group_id,
            'messages' => $clean_msgs
        ], 200);
    }

    /**
     * POST api/add_group_members
     * Adds members to a group.
     * - If caller is ADMIN: Member is added immediately with status='active' (No permission needed!).
     * - If caller is REGULAR MEMBER: Member is added with status='pending' (Awaiting admin approval).
     */
    public function add_group_members()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');
        $user_ids     = $this->get_input('user_ids');

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }
        if (empty($user_ids)) {
            $this->response(false, 'user_ids is required', null, 422);
        }

        $my_membership = $this->db->where('group_id', $group_id)
            ->where('user_id', $my_id)
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$my_membership) {
            $this->response(false, 'You must be an active member of this group', null, 403);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        $is_admin = ($my_membership['role'] === 'admin');
        $status_to_assign = $is_admin ? 'active' : 'pending';

        $ids = is_array($user_ids) ? $user_ids : explode(',', (string)$user_ids);
        $added_active = [];
        $added_pending = [];
        $now = date('Y-m-d H:i:s');

        foreach ($ids as $id) {
            $uid = (int)trim($id);
            if ($uid <= 0) continue;

            $exists = $this->db->where('group_id', $group_id)
                ->where('user_id', $uid)
                ->get('group_members')
                ->row_array();

            if ($exists) {
                if ($exists['status'] === 'pending' && $is_admin) {
                    // Admin is adding a pending user -> approve them directly!
                    $this->db->where('id', $exists['id'])->update('group_members', [
                        'status'    => 'active',
                        'joined_at' => $now
                    ]);
                    $added_active[] = $uid;
                }
                continue;
            }

            $user = $this->db->where('id', $uid)->get('users')->row_array();
            if ($user) {
                $this->db->insert('group_members', [
                    'group_id'             => $group_id,
                    'user_id'              => $uid,
                    'role'                 => 'member',
                    'status'               => $status_to_assign,
                    'invited_by'           => $my_id,
                    'last_read_message_id' => 0,
                    'joined_at'            => $now
                ]);

                if ($is_admin) {
                    $added_active[] = $uid;
                    // Notify added user directly
                    $this->send_fcm_notification($uid, $group['title'], "{$current_user['name']} added you to group '{$group['title']}'", [
                        'type'        => 'group_invite',
                        'group_id'    => (string)$group_id,
                        'group_title' => (string)$group['title'],
                        'group_icon'  => (string)($group['icon'] ?: '')
                    ]);
                } else {
                    $added_pending[] = $uid;
                }
            }
        }

        // If regular member invited users, notify group admins about pending approval requests
        if (!$is_admin && !empty($added_pending)) {
            $admins = $this->db->where('group_id', $group_id)
                ->where('role', 'admin')
                ->where('status', 'active')
                ->get('group_members')
                ->result_array();

            foreach ($admins as $adm) {
                $this->send_fcm_notification($adm['user_id'], $group['title'], "{$current_user['name']} invited new members awaiting your approval", [
                    'type'        => 'group_join_request',
                    'group_id'    => (string)$group_id,
                    'group_title' => (string)$group['title']
                ]);
            }
        }

        $message = $is_admin
            ? count($added_active) . ' member(s) added successfully without approval'
            : count($added_pending) . ' member(s) invited; awaiting admin approval';

        $this->response(true, $message, [
            'added_active'      => $added_active,
            'added_pending'     => $added_pending,
            'requires_approval' => !$is_admin
        ], 200);
    }

    /**
     * POST api/approve_group_member
     * Approves or rejects a pending member request. Only callable by Group Admins.
     */
    public function approve_group_member()
    {
        $current_user   = $this->authenticate();
        $admin_id       = (int)$current_user['id'];
        $group_id       = (int)$this->get_input('group_id');
        $target_user_id = (int)$this->get_input('target_user_id');
        $action         = strtolower(trim((string)$this->get_input('action', 'approve')));

        if (empty($group_id) || empty($target_user_id)) {
            $this->response(false, 'group_id and target_user_id are required', null, 422);
        }

        // Verify caller is admin
        $admin_check = $this->db->where('group_id', $group_id)
            ->where('user_id', $admin_id)
            ->where('role', 'admin')
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$admin_check) {
            $this->response(false, 'Permission denied. Only group admins can approve or reject members.', null, 403);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        $pending_record = $this->db->where('group_id', $group_id)
            ->where('user_id', $target_user_id)
            ->where('status', 'pending')
            ->get('group_members')
            ->row_array();

        if (!$pending_record) {
            $this->response(false, 'No pending join request found for this user in this group', null, 404);
        }

        if ($action === 'approve') {
            $this->db->where('id', $pending_record['id'])->update('group_members', [
                'status'    => 'active',
                'joined_at' => date('Y-m-d H:i:s')
            ]);

            // Notify user
            $this->send_fcm_notification($target_user_id, $group['title'], "Your request to join '{$group['title']}' was approved by admin", [
                'type'        => 'group_approved',
                'group_id'    => (string)$group_id,
                'group_title' => (string)$group['title'],
                'group_icon'  => (string)($group['icon'] ?: '')
            ]);

            $this->response(true, 'Member approved successfully and added to group', null, 200);
        } else {
            $this->db->where('id', $pending_record['id'])->delete('group_members');
            $this->response(true, 'Join request rejected and removed', null, 200);
        }
    }

    /**
     * POST api/update_member_role
     * Promotes a member to Admin or demotes an Admin to Member.
     * Admin stays as admin as well when promoting others!
     */
    public function update_member_role()
    {
        $current_user   = $this->authenticate();
        $admin_id       = (int)$current_user['id'];
        $group_id       = (int)$this->get_input('group_id');
        $target_user_id = (int)$this->get_input('target_user_id');
        $new_role       = strtolower(trim((string)$this->get_input('role')));

        if (empty($group_id) || empty($target_user_id) || !in_array($new_role, ['admin', 'member'])) {
            $this->response(false, 'group_id, target_user_id, and valid role (admin/member) are required', null, 422);
        }

        // Verify caller is admin
        $admin_check = $this->db->where('group_id', $group_id)
            ->where('user_id', $admin_id)
            ->where('role', 'admin')
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$admin_check) {
            $this->response(false, 'Only group admins can change member roles', null, 403);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        $target = $this->db->where('group_id', $group_id)
            ->where('user_id', $target_user_id)
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        if (!$target) {
            $this->response(false, 'Target user is not an active member of this group', null, 404);
        }

        // Prevent demoting group creator
        if ($target_user_id === (int)$group['created_by'] && $new_role === 'member') {
            $this->response(false, 'The group creator cannot be demoted from admin', null, 400);
        }

        $this->db->where('id', $target['id'])->update('group_members', [
            'role' => $new_role
        ]);

        // Notify user about their role change
        $role_text = ($new_role === 'admin') ? 'Group Admin' : 'Member';
        $this->send_fcm_notification($target_user_id, $group['title'], "You are now a {$role_text} of '{$group['title']}'", [
            'type'        => 'group_role_update',
            'group_id'    => (string)$group_id,
            'group_title' => (string)$group['title'],
            'new_role'    => $new_role
        ]);

        $this->response(true, "Member role updated to {$new_role} successfully", [
            'target_user_id' => $target_user_id,
            'role'           => $new_role
        ], 200);
    }

    /**
     * POST api/remove_group_member
     * Removes a member from group (or allows user to leave).
     */
    public function remove_group_member()
    {
        $current_user   = $this->authenticate();
        $caller_id      = (int)$current_user['id'];
        $group_id       = (int)$this->get_input('group_id');
        $target_user_id = (int)$this->get_input('target_user_id');

        if (empty($group_id) || empty($target_user_id)) {
            $this->response(false, 'group_id and target_user_id are required', null, 422);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        $target = $this->db->where('group_id', $group_id)
            ->where('user_id', $target_user_id)
            ->get('group_members')
            ->row_array();

        if (!$target) {
            $this->response(false, 'Member not found in group', null, 404);
        }

        if ($caller_id !== $target_user_id) {
            // Admin removing someone
            $caller_membership = $this->db->where('group_id', $group_id)
                ->where('user_id', $caller_id)
                ->where('role', 'admin')
                ->where('status', 'active')
                ->get('group_members')
                ->row_array();

            if (!$caller_membership) {
                $this->response(false, 'Only group admins can remove other members', null, 403);
            }

            if ($target_user_id === (int)$group['created_by']) {
                $this->response(false, 'The group creator cannot be removed', null, 400);
            }
        }

        $this->db->where('id', $target['id'])->delete('group_members');

        // If creator left and other members exist, promote the oldest active member to admin
        if ($target_user_id === (int)$group['created_by']) {
            $next_admin = $this->db->where('group_id', $group_id)
                ->where('status', 'active')
                ->order_by('joined_at', 'ASC')
                ->get('group_members')
                ->row_array();

            if ($next_admin) {
                $this->db->where('id', $next_admin['id'])->update('group_members', [
                    'role' => 'admin'
                ]);
            }
        }

        $this->response(true, 'Member removed from group successfully', null, 200);
    }

    /**
     * POST api/update_group
     * Updates group title, description, or group icon.
     * Accessible by group admins and group creator.
     */
    public function update_group()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');
        $title        = $this->get_input('title');
        $description  = $this->get_input('description');

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }

        $group = $this->db->where('id', $group_id)->get('groups')->row_array();
        if (!$group) {
            $this->response(false, 'Group not found', null, 404);
        }

        // Verify user is an active admin or creator of the group
        $membership = $this->db->where('group_id', $group_id)
            ->where('user_id', $my_id)
            ->where('status', 'active')
            ->get('group_members')
            ->row_array();

        $is_creator = ((int)$group['created_by'] === $my_id);
        $is_admin   = ($membership && $membership['role'] === 'admin');

        if (!$is_creator && !$is_admin) {
            $this->response(false, 'Only group admins can update group information', null, 403);
        }

        $updates = [];

        if ($title !== null && trim($title) !== '') {
            $updates['title'] = trim($title);
        }

        if ($description !== null) {
            $updates['description'] = trim($description);
        }

        // Handle group icon upload if multipart file provided
        if (isset($_FILES['icon']) && $_FILES['icon']['error'] === UPLOAD_ERR_OK) {
            $ext = strtolower(pathinfo($_FILES['icon']['name'], PATHINFO_EXTENSION));
            if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp'])) {
                $dir = FCPATH . 'uploads/group_icons/';
                if (!is_dir($dir)) {
                    @mkdir($dir, 0755, true);
                }
                $filename = 'grp_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
                if (@move_uploaded_file($_FILES['icon']['tmp_name'], $dir . $filename)) {
                    $updates['icon'] = base_url('uploads/group_icons/' . $filename);
                }
            }
        } elseif ($this->get_input('icon')) {
            $updates['icon'] = trim($this->get_input('icon'));
        }

        if (empty($updates)) {
            $this->response(false, 'No fields provided to update', null, 422);
        }

        $updates['updated_at'] = date('Y-m-d H:i:s');
        $this->db->where('id', $group_id)->update('groups', $updates);

        $updated_group = $this->db->where('id', $group_id)->get('groups')->row_array();

        // Broadcast notification to group members
        $action_text = !empty($updates['title']) ? "renamed the group to '{$updated_group['title']}'" : "updated group info";
        $this->broadcast_group_fcm(
            $group_id,
            $my_id,
            $updated_group['title'],
            "{$current_user['name']} {$action_text}",
            [
                'type'        => 'group_updated',
                'group_id'    => (string)$group_id,
                'title'       => (string)$updated_group['title'],
                'icon'        => (string)($updated_group['icon'] ?: ''),
                'description' => (string)($updated_group['description'] ?: '')
            ]
        );

        $this->response(true, 'Group updated successfully', [
            'group_id'    => (int)$updated_group['id'],
            'title'       => $updated_group['title'],
            'description' => $updated_group['description'] ?: '',
            'icon'        => $updated_group['icon'] ?: '',
            'updated_at'  => $updated_group['updated_at']
        ], 200);
    }

    /**
     * POST api/mark_group_read
     * Marks all messages in group as read for current user.
     */
    public function mark_group_read()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $group_id     = (int)$this->get_input('group_id');

        if (empty($group_id)) {
            $this->response(false, 'group_id is required', null, 422);
        }

        $max_msg = $this->db->select_max('id')
            ->where('group_id', $group_id)
            ->get('messages')
            ->row_array();

        $latest_id = (int)($max_msg['id'] ?? 0);

        if ($latest_id > 0) {
            $this->db->where('group_id', $group_id)
                ->where('user_id', $my_id)
                ->update('group_members', [
                    'last_read_message_id' => $latest_id
                ]);
        }

        $this->response(true, 'Group marked as read', [
            'group_id'             => $group_id,
            'last_read_message_id' => $latest_id
        ], 200);
    }

    /*
    |--------------------------------------------------------------------------
    | 1-TO-1 WebRTC VOICE & VIDEO CALLING ENDPOINTS (100% FREE P2P)
    |--------------------------------------------------------------------------
    */

    /**
     * POST api/call_initiate
     * Starts a 1-to-1 WebRTC audio or video call session and rings the receiver via FCM.
     */
    public function call_initiate()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $receiver_id  = (int)$this->get_input('receiver_id');
        $call_type    = strtolower(trim((string)$this->get_input('call_type'))) === 'video' ? 'video' : 'audio';
        $offer_sdp    = $this->get_input('offer_sdp');

        if (empty($receiver_id)) {
            $this->response(false, 'receiver_id is required', null, 422);
        }
        if ($receiver_id === $my_id) {
            $this->response(false, 'You cannot call yourself', null, 422);
        }

        // Verify receiver exists
        $receiver = $this->db->where('id', $receiver_id)->get('users')->row_array();
        if (!$receiver) {
            $this->response(false, 'Receiver not found', null, 404);
        }

        // Auto-expire stale ringing calls older than 30 seconds
        $this->db->query("
            UPDATE `calls`
            SET status = 'missed', ended_at = NOW(), updated_at = NOW()
            WHERE status = 'ringing'
              AND created_at < DATE_SUB(NOW(), INTERVAL 30 SECOND)
        ");

        // If caller previously dialed this receiver and it's still ringing, cancel prior ringing attempt
        $this->db->query("
            UPDATE `calls`
            SET status = 'cancelled', ended_at = NOW(), updated_at = NOW()
            WHERE caller_id = ? AND receiver_id = ? AND status = 'ringing'
        ", [$my_id, $receiver_id]);

        // Check if receiver is already in an active connected call (accepted)
        // OR ringing with someone else in the last 25 seconds
        $busy_check = $this->db->query("
            SELECT id FROM `calls`
            WHERE (receiver_id = ? OR caller_id = ?)
              AND (
                status = 'accepted'
                OR (status = 'ringing' AND updated_at >= DATE_SUB(NOW(), INTERVAL 25 SECOND) AND caller_id != ?)
              )
            LIMIT 1
        ", [$receiver_id, $receiver_id, $my_id])->row_array();

        if ($busy_check) {
            $this->db->insert('calls', [
                'caller_id'        => $my_id,
                'receiver_id'      => $receiver_id,
                'call_type'        => $call_type,
                'status'           => 'busy',
                'offer_sdp'        => $offer_sdp ?: null,
                'started_at'       => null,
                'ended_at'         => date('Y-m-d H:i:s'),
                'duration_seconds' => 0,
                'created_at'       => date('Y-m-d H:i:s'),
                'updated_at'       => date('Y-m-d H:i:s')
            ]);
            $call_id = (int)$this->db->insert_id();

            $this->response(true, 'User is busy on another call', [
                'call_id' => $call_id,
                'status'  => 'busy'
            ], 200);
            return;
        }

        // Create ringing call record
        $now = date('Y-m-d H:i:s');
        $this->db->insert('calls', [
            'caller_id'        => $my_id,
            'receiver_id'      => $receiver_id,
            'call_type'        => $call_type,
            'status'           => 'ringing',
            'offer_sdp'        => $offer_sdp ?: null,
            'started_at'       => null,
            'ended_at'         => null,
            'duration_seconds' => 0,
            'created_at'       => $now,
            'updated_at'       => $now
        ]);
        $call_id = (int)$this->db->insert_id();

        // High priority ringing push notification via FCM
        $caller_avatar = !empty($current_user['profile_image']) ? $this->get_full_url($current_user['profile_image']) : '';
        $call_label = ($call_type === 'video') ? 'Incoming Video Call' : 'Incoming Voice Call';

        $this->send_fcm_notification(
            $receiver_id,
            $call_label,
            "{$current_user['name']} is calling...",
            [
                'type'          => 'incoming_call',
                'call_id'       => (string)$call_id,
                'caller_id'     => (string)$my_id,
                'caller_name'   => (string)$current_user['name'],
                'caller_avatar' => (string)$caller_avatar,
                'call_type'     => (string)$call_type
            ]
        );

        $this->response(true, 'Call initiated successfully', [
            'call_id'     => $call_id,
            'caller_id'   => $my_id,
            'receiver_id' => $receiver_id,
            'call_type'   => $call_type,
            'status'      => 'ringing',
            'created_at'  => $now
        ], 201);
    }

    /**
     * POST api/call_answer
     * Receiver accepts the call and submits their WebRTC answer SDP.
     */
    public function call_answer()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $call_id      = (int)$this->get_input('call_id');
        $answer_sdp   = $this->get_input('answer_sdp');

        if (empty($call_id)) {
            $this->response(false, 'call_id is required', null, 422);
        }

        $call = $this->db->where('id', $call_id)->get('calls')->row_array();
        if (!$call) {
            $this->response(false, 'Call not found', null, 404);
        }

        if ((int)$call['receiver_id'] !== $my_id) {
            $this->response(false, 'Only the receiver can accept this call', null, 403);
        }

        if ($call['status'] !== 'ringing') {
            $this->response(false, "Call is already {$call['status']}", [
                'call_id' => $call_id,
                'status'  => $call['status']
            ], 400);
        }

        $now = date('Y-m-d H:i:s');
        $this->db->where('id', $call_id)->update('calls', [
            'status'     => 'accepted',
            'answer_sdp' => $answer_sdp ?: null,
            'started_at' => $now,
            'updated_at' => $now
        ]);

        // Insert answer signal into call_signals so caller picks it up immediately
        $this->db->insert('call_signals', [
            'call_id'    => $call_id,
            'sender_id'  => $my_id,
            'type'       => 'answer',
            'payload'    => json_encode(['answer_sdp' => $answer_sdp ?: '']),
            'created_at' => $now
        ]);

        // High priority FCM push event so caller transitions to connected without waiting
        $this->send_fcm_notification((int)$call['caller_id'], 'Call Accepted', 'Call accepted', [
            'type'       => 'call_accepted',
            'call_id'    => (string)$call_id,
            'answer_sdp' => (string)($answer_sdp ?: '')
        ]);

        $this->response(true, 'Call accepted', [
            'call_id'    => $call_id,
            'status'     => 'accepted',
            'started_at' => $now
        ], 200);
    }

    /**
     * POST api/call_reject
     * Declines or rejects an incoming ringing call.
     */
    public function call_reject()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $call_id      = (int)$this->get_input('call_id');
        $reason       = strtolower(trim((string)$this->get_input('reason')));
        $final_status = in_array($reason, ['busy', 'missed', 'rejected', 'cancelled']) ? $reason : 'rejected';

        if (empty($call_id)) {
            $this->response(false, 'call_id is required', null, 422);
        }

        $call = $this->db->where('id', $call_id)->get('calls')->row_array();
        if (!$call) {
            $this->response(false, 'Call not found', null, 404);
        }

        if ((int)$call['receiver_id'] !== $my_id && (int)$call['caller_id'] !== $my_id) {
            $this->response(false, 'Not authorized for this call', null, 403);
        }

        $now = date('Y-m-d H:i:s');
        $this->db->where('id', $call_id)->update('calls', [
            'status'     => $final_status,
            'ended_at'   => $now,
            'updated_at' => $now
        ]);

        // Record call entry into chat conversation like WhatsApp
        $this->log_call_as_chat_message(
            $call_id,
            (int)$call['caller_id'],
            (int)$call['receiver_id'],
            $call['call_type'],
            $final_status,
            0
        );

        // Notify other user via FCM so their ringing or active call UI closes immediately
        $other_user_id = ((int)$call['caller_id'] === $my_id) ? (int)$call['receiver_id'] : (int)$call['caller_id'];
        $this->send_fcm_notification($other_user_id, 'Call Status', "Call {$final_status}", [
            'type'       => 'call_rejected',
            'call_id'    => (string)$call_id,
            'reason'     => (string)$final_status,
            'by_user_id' => (string)$my_id
        ]);

        $this->response(true, "Call marked as {$final_status}", [
            'call_id' => $call_id,
            'status'  => $final_status
        ], 200);
    }

    /**
     * POST api/call_end
     * Either participant ends or hangs up the active call.
     */
    public function call_end()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $call_id      = (int)$this->get_input('call_id');

        if (empty($call_id)) {
            $this->response(false, 'call_id is required', null, 422);
        }

        $call = $this->db->where('id', $call_id)->get('calls')->row_array();
        if (!$call) {
            $this->response(false, 'Call not found', null, 404);
        }

        if ((int)$call['caller_id'] !== $my_id && (int)$call['receiver_id'] !== $my_id) {
            $this->response(false, 'Not authorized for this call', null, 403);
        }

        $now = date('Y-m-d H:i:s');
        $duration = 0;
        if (!empty($call['started_at'])) {
            $duration = max(0, strtotime($now) - strtotime($call['started_at']));
        }

        $this->db->where('id', $call_id)->update('calls', [
            'status'           => 'ended',
            'ended_at'         => $now,
            'duration_seconds' => $duration,
            'updated_at'       => $now
        ]);

        // Record call entry into chat conversation like WhatsApp
        $this->log_call_as_chat_message(
            $call_id,
            (int)$call['caller_id'],
            (int)$call['receiver_id'],
            $call['call_type'],
            'ended',
            $duration
        );

        // Insert hangup signal so peer disconnects immediately
        $this->db->insert('call_signals', [
            'call_id'    => $call_id,
            'sender_id'  => $my_id,
            'type'       => 'hangup',
            'payload'    => json_encode(['by_user_id' => $my_id]),
            'created_at' => $now
        ]);

        // Push FCM hangup event to other user
        $other_user_id = ((int)$call['caller_id'] === $my_id) ? (int)$call['receiver_id'] : (int)$call['caller_id'];
        $this->send_fcm_notification($other_user_id, 'Call Ended', 'Call ended', [
            'type'       => 'call_ended',
            'call_id'    => (string)$call_id,
            'by_user_id' => (string)$my_id
        ]);

        $this->response(true, 'Call ended', [
            'call_id'          => $call_id,
            'status'           => 'ended',
            'duration_seconds' => $duration
        ], 200);
    }

    /**
     * GET api/call_status
     * Returns current status, answer SDP, and call details.
     */
    public function call_status()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $call_id      = (int)$this->get_input('call_id');

        if (empty($call_id)) {
            $this->response(false, 'call_id is required', null, 422);
        }

        $call = $this->db->where('id', $call_id)->get('calls')->row_array();
        if (!$call) {
            $this->response(false, 'Call not found', null, 404);
        }

        if ((int)$call['caller_id'] !== $my_id && (int)$call['receiver_id'] !== $my_id) {
            $this->response(false, 'Not authorized for this call', null, 403);
        }

        // Auto-mark missed if ringing for more than 75 seconds without answer
        if ($call['status'] === 'ringing') {
            $created_ts = strtotime($call['created_at']);
            if (time() - $created_ts > 75) {
                $now = date('Y-m-d H:i:s');
                $this->db->where('id', $call_id)->update('calls', [
                    'status'     => 'missed',
                    'ended_at'   => $now,
                    'updated_at' => $now
                ]);
                $this->log_call_as_chat_message(
                    $call_id,
                    (int)$call['caller_id'],
                    (int)$call['receiver_id'],
                    $call['call_type'],
                    'missed',
                    0
                );
                $call['status'] = 'missed';
            }
        }

        $this->response(true, 'Call status', [
            'call_id'          => (int)$call['id'],
            'caller_id'        => (int)$call['caller_id'],
            'receiver_id'      => (int)$call['receiver_id'],
            'call_type'        => $call['call_type'],
            'status'           => $call['status'],
            'offer_sdp'        => $call['offer_sdp'],
            'answer_sdp'       => $call['answer_sdp'],
            'started_at'       => $call['started_at'],
            'duration_seconds' => (int)$call['duration_seconds']
        ], 200);
    }

    /**
     * POST api/call_signal
     * Sends an ICE candidate or session signal to peer.
     */
    public function call_signal()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $call_id      = (int)$this->get_input('call_id');
        $type         = trim((string)$this->get_input('type'));
        $payload      = $this->get_input('payload');

        if (empty($call_id) || empty($payload)) {
            $this->response(false, 'call_id and payload are required', null, 422);
        }

        $sig_type = ($type === 'hangup') ? 'hangup' : 'ice_candidate';

        $this->db->insert('call_signals', [
            'call_id'    => $call_id,
            'sender_id'  => $my_id,
            'type'       => $sig_type,
            'payload'    => is_string($payload) ? $payload : json_encode($payload),
            'created_at' => date('Y-m-d H:i:s')
        ]);

        $this->response(true, 'Signal sent', [
            'signal_id' => (int)$this->db->insert_id()
        ], 201);
    }

    /**
     * GET api/call_signals
     * Retrieves ICE candidate signals from peer for this call.
     */
    public function call_signals()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $call_id      = (int)$this->get_input('call_id');
        $after_id     = (int)$this->get_input('after_id');

        if (empty($call_id)) {
            $this->response(false, 'call_id is required', null, 422);
        }

        $signals = $this->db->where('call_id', $call_id)
            ->where('sender_id !=', $my_id)
            ->where('id >', $after_id)
            ->order_by('id', 'ASC')
            ->get('call_signals')
            ->result_array();

        $formatted = [];
        foreach ($signals as $s) {
            $payload = json_decode($s['payload'], true);
            $formatted[] = [
                'id'         => (int)$s['id'],
                'type'       => $s['type'],
                'payload'    => $payload !== null ? $payload : $s['payload'],
                'created_at' => $s['created_at']
            ];
        }

        $this->response(true, 'Signals retrieved', [
            'signals' => $formatted
        ], 200);
    }

    /**
     * GET api/call_logs
     * Returns user call history (both incoming and outgoing).
     */
    public function call_logs()
    {
        $current_user = $this->authenticate();
        $my_id        = (int)$current_user['id'];
        $limit        = min(50, max(1, (int)($this->get_input('limit') ?: 20)));
        $offset       = max(0, (int)($this->get_input('offset') ?: 0));

        $sql = "SELECT c.*,
                       caller.name AS caller_name, caller.profile_image AS caller_image,
                       receiver.name AS receiver_name, receiver.profile_image AS receiver_image
                FROM `calls` c
                INNER JOIN users caller ON caller.id = c.caller_id
                INNER JOIN users receiver ON receiver.id = c.receiver_id
                WHERE c.caller_id = ? OR c.receiver_id = ?
                ORDER BY c.created_at DESC
                LIMIT ? OFFSET ?";

        $rows = $this->db->query($sql, [$my_id, $my_id, $limit, $offset])->result_array();

        $calls = [];
        foreach ($rows as $r) {
            $is_outgoing = ((int)$r['caller_id'] === $my_id);
            $partner_id = $is_outgoing ? (int)$r['receiver_id'] : (int)$r['caller_id'];
            $partner_name = $is_outgoing ? $r['receiver_name'] : $r['caller_name'];
            $partner_image = $is_outgoing ? $r['receiver_image'] : $r['caller_image'];

            $calls[] = [
                'id'               => (int)$r['id'],
                'call_type'        => $r['call_type'],
                'direction'        => $is_outgoing ? 'outgoing' : 'incoming',
                'status'           => $r['status'],
                'duration_seconds' => (int)$r['duration_seconds'],
                'partner'          => [
                    'id'            => $partner_id,
                    'name'          => $partner_name,
                    'profile_image' => !empty($partner_image) ? $this->get_full_url($partner_image) : null
                ],
                'started_at'       => $r['started_at'],
                'ended_at'         => $r['ended_at'],
                'created_at'       => $r['created_at']
            ];
        }

        $this->response(true, 'Call logs retrieved', [
            'calls' => $calls
        ], 200);
    }

    /**
     * Logs call events (ended, missed, rejected) as inline chat messages
     * so they appear directly in the conversation like WhatsApp.
     */
    private function log_call_as_chat_message($call_id, $caller_id, $receiver_id, $call_type, $status, $duration_seconds = 0)
    {
        try {
            $conv_id = $this->get_or_create_conversation((int)$caller_id, (int)$receiver_id);
            if (!$conv_id) return;

            $now = date('Y-m-d H:i:s');
            $call_meta = json_encode([
                'call_id'          => (int)$call_id,
                'call_type'        => $call_type,
                'status'           => $status,
                'duration_seconds' => (int)$duration_seconds,
            ]);

            $this->db->insert('messages', [
                'conversation_id' => $conv_id,
                'sender_id'       => (int)$caller_id,
                'receiver_id'     => (int)$receiver_id,
                'message_type'    => 'call',
                'message_text'    => $call_meta,
                'media_url'       => null,
                'media_size'      => 0,
                'status'          => 'delivered',
                'created_at'      => $now
            ]);
            $msg_id = (int)$this->db->insert_id();

            $this->db->where('id', $conv_id)->update('conversations', [
                'last_message_id' => $msg_id,
                'updated_at'      => $now
            ]);
        } catch (\Throwable $e) {
            log_message('error', 'log_call_as_chat_message failed: ' . $e->getMessage());
        }
    }

    /**
     * Broadcasts an FCM push notification to all active members of a group except the sender.
     */
    private function broadcast_group_fcm($group_id, $sender_id, $title, $body, array $data = [])
    {
        try {
            $members = $this->db->select('user_id')
                ->where('group_id', (int)$group_id)
                ->where('status', 'active')
                ->where('user_id !=', (int)$sender_id)
                ->get('group_members')
                ->result_array();

            if (empty($members)) {
                return;
            }

            $user_ids = array_column($members, 'user_id');

            $tokens = $this->db->select('id, user_id, fcm_token')
                ->where_in('user_id', $user_ids)
                ->get('device_tokens')
                ->result_array();

            if (empty($tokens)) {
                return;
            }

            $access_token = $this->get_fcm_access_token();
            if (!$access_token) {
                return;
            }

            $string_data = [];
            foreach ($data as $k => $v) {
                $string_data[(string)$k] = (string)$v;
            }

            $url = 'https://fcm.googleapis.com/v1/projects/' . self::FCM_PROJECT_ID . '/messages:send';

            foreach ($tokens as $t) {
                $payload = [
                    'message' => [
                        'token'        => $t['fcm_token'],
                        'notification' => [
                            'title' => (string)$title,
                            'body'  => (string)$body
                        ],
                        'data'         => $string_data,
                        'android'      => [
                            'priority'     => 'HIGH',
                            'notification' => [
                                'channel_id'              => 'chat_messages',
                                'sound'                   => 'default',
                                'default_sound'           => true,
                                'default_vibrate_timings' => true,
                                'notification_priority'   => 'PRIORITY_MAX',
                                'visibility'              => 'PUBLIC'
                            ]
                        ]
                    ]
                ];

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'Authorization: Bearer ' . $access_token,
                    'Content-Type: application/json; UTF-8'
                ]);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 6);

                $response  = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curl_err  = curl_error($ch);
                curl_close($ch);

                $resp_str = $curl_err ? 'CURL Error: ' . $curl_err : $response;

                // Log response
                $this->db->insert('notification_logs', [
                    'user_id'      => (int)$t['user_id'],
                    'title'        => (string)$title,
                    'body'         => (string)$body,
                    'fcm_response' => substr($resp_str, 0, 4000),
                    'created_at'   => date('Y-m-d H:i:s')
                ]);

                // Auto clean up dead tokens
                if ($http_code === 404 || strpos($resp_str, 'UNREGISTERED') !== false) {
                    $this->db->where('id', $t['id'])->delete('device_tokens');
                }
            }
        } catch (\Throwable $e) {
            log_message('error', 'Group FCM Broadcast Exception: ' . $e->getMessage());
        }
    }
















    // =========================================================================
    // 5. PRIVATE UTILITY & HELPER METHODS
    // =========================================================================

    /**
     * Handles CORS headers and OPTIONS preflight requests.
     */
    private function handle_cors()
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : '';
        if ($method === 'OPTIONS') {
            $this->output->set_status_header(200)->_display();
            exit;
        }
    }

    /**
     * Output standard JSON response and terminate.
     */
    private function response($status, $message, $data = null, $http_code = 200)
    {
        if ($data === null) {
            $data = (object)[];
        }

        $payload = [
            'status'  => (bool)$status,
            'message' => (string)$message,
            'data'    => $data
        ];

        $this->output
            ->set_status_header($http_code)
            ->set_content_type('application/json', 'utf-8')
            ->set_output(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))
            ->_display();
        exit;
    }

    /**
     * Extracts input parameter supporting JSON body, form-data, and query parameters.
     */
    private function get_input($key = null, $default = null)
    {
        static $input_data = null;

        if ($input_data === null) {
            $get  = $this->input->get(NULL, TRUE) ?: [];
            $post = $this->input->post(NULL, TRUE) ?: [];

            // Robust query string recovery for Nginx / index.php routing
            if (!empty($_SERVER['QUERY_STRING'])) {
                $qs = $_SERVER['QUERY_STRING'];
                // Handle second '?' e.g. /api/messages?other_user_id=1
                $pos = strpos($qs, '?');
                if ($pos !== false) {
                    parse_str(substr($qs, $pos + 1), $extra_get);
                    if (is_array($extra_get)) {
                        $get = array_merge($get, $extra_get);
                    }
                }
                // Handle & e.g. /api/messages&other_user_id=1
                parse_str($qs, $all_get);
                if (is_array($all_get)) {
                    foreach ($all_get as $k => $v) {
                        if (strpos($k, '/') === false && strpos($k, 'api') === false) {
                            $get[$k] = $v;
                        }
                    }
                }
            }

            // Also check REQUEST_URI for trailing query strings
            if (!empty($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '?') !== false) {
                $uri_parts = explode('?', $_SERVER['REQUEST_URI']);
                if (count($uri_parts) > 1) {
                    for ($i = 1; $i < count($uri_parts); $i++) {
                        parse_str($uri_parts[$i], $uri_get);
                        if (is_array($uri_get)) {
                            foreach ($uri_get as $uk => $uv) {
                                if (strpos($uk, '/') === false && strpos($uk, 'api') === false) {
                                    $get[$uk] = $uv;
                                }
                            }
                        }
                    }
                }
            }

            $raw_body = file_get_contents('php://input');
            $json = [];
            if (!empty($raw_body)) {
                $decoded = json_decode($raw_body, true);
                if (is_array($decoded)) {
                    $json = $decoded;
                }
            }

            // Merged: JSON body takes precedence, followed by POST, then GET
            $input_data = array_merge($get, $post, $json);
        }

        if ($key === null) {
            return $input_data;
        }

        if (array_key_exists($key, $input_data)) {
            $val = $input_data[$key];
            return is_string($val) ? trim($val) : $val;
        }

        return $default;
    }

    /**
     * RFC 7515 Base64URL encoder.
     */
    private function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * RFC 7515 Base64URL decoder.
     */
    private function base64url_decode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Retrieves the JWT secret key.
     * Supports environment variable override (JWT_SECRET) for live/production deployments.
     */
    private function get_jwt_secret()
    {
        $env_secret = getenv('JWT_SECRET');
        if (!empty($env_secret)) {
            return $env_secret;
        }

        return self::JWT_SECRET;
    }

    /**
     * Generate an HS256 signed JWT string for a user using Firebase JWT.
     */
    private function generate_jwt($user_id)
    {
        $now = time();
        $payload = [
            'iss' => base_url(),
            'aud' => base_url(),
            'sub' => (int)$user_id,
            'iat' => $now,
            'exp' => $now + (self::JWT_EXPIRY_DAYS * 86400)
        ];

        return JWT::encode($payload, $this->get_jwt_secret(), 'HS256');
    }

    /**
     * Extracts Bearer token from authorization headers across varied server setups.
     */
    private function get_bearer_token()
    {
        $auth_header = null;

        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            foreach ($headers as $k => $v) {
                if (strtolower($k) === 'authorization') {
                    $auth_header = $v;
                    break;
                }
            }
        }

        if (!$auth_header && function_exists('getallheaders')) {
            $headers = getallheaders();
            foreach ($headers as $k => $v) {
                if (strtolower($k) === 'authorization') {
                    $auth_header = $v;
                    break;
                }
            }
        }

        if (!$auth_header) {
            if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
            } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
                $auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
            }
        }

        if ($auth_header && preg_match('/Bearer\s+(\S+)/i', $auth_header, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Verifies the JWT Bearer token and returns the authenticated user row using Firebase JWT.
     */
    private function authenticate()
    {
        $token = $this->get_bearer_token();
        if (!$token) {
            $this->response(false, 'Unauthorized: Access token is missing', null, 401);
        }

        try {
            $decoded = JWT::decode($token, new Key($this->get_jwt_secret(), 'HS256'));
        } catch (ExpiredException $e) {
            $this->response(false, 'Unauthorized: Token has expired', null, 401);
        } catch (SignatureInvalidException $e) {
            $this->response(false, 'Unauthorized: Token signature verification failed', null, 401);
        } catch (\Throwable $e) {
            $this->response(false, 'Unauthorized: Invalid token (' . $e->getMessage() . ')', null, 401);
        }

        $user_id = isset($decoded->sub) ? (int)$decoded->sub : 0;
        if (!$user_id) {
            $this->response(false, 'Unauthorized: Invalid token payload', null, 401);
        }

        $user = $this->db->where('id', $user_id)->get('users')->row_array();
        if (!$user) {
            $this->response(false, 'Unauthorized: User not found', null, 401);
        }

        return $user;
    }

    /**
     * Cleans sensitive fields and normalizes user profile data.
     */
    private function format_user(array $user)
    {
        unset($user['password_hash']);
        $user['id'] = (int)$user['id'];

        $is_online = (int)$user['is_online'];
        if ($is_online === 1 && !empty($user['last_seen'])) {
            if ((time() - strtotime($user['last_seen'])) > 60) {
                $is_online = 0;
            }
        }
        $user['is_online'] = $is_online;

        if (!empty($user['profile_image'])) {
            if (!preg_match('/^https?:\/\//i', $user['profile_image'])) {
                $user['profile_image'] = base_url($user['profile_image']);
            }
        } else {
            $user['profile_image'] = null;
        }

        return $user;
    }

    /**
     * Finds or creates a conversation record between two users (smaller user ID in user1_id).
     */
    private function get_or_create_conversation($user_a, $user_b)
    {
        $u1 = min((int)$user_a, (int)$user_b);
        $u2 = max((int)$user_a, (int)$user_b);

        $conv = $this->db->where('user1_id', $u1)
            ->where('user2_id', $u2)
            ->get('conversations')
            ->row_array();

        if ($conv) {
            return (int)$conv['id'];
        }

        $now = date('Y-m-d H:i:s');
        $this->db->insert('conversations', [
            'user1_id'        => $u1,
            'user2_id'        => $u2,
            'last_message_id' => null,
            'updated_at'      => $now
        ]);

        return (int)$this->db->insert_id();
    }

    /**
     * Ensures required upload and cache directories exist with forbidden index files.
     */
    private function ensure_directories()
    {
        $dirs = [
            FCPATH . self::UPLOAD_PROFILE_DIR,
            FCPATH . self::UPLOAD_CHAT_DIR,
            APPPATH . 'cache/'
        ];

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                @mkdir($dir, 0755, true);
                @file_put_contents($dir . 'index.html', '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>Directory access forbidden.</body></html>');
            }
        }
    }

    /**
     * Automatically applies schema migrations for edit/delete columns
     * so both local development and live servers support new features immediately.
     */
    private function ensure_schema()
    {
        static $schema_checked = false;
        if ($schema_checked) {
            return;
        }
        $schema_checked = true;

        try {
            // 1. Ensure groups table exists
            if (!$this->db->table_exists('groups')) {
                $this->db->query("CREATE TABLE IF NOT EXISTS `groups` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `title` VARCHAR(150) NOT NULL,
                    `description` TEXT NULL,
                    `icon` VARCHAR(255) NULL,
                    `created_by` INT NOT NULL,
                    `last_message_id` INT NULL,
                    `created_at` DATETIME NOT NULL,
                    `updated_at` DATETIME NOT NULL,
                    INDEX (`created_by`),
                    INDEX (`updated_at`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
            } else {
                $fields = $this->db->list_fields('groups');
                if (!in_array('title', $fields)) {
                    if (in_array('name', $fields)) {
                        $this->db->query("ALTER TABLE `groups` CHANGE `name` `title` VARCHAR(150) NOT NULL");
                    } else {
                        $this->db->query("ALTER TABLE `groups` ADD COLUMN `title` VARCHAR(150) NOT NULL");
                    }
                }
                if (!in_array('description', $fields)) {
                    $this->db->query("ALTER TABLE `groups` ADD COLUMN `description` TEXT NULL");
                }
                if (!in_array('icon', $fields)) {
                    $this->db->query("ALTER TABLE `groups` ADD COLUMN `icon` VARCHAR(255) NULL");
                }
                if (!in_array('created_by', $fields)) {
                    $this->db->query("ALTER TABLE `groups` ADD COLUMN `created_by` INT NOT NULL");
                }
                if (!in_array('last_message_id', $fields)) {
                    $this->db->query("ALTER TABLE `groups` ADD COLUMN `last_message_id` INT NULL");
                }
                if (!in_array('created_at', $fields)) {
                    $this->db->query("ALTER TABLE `groups` ADD COLUMN `created_at` DATETIME NOT NULL");
                }
                if (!in_array('updated_at', $fields)) {
                    $this->db->query("ALTER TABLE `groups` ADD COLUMN `updated_at` DATETIME NOT NULL");
                }
            }

            // 2. Ensure group_members table exists
            if (!$this->db->table_exists('group_members')) {
                $this->db->query("CREATE TABLE IF NOT EXISTS `group_members` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `group_id` INT NOT NULL,
                    `user_id` INT NOT NULL,
                    `role` ENUM('admin', 'member') DEFAULT 'member',
                    `status` ENUM('active', 'pending') DEFAULT 'active',
                    `invited_by` INT NULL,
                    `last_read_message_id` INT DEFAULT 0,
                    `joined_at` DATETIME NOT NULL,
                    UNIQUE KEY `uniq_group_user` (`group_id`, `user_id`),
                    INDEX (`user_id`, `status`),
                    INDEX (`group_id`, `status`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");
            } else {
                $gm_fields = $this->db->list_fields('group_members');
                if (!in_array('role', $gm_fields)) {
                    $this->db->query("ALTER TABLE `group_members` ADD COLUMN `role` ENUM('admin', 'member') DEFAULT 'member'");
                }
                if (!in_array('status', $gm_fields)) {
                    $this->db->query("ALTER TABLE `group_members` ADD COLUMN `status` ENUM('active', 'pending') DEFAULT 'active'");
                }
                if (!in_array('invited_by', $gm_fields)) {
                    $this->db->query("ALTER TABLE `group_members` ADD COLUMN `invited_by` INT NULL");
                }
                if (!in_array('last_read_message_id', $gm_fields)) {
                    $this->db->query("ALTER TABLE `group_members` ADD COLUMN `last_read_message_id` INT DEFAULT 0");
                }
                if (!in_array('joined_at', $gm_fields)) {
                    $this->db->query("ALTER TABLE `group_members` ADD COLUMN `joined_at` DATETIME NOT NULL");
                }
            }

            // 3. Ensure messages table supports group chat & edits
            if ($this->db->table_exists('messages')) {
                $fields = $this->db->list_fields('messages');
                if (!in_array('group_id', $fields)) {
                    $this->db->query("ALTER TABLE `messages` ADD COLUMN `group_id` INT(10) UNSIGNED NULL AFTER `conversation_id`, ADD INDEX (`group_id`)");
                    try { $this->db->query("ALTER TABLE `messages` DROP FOREIGN KEY `fk_messages_receiver`"); } catch (\Throwable $e) {}
                    try { $this->db->query("ALTER TABLE `messages` DROP FOREIGN KEY `fk_messages_conversation`"); } catch (\Throwable $e) {}
                    $this->db->query("ALTER TABLE `messages` MODIFY `receiver_id` INT(10) UNSIGNED NULL");
                    $this->db->query("ALTER TABLE `messages` MODIFY `conversation_id` INT(10) UNSIGNED NULL");
                    try { $this->db->query("ALTER TABLE `messages` ADD CONSTRAINT `fk_messages_receiver` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`id`) ON DELETE CASCADE"); } catch (\Throwable $e) {}
                    try { $this->db->query("ALTER TABLE `messages` ADD CONSTRAINT `fk_messages_conversation` FOREIGN KEY (`conversation_id`) REFERENCES `conversations` (`id`) ON DELETE CASCADE"); } catch (\Throwable $e) {}
                }
                if (!in_array('is_edited', $fields)) {
                    $this->db->query("ALTER TABLE `messages` ADD COLUMN `is_edited` TINYINT(1) NOT NULL DEFAULT 0");
                }
                if (!in_array('edited_at', $fields)) {
                    $this->db->query("ALTER TABLE `messages` ADD COLUMN `edited_at` DATETIME NULL DEFAULT NULL");
                }
                if (!in_array('is_deleted', $fields)) {
                    $this->db->query("ALTER TABLE `messages` ADD COLUMN `is_deleted` TINYINT(1) NOT NULL DEFAULT 0");
                }
                if (!in_array('deleted_by_sender', $fields)) {
                    $this->db->query("ALTER TABLE `messages` ADD COLUMN `deleted_by_sender` TINYINT(1) NOT NULL DEFAULT 0");
                }
                if (!in_array('deleted_by_receiver', $fields)) {
                    $this->db->query("ALTER TABLE `messages` ADD COLUMN `deleted_by_receiver` TINYINT(1) NOT NULL DEFAULT 0");
                }
                try {
                    $this->db->query("ALTER TABLE `messages` MODIFY COLUMN `message_type` VARCHAR(32) NOT NULL DEFAULT 'text'");
                } catch (\Throwable $e) {}
            }

            // 4. Ensure calls table exists for 1-to-1 WebRTC audio/video calls
            if (!$this->db->table_exists('calls')) {
                $this->db->query("CREATE TABLE IF NOT EXISTS `calls` (
                    `id` INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `caller_id` INT(10) UNSIGNED NOT NULL,
                    `receiver_id` INT(10) UNSIGNED NOT NULL,
                    `call_type` ENUM('audio', 'video') NOT NULL DEFAULT 'audio',
                    `status` ENUM('ringing', 'accepted', 'rejected', 'missed', 'ended', 'busy', 'cancelled') NOT NULL DEFAULT 'ringing',
                    `offer_sdp` MEDIUMTEXT NULL,
                    `answer_sdp` MEDIUMTEXT NULL,
                    `started_at` DATETIME NULL DEFAULT NULL,
                    `ended_at` DATETIME NULL DEFAULT NULL,
                    `duration_seconds` INT(10) UNSIGNED NOT NULL DEFAULT 0,
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX `idx_calls_caller` (`caller_id`),
                    INDEX `idx_calls_receiver` (`receiver_id`),
                    INDEX `idx_calls_status` (`status`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;");
            } else {
                try {
                    $this->db->query("ALTER TABLE `calls` MODIFY COLUMN `status` ENUM('ringing', 'accepted', 'rejected', 'missed', 'ended', 'busy', 'cancelled') NOT NULL DEFAULT 'ringing'");
                } catch (\Throwable $e) {}
            }

            // 5. Ensure call_signals table exists for WebRTC ICE candidates
            if (!$this->db->table_exists('call_signals')) {
                $this->db->query("CREATE TABLE IF NOT EXISTS `call_signals` (
                    `id` INT(10) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    `call_id` INT(10) UNSIGNED NOT NULL,
                    `sender_id` INT(10) UNSIGNED NOT NULL,
                    `type` ENUM('ice_candidate', 'hangup') NOT NULL,
                    `payload` MEDIUMTEXT NOT NULL,
                    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_signals_call_id` (`call_id`, `id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;");
            }
        } catch (\Throwable $e) {
            log_message('error', 'Schema check exception: ' . $e->getMessage());
        }
    }

    /**
     * Resolves the FCM service account JSON file path dynamically.
     * Works seamlessly across both local development (e.g. XAMPP) and live production servers (Linux/Unix/Windows),
     * preventing breaks caused by hardcoded absolute paths.
     */
    private function get_fcm_service_account_path()
    {
        // 1. Check environment variable (recommended for cloud/containerized live servers)
        $env_path = getenv('FCM_SERVICE_ACCOUNT_PATH');
        if (!empty($env_path) && file_exists($env_path)) {
            return $env_path;
        }

        // 2. Check application/config directory (recommended secure location on live servers)
        $config_path = APPPATH . 'config' . DIRECTORY_SEPARATOR . 'firebase-service-account.json';
        if (file_exists($config_path)) {
            return $config_path;
        }

        // 3. Check project root directory using FCPATH (works universally in local XAMPP and live server)
        $root_path = FCPATH . 'firebase-service-account.json';
        if (file_exists($root_path)) {
            return $root_path;
        }

        // 4. Check defined constant path directly (if specified as absolute or relative)
        if (defined('self::FCM_SERVICE_ACCOUNT_PATH') && !empty(self::FCM_SERVICE_ACCOUNT_PATH)) {
            if (file_exists(self::FCM_SERVICE_ACCOUNT_PATH)) {
                return self::FCM_SERVICE_ACCOUNT_PATH;
            }
            if (file_exists(FCPATH . self::FCM_SERVICE_ACCOUNT_PATH)) {
                return FCPATH . self::FCM_SERVICE_ACCOUNT_PATH;
            }

            // Fallback: If constant still contains a legacy hardcoded path from local (e.g. C:/xampp/...),
            // extract the filename and search for it dynamically in current live root / config
            $filename = basename(self::FCM_SERVICE_ACCOUNT_PATH);
            if (file_exists(FCPATH . $filename)) {
                return FCPATH . $filename;
            }
            if (file_exists(APPPATH . 'config' . DIRECTORY_SEPARATOR . $filename)) {
                return APPPATH . 'config' . DIRECTORY_SEPARATOR . $filename;
            }
        }

        // Default to project root path if file has not been uploaded yet
        return $root_path;
    }

    /**
     * Reads Google service account, signs RS256 JWT using Firebase JWT, and retrieves OAuth access token.
     * Works seamlessly in local XAMPP and live production servers.
     */
    private function get_fcm_access_token()
    {
        $cache_file = APPPATH . 'cache/fcm_oauth_token.json';
        if (file_exists($cache_file)) {
            $cached = json_decode(@file_get_contents($cache_file), true);
            if (isset($cached['access_token']) && isset($cached['expires_at']) && $cached['expires_at'] > time()) {
                return $cached['access_token'];
            }
        }

        $sa_path = $this->get_fcm_service_account_path();
        if (!$sa_path || !file_exists($sa_path)) {
            log_message('error', 'FCM service account file not found. Expected at: ' . $sa_path);
            return null;
        }

        $sa_content = @file_get_contents($sa_path);
        $sa = json_decode($sa_content, true);
        if (!is_array($sa) || !isset($sa['client_email']) || !isset($sa['private_key'])) {
            log_message('error', 'Invalid FCM service account JSON structure in: ' . $sa_path);
            return null;
        }

        $now = time();
        $claims = [
            'iss'   => $sa['client_email'],
            'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
            'aud'   => 'https://oauth2.googleapis.com/token',
            'iat'   => $now,
            'exp'   => $now + 3600
        ];

        try {
            $assertion = JWT::encode($claims, $sa['private_key'], 'RS256');
        } catch (\Throwable $e) {
            log_message('error', 'Failed to sign OAuth assertion for FCM using JWT: ' . $e->getMessage());
            return null;
        }

        $ch = curl_init('https://oauth2.googleapis.com/token');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => $assertion
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response  = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_err  = curl_error($ch);
        curl_close($ch);

        if ($curl_err || $http_code !== 200) {
            log_message('error', 'FCM OAuth token exchange failed (HTTP ' . $http_code . '): ' . ($curl_err ?: $response));
            return null;
        }

        $token_data = json_decode($response, true);
        if (!isset($token_data['access_token'])) {
            log_message('error', 'Missing access_token in FCM OAuth response: ' . $response);
            return null;
        }

        $access_token = $token_data['access_token'];
        $expires_in   = isset($token_data['expires_in']) ? (int)$token_data['expires_in'] : 3600;

        @file_put_contents($cache_file, json_encode([
            'access_token' => $access_token,
            'expires_at'   => $now + $expires_in - 60
        ]));

        return $access_token;
    }

    /**
     * Sends FCM HTTP v1 push notification to all device tokens of a user.
     */
    private function send_fcm_notification($receiver_id, $title, $body, array $data = [])
    {
        try {
            $access_token = $this->get_fcm_access_token();
            if (!$access_token) {
                $sa_path = $this->get_fcm_service_account_path();
                $this->db->insert('notification_logs', [
                    'user_id'      => (int)$receiver_id,
                    'title'        => (string)$title,
                    'body'         => (string)$body,
                    'fcm_response' => 'NOTIFICATION PENDING: Firebase service account key not yet placed. Upload key to: ' . $sa_path,
                    'created_at'   => date('Y-m-d H:i:s')
                ]);
                return;
            }

            $tokens = $this->db->select('id, fcm_token')
                ->where('user_id', (int)$receiver_id)
                ->get('device_tokens')
                ->result_array();

            if (empty($tokens)) {
                return;
            }

            $string_data = [];
            foreach ($data as $k => $v) {
                $string_data[(string)$k] = (string)$v;
            }

            $url = 'https://fcm.googleapis.com/v1/projects/' . self::FCM_PROJECT_ID . '/messages:send';

            $is_call = isset($string_data['type']) && $string_data['type'] === 'incoming_call';
            $channel_id = $is_call ? 'incoming_calls' : 'chat_messages';

            foreach ($tokens as $t) {
                $fcm_token = $t['fcm_token'];
                $payload = [
                    'message' => [
                        'token'        => $fcm_token,
                        'notification' => [
                            'title' => (string)$title,
                            'body'  => (string)$body
                        ],
                        'data'         => $string_data,
                        'android'      => [
                            'priority'     => 'HIGH',
                            'notification' => [
                                'channel_id'              => $channel_id,
                                'sound'                   => 'default',
                                'default_sound'           => true,
                                'default_vibrate_timings' => true,
                                'notification_priority'   => 'PRIORITY_MAX',
                                'visibility'              => 'PUBLIC'
                            ]
                        ]
                    ]
                ];

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'Authorization: Bearer ' . $access_token,
                    'Content-Type: application/json; UTF-8'
                ]);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 6);

                $response  = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curl_err  = curl_error($ch);
                curl_close($ch);

                $resp_str = $curl_err ? 'CURL Error: ' . $curl_err : $response;

                // Log response
                $this->db->insert('notification_logs', [
                    'user_id'      => (int)$receiver_id,
                    'title'        => (string)$title,
                    'body'         => (string)$body,
                    'fcm_response' => substr($resp_str, 0, 4000),
                    'created_at'   => date('Y-m-d H:i:s')
                ]);

                // Clean up dead tokens that Google explicitly confirmed are UNREGISTERED (app uninstalled / replaced)
                if ($http_code === 404 || strpos($resp_str, 'UNREGISTERED') !== false) {
                    $this->db->where('id', $t['id'])->delete('device_tokens');
                }
            }
        } catch (\Throwable $e) {
            log_message('error', 'FCM Notification Exception: ' . $e->getMessage());
        }
    }

    /**
     * Broadcasts an FCM push notification to all users except the excluded user ID.
     */
    private function broadcast_fcm_notification($exclude_user_id, $title, $body, array $data = [])
    {
        try {
            $access_token = $this->get_fcm_access_token();
            if (!$access_token) {
                $sa_path = $this->get_fcm_service_account_path();
                $this->db->insert('notification_logs', [
                    'user_id'      => (int)$exclude_user_id,
                    'title'        => (string)$title,
                    'body'         => (string)$body,
                    'fcm_response' => 'NOTIFICATION PENDING: Firebase service account key not yet placed. Upload key to: ' . $sa_path,
                    'created_at'   => date('Y-m-d H:i:s')
                ]);
                return;
            }

            $tokens = $this->db->select('id, user_id, fcm_token')
                ->where('user_id !=', (int)$exclude_user_id)
                ->get('device_tokens')
                ->result_array();

            if (empty($tokens)) {
                return;
            }

            $string_data = [];
            foreach ($data as $k => $v) {
                $string_data[(string)$k] = (string)$v;
            }

            $url = 'https://fcm.googleapis.com/v1/projects/' . self::FCM_PROJECT_ID . '/messages:send';

            $is_call = isset($string_data['type']) && $string_data['type'] === 'incoming_call';
            $channel_id = $is_call ? 'incoming_calls' : 'chat_messages';

            foreach ($tokens as $t) {
                $fcm_token = $t['fcm_token'];
                $payload = [
                    'message' => [
                        'token'        => $fcm_token,
                        'notification' => [
                            'title' => (string)$title,
                            'body'  => (string)$body
                        ],
                        'data'         => $string_data,
                        'android'      => [
                            'priority'     => 'HIGH',
                            'notification' => [
                                'channel_id'              => $channel_id,
                                'sound'                   => 'default',
                                'default_sound'           => true,
                                'default_vibrate_timings' => true,
                                'notification_priority'   => 'PRIORITY_MAX',
                                'visibility'              => 'PUBLIC'
                            ]
                        ]
                    ]
                ];

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'Authorization: Bearer ' . $access_token,
                    'Content-Type: application/json; UTF-8'
                ]);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);

                $response  = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curl_err  = curl_error($ch);
                curl_close($ch);

                $resp_str = $curl_err ? 'CURL Error: ' . $curl_err : $response;

                $this->db->insert('notification_logs', [
                    'user_id'      => (int)$t['user_id'],
                    'title'        => (string)$title,
                    'body'         => (string)$body,
                    'fcm_response' => substr($resp_str, 0, 4000),
                    'created_at'   => date('Y-m-d H:i:s')
                ]);

                // Clean up dead tokens that Google explicitly confirmed are UNREGISTERED (app uninstalled / replaced)
                if ($http_code === 404 || strpos($resp_str, 'UNREGISTERED') !== false) {
                    $this->db->where('id', $t['id'])->delete('device_tokens');
                }
            }
        } catch (\Throwable $e) {
            log_message('error', 'FCM Broadcast Exception: ' . $e->getMessage());
        }
    }
}
