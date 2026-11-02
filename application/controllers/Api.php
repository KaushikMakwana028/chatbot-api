<?php
defined('BASEPATH') OR exit('No direct script access allowed');

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
    const JWT_EXPIRY_DAYS          = 30;
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
        $name     = $this->get_input('name');
        $email    = $this->get_input('email');
        $mobile   = $this->get_input('mobile');
        $password = $this->get_input('password');

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

        // Notify other active devices that a new user joined
        $this->broadcast_fcm_notification($user_id, 'New Contact', "{$name} joined", [
            'type'      => 'new_user',
            'user_id'   => (string)$user_id,
            'user_name' => $name
        ]);

        $this->response(true, 'User registered successfully', [
            'user'  => $this->format_user($user),
            'token' => $token
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
            'user'  => $this->format_user($user),
            'token' => $token
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
        }

        $this->db->where('id', $user['id'])->update('users', [
            'is_online' => 0,
            'last_seen' => date('Y-m-d H:i:s')
        ]);

        $this->response(true, 'Logged out successfully', null, 200);
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
                $last_message = [
                    'id'           => (int)$r['msg_id'],
                    'sender_id'    => (int)$r['msg_sender_id'],
                    'receiver_id'  => (int)$r['msg_receiver_id'],
                    'message_type' => $r['msg_type'],
                    'message_text' => $r['msg_text'],
                    'media_url'    => !empty($r['msg_media_url']) ? base_url($r['msg_media_url']) : null,
                    'media_size'   => (int)$r['msg_media_size'],
                    'status'       => $r['msg_status'],
                    'created_at'   => $r['msg_created_at']
                ];
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
            $formatted[] = [
                'id'              => (int)$m['id'],
                'conversation_id' => (int)$m['conversation_id'],
                'sender_id'       => (int)$m['sender_id'],
                'receiver_id'     => (int)$m['receiver_id'],
                'message_type'    => $m['message_type'],
                'message_text'    => $m['message_text'],
                'media_url'       => !empty($m['media_url']) ? base_url($m['media_url']) : null,
                'media_size'      => (int)$m['media_size'],
                'status'          => $m['status'],
                'created_at'      => $m['created_at']
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
        $this->send_fcm_notification($receiver_id, $current_user['name'], $message_text, [
            'type'            => 'chat',
            'conversation_id' => (string)$conv_id,
            'sender_id'       => (string)$sender_id,
            'sender_name'     => $current_user['name'],
            'message_type'    => 'text',
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

        $this->send_fcm_notification($receiver_id, $current_user['name'], $push_body, [
            'type'            => 'chat',
            'conversation_id' => (string)$conv_id,
            'sender_id'       => (string)$sender_id,
            'sender_name'     => $current_user['name'],
            'message_type'    => $msg_type,
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
                                'channel_id' => 'chat_messages'
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

                // Cleanup dead tokens
                if ($http_code === 400 || $http_code === 404) {
                    if (stripos($resp_str, 'UNREGISTERED') !== false || stripos($resp_str, 'INVALID_ARGUMENT') !== false) {
                        $this->db->where('fcm_token', $fcm_token)->delete('device_tokens');
                    }
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
                return;
            }

            $tokens = $this->db->select('user_id, fcm_token')
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
                                'channel_id' => 'chat_messages'
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

                if ($http_code === 400 || $http_code === 404) {
                    if (stripos($resp_str, 'UNREGISTERED') !== false || stripos($resp_str, 'INVALID_ARGUMENT') !== false) {
                        $this->db->where('fcm_token', $fcm_token)->delete('device_tokens');
                    }
                }
            }
        } catch (\Throwable $e) {
            log_message('error', 'FCM Broadcast Exception: ' . $e->getMessage());
        }
    }
}
