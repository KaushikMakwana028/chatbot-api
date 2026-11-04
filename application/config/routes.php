<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/*
| -------------------------------------------------------------------------
| URI ROUTING
| -------------------------------------------------------------------------
| This file lets you re-map URI requests to specific controller functions.
|
| Typically there is a one-to-one relationship between a URL string
| and its corresponding controller class/method. The segments in a
| URL normally follow this pattern:
|
|	example.com/class/method/id/
|
| In some instances, however, you may want to remap this relationship
| so that a different class/function is called than the one
| corresponding to the URL.
|
| Please see the user guide for complete details:
|
|	https://codeigniter.com/userguide3/general/routing.html
|
| -------------------------------------------------------------------------
| RESERVED ROUTES
| -------------------------------------------------------------------------
|
| There are three reserved routes:
|
|	$route['default_controller'] = 'welcome';
|
| This route indicates which controller class should be loaded if the
| URI contains no data. In the above example, the "welcome" class
| would be loaded.
|
|	$route['404_override'] = 'errors/page_missing';
|
| This route will tell the Router which controller/method to use if those
| provided in the URL cannot be matched to a valid route.
|
|	$route['translate_uri_dashes'] = FALSE;
|
| This is not exactly a route, but allows you to automatically route
| controller and method names that contain dashes. '-' isn't a valid
| class or method name character, so it requires translation.
| When you set this option to TRUE, it will replace ALL dashes in the
| controller and method URI segments.
|
| Examples:	my-controller/index	-> my_controller/index
|		my-controller/my-method	-> my_controller/my_method
*/
$route['default_controller'] = 'welcome';
$route['404_override'] = '';
$route['translate_uri_dashes'] = FALSE;

/*
| -------------------------------------------------------------------------
| API ROUTES (WhatsApp-like Chat Backend)
| -------------------------------------------------------------------------
*/
$route['api/install']              = 'api/install';
$route['api/register']             = 'api/register';
$route['api/login']                = 'api/login';
$route['api/logout']               = 'api/logout';
$route['api/change_password']      = 'api/change_password';
$route['api/forgot_password']      = 'api/forgot_password';
$route['api/fcm_status']           = 'api/fcm_status';
$route['api/upload_service_account'] = 'api/upload_service_account';
$route['api/profile']              = 'api/profile';
$route['api/update_profile']       = 'api/update_profile';
$route['api/update_profile_image'] = 'api/update_profile_image';
$route['api/save_token']           = 'api/save_token';
$route['api/check_device_token']   = 'api/check_device_token';
$route['api/users']                = 'api/users';
$route['api/conversations']        = 'api/conversations';
$route['api/messages']             = 'api/messages';
$route['api/send_message']         = 'api/send_message';
$route['api/send_media']           = 'api/send_media';
$route['api/edit_message']         = 'api/edit_message';
$route['api/delete_message']       = 'api/delete_message';
$route['api/mark_read']            = 'api/mark_read';
$route['api/heartbeat']            = 'api/heartbeat';
$route['api/user_status']          = 'api/user_status';

// Group Chat Routes
$route['api/create_group']         = 'api/create_group';
$route['api/groups']               = 'api/groups';
$route['api/group_details']        = 'api/group_details';
$route['api/send_group_message']   = 'api/send_group_message';
$route['api/send_group_media']     = 'api/send_group_media';
$route['api/group_messages']       = 'api/group_messages';
$route['api/add_group_members']    = 'api/add_group_members';
$route['api/approve_group_member'] = 'api/approve_group_member';
$route['api/update_member_role']   = 'api/update_member_role';
$route['api/remove_group_member']  = 'api/remove_group_member';
$route['api/mark_group_read']      = 'api/mark_group_read';

// 1-to-1 WebRTC Calling Routes
$route['api/call_initiate']        = 'api/call_initiate';
$route['api/call_answer']          = 'api/call_answer';
$route['api/call_reject']          = 'api/call_reject';
$route['api/call_end']             = 'api/call_end';
$route['api/call_status']          = 'api/call_status';
$route['api/call_signal']          = 'api/call_signal';
$route['api/call_signals']         = 'api/call_signals';
$route['api/call_logs']            = 'api/call_logs';

$route['api/(:any)']               = 'api/$1';

