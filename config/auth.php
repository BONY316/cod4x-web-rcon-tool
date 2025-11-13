<?php
// config/auth.php — users + helpers

ini_set('display_errors','0');
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
function panel_log_error($msg){ if(is_string($msg)&&$msg!==''){ error_log('RCON Panel: '.$msg); } }

$USERS = [
  'admin' => 'PLAINTEXT:changeme',
];

$SITE_NAME = 'CoD4X Web RCON Tool';
$LOGIN_MAX_ATTEMPTS = 8;
$LOGIN_WINDOW_SECONDS = 900;

function _auth_users_json_path(){ return __DIR__ . '/users.json'; }

function auth_load_users(){
  $json = _auth_users_json_path();
  if (is_file($json)){
    $raw = @file_get_contents($json);
    if ($raw !== false){
      $d = @json_decode($raw, true);
      if (is_array($d) && isset($d['users']) && is_array($d['users'])) return $d['users'];
    }
  }
  $res = [];
  foreach ($GLOBALS['USERS'] as $u => $h){
    $res[$u] = ['hash'=>$h, 'role'=>($u==='admin' ? 'admin' : 'mod')];
  }
  return $res;
}

function auth_has_persisted_users(){
  $json = _auth_users_json_path();
  if (!is_file($json)) return false;
  $raw = @file_get_contents($json);
  if ($raw === false) return false;
  $d = @json_decode($raw, true);
  if (!is_array($d) || !isset($d['users']) || !is_array($d['users'])) return false;
  return count($d['users']) > 0;
}

function auth_save_users($users_assoc, &$error=null){
  $json = _auth_users_json_path();
  $dir = dirname($json);
  if (!is_dir($dir)) {
    if (!@mkdir($dir, 0750, true)) { $error = 'Cannot create config dir: '.$dir; return false; }
  }
  if (!is_writable($dir)) {
    @chmod($dir, 0750);
    if (!is_writable($dir)) { $error = 'Config dir not writable: '.$dir; return false; }
  }
  $payload = ['users'=>$users_assoc, 'updated'=>date('c')];
  $tmp = $json . '.tmp';
  $enc = json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
  if ($enc === false){ $error = 'Failed to encode JSON.'; return false; }
  if (@file_put_contents($tmp, $enc, LOCK_EX) === false){ $error='Failed to write temp file'; return false; }
  if (!@rename($tmp, $json)){
    if (!@copy($tmp, $json) || !@unlink($tmp)){ $error='Failed to move users.json into place'; return false; }
  }
  @chmod($json, 0640);
  return true;
}

function auth_is_admin($username){
  $users = auth_load_users();
  return isset($users[$username]) && (($users[$username]['role'] ?? 'mod') === 'admin');
}
