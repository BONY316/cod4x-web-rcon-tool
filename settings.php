<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/config/auth.php';
require_once __DIR__ . '/includes/footer.php';
if (empty($_SESSION['user'])) { header("Location: login.php?next=" . urlencode($_SERVER['REQUEST_URI'])); exit; }
$ME = $_SESSION['user']; $IS_ADMIN = auth_is_admin($ME);

$LOG_DIR = __DIR__ . '/rcon_logs'; if (!is_dir($LOG_DIR)) { @mkdir($LOG_DIR, 0750, true); }
$AUTH_LOG = $LOG_DIR . '/auth.log';
function audit($msg){ global $AUTH_LOG; @file_put_contents($AUTH_LOG, "[@".date('Y-m-d H:i:s')."] ".$msg.PHP_EOL, FILE_APPEND | LOCK_EX); }

$users = auth_load_users();
if (empty($_SESSION['csrf_settings'])) $_SESSION['csrf_settings'] = bin2hex(random_bytes(16));
$CSRF = $_SESSION['csrf_settings']; $flash=''; $err='';

if ($_SERVER['REQUEST_METHOD']==='POST'){
  if (!hash_equals($CSRF, $_POST['csrf'] ?? '')) $err='Invalid CSRF token.';
  else {
    if (isset($_POST['act']) && $_POST['act']==='change_pass'){
      $cur=$_POST['cur']??''; $new=$_POST['new']??''; $again=$_POST['again']??'';
      if (!isset($users[$ME])) $err='Account not found.';
      elseif ($new===''||strlen($new)<6) $err='New password must be at least 6 characters.';
      elseif ($new!==$again) $err='Passwords do not match.';
      else {
        $stored=$users[$ME]['hash']??''; $ok=false;
        if (is_string($stored) && strncmp($stored,'PLAINTEXT:',10)===0){ $ok=(substr($stored,10)===$cur);} else { $ok=password_verify($cur,$stored); }
        if(!$ok) $err='Current password is incorrect.';
        else{
          $users[$ME]['hash']=password_hash($new,PASSWORD_DEFAULT);
          $saveErr=null; if(auth_save_users($users,$saveErr)){ $flash='Password updated.'; audit("user={$ME} event=change_password ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save new password. '.htmlspecialchars($saveErr ?? ''); }
        }
      }
    }
  }
}
?><!doctype html><html lang="en"><head><meta charset="utf-8"><title>Settings – <?=htmlspecialchars($SITE_NAME)?></title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="assets/styles.css"></head>
<body><div class="container"><div class="topbar"><div class="logo-wrap"><span class="logo-pill">CoD4X</span><h2>CoD4X Web RCON Tool</h2></div><div><a class="linkbtn" href="index.php">Back to Panel</a><?php if ($IS_ADMIN): ?><a class="linkbtn" href="users.php" style="margin-left:8px">Users</a><a class="linkbtn" href="servers.php" style="margin-left:8px">Servers</a><?php endif; ?><a class="linkbtn danger" href="logout.php" style="margin-left:8px">Logout</a></div></div>
<?php if($err): ?><div class="error"><?=$err?></div><?php endif; ?>
<?php if($flash): ?><div class="flash"><?=$flash?></div><?php endif; ?>
<div class="card"><h3>Change Password</h3><form method="post" class="row"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="change_pass"><label>Current password<input type="password" name="cur" required></label><label>New password<input type="password" name="new" required></label><label>Repeat new password<input type="password" name="again" required></label><button>Update Password</button></form><p class="small-note">Use at least 12 chars; mix letters, numbers, symbols.</p></div></div><?php if(function_exists('panel_footer')) panel_footer(); ?>
</body></html>
