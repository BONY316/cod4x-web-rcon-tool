<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/config/auth.php';
require_once __DIR__ . '/includes/footer.php';
if (function_exists('auth_has_persisted_users') && !auth_has_persisted_users()) { header('Location: install.php'); exit; }

$LOG_DIR = __DIR__ . '/rcon_logs'; if (!is_dir($LOG_DIR)) { @mkdir($LOG_DIR, 0750, true); }
$AUTH_LOG = $LOG_DIR . '/auth.log';
function auth_log_line($msg){ global $AUTH_LOG; @file_put_contents($AUTH_LOG, "[@".date('Y-m-d H:i:s')."] ".$msg.PHP_EOL, FILE_APPEND | LOCK_EX); }

$err=''; if (empty($_SESSION['csrf_login'])) { $_SESSION['csrf_login']=bin2hex(random_bytes(16)); }
$_SESSION['login_attempts']=$_SESSION['login_attempts']??0; $_SESSION['login_first']=$_SESSION['login_first']??time();
function throttled(){ global $LOGIN_MAX_ATTEMPTS,$LOGIN_WINDOW_SECONDS; $a=$_SESSION['login_attempts']??0; $f=$_SESSION['login_first']??time(); if((time()-$f)>$LOGIN_WINDOW_SECONDS){$_SESSION['login_attempts']=0;$_SESSION['login_first']=time();return false;} return $a>=$LOGIN_MAX_ATTEMPTS; }

if($_SERVER['REQUEST_METHOD']==='POST'){
  if(!hash_equals($_SESSION['csrf_login'], $_POST['csrf']??'')){ $err='Invalid session token.'; }
  elseif(throttled()){ $err='Too many attempts. Try again later.'; }
  else{
    $u=trim($_POST['username']??''); $p=$_POST['password']??''; $ok=false;
    $US = auth_load_users(); // JSON-first
    if($u!=='' && isset($US[$u])){
      $stored = $US[$u]['hash'] ?? '';
      if(is_string($stored) && strncmp($stored,'PLAINTEXT:',10)===0){ $ok=(substr($stored,10)===$p);} else { $ok=password_verify($p,$stored); }
    }
    if($ok){ $_SESSION['user']=$u; $_SESSION['login_attempts']=0; $_SESSION['login_first']=time(); auth_log_line("user={$u} event=login success ip=".$_SERVER['REMOTE_ADDR']); $next=$_GET['next']??'index.php'; header('Location: '.$next); exit; }
    else { $_SESSION['login_attempts']=($_SESSION['login_attempts']??0)+1; $err='Invalid username or password.'; auth_log_line("user={$u} event=login failure ip=".$_SERVER['REMOTE_ADDR']); }
  }
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Login – <?=htmlspecialchars($SITE_NAME)?></title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="assets/styles.css"></head>
<body><div class="login-card"><h2 class="login-title"><?=htmlspecialchars($SITE_NAME)?></h2>
<?php if($err): ?><div class="error" role="alert"><?=$err?></div><?php endif; ?>
<?php if(throttled()): ?><div class="flash">Locked due to too many attempts. Try again later.</div><?php endif; ?>
<form method="post" autocomplete="off"><label>Username<input type="text" name="username" autofocus required></label><label>Password<input type="password" name="password" required></label><input type="hidden" name="csrf" value="<?=htmlspecialchars($_SESSION['csrf_login'])?>"><button type="submit" style="width:100%">Sign in</button></form>
<p class="small-note" style="margin-top:10px">Accounts live in <code>config/users.json</code>. Inline <code>$USERS</code> is only for first-run.</p>
</div><?php if(function_exists('panel_footer')) panel_footer(); ?>
</body></html>