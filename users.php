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
if (empty($_SESSION['csrf_users'])) $_SESSION['csrf_users'] = bin2hex(random_bytes(16));
$CSRF = $_SESSION['csrf_users']; $flash=''; $err='';

if ($_SERVER['REQUEST_METHOD']==='POST'){
  if (!hash_equals($CSRF, $_POST['csrf'] ?? '')) $err='Invalid CSRF token.';
  elseif (!$IS_ADMIN) $err='Only admins can manage users.';
  else {
    $act = $_POST['act'] ?? '';
    if ($act==='add_user'){
      $u=trim($_POST['new_user']??''); $p=$_POST['new_pass']??''; $role=$_POST['new_role']??'mod';
      if($u===''||$p==='') $err='Username and password are required.';
      elseif(isset($users[$u])) $err='That username already exists.';
      elseif(!preg_match('/^[A-Za-z0-9_\-\.]{3,32}$/',$u)) $err='Username must be 3–32 chars: letters, numbers, _ - .';
      elseif(!in_array($role,['admin','mod'],true)) $err='Invalid role.';
      else{
        $users[$u]=['hash'=>password_hash($p,PASSWORD_DEFAULT),'role'=>$role];
        $saveErr=null; if(auth_save_users($users,$saveErr)){ $flash="Added user {$u} (role: {$role})."; audit("user={$ME} event=add_user target={$u} role={$role} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save users (permissions?). '.htmlspecialchars($saveErr ?? ''); }
      }
    } elseif ($act==='reset_pass'){
      $u=$_POST['user']??''; $p=$_POST['new_pass']??'';
      if($u===''||$p==='') $err='Select a user and enter a new password.';
      elseif(!isset($users[$u])) $err='User not found.';
      else{
        $users[$u]['hash']=password_hash($p,PASSWORD_DEFAULT);
        $saveErr=null; if(auth_save_users($users,$saveErr)){ $flash="Password reset for {$u}."; audit("user={$ME} event=reset_pass target={$u} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save users (permissions?). '.htmlspecialchars($saveErr ?? ''); }
      }
    } elseif ($act==='change_role'){
      $u=$_POST['user']??''; $role=$_POST['role']??'mod';
      if(!isset($users[$u])) $err='User not found.';
      elseif(!in_array($role,['admin','mod'],true)) $err='Invalid role.';
      else{
        $old=isset($users[$u]['role'])?$users[$u]['role']:'mod';
        $users[$u]['role']=$role;
        $admins=array_filter($users,function($v){ return isset($v['role'])?$v['role']==='admin':false; });
        if(count($admins)===0){ $users[$u]['role']=$old; $err='Cannot remove the last admin.'; }
        else{ $saveErr=null; if(auth_save_users($users,$saveErr)){ $flash="Updated role for {$u} to {$role}."; audit("user={$ME} event=change_role target={$u} role={$role} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save users (permissions?). '.htmlspecialchars($saveErr ?? ''); } }
      }
    } elseif ($act==='delete_user'){
      $u=$_POST['user']??'';
      if($u===$ME) $err='You cannot delete your own account while logged in.';
      elseif(!isset($users[$u])) $err='User not found.';
      else{
        $isAdminTarget=(isset($users[$u]['role']) && $users[$u]['role']==='admin');
        $admins=array_filter($users,function($v){ return isset($v['role'])?$v['role']==='admin':false; });
        if($isAdminTarget && count($admins)<=1) $err='Cannot delete the last admin.';
        else{
          unset($users[$u]);
          $saveErr=null; if(auth_save_users($users,$saveErr)){ $flash="Deleted user {$u}."; audit("user={$ME} event=delete_user target={$u} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save users (permissions?). '.htmlspecialchars($saveErr ?? ''); }
        }
      }
    }
  }
}
$users = auth_load_users();
?><!doctype html><html lang="en"><head><meta charset="utf-8"><title>Users – <?=htmlspecialchars($SITE_NAME)?></title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="assets/styles.css"></head>
<body><div class="container"><div class="topbar"><div class="logo-wrap"><span class="logo-pill">CoD4X</span><h2>CoD4X Web RCON Tool</h2></div><div><a class="linkbtn" href="index.php">Back to Panel</a><a class="linkbtn" href="settings.php" style="margin-left:8px">Settings</a><a class="linkbtn danger" href="logout.php" style="margin-left:8px">Logout</a></div></div>
<?php if(!$IS_ADMIN): ?><div class="error">Only admins can view this page.</div><?php else: ?>
<?php if($err): ?><div class="error"><?=$err?></div><?php endif; ?><?php if($flash): ?><div class="flash"><?=$flash?></div><?php endif; ?>
<div class="card"><h3>Accounts</h3><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Actions</th></tr></thead><tbody>
<?php foreach($users as $u=>$meta): $role=isset($meta['role'])?$meta['role']:'mod'; ?><tr><td><?=htmlspecialchars($u)?></td><td><?=htmlspecialchars($role)?></td><td class="actions">
<form method="post"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="change_role"><input type="hidden" name="user" value="<?=htmlspecialchars($u)?>"><select name="role"><option value="mod" <?=$role==='mod'?'selected':''?>>mod</option><option value="admin" <?=$role==='admin'?'selected':''?>>admin</option></select><button>Update Role</button></form>
<form method="post"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="reset_pass"><input type="hidden" name="user" value="<?=htmlspecialchars($u)?>"><input type="text" name="new_pass" placeholder="New password"><button>Reset Password</button></form>
<form method="post" onsubmit="return confirm('Delete user <?=$u?>?');"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="delete_user"><input type="hidden" name="user" value="<?=htmlspecialchars($u)?>"><button class="ban">Delete</button></form>
</td></tr><?php endforeach; ?></tbody></table></div></div>
<div class="card"><h3>Add User</h3><form method="post" class="controls-row"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="add_user"><label>Username<input type="text" name="new_user" placeholder="e.g. mod1" required></label><label>Password<input type="text" name="new_pass" placeholder="temporary password" required></label><label>Role<select name="new_role"><option value="mod" selected>mod</option><option value="admin">admin</option></select></label><button>Add</button></form><p class="small-note">Tip: After a moderator logs in, have them change their password via the Settings page.</p></div>
<?php endif; ?></div><?php if(function_exists('panel_footer')) panel_footer(); ?>
</body></html>
