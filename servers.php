<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/config/auth.php';
require_once __DIR__ . '/includes/footer.php';
if (empty($_SESSION['user'])) { header("Location: login.php?next=" . urlencode($_SERVER['REQUEST_URI'])); exit; }
$ME = $_SESSION['user']; $IS_ADMIN = auth_is_admin($ME);
if (!$IS_ADMIN) { http_response_code(403); echo "<!doctype html><meta charset='utf-8'><link rel='stylesheet' href='assets/styles.css'><div class='container'><div class='error'>Admins only.</div></div>"; exit; }

$LOG_DIR = __DIR__ . '/rcon_logs'; if (!is_dir($LOG_DIR)) { @mkdir($LOG_DIR, 0750, true); }
$AUTH_LOG = $LOG_DIR . '/auth.log';
function audit($msg){ global $AUTH_LOG; @file_put_contents($AUTH_LOG, "[@".date('Y-m-d H:i:s')."] ".$msg.PHP_EOL, FILE_APPEND | LOCK_EX); }

$CFG = __DIR__ . '/config/servers.json';
if (!is_dir(dirname($CFG))) @mkdir(dirname($CFG), 0750, true);

function load_servers($p){ if(is_file($p)){ $raw=@file_get_contents($p); if($raw!==false){ $j=@json_decode($raw,true); if(is_array($j)&&isset($j['servers'])&&is_array($j['servers'])) return $j['servers']; } } return []; }
function save_servers($p,$list,&$err=null){
  $payload=['servers'=>$list,'updated'=>date('c')]; $tmp=$p.'.tmp';
  if(@file_put_contents($tmp,json_encode($payload,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX)===false){$err='write failed';return false;}
  if(!@rename($tmp,$p)){ if(!@copy($tmp,$p)||!@unlink($tmp)){ $err='move failed'; return false; } }
  @chmod($p,0640); return true;
}
$servers = load_servers($CFG);
if (empty($_SESSION['csrf_servers'])) $_SESSION['csrf_servers']=bin2hex(random_bytes(16)); $CSRF=$_SESSION['csrf_servers']; $flash=''; $err='';

if($_SERVER['REQUEST_METHOD']==='POST'){
  if(!hash_equals($CSRF,$_POST['csrf']??'')) $err='Invalid CSRF token.';
  else {
    $act=$_POST['act']??'';
    if($act==='add'){
      $name=trim($_POST['name']??''); $host=trim($_POST['host']??''); $port=(int)($_POST['port']??28960); $rcon=(string)($_POST['rcon']??'');
      if($name===''||$host===''||$rcon==='') $err='Name, host, and RCON are required.';
      else { $id=bin2hex(random_bytes(8)); $servers[]=['id'=>$id,'name'=>$name,'host'=>$host,'port'=>$port,'rcon'=>$rcon]; if(save_servers($CFG,$servers,$saveErr)){ $flash="Added server {$name}."; audit("user={$ME} event=add_server name={$name} host={$host}:{$port} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save servers. '.htmlspecialchars($saveErr ?? ''); } }
    } elseif($act==='delete'){
      $id=$_POST['id']??''; $old=count($servers);
      $servers=array_values(array_filter($servers,function($s) use ($id){ return isset($s['id']) ? $s['id']!==$id : true; }));
      if(count($servers)===$old) $err='Server not found.';
      else { if(save_servers($CFG,$servers,$saveErr)){ $flash='Deleted server.'; audit("user={$ME} event=delete_server id={$id} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save servers. '.htmlspecialchars($saveErr ?? ''); } }
    } elseif($act==='update'){
      $id=$_POST['id']??''; $found=false;
      foreach($servers as &$s){
        if(($s['id']??'')===$id){ $found=true;
          if(isset($_POST['name'])&&$_POST['name']!=='') $s['name']=trim($_POST['name']);
          if(isset($_POST['host'])&&$_POST['host']!=='') $s['host']=trim($_POST['host']);
          if(isset($_POST['port'])&&$_POST['port']!=='') $s['port']=(int)$_POST['port'];
          if(isset($_POST['rcon'])&&$_POST['rcon']!=='') $s['rcon']=(string)$_POST['rcon'];
          break;
        }
      }
      if(!$found) $err='Server not found.';
      else { if(save_servers($CFG,$servers,$saveErr)){ $flash='Updated server.'; audit("user={$ME} event=update_server id={$id} ip=".$_SERVER['REMOTE_ADDR']); } else { $err='Failed to save servers. '.htmlspecialchars($saveErr ?? ''); } }
    }
  }
}
$servers = load_servers($CFG);
?><!doctype html><html lang="en"><head><meta charset="utf-8"><title>Servers – <?=htmlspecialchars($SITE_NAME)?></title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="assets/styles.css"></head>
<body><div class="container"><div class="topbar"><div class="logo-wrap"><span class="logo-pill">CoD4X</span><h2>CoD4X Web RCON Tool</h2></div><div><a class="linkbtn" href="index.php">Back to Panel</a><a class="linkbtn" href="settings.php" style="margin-left:8px">Settings</a><a class="linkbtn danger" href="logout.php" style="margin-left:8px">Logout</a></div></div>
<?php if($err): ?><div class="error"><?=$err?></div><?php endif; ?><?php if($flash): ?><div class="flash"><?=$flash?></div><?php endif; ?>
<div class="card"><h3>Saved Servers</h3><div class="table-wrap"><table><thead><tr><th>Name</th><th>Host</th><th>Port</th><th>Actions</th></tr></thead><tbody>
<?php foreach($servers as $s): ?><tr><td><?=htmlspecialchars($s['name']??'')?></td><td><?=htmlspecialchars($s['host']??'')?></td><td><?=htmlspecialchars($s['port']??'')?></td><td class="actions"><form method="post"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="delete"><input type="hidden" name="id" value="<?=htmlspecialchars($s['id']??'')?>"><button class="ban" onclick="return confirm('Delete this server?')">Delete</button></form></td></tr><?php endforeach; if(empty($servers)): ?><tr><td colspan="4"><small>No servers saved yet.</small></td></tr><?php endif; ?></tbody></table></div></div>
<div class="card"><h3>Add / Update Server</h3><form method="post" class="row"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="add"><label>Name<input type="text" name="name" placeholder="e.g., Outpost ZOM_DB" required></label><label>Host/IP<input type="text" name="host" placeholder="1.2.3.4" required></label><label>Port<input type="number" name="port" value="28960" min="1" max="65535" required></label><label>RCON Password<input type="text" name="rcon" placeholder="server rcon password" required></label><button>Add Server</button></form>
<?php if(!empty($servers)): ?><hr><form method="post" class="row"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><input type="hidden" name="act" value="update"><label>Server<select name="id" required><?php foreach($servers as $s): ?><option value="<?=htmlspecialchars($s['id'])?>"><?=htmlspecialchars(($s['name']??'').' ('.($s['host']??'').':'.($s['port']??'').')')?></option><?php endforeach; ?></select></label><label>Name<input type="text" name="name" placeholder="leave blank to keep"></label><label>Host/IP<input type="text" name="host" placeholder="leave blank to keep"></label><label>Port<input type="number" name="port" placeholder="leave blank to keep"></label><label>RCON Password<input type="text" name="rcon" placeholder="leave blank to keep"></label><button>Update</button></form><?php endif; ?></div></div><?php if(function_exists('panel_footer')) panel_footer(); ?>
</body></html>
