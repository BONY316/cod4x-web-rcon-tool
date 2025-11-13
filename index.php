<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/config/auth.php';
require_once __DIR__ . '/includes/footer.php';
if (empty($_SESSION['user'])) { $next=urlencode($_SERVER['REQUEST_URI'] ?? '/rcon/'); header("Location: login.php?next={$next}"); exit; }
$CURRENT_USER = $_SESSION['user'] ?? 'unknown';
$IS_ADMIN = auth_is_admin($CURRENT_USER);

$LOG_DIR = __DIR__ . '/rcon_logs'; if (!is_dir($LOG_DIR)) { @mkdir($LOG_DIR, 0750, true); }
if (is_dir($LOG_DIR) && !is_writable($LOG_DIR)) { @chmod($LOG_DIR, 0750); }
$SERVER_LOGS_DIR = $LOG_DIR . '/servers'; if (!is_dir($SERVER_LOGS_DIR)) { @mkdir($SERVER_LOGS_DIR, 0750, true); }
function server_log_path($serverId, $filename){
  $safe = preg_replace('/[^A-Za-z0-9_\-]/','_', (string)$serverId);
  if ($safe==='') return null;
  $dir = __DIR__ . '/rcon_logs/servers/' . $safe;
  if (!is_dir($dir)) { @mkdir($dir, 0750, true); }
  return $dir . '/' . $filename;
}
$COMMANDS_LOG = $LOG_DIR . '/commands.log'; $KICKED_LOG = $LOG_DIR . '/kicked.log'; $TEMPBAN_LOG = $LOG_DIR . '/tempbanned.log'; $BANNED_LOG = $LOG_DIR . '/banned.log'; $UNBANNED_LOG = $LOG_DIR . '/unbanned.log'; $AUTH_LOG = $LOG_DIR . '/auth.log'; $BANLIST_LOG = $LOG_DIR . '/banlist.log';
$LOG_MAP = ['commands.log'=>$COMMANDS_LOG,'kicked.log'=>$KICKED_LOG,'tempbanned.log'=>$TEMPBAN_LOG,'banned.log'=>$BANNED_LOG,'unbanned.log'=>$UNBANNED_LOG,'banlist.log'=>$BANLIST_LOG,'auth.log'=>$AUTH_LOG];
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16)); $CSRF=$_SESSION['csrf']; $LOG_ERRORS=[];

function append_log_safe($file,$line){ global $LOG_ERRORS,$LOG_DIR,$CURRENT_SERVER_ID;
  if(!is_dir($LOG_DIR)&&!@mkdir($LOG_DIR,0750,true)){ $LOG_ERRORS[]="Log dir not writable/creatable: ".htmlspecialchars($LOG_DIR); return false; }
  if(!is_writable($LOG_DIR)){ @chmod($LOG_DIR,0750); if(!is_writable($LOG_DIR)){ $LOG_ERRORS[]="Log dir not writable: ".htmlspecialchars($LOG_DIR); return false; } }
  $ok=@file_put_contents($file,$line.PHP_EOL,FILE_APPEND|LOCK_EX); if($ok===false){ $LOG_ERRORS[]="Failed writing log file: ".htmlspecialchars(basename($file)); }
  if(!empty($CURRENT_SERVER_ID)){ $per = server_log_path($CURRENT_SERVER_ID, basename($file)); if($per){ @file_put_contents($per,$line.PHP_EOL,FILE_APPEND|LOCK_EX); } }
  return $ok!==False;
}
function tail_lines($filePath,$lines=200,$maxReadBytes=1048576){ $lines=max(1,(int)$lines); if(!is_file($filePath)) return "[no file]"; $size=filesize($filePath); if($size===0) return "[empty]"; $fh=@fopen($filePath,'rb'); if(!$fh) return "[unreadable]"; $chunk=4096; $pos=max(0,$size-min($size,$maxReadBytes)); fseek($fh,$pos); $data=''; while(!feof($fh)){ $data.=fread($fh,$chunk);} fclose($fh); $arr=preg_split('/\r\n|\r|\n/',$data); return implode("\n", array_slice($arr, -$lines)); }

class Cod4Rcon{ private $server,$port,$password,$timeout; public function __construct($server,$port=28960,$password='',$timeout=2){$this->server=$server;$this->port=(int)$port;$this->password=$password;$this->timeout=(float)$timeout;} private function buildPacket($cmd){return "\xFF\xFF\xFF\xFF".'rcon "'.$this->password.'" '.$cmd;} public function sendCommand($cmd){ $sock=socket_create(AF_INET,SOCK_DGRAM,SOL_UDP); if($sock===false) return ['error'=>'socket_create failed: '.socket_strerror(socket_last_error())]; socket_set_option($sock,SOL_SOCKET,SO_RCVTIMEO,["sec"=>(int)$this->timeout,"usec"=>(int)(($this->timeout-(int)$this->timeout)*1000000)]); $packet=$this->buildPacket($cmd); $sent=@socket_sendto($sock,$packet,strlen($packet),0,$this->server,$this->port); if($sent===false){$err=socket_strerror(socket_last_error($sock));socket_close($sock);return ['error'=>"socket_sendto failed: $err"];} global $COMMANDS_LOG,$CURRENT_SERVER_ID; $timestamp=date('Y-m-d H:i:s'); $logCmd=preg_replace('/rcon\s+"[^"]*"/i','rcon "REDACTED"',$packet); $u = isset($_SESSION['user']) ? $_SESSION['user'] : 'unknown'; append_log_safe($COMMANDS_LOG,"[$timestamp] user={$u} {$this->server}:{$this->port}".($CURRENT_SERVER_ID?(" server_id=".$CURRENT_SERVER_ID):"")." -> ".trim($logCmd)); $responses=[]; while(true){ $buf='';$from='';$port=0; $r=@socket_recvfrom($sock,$buf,8192,0,$from,$port); if($r===false||$r===0) break; if(strpos($buf,"\xFF\xFF\xFF\xFF")===0) $buf=substr($buf,4); $responses[]=$buf;} socket_close($sock); if(empty($responses)) return ['error'=>'No response (timed out or blocked by firewall)']; return ['ok'=>implode("\n",$responses)]; } }

function parse_status_players($txt){ $players=[]; foreach(preg_split('/\r\n|\r|\n/',$txt) as $line){ $line=trim($line); if($line===''||!preg_match('/^\d+\s+/',$line)) continue; $t=preg_split('/\s+/',$line); if(count($t)<8) continue; $i=0;$num=$t[$i++]??'';$score=$t[$i++]??'';$ping=$t[$i++]??'';$guid=$t[$i++]??''; $nameParts=[];$ipTok=null; for(;$i<count($t);$i++){ $x=$t[$i]; if(preg_match('/^\d{1,3}(\.\d{1,3}){3}:\d+$/',$x)||$x==='bot'||$x==='loopback'){$ipTok=$x;$i++;break;} $nameParts[]=$x;} $name=trim(implode(' ',$nameParts)); $qport=$t[$i++]??''; $rate=$t[$i++]??''; $ip='';$port=''; if($ipTok && preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/',$ipTok,$m)){$ip=$m[1];$port=$m[2];} else {$ip=$ipTok?:'';} $players[]=['num'=>$num,'score'=>$score,'ping'=>$ping,'guid'=>$guid,'name'=>$name,'addr'=>$ipTok?:'','ip'=>$ip,'ipport'=>$port,'qport'=>$qport,'rate'=>$rate]; } return $players; }

function _servers_json_path(){ return __DIR__ . '/config/servers.json'; }
function load_saved_servers(){ $p=_servers_json_path(); if(is_file($p)){ $raw=@file_get_contents($p); if($raw!==false){ $j=@json_decode($raw,true); if(is_array($j)&&isset($j['servers'])&&is_array($j['servers'])) return $j['servers']; } } return []; }
$SAVED_SERVERS = load_saved_servers();

function bans_json_path(){ return __DIR__ . '/config/bans.json'; }
function load_bans(){ $p=bans_json_path(); if(is_file($p)){ $raw=@file_get_contents($p); if($raw!==false){ $j=@json_decode($raw,true); if(is_array($j)&&isset($j['bans'])) return $j['bans']; } } return []; }
function save_bans($arr,&$err=null){ $p=bans_json_path(); $dir=dirname($p); if(!is_dir($dir)) @mkdir($dir,0750,true); $tmp=$p.'.tmp'; $payload=['bans'=>$arr,'updated'=>date('c')]; if(@file_put_contents($tmp,json_encode($payload,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX)===false){$err='write failed';return false;} if(!@rename($tmp,$p)){ if(!@copy($tmp,$p)||!@unlink($tmp)){ $err='move failed'; return false; } } @chmod($p,0640); return true; }

$flash=null; if(isset($_GET['download'])){ $fname=basename($_GET['download']); global $LOG_MAP; if(isset($LOG_MAP[$fname])&&is_file($LOG_MAP[$fname])){ header('Content-Type: text/plain'); header('Content-Disposition: attachment; filename="'.$fname.'"'); header('Content-Length: '.filesize($LOG_MAP[$fname])); readfile($LOG_MAP[$fname]); exit; } else $flash="Download not available."; }
$server=isset($_POST['server'])?trim((string)$_POST['server']):''; $port=isset($_POST['port'])?(int)$_POST['port']:28960; $pass=$_POST['password']??''; $cmd=isset($_POST['command'])?trim((string)$_POST['command']):''; $action=$_POST['action']??''; $output=null; $error=null; $players=[]; $CURRENT_SERVER_ID='';

if($_SERVER['REQUEST_METHOD']==='POST' && (!isset($_POST['action']) || $_POST['action']!=='clear_log')){
  if (!empty($_POST['saved_server_id'])){
    foreach($SAVED_SERVERS as $S){
      if (($S['id']??'') === $_POST['saved_server_id']){
        $server = $S['host'] ?? $server;
        $port   = $S['port'] ?? $port;
        $pass   = $S['rcon'] ?? $pass;
        $CURRENT_SERVER_ID = $_POST['saved_server_id'];
        break;
      }
    }
  }
  $rcon=null; if(!empty($server)) $rcon=new Cod4Rcon($server,$port,$pass,2.0);
  if($action==='refresh_players'){ if(!$rcon){$error="Please supply server IP to fetch players.";} else { $res=$rcon->sendCommand('status'); if(isset($res['error']))$error=htmlspecialchars($res['error']); else $players=parse_status_players($res['ok']);} }
  elseif($action==='kick' && isset($_POST['slot'])){ if(!$rcon){$error="Please supply server IP to kick.";} else { $slot=(int)$_POST['slot']; $resKick=$rcon->sendCommand("clientkick $slot"); $playerName=$_POST['player_name']??'UNKNOWN'; $playerAddr=$_POST['player_addr']??''; $ts=date('Y-m-d H:i:s'); append_log_safe($KICKED_LOG,"[$ts] user={$CURRENT_USER} {$server}:{$port} - Kick slot={$slot} name=\"{$playerName}\" addr=\"{$playerAddr}\" result=\"".(isset($resKick['error'])?$resKick['error']:'OK')."\""); $res=$rcon->sendCommand('status'); if(!isset($res['error'])) $players=parse_status_players($res['ok']); $flash="Kick sent for #$slot."; } }
  elseif($action==='ban' && isset($_POST['slot'])){ if(!$rcon){$error="Please supply server IP to ban.";} else { $slot=(int)$_POST['slot']; $resBan=$rcon->sendCommand("banClient $slot"); $pn=$_POST['player_name']??'UNKNOWN'; $pa=$_POST['player_addr']??''; $ts=date('Y-m-d H:i:s'); append_log_safe($BANNED_LOG,"[$ts] user={$CURRENT_USER} {$server}:{$port} - BAN slot={$slot} name=\"{$pn}\" addr=\"{$pa}\" result=\"".(isset($resBan['error'])?$resBan['error']:'OK')."\""); $res=$rcon->sendCommand('status'); if(!isset($res['error'])) $players=parse_status_players($res['ok']); $flash="Permanent ban sent for #$slot."; } }
  elseif($action==='tempban' && isset($_POST['slot'])){ if(!$rcon){$error="Please supply server IP to tempban.";} else { $slot=(int)$_POST['slot']; $dur=0; if(!empty($_POST['duration_preset'])&&is_numeric($_POST['duration_preset'])) $dur=(int)$_POST['duration_preset']; elseif(!empty($_POST['duration_custom'])&&is_numeric($_POST['duration_custom'])) $dur=(int)$_POST['duration_custom']; $reason=''; if(!empty($_POST['reason_preset'])) $reason=trim($_POST['reason_preset']); if(!empty($_POST['reason_custom'])) $reason=trim($_POST['reason_custom']); if($reason==='') $reason='No reason provided'; $pn=$_POST['player_name']??'UNKNOWN'; $announce=substr("Player {$pn} temporarily banned for {$dur}s. Reason: {$reason}",0,200); $rcon->sendCommand("say \"$announce\""); $cmdTemp="tempBanClient $slot $dur"; $resTemp=$rcon->sendCommand($cmdTemp); $pa=$_POST['player_addr']??''; $ts=date('Y-m-d H:i:s'); append_log_safe($TEMPBAN_LOG,"[$ts] user={$CURRENT_USER} {$server}:{$port} - TEMPBAN slot={$slot} name=\"{$pn}\" addr=\"{$pa}\" duration_seconds={$dur} reason=\"{$reason}\" result=\"".(isset($resTemp['error'])?$resTemp['error']:'OK')."\" cmd=\"{$cmdTemp}\""); $res=$rcon->sendCommand('status'); if(!isset($res['error'])) $players=parse_status_players($res['ok']); $flash="Tempban sent for #$slot ({$dur} sec)."; } }
  elseif(!empty($cmd)){ if(empty($server)) $error="Please supply server IP and command."; else { $rcon=$rcon?:new Cod4Rcon($server,$port,$pass,2.0); $res=$rcon->sendCommand($cmd); if(isset($res['error'])) $error=htmlspecialchars($res['error']); else $output=htmlspecialchars($res['ok']); } }
}

$SHOW_LOGS=isset($_GET['logs'])&&$_GET['logs']==='1'; $SHOW_BANS=isset($_GET['bans'])&&$_GET['bans']==='1';
$TAIL_FILE=(isset($_GET['file'])&&isset($LOG_MAP[$_GET['file']]))?$_GET['file']:'commands.log'; $TAIL_LINES=(isset($_GET['lines'])&&is_numeric($_GET['lines']))?max(10,min(5000,(int)$_GET['lines'])):200; $QUERY=isset($_GET['q'])?trim($_GET['q']):''; $USER_FILTER=isset($_GET['user'])?trim($_GET['user']):'all'; $SCOPE=isset($_GET['scope'])?trim($_GET['scope']):'global';
$SCOPE_LABEL = $SCOPE === 'global' ? 'global' : $SCOPE;
if($SCOPE !== 'global'){
  foreach($SAVED_SERVERS as $s){ $sid=$s['id']??''; if($sid===$SCOPE){ $nm=$s['name']??$sid; $host=$s['host']??''; $port=$s['port']??28960; $SCOPE_LABEL = trim($nm.($host ? " @ {$host}:{$port}" : '')); break; } }
}

$ACTIVE_LOG_MAP = $LOG_MAP; if($SCOPE!=='global' && $SCOPE!==''){ foreach($ACTIVE_LOG_MAP as $k=>$p){ $per=server_log_path($SCOPE,$k); if($per && is_file($per)) $ACTIVE_LOG_MAP[$k]=$per; } }
$TAIL_TEXT=tail_lines($ACTIVE_LOG_MAP[$TAIL_FILE],$TAIL_LINES); $FILTERED_TEXT=$TAIL_TEXT; $MATCH_COUNT=0;
if(!in_array($TAIL_TEXT,["[no file]","[empty]","[unreadable]"],true)){ $lines=preg_split('/\r\n|\r|\n/',$TAIL_TEXT); $out=[]; foreach($lines as $ln){ if($USER_FILTER!=='all' && stripos($ln,"user=".$USER_FILTER)===false) continue; if($QUERY!=='' && stripos($ln,$QUERY)===false) continue; $safe=htmlspecialchars($ln); if($QUERY!==''){ $safe=preg_replace('/('.preg_quote($QUERY,'/').')/i','<mark>$1</mark>',$safe);} $out[]=$safe;} $MATCH_COUNT=count($out); $FILTERED_TEXT=$MATCH_COUNT?implode("\n",$out):"[no matches]"; }

$BANS = load_bans(); $BANLIST_TEXT=''; $BAN_FLASH=null; $BAN_ERROR=null;
if ($SHOW_BANS) {
  $active = array_values(array_filter($BANS, function($b){ return ($b['status'] ?? 'active') === 'active'; }));
  $lines = []; foreach($active as $b){ $lines[] = sprintf("id=%s guid=%s type=%s duration=%s created=%s expires=%s by=%s server=%s reason=%s", $b['id']??'', $b['guid']??'', $b['type']??'', $b['duration']??0, $b['created_at']??'', $b['expires_at']??'n/a', $b['created_by']??'', $b['server_id']??'global', $b['reason']??'' ); } $BANLIST_TEXT = htmlspecialchars($lines ? implode("\n", $lines) : "[no active website bans]");
  if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['bans_action'])) {
    $act = $_POST['bans_action'];
    if ($act==='add_temp' || $act==='add_perm') {
      $guid = trim($_POST['guid'] ?? ''); $name = trim($_POST['player_name'] ?? ''); $reason = trim($_POST['reason_custom'] ?? ($_POST['reason_preset'] ?? '')); if ($reason==='') $reason = 'No reason provided';
      $serverId = trim($_POST['saved_server_id'] ?? ''); $duration = 0;
      if ($act==='add_temp') { if (!empty($_POST['duration_preset']) && is_numeric($_POST['duration_preset'])) $duration=(int)$_POST['duration_preset']; elseif (!empty($_POST['duration_custom']) && is_numeric($_POST['duration_custom'])) $duration=(int)$_POST['duration_custom']; }
      if ($guid==='') { $BAN_ERROR='GUID is required.'; }
      else { $id = bin2hex(random_bytes(8)); $entry = ['id'=>$id,'guid'=>$guid,'name'=>$name,'reason'=>$reason,'type'=>($act==='add_perm'?'perm':'temp'),'duration'=>$duration,'created_by'=>$CURRENT_USER,'server_id'=>$serverId,'created_at'=>date('c'),'expires_at'=>($act==='add_perm'?null:date('c', time()+$duration)),'status'=>'active']; $BANS[]=$entry; $saveErr=null; if (save_bans($BANS,$saveErr)){ $BAN_FLASH = ($act==='add_perm'?'Perm ban':'Temp ban').' added locally for GUID '.$guid.'.'; $ts=date('Y-m-d H:i:s'); append_log_safe($BANLIST_LOG,"[$ts] user={$CURRENT_USER} server_id=".($serverId?:'global')." action=".( $act==='add_perm'?'perm_ban':'temp_ban' )." guid={$guid} name=\"{$name}\" reason=\"{$reason}\" duration={$duration}"); } else { $BAN_ERROR='Failed to save banlist. '.htmlspecialchars($saveErr ?? ''); } }
    } elseif ($act==='unban_guid') {
      $guid = trim($_POST['guid'] ?? ''); if ($guid==='') { $BAN_ERROR='Enter a GUID to unban.'; } else { $changed=false; foreach($BANS as &$b){ if(($b['guid']??'')===$guid && ($b['status']??'active')==='active'){ $b['status']='unbanned'; $b['unbanned_by']=$CURRENT_USER; $b['unbanned_at']=date('c'); $changed=true; } } if($changed){ $saveErr=null; if(save_bans($BANS,$saveErr)){ $BAN_FLASH='Unbanned GUID '.$guid.' (website list).'; $ts=date('Y-m-d H:i:s'); append_log_safe($UNBANNED_LOG,"[$ts] user={$CURRENT_USER} server_id=".($_POST['saved_server_id']??'global')." - UNBAN guid={$guid}"); } else { $BAN_ERROR='Failed to write bans.json.'; } } else { $BAN_ERROR='GUID not found or already unbanned.'; } }
    } elseif ($act==='unban_id') {
      $bid = trim($_POST['ban_id'] ?? ''); if ($bid==='') { $BAN_ERROR='Enter a Ban ID to unban.'; } else { $changed=false; foreach($BANS as &$b){ if(($b['id']??'')===$bid && ($b['status']??'active')==='active'){ $b['status']='unbanned'; $b['unbanned_by']=$CURRENT_USER; $b['unbanned_at']=date('c'); $changed=true; } } if($changed){ $saveErr=null; if(save_bans($BANS,$saveErr)){ $BAN_FLASH='Unbanned ID '.$bid.' (website list).'; $ts=date('Y-m-d H:i:s'); append_log_safe($UNBANNED_LOG,"[$ts] user={$CURRENT_USER} server_id=".($_POST['saved_server_id']??'global')." - UNBAN id={$bid}"); } else { $BAN_ERROR='Failed to write bans.json.'; } } else { $BAN_ERROR='Ban ID not found or already unbanned.'; } }
    }
  }
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CoD4x RCON Tool</title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="assets/styles.css"></head>
<body><div class="container"><div class="topbar"><div class="logo-wrap"><span class="logo-pill">CoD4X</span><h2>CoD4X Web RCON Tool</h2></div><div><?php if($SHOW_LOGS): ?><a class="linkbtn" href="?">Back to Control</a><?php else: ?><a class="linkbtn" href="?logs=1">View Logs</a><?php endif; ?><a class="linkbtn" href="?bans=1" style="margin-left:8px">Bans</a><a class="linkbtn" href="settings.php" style="margin-left:8px">Settings</a><?php if($IS_ADMIN): ?><a class="linkbtn" href="servers.php" style="margin-left:8px">Servers</a><a class="linkbtn" href="users.php" style="margin-left:8px">Users</a><?php endif; ?><a class="linkbtn danger" href="logout.php" style="margin-left:8px">Logout</a></div></div>
<?php if(!$SHOW_LOGS && !$SHOW_BANS): ?>
<form method="post" id="controlForm">
  <div class="row">
    <label>Saved server
      <select id="serverSelect" onchange="applyServer(this.value)">
        <option value="">— Select a saved server —</option>
        <?php foreach($SAVED_SERVERS as $s): $sid=$s['id']??''; $label=($s['name']??'').' ('.($s['host']??'').':'.($s['port']??'').')'; ?>
          <option value="<?=htmlspecialchars($sid)?>"><?=htmlspecialchars($label)?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label>Server IP or Hostname <input type="text" name="server" value="<?=htmlspecialchars($server)?>" placeholder="1.2.3.4 or hostname"></label>
  </div>
  <div class="row">
    <label>Port <input type="number" name="port" value="<?=htmlspecialchars($port)?>" min="1" max="65535"></label>
    <label>RCON Password <?php if(!$IS_ADMIN): ?><small>(Auto-filled; hidden for moderators)</small><?php endif; ?>
      <input type="text" id="rconInput" name="password" value="<?=htmlspecialchars($pass)?>" <?php if(!$IS_ADMIN): ?>style="display:none"<?php endif; ?>>
    </label>
    <input type="hidden" name="saved_server_id" id="savedServerId" value="">
  </div>
  <div class="row">
    <label>Command <input type="text" name="command" value="<?=htmlspecialchars($cmd)?>" placeholder="e.g. status"><small>This tool wraps your command with <code>rcon &quot;PASSWORD&quot;</code>.</small></label>
  </div>
  <button type="submit">Send Command</button>
</form>
<?php if($error): ?><div class="error"><?=$error?></div><?php endif; ?>
<?php if($output!==null): ?><h3 class="section-title">Response</h3><pre><?=$output?></pre><?php endif; ?>
<?php if($flash): ?><div class="flash"><?=htmlspecialchars($flash)?></div><?php endif; ?>
<?php if(!empty($LOG_ERRORS)): ?><div class="logwarn"><strong>Log warning:</strong><ul><?php foreach($LOG_ERRORS as $le):?><li><?=$le?></li><?php endforeach;?></ul><div class="small-note">Ensure the web user can write to <code><?=htmlspecialchars($LOG_DIR)?></code>.</div></div><?php endif; ?>
<hr><h3 class="section-title">Players Online</h3>
<form method="post" style="margin-bottom:10px"><input type="hidden" name="server" value="<?=htmlspecialchars($server)?>"><input type="hidden" name="port" value="<?=htmlspecialchars($port)?>"><input type="hidden" name="password" value="<?=htmlspecialchars($pass)?>"><input type="hidden" name="action" value="refresh_players"><input type="hidden" name="saved_server_id" id="savedServerId2" value=""><button type="submit">Refresh Players</button></form>
<?php if(!empty($players)): ?><div class="table-wrap"><table><thead><tr><th>#</th><th class="name">Name</th><th>Score</th><th>Ping</th><th>GUID</th><th>IP:Port</th><th class="actions">Actions</th></tr></thead><tbody>
<?php foreach($players as $p): ?><tr><td><?=htmlspecialchars($p['num'])?></td><td class="name"><?=htmlspecialchars($p['name'])?></td><td><?=htmlspecialchars($p['score'])?></td><td><?=htmlspecialchars($p['ping'])?></td><td><?=htmlspecialchars($p['guid'])?></td><td><?=htmlspecialchars($p['ip'].($p['ipport']?':'.$p['ipport']:''))?></td><td class="actions">
<form method="post"><input type="hidden" name="server" value="<?=htmlspecialchars($server)?>"><input type="hidden" name="port" value="<?=htmlspecialchars($port)?>"><input type="hidden" name="password" value="<?=htmlspecialchars($pass)?>"><input type="hidden" name="slot" value="<?=htmlspecialchars($p['num'])?>"><input type="hidden" name="player_name" value="<?=htmlspecialchars($p['name'])?>"><input type="hidden" name="player_addr" value="<?=htmlspecialchars($p['addr'])?>"><input type="hidden" name="saved_server_id" id="savedServerId3" value=""><button class="kick" name="action" value="kick" onclick="return confirm('Kick #<?=htmlspecialchars($p['num'])?> (<?=htmlspecialchars($p['name'])?>)?')">Kick</button></form>
<form method="post"><input type="hidden" name="server" value="<?=htmlspecialchars($server)?>"><input type="hidden" name="port" value="<?=htmlspecialchars($port)?>"><input type="hidden" name="password" value="<?=htmlspecialchars($pass)?>"><input type="hidden" name="slot" value="<?=htmlspecialchars($p['num'])?>"><input type="hidden" name="player_name" value="<?=htmlspecialchars($p['name'])?>"><input type="hidden" name="player_addr" value="<?=htmlspecialchars($p['addr'])?>"><input type="hidden" name="saved_server_id" id="savedServerId4" value=""><div class="tempban-controls"><select name="duration_preset"><option value="300">5 min</option><option value="1800">30 min</option><option value="3600" selected>1 hour</option><option value="21600">6 hours</option><option value="86400">24 hours</option><option value="604800">7 days</option></select><select name="reason_preset"><option value="Rule violation">Rule violation</option><option value="Abusive language">Abusive language</option><option value="Hacking / cheating">Hacking / cheating</option><option value="AFK / inactivity">AFK / inactivity</option><option value="Griefing">Griefing</option><option value="Other" selected>Other</option></select><input type="text" name="reason_custom" placeholder="Custom reason (optional)"><button class="ban" name="action" value="tempban" onclick="return confirm('Tempban #<?=htmlspecialchars($p['num'])?> (<?=htmlspecialchars($p['name'])?>)?')">TempBan</button></div></form>
<form method="post"><input type="hidden" name="server" value="<?=htmlspecialchars($server)?>"><input type="hidden" name="port" value="<?=htmlspecialchars($port)?>"><input type="hidden" name="password" value="<?=htmlspecialchars($pass)?>"><input type="hidden" name="slot" value="<?=htmlspecialchars($p['num'])?>"><input type="hidden" name="player_name" value="<?=htmlspecialchars($p['name'])?>"><input type="hidden" name="player_addr" value="<?=htmlspecialchars($p['addr'])?>"><input type="hidden" name="saved_server_id" id="savedServerId5" value=""><button class="ban" name="action" value="ban" onclick="return confirm('Permanent ban #<?=htmlspecialchars($p['num'])?> (<?=htmlspecialchars($p['name'])?>)?')">Ban</button></form>
</td></tr><?php endforeach; ?></tbody></table></div>
<?php elseif(in_array($action,['refresh_players','kick','ban','tempban'])): ?><p><small>No players found or status could not be parsed.</small></p>
<?php else: ?><p><small>Select a saved server or enter host/port, then click “Refresh Players”.</small></p><?php endif; ?>
<hr><h4>Logs directory</h4><p class="small-note">Logs: <code><?=htmlspecialchars($LOG_DIR)?></code></p><ul><li><code>commands.log</code></li><li><code>kicked.log</code></li><li><code>tempbanned.log</code></li><li><code>banned.log</code></li><li><code>unbanned.log</code></li><li><code>banlist.log</code> (website bans)</li><li><code>auth.log</code> (logins/logouts)</li></ul><p class="small-note">Each file also mirrors to <code>rcon_logs/servers/&lt;serverId&gt;/</code> when a saved server is used.</p>
<?php elseif($SHOW_BANS): ?>
<div class="tabbar"><a class="tab" href="?">Control</a><a class="tab" href="?logs=1">Logs</a><a class="tab active" href="?bans=1">Bans</a></div>
<div class="card">
  <?php if($BAN_ERROR): ?><div class="error"><?=$BAN_ERROR?></div><?php endif; ?>
  <?php if($BAN_FLASH): ?><div class="flash"><?=$BAN_FLASH?></div><?php endif; ?>
  <div class="row">
    <div>
      <h3>Add Website Temp Ban</h3>
      <form method="post" class="controls-row">
        <input type="hidden" name="bans_action" value="add_temp">
        <label>Apply to Saved Server
          <select name="saved_server_id">
            <option value="">Global (all)</option>
            <?php foreach($SAVED_SERVERS as $s): $sid=$s['id']??''; $label=($s['name']??'').' ('.($s['host']??'').':'.($s['port']??'').')'; ?>
              <option value="<?=htmlspecialchars($sid)?>"><?=htmlspecialchars($label)?></option>
            <?php endforeach; ?>
          </select>
        </label>
        <label>GUID<input type="text" name="guid" placeholder="Player GUID" required></label>
        <label>Player name (optional)<input type="text" name="player_name" placeholder="Name (for log only)"></label>
        <div class="tempban-controls">
          <select name="duration_preset"><option value="300">5 min</option><option value="1800">30 min</option><option value="3600" selected>1 hour</option><option value="21600">6 hours</option><option value="86400">24 hours</option><option value="604800">7 days</option></select>
          <input type="text" name="duration_custom" placeholder="Or custom seconds">
          <select name="reason_preset"><option value="Rule violation">Rule violation</option><option value="Abusive language">Abusive language</option><option value="Hacking / cheating">Hacking / cheating</option><option value="AFK / inactivity">AFK / inactivity</option><option value="Griefing">Griefing</option><option value="Other" selected>Other</option></select>
          <input type="text" name="reason_custom" placeholder="Custom reason (optional)">
          <button class="ban">Add Temp Ban</button>
        </div>
      </form>
    </div>
    <div>
      <h3>Add Website Perm Ban</h3>
      <form method="post" class="controls-row">
        <input type="hidden" name="bans_action" value="add_perm">
        <label>Apply to Saved Server
          <select name="saved_server_id">
            <option value="">Global (all)</option>
            <?php foreach($SAVED_SERVERS as $s): $sid=$s['id']??''; $label=($s['name']??'').' ('.($s['host']??'').':'.($s['port']??'').')'; ?>
              <option value="<?=htmlspecialchars($sid)?>"><?=htmlspecialchars($label)?></option>
            <?php endforeach; ?>
          </select>
        </label>
        <label>GUID<input type="text" name="guid" placeholder="Player GUID" required></label>
        <label>Player name (optional)<input type="text" name="player_name" placeholder="Name (for log only)"></label>
        <label>Reason<input type="text" name="reason_custom" placeholder="Reason" required></label>
        <button class="ban">Add Perm Ban</button>
      </form>
    </div>
  </div>
  <hr>
  <h3 class="section-title">Active Website Bans</h3>
  <pre style="max-height:300px;overflow:auto"><?= $BANLIST_TEXT !== '' ? $BANLIST_TEXT : '[no active website bans]' ?></pre>
  <div class="row">
    <form method="post">
      <input type="hidden" name="bans_action" value="unban_guid">
      <label>Unban by GUID<input type="text" name="guid" placeholder="GUID string"></label>
      <button class="kick">Unban GUID</button>
    </form>
    <form method="post">
      <input type="hidden" name="bans_action" value="unban_id">
      <label>Unban by Ban ID<input type="text" name="ban_id" placeholder="Website Ban ID"></label>
      <button class="kick">Unban ID</button>
    </form>
  </div>
</div>
<?php else: ?>
<div class="tabbar"><a class="tab active" href="?logs=1">Logs</a><a class="tab" href="?">Control</a><a class="tab" href="?bans=1">Bans</a></div>
<div class="card"><div class="controls-row">
<form method="get" class="controls-inline" style="display:inline-flex;gap:10px;align-items:center;"><input type="hidden" name="logs" value="1">
<label>Scope<select name="scope"><option value="global" <?= (!isset($_GET['scope'])||$_GET['scope']==="global")?'selected':'' ?>>Global</option><?php foreach($SAVED_SERVERS as $s): $sid=$s['id']??''; ?><option value="<?=htmlspecialchars($sid)?>" <?= (($_GET['scope']??'global')===$sid)?'selected':'' ?>>Server: <?=htmlspecialchars($s['name']??$sid)?></option><?php endforeach; ?></select></label>
<label>File<select name="file"><?php foreach(array_keys($LOG_MAP) as $fn): ?><option value="<?=$fn?>" <?=$fn===$TAIL_FILE?'selected':''?>><?=$fn?></option><?php endforeach; ?></select></label>
<label>Lines<input type="number" name="lines" min="10" max="5000" value="<?=htmlspecialchars($TAIL_LINES)?>" style="width:100px"></label>
<label>Search<input type="text" name="q" value="<?=htmlspecialchars($QUERY)?>" placeholder="slot, name, IP…" style="width:200px"></label>
<label>User<select name="user"><option value="all" <?= $USER_FILTER==='all'?'selected':'' ?>>All users</option><?php foreach(array_keys(auth_load_users()) as $uname): ?><option value="<?=htmlspecialchars($uname)?>" <?= $USER_FILTER===$uname?'selected':'' ?>><?=htmlspecialchars($uname)?></option><?php endforeach; ?></select></label>
<button type="submit">Refresh</button><a class="linkbtn" href="?download=<?=urlencode($TAIL_FILE)?>">Download</a></form>
<form method="post" style="display:inline-flex;gap:10px;align-items:center;" onsubmit="return confirm('Clear <?=htmlspecialchars($TAIL_FILE)?>? This cannot be undone.');"><input type="hidden" name="action" value="clear_log"><input type="hidden" name="file" value="<?=htmlspecialchars($TAIL_FILE)?>"><input type="hidden" name="csrf" value="<?=htmlspecialchars($CSRF)?>"><button type="submit" class="linkbtn danger">Clear Log</button></form>
</div>
<h3 style="margin-top:12px;">Viewing: <?=htmlspecialchars($TAIL_FILE)?> (last <?=htmlspecialchars($TAIL_LINES)?> lines, scope: <?=htmlspecialchars($SCOPE_LABEL ?? $SCOPE)?>)</h3>
<pre><?=htmlspecialchars($FILTERED_TEXT)?></pre>
<p class="small-note">Use the <b>User</b> filter to see actions from a specific admin. Use <b>Scope</b> to view a specific server's mirrored logs.</p>
</div>
<?php if(!empty($LOG_ERRORS)): ?><div class="logwarn"><strong>Log warning:</strong><ul><?php foreach($LOG_ERRORS as $le):?><li><?=$le?></li><?php endforeach;?></ul><div class="small-note">Ensure the web user can write to <code><?=htmlspecialchars($LOG_DIR)?></code>.</div></div><?php endif; ?>
<?php endif; ?></div>
<script>
  const servers = <?php
    $arr = [];
    foreach($SAVED_SERVERS as $s){
      $arr[$s['id']] = ['host'=>$s['host']??'', 'port'=>$s['port']??28960, 'rcon'=>$s['rcon']??''];
    }
    echo json_encode($arr);
  ?>;
  function applyServer(id){
    const s = servers[id] || null;
    const host = document.querySelector('input[name="server"]');
    const port = document.querySelector('input[name="port"]');
    const rcon = document.getElementById('rconInput');
    const ids = ['savedServerId','savedServerId2','savedServerId3','savedServerId4','savedServerId5'];
    if (s){
      if (host) host.value = s.host || '';
      if (port) port.value = s.port || 28960;
      if (rcon) rcon.value = s.rcon || '';
      ids.forEach(id2=>{ const el=document.getElementById(id2); if(el) el.value = id; });
    } else {
      ids.forEach(id2=>{ const el=document.getElementById(id2); if(el) el.value=''; });
    }
  }
</script>
<?php if(function_exists('panel_footer')) panel_footer(); ?>
</body></html>