<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$LOG_DIR = __DIR__ . '/rcon_logs'; if (!is_dir($LOG_DIR)) { @mkdir($LOG_DIR, 0750, true); }
$AUTH_LOG = $LOG_DIR . '/auth.log';
function auth_log_line($msg){ global $AUTH_LOG; @file_put_contents($AUTH_LOG, "[@".date('Y-m-d H:i:s')."] ".$msg.PHP_EOL, FILE_APPEND | LOCK_EX); }
$u=$_SESSION['user']??'unknown'; auth_log_line("user={$u} event=logout ip=".$_SERVER['REMOTE_ADDR']);
session_unset(); session_destroy(); header('Location: login.php'); exit;
