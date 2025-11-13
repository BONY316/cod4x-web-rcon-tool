<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/config/auth.php';
require_once __DIR__ . '/includes/footer.php';

if (function_exists('auth_has_persisted_users') && auth_has_persisted_users()){
  header("Location: login.php");
  exit;
}

$err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST'){
  $username = trim($_POST['username'] ?? '');
  $password = (string)($_POST['password'] ?? '');
  $confirm  = (string)($_POST['confirm'] ?? '');
  if ($username === '' || $password === ''){
    $err = 'Username and password are required.';
  } elseif ($password !== $confirm){
    $err = 'Passwords do not match.';
  } else {
    $users = [
      $username => [
        'hash' => password_hash($password, PASSWORD_DEFAULT),
        'role' => 'admin',
      ],
    ];
    $saveErr = null;
    if (auth_save_users($users, $saveErr)){
      $_SESSION['user'] = $username;
      header("Location: index.php");
      exit;
    } else {
      $err = 'Failed to save users. ' . htmlspecialchars($saveErr ?? '');
    }
  }
}
?>
<!doctype html><html lang="en">
<head>
  <meta charset="utf-8">
  <title>Install &ndash; CoD4X Web RCON Tool</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link rel="stylesheet" href="assets/styles.css">
</head>
<body>
<div class="login-card">
  <div class="logo-wrap" style="justify-content:center;margin-bottom:8px;">
    <span class="logo-pill">CoD4X</span>
  </div>
  <h2 class="login-title">First-time Setup</h2>
  <p class="small-note">Create your initial admin account for the CoD4X Web RCON Tool.</p>
  <?php if($err): ?><div class="error" role="alert"><?=$err?></div><?php endif; ?>
  <form method="post" autocomplete="off">
    <label>Admin Username
      <input type="text" name="username" required autofocus>
    </label>
    <label>Password
      <input type="password" name="password" required>
    </label>
    <label>Confirm Password
      <input type="password" name="confirm" required>
    </label>
    <button type="submit" style="width:100%;margin-top:16px;">Create Admin &amp; Login</button>
  </form>
</div>
<?php if(function_exists('panel_footer')) panel_footer(); ?>
</body>
</html>
