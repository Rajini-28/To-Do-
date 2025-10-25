<?php
// signup.php
require 'config.php';
if (is_logged_in()) {
  header('Location: dashboard.php');
  exit;
}

$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $username = trim($_POST['username'] ?? '');
  $email = trim($_POST['email'] ?? '');
  $password = $_POST['password'] ?? '';
  $password2 = $_POST['password2'] ?? '';

  if (strlen($username) < 3) $errors[] = 'Username must be at least 3 characters';
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Invalid email';
  if (strlen($password) < 6) $errors[] = 'Password must be at least 6 characters';
  if ($password !== $password2) $errors[] = 'Passwords do not match';

  if (empty($errors)) {
    // check unique
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1');
    $stmt->execute([$email, $username]);
    if ($stmt->fetch()) {
      $errors[] = 'Email or username already taken';
    } else {
      $hash = password_hash($password, PASSWORD_DEFAULT);
      $stmt = $pdo->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
      $stmt->execute([$username, $email, $hash]);
      // auto-login
      $_SESSION['user_id'] = $pdo->lastInsertId();
      $_SESSION['username'] = $username;
      header('Location: dashboard.php');
      exit;
    }
  }
}
?>

<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign up — TaskApp</title>
  <link rel="stylesheet" href="assets/styles.css">
</head>
<body class="page-signup">
  <main class="card center">
    <h1>Create account ✨</h1>
    <?php if (!empty($errors)): ?>
      <div class="error">
        <ul>
          <?php foreach ($errors as $e): ?>
            <li><?php echo htmlspecialchars($e); ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>
    <form method="post" class="form">
      <label>Username <input type="text" name="username" required></label>
      <label>Email <input type="email" name="email" required></label>
      <label>Password <input type="password" name="password" required></label>
      <label>Confirm Password <input type="password" name="password2" required></label>
      <button type="submit" class="btn">Sign up</button>
    </form>
    <p>Have an account? <a href="index.php">Log in</a></p>
  </main>
</body>
</html>
