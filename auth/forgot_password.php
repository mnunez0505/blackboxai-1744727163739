<?php
require_once '../config/db.php';

$success = false;
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    if (empty($email)) {
        $errors[] = "Por favor ingrese su correo electrónico.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Correo electrónico inválido.";
    } else {
        // Check if email exists
        $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Generate token and expiration
            $token = bin2hex(random_bytes(16));
            $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));

            // Store token and expiration in a password_resets table (to be created)
            $insert = $conn->prepare("INSERT INTO password_resets (user_id, token, expires_at) VALUES (:user_id, :token, TO_TIMESTAMP(:expires, 'YYYY-MM-DD HH24:MI:SS'))");
            $insert->bindParam(':user_id', $user['user_id']);
            $insert->bindParam(':token', $token);
            $insert->bindParam(':expires', $expires);
            $insert->execute();

            // Send email with reset link (assuming mail setup)
            $reset_link = "http://yourdomain.com/auth/reset_password.php?token=" . $token;
            $subject = "Restablecer contraseña";
            $message = "Para restablecer su contraseña, haga clic en el siguiente enlace: " . $reset_link;
            $headers = "From: no-reply@yourdomain.com\r\n";

            mail($email, $subject, $message, $headers);

            $success = true;
        } else {
            $errors[] = "No se encontró una cuenta con ese correo electrónico.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Olvidé mi contraseña</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
<div class="container mt-5">
    <h2>Olvidé mi contraseña</h2>
    <?php if ($success): ?>
        <div class="alert alert-success">
            Se ha enviado un correo con instrucciones para restablecer su contraseña.
        </div>
    <?php else: ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?=htmlspecialchars($error)?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        <form method="POST" action="forgot_password.php" novalidate>
            <div class="mb-3">
                <label for="email" class="form-label">Correo electrónico</label>
                <input type="email" class="form-control" id="email" name="email" required value="<?=htmlspecialchars($_POST['email'] ?? '')?>" />
            </div>
            <button type="submit" class="btn btn-primary">Enviar instrucciones</button>
            <a href="login.php" class="btn btn-link">Volver al inicio de sesión</a>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
