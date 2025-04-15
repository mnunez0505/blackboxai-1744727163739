<?php
require_once '../config/db.php';

$errors = [];
$success = false;
$token = $_GET['token'] ?? '';

if (empty($token)) {
    die("Token inválido.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($password) || empty($confirm_password)) {
        $errors[] = "Por favor complete ambos campos de contraseña.";
    } elseif ($password !== $confirm_password) {
        $errors[] = "Las contraseñas no coinciden.";
    }

    if (empty($errors)) {
        // Validate token and get user_id
        $stmt = $conn->prepare("SELECT user_id, expires_at FROM password_resets WHERE token = :token");
        $stmt->bindParam(':token', $token);
        $stmt->execute();
        $reset = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$reset) {
            $errors[] = "Token inválido o expirado.";
        } else {
            $expires_at = strtotime($reset['expires_at']);
            if ($expires_at < time()) {
                $errors[] = "El token ha expirado.";
            } else {
                // Update password
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $update = $conn->prepare("UPDATE users SET password_hash = :password_hash WHERE user_id = :user_id");
                $update->bindParam(':password_hash', $password_hash);
                $update->bindParam(':user_id', $reset['user_id']);
                if ($update->execute()) {
                    // Delete token after use
                    $delete = $conn->prepare("DELETE FROM password_resets WHERE token = :token");
                    $delete->bindParam(':token', $token);
                    $delete->execute();

                    $success = true;
                } else {
                    $errors[] = "Error al actualizar la contraseña.";
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Restablecer Contraseña</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
<div class="container mt-5">
    <h2>Restablecer Contraseña</h2>
    <?php if ($success): ?>
        <div class="alert alert-success">
            Su contraseña ha sido actualizada. <a href="login.php">Inicie sesión</a>.
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
        <form method="POST" action="reset_password.php?token=<?=htmlspecialchars($token)?>" novalidate>
            <div class="mb-3">
                <label for="password" class="form-label">Nueva Contraseña</label>
                <input type="password" class="form-control" id="password" name="password" required />
            </div>
            <div class="mb-3">
                <label for="confirm_password" class="form-label">Confirmar Nueva Contraseña</label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required />
            </div>
            <button type="submit" class="btn btn-primary">Actualizar Contraseña</button>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
