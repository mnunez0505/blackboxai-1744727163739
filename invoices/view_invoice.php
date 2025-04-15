<?php
session_start();
require_once '../config/db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$role = $_SESSION['role'];
$invoice_id = $_GET['id'] ?? null;

if (!$invoice_id) {
    die("Factura no especificada.");
}

// Fetch invoice
if ($role === 'admin') {
    $stmt = $conn->prepare("SELECT invoices.*, users.username FROM invoices JOIN users ON invoices.user_id = users.user_id WHERE invoice_id = :invoice_id");
} else {
    $stmt = $conn->prepare("SELECT * FROM invoices WHERE invoice_id = :invoice_id AND user_id = :user_id");
    $stmt->bindParam(':user_id', $user_id);
}
$stmt->bindParam(':invoice_id', $invoice_id);
$stmt->execute();
$invoice = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$invoice) {
    die("Factura no encontrada o acceso denegado.");
}

// Handle file upload
$upload_errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file']) && $invoice['status'] === 'open' && $role !== 'admin') {
    $file = $_FILES['file'];
    if ($file['error'] === UPLOAD_ERR_OK) {
        $upload_dir = '../uploads/' . $user_id . '/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        $filename = basename($file['name']);
        $target_path = $upload_dir . uniqid() . '_' . $filename;
        if (move_uploaded_file($file['tmp_name'], $target_path)) {
            // Insert file record
            $stmt = $conn->prepare("INSERT INTO files (user_id, filename, filepath, used_in_invoice) VALUES (:user_id, :filename, :filepath, :invoice_id)");
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':filename', $filename);
            $stmt->bindParam(':filepath', $target_path);
            $stmt->bindParam(':invoice_id', $invoice_id);
            $stmt->execute();
            header("Location: view_invoice.php?id=" . $invoice_id);
            exit;
        } else {
            $upload_errors[] = "Error al mover el archivo.";
        }
    } else {
        $upload_errors[] = "Error en la subida del archivo.";
    }
}

// Fetch files for this invoice
if ($role === 'admin') {
    $stmt = $conn->prepare("SELECT files.* FROM files JOIN invoices ON files.used_in_invoice = invoices.invoice_id WHERE invoices.invoice_id = :invoice_id");
} else {
    $stmt = $conn->prepare("SELECT * FROM files WHERE used_in_invoice = :invoice_id AND user_id = :user_id");
    $stmt->bindParam(':user_id', $user_id);
}
$stmt->bindParam(':invoice_id', $invoice_id);
$stmt->execute();
$files = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Handle closing invoice
$close_errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['close_invoice']) && $invoice['status'] === 'open' && $role !== 'admin') {
    // Update invoice status
    $stmt = $conn->prepare("UPDATE invoices SET status = 'closed' WHERE invoice_id = :invoice_id");
    $stmt->bindParam(':invoice_id', $invoice_id);
    if ($stmt->execute()) {
        // Send email notification
        $stmt = $conn->prepare("SELECT email FROM users WHERE user_id = :user_id");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $to = $user['email'];
        $subject = "Factura Cerrada";
        $message = "La factura con ID $invoice_id ha sido cerrada y no permite más modificaciones.";
        $headers = "From: no-reply@yourdomain.com\r\n";
        mail($to, $subject, $message, $headers);
        header("Location: view_invoice.php?id=" . $invoice_id);
        exit;
    } else {
        $close_errors[] = "Error al cerrar la factura.";
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Detalle de Factura</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
<div class="container mt-5">
    <h2>Detalle de Factura #<?=htmlspecialchars($invoice['invoice_id'])?></h2>
    <p><strong>Proveedor:</strong> <?=htmlspecialchars($invoice['supplier_name'])?></p>
    <p><strong>Número de Factura:</strong> <?=htmlspecialchars($invoice['invoice_number'])?></p>
    <p><strong>Monto:</strong> <?=htmlspecialchars(number_format($invoice['amount'], 2))?></p>
    <p><strong>Estado:</strong> <?=htmlspecialchars($invoice['status'])?></p>
    <?php if ($role === 'admin'): ?>
        <p><strong>Usuario:</strong> <?=htmlspecialchars($invoice['username'])?></p>
    <?php endif; ?>

    <h4>Archivos Adjuntos</h4>
    <?php if (!empty($files)): ?>
        <ul>
            <?php foreach ($files as $file): ?>
                <li><a href="<?=htmlspecialchars($file['filepath'])?>" target="_blank"><?=htmlspecialchars($file['filename'])?></a></li>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <p>No hay archivos adjuntos.</p>
    <?php endif; ?>

    <?php if ($role !== 'admin' && $invoice['status'] === 'open'): ?>
        <h5>Subir Archivo de Respaldo</h5>
        <?php if (!empty($upload_errors)): ?>
            <div class="alert alert-danger">
                <ul>
                    <?php foreach ($upload_errors as $error): ?>
                        <li><?=htmlspecialchars($error)?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        <form method="POST" action="view_invoice.php?id=<?=htmlspecialchars($invoice_id)?>" enctype="multipart/form-data">
            <div class="mb-3">
                <input type="file" name="file" required />
            </div>
            <button type="submit" class="btn btn-primary">Subir Archivo</button>
        </form>

        <h5 class="mt-4">Cerrar Factura</h5>
        <?php if (!empty($close_errors)): ?>
            <div class="alert alert-danger">
                <ul>
                    <?php foreach ($close_errors as $error): ?>
                        <li><?=htmlspecialchars($error)?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        <form method="POST" action="view_invoice.php?id=<?=htmlspecialchars($invoice_id)?>">
            <button type="submit" name="close_invoice" class="btn btn-danger" onclick="return confirm('¿Está seguro de cerrar esta factura? Esta acción no se puede deshacer.')">Cerrar Factura</button>
        </form>
    <?php endif; ?>

    <a href="dashboard.php" class="btn btn-link mt-3">Volver al Dashboard</a>
</div>
</body>
</html>
