<?php
session_start();
require_once '../config/db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$role = $_SESSION['role'];

// Fetch invoices based on role
if ($role === 'admin') {
    $stmt = $conn->prepare("SELECT invoices.*, users.username FROM invoices JOIN users ON invoices.user_id = users.user_id ORDER BY invoices.created_at DESC");
    $stmt->execute();
    $invoices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} else {
    $stmt = $conn->prepare("SELECT * FROM invoices WHERE user_id = :user_id ORDER BY created_at DESC");
    $stmt->bindParam(':user_id', $user_id);
    $stmt->execute();
    $invoices = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Dashboard de Facturas</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
<div class="container mt-5">
    <h2>Dashboard de Facturas</h2>
    <p>Bienvenido, <?=htmlspecialchars($_SESSION['username'])?> | <a href="../auth/logout.php">Cerrar sesión</a></p>
    <?php if ($role !== 'admin'): ?>
        <a href="create_invoice.php" class="btn btn-primary mb-3">Registrar Nueva Factura</a>
    <?php endif; ?>
    <table class="table table-bordered">
        <thead>
            <tr>
                <th>ID</th>
                <?php if ($role === 'admin'): ?>
                    <th>Usuario</th>
                <?php endif; ?>
                <th>Proveedor</th>
                <th>Número de Factura</th>
                <th>Monto</th>
                <th>Estado</th>
                <th>Fecha de Creación</th>
                <th>Acciones</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($invoices as $invoice): ?>
                <tr>
                    <td><?=htmlspecialchars($invoice['invoice_id'])?></td>
                    <?php if ($role === 'admin'): ?>
                        <td><?=htmlspecialchars($invoice['username'])?></td>
                    <?php endif; ?>
                    <td><?=htmlspecialchars($invoice['supplier_name'])?></td>
                    <td><?=htmlspecialchars($invoice['invoice_number'])?></td>
                    <td><?=htmlspecialchars(number_format($invoice['amount'], 2))?></td>
                    <td><?=htmlspecialchars($invoice['status'])?></td>
                    <td><?=htmlspecialchars($invoice['created_at'])?></td>
                    <td>
                        <a href="view_invoice.php?id=<?=htmlspecialchars($invoice['invoice_id'])?>" class="btn btn-info btn-sm">Ver</a>
                        <?php if ($role !== 'admin' && $invoice['status'] === 'open'): ?>
                            <a href="edit_invoice.php?id=<?=htmlspecialchars($invoice['invoice_id'])?>" class="btn btn-warning btn-sm">Editar</a>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($invoices)): ?>
                <tr><td colspan="<?= $role === 'admin' ? 8 : 7 ?>" class="text-center">No hay facturas registradas.</td></tr>
            <?php endif; ?>
        </tbody>
    </table>
</div>
</body>
</html>
