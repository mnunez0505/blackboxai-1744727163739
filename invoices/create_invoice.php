<?php
session_start();
require_once '../config/db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] === 'admin') {
    header("Location: ../auth/login.php");
    exit;
}

$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $supplier_name = trim($_POST['supplier_name']);
    $invoice_number = trim($_POST['invoice_number']);
    $amount = trim($_POST['amount']);
    $user_id = $_SESSION['user_id'];

    if (empty($supplier_name) || empty($invoice_number) || empty($amount)) {
        $errors[] = "Todos los campos son obligatorios.";
    } elseif (!is_numeric($amount) || $amount <= 0) {
        $errors[] = "El monto debe ser un número positivo.";
    }

    if (empty($errors)) {
        $stmt = $conn->prepare("INSERT INTO invoices (user_id, supplier_name, invoice_number, amount, status) VALUES (:user_id, :supplier_name, :invoice_number, :amount, 'open')");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':supplier_name', $supplier_name);
        $stmt->bindParam(':invoice_number', $invoice_number);
        $stmt->bindParam(':amount', $amount);
        if ($stmt->execute()) {
            header("Location: dashboard.php");
            exit;
        } else {
            $errors[] = "Error al registrar la factura.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Registrar Factura</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
<div class="container mt-5">
    <h2>Registrar Nueva Factura</h2>
    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger">
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?=htmlspecialchars($error)?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>
    <form method="POST" action="create_invoice.php" novalidate>
        <div class="mb-3">
            <label for="supplier_name" class="form-label">Nombre del Proveedor</label>
            <input type="text" class="form-control" id="supplier_name" name="supplier_name" required value="<?=htmlspecialchars($_POST['supplier_name'] ?? '')?>" />
        </div>
        <div class="mb-3">
            <label for="invoice_number" class="form-label">Número de Factura</label>
            <input type="text" class="form-control" id="invoice_number" name="invoice_number" required value="<?=htmlspecialchars($_POST['invoice_number'] ?? '')?>" />
        </div>
        <div class="mb-3">
            <label for="amount" class="form-label">Monto</label>
            <input type="number" step="0.01" class="form-control" id="amount" name="amount" required value="<?=htmlspecialchars($_POST['amount'] ?? '')?>" />
        </div>
        <button type="submit" class="btn btn-primary">Registrar</button>
        <a href="dashboard.php" class="btn btn-link">Cancelar</a>
    </form>
</div>
</body>
</html>
