<?php

if (isset($_POST['Submit'])) {
    // Obtener entrada y limpiarla
    $target = trim($_POST['ip']);

    // Validar que la entrada sea una dirección IP válida
    if (filter_var($target, FILTER_VALIDATE_IP)) {

        // Determinar el sistema operativo
        if (stripos(PHP_OS, 'WIN') === 0) {
            // Windows
            $cmd = escapeshellcmd("ping -n 4 " . escapeshellarg($target));
        } else {
            // Unix/Linux
            $cmd = escapeshellcmd("ping -c 4 " . escapeshellarg($target));
        }

        // Ejecutar comando de forma segura
        $output = shell_exec($cmd);

        // Mostrar salida al usuario
        echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
    } else {
        echo "<pre>Dirección IP inválida.</pre>";
    }
}
?>
