<?php
// ── Konfiguration ──────────────────────────────────────────────────────────
define('DATA_FILE', __DIR__ . '/sodavand_data.json');
define('ADMIN_PW_FILE', __DIR__ . '/sodavand_pw.json');

// CORS + JSON headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// ── Hjælpefunktioner ───────────────────────────────────────────────────────
function readData() {
    if (!file_exists(DATA_FILE)) return ['players' => [], 'events' => []];
    $raw = file_get_contents(DATA_FILE);
    return json_decode($raw, true) ?: ['players' => [], 'events' => []];
}

function writeData($data) {
    // Filnøgle til at undgå race conditions
    $fp = fopen(DATA_FILE, 'c+');
    if (flock($fp, LOCK_EX)) {
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}

function readPw() {
    if (!file_exists(ADMIN_PW_FILE)) return null;
    $raw = json_decode(file_get_contents(ADMIN_PW_FILE), true);
    return $raw['pw'] ?? null;
}

function writePw($pw) {
    file_put_contents(ADMIN_PW_FILE, json_encode(['pw' => $pw]));
}

function err($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function ok($data = []) {
    echo json_encode(array_merge(['ok' => true], $data));
    exit;
}

// ── Routes ─────────────────────────────────────────────────────────────────

// GET data — åben for alle
if ($method === 'GET' && $action === 'load') {
    $data = readData();
    $hasPw = readPw() !== null;
    echo json_encode(array_merge($data, ['hasPw' => $hasPw]));
    exit;
}

// POST login — tjek kodeord
if ($method === 'POST' && $action === 'login') {
    $body = json_decode(file_get_contents('php://input'), true);
    $pw = $body['pw'] ?? '';
    $stored = readPw();
    if ($stored === null) err('Intet kodeord sat endnu');
    if ($pw !== $stored) err('Forkert kodeord', 401);
    ok(['token' => hash('sha256', $stored . date('Y-m-d'))]);
}

// POST set_pw — sæt kodeord (kræver eksisterende kodeord, eller hvis intet er sat)
if ($method === 'POST' && $action === 'set_pw') {
    $body = json_decode(file_get_contents('php://input'), true);
    $oldPw = $body['oldPw'] ?? '';
    $newPw = trim($body['newPw'] ?? '');
    $stored = readPw();

    if ($stored !== null && $oldPw !== $stored) err('Forkert nuværende kodeord', 401);
    if (strlen($newPw) < 3) err('Kodeord skal være mindst 3 tegn');
    writePw($newPw);
    ok();
}

// Alle andre POST-kald kræver gyldigt token
if ($method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    $token = $body['token'] ?? '';
    $stored = readPw();
    $expected = $stored ? hash('sha256', $stored . date('Y-m-d')) : null;

    if (!$stored || $token !== $expected) err('Ikke autoriseret', 401);

    // POST save — gem hele state
    if ($action === 'save') {
        $players = $body['players'] ?? [];
        $events  = $body['events']  ?? [];

        // Sanitér input
        $players = array_values(array_filter(array_map(fn($p) => substr(trim((string)$p), 0, 50), $players)));
        $events  = array_values(array_filter($events, fn($e) =>
            isset($e['date'], $e['type']) &&
            preg_match('/^\d{4}-\d{2}-\d{2}$/', $e['date']) &&
            in_array($e['type'], ['training', 'match'])
        ));

        writeData(['players' => $players, 'events' => $events]);
        ok();
    }

    err('Ukendt handling');
}

err('Ugyldig forespørgsel');
