<?php
/**
 * Plugin Name: ALTCHA for MetForm
 * Description: Integriert ein ALTCHA-Widget (spam protection) in MetForm-Formulare. Mit HMAC-Prüfung und Replay-Schutz.
 * Version: 2.1.0
 * Author: Carolin Hoffmann
 * License: MIT
 */

if (!defined('ABSPATH')) {
    exit;
}

// 1. ALTCHA Script laden (als ES Module!)
add_action('wp_enqueue_scripts', function() {
    wp_enqueue_script('altcha', 'https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js', [], null, true);
});
add_filter('script_loader_tag', function($tag, $handle, $src) {
    if ($handle === 'altcha') {
        return '<script type="module" src="' . esc_url($src) . '" id="altcha-js"></script>' . "\n";
    }
    return $tag;
}, 10, 3);

// 1b. Challenge-Proxy: WordPress holt die Challenge vom ALTCHA-Server (umgeht CORS)
add_action('rest_api_init', function() {
    register_rest_route('altcha/v1', '/challenge', [
        'methods'             => 'GET',
        'callback'            => 'altcha_proxy_challenge',
        'permission_callback' => '__return_true',
    ]);
});

function altcha_proxy_challenge() {
    $altcha_server = 'https://altcha.example.com/challenge';
    $response = wp_remote_get($altcha_server, ['timeout' => 10]);

    if (is_wp_error($response)) {
        return new WP_REST_Response(['error' => 'ALTCHA-Server nicht erreichbar.'], 502);
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!$data) {
        return new WP_REST_Response(['error' => 'Ungültige Antwort vom ALTCHA-Server.'], 502);
    }

    return new WP_REST_Response($data, 200);
}

// 2. JavaScript: Widget unsichtbar einfügen + Payload per Cookie übertragen
add_action('wp_footer', function() {
    // Challenge kommt jetzt von der eigenen Domain (kein CORS!)
    $challenge_url = rest_url('altcha/v1/challenge');
    ?>
    <script>
    (function() {
        var widget = document.querySelector('altcha-widget');
        if (!widget) {
            widget = document.createElement('altcha-widget');
            widget.setAttribute('challengeurl', '<?php echo esc_url($challenge_url); ?>');
            widget.setAttribute('hidefooter', '');
            widget.setAttribute('hidelogo', '');
            widget.setAttribute('auto', 'onload');
            widget.style.display = 'none';
            document.body.appendChild(widget);
        }

        widget.addEventListener('statechange', function(e) {
            if (e.detail && e.detail.state === 'verified') {
                var payload = e.detail.payload || '';
                document.cookie = 'mf_altcha=' + encodeURIComponent(payload) + '; path=/; max-age=300; SameSite=Lax';
                console.log('[ALTCHA] Verifiziert – Cookie gesetzt.');
            }
        });

        console.log('[ALTCHA] Widget erstellt, löse Challenge...');
    })();
    </script>
    <?php
});

// 3. MetForm's eigenen Validierungs-Filter nutzen
//    Wird in MetForm\Core\Entries\Action::submit() aufgerufen, BEVOR Daten gespeichert werden.
//    Rückgabe von ['is_valid' => false, 'message' => '...'] lässt MetForm die Fehler-Response
//    korrekt selbst bauen (mit dem richtigen Objekt-Format für das React-Frontend).
add_filter('mf_after_validation_check', function($validation_data) {
    $payload = isset($_COOKIE['mf_altcha']) ? urldecode($_COOKIE['mf_altcha']) : '';

    if (empty($payload)) {
        // KEIN setcookie() hier! Sonst löscht der Set-Cookie-Header im Response
        // das Cookie, das JavaScript zwischenzeitlich gesetzt hat (Race Condition).
        return [
            'is_valid' => false,
            'message'  => 'Bitte warte einen Moment und versuche es erneut (CAPTCHA wird im Hintergrund gelöst).',
        ];
    }

    $verify = verify_altcha_metform($payload);
    if (is_wp_error($verify)) {
        return [
            'is_valid' => false,
            'message'  => $verify->get_error_message(),
        ];
    }

    // Verifizierung erfolgreich: Cookie löschen, damit es nicht wiederverwendet werden kann
    setcookie('mf_altcha', '', time() - 3600, '/');

    return $validation_data;
});

// 4. Verifizierung serverseitig (Kernlogik inkl. HMAC und Replay Protection)
function verify_altcha_metform(string $payload) {
    if (!defined('ALTCHA_HMAC_KEY') || empty(ALTCHA_HMAC_KEY)) {
        return new WP_Error('altcha_config_error', 'ALTCHA_HMAC_KEY ist in der wp-config.php nicht konfiguriert.');
    }

    $decoded = json_decode(base64_decode($payload), true);
    if (!$decoded || !isset($decoded['algorithm'], $decoded['challenge'], $decoded['number'], $decoded['signature'])) {
        return new WP_Error('altcha_invalid', 'Ungültiges ALTCHA-Format.');
    }

    $salt = $decoded['salt'] ?? '';

    // 1. Ablaufdatum prüfen
    $expires = isset($decoded['expires']) ? (int) $decoded['expires'] : 0;
    $time_to_live = DAY_IN_SECONDS;

    if ($expires > 0) {
        $now = time();
        if ($now > $expires) {
            return new WP_Error('altcha_expired', 'Das CAPTCHA ist abgelaufen. Bitte lade die Seite neu.');
        }
        $time_to_live = max(1, $expires - $now);
    }

    // 2. Replay-Schutz
    $transient_key = 'altcha_' . md5($decoded['challenge']);
    if (get_transient($transient_key)) {
        return new WP_Error('altcha_reused', 'Dieses CAPTCHA wurde bereits verwendet (Replay-Schutz).');
    }

    // 3. HMAC-Signatur-Prüfung
    $sig_v1 = hash_hmac('sha256', $decoded['challenge'], ALTCHA_HMAC_KEY);
    $sig_v2 = hash_hmac('sha256', $decoded['algorithm'] . '-' . $decoded['challenge'] . '-' . $salt, ALTCHA_HMAC_KEY);

    if (!hash_equals($sig_v1, $decoded['signature']) && !hash_equals($sig_v2, $decoded['signature'])) {
        return new WP_Error('altcha_signature_failed', 'CAPTCHA Signatur ungültig.');
    }

    // 4. Proof of Work (PoW) prüfen
    $algo = strtoupper($decoded['algorithm']);
    $hash_func = ($algo === 'SHA-512') ? 'sha512' : 'sha256';
    $check = hash($hash_func, $salt . $decoded['number']);

    if (!hash_equals($decoded['challenge'], $check)) {
        return new WP_Error('altcha_pow_failed', 'Proof-of-Work ungültig.');
    }

    // Erfolgreich: Challenge als verbraucht markieren
    set_transient($transient_key, true, $time_to_live);

    return true;
}
