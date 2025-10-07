<?php

if( !defined( 'DVWA_WEB_PAGE_TO_ROOT' ) ) {
    die( 'DVWA System error- WEB_PAGE_TO_ROOT undefined' );
    exit;
}

if (!file_exists(DVWA_WEB_PAGE_TO_ROOT . 'config/config.inc.php')) {
    die ("DVWA System error - config file not found. Copy config/config.inc.php.dist to config/config.inc.php and configure to your environment.");
}

// Include configs
require_once DVWA_WEB_PAGE_TO_ROOT . 'config/config.inc.php';

// --- Helpers de escape (usar siempre en salidas HTML) ---
function escapeHtml($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function escapeAttr($s) {
    // idéntico a escapeHtml pero semántico para atributos
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// --- Fin helpers ---

// Declare the $html variable
if( !isset( $html ) ) {
    $html = "";
}

// Valid security levels
$security_levels = array('low', 'medium', 'high', 'impossible');
if( !isset( $_COOKIE[ 'security' ] ) || !in_array( $_COOKIE[ 'security' ], $security_levels ) ) {
    // Set security cookie to impossible if no cookie exists
    if( in_array( $_DVWA[ 'default_security_level' ], $security_levels) ) {
        dvwaSecurityLevelSet( $_DVWA[ 'default_security_level' ] );
    } else {
        dvwaSecurityLevelSet( 'impossible' );
    }
    // If the cookie wasn't set then the session flags need updating.
    dvwa_start_session();
}

/*
 * This function is called after login and when you change the security level.
 * It gets the security level and sets the httponly and samesite cookie flags
 * appropriately.
 *
 * To force an update of the cookie flags we need to update the session id,
 * just setting the flags and doing a session_start() does not change anything.
 * For this, session_id() or session_regenerate_id() can be used.
 * Both keep the existing session values, so nothing is lost,
 * it will just cause a new Set-Cookie header to be sent with the new right
 * flags and the new id (or the same one if we wish to keep it).
*/
function dvwa_start_session() {
    // This will setup the session cookie based on
    // the security level.

    $security_level = dvwaSecurityLevelGet();
    if ($security_level == 'impossible') {
        $httponly = true;
        $samesite = "Strict";
    }
    else {
        $httponly = false;
        $samesite = "";
    }

    $maxlifetime = 86400;
    $secure = false;
    // domain: prefer an empty domain to avoid parsing issues; keep as host if valid
    $domain = '';
    if (!empty($_SERVER['HTTP_HOST'])) {
        // no parse_url here; accept only hostname chars
        $host = preg_replace('/[^A-Za-z0-9\.\-]/', '', $_SERVER['HTTP_HOST']);
        $domain = $host;
    }

    /*
     * Need to do this as you can't update the settings of a session
     * while it is open. So check if one is open, close it if needed
     * then update the values and start it again.
    */
    if (session_status() == PHP_SESSION_ACTIVE) {
        session_write_close();
    }

    session_set_cookie_params([
        'lifetime' => $maxlifetime,
        'path' => '/',
        'domain' => $domain,
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => $samesite
    ]);

    /*
     * We need to force a new Set-Cookie header with the updated flags by updating
     * the session id, either regenerating it or setting it to a value, because
     * session_start() might not generate a Set-Cookie header if a cookie already
     * exists.
     *
     * For impossible security level, we regenerate the session id, PHP will
     * generate a new random id. This is good security practice because it
     * prevents the reuse of a previous unauthenticated id that an attacker
     * might have knowledge of (aka session fixation attack).
     *
     * For lower levels, we want to allow session fixation attacks, so if an id
     * already exists, we don't want it to change after authentication. We thus
     * set the id to its previous value using session_id(), which will force
     * the Set-Cookie header.
    */
    if ($security_level == 'impossible') {
        session_start();
        session_regenerate_id(); // force a new id to be generated
    }
    else {
        if (isset($_COOKIE[session_name()])) // if a session id already exists
            session_id($_COOKIE[session_name()]); // we keep the same id
        session_start(); // otherwise a new one will be generated here
    }
}

if (array_key_exists ("Login", $_POST) && $_POST['Login'] == "Login") {
    dvwa_start_session();
} else {
    if (!session_id()) {
        session_start();
    }
}

if (!array_key_exists ("default_locale", $_DVWA)) {
    $_DVWA[ 'default_locale' ] = "en";
}

dvwaLocaleSet( $_DVWA[ 'default_locale' ] );

// Start session functions --

function &dvwaSessionGrab() {
    if( !isset( $_SESSION[ 'dvwa' ] ) ) {
        $_SESSION[ 'dvwa' ] = array();
    }
    return $_SESSION[ 'dvwa' ];
}


function dvwaPageStartup( $pActions ) {
    if (in_array('authenticated', $pActions)) {
        if( !dvwaIsLoggedIn()) {
            dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'login.php' );
        }
    }
}

function dvwaLogin( $pUsername ) {
    $dvwaSession =& dvwaSessionGrab();
    $dvwaSession[ 'username' ] = $pUsername;
}


function dvwaIsLoggedIn() {
    global $_DVWA;

    if (array_key_exists("disable_authentication", $_DVWA) && $_DVWA['disable_authentication']) {
        return true;
    }
    $dvwaSession =& dvwaSessionGrab();
    return isset( $dvwaSession[ 'username' ] );
}


function dvwaLogout() {
    $dvwaSession =& dvwaSessionGrab();
    unset( $dvwaSession[ 'username' ] );
}


function dvwaPageReload() {
    if  ( array_key_exists( 'HTTP_X_FORWARDED_PREFIX' , $_SERVER )) {
        dvwaRedirect( $_SERVER[ 'HTTP_X_FORWARDED_PREFIX' ] . $_SERVER[ 'PHP_SELF' ] );
    }
    else {
        dvwaRedirect( $_SERVER[ 'PHP_SELF' ] );
    }
}

function dvwaCurrentUser() {
    $dvwaSession =& dvwaSessionGrab();
    return ( isset( $dvwaSession[ 'username' ]) ? $dvwaSession[ 'username' ] : 'Unknown') ;
}

// -- END (Session functions)

function &dvwaPageNewGrab() {
    $returnArray = array(
        'title'           => 'Damn Vulnerable Web Application (DVWA)',
        'title_separator' => ' :: ',
        'body'            => '',
        'page_id'         => '',
        'help_button'     => '',
        'source_button'   => '',
    );
    return $returnArray;
}


function dvwaThemeGet() {
    // whitelisted themes only (evita inyección en class)
    $allowed = array('light', 'dark');
    if (isset($_COOKIE['theme']) && in_array($_COOKIE['theme'], $allowed, true)) {
        return $_COOKIE['theme'];
    }
    return 'light';
}


function dvwaSecurityLevelGet() {
    global $_DVWA;

    // If there is a security cookie, that takes priority.
    if (isset($_COOKIE['security'])) {
        // validate cookie value
        $levels = array('low', 'medium', 'high', 'impossible');
        if (in_array($_COOKIE['security'], $levels, true)) {
            return $_COOKIE[ 'security' ];
        }
    }

    // If not, check to see if authentication is disabled, if it is, use
    // the default security level.
    if (array_key_exists("disable_authentication", $_DVWA) && $_DVWA['disable_authentication']) {
        return $_DVWA[ 'default_security_level' ];
    }

    // Worse case, set the level to impossible.
    return 'impossible';
}


function dvwaSecurityLevelSet( $pSecurityLevel ) {
    if( $pSecurityLevel == 'impossible' ) {
        $httponly = true;
    }
    else {
        $httponly = false;
    }

    // validate before set
    $levels = array('low', 'medium', 'high', 'impossible');
    if (!in_array($pSecurityLevel, $levels, true)) {
        $pSecurityLevel = 'impossible';
    }

    setcookie( 'security', $pSecurityLevel, 0, "/", "", false, $httponly );
    $_COOKIE['security'] = $pSecurityLevel;
}

function dvwaLocaleGet() {
    $dvwaSession =& dvwaSessionGrab();
    return $dvwaSession[ 'locale' ];
}

function dvwaSQLiDBGet() {
    global $_DVWA;
    return $_DVWA['SQLI_DB'];
}

function dvwaLocaleSet( $pLocale ) {
    $dvwaSession =& dvwaSessionGrab();
    $locales = array('en', 'zh');
    if( in_array( $pLocale, $locales) ) {
        $dvwaSession[ 'locale' ] = $pLocale;
    } else {
        $dvwaSession[ 'locale' ] = 'en';
    }
}

// Start message functions --

function dvwaMessagePush( $pMessage ) {
    $dvwaSession =& dvwaSessionGrab();
    if( !isset( $dvwaSession[ 'messages' ] ) ) {
        $dvwaSession[ 'messages' ] = array();
    }
    $dvwaSession[ 'messages' ][] = $pMessage;
}


function dvwaMessagePop() {
    $dvwaSession =& dvwaSessionGrab();
    if( !isset( $dvwaSession[ 'messages' ] ) || count( $dvwaSession[ 'messages' ] ) == 0 ) {
        return false;
    }
    return array_shift( $dvwaSession[ 'messages' ] );
}


function messagesPopAllToHtml() {
    $messagesHtml = '';
    while( $message = dvwaMessagePop() ) {   // TODO- sharpen!
        // escapar mensajes antes de imprimir
        $safeMessage = escapeHtml($message);
        $messagesHtml .= "<div class=\"message\">{$safeMessage}</div>";
    }

    return $messagesHtml;
}

// --END (message functions)

function dvwaHtmlEcho( $pPage ) {
    $menuBlocks = array();

    $menuBlocks[ 'home' ] = array();
    if( dvwaIsLoggedIn() ) {
        $menuBlocks[ 'home' ][] = array( 'id' => 'home', 'name' => 'Home', 'url' => '.' );
        $menuBlocks[ 'home' ][] = array( 'id' => 'instructions', 'name' => 'Instructions', 'url' => 'instructions.php' );
        $menuBlocks[ 'home' ][] = array( 'id' => 'setup', 'name' => 'Setup / Reset DB', 'url' => 'setup.php' );
    }
    else {
        $menuBlocks[ 'home' ][] = array( 'id' => 'setup', 'name' => 'Setup DVWA', 'url' => 'setup.php' );
        $menuBlocks[ 'home' ][] = array( 'id' => 'instructions', 'name' => 'Instructions', 'url' => 'instructions.php' );
    }

    if( dvwaIsLoggedIn() ) {
        $menuBlocks[ 'vulnerabilities' ] = array();
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'brute', 'name' => 'Brute Force', 'url' => 'vulnerabilities/brute/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'exec', 'name' => 'Command Injection', 'url' => 'vulnerabilities/exec/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'csrf', 'name' => 'CSRF', 'url' => 'vulnerabilities/csrf/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'fi', 'name' => 'File Inclusion', 'url' => 'vulnerabilities/fi/.?page=include.php' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'upload', 'name' => 'File Upload', 'url' => 'vulnerabilities/upload/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'captcha', 'name' => 'Insecure CAPTCHA', 'url' => 'vulnerabilities/captcha/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'sqli', 'name' => 'SQL Injection', 'url' => 'vulnerabilities/sqli/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'sqli_blind', 'name' => 'SQL Injection (Blind)', 'url' => 'vulnerabilities/sqli_blind/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'weak_id', 'name' => 'Weak Session IDs', 'url' => 'vulnerabilities/weak_id/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'xss_d', 'name' => 'XSS (DOM)', 'url' => 'vulnerabilities/xss_d/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'xss_r', 'name' => 'XSS (Reflected)', 'url' => 'vulnerabilities/xss_r/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'xss_s', 'name' => 'XSS (Stored)', 'url' => 'vulnerabilities/xss_s/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'csp', 'name' => 'CSP Bypass', 'url' => 'vulnerabilities/csp/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'javascript', 'name' => 'JavaScript', 'url' => 'vulnerabilities/javascript/' );
        if (dvwaCurrentUser() == "admin") {
            $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'authbypass', 'name' => 'Authorisation Bypass', 'url' => 'vulnerabilities/authbypass/' );
        }
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'open_redirect', 'name' => 'Open HTTP Redirect', 'url' => 'vulnerabilities/open_redirect/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'encryption', 'name' => 'Cryptography', 'url' => 'vulnerabilities/cryptography/' );
        $menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'api', 'name' => 'API', 'url' => 'vulnerabilities/api/' );
    }

    $menuBlocks[ 'meta' ] = array();
    if( dvwaIsLoggedIn() ) {
        $menuBlocks[ 'meta' ][] = array( 'id' => 'security', 'name' => 'DVWA Security', 'url' => 'security.php' );
        $menuBlocks[ 'meta' ][] = array( 'id' => 'phpinfo', 'name' => 'PHP Info', 'url' => 'phpinfo.php' );
    }
    $menuBlocks[ 'meta' ][] = array( 'id' => 'about', 'name' => 'About', 'url' => 'about.php' );

    if( dvwaIsLoggedIn() ) {
        $menuBlocks[ 'logout' ] = array();
        $menuBlocks[ 'logout' ][] = array( 'id' => 'logout', 'name' => 'Logout', 'url' => 'logout.php' );
    }

    $menuHtml = '';

    foreach( $menuBlocks as $menuBlock ) {
        $menuBlockHtml = '';
        foreach( $menuBlock as $menuItem ) {
            $selectedClass = ( $menuItem[ 'id' ] == $pPage[ 'page_id' ] ) ? 'selected' : '';
            $fixedUrl = DVWA_WEB_PAGE_TO_ROOT . $menuItem[ 'url' ];
            $safeUrl = escapeAttr($fixedUrl);
            $safeName = escapeHtml($menuItem[ 'name' ]);
            $menuBlockHtml .= "<li class=\"" . escapeAttr($selectedClass) . "\"><a href=\"" . $safeUrl . "\">" . $safeName . "</a></li>\n";
        }
        $menuHtml .= "<ul class=\"menuBlocks\">{$menuBlockHtml}</ul>";
    }

    // Get security cookie --
    $securityLevelHtml = '';
    switch( dvwaSecurityLevelGet() ) {
        case 'low':
            $securityLevelHtml = 'low';
            break;
        case 'medium':
            $securityLevelHtml = 'medium';
            break;
        case 'high':
            $securityLevelHtml = 'high';
            break;
        default:
            $securityLevelHtml = 'impossible';
            break;
    }
    // -- END (security cookie)

    // Escapar user info y system info antes de concatenar
    $userInfoHtml = '<em>Username:</em> ' . escapeHtml( dvwaCurrentUser() );
    $securityLevelHtmlEsc = "<em>Security Level:</em> " . escapeHtml($securityLevelHtml);
    $localeHtml = '<em>Locale:</em> ' . escapeHtml( dvwaLocaleGet() );
    $sqliDbHtml = '<em>SQLi DB:</em> ' . escapeHtml( dvwaSQLiDBGet() );


    $messagesHtml = messagesPopAllToHtml();
    if( $messagesHtml ) {
        $messagesHtml = "<div class=\"body_padded\">{$messagesHtml}</div>";
    }

    $systemInfoHtml = "";
    if( dvwaIsLoggedIn() )
        $systemInfoHtml = "<div align=\"left\">{$userInfoHtml}<br />{$securityLevelHtmlEsc}<br />{$localeHtml}<br />{$sqliDbHtml}</div>";
    if( $pPage[ 'source_button' ] ) {
        $systemInfoHtml = dvwaButtonSourceHtmlGet( $pPage[ 'source_button' ] ) . " $systemInfoHtml";
    }
    if( $pPage[ 'help_button' ] ) {
        $systemInfoHtml = dvwaButtonHelpHtmlGet( $pPage[ 'help_button' ] ) . " $systemInfoHtml";
    }

    // Send Headers + main HTML code
    Header( 'Cache-Control: no-cache, must-revalidate');   // HTTP/1.1
    Header( 'Content-Type: text/html;charset=utf-8' );     // TODO- proper XHTML headers...
    Header( 'Expires: Tue, 23 Jun 2009 12:00:00 GMT' );    // Date in the past

    // Escape title. For body, allow raw HTML only if explicitly requested.
    $safeTitle = isset($pPage['title']) ? escapeHtml($pPage['title']) : 'Damn Vulnerable Web Application (DVWA)';
    $bodyIsRaw = isset($pPage['raw_body']) && $pPage['raw_body'] === true;

    // Theme is returned by dvwaThemeGet() (whitelisted)
    $themeClass = escapeAttr(dvwaThemeGet());

    echo "<!DOCTYPE html>

<html lang=\"en-GB\">

    <head>
        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />

        <title>{$safeTitle}</title>

        <link rel=\"stylesheet\" type=\"text/css\" href=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/css/main.css\" />

        <link rel=\"icon\" type=\"image/ico\" href=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "favicon.ico\" />

        <script type=\"text/javascript\" src=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/js/dvwaPage.js\"></script>

    </head>

    <body class=\"home " . $themeClass . "\">
        <div id=\"container\">

            <div id=\"header\">

                <img src=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/images/logo.png\" alt=\"Damn Vulnerable Web Application\" />
                <a href=\"#\" onclick=\"javascript:toggleTheme();\" class=\"theme-icon\" title=\"Toggle theme between light and dark.\">
                    <img src=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/images/theme-light-dark.png\" alt=\"Damn Vulnerable Web Application\" />
                </a>
            </div>

            <div id=\"main_menu\">

                <div id=\"main_menu_padded\">
                {$menuHtml}
                </div>

            </div>

            <div id=\"main_body\">
";

    if ($bodyIsRaw) {
        // Si el desarrollador ha marcado raw_body => true, imprimimos tal cual.
        // ADVERTENCIA: solo usar si el HTML ha sido limpiado previamente.
        echo isset($pPage['body']) ? $pPage['body'] : '';
    } else {
        // Escapar por defecto
        echo isset($pPage['body']) ? escapeHtml($pPage['body']) : '';
    }

    echo "
                <br /><br />
                {$messagesHtml}

            </div>

            <div class=\"clear\">
            </div>

            <div id=\"system_info\">
                " . $systemInfoHtml . "
            </div>

            <div id=\"footer\">

                <p>Damn Vulnerable Web Application (DVWA)</p>
                <script src='" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/js/add_event_listeners.js'></script>

            </div>

        </div>

    </body>

</html>";
}


function dvwaHelpHtmlEcho( $pPage ) {
    // Send Headers
    Header( 'Cache-Control: no-cache, must-revalidate');   // HTTP/1.1
    Header( 'Content-Type: text/html;charset=utf-8' );     // TODO- proper XHTML headers...
    Header( 'Expires: Tue, 23 Jun 2009 12:00:00 GMT' );    // Date in the past

    $safeTitle = isset($pPage['title']) ? escapeHtml($pPage['title']) : 'Help';

    echo "<!DOCTYPE html>

<html lang=\"en-GB\">

    <head>

        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />

        <title>{$safeTitle}</title>

        <link rel=\"stylesheet\" type=\"text/css\" href=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/css/help.css\" />

        <link rel=\"icon\" type=\"image/ico\" href=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "favicon.ico\" />

    </head>

    <body class=\"" . escapeAttr(dvwaThemeGet()) . "\">

    <div id=\"container\">

            " . (isset($pPage['body']) ? escapeHtml($pPage['body']) : '') . "

        </div>

    </body>

</html>";
}


function dvwaSourceHtmlEcho( $pPage ) {
    // Send Headers
    Header( 'Cache-Control: no-cache, must-revalidate');   // HTTP/1.1
    Header( 'Content-Type: text/html;charset=utf-8' );     // TODO- proper XHTML headers...
    Header( 'Expires: Tue, 23 Jun 2009 12:00:00 GMT' );    // Date in the past

    $safeTitle = isset($pPage['title']) ? escapeHtml($pPage['title']) : 'Source';

    echo "<!DOCTYPE html>

<html lang=\"en-GB\">

    <head>

        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />

        <title>{$safeTitle}</title>

        <link rel=\"stylesheet\" type=\"text/css\" href=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "dvwa/css/source.css\" />

        <link rel=\"icon\" type=\"image/ico\" href=\"" . escapeAttr(DVWA_WEB_PAGE_TO_ROOT) . "favicon.ico\" />

    </head>

    <body class=\"" . escapeAttr(dvwaThemeGet()) . "\">

        <div id=\"container\">

            " . (isset($pPage['body']) ? escapeHtml($pPage['body']) : '') . "

        </div>

    </body>

</html>";
}

// To be used on all external links --
function dvwaExternalLinkUrlGet( $pLink, $text = null ) {
    $safeHref = escapeAttr($pLink);
    if (is_null( $text ) || $text == "") {
        $safeText = escapeHtml($pLink);
    }
    else {
        $safeText = escapeHtml($text);
    }
    // rel="noopener noreferrer" para seguridad
    return '<a href="' . $safeHref . '" target="_blank" rel="noopener noreferrer">' . $safeText . '</a>';
}
// -- END ( external links)

function dvwaButtonHelpHtmlGet( $pId ) {
    $security = dvwaSecurityLevelGet();
    $locale = dvwaLocaleGet();

    // Sanear valores para la URL
    $safeId = urlencode($pId);
    $safeSecurity = urlencode($security);
    $safeLocale = urlencode($locale);

    $url = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/view_help.php?id={$safeId}&security={$safeSecurity}&locale={$safeLocale}";

    $safeDataUrl = escapeAttr($url);

    return "<input type=\"button\" value=\"View Help\" class=\"popup_button\" id='help_button' data-help-url='{$safeDataUrl}' />";
}


function dvwaButtonSourceHtmlGet( $pId ) {
    $security = dvwaSecurityLevelGet();
    $safeId = urlencode($pId);
    $safeSecurity = urlencode($security);

    $url = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/view_source.php?id={$safeId}&security={$safeSecurity}";
    $safeDataUrl = escapeAttr($url);

    return "<input type=\"button\" value=\"View Source\" class=\"popup_button\" id='source_button' data-source-url='{$safeDataUrl}' />";
}


// Database Management --

if( $DBMS == 'MySQL' ) {
    $DBMS = htmlspecialchars(strip_tags( $DBMS ));
}
elseif( $DBMS == 'PGSQL' ) {
    $DBMS = htmlspecialchars(strip_tags( $DBMS ));
}
else {
    $DBMS = "No DBMS selected.";
}

function dvwaDatabaseConnect() {
    global $_DVWA;
    global $DBMS;
    //global $DBMS_connError;
    global $db;
    global $sqlite_db_connection;

    if( $DBMS == 'MySQL' ) {
        if( !@($GLOBALS["___mysqli_ston"] = mysqli_connect( $_DVWA[ 'db_server' ],  $_DVWA[ 'db_user' ],  $_DVWA[ 'db_password' ], "", $_DVWA[ 'db_port' ] ))
        || !@((bool)mysqli_query($GLOBALS["___mysqli_ston"], "USE " . $_DVWA[ 'db_database' ])) ) {
            //die( $DBMS_connError );
            dvwaLogout();
            dvwaMessagePush( 'Unable to connect to the database.<br />' . mysqli_error($GLOBALS["___mysqli_ston"]));
            dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'setup.php' );
        }
        // MySQL PDO Prepared Statements (for impossible levels)
        $db = new PDO('mysql:host=' . $_DVWA[ 'db_server' ].';dbname=' . $_DVWA[ 'db_database' ].';port=' . $_DVWA['db_port'] . ';charset=utf8', $_DVWA[ 'db_user' ], $_DVWA[ 'db_password' ]);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }
    elseif( $DBMS == 'PGSQL' ) {
        //$dbconn = pg_connect("host={$_DVWA[ 'db_server' ]} dbname={$_DVWA[ 'db_database' ]} user={$_DVWA[ 'db_user' ]} password={$_DVWA[ 'db_password' ])}"
        //or die( $DBMS_connError );
        dvwaMessagePush( 'PostgreSQL is not currently supported.' );
        dvwaPageReload();
    }
    else {
        die ( "Unknown {$DBMS} selected." );
    }

    if ($_DVWA['SQLI_DB'] == SQLITE) {
        $location = DVWA_WEB_PAGE_TO_ROOT . "database/" . $_DVWA['SQLITE_DB'];
        $sqlite_db_connection = new SQLite3($location);
        $sqlite_db_connection->enableExceptions(true);
    #   print "sqlite db setup";
    }
}

// -- END (Database Management)


function dvwaRedirect( $pLocation ) {
    session_commit();
    header( "Location: {$pLocation}" );
    exit;
}

// XSS Stored guestbook function --
function dvwaGuestbook() {
    $query  = "SELECT name, comment FROM guestbook";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

    $guestbook = '';

    while( $row = mysqli_fetch_row( $result ) ) {
        // Escapar siempre contenido proveniente de la DB
        $name    = escapeHtml($row[0]);
        $comment = escapeHtml($row[1]);

        $guestbook .= "<div id=\"guestbook_comments\">Name: {$name}<br />" . "Message: {$comment}<br /></div>\n";
    }
    return $guestbook;
}
// -- END (XSS Stored guestbook)


// Token functions --
function checkToken( $user_token, $session_token, $returnURL ) {  # Validate the given (CSRF) token
    global $_DVWA;

    if (array_key_exists("disable_authentication", $_DVWA) && $_DVWA['disable_authentication']) {
        return true;
    }

    if( $user_token !== $session_token || !isset( $session_token ) ) {
        dvwaMessagePush( 'CSRF token is incorrect' );
        dvwaRedirect( $returnURL );
    }
}

function generateSessionToken() {  # Generate a brand new (CSRF) token
    if( isset( $_SESSION[ 'session_token' ] ) ) {
        destroySessionToken();
    }
    // usar random_bytes para más entropía si está disponible
    if (function_exists('random_bytes')) {
        $_SESSION[ 'session_token' ] = bin2hex(random_bytes(16));
    } else {
        $_SESSION[ 'session_token' ] = md5( uniqid() );
    }
}

function destroySessionToken() {  # Destroy any session with the name 'session_token'
    unset( $_SESSION[ 'session_token' ] );
}

function tokenField() {  # Return a field for the (CSRF) token
    $val = isset($_SESSION['session_token']) ? $_SESSION['session_token'] : '';
    return "<input type='hidden' name='user_token' value='" . escapeAttr($val) . "' />";
}
// -- END (Token functions)


// Setup Functions --
$PHPUploadPath    = realpath( getcwd() . DIRECTORY_SEPARATOR . DVWA_WEB_PAGE_TO_ROOT . "hackable" . DIRECTORY_SEPARATOR . "uploads" ) . DIRECTORY_SEPARATOR;
$PHPCONFIGPath       = realpath( getcwd() . DIRECTORY_SEPARATOR . DVWA_WEB_PAGE_TO_ROOT . "config");


$phpDisplayErrors = 'PHP function display_errors: <span class="' . ( ini_get( 'display_errors' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                                  // Verbose error messages (e.g. full path disclosure)
$phpDisplayStartupErrors = 'PHP function display_startup_errors: <span class="' . ( ini_get( 'display_startup_errors' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                                  // Verbose error messages (e.g. full path disclosure)
$phpDisplayErrors = 'PHP function display_errors: <span class="' . ( ini_get( 'display_errors' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                                  // Verbose error messages (e.g. full path disclosure)
$phpURLInclude    = 'PHP function allow_url_include: <span class="' . ( ini_get( 'allow_url_include' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                   // RFI
$phpURLFopen      = 'PHP function allow_url_fopen: <span class="' . ( ini_get( 'allow_url_fopen' ) ? 'success">Enabled' : 'failure">Disabled' ) . '</span>';                                       // RFI
$phpGD            = 'PHP module gd: <span class="' . ( ( extension_loaded( 'gd' ) && function_exists( 'gd_info' ) ) ? 'success">Installed' : 'failure">Missing - Only an issue if you want to play with captchas' ) . '</span>';                    // File Upload
$phpMySQL         = 'PHP module mysql: <span class="' . ( ( extension_loaded( 'mysqli' ) && function_exists( 'mysqli_query' ) ) ? 'success">Installed' : 'failure">Missing' ) . '</span>';                // Core DVWA
$phpPDO           = 'PHP module pdo_mysql: <span class="' . ( extension_loaded( 'pdo_mysql' ) ? 'success">Installed' : 'failure">Missing' ) . '</span>';                // SQLi
$DVWARecaptcha    = 'reCAPTCHA key: <span class="' . ( ( isset( $_DVWA[ 'recaptcha_public_key' ] ) && $_DVWA[ 'recaptcha_public_key' ] != '' ) ? 'success">' . escapeHtml($_DVWA[ 'recaptcha_public_key' ]) : 'failure">Missing' ) . '</span>';

$DVWAUploadsWrite = 'Writable folder ' . escapeHtml($PHPUploadPath) . ': <span class="' . ( is_writable( $PHPUploadPath ) ? 'success">Yes' : 'failure">No' ) . '</span>';                                     // File Upload
$bakWritable = 'Writable folder ' . escapeHtml($PHPCONFIGPath) . ': <span class="' . ( is_writable( $PHPCONFIGPath ) ? 'success">Yes' : 'failure">No' ) . '</span>';   // config.php.bak check                                  // File Upload

$DVWAOS           = 'Operating system: <em>' . ( strtoupper( substr (PHP_OS, 0, 3)) === 'WIN' ? 'Windows' : '*nix' ) . '</em>';
$SERVER_NAME      = 'Web Server SERVER_NAME: <em>' . escapeHtml($_SERVER[ 'SERVER_NAME' ]) . '</em>';                                                                                                          // CSRF

$MYSQL_USER       = 'Database username: <em>' . escapeHtml($_DVWA[ 'db_user' ]) . '</em>';
$MYSQL_PASS       = 'Database password: <em>' . ( ($_DVWA[ 'db_password' ] != "" ) ? '******' : '*blank*' ) . '</em>';
$MYSQL_DB         = 'Database database: <em>' . escapeHtml($_DVWA[ 'db_database' ]) . '</em>';
$MYSQL_SERVER     = 'Database host: <em>' . escapeHtml($_DVWA[ 'db_server' ]) . '</em>';
$MYSQL_PORT       = 'Database port: <em>' . escapeHtml($_DVWA[ 'db_port' ]) . '</em>';
// -- END (Setup Functions)

?>
